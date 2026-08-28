//! VM layer — PRODUCTION PolicyVault.v0.3.sil driven through the real
//! TxScriptEngine with covenants enabled and real Schnorr signatures.
//!
//! Covers the corrected v0.3 architecture: Merkle recipient allowlist,
//! M-of-N approvals with the SIG_HASH_ALL gate (A7) and duplicate-key
//! rejection (A2), and the owner lifecycle/governance paths. Valid paths
//! + negative-validation matrix on the ACTUAL production contract (not the
//! Phase 3 probes). Consensus-visible bytes here go through the
//! SilverScript compiler + covenant-decl call encoder; the pv_call_encoder
//! production-byte integration is a separate later step (4C/4D).

use policyvault_vm_tests::*;
use secp256k1::Keypair;
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CompiledContract, CovenantDeclCallOptions};
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL, SIG_HASH_NONE, SIG_HASH_SINGLE, SIG_HASH_ANY_ONE_CAN_PAY};
use kaspa_consensus_core::tx::{MutableTransaction, Transaction};

const KAS: i64 = 100_000_000;
const VAULT_ID: &str = "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f";
const LEAF_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn leaf(xo: &[u8; 32]) -> [u8; 32] {
    sha256(&[&LEAF_DOMAIN, xo])
}
/// Merkle root + (siblings, pathBits) proof for `leaves[target]`.
fn merkle(leaves: &[[u8; 32]], target: usize) -> ([u8; 32], Vec<u8>, u64) {
    let mut level = leaves.to_vec();
    while level.len().count_ones() != 1 {
        level.push(*level.last().unwrap());
    }
    let (mut idx, mut sibs, mut bits, mut lvl) = (target, Vec::new(), 0u64, 0);
    while level.len() > 1 {
        let s = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        sibs.extend_from_slice(&level[s]);
        if idx % 2 == 1 {
            bits |= 1 << lvl;
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(sha256(&[&pair[0], &pair[1]]));
        }
        idx /= 2;
        level = next;
        lvl += 1;
    }
    (level[0], sibs, bits)
}

#[derive(Clone)]
struct V3 {
    protected_value: i64,
    period_start_daa: i64,
    period_spent: i64,
    paused: i64,
    delegate: [u8; 32],
    delegate_active: i64,
    max_per_spend: i64,
    period_budget: i64,
    period_length_daa: i64,
    recipient_root: [u8; 32],
    approvers: [[u8; 32]; 10],
    approval_m: i64,
    approval_threshold: i64,
    policy_nonce: i64,
}

fn base_state(delegate: &Keypair, root: [u8; 32], approvers: [[u8; 32]; 10], m: i64, threshold: i64) -> V3 {
    V3 {
        protected_value: 1000 * KAS,
        period_start_daa: 541_000_000,
        period_spent: 0,
        paused: 0,
        delegate: xonly(delegate),
        delegate_active: 1,
        max_per_spend: 200 * KAS,
        period_budget: 800 * KAS,
        period_length_daa: 864_000,
        recipient_root: root,
        approvers,
        approval_m: m,
        approval_threshold: threshold,
        policy_nonce: 0,
    }
}

fn templated_source(s: &V3) -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.3.sil", env!("CARGO_MANIFEST_DIR"));
    let mut src = std::fs::read_to_string(&path).unwrap();
    let r = |src: String, from: &str, to: String| {
        assert!(src.contains(from), "template anchor missing: {from}");
        src.replacen(from, &to, 1)
    };
    src = r(src, "int protectedValue = initValue;", format!("int protectedValue = {};", s.protected_value));
    src = r(src, "int periodStartDaa = initPeriodStartDaa;", format!("int periodStartDaa = {};", s.period_start_daa));
    src = r(src, "int periodSpent = 0;", format!("int periodSpent = {};", s.period_spent));
    src = r(src, "int paused = 0;", format!("int paused = {};", s.paused));
    src = r(src, "pubkey delegate = initDelegate;", format!("pubkey delegate = 0x{};", hx(&s.delegate)));
    src = r(src, "int delegateActive = 1;", format!("int delegateActive = {};", s.delegate_active));
    src = r(src, "int maxPerSpend = initMaxPerSpend;", format!("int maxPerSpend = {};", s.max_per_spend));
    src = r(src, "int periodBudget = initPeriodBudget;", format!("int periodBudget = {};", s.period_budget));
    src = r(src, "int periodLengthDaa = initPeriodLengthDaa;", format!("int periodLengthDaa = {};", s.period_length_daa));
    src = r(src, "byte[32] recipientRoot = initRecipientRoot;", format!("byte[32] recipientRoot = 0x{};", hx(&s.recipient_root)));
    for i in 0..10 {
        src = r(src, &format!("pubkey approver{} = initApprover{};", i + 1, i + 1), format!("pubkey approver{} = 0x{};", i + 1, hx(&s.approvers[i])));
    }
    src = r(src, "int approvalM = initApprovalM;", format!("int approvalM = {};", s.approval_m));
    src = r(src, "int approvalThresholdAmount = initApprovalThresholdAmount;", format!("int approvalThresholdAmount = {};", s.approval_threshold));
    src = r(src, "int policyNonce = 0;", format!("int policyNonce = {};", s.policy_nonce));
    src
}

fn ctor_args(owner: &[u8; 32], s: &V3) -> Vec<Expr<'static>> {
    let mut a = vec![
        Expr::bytes(owner.to_vec()),
        Expr::bytes(hex32(VAULT_ID)),
        Expr::bytes(s.delegate.to_vec()),
        Expr::int(s.max_per_spend),
        Expr::int(s.period_budget),
        Expr::int(s.period_length_daa),
        Expr::bytes(s.recipient_root.to_vec()),
    ];
    for i in 0..10 {
        a.push(Expr::bytes(s.approvers[i].to_vec()));
    }
    a.push(Expr::int(s.approval_m));
    a.push(Expr::int(s.approval_threshold));
    a.push(Expr::int(s.protected_value));
    a.push(Expr::int(s.period_start_daa));
    a
}

fn compile_state(owner: &[u8; 32], s: &V3) -> CompiledContract<'static> {
    let src: &'static str = Box::leak(templated_source(s).into_boxed_str());
    compile_contract(src, &ctor_args(owner, s), CompileOptions::default()).expect("v0.3 compile")
}

fn state_arg(s: &V3) -> Expr<'static> {
    let mut fields = vec![
        ("boundVaultId", Expr::bytes(hex32(VAULT_ID))),
        ("protectedValue", Expr::int(s.protected_value)),
        ("periodStartDaa", Expr::int(s.period_start_daa)),
        ("periodSpent", Expr::int(s.period_spent)),
        ("paused", Expr::int(s.paused)),
        ("delegate", Expr::bytes(s.delegate.to_vec())),
        ("delegateActive", Expr::int(s.delegate_active)),
        ("maxPerSpend", Expr::int(s.max_per_spend)),
        ("periodBudget", Expr::int(s.period_budget)),
        ("periodLengthDaa", Expr::int(s.period_length_daa)),
        ("recipientRoot", Expr::bytes(s.recipient_root.to_vec())),
    ];
    // approver fields need 'static names; use a fixed table.
    const NAMES: [&str; 10] = ["approver1","approver2","approver3","approver4","approver5","approver6","approver7","approver8","approver9","approver10"];
    for i in 0..10 {
        fields.push((NAMES[i], Expr::bytes(s.approvers[i].to_vec())));
    }
    fields.push(("approvalM", Expr::int(s.approval_m)));
    fields.push(("approvalThresholdAmount", Expr::int(s.approval_threshold)));
    fields.push(("policyNonce", Expr::int(s.policy_nonce)));
    struct_object(fields)
}

fn sign_typed(m: &MutableTransaction<Transaction>, k: &Keypair, ty: SigHashType) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&m.as_verifiable(), 0, ty, &reused);
    let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap();
    let mut s = k.sign_schnorr(msg).as_ref().to_vec();
    s.push(ty.to_u8());
    s
}
fn placeholder() -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p.push(0x01);
    p
}

/// approvals blob: 10 × 65 bytes; `sigs[i]` = Some(keypair,type) signs slot i, None = placeholder.
fn approvals_blob(m: &MutableTransaction<Transaction>, sigs: &[Option<(&Keypair, SigHashType)>; 10]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(650);
    for slot in sigs.iter() {
        match slot {
            Some((k, ty)) => blob.extend_from_slice(&sign_typed(m, k, *ty)),
            None => blob.extend_from_slice(&placeholder()),
        }
    }
    blob
}

struct Spend<'a> {
    prev: V3,
    succ: V3,
    pay: i64,
    recipient_pk: [u8; 32],
    recipient_output: [u8; 32],
    siblings: Vec<u8>,
    path_bits: u64,
    delegate: &'a Keypair,
    delegate_sighash: SigHashType,
    approvers: [Option<(&'a Keypair, SigHashType)>; 10],
}

fn run_delegate_spend(owner: &[u8; 32], sp: Spend) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let active = compile_state(owner, &sp.prev);
    let succ_c = compile_state(owner, &sp.succ);
    let outputs = vec![
        p2pk_output(&sp.recipient_output, sp.pay as u64),
        successor_output(&succ_c, sp.succ.protected_value as u64),
    ];
    let tx = Transaction::new(1, vec![covenant_input()], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, sp.prev.protected_value as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let dsig = sign_typed(&mutable, sp.delegate, sp.delegate_sighash);
    let blob = approvals_blob(&mutable, &sp.approvers);
    let args = vec![
        state_arg(&sp.succ),
        Expr::int(sp.pay),
        Expr::bytes(sp.recipient_pk.to_vec()),
        Expr::bytes(sp.siblings.clone()),
        Expr::int(sp.path_bits as i64),
        Expr::bytes(dsig),
        Expr::bytes(blob),
    ];
    let mut ss = active.build_sig_script_for_covenant_decl("delegateSpend", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    execute_input_measured(t, vec![utxo], 0).0
}

/// Owner op with a single owner signature; successor = `succ`.
fn run_owner_op(owner_kp: &Keypair, func: &str, prev: &V3, succ: &V3) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let owner = xonly(owner_kp);
    let active = compile_state(&owner, prev);
    let succ_c = compile_state(&owner, succ);
    let outputs = vec![successor_output(&succ_c, succ.protected_value as u64)];
    let tx = Transaction::new(1, vec![covenant_input()], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, prev.protected_value as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, owner_kp, SIG_HASH_ALL);
    let args = vec![state_arg(succ), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl(func, args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    execute_input_measured(t, vec![utxo], 0).0
}

// ---- fixtures ----
fn approver_set(keys: &[&Keypair]) -> [[u8; 32]; 10] {
    // Sorted-ascending prefix is the SDK's CANONICAL layout convention; the
    // covenant itself requires only pairwise distinctness (45 `!=` checks).
    let mut active: Vec<[u8; 32]> = keys.iter().map(|k| xonly(k)).collect();
    active.sort();
    let mut a = [ZERO32; 10];
    for (i, k) in active.iter().enumerate() {
        a[i] = *k;
    }
    a
}
/// Place each signer's (keypair, sighash) in the slot whose sorted key
/// matches it, so signatures align with the covenant's sorted layout.
fn approvals_by_key<'a>(slots: &[[u8; 32]; 10], signers: &[(&'a Keypair, SigHashType)]) -> [Option<(&'a Keypair, SigHashType)>; 10] {
    let mut ap: [Option<(&'a Keypair, SigHashType)>; 10] = Default::default();
    for i in 0..10 {
        for (s, ty) in signers {
            if xonly(s) == slots[i] {
                ap[i] = Some((*s, *ty));
            }
        }
    }
    ap
}
fn recipients8(target_pk: &[u8; 32]) -> ([u8; 32], Vec<u8>, u64) {
    let mut leaves: Vec<[u8; 32]> = (0..8).map(|i| sha256(&[&LEAF_DOMAIN, &(i as u64).to_le_bytes()])).collect();
    leaves[5] = leaf(target_pk);
    merkle(&leaves, 5)
}

// ========================================================= VALID PATHS

#[test]
fn v3_delegate_spend_below_threshold_valid() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let prev = base_state(&delegate, root, [ZERO32; 10], 1, 50 * KAS); // no approvers; threshold 50
    let pay = 40 * KAS; // below threshold -> delegate only
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert!(r.is_ok(), "valid below-threshold spend must pass: {r:?}");
}

#[test]
fn v3_approved_spend_2of3_valid() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let prev = base_state(&delegate, root, slots, 2, 50 * KAS);
    let pay = 150 * KAS; // above threshold -> needs 2-of-3
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let approvers = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)]);
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers,
    });
    assert!(r.is_ok(), "valid 2-of-3 approved spend must pass: {r:?}");
}

// ========================================================= NEGATIVES

fn approved_spend_variant(mutate: impl FnOnce(&mut Spend)) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let prev = base_state(&delegate, root, slots, 2, 50 * KAS);
    let pay = 150 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let approvers = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)]);
    let mut sp = Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers,
    };
    // keypairs must outlive the call; mutate operates on borrowed refs held above
    mutate(&mut sp);
    run_delegate_spend(&owner, sp)
}

#[test]
fn v3_over_cap_rejected() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let prev = base_state(&delegate, root, [ZERO32; 10], 1, 10_000 * KAS); // threshold high so no approvals needed
    let pay = prev.max_per_spend + KAS; // over cap
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert_rejected(r, "over-cap spend");
}

#[test]
fn v3_wrong_recipient_rejected() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let recipient = deterministic_keypair(40);
    let other = deterministic_keypair(41);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let prev = base_state(&delegate, root, [ZERO32; 10], 1, 10_000 * KAS);
    let pay = 40 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    // prove `recipient` but pay `other`
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&other),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert_rejected(r, "leaf/output substitution");
}

#[test]
fn v3_insufficient_approvals_rejected() {
    // Provide only ONE valid approval where M = 2.
    let r = approved_spend_variant(|sp| {
        let mut seen = false;
        for slot in sp.approvers.iter_mut() {
            if slot.is_some() {
                if seen {
                    *slot = None; // keep only the first signed slot
                } else {
                    seen = true;
                }
            }
        }
    });
    assert_rejected(r, "insufficient approvals");
}

#[test]
fn v3_sighash_none_approval_rejected_production() {
    // A7 on the PRODUCTION covenant: a SIG_HASH_NONE approval must be
    // rejected by the covenant's sighash gate.
    let r = approved_spend_variant(|_sp| {});
    assert!(r.is_ok(), "control: all-ALL approvals pass");
    // Now flip one approval to SIG_HASH_NONE by rebuilding with that type.
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let prev = base_state(&delegate, root, slots, 2, 50 * KAS);
    let pay = 150 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    // a1 signs SIG_HASH_NONE (wrong), a2 signs ALL — each in its sorted slot.
    let approvers = approvals_by_key(&slots, &[(&a1, SIG_HASH_NONE), (&a2, SIG_HASH_ALL)]);
    let r2 = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers,
    });
    assert_rejected(r2, "SIG_HASH_NONE approval must be rejected by the production A7 gate");
}

// ========================================================= OWNER PATHS

#[test]
fn v3_owner_pause_valid_and_accounting_preserved() {
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let prev = { let mut s = base_state(&delegate, [0x44u8;32], [ZERO32;10], 1, 50*KAS); s.period_spent = 5*KAS; s };
    let succ = V3 { paused: 1, ..prev.clone() };
    assert!(run_owner_op(&owner_kp, "ownerPause", &prev, &succ).is_ok(), "valid pause");
    // pause that resets period_spent must be rejected
    let bad = V3 { paused: 1, period_spent: 0, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerPause", &prev, &bad), "pause cannot reset accounting");
}

#[test]
fn v3_rotate_delegate_cannot_reset_accounting() {
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let new_delegate = deterministic_keypair(7);
    let prev = { let mut s = base_state(&delegate, [0x44u8;32], [ZERO32;10], 1, 50*KAS); s.period_spent = 5*KAS; s };
    let succ = V3 { delegate: xonly(&new_delegate), delegate_active: 1, ..prev.clone() };
    assert!(run_owner_op(&owner_kp, "rotateDelegate", &prev, &succ).is_ok(), "valid rotate");
    let bad = V3 { delegate: xonly(&new_delegate), delegate_active: 1, period_spent: 0, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "rotateDelegate", &prev, &bad), "rotate cannot reset accounting");
}

#[test]
fn v3_migrate_policy_cannot_reset_period_spent() {
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let prev = { let mut s = base_state(&delegate, [0x44u8;32], [ZERO32;10], 1, 50*KAS); s.period_spent = 5*KAS; s };
    let good = V3 { max_per_spend: 300*KAS, policy_nonce: prev.policy_nonce + 1, ..prev.clone() };
    assert!(run_owner_op(&owner_kp, "migratePolicy", &prev, &good).is_ok(), "valid migrate");
    let bad = V3 { max_per_spend: 300*KAS, policy_nonce: prev.policy_nonce + 1, period_spent: 0, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "migratePolicy", &prev, &bad), "migrate cannot reset periodSpent");
    let no_nonce = V3 { max_per_spend: 300*KAS, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "migratePolicy", &prev, &no_nonce), "migrate must bump nonce");
}

#[test]
fn v3_owner_set_approvers_valid_and_duplicate_rejected_production() {
    // A2 on the PRODUCTION covenant.
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let prev = base_state(&delegate, [0x44u8;32], [ZERO32;10], 1, 50*KAS);
    // valid: 3 distinct approvers, M=2
    let good = V3 { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 2, policy_nonce: prev.policy_nonce + 1, ..prev.clone() };
    assert!(run_owner_op(&owner_kp, "ownerSetApprovers", &prev, &good).is_ok(), "valid setApprovers");
    // duplicate key a1 in two slots -> rejected
    let dup = V3 { approvers: approver_set(&[&a1, &a1, &a3]), approval_m: 2, policy_nonce: prev.policy_nonce + 1, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerSetApprovers", &prev, &dup), "duplicate approver key must be rejected");
    // M > active count -> rejected
    let bad_m = V3 { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 4, policy_nonce: prev.policy_nonce + 1, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerSetApprovers", &prev, &bad_m), "M>active must be rejected");
    // M < 1 -> rejected
    let zero_m = V3 { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 0, policy_nonce: prev.policy_nonce + 1, ..prev.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerSetApprovers", &prev, &zero_m), "M<1 must be rejected");
}

#[test]
fn v3_owner_recover_terminal_valid() {
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let prev = base_state(&delegate, [0x44u8;32], [ZERO32;10], 1, 50*KAS);
    let active = compile_state(&xonly(&owner_kp), &prev);
    let outputs = vec![p2pk_output(&xonly(&owner_kp), prev.protected_value as u64)];
    let tx = Transaction::new(1, vec![covenant_input()], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, prev.protected_value as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, &owner_kp, SIG_HASH_ALL);
    let args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl("ownerRecover", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    assert!(execute_input_measured(t, vec![utxo], 0).0.is_ok(), "valid terminal recover");
}

// ========================================================= 4E/4F EXPANSION

/// Build a tree of `1<<depth` leaves and prove a real recipient at index 1.
fn tree_at_depth(depth: u32, target_pk: &[u8; 32]) -> ([u8; 32], Vec<u8>, u64) {
    let n = 1usize << depth;
    let mut leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&LEAF_DOMAIN, &(i as u64).to_le_bytes()])).collect();
    if depth == 0 {
        return (leaf(target_pk), vec![], 0);
    }
    leaves[1] = leaf(target_pk);
    merkle(&leaves, 1)
}

#[test]
fn v3_recipient_depth_matrix_valid() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let recipient = deterministic_keypair(40);
    for depth in [0u32, 1, 4, 8, 12, 16] {
        let (root, sibs, bits) = tree_at_depth(depth, &xonly(&recipient));
        let prev = base_state(&delegate, root, [ZERO32; 10], 1, 500 * KAS); // threshold high -> delegate only
        let pay = 40 * KAS;
        let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
        let r = run_delegate_spend(&owner, Spend {
            prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
            siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
        });
        assert!(r.is_ok(), "depth {depth} valid spend must pass: {r:?}");
    }
}

#[test]
fn v3_threshold_boundary() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let threshold = 50 * KAS;
    let base = base_state(&delegate, root, approver_set(&[&a1, &a2, &a3]), 2, threshold);

    // amount == threshold -> delegate only (no approvals), passes with none
    let pay = threshold;
    let succ = V3 { protected_value: base.protected_value - pay, period_spent: base.period_spent + pay, ..base.clone() };
    let r = run_delegate_spend(&owner, Spend {
        prev: base.clone(), succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs.clone(), path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert!(r.is_ok(), "amount == threshold must be delegate-only: {r:?}");

    // amount == threshold + 1 with NO approvals -> rejected
    let pay2 = threshold + 1;
    let succ2 = V3 { protected_value: base.protected_value - pay2, period_spent: base.period_spent + pay2, ..base.clone() };
    let r2 = run_delegate_spend(&owner, Spend {
        prev: base, succ: succ2, pay: pay2, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert_rejected(r2, "amount just above threshold with no approvals");
}

#[test]
fn v3_approvals_10_of_10() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let keys: Vec<Keypair> = (0..10).map(|i| deterministic_keypair(60 + i)).collect();
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let refs: Vec<&Keypair> = keys.iter().collect();
    let slots = approver_set(&refs);
    let prev = base_state(&delegate, root, slots, 10, 50 * KAS); // N=10, M=10
    let pay = 150 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let signers: Vec<(&Keypair, SigHashType)> = keys.iter().map(|k| (k, SIG_HASH_ALL)).collect();
    let ap = approvals_by_key(&slots, &signers);
    let (r, units) = {
        // measure this worst-case shape
        let active = compile_state(&owner, &prev);
        let succ_c = compile_state(&owner, &succ);
        let outputs = vec![p2pk_output(&xonly(&recipient), pay as u64), successor_output(&succ_c, succ.protected_value as u64)];
        let tx = Transaction::new(1, vec![covenant_input()], outputs, 0, Default::default(), 0, vec![]);
        let utxo = active_utxo(&active, prev.protected_value as u64);
        let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
        let dsig = sign_typed(&mutable, &delegate, SIG_HASH_ALL);
        let blob = approvals_blob(&mutable, &ap);
        let args = vec![state_arg(&succ), Expr::int(pay), Expr::bytes(xonly(&recipient).to_vec()), Expr::bytes(sibs.clone()), Expr::int(bits as i64), Expr::bytes(dsig), Expr::bytes(blob)];
        let mut ss = active.build_sig_script_for_covenant_decl("delegateSpend", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
        ss.extend_from_slice(&push_redeem_script(&active.script));
        let mut t = mutable.tx;
        t.inputs[0].signature_script = ss;
        execute_input_measured(t, vec![utxo], 0)
    };
    assert!(r.is_ok(), "10-of-10 approved spend must pass: {r:?}");
    println!("v3 10-of-10 approved spend compute script_units={units}");
}

#[test]
fn v3_all_nonstandard_approver_sighash_types_rejected() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let variants = [
        ("NONE", SIG_HASH_NONE),
        ("SINGLE", SIG_HASH_SINGLE),
        ("ALL|ACP", SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY),
        ("NONE|ACP", SIG_HASH_NONE | SIG_HASH_ANY_ONE_CAN_PAY),
        ("SINGLE|ACP", SIG_HASH_SINGLE | SIG_HASH_ANY_ONE_CAN_PAY),
    ];
    for (name, ty) in variants {
        let (root, sibs, bits) = recipients8(&xonly(&recipient));
        let slots = approver_set(&[&a1, &a2, &a3]);
        let prev = base_state(&delegate, root, slots, 2, 50 * KAS);
        let pay = 150 * KAS;
        let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
        // a1 signs the non-ALL sighash, a2 signs ALL — placed in sorted slots.
        let ap = approvals_by_key(&slots, &[(&a1, ty), (&a2, SIG_HASH_ALL)]);
        let r = run_delegate_spend(&owner, Spend {
            prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
            siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: ap,
        });
        assert_rejected(r, &format!("approver sighash {name} must be rejected by the A7 gate"));
    }
}

#[test]
fn v3_recipient_negatives_root_and_foreign_tree() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    // modified root in state
    let mut bad_root = root;
    bad_root[0] ^= 0x01;
    let prev = base_state(&delegate, bad_root, [ZERO32; 10], 1, 500 * KAS);
    let pay = 40 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert_rejected(r, "proof against a modified root");
}

#[test]
fn v3_state_negatives_unauthorized_transitions() {
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let base = base_state(&delegate, [0x44u8; 32], [ZERO32; 10], 1, 50 * KAS);

    // unpause when not paused (unauthorized state) -> rejected
    let bogus_unpause = V3 { paused: 0, ..base.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerUnpause", &base, &bogus_unpause), "unpause of an active vault");

    // revoke that also reactivates something / forged protectedValue -> rejected
    let forged = V3 { delegate_active: 0, protected_value: base.protected_value + KAS, ..base.clone() };
    assert_rejected(run_owner_op(&owner_kp, "revokeDelegate", &base, &forged), "revoke forging protectedValue");

    // setRecipientRoot without nonce bump -> rejected
    let no_nonce = V3 { recipient_root: [0x55u8; 32], ..base.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerSetRecipientRoot", &base, &no_nonce), "setRecipientRoot must bump nonce");

    // setApprovers resetting accounting -> rejected
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let base2 = { let mut s = base.clone(); s.period_spent = 5 * KAS; s };
    let reset = V3 { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 2, policy_nonce: base2.policy_nonce + 1, period_spent: 0, ..base2.clone() };
    assert_rejected(run_owner_op(&owner_kp, "ownerSetApprovers", &base2, &reset), "setApprovers must not reset accounting");
}

// ================================================= PHASE 4.5 SECURITY REVIEW

/// FALSIFICATION (review item 1): the spend path counts approvals against
/// prevState approver slots but never re-checks that the predecessor set is
/// well-formed. Genesis state is NOT covenant-validated. A predecessor with
/// a DUPLICATE active approver key (K in slots 1 and 2) lets ONE signer K
/// satisfy M=2 on an above-threshold spend. This test DEMONSTRATES the gap;
/// after the fix it must be REJECTED.
#[test]
fn v3_REVIEW_malformed_genesis_duplicate_predecessor_key() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let k = deterministic_keypair(20); // one real approver, placed in TWO slots
    let a3 = deterministic_keypair(22);
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    // Malformed predecessor: approver1 == approver2 == K, M = 2, low threshold.
    let mut approvers = [ZERO32; 10];
    approvers[0] = xonly(&k);
    approvers[1] = xonly(&k);
    approvers[2] = xonly(&a3);
    let prev = base_state(&delegate, root, approvers, 2, 50 * KAS);
    let pay = 150 * KAS; // above threshold -> needs M=2
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    // K signs BOTH slot 0 and slot 1 (its key matches both). Only ONE approver.
    let mut ap: [Option<(&Keypair, SigHashType)>; 10] = Default::default();
    ap[0] = Some((&k, SIG_HASH_ALL));
    ap[1] = Some((&k, SIG_HASH_ALL));
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: ap,
    });
    // After the fix, a duplicate predecessor approver set must be rejected
    // on the spend path (requireApprovals asserts A2 + M validity).
    assert_rejected(r, "duplicate predecessor approver keys must not let one signer satisfy M");
}

/// FALSIFICATION (review item 1): a malformed genesis with approvalM=0 and
/// active approvers + a low threshold would let an above-threshold spend
/// proceed with ZERO approvals (count >= 0 is always true). The spend path
/// must reject an above-threshold spend when the predecessor M < 1.
#[test]
fn v3_REVIEW_malformed_genesis_zero_M_above_threshold() {
    let owner = xonly(&deterministic_keypair(1));
    let delegate = deterministic_keypair(2);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    // Malformed: active approvers but approvalM = 0, threshold low.
    let prev = base_state(&delegate, root, approver_set(&[&a1, &a2, &a3]), 0, 50 * KAS);
    let pay = 150 * KAS; // above threshold
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    // Provide NO approvals (all placeholders).
    let r = run_delegate_spend(&owner, Spend {
        prev, succ, pay, recipient_pk: xonly(&recipient), recipient_output: xonly(&recipient),
        siblings: sibs, path_bits: bits, delegate: &delegate, delegate_sighash: SIG_HASH_ALL, approvers: Default::default(),
    });
    assert_rejected(r, "above-threshold spend with predecessor M=0 must be rejected");
}

/// REVIEW item 15 (no trapped funds): ownerRecover must close the vault
/// from ANY reachable state, including a malformed-genesis state (duplicate
/// approvers, M=0) that blocks approved spends. It depends only on the owner
/// signature, never on approver/recipient well-formedness.
#[test]
fn v3_REVIEW_recover_from_malformed_state() {
    let owner_kp = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let k = deterministic_keypair(20);
    // Malformed: duplicate approver key, M=0, low threshold, paused, revoked.
    let mut approvers = [ZERO32; 10];
    approvers[0] = xonly(&k);
    approvers[1] = xonly(&k);
    let prev = V3 { paused: 1, delegate_active: 0, ..base_state(&delegate, [0x44u8; 32], approvers, 0, 1) };
    let active = compile_state(&xonly(&owner_kp), &prev);
    let outputs = vec![p2pk_output(&xonly(&owner_kp), prev.protected_value as u64)];
    let tx = Transaction::new(1, vec![covenant_input()], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, prev.protected_value as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, &owner_kp, SIG_HASH_ALL);
    let args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl("ownerRecover", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    assert!(execute_input_measured(t, vec![utxo], 0).0.is_ok(), "ownerRecover must work from a malformed/paused/revoked state — funds never trapped");
}
