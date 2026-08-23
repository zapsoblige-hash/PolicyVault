//! VM layer — v0.3 PRODUCTION-BYTE integration (4D). The consensus-visible
//! bytes for every v0.3 entrypoint are produced by the REAL
//! `pv_call_encoder` binary (exact-live-state source + constructor-args +
//! call.json, exactly as the SDK will drive it), then executed on the real
//! TxScriptEngine. It never uses the in-process library encoder — that is
//! the blind spot that let the v0.2 boundVaultId defect ship.
//!
//! Plus a mutation matrix: feeding the production encoder a mutated intent
//! (wrong recipient/proof/path/nonce/successor, a SIG_HASH_NONE approval, a
//! swapped approval slot, a wrong contract version, a terminal/shape
//! mismatch) MUST be rejected by consensus.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use policyvault_vm_tests::*;
use secp256k1::Keypair;
use sha2::{Digest, Sha256};

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL, SIG_HASH_NONE};
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript_errors::TxScriptError;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

const KAS: i64 = 100_000_000;
const VAULT_ID_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const LEAF_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];

fn encoder_path() -> PathBuf {
    PathBuf::from(format!("{}/policyvault/tests/vm/target/debug/pv_call_encoder", std::env::var("HOME").unwrap()))
}
fn hexs(b: &[u8]) -> String {
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
fn recipients8(target_pk: &[u8; 32]) -> ([u8; 32], Vec<u8>, u64) {
    let mut leaves: Vec<[u8; 32]> = (0..8).map(|i| sha256(&[&LEAF_DOMAIN, &(i as u64).to_le_bytes()])).collect();
    leaves[5] = leaf(target_pk);
    merkle(&leaves, 5)
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
        period_start_daa: 542_000_000,
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

const APPROVER_NAMES: [&str; 10] = ["approver1","approver2","approver3","approver4","approver5","approver6","approver7","approver8","approver9","approver10"];

fn templated_source(s: &V3) -> String {
    let path = format!("{}/policyvault/contracts/PolicyVault.v0.3.sil", std::env::var("HOME").unwrap());
    let mut src = std::fs::read_to_string(&path).unwrap();
    let mut r = |from: String, to: String| {
        assert!(src.contains(&from), "anchor missing: {from}");
        src = src.replacen(&from, &to, 1);
    };
    r("int protectedValue = initValue;".into(), format!("int protectedValue = {};", s.protected_value));
    r("int periodStartDaa = initPeriodStartDaa;".into(), format!("int periodStartDaa = {};", s.period_start_daa));
    r("int periodSpent = 0;".into(), format!("int periodSpent = {};", s.period_spent));
    r("int paused = 0;".into(), format!("int paused = {};", s.paused));
    r("pubkey delegate = initDelegate;".into(), format!("pubkey delegate = 0x{};", hexs(&s.delegate)));
    r("int delegateActive = 1;".into(), format!("int delegateActive = {};", s.delegate_active));
    r("int maxPerSpend = initMaxPerSpend;".into(), format!("int maxPerSpend = {};", s.max_per_spend));
    r("int periodBudget = initPeriodBudget;".into(), format!("int periodBudget = {};", s.period_budget));
    r("int periodLengthDaa = initPeriodLengthDaa;".into(), format!("int periodLengthDaa = {};", s.period_length_daa));
    r("byte[32] recipientRoot = initRecipientRoot;".into(), format!("byte[32] recipientRoot = 0x{};", hexs(&s.recipient_root)));
    for i in 0..10 {
        r(format!("pubkey approver{} = initApprover{};", i + 1, i + 1), format!("pubkey approver{} = 0x{};", i + 1, hexs(&s.approvers[i])));
    }
    r("int approvalM = initApprovalM;".into(), format!("int approvalM = {};", s.approval_m));
    r("int approvalThresholdAmount = initApprovalThresholdAmount;".into(), format!("int approvalThresholdAmount = {};", s.approval_threshold));
    r("int policyNonce = 0;".into(), format!("int policyNonce = {};", s.policy_nonce));
    src
}

fn ctor_args_json(owner: &[u8; 32], s: &V3) -> String {
    let pk = |b: &[u8]| serde_json::json!({ "kind": "array", "data": b.iter().map(|x| serde_json::json!({"kind":"byte","data":*x})).collect::<Vec<_>>() });
    let int = |v: i64| serde_json::json!({ "kind": "int", "data": v });
    let vault_id: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&VAULT_ID_HEX[i * 2..i * 2 + 2], 16).unwrap()).collect();
    let mut a = vec![pk(owner), pk(&vault_id), pk(&s.delegate), int(s.max_per_spend), int(s.period_budget), int(s.period_length_daa), pk(&s.recipient_root)];
    for i in 0..10 {
        a.push(pk(&s.approvers[i]));
    }
    a.push(int(s.approval_m));
    a.push(int(s.approval_threshold));
    a.push(int(s.protected_value));
    a.push(int(s.period_start_daa));
    serde_json::to_string_pretty(&serde_json::Value::Array(a)).unwrap()
}

fn successor_json(s: &V3) -> serde_json::Value {
    let mut o = serde_json::json!({
        "protectedValue": s.protected_value.to_string(),
        "periodStartDaa": s.period_start_daa.to_string(),
        "periodSpent": s.period_spent.to_string(),
        "paused": s.paused,
        "delegate": hexs(&s.delegate),
        "delegateActive": s.delegate_active,
        "maxPerSpend": s.max_per_spend.to_string(),
        "periodBudget": s.period_budget.to_string(),
        "periodLengthDaa": s.period_length_daa.to_string(),
        "recipientRoot": hexs(&s.recipient_root),
        "approvalM": s.approval_m.to_string(),
        "approvalThresholdAmount": s.approval_threshold.to_string(),
        "policyNonce": s.policy_nonce.to_string(),
    });
    for i in 0..10 {
        o[APPROVER_NAMES[i]] = serde_json::json!(hexs(&s.approvers[i]));
    }
    o
}

fn ctor_exprs(owner: &[u8; 32], s: &V3) -> Vec<Expr<'static>> {
    let mut a = vec![
        Expr::bytes(owner.to_vec()),
        Expr::bytes((0..32).map(|i| u8::from_str_radix(&VAULT_ID_HEX[i * 2..i * 2 + 2], 16).unwrap()).collect()),
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
    compile_contract(src, &ctor_exprs(owner, s), CompileOptions::default()).expect("v0.3 compile")
}

fn sign_input_typed(m: &MutableTransaction<Transaction>, idx: usize, kp: &Keypair, ty: SigHashType) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&m.as_verifiable(), idx, ty, &reused);
    let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap();
    let mut out = kp.sign_schnorr(msg).as_ref().to_vec();
    out.push(ty.to_u8());
    out
}
fn placeholder() -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p.push(0x01);
    p
}

/// Fuel/change scaffolding shared by all cases.
fn fuel_input() -> (TransactionInput, [u8; 32]) {
    let fuel_pk = xonly(&deterministic_keypair(90));
    (
        TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x43; 32]), index: 1 },
            signature_script: vec![],
            sequence: 0,
            compute_commit: ComputeBudget(10).into(),
        },
        fuel_pk,
    )
}
fn cov_input() -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeBudget(200).into(),
    }
}

/// Encode via the REAL pv_call_encoder binary and return the call-portion bytes.
fn encode_via_binary(owner: &[u8; 32], prev: &V3, call: &serde_json::Value) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir().join(format!("pv3enc-{}-{}", std::process::id(), rand_suffix()));
    fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("PolicyVault.state.sil");
    let args_path = dir.join("constructor-args.json");
    let call_path = dir.join("call.json");
    fs::write(&source_path, templated_source(prev)).unwrap();
    fs::write(&args_path, ctor_args_json(owner, prev)).unwrap();
    fs::write(&call_path, serde_json::to_string(call).unwrap()).unwrap();
    let out = Command::new(encoder_path()).arg(&source_path).arg(&args_path).arg(&call_path).output().expect("run encoder");
    let _ = fs::remove_dir_all(&dir);
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let hex = String::from_utf8(out.stdout).unwrap().trim().to_string();
    Ok((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect())
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
}

/// A delegate spend built + signed + encoded via the production binary and
/// executed on the VM. `approver_sigs[i]` = Some((kp,type)) signs slot i.
#[allow(clippy::too_many_arguments)]
fn run_delegate_spend(
    owner_kp: &Keypair,
    prev: &V3,
    succ: &V3,
    pay: i64,
    recipient_leaf_pk: &[u8; 32],
    recipient_output_pk: &[u8; 32],
    siblings: &[u8],
    path_bits: u64,
    delegate: &Keypair,
    delegate_type: SigHashType,
    approver_sigs: &[Option<(&Keypair, SigHashType)>; 10],
    mutate_call: impl FnOnce(&mut serde_json::Value),
) -> Result<(), TxScriptError> {
    let owner = xonly(owner_kp);
    let active = compile_state(&owner, prev);
    let succ_c = compile_state(&owner, succ);
    let (fin, fuel_pk) = fuel_input();
    let fuel_value = 10 * KAS as u64;
    let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
    let outputs = vec![
        p2pk_output(recipient_output_pk, pay as u64),
        TransactionOutput {
            value: succ.protected_value as u64,
            script_public_key: pay_to_script_hash_script(&succ_c.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
        TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None },
    ];
    let tx = Transaction::new(1, vec![cov_input(), fin], outputs, 0, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, prev.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);

    let dsig = sign_input_typed(&mutable, 0, delegate, delegate_type);
    let mut blob = Vec::with_capacity(650);
    for slot in approver_sigs.iter() {
        match slot {
            Some((kp, ty)) => blob.extend_from_slice(&sign_input_typed(&mutable, 0, kp, *ty)),
            None => blob.extend_from_slice(&placeholder()),
        }
    }
    let mut call = serde_json::json!({
        "contractVersion": "policyvault-0.3",
        "function": "delegateSpend",
        "signature": hexs(&dsig),
        "successor": successor_json(succ),
        "payAmount": pay.to_string(),
        "recipientPk": hexs(recipient_leaf_pk),
        "siblings": hexs(siblings),
        "pathBits": path_bits,
        "approvals": hexs(&blob),
    });
    mutate_call(&mut call);
    let call_bytes = match encode_via_binary(&owner, prev, &call) {
        Ok(b) => b,
        Err(_e) => return Err(TxScriptError::VerifyError), // encoder fail-closed == rejection
    };
    let mut sigscript = call_bytes;
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;
    execute_input_with_covenants(mutable.tx, vec![cov_utxo, fuel_utxo], 0)
}

/// An owner op via the production binary.
fn run_owner_op(owner_kp: &Keypair, func: &str, prev: &V3, succ: Option<&V3>, recover: bool) -> Result<(), TxScriptError> {
    let owner = xonly(owner_kp);
    let active = compile_state(&owner, prev);
    let (fin, fuel_pk) = fuel_input();
    let fuel_value = 10 * KAS as u64;
    let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
    let mut outputs = Vec::new();
    if recover {
        outputs.push(p2pk_output(&owner, prev.protected_value as u64));
    } else {
        let s = succ.unwrap();
        let succ_c = compile_state(&owner, s);
        outputs.push(TransactionOutput {
            value: s.protected_value as u64,
            script_public_key: pay_to_script_hash_script(&succ_c.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        });
    }
    outputs.push(TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None });
    let tx = Transaction::new(1, vec![cov_input(), fin], outputs, 0, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, prev.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
    let osig = sign_input_typed(&mutable, 0, owner_kp, SIG_HASH_ALL);
    let mut call = serde_json::json!({ "contractVersion": "policyvault-0.3", "function": func, "signature": hexs(&osig) });
    if !recover {
        call["successor"] = successor_json(succ.unwrap());
    }
    let call_bytes = match encode_via_binary(&owner, prev, &call) {
        Ok(b) => b,
        Err(_e) => return Err(TxScriptError::VerifyError),
    };
    let mut sigscript = call_bytes;
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;
    execute_input_with_covenants(mutable.tx, vec![cov_utxo, fuel_utxo], 0)
}

// -------- fixtures --------
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
fn actors() -> (Keypair, Keypair, Keypair, Keypair, Keypair, Keypair) {
    (deterministic_keypair(1), deterministic_keypair(2), deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22), deterministic_keypair(40))
}
/// Align each signer's (keypair, sighash) to the slot holding its sorted key.
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

// ================================================= ENCODER-BACKED VALID PATHS

#[test]
fn enc3_delegate_spend_below_threshold() {
    let (owner, delegate, _a1, _a2, _a3, recipient) = actors();
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let prev = base_state(&delegate, root, [ZERO32; 10], 1, 50 * KAS);
    let pay = 40 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let r = run_delegate_spend(&owner, &prev, &succ, pay, &xonly(&recipient), &xonly(&recipient), &sibs, bits, &delegate, SIG_HASH_ALL, &Default::default(), |_| {});
    assert!(r.is_ok(), "encoder-backed below-threshold spend: {r:?}");
}

#[test]
fn enc3_approved_spend_2of3() {
    let (owner, delegate, a1, a2, a3, recipient) = actors();
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let prev = base_state(&delegate, root, slots, 2, 50 * KAS);
    let pay = 150 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)]);
    let r = run_delegate_spend(&owner, &prev, &succ, pay, &xonly(&recipient), &xonly(&recipient), &sibs, bits, &delegate, SIG_HASH_ALL, &ap, |_| {});
    assert!(r.is_ok(), "encoder-backed 2-of-3 approved spend: {r:?}");
}

#[test]
fn enc3_owner_paths_and_recover() {
    let (owner, delegate, a1, a2, a3, _r) = actors();
    let prev = base_state(&delegate, [0x44u8; 32], [ZERO32; 10], 1, 50 * KAS);
    // pause
    let paused = V3 { paused: 1, ..prev.clone() };
    assert!(run_owner_op(&owner, "ownerPause", &prev, Some(&paused), false).is_ok(), "enc ownerPause");
    // unpause
    assert!(run_owner_op(&owner, "ownerUnpause", &paused, Some(&prev), false).is_ok(), "enc ownerUnpause");
    // revoke
    let revoked = V3 { delegate_active: 0, ..prev.clone() };
    assert!(run_owner_op(&owner, "revokeDelegate", &prev, Some(&revoked), false).is_ok(), "enc revoke");
    // rotate
    let rotated = V3 { delegate: xonly(&deterministic_keypair(7)), delegate_active: 1, ..prev.clone() };
    assert!(run_owner_op(&owner, "rotateDelegate", &prev, Some(&rotated), false).is_ok(), "enc rotate");
    // topup
    let topped = V3 { protected_value: prev.protected_value + 100 * KAS, ..prev.clone() };
    assert!(run_owner_op(&owner, "ownerTopUp", &prev, Some(&topped), false).is_ok(), "enc topup");
    // migrate
    let migrated = V3 { max_per_spend: 300 * KAS, policy_nonce: 1, ..prev.clone() };
    assert!(run_owner_op(&owner, "migratePolicy", &prev, Some(&migrated), false).is_ok(), "enc migrate");
    // set recipient root
    let new_root = V3 { recipient_root: [0x55u8; 32], policy_nonce: 1, ..prev.clone() };
    assert!(run_owner_op(&owner, "ownerSetRecipientRoot", &prev, Some(&new_root), false).is_ok(), "enc setRecipientRoot");
    // set approvers
    let new_ap = V3 { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 2, policy_nonce: 1, ..prev.clone() };
    assert!(run_owner_op(&owner, "ownerSetApprovers", &prev, Some(&new_ap), false).is_ok(), "enc setApprovers");
    // recover
    assert!(run_owner_op(&owner, "ownerRecover", &prev, None, true).is_ok(), "enc recover");
}

#[test]
fn enc3_rollover_and_spend() {
    let (owner, delegate, _a1, _a2, _a3, recipient) = actors();
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let mut prev = base_state(&delegate, root, [ZERO32; 10], 1, 50 * KAS);
    prev.period_spent = 700 * KAS;
    let pay = 40 * KAS;
    let periods = 2i64;
    let new_start = prev.period_start_daa + periods * prev.period_length_daa;
    let succ = V3 { protected_value: prev.protected_value - pay, period_start_daa: new_start, period_spent: pay, ..prev.clone() };
    // rollover uses lock_time; rebuild via a direct call (run_delegate_spend uses lock_time 0),
    // so encode+execute here with the correct lock_time.
    let owner_pk = xonly(&owner);
    let active = compile_state(&owner_pk, &prev);
    let succ_c = compile_state(&owner_pk, &succ);
    let (fin, fuel_pk) = fuel_input();
    let fuel_value = 10 * KAS as u64;
    let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
    let outputs = vec![
        p2pk_output(&xonly(&recipient), pay as u64),
        TransactionOutput { value: succ.protected_value as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
        TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None },
    ];
    let tx = Transaction::new(1, vec![cov_input(), fin], outputs, new_start as u64, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, prev.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
    let dsig = sign_input_typed(&mutable, 0, &delegate, SIG_HASH_ALL);
    let call = serde_json::json!({
        "contractVersion": "policyvault-0.3", "function": "rolloverAndSpend", "signature": hexs(&dsig),
        "successor": successor_json(&succ), "payAmount": pay.to_string(), "recipientPk": hexs(&xonly(&recipient)),
        "siblings": hexs(&sibs), "pathBits": bits, "periodsElapsed": periods.to_string(), "approvals": hexs(&vec![0u8;650].iter().enumerate().map(|(i,_)| if i%65==64 {1} else {0}).collect::<Vec<u8>>()),
    });
    let call_bytes = encode_via_binary(&owner_pk, &prev, &call).expect("encode rollover");
    let mut sigscript = call_bytes;
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;
    assert!(execute_input_with_covenants(mutable.tx, vec![cov_utxo, fuel_utxo], 0).is_ok(), "enc rolloverAndSpend");
}

// ================================================= MUTATION MATRIX (4D)

/// Base approved-spend variant with an optional call.json mutation.
fn approved_variant(mutate: impl FnOnce(&mut serde_json::Value), swap_slot_sigs: bool, none_slot0: bool) -> Result<(), TxScriptError> {
    let (owner, delegate, a1, a2, a3, recipient) = actors();
    let (root, sibs, bits) = recipients8(&xonly(&recipient));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let prev = base_state(&delegate, root, slots, 2, 50 * KAS);
    let pay = 150 * KAS;
    let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
    let ap = if none_slot0 {
        // a1 signs SIG_HASH_NONE (wrong), a2 signs ALL — aligned to sorted slots.
        approvals_by_key(&slots, &[(&a1, SIG_HASH_NONE), (&a2, SIG_HASH_ALL)])
    } else if swap_slot_sigs {
        // Deliberately misalign: a2's sig where a1's key sits and vice-versa,
        // so each checkSig fails and the count falls short.
        let mut m: [Option<(&Keypair, SigHashType)>; 10] = Default::default();
        for i in 0..10 {
            if slots[i] == xonly(&a1) { m[i] = Some((&a2, SIG_HASH_ALL)); }
            if slots[i] == xonly(&a2) { m[i] = Some((&a1, SIG_HASH_ALL)); }
        }
        m
    } else {
        approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)])
    };
    run_delegate_spend(&owner, &prev, &succ, pay, &xonly(&recipient), &xonly(&recipient), &sibs, bits, &delegate, SIG_HASH_ALL, &ap, mutate)
}

#[test]
fn enc3_mut_control_passes() {
    assert!(approved_variant(|_| {}, false, false).is_ok(), "control approved spend must pass");
}

#[test]
fn enc3_mut_wrong_path_bits() {
    assert_rejected(approved_variant(|c| { c["pathBits"] = serde_json::json!(c["pathBits"].as_u64().unwrap() ^ 1); }, false, false), "mutated pathBits");
}

#[test]
fn enc3_mut_reordered_siblings() {
    assert_rejected(approved_variant(|c| {
        let s = c["siblings"].as_str().unwrap().to_string();
        // swap first two 32-byte (64-hex) siblings
        if s.len() >= 128 {
            let reordered = format!("{}{}{}", &s[64..128], &s[0..64], &s[128..]);
            c["siblings"] = serde_json::json!(reordered);
        }
    }, false, false), "reordered siblings");
}

#[test]
fn enc3_mut_truncated_proof_depth() {
    assert_rejected(approved_variant(|c| {
        let s = c["siblings"].as_str().unwrap().to_string();
        c["siblings"] = serde_json::json!(s[..s.len() - 64].to_string()); // drop one sibling
    }, false, false), "truncated proof depth");
}

#[test]
fn enc3_mut_wrong_recipient() {
    assert_rejected(approved_variant(|c| { c["recipientPk"] = serde_json::json!(hexs(&xonly(&deterministic_keypair(99)))); }, false, false), "wrong recipient pk");
}

#[test]
fn enc3_mut_successor_nonce_bumped() {
    assert_rejected(approved_variant(|c| { c["successor"]["policyNonce"] = serde_json::json!("1"); }, false, false), "spend must not change policyNonce");
}

#[test]
fn enc3_mut_successor_protected_value() {
    assert_rejected(approved_variant(|c| { c["successor"]["protectedValue"] = serde_json::json!((999 * KAS).to_string()); }, false, false), "forged successor protectedValue");
}

#[test]
fn enc3_mut_approval_sighash_none() {
    assert_rejected(approved_variant(|_| {}, false, true), "SIG_HASH_NONE approval via production encoder");
}

#[test]
fn enc3_mut_approval_slot_swapped() {
    assert_rejected(approved_variant(|_| {}, true, false), "swapped approval slots -> keys mismatch -> insufficient");
}

#[test]
fn enc3_mut_approval_placeholder_bad_trailing_byte() {
    // Corrupt an active slot's trailing sighash byte in the approvals blob.
    assert_rejected(approved_variant(|c| {
        let mut blob = c["approvals"].as_str().unwrap().to_string();
        // slot 0 trailing byte = hex chars [128..130]; set to 0x02 (SIG_HASH_NONE code)
        blob.replace_range(128..130, "02");
        c["approvals"] = serde_json::json!(blob);
    }, false, false), "active-slot trailing byte != 0x01");
}

#[test]
fn enc3_mut_version_dispatch_mismatch() {
    // Encoding a v0.3 call as v0.2 must not produce a valid v0.3 spend.
    assert_rejected(approved_variant(|c| { c["contractVersion"] = serde_json::json!("policyvault-0.2"); }, false, false), "wrong version dispatch");
}

#[test]
fn enc3_mut_terminal_shape_mismatch() {
    // ownerRecover intent but with a covenant successor output present.
    let (owner, delegate, _a1, _a2, _a3, _r) = actors();
    let prev = base_state(&delegate, [0x44u8; 32], [ZERO32; 10], 1, 50 * KAS);
    // Build a recover call but give it a successor covenant output (wrong shape).
    let succ = prev.clone();
    let r = run_owner_op_recover_with_successor(&owner, &prev, &succ);
    assert_rejected(r, "ownerRecover with a successor covenant output must fail");
}

/// ownerRecover encoded, but the tx wrongly carries a covenant successor output.
fn run_owner_op_recover_with_successor(owner_kp: &Keypair, prev: &V3, succ: &V3) -> Result<(), TxScriptError> {
    let owner = xonly(owner_kp);
    let active = compile_state(&owner, prev);
    let succ_c = compile_state(&owner, succ);
    let (fin, fuel_pk) = fuel_input();
    let fuel_value = 10 * KAS as u64;
    let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
    let outputs = vec![
        TransactionOutput { value: prev.protected_value as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
        TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None },
    ];
    let tx = Transaction::new(1, vec![cov_input(), fin], outputs, 0, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, prev.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
    let osig = sign_input_typed(&mutable, 0, owner_kp, SIG_HASH_ALL);
    let call = serde_json::json!({ "contractVersion": "policyvault-0.3", "function": "ownerRecover", "signature": hexs(&osig) });
    let call_bytes = match encode_via_binary(&owner, prev, &call) {
        Ok(b) => b,
        Err(_e) => return Err(TxScriptError::VerifyError),
    };
    let mut sigscript = call_bytes;
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;
    execute_input_with_covenants(mutable.tx, vec![cov_utxo, fuel_utxo], 0)
}

// ---- 4G: measure ACTUAL production sig-script sizes for mass vectors ----
#[test]
fn enc3_measure_sizes_for_mass_probe() {
    let (owner, delegate, a1, a2, a3, recipient) = actors();
    let owner_pk = xonly(&owner);

    // redeem-script length is fixed by the template (state region fixed).
    let prev0 = base_state(&delegate, [0x44u8; 32], [ZERO32; 10], 1, 50 * KAS);
    let redeem = compile_state(&owner_pk, &prev0).script.len();
    println!("MASS redeem_script_len={redeem}");

    // helper: build a delegate-spend and report its input-0 sig-script len.
    let measure_spend = |label: &str, depth: u32, approvers: &[&Keypair], m: i64, threshold: i64, pay: i64| {
        let (root, sibs, bits) = {
            let n = 1usize << depth;
            if depth == 0 {
                (leaf(&xonly(&recipient)), vec![], 0u64)
            } else {
                let mut leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&LEAF_DOMAIN, &(i as u64).to_le_bytes()])).collect();
                leaves[1] = leaf(&xonly(&recipient));
                merkle(&leaves, 1)
            }
        };
        let aset = approver_set(approvers);
        let prev = base_state(&delegate, root, aset, m, threshold);
        let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
        let active = compile_state(&owner_pk, &prev);
        let (fin, fuel_pk) = fuel_input();
        let fuel_value = 10 * KAS as u64;
        let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
        let succ_c = compile_state(&owner_pk, &succ);
        let outputs = vec![
            p2pk_output(&xonly(&recipient), pay as u64),
            TransactionOutput { value: succ.protected_value as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
            TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None },
        ];
        let tx = Transaction::new(1, vec![cov_input(), fin], outputs, 0, Default::default(), 0, vec![]);
        let cov_utxo = active_utxo(&active, prev.protected_value as u64);
        let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
        let mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
        let dsig = sign_input_typed(&mutable, 0, &delegate, SIG_HASH_ALL);
        let mut blob = Vec::with_capacity(650);
        for i in 0..10 {
            if i < approvers.len() {
                blob.extend_from_slice(&sign_input_typed(&mutable, 0, approvers[i], SIG_HASH_ALL));
            } else {
                blob.extend_from_slice(&placeholder());
            }
        }
        let call = serde_json::json!({
            "contractVersion": "policyvault-0.3", "function": "delegateSpend", "signature": hexs(&dsig),
            "successor": successor_json(&succ), "payAmount": pay.to_string(), "recipientPk": hexs(&xonly(&recipient)),
            "siblings": hexs(&sibs), "pathBits": bits, "approvals": hexs(&blob),
        });
        let call_bytes = encode_via_binary(&owner_pk, &prev, &call).expect("encode");
        let sigscript_len = call_bytes.len() + push_redeem_script(&active.script).len();
        println!("MASS {label} sigscript_len={sigscript_len}");
    };

    measure_spend("delegate_spend_depth0_noapprovals", 0, &[], 1, 500 * KAS, 40 * KAS);
    measure_spend("delegate_spend_depth16_noapprovals", 16, &[], 1, 500 * KAS, 40 * KAS);
    measure_spend("approved_spend_2of3", 8, &[&a1, &a2, &a3], 2, 50 * KAS, 150 * KAS);
    let ten: Vec<Keypair> = (0..10).map(|i| deterministic_keypair(60 + i)).collect();
    let ten_refs: Vec<&Keypair> = ten.iter().collect();
    measure_spend("approved_spend_10of10", 8, &ten_refs, 10, 50 * KAS, 150 * KAS);

    // owner op + recover sig-script sizes
    let measure_owner = |label: &str, func: &str, succ: Option<&V3>, recover: bool| {
        let prev = prev0.clone();
        let active = compile_state(&owner_pk, &prev);
        let (fin, fuel_pk) = fuel_input();
        let fuel_value = 10 * KAS as u64;
        let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
        let mut outputs = Vec::new();
        if recover {
            outputs.push(p2pk_output(&owner_pk, prev.protected_value as u64));
        } else {
            let s = succ.unwrap();
            let sc = compile_state(&owner_pk, s);
            outputs.push(TransactionOutput { value: s.protected_value as u64, script_public_key: pay_to_script_hash_script(&sc.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) });
        }
        outputs.push(TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None });
        let tx = Transaction::new(1, vec![cov_input(), fin], outputs, 0, Default::default(), 0, vec![]);
        let cov_utxo = active_utxo(&active, prev.protected_value as u64);
        let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
        let mutable = MutableTransaction::with_entries(tx, vec![cov_utxo, fuel_utxo]);
        let osig = sign_input_typed(&mutable, 0, &owner, SIG_HASH_ALL);
        let mut call = serde_json::json!({ "contractVersion": "policyvault-0.3", "function": func, "signature": hexs(&osig) });
        if !recover {
            call["successor"] = successor_json(succ.unwrap());
        }
        let call_bytes = encode_via_binary(&owner_pk, &prev, &call).expect("encode");
        let sigscript_len = call_bytes.len() + push_redeem_script(&active.script).len();
        println!("MASS {label} sigscript_len={sigscript_len}");
    };
    let paused = V3 { paused: 1, ..prev0.clone() };
    measure_owner("owner_op", "ownerPause", Some(&paused), false);
    measure_owner("recover", "ownerRecover", None, true);
}

// ---- 4G: measure REQUIRED compute budget under production sig-op pricing ----
#[test]
fn enc3_measure_required_compute_budget() {
    let (owner, delegate, a1, a2, a3, recipient) = actors();
    let owner_pk = xonly(&owner);
    // cov input with a generous ComputeBudget so metering completes; then
    // used_script_units (priced at Gram(1000)/sigop) gives the real minimum.
    let big_cov = || TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeBudget(400).into(),
    };
    let measure = |label: &str, depth: u32, approvers: &[&Keypair], m: i64, threshold: i64, pay: i64| {
        let (root, sibs, bits) = {
            if depth == 0 {
                (leaf(&xonly(&recipient)), vec![], 0u64)
            } else {
                let n = 1usize << depth;
                let mut leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&LEAF_DOMAIN, &(i as u64).to_le_bytes()])).collect();
                leaves[1] = leaf(&xonly(&recipient));
                merkle(&leaves, 1)
            }
        };
        let slots = approver_set(approvers);
        let prev = base_state(&delegate, root, slots, m, threshold);
        let succ = V3 { protected_value: prev.protected_value - pay, period_spent: prev.period_spent + pay, ..prev.clone() };
        let active = compile_state(&owner_pk, &prev);
        let succ_c = compile_state(&owner_pk, &succ);
        let (fin, fuel_pk) = fuel_input();
        let fuel_value = 10 * KAS as u64;
        let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
        let outputs = vec![
            p2pk_output(&xonly(&recipient), pay as u64),
            TransactionOutput { value: succ.protected_value as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
            TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None },
        ];
        let tx = Transaction::new(1, vec![big_cov(), fin], outputs, 0, Default::default(), 0, vec![]);
        let cov_utxo = active_utxo(&active, prev.protected_value as u64);
        let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
        let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
        let dsig = sign_input_typed(&mutable, 0, &delegate, SIG_HASH_ALL);
        // Sign the approver whose sorted key sits in each slot (align with layout).
        let mut blob = Vec::with_capacity(650);
        for i in 0..10 {
            let mut signed = false;
            for kp in approvers {
                if xonly(kp) == slots[i] {
                    blob.extend_from_slice(&sign_input_typed(&mutable, 0, kp, SIG_HASH_ALL));
                    signed = true;
                }
            }
            if !signed { blob.extend_from_slice(&placeholder()); }
        }
        let call = serde_json::json!({
            "contractVersion": "policyvault-0.3", "function": "delegateSpend", "signature": hexs(&dsig),
            "successor": successor_json(&succ), "payAmount": pay.to_string(), "recipientPk": hexs(&xonly(&recipient)),
            "siblings": hexs(&sibs), "pathBits": bits, "approvals": hexs(&blob),
        });
        let call_bytes = encode_via_binary(&owner_pk, &prev, &call).expect("encode");
        let mut ss = call_bytes;
        ss.extend_from_slice(&push_redeem_script(&active.script));
        mutable.tx.inputs[0].signature_script = ss;
        let (res, units) = execute_input_measured_priced(mutable.tx, vec![cov_utxo, fuel_utxo], 0, 1000);
        assert!(res.is_ok(), "{label} priced exec must pass: {res:?}");
        let budget = (units + 9999) / 10000;
        println!("BUDGET {label} used_script_units={units} required_compute_budget={budget}");
    };
    measure("delegate_spend_depth0_noapprovals", 0, &[], 1, 500 * KAS, 40 * KAS);
    measure("delegate_spend_depth16_noapprovals", 16, &[], 1, 500 * KAS, 40 * KAS);
    measure("approved_spend_2of3", 8, &[&a1, &a2, &a3], 2, 50 * KAS, 150 * KAS);
    let ten: Vec<Keypair> = (0..10).map(|i| deterministic_keypair(60 + i)).collect();
    let ten_refs: Vec<&Keypair> = ten.iter().collect();
    measure("approved_spend_10of10", 8, &ten_refs, 10, 50 * KAS, 150 * KAS);
    // TRUE global worst case: max Merkle depth 16 + 10-of-10 approvals.
    measure("WORST_depth16_10of10", 16, &ten_refs, 10, 50 * KAS, 150 * KAS);
}

#[test]
fn enc3_measure_owner_op_budgets() {
    let (owner, delegate, _a1, _a2, _a3, _r) = actors();
    let owner_pk = xonly(&owner);
    let prev = base_state(&delegate, [0x44u8; 32], [ZERO32; 10], 1, 50 * KAS);
    let big_cov = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![], sequence: 0, compute_commit: ComputeBudget(400).into(),
    };
    let run = |label: &str, func: &str, succ: Option<&V3>, recover: bool| {
        let active = compile_state(&owner_pk, &prev);
        let (fin, fuel_pk) = fuel_input();
        let fuel_value = 10 * KAS as u64;
        let change_spk = ScriptBuilder::new().add_data(&fuel_pk).unwrap().add_op(OpCheckSig).unwrap().drain();
        let mut outputs = Vec::new();
        if recover {
            outputs.push(p2pk_output(&owner_pk, prev.protected_value as u64));
        } else {
            let s = succ.unwrap();
            let sc = compile_state(&owner_pk, s);
            outputs.push(TransactionOutput { value: s.protected_value as u64, script_public_key: pay_to_script_hash_script(&sc.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) });
        }
        outputs.push(TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, change_spk.into()), covenant: None });
        let tx = Transaction::new(1, vec![big_cov.clone(), fin], outputs, 0, Default::default(), 0, vec![]);
        let cov_utxo = active_utxo(&active, prev.protected_value as u64);
        let fuel_utxo = UtxoEntry::new(fuel_value, p2pk_output(&fuel_pk, 0).script_public_key, 0, false, None);
        let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
        let osig = sign_input_typed(&mutable, 0, &owner, SIG_HASH_ALL);
        let mut call = serde_json::json!({ "contractVersion": "policyvault-0.3", "function": func, "signature": hexs(&osig) });
        if !recover { call["successor"] = successor_json(succ.unwrap()); }
        let call_bytes = encode_via_binary(&owner_pk, &prev, &call).expect("encode");
        let mut ss = call_bytes;
        ss.extend_from_slice(&push_redeem_script(&active.script));
        mutable.tx.inputs[0].signature_script = ss;
        let (res, units) = execute_input_measured_priced(mutable.tx, vec![cov_utxo, fuel_utxo], 0, 1000);
        assert!(res.is_ok(), "{label}: {res:?}");
        println!("BUDGET {label} used_script_units={units} required_compute_budget={}", (units + 9999) / 10000);
    };
    let paused = V3 { paused: 1, ..prev.clone() };
    run("owner_op_pause", "ownerPause", Some(&paused), false);
    let ap = V3 { approvers: approver_set(&[&deterministic_keypair(20), &deterministic_keypair(21), &deterministic_keypair(22)]), approval_m: 2, policy_nonce: 1, ..prev.clone() };
    run("owner_set_approvers", "ownerSetApprovers", Some(&ap), false);
    run("recover", "ownerRecover", None, true);
}
