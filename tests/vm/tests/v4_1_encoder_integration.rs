//! VM layer — v0.4 PRODUCTION-BYTE integration. The consensus-visible bytes
//! for every v0.4 entrypoint are produced by the REAL `pv_call_encoder`
//! BINARY (exact-live-state source + constructor-args + call.json, exactly as
//! the SDK drives it), then executed on the real TxScriptEngine against the
//! production PolicyVault.v0.4.1.sil. Never the in-process library encoder —
//! that is the blind spot that shipped the v0.2 boundVaultId defect.
//!
//! Plus a mutation matrix: feeding the production encoder a mutated intent
//! (wrong recipient/proof/path/root, forged successor, non-ALL approval,
//! swapped/duplicated approval slots, wrong version dispatch, terminal-shape
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
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript_errors::TxScriptError;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

const KAS: i64 = 100_000_000;
const VAULT_ID_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const AGENT_DOMAIN: [u8; 4] = [0x50, 0x56, 0x34, 0x01];
const RECIP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];

fn encoder_path() -> PathBuf {
    PathBuf::from(format!("{}/target/debug/pv_call_encoder", env!("CARGO_MANIFEST_DIR")))
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
fn num8(v: i64) -> [u8; 8] {
    (v as u64).to_le_bytes()
}

#[derive(Clone)]
struct Agent {
    pk: [u8; 32],
    max_per_spend: i64,
    period_budget: i64,
    period_length_daa: i64,
    period_start_daa: i64,
    period_spent: i64,
    approval_threshold: i64,
    max_fee_per_tx: i64,
    recipient_root: [u8; 32],
}
fn agent_leaf(a: &Agent) -> [u8; 32] {
    sha256(&[
        &AGENT_DOMAIN, &a.pk, &num8(a.max_per_spend), &num8(a.period_budget), &num8(a.period_length_daa),
        &num8(a.period_start_daa), &num8(a.period_spent), &num8(a.approval_threshold), &num8(a.max_fee_per_tx), &a.recipient_root,
    ])
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
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            next.push(sha256(&[&pair[0], &pair[1]]));
        }
        idx /= 2;
        level = next;
        lvl += 1;
    }
    (level[0], sibs, bits)
}
fn fold(leaf: [u8; 32], sibs: &[u8], mut bits: u64) -> [u8; 32] {
    let mut node = leaf;
    for level in 0..(sibs.len() / 32) {
        let sib: [u8; 32] = sibs[level * 32..level * 32 + 32].try_into().unwrap();
        node = if bits & 1 == 1 { sha256(&[&sib, &node]) } else { sha256(&[&node, &sib]) };
        bits >>= 1;
    }
    node
}

#[derive(Clone)]
struct S {
    protected: i64,
    reserve: i64,
    paused: i64,
    agent_root: [u8; 32],
    approvers: [[u8; 32]; 10],
    approval_m: i64,
    policy_nonce: i64,
}

const NAMES: [&str; 10] = ["approver1","approver2","approver3","approver4","approver5","approver6","approver7","approver8","approver9","approver10"];

/// Exact-live-state source — the SAME templating the SDK contract-compiler-v4
/// produces (anchors identical to PolicyVault.v0.4.1.sil initializers).
fn templated_source(s: &S) -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.4.1.sil", env!("CARGO_MANIFEST_DIR"));
    let mut src = std::fs::read_to_string(&path).unwrap();
    let mut r = |from: String, to: String| {
        assert!(src.contains(&from), "anchor missing: {from}");
        src = src.replacen(&from, &to, 1);
    };
    r("int protectedValue = initValue;".into(), format!("int protectedValue = {};", s.protected));
    r("int feeReserve = initFeeReserve;".into(), format!("int feeReserve = {};", s.reserve));
    r("int paused = 0;".into(), format!("int paused = {};", s.paused));
    r("byte[32] agentRoot = initAgentRoot;".into(), format!("byte[32] agentRoot = 0x{};", hexs(&s.agent_root)));
    for i in 0..10 {
        r(format!("pubkey approver{} = initApprover{};", i + 1, i + 1), format!("pubkey approver{} = 0x{};", i + 1, hexs(&s.approvers[i])));
    }
    r("int approvalM = initApprovalM;".into(), format!("int approvalM = {};", s.approval_m));
    r("int policyNonce = 0;".into(), format!("int policyNonce = {};", s.policy_nonce));
    src
}
/// Constructor args JSON — SAME order as contract-compiler-v4 constructorArgsV4.
fn ctor_args_json(owner: &[u8; 32], s: &S) -> String {
    let pk = |b: &[u8]| serde_json::json!({ "kind": "array", "data": b.iter().map(|x| serde_json::json!({"kind":"byte","data":*x})).collect::<Vec<_>>() });
    let int = |v: i64| serde_json::json!({ "kind": "int", "data": v });
    let vault_id: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&VAULT_ID_HEX[i * 2..i * 2 + 2], 16).unwrap()).collect();
    let mut a = vec![pk(owner), pk(&vault_id), pk(&s.agent_root), int(s.reserve)];
    for i in 0..10 {
        a.push(pk(&s.approvers[i]));
    }
    a.push(int(s.approval_m));
    a.push(int(s.protected));
    serde_json::to_string_pretty(&serde_json::Value::Array(a)).unwrap()
}
fn successor_json(s: &S) -> serde_json::Value {
    let mut o = serde_json::json!({
        "protectedValue": s.protected.to_string(),
        "feeReserve": s.reserve.to_string(),
        "paused": s.paused,
        "agentRoot": hexs(&s.agent_root),
        "approvalM": s.approval_m,
        "policyNonce": s.policy_nonce,
    });
    for i in 0..10 {
        o[NAMES[i]] = serde_json::json!(hexs(&s.approvers[i]));
    }
    o
}
fn ctor_exprs(owner: &[u8; 32], s: &S) -> Vec<Expr<'static>> {
    let vid: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&VAULT_ID_HEX[i * 2..i * 2 + 2], 16).unwrap()).collect();
    let mut a = vec![Expr::bytes(owner.to_vec()), Expr::bytes(vid), Expr::bytes(s.agent_root.to_vec()), Expr::int(s.reserve)];
    for i in 0..10 {
        a.push(Expr::bytes(s.approvers[i].to_vec()));
    }
    a.push(Expr::int(s.approval_m));
    a.push(Expr::int(s.protected));
    a
}
fn compile_state(owner: &[u8; 32], s: &S) -> CompiledContract<'static> {
    let src: &'static str = Box::leak(templated_source(s).into_boxed_str());
    compile_contract(src, &ctor_exprs(owner, s), CompileOptions::default()).expect("v0.4 compile")
}

fn sign_typed(m: &MutableTransaction<Transaction>, idx: usize, kp: &Keypair, ty: SigHashType) -> Vec<u8> {
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
fn cov_input(budget: u16) -> TransactionInput {
    TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 }, signature_script: vec![], sequence: 0, compute_commit: ComputeBudget(budget).into() }
}
fn ext_input(id: u8) -> (TransactionInput, [u8; 32]) {
    let pk = xonly(&deterministic_keypair(id));
    (TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([id; 32]), index: 1 }, signature_script: vec![], sequence: 0, compute_commit: ComputeBudget(10).into() }, pk)
}
fn ext_utxo(pk: &[u8; 32], v: u64) -> UtxoEntry {
    UtxoEntry::new(v, p2pk_output(pk, 0).script_public_key, 0, false, None)
}
fn change_out(pk: &[u8; 32], v: u64) -> TransactionOutput {
    let spk = ScriptBuilder::new().add_data(pk).unwrap().add_op(OpCheckSig).unwrap().drain();
    TransactionOutput { value: v, script_public_key: ScriptPublicKey::new(0, spk.into()), covenant: None }
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
}
/// Encode via the REAL pv_call_encoder binary using SDK-shaped inputs.
fn encode_via_binary(owner: &[u8; 32], prev: &S, call: &serde_json::Value) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir().join(format!("pv4enc-{}", rand_suffix()));
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

fn agent(kp: &Keypair, cap: i64, budget: i64, threshold: i64, fee_cap: i64, rroot: [u8; 32]) -> Agent {
    Agent { pk: xonly(kp), max_per_spend: cap, period_budget: budget, period_length_daa: 864_000, period_start_daa: 541_000_000, period_spent: 0, approval_threshold: threshold, max_fee_per_tx: fee_cap, recipient_root: rroot }
}
fn approver_set(keys: &[&Keypair]) -> [[u8; 32]; 10] {
    let mut active: Vec<[u8; 32]> = keys.iter().map(|k| xonly(k)).collect();
    active.sort();
    let mut a = [ZERO32; 10];
    for (i, k) in active.iter().enumerate() {
        a[i] = *k;
    }
    a
}
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

/// A full agent spend built + signed + encoded via the production binary and
/// executed on the VM. `mutate_call` tampers with the JSON after construction.
#[allow(clippy::too_many_arguments)]
fn run_agent_spend(
    owner_kp: &Keypair,
    prev: &S,
    claim: &Agent,
    pay: i64,
    reserve_consumed: i64,
    periods_elapsed: i64,
    policy_sibs: &[u8],
    policy_bits: u64,
    recipient_leaf_pk: &[u8; 32],
    recipient_out_pk: &[u8; 32],
    recip_sibs: &[u8],
    recip_bits: u64,
    new_root: [u8; 32],
    signer: &Keypair,
    signer_type: SigHashType,
    approver_sigs: &[Option<(&Keypair, SigHashType)>; 10],
    ext_in: Option<i64>,
    ext_out: Option<i64>,
    budget: u16,
    mutate_call: impl FnOnce(&mut serde_json::Value),
) -> Result<(), TxScriptError> {
    let owner = xonly(owner_kp);
    let succ = S { protected: prev.protected - pay, reserve: prev.reserve - reserve_consumed, agent_root: new_root, ..prev.clone() };
    let active = compile_state(&owner, prev);
    let succ_c = compile_state(&owner, &succ);

    let mut inputs = vec![cov_input(budget)];
    let mut entries = vec![active_utxo(&active, (prev.protected + prev.reserve) as u64)];
    let mut ext_pk = None;
    if let Some(ev) = ext_in {
        let (ei, pk) = ext_input(0x71);
        inputs.push(ei);
        entries.push(ext_utxo(&pk, ev as u64));
        ext_pk = Some(pk);
    }
    let mut outputs = vec![
        p2pk_output(recipient_out_pk, pay as u64),
        TransactionOutput { value: (succ.protected + succ.reserve) as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
    ];
    if let Some(ov) = ext_out {
        outputs.push(change_out(ext_pk.as_ref().unwrap_or(recipient_out_pk), ov as u64));
    }
    let lock = if periods_elapsed >= 1 { let ns = claim.period_start_daa + periods_elapsed * claim.period_length_daa; ns as u64 } else { 0 };
    let tx = Transaction::new(1, inputs, outputs, lock, Default::default(), 0, vec![]);
    let mut mutable = MutableTransaction::with_entries(tx, entries.clone());
    let agent_sig = sign_typed(&mutable, 0, signer, signer_type);
    let mut blob = Vec::with_capacity(650);
    for slot in approver_sigs.iter() {
        match slot {
            Some((kp, ty)) => blob.extend_from_slice(&sign_typed(&mutable, 0, kp, *ty)),
            None => blob.extend_from_slice(&placeholder()),
        }
    }
    let mut call = serde_json::json!({
        "contractVersion": "policyvault-0.4.1",
        "function": "agentSpend",
        "signature": hexs(&agent_sig),
        "successor": successor_json(&succ),
        "payAmount": pay.to_string(),
        "agentPk": hexs(&claim.pk),
        "maxPerSpend": claim.max_per_spend.to_string(),
        "periodBudget": claim.period_budget.to_string(),
        "periodLengthDaa": claim.period_length_daa.to_string(),
        "periodStartDaa": claim.period_start_daa.to_string(),
        "periodSpent": claim.period_spent.to_string(),
        "approvalThreshold": claim.approval_threshold.to_string(),
        "agentMaxFeePerTx": claim.max_fee_per_tx.to_string(),
        "agentRecipientRoot": hexs(&claim.recipient_root),
        "policySiblings": hexs(policy_sibs),
        "policyPathBits": policy_bits,
        "periodsElapsed": periods_elapsed.to_string(),
        "recipientPk": hexs(recipient_leaf_pk),
        "recipientSiblings": hexs(recip_sibs),
        "recipientPathBits": recip_bits,
        "approvals": hexs(&blob),
    });
    mutate_call(&mut call);
    let call_bytes = match encode_via_binary(&owner, prev, &call) {
        Ok(b) => b,
        Err(_) => return Err(TxScriptError::VerifyError),
    };
    let mut ss = call_bytes;
    ss.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = ss;
    execute_input_with_covenants(mutable.tx, entries, 0)
}

/// v0.4.1 owner path through the production encoder. `func` is "ownerControl"
/// (with `op` = the opSelector) or "ownerRecover" (op = None, recover = true).
/// `extra` can tamper with the call JSON (e.g., drop the selector, swap it, or
/// add a selector to a recover) to exercise the encoder's fail-closed dispatch.
fn owner_op(owner_kp: &Keypair, func: &str, op: Option<i64>, prev: &S, succ: Option<&S>, recover: bool, extra: impl FnOnce(&mut serde_json::Value)) -> Result<(), TxScriptError> {
    let owner = xonly(owner_kp);
    let active = compile_state(&owner, prev);
    let mut outputs = Vec::new();
    if recover {
        outputs.push(p2pk_output(&owner, (prev.protected + prev.reserve) as u64));
    } else {
        let s = succ.unwrap();
        let sc = compile_state(&owner, s);
        outputs.push(TransactionOutput { value: (s.protected + s.reserve) as u64, script_public_key: pay_to_script_hash_script(&sc.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) });
    }
    let tx = Transaction::new(1, vec![cov_input(40)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
    let mut mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, 0, owner_kp, SIG_HASH_ALL);
    let mut call = serde_json::json!({ "contractVersion": "policyvault-0.4.1", "function": func, "signature": hexs(&osig) });
    if let Some(o) = op {
        call["opSelector"] = serde_json::json!(o);
    }
    if !recover {
        call["successor"] = successor_json(succ.unwrap());
    }
    extra(&mut call);
    let call_bytes = match encode_via_binary(&owner, prev, &call) {
        Ok(b) => b,
        Err(_) => return Err(TxScriptError::VerifyError),
    };
    let mut ss = call_bytes;
    ss.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = ss;
    execute_input_with_covenants(mutable.tx, vec![utxo], 0)
}

// Convenience: encode-and-run an ownerControl with a fixed selector.
fn owner_control(owner_kp: &Keypair, op: i64, prev: &S, succ: &S) -> Result<(), TxScriptError> {
    owner_op(owner_kp, "ownerControl", Some(op), prev, Some(succ), false, |_| {})
}

/// Base single-agent setup: one agent at index 0, depth-0 recipient tree.
fn setup(threshold: i64, approvers: [[u8; 32]; 10], approval_m: i64) -> (Keypair, Keypair, Keypair, S, Agent, Vec<u8>, u64, [u8; 32]) {
    let owner = deterministic_keypair(1);
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let rroot = sha256(&[&RECIP_DOMAIN, &xonly(&recipient)]);
    let pa = agent(&a, 200 * KAS, 500 * KAS, threshold, 1 * KAS, rroot);
    let (root, psibs, pbits) = merkle(&[agent_leaf(&pa)], 0);
    let prev = S { protected: 1000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers, approval_m, policy_nonce: 0 };
    (owner, a, recipient, prev, pa, psibs, pbits, rroot)
}

fn new_root_for(pa: &Agent, pay: i64, periods: i64, psibs: &[u8], pbits: u64) -> [u8; 32] {
    let mut np = pa.clone();
    if periods >= 1 {
        np.period_start_daa = pa.period_start_daa + periods * pa.period_length_daa;
        np.period_spent = pay;
    } else {
        np.period_spent = pa.period_spent + pay;
    }
    fold(agent_leaf(&np), psibs, pbits)
}

// ============================================ VALID PATHS (encoder-backed)
#[test]
fn enc41_agent_spend_below_threshold() {
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(100_000 * KAS, [ZERO32; 10], 0);
    let nr = new_root_for(&pa, 40 * KAS, 0, &psibs, pbits);
    let r = run_agent_spend(&owner, &prev, &pa, 40 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &Default::default(), None, None, 60, |_| {});
    assert!(r.is_ok(), "encoder-backed below-threshold agent spend: {r:?}");
}

#[test]
fn enc41_approved_spend_2of3() {
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(50 * KAS, slots, 2);
    let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)]);
    let nr = new_root_for(&pa, 150 * KAS, 0, &psibs, pbits);
    let r = run_agent_spend(&owner, &prev, &pa, 150 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &ap, None, None, 80, |_| {});
    assert!(r.is_ok(), "encoder-backed 2-of-3 approved spend: {r:?}");
}

#[test]
fn enc41_owner_ops_and_recover() {
    let owner = deterministic_keypair(1);
    let a = deterministic_keypair(30);
    let rroot = sha256(&[&RECIP_DOMAIN, &xonly(&deterministic_keypair(40))]);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, rroot);
    let (root, _, _) = merkle(&[agent_leaf(&pa)], 0);
    let prev = S { protected: 1000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    // v0.4.1: all six owner ops go through ownerControl + opSelector.
    // 0 setAgentRoot
    assert!(owner_control(&owner, 0, &prev, &S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() }).is_ok(), "setAgentRoot (sel 0)");
    // 1 setApprovers
    assert!(owner_control(&owner, 1, &prev, &S { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 2, policy_nonce: 1, ..prev.clone() }).is_ok(), "setApprovers (sel 1)");
    // 2 topUp / 3 topUpReserve
    assert!(owner_control(&owner, 2, &prev, &S { protected: prev.protected + 100 * KAS, ..prev.clone() }).is_ok(), "topUp (sel 2)");
    assert!(owner_control(&owner, 3, &prev, &S { reserve: prev.reserve + 3 * KAS, ..prev.clone() }).is_ok(), "topUpReserve (sel 3)");
    // 4 pause / 5 unpause
    assert!(owner_control(&owner, 4, &prev, &S { paused: 1, ..prev.clone() }).is_ok(), "pause (sel 4)");
    let paused = S { paused: 1, ..prev.clone() };
    assert!(owner_control(&owner, 5, &paused, &prev).is_ok(), "unpause (sel 5)");
    // recover (terminal, separate entrypoint)
    assert!(owner_op(&owner, "ownerRecover", None, &prev, None, true, |_| {}).is_ok(), "recover");
}

// ============================================ v0.4.1 ENCODER DISPATCH (fail-closed)
// These prove the PRODUCTION encoder rejects malformed/ambiguous owner calls
// BEFORE emitting any bytes (encode_via_binary returns Err), and that a
// well-formed-but-wrong selector is caught by consensus (VM reject).
fn base_owner_setup() -> (Keypair, S) {
    let owner = deterministic_keypair(1);
    let a = deterministic_keypair(30);
    let rroot = sha256(&[&RECIP_DOMAIN, &xonly(&deterministic_keypair(40))]);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, rroot);
    let (root, _, _) = merkle(&[agent_leaf(&pa)], 0);
    let prev = S { protected: 1000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    (owner, prev)
}

#[test]
fn enc41_reject_missing_selector() {
    let (owner, prev) = base_owner_setup();
    // ownerControl but drop the opSelector -> encoder must fail closed.
    let r = owner_op(&owner, "ownerControl", Some(0), &prev, Some(&S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() }), false, |c| {
        c.as_object_mut().unwrap().remove("opSelector");
    });
    assert_rejected(r, "ownerControl with no opSelector must be rejected (encoder fail-closed)");
}

#[test]
fn enc41_reject_out_of_range_selector() {
    let (owner, prev) = base_owner_setup();
    for bad in [6i64, 7, 99, -1] {
        let r = owner_op(&owner, "ownerControl", Some(bad), &prev, Some(&S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() }), false, |_| {});
        assert_rejected(r, "out-of-range opSelector must be rejected (encoder fail-closed)");
    }
}

#[test]
fn enc41_reject_control_as_recover() {
    // ownerControl shaped like a recover (no successor) -> encoder fail-closed.
    let (owner, prev) = base_owner_setup();
    let ox = xonly(&owner);
    let call = serde_json::json!({ "contractVersion": "policyvault-0.4.1", "function": "ownerControl", "opSelector": 0, "signature": hexs(&[0u8; 65]) });
    assert!(encode_via_binary(&ox, &prev, &call).is_err(), "ownerControl without a successor must be rejected by the encoder");
}

#[test]
fn enc41_reject_recover_as_control() {
    // ownerRecover carrying an opSelector -> encoder fail-closed.
    let (owner, prev) = base_owner_setup();
    let ox = xonly(&owner);
    let call = serde_json::json!({ "contractVersion": "policyvault-0.4.1", "function": "ownerRecover", "opSelector": 3, "signature": hexs(&[0u8; 65]) });
    assert!(encode_via_binary(&ox, &prev, &call).is_err(), "ownerRecover with an opSelector must be rejected by the encoder");
}

#[test]
fn enc41_reject_legacy_owner_function_names() {
    // The six v0.4 owner-op function names are NOT valid under v0.4.1.
    let (owner, prev) = base_owner_setup();
    let ox = xonly(&owner);
    for f in ["ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause"] {
        let call = serde_json::json!({ "contractVersion": "policyvault-0.4.1", "function": f, "opSelector": 0, "signature": hexs(&[0u8; 65]), "successor": successor_json(&prev) });
        assert!(encode_via_binary(&ox, &prev, &call).is_err(), "legacy v0.4 owner function {f} must be rejected under v0.4.1");
    }
}

#[test]
fn enc41_cross_selector_swap_rejected_by_consensus() {
    // A WELL-FORMED setAgentRoot successor (agentRoot changed, nonce+1) encoded
    // under the WRONG selector must be rejected by the covenant. The successor
    // is committed by SIG_HASH_ALL; the opSelector is not — but the covenant's
    // mutually-exclusive branches reject any selector whose field rules the
    // fixed successor does not satisfy.
    let (owner, prev) = base_owner_setup();
    let set_root = S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() };
    // selector 0 (correct) passes; every other selector rejects.
    assert!(owner_control(&owner, 0, &prev, &set_root).is_ok(), "correct selector 0 must pass");
    for other in [1i64, 2, 3, 4, 5] {
        assert_rejected(owner_control(&owner, other, &prev, &set_root), "setAgentRoot successor under wrong selector must be rejected by consensus");
    }
}

#[test]
fn enc41_rollover_and_reserve() {
    let (owner, a, recipient, mut prev0, mut pa, psibs, pbits, _r) = setup(100_000 * KAS, [ZERO32; 10], 0);
    pa.period_spent = 480 * KAS;
    let (root, ps, pb) = merkle(&[agent_leaf(&pa)], 0);
    prev0.agent_root = root;
    let nr = new_root_for(&pa, 40 * KAS, 2, &ps, pb);
    let r = run_agent_spend(&owner, &prev0, &pa, 40 * KAS, 5_000_000, 2, &ps, pb, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &Default::default(), None, None, 60, |_| {});
    assert!(r.is_ok(), "encoder-backed rollover spend: {r:?}");
    let _ = (psibs, pbits);
}

// ============================================ MUTATION MATRIX (encoder-backed)
fn approved_variant(mutate: impl FnOnce(&mut serde_json::Value)) -> Result<(), TxScriptError> {
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(50 * KAS, slots, 2);
    let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)]);
    let nr = new_root_for(&pa, 150 * KAS, 0, &psibs, pbits);
    run_agent_spend(&owner, &prev, &pa, 150 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &ap, None, None, 80, mutate)
}

#[test]
fn enc41_mut_control_passes() {
    assert!(approved_variant(|_| {}).is_ok(), "control approved spend must pass");
}
#[test]
fn enc41_mut_wrong_recipient() {
    assert_rejected(approved_variant(|c| c["recipientPk"] = serde_json::json!(hexs(&xonly(&deterministic_keypair(99))))), "wrong recipient");
}
#[test]
fn enc41_mut_successor_nonce_bumped() {
    assert_rejected(approved_variant(|c| c["successor"]["policyNonce"] = serde_json::json!(1)), "spend must not change policyNonce");
}
#[test]
fn enc41_mut_successor_forged_protected() {
    assert_rejected(approved_variant(|c| c["successor"]["protectedValue"] = serde_json::json!((999 * KAS).to_string())), "forged successor protectedValue");
}
#[test]
fn enc41_mut_successor_forged_reserve() {
    assert_rejected(approved_variant(|c| c["successor"]["feeReserve"] = serde_json::json!((999 * KAS).to_string())), "forged successor feeReserve");
}
#[test]
fn enc41_mut_borrow_bigger_cap() {
    // claim a bigger maxPerSpend than the real leaf -> membership fails
    assert_rejected(approved_variant(|c| c["maxPerSpend"] = serde_json::json!((999_999 * KAS).to_string())), "borrowed cap");
}
#[test]
fn enc41_mut_borrow_fee_cap() {
    assert_rejected(approved_variant(|c| c["agentMaxFeePerTx"] = serde_json::json!((999 * KAS).to_string())), "borrowed fee cap");
}
#[test]
fn enc41_mut_approval_sighash_none() {
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(50 * KAS, slots, 2);
    let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_NONE), (&a2, SIG_HASH_ALL)]);
    let nr = new_root_for(&pa, 150 * KAS, 0, &psibs, pbits);
    let r = run_agent_spend(&owner, &prev, &pa, 150 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &ap, None, None, 80, |_| {});
    assert_rejected(r, "SIG_HASH_NONE approval via production encoder");
}
#[test]
fn enc41_mut_insufficient_approvals() {
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let slots = approver_set(&[&a1, &a2, &a3]);
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(50 * KAS, slots, 2);
    let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL)]); // only 1 of 2
    let nr = new_root_for(&pa, 150 * KAS, 0, &psibs, pbits);
    let r = run_agent_spend(&owner, &prev, &pa, 150 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &ap, None, None, 80, |_| {});
    assert_rejected(r, "insufficient approvals");
}
#[test]
fn enc41_mut_reserve_redirect() {
    // claim reserveConsumed to an extra output (isolation: reserveConsumed <= fee fails)
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(100_000 * KAS, [ZERO32; 10], 0);
    let nr = new_root_for(&pa, 40 * KAS, 0, &psibs, pbits);
    let r = run_agent_spend(&owner, &prev, &pa, 40 * KAS, 1 * KAS, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &Default::default(), None, Some(1 * KAS), 60, |_| {});
    assert_rejected(r, "reserve redirected to an extra output");
}
#[test]
fn enc41_mut_over_fee_cap() {
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(100_000 * KAS, [ZERO32; 10], 0);
    let nr = new_root_for(&pa, 40 * KAS, 0, &psibs, pbits);
    // consume 2 KAS > agentMaxFeePerTx 1 KAS (externally funded so fee is high)
    let r = run_agent_spend(&owner, &prev, &pa, 40 * KAS, 2 * KAS, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &Default::default(), Some(3 * KAS), Some(1 * KAS), 60, |_| {});
    assert_rejected(r, "reserve consumption over the per-agent fee cap");
}
#[test]
fn enc41_mut_forged_successor_root() {
    let (owner, a, recipient, prev, pa, psibs, pbits, _r) = setup(100_000 * KAS, [ZERO32; 10], 0);
    let orig = merkle(&[agent_leaf(&pa)], 0).0; // un-advanced root
    let r = run_agent_spend(&owner, &prev, &pa, 40 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, orig, &a, SIG_HASH_ALL, &Default::default(), None, None, 60, |_| {});
    assert_rejected(r, "forged successor root (accounting not advanced)");
}
#[test]
fn enc41_mut_wrong_version_dispatch() {
    assert_rejected(approved_variant(|c| c["contractVersion"] = serde_json::json!("policyvault-0.3")), "wrong version dispatch");
}
#[test]
fn enc41_mut_truncated_policy_proof() {
    // agent at depth 1 so the policy proof has one sibling; truncate it.
    let owner = deterministic_keypair(1);
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let rroot = sha256(&[&RECIP_DOMAIN, &xonly(&recipient)]);
    let pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, rroot);
    let filler = agent(&deterministic_keypair(31), 1 * KAS, 1 * KAS, 1, 1, [0x09; 32]);
    let (root, psibs, pbits) = merkle(&[agent_leaf(&pa), agent_leaf(&filler)], 0);
    let prev = S { protected: 1000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let nr = new_root_for(&pa, 40 * KAS, 0, &psibs, pbits);
    let r = run_agent_spend(&owner, &prev, &pa, 40 * KAS, 5_000_000, 0, &psibs, pbits, &xonly(&recipient), &xonly(&recipient), &[], 0, nr, &a, SIG_HASH_ALL, &Default::default(), None, None, 60,
        |c| { let s = c["policySiblings"].as_str().unwrap().to_string(); c["policySiblings"] = serde_json::json!(s[..s.len()-64].to_string()); });
    assert_rejected(r, "truncated policy proof");
}
#[test]
fn enc41_mut_terminal_shape_mismatch() {
    // ownerRecover intent but a covenant successor output present -> reject
    let owner = deterministic_keypair(1);
    let a = deterministic_keypair(30);
    let rroot = sha256(&[&RECIP_DOMAIN, &xonly(&deterministic_keypair(40))]);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, rroot);
    let (root, _, _) = merkle(&[agent_leaf(&pa)], 0);
    let prev = S { protected: 1000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let owner_x = xonly(&owner);
    let active = compile_state(&owner_x, &prev);
    let succ_c = compile_state(&owner_x, &prev);
    let outputs = vec![TransactionOutput { value: (prev.protected + prev.reserve) as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) }];
    let tx = Transaction::new(1, vec![cov_input(20)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
    let mut mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, 0, &owner, SIG_HASH_ALL);
    let call = serde_json::json!({ "contractVersion": "policyvault-0.4.1", "function": "ownerRecover", "signature": hexs(&osig) });
    let call_bytes = encode_via_binary(&owner_x, &prev, &call).expect("encode recover");
    let mut ss = call_bytes;
    ss.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = ss;
    assert_rejected(execute_input_with_covenants(mutable.tx, vec![utxo], 0), "ownerRecover with a successor covenant output");
}

// ============================================ MASS MEASUREMENT
#[test]
fn enc41_measure_sizes() {
    let owner = deterministic_keypair(1);
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let rroot = sha256(&[&RECIP_DOMAIN, &xonly(&recipient)]);
    let pa = agent(&a, 200 * KAS, 500 * KAS, 50 * KAS, 1 * KAS, rroot);
    let prev = S { protected: 1000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: merkle(&[agent_leaf(&pa)], 0).0, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let redeem = compile_state(&xonly(&owner), &prev).script.len();
    println!("MASS4 redeem_script_len={redeem}");
}
