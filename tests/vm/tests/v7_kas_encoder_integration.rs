//! VM layer — v0.7-kas PRODUCTION-BYTE integration. The consensus-visible
//! bytes for every v0.7-kas entrypoint are produced by the REAL
//! `pv_call_encoder` BINARY (exact-live-state source + constructor-args +
//! call.json, exactly as an SDK would drive it), then executed on the real
//! TxScriptEngine against the production PolicyVault.v0.7-kas.sil. Never the
//! in-process library encoder — that is the blind spot that shipped the
//! v0.2 boundVaultId defect (CLAUDE.md production-byte rule).
//!
//! The ROOT side of a combined transaction uses the in-process compiler
//! (tests/vm/tests/v7_root_production.rs already drives the root's OWN
//! encoder arm through the binary; that arm is UNCHANGED by this lane).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use secp256k1::Keypair;
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL, SIG_HASH_NONE};
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_script_hash_script, EngineFlags};
use kaspa_txscript_errors::TxScriptError;
use policyvault_vm_tests::execute_input_measured;

const KAS: i64 = 100_000_000;
const VAULT_ID_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const AGENT_DOMAIN: [u8; 4] = [0x50, 0x56, 0x34, 0x01];
const RECIP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];
const COV_VAULT: Hash = Hash::from_bytes(*b"KENCKENCKENCKENCKENCKENCKENCKENC");
const COV_ROOT: Hash = Hash::from_bytes(*b"RENCRENCRENCRENCRENCRENCRENCRENC");

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
fn kp(seed: u8) -> Keypair {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).expect("seed key");
    Keypair::from_secret_key(&secp, &sk)
}
fn xonly32(k: &Keypair) -> [u8; 32] {
    k.x_only_public_key().0.serialize()
}
fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
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
        &AGENT_DOMAIN,
        &a.pk,
        &num8(a.max_per_spend),
        &num8(a.period_budget),
        &num8(a.period_length_daa),
        &num8(a.period_start_daa),
        &num8(a.period_spent),
        &num8(a.approval_threshold),
        &num8(a.max_fee_per_tx),
        &a.recipient_root,
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
fn recip_tree(depth: u32, target: &[u8; 32]) -> ([u8; 32], Vec<u8>, u64) {
    if depth == 0 {
        return (sha256(&[&RECIP_DOMAIN, target]), vec![], 0);
    }
    let n = 1usize << depth;
    let mut leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&RECIP_DOMAIN, &(i as u64 + 900).to_le_bytes()])).collect();
    leaves[1] = sha256(&[&RECIP_DOMAIN, target]);
    merkle(&leaves, 1)
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
const NAMES: [&str; 10] =
    ["approver1", "approver2", "approver3", "approver4", "approver5", "approver6", "approver7", "approver8", "approver9", "approver10"];

struct RootPin {
    covid_hex: String,
    hash_hex: String,
    prefix_len: i64,
    state_len: i64,
    suffix_len: i64,
}
fn recovery_pk() -> [u8; 32] {
    xonly32(&kp(0x51))
}
fn root_pin() -> RootPin {
    RootPin {
        covid_hex: hexs(&COV_ROOT.as_bytes()[..]),
        hash_hex: hexs(&root_template_vm_hash()),
        prefix_len: root_prefix_len(),
        state_len: 467,
        suffix_len: root_suffix_len(),
    }
}
/* Root template geometry is measured once from a real compiled root
 * (contracts/PolicyVault.v0.7-root.sil is unchanged by this lane; the
 * numbers match tests/vm/tests/v7_kas_production.rs's own measurement). */
fn root_template_vm_hash() -> [u8; 32] {
    let hex = "43a0388dbb92fe95953baa100e85215b9f78aa351e60a87521e02a28b3454459";
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
fn root_prefix_len() -> i64 {
    1
}
fn root_suffix_len() -> i64 {
    11_077
}

fn templated_source(s: &S) -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.7-kas.sil", env!("CARGO_MANIFEST_DIR"));
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
fn ctor_args_json(s: &S) -> String {
    let pin = root_pin();
    let bytes = |hex: &str| -> Vec<u8> { (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect() };
    let pk = |b: &[u8]| serde_json::json!({ "kind": "array", "data": b.iter().map(|x| serde_json::json!({"kind":"byte","data":*x})).collect::<Vec<_>>() });
    let int = |v: i64| serde_json::json!({ "kind": "int", "data": v });
    let vault_id = bytes(VAULT_ID_HEX);
    let mut a = vec![
        pk(&vault_id),
        pk(&bytes(&pin.covid_hex)),
        pk(&bytes(&pin.hash_hex)),
        int(pin.prefix_len),
        int(pin.state_len),
        int(pin.suffix_len),
        pk(&recovery_pk()),
        pk(&s.agent_root),
        int(s.reserve),
    ];
    for i in 0..10 {
        a.push(pk(&s.approvers[i]));
    }
    a.push(int(s.approval_m));
    a.push(int(s.protected));
    serde_json::to_string_pretty(&serde_json::Value::Array(a)).unwrap()
}
fn ctor_exprs(s: &S) -> Vec<Expr<'static>> {
    let pin = root_pin();
    let bytes = |hex: &str| -> Vec<u8> { (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect() };
    let vid: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&VAULT_ID_HEX[i * 2..i * 2 + 2], 16).unwrap()).collect();
    let mut a = vec![
        Expr::bytes(vid),
        Expr::bytes(bytes(&pin.covid_hex)),
        Expr::bytes(bytes(&pin.hash_hex)),
        Expr::int(pin.prefix_len),
        Expr::int(pin.state_len),
        Expr::int(pin.suffix_len),
        Expr::bytes(recovery_pk().to_vec()),
        Expr::bytes(s.agent_root.to_vec()),
        Expr::int(s.reserve),
    ];
    for i in 0..10 {
        a.push(Expr::bytes(s.approvers[i].to_vec()));
    }
    a.push(Expr::int(s.approval_m));
    a.push(Expr::int(s.protected));
    a
}
fn compile_state(s: &S) -> CompiledContract<'static> {
    let src: &'static str = Box::leak(templated_source(s).into_boxed_str());
    compile_contract(src, &ctor_exprs(s), CompileOptions::default()).expect("v0.7-kas compile")
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

/* ---------------- transaction plumbing (mirrors v4_1_encoder_integration) */

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
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::ComputeBudget(ComputeBudget(budget)),
    }
}
fn p2pk_spk(pk: &[u8; 32]) -> ScriptPublicKey {
    ScriptPublicKey::new(0, ScriptBuilder::new().add_data(pk).unwrap().add_op(OpCheckSig).unwrap().drain().into())
}
fn p2pk_output(pk: &[u8; 32], value: u64) -> TransactionOutput {
    TransactionOutput { value, script_public_key: p2pk_spk(pk), covenant: None }
}
fn active_utxo(c: &CompiledContract<'_>, value: u64) -> UtxoEntry {
    UtxoEntry::new(value, pay_to_script_hash_script(&c.script), 0, false, Some(COV_VAULT))
}
fn push_redeem(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() }).add_data(script).unwrap().drain()
}

fn encode_via_binary(prev: &S, call: &serde_json::Value) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir().join(format!("pv7kasenc-{}", rand_suffix()));
    fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("PolicyVault.state.sil");
    let args_path = dir.join("constructor-args.json");
    let call_path = dir.join("call.json");
    fs::write(&source_path, templated_source(prev)).unwrap();
    fs::write(&args_path, ctor_args_json(prev)).unwrap();
    fs::write(&call_path, serde_json::to_string(call).unwrap()).unwrap();
    let out = Command::new(encoder_path()).arg(&source_path).arg(&args_path).arg(&call_path).output().expect("run encoder");
    let _ = fs::remove_dir_all(&dir);
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let hex = String::from_utf8(out.stdout).unwrap().trim().to_string();
    Ok((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect())
}

fn agent(k: &Keypair, cap: i64, budget: i64, threshold: i64, fee_cap: i64, rroot: [u8; 32]) -> Agent {
    Agent {
        pk: xonly32(k),
        max_per_spend: cap,
        period_budget: budget,
        period_length_daa: 864_000,
        period_start_daa: 541_000_000,
        period_spent: 0,
        approval_threshold: threshold,
        max_fee_per_tx: fee_cap,
        recipient_root: rroot,
    }
}

/* ---------------- delegate spend via the production BINARY ------------- */

#[allow(clippy::too_many_arguments)]
fn run_agent_spend_via_binary(
    prev: &S,
    claim: &Agent,
    pay: i64,
    reserve_consumed: i64,
    policy_sibs: &[u8],
    policy_bits: u64,
    recipient_leaf_pk: &[u8; 32],
    recipient_out_pk: &[u8; 32],
    recip_sibs: &[u8],
    recip_bits: u64,
    new_root: [u8; 32],
    signer: &Keypair,
    signer_type: SigHashType,
    mutate_call: impl FnOnce(&mut serde_json::Value),
) -> Result<(), TxScriptError> {
    let succ = S { protected: prev.protected - pay, reserve: prev.reserve - reserve_consumed, agent_root: new_root, ..prev.clone() };
    let active = compile_state(prev);
    let succ_c = compile_state(&succ);

    let inputs = vec![cov_input(400)];
    let entries = vec![active_utxo(&active, (prev.protected + prev.reserve) as u64)];
    let outputs = vec![
        p2pk_output(recipient_out_pk, pay as u64),
        TransactionOutput {
            value: (succ.protected + succ.reserve) as u64,
            script_public_key: pay_to_script_hash_script(&succ_c.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_VAULT }),
        },
    ];
    let tx = Transaction::new(1, inputs, outputs.clone(), 0, SubnetworkId::default(), 0, vec![]);
    let mutable = MutableTransaction::with_entries(tx.clone(), entries.clone());
    let agent_sig = sign_typed(&mutable, 0, signer, signer_type);
    let blob: Vec<u8> = (0..10).flat_map(|_| placeholder()).collect();

    let mut call = serde_json::json!({
        "contractVersion": "policyvault-0.7-kas",
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
        "periodsElapsed": "0",
        "recipientPk": hexs(recipient_leaf_pk),
        "recipientSiblings": hexs(recip_sibs),
        "recipientPathBits": recip_bits,
        "approvals": hexs(&blob),
    });
    mutate_call(&mut call);
    let call_bytes = match encode_via_binary(prev, &call) {
        Ok(b) => b,
        Err(stderr) => return Err(TxScriptError::InvalidState(format!("ENCODER_REJECTED: {stderr}"))),
    };
    let mut sigscript = call_bytes;
    sigscript.extend_from_slice(&push_redeem(&active.script));
    let mut t = tx;
    t.inputs[0].signature_script = sigscript;
    execute_input_measured(t, entries, 0).0
}

#[test]
fn v7kasenc_honest_agent_spend_via_production_binary() {
    let a = kp(0x30);
    let recipient = kp(0x40);
    let claim = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, ZERO32);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly32(&recipient));
    let real_claim = Agent { recipient_root: rroot, ..claim.clone() };
    let leaves = vec![agent_leaf(&real_claim)];
    let (root, psibs, pbits) = merkle(&leaves, 0);
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let pay = 40 * KAS;
    let mut np = real_claim.clone();
    np.period_spent += pay;
    let new_leaves = vec![agent_leaf(&np)];
    let (new_root, _, _) = merkle(&new_leaves, 0);
    let r = run_agent_spend_via_binary(&prev, &real_claim, pay, 5_000_000, &psibs, pbits, &xonly32(&recipient), &xonly32(&recipient), &rsibs, rbits, new_root, &a, SIG_HASH_ALL, |_| {});
    r.unwrap_or_else(|e| panic!("honest v0.7-kas agentSpend via the production binary must accept: {e:?}"));
}

#[test]
fn v7kasenc_agent_spend_mutation_matrix() {
    let a = kp(0x30);
    let recipient = kp(0x40);
    let other = kp(0x41);
    let claim = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, ZERO32);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly32(&recipient));
    let real_claim = Agent { recipient_root: rroot, ..claim.clone() };
    let leaves = vec![agent_leaf(&real_claim)];
    let (root, psibs, pbits) = merkle(&leaves, 0);
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let pay = 40 * KAS;
    let mut np = real_claim.clone();
    np.period_spent += pay;
    let new_leaves = vec![agent_leaf(&np)];
    let (new_root, _, _) = merkle(&new_leaves, 0);

    let cases: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        ("recipient substitution", Box::new(|c: &mut serde_json::Value| c["recipientPk"] = serde_json::json!(hexs(&xonly32(&other))))),
        ("forged successor root (unchanged)", Box::new(move |c: &mut serde_json::Value| c["successor"]["agentRoot"] = serde_json::json!(hexs(&root)))),
        ("payAmount above cap", Box::new(|c: &mut serde_json::Value| c["payAmount"] = serde_json::json!((101 * KAS).to_string()))),
    ];

    for (label, mutate) in cases {
        let r = run_agent_spend_via_binary(&prev, &real_claim, pay, 5_000_000, &psibs, pbits, &xonly32(&recipient), &xonly32(&recipient), &rsibs, rbits, new_root, &a, SIG_HASH_ALL, |c| mutate(c));
        assert!(r.is_err(), "{label}: must be REFUSED (encoder-level or VM-level) via the production binary");
        println!("v7-kas encoder mutation REFUSED: {label} -> {r:?}");
    }
}

#[test]
fn v7kasenc_non_all_agent_sighash_is_refused() {
    // v0.7-kas candidate hardening E6(a) (requireAgentAuthorization, parity
    // with the already-proven gate in contracts/PolicyVault.v0.6.sil):
    // UNLIKE the frozen v0.4.1 base and the frozen v0.7-payment profile
    // (whose agentSig carries no sighash-type gate at all — documented,
    // verified-safe THERE because the outputs are bound structurally
    // regardless of what the signature covers), this profile now REQUIRES
    // the agent's own signature to be SIG_HASH_ALL (trailing byte 0x01),
    // exactly the A7 gate already applied to the 10 approval slots. Driven
    // through the real production BINARY, not the in-process encoder.
    let a = kp(0x30);
    let recipient = kp(0x40);
    let claim = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, ZERO32);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly32(&recipient));
    let real_claim = Agent { recipient_root: rroot, ..claim.clone() };
    let leaves = vec![agent_leaf(&real_claim)];
    let (root, psibs, pbits) = merkle(&leaves, 0);
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let pay = 40 * KAS;
    let mut np = real_claim.clone();
    np.period_spent += pay;
    let new_leaves = vec![agent_leaf(&np)];
    let (new_root, _, _) = merkle(&new_leaves, 0);
    let r = run_agent_spend_via_binary(
        &prev,
        &real_claim,
        pay,
        5_000_000,
        &psibs,
        pbits,
        &xonly32(&recipient),
        &xonly32(&recipient),
        &rsibs,
        rbits,
        new_root,
        &a,
        SIG_HASH_NONE,
        |_| {},
    );
    assert!(r.is_err(), "E6(a): a non-ALL agent signature must now be REFUSED via the production binary, got {r:?}");
    println!("v7-kas: a non-ALL agent signature is now REFUSED via the production binary (E6(a)): {r:?}");
}

#[test]
fn v7kasenc_agent_sighash_all_positive_control_still_accepts() {
    // Positive control paired with the refusal above: the SAME shape, with a
    // genuine SIG_HASH_ALL agent signature, must still accept via the
    // production binary.
    let a = kp(0x30);
    let recipient = kp(0x40);
    let claim = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, ZERO32);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly32(&recipient));
    let real_claim = Agent { recipient_root: rroot, ..claim.clone() };
    let leaves = vec![agent_leaf(&real_claim)];
    let (root, psibs, pbits) = merkle(&leaves, 0);
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let pay = 40 * KAS;
    let mut np = real_claim.clone();
    np.period_spent += pay;
    let new_leaves = vec![agent_leaf(&np)];
    let (new_root, _, _) = merkle(&new_leaves, 0);
    let r = run_agent_spend_via_binary(
        &prev, &real_claim, pay, 5_000_000, &psibs, pbits, &xonly32(&recipient), &xonly32(&recipient), &rsibs, rbits, new_root, &a,
        SIG_HASH_ALL, |_| {},
    );
    r.unwrap_or_else(|e| panic!("positive control: a genuine SIG_HASH_ALL agent signature must accept via the production binary: {e:?}"));
}

#[test]
fn v7kasenc_forged_agent_sig_gate_byte_is_refused() {
    // Sign with a real SIG_HASH_ALL signature (the 64-byte body is genuine),
    // then forge only the trailing gate byte of the hex "signature" call
    // field before it reaches the encoder binary. The encoder itself only
    // length-checks (65 bytes); the covenant's requireAgentAuthorization must
    // be the one that reads the actual trailing byte and refuses.
    let a = kp(0x30);
    let recipient = kp(0x40);
    let claim = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS, ZERO32);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly32(&recipient));
    let real_claim = Agent { recipient_root: rroot, ..claim.clone() };
    let leaves = vec![agent_leaf(&real_claim)];
    let (root, psibs, pbits) = merkle(&leaves, 0);
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let pay = 40 * KAS;
    let mut np = real_claim.clone();
    np.period_spent += pay;
    let new_leaves = vec![agent_leaf(&np)];
    let (new_root, _, _) = merkle(&new_leaves, 0);
    let r = run_agent_spend_via_binary(
        &prev,
        &real_claim,
        pay,
        5_000_000,
        &psibs,
        pbits,
        &xonly32(&recipient),
        &xonly32(&recipient),
        &rsibs,
        rbits,
        new_root,
        &a,
        SIG_HASH_ALL,
        |c: &mut serde_json::Value| {
            let mut sig_hex = c["signature"].as_str().expect("signature present").to_string();
            assert_eq!(sig_hex.len(), 130, "sanity: 65-byte hex signature");
            assert_eq!(&sig_hex[128..130], "01", "sanity: forging test must start from a real SIG_HASH_ALL trailing byte");
            sig_hex.replace_range(128..130, "02");
            c["signature"] = serde_json::json!(sig_hex);
        },
    );
    assert!(r.is_err(), "E6(a): a forged (non-0x01) trailing gate byte must be REFUSED even over an ALL-computed signature, got {r:?}");
    println!("v7-kas: forged agent-sig gate byte REFUSED via the production binary (E6(a)): {r:?}");
}

#[test]
fn v7kasenc_owner_control_opselector_out_of_range_refused_by_the_encoder_itself() {
    // The encoder's own bound check (0..6) must reject BEFORE any VM
    // execution — a caller error, not a covenant-level ambiguity.
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: ZERO32, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let succ = S { agent_root: [0x99; 32], policy_nonce: 1, ..prev.clone() };
    let call = serde_json::json!({
        "contractVersion": "policyvault-0.7-kas",
        "function": "ownerControl",
        "successor": successor_json(&succ),
        "opSelector": 7,
    });
    let err = encode_via_binary(&prev, &call).expect_err("opSelector 7 must be refused by the encoder");
    println!("v0.7-kas encoder correctly refused opSelector 7: {err}");
    assert!(err.contains("out of range"), "expected an out-of-range refusal, got: {err}");
}

#[test]
fn v7kasenc_owner_paths_carrying_a_signature_are_refused_by_the_encoder() {
    let prev = S { protected: 10_000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: ZERO32, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 };
    let succ = S { paused: 1, ..prev.clone() };
    let call = serde_json::json!({
        "contractVersion": "policyvault-0.7-kas",
        "function": "ownerControl",
        "successor": successor_json(&succ),
        "opSelector": 4,
        "signature": hexs(&placeholder()),
    });
    let err = encode_via_binary(&prev, &call).expect_err("ownerControl must not accept a signature (the root input is the authority)");
    println!("v0.7-kas encoder correctly refused a signed ownerControl call: {err}");
}
