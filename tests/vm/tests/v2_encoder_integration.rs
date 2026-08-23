//! VM layer — production-encoder ABI integration coverage (closes the
//! boundVaultId blind spot).
//!
//! For every v0.2 entrypoint this test builds the call the way the SDK does
//! — writing the exact-live-state source + constructor-args and invoking the
//! REAL `pv_call_encoder` binary — then executes the resulting sigscript on
//! the real TxScriptEngine. It never builds the newState struct in-process
//! (`v2_state_arg`), because that is exactly the path that let the
//! constructor-index defect ship while every VM test passed.
//!
//! Acceptance proves every field (boundVaultId, owner-authority, delegate,
//! all accounting/policy fields, signatures, successor value) landed in the
//! correct covenant position: any misplacement fails a covenant `require`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use policyvault_vm_tests::*;

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript_errors::TxScriptError;

const KAS: i64 = 100_000_000;
const VAULT_ID_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn encoder_path() -> PathBuf {
    PathBuf::from(format!("{}/policyvault/tests/vm/target/debug/pv_call_encoder", std::env::var("HOME").unwrap()))
}

fn hexs(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Emit constructor-args.json in the SDK's exact {kind,data} dialect so the
/// encoder reads the same bytes it reads in production.
fn ctor_args_json(template: &V2Template, state: &V2State) -> String {
    let pk = |b: &[u8]| -> serde_json::Value {
        serde_json::json!({ "kind": "array", "data": b.iter().map(|x| serde_json::json!({"kind":"byte","data":*x})).collect::<Vec<_>>() })
    };
    let int = |v: i64| serde_json::json!({ "kind": "int", "data": v });
    let vault_id: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&VAULT_ID_HEX[i * 2..i * 2 + 2], 16).unwrap()).collect();
    serde_json::to_string_pretty(&serde_json::json!([
        pk(&template.owner_pk),
        pk(&vault_id),
        pk(&state.delegate_pk),
        int(state.max_per_spend),
        int(state.period_budget),
        int(state.period_length_daa),
        pk(&state.recipient1_pk),
        pk(&state.recipient2_pk),
        pk(&state.recipient3_pk),
        int(state.protected_value),
        int(state.period_start_daa),
    ]))
    .unwrap()
}

/// The successor object in the encoder's call.json format.
fn successor_json(s: &V2State) -> serde_json::Value {
    serde_json::json!({
        "protectedValue": s.protected_value.to_string(),
        "periodStartDaa": s.period_start_daa.to_string(),
        "periodSpent": s.period_spent.to_string(),
        "paused": s.paused,
        "delegate": hexs(&s.delegate_pk),
        "maxPerSpend": s.max_per_spend.to_string(),
        "periodBudget": s.period_budget.to_string(),
        "periodLengthDaa": s.period_length_daa.to_string(),
        "recipient1": hexs(&s.recipient1_pk),
        "recipient2": hexs(&s.recipient2_pk),
        "recipient3": hexs(&s.recipient3_pk),
        "delegateActive": s.delegate_active,
        "policyNonce": s.policy_nonce.to_string(),
    })
}

fn sign_input(mutable: &MutableTransaction<Transaction>, idx: usize, kp: &secp256k1::Keypair) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&mutable.as_verifiable(), idx, SIG_HASH_ALL, &reused);
    let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap();
    let sig = kp.sign_schnorr(msg);
    let mut out = sig.as_ref().to_vec();
    out.push(SIG_HASH_ALL.to_u8());
    out
}

struct Case {
    function: &'static str,
    /// Extra top-level fields merged into the call json (payAmount, etc.).
    extra: serde_json::Value,
    /// Successor state (None => ownerRecover, empty nextStates).
    successor: Option<V2State>,
    /// Optional payment output prepended (recipient pk, value).
    payment: Option<([u8; 32], u64)>,
    /// Terminal owner-recover payout instead of a successor covenant output.
    recover_owner: Option<[u8; 32]>,
    lock_time: u64,
    signer: secp256k1::Keypair,
}

/// Build tx + sign + encode via the REAL pv_call_encoder + execute on VM.
fn run_via_encoder(template: &V2Template, prev: &V2State, case: Case) -> Result<(), TxScriptError> {
    let active = compile_v2_state_with_vault_id(template, prev, VAULT_ID_HEX);

    // Write the exact encoder inputs the SDK writes.
    let dir = std::env::temp_dir().join(format!("pv2enc-{}-{}", std::process::id(), rand_suffix()));
    fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("PolicyVault.state.sil");
    let args_path = dir.join("constructor-args.json");
    fs::write(&source_path, v2_templated_source(prev)).unwrap();
    fs::write(&args_path, ctor_args_json(template, prev)).unwrap();

    // Outputs: [payment?] successor|owner-payout, change.
    let mut outputs = Vec::new();
    if let Some((pk, v)) = case.payment {
        outputs.push(p2pk_output(&pk, v));
    }
    let fuel_value: u64 = 10 * KAS as u64;
    match (&case.successor, &case.recover_owner) {
        (Some(next_state), None) => {
            let next = compile_v2_state_with_vault_id(template, next_state, VAULT_ID_HEX);
            outputs.push(TransactionOutput {
                value: next_state.protected_value as u64,
                script_public_key: pay_to_script_hash_script(&next.script),
                covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
            });
        }
        (None, Some(owner_pk)) => {
            outputs.push(p2pk_output(owner_pk, prev.protected_value as u64));
        }
        _ => panic!("exactly one of successor / recover_owner"),
    }
    // Ordinary change (fuel input minus a nominal fee).
    let delegate_p2pk = ScriptBuilder::new().add_data(&case.signer_change_pk()).unwrap().add_op(OpCheckSig).unwrap().drain();
    outputs.push(TransactionOutput { value: fuel_value - 1_100_000, script_public_key: ScriptPublicKey::new(0, delegate_p2pk.clone().into()), covenant: None });

    let cov_input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeBudget(20).into(),
    };
    let fuel_input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x43; 32]), index: 1 },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeBudget(10).into(),
    };
    let tx = Transaction::new(1, vec![cov_input, fuel_input], outputs, case.lock_time, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, prev.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, ScriptPublicKey::new(0, delegate_p2pk.into()), 0, false, None);
    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);

    // Sign input 0 and build the call.json exactly like the SDK.
    let sig0 = sign_input(&mutable, 0, &case.signer);
    let mut call = serde_json::json!({
        "contractVersion": "policyvault-0.2",
        "function": case.function,
        "signature": hexs(&sig0),
    });
    if let Some(next_state) = &case.successor {
        call["successor"] = successor_json(next_state);
    }
    if let serde_json::Value::Object(extra) = &case.extra {
        for (k, v) in extra {
            call[k] = v.clone();
        }
    }
    let call_path = dir.join("call.json");
    fs::write(&call_path, serde_json::to_string(&call).unwrap()).unwrap();

    let out = Command::new(encoder_path())
        .arg(&source_path)
        .arg(&args_path)
        .arg(&call_path)
        .output()
        .expect("run pv_call_encoder");
    assert!(out.status.success(), "encoder failed: {}", String::from_utf8_lossy(&out.stderr));
    let call_hex = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let call_bytes: Vec<u8> = (0..call_hex.len()).step_by(2).map(|i| u8::from_str_radix(&call_hex[i..i + 2], 16).unwrap()).collect();

    let mut sigscript = call_bytes;
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;

    let result = execute_input_with_covenants(mutable.tx, vec![cov_utxo, fuel_utxo], 0);
    let _ = fs::remove_dir_all(&dir);
    result
}

impl Case {
    fn signer_change_pk(&self) -> [u8; 32] {
        xonly(&self.signer)
    }
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
}

// ---------------------------------------------------------------- fixtures

fn fixture() -> (V2Template, V2State, secp256k1::Keypair, secp256k1::Keypair, secp256k1::Keypair, secp256k1::Keypair) {
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let delegate2 = deterministic_keypair(7);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let template = V2Template { owner_pk: xonly(&owner) };
    let mut state = test_v2_state(&delegate, [&r1, &r2, &r3]);
    state.period_start_daa = 542_000_000;
    (template, state, owner, delegate, delegate2, r1)
}

// ---------------------------------------------------------------- tests

#[test]
fn enc_delegate_spend() {
    let (t, s, _o, d, _d2, r1) = fixture();
    let amount = 25 * KAS;
    let succ = V2State { protected_value: s.protected_value - amount, period_spent: s.period_spent + amount, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case {
        function: "delegateSpend",
        extra: serde_json::json!({ "payAmount": amount.to_string(), "recipientIndex": 1 }),
        successor: Some(succ),
        payment: Some((xonly(&r1), amount as u64)),
        recover_owner: None,
        lock_time: 0,
        signer: d,
    });
    assert!(res.is_ok(), "delegateSpend via production encoder must verify: {res:?}");
}

#[test]
fn enc_rollover_and_spend() {
    let (t, mut s, _o, d, _d2, r1) = fixture();
    s.period_spent = 45 * KAS;
    let amount = 30 * KAS;
    let periods = 2i64;
    let new_start = s.period_start_daa + periods * s.period_length_daa;
    let succ = V2State { protected_value: s.protected_value - amount, period_start_daa: new_start, period_spent: amount, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case {
        function: "rolloverAndSpend",
        extra: serde_json::json!({ "payAmount": amount.to_string(), "recipientIndex": 1, "periodsElapsed": periods.to_string() }),
        successor: Some(succ),
        payment: Some((xonly(&r1), amount as u64)),
        recover_owner: None,
        lock_time: new_start as u64,
        signer: d,
    });
    assert!(res.is_ok(), "rolloverAndSpend via production encoder must verify: {res:?}");
}

#[test]
fn enc_pause_and_unpause() {
    let (t, s, o, _d, _d2, _r1) = fixture();
    let paused = V2State { paused: 1, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case { function: "ownerPause", extra: serde_json::json!({}), successor: Some(paused.clone()), payment: None, recover_owner: None, lock_time: 0, signer: o });
    assert!(res.is_ok(), "ownerPause via encoder: {res:?}");
    let active = V2State { paused: 0, ..paused.clone() };
    let res = run_via_encoder(&t, &paused, Case { function: "ownerUnpause", extra: serde_json::json!({}), successor: Some(active), payment: None, recover_owner: None, lock_time: 0, signer: o });
    assert!(res.is_ok(), "ownerUnpause via encoder: {res:?}");
}

#[test]
fn enc_revoke() {
    let (t, s, o, _d, _d2, _r1) = fixture();
    let revoked = V2State { delegate_active: 0, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case { function: "revokeDelegate", extra: serde_json::json!({}), successor: Some(revoked), payment: None, recover_owner: None, lock_time: 0, signer: o });
    assert!(res.is_ok(), "revokeDelegate via encoder: {res:?}");
}

#[test]
fn enc_rotate() {
    let (t, s, o, _d, d2, _r1) = fixture();
    let rotated = V2State { delegate_pk: xonly(&d2), delegate_active: 1, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case {
        function: "rotateDelegate",
        extra: serde_json::json!({ "newDelegate": hexs(&xonly(&d2)) }),
        successor: Some(rotated),
        payment: None,
        recover_owner: None,
        lock_time: 0,
        signer: o,
    });
    assert!(res.is_ok(), "rotateDelegate via encoder: {res:?}");
}

#[test]
fn enc_topup() {
    let (t, s, o, _d, _d2, _r1) = fixture();
    let topped = V2State { protected_value: s.protected_value + 500 * KAS, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case { function: "ownerTopUp", extra: serde_json::json!({}), successor: Some(topped), payment: None, recover_owner: None, lock_time: 0, signer: o });
    assert!(res.is_ok(), "ownerTopUp via encoder: {res:?}");
}

#[test]
fn enc_migrate() {
    let (t, s, o, _d, _d2, _r1) = fixture();
    let migrated = V2State { max_per_spend: 200 * KAS, period_budget: 1000 * KAS, policy_nonce: 1, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case { function: "migratePolicy", extra: serde_json::json!({}), successor: Some(migrated), payment: None, recover_owner: None, lock_time: 0, signer: o });
    assert!(res.is_ok(), "migratePolicy via encoder: {res:?}");
}

#[test]
fn enc_recover() {
    let (t, s, o, _d, _d2, _r1) = fixture();
    let res = run_via_encoder(&t, &s, Case { function: "ownerRecover", extra: serde_json::json!({}), successor: None, payment: None, recover_owner: Some(t.owner_pk), lock_time: 0, signer: o });
    assert!(res.is_ok(), "ownerRecover via encoder: {res:?}");
}

/// The boundVaultId regression: if the encoder pulled boundVaultId from the
/// wrong constructor index, this would VerifyError (as it did live).
#[test]
fn enc_boundvaultid_lands_correctly() {
    // Covered implicitly by every case above (all preserve boundVaultId),
    // but assert explicitly on the cheapest owner path.
    let (t, s, o, _d, _d2, _r1) = fixture();
    let revoked = V2State { delegate_active: 0, ..s.clone() };
    let res = run_via_encoder(&t, &s, Case { function: "revokeDelegate", extra: serde_json::json!({}), successor: Some(revoked), payment: None, recover_owner: None, lock_time: 0, signer: o });
    assert!(res.is_ok(), "boundVaultId must land at the vaultId, not the delegate key: {res:?}");
}
