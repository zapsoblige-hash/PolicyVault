//! VM layer — v0.3 SDK PRODUCTION-BYTE integration (Phase 4H §19/§20).
//!
//! Runs the ACTUAL PolicyVault SDK (node: vault-state-v3, exact-state
//! compiler via silverc, recipient-merkle-v3, vault-transitions-v3,
//! compute-budget-v3, frozen-tx-v3, approval-package-v3,
//! vault-builders-v3, the real pv_call_encoder AND pv_tx_probe binaries)
//! to construct fully-finalized v0.3 transactions with real Schnorr
//! signatures, then executes every emitted vector's EXACT bytes on the
//! real TxScriptEngine against the production covenant.
//!
//! This is the entire SDK construction path driven through the downstream
//! consensus validator — the production-byte rule applied end to end, not
//! just to the encoder (the v0.2 boundVaultId lesson).
//!
//! Accept vectors are executed under PRODUCTION sig-op pricing with the
//! SDK's OWN committed compute budget, proving the committed budget is
//! sufficient for every supported shape (incl. depth16 + 10-of-10).

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use policyvault_vm_tests::{execute_input_measured_priced, execute_input_with_covenants};

use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;

fn home() -> String {
    std::env::var("HOME").expect("HOME")
}

/// Generate the SDK vectors exactly once per test process.
fn vectors_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("pv3-sdk-vectors-{}", std::process::id()));
        let generator = format!("{}/policyvault/sdk/tools/gen-v3-vectors.js", home());
        let out = Command::new("node")
            .arg(&generator)
            .arg(&dir)
            .output()
            .expect("run the SDK vector generator (node)");
        assert!(
            out.status.success(),
            "SDK vector generation failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        dir
    })
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0 && value.chars().all(|c| c.is_ascii_hexdigit()), "bad hex in vector: {value:?}");
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}

fn hex32(value: &str) -> Hash {
    let bytes = hex_bytes(value);
    assert_eq!(bytes.len(), 32, "expected 32-byte hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Hash::from_bytes(arr)
}

fn ju64(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::String(s) => s.parse().expect("u64 digit string"),
        serde_json::Value::Number(n) => n.as_u64().expect("u64"),
        _ => panic!("expected u64 field, got {v:?}"),
    }
}

fn parse_spk(v: &serde_json::Value) -> ScriptPublicKey {
    ScriptPublicKey::new(ju64(&v["version"]) as u16, hex_bytes(v["scriptHex"].as_str().expect("scriptHex")).into())
}

/// Parse a vector's final transaction JSON (the SDK's exact output,
/// signature scripts included) into a consensus Transaction + UtxoEntries.
fn parse_vector_tx(v: &serde_json::Value) -> (Transaction, Vec<UtxoEntry>) {
    assert_eq!(ju64(&v["version"]), 1, "v0.3 transactions are version 1");
    let native: &[u8] = SUBNETWORK_ID_NATIVE.as_ref();
    assert_eq!(hex_bytes(v["subnetworkId"].as_str().unwrap()), native, "native subnetwork required");

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for input in v["inputs"].as_array().expect("inputs") {
        let op = &input["previousOutpoint"];
        inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: hex32(op["transactionId"].as_str().expect("transactionId")),
                index: ju64(&op["index"]) as u32,
            },
            signature_script: hex_bytes(input["signatureScript"].as_str().expect("signatureScript")),
            sequence: ju64(&input["sequence"]),
            compute_commit: ComputeBudget(ju64(&input["computeBudget"]) as u16).into(),
        });
        let utxo = &input["utxo"];
        let covenant_id = match &utxo["covenantId"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => Some(hex32(s)),
            other => panic!("bad covenantId {other:?}"),
        };
        entries.push(UtxoEntry::new(
            ju64(&utxo["amount"]),
            parse_spk(&utxo["scriptPublicKey"]),
            ju64(&utxo["blockDaaScore"]),
            false,
            covenant_id,
        ));
    }

    let mut outputs = Vec::new();
    for output in v["outputs"].as_array().expect("outputs") {
        let covenant = match &output["covenant"] {
            serde_json::Value::Null => None,
            obj => Some(CovenantBinding {
                authorizing_input: ju64(&obj["authorizingInput"]) as u16,
                covenant_id: hex32(obj["covenantId"].as_str().expect("covenant covenantId")),
            }),
        };
        outputs.push(TransactionOutput { value: ju64(&output["value"]), script_public_key: parse_spk(&output["scriptPublicKey"]), covenant });
    }

    let tx = Transaction::new(
        1,
        inputs,
        outputs,
        ju64(&v["lockTime"]),
        SUBNETWORK_ID_NATIVE,
        ju64(&v["gas"]),
        hex_bytes(v["payload"].as_str().unwrap_or("")),
    );
    (tx, entries)
}

struct Vector {
    name: String,
    expect_accept: bool,
    committed_budget: u16,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

fn load_vectors() -> Vec<Vector> {
    let dir = vectors_dir();
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("index.json")).expect("index.json")).expect("index json");
    let mut vectors = Vec::new();
    for entry in index.as_array().expect("index array") {
        let name = entry["name"].as_str().expect("name").to_string();
        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(&name).join("vector.json")).unwrap_or_else(|e| panic!("vector {name}: {e}")),
        )
        .expect("vector json");
        let expect_accept = match doc["expect"].as_str().expect("expect") {
            "accept" => true,
            "reject" => false,
            other => panic!("vector {name}: unknown expect {other:?}"),
        };
        let committed_budget = doc["committedBudget"].as_u64().unwrap_or(0) as u16;
        let (tx, entries) = parse_vector_tx(&doc["tx"]);
        vectors.push(Vector { name, expect_accept, committed_budget, tx, entries });
    }
    assert!(vectors.len() >= 20, "expected a full vector matrix, got {}", vectors.len());
    vectors
}

/// EVERY SDK-built vector executes (or is rejected) exactly as declared,
/// on the real engine with covenants enabled. Accept vectors additionally
/// run under PRODUCTION sig-op pricing with the SDK's OWN committed
/// budget — proving the committed budget suffices for the exact shape.
#[test]
fn v3_sdk_vectors_execute_on_production_covenant() {
    let vectors = load_vectors();
    let mut accepted = 0;
    let mut rejected = 0;
    for v in &vectors {
        if v.expect_accept {
            // Production-priced execution under the SDK's committed budget.
            let (res, units) = execute_input_measured_priced(v.tx.clone(), v.entries.clone(), 0, 1000);
            assert!(res.is_ok(), "vector {} must execute under production pricing with its committed budget: {res:?}", v.name);
            let required = (units + 9_999) / 10_000;
            assert!(
                required <= v.committed_budget as u64,
                "vector {}: used {units} units require budget {required} > committed {}",
                v.name,
                v.committed_budget
            );
            println!("SDKVEC {} accept used_units={units} required_budget={required} committed={}", v.name, v.committed_budget);
            accepted += 1;
        } else {
            let res = execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0);
            assert!(res.is_err(), "vector {} must be REJECTED by consensus but was accepted", v.name);
            println!("SDKVEC {} rejected as required", v.name);
            rejected += 1;
        }
    }
    println!("SDKVEC total accepted={accepted} rejected={rejected}");
    assert!(accepted >= 15 && rejected >= 5, "unexpected vector distribution: {accepted} accepts, {rejected} rejects");
}

/// The true worst case (depth 16 + 10-of-10) must carry committed budget
/// >= 135 and execute under production pricing (Phase 4.5 measurement:
/// 1,349,839 script units).
#[test]
fn v3_sdk_worst_case_depth16_10of10_budget() {
    let vectors = load_vectors();
    let v = vectors.iter().find(|v| v.name == "worst_depth16_10of10").expect("worst-case vector present");
    assert!(v.committed_budget >= 135, "worst case must commit >= 135, got {}", v.committed_budget);
    let (res, units) = execute_input_measured_priced(v.tx.clone(), v.entries.clone(), 0, 1000);
    assert!(res.is_ok(), "worst case must execute: {res:?}");
    println!("SDKVEC worst_depth16_10of10 used_units={units} committed={}", v.committed_budget);
    assert!(units > 1_000_000, "worst case should consume >1M script units (sanity), got {units}");
}

/// ownerRecover from a malformed predecessor (duplicate approver keys,
/// M = 0, paused, revoked) — the SDK's break-glass construction must
/// execute: funds are never operationally trapped where consensus allows
/// recovery.
#[test]
fn v3_sdk_recover_from_malformed_state_executes() {
    let vectors = load_vectors();
    let v = vectors.iter().find(|v| v.name == "owner_recover_malformed_state").expect("malformed-recover vector present");
    let res = execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0);
    assert!(res.is_ok(), "SDK-built recovery from malformed state must execute: {res:?}");
}
