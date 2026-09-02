//! VM layer — v0.5 SDK PRODUCTION-BYTE integration.
//!
//! Runs the ACTUAL PolicyVault SDK (node: core/assets, token-program-kcc20
//! via silverc on the vendored KCC20 reference program, vault-state-v5,
//! contract-compiler-v5, agent-merkle-v5, recipient-merkle-v3,
//! vault-transitions-v5, compute-budget-v5, frozen-tx-v3, vault-builders-v5,
//! the real pv_call_encoder (v0.5 + kcc20/1 arms) AND pv_tx_probe) to
//! construct fully-finalized v0.5 transactions with real Schnorr
//! signatures, then executes EVERY input of every emitted vector's EXACT
//! bytes on the real TxScriptEngine against the PRODUCTION
//! PolicyVault.v0.5.sil and the token family's own program.
//!
//! Accept vectors run under PRODUCTION sig-op pricing with the SDK's OWN
//! committed compute budgets (controller AND token input); reject vectors
//! (post-finalize single-field mutations the SDK refuses to build) must be
//! rejected by consensus. The SDK's own pre-build refusals are asserted by
//! the generator itself (it exits non-zero if any expected refusal is
//! missing).

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use policyvault_vm_tests::{execute_input_measured_priced, execute_input_with_covenants};

use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_consensus_core::Hash;

fn repo_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

fn vectors_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("pv5-sdk-vectors-{}", std::process::id()));
        let generator = format!("{}/sdk/tools/gen-v5-vectors.js", repo_root());
        let out = Command::new("node").arg(&generator).arg(&dir).output().expect("run the SDK vector generator (node)");
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
    assert_eq!(bytes.len(), 32);
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

fn parse_vector_tx(v: &serde_json::Value) -> (Transaction, Vec<UtxoEntry>) {
    assert_eq!(ju64(&v["version"]), 1);
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for input in v["inputs"].as_array().expect("inputs") {
        let op = &input["previousOutpoint"];
        inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: hex32(op["transactionId"].as_str().unwrap()), index: ju64(&op["index"]) as u32 },
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
        entries.push(UtxoEntry::new(ju64(&utxo["amount"]), parse_spk(&utxo["scriptPublicKey"]), ju64(&utxo["blockDaaScore"]), false, covenant_id));
    }
    let mut outputs = Vec::new();
    for output in v["outputs"].as_array().expect("outputs") {
        let covenant = match &output["covenant"] {
            serde_json::Value::Null => None,
            obj => Some(CovenantBinding { authorizing_input: ju64(&obj["authorizingInput"]) as u16, covenant_id: hex32(obj["covenantId"].as_str().unwrap()) }),
        };
        outputs.push(TransactionOutput { value: ju64(&output["value"]), script_public_key: parse_spk(&output["scriptPublicKey"]), covenant });
    }
    let tx = Transaction::new(1, inputs, outputs, ju64(&v["lockTime"]), SUBNETWORK_ID_NATIVE, ju64(&v["gas"]), hex_bytes(v["payload"].as_str().unwrap_or("")));
    (tx, entries)
}

struct Vector {
    name: String,
    expect_accept: bool,
    action: String,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

fn load_vectors() -> Vec<Vector> {
    let dir = vectors_dir();
    let index: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("index.json")).expect("index.json")).expect("index json");
    let refusals = index["refusals"].as_array().expect("refusals");
    assert!(refusals.len() >= 15, "expected the SDK refusal matrix, got {}", refusals.len());
    for r in refusals {
        assert_eq!(r["refused"].as_bool(), Some(true), "SDK refusal {} must have refused", r["name"]);
    }
    let mut vectors = Vec::new();
    for entry in index["vectors"].as_array().expect("vectors") {
        let name = entry["name"].as_str().unwrap().to_string();
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join(&name).join("vector.json")).unwrap()).unwrap();
        let expect_accept = match doc["expect"].as_str().unwrap() {
            "accept" => true,
            "reject" => false,
            other => panic!("unknown expect {other:?}"),
        };
        let (tx, entries) = parse_vector_tx(&doc["tx"]);
        vectors.push(Vector { name, expect_accept, action: doc["action"].as_str().unwrap_or("").to_string(), tx, entries });
    }
    assert!(vectors.len() >= 18, "expected the full vector matrix, got {}", vectors.len());
    vectors
}

/// EVERY input of every accept vector executes under PRODUCTION pricing
/// within the SDK's own committed budget; every reject vector is refused
/// by consensus on the controller input.
#[test]
fn v5_sdk_vectors_execute_on_production_covenant() {
    let vectors = load_vectors();
    let (mut accepted, mut rejected) = (0, 0);
    for v in &vectors {
        if v.expect_accept {
            for i in 0..v.tx.inputs.len() {
                let (res, units) = execute_input_measured_priced(v.tx.clone(), v.entries.clone(), i, 1000);
                assert!(res.is_ok(), "vector {} input {i} must execute under production pricing: {res:?}", v.name);
                let committed = v.tx.inputs[i].compute_commit.compute_budget().expect("v1 budget") as u64;
                let required = ComputeBudget::checked_covering_script_units(units.into()).expect("budget").0 as u64;
                assert!(required <= committed, "vector {} input {i}: used {units} units require budget {required} > committed {committed}", v.name);
                println!("SDKVEC5 {} input {i} accept used_units={units} required_budget={required} committed={committed}", v.name);
            }
            accepted += 1;
        } else {
            let res = execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0);
            assert!(res.is_err(), "vector {} must be REJECTED by consensus but was accepted", v.name);
            println!("SDKVEC5 {} rejected as required ({})", v.name, v.action);
            rejected += 1;
        }
    }
    println!("SDKVEC5 total accepted={accepted} rejected={rejected}");
    assert!(accepted >= 10 && rejected >= 8, "unexpected vector distribution: {accepted} accepts, {rejected} rejects");
}

/// The genesis transaction is plain (no covenant input) — its funding
/// input must execute and its controller output must be covenant-bound.
#[test]
fn v5_sdk_genesis_shape() {
    let vectors = load_vectors();
    let v = vectors.iter().find(|v| v.name == "genesis_controller").expect("genesis vector present");
    assert!(execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0).is_ok());
    assert!(v.tx.outputs[0].covenant.is_some(), "controller output must carry a covenant binding");
}
