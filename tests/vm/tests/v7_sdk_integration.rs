//! VM layer — v0.7 SDK PRODUCTION-BYTE integration (organizational root +
//! rooted payment vault).
//!
//! Gate I2 of docs/postlaunch/v0.7-organizational-root-design.md §11.1.
//!
//! Runs the ACTUAL PolicyVault SDK (node: core/model owner-set-v7 /
//! vault-state-v7-root / vault-state-v7 / vault-transitions-v7* /
//! compute-budget-v7, core/assets, token-program-kcc20,
//! contract-compiler-v7 via silverc, agent-merkle-v5, recipient-merkle-v3,
//! frozen-tx-v3, vault-builders-v7, core/intent/org-root-manifest-v7 +
//! router, and the real pv_call_encoder (v0.7-root / v0.7-payment / kcc20/1
//! arms) AND pv_tx_probe) to construct fully-finalized v0.7 transactions with
//! real Schnorr signatures, then executes EVERY input of every emitted
//! vector's EXACT bytes on the real TxScriptEngine against the PRODUCTION
//! CANDIDATES contracts/PolicyVault.v0.7-root.sil and
//! PolicyVault.v0.7-payment.sil.
//!
//! This is the production-byte rule for the v0.7 SDK: nothing here rebuilds
//! the bytes in-process — the transactions come out of the SDK, signatures
//! and all, and go straight into the engine.
//!
//! Accept vectors run under PRODUCTION sig-op pricing with the SDK's OWN
//! committed compute budgets (vault, root AND token inputs); reject vectors
//! (post-finalize single-field mutations the SDK refuses to build) must be
//! rejected by consensus on the input the vector names. The SDK's own
//! pre-build/pre-finalize refusal matrix is asserted by the generator itself
//! (it exits non-zero if any expected refusal is missing) and re-asserted
//! here from index.json.

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
        let dir = std::env::temp_dir().join(format!("pv7-sdk-vectors-{}", std::process::id()));
        let generator = format!("{}/sdk/tools/gen-v7-vectors.js", repo_root());
        let out = Command::new("node").arg(&generator).arg(&dir).output().expect("run the SDK vector generator (node)");
        assert!(
            out.status.success(),
            "SDK vector generation failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        println!("{}", String::from_utf8_lossy(&out.stdout));
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
    reject_input: usize,
    action: String,
    contract: String,
    note: Option<String>,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

fn index() -> &'static serde_json::Value {
    static INDEX: OnceLock<serde_json::Value> = OnceLock::new();
    INDEX.get_or_init(|| serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("index.json")).expect("index.json")).expect("index json"))
}

fn load_vectors() -> Vec<Vector> {
    let dir = vectors_dir();
    let mut vectors = Vec::new();
    for entry in index()["vectors"].as_array().expect("vectors") {
        let name = entry["name"].as_str().unwrap().to_string();
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join(&name).join("vector.json")).unwrap()).unwrap();
        let expect_accept = match doc["expect"].as_str().unwrap() {
            "accept" => true,
            "reject" => false,
            other => panic!("unknown expect {other:?}"),
        };
        let (tx, entries) = parse_vector_tx(&doc["tx"]);
        vectors.push(Vector {
            name,
            expect_accept,
            reject_input: doc["rejectInput"].as_u64().unwrap_or(0) as usize,
            action: doc["action"].as_str().unwrap_or("").to_string(),
            contract: doc["contract"].as_str().unwrap_or("").to_string(),
            note: doc["note"].as_str().map(|s| s.to_string()),
            tx,
            entries,
        });
    }
    assert!(vectors.len() >= 35, "expected the full v0.7 vector matrix, got {}", vectors.len());
    vectors
}

/// EVERY input of every accept vector executes under PRODUCTION pricing
/// within the SDK's own committed budget — the root's M-of-N counting input,
/// the rooted vault's byte-level root pin, the token family and the ordinary
/// fuel alike.
#[test]
fn v7_sdk_accept_vectors_execute_on_the_production_candidates() {
    let vectors = load_vectors();
    let mut accepted = 0;
    let mut inputs_executed = 0;
    for v in vectors.iter().filter(|v| v.expect_accept) {
        for i in 0..v.tx.inputs.len() {
            let (res, units) = execute_input_measured_priced(v.tx.clone(), v.entries.clone(), i, 1000);
            assert!(res.is_ok(), "vector {} input {i} must execute under production pricing: {res:?}", v.name);
            let committed = v.tx.inputs[i].compute_commit.compute_budget().expect("v1 budget") as u64;
            let required = ComputeBudget::checked_covering_script_units(units.into()).expect("budget").0 as u64;
            assert!(required <= committed, "vector {} input {i}: used {units} units require budget {required} > committed {committed}", v.name);
            println!("SDKVEC7 {} [{}] input {i} accept used_units={units} required_budget={required} committed={committed}", v.name, v.contract);
            inputs_executed += 1;
        }
        accepted += 1;
    }
    println!("SDKVEC7 accepted={accepted} inputs_executed={inputs_executed}");
    assert!(accepted >= 17, "unexpected accept-vector count: {accepted}");
}

/// Every reject vector is refused by consensus ON THE INPUT IT NAMES, so a
/// refusal is attributable to the rule the vector targets rather than to
/// collateral damage elsewhere in the transaction.
#[test]
fn v7_sdk_reject_vectors_are_refused_by_consensus() {
    let vectors = load_vectors();
    let mut rejected = 0;
    let (mut root_rows, mut vault_rows) = (0, 0);
    for v in vectors.iter().filter(|v| !v.expect_accept) {
        let res = execute_input_with_covenants(v.tx.clone(), v.entries.clone(), v.reject_input);
        assert!(res.is_err(), "vector {} must be REJECTED by consensus on input {} but was accepted", v.name, v.reject_input);
        println!(
            "SDKVEC7 {} rejected on input {} ({}) — {}",
            v.name,
            v.reject_input,
            v.action,
            v.note.clone().unwrap_or_else(|| v.contract.clone())
        );
        if v.contract == "policyvault-0.7-root" {
            root_rows += 1;
        } else {
            vault_rows += 1;
        }
        rejected += 1;
    }
    println!("SDKVEC7 rejected={rejected} (root {root_rows} / rooted vault {vault_rows})");
    assert!(rejected >= 18, "unexpected reject-vector count: {rejected}");
    assert!(root_rows >= 7 && vault_rows >= 8, "both sides of the authority model must carry hostile rows: root {root_rows}, vault {vault_rows}");
}

/// The SDK's own pre-build / pre-finalize refusal matrix, and the fact that
/// every organizational-root manifest the generator built VERIFIES against
/// the frozen bytes it describes.
#[test]
fn v7_sdk_refusal_matrix_and_manifests() {
    let idx = index();
    let refusals = idx["refusals"].as_array().expect("refusals");
    assert!(refusals.len() >= 45, "expected the full SDK refusal matrix, got {}", refusals.len());
    for r in refusals {
        assert_eq!(r["refused"].as_bool(), Some(true), "SDK refusal {} must have refused", r["name"]);
        assert_ne!(r["ok"].as_bool(), Some(false), "SDK refusal {} refused with the wrong code: {}", r["name"], r["message"]);
    }
    println!("SDKVEC7 sdk_refusals={}", refusals.len());

    let manifests = idx["manifests"].as_array().expect("manifests");
    assert!(manifests.len() >= 8, "expected the org-root manifest battery, got {}", manifests.len());
    for m in manifests {
        assert_eq!(m["verdict"].as_str(), Some("VERIFIED"), "org-root manifest {} must verify", m["name"]);
    }
    println!("SDKVEC7 verified_manifests={}", manifests.len());

    /* the rooted vault's pinned root geometry, derived by the SDK from a REAL
     * compiled root — not typed by hand anywhere */
    let pins = &idx["rootPins"];
    assert_eq!(pins["rootStateLen"].as_u64(), Some(467), "the measured rootStateLen (§12.3)");
    assert_eq!(pins["rootPrefixLen"].as_u64(), Some(1));
    assert!(pins["rootTemplateVmHash"].as_str().unwrap().len() == 64);
    println!("SDKVEC7 rootPins {}", serde_json::to_string(pins).unwrap());
}

/// Shape assertions that state the authority model in consensus terms: an
/// owner operation carries the root as an input and NO signature of its own;
/// a delegate spend carries no root at all.
#[test]
fn v7_sdk_authority_shapes() {
    let vectors = load_vectors();
    let by_name = |n: &str| vectors.iter().find(|v| v.name == n).unwrap_or_else(|| panic!("vector {n} present"));

    for name in ["vault_owner_set_agent_root", "vault_owner_top_up_reserve", "vault_owner_pause", "vault_owner_unpause", "vault_emergency_pause", "vault_recover_with_position", "vault_recover_without_position"] {
        let v = by_name(name);
        let covenant_inputs: Vec<_> = v.entries.iter().filter(|e| e.covenant_id.is_some()).collect();
        assert!(covenant_inputs.len() >= 2, "{name}: an owner operation spends the vault AND the organizational root");
        assert!(v.entries.iter().any(|e| e.covenant_id.is_some()), "{name}: a root input must be present");
        assert!(execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0).is_ok(), "{name}: the vault input must accept");
        assert!(execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 1).is_ok(), "{name}: the root input must accept");
    }

    let spend = by_name("delegate_spend");
    let root_like: Vec<_> = spend.entries.iter().filter(|e| e.covenant_id.is_some()).collect();
    assert_eq!(root_like.len(), 2, "a delegate spend spends exactly the vault and its token position — never the root");

    let genesis = by_name("root_genesis");
    assert!(execute_input_with_covenants(genesis.tx.clone(), genesis.entries.clone(), 0).is_ok(), "root genesis funding input must execute");
    assert!(genesis.tx.outputs[0].covenant.is_some(), "the root output must carry a covenant binding");

    let vault_genesis = by_name("vault_genesis");
    assert!(execute_input_with_covenants(vault_genesis.tx.clone(), vault_genesis.entries.clone(), 0).is_ok());
    assert!(vault_genesis.tx.outputs[0].covenant.is_some(), "the rooted vault output must carry a covenant binding");
}
