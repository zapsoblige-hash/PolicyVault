//! VM layer — v0.7-payment-hd SDK PRODUCTION-BYTE integration.
//!
//! Wave 2 Track D, gate I2 (docs/postlaunch/hierarchical-delegation-design-
//! freeze.md §4). Sibling of tests/vm/tests/v7_sdk_integration.rs.
//!
//! Runs the ACTUAL PolicyVault SDK — sdk/src/vault-builders-v7-hd.js,
//! core/model/hd-leaf-v7.js, core/model/compute-budget-v7-hd.js, the reused
//! v0.7 root/owner-op/deposit machinery, and the real `pv_call_encoder`
//! (`policyvault-0.7-payment-hd` arm) + `pv_tx_probe` binaries — to
//! construct fully-finalized v0.7-payment-hd transactions with real Schnorr
//! signatures, then executes EVERY input of every emitted vector's EXACT
//! bytes on the real TxScriptEngine against the PRODUCTION CANDIDATE
//! `contracts/PolicyVault.v0.7-payment-hd.sil` (plus the reused v0.7-root
//! candidate for owner ops). Nothing here rebuilds the bytes in-process —
//! the transactions come out of the SDK, signatures and all, and go
//! straight into the engine. This is the production-byte rule for the HD
//! SDK layer.

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

/*
 * `tests/vm/target` is a SYMLINK into the SHARED cargo target directory
 * (CLAUDE.md: "shared cargo target — never cargo clean"): other development
 * lanes build their OWN `pv_call_encoder` (same [[bin]] name, same output
 * path) concurrently, and whichever build finishes last wins that ONE
 * shared file — observed in practice as this exact binary losing the
 * `policyvault-0.7-payment-hd` arm within a fraction of a second of a fresh
 * rebuild. Rebuilding immediately before use (the standing rule) narrows
 * but does not close that window, since another lane's build can land in
 * between the rebuild and the SDK's first invocation. This copies the
 * freshly-built binary aside to a PRIVATE, PID-scoped path (immune to any
 * later overwrite of the shared one) and points the SDK at it via
 * POLICYVAULT_PV_CALL_ENCODER_PATH (sdk/src/vault-builders-v4.js, additive
 * escape hatch — every other caller is unaffected).
 */
/*
 * `tests/vm/target` is a SYMLINK into a target directory SHARED with other
 * development lanes (CLAUDE.md: "shared cargo target — never cargo clean").
 * In practice this is not just a narrow overwrite race: cargo's own
 * fingerprint cache under that shared `target/` lives alongside other
 * worktrees' fingerprints for the SAME [[bin]] name and profile, and was
 * observed reporting `pv_call_encoder` "Finished in 0.1-0.2s" (i.e. treating
 * it as already up to date — no rustc invocation at all, confirmed with
 * `cargo build -v`) while the actual file on disk did not contain this
 * worktree's `policyvault-0.7-payment-hd` arm, even immediately after
 * `touch`ing the source — 8/8 retries against the shared target directory
 * all failed. A completely PRIVATE `--target-dir` (still using the shared
 * registry/dependency cache, so only this crate's own objects rebuild — a
 * clean private build measured at ~27s once, ~0.4s incrementally after)
 * sidesteps the shared fingerprint cache entirely and was 100% reliable in
 * testing. This never touches or repairs the shared target dir — "never
 * cargo clean" is respected.
 */
fn stable_encoder_copy() -> PathBuf {
    let private_target = std::env::temp_dir().join("pv7hd-sdk-private-cargo-target");
    let build = Command::new("cargo")
        .args(["build", "--bin", "pv_call_encoder", "--target-dir"])
        .arg(&private_target)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo build --bin pv_call_encoder --target-dir <private>");
    assert!(build.status.success(), "cargo build --bin pv_call_encoder (private target dir) failed:\n{}", String::from_utf8_lossy(&build.stderr));
    let built = private_target.join("debug/pv_call_encoder");
    let bytes = std::fs::read(&built).unwrap_or_else(|e| panic!("read {}: {e}", built.display()));
    let has_arm = bytes.windows(b"policyvault-0.7-payment-hd".len()).any(|w| w == b"policyvault-0.7-payment-hd");
    assert!(has_arm, "the privately-built pv_call_encoder at {} does not contain the policyvault-0.7-payment-hd arm — the SOURCE (tests/vm/src/bin/pv_call_encoder.rs, never shared/symlinked) is missing the arm; this is a real defect, not a race", built.display());
    built
}

fn vectors_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("pv7-hd-sdk-vectors-{}", std::process::id()));
        let generator = format!("{}/sdk/tools/gen-v7-hd-vectors.js", repo_root());
        let stable_encoder = stable_encoder_copy();
        let out = Command::new("node")
            .arg(&generator)
            .arg(&dir)
            .env("POLICYVAULT_PV_CALL_ENCODER_PATH", &stable_encoder)
            .output()
            .expect("run the SDK HD vector generator (node)");
        assert!(
            out.status.success(),
            "SDK HD vector generation failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        println!("{}", String::from_utf8_lossy(&out.stdout));
        /* the private target dir (and its built binary) is intentionally
         * KEPT — a persistent private cargo target makes every subsequent
         * run of this test incremental (~0.4s) instead of a full rebuild */
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
    assert!(vectors.len() >= 15, "expected the HD vector set, got {}", vectors.len());
    vectors
}

/// EVERY input of every accept vector executes under PRODUCTION pricing
/// within the SDK's own committed budget (`selectHdComputeBudgetV7` for the
/// five HD entrypoints, the reused v0.7 root/owner-op/token budgets
/// elsewhere).
#[test]
fn v7_hd_sdk_accept_vectors_execute_on_the_production_candidate() {
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
            println!("HDSDKVEC7 {} [{}] input {i} accept used_units={units} required_budget={required} committed={committed}", v.name, v.contract);
            inputs_executed += 1;
        }
        accepted += 1;
    }
    println!("HDSDKVEC7 accepted={accepted} inputs_executed={inputs_executed}");
    assert!(accepted >= 13, "unexpected accept-vector count: {accepted}");
}

/// Every reject vector is refused by consensus ON THE INPUT IT NAMES.
#[test]
fn v7_hd_sdk_reject_vectors_are_refused_by_consensus() {
    let vectors = load_vectors();
    let mut rejected = 0;
    for v in vectors.iter().filter(|v| !v.expect_accept) {
        let res = execute_input_with_covenants(v.tx.clone(), v.entries.clone(), v.reject_input);
        assert!(res.is_err(), "vector {} must be REJECTED by consensus on input {} but was accepted", v.name, v.reject_input);
        println!("HDSDKVEC7 {} rejected on input {} ({}) — {}", v.name, v.reject_input, v.action, v.note.clone().unwrap_or_else(|| v.contract.clone()));
        rejected += 1;
    }
    println!("HDSDKVEC7 rejected={rejected}");
    assert!(rejected >= 2, "unexpected reject-vector count: {rejected}");
}

/// The SDK's own pre-build/pre-finalize refusal matrix for the HD builders
/// (agentRoot mismatch, spend/delegation touching the root, paused refusal,
/// unknown action, no-approvals-on-the-HD-path).
#[test]
fn v7_hd_sdk_refusal_matrix() {
    let idx = index();
    let refusals = idx["refusals"].as_array().expect("refusals");
    assert!(refusals.len() >= 7, "expected the HD SDK refusal matrix, got {}", refusals.len());
    for r in refusals {
        assert_eq!(r["refused"].as_bool(), Some(true), "SDK refusal {} must have refused", r["name"]);
        assert_ne!(r["ok"].as_bool(), Some(false), "SDK refusal {} refused with the wrong code: {}", r["name"], r["message"]);
    }
    println!("HDSDKVEC7 sdk_refusals={}", refusals.len());
}

/// Shape assertions stating the authority model in consensus terms: an HD
/// spend/delegation carries NO root input at all; an owner op on the HD
/// vault carries the root as an input and no HD-leaf signature slot.
#[test]
fn v7_hd_sdk_authority_shapes() {
    let vectors = load_vectors();
    let by_name = |n: &str| vectors.iter().find(|v| v.name == n).unwrap_or_else(|| panic!("vector {n} present"));

    for name in ["hd_level1_spend", "hd_level2_spend", "hd_level3_spend", "hd_delegate_level1", "hd_delegate_level2"] {
        let v = by_name(name);
        let covenant_inputs: Vec<_> = v.entries.iter().filter(|e| e.covenant_id.is_some()).collect();
        assert!(covenant_inputs.len() <= 2, "{name}: an HD spend/delegation never carries a root input alongside the vault (and token, for a spend)");
        assert!(execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0).is_ok(), "{name}: the vault input must accept");
    }

    for name in ["hd_vault_owner_set_agent_root", "hd_vault_owner_top_up_reserve", "hd_vault_owner_pause", "hd_vault_emergency_pause", "hd_owner_recover_with_position"] {
        let v = by_name(name);
        let covenant_inputs: Vec<_> = v.entries.iter().filter(|e| e.covenant_id.is_some()).collect();
        assert!(covenant_inputs.len() >= 2, "{name}: an owner operation spends the HD vault AND the organizational root");
        assert!(execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 0).is_ok(), "{name}: the vault input must accept");
        assert!(execute_input_with_covenants(v.tx.clone(), v.entries.clone(), 1).is_ok(), "{name}: the root input must accept");
    }

    let genesis = by_name("hd_vault_genesis");
    assert!(execute_input_with_covenants(genesis.tx.clone(), genesis.entries.clone(), 0).is_ok());
    assert!(genesis.tx.outputs[0].covenant.is_some(), "the rooted HD vault output must carry a covenant binding");

    let root_genesis = by_name("hd_root_genesis");
    assert!(execute_input_with_covenants(root_genesis.tx.clone(), root_genesis.entries.clone(), 0).is_ok());
}

/// The maximum proven level's spend carries the deepest chain the covenant
/// accepts (level 3), and the composition proof (a FROZEN root's EMERGENCY
/// pause reaches delegation/spend through `paused`) is present as vectors.
#[test]
fn v7_hd_sdk_max_level_and_composition() {
    let vectors = load_vectors();
    let by_name = |n: &str| vectors.iter().find(|v| v.name == n).unwrap_or_else(|| panic!("vector {n} present"));
    let l3 = by_name("hd_level3_spend");
    assert_eq!(l3.action, "childSpendL3");
    assert!(execute_input_with_covenants(l3.tx.clone(), l3.entries.clone(), 0).is_ok());

    let freeze = by_name("hd_emergency_pause_via_root_freeze");
    assert!(execute_input_with_covenants(freeze.tx.clone(), freeze.entries.clone(), 0).is_ok());
    assert!(execute_input_with_covenants(freeze.tx.clone(), freeze.entries.clone(), 1).is_ok());

    let revocation = by_name("hd_revocation_zero_child_root");
    assert!(execute_input_with_covenants(revocation.tx.clone(), revocation.entries.clone(), 0).is_ok(), "a zeroed childRoot (structural revocation) is a normal accepted delegation");
}
