//! PolicyVault production-covenant VM PREFLIGHT (Checkpoint G §G12).
//!
//! Gives the server an AUTHORITATIVE, no-broadcast answer about whether a
//! FINALIZED transaction would execute against the production covenant on a
//! real Kaspa node, using the real `TxScriptEngine` with covenants enabled —
//! never a JS reimplementation of consensus. This is the deepest offline
//! preflight: the exact bytes the wallet signed and the server assembled are
//! executed against `contracts/PolicyVault.v0.4.sil` (compiled into the
//! spent covenant UTXO's P2SH script, embedded in the transaction the server
//! passes here).
//!
//! Usage:
//!   pv_vm_preflight <final-tx.json> [input-index]
//!       -> {"valid":true}
//!       -> {"valid":false,"reason":"…"}
//!
//! The JSON is the server's finalized-transaction descriptor (identical shape
//! to the v4_sdk_integration vectors' `tx`): every input carries its
//! signatureScript AND its spent UTXO (amount + scriptPublicKey + covenantId),
//! so the covenant context is fully reconstructable offline. Exit code is 0
//! whenever the JSON parsed and execution ran (valid true OR false); a nonzero
//! exit means the descriptor itself was malformed (fail closed).

use std::{env, fs};

use policyvault_vm_tests::execute_input_with_covenants;

use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;

fn die(message: &str) -> ! {
    eprintln!("pv_vm_preflight: {message}");
    std::process::exit(1);
}

fn hex_bytes(value: &str, label: &str) -> Vec<u8> {
    if value.len() % 2 != 0 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        die(&format!("{label} must be even-length hex"));
    }
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect()
}

fn hex32(value: &str, label: &str) -> Hash {
    let bytes = hex_bytes(value, label);
    if bytes.len() != 32 {
        die(&format!("{label} must be 32-byte hex"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Hash::from_bytes(arr)
}

fn ju64(v: &serde_json::Value, label: &str) -> u64 {
    match v {
        serde_json::Value::String(s) => s.parse().unwrap_or_else(|_| die(&format!("{label} must be a u64 digit string"))),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or_else(|| die(&format!("{label} must be a u64"))),
        _ => die(&format!("{label} is required")),
    }
}

fn parse_spk(v: &serde_json::Value, label: &str) -> ScriptPublicKey {
    let version = ju64(&v["version"], &format!("{label}.version")) as u16;
    let script = hex_bytes(v["scriptHex"].as_str().unwrap_or_else(|| die(&format!("{label}.scriptHex"))), &format!("{label}.scriptHex"));
    ScriptPublicKey::new(version, script.into())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        die("usage: pv_vm_preflight <final-tx.json> [input-index]");
    }
    let input_index: usize = if args.len() == 2 {
        args[1].parse().unwrap_or_else(|_| die("input index must be an integer"))
    } else {
        0
    };

    let raw = fs::read_to_string(&args[0]).unwrap_or_else(|e| die(&format!("cannot read {}: {e}", args[0])));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("bad final-tx json: {e}")));

    if ju64(&v["version"], "version") != 1 {
        die("final transaction version must be 1");
    }
    let native: &[u8] = SUBNETWORK_ID_NATIVE.as_ref();
    if hex_bytes(v["subnetworkId"].as_str().unwrap_or_else(|| die("subnetworkId")), "subnetworkId") != native {
        die("final transaction must use the native subnetwork");
    }

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for (i, input) in v["inputs"].as_array().unwrap_or_else(|| die("inputs array required")).iter().enumerate() {
        let op = &input["previousOutpoint"];
        let sig = input["signatureScript"].as_str().unwrap_or_else(|| die(&format!("inputs[{i}].signatureScript required")));
        inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: hex32(op["transactionId"].as_str().unwrap_or_else(|| die("transactionId")), "previousOutpoint.transactionId"),
                index: ju64(&op["index"], "previousOutpoint.index") as u32,
            },
            signature_script: hex_bytes(sig, &format!("inputs[{i}].signatureScript")),
            sequence: ju64(&input["sequence"], "sequence"),
            compute_commit: ComputeBudget(ju64(&input["computeBudget"], "computeBudget") as u16).into(),
        });
        let utxo = &input["utxo"];
        let covenant_id = match &utxo["covenantId"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => Some(hex32(s, "utxo.covenantId")),
            _ => die(&format!("inputs[{i}].utxo.covenantId must be null or 32-byte hex")),
        };
        entries.push(UtxoEntry::new(
            ju64(&utxo["amount"], "utxo.amount"),
            parse_spk(&utxo["scriptPublicKey"], &format!("inputs[{i}].utxo.scriptPublicKey")),
            ju64(&utxo["blockDaaScore"], "utxo.blockDaaScore"),
            false,
            covenant_id,
        ));
    }

    let mut outputs = Vec::new();
    for (i, output) in v["outputs"].as_array().unwrap_or_else(|| die("outputs array required")).iter().enumerate() {
        let covenant = match &output["covenant"] {
            serde_json::Value::Null => None,
            obj @ serde_json::Value::Object(_) => Some(CovenantBinding {
                authorizing_input: ju64(&obj["authorizingInput"], "authorizingInput") as u16,
                covenant_id: hex32(obj["covenantId"].as_str().unwrap_or_else(|| die("covenant.covenantId")), "covenant.covenantId"),
            }),
            _ => die(&format!("outputs[{i}].covenant must be null or an object")),
        };
        outputs.push(TransactionOutput { value: ju64(&output["value"], "output.value"), script_public_key: parse_spk(&output["scriptPublicKey"], "output.scriptPublicKey"), covenant });
    }

    let tx = Transaction::new(
        1,
        inputs,
        outputs,
        ju64(&v["lockTime"], "lockTime"),
        SUBNETWORK_ID_NATIVE,
        ju64(&v["gas"], "gas"),
        hex_bytes(v["payload"].as_str().unwrap_or(""), "payload"),
    );

    if input_index >= tx.inputs.len() {
        die("input index out of range");
    }

    match execute_input_with_covenants(tx, entries, input_index) {
        Ok(()) => println!("{}", serde_json::json!({ "valid": true })),
        Err(e) => println!("{}", serde_json::json!({ "valid": false, "reason": format!("{e:?}") })),
    }
}
