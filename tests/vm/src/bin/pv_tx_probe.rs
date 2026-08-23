//! PolicyVault frozen-transaction probe.
//!
//! Gives the SDK AUTHORITATIVE, source-of-truth answers about a frozen
//! (unsigned) transaction using the real rusty-kaspa consensus code —
//! never a JS reimplementation of consensus hashing or signature
//! verification (mission §6/§58: no custom crypto, no reconstruction of
//! funds-critical behavior).
//!
//! Usage:
//!   pv_tx_probe describe <frozen-tx.json>
//!       -> {"txId":"…","sighashAll":["…", …]}   (one sighash per input)
//!   pv_tx_probe verify <frozen-tx.json> <input-index> <sig-65-hex> <xonly-hex>
//!       -> {"valid":true} | {"valid":false,"reason":"…"}
//!
//! The frozen-transaction JSON is the SDK's canonical unsigned descriptor
//! (sdk/src/frozen-tx-v3.js). It carries NO signature scripts: for
//! version-1 transactions neither the transaction ID nor the SIG_HASH_ALL
//! sighash commits signature scripts, so the txId printed here equals the
//! final broadcast txId and every signer signs exactly the sighash printed
//! here (consensus/core/src/hashing/{tx.rs,sighash.rs}).
//!
//! verify enforces the production A7 approval gate shape BEFORE schnorr
//! verification: exactly 65 bytes with trailing byte 0x01 (SIG_HASH_ALL).
//! Everything else fails closed with a reason.

use std::{env, fs};

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::Hash;

fn die(message: &str) -> ! {
    eprintln!("pv_tx_probe: {message}");
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

fn json_str<'a>(v: &'a serde_json::Value, field: &str) -> &'a str {
    v[field].as_str().unwrap_or_else(|| die(&format!("{field} is required and must be a string")))
}

fn json_u64(v: &serde_json::Value, field: &str) -> u64 {
    match &v[field] {
        serde_json::Value::String(s) => s.parse::<u64>().unwrap_or_else(|_| die(&format!("{field} must be a u64 digit string"))),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or_else(|| die(&format!("{field} must be a u64"))),
        _ => die(&format!("{field} is required")),
    }
}

fn json_u32(v: &serde_json::Value, field: &str) -> u32 {
    let n = json_u64(v, field);
    u32::try_from(n).unwrap_or_else(|_| die(&format!("{field} out of u32 range")))
}

fn json_u16(v: &serde_json::Value, field: &str) -> u16 {
    let n = json_u64(v, field);
    u16::try_from(n).unwrap_or_else(|_| die(&format!("{field} out of u16 range")))
}

fn parse_spk(v: &serde_json::Value, label: &str) -> ScriptPublicKey {
    let version = json_u16(v, "version");
    let script = hex_bytes(json_str(v, "scriptHex"), &format!("{label}.scriptHex"));
    ScriptPublicKey::new(version, script.into())
}

/// Parse the SDK's canonical frozen-transaction JSON into a consensus
/// Transaction plus per-input UtxoEntries. Fails closed on anything
/// missing or malformed.
fn parse_frozen(path: &str) -> (Transaction, Vec<UtxoEntry>) {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("bad frozen-tx json: {e}")));

    let version = json_u16(&v, "version");
    if version != 1 {
        die("frozen transaction version must be 1 (Toccata)");
    }

    let subnetwork = hex_bytes(json_str(&v, "subnetworkId"), "subnetworkId");
    let native: &[u8] = SUBNETWORK_ID_NATIVE.as_ref();
    if subnetwork.as_slice() != native {
        die("frozen transaction subnetworkId must be the native subnetwork");
    }
    let gas = json_u64(&v, "gas");
    if gas != 0 {
        die("frozen transaction gas must be 0");
    }
    let payload = hex_bytes(v["payload"].as_str().unwrap_or_else(|| die("payload is required (hex, may be empty)")), "payload");
    let lock_time = json_u64(&v, "lockTime");

    let inputs_json = v["inputs"].as_array().unwrap_or_else(|| die("inputs array is required"));
    if inputs_json.is_empty() {
        die("frozen transaction needs at least one input");
    }
    let mut inputs = Vec::with_capacity(inputs_json.len());
    let mut entries = Vec::with_capacity(inputs_json.len());
    for (i, input) in inputs_json.iter().enumerate() {
        let op = &input["previousOutpoint"];
        let outpoint = TransactionOutpoint {
            transaction_id: hex32(json_str(op, "transactionId"), &format!("inputs[{i}].previousOutpoint.transactionId")),
            index: json_u32(op, "index"),
        };
        if !input["signatureScript"].is_null() {
            die(&format!("inputs[{i}] must not carry a signatureScript — the frozen form is unsigned"));
        }
        let sequence = json_u64(input, "sequence");
        let compute_budget = json_u16(input, "computeBudget");
        inputs.push(TransactionInput {
            previous_outpoint: outpoint,
            signature_script: vec![],
            sequence,
            compute_commit: ComputeBudget(compute_budget).into(),
        });

        let utxo = &input["utxo"];
        if utxo.is_null() {
            die(&format!("inputs[{i}].utxo is required (amount + scriptPublicKey + covenantId)"));
        }
        let amount = json_u64(utxo, "amount");
        let spk = parse_spk(&utxo["scriptPublicKey"], &format!("inputs[{i}].utxo.scriptPublicKey"));
        let covenant_id = match &utxo["covenantId"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => Some(hex32(s, &format!("inputs[{i}].utxo.covenantId"))),
            _ => die(&format!("inputs[{i}].utxo.covenantId must be null or 32-byte hex")),
        };
        let block_daa_score = json_u64(utxo, "blockDaaScore");
        entries.push(UtxoEntry::new(amount, spk, block_daa_score, false, covenant_id));
    }

    let outputs_json = v["outputs"].as_array().unwrap_or_else(|| die("outputs array is required"));
    let mut outputs = Vec::with_capacity(outputs_json.len());
    for (i, output) in outputs_json.iter().enumerate() {
        let value = json_u64(output, "value");
        let spk = parse_spk(&output["scriptPublicKey"], &format!("outputs[{i}].scriptPublicKey"));
        let covenant = match &output["covenant"] {
            serde_json::Value::Null => None,
            obj @ serde_json::Value::Object(_) => Some(CovenantBinding {
                authorizing_input: json_u16(obj, "authorizingInput"),
                covenant_id: hex32(json_str(obj, "covenantId"), &format!("outputs[{i}].covenant.covenantId")),
            }),
            _ => die(&format!("outputs[{i}].covenant must be null or an object")),
        };
        outputs.push(TransactionOutput { value, script_public_key: spk, covenant });
    }

    let tx = Transaction::new(version, inputs, outputs, lock_time, SUBNETWORK_ID_NATIVE, gas, payload);
    (tx, entries)
}

fn hexs(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sighash_for_input(tx: &Transaction, entries: &[UtxoEntry], input_index: usize) -> [u8; 32] {
    if input_index >= tx.inputs.len() {
        die("input index out of range");
    }
    let mutable = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&mutable.as_verifiable(), input_index, SIG_HASH_ALL, &reused);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes().as_slice());
    out
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("describe") => {
            if args.len() != 2 {
                die("usage: pv_tx_probe describe <frozen-tx.json>");
            }
            let (tx, entries) = parse_frozen(&args[1]);
            let sighashes: Vec<String> =
                (0..tx.inputs.len()).map(|i| hexs(&sighash_for_input(&tx, &entries, i))).collect();
            println!(
                "{}",
                serde_json::json!({
                    "txId": tx.id().to_string().to_lowercase(),
                    "sighashAll": sighashes,
                })
            );
        }
        Some("verify") => {
            if args.len() != 5 {
                die("usage: pv_tx_probe verify <frozen-tx.json> <input-index> <sig-65-hex> <xonly-hex>");
            }
            let (tx, entries) = parse_frozen(&args[1]);
            let input_index: usize = args[2].parse().unwrap_or_else(|_| die("input index must be an integer"));
            let sig = hex_bytes(&args[3], "signature");
            let key = hex_bytes(&args[4], "xonly pubkey");

            // Production A7 gate shape first: exactly 65 bytes, trailing 0x01.
            fn reject(reason: &str) -> ! {
                println!("{}", serde_json::json!({ "valid": false, "reason": reason }));
                std::process::exit(0);
            }
            if sig.len() != 65 {
                reject(&format!("signature must be exactly 65 bytes, got {}", sig.len()));
            }
            if sig[64] != 0x01 {
                reject(&format!(
                    "trailing sighash byte 0x{:02x} != 0x01 (only SIG_HASH_ALL approvals are accepted)",
                    sig[64]
                ));
            }
            if key.len() != 32 {
                reject("approver key must be 32-byte x-only");
            }
            let digest = sighash_for_input(&tx, &entries, input_index);
            let secp = secp256k1::Secp256k1::verification_only();
            let msg = secp256k1::Message::from_digest_slice(&digest).unwrap_or_else(|_| die("internal: bad digest"));
            let schnorr = match secp256k1::schnorr::Signature::from_slice(&sig[..64]) {
                Ok(s) => s,
                Err(_) => reject("malformed schnorr signature bytes"),
            };
            let xonly = match secp256k1::XOnlyPublicKey::from_slice(&key) {
                Ok(k) => k,
                Err(_) => reject("invalid x-only public key"),
            };
            match secp.verify_schnorr(&schnorr, &msg, &xonly) {
                Ok(()) => println!("{}", serde_json::json!({ "valid": true })),
                Err(_) => reject("schnorr verification failed against the frozen transaction sighash"),
            }
        }
        _ => die("usage: pv_tx_probe <describe|verify> …"),
    }
}
