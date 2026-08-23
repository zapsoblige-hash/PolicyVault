//! Replay a dumped (already-signed) PolicyVault transaction through the real
//! TxScriptEngine and report per-input verification results. Reproduces the
//! exact bytes the SDK submitted so a live rejection can be diagnosed
//! offline.
//!
//! Input JSON: { tx: <serializeToSafeJSON>, ... } as written by
//! vault-ops-v2.js under PV_DEBUG_DUMP.

use std::{env, fs};

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::units::{ComputeBudget, SigopCount};
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};

fn hexd(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn spk_from_hex(s: &str) -> ScriptPublicKey {
    // serializeToSafeJSON encodes spk as version(u16 LE, 4 hex) + script.
    let version = u16::from_le_bytes([u8::from_str_radix(&s[0..2], 16).unwrap(), u8::from_str_radix(&s[2..4], 16).unwrap()]);
    ScriptPublicKey::new(version, hexd(&s[4..]).into())
}

fn txid(s: &str) -> TransactionId {
    let mut b = [0u8; 32];
    b.copy_from_slice(&hexd(s));
    Hash::from_bytes(b)
}

fn main() {
    let path = env::args().nth(1).expect("usage: pv_replay_probe <dump.json>");
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let tx = &doc["tx"];

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for inp in tx["inputs"].as_array().unwrap() {
        let compute_budget = inp["computeBudget"].as_u64();
        let commit = match compute_budget {
            Some(b) => ComputeBudget(b as u16).into(),
            None => SigopCount(inp["sigOpCount"].as_u64().unwrap_or(0) as u8).into(),
        };
        inputs.push(TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: txid(inp["transactionId"].as_str().unwrap()),
                index: inp["index"].as_u64().unwrap() as u32,
            },
            signature_script: hexd(inp["signatureScript"].as_str().unwrap()),
            sequence: inp["sequence"].as_str().unwrap_or("0").parse().unwrap(),
            compute_commit: commit,
        });
        let u = &inp["utxo"];
        let cov = u["covenantId"].as_str().map(txid);
        entries.push(UtxoEntry::new(
            u["amount"].as_str().unwrap().parse().unwrap(),
            spk_from_hex(u["scriptPublicKey"].as_str().unwrap()),
            u["blockDaaScore"].as_str().unwrap_or("0").parse().unwrap(),
            u["isCoinbase"].as_bool().unwrap_or(false),
            cov,
        ));
    }

    let mut outputs = Vec::new();
    for out in tx["outputs"].as_array().unwrap() {
        let covenant = out["covenant"].as_object().map(|c| CovenantBinding {
            authorizing_input: c["authorizingInput"].as_u64().unwrap() as u16,
            covenant_id: txid(c["covenantId"].as_str().unwrap()),
        });
        let spk = out["scriptPublicKey"]["script"].as_str().or_else(|| out["scriptPublicKey"].as_str()).unwrap();
        outputs.push(TransactionOutput { value: out["value"].as_str().unwrap().parse().unwrap(), script_public_key: spk_from_hex(spk), covenant });
    }

    let lock_time: u64 = tx["lockTime"].as_str().unwrap_or("0").parse().unwrap();
    let transaction = Transaction::new(tx["version"].as_u64().unwrap_or(1) as u16, inputs, outputs, lock_time, Default::default(), 0, vec![]);

    let populated = PopulatedTransaction::new(&transaction, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => {
            println!("CovenantsContext::from_tx FAILED: {e:?}");
            return;
        }
    };

    let trace = env::args().any(|a| a == "--trace");
    for idx in 0..transaction.inputs.len() {
        let reused = SigHashReusedValuesUnsync::new();
        let sig_cache = Cache::new(10_000);
        let input = transaction.inputs[idx].clone();
        let utxo = populated.utxo(idx).unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        let r;
        {
            let mut builder = TxScriptEngine::from_transaction_input(
                &populated,
                &input,
                idx,
                utxo,
                EngineCtx::new(&sig_cache).with_reused(&reused).with_covenants_ctx(&cov_ctx),
                EngineFlags { covenants_enabled: true, sigop_script_units: 0.into() },
            );
            if trace && idx == 0 {
                let mut vm = builder.with_opcode_execution_log_buffer(&mut buffer);
                r = vm.execute();
                let units: u64 = vm.used_script_units().into();
                println!("input {idx}: {r:?} ({units} script units)");
            } else {
                r = builder.execute();
                let units: u64 = builder.used_script_units().into();
                println!("input {idx}: {r:?} ({units} script units)");
            }
        }
        if trace && idx == 0 {
            let text = String::from_utf8_lossy(&buffer);
            let lines: Vec<&str> = text.lines().collect();
            println!("--- last 18 opcodes before failure ---");
            for line in lines.iter().rev().take(18).rev() {
                println!("{}", line.chars().take(220).collect::<String>());
            }
        }
    }
}
