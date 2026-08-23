//! Authoritative mass cross-check.
//!
//! Builds representative PolicyVault transaction shapes and prints the mass
//! that rusty-kaspa's own `MassCalculator::calc_non_contextual_masses`
//! computes, plus the derived minimum relay fee. The PolicyVault JS module
//! (sdk/src/fee-mass.js) must match these numbers exactly.
//!
//! Shapes are parameterized by input/output byte sizes so the JS side can
//! reproduce the identical descriptor. Output is JSON lines.

use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_consensus_core::Hash;

// testnet-10 params.
const MASS_PER_TX_BYTE: u64 = 1;
const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
const STORAGE_MASS_PARAMETER: u64 = 1_000_000_000_000;
const RELAY_FEE: u64 = 100_000;
const BLOCK_COMPUTE_LIMIT: u64 = 500_000;
const BLOCK_TRANSIENT_LIMIT: u64 = 1_000_000;

fn input(sig_len: usize, compute_budget: u16) -> TransactionInput {
    let mut i = TransactionInput::new(
        TransactionOutpoint { transaction_id: Hash::from_bytes([1; 32]), index: 0 },
        vec![0u8; sig_len],
        0,
        0,
    );
    i.compute_commit = kaspa_consensus_core::mass::units::ComputeBudget(compute_budget).into();
    i
}

fn output(spk_len: usize, has_covenant: bool) -> TransactionOutput {
    TransactionOutput {
        value: 1_000_000_000,
        script_public_key: ScriptPublicKey::new(0, vec![0u8; spk_len].into()),
        covenant: if has_covenant {
            Some(CovenantBinding { authorizing_input: 0, covenant_id: Hash::from_bytes([2; 32]) })
        } else {
            None
        },
    }
}

fn probe(name: &str, inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) {
    let tx = Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let mc = MassCalculator::new(MASS_PER_TX_BYTE, MASS_PER_SCRIPT_PUB_KEY_BYTE, STORAGE_MASS_PARAMETER);
    let masses = mc.calc_non_contextual_masses(&tx);
    let normalized_transient =
        ((masses.transient_mass as u128 * BLOCK_COMPUTE_LIMIT as u128 + BLOCK_TRANSIENT_LIMIT as u128 - 1)
            / BLOCK_TRANSIENT_LIMIT as u128) as u64;
    let fee_mass = masses.compute_mass.max(normalized_transient);
    let min_fee = fee_mass * RELAY_FEE / 1000;
    println!(
        "{{\"shape\":\"{name}\",\"computeMass\":{},\"transientMass\":{},\"normalizedTransient\":{},\"feeMass\":{},\"minimumRequiredFee\":{}}}",
        masses.compute_mass, masses.transient_mass, normalized_transient, fee_mass, min_fee
    );
}

fn main() {
    // Descriptors chosen to be reproduced byte-for-byte on the JS side.
    // covenant redeem push (~1691-byte script) lives in the covenant input's
    // signature script alongside the call data; we model it as a single
    // sig-script length.
    probe("create_2in_3out", vec![input(66, 10), input(66, 10)], vec![output(34, true), output(34, false), output(34, false)]);
    probe(
        "delegate_spend",
        vec![input(1950, 100), input(66, 10)],
        vec![output(34, false), output(35, true), output(34, false)],
    );
    probe(
        "rollover_spend",
        vec![input(1970, 100), input(66, 10)],
        vec![output(34, false), output(35, true), output(34, false)],
    );
    probe("pause", vec![input(1930, 100), input(66, 10)], vec![output(35, true), output(34, false)]);
    probe("unpause", vec![input(1930, 100), input(66, 10)], vec![output(35, true), output(34, false)]);
    probe("recover", vec![input(1900, 100), input(66, 10)], vec![output(34, false), output(34, false)]);

    // v0.2 shapes: ~4708-byte redeem script + 14-field successor call in the
    // covenant sigscript; covenant compute budget 20 (measured ~32K script
    // units, 200K allowed), ordinary inputs 10.
    probe(
        "v2_delegate_spend",
        vec![input(5150, 20), input(66, 10)],
        vec![output(34, false), output(35, true), output(34, false)],
    );
    probe("v2_lifecycle", vec![input(5100, 20), input(66, 10)], vec![output(35, true), output(34, false)]);
    probe("v2_recover", vec![input(4850, 20), input(66, 10)], vec![output(34, false), output(34, false)]);

    // v0.3 shapes. Sig-script lengths and covenant compute budgets are the
    // EXACT values measured from real encoded transactions on the VM with
    // production sig-op pricing (Gram(1000) = 100,000 script units/checkSig):
    // see tests/vm/tests/v3_encoder_integration.rs (enc3_measure_* tests).
    // Redeem script 28,483 bytes (includes the Phase 4.5 predecessor
    // approver-set well-formedness gate). Budgets: depth0=29, depth16=31,
    // 2-of-3=61, 10-of-10=134, owner op=29, recover=16.
    probe("v3_create_2in_3out", vec![input(66, 10), input(66, 10)], vec![output(34, true), output(34, false), output(34, false)]);
    probe("v3_delegate_spend_depth0", vec![input(29719, 29), input(66, 10)], vec![output(34, false), output(35, true), output(34, false)]);
    probe("v3_delegate_spend_depth16", vec![input(30233, 31), input(66, 10)], vec![output(34, false), output(35, true), output(34, false)]);
    probe("v3_approved_spend_2of3", vec![input(29977, 61), input(66, 10)], vec![output(34, false), output(35, true), output(34, false)]);
    probe("v3_approved_spend_10of10", vec![input(29977, 134), input(66, 10)], vec![output(34, false), output(35, true), output(34, false)]);
    probe("v3_owner_op", vec![input(29020, 29), input(66, 10)], vec![output(35, true), output(34, false)]);
    probe("v3_recover", vec![input(28577, 16), input(66, 10)], vec![output(34, false), output(34, false)]);

    // v0.4 shapes. Redeem script 18,839 B (fee reserve + agent tree + per-
    // agent fee cap + inlined distinctness). Sig-script lengths and compute
    // budgets are the EXACT values measured from the production covenant under
    // production sig-op pricing (Gram(1000) = 100,000 script units/checkSig):
    // tests/vm/tests/v4_production.rs (v4p_measure_production_budgets) +
    // v4_encoder_integration.rs. Budgets: agent-spend below (agent0/recip0)=23,
    // WORST (agent12+recip16+10-of-10)=132, owner op=22, recover=14.
    // "reserve-funded" spends carry NO fuel input (the fee comes from the
    // covenant fee reserve): 1 covenant input, payment + successor outputs.
    probe("v4_create_2in_3out", vec![input(66, 10), input(66, 10)], vec![output(34, true), output(34, false), output(34, false)]);
    probe("v4_agent_spend_min_reserve_funded", vec![input(20117, 23)], vec![output(34, false), output(35, true)]);
    probe("v4_agent_spend_min_fuel", vec![input(20117, 23), input(66, 10)], vec![output(34, false), output(35, true), output(34, false)]);
    probe("v4_agent_spend_worst_fuel", vec![input(21016, 132), input(66, 10)], vec![output(34, false), output(35, true), output(34, false)]);
    probe("v4_owner_op", vec![input(19320, 22), input(66, 10)], vec![output(35, true), output(34, false)]);
    probe("v4_recover", vec![input(18926, 14), input(66, 10)], vec![output(34, false), output(34, false)]);
}
