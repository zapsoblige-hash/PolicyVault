//! VM layer — replicate the EXACT live testnet-10 transaction shape for a
//! v0.2 delegateSpend: two inputs (covenant + ordinary p2pk fuel), three
//! outputs (payment, successor at index 1, ordinary change), delegate signs
//! both inputs with SIG_HASH_ALL. Diagnoses the live rejection
//! "script ran, but verification failed".

use policyvault_vm_tests::*;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::CovenantDeclCallOptions;

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::pay_to_script_hash_script;

const KAS: i64 = 100_000_000;

fn sign_input(mutable: &MutableTransaction<Transaction>, idx: usize, keypair: &secp256k1::Keypair) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&mutable.as_verifiable(), idx, SIG_HASH_ALL, &reused);
    let message = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).expect("sighash");
    let schnorr = keypair.sign_schnorr(message);
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(schnorr.as_ref().as_slice());
    sig.push(SIG_HASH_ALL.to_u8());
    sig
}

#[test]
fn v2_live_shape_delegate_spend_two_inputs_three_outputs() {
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let template = V2Template { owner_pk: xonly(&owner) };
    let mut state = test_v2_state(&delegate, [&r1, &r2, &r3]);
    state.period_length_daa = 600;
    state.period_start_daa = 542_324_037 - 10;

    let amount = 40 * KAS;
    let succ = V2State { protected_value: state.protected_value - amount, period_spent: state.period_spent + amount, ..state.clone() };

    let active = compile_v2_state(&template, &state);
    let next = compile_v2_state(&template, &succ);

    // p2pk fuel utxo for the delegate.
    let delegate_p2pk = ScriptBuilder::new().add_data(&xonly(&delegate)).unwrap().add_op(OpCheckSig).unwrap().drain();
    let fuel_value: u64 = 10 * KAS as u64;

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

    let outputs = vec![
        p2pk_output(&xonly(&r1), amount as u64),                       // payment
        TransactionOutput {
            value: succ.protected_value as u64,
            script_public_key: pay_to_script_hash_script(&next.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
        p2pk_output(&xonly(&delegate), fuel_value - 1_121_800),        // change after exact fee
    ];

    let tx = Transaction::new(1, vec![cov_input, fuel_input], outputs, 0, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, state.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, kaspa_consensus_core::tx::ScriptPublicKey::new(0, delegate_p2pk.into()), 0, false, None);

    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);

    // Covenant input 0: encoded call + redeem push.
    let sig0 = sign_input(&mutable, 0, &delegate);
    let succ_c = succ.clone();
    let args = vec![v2_state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::bytes(sig0)];
    let mut sigscript = active
        .build_sig_script_for_covenant_decl("delegateSpend", args, CovenantDeclCallOptions { is_leader: false })
        .expect("encode");
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;

    // Fuel input 1: ordinary p2pk signature push.
    let sig1 = sign_input(&mutable, 1, &delegate);
    mutable.tx.inputs[1].signature_script = ScriptBuilder::new().add_data(&sig1).unwrap().drain();

    // Execute BOTH inputs like the node does.
    let (res0, units0) = execute_input_measured(mutable.tx.clone(), vec![cov_utxo.clone(), fuel_utxo.clone()], 0);
    println!("covenant input: {res0:?} ({units0} script units)");
    let (res1, units1) = execute_input_measured(mutable.tx.clone(), vec![cov_utxo, fuel_utxo], 1);
    println!("fuel input: {res1:?} ({units1} script units)");

    assert!(res0.is_ok(), "covenant input must verify in the live shape: {res0:?}");
    assert!(res1.is_ok(), "fuel input must verify in the live shape: {res1:?}");
}

#[test]
fn v2_live_shape_bad_signature_unit_marker() {
    // Same as the passing test but corrupt the covenant signature, to learn
    // the script-unit count at which a checkSig failure surfaces.
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let template = V2Template { owner_pk: xonly(&owner) };
    let state = test_v2_state(&delegate, [&r1, &r2, &r3]);
    let amount = 40 * KAS;
    let succ = V2State { protected_value: state.protected_value - amount, period_spent: state.period_spent + amount, ..state.clone() };
    let active = compile_v2_state(&template, &state);
    let next = compile_v2_state(&template, &succ);
    let delegate_p2pk = ScriptBuilder::new().add_data(&xonly(&delegate)).unwrap().add_op(OpCheckSig).unwrap().drain();
    let fuel_value: u64 = 10 * KAS as u64;
    let cov_input = TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 }, signature_script: vec![], sequence: 0, compute_commit: ComputeBudget(20).into() };
    let fuel_input = TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x43; 32]), index: 1 }, signature_script: vec![], sequence: 0, compute_commit: ComputeBudget(10).into() };
    let outputs = vec![
        p2pk_output(&xonly(&r1), amount as u64),
        TransactionOutput { value: succ.protected_value as u64, script_public_key: pay_to_script_hash_script(&next.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
        p2pk_output(&xonly(&delegate), fuel_value - 1_121_800),
    ];
    let tx = Transaction::new(1, vec![cov_input, fuel_input], outputs, 0, Default::default(), 0, vec![]);
    let cov_utxo = active_utxo(&active, state.protected_value as u64);
    let fuel_utxo = UtxoEntry::new(fuel_value, kaspa_consensus_core::tx::ScriptPublicKey::new(0, delegate_p2pk.into()), 0, false, None);
    let mut mutable = MutableTransaction::with_entries(tx, vec![cov_utxo.clone(), fuel_utxo.clone()]);
    let mut sig0 = sign_input(&mutable, 0, &delegate);
    sig0[10] ^= 0xff; // corrupt the schnorr signature
    let args = vec![v2_state_arg(&succ), Expr::int(amount), Expr::int(1), Expr::bytes(sig0)];
    let mut sigscript = active.build_sig_script_for_covenant_decl("delegateSpend", args, CovenantDeclCallOptions { is_leader: false }).unwrap();
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;
    let sig1 = sign_input(&mutable, 1, &delegate);
    mutable.tx.inputs[1].signature_script = ScriptBuilder::new().add_data(&sig1).unwrap().drain();
    let (res0, units0) = execute_input_measured(mutable.tx.clone(), vec![cov_utxo, fuel_utxo], 0);
    println!("corrupted-sig covenant input: {res0:?} ({units0} script units)");
}
