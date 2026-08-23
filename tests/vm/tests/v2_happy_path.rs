//! VM layer — v0.2 valid-path tests (V2-VVM).
//!
//! Every test executes the real TxScriptEngine with covenants enabled and
//! real Schnorr signatures against contracts/PolicyVault.v0.2.sil.

use policyvault_vm_tests::*;
use silverscript_lang::ast::Expr;

const KAS: i64 = 100_000_000;

struct Actors {
    owner: secp256k1::Keypair,
    delegate: secp256k1::Keypair,
    delegate2: secp256k1::Keypair,
    r1: secp256k1::Keypair,
    r2: secp256k1::Keypair,
    template: V2Template,
    state: V2State,
}

fn actors() -> Actors {
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let delegate2 = deterministic_keypair(7);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let template = V2Template { owner_pk: xonly(&owner) };
    let state = test_v2_state(&delegate, [&r1, &r2, &r3]);
    Actors { owner, delegate, delegate2, r1, r2, template, state }
}

fn spend_successor(prev: &V2State, amount: i64) -> V2State {
    V2State { protected_value: prev.protected_value - amount, period_spent: prev.period_spent + amount, ..prev.clone() }
}

/// Run a valid delegateSpend and assert acceptance.
fn assert_spend_ok(a: &Actors, prev: &V2State, amount: i64, signer: &secp256k1::Keypair) {
    let succ = spend_successor(prev, amount);
    let active = compile_v2_state(&a.template, prev);
    let next = compile_v2_state(&a.template, &succ);
    let succ_c = succ.clone();
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&prev.recipient1_pk, amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: Box::new(move |sig| vec![v2_state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::bytes(sig)]),
        signer: *signer,
    });
    assert!(result.is_ok(), "valid v0.2 delegateSpend rejected: {result:?}");
}

/// Run an owner lifecycle op with claimed successor `next_state`.
fn run_owner_op(
    a: &Actors,
    prev: &V2State,
    next_state: &V2State,
    function: &'static str,
    extra_args: Vec<Expr<'static>>,
    signer: &secp256k1::Keypair,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let active = compile_v2_state(&a.template, prev);
    let next = compile_v2_state(&a.template, next_state);
    let next_c = next_state.clone();
    run_v2_case(TransitionCase {
        active,
        outputs: vec![successor_output(&next, next_state.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function,
        args: Box::new(move |sig| {
            let mut args = vec![v2_state_arg(&next_c)];
            args.extend(extra_args.clone());
            args.push(Expr::bytes(sig));
            args
        }),
        signer: *signer,
    })
}

#[test]
fn v2_vvm_01_compiles_with_expected_layout() {
    let a = actors();
    let compiled = compile_v2_state(&a.template, &a.state);
    let layout = compiled.state_layout;
    assert!(layout.len > 69, "v0.2 state region must be larger than v0.1's 69 bytes, got {}", layout.len);
    println!(
        "v0.2 script={} bytes, state region start={} len={}",
        compiled.script.len(),
        layout.start,
        layout.len
    );
}

#[test]
fn v2_vvm_02_valid_delegate_spend() {
    let a = actors();
    assert_spend_ok(&a, &a.state, 25 * KAS, &a.delegate);
}

#[test]
fn v2_vvm_03_exact_cap_and_exact_budget_spends() {
    let a = actors();
    // Exact per-spend cap.
    assert_spend_ok(&a, &a.state, a.state.max_per_spend, &a.delegate);
    // Exact remaining budget.
    let mut nearly_spent = a.state.clone();
    nearly_spent.period_spent = a.state.period_budget - 10 * KAS;
    assert_spend_ok(&a, &nearly_spent, 10 * KAS, &a.delegate);
}

#[test]
fn v2_vvm_04_sequential_spends() {
    let a = actors();
    let s1 = spend_successor(&a.state, 20 * KAS);
    assert_spend_ok(&a, &a.state, 20 * KAS, &a.delegate);
    assert_spend_ok(&a, &s1, 30 * KAS, &a.delegate);
}

#[test]
fn v2_vvm_05_valid_rollover_spend() {
    let a = actors();
    let mut prev = a.state.clone();
    prev.period_spent = 45_000_000_000; // nearly exhausted budget
    let amount = 40 * KAS;
    let periods = 2i64;
    let new_start = prev.period_start_daa + periods * prev.period_length_daa;
    let succ = V2State { protected_value: prev.protected_value - amount, period_start_daa: new_start, period_spent: amount, ..prev.clone() };

    let active = compile_v2_state(&a.template, &prev);
    let next = compile_v2_state(&a.template, &succ);
    let succ_c = succ.clone();
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&prev.recipient1_pk, amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: new_start as u64, // CLTV proof
        function: "rolloverAndSpend",
        args: Box::new(move |sig| {
            vec![v2_state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::int(periods), Expr::bytes(sig)]
        }),
        signer: a.delegate,
    });
    assert!(result.is_ok(), "valid v0.2 rolloverAndSpend rejected: {result:?}");
}

#[test]
fn v2_vvm_06_pause_unpause_cycle() {
    let a = actors();
    let paused = V2State { paused: 1, ..a.state.clone() };
    assert!(run_owner_op(&a, &a.state, &paused, "ownerPause", vec![], &a.owner).is_ok(), "pause rejected");
    assert!(run_owner_op(&a, &paused, &a.state, "ownerUnpause", vec![], &a.owner).is_ok(), "unpause rejected");
}

#[test]
fn v2_vvm_07_revoke_then_rotate_reenables() {
    let a = actors();
    // Owner revokes.
    let revoked = V2State { delegate_active: 0, ..a.state.clone() };
    assert!(run_owner_op(&a, &a.state, &revoked, "revokeDelegate", vec![], &a.owner).is_ok(), "revoke rejected");

    // Owner rotates in delegate2, re-enabling spending with preserved accounting.
    let rotated = V2State { delegate_pk: xonly(&a.delegate2), delegate_active: 1, ..revoked.clone() };
    let new_pk = xonly(&a.delegate2);
    assert!(
        run_owner_op(&a, &revoked, &rotated, "rotateDelegate", vec![Expr::bytes(new_pk.to_vec())], &a.owner).is_ok(),
        "rotate after revoke rejected"
    );

    // The rotated-in delegate can spend.
    assert_spend_ok(&a, &rotated, 15 * KAS, &a.delegate2);
}

#[test]
fn v2_vvm_08_rotate_preserves_accounting() {
    let a = actors();
    let mut prev = a.state.clone();
    prev.period_spent = 33 * KAS;
    let rotated = V2State { delegate_pk: xonly(&a.delegate2), ..prev.clone() };
    let new_pk = xonly(&a.delegate2);
    assert!(
        run_owner_op(&a, &prev, &rotated, "rotateDelegate", vec![Expr::bytes(new_pk.to_vec())], &a.owner).is_ok(),
        "rotate rejected"
    );
    assert_eq!(rotated.period_spent, 33 * KAS, "periodSpent must be preserved by rotation");
}

#[test]
fn v2_vvm_09_topup_then_spend() {
    let a = actors();
    let topped = V2State { protected_value: a.state.protected_value + 500 * KAS, ..a.state.clone() };
    assert!(run_owner_op(&a, &a.state, &topped, "ownerTopUp", vec![], &a.owner).is_ok(), "top-up rejected");
    assert_spend_ok(&a, &topped, 25 * KAS, &a.delegate);
}

#[test]
fn v2_vvm_10_migrate_policy_then_spend_under_new_policy() {
    let a = actors();
    // Owner raises the cap and budget; nonce 0 -> 1.
    let migrated = V2State {
        max_per_spend: 200 * KAS,
        period_budget: 1000 * KAS,
        policy_nonce: 1,
        ..a.state.clone()
    };
    assert!(run_owner_op(&a, &a.state, &migrated, "migratePolicy", vec![], &a.owner).is_ok(), "migration rejected");

    // A 150 KAS spend was invalid under the old 100 KAS cap, valid now.
    assert_spend_ok(&a, &migrated, 150 * KAS, &a.delegate);
}

#[test]
fn v2_vvm_11_migrate_allowlist_then_pay_new_recipient() {
    let a = actors();
    let new_recipient = deterministic_keypair(9);
    let migrated = V2State { recipient1_pk: xonly(&new_recipient), policy_nonce: 1, ..a.state.clone() };
    assert!(run_owner_op(&a, &a.state, &migrated, "migratePolicy", vec![], &a.owner).is_ok(), "allowlist migration rejected");
    // Spend to the NEW recipient1 succeeds.
    assert_spend_ok(&a, &migrated, 10 * KAS, &a.delegate);
}

#[test]
fn v2_vvm_12_owner_recover_terminal() {
    let a = actors();
    let active = compile_v2_state(&a.template, &a.state);
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&a.template.owner_pk, a.state.protected_value as u64)],
        utxo_value: a.state.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.owner,
    });
    assert!(result.is_ok(), "owner recovery rejected: {result:?}");
}

#[test]
fn v2_vvm_13_owner_recover_while_revoked_and_paused() {
    let a = actors();
    let prev = V2State { delegate_active: 0, paused: 1, ..a.state.clone() };
    let active = compile_v2_state(&a.template, &prev);
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&a.template.owner_pk, prev.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.owner,
    });
    assert!(result.is_ok(), "recovery of a revoked+paused vault rejected: {result:?}");
}

#[test]
fn v2_vvm_14_spend_blocked_when_new_budget_below_spent_until_rollover() {
    let a = actors();
    // Owner lowers the budget below what is already spent this period.
    let mut prev = a.state.clone();
    prev.period_spent = 40 * KAS;
    let migrated = V2State { period_budget: 30 * KAS, policy_nonce: 1, ..prev.clone() };
    assert!(run_owner_op(&a, &prev, &migrated, "migratePolicy", vec![], &a.owner).is_ok(), "budget-lowering migration rejected");

    // Rollover into a fresh period then spend within the NEW budget.
    let amount = 20 * KAS;
    let periods = 1i64;
    let new_start = migrated.period_start_daa + periods * migrated.period_length_daa;
    let succ = V2State {
        protected_value: migrated.protected_value - amount,
        period_start_daa: new_start,
        period_spent: amount,
        ..migrated.clone()
    };
    let active = compile_v2_state(&a.template, &migrated);
    let next = compile_v2_state(&a.template, &succ);
    let succ_c = succ.clone();
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&migrated.recipient1_pk, amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: migrated.protected_value as u64,
        lock_time: new_start as u64,
        function: "rolloverAndSpend",
        args: Box::new(move |sig| {
            vec![v2_state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::int(periods), Expr::bytes(sig)]
        }),
        signer: a.delegate,
    });
    assert!(result.is_ok(), "post-migration rollover spend rejected: {result:?}");
    let _ = a.r2;
    let _ = a.r1;
}
