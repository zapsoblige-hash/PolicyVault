//! VM layer — v0.2 compute-cost measurement.
//!
//! Measures the script units each v0.2 path actually consumes on the real
//! VM and asserts the compute budget the SDK will commit to (per path)
//! covers it with headroom. 1 budget unit = 10,000 script units;
//! grams = budget * 100; fee impact = grams * 100 sompi.

use policyvault_vm_tests::*;
use silverscript_lang::ast::Expr;

const KAS: i64 = 100_000_000;
/// Budget the v0.2 SDK commits for the covenant input (v0.1 used 100).
const V2_COVENANT_COMPUTE_BUDGET: u64 = 100;

fn measure(function: &'static str, build: impl FnOnce() -> TransitionCase) -> u64 {
    let (result, units) = run_case_measured(build());
    assert!(result.is_ok(), "{function}: case must be valid to measure: {result:?}");
    let budget_units = V2_COVENANT_COMPUTE_BUDGET * 10_000;
    println!("{function}: used_script_units={units} (budget {V2_COVENANT_COMPUTE_BUDGET} => {budget_units})");
    assert!(
        units <= budget_units,
        "{function}: consumes {units} script units, above the committed budget {budget_units}"
    );
    units
}

#[test]
fn v2_compute_costs_fit_committed_budget() {
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let delegate2 = deterministic_keypair(7);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let template = V2Template { owner_pk: xonly(&owner) };
    let state = test_v2_state(&delegate, [&r1, &r2, &r3]);

    // delegateSpend
    let amount = 25 * KAS;
    let succ = V2State { protected_value: state.protected_value - amount, period_spent: state.period_spent + amount, ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), succ.clone());
    measure("delegateSpend", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![p2pk_output(&s.recipient1_pk, amount as u64), successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::int(amount), Expr::int(1), Expr::bytes(sig)])
        },
        signer: delegate,
    });

    // rolloverAndSpend (worst arithmetic path)
    let new_start = state.period_start_daa + 2 * state.period_length_daa;
    let rsucc = V2State { protected_value: state.protected_value - amount, period_start_daa: new_start, period_spent: amount, ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), rsucc.clone());
    measure("rolloverAndSpend", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![p2pk_output(&s.recipient1_pk, amount as u64), successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: new_start as u64,
        function: "rolloverAndSpend",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::int(amount), Expr::int(1), Expr::int(2), Expr::bytes(sig)])
        },
        signer: delegate,
    });

    // rotateDelegate
    let rot = V2State { delegate_pk: xonly(&delegate2), ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), rot.clone());
    let new_pk = xonly(&delegate2);
    measure("rotateDelegate", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "rotateDelegate",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::bytes(new_pk.to_vec()), Expr::bytes(sig)])
        },
        signer: owner,
    });

    // migratePolicy
    let mig = V2State { max_per_spend: 200 * KAS, period_budget: 1000 * KAS, policy_nonce: 1, ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), mig.clone());
    measure("migratePolicy", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "migratePolicy",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::bytes(sig)])
        },
        signer: owner,
    });

    // ownerTopUp
    let top = V2State { protected_value: state.protected_value + 500 * KAS, ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), top.clone());
    measure("ownerTopUp", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "ownerTopUp",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::bytes(sig)])
        },
        signer: owner,
    });

    // revokeDelegate
    let rev = V2State { delegate_active: 0, ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), rev.clone());
    measure("revokeDelegate", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "revokeDelegate",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::bytes(sig)])
        },
        signer: owner,
    });

    // ownerRecover
    let (t, s) = (template.clone(), state.clone());
    measure("ownerRecover", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![p2pk_output(&t.owner_pk, s.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: owner,
    });

    // pause/unpause
    let paused = V2State { paused: 1, ..state.clone() };
    let (t, s, sc) = (template.clone(), state.clone(), paused.clone());
    measure("ownerPause", move || TransitionCase {
        active: compile_v2_state(&t, &s),
        outputs: vec![successor_output(&compile_v2_state(&t, &sc), sc.protected_value as u64)],
        utxo_value: s.protected_value as u64,
        lock_time: 0,
        function: "ownerPause",
        args: {
            let sc2 = sc.clone();
            Box::new(move |sig| vec![v2_state_arg(&sc2), Expr::bytes(sig)])
        },
        signer: owner,
    });
}
