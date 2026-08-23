//! VM layer — valid-path tests (VVM).
//!
//! Every test executes the real TxScriptEngine with covenants enabled and
//! real Schnorr signatures.

use policyvault_vm_tests::*;
use silverscript_lang::ast::Expr;

const KAS: i64 = 100_000_000;

struct Actors {
    owner: secp256k1::Keypair,
    delegate: secp256k1::Keypair,
    r1: secp256k1::Keypair,
    r2: secp256k1::Keypair,
    r3: secp256k1::Keypair,
    policy: PolicySpec,
}

fn actors() -> Actors {
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let policy = test_policy(&owner, &delegate, [&r1, &r2, &r3]);
    Actors { owner, delegate, r1, r2, r3, policy }
}

fn initial_state(policy: &PolicySpec) -> StateSpec {
    StateSpec {
        protected_value: policy.init_value,
        period_start_daa: policy.init_period_start_daa,
        period_spent: 0,
        paused: 0,
    }
}

/// Build a delegateSpend case: pay `amount` to recipient `idx`, expecting
/// `successor` as the exact new state.
fn spend_case(
    a: &Actors,
    prev: &StateSpec,
    successor: &StateSpec,
    amount: i64,
    idx: i64,
    recipient_pk: [u8; 32],
) -> TransitionCase {
    let active = compile_state(&a.policy, prev);
    let next = compile_state(&a.policy, successor);
    let succ = successor.clone();
    TransitionCase {
        outputs: vec![p2pk_output(&recipient_pk, amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: Box::new(move |sig| vec![state_arg(&succ), Expr::int(amount), Expr::int(idx), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    }
}

#[test]
fn vvm_valid_delegate_payment() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let succ = StateSpec { protected_value: prev.protected_value - 25 * KAS, period_spent: 25 * KAS, ..prev.clone() };
    let result = run_case(spend_case(&a, &prev, &succ, 25 * KAS, 1, xonly(&a.r1)));
    assert!(result.is_ok(), "valid delegate payment failed: {:?}", result.err());
}

#[test]
fn vvm_exact_cap_payment() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let amount = a.policy.max_per_spend;
    let succ = StateSpec { protected_value: prev.protected_value - amount, period_spent: amount, ..prev.clone() };
    let result = run_case(spend_case(&a, &prev, &succ, amount, 2, xonly(&a.r2)));
    assert!(result.is_ok(), "exact cap payment failed: {:?}", result.err());
}

#[test]
fn vvm_exact_remaining_budget_payment() {
    let a = actors();
    // 450 KAS already spent this period; exactly 50 KAS of budget remains.
    let prev = StateSpec { period_spent: 45_000_000_000, protected_value: 55_000_000_000, ..initial_state(&a.policy) };
    let amount = a.policy.period_budget - prev.period_spent;
    let succ = StateSpec {
        protected_value: prev.protected_value - amount,
        period_spent: a.policy.period_budget,
        ..prev.clone()
    };
    let result = run_case(spend_case(&a, &prev, &succ, amount, 3, xonly(&a.r3)));
    assert!(result.is_ok(), "exact remaining-budget payment failed: {:?}", result.err());
}

#[test]
fn vvm_sequential_payments() {
    let a = actors();
    let mut prev = initial_state(&a.policy);
    for step in 1..=3i64 {
        let amount = step * 10 * KAS;
        let succ = StateSpec {
            protected_value: prev.protected_value - amount,
            period_spent: prev.period_spent + amount,
            ..prev.clone()
        };
        let result = run_case(spend_case(&a, &prev, &succ, amount, 1, xonly(&a.r1)));
        assert!(result.is_ok(), "sequential payment #{step} failed: {:?}", result.err());
        prev = succ;
    }
    assert_eq!(prev.period_spent, 60 * KAS);
    assert_eq!(prev.protected_value, a.policy.init_value - 60 * KAS);
}

#[test]
fn vvm_valid_rollover_and_spend() {
    let a = actors();
    // Budget exhausted in the current period.
    let prev = StateSpec { period_spent: a.policy.period_budget, protected_value: 50_000_000_000, ..initial_state(&a.policy) };
    let amount = 30 * KAS;
    let new_start = prev.period_start_daa + a.policy.period_length_daa;
    let succ = StateSpec {
        protected_value: prev.protected_value - amount,
        period_start_daa: new_start,
        period_spent: amount,
        paused: 0,
    };
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &succ);
    let succ_c = succ.clone();
    let result = run_case(TransitionCase {
        outputs: vec![p2pk_output(&xonly(&a.r1), amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        // lock_time proves the new period start has been reached.
        lock_time: new_start as u64,
        function: "rolloverAndSpend",
        args: Box::new(move |sig| {
            vec![state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::int(1), Expr::bytes(sig)]
        }),
        signer: a.delegate,
        active,
    });
    assert!(result.is_ok(), "valid rollover+spend failed: {:?}", result.err());
}

#[test]
fn vvm_valid_multi_period_rollover() {
    let a = actors();
    let prev = StateSpec { period_spent: a.policy.period_budget, protected_value: 50_000_000_000, ..initial_state(&a.policy) };
    let amount = 10 * KAS;
    let periods = 3i64;
    let new_start = prev.period_start_daa + periods * a.policy.period_length_daa;
    let succ = StateSpec {
        protected_value: prev.protected_value - amount,
        period_start_daa: new_start,
        period_spent: amount,
        paused: 0,
    };
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &succ);
    let succ_c = succ.clone();
    let result = run_case(TransitionCase {
        outputs: vec![p2pk_output(&xonly(&a.r2), amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        // Lock time is even later than the claimed new start: still valid.
        lock_time: (new_start + 500) as u64,
        function: "rolloverAndSpend",
        args: Box::new(move |sig| {
            vec![state_arg(&succ_c), Expr::int(amount), Expr::int(2), Expr::int(periods), Expr::bytes(sig)]
        }),
        signer: a.delegate,
        active,
    });
    assert!(result.is_ok(), "valid multi-period rollover failed: {:?}", result.err());
}

#[test]
fn vvm_owner_pause_then_unpause() {
    let a = actors();
    let prev = StateSpec { period_spent: 20 * KAS, protected_value: 80_000_000_000, ..initial_state(&a.policy) };

    // Pause.
    let paused_state = StateSpec { paused: 1, ..prev.clone() };
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &paused_state);
    let ps = paused_state.clone();
    let result = run_case(TransitionCase {
        outputs: vec![successor_output(&next, paused_state.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerPause",
        args: Box::new(move |sig| vec![state_arg(&ps), Expr::bytes(sig)]),
        signer: a.owner,
        active,
    });
    assert!(result.is_ok(), "owner pause failed: {:?}", result.err());

    // Unpause.
    let unpaused = StateSpec { paused: 0, ..paused_state.clone() };
    let active = compile_state(&a.policy, &paused_state);
    let next = compile_state(&a.policy, &unpaused);
    let us = unpaused.clone();
    let result = run_case(TransitionCase {
        outputs: vec![successor_output(&next, unpaused.protected_value as u64)],
        utxo_value: paused_state.protected_value as u64,
        lock_time: 0,
        function: "ownerUnpause",
        args: Box::new(move |sig| vec![state_arg(&us), Expr::bytes(sig)]),
        signer: a.owner,
        active,
    });
    assert!(result.is_ok(), "owner unpause failed: {:?}", result.err());
}

#[test]
fn vvm_valid_owner_recovery() {
    let a = actors();
    let prev = StateSpec { period_spent: 20 * KAS, protected_value: 80_000_000_000, ..initial_state(&a.policy) };
    let active = compile_state(&a.policy, &prev);
    let result = run_case(TransitionCase {
        outputs: vec![p2pk_output(&xonly(&a.owner), prev.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.owner,
        active,
    });
    assert!(result.is_ok(), "valid owner recovery failed: {:?}", result.err());
}

#[test]
fn vvm_owner_recovery_while_paused() {
    let a = actors();
    let prev = StateSpec { paused: 1, protected_value: 80_000_000_000, period_spent: 20 * KAS, ..initial_state(&a.policy) };
    let active = compile_state(&a.policy, &prev);
    let result = run_case(TransitionCase {
        outputs: vec![p2pk_output(&xonly(&a.owner), prev.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.owner,
        active,
    });
    assert!(result.is_ok(), "owner recovery while paused failed: {:?}", result.err());
}
