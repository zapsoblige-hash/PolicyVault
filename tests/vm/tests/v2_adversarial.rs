//! VM layer — v0.2 negative-validation tests (V2-AVM).
//!
//! Adversary model: policy-invalid adversarial test transactions correctly
//! signed by the stated key (usually the legitimate delegate, sometimes the
//! owner for successor-forgery cases, sometimes an outside attacker),
//! executed on the real TxScriptEngine with covenants enabled. Every case
//! must be rejected by the VM.

use policyvault_vm_tests::*;
use silverscript_lang::ast::Expr;

const KAS: i64 = 100_000_000;

struct Actors {
    owner: secp256k1::Keypair,
    delegate: secp256k1::Keypair,
    delegate2: secp256k1::Keypair,
    attacker: secp256k1::Keypair,
    r1: secp256k1::Keypair,
    template: V2Template,
    state: V2State,
}

fn actors() -> Actors {
    let owner = deterministic_keypair(1);
    let delegate = deterministic_keypair(2);
    let delegate2 = deterministic_keypair(7);
    let attacker = deterministic_keypair(66);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let template = V2Template { owner_pk: xonly(&owner) };
    let state = test_v2_state(&delegate, [&r1, &r2, &r3]);
    Actors { owner, delegate, delegate2, attacker, r1, template, state }
}

fn spend_successor(prev: &V2State, amount: i64) -> V2State {
    V2State { protected_value: prev.protected_value - amount, period_spent: prev.period_spent + amount, ..prev.clone() }
}

/// Generic transition runner: `claimed` is the successor state in the call,
/// `baked` the state actually compiled into the successor output.
struct V2Attack {
    prev: V2State,
    claimed: V2State,
    baked: V2State,
    baked_vault_id: &'static str,
    outputs_head: Vec<kaspa_consensus_core::tx::TransactionOutput>,
    successor_value: u64,
    function: &'static str,
    extra_args: Vec<Expr<'static>>,
    signer: secp256k1::Keypair,
}

impl V2Attack {
    fn owner_op(a: &Actors, prev: &V2State, next: &V2State, function: &'static str) -> Self {
        V2Attack {
            prev: prev.clone(),
            claimed: next.clone(),
            baked: next.clone(),
            baked_vault_id: VAULT_ID,
            outputs_head: vec![],
            successor_value: next.protected_value as u64,
            function,
            extra_args: vec![],
            signer: a.owner,
        }
    }

    fn spend(a: &Actors, prev: &V2State, amount: i64) -> Self {
        let succ = spend_successor(prev, amount);
        V2Attack {
            prev: prev.clone(),
            claimed: succ.clone(),
            baked: succ.clone(),
            baked_vault_id: VAULT_ID,
            outputs_head: vec![p2pk_output(&prev.recipient1_pk, amount as u64)],
            successor_value: succ.protected_value as u64,
            function: "delegateSpend",
            extra_args: vec![Expr::int(amount), Expr::int(1)],
            signer: a.delegate,
        }
    }

    fn run(self, a: &Actors) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        let active = compile_v2_state(&a.template, &self.prev);
        let next = compile_v2_state_with_vault_id(&a.template, &self.baked, self.baked_vault_id);
        let claimed = self.claimed.clone();
        let extra = self.extra_args.clone();
        let mut outputs = self.outputs_head;
        outputs.push(successor_output(&next, self.successor_value));
        run_v2_case(TransitionCase {
            active,
            outputs,
            utxo_value: self.prev.protected_value as u64,
            lock_time: 0,
            function: self.function,
            args: Box::new(move |sig| {
                let mut args = vec![v2_state_arg(&claimed)];
                args.extend(extra.clone());
                args.push(Expr::bytes(sig));
                args
            }),
            signer: self.signer,
        })
    }
}

// ============================================================ DELEGATE SPEND
// The v0.1 spend threats re-proven against the v0.2 template (policy now
// lives in state).

#[test]
fn v2_avm_01_wrong_delegate_key() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.signer = a.attacker;
    assert!(attack.run(&a).is_err(), "wrong delegate key must be rejected");
}

#[test]
fn v2_avm_02_wrong_recipient() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.outputs_head = vec![p2pk_output(&xonly(&a.attacker), 25 * KAS as u64)];
    assert!(attack.run(&a).is_err(), "non-allowlisted recipient must be rejected");
}

#[test]
fn v2_avm_03_over_per_spend_cap() {
    let a = actors();
    let attack = V2Attack::spend(&a, &a.state, a.state.max_per_spend + 1);
    assert!(attack.run(&a).is_err(), "over-cap spend must be rejected");
}

#[test]
fn v2_avm_04_cumulative_over_budget() {
    let a = actors();
    let mut prev = a.state.clone();
    prev.period_spent = prev.period_budget - 5 * KAS;
    let attack = V2Attack::spend(&a, &prev, 6 * KAS);
    assert!(attack.run(&a).is_err(), "over-budget spend must be rejected");
}

#[test]
fn v2_avm_05_forged_successor_period_spent() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.claimed.period_spent = a.state.period_spent; // unchanged
    attack.baked.period_spent = a.state.period_spent;
    assert!(attack.run(&a).is_err(), "unchanged periodSpent must be rejected");
}

#[test]
fn v2_avm_06_delegate_bumps_own_cap_in_successor() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.claimed.max_per_spend = 1000 * KAS;
    attack.baked.max_per_spend = 1000 * KAS;
    assert!(attack.run(&a).is_err(), "delegate must not raise its own cap");
}

#[test]
fn v2_avm_07_delegate_swaps_allowlist_in_successor() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.claimed.recipient1_pk = xonly(&a.attacker);
    attack.baked.recipient1_pk = xonly(&a.attacker);
    assert!(attack.run(&a).is_err(), "delegate must not modify the allowlist");
}

#[test]
fn v2_avm_08_delegate_rotates_itself_in_successor() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.claimed.delegate_pk = xonly(&a.attacker);
    attack.baked.delegate_pk = xonly(&a.attacker);
    assert!(attack.run(&a).is_err(), "delegate must not rotate the delegate key in a spend");
}

#[test]
fn v2_avm_09_delegate_bumps_policy_nonce() {
    let a = actors();
    let mut attack = V2Attack::spend(&a, &a.state, 25 * KAS);
    attack.claimed.policy_nonce = 1;
    attack.baked.policy_nonce = 1;
    assert!(attack.run(&a).is_err(), "delegate must not bump policyNonce");
}

#[test]
fn v2_avm_10_spend_while_paused_and_while_revoked() {
    let a = actors();
    let paused = V2State { paused: 1, ..a.state.clone() };
    let mut attack = V2Attack::spend(&a, &paused, 10 * KAS);
    attack.claimed.paused = 0;
    attack.baked.paused = 0;
    assert!(attack.run(&a).is_err(), "paused spend must be rejected");

    let revoked = V2State { delegate_active: 0, ..a.state.clone() };
    let mut attack = V2Attack::spend(&a, &revoked, 10 * KAS);
    attack.claimed.delegate_active = 1;
    attack.baked.delegate_active = 1;
    assert!(attack.run(&a).is_err(), "revoked spend must be rejected");
}

#[test]
fn v2_avm_11_revoked_delegate_rollover() {
    let a = actors();
    let revoked = V2State { delegate_active: 0, period_spent: 45_000_000_000, ..a.state.clone() };
    let amount = 10 * KAS;
    let new_start = revoked.period_start_daa + revoked.period_length_daa;
    let succ = V2State {
        protected_value: revoked.protected_value - amount,
        period_start_daa: new_start,
        period_spent: amount,
        delegate_active: 1, // forged re-enable
        ..revoked.clone()
    };
    let active = compile_v2_state(&a.template, &revoked);
    let next = compile_v2_state(&a.template, &succ);
    let succ_c = succ.clone();
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&revoked.recipient1_pk, amount as u64), successor_output(&next, succ.protected_value as u64)],
        utxo_value: revoked.protected_value as u64,
        lock_time: new_start as u64,
        function: "rolloverAndSpend",
        args: Box::new(move |sig| {
            vec![v2_state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::int(1), Expr::bytes(sig)]
        }),
        signer: a.delegate,
    });
    assert!(result.is_err(), "revoked delegate rollover must be rejected");
}

// ================================================================== REVOKE

#[test]
fn v2_avm_12_delegate_attempts_revoke() {
    let a = actors();
    let revoked = V2State { delegate_active: 0, ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &revoked, "revokeDelegate");
    attack.signer = a.delegate;
    assert!(attack.run(&a).is_err(), "delegate-signed revoke must be rejected");
}

#[test]
fn v2_avm_13_revoke_with_attacker_signature() {
    let a = actors();
    let revoked = V2State { delegate_active: 0, ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &revoked, "revokeDelegate");
    attack.signer = a.attacker;
    assert!(attack.run(&a).is_err(), "attacker-signed revoke must be rejected");
}

#[test]
fn v2_avm_14_revoke_successor_retains_authority() {
    let a = actors();
    // Claim revoke but bake delegateActive = 1 in the successor.
    let mut next = a.state.clone();
    next.delegate_active = 0;
    let mut attack = V2Attack::owner_op(&a, &a.state, &next, "revokeDelegate");
    attack.baked.delegate_active = 1;
    assert!(attack.run(&a).is_err(), "successor secretly retaining delegate authority must be rejected");
}

#[test]
fn v2_avm_15_revoke_mutates_value_or_accounting() {
    let a = actors();
    // Nonzero periodSpent so an accounting reset is a real mutation.
    let mut prev = a.state.clone();
    prev.period_spent = 40 * KAS;
    for mutate in [
        |s: &mut V2State| s.protected_value -= 10 * KAS,
        |s: &mut V2State| s.period_spent = 0,
        |s: &mut V2State| s.period_start_daa += 1000,
    ] {
        let mut next = prev.clone();
        next.delegate_active = 0;
        mutate(&mut next);
        let mut attack = V2Attack::owner_op(&a, &prev, &next, "revokeDelegate");
        attack.successor_value = next.protected_value as u64;
        assert!(attack.run(&a).is_err(), "revoke mutating value/accounting must be rejected");
    }
}

// ================================================================== ROTATE

#[test]
fn v2_avm_16_delegate_attempts_rotation() {
    let a = actors();
    let rotated = V2State { delegate_pk: xonly(&a.attacker), ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &rotated, "rotateDelegate");
    attack.extra_args = vec![Expr::bytes(xonly(&a.attacker).to_vec())];
    attack.signer = a.delegate;
    assert!(attack.run(&a).is_err(), "delegate-signed rotation must be rejected");
}

#[test]
fn v2_avm_17_rotation_successor_uses_unintended_key() {
    let a = actors();
    // Owner authorizes rotation to delegate2, but the successor bakes the
    // attacker's key (and the claimed state matches the bake — the arg pin
    // must catch it).
    let rotated = V2State { delegate_pk: xonly(&a.attacker), ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &rotated, "rotateDelegate");
    attack.extra_args = vec![Expr::bytes(xonly(&a.delegate2).to_vec())]; // owner-selected key
    assert!(attack.run(&a).is_err(), "successor with unintended delegate key must be rejected");
}

#[test]
fn v2_avm_18_rotation_resets_accounting_or_policy() {
    let a = actors();
    let mut prev = a.state.clone();
    prev.period_spent = 40 * KAS;
    for mutate in [
        |s: &mut V2State| s.period_spent = 0,
        |s: &mut V2State| s.period_start_daa += 864_000,
        |s: &mut V2State| s.max_per_spend *= 10,
        |s: &mut V2State| s.period_budget *= 10,
        |s: &mut V2State| s.recipient1_pk = [0x33; 32],
    ] {
        let mut rotated = prev.clone();
        rotated.delegate_pk = xonly(&a.delegate2);
        mutate(&mut rotated);
        let mut attack = V2Attack::owner_op(&a, &prev, &rotated, "rotateDelegate");
        attack.extra_args = vec![Expr::bytes(xonly(&a.delegate2).to_vec())];
        assert!(attack.run(&a).is_err(), "rotation smuggling accounting/policy changes must be rejected");
    }
}

// ================================================================== TOP-UP

#[test]
fn v2_avm_19_delegate_attempts_topup() {
    let a = actors();
    let topped = V2State { protected_value: a.state.protected_value + 100 * KAS, ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &topped, "ownerTopUp");
    attack.signer = a.delegate;
    assert!(attack.run(&a).is_err(), "delegate-signed top-up must be rejected");
}

#[test]
fn v2_avm_20_topup_successor_value_mismatch() {
    let a = actors();
    let topped = V2State { protected_value: a.state.protected_value + 100 * KAS, ..a.state.clone() };
    // Successor output carries LESS than the claimed new principal.
    let mut attack = V2Attack::owner_op(&a, &a.state, &topped, "ownerTopUp");
    attack.successor_value = (topped.protected_value - 1) as u64;
    assert!(attack.run(&a).is_err(), "top-up successor underfunding must be rejected");
    // And MORE than claimed.
    let mut attack = V2Attack::owner_op(&a, &a.state, &topped, "ownerTopUp");
    attack.successor_value = (topped.protected_value + 1) as u64;
    assert!(attack.run(&a).is_err(), "top-up successor overfunding must be rejected");
}

#[test]
fn v2_avm_21_topup_not_an_increase() {
    let a = actors();
    let same = a.state.clone();
    let attack = V2Attack::owner_op(&a, &a.state, &same, "ownerTopUp");
    assert!(attack.run(&a).is_err(), "top-up with no increase must be rejected");

    let mut lowered = a.state.clone();
    lowered.protected_value -= 10 * KAS;
    let mut attack = V2Attack::owner_op(&a, &a.state, &lowered, "ownerTopUp");
    attack.successor_value = lowered.protected_value as u64;
    assert!(attack.run(&a).is_err(), "top-up decreasing principal must be rejected");
}

#[test]
fn v2_avm_22_topup_smuggles_policy_or_accounting_change() {
    let a = actors();
    // Nonzero periodSpent so an accounting reset is a real mutation.
    let mut prev = a.state.clone();
    prev.period_spent = 40 * KAS;
    for mutate in [
        |s: &mut V2State| s.period_spent = 0,
        |s: &mut V2State| s.period_start_daa += 1000,
        |s: &mut V2State| s.max_per_spend *= 2,
        |s: &mut V2State| s.delegate_pk = [0x44; 32],
        |s: &mut V2State| s.paused = 1,
        |s: &mut V2State| s.policy_nonce += 1,
    ] {
        let mut topped = prev.clone();
        topped.protected_value += 100 * KAS;
        mutate(&mut topped);
        let mut attack = V2Attack::owner_op(&a, &prev, &topped, "ownerTopUp");
        attack.successor_value = topped.protected_value as u64;
        assert!(attack.run(&a).is_err(), "top-up smuggling a policy/accounting change must be rejected");
    }
}

// ================================================================ MIGRATION

#[test]
fn v2_avm_23_delegate_attempts_migration() {
    let a = actors();
    let migrated = V2State { max_per_spend: 1000 * KAS, policy_nonce: 1, ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &migrated, "migratePolicy");
    attack.signer = a.delegate;
    assert!(attack.run(&a).is_err(), "delegate-signed migration must be rejected");
}

#[test]
fn v2_avm_24_migration_wrong_nonce() {
    let a = actors();
    for nonce in [0i64, 2] {
        let migrated = V2State { max_per_spend: 200 * KAS, policy_nonce: nonce, ..a.state.clone() };
        let attack = V2Attack::owner_op(&a, &a.state, &migrated, "migratePolicy");
        assert!(attack.run(&a).is_err(), "migration with policyNonce {nonce} (expected 1) must be rejected");
    }
}

#[test]
fn v2_avm_25_migration_mutates_protected_or_accounting() {
    let a = actors();
    let mut prev = a.state.clone();
    prev.period_spent = 40 * KAS;
    for mutate in [
        |s: &mut V2State| s.protected_value -= 10 * KAS,
        |s: &mut V2State| s.period_spent = 0,
        |s: &mut V2State| s.period_start_daa += 864_000,
    ] {
        let mut migrated = prev.clone();
        migrated.max_per_spend = 200 * KAS;
        migrated.policy_nonce = 1;
        mutate(&mut migrated);
        let mut attack = V2Attack::owner_op(&a, &prev, &migrated, "migratePolicy");
        attack.successor_value = migrated.protected_value as u64;
        assert!(attack.run(&a).is_err(), "migration mutating principal/accounting must be rejected");
    }
}

#[test]
fn v2_avm_26_migration_changes_delegate_or_status() {
    let a = actors();
    for mutate in [
        |s: &mut V2State| s.delegate_pk = [0x55; 32],
        |s: &mut V2State| s.delegate_active = 0,
        |s: &mut V2State| s.paused = 1,
    ] {
        let mut migrated = a.state.clone();
        migrated.period_budget = 1000 * KAS;
        migrated.policy_nonce = 1;
        mutate(&mut migrated);
        let attack = V2Attack::owner_op(&a, &a.state, &migrated, "migratePolicy");
        assert!(attack.run(&a).is_err(), "migration changing delegate identity/status must be rejected");
    }
}

#[test]
fn v2_avm_27_migration_invalid_policy_values() {
    let a = actors();
    for mutate in [
        |s: &mut V2State| s.max_per_spend = 0,
        |s: &mut V2State| s.period_budget = 0,
        |s: &mut V2State| s.period_length_daa = 0,
    ] {
        let mut migrated = a.state.clone();
        migrated.policy_nonce = 1;
        mutate(&mut migrated);
        let attack = V2Attack::owner_op(&a, &a.state, &migrated, "migratePolicy");
        assert!(attack.run(&a).is_err(), "migration to zero policy values must be rejected");
    }
}

#[test]
fn v2_avm_28_migration_wrong_vault_identity() {
    let a = actors();
    let migrated = V2State { max_per_spend: 200 * KAS, policy_nonce: 1, ..a.state.clone() };
    let mut attack = V2Attack::owner_op(&a, &a.state, &migrated, "migratePolicy");
    attack.baked_vault_id = "3333333333333333333333333333333333333333333333333333333333333333";
    // Claimed boundVaultId also forged to match the bake.
    let forged = "3333333333333333333333333333333333333333333333333333333333333333";
    let migrated_c = migrated.clone();
    attack.claimed = migrated.clone();
    let active = compile_v2_state(&a.template, &a.state);
    let next = compile_v2_state_with_vault_id(&a.template, &migrated, forged);
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![successor_output(&next, migrated.protected_value as u64)],
        utxo_value: a.state.protected_value as u64,
        lock_time: 0,
        function: "migratePolicy",
        args: Box::new(move |sig| vec![v2_state_arg_with_vault_id(&migrated_c, forged), Expr::bytes(sig)]),
        signer: a.owner,
    });
    assert!(result.is_err(), "migration to a different vault identity must be rejected");
    let _ = attack;
}

// ===================================================== LINEAGE / TERMINATION

#[test]
fn v2_avm_29_cross_template_successor_rejected() {
    let a = actors();
    // Owner-signed rotate whose successor output is a v0.1-template script
    // carrying the same covenant id: same-template binding must reject it.
    let owner = a.owner;
    let d1 = deterministic_keypair(2);
    let r1 = deterministic_keypair(3);
    let r2 = deterministic_keypair(4);
    let r3 = deterministic_keypair(5);
    let v01_policy = test_policy(&owner, &d1, [&r1, &r2, &r3]);
    let v01_state = StateSpec {
        protected_value: a.state.protected_value,
        period_start_daa: a.state.period_start_daa,
        period_spent: 0,
        paused: 0,
    };
    let v01_next = compile_state(&v01_policy, &v01_state);

    let rotated = V2State { delegate_pk: xonly(&a.delegate2), ..a.state.clone() };
    let rotated_c = rotated.clone();
    let new_pk = xonly(&a.delegate2);
    let active = compile_v2_state(&a.template, &a.state);
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![successor_output(&v01_next, rotated.protected_value as u64)],
        utxo_value: a.state.protected_value as u64,
        lock_time: 0,
        function: "rotateDelegate",
        args: Box::new(move |sig| vec![v2_state_arg(&rotated_c), Expr::bytes(new_pk.to_vec()), Expr::bytes(sig)]),
        signer: a.owner,
    });
    assert!(result.is_err(), "v0.2 must reject a cross-template successor even when owner-signed");
}

#[test]
fn v2_avm_30_delegate_attempts_recovery() {
    let a = actors();
    let active = compile_v2_state(&a.template, &a.state);
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&xonly(&a.delegate), a.state.protected_value as u64)],
        utxo_value: a.state.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.delegate,
    });
    assert!(result.is_err(), "delegate-signed recovery must be rejected");
    let _ = a.r1;
}

#[test]
fn v2_avm_31_lifecycle_op_with_extra_bound_successor() {
    let a = actors();
    // Rotate with TWO covenant-bound successors: singleton must reject.
    let rotated = V2State { delegate_pk: xonly(&a.delegate2), ..a.state.clone() };
    let next = compile_v2_state(&a.template, &rotated);
    let rotated_c = rotated.clone();
    let new_pk = xonly(&a.delegate2);
    let active = compile_v2_state(&a.template, &a.state);
    let half = (rotated.protected_value / 2) as u64;
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![successor_output(&next, half), successor_output(&next, half)],
        utxo_value: a.state.protected_value as u64,
        lock_time: 0,
        function: "rotateDelegate",
        args: Box::new(move |sig| vec![v2_state_arg(&rotated_c), Expr::bytes(new_pk.to_vec()), Expr::bytes(sig)]),
        signer: a.owner,
    });
    assert!(result.is_err(), "two bound successors on a singleton lifecycle op must be rejected");
}

#[test]
fn v2_avm_32_unauthorized_termination_via_lifecycle() {
    let a = actors();
    // revokeDelegate with NO successor output at all — the delegate/owner
    // cannot terminate the lineage through a non-terminal path.
    let revoked = V2State { delegate_active: 0, ..a.state.clone() };
    let revoked_c = revoked.clone();
    let active = compile_v2_state(&a.template, &a.state);
    let result = run_v2_case(TransitionCase {
        active,
        outputs: vec![p2pk_output(&a.template.owner_pk, a.state.protected_value as u64)],
        utxo_value: a.state.protected_value as u64,
        lock_time: 0,
        function: "revokeDelegate",
        args: Box::new(move |sig| vec![v2_state_arg(&revoked_c), Expr::bytes(sig)]),
        signer: a.owner,
    });
    assert!(result.is_err(), "lifecycle op without a bound successor must be rejected");
}
