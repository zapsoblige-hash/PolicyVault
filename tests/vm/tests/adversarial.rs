//! ADVERSARIAL VM layer (AVM tests, docs/threat-model.md).
//!
//! Attacker model: the legitimate delegate key (unless a test says
//! otherwise), real Schnorr signatures over the actual malicious
//! transaction, executed on the real TxScriptEngine with covenants
//! enabled. Every case is a minimal mutation of a proven-valid case, so a
//! rejection isolates the covenant rule under attack.

use policyvault_vm_tests::*;
use silverscript_lang::ast::Expr;

const KAS: i64 = 100_000_000;

const OTHER_VAULT_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Actors {
    owner: secp256k1::Keypair,
    delegate: secp256k1::Keypair,
    attacker: secp256k1::Keypair,
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
    let attacker = deterministic_keypair(66);
    let policy = test_policy(&owner, &delegate, [&r1, &r2, &r3]);
    Actors { owner, delegate, attacker, r1, r2, r3, policy }
}

fn initial_state(policy: &PolicySpec) -> StateSpec {
    StateSpec {
        protected_value: policy.init_value,
        period_start_daa: policy.init_period_start_daa,
        period_spent: 0,
        paused: 0,
    }
}

/// Honest successor for a spend of `amount` from `prev`.
fn spend_successor(prev: &StateSpec, amount: i64) -> StateSpec {
    StateSpec { protected_value: prev.protected_value - amount, period_spent: prev.period_spent + amount, ..prev.clone() }
}

/// Case builder mirroring the proven-valid delegateSpend, with every field
/// overridable by the attack.
struct SpendAttack {
    prev: StateSpec,
    /// State claimed in the covenant call.
    claimed: StateSpec,
    /// State actually baked into the successor output script (usually ==
    /// claimed; differs for output-forgery attacks).
    baked: StateSpec,
    /// Policy used to compile the successor output (template forgery).
    successor_policy: PolicySpec,
    successor_vault_id: &'static str,
    pay_amount: i64,
    recipient_index: i64,
    /// Recipient pubkey actually placed at output 0.
    payment_pk: [u8; 32],
    /// Value actually placed at output 0.
    payment_value: u64,
    /// Value actually carried by the successor output.
    successor_value: u64,
    signer: secp256k1::Keypair,
}

impl SpendAttack {
    /// Honest baseline: everything consistent.
    fn honest(a: &Actors, prev: StateSpec, amount: i64) -> Self {
        let succ = spend_successor(&prev, amount);
        SpendAttack {
            claimed: succ.clone(),
            baked: succ.clone(),
            successor_policy: a.policy.clone(),
            successor_vault_id: VAULT_ID,
            pay_amount: amount,
            recipient_index: 1,
            payment_pk: xonly(&a.r1),
            payment_value: amount as u64,
            successor_value: succ.protected_value as u64,
            signer: a.delegate,
            prev,
        }
    }

    fn run(self, a: &Actors) -> Result<(), kaspa_txscript_errors::TxScriptError> {
        let active = compile_state(&a.policy, &self.prev);
        let next = compile_state_with_vault_id(&self.successor_policy, &self.baked, self.successor_vault_id);
        let claimed = self.claimed.clone();
        let (amount, idx) = (self.pay_amount, self.recipient_index);
        run_case(TransitionCase {
            outputs: vec![p2pk_output(&self.payment_pk, self.payment_value), successor_output(&next, self.successor_value)],
            utxo_value: self.prev.protected_value as u64,
            lock_time: 0,
            function: "delegateSpend",
            args: Box::new(move |sig| vec![state_arg(&claimed), Expr::int(amount), Expr::int(idx), Expr::bytes(sig)]),
            signer: self.signer,
            active,
        })
    }
}

// ---------------------------------------------------------------- identity

#[test]
fn avm_01_wrong_delegate_key() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    attack.signer = a.attacker;
    assert_rejected(attack.run(&a), "AVM-01 wrong delegate key");
}

#[test]
fn avm_36_malformed_signature() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let succ = spend_successor(&prev, 25 * KAS);
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &succ);
    // Note: a 64-byte (truncated) signature cannot even be encoded — the
    // covenant declaration encoder enforces the declared `sig` width. The
    // attacks below stay 65 bytes long but are cryptographically invalid.
    for (label, corrupt) in [
        ("flipped schnorr byte", 10usize),
        ("flipped sighash-type byte", 64usize),
    ] {
        let succ_c = succ.clone();
        let result = run_case(TransitionCase {
            outputs: vec![p2pk_output(&xonly(&a.r1), 25 * KAS as u64), successor_output(&next, succ.protected_value as u64)],
            utxo_value: prev.protected_value as u64,
            lock_time: 0,
            function: "delegateSpend",
            args: Box::new(move |sig| {
                let mut bad = sig.clone();
                bad[corrupt] ^= 0x01;
                vec![state_arg(&succ_c), Expr::int(25 * KAS), Expr::int(1), Expr::bytes(bad)]
            }),
            signer: a.delegate,
            active: compile_state(&a.policy, &prev),
        });
        assert_rejected(result, &format!("AVM-36 malformed signature ({label})"));
    }
    let _ = active;
}

// ---------------------------------------------------------------- recipient

#[test]
fn avm_02_wrong_recipient() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    attack.payment_pk = xonly(&a.attacker);
    assert_rejected(attack.run(&a), "AVM-02 non-allowlisted recipient");
}

#[test]
fn avm_42_recipient_index_out_of_range() {
    let a = actors();
    for idx in [0i64, 4] {
        let prev = initial_state(&a.policy);
        let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
        attack.recipient_index = idx;
        assert_rejected(attack.run(&a), "AVM-42 recipientIndex out of range");
    }
}

#[test]
fn avm_41_payment_output_above_pay_amount() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    attack.payment_value = (25 * KAS + 1) as u64;
    assert_rejected(attack.run(&a), "AVM-41 payment above accounted amount");
}

// ---------------------------------------------------------------- caps / budget

#[test]
fn avm_03_over_per_spend_cap() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let amount = a.policy.max_per_spend + 1;
    let attack = SpendAttack::honest(&a, prev, amount);
    assert_rejected(attack.run(&a), "AVM-03 over per-spend cap");
}

#[test]
fn avm_04_cumulative_over_budget() {
    let a = actors();
    // 450 KAS spent; 60 KAS more would exceed the 500 KAS budget.
    let prev = StateSpec { period_spent: 45_000_000_000, protected_value: 55_000_000_000, ..initial_state(&a.policy) };
    let attack = SpendAttack::honest(&a, prev, 60 * KAS);
    assert_rejected(attack.run(&a), "AVM-04 cumulative over budget");
}

// ---------------------------------------------------------------- accounting forgery

#[test]
fn avm_07_reduced_period_spent() {
    let a = actors();
    let prev = StateSpec { period_spent: 40_000_000_000, protected_value: 60_000_000_000, ..initial_state(&a.policy) };
    let mut attack = SpendAttack::honest(&a, prev.clone(), 25 * KAS);
    let forged = StateSpec { period_spent: 0, ..spend_successor(&prev, 25 * KAS) };
    attack.claimed = forged.clone();
    attack.baked = forged;
    assert_rejected(attack.run(&a), "AVM-07 reduced periodSpent");
}

#[test]
fn avm_08_unchanged_period_spent() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev.clone(), 25 * KAS);
    let forged = StateSpec { period_spent: prev.period_spent, ..spend_successor(&prev, 25 * KAS) };
    attack.claimed = forged.clone();
    attack.baked = forged;
    assert_rejected(attack.run(&a), "AVM-08 unchanged periodSpent");
}

#[test]
fn avm_09_wrong_increment() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev.clone(), 25 * KAS);
    let forged = StateSpec { period_spent: prev.period_spent + 25 * KAS - 1, ..spend_successor(&prev, 25 * KAS) };
    attack.claimed = forged.clone();
    attack.baked = forged;
    assert_rejected(attack.run(&a), "AVM-09 wrong periodSpent increment");
}

#[test]
fn avm_06_forged_period_start_in_spend() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev.clone(), 25 * KAS);
    // Pretend the period started later (delays future budget pressure).
    let forged = StateSpec { period_start_daa: prev.period_start_daa + 100_000, ..spend_successor(&prev, 25 * KAS) };
    attack.claimed = forged.clone();
    attack.baked = forged;
    assert_rejected(attack.run(&a), "AVM-06 forged periodStartDaa in delegateSpend");
}

// ---------------------------------------------------------------- value conservation

#[test]
fn avm_17_successor_value_mismatch() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    attack.successor_value -= 10 * KAS as u64;
    assert_rejected(attack.run(&a), "AVM-17 successor value below accounted state");
}

#[test]
fn avm_18_siphon_into_change() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let amount = 25 * KAS;
    let succ = spend_successor(&prev, amount);
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &succ);
    let succ_c = succ.clone();
    let siphon = 10 * KAS as u64;
    // Successor short by `siphon`; the difference appears as an ordinary
    // attacker-keyed change output.
    let result = run_case(TransitionCase {
        outputs: vec![
            p2pk_output(&xonly(&a.r1), amount as u64),
            successor_output(&next, succ.protected_value as u64 - siphon),
            p2pk_output(&xonly(&a.attacker), siphon),
        ],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: Box::new(move |sig| vec![state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    });
    assert_rejected(result, "AVM-18 siphon protected principal into change");
}

#[test]
fn avm_35_fee_drain_one_sompi() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    // Even a single sompi of protected principal must not leak into fees.
    attack.successor_value -= 1;
    assert_rejected(attack.run(&a), "AVM-35 one-sompi fee drain");
}

#[test]
fn avm_45_spend_zeroes_vault() {
    let a = actors();
    let prev = StateSpec { protected_value: 50 * KAS, ..initial_state(&a.policy) };
    let attack = SpendAttack::honest(&a, prev, 50 * KAS);
    assert_rejected(attack.run(&a), "AVM-45 spend that zeroes the vault");
}

// ---------------------------------------------------------------- template forgery

fn template_forgery(mutate: impl FnOnce(&mut PolicySpec)) {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    mutate(&mut attack.successor_policy);
    assert_rejected(attack.run(&a), "template forgery");
}

#[test]
fn avm_10_modified_owner() {
    template_forgery(|p| p.owner_pk = xonly(&deterministic_keypair(66)));
}

#[test]
fn avm_11_modified_delegate() {
    template_forgery(|p| p.delegate_pk = xonly(&deterministic_keypair(66)));
}

#[test]
fn avm_12_modified_cap() {
    template_forgery(|p| p.max_per_spend *= 10);
}

#[test]
fn avm_13_modified_budget() {
    template_forgery(|p| p.period_budget *= 10);
}

#[test]
fn avm_14_modified_allowlist() {
    template_forgery(|p| p.recipient1_pk = xonly(&deterministic_keypair(66)));
}

#[test]
fn avm_15_modified_period_length() {
    template_forgery(|p| p.period_length_daa = 1);
}

#[test]
fn avm_16_wrong_vault_identity() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let mut attack = SpendAttack::honest(&a, prev, 25 * KAS);
    // Successor output belongs to a different vault lineage.
    attack.successor_vault_id = OTHER_VAULT_ID;
    attack.baked = attack.claimed.clone();
    assert_rejected(attack.run(&a), "AVM-16 wrong vault identity");
}

// ---------------------------------------------------------------- successor structure

#[test]
fn avm_20_missing_successor() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let amount = 25 * KAS;
    let succ = spend_successor(&prev, amount);
    let active = compile_state(&a.policy, &prev);
    let succ_c = succ.clone();
    let result = run_case(TransitionCase {
        // Payment only — the delegate tries to burn the vault.
        outputs: vec![p2pk_output(&xonly(&a.r1), amount as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: Box::new(move |sig| vec![state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    });
    assert_rejected(result, "AVM-20 missing successor");
}

#[test]
fn avm_21_multiple_successors() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let amount = 25 * KAS;
    let succ = spend_successor(&prev, amount);
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &succ);
    let succ_c = succ.clone();
    let half = (succ.protected_value / 2) as u64;
    let result = run_case(TransitionCase {
        outputs: vec![
            p2pk_output(&xonly(&a.r1), amount as u64),
            successor_output(&next, half),
            successor_output(&next, succ.protected_value as u64 - half),
        ],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: Box::new(move |sig| vec![state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    });
    assert_rejected(result, "AVM-21 multiple successors");
}

#[test]
fn avm_19_extra_bound_output() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let amount = 25 * KAS;
    let succ = spend_successor(&prev, amount);
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &succ);
    let succ_c = succ.clone();
    // A second output claims the covenant binding but carries an ordinary
    // attacker script.
    let mut rogue = p2pk_output(&xonly(&a.attacker), 10 * KAS as u64);
    rogue.covenant = Some(kaspa_consensus_core::tx::CovenantBinding { authorizing_input: 0, covenant_id: COV_A });
    let result = run_case(TransitionCase {
        outputs: vec![
            p2pk_output(&xonly(&a.r1), amount as u64),
            successor_output(&next, succ.protected_value as u64),
            rogue,
        ],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "delegateSpend",
        args: Box::new(move |sig| vec![state_arg(&succ_c), Expr::int(amount), Expr::int(1), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    });
    assert_rejected(result, "AVM-19 extra covenant-bound output");
}

// ---------------------------------------------------------------- period / CLTV

fn rollover_case(
    a: &Actors,
    prev: &StateSpec,
    claimed: &StateSpec,
    amount: i64,
    periods_elapsed: i64,
    lock_time: u64,
    sequence: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let active = compile_state(&a.policy, prev);
    let next = compile_state(&a.policy, claimed);
    let claimed_c = claimed.clone();
    let tx = kaspa_consensus_core::tx::Transaction::new(
        1,
        vec![covenant_input_with_sequence(sequence)],
        vec![p2pk_output(&xonly(&a.r1), amount as u64), successor_output(&next, claimed.protected_value as u64)],
        lock_time,
        Default::default(),
        0,
        vec![],
    );
    let utxo = active_utxo(&active, prev.protected_value as u64);
    let mut mutable = kaspa_consensus_core::tx::MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let sig = sign_input0(&mutable, &a.delegate);
    let args = vec![state_arg(&claimed_c), Expr::int(amount), Expr::int(1), Expr::int(periods_elapsed), Expr::bytes(sig)];
    let mut sigscript = active
        .build_sig_script_for_covenant_decl(
            "rolloverAndSpend",
            args,
            silverscript_lang::compiler::CovenantDeclCallOptions { is_leader: false },
        )
        .expect("rolloverAndSpend encoding");
    sigscript.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = sigscript;
    execute_input_with_covenants(mutable.tx, vec![utxo], 0)
}

fn exhausted_prev(a: &Actors) -> StateSpec {
    StateSpec { period_spent: a.policy.period_budget, protected_value: 50_000_000_000, ..initial_state(&a.policy) }
}

fn rollover_successor(a: &Actors, prev: &StateSpec, amount: i64, periods: i64) -> StateSpec {
    StateSpec {
        protected_value: prev.protected_value - amount,
        period_start_daa: prev.period_start_daa + periods * a.policy.period_length_daa,
        period_spent: amount,
        paused: 0,
    }
}

#[test]
fn avm_05_early_period_reset() {
    let a = actors();
    let prev = exhausted_prev(&a);
    let amount = 30 * KAS;
    let succ = rollover_successor(&a, &prev, amount, 1);
    // Lock time one DAA unit short of the claimed new period start.
    let lock_time = (succ.period_start_daa - 1) as u64;
    assert_rejected(rollover_case(&a, &prev, &succ, amount, 1, lock_time, 0), "AVM-05 early period reset");
}

#[test]
fn avm_06_forged_rollover_period_start() {
    let a = actors();
    let prev = exhausted_prev(&a);
    let amount = 30 * KAS;
    // Claim one elapsed period but bake a two-period advance into the
    // successor (banking future budget).
    let mut succ = rollover_successor(&a, &prev, amount, 1);
    succ.period_start_daa = prev.period_start_daa + 2 * a.policy.period_length_daa;
    let lock_time = (prev.period_start_daa + a.policy.period_length_daa) as u64;
    assert_rejected(rollover_case(&a, &prev, &succ, amount, 1, lock_time, 0), "AVM-06 forged rollover periodStartDaa");
}

#[test]
fn avm_39_zero_periods_elapsed() {
    let a = actors();
    let prev = exhausted_prev(&a);
    let amount = 30 * KAS;
    let succ = StateSpec { period_spent: amount, protected_value: prev.protected_value - amount, ..prev.clone() };
    let lock_time = (prev.period_start_daa + 1) as u64;
    assert_rejected(rollover_case(&a, &prev, &succ, amount, 0, lock_time, 0), "AVM-39 zero periodsElapsed");
}

#[test]
fn avm_40_excessive_periods_elapsed() {
    let a = actors();
    let prev = exhausted_prev(&a);
    let amount = 30 * KAS;
    let succ = rollover_successor(&a, &prev, amount, 1001);
    let lock_time = (succ.period_start_daa + 1) as u64;
    assert_rejected(rollover_case(&a, &prev, &succ, amount, 1001, lock_time, 0), "AVM-40 excessive periodsElapsed");
}

#[test]
fn avm_43_max_sequence_cltv_bypass() {
    let a = actors();
    let prev = exhausted_prev(&a);
    let amount = 30 * KAS;
    let succ = rollover_successor(&a, &prev, amount, 1);
    let lock_time = succ.period_start_daa as u64;
    // Valid lock time but a finalized (max-sequence) input: CLTV must
    // reject the bypass.
    assert_rejected(rollover_case(&a, &prev, &succ, amount, 1, lock_time, u64::MAX), "AVM-43 max-sequence CLTV bypass");
}

#[test]
fn avm_44_lock_time_type_confusion() {
    let a = actors();
    let prev = exhausted_prev(&a);
    let amount = 30 * KAS;
    let succ = rollover_successor(&a, &prev, amount, 1);
    // Timestamp-form lock time (>= LOCK_TIME_THRESHOLD) against a
    // DAA-score requirement: mismatched lock-time types.
    let lock_time = 600_000_000_000u64;
    assert_rejected(rollover_case(&a, &prev, &succ, amount, 1, lock_time, 0), "AVM-44 lock-time type confusion");
}

// ---------------------------------------------------------------- pause / authority

#[test]
fn avm_38_spend_while_paused() {
    let a = actors();
    let prev = StateSpec { paused: 1, ..initial_state(&a.policy) };
    let attack = SpendAttack::honest(&a, prev, 25 * KAS);
    assert_rejected(attack.run(&a), "AVM-38 delegate spend while paused");
}

#[test]
fn avm_46_delegate_forged_unpause() {
    let a = actors();
    let prev = StateSpec { paused: 1, ..initial_state(&a.policy) };
    let unpaused = StateSpec { paused: 0, ..prev.clone() };
    let active = compile_state(&a.policy, &prev);
    let next = compile_state(&a.policy, &unpaused);
    let us = unpaused.clone();
    let result = run_case(TransitionCase {
        outputs: vec![successor_output(&next, unpaused.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerUnpause",
        args: Box::new(move |sig| vec![state_arg(&us), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    });
    assert_rejected(result, "AVM-46 delegate-signed unpause");
}

#[test]
fn avm_22_23_delegate_recovery_attempt() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let active = compile_state(&a.policy, &prev);
    // The delegate signs ownerRecover, paying the vault to the delegate.
    let result = run_case(TransitionCase {
        outputs: vec![p2pk_output(&xonly(&a.delegate), prev.protected_value as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.delegate,
        active,
    });
    assert_rejected(result, "AVM-22/23 delegate recovery attempt");
}

#[test]
fn avm_recover_partial_value() {
    let a = actors();
    let prev = initial_state(&a.policy);
    let active = compile_state(&a.policy, &prev);
    // Owner signature but output 0 underpays the owner: exact-recovery
    // accounting must reject (defense against sloppy recovery tooling).
    let result = run_case(TransitionCase {
        outputs: vec![p2pk_output(&xonly(&a.owner), (prev.protected_value - 1) as u64)],
        utxo_value: prev.protected_value as u64,
        lock_time: 0,
        function: "ownerRecover",
        args: Box::new(move |sig| vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(sig)]),
        signer: a.owner,
        active,
    });
    assert_rejected(result, "recovery with inexact value");
}
