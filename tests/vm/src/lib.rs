//! Real-VM test harness for the PolicyVault covenant.
//!
//! Executes the actual Kaspa TxScriptEngine (covenants enabled) against
//! transactions carrying real Schnorr signatures, following the proven
//! harness pattern from silverscript-lang's integration tests.

use std::fs;

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::SigopCount;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;

use secp256k1::{Keypair, Secp256k1, SecretKey};

use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CompiledContract, CovenantDeclCallOptions};

pub const COV_A: Hash = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

pub const VAULT_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Immutable policy for one compiled vault template.
#[derive(Clone)]
pub struct PolicySpec {
    pub owner_pk: [u8; 32],
    pub delegate_pk: [u8; 32],
    pub max_per_spend: i64,
    pub period_budget: i64,
    pub period_length_daa: i64,
    pub recipient1_pk: [u8; 32],
    pub recipient2_pk: [u8; 32],
    pub recipient3_pk: [u8; 32],
    pub init_value: i64,
    pub init_period_start_daa: i64,
}

/// Mutable exact live state of one vault instance.
#[derive(Clone, Debug, PartialEq)]
pub struct StateSpec {
    pub protected_value: i64,
    pub period_start_daa: i64,
    pub period_spent: i64,
    pub paused: i64,
}

pub fn hex32(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 64);
    (0..32).map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("valid hex")).collect()
}

pub fn deterministic_keypair(value: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[value; 32]).expect("valid deterministic key");
    Keypair::from_secret_key(&secp, &secret)
}

pub fn xonly(keypair: &Keypair) -> [u8; 32] {
    keypair.x_only_public_key().0.serialize()
}

fn replace_exact(source: String, old: &str, new: String) -> String {
    assert_eq!(source.matches(old).count(), 1, "expected exactly one match for {old:?}");
    source.replacen(old, &new, 1)
}

/// Compile the PolicyVault contract with the given exact live state baked
/// into the state initializers (the exact-live-state pattern).
pub fn compile_state(policy: &PolicySpec, state: &StateSpec) -> CompiledContract<'static> {
    compile_state_with_vault_id(policy, state, VAULT_ID)
}

/// Variant used by identity-forgery tests: bake a different vaultId.
pub fn compile_state_with_vault_id(policy: &PolicySpec, state: &StateSpec, vault_id: &str) -> CompiledContract<'static> {
    let path = format!("{}/../../contracts/PolicyVault.v0.1.beta.sil", env!("CARGO_MANIFEST_DIR"));
    let mut source = fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed reading {path}: {err}"));

    source = replace_exact(
        source,
        "int protectedValue =\n        initValue;",
        format!("int protectedValue =\n        {};", state.protected_value),
    );
    source = replace_exact(
        source,
        "int periodStartDaa =\n        initPeriodStartDaa;",
        format!("int periodStartDaa =\n        {};", state.period_start_daa),
    );
    source = replace_exact(source, "int periodSpent = 0;", format!("int periodSpent = {};", state.period_spent));
    source = replace_exact(source, "int paused = 0;", format!("int paused = {};", state.paused));

    let source: &'static str = Box::leak(source.into_boxed_str());

    compile_contract(
        source,
        &[
            Expr::bytes(policy.owner_pk.to_vec()),
            Expr::bytes(policy.delegate_pk.to_vec()),
            Expr::bytes(hex32(vault_id)),
            Expr::int(policy.max_per_spend),
            Expr::int(policy.period_budget),
            Expr::int(policy.period_length_daa),
            Expr::bytes(policy.recipient1_pk.to_vec()),
            Expr::bytes(policy.recipient2_pk.to_vec()),
            Expr::bytes(policy.recipient3_pk.to_vec()),
            Expr::int(policy.init_value),
            Expr::int(policy.init_period_start_daa),
        ],
        CompileOptions::default(),
    )
    .expect("PolicyVault state compile")
}

/// The `State` struct literal passed as `newState` in covenant calls.
/// Field order matches the contract field declaration order.
pub fn state_arg(state: &StateSpec) -> Expr<'static> {
    struct_object(vec![
        ("boundVaultId", Expr::bytes(hex32(VAULT_ID))),
        ("protectedValue", Expr::int(state.protected_value)),
        ("periodStartDaa", Expr::int(state.period_start_daa)),
        ("periodSpent", Expr::int(state.period_spent)),
        ("paused", Expr::int(state.paused)),
    ])
}

/// P2PK output: push(pubkey) + OpCheckSig, script version 0.
pub fn p2pk_output(pk: &[u8; 32], value: u64) -> TransactionOutput {
    let script = ScriptBuilder::new().add_data(pk).expect("push pubkey").add_op(OpCheckSig).expect("add checksig").drain();
    TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, script.into()), covenant: None }
}

/// Authorized successor covenant output bound to input 0.
pub fn successor_output(compiled: &CompiledContract<'_>, value: u64) -> TransactionOutput {
    TransactionOutput {
        value,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }
}

/// The live covenant UTXO being spent.
pub fn active_utxo(compiled: &CompiledContract<'_>, value: u64) -> UtxoEntry {
    UtxoEntry::new(value, pay_to_script_hash_script(&compiled.script), 0, false, Some(COV_A))
}

pub fn push_redeem_script(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
        .add_data(script)
        .expect("push redeem script")
        .drain()
}

/// Build the single covenant input (empty sigscript) spending a synthetic
/// outpoint. Sequence 0 keeps CLTV effective; u64::MAX models the
/// finalization-bypass attack.
pub fn covenant_input_with_sequence(sequence: u64) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![],
        sequence,
        compute_commit: SigopCount(1).into(),
    }
}

pub fn covenant_input() -> TransactionInput {
    covenant_input_with_sequence(0)
}

/// Sign input 0 of the transaction with SIG_HASH_ALL and return the 65-byte
/// signature (64-byte schnorr + sighash type byte).
pub fn sign_input0(mutable: &MutableTransaction<Transaction>, keypair: &Keypair) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&mutable.as_verifiable(), 0, SIG_HASH_ALL, &reused);
    let message = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).expect("valid sighash");
    let schnorr = keypair.sign_schnorr(message);
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(schnorr.as_ref().as_slice());
    sig.push(SIG_HASH_ALL.to_u8());
    assert_eq!(sig.len(), 65);
    sig
}

/// Execute input `input_idx` of the transaction on the real TxScriptEngine
/// with covenants enabled.
pub fn execute_input_with_covenants(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input: TransactionInput = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true, sigop_script_units: 0.into() },
    );
    vm.execute()
}

/// Execute like `execute_input_with_covenants` but also return the script
/// units actually consumed (drives live compute-budget selection).
pub fn execute_input_measured(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> (Result<(), TxScriptError>, u64) {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input: TransactionInput = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(ctx) => ctx,
        Err(err) => return (Err(TxScriptError::from(err)), 0),
    };
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true, sigop_script_units: 0.into() },
    );
    let result = vm.execute();
    let units: u64 = vm.used_script_units().into();
    (result, units)
}

/// Execute with PRODUCTION sig-op pricing (sigop_script_units =
/// Gram(mass_per_sig_op) = Gram(1000) = 100,000 script units per checkSig),
/// so the measured used_script_units reflects what a live node charges —
/// used to size the committed compute budget (the test harness otherwise
/// prices sig-ops at zero).
pub fn execute_input_measured_priced(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize, sigop_gram: u64) -> (Result<(), TxScriptError>, u64) {
    use kaspa_consensus_core::mass::units::Gram;
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input: TransactionInput = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(ctx) => ctx,
        Err(err) => return (Err(TxScriptError::from(err)), 0),
    };
    let utxo = populated.utxo(input_idx).expect("selected input utxo");
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true, sigop_script_units: Gram(sigop_gram).into() },
    );
    let result = vm.execute();
    let units: u64 = vm.used_script_units().into();
    (result, units)
}

/// Everything needed to run one covenant transition case.
pub struct TransitionCase {
    /// Compiled current state (the covenant being spent).
    pub active: CompiledContract<'static>,
    /// Transaction outputs (payment / successor / etc.).
    pub outputs: Vec<TransactionOutput>,
    /// Value held by the live covenant UTXO.
    pub utxo_value: u64,
    /// Transaction lock_time (DAA-score form for rollover proofs).
    pub lock_time: u64,
    /// Covenant function to call.
    pub function: &'static str,
    /// Extra call args appended after any newState arg; built by the
    /// closure receiving the delegate/owner signature.
    pub args: Box<dyn Fn(Vec<u8>) -> Vec<Expr<'static>>>,
    /// Keypair whose signature the args closure receives.
    pub signer: Keypair,
}

/// Build, sign, and execute a transition case on the real VM.
pub fn run_case(case: TransitionCase) -> Result<(), TxScriptError> {
    run_case_measured(case).0
}

/// Like `run_case` but also returns the consumed script units.
pub fn run_case_measured(case: TransitionCase) -> (Result<(), TxScriptError>, u64) {
    let tx = Transaction::new(1, vec![covenant_input()], case.outputs, case.lock_time, Default::default(), 0, vec![]);
    let utxo = active_utxo(&case.active, case.utxo_value);
    let mut mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);

    let sig = sign_input0(&mutable, &case.signer);
    let args = (case.args)(sig);

    let mut sigscript = case
        .active
        .build_sig_script_for_covenant_decl(case.function, args, CovenantDeclCallOptions { is_leader: false })
        .expect("covenant call encoding");
    sigscript.extend_from_slice(&push_redeem_script(&case.active.script));
    mutable.tx.inputs[0].signature_script = sigscript;

    execute_input_measured(mutable.tx, vec![utxo], 0)
}

pub fn assert_rejected(result: Result<(), TxScriptError>, label: &str) {
    assert!(result.is_err(), "{label}: expected covenant rejection but the VM accepted the transaction");
}

// ===================================================================== v0.2

/// v0.2 immutable template constants: only owner + vaultId.
#[derive(Clone)]
pub struct V2Template {
    pub owner_pk: [u8; 32],
}

/// v0.2 mutable exact live state (policy fields are owner-guarded state).
#[derive(Clone, Debug, PartialEq)]
pub struct V2State {
    pub protected_value: i64,
    pub period_start_daa: i64,
    pub period_spent: i64,
    pub paused: i64,
    pub delegate_pk: [u8; 32],
    pub max_per_spend: i64,
    pub period_budget: i64,
    pub period_length_daa: i64,
    pub recipient1_pk: [u8; 32],
    pub recipient2_pk: [u8; 32],
    pub recipient3_pk: [u8; 32],
    pub delegate_active: i64,
    pub policy_nonce: i64,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The exact-live-state source string for a v0.2 (template, state): the
/// contract with every state initializer templated. Shared by the in-process
/// compiler AND the encoder-input writer so they can never drift.
pub fn v2_templated_source(state: &V2State) -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.2.sil", env!("CARGO_MANIFEST_DIR"));
    let mut source = fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed reading {path}: {err}"));

    source = replace_exact(source, "int protectedValue = initValue;", format!("int protectedValue = {};", state.protected_value));
    source = replace_exact(
        source,
        "int periodStartDaa = initPeriodStartDaa;",
        format!("int periodStartDaa = {};", state.period_start_daa),
    );
    source = replace_exact(source, "int periodSpent = 0;", format!("int periodSpent = {};", state.period_spent));
    source = replace_exact(source, "int paused = 0;", format!("int paused = {};", state.paused));
    source = replace_exact(source, "pubkey delegate = initDelegate;", format!("pubkey delegate = 0x{};", to_hex(&state.delegate_pk)));
    source = replace_exact(source, "int maxPerSpend = initMaxPerSpend;", format!("int maxPerSpend = {};", state.max_per_spend));
    source = replace_exact(source, "int periodBudget = initPeriodBudget;", format!("int periodBudget = {};", state.period_budget));
    source = replace_exact(
        source,
        "int periodLengthDaa = initPeriodLengthDaa;",
        format!("int periodLengthDaa = {};", state.period_length_daa),
    );
    source = replace_exact(
        source,
        "pubkey recipient1 = initRecipient1;",
        format!("pubkey recipient1 = 0x{};", to_hex(&state.recipient1_pk)),
    );
    source = replace_exact(
        source,
        "pubkey recipient2 = initRecipient2;",
        format!("pubkey recipient2 = 0x{};", to_hex(&state.recipient2_pk)),
    );
    source = replace_exact(
        source,
        "pubkey recipient3 = initRecipient3;",
        format!("pubkey recipient3 = 0x{};", to_hex(&state.recipient3_pk)),
    );
    source = replace_exact(source, "int delegateActive = 1;", format!("int delegateActive = {};", state.delegate_active));
    source = replace_exact(source, "int policyNonce = 0;", format!("int policyNonce = {};", state.policy_nonce));
    source
}

/// Constructor args for a v0.2 (template, state), in declaration order. The
/// vaultId sits at index 1 (the encoder must pull boundVaultId from here).
pub fn v2_constructor_args(template: &V2Template, state: &V2State, vault_id: &str) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(template.owner_pk.to_vec()),
        Expr::bytes(hex32(vault_id)),
        Expr::bytes(state.delegate_pk.to_vec()),
        Expr::int(state.max_per_spend),
        Expr::int(state.period_budget),
        Expr::int(state.period_length_daa),
        Expr::bytes(state.recipient1_pk.to_vec()),
        Expr::bytes(state.recipient2_pk.to_vec()),
        Expr::bytes(state.recipient3_pk.to_vec()),
        Expr::int(state.protected_value),
        Expr::int(state.period_start_daa),
    ]
}

/// Compile the v0.2 contract with the exact live state baked into the state
/// initializers (the exact-live-state pattern).
pub fn compile_v2_state(template: &V2Template, state: &V2State) -> CompiledContract<'static> {
    compile_v2_state_with_vault_id(template, state, VAULT_ID)
}

pub fn compile_v2_state_with_vault_id(template: &V2Template, state: &V2State, vault_id: &str) -> CompiledContract<'static> {
    let source: &'static str = Box::leak(v2_templated_source(state).into_boxed_str());
    compile_contract(source, &v2_constructor_args(template, state, vault_id), CompileOptions::default())
        .expect("PolicyVault v0.2 state compile")
}

/// The v0.2 `State` struct literal passed as `newState` in covenant calls.
/// Field order matches the contract field declaration order.
pub fn v2_state_arg(state: &V2State) -> Expr<'static> {
    v2_state_arg_with_vault_id(state, VAULT_ID)
}

pub fn v2_state_arg_with_vault_id(state: &V2State, vault_id: &str) -> Expr<'static> {
    struct_object(vec![
        ("boundVaultId", Expr::bytes(hex32(vault_id))),
        ("protectedValue", Expr::int(state.protected_value)),
        ("periodStartDaa", Expr::int(state.period_start_daa)),
        ("periodSpent", Expr::int(state.period_spent)),
        ("paused", Expr::int(state.paused)),
        ("delegate", Expr::bytes(state.delegate_pk.to_vec())),
        ("maxPerSpend", Expr::int(state.max_per_spend)),
        ("periodBudget", Expr::int(state.period_budget)),
        ("periodLengthDaa", Expr::int(state.period_length_daa)),
        ("recipient1", Expr::bytes(state.recipient1_pk.to_vec())),
        ("recipient2", Expr::bytes(state.recipient2_pk.to_vec())),
        ("recipient3", Expr::bytes(state.recipient3_pk.to_vec())),
        ("delegateActive", Expr::int(state.delegate_active)),
        ("policyNonce", Expr::int(state.policy_nonce)),
    ])
}

/// Build, sign, and execute a v0.2 transition case on the real VM (same
/// machinery as run_case; the active/successor templates are v0.2).
pub fn run_v2_case(case: TransitionCase) -> Result<(), TxScriptError> {
    run_case(case)
}

/// Standard v0.2 test state: cap 100 KAS, budget 500 KAS, period 864000 DAA.
pub fn test_v2_state(delegate: &Keypair, recipients: [&Keypair; 3]) -> V2State {
    V2State {
        protected_value: 100_000_000_000,
        period_start_daa: 541_000_000,
        period_spent: 0,
        paused: 0,
        delegate_pk: xonly(delegate),
        max_per_spend: 10_000_000_000,
        period_budget: 50_000_000_000,
        period_length_daa: 864_000,
        recipient1_pk: xonly(recipients[0]),
        recipient2_pk: xonly(recipients[1]),
        recipient3_pk: xonly(recipients[2]),
        delegate_active: 1,
        policy_nonce: 0,
    }
}

/// Standard test policy: cap 100 KAS, budget 500 KAS, period 864000 DAA.
pub fn test_policy(owner: &Keypair, delegate: &Keypair, recipients: [&Keypair; 3]) -> PolicySpec {
    PolicySpec {
        owner_pk: xonly(owner),
        delegate_pk: xonly(delegate),
        max_per_spend: 10_000_000_000,
        period_budget: 50_000_000_000,
        period_length_daa: 864_000,
        recipient1_pk: xonly(recipients[0]),
        recipient2_pk: xonly(recipients[1]),
        recipient3_pk: xonly(recipients[2]),
        init_value: 100_000_000_000,
        init_period_start_daa: 541_000_000,
    }
}
