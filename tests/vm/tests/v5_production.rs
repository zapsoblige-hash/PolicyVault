//! VM layer — PRODUCTION PolicyVault.v0.5.sil (token controller) driven
//! through the real TxScriptEngine (covenants enabled, real Schnorr).
//! Honest paths + the frozen-design hostile matrix
//! (docs/postlaunch/v0.5-design-freeze.md §III) + sabotage sensitivity of
//! the binding guards + compute/mass/standardness measurement on the ACTUAL
//! covenant source. Consensus-visible bytes go through the SilverScript
//! compiler + covenant-decl call encoder; the pv_call_encoder production-
//! byte integration is a separate step.
//!
//! Composition: the v0.5 controller (input 0) owns a KCC20 position (the
//! upstream kcc20.sil example, input 1, covenant-id/v1 owner scheme) and an
//! agent funds the fee from a plain fuel input (input 2). Every input is
//! executed on the real engine.

use policyvault_vm_tests::{deterministic_keypair, execute_input_measured, execute_input_measured_priced, xonly};
use secp256k1::Keypair;
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CompiledContract, CovenantDeclCallOptions};

use kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::{ComputeBudget, ScriptUnits};
use kaspa_consensus_core::mass::{transaction_estimated_serialized_size, MassCalculator};
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::{
    estimate_script_units_upper_bound, pay_to_script_hash_script, post_toccata_p2sh_sig_scanner, script_builder::ScriptBuilder,
    EngineFlags,
};
use kaspa_txscript_errors::TxScriptError;

const KAS: i64 = 100_000_000;
const IDENTIFIER_PUBKEY: u8 = 0x00;
const IDENTIFIER_COVENANT_ID: u8 = 0x02;
const TOKEN_AGENT_DOMAIN: [u8; 4] = [0x50, 0x56, 0x35, 0x01];
const RECIP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];
const VAULT_ID: [u8; 32] = [0x44; 32];
const DESCRIPTOR_HASH: [u8; 32] = [0xd5; 32];

const COV_CTRL: Hash = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const COV_TOKEN: Hash = Hash::from_bytes(*b"TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT");
const COV_WRONG: Hash = Hash::from_bytes(*b"WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
const COV_ALIEN: Hash = Hash::from_bytes(*b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

/* KAS shape (sompi) */
const RESERVE: i64 = 5 * KAS;
const TOKEN_CARRY: i64 = 2 * KAS;
const FUEL: i64 = 1 * KAS;
const RECIPIENT_CARRY: i64 = KAS / 5;
const FEE: i64 = 100_000;
const RESERVE_CONSUMED: i64 = 50_000;

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn num8(v: i64) -> [u8; 8] {
    (v as u64).to_le_bytes()
}
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/* ---------------------------------------------------------------- */
/* token side (upstream KCC20 example)                                */
/* ---------------------------------------------------------------- */

fn kcc20_source() -> &'static str {
    let path = format!("{}/../../../silverscript/silverscript-lang/tests/examples/kcc20.sil", env!("CARGO_MANIFEST_DIR"));
    leak(std::fs::read_to_string(&path).expect("read kcc20.sil"))
}
fn alien_source() -> &'static str {
    leak(kcc20_source().replace("int amount = genesisAmount;", "int amount = genesisAmount;\n    int alienPadding = 0;"))
}
fn compile_kcc20(source: &'static str, owner: [u8; 32], ty: u8, amount: i64, minter: bool, max_cov: i64) -> CompiledContract<'static> {
    compile_contract(
        source,
        &[Expr::bytes(owner.to_vec()), Expr::int(amount), Expr::byte(ty), Expr::bool(minter), Expr::int(max_cov), Expr::int(max_cov)],
        CompileOptions::default(),
    )
    .expect("compile kcc20")
}
#[derive(Clone)]
struct Template {
    prefix: Vec<u8>,
    state_len: usize,
    suffix: Vec<u8>,
    hash: [u8; 32],
}
fn template_of(c: &CompiledContract<'_>) -> Template {
    let l = c.state_layout;
    let prefix = c.script[..l.start].to_vec();
    let suffix = c.script[l.start + l.len..].to_vec();
    let h = blake2b_simd::Params::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(h.as_bytes());
    Template { prefix, state_len: l.len, suffix, hash }
}
fn kcc20_state<'i>(owner: [u8; 32], ty: u8, amount: i64, minter: bool, alien: bool) -> Expr<'i> {
    let mut f = vec![("ownerIdentifier", Expr::bytes(owner.to_vec())), ("identifierType", Expr::byte(ty)), ("amount", Expr::int(amount))];
    if alien {
        f.push(("alienPadding", Expr::int(0)));
    }
    f.push(("isMinter", Expr::bool(minter)));
    struct_object(f)
}

/* ---------------------------------------------------------------- */
/* controller side                                                    */
/* ---------------------------------------------------------------- */

#[derive(Clone)]
struct Agent {
    pk: [u8; 32],
    max_per_spend: i64,
    period_budget: i64,
    period_length_daa: i64,
    period_start_daa: i64,
    period_spent: i64,
    max_fee_per_tx: i64,
    max_carry_kas: i64,
    recipient_root: [u8; 32],
}
fn agent_leaf(a: &Agent) -> [u8; 32] {
    let leaf = sha256(&[
        &TOKEN_AGENT_DOMAIN,
        &a.pk,
        &num8(a.max_per_spend),
        &num8(a.period_budget),
        &num8(a.period_length_daa),
        &num8(a.period_start_daa),
        &num8(a.period_spent),
        &num8(a.max_fee_per_tx),
        &num8(a.max_carry_kas),
        &a.recipient_root,
        &[0x00],
    ]);
    leaf
}
fn merkle(leaves: &[[u8; 32]], target: usize) -> ([u8; 32], Vec<u8>, u64) {
    let mut level = leaves.to_vec();
    while level.len().count_ones() != 1 {
        level.push(*level.last().unwrap());
    }
    let (mut idx, mut sibs, mut bits, mut lvl) = (target, Vec::new(), 0u64, 0);
    while level.len() > 1 {
        let s = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        sibs.extend_from_slice(&level[s]);
        if idx % 2 == 1 {
            bits |= 1 << lvl;
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(sha256(&[&pair[0], &pair[1]]));
        }
        idx /= 2;
        level = next;
        lvl += 1;
    }
    (level[0], sibs, bits)
}
fn fold(leaf: [u8; 32], sibs: &[u8], mut bits: u64) -> [u8; 32] {
    let mut node = leaf;
    for level in 0..sibs.len() / 32 {
        let sib: [u8; 32] = sibs[level * 32..level * 32 + 32].try_into().unwrap();
        node = if bits & 1 == 1 { sha256(&[&sib, &node]) } else { sha256(&[&node, &sib]) };
        bits >>= 1;
    }
    node
}
fn recip_tree(depth: u32, target: &[u8; 32]) -> ([u8; 32], Vec<u8>, u64) {
    if depth == 0 {
        return (sha256(&[&RECIP_DOMAIN, target]), vec![], 0);
    }
    let n = 1usize << depth;
    let mut leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&RECIP_DOMAIN, &(i as u64 + 900).to_le_bytes()])).collect();
    leaves[1] = sha256(&[&RECIP_DOMAIN, target]);
    merkle(&leaves, 1)
}

#[derive(Clone)]
struct S {
    reserve: i64,
    paused: i64,
    agent_root: [u8; 32],
    policy_nonce: i64,
}

fn v5_source() -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.5.sil", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).expect("read PolicyVault.v0.5.sil")
}
fn templated(src: &str, s: &S) -> String {
    let mut src = src.to_string();
    let mut r = |from: String, to: String| {
        assert!(src.contains(&from), "anchor missing: {from}");
        src = src.replacen(&from, &to, 1);
    };
    r("int feeReserve = initFeeReserve;".into(), format!("int feeReserve = {};", s.reserve));
    r("int paused = 0;".into(), format!("int paused = {};", s.paused));
    r("byte[32] agentRoot = initAgentRoot;".into(), format!("byte[32] agentRoot = 0x{};", hx(&s.agent_root)));
    r("int policyNonce = 0;".into(), format!("int policyNonce = {};", s.policy_nonce));
    src
}
#[derive(Clone)]
struct Pin {
    token_covid: Hash,
    template_hash: [u8; 32],
    prefix_len: i64,
    state_len: i64,
    suffix_len: i64,
}
fn compile_ctrl(src: &str, owner: &[u8; 32], pin: &Pin, s: &S) -> CompiledContract<'static> {
    let src: &'static str = leak(templated(src, s));
    compile_contract(
        src,
        &[
            Expr::bytes(owner.to_vec()),
            Expr::bytes(VAULT_ID.to_vec()),
            Expr::bytes(DESCRIPTOR_HASH.to_vec()),
            Expr::bytes(pin.token_covid.as_bytes().to_vec()),
            Expr::bytes(pin.template_hash.to_vec()),
            Expr::int(pin.prefix_len),
            Expr::int(pin.state_len),
            Expr::int(pin.suffix_len),
            Expr::bytes(s.agent_root.to_vec()),
            Expr::int(s.reserve),
        ],
        CompileOptions::default(),
    )
    .unwrap_or_else(|e| panic!("v0.5 compile: {e:?}"))
}
fn state_arg(s: &S) -> Expr<'static> {
    struct_object(vec![
        ("boundVaultId", Expr::bytes(VAULT_ID.to_vec())),
        ("feeReserve", Expr::int(s.reserve)),
        ("paused", Expr::int(s.paused)),
        ("agentRoot", Expr::bytes(s.agent_root.to_vec())),
        ("policyNonce", Expr::int(s.policy_nonce)),
    ])
}

/* ---------------------------------------------------------------- */
/* transaction plumbing                                               */
/* ---------------------------------------------------------------- */

fn push_redeem(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() }).add_data(script).unwrap().drain()
}
fn cov_call(c: &CompiledContract<'_>, f: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    cov_call_opt(c, f, args, true)
}
/// `is_leader` selects the family-leader entrypoint for `#[covenant(binding=...)]`
/// functions (the KCC20 transfer). The v0.5 controller entrypoints are
/// singletons and are encoded with the production encoder's default
/// (is_leader = false), exactly as the SDK drives pv_call_encoder.
fn cov_call_opt(c: &CompiledContract<'_>, f: &str, args: Vec<Expr<'_>>, is_leader: bool) -> Vec<u8> {
    let mut s = c.build_sig_script_for_covenant_decl(f, args, CovenantDeclCallOptions { is_leader }).expect("call");
    s.extend_from_slice(&push_redeem(&c.script));
    s
}
fn input(id: u8, index: u32, sigscript: Vec<u8>, budget: u16) -> TransactionInput {
    TransactionInput::new_with_compute_budget(TransactionOutpoint { transaction_id: TransactionId::from_bytes([id; 32]), index }, sigscript, 0, budget)
}
fn cov_out(value: i64, c: &CompiledContract<'_>, auth: u16, covid: Hash) -> TransactionOutput {
    TransactionOutput { value: value as u64, script_public_key: pay_to_script_hash_script(&c.script), covenant: Some(CovenantBinding { authorizing_input: auth, covenant_id: covid }) }
}
fn cov_utxo(value: i64, c: &CompiledContract<'_>, covid: Hash) -> UtxoEntry {
    UtxoEntry::new(value as u64, pay_to_script_hash_script(&c.script), 0, false, Some(covid))
}
fn p2pk_spk(pk: &[u8; 32]) -> ScriptPublicKey {
    ScriptPublicKey::new(0, ScriptBuilder::new().add_data(pk).unwrap().add_op(OpCheckSig).unwrap().drain().into())
}
fn p2pk_out(pk: &[u8; 32], value: i64) -> TransactionOutput {
    TransactionOutput { value: value as u64, script_public_key: p2pk_spk(pk), covenant: None }
}
fn sign(tx: &Transaction, entries: &[UtxoEntry], idx: usize, kp: &Keypair) -> Vec<u8> {
    let m = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    let h = calc_schnorr_signature_hash(&m.as_verifiable(), idx, SIG_HASH_ALL, &reused);
    let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice()).unwrap();
    let mut out = kp.sign_schnorr(msg).as_ref().to_vec();
    out.push(SIG_HASH_ALL.to_u8());
    out
}
fn p2pk_sigscript(sig: Vec<u8>) -> Vec<u8> {
    ScriptBuilder::new().add_data(&sig).unwrap().drain()
}

/* ---------------------------------------------------------------- */
/* scenario                                                           */
/* ---------------------------------------------------------------- */

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    AgentSpend,
    OwnerControl(i64),
    OwnerRecover,
}

#[derive(Clone)]
struct Scen {
    op: Op,
    /* token family + template */
    family_id: Hash,
    pin_covid: Hash,
    max_cov: i64,
    pin_hash_override: Option<[u8; 32]>,
    pin_geometry_delta: (i64, i64, i64),
    alien_input: bool,
    malformed_input_state: bool,
    alien_self_output: bool,
    variant_outputs: bool,
    hidden_extra_output: bool,
    foreign_family_rider: bool,
    /// an extra output bound to the CONTROLLER's own family (a self-clone continuation) authorized by input 0
    extra_self_family_output: bool,
    /// an extra GENESIS output of a new family authorized by the controller input
    extra_genesis_output_by_controller: bool,
    /* controller state */
    prev: S,
    agents: Vec<Agent>,
    target: usize,
    claim_override: Option<Agent>,
    /* spend */
    spend: i64,
    self_amount_delta: i64,
    periods_elapsed: i64,
    lock_time: u64,
    recip_depth: u32,
    recipient_override: Option<[u8; 32]>,
    recipient_type: u8,
    self_owner_override: Option<([u8; 32], u8)>,
    self_minter: bool,
    recipient_minter: bool,
    new_root_override: Option<[u8; 32]>,
    /* KAS */
    reserve_consumed: i64,
    succ_reserve_override: Option<i64>,
    succ_value_override: Option<i64>,
    recipient_carry: i64,
    self_carry_override: Option<i64>,
    fee: i64,
    /* signer */
    signer_seed: u8,
    /* owner ops */
    owner_new: Option<S>,
    owner_tokens_ride: bool,
    recover_recipient_override: Option<([u8; 32], u8)>,
    recover_amount_delta: i64,
    recover_no_position: bool,
    recover_payout_override: Option<i64>,
    budgets: (u16, u16, u16),
}

fn keys() -> (Keypair, Keypair, Keypair, Keypair, Keypair) {
    (deterministic_keypair(0x61), deterministic_keypair(0x62), deterministic_keypair(0x63), deterministic_keypair(0x64), deterministic_keypair(0x65))
}

fn honest_agent(agent_pk: [u8; 32]) -> Agent {
    Agent {
        pk: agent_pk,
        max_per_spend: 250,
        period_budget: 400,
        period_length_daa: 1000,
        period_start_daa: 5000,
        period_spent: 0,
        max_fee_per_tx: 60_000,
        max_carry_kas: KAS / 4,
        recipient_root: ZERO32,
    }
}

fn honest(op: Op) -> Scen {
    let (_owner, agent, _recipient, _fuel, other) = keys();
    let agents = vec![honest_agent(xonly(&agent)), honest_agent(xonly(&other))];
    Scen {
        op,
        family_id: COV_TOKEN,
        pin_covid: COV_TOKEN,
        max_cov: 2,
        pin_hash_override: None,
        pin_geometry_delta: (0, 0, 0),
        alien_input: false,
        malformed_input_state: false,
        alien_self_output: false,
        variant_outputs: false,
        hidden_extra_output: false,
        foreign_family_rider: false,
        extra_self_family_output: false,
        extra_genesis_output_by_controller: false,
        prev: S { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 },
        agents,
        target: 0,
        claim_override: None,
        spend: 200,
        self_amount_delta: 0,
        periods_elapsed: 0,
        lock_time: 0,
        recip_depth: 0,
        recipient_override: None,
        recipient_type: IDENTIFIER_PUBKEY,
        self_owner_override: None,
        self_minter: false,
        recipient_minter: false,
        new_root_override: None,
        reserve_consumed: RESERVE_CONSUMED,
        succ_reserve_override: None,
        succ_value_override: None,
        recipient_carry: RECIPIENT_CARRY,
        self_carry_override: None,
        fee: FEE,
        signer_seed: 0x62,
        owner_new: None,
        owner_tokens_ride: false,
        recover_recipient_override: None,
        recover_amount_delta: 0,
        recover_no_position: false,
        recover_payout_override: None,
        budgets: (200, 100, 10),
    }
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    ctrl_redeem_len: usize,
}

const PREV_TOKEN_AMOUNT: i64 = 300;

fn build(c: &Scen) -> Built {
    build_src(c, &v5_source())
}

fn build_src(c: &Scen, ctrl_src: &str) -> Built {
    let (owner, _agent, recipient, fuel, _other) = keys();
    let signer = deterministic_keypair(c.signer_seed);
    let owner_pk = xonly(&owner);
    let honest_recipient = xonly(&recipient);
    let recipient_pk = c.recipient_override.unwrap_or(honest_recipient);
    let fuel_pk = xonly(&fuel);

    /* --- token template (honest reference at the scenario's bound) --- */
    let tok_ref = compile_kcc20(kcc20_source(), COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, c.max_cov);
    let tpl = template_of(&tok_ref);
    let pin = Pin {
        token_covid: c.pin_covid,
        template_hash: c.pin_hash_override.unwrap_or(tpl.hash),
        prefix_len: tpl.prefix.len() as i64 + c.pin_geometry_delta.0,
        state_len: tpl.state_len as i64 + c.pin_geometry_delta.1,
        suffix_len: tpl.suffix.len() as i64 + c.pin_geometry_delta.2,
    };

    /* --- recipient tree + agent tree (real committed root) --- */
    let (rroot, rsibs, rbits) = recip_tree(c.recip_depth, &honest_recipient);
    let mut real = c.agents.clone();
    real[c.target].recipient_root = rroot;
    let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let (root, psibs, pbits) = merkle(&leaves, c.target);
    let prev = S { agent_root: root, ..c.prev.clone() };
    let claim = Agent { recipient_root: rroot, ..c.claim_override.clone().unwrap_or(real[c.target].clone()) };

    /* --- token input --- */
    let tok_prev = if c.alien_input {
        compile_kcc20(alien_source(), COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, c.max_cov)
    } else if c.malformed_input_state {
        /* amount with the i64 sign bit set: negative in-VM */
        compile_kcc20(kcc20_source(), COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, -300, false, c.max_cov)
    } else {
        compile_kcc20(kcc20_source(), COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, c.max_cov)
    };

    let ctrl_prev = compile_ctrl(ctrl_src, &owner_pk, &pin, &prev);

    let mut inputs = vec![input(1, 0, vec![], c.budgets.0)];
    let mut entries = vec![cov_utxo(prev.reserve, &ctrl_prev, COV_CTRL)];
    let mut outputs: Vec<TransactionOutput> = Vec::new();
    let mut token_sigscript: Option<Vec<u8>> = None;
    let mut rider_sigscript: Option<Vec<u8>> = None;
    let ctrl_call_args: Vec<Expr<'static>>;
    let ctrl_function: &str;

    match c.op {
        Op::AgentSpend => {
            let spend = c.spend;
            let self_after = PREV_TOKEN_AMOUNT - spend + c.self_amount_delta;
            let (self_owner, self_type) = c.self_owner_override.unwrap_or((*COV_CTRL.as_bytes().as_slice().first_chunk::<32>().unwrap(), IDENTIFIER_COVENANT_ID));
            let out_bound = if c.variant_outputs { c.max_cov + 2 } else { c.max_cov };
            let tok_self = if c.alien_self_output {
                compile_kcc20(alien_source(), self_owner, self_type, self_after, c.self_minter, c.max_cov)
            } else {
                compile_kcc20(kcc20_source(), self_owner, self_type, self_after, c.self_minter, out_bound)
            };
            let tok_recipient = compile_kcc20(kcc20_source(), recipient_pk, c.recipient_type, spend, c.recipient_minter, out_bound);

            /* period accounting + successor root (from the claim) */
            let mut new_start = claim.period_start_daa;
            let mut new_spent = claim.period_spent + spend;
            if c.periods_elapsed >= 1 {
                new_start = claim.period_start_daa + c.periods_elapsed * claim.period_length_daa;
                new_spent = spend;
            }
            let new_leaf = agent_leaf(&Agent { period_start_daa: new_start, period_spent: new_spent, ..claim.clone() });
            let new_root = c.new_root_override.unwrap_or(fold(new_leaf, &psibs, pbits));
            let succ_reserve = c.succ_reserve_override.unwrap_or(prev.reserve - c.reserve_consumed);
            let new_state = S { reserve: succ_reserve, agent_root: new_root, ..prev.clone() };
            let ctrl_next = compile_ctrl(ctrl_src, &owner_pk, &pin, &new_state);

            /* KAS shape */
            let self_carry = c.self_carry_override.unwrap_or(TOKEN_CARRY - c.recipient_carry);
            let change = FUEL - (c.fee - c.reserve_consumed);
            let succ_value = c.succ_value_override.unwrap_or(succ_reserve);

            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(cov_out(self_carry, &tok_self, 1, c.family_id));
            outputs.push(cov_out(c.recipient_carry, &tok_recipient, 1, c.family_id));
            let mut token_new_states = vec![
                kcc20_state(self_owner, self_type, self_after, c.self_minter, false),
                kcc20_state(recipient_pk, c.recipient_type, spend, c.recipient_minter, false),
            ];
            if c.hidden_extra_output {
                outputs.push(cov_out(1000, &tok_recipient, 1, c.family_id));
                token_new_states.push(kcc20_state(recipient_pk, IDENTIFIER_PUBKEY, 0, false, false));
            }
            outputs.push(p2pk_out(&fuel_pk, change));
            if c.extra_self_family_output {
                /* a second output bound to the controller's OWN family id, authorized by input 0 */
                let last = outputs.len() - 1;
                outputs[last].value -= 1000;
                outputs.push(cov_out(1000, &ctrl_next, 0, COV_CTRL));
            }
            if c.extra_genesis_output_by_controller {
                /* a genesis output of a NEW family authorized by the controller input */
                let last = outputs.len() - 1;
                outputs[last].value -= 1000;
                outputs.push(cov_out(1000, &tok_recipient, 0, COV_ALIEN));
            }

            inputs.push(input(2, 0, vec![], c.budgets.1));
            entries.push(cov_utxo(TOKEN_CARRY, &tok_prev, c.family_id));
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

            if c.foreign_family_rider {
                /* a DIFFERENT asset family (alien template) deposited to this
                 * controller's covenant id — the rider moves it to the agent */
                let rider_prev = compile_kcc20(alien_source(), COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, 900, false, 2);
                let rider_out = compile_kcc20(alien_source(), xonly(&signer), IDENTIFIER_PUBKEY, 900, false, 2);
                inputs.push(input(4, 0, vec![], 100));
                entries.push(cov_utxo(KAS, &rider_prev, COV_ALIEN));
                outputs.push(cov_out(KAS, &rider_out, 3, COV_ALIEN));
                rider_sigscript = Some(cov_call(
                    &rider_prev,
                    "transfer",
                    vec![vec![kcc20_state(xonly(&signer), IDENTIFIER_PUBKEY, 900, false, true)].into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])],
                ));
            }

            let alien_states = c.alien_input;
            let token_new_states: Vec<Expr> = if alien_states {
                let mut v = vec![
                    kcc20_state(self_owner, self_type, self_after, c.self_minter, true),
                    kcc20_state(recipient_pk, c.recipient_type, spend, c.recipient_minter, true),
                ];
                if c.hidden_extra_output {
                    v.push(kcc20_state(recipient_pk, IDENTIFIER_PUBKEY, 0, false, true));
                }
                v
            } else {
                token_new_states
            };
            token_sigscript = Some(cov_call(&tok_prev, "transfer", vec![token_new_states.into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])]));

            ctrl_function = "tokenAgentSpend";
            ctrl_call_args = vec![
                state_arg(&new_state),
                kcc20_state(self_owner, self_type, self_after, c.self_minter, false),
                kcc20_state(recipient_pk, c.recipient_type, spend, c.recipient_minter, false),
                Expr::bytes(claim.pk.to_vec()),
                Expr::int(claim.max_per_spend),
                Expr::int(claim.period_budget),
                Expr::int(claim.period_length_daa),
                Expr::int(claim.period_start_daa),
                Expr::int(claim.period_spent),
                Expr::int(claim.max_fee_per_tx),
                Expr::int(claim.max_carry_kas),
                Expr::bytes(claim.recipient_root.to_vec()),
                Expr::bytes(psibs.clone()),
                Expr::int(pbits as i64),
                Expr::int(c.periods_elapsed),
                Expr::bytes(recipient_pk.to_vec()),
                Expr::bytes(rsibs.clone()),
                Expr::int(rbits as i64),
                Expr::bytes(vec![]), // signature placeholder, filled below
            ];
        }
        Op::OwnerControl(sel) => {
            let new_state = c.owner_new.clone().unwrap_or(prev.clone());
            let ctrl_next = compile_ctrl(ctrl_src, &owner_pk, &pin, &new_state);
            let succ_value = c.succ_value_override.unwrap_or(new_state.reserve);
            let top_up = new_state.reserve - prev.reserve;
            let change = FUEL - c.fee - top_up.max(0);
            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(p2pk_out(&fuel_pk, change));
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            if c.owner_tokens_ride {
                /* tokens must never move under an owner control op */
                let tok_out = compile_kcc20(kcc20_source(), owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false, c.max_cov);
                inputs.push(input(2, 0, vec![], c.budgets.1));
                entries.push(cov_utxo(TOKEN_CARRY, &tok_prev, c.family_id));
                outputs.push(cov_out(TOKEN_CARRY, &tok_out, 2, c.family_id));
                token_sigscript = Some(cov_call(
                    &tok_prev,
                    "transfer",
                    vec![vec![kcc20_state(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false, false)].into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])],
                ));
            }
            ctrl_function = "ownerControl";
            ctrl_call_args = vec![state_arg(&new_state), Expr::int(sel), Expr::bytes(vec![])];
        }
        Op::OwnerRecover => {
            let payout = c.recover_payout_override.unwrap_or(prev.reserve);
            outputs.push(p2pk_out(&owner_pk, payout));
            let (r_owner, r_type) = c.recover_recipient_override.unwrap_or((owner_pk, IDENTIFIER_PUBKEY));
            let r_amount = PREV_TOKEN_AMOUNT + c.recover_amount_delta;
            if !c.recover_no_position {
                let tok_out = compile_kcc20(kcc20_source(), r_owner, r_type, r_amount, false, c.max_cov);
                inputs.push(input(2, 0, vec![], c.budgets.1));
                entries.push(cov_utxo(TOKEN_CARRY, &tok_prev, c.family_id));
                outputs.push(cov_out(TOKEN_CARRY, &tok_out, 1, c.family_id));
                let mut states = vec![kcc20_state(r_owner, r_type, r_amount, false, c.alien_input)];
                if c.hidden_extra_output {
                    outputs.push(cov_out(1000, &tok_out, 1, c.family_id));
                    states.push(kcc20_state(r_owner, r_type, 0, false, c.alien_input));
                }
                token_sigscript = Some(cov_call(&tok_prev, "transfer", vec![states.into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])]));
            }
            let change = FUEL - c.fee;
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            outputs.push(p2pk_out(&fuel_pk, change));
            ctrl_function = "ownerRecover";
            ctrl_call_args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(vec![]), kcc20_state(r_owner, r_type, r_amount, false, false)];
        }
    }

    /* --- sign (budgets + all outputs are fixed now) --- */
    let unsigned = Transaction::new(1, inputs.clone(), outputs.clone(), c.lock_time, SubnetworkId::default(), 0, vec![]);
    let ctrl_sig = sign(&unsigned, &entries, 0, &signer);
    let fuel_idx = inputs.iter().position(|i| i.previous_outpoint.transaction_id == TransactionId::from_bytes([3; 32])).unwrap();
    let fuel_sig = sign(&unsigned, &entries, fuel_idx, &fuel);

    /* splice the signature into the controller call */
    let mut args = ctrl_call_args;
    match c.op {
        Op::AgentSpend => {
            let last = args.len() - 1;
            args[last] = Expr::bytes(ctrl_sig);
        }
        Op::OwnerControl(_) => args[2] = Expr::bytes(ctrl_sig),
        Op::OwnerRecover => args[1] = Expr::bytes(ctrl_sig),
    }
    let ctrl_sigscript = cov_call_opt(&ctrl_prev, ctrl_function, args, false);

    let mut signed_inputs = inputs.clone();
    signed_inputs[0].signature_script = ctrl_sigscript;
    for inp in signed_inputs.iter_mut() {
        let id = inp.previous_outpoint.transaction_id;
        if id == TransactionId::from_bytes([2; 32]) {
            inp.signature_script = token_sigscript.clone().expect("token sigscript");
        } else if id == TransactionId::from_bytes([3; 32]) {
            inp.signature_script = p2pk_sigscript(fuel_sig.clone());
        } else if id == TransactionId::from_bytes([4; 32]) {
            inp.signature_script = rider_sigscript.clone().expect("rider sigscript");
        }
    }
    let tx = Transaction::new(1, signed_inputs, outputs, c.lock_time, SubnetworkId::default(), 0, vec![]);
    Built { tx, entries, ctrl_redeem_len: ctrl_prev.script.len() }
}

/// Execute every input; returns (controller result, other inputs' results).
fn run(c: &Scen) -> (Result<(), TxScriptError>, Vec<Result<(), TxScriptError>>) {
    run_src(c, &v5_source())
}
fn run_src(c: &Scen, src: &str) -> (Result<(), TxScriptError>, Vec<Result<(), TxScriptError>>) {
    let b = build_src(c, src);
    let (ctrl, _) = execute_input_measured(b.tx.clone(), b.entries.clone(), 0);
    let others: Vec<_> = (1..b.tx.inputs.len()).map(|i| execute_input_measured(b.tx.clone(), b.entries.clone(), i).0).collect();
    (ctrl, others)
}

fn assert_accepts(label: &str, c: &Scen) {
    let (ctrl, others) = run(c);
    ctrl.unwrap_or_else(|e| panic!("{label}: controller must ACCEPT: {e:?}"));
    for (i, r) in others.iter().enumerate() {
        r.clone().unwrap_or_else(|e| panic!("{label}: input {} must ACCEPT: {e:?}", i + 1));
    }
}

/* ---------------------------------------------------------------- */
/* honest paths                                                       */
/* ---------------------------------------------------------------- */

#[test]
fn v5_honest_token_agent_spend_accepts_every_input() {
    assert_accepts("tokenAgentSpend", &honest(Op::AgentSpend));
}

#[test]
fn v5_honest_rollover_spend_accepts() {
    let mut c = honest(Op::AgentSpend);
    c.agents[0].period_spent = 350; // exhausted in the old period
    c.periods_elapsed = 2;
    c.lock_time = 7000; // >= 5000 + 2*1000
    assert_accepts("rollover", &c);
}

#[test]
fn v5_honest_deep_proofs_accept_at_maximum_depths() {
    let mut c = honest(Op::AgentSpend);
    /* 4096 agents = depth 12 */
    let (owner_unused, agent, _r, _f, _o) = keys();
    let _ = owner_unused;
    let mut agents: Vec<Agent> = (0..4096u32).map(|i| {
        let mut pk = [0u8; 32];
        pk[..4].copy_from_slice(&i.to_le_bytes());
        pk[31] = 0x77;
        honest_agent(pk)
    }).collect();
    agents[1337] = honest_agent(xonly(&agent));
    c.agents = agents;
    c.target = 1337;
    c.recip_depth = 16;
    assert_accepts("deep proofs", &c);
}

#[test]
fn v5_honest_owner_ops_accept() {
    let base = honest(Op::OwnerControl(0));
    let root2 = [0x99; 32];
    let cases: Vec<(&str, Scen)> = vec![
        ("setAgentRoot", { let mut c = base.clone(); c.op = Op::OwnerControl(0); c.owner_new = Some(S { agent_root: root2, policy_nonce: 1, ..c.prev.clone() }); c }),
        ("topUpReserve", { let mut c = base.clone(); c.op = Op::OwnerControl(1); c.owner_new = Some(S { reserve: RESERVE + KAS / 2, ..c.prev.clone() }); c }),
        ("pause", { let mut c = base.clone(); c.op = Op::OwnerControl(2); c.owner_new = Some(S { paused: 1, ..c.prev.clone() }); c }),
        ("unpause", { let mut c = base.clone(); c.op = Op::OwnerControl(3); c.prev.paused = 1; c.owner_new = Some(S { paused: 0, ..c.prev.clone() }); c }),
    ];
    for (label, mut c) in cases {
        c.signer_seed = 0x61; // owner
        // owner_new must carry the REAL committed root for non-root ops
        if let Some(n) = c.owner_new.as_mut() {
            if label != "setAgentRoot" {
                let (_o, agent, _r, _f, other) = keys();
                let _ = (agent, other);
                n.agent_root = ZERO32; // placeholder; build() recomputes prev root, so patch below
            }
        }
        assert_owner_op(label, &c);
    }
}

/// Owner ops: the committed prev root is computed inside build(); the
/// successor must carry it unchanged except for setAgentRoot. Patch by
/// building once to learn the real root.
fn assert_owner_op(label: &str, c: &Scen) {
    let mut c = c.clone();
    let real_root = {
        let (rroot, _, _) = recip_tree(c.recip_depth, &xonly(&keys().2));
        let mut real = c.agents.clone();
        real[c.target].recipient_root = rroot;
        let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
        merkle(&leaves, c.target).0
    };
    if let Some(n) = c.owner_new.as_mut() {
        if !matches!(c.op, Op::OwnerControl(0)) {
            n.agent_root = real_root;
        }
    }
    assert_accepts(label, &c);
}

#[test]
fn v5_honest_owner_recover_accepts_with_and_without_position() {
    let mut c = honest(Op::OwnerRecover);
    c.signer_seed = 0x61;
    assert_accepts("recover(with position)", &c);
    let mut c2 = c.clone();
    c2.recover_no_position = true;
    assert_accepts("recover(no position)", &c2);
}

/* ---------------------------------------------------------------- */
/* hostile matrix                                                     */
/* ---------------------------------------------------------------- */

type Mut = fn(&mut Scen);

fn refuse_all(cases: &[(&str, Mut)], base: fn() -> Scen) -> Vec<String> {
    let mut failures = Vec::new();
    for (label, m) in cases {
        let mut c = base();
        m(&mut c);
        let (ctrl, _) = run(&c);
        match ctrl {
            Ok(()) => failures.push(format!("{label}: controller ACCEPTED — must REFUSE")),
            Err(e) => println!("  REFUSED {label:<64} {e:?}"),
        }
    }
    failures
}

fn spend_base() -> Scen {
    honest(Op::AgentSpend)
}

const SPEND_MATRIX: &[(&str, Mut)] = &[
    ("wrong-covenant-family (family id != pinned)", |c| c.family_id = COV_WRONG),
    ("wrong-token-template (alien self output)", |c| c.alien_self_output = true),
    ("wrong-accepted-template-variant (outputs bound 4, same family)", |c| c.variant_outputs = true),
    ("alien-token-input (same family id, alien template)", |c| c.alien_input = true),
    ("hidden-extra-token-family-output", |c| c.hidden_extra_output = true),
    ("token-conservation(+1)", |c| c.self_amount_delta = 1),
    ("token-conservation(-1)", |c| c.self_amount_delta = -1),
    ("over-cap spend (251 > 250)", |c| c.spend = 251),
    ("budget-exhaustion (200 spent + 250 > 400)", |c| { c.agents[0].period_spent = 200; c.spend = 250; }),
    ("period-accounting-misreport (claim spent 0, tree says 200)", |c| { c.agents[0].period_spent = 200; c.claim_override = Some({ let mut a = c.agents[0].clone(); a.period_spent = 0; a }); }),
    ("premature-rollover (periodsElapsed 1 before the boundary)", |c| { c.agents[0].period_spent = 350; c.periods_elapsed = 1; c.lock_time = 5999; }),
    ("stale-rollover-lock (locktime below new period start)", |c| { c.agents[0].period_spent = 350; c.periods_elapsed = 2; c.lock_time = 6999; }),
    ("wrong-VM-hash pinned (controller instance bound to another template)", |c| c.pin_hash_override = Some([0xab; 32])),
    ("wrong-geometry pinned (suffixLen+1)", |c| c.pin_geometry_delta = (0, 0, 1)),
    ("geometry/split manipulation (prefixLen+1, suffixLen-1, same hash)", |c| c.pin_geometry_delta = (1, 0, -1)),
    ("wrong-signer (owner key on the agent path)", |c| c.signer_seed = 0x61),
    ("wrong-signer (unlisted key)", |c| c.signer_seed = 0x71),
    ("ownership-theft (self continuation re-owned to the agent key)", |c| { let pk = xonly(&keys().1); c.self_owner_override = Some((pk, IDENTIFIER_PUBKEY)); }),
    ("ownership-theft (self continuation re-owned to the recipient key)", |c| { let pk = xonly(&keys().2); c.self_owner_override = Some((pk, IDENTIFIER_PUBKEY)); }),
    ("recipient not in allowlist", |c| c.recipient_override = Some(xonly(&keys().4))),
    ("recipient owned by covenant-id scheme instead of p2pk", |c| c.recipient_type = IDENTIFIER_COVENANT_ID),
    ("self becomes minter", |c| c.self_minter = true),
    ("recipient becomes minter", |c| c.recipient_minter = true),
    ("agent not in tree (forged leaf)", |c| { c.claim_override = Some({ let mut a = c.agents[0].clone(); a.max_per_spend = 10_000; a }); c.spend = 200; }),
    ("successor root misreport", |c| c.new_root_override = Some([0x55; 32])),
    ("paused vault", |c| c.prev.paused = 1),
    ("controller-KAS drain (successor value below declared reserve)", |c| c.succ_value_override = Some(RESERVE - RESERVE_CONSUMED - 1_000_000)),
    ("controller-KAS drain (reserve consumed > exact fee)", |c| { c.reserve_consumed = FEE + 1; }),
    ("controller-KAS drain (reserve consumed > agentMaxFeePerTx)", |c| { c.fee = 100_000; c.reserve_consumed = 60_001; c.agents[0].max_fee_per_tx = 60_000; c.fee = 200_000; }),
    ("token/KAS confusion (recipient carry > agentMaxCarryKas)", |c| c.recipient_carry = KAS / 4 + 1),
    ("token/KAS confusion (token family KAS leaks to change)", |c| c.self_carry_override = Some(TOKEN_CARRY - RECIPIENT_CARRY - 1)),
    ("foreign-family rider (another asset owned by the controller moved to the agent)", |c| c.foreign_family_rider = true),
    ("malformed token state (negative amount in-VM)", |c| c.malformed_input_state = true),
    ("zero spend", |c| c.spend = 0),
    ("declared successor reserve inflated", |c| c.succ_reserve_override = Some(RESERVE + 1)),
    ("self-clone: second output bound to the controller's own family (reread finding)", |c| c.extra_self_family_output = true),
    ("foreign genesis output authorized by the controller input (reread finding)", |c| c.extra_genesis_output_by_controller = true),
];

#[test]
fn v5_hostile_matrix_token_agent_spend_refuses_everything() {
    let f = refuse_all(SPEND_MATRIX, spend_base);
    assert!(f.is_empty(), "v0.5 spend matrix failures:\n{}", f.join("\n"));
}

fn owner_base() -> Scen {
    let mut c = honest(Op::OwnerControl(0));
    c.signer_seed = 0x61;
    c
}

#[test]
fn v5_hostile_matrix_owner_ops_refuse() {
    let real_root = {
        let c = owner_base();
        let (rroot, _, _) = recip_tree(0, &xonly(&keys().2));
        let mut real = c.agents.clone();
        real[0].recipient_root = rroot;
        let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
        merkle(&leaves, 0).0
    };
    let with = |f: &dyn Fn(&mut Scen, [u8; 32])| {
        let mut c = owner_base();
        f(&mut c, real_root);
        c
    };
    let cases: Vec<(&str, Scen)> = vec![
        ("agent key on ownerControl", with(&|c, r| { c.signer_seed = 0x62; c.owner_new = Some(S { paused: 1, agent_root: r, ..c.prev.clone() }); c.op = Op::OwnerControl(2); })),
        ("selector out of range (4)", with(&|c, r| { c.op = Op::OwnerControl(4); c.owner_new = Some(S { paused: 1, agent_root: r, ..c.prev.clone() }); })),
        ("selector/successor mismatch (pause selector, root change)", with(&|c, _r| { c.op = Op::OwnerControl(2); c.owner_new = Some(S { agent_root: [0x99; 32], policy_nonce: 1, ..c.prev.clone() }); })),
        ("setAgentRoot without nonce increment", with(&|c, _r| { c.op = Op::OwnerControl(0); c.owner_new = Some(S { agent_root: [0x99; 32], ..c.prev.clone() }); })),
        ("setAgentRoot draining reserve", with(&|c, _r| { c.op = Op::OwnerControl(0); c.owner_new = Some(S { agent_root: [0x99; 32], policy_nonce: 1, reserve: RESERVE - 1, ..c.prev.clone() }); })),
        ("topUpReserve with decrease", with(&|c, r| { c.op = Op::OwnerControl(1); c.owner_new = Some(S { reserve: RESERVE - 1, agent_root: r, ..c.prev.clone() }); })),
        ("successor value != declared reserve", with(&|c, r| { c.op = Op::OwnerControl(2); c.owner_new = Some(S { paused: 1, agent_root: r, ..c.prev.clone() }); c.succ_value_override = Some(RESERVE - 1); })),
        ("tokens riding an owner control op", with(&|c, r| { c.op = Op::OwnerControl(2); c.owner_new = Some(S { paused: 1, agent_root: r, ..c.prev.clone() }); c.owner_tokens_ride = true; })),
        ("recover: agent key", with(&|c, _r| { c.op = Op::OwnerRecover; c.signer_seed = 0x62; })),
        ("recover: tokens to a non-owner key", with(&|c, _r| { c.op = Op::OwnerRecover; c.recover_recipient_override = Some((xonly(&keys().1), IDENTIFIER_PUBKEY)); })),
        ("recover: tokens kept under covenant-id scheme", with(&|c, _r| { c.op = Op::OwnerRecover; c.recover_recipient_override = Some((*COV_CTRL.as_bytes().as_slice().first_chunk::<32>().unwrap(), IDENTIFIER_COVENANT_ID)); })),
        ("recover: partial token amount", with(&|c, _r| { c.op = Op::OwnerRecover; c.recover_amount_delta = -1; })),
        ("recover: hidden extra family output", with(&|c, _r| { c.op = Op::OwnerRecover; c.hidden_extra_output = true; })),
        ("recover: reserve payout short", with(&|c, _r| { c.op = Op::OwnerRecover; c.recover_payout_override = Some(RESERVE - 1); })),
        ("recover: alien token input", with(&|c, _r| { c.op = Op::OwnerRecover; c.alien_input = true; })),
    ];
    let mut failures = Vec::new();
    for (label, c) in cases {
        let (ctrl, _) = run(&c);
        match ctrl {
            Ok(()) => failures.push(format!("{label}: controller ACCEPTED — must REFUSE")),
            Err(e) => println!("  REFUSED {label:<64} {e:?}"),
        }
    }
    assert!(failures.is_empty(), "v0.5 owner matrix failures:\n{}", failures.join("\n"));
}

/* ---------------------------------------------------------------- */
/* sabotage sensitivity — each binding guard is load-bearing          */
/* ---------------------------------------------------------------- */

#[test]
fn v5_sabotage_guards_are_load_bearing() {
    let src = v5_source();
    let cases: Vec<(&str, &str, Mut)> = vec![
        (
            "family isolation guard",
            "        requireNoForeignCovenantInputs(tokIn);\n\n        /* BINDING B",
            |c| c.foreign_family_rider = true,
        ),
        (
            "ownership guard (self continuation owner == controller id)",
            "        require(prevTok.ownerIdentifier == selfId);\n        require(prevTok.identifierType == IDENTIFIER_COVENANT_ID);\n        require(!prevTok.isMinter);\n        require(selfNew.ownerIdentifier == selfId);",
            /* re-own the position to a FOREIGN covenant id (scheme unchanged) */
            |c| { let pk = xonly(&keys().1); c.self_owner_override = Some((pk, IDENTIFIER_COVENANT_ID)); },
        ),
        (
            "recipient carry cap",
            "        require(tx.outputs[recipientOut].value <= agentMaxCarryKas);",
            |c| c.recipient_carry = KAS / 4 + 1,
        ),
    ];
    for (label, anchor, m) in cases {
        assert!(src.contains(anchor), "sabotage anchor missing for {label}");
        let mutated = match label {
            "ownership guard (self continuation owner == controller id)" => src.replacen(
                anchor,
                "        require(prevTok.identifierType == IDENTIFIER_COVENANT_ID);\n        require(!prevTok.isMinter);\n        require(bytes(selfNew.ownerIdentifier) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));",
                1,
            ),
            "family isolation guard" => src.replacen(anchor, "\n        /* BINDING B", 1),
            _ => src.replacen(anchor, "", 1),
        };
        let mut c = spend_base();
        m(&mut c);
        let (intact, _) = run(&c);
        assert!(intact.is_err(), "{label}: intact covenant must refuse");
        let (sabotaged, _) = run_src(&c, &mutated);
        sabotaged.unwrap_or_else(|e| panic!("{label}: with the guard removed the attack must PASS (guard is load-bearing): {e:?}"));
        println!("  LOAD-BEARING {label}");
    }
}

/* ---------------------------------------------------------------- */
/* measurement                                                        */
/* ---------------------------------------------------------------- */

#[test]
fn v5_measurement_units_mass_standardness() {
    let mc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    println!("shape | ctrl_units(+sigop)->budget token_units->budget | ctrl_redeem ctrl_ss | tx_bytes compute transient fee_mass min_fee | est_ctrl | sigops ctrl/token");
    let shapes: Vec<(&str, Scen)> = vec![
        ("spend depth0/0", honest(Op::AgentSpend)),
        ("spend depth12/16", {
            let mut c = honest(Op::AgentSpend);
            let (_o, agent, _r, _f, _x) = keys();
            let mut agents: Vec<Agent> = (0..4096u32).map(|i| { let mut pk = [0u8; 32]; pk[..4].copy_from_slice(&i.to_le_bytes()); pk[31] = 0x77; honest_agent(pk) }).collect();
            agents[1337] = honest_agent(xonly(&agent));
            c.agents = agents; c.target = 1337; c.recip_depth = 16; c
        }),
        ("spend bound4", { let mut c = honest(Op::AgentSpend); c.max_cov = 4; c }),
        ("spend bound8", { let mut c = honest(Op::AgentSpend); c.max_cov = 8; c }),
        ("ownerControl(pause)", { let mut c = owner_base(); c.op = Op::OwnerControl(2); c.owner_new = Some(S { paused: 1, ..c.prev.clone() }); c }),
        ("ownerRecover", { let mut c = honest(Op::OwnerRecover); c.signer_seed = 0x61; c }),
    ];
    let mut envelope_ok = true;
    for (label, mut c) in shapes {
        if let Op::OwnerControl(_) = c.op {
            let (rroot, _, _) = recip_tree(0, &xonly(&keys().2));
            let mut real = c.agents.clone();
            real[0].recipient_root = rroot;
            let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
            c.owner_new.as_mut().unwrap().agent_root = merkle(&leaves, 0).0;
        }
        /* pass 1: priced units -> covering budgets; pass 2: rebuild with the budgets (sighash-covered) */
        let b0 = build(&c);
        let priced = |b: &Built, i: usize| execute_input_measured_priced(b.tx.clone(), b.entries.clone(), i, 1000);
        let (r0, u0) = priced(&b0, 0);
        r0.unwrap_or_else(|e| panic!("{label}: controller must accept: {e:?}"));
        let n = b0.tx.inputs.len();
        let mut units = vec![u0];
        for i in 1..n {
            let (r, u) = priced(&b0, i);
            r.unwrap_or_else(|e| panic!("{label}: input {i} must accept: {e:?}"));
            units.push(u);
        }
        let budget = |u: u64| ComputeBudget::checked_covering_script_units(ScriptUnits(u)).expect("budget").0;
        c.budgets = (budget(units[0]), if n > 2 { budget(units[1]) } else { 10 }, budget(units[n - 1]));
        let b = build(&c);
        for i in 0..n {
            let (r, u) = priced(&b, i);
            r.unwrap_or_else(|e| panic!("{label}: pass-2 input {i} must accept: {e:?}"));
            assert_eq!(u, units[i], "{label}: units must not depend on committed budgets");
        }
        let (_, ctrl_units) = execute_input_measured(b.tx.clone(), b.entries.clone(), 0);
        let masses = mc.calc_non_contextual_masses(&b.tx);
        let size = transaction_estimated_serialized_size(&b.tx);
        let normalized_transient = (masses.transient_mass * 500_000).div_ceil(1_000_000);
        let fee_mass = masses.compute_mass.max(normalized_transient);
        let est = estimate_script_units_upper_bound::<PopulatedTransaction, SigHashReusedValuesUnsync>(&b.tx.inputs[0].signature_script, &b.entries[0].script_public_key, 100_000).0;
        let sig_ctrl = post_toccata_p2sh_sig_scanner(&b.tx.inputs[0].signature_script, &b.entries[0].script_public_key);
        let sig_tok = if n > 2 { post_toccata_p2sh_sig_scanner(&b.tx.inputs[1].signature_script, &b.entries[1].script_public_key) } else { 0 };
        println!(
            "{label:<20} | {ctrl_units:>7}({:>7})->{:<3} {:>6}->{:<2} | {:>5} {:>5} | {:>5} {:>6} {:>7} {:>7} {:>8} | {est:>7} | {sig_ctrl}/{sig_tok}",
            units[0], c.budgets.0, if n > 2 { units[1] } else { 0 }, c.budgets.1, b.ctrl_redeem_len, b.tx.inputs[0].signature_script.len(),
            size, masses.compute_mass, masses.transient_mass, fee_mass, fee_mass * 100
        );
        assert!(sig_ctrl <= 15, "controller static sig-ops must be standard");
        assert_eq!(sig_ctrl, 3, "v0.5 controller redeem carries exactly 3 static sig-ops");
        assert!(b.tx.inputs[0].signature_script.len() <= 250_000);
        if label == "spend depth0/0" && ctrl_units > 120_000 {
            envelope_ok = false;
        }
    }
    assert!(envelope_ok, "v0.5 target-shape controller compute blew the 120,000-unit envelope");
}

/* ---------------------------------------------------------------- */
/* PRODUCTION-BYTE integration: the REAL pv_call_encoder binary       */
/* ---------------------------------------------------------------- */

fn encoder_path() -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}/target/debug/pv_call_encoder", env!("CARGO_MANIFEST_DIR")))
}

/// Encode a v0.5 covenant call via the production encoder binary, exactly
/// as the SDK drives it (exact-live-state source + constructor-args.json +
/// call.json). Returns the call bytes (without the redeem push).
fn encode_via_binary(owner: &[u8; 32], pin: &Pin, prev: &S, call: &serde_json::Value) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir().join(format!("pv5-enc-{}-{}", std::process::id(), rand_tag()));
    std::fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("PolicyVault.state.sil");
    let args_path = dir.join("constructor-args.json");
    let call_path = dir.join("call.json");
    std::fs::write(&source_path, templated(&v5_source(), prev)).unwrap();
    let bytes_arg = |b: &[u8]| -> serde_json::Value {
        serde_json::json!({ "kind": "array", "data": b.iter().map(|x| serde_json::json!({ "kind": "byte", "data": x })).collect::<Vec<_>>() })
    };
    let int_arg = |v: i64| serde_json::json!({ "kind": "int", "data": v });
    let ctor = serde_json::json!([
        bytes_arg(owner),
        bytes_arg(&VAULT_ID),
        bytes_arg(&DESCRIPTOR_HASH),
        bytes_arg(&pin.token_covid.as_bytes()),
        bytes_arg(&pin.template_hash),
        int_arg(pin.prefix_len),
        int_arg(pin.state_len),
        int_arg(pin.suffix_len),
        bytes_arg(&prev.agent_root),
        int_arg(prev.reserve),
    ]);
    std::fs::write(&args_path, serde_json::to_string(&ctor).unwrap()).unwrap();
    std::fs::write(&call_path, serde_json::to_string(call).unwrap()).unwrap();
    let out = std::process::Command::new(encoder_path()).arg(&source_path).arg(&args_path).arg(&call_path).output().expect("run encoder");
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let hex = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect())
}
fn rand_tag() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

/// Build the honest spend, then REPLACE the controller's in-process call
/// bytes with the encoder BINARY's bytes and execute every input.
#[test]
fn v5_encoder_binary_bytes_accepted_by_engine_and_mutations_refused() {
    let c = honest(Op::AgentSpend);
    let (owner, agent, recipient, _fuel, _o) = keys();
    let owner_pk = xonly(&owner);
    let b = build(&c);

    /* Recover the exact planned call inputs (same derivation as build()). */
    let tok_ref = compile_kcc20(kcc20_source(), COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, c.max_cov);
    let tpl = template_of(&tok_ref);
    let pin = Pin { token_covid: c.pin_covid, template_hash: tpl.hash, prefix_len: tpl.prefix.len() as i64, state_len: tpl.state_len as i64, suffix_len: tpl.suffix.len() as i64 };
    let (rroot, rsibs, rbits) = recip_tree(c.recip_depth, &xonly(&recipient));
    let mut real = c.agents.clone();
    real[c.target].recipient_root = rroot;
    let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let (root, psibs, pbits) = merkle(&leaves, c.target);
    let prev = S { agent_root: root, ..c.prev.clone() };
    let claim = Agent { recipient_root: rroot, ..real[c.target].clone() };
    let new_leaf = agent_leaf(&Agent { period_spent: claim.period_spent + c.spend, ..claim.clone() });
    let new_root = fold(new_leaf, &psibs, pbits);
    let succ = S { reserve: prev.reserve - c.reserve_consumed, agent_root: new_root, ..prev.clone() };

    /* the signature the in-process build produced is bound to this exact tx;
     * the encoder must reproduce the SAME call bytes given the same inputs */
    let unsigned = Transaction::new(1, b.tx.inputs.iter().map(|i| TransactionInput { signature_script: vec![], ..i.clone() }).collect(), b.tx.outputs.clone(), c.lock_time, SubnetworkId::default(), 0, vec![]);
    let sig = sign(&unsigned, &b.entries, 0, &agent);
    let ctrl_id = hx(&COV_CTRL.as_bytes());
    let call = serde_json::json!({
        "function": "tokenAgentSpend",
        "contractVersion": "policyvault-0.5",
        "signature": hx(&sig),
        "successor": { "feeReserve": succ.reserve.to_string(), "paused": succ.paused, "agentRoot": hx(&succ.agent_root), "policyNonce": succ.policy_nonce.to_string() },
        "selfNew": { "ownerIdentifier": ctrl_id, "identifierType": 2, "amount": (PREV_TOKEN_AMOUNT - c.spend).to_string(), "isMinter": false },
        "recipientNew": { "ownerIdentifier": hx(&xonly(&recipient)), "identifierType": 0, "amount": c.spend.to_string(), "isMinter": false },
        "agentPk": hx(&claim.pk),
        "tokenMaxPerSpend": claim.max_per_spend.to_string(),
        "tokenPeriodBudget": claim.period_budget.to_string(),
        "periodLengthDaa": claim.period_length_daa.to_string(),
        "periodStartDaa": claim.period_start_daa.to_string(),
        "tokenPeriodSpent": claim.period_spent.to_string(),
        "agentMaxFeePerTx": claim.max_fee_per_tx.to_string(),
        "agentMaxCarryKas": claim.max_carry_kas.to_string(),
        "agentRecipientRoot": hx(&claim.recipient_root),
        "policySiblings": hx(&psibs),
        "policyPathBits": pbits.to_string(),
        "periodsElapsed": "0",
        "recipientPk": hx(&xonly(&recipient)),
        "recipientSiblings": hx(&rsibs),
        "recipientPathBits": rbits.to_string(),
    });
    let encoded = encode_via_binary(&owner_pk, &pin, &prev, &call).expect("encoder must accept the honest v0.5 call");
    let ctrl_prev = compile_ctrl(&v5_source(), &owner_pk, &pin, &prev);
    let mut sigscript = encoded.clone();
    sigscript.extend_from_slice(&push_redeem(&ctrl_prev.script));

    /* PRODUCTION-BYTE: the binary's bytes must equal the in-process bytes for
     * the SAME signature (Schnorr signing is randomized, so the signature is
     * generated once here and fed to both encoders), then execute. */
    let in_process = cov_call_opt(
        &ctrl_prev,
        "tokenAgentSpend",
        vec![
            state_arg(&succ),
            kcc20_state(*COV_CTRL.as_bytes().as_slice().first_chunk::<32>().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT - c.spend, false, false),
            kcc20_state(xonly(&recipient), IDENTIFIER_PUBKEY, c.spend, false, false),
            Expr::bytes(claim.pk.to_vec()),
            Expr::int(claim.max_per_spend),
            Expr::int(claim.period_budget),
            Expr::int(claim.period_length_daa),
            Expr::int(claim.period_start_daa),
            Expr::int(claim.period_spent),
            Expr::int(claim.max_fee_per_tx),
            Expr::int(claim.max_carry_kas),
            Expr::bytes(claim.recipient_root.to_vec()),
            Expr::bytes(psibs.clone()),
            Expr::int(pbits as i64),
            Expr::int(0),
            Expr::bytes(xonly(&recipient).to_vec()),
            Expr::bytes(rsibs.clone()),
            Expr::int(rbits as i64),
            Expr::bytes(sig.clone()),
        ],
        false,
    );
    assert_eq!(hx(&sigscript), hx(&in_process), "encoder binary must reproduce the in-process covenant call bytes exactly");
    assert_eq!(sigscript.len(), b.tx.inputs[0].signature_script.len(), "byte length must match the build's planned length");
    let mut tx = b.tx.clone();
    tx.inputs[0].signature_script = sigscript;
    for i in 0..tx.inputs.len() {
        execute_input_measured(tx.clone(), b.entries.clone(), i).0.unwrap_or_else(|e| panic!("input {i} must accept encoder-binary bytes: {e:?}"));
    }

    /* encoder-level fail-closed: wrong version dispatch, bad selector, recover with selector, unknown function */
    let mut wrong_version = call.clone();
    wrong_version["contractVersion"] = serde_json::json!("policyvault-0.4.1");
    assert!(encode_via_binary(&owner_pk, &pin, &prev, &wrong_version).is_err(), "v0.4.1 dispatch must not encode a v0.5 call");
    let bad_sel = serde_json::json!({ "function": "ownerControl", "contractVersion": "policyvault-0.5", "signature": hx(&sig), "opSelector": 4,
        "successor": { "feeReserve": prev.reserve.to_string(), "paused": 1, "agentRoot": hx(&prev.agent_root), "policyNonce": "0" } });
    assert!(encode_via_binary(&owner_pk, &pin, &prev, &bad_sel).is_err(), "opSelector 4 must fail closed");
    let rec_sel = serde_json::json!({ "function": "ownerRecover", "contractVersion": "policyvault-0.5", "signature": hx(&sig), "opSelector": 0,
        "recipientNew": { "ownerIdentifier": hx(&owner_pk), "identifierType": 0, "amount": "300", "isMinter": false } });
    assert!(encode_via_binary(&owner_pk, &pin, &prev, &rec_sel).is_err(), "ownerRecover must not carry opSelector");
    let unknown = serde_json::json!({ "function": "agentSpend", "contractVersion": "policyvault-0.5", "signature": hx(&sig) });
    assert!(encode_via_binary(&owner_pk, &pin, &prev, &unknown).is_err(), "v0.4 function names must fail closed under v0.5");
    let bad_type = {
        let mut v = call.clone();
        v["recipientNew"]["identifierType"] = serde_json::json!(3);
        v
    };
    assert!(encode_via_binary(&owner_pk, &pin, &prev, &bad_type).is_err(), "unknown owner scheme must fail closed");

    /* a MUTATED intent through the real encoder is refused by consensus (recipient swap) */
    let mut swapped = call.clone();
    swapped["recipientPk"] = serde_json::json!(hx(&xonly(&_o)));
    swapped["recipientNew"]["ownerIdentifier"] = serde_json::json!(hx(&xonly(&_o)));
    let enc2 = encode_via_binary(&owner_pk, &pin, &prev, &swapped).expect("encoder encodes syntactically valid mutations");
    let mut s2 = enc2;
    s2.extend_from_slice(&push_redeem(&ctrl_prev.script));
    let mut tx2 = b.tx.clone();
    tx2.inputs[0].signature_script = s2;
    assert!(execute_input_measured(tx2, b.entries.clone(), 0).0.is_err(), "consensus must refuse the recipient-swapped call");
}
