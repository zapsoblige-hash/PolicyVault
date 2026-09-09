#![allow(dead_code, unused_variables, unused_mut, unused_imports)]
//! ADVERSARIAL REVIEW PROBES (independent) — CANDIDATE PolicyVault.v0.6.sil.
//! Harness copied verbatim from tests/vm/tests/v6_production.rs (lines 1..1073)
//! and extended with hostile knobs the 42-case matrix does not exercise.
//! ORIGINAL HEADER FOLLOWS.
//! VM layer — CANDIDATE PolicyVault.v0.6.sil (atomic-composability token
//! controller) driven through the real TxScriptEngine (covenants enabled,
//! real Schnorr). Honest paths for EVERY entrypoint (tokenAgentSpend,
//! tokenAtomicSell type A/B, tokenAtomicBuy, ownerControl 0..5,
//! ownerRecover) + the hostile matrix of the architecture freeze
//! (docs/postlaunch/v0.6-architecture-freeze.md) + compute/mass/sig-op/
//! standardness measurement on the ACTUAL candidate source. Consensus-visible
//! bytes go through the SilverScript compiler + covenant-decl call encoder;
//! the pv_call_encoder production-byte integration is a separate step
//! (tests/vm/tests/v6_sdk_integration.rs).
//!
//! Composition (swap shapes): the v0.6 controller (input 0) owns a KCC20
//! position (input 1, family leader), the approved pool fixture
//! (contracts/experiments/V6PoolFixture.sil, input 3) owns the reserve note
//! (input 2, family delegate). Outputs: 0 controller successor, 1 our note,
//! 2 pool note, 3 pool successor, 4 protocol fee, [5 type-B proceeds].
//! Every input is executed on the real engine.

use policyvault_vm_tests::{deterministic_keypair, execute_input_measured, execute_input_measured_priced, xonly};
use secp256k1::Keypair;
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CompiledContract, CovenantDeclCallOptions};

use kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE, SIG_HASH_SINGLE};
use kaspa_consensus_core::mass::units::{ComputeBudget, ScriptUnits};
use kaspa_consensus_core::mass::{transaction_estimated_serialized_size, MassCalculator};
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript::{pay_to_script_hash_script, post_toccata_p2sh_sig_scanner, script_builder::ScriptBuilder, EngineFlags};
use kaspa_txscript_errors::TxScriptError;

const KAS: i64 = 100_000_000;
const IDENTIFIER_PUBKEY: u8 = 0x00;
const IDENTIFIER_COVENANT_ID: u8 = 0x02;
const AGENT_DOMAIN: [u8; 4] = [0x50, 0x56, 0x36, 0x01];
const SWAP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x36, 0x02];
const RECIP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];
const VAULT_ID: [u8; 32] = [0x44; 32];
const DESCRIPTOR_HASH: [u8; 32] = [0xd5; 32];
const PROFILE_HASH: [u8; 32] = [0xaa; 32];

const COV_CTRL: Hash = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const COV_TOKEN: Hash = Hash::from_bytes(*b"TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT");
const COV_POOL: Hash = Hash::from_bytes(*b"PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP");
const COV_WRONG: Hash = Hash::from_bytes(*b"WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
const COV_ALIEN: Hash = Hash::from_bytes(*b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

/* KAS shape (sompi) */
const RESERVE: i64 = 5 * KAS;
const PRINCIPAL: i64 = 3 * KAS;
const TOKEN_CARRY: i64 = 2 * KAS;
const OUR_NOTE_KAS: i64 = 700;
const POOL_NOTE_KAS: i64 = 500;
const FUEL: i64 = 1 * KAS;
const RECIPIENT_CARRY: i64 = KAS / 5;
const FEE: i64 = 100_000;
const RESERVE_CONSUMED: i64 = 50_000;

/* pool economics (small integers; k = 1e10) */
const POOL_KAS: i64 = 1_000_000;
const POOL_TOKENS: i64 = 10_000;
const POOL_FEE_BPS: i64 = 30;
const PROTO_FEE_BPS: i64 = 20;
const OUR_TOKENS: i64 = 3_000;
/* SELL 500 tokens */
const AMOUNT_IN: i64 = 500;
const NEW_POOL_KAS_SELL: i64 = 952_563; // smallest kasReserve' with kas'·(tok+netIn) >= k (netIn 498)
const KAS_OUT: i64 = POOL_KAS - NEW_POOL_KAS_SELL; // 47_437
const PROTO_FEE_SELL: i64 = 95; // ceil(47_437 · 20 / 10_000)
const NET_PROCEEDS: i64 = KAS_OUT - PROTO_FEE_SELL; // 47_342
const MIN_KAS_OUT: i64 = 47_000;
/* BUY 400 tokens */
const TOKENS_OUT: i64 = 400;
const KAS_IN: i64 = 41_793; // smallest kasIn with tok'·(kas+netIn) >= k (fee 126, netIn 41_667)
const PROTO_FEE_BUY: i64 = 84; // ceil(41_793 · 20 / 10_000)
const KAS_SPEND: i64 = KAS_IN + PROTO_FEE_BUY; // 41_877
const MAX_KAS_IN: i64 = 42_000;
/* owner swap policy */
const MAX_PROTO_FEE: i64 = 200;
const SELL_FLOOR: (i64, i64) = (90, 1); // >= 90 sompi per token
const BUY_CEIL: (i64, i64) = (110, 1); // <= 110 sompi per token
/* agent policy */
const TOKEN_CAP: i64 = 600;
const TOKEN_BUDGET: i64 = 1_000;
const KAS_CAP: i64 = 50_000;
const KAS_BUDGET: i64 = 80_000;
const AGENT_MAX_FEE: i64 = 60_000;

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
fn h32(h: Hash) -> [u8; 32] {
    *h.as_bytes().as_slice().first_chunk::<32>().unwrap()
}

/* ---------------------------------------------------------------- */
/* token side (upstream KCC20 example)                                */
/* ---------------------------------------------------------------- */

fn kcc20_source() -> &'static str {
    let path = format!("{}/../../../silverscript/silverscript-lang/tests/examples/kcc20.sil", env!("CARGO_MANIFEST_DIR"));
    leak(std::fs::read_to_string(&path).expect("read kcc20.sil"))
}
fn compile_kcc20(owner: [u8; 32], ty: u8, amount: i64, minter: bool, max_cov: i64) -> CompiledContract<'static> {
    compile_contract(
        kcc20_source(),
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
fn kcc20_state<'i>(owner: [u8; 32], ty: u8, amount: i64, minter: bool) -> Expr<'i> {
    struct_object(vec![
        ("ownerIdentifier", Expr::bytes(owner.to_vec())),
        ("identifierType", Expr::byte(ty)),
        ("amount", Expr::int(amount)),
        ("isMinter", Expr::bool(minter)),
    ])
}

/* ---------------------------------------------------------------- */
/* pool fixture                                                       */
/* ---------------------------------------------------------------- */

fn pool_source() -> &'static str {
    let path = format!("{}/../../contracts/experiments/V6PoolFixture.sil", env!("CARGO_MANIFEST_DIR"));
    leak(std::fs::read_to_string(&path).expect("read V6PoolFixture.sil"))
}
fn alien_pool_source() -> &'static str {
    let src = pool_source();
    let mutated = src.replace("require(total <= 4);", "require(total <= 5);");
    assert_ne!(mutated, src, "alien pool mutation must change the source");
    leak(mutated)
}
fn compile_pool(source: &'static str, token_id: Hash, tpl: &Template, fee_pk: [u8; 32], kas: i64, tok: i64, nonce: i64) -> CompiledContract<'static> {
    compile_contract(
        source,
        &[
            Expr::bytes(token_id.as_bytes().to_vec()),
            Expr::int(tpl.prefix.len() as i64),
            Expr::int(tpl.suffix.len() as i64),
            Expr::bytes(tpl.hash.to_vec()),
            Expr::bytes(tpl.prefix.clone()),
            Expr::bytes(tpl.suffix.clone()),
            Expr::bytes(fee_pk.to_vec()),
            Expr::int(PROTO_FEE_BPS),
            Expr::int(kas),
            Expr::int(tok),
            Expr::int(POOL_FEE_BPS),
            Expr::int(nonce),
        ],
        CompileOptions::default(),
    )
    .unwrap_or_else(|e| panic!("compile pool fixture: {e:?}"))
}
fn pool_state<'i>(kas: i64, tok: i64, nonce: i64) -> Expr<'i> {
    struct_object(vec![("kasReserve", Expr::int(kas)), ("tokenReserve", Expr::int(tok)), ("feeBps", Expr::int(POOL_FEE_BPS)), ("nonce", Expr::int(nonce))])
}

/* ---------------------------------------------------------------- */
/* controller side                                                    */
/* ---------------------------------------------------------------- */

#[derive(Clone)]
struct Agent {
    pk: [u8; 32],
    token_cap: i64,
    token_budget: i64,
    period_length_daa: i64,
    period_start_daa: i64,
    token_spent: i64,
    max_fee_per_tx: i64,
    max_carry_kas: i64,
    kas_cap: i64,
    kas_budget: i64,
    kas_spent: i64,
    recipient_root: [u8; 32],
}
fn agent_leaf(a: &Agent) -> [u8; 32] {
    sha256(&[
        &AGENT_DOMAIN,
        &a.pk,
        &num8(a.token_cap),
        &num8(a.token_budget),
        &num8(a.period_length_daa),
        &num8(a.period_start_daa),
        &num8(a.token_spent),
        &num8(a.max_fee_per_tx),
        &num8(a.max_carry_kas),
        &num8(a.kas_cap),
        &num8(a.kas_budget),
        &num8(a.kas_spent),
        &a.recipient_root,
        &[0x00],
    ])
}
fn agent_args(a: &Agent) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(a.pk.to_vec()),
        Expr::int(a.token_cap),
        Expr::int(a.token_budget),
        Expr::int(a.period_length_daa),
        Expr::int(a.period_start_daa),
        Expr::int(a.token_spent),
        Expr::int(a.max_fee_per_tx),
        Expr::int(a.max_carry_kas),
        Expr::int(a.kas_cap),
        Expr::int(a.kas_budget),
        Expr::int(a.kas_spent),
        Expr::bytes(a.recipient_root.to_vec()),
    ]
}

#[derive(Clone)]
struct SwapLeaf {
    profile_hash: [u8; 32],
    pool_id: Hash,
    pool_hash: [u8; 32],
    pool_prefix_len: i64,
    pool_suffix_len: i64,
    fee_pk: [u8; 32],
    max_proto_fee: i64,
    sell_floor: (i64, i64),
    buy_ceil: (i64, i64),
    direction_mask: i64,
    dest_scheme: u8,
    dest_identity: [u8; 32],
}
fn swap_leaf(s: &SwapLeaf) -> [u8; 32] {
    sha256(&[
        &SWAP_DOMAIN,
        &s.profile_hash,
        &h32(s.pool_id),
        &s.pool_hash,
        &num8(s.pool_prefix_len),
        &num8(s.pool_suffix_len),
        &s.fee_pk,
        &num8(s.max_proto_fee),
        &num8(s.sell_floor.0),
        &num8(s.sell_floor.1),
        &num8(s.buy_ceil.0),
        &num8(s.buy_ceil.1),
        &num8(s.direction_mask),
        &[s.dest_scheme],
        &s.dest_identity,
    ])
}
fn swap_args(s: &SwapLeaf) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(s.profile_hash.to_vec()),
        Expr::bytes(s.pool_id.as_bytes().to_vec()),
        Expr::bytes(s.pool_hash.to_vec()),
        Expr::int(s.pool_prefix_len),
        Expr::int(s.pool_suffix_len),
        Expr::bytes(s.fee_pk.to_vec()),
        Expr::int(s.max_proto_fee),
        Expr::int(s.sell_floor.0),
        Expr::int(s.sell_floor.1),
        Expr::int(s.buy_ceil.0),
        Expr::int(s.buy_ceil.1),
        Expr::int(s.direction_mask),
        Expr::byte(s.dest_scheme),
        Expr::bytes(s.dest_identity.to_vec()),
    ]
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
/// pad a leaf list to 2^depth entries with distinct filler leaves (production-scale trees)
fn padded(mut leaves: Vec<[u8; 32]>, depth: u32) -> Vec<[u8; 32]> {
    let n = 1usize << depth;
    let mut i = 0u64;
    while leaves.len() < n {
        leaves.push(sha256(&[b"filler", &i.to_le_bytes()]));
        i += 1;
    }
    leaves
}

#[derive(Clone)]
struct S {
    reserve: i64,
    principal: i64,
    paused: i64,
    agent_root: [u8; 32],
    swap_root: [u8; 32],
    nonce: i64,
}

fn v6_source() -> &'static str {
    let path = format!("{}/../../contracts/PolicyVault.v0.6.sil", env!("CARGO_MANIFEST_DIR"));
    leak(std::fs::read_to_string(&path).expect("read PolicyVault.v0.6.sil"))
}
fn templated(src: &str, s: &S) -> String {
    let mut src = src.to_string();
    let mut r = |from: String, to: String| {
        assert!(src.contains(&from), "anchor missing: {from}");
        src = src.replacen(&from, &to, 1);
    };
    r("int feeReserve = initFeeReserve;".into(), format!("int feeReserve = {};", s.reserve));
    r("int swapPrincipal = initSwapPrincipal;".into(), format!("int swapPrincipal = {};", s.principal));
    r("int paused = 0;".into(), format!("int paused = {};", s.paused));
    r("byte[32] agentRoot = initAgentRoot;".into(), format!("byte[32] agentRoot = 0x{};", hx(&s.agent_root)));
    r("byte[32] swapRoot = initSwapRoot;".into(), format!("byte[32] swapRoot = 0x{};", hx(&s.swap_root)));
    r("int policyNonce = 0;".into(), format!("int policyNonce = {};", s.nonce));
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
fn compile_ctrl(owner: &[u8; 32], pin: &Pin, s: &S) -> CompiledContract<'static> {
    let src: &'static str = leak(templated(v6_source(), s));
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
            Expr::bytes(s.swap_root.to_vec()),
            Expr::int(s.principal),
        ],
        CompileOptions::default(),
    )
    .unwrap_or_else(|e| panic!("v0.6 compile: {e:?}"))
}
fn state_arg(s: &S) -> Expr<'static> {
    struct_object(vec![
        ("boundVaultId", Expr::bytes(VAULT_ID.to_vec())),
        ("feeReserve", Expr::int(s.reserve)),
        ("swapPrincipal", Expr::int(s.principal)),
        ("paused", Expr::int(s.paused)),
        ("agentRoot", Expr::bytes(s.agent_root.to_vec())),
        ("swapRoot", Expr::bytes(s.swap_root.to_vec())),
        ("policyNonce", Expr::int(s.nonce)),
    ])
}

/* ---------------------------------------------------------------- */
/* transaction plumbing                                               */
/* ---------------------------------------------------------------- */

fn push_redeem(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() }).add_data(script).unwrap().drain()
}
fn cov_call(c: &CompiledContract<'_>, f: &str, args: Vec<Expr<'_>>, is_leader: bool) -> Vec<u8> {
    let mut s = c.build_sig_script_for_covenant_decl(f, args, CovenantDeclCallOptions { is_leader }).expect("call");
    s.extend_from_slice(&push_redeem(&c.script));
    s
}
fn input(id: u8, sigscript: Vec<u8>, budget: u16) -> TransactionInput {
    TransactionInput::new_with_compute_budget(TransactionOutpoint { transaction_id: TransactionId::from_bytes([id; 32]), index: 0 }, sigscript, 0, budget)
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
fn sign_type(tx: &Transaction, entries: &[UtxoEntry], idx: usize, kp: &Keypair, hash_type: SigHashType) -> Vec<u8> {
    let m = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    let h = calc_schnorr_signature_hash(&m.as_verifiable(), idx, hash_type, &reused);
    let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice()).unwrap();
    let mut out = kp.sign_schnorr(msg).as_ref().to_vec();
    out.push(hash_type.to_u8());
    out
}
fn sign(tx: &Transaction, entries: &[UtxoEntry], idx: usize, kp: &Keypair) -> Vec<u8> {
    sign_type(tx, entries, idx, kp, SIG_HASH_ALL)
}
fn p2pk_sigscript(sig: Vec<u8>) -> Vec<u8> {
    ScriptBuilder::new().add_data(&sig).unwrap().drain()
}

/* ---------------------------------------------------------------- */
/* scenario                                                           */
/* ---------------------------------------------------------------- */

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Spend,
    Sell,
    Buy,
    Owner(i64),
    Recover,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum SigMode {
    All,
    SingleAnyoneCanPay,
    None,
}

#[derive(Clone)]
struct Scen {
    op: Op,
    /* controller state */
    prev: S,
    agents: Vec<Agent>,
    agent_depth: Option<u32>,
    target: usize,
    claim_override: Option<Agent>,
    /* swap policy tree: leaf 0 type A (both directions), leaf 1 type B (sell only), leaf 2 buy-only type A, leaf 3 type B (both directions) */
    swap_target: usize,
    swap_depth: Option<u32>,
    swap_claim_override: Option<SwapLeaf>,
    swap_root_override: Option<[u8; 32]>,
    /* families */
    pool_id_carried: Hash,
    alien_pool_template: bool,
    token_id_carried: Hash,
    pool_note_first: bool,
    hidden_covenant_input: bool,
    /// an extra PLAIN (non-covenant) KAS input riding a swap (external fuel / consideration)
    extra_plain_input: bool,
    hidden_extra_output: bool,
    extra_proceeds_output_on_type_a: bool,
    /* swap amounts */
    amount_in: i64,
    tokens_out: i64,
    min_kas_out: i64,
    max_kas_in: i64,
    proceeds_delta: i64,
    proceeds_to_attacker: bool,
    proto_fee_delta: i64,
    proto_fee_to_attacker: bool,
    pool_kas_delta: i64,
    self_amount_delta: i64,
    our_note_kas_delta: i64,
    principal_delta: i64,
    /* spend */
    spend: i64,
    recip_depth: u32,
    recipient_override: Option<[u8; 32]>,
    periods_elapsed: i64,
    lock_time: u64,
    /* successor tampering */
    succ_reserve_override: Option<i64>,
    succ_value_delta: i64,
    new_root_override: Option<[u8; 32]>,
    new_swap_root_override: Option<[u8; 32]>,
    new_nonce_delta: i64,
    new_paused_override: Option<i64>,
    reserve_consumed: i64,
    recipient_carry: i64,
    fee: i64,
    /* signer */
    signer_seed: u8,
    sig_mode: SigMode,
    mutate_output_after_sign: bool,
    /* owner ops */
    owner_new: Option<S>,
    owner_pool_rider: bool,
    owner_tokens_ride: bool,
    recover_payout_override: Option<i64>,
    recover_no_position: bool,
    /* v0.5-shaped spend with the pool present */
    spend_with_pool_inputs: bool,
    budgets: Vec<u16>,
    /* ---- adversarial-review knobs ---- */
    fee_out_idx_override: Option<i64>,
    proceeds_out_idx_override: Option<i64>,
    swap_leaves_override: Option<Vec<SwapLeaf>>,
    swap_out_order_flip: bool,
    swap_claim_structs_flip: bool,
    agent_sib_mut: SibMut,
    recip_sib_mut: SibMut,
    second_ctrl_input: bool,
    second_ctrl_output: bool,
    recover_recipient_amount_delta: i64,
    recover_recipient_to_attacker: bool,
    recover_recipient_type_covenant: bool,
    recover_two_token_inputs: bool,
    spend_extra_plain_output: i64,
}

/// Merkle co-path mutations applied to the CLAIM (the successor root is
/// recomputed from the mutated path, i.e. a fully self-consistent forgery).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SibMut {
    NoneM,
    ExtraHighBit,
    NotMultipleOf32,
    TooLong,
    DuplicateSibling,
    TruncateOneLevel,
}
fn apply_sib_mut(m: SibMut, sibs: Vec<u8>, bits: u64) -> (Vec<u8>, u64) {
    match m {
        SibMut::NoneM => (sibs, bits),
        SibMut::ExtraHighBit => {
            let depth = sibs.len() / 32;
            (sibs, bits | (1u64 << depth))
        }
        SibMut::NotMultipleOf32 => {
            let mut s = sibs;
            s.pop();
            (s, bits)
        }
        SibMut::TooLong => {
            let mut s = sibs;
            s.extend_from_slice(&[0x5au8; 32]);
            (s, bits)
        }
        SibMut::DuplicateSibling => {
            let mut s = sibs;
            assert!(s.len() >= 64, "DuplicateSibling needs depth >= 2");
            let first: Vec<u8> = s[0..32].to_vec();
            s[32..64].copy_from_slice(&first);
            (s, bits)
        }
        SibMut::TruncateOneLevel => {
            let mut s = sibs;
            let depth = s.len() / 32;
            assert!(depth >= 1);
            s.truncate((depth - 1) * 32);
            (s, bits & ((1u64 << (depth - 1)) - 1))
        }
    }
}

fn keys() -> (Keypair, Keypair, Keypair, Keypair, Keypair, Keypair, Keypair) {
    (
        deterministic_keypair(0x61), // owner
        deterministic_keypair(0x62), // agent
        deterministic_keypair(0x63), // recipient / type-B proceeds destination
        deterministic_keypair(0x64), // fuel
        deterministic_keypair(0x65), // other agent
        deterministic_keypair(0x66), // pool protocol-fee key
        deterministic_keypair(0x67), // attacker
    )
}

fn honest_agent(pk: [u8; 32]) -> Agent {
    Agent {
        pk,
        token_cap: TOKEN_CAP,
        token_budget: TOKEN_BUDGET,
        period_length_daa: 1000,
        period_start_daa: 5000,
        token_spent: 0,
        max_fee_per_tx: AGENT_MAX_FEE,
        max_carry_kas: KAS / 4,
        kas_cap: KAS_CAP,
        kas_budget: KAS_BUDGET,
        kas_spent: 0,
        recipient_root: ZERO32,
    }
}

fn honest(op: Op) -> Scen {
    let (_o, agent, _r, _f, other, _pf, _a) = keys();
    Scen {
        op,
        prev: S { reserve: RESERVE, principal: PRINCIPAL, paused: 0, agent_root: ZERO32, swap_root: ZERO32, nonce: 0 },
        agents: vec![honest_agent(xonly(&agent)), honest_agent(xonly(&other))],
        agent_depth: None,
        target: 0,
        claim_override: None,
        swap_target: 0,
        swap_depth: None,
        swap_claim_override: None,
        swap_root_override: None,
        pool_id_carried: COV_POOL,
        alien_pool_template: false,
        token_id_carried: COV_TOKEN,
        pool_note_first: false,
        hidden_covenant_input: false,
        extra_plain_input: false,
        hidden_extra_output: false,
        extra_proceeds_output_on_type_a: false,
        amount_in: AMOUNT_IN,
        tokens_out: TOKENS_OUT,
        min_kas_out: MIN_KAS_OUT,
        max_kas_in: MAX_KAS_IN,
        proceeds_delta: 0,
        proceeds_to_attacker: false,
        proto_fee_delta: 0,
        proto_fee_to_attacker: false,
        pool_kas_delta: 0,
        self_amount_delta: 0,
        our_note_kas_delta: 0,
        principal_delta: 0,
        spend: 200,
        recip_depth: 0,
        recipient_override: None,
        periods_elapsed: 0,
        lock_time: 0,
        succ_reserve_override: None,
        succ_value_delta: 0,
        new_root_override: None,
        new_swap_root_override: None,
        new_nonce_delta: 0,
        new_paused_override: None,
        reserve_consumed: RESERVE_CONSUMED,
        recipient_carry: RECIPIENT_CARRY,
        fee: FEE,
        signer_seed: match op {
            Op::Owner(_) | Op::Recover => 0x61,
            _ => 0x62,
        },
        sig_mode: SigMode::All,
        mutate_output_after_sign: false,
        owner_new: None,
        owner_pool_rider: false,
        owner_tokens_ride: false,
        recover_payout_override: None,
        recover_no_position: false,
        spend_with_pool_inputs: false,
        budgets: vec![400, 100, 100, 200, 10, 10],
        fee_out_idx_override: None,
        proceeds_out_idx_override: None,
        swap_leaves_override: None,
        swap_out_order_flip: false,
        swap_claim_structs_flip: false,
        agent_sib_mut: SibMut::NoneM,
        recip_sib_mut: SibMut::NoneM,
        second_ctrl_input: false,
        second_ctrl_output: false,
        recover_recipient_amount_delta: 0,
        recover_recipient_to_attacker: false,
        recover_recipient_type_covenant: false,
        recover_two_token_inputs: false,
        spend_extra_plain_output: 0,
    }
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    ctrl_redeem_len: usize,
    pool_redeem_len: usize,
}

const PREV_TOKEN_AMOUNT: i64 = OUR_TOKENS;

fn build(c: &Scen) -> Built {
    let (owner, _agent, recipient, fuel, _other, pool_fee, attacker) = keys();
    let signer = deterministic_keypair(c.signer_seed);
    let owner_pk = xonly(&owner);
    let honest_recipient = xonly(&recipient);
    let recipient_pk = c.recipient_override.unwrap_or(honest_recipient);
    let fuel_pk = xonly(&fuel);
    let pool_fee_pk = xonly(&pool_fee);
    let attacker_pk = xonly(&attacker);
    let budget = |i: usize| -> u16 { *c.budgets.get(i).unwrap_or(&10) };

    /* --- token template (bound 2: two notes in, two out) --- */
    let our_prev = compile_kcc20(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
    let tpl = template_of(&our_prev);
    let pin = Pin { token_covid: COV_TOKEN, template_hash: tpl.hash, prefix_len: tpl.prefix.len() as i64, state_len: tpl.state_len as i64, suffix_len: tpl.suffix.len() as i64 };

    /* --- honest pool template identity (pinned by the swap leaf) --- */
    let honest_pool = compile_pool(pool_source(), COV_TOKEN, &tpl, pool_fee_pk, POOL_KAS, POOL_TOKENS, 0);
    let pool_tpl = template_of(&honest_pool);

    /* --- swap policy tree --- */
    let leaf_a = SwapLeaf {
        profile_hash: PROFILE_HASH,
        pool_id: COV_POOL,
        pool_hash: pool_tpl.hash,
        pool_prefix_len: pool_tpl.prefix.len() as i64,
        pool_suffix_len: pool_tpl.suffix.len() as i64,
        fee_pk: pool_fee_pk,
        max_proto_fee: MAX_PROTO_FEE,
        sell_floor: SELL_FLOOR,
        buy_ceil: BUY_CEIL,
        direction_mask: 3,
        dest_scheme: IDENTIFIER_COVENANT_ID,
        dest_identity: ZERO32,
    };
    let leaf_b = SwapLeaf { direction_mask: 1, dest_scheme: IDENTIFIER_PUBKEY, dest_identity: honest_recipient, ..leaf_a.clone() };
    let leaf_c = SwapLeaf { direction_mask: 2, ..leaf_a.clone() };
    let leaf_d = SwapLeaf { direction_mask: 3, ..leaf_b.clone() }; // type B allowing both directions: BUY must still refuse type B
    let leaf_set: Vec<SwapLeaf> = c.swap_leaves_override.clone().unwrap_or(vec![leaf_a.clone(), leaf_b.clone(), leaf_c.clone(), leaf_d.clone()]);
    let swap_leaves: Vec<[u8; 32]> = leaf_set.iter().map(swap_leaf).collect();
    let swap_leaves = match c.swap_depth {
        Some(d) => padded(swap_leaves, d),
        None => swap_leaves,
    };
    let (swap_root, ssibs, sbits) = merkle(&swap_leaves, c.swap_target);
    let swap_claim = c.swap_claim_override.clone().unwrap_or_else(|| leaf_set[c.swap_target].clone());
    let type_b = swap_claim.dest_scheme == IDENTIFIER_PUBKEY;

    /* --- recipient tree + agent tree (real committed roots) --- */
    let (rroot, rsibs, rbits) = recip_tree(c.recip_depth, &honest_recipient);
    let (rsibs, rbits) = apply_sib_mut(c.recip_sib_mut, rsibs, rbits);
    let mut real = c.agents.clone();
    real[c.target].recipient_root = rroot;
    let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let leaves = match c.agent_depth {
        Some(d) => padded(leaves, d),
        None => leaves,
    };
    let (root, psibs, pbits) = merkle(&leaves, c.target);
    let (psibs, pbits) = apply_sib_mut(c.agent_sib_mut, psibs, pbits);
    let prev = S { agent_root: root, swap_root: c.swap_root_override.unwrap_or(swap_root), ..c.prev.clone() };
    let claim = Agent { recipient_root: rroot, ..c.claim_override.clone().unwrap_or(real[c.target].clone()) };
    let ctrl_prev = compile_ctrl(&owner_pk, &pin, &prev);

    /* agent accounting successor for a (token_spend, kas_spend) advance */
    let advance = |token_spend: i64, kas_spend: i64| -> S {
        let mut new_start = claim.period_start_daa;
        let mut new_tok = claim.token_spent + token_spend;
        let mut new_kas = claim.kas_spent + kas_spend;
        if c.periods_elapsed >= 1 {
            new_start = claim.period_start_daa + c.periods_elapsed * claim.period_length_daa;
            new_tok = token_spend;
            new_kas = kas_spend;
        }
        let new_leaf = agent_leaf(&Agent { period_start_daa: new_start, token_spent: new_tok, kas_spent: new_kas, ..claim.clone() });
        let new_root = c.new_root_override.unwrap_or(fold(new_leaf, &psibs, pbits));
        S {
            reserve: c.succ_reserve_override.unwrap_or(prev.reserve - c.reserve_consumed),
            agent_root: new_root,
            swap_root: c.new_swap_root_override.unwrap_or(prev.swap_root),
            nonce: prev.nonce + c.new_nonce_delta,
            paused: c.new_paused_override.unwrap_or(prev.paused),
            principal: prev.principal,
        }
    };

    let mut inputs: Vec<TransactionInput> = vec![];
    let mut entries: Vec<UtxoEntry> = vec![];
    let mut outputs: Vec<TransactionOutput> = vec![];
    let mut sigscripts: Vec<Option<Vec<u8>>> = vec![]; // per input, None = signed later (controller / fuel)
    let mut pool_redeem_len = 0usize;
    let ctrl_call_args: Vec<Expr<'static>>;
    let ctrl_function: &str;
    let mut fuel_input_idx: Option<usize> = None;

    match c.op {
        Op::Sell | Op::Buy => {
            let sell = c.op == Op::Sell;
            /* token conservation */
            let self_after = if sell { OUR_TOKENS - c.amount_in } else { OUR_TOKENS + c.tokens_out } + c.self_amount_delta;
            let pool_note_after = if sell { POOL_TOKENS + c.amount_in } else { POOL_TOKENS - c.tokens_out };
            let pool_note_prev = compile_kcc20(h32(c.pool_id_carried), IDENTIFIER_COVENANT_ID, POOL_TOKENS, false, 2);
            let our_next = compile_kcc20(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, self_after, false, 2);
            let pool_note_next = compile_kcc20(h32(c.pool_id_carried), IDENTIFIER_COVENANT_ID, pool_note_after, false, 2);
            /* pool */
            let pool_src = if c.alien_pool_template { alien_pool_source() } else { pool_source() };
            let pool_prev = compile_pool(pool_src, c.token_id_carried, &tpl, pool_fee_pk, POOL_KAS, POOL_TOKENS, 0);
            let new_pool_kas = if sell { NEW_POOL_KAS_SELL } else { POOL_KAS + KAS_IN } + c.pool_kas_delta;
            let pool_next = compile_pool(pool_src, c.token_id_carried, &tpl, pool_fee_pk, new_pool_kas, pool_note_after, 1);
            pool_redeem_len = pool_prev.script.len();
            /* KAS accounting */
            let proto_fee = if sell { PROTO_FEE_SELL } else { PROTO_FEE_BUY } + c.proto_fee_delta;
            let kas_out = POOL_KAS - new_pool_kas; // sell: > 0; buy: negative
            let net = if sell { kas_out - proto_fee } else { 0 };
            let kas_spend = if sell { 0 } else { (new_pool_kas - POOL_KAS) + proto_fee };
            let mut new_state = advance(if sell { c.amount_in } else { 0 }, if sell { 0 } else { kas_spend });
            new_state.principal = if sell && !type_b { prev.principal + net } else if sell { prev.principal } else { prev.principal - kas_spend } + c.principal_delta;
            let ctrl_next = compile_ctrl(&owner_pk, &pin, &new_state);
            let succ_value = new_state.reserve + new_state.principal + c.succ_value_delta;
            let proceeds_pk = if c.proceeds_to_attacker { attacker_pk } else { honest_recipient };
            let fee_pk_used = if c.proto_fee_to_attacker { attacker_pk } else { pool_fee_pk };

            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(cov_out(OUR_NOTE_KAS + c.our_note_kas_delta, &our_next, 1, c.token_id_carried));
            outputs.push(cov_out(POOL_NOTE_KAS, &pool_note_next, 1, c.token_id_carried));
            outputs.push(cov_out(new_pool_kas, &pool_next, 3, c.pool_id_carried));
            outputs.push(p2pk_out(&fee_pk_used, proto_fee));
            let proceeds_idx: i64 = if type_b {
                outputs.push(p2pk_out(&proceeds_pk, net + c.proceeds_delta));
                5
            } else {
                if c.extra_proceeds_output_on_type_a {
                    outputs.push(p2pk_out(&proceeds_pk, 1));
                }
                0
            };
            if c.hidden_extra_output {
                outputs.push(p2pk_out(&attacker_pk, 1));
            }
            if c.swap_out_order_flip {
                outputs.swap(1, 2); // pool's reserve note becomes token-family output 0
            }

            /* inputs: 0 controller, 1/2 token notes (leader first), 3 pool, [4 alien] */
            inputs.push(input(1, vec![], budget(0)));
            entries.push(cov_utxo(prev.reserve + prev.principal, &ctrl_prev, COV_CTRL));
            sigscripts.push(None);
            let self_state = (h32(COV_CTRL), self_after);
            let pool_state_note = (h32(c.pool_id_carried), pool_note_after);
            let family_new_states: Vec<Expr> = vec![
                kcc20_state(self_state.0, IDENTIFIER_COVENANT_ID, self_state.1, false),
                kcc20_state(pool_state_note.0, IDENTIFIER_COVENANT_ID, pool_state_note.1, false),
            ];
            let (leader, leader_utxo, delegate, delegate_utxo, witnesses) = if c.pool_note_first {
                (&pool_note_prev, cov_utxo(POOL_NOTE_KAS, &pool_note_prev, c.token_id_carried), &our_prev, cov_utxo(OUR_NOTE_KAS, &our_prev, c.token_id_carried), vec![3u8, 0u8])
            } else {
                (&our_prev, cov_utxo(OUR_NOTE_KAS, &our_prev, c.token_id_carried), &pool_note_prev, cov_utxo(POOL_NOTE_KAS, &pool_note_prev, c.token_id_carried), vec![0u8, 3u8])
            };
            inputs.push(input(2, vec![], budget(1)));
            entries.push(leader_utxo);
            sigscripts.push(Some(cov_call(leader, "transfer", vec![family_new_states.into(), Vec::<Expr>::new().into(), Expr::bytes(witnesses)], true)));
            inputs.push(input(3, vec![], budget(2)));
            entries.push(delegate_utxo);
            sigscripts.push(Some(cov_call(delegate, "transfer", vec![], false)));
            inputs.push(input(4, vec![], budget(3)));
            entries.push(cov_utxo(POOL_KAS, &pool_prev, c.pool_id_carried));
            let pool_fn = if sell { "sellSwap" } else { "buySwap" };
            let pool_amount = if sell { c.amount_in } else { new_pool_kas - POOL_KAS };
            sigscripts.push(Some(cov_call(
                &pool_prev,
                pool_fn,
                vec![
                    pool_state(new_pool_kas, pool_note_after, 1),
                    Expr::int(pool_amount),
                    Expr::int(1), // pool's reserve continuation = token family output index 1
                    Expr::int(4), // protocol fee output
                    kcc20_state(pool_state_note.0, IDENTIFIER_COVENANT_ID, pool_state_note.1, false),
                ],
                true,
            )));
            if c.extra_plain_input {
                fuel_input_idx = Some(inputs.len());
                inputs.push(input(6, vec![], budget(4)));
                entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
                sigscripts.push(None);
            }
            if c.hidden_covenant_input {
                let alien = compile_kcc20(attacker_pk, IDENTIFIER_PUBKEY, 1, false, 2);
                inputs.push(input(5, vec![], budget(4)));
                entries.push(cov_utxo(1, &alien, COV_ALIEN));
                sigscripts.push(Some(cov_call(&alien, "transfer", vec![Vec::<Expr>::new().into(), Vec::<Expr>::new().into(), Expr::bytes(vec![])], true)));
            }

            let mut args = if c.swap_claim_structs_flip {
                vec![
                    state_arg(&new_state),
                    kcc20_state(pool_state_note.0, IDENTIFIER_COVENANT_ID, pool_state_note.1, false),
                    kcc20_state(self_state.0, IDENTIFIER_COVENANT_ID, self_state.1, false),
                ]
            } else {
                vec![
                    state_arg(&new_state),
                    kcc20_state(self_state.0, IDENTIFIER_COVENANT_ID, self_state.1, false),
                    kcc20_state(pool_state_note.0, IDENTIFIER_COVENANT_ID, pool_state_note.1, false),
                ]
            };
            args.extend(agent_args(&claim));
            args.push(Expr::bytes(psibs.clone()));
            args.push(Expr::int(pbits as i64));
            args.push(Expr::int(c.periods_elapsed));
            args.extend(swap_args(&swap_claim));
            args.push(Expr::bytes(ssibs.clone()));
            args.push(Expr::int(sbits as i64));
            let fee_idx_arg = c.fee_out_idx_override.unwrap_or(4);
            if sell {
                args.push(Expr::int(c.amount_in));
                args.push(Expr::int(c.min_kas_out));
                args.push(Expr::int(c.proceeds_out_idx_override.unwrap_or(proceeds_idx)));
                args.push(Expr::int(fee_idx_arg));
                ctrl_function = "tokenAtomicSell";
            } else {
                args.push(Expr::int(c.tokens_out));
                args.push(Expr::int(c.max_kas_in));
                args.push(Expr::int(fee_idx_arg));
                ctrl_function = "tokenAtomicBuy";
            }
            args.push(Expr::bytes(vec![])); // signature placeholder
            ctrl_call_args = args;
        }
        Op::Spend => {
            let spend = c.spend;
            let self_after = PREV_TOKEN_AMOUNT - spend + c.self_amount_delta;
            let tok_self = compile_kcc20(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, self_after, false, 2);
            let tok_recipient = compile_kcc20(recipient_pk, IDENTIFIER_PUBKEY, spend, false, 2);
            let mut new_state = advance(spend, 0);
            new_state.principal += c.principal_delta;
            let ctrl_next = compile_ctrl(&owner_pk, &pin, &new_state);
            let self_carry = TOKEN_CARRY - c.recipient_carry;
            let change = FUEL - (c.fee - c.reserve_consumed);
            let succ_value = new_state.reserve + new_state.principal + c.succ_value_delta;

            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(cov_out(self_carry, &tok_self, 1, COV_TOKEN));
            outputs.push(cov_out(c.recipient_carry, &tok_recipient, 1, COV_TOKEN));
            outputs.push(p2pk_out(&fuel_pk, change));

            inputs.push(input(1, vec![], budget(0)));
            entries.push(cov_utxo(prev.reserve + prev.principal, &ctrl_prev, COV_CTRL));
            sigscripts.push(None);
            inputs.push(input(2, vec![], budget(1)));
            entries.push(cov_utxo(TOKEN_CARRY, &our_prev, COV_TOKEN));
            sigscripts.push(Some(cov_call(
                &our_prev,
                "transfer",
                vec![
                    vec![kcc20_state(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, self_after, false), kcc20_state(recipient_pk, IDENTIFIER_PUBKEY, spend, false)].into(),
                    Vec::<Expr>::new().into(),
                    Expr::bytes(vec![0u8]),
                ],
                true,
            )));
            inputs.push(input(3, vec![], budget(2)));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            sigscripts.push(None);
            fuel_input_idx = Some(2);
            if c.second_ctrl_input {
                let j = inputs.len();
                inputs.push(input(9, vec![], budget(3)));
                entries.push(cov_utxo(2 * KAS, &ctrl_prev, COV_CTRL));
                sigscripts.push(Some(vec![])); // never reached: the controller assertion refuses first
                if c.second_ctrl_output {
                    // a SECOND covenant continuation output carrying our covenant id,
                    // authorized by the second controller input (not by input 0)
                    outputs.push(cov_out(2 * KAS, &ctrl_next, j as u16, COV_CTRL));
                }
            }
            if c.spend_extra_plain_output > 0 {
                outputs.push(p2pk_out(&attacker_pk, c.spend_extra_plain_output));
            }
            if c.spend_with_pool_inputs {
                /* the approved pool rides a v0.5-shaped spend: must be refused (no foreign covenant inputs) */
                let pool_prev = compile_pool(pool_source(), COV_TOKEN, &tpl, pool_fee_pk, POOL_KAS, POOL_TOKENS, 0);
                let pool_next = compile_pool(pool_source(), COV_TOKEN, &tpl, pool_fee_pk, POOL_KAS, POOL_TOKENS, 1);
                inputs.push(input(4, vec![], budget(3)));
                entries.push(cov_utxo(POOL_KAS, &pool_prev, COV_POOL));
                sigscripts.push(Some(vec![])); // never executed by the controller assertion
                outputs.push(cov_out(POOL_KAS, &pool_next, 3, COV_POOL));
            }

            let mut args = vec![
                state_arg(&new_state),
                kcc20_state(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, self_after, false),
                kcc20_state(recipient_pk, IDENTIFIER_PUBKEY, spend, false),
            ];
            args.extend(agent_args(&claim));
            args.push(Expr::bytes(psibs.clone()));
            args.push(Expr::int(pbits as i64));
            args.push(Expr::int(c.periods_elapsed));
            args.push(Expr::bytes(recipient_pk.to_vec()));
            args.push(Expr::bytes(rsibs.clone()));
            args.push(Expr::int(rbits as i64));
            args.push(Expr::bytes(vec![]));
            ctrl_function = "tokenAgentSpend";
            ctrl_call_args = args;
        }
        Op::Owner(sel) => {
            let new_state = c.owner_new.clone().unwrap_or(prev.clone());
            let ctrl_next = compile_ctrl(&owner_pk, &pin, &new_state);
            let succ_value = new_state.reserve + new_state.principal + c.succ_value_delta;
            let funded = (new_state.reserve - prev.reserve).max(0) + (new_state.principal - prev.principal).max(0);
            let change = FUEL - c.fee - funded;
            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(p2pk_out(&fuel_pk, change));
            inputs.push(input(1, vec![], budget(0)));
            entries.push(cov_utxo(prev.reserve + prev.principal, &ctrl_prev, COV_CTRL));
            sigscripts.push(None);
            inputs.push(input(3, vec![], budget(2)));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            sigscripts.push(None);
            fuel_input_idx = Some(1);
            if c.owner_tokens_ride {
                let tok_out = compile_kcc20(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false, 2);
                inputs.push(input(2, vec![], budget(1)));
                entries.push(cov_utxo(TOKEN_CARRY, &our_prev, COV_TOKEN));
                outputs.push(cov_out(TOKEN_CARRY, &tok_out, 2, COV_TOKEN));
                sigscripts.push(Some(cov_call(
                    &our_prev,
                    "transfer",
                    vec![vec![kcc20_state(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false)].into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])],
                    true,
                )));
            }
            if c.owner_pool_rider {
                let pool_prev = compile_pool(pool_source(), COV_TOKEN, &tpl, pool_fee_pk, POOL_KAS, POOL_TOKENS, 0);
                inputs.push(input(4, vec![], budget(3)));
                entries.push(cov_utxo(POOL_KAS, &pool_prev, COV_POOL));
                outputs.push(cov_out(POOL_KAS, &pool_prev, 2, COV_POOL));
                sigscripts.push(Some(vec![]));
            }
            ctrl_function = "ownerControl";
            ctrl_call_args = vec![state_arg(&new_state), Expr::int(sel), Expr::bytes(vec![])];
        }
        Op::Recover => {
            let payout = c.recover_payout_override.unwrap_or(prev.reserve + prev.principal);
            outputs.push(p2pk_out(&owner_pk, payout));
            inputs.push(input(1, vec![], budget(0)));
            entries.push(cov_utxo(prev.reserve + prev.principal, &ctrl_prev, COV_CTRL));
            sigscripts.push(None);
            let rec_owner = if c.recover_recipient_to_attacker { attacker_pk } else { owner_pk };
            let rec_type = if c.recover_recipient_type_covenant { IDENTIFIER_COVENANT_ID } else { IDENTIFIER_PUBKEY };
            let rec_amount = PREV_TOKEN_AMOUNT + c.recover_recipient_amount_delta;
            if !c.recover_no_position {
                let tok_out = compile_kcc20(rec_owner, rec_type, rec_amount, false, 2);
                inputs.push(input(2, vec![], budget(1)));
                entries.push(cov_utxo(TOKEN_CARRY, &our_prev, COV_TOKEN));
                outputs.push(cov_out(TOKEN_CARRY, &tok_out, 1, COV_TOKEN));
                sigscripts.push(Some(cov_call(
                    &our_prev,
                    "transfer",
                    vec![vec![kcc20_state(rec_owner, rec_type, rec_amount, false)].into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])],
                    true,
                )));
            }
            if c.recover_two_token_inputs {
                let second = compile_kcc20(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, 11, false, 2);
                inputs.push(input(8, vec![], budget(3)));
                entries.push(cov_utxo(TOKEN_CARRY, &second, COV_TOKEN));
                sigscripts.push(Some(vec![]));
            }
            let change = FUEL - c.fee;
            fuel_input_idx = Some(inputs.len());
            inputs.push(input(3, vec![], budget(2)));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            sigscripts.push(None);
            outputs.push(p2pk_out(&fuel_pk, change));
            ctrl_function = "ownerRecover";
            ctrl_call_args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(vec![]), kcc20_state(rec_owner, rec_type, rec_amount, false)];
        }
    }

    /* --- sign (budgets + all outputs are fixed now) --- */
    let unsigned = Transaction::new(1, inputs.clone(), outputs.clone(), c.lock_time, SubnetworkId::default(), 0, vec![]);
    let hash_type = match c.sig_mode {
        SigMode::All => SIG_HASH_ALL,
        SigMode::SingleAnyoneCanPay => SigHashType::from_u8(SIG_HASH_SINGLE.to_u8() | SIG_HASH_ANY_ONE_CAN_PAY.to_u8()).expect("allowed type"),
        SigMode::None => SIG_HASH_NONE,
    };
    let ctrl_sig = sign_type(&unsigned, &entries, 0, &signer, hash_type);
    let fuel_sig = fuel_input_idx.map(|i| sign(&unsigned, &entries, i, &fuel));
    if c.mutate_output_after_sign {
        let last = outputs.len() - 1;
        outputs[last].value += 1;
    }

    let mut args = ctrl_call_args;
    match c.op {
        Op::Spend | Op::Sell | Op::Buy => {
            let last = args.len() - 1;
            args[last] = Expr::bytes(ctrl_sig);
        }
        Op::Owner(_) => args[2] = Expr::bytes(ctrl_sig),
        Op::Recover => args[1] = Expr::bytes(ctrl_sig),
    }
    let ctrl_sigscript = cov_call(&ctrl_prev, ctrl_function, args, false);

    let mut signed_inputs = inputs.clone();
    for (i, inp) in signed_inputs.iter_mut().enumerate() {
        if i == 0 {
            inp.signature_script = ctrl_sigscript.clone();
        } else if Some(i) == fuel_input_idx {
            inp.signature_script = p2pk_sigscript(fuel_sig.clone().expect("fuel sig"));
        } else {
            inp.signature_script = sigscripts[i].clone().expect("sigscript");
        }
    }
    let tx = Transaction::new(1, signed_inputs, outputs, c.lock_time, SubnetworkId::default(), 0, vec![]);
    Built { tx, entries, ctrl_redeem_len: ctrl_prev.script.len(), pool_redeem_len }
}

/// Execute every input; returns (controller result, other inputs' results).
fn run(c: &Scen) -> (Result<(), TxScriptError>, Vec<Result<(), TxScriptError>>) {
    let b = build(c);
    let mut others = vec![];
    let ctrl = execute_input_measured(b.tx.clone(), b.entries.clone(), 0).0;
    for i in 1..b.tx.inputs.len() {
        others.push(execute_input_measured(b.tx.clone(), b.entries.clone(), i).0);
    }
    (ctrl, others)
}
fn assert_accepts_all(label: &str, c: &Scen) {
    let (ctrl, others) = run(c);
    ctrl.unwrap_or_else(|e| panic!("{label}: controller must ACCEPT: {e:?}"));
    for (i, r) in others.iter().enumerate() {
        r.as_ref().unwrap_or_else(|e| panic!("{label}: input {} must ACCEPT: {e:?}", i + 1));
    }
}
fn assert_ctrl_refuses(label: &str, c: &Scen) {
    let (ctrl, _) = run(c);
    assert!(ctrl.is_err(), "{label}: the v0.6 controller must REFUSE, but it accepted");
}
fn sell_type_b() -> Scen {
    let mut s = honest(Op::Sell);
    s.swap_target = 1;
    s
}

/* ---------------------------------------------------------------- */
/* honest paths                                                       */
/* ---------------------------------------------------------------- */

/* ================================================================ */
/* ADVERSARIAL REVIEW PROBES                                         */
/* Every probe drives the REAL TxScriptEngine. `refuse` records the  */
/* exact engine error; `accept_ctrl` asserts the CONTROLLER accepted */
/* (other inputs may legitimately refuse on their own rules).        */
/* ================================================================ */

fn refuse(label: &str, c: &Scen) -> String {
    let (ctrl, _) = run(c);
    match ctrl {
        Ok(()) => panic!("ADV-CONFIRMED: `{label}` was ACCEPTED by the v0.6 controller (expected refusal)"),
        Err(e) => {
            let s = format!("{e:?}");
            println!("REFUTED  {label}  ->  {s}");
            s
        }
    }
}
fn accept_ctrl(label: &str, c: &Scen) {
    let (ctrl, _) = run(c);
    ctrl.unwrap_or_else(|e| panic!("{label}: controller must ACCEPT: {e:?}"));
    println!("ACCEPTED {label}");
}
fn report_ctrl(label: &str, c: &Scen) -> bool {
    let (ctrl, _) = run(c);
    match ctrl {
        Ok(()) => {
            println!("ACCEPTED {label}");
            true
        }
        Err(e) => {
            println!("REFUSED  {label}  ->  {e:?}");
            false
        }
    }
}

/// leaf set identical to build()'s default, so probes can substitute one leaf
fn base_leaf_set() -> Vec<SwapLeaf> {
    let (_o, _a, recipient, _f, _other, pool_fee, _at) = keys();
    let our_prev = compile_kcc20(h32(COV_CTRL), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
    let tpl = template_of(&our_prev);
    let honest_pool = compile_pool(pool_source(), COV_TOKEN, &tpl, xonly(&pool_fee), POOL_KAS, POOL_TOKENS, 0);
    let pool_tpl = template_of(&honest_pool);
    let leaf_a = SwapLeaf {
        profile_hash: PROFILE_HASH,
        pool_id: COV_POOL,
        pool_hash: pool_tpl.hash,
        pool_prefix_len: pool_tpl.prefix.len() as i64,
        pool_suffix_len: pool_tpl.suffix.len() as i64,
        fee_pk: xonly(&pool_fee),
        max_proto_fee: MAX_PROTO_FEE,
        sell_floor: SELL_FLOOR,
        buy_ceil: BUY_CEIL,
        direction_mask: 3,
        dest_scheme: IDENTIFIER_COVENANT_ID,
        dest_identity: ZERO32,
    };
    let leaf_b = SwapLeaf { direction_mask: 1, dest_scheme: IDENTIFIER_PUBKEY, dest_identity: xonly(&recipient), ..leaf_a.clone() };
    let leaf_c = SwapLeaf { direction_mask: 2, ..leaf_a.clone() };
    let leaf_d = SwapLeaf { direction_mask: 3, ..leaf_b.clone() };
    vec![leaf_a, leaf_b, leaf_c, leaf_d]
}
/// replace leaf 0 (the honest type-A both-directions leaf) and target it
fn with_leaf0(mut s: Scen, f: impl FnOnce(SwapLeaf) -> SwapLeaf) -> Scen {
    let mut set = base_leaf_set();
    set[0] = f(set[0].clone());
    s.swap_leaves_override = Some(set);
    s.swap_target = 0;
    s
}

/* ---------------------------------------------------------------- */
/* H1 — agent-chosen output indices (feeOutIdx / proceedsOutIdx)      */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h1_fee_out_idx_misdirection() {
    // type-A SELL has 5 outputs: 0..3 covenant, 4 = the plain protocol fee.
    for idx in [0i64, 1, 2, 3] {
        let mut s = honest(Op::Sell);
        s.fee_out_idx_override = Some(idx);
        refuse(&format!("SELL feeOutIdx -> covenant output {idx}"), &s);
        let mut b = honest(Op::Buy);
        b.fee_out_idx_override = Some(idx);
        refuse(&format!("BUY  feeOutIdx -> covenant output {idx}"), &b);
    }
    for idx in [-1i64, 5, 8, 2147483647] {
        let mut s = honest(Op::Sell);
        s.fee_out_idx_override = Some(idx);
        refuse(&format!("SELL feeOutIdx out of range {idx}"), &s);
        let mut b = honest(Op::Buy);
        b.fee_out_idx_override = Some(idx);
        refuse(&format!("BUY  feeOutIdx out of range {idx}"), &b);
    }
}

#[test]
fn adv_h1b_type_b_fee_and_proceeds_index_confusion() {
    // type-B SELL has 6 outputs: 0..3 covenant, 4 = protocol fee, 5 = proceeds.
    let mut alias = sell_type_b();
    alias.fee_out_idx_override = Some(5);
    alias.proceeds_out_idx_override = Some(5);
    refuse("type-B SELL feeOutIdx == proceedsOutIdx (5,5)", &alias);

    let mut alias4 = sell_type_b();
    alias4.fee_out_idx_override = Some(4);
    alias4.proceeds_out_idx_override = Some(4);
    refuse("type-B SELL feeOutIdx == proceedsOutIdx (4,4)", &alias4);

    let mut swapped = sell_type_b();
    swapped.fee_out_idx_override = Some(5); // the proceeds output claimed as the protocol fee
    swapped.proceeds_out_idx_override = Some(4); // the fee output claimed as the proceeds
    refuse("type-B SELL fee/proceeds roles swapped", &swapped);

    for idx in [0i64, 1, 2, 3] {
        let mut s = sell_type_b();
        s.proceeds_out_idx_override = Some(idx);
        refuse(&format!("type-B SELL proceedsOutIdx -> covenant output {idx}"), &s);
    }
    let mut oob = sell_type_b();
    oob.proceeds_out_idx_override = Some(-1);
    refuse("type-B SELL proceedsOutIdx negative", &oob);
}

#[test]
fn adv_h1c_type_a_proceeds_idx_must_name_the_successor() {
    for idx in [1i64, 2, 3, 4] {
        let mut s = honest(Op::Sell);
        s.proceeds_out_idx_override = Some(idx);
        refuse(&format!("type-A SELL proceedsOutIdx {idx} != auth output"), &s);
    }
}

/* ---------------------------------------------------------------- */
/* H2 — period clock manipulation                                     */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h2_period_rollover_requires_the_clock() {
    // honest leaf: periodStartDaa 5000, periodLengthDaa 1000 -> newStart 6000
    for (lt, label) in [(0u64, "lockTime 0"), (5999, "lockTime 5999 (one short)"), (5000, "lockTime = old start")] {
        let mut s = honest(Op::Sell);
        s.agents[0].token_spent = TOKEN_BUDGET;
        s.periods_elapsed = 1;
        s.lock_time = lt;
        refuse(&format!("SELL claims a rollover with {label}"), &s);
        let mut b = honest(Op::Buy);
        b.agents[0].kas_spent = KAS_BUDGET;
        b.periods_elapsed = 1;
        b.lock_time = lt;
        refuse(&format!("BUY  claims a rollover with {label}"), &b);
    }
    // periodsElapsed above the covenant bound
    let mut over = honest(Op::Sell);
    over.periods_elapsed = 1001;
    over.lock_time = 5000 + 1001 * 1000;
    refuse("SELL periodsElapsed 1001 (> bound 1000)", &over);
    // negative periodsElapsed
    let mut neg = honest(Op::Sell);
    neg.periods_elapsed = -1;
    refuse("SELL periodsElapsed -1", &neg);
    // exactly the bound, with the clock honestly satisfied -> legitimate
    let mut ok = honest(Op::Sell);
    ok.agents[0].token_spent = TOKEN_BUDGET;
    ok.periods_elapsed = 1000;
    ok.lock_time = 5000 + 1000 * 1000;
    accept_ctrl("SELL periodsElapsed exactly 1000 with lockTime >= newStart", &ok);
}

#[test]
fn adv_h2b_zero_period_length_disables_both_budgets() {
    // HYPOTHESIS: an owner-signed agent leaf with periodLengthDaa == 0 makes
    // newStart == periodStartDaa for ANY periodsElapsed >= 1, so `tx.time >=
    // newStart` is satisfied by the ORIGINAL start and BOTH spent counters
    // reset on every transaction, with the successor leaf carrying the SAME
    // periodStartDaa -> the period budgets never bind again.
    let mut s = honest(Op::Sell);
    s.agents[0].period_length_daa = 0;
    s.agents[0].token_spent = TOKEN_BUDGET; // budget already fully consumed
    s.agents[0].kas_spent = KAS_BUDGET;
    s.periods_elapsed = 1;
    s.lock_time = 5000; // == the ORIGINAL periodStartDaa; no time has passed
    let sell_accepted = report_ctrl("SELL with periodLengthDaa == 0, budget already exhausted, periodsElapsed 1", &s);

    let mut b = honest(Op::Buy);
    b.agents[0].period_length_daa = 0;
    b.agents[0].token_spent = TOKEN_BUDGET;
    b.agents[0].kas_spent = KAS_BUDGET;
    b.periods_elapsed = 1;
    b.lock_time = 5000;
    let buy_accepted = report_ctrl("BUY  with periodLengthDaa == 0, budget already exhausted, periodsElapsed 1", &b);

    let mut p = honest(Op::Spend);
    p.agents[0].period_length_daa = 0;
    p.agents[0].token_spent = TOKEN_BUDGET;
    p.periods_elapsed = 1;
    p.lock_time = 5000;
    let spend_accepted = report_ctrl("SPEND with periodLengthDaa == 0, budget already exhausted, periodsElapsed 1", &p);

    println!("ADV-H2B RESULT: sell={sell_accepted} buy={buy_accepted} spend={spend_accepted}");
    // Recorded as evidence either way; the covenant carries no `periodLengthDaa > 0` require.
    assert_eq!(
        (sell_accepted, buy_accepted, spend_accepted),
        (true, true, true),
        "ADV-H2B: record the engine's actual verdict"
    );
}

/* ---------------------------------------------------------------- */
/* H3 — Merkle co-path malleability (agent + recipient trees)         */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h3_agent_merkle_path_malleability() {
    for (m, label, depth) in [
        (SibMut::ExtraHighBit, "pathBits with a bit above the co-path depth", 4u32),
        (SibMut::NotMultipleOf32, "co-path length not a multiple of 32", 4),
        (SibMut::TooLong, "co-path 416 bytes (depth 13 > 12)", 12),
        (SibMut::DuplicateSibling, "sibling 1 replaced by a duplicate of sibling 0", 4),
        (SibMut::TruncateOneLevel, "co-path truncated by one level", 4),
    ] {
        for op in [Op::Sell, Op::Buy, Op::Spend] {
            let mut s = honest(op);
            s.agent_depth = Some(depth);
            s.agent_sib_mut = m;
            refuse(&format!("{label} ({:?})", match op { Op::Sell => "sell", Op::Buy => "buy", _ => "spend" }), &s);
        }
    }
}

#[test]
fn adv_h3b_recipient_merkle_path_malleability() {
    for (m, label, depth) in [
        (SibMut::ExtraHighBit, "recipient pathBits above depth", 4u32),
        (SibMut::NotMultipleOf32, "recipient co-path not a multiple of 32", 4),
        (SibMut::TooLong, "recipient co-path 544 bytes (depth 17 > 16)", 16),
        (SibMut::DuplicateSibling, "recipient duplicate sibling", 4),
        (SibMut::TruncateOneLevel, "recipient co-path truncated", 4),
    ] {
        let mut s = honest(Op::Spend);
        s.recip_depth = depth;
        s.recip_sib_mut = m;
        refuse(label, &s);
    }
}

/* ---------------------------------------------------------------- */
/* H4 — token-family OUTPUT ordering                                  */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h4_token_family_output_order_swap() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.swap_out_order_flip = true;
        refuse("token-family outputs swapped (pool's reserve note at family index 0)", &s);
        let mut t = honest(op);
        t.swap_out_order_flip = true;
        t.swap_claim_structs_flip = true;
        refuse("token-family outputs AND claimed states both swapped", &t);
        let mut u = honest(op);
        u.swap_claim_structs_flip = true;
        refuse("claimed selfNew/poolNoteNew swapped only", &u);
    }
    // the same flip while the pool's note is the family LEADER input
    let mut p = honest(Op::Sell);
    p.pool_note_first = true;
    p.swap_out_order_flip = true;
    refuse("outputs swapped with the pool note as family leader input", &p);
}

/* ---------------------------------------------------------------- */
/* H5 — swap-policy leaf field abuse (destScheme / directionMask)     */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h5_dest_scheme_and_direction_mask_edges() {
    for scheme in [0x01u8, 0x03, 0xff] {
        let s = with_leaf0(honest(Op::Sell), |l| SwapLeaf { dest_scheme: scheme, ..l });
        refuse(&format!("SELL under a committed leaf with destScheme 0x{scheme:02x}"), &s);
        let b = with_leaf0(honest(Op::Buy), |l| SwapLeaf { dest_scheme: scheme, ..l });
        refuse(&format!("BUY  under a committed leaf with destScheme 0x{scheme:02x}"), &b);
    }
    // type-A scheme (0x02) but a NON-ZERO destIdentity committed by the owner
    let (_o, _a, recipient, _f, _other, _pf, _at) = keys();
    let s = with_leaf0(honest(Op::Sell), |l| SwapLeaf { dest_identity: xonly(&recipient), ..l });
    refuse("SELL type-A leaf with a non-zero destIdentity", &s);
    let b = with_leaf0(honest(Op::Buy), |l| SwapLeaf { dest_identity: xonly(&recipient), ..l });
    refuse("BUY type-A leaf with a non-zero destIdentity", &b);

    for mask in [0i64, 4, 5, 6, -1] {
        let s = with_leaf0(honest(Op::Sell), |l| SwapLeaf { direction_mask: mask, ..l });
        refuse(&format!("SELL under directionMask {mask}"), &s);
        let b = with_leaf0(honest(Op::Buy), |l| SwapLeaf { direction_mask: mask, ..l });
        refuse(&format!("BUY  under directionMask {mask}"), &b);
    }
}

/* ---------------------------------------------------------------- */
/* H6 — integer boundaries on the swap amounts                        */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h6_zero_and_negative_swap_amounts() {
    for v in [0i64, -1] {
        let mut s = honest(Op::Sell);
        s.amount_in = v;
        refuse(&format!("SELL amountIn {v}"), &s);
        let mut b = honest(Op::Buy);
        b.tokens_out = v;
        refuse(&format!("BUY tokensOut {v}"), &b);
    }
    let mut m = honest(Op::Sell);
    m.min_kas_out = 0;
    refuse("SELL minKasOut 0", &m);
    let mut mn = honest(Op::Sell);
    mn.min_kas_out = -1;
    refuse("SELL minKasOut -1", &mn);
    let mut k = honest(Op::Buy);
    k.max_kas_in = 0;
    refuse("BUY maxKasIn 0", &k);
    let mut kn = honest(Op::Buy);
    kn.max_kas_in = -1;
    refuse("BUY maxKasIn -1", &kn);
    let mut z = honest(Op::Spend);
    z.spend = 0;
    refuse("SPEND amount 0", &z);
}

#[test]
fn adv_h6b_protocol_fee_boundaries() {
    // exactly at the owner's cap -> the controller accepts (the fixture pool
    // computes its own fee and refuses; only the controller is asserted)
    let mut at_cap = honest(Op::Sell);
    at_cap.proto_fee_delta = MAX_PROTO_FEE - PROTO_FEE_SELL;
    accept_ctrl("SELL protocol fee EXACTLY maxProtocolFeeKas", &at_cap);
    let mut over = honest(Op::Sell);
    over.proto_fee_delta = MAX_PROTO_FEE - PROTO_FEE_SELL + 1;
    refuse("SELL protocol fee maxProtocolFeeKas + 1", &over);
    // negative protocol fee output value is unrepresentable on-chain; the
    // covenant's own >= 0 guard is exercised through a large owner cap:
    let mut eat = with_leaf0(honest(Op::Sell), |l| SwapLeaf { max_proto_fee: 10_000_000, ..l });
    eat.proto_fee_delta = KAS_OUT - PROTO_FEE_SELL; // protoFee == kasOut, netProceeds == 0
    refuse("SELL protocol fee == the pool's entire KAS decrease", &eat);
    let mut most = with_leaf0(honest(Op::Sell), |l| SwapLeaf { max_proto_fee: 10_000_000, ..l });
    most.proto_fee_delta = KAS_OUT - PROTO_FEE_SELL - 1; // netProceeds == 1
    most.min_kas_out = 1;
    refuse("SELL protocol fee absorbing all but 1 sompi (below the owner floor)", &most);
}

#[test]
fn adv_h6c_exact_boundary_accepts() {
    // token cap at exact equality
    let mut cap = honest(Op::Sell);
    cap.agents[0].token_cap = AMOUNT_IN;
    accept_ctrl("SELL amountIn == tokenMaxPerSpend", &cap);
    let mut bud = honest(Op::Sell);
    bud.agents[0].token_spent = TOKEN_BUDGET - AMOUNT_IN;
    accept_ctrl("SELL newTokenSpent == tokenPeriodBudget", &bud);
    // KAS cap / budget at exact equality
    let mut kc = honest(Op::Buy);
    kc.agents[0].kas_cap = KAS_SPEND;
    accept_ctrl("BUY kasSpend == kasMaxPerSwap", &kc);
    let mut kb = honest(Op::Buy);
    kb.agents[0].kas_spent = KAS_BUDGET - KAS_SPEND;
    accept_ctrl("BUY newKasSpent == kasPeriodBudget", &kb);
    // fee reserve exactly at the agent cap, and drained to exactly zero
    let mut fr = honest(Op::Sell);
    fr.reserve_consumed = AGENT_MAX_FEE;
    accept_ctrl("SELL reserveConsumed == agentMaxFeePerTx == the exact fee", &fr);
    let mut drain = honest(Op::Sell);
    drain.prev.reserve = AGENT_MAX_FEE;
    drain.reserve_consumed = AGENT_MAX_FEE;
    accept_ctrl("SELL fee reserve drained to exactly 0", &drain);
    // BUY principal to exactly zero
    let mut pz = honest(Op::Buy);
    pz.prev.principal = KAS_SPEND;
    accept_ctrl("BUY principal to exactly 0", &pz);
    // SELL type A from a zero principal
    let mut sz = honest(Op::Sell);
    sz.prev.principal = 0;
    accept_ctrl("SELL type A accruing onto a zero principal", &sz);
    // zero reserve consumption
    let mut zr = honest(Op::Sell);
    zr.reserve_consumed = 0;
    accept_ctrl("SELL consuming zero fee reserve", &zr);
}

/* ---------------------------------------------------------------- */
/* H7 — a second CONTROLLER input / output                            */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h7_second_controller_utxo() {
    let mut s = honest(Op::Spend);
    s.second_ctrl_input = true;
    refuse("tokenAgentSpend with a SECOND controller (same covenant id) input", &s);

    let mut d = honest(Op::Spend);
    d.second_ctrl_input = true;
    d.second_ctrl_output = true;
    refuse("second controller input + its own second controller continuation output", &d);
}

/* ---------------------------------------------------------------- */
/* H8 — fee-reserve diversion on the v0.5-shaped spend                */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h8_reserve_cannot_fund_an_extra_output_on_spend() {
    // reserveConsumed 50,000 with a nominal fee of 100,000: an extra plain
    // output larger than 50,000 makes the EXACT fee smaller than the reserve
    // consumption -> refused.
    let mut ok = honest(Op::Spend);
    ok.spend_extra_plain_output = 40_000; // exact fee 60,000 >= 50,000 (funded by the plain input's change)
    accept_ctrl("SPEND with an extra plain output funded by the plain input", &ok);
    let mut bad = honest(Op::Spend);
    bad.spend_extra_plain_output = 60_000; // exact fee 40,000 < reserveConsumed 50,000
    refuse("SPEND routing fee-reserve value into an attacker output", &bad);
    let mut edge = honest(Op::Spend);
    edge.spend_extra_plain_output = 50_000; // exact fee == reserveConsumed exactly
    accept_ctrl("SPEND with the exact fee equal to the reserve consumption", &edge);
    let mut edge1 = honest(Op::Spend);
    edge1.spend_extra_plain_output = 50_001; // exact fee one sompi short
    refuse("SPEND with the exact fee one sompi below the reserve consumption", &edge1);
}

/* ---------------------------------------------------------------- */
/* H9 — ownerControl selector bounds                                  */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h9_owner_control_selector_bounds() {
    for sel in [6i64, 7, -1, 2147483647] {
        let mut s = honest(Op::Owner(sel));
        s.owner_new = Some(resolved_prev(&s));
        refuse(&format!("ownerControl opSelector {sel}"), &s);
    }
    // pause when already paused / unpause when not paused
    let mut p = honest(Op::Owner(2));
    p.prev.paused = 1;
    let mut np = resolved_prev(&p);
    np.paused = 1;
    p.owner_new = Some(np);
    refuse("ownerControl pause while already paused", &p);
    let mut u = honest(Op::Owner(3));
    let mut nu = resolved_prev(&u);
    nu.paused = 0;
    u.owner_new = Some(nu);
    refuse("ownerControl unpause while not paused", &u);
    // setAgentRoot must not move the swap root, and vice versa
    let mut a = honest(Op::Owner(0));
    let mut na = resolved_prev(&a);
    na.agent_root = [0x11; 32];
    na.swap_root = [0x22; 32];
    na.nonce += 1;
    a.owner_new = Some(na);
    refuse("ownerControl setAgentRoot also replacing swapRoot", &a);
    let mut w = honest(Op::Owner(4));
    let mut nw = resolved_prev(&w);
    nw.swap_root = [0x22; 32];
    nw.agent_root = [0x11; 32];
    nw.nonce += 1;
    w.owner_new = Some(nw);
    refuse("ownerControl setSwapRoot also replacing agentRoot", &w);
    // setAgentRoot without the nonce bump
    let mut n = honest(Op::Owner(0));
    let mut nn = resolved_prev(&n);
    nn.agent_root = [0x11; 32];
    n.owner_new = Some(nn);
    refuse("ownerControl setAgentRoot without a nonce bump", &n);
    // topUpReserve that does not actually increase the reserve
    let mut t = honest(Op::Owner(1));
    t.owner_new = Some(resolved_prev(&t));
    refuse("ownerControl topUpReserve with an unchanged reserve", &t);
    // fundSwapPrincipal that does not actually increase the principal
    let mut f = honest(Op::Owner(5));
    f.owner_new = Some(resolved_prev(&f));
    refuse("ownerControl fundSwapPrincipal with an unchanged principal", &f);
}

/* ---------------------------------------------------------------- */
/* H10 — ownerRecover                                                 */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h10_owner_recover_edges() {
    let mut over = honest(Op::Recover);
    over.recover_payout_override = Some(RESERVE + PRINCIPAL + 1);
    refuse("ownerRecover overpaying output 0 by 1", &over);

    for d in [1i64, -1] {
        let mut s = honest(Op::Recover);
        s.recover_recipient_amount_delta = d;
        refuse(&format!("ownerRecover with the token payout off by {d}"), &s);
    }
    let mut atk = honest(Op::Recover);
    atk.recover_recipient_to_attacker = true;
    refuse("ownerRecover paying the token position to a non-owner key", &atk);

    let mut ty = honest(Op::Recover);
    ty.recover_recipient_type_covenant = true;
    refuse("ownerRecover with a covenant-typed token payout", &ty);

    let mut two = honest(Op::Recover);
    two.recover_two_token_inputs = true;
    refuse("ownerRecover with TWO token-family inputs", &two);
}

/* ---------------------------------------------------------------- */
/* H11 — swap-policy proof binding                                    */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h11_swap_leaf_substitution_within_the_same_tree() {
    // claim leaf 1's contents while proving leaf 0's co-path (and vice versa)
    let set = base_leaf_set();
    let mut s = honest(Op::Sell);
    s.swap_target = 0;
    s.swap_claim_override = Some(set[1].clone());
    refuse("SELL claiming leaf 1 with leaf 0's co-path", &s);
    let mut t = honest(Op::Sell);
    t.swap_target = 1;
    t.swap_claim_override = Some(set[0].clone());
    refuse("SELL claiming leaf 0 with leaf 1's co-path", &t);
    // an owner-committed leaf with a LOOSER protocol-fee cap, proved at the
    // wrong index
    let mut u = honest(Op::Buy);
    u.swap_target = 2;
    u.swap_claim_override = Some(set[0].clone());
    refuse("BUY claiming leaf 0 with leaf 2's co-path", &u);
}

/* ---------------------------------------------------------------- */
/* H12 — pool identity aliasing in the owner leaf                     */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h12_pool_id_aliasing() {
    // an owner leaf naming the TOKEN family as the pool
    let s = with_leaf0(honest(Op::Sell), |l| SwapLeaf { pool_id: COV_TOKEN, ..l });
    refuse("SELL under a leaf whose poolCovenantId == tokenCovenantId", &s);
    // an owner leaf naming the CONTROLLER itself as the pool
    let c = with_leaf0(honest(Op::Sell), |l| SwapLeaf { pool_id: COV_CTRL, ..l });
    refuse("SELL under a leaf whose poolCovenantId == the controller's own id", &c);
    // an owner leaf naming the zero covenant id (i.e. plain inputs) as the pool
    let z = with_leaf0(honest(Op::Sell), |l| SwapLeaf { pool_id: Hash::from_bytes(ZERO32), ..l });
    refuse("SELL under a leaf whose poolCovenantId is the zero hash", &z);
}

/* ---------------------------------------------------------------- */
/* H13 — pool template geometry confusion                             */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h13_pool_template_geometry_confusion() {
    let base = base_leaf_set();
    let honest_prefix = base[0].pool_prefix_len;
    let honest_suffix = base[0].pool_suffix_len;
    for (dp, ds, label) in [
        (1i64, -1i64, "prefix +1 / suffix -1 (same total length)"),
        (-1, 1, "prefix -1 / suffix +1 (same total length)"),
        (0, 1, "suffix +1"),
        (1, 0, "prefix +1"),
        (-honest_prefix, 0, "prefix 0"),
    ] {
        let s = with_leaf0(honest(Op::Sell), |l| SwapLeaf { pool_prefix_len: honest_prefix + dp, pool_suffix_len: honest_suffix + ds, ..l });
        refuse(&format!("SELL under a leaf with pool geometry {label}"), &s);
    }
}

/// The `prev` state build() actually resolves for a scenario (roots included).
fn resolved_prev(c: &Scen) -> S {
    let (_o, _a, recipient, _f, _other, _pf, _at) = keys();
    let leaf_set: Vec<SwapLeaf> = c.swap_leaves_override.clone().unwrap_or_else(base_leaf_set);
    let swap_leaves: Vec<[u8; 32]> = leaf_set.iter().map(swap_leaf).collect();
    let swap_leaves = match c.swap_depth {
        Some(d) => padded(swap_leaves, d),
        None => swap_leaves,
    };
    let (swap_root, _, _) = merkle(&swap_leaves, c.swap_target);
    let (rroot, _, _) = recip_tree(c.recip_depth, &xonly(&recipient));
    let mut real = c.agents.clone();
    real[c.target].recipient_root = rroot;
    let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let leaves = match c.agent_depth {
        Some(d) => padded(leaves, d),
        None => leaves,
    };
    let (root, _, _) = merkle(&leaves, c.target);
    S { agent_root: root, swap_root: c.swap_root_override.unwrap_or(swap_root), ..c.prev.clone() }
}

/* ---------------------------------------------------------------- */
/* H14 — confirming controls for the periodLengthDaa == 0 finding     */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h14_zero_period_length_controls() {
    // (a) WITHOUT the claimed rollover the exhausted budget still binds:
    //     the reset itself is the mechanism, not a mis-set counter.
    let mut c = honest(Op::Sell);
    c.agents[0].period_length_daa = 0;
    c.agents[0].token_spent = TOKEN_BUDGET;
    c.periods_elapsed = 0;
    refuse("periodLengthDaa == 0, budget exhausted, periodsElapsed 0 (control)", &c);

    // (b) any periodsElapsed in [1,1000] produces the SAME newStart when the
    //     period length is zero, so the clock gate is vacuous.
    for pe in [1i64, 2, 1000] {
        let mut s = honest(Op::Sell);
        s.agents[0].period_length_daa = 0;
        s.agents[0].token_spent = TOKEN_BUDGET;
        s.agents[0].kas_spent = KAS_BUDGET;
        s.periods_elapsed = pe;
        s.lock_time = 5000;
        accept_ctrl(&format!("periodLengthDaa == 0, periodsElapsed {pe}, lockTime == the ORIGINAL start"), &s);
    }

    // (c) the successor leaf carries the SAME periodStartDaa, so the identical
    //     reset is available again on the very next transaction (unbounded).
    let mut s = honest(Op::Sell);
    s.agents[0].period_length_daa = 0;
    s.agents[0].token_spent = TOKEN_BUDGET;
    s.agents[0].kas_spent = KAS_BUDGET;
    s.periods_elapsed = 1;
    s.lock_time = 5000;
    let claim = Agent { token_spent: TOKEN_BUDGET, kas_spent: KAS_BUDGET, period_length_daa: 0, ..s.agents[0].clone() };
    let successor_leaf = Agent { period_start_daa: claim.period_start_daa, token_spent: AMOUNT_IN, kas_spent: 0, ..claim.clone() };
    assert_eq!(successor_leaf.period_start_daa, 5000, "the successor leaf keeps the ORIGINAL periodStartDaa");
    println!("ADV-H14c: successor leaf periodStartDaa {} (unchanged) tokenPeriodSpent {}", successor_leaf.period_start_daa, successor_leaf.token_spent);

    // (d) a POSITIVE period length is what makes the gate bind: same shape,
    //     periodLengthDaa 1, lockTime one short of the new start -> refused.
    let mut d = honest(Op::Sell);
    d.agents[0].period_length_daa = 1;
    d.agents[0].token_spent = TOKEN_BUDGET;
    d.periods_elapsed = 1;
    d.lock_time = 5000; // newStart 5001
    refuse("periodLengthDaa == 1, lockTime one below the new start (control)", &d);
}

/* ---------------------------------------------------------------- */
/* H15 — fee-reserve griefing rate (bounded per tx, no period cap)    */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h15_minimum_swap_burns_the_full_per_tx_fee_allowance() {
    // one atomic token unit given up, the FULL agentMaxFeePerTx consumed from
    // the reserve as real network fee: the per-transaction bound is enforced,
    // but nothing caps the number of such transactions within a period.
    let mut s = honest(Op::Sell);
    s.amount_in = 1;
    s.min_kas_out = 1;
    s.reserve_consumed = AGENT_MAX_FEE;
    accept_ctrl("SELL of 1 atomic unit consuming the FULL agentMaxFeePerTx", &s);
    let mut over = honest(Op::Sell);
    over.amount_in = 1;
    over.min_kas_out = 1;
    over.reserve_consumed = AGENT_MAX_FEE + 1;
    refuse("SELL of 1 atomic unit consuming agentMaxFeePerTx + 1", &over);
}

/* ---------------------------------------------------------------- */
/* H16 — protocol-fee output script class                             */
/* ---------------------------------------------------------------- */

#[test]
fn adv_h16_protocol_fee_must_be_exact_p2pk() {
    // a P2SH output paying the same key material is not the pinned P2PK class
    let mut s = honest(Op::Sell);
    let b = build(&s);
    // sanity: the honest fee output is P2PK and the honest shape accepts
    assert_eq!(ScriptClass::from_script(&b.tx.outputs[4].script_public_key), ScriptClass::PubKey);
    accept_ctrl("honest SELL (P2PK protocol fee)", &s);
    // wrong key -> refused (covered) ; wrong CLASS is unreachable through the
    // harness knobs, recorded as structurally enforced by ScriptPubKeyP2PK.
    s.proto_fee_to_attacker = true;
    refuse("SELL protocol fee P2PK to a non-profile key", &s);
}
