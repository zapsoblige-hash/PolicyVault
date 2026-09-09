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
    let swap_leaves = vec![swap_leaf(&leaf_a), swap_leaf(&leaf_b), swap_leaf(&leaf_c), swap_leaf(&leaf_d)];
    let swap_leaves = match c.swap_depth {
        Some(d) => padded(swap_leaves, d),
        None => swap_leaves,
    };
    let (swap_root, ssibs, sbits) = merkle(&swap_leaves, c.swap_target);
    let swap_claim = c.swap_claim_override.clone().unwrap_or(match c.swap_target {
        0 => leaf_a.clone(),
        1 => leaf_b.clone(),
        2 => leaf_c.clone(),
        _ => leaf_d.clone(),
    });
    let type_b = swap_claim.dest_scheme == IDENTIFIER_PUBKEY;

    /* --- recipient tree + agent tree (real committed roots) --- */
    let (rroot, rsibs, rbits) = recip_tree(c.recip_depth, &honest_recipient);
    let mut real = c.agents.clone();
    real[c.target].recipient_root = rroot;
    let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let leaves = match c.agent_depth {
        Some(d) => padded(leaves, d),
        None => leaves,
    };
    let (root, psibs, pbits) = merkle(&leaves, c.target);
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

            let mut args = vec![
                state_arg(&new_state),
                kcc20_state(self_state.0, IDENTIFIER_COVENANT_ID, self_state.1, false),
                kcc20_state(pool_state_note.0, IDENTIFIER_COVENANT_ID, pool_state_note.1, false),
            ];
            args.extend(agent_args(&claim));
            args.push(Expr::bytes(psibs.clone()));
            args.push(Expr::int(pbits as i64));
            args.push(Expr::int(c.periods_elapsed));
            args.extend(swap_args(&swap_claim));
            args.push(Expr::bytes(ssibs.clone()));
            args.push(Expr::int(sbits as i64));
            if sell {
                args.push(Expr::int(c.amount_in));
                args.push(Expr::int(c.min_kas_out));
                args.push(Expr::int(proceeds_idx));
                args.push(Expr::int(4));
                ctrl_function = "tokenAtomicSell";
            } else {
                args.push(Expr::int(c.tokens_out));
                args.push(Expr::int(c.max_kas_in));
                args.push(Expr::int(4));
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
            if !c.recover_no_position {
                let tok_out = compile_kcc20(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false, 2);
                inputs.push(input(2, vec![], budget(1)));
                entries.push(cov_utxo(TOKEN_CARRY, &our_prev, COV_TOKEN));
                outputs.push(cov_out(TOKEN_CARRY, &tok_out, 1, COV_TOKEN));
                sigscripts.push(Some(cov_call(
                    &our_prev,
                    "transfer",
                    vec![vec![kcc20_state(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false)].into(), Vec::<Expr>::new().into(), Expr::bytes(vec![0u8])],
                    true,
                )));
            }
            let change = FUEL - c.fee;
            fuel_input_idx = Some(inputs.len());
            inputs.push(input(3, vec![], budget(2)));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            sigscripts.push(None);
            outputs.push(p2pk_out(&fuel_pk, change));
            ctrl_function = "ownerRecover";
            ctrl_call_args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(vec![]), kcc20_state(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false)];
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

#[test]
fn v6_honest_atomic_sell_type_a_principal_accrual() {
    assert_accepts_all("sell type A", &honest(Op::Sell));
}
#[test]
fn v6_honest_atomic_sell_type_b_allowlisted_p2pk() {
    assert_accepts_all("sell type B", &sell_type_b());
}
#[test]
fn v6_honest_atomic_buy_from_principal() {
    assert_accepts_all("buy", &honest(Op::Buy));
}
#[test]
fn v6_honest_swaps_accept_when_pool_note_precedes_ours() {
    let mut s = honest(Op::Sell);
    s.pool_note_first = true;
    assert_accepts_all("sell pool-note-first", &s);
    let mut b = honest(Op::Buy);
    b.pool_note_first = true;
    assert_accepts_all("buy pool-note-first", &b);
}
#[test]
fn v6_honest_swaps_at_production_tree_depths() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.agent_depth = Some(12);
        s.swap_depth = Some(12);
        assert_accepts_all("swap at agent depth 12 + swap depth 12", &s);
    }
}
#[test]
fn v6_honest_swap_period_rollover_resets_both_counters() {
    let mut s = honest(Op::Sell);
    s.agents[0].token_spent = TOKEN_BUDGET; // exhausted in the old period
    s.agents[0].kas_spent = KAS_BUDGET;
    s.periods_elapsed = 1;
    s.lock_time = 6000;
    assert_accepts_all("sell after rollover", &s);
    let mut b = honest(Op::Buy);
    b.agents[0].token_spent = TOKEN_BUDGET;
    b.agents[0].kas_spent = KAS_BUDGET;
    b.periods_elapsed = 1;
    b.lock_time = 6000;
    assert_accepts_all("buy after rollover", &b);
}
#[test]
fn v6_honest_token_agent_spend_v5_shape() {
    assert_accepts_all("spend", &honest(Op::Spend));
    let mut d = honest(Op::Spend);
    d.agent_depth = Some(12);
    d.recip_depth = 16;
    assert_accepts_all("spend at depths 12/16", &d);
}
#[test]
fn v6_honest_owner_control_all_six_selectors() {
    for (sel, label) in [(0, "setAgentRoot"), (1, "topUpReserve"), (2, "pause"), (3, "unpause"), (4, "setSwapRoot"), (5, "fundSwapPrincipal")] {
        let mut s = honest(Op::Owner(sel));
        if sel == 3 {
            s.prev.paused = 1;
        }
        s.owner_new = Some(owner_successor(&s, sel));
        assert_accepts_all(label, &s);
    }
}
/// The successor an honest owner op produces (roots resolved exactly as build() resolves them).
fn owner_successor(s: &Scen, sel: i64) -> S {
    let prev = resolved_prev(s);
    match sel {
        0 => S { agent_root: [0x11; 32], nonce: prev.nonce + 1, ..prev },
        1 => S { reserve: prev.reserve + KAS / 2, ..prev },
        2 => S { paused: 1, ..prev },
        3 => S { paused: 0, ..prev },
        4 => S { swap_root: [0x22; 32], nonce: prev.nonce + 1, ..prev },
        _ => S { principal: prev.principal + KAS / 2, ..prev },
    }
}
fn resolved_prev(c: &Scen) -> S {
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
    let (swap_root, _, _) = merkle(&[swap_leaf(&leaf_a), swap_leaf(&leaf_b), swap_leaf(&leaf_c), swap_leaf(&leaf_d)], 0);
    let (rroot, _, _) = recip_tree(c.recip_depth, &xonly(&recipient));
    let mut real = c.agents.clone();
    real[c.target].recipient_root = rroot;
    let leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let (root, _, _) = merkle(&leaves, c.target);
    S { agent_root: root, swap_root, ..c.prev.clone() }
}
#[test]
fn v6_honest_owner_recover_returns_reserve_plus_principal() {
    assert_accepts_all("recover with position", &honest(Op::Recover));
    let mut n = honest(Op::Recover);
    n.recover_no_position = true;
    assert_accepts_all("recover without position", &n);
}

/* ---------------------------------------------------------------- */
/* hostile matrix — swaps (both directions where meaningful)          */
/* ---------------------------------------------------------------- */

#[test]
fn v6_rejects_wrong_venue_unapproved_pool_family() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.pool_id_carried = COV_WRONG;
        assert_ctrl_refuses("unapproved pool family", &s);
    }
}
#[test]
fn v6_rejects_wrong_pool_template_version() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.alien_pool_template = true;
        assert_ctrl_refuses("alien pool template", &s);
    }
}
#[test]
fn v6_rejects_wrong_input_asset_family_pair_substitution() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.token_id_carried = COV_WRONG;
        assert_ctrl_refuses("pair substitution", &s);
    }
}
#[test]
fn v6_rejects_sell_over_token_cap_and_budget() {
    let mut s = honest(Op::Sell);
    s.amount_in = TOKEN_CAP + 1;
    assert_ctrl_refuses("sell above tokenMaxPerSpend", &s);
    let mut b = honest(Op::Sell);
    b.agents[0].token_spent = TOKEN_BUDGET - AMOUNT_IN + 1;
    assert_ctrl_refuses("sell exhausts the token period budget", &b);
}
#[test]
fn v6_rejects_buy_over_kas_cap_and_budget() {
    let mut s = honest(Op::Buy);
    s.agents[0].kas_cap = KAS_SPEND - 1;
    assert_ctrl_refuses("buy consideration above kasMaxPerSwap", &s);
    let mut b = honest(Op::Buy);
    b.agents[0].kas_spent = KAS_BUDGET - KAS_SPEND + 1;
    assert_ctrl_refuses("buy exhausts the KAS period budget", &b);
    let mut z = honest(Op::Buy);
    z.agents[0].kas_cap = 0; // an agent with no BUY authority at all
    assert_ctrl_refuses("agent without KAS swap authority", &z);
}
#[test]
fn v6_rejects_sell_proceeds_below_min_or_floor() {
    let mut s = honest(Op::Sell);
    s.min_kas_out = NET_PROCEEDS + 1;
    assert_ctrl_refuses("net proceeds below minKasOut", &s);
    /* the committed floor is 90/1; a floor violation = a worse price: the pool gives less KAS
     * (pool_kas_delta > 0 keeps the pool's own invariant satisfied; the trader simply gets less) */
    let mut f = honest(Op::Sell);
    f.pool_kas_delta = 3_000; // kasOut 44,437; net 44,342 < 500 × 90 = 45,000
    f.min_kas_out = 44_000;
    assert_ctrl_refuses("net proceeds below the owner floor price", &f);
}
fn swap_leaf_a_for(_s: &Scen) -> SwapLeaf {
    SwapLeaf {
        profile_hash: PROFILE_HASH,
        pool_id: COV_POOL,
        pool_hash: ZERO32,
        pool_prefix_len: 0,
        pool_suffix_len: 0,
        fee_pk: ZERO32,
        max_proto_fee: MAX_PROTO_FEE,
        sell_floor: SELL_FLOOR,
        buy_ceil: BUY_CEIL,
        direction_mask: 3,
        dest_scheme: IDENTIFIER_COVENANT_ID,
        dest_identity: ZERO32,
    }
}
#[test]
fn v6_rejects_buy_above_max_kas_in_or_ceiling() {
    let mut s = honest(Op::Buy);
    s.max_kas_in = KAS_SPEND - 1;
    assert_ctrl_refuses("consideration above maxKasIn", &s);
    let mut c = honest(Op::Buy);
    c.pool_kas_delta = 3_000; // pay 44,793 for 400 tokens: 44,877 > 400 × 110 = 44,000
    c.max_kas_in = 45_000;
    assert_ctrl_refuses("consideration above the owner ceiling price", &c);
}
#[test]
fn v6_rejects_direction_not_allowed_by_the_leaf() {
    let mut s = honest(Op::Buy);
    s.swap_target = 1; // type-B SELL-only leaf used for a BUY
    assert_ctrl_refuses("BUY under a SELL-only leaf", &s);
    let mut t = honest(Op::Sell);
    t.swap_target = 2; // BUY-only leaf used for a SELL
    assert_ctrl_refuses("SELL under a BUY-only leaf", &t);
}
#[test]
fn v6_rejects_type_b_destination_on_buy() {
    let mut s = honest(Op::Buy);
    s.swap_target = 3; // a COMMITTED type-B leaf that allows both directions: the buy must refuse the destination type
    assert_ctrl_refuses("type-B destination on a buy", &s);
    let mut ok = honest(Op::Sell);
    ok.swap_target = 3;
    assert_accepts_all("type-B sell under the both-directions type-B leaf", &ok);
}
#[test]
fn v6_rejects_type_a_sell_with_a_proceeds_output() {
    let mut s = honest(Op::Sell);
    s.extra_proceeds_output_on_type_a = true;
    assert_ctrl_refuses("type-A sell carrying an extra plain output", &s);
}
#[test]
fn v6_rejects_type_b_redirected_or_inexact_proceeds() {
    let mut s = sell_type_b();
    s.proceeds_to_attacker = true;
    assert_ctrl_refuses("type-B proceeds to a non-allowlisted key", &s);
    let mut short = sell_type_b();
    short.proceeds_delta = -1;
    assert_ctrl_refuses("type-B proceeds short-paid by 1", &short);
    let mut over = sell_type_b();
    over.proceeds_delta = 1;
    assert_ctrl_refuses("type-B proceeds over-paid by 1 (value leaves the fee reserve)", &over);
}
#[test]
fn v6_rejects_hidden_extra_output() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.hidden_extra_output = true;
        assert_ctrl_refuses("hidden extra plain output", &s);
    }
    let mut b = sell_type_b();
    b.hidden_extra_output = true;
    assert_ctrl_refuses("hidden extra plain output (type B)", &b);
}
#[test]
fn v6_rejects_external_plain_kas_input_on_swaps() {
    // Addendum C (2026-09-03): the candidate admits NO external non-covenant KAS
    // input on a swap — the exact input count (4) is pinned in-covenant, so an
    // external input can satisfy no authority check, fund nothing, mask nothing.
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.extra_plain_input = true;
        assert_ctrl_refuses("external plain KAS input riding a swap", &s);
    }
    let mut b = sell_type_b();
    b.extra_plain_input = true;
    assert_ctrl_refuses("external plain KAS input riding a type-B sell", &b);
}
#[test]
fn v6_rejects_hidden_covenant_input() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.hidden_covenant_input = true;
        assert_ctrl_refuses("hidden third covenant family input", &s);
    }
}
#[test]
fn v6_rejects_token_conservation_break() {
    for op in [Op::Sell, Op::Buy] {
        for d in [1, -1] {
            let mut s = honest(op);
            s.self_amount_delta = d;
            assert_ctrl_refuses("token conservation ±1", &s);
        }
    }
}
#[test]
fn v6_rejects_kas_leak_from_our_token_note() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.our_note_kas_delta = -1;
        assert_ctrl_refuses("KAS leak from the vault's token note", &s);
    }
}
#[test]
fn v6_rejects_malformed_successor_value() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        for d in [1, -1] {
            let mut s = honest(op);
            s.succ_value_delta = d;
            assert_ctrl_refuses("successor output value != feeReserve + swapPrincipal", &s);
        }
    }
}
#[test]
fn v6_rejects_reserve_consumption_above_agent_cap() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        let mut s = honest(op);
        s.reserve_consumed = AGENT_MAX_FEE + 1;
        s.fee = AGENT_MAX_FEE + 1 + 50_000;
        assert_ctrl_refuses("reserve consumed above agentMaxFeePerTx", &s);
    }
}
#[test]
fn v6_rejects_reserve_consumption_above_the_exact_fee() {
    // the reserve may only become NETWORK FEE: routing one sompi of it into our
    // token note's KAS carry makes reserveConsumed exceed the exact fee -> refused
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.our_note_kas_delta = 1;
        assert_ctrl_refuses("fee reserve converted into token-note backing", &s);
    }
}
#[test]
fn v6_rejects_principal_tamper() {
    for d in [1, -1] {
        let mut s = honest(Op::Sell);
        s.principal_delta = d;
        assert_ctrl_refuses("type-A sell principal != prev + net proceeds", &s);
        let mut b = honest(Op::Buy);
        b.principal_delta = d;
        assert_ctrl_refuses("buy principal != prev - consideration", &b);
        let mut t = sell_type_b();
        t.principal_delta = d;
        assert_ctrl_refuses("type-B sell principal must be preserved", &t);
        let mut p = honest(Op::Spend);
        p.principal_delta = d;
        assert_ctrl_refuses("spend principal must be preserved", &p);
    }
}
#[test]
fn v6_rejects_buy_principal_exhaustion() {
    // a principal one sompi short: the only representable successor (principal 0)
    // violates the exact consideration equation -> refused (a negative declared
    // principal is refused by the covenant's >= 0 check and cannot even be compiled)
    let mut s = honest(Op::Buy);
    s.prev.principal = KAS_SPEND - 1;
    s.principal_delta = 1;
    assert_ctrl_refuses("buy consideration exceeds the protected principal", &s);
}
#[test]
fn v6_rejects_unauthorized_state_mutation_in_successor() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        let mut a = honest(op);
        a.new_root_override = Some([0x99; 32]);
        assert_ctrl_refuses("agentRoot forged", &a);
        let mut w = honest(op);
        w.new_swap_root_override = Some([0x98; 32]);
        assert_ctrl_refuses("swapRoot mutated by an agent", &w);
        let mut n = honest(op);
        n.new_nonce_delta = 1;
        assert_ctrl_refuses("policyNonce mutated by an agent", &n);
        let mut p = honest(op);
        p.new_paused_override = Some(1);
        assert_ctrl_refuses("paused mutated by an agent", &p);
    }
}
#[test]
fn v6_rejects_paused_controller() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        let mut s = honest(op);
        s.prev.paused = 1;
        assert_ctrl_refuses("paused controller", &s);
    }
}
#[test]
fn v6_rejects_forged_or_stale_swap_policy() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        let mut leaf = SwapLeaf { pool_hash: ZERO32, ..swap_leaf_a_for(&s) };
        leaf.max_proto_fee = MAX_PROTO_FEE * 10; // a leaf the owner never approved, with the real co-path
        s.swap_claim_override = Some(leaf);
        assert_ctrl_refuses("forged swap leaf", &s);
        let mut stale = honest(op);
        stale.swap_root_override = Some([0x77; 32]); // live root differs from the proof's root
        assert_ctrl_refuses("stale swap proof / different live swapRoot", &stale);
    }
}
#[test]
fn v6_rejects_forged_agent_policy() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        let mut s = honest(op);
        let mut claim = s.agents[0].clone();
        claim.token_cap = 1_000_000;
        claim.kas_cap = 1_000_000_000;
        s.claim_override = Some(claim);
        assert_ctrl_refuses("forged agent leaf", &s);
    }
}
#[test]
fn v6_rejects_protocol_fee_above_bound_or_to_wrong_key() {
    for op in [Op::Sell, Op::Buy] {
        let mut s = honest(op);
        s.proto_fee_delta = MAX_PROTO_FEE; // above the owner's maxProtocolFeeKas
        assert_ctrl_refuses("protocol fee above the owner bound", &s);
        let mut k = honest(op);
        k.proto_fee_to_attacker = true;
        assert_ctrl_refuses("protocol fee output to a non-profile key", &k);
    }
}
#[test]
fn v6_rejects_non_all_sighash_and_post_sign_mutation() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        let mut s = honest(op);
        s.sig_mode = SigMode::SingleAnyoneCanPay;
        assert_ctrl_refuses("SIGHASH_SINGLE|ANYONECANPAY", &s);
        let mut n = honest(op);
        n.sig_mode = SigMode::None;
        assert_ctrl_refuses("SIGHASH_NONE", &n);
        let mut m = honest(op);
        m.mutate_output_after_sign = true;
        assert_ctrl_refuses("output mutated after signing", &m);
    }
}
#[test]
fn v6_rejects_wrong_signer() {
    for op in [Op::Sell, Op::Buy, Op::Spend] {
        let mut s = honest(op);
        s.signer_seed = 0x61; // owner key signs an agent entrypoint
        assert_ctrl_refuses("owner key on an agent entrypoint", &s);
        let mut a = honest(op);
        a.signer_seed = 0x67; // attacker
        assert_ctrl_refuses("attacker key", &a);
    }
}
#[test]
fn v6_pool_refuses_invariant_break_while_controller_envelope_holds() {
    let mut s = honest(Op::Sell);
    s.pool_kas_delta = -1_000; // pool pays 1,000 more than k allows
    s.min_kas_out = 48_000;
    let b = build(&s);
    assert!(execute_input_measured(b.tx.clone(), b.entries.clone(), 3).0.is_err(), "pool must refuse a sell invariant break");
    let mut t = honest(Op::Buy);
    t.pool_kas_delta = -1_000; // trader pays 1,000 less than k allows
    let b2 = build(&t);
    assert!(execute_input_measured(b2.tx.clone(), b2.entries.clone(), 3).0.is_err(), "pool must refuse a buy invariant break");
}
#[test]
fn v6_v5_shaped_spend_refuses_any_foreign_covenant_input() {
    let mut s = honest(Op::Spend);
    s.spend_with_pool_inputs = true;
    assert_ctrl_refuses("tokenAgentSpend with the approved pool present", &s);
}
#[test]
fn v6_owner_control_refuses_riders_and_cross_selector_mutations() {
    let mut r = honest(Op::Owner(2));
    r.owner_new = Some(owner_successor(&r, 2));
    r.owner_pool_rider = true;
    assert_ctrl_refuses("owner op with the approved pool riding", &r);
    let mut t = honest(Op::Owner(2));
    t.owner_new = Some(owner_successor(&t, 2));
    t.owner_tokens_ride = true;
    assert_ctrl_refuses("owner op moving tokens", &t);
    /* selector 5 (fund principal) must not touch the reserve; selector 1 must not touch the principal */
    let mut f = honest(Op::Owner(5));
    let mut n = owner_successor(&f, 5);
    n.reserve += 1;
    f.owner_new = Some(n);
    assert_ctrl_refuses("fundSwapPrincipal also raising the reserve", &f);
    let mut u = honest(Op::Owner(1));
    let mut n1 = owner_successor(&u, 1);
    n1.principal += 1;
    u.owner_new = Some(n1);
    assert_ctrl_refuses("topUpReserve also raising the principal", &u);
    /* principal can never DEcrease through ownerControl */
    let mut d = honest(Op::Owner(5));
    let mut nd = resolved_prev(&d);
    nd.principal -= 1;
    d.owner_new = Some(nd);
    assert_ctrl_refuses("fundSwapPrincipal decreasing the principal", &d);
    /* setSwapRoot must bump the nonce */
    let mut w = honest(Op::Owner(4));
    let mut nw = owner_successor(&w, 4);
    nw.nonce -= 1;
    w.owner_new = Some(nw);
    assert_ctrl_refuses("setSwapRoot without a nonce bump", &w);
    /* successor value must equal reserve + principal */
    let mut v = honest(Op::Owner(5));
    v.owner_new = Some(owner_successor(&v, 5));
    v.succ_value_delta = -1;
    assert_ctrl_refuses("owner successor value != reserve + principal", &v);
    /* wrong signer */
    let mut a = honest(Op::Owner(2));
    a.owner_new = Some(owner_successor(&a, 2));
    a.signer_seed = 0x62;
    assert_ctrl_refuses("agent key on ownerControl", &a);
}
#[test]
fn v6_owner_recover_refuses_partial_payout() {
    let mut s = honest(Op::Recover);
    s.recover_payout_override = Some(RESERVE); // forgets the principal
    assert_ctrl_refuses("recover paying out the reserve only", &s);
    let mut t = honest(Op::Recover);
    t.recover_payout_override = Some(RESERVE + PRINCIPAL - 1);
    assert_ctrl_refuses("recover short-paying by 1", &t);
}

/* ---------------------------------------------------------------- */
/* measurement + standardness                                         */
/* ---------------------------------------------------------------- */

#[test]
fn v6_measurement_units_mass_standardness() {
    let mc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    println!("V6 CANDIDATE measurement (real engine; budgets = covering priced units incl. sig-op pricing)");
    println!("shape | ctrl priced->budget | per-input budgets | ctrl_redeem pool_redeem ctrl_ss | tx_bytes compute transient fee_mass | sigops ctrl");
    let shapes: Vec<(&str, Scen)> = vec![
        ("spend", honest(Op::Spend)),
        ("spend@12/16", {
            let mut s = honest(Op::Spend);
            s.agent_depth = Some(12);
            s.recip_depth = 16;
            s
        }),
        ("sellA", honest(Op::Sell)),
        ("sellA@12/12", {
            let mut s = honest(Op::Sell);
            s.agent_depth = Some(12);
            s.swap_depth = Some(12);
            s
        }),
        ("sellB", sell_type_b()),
        ("buy", honest(Op::Buy)),
        ("buy@12/12", {
            let mut s = honest(Op::Buy);
            s.agent_depth = Some(12);
            s.swap_depth = Some(12);
            s
        }),
        ("owner5", {
            let mut s = honest(Op::Owner(5));
            s.owner_new = Some(owner_successor(&s, 5));
            s
        }),
        ("recover", honest(Op::Recover)),
    ];
    for (label, scen) in shapes {
        /* pass 1: priced units with placeholder budgets -> covering budgets; pass 2: rebuild (budgets are sighash-covered) */
        let p1 = build(&scen);
        let mut budgets = vec![];
        for i in 0..p1.tx.inputs.len() {
            let (r, priced) = execute_input_measured_priced(p1.tx.clone(), p1.entries.clone(), i, 1000);
            r.unwrap_or_else(|e| panic!("{label}: pass-1 input {i} must accept: {e:?}"));
            budgets.push(ComputeBudget::checked_covering_script_units(ScriptUnits(priced)).expect("budget").0);
        }
        let mut s2 = scen.clone();
        s2.budgets = budgets.clone();
        let b = build(&s2);
        let mut ctrl_priced = 0;
        for i in 0..b.tx.inputs.len() {
            let (r, priced) = execute_input_measured_priced(b.tx.clone(), b.entries.clone(), i, 1000);
            r.unwrap_or_else(|e| panic!("{label}: input {i} must accept with covering budgets {budgets:?}: {e:?}"));
            if i == 0 {
                ctrl_priced = priced;
            }
        }
        let masses = mc.calc_non_contextual_masses(&b.tx);
        let populated = PopulatedTransaction::new(&b.tx, b.entries.clone());
        let storage = mc.calc_contextual_masses(&populated);
        let size = transaction_estimated_serialized_size(&b.tx);
        let normalized_transient = (masses.transient_mass * 500_000).div_ceil(1_000_000);
        let fee_mass = masses.compute_mass.max(normalized_transient);
        let sig_ctrl = post_toccata_p2sh_sig_scanner(&b.tx.inputs[0].signature_script, &b.entries[0].script_public_key);
        println!("  {label} storage (contextual, at the VM's small note carries): {storage:?}");
        println!(
            "{label} | {ctrl_priced}->{} | {:?} | {} {} {} | {size} {} {} {fee_mass} | {sig_ctrl}",
            budgets[0],
            budgets,
            b.ctrl_redeem_len,
            b.pool_redeem_len,
            b.tx.inputs[0].signature_script.len(),
            masses.compute_mass,
            masses.transient_mass
        );
        /* standardness (rusty-kaspa mining/src/mempool/check_transaction_standard.rs):
         *  - static P2SH sig-ops per input <= 15;
         *  - every output script class standard (P2PK / P2SH);
         *  - post-Toccata per-transaction block-fit limits: compute <= 500,000, transient <= 1,000,000;
         *  - the PRE-Toccata standard cap (100,000 per dimension) is reported, never asserted:
         *    covenant transactions cannot exist on a pre-Toccata network. */
        for i in 0..b.tx.inputs.len() {
            let ops = post_toccata_p2sh_sig_scanner(&b.tx.inputs[i].signature_script, &b.entries[i].script_public_key);
            assert!(ops <= 15, "{label}: input {i} static sig-ops {ops} must be <= 15 (standard)");
        }
        for (i, o) in b.tx.outputs.iter().enumerate() {
            assert_ne!(ScriptClass::from_script(&o.script_public_key), ScriptClass::NonStandard, "{label}: output {i} must be a standard script class");
        }
        assert!(masses.compute_mass <= 500_000, "{label}: compute mass {} exceeds the post-Toccata block-fit limit", masses.compute_mass);
        assert!(masses.transient_mass <= 1_000_000, "{label}: transient mass {} exceeds the post-Toccata block-fit limit", masses.transient_mass);
        if masses.transient_mass > 100_000 || masses.compute_mass > 100_000 {
            println!("  note: {label} exceeds the PRE-Toccata 100,000 standard cap (transient {}, compute {}) — post-Toccata only", masses.transient_mass, masses.compute_mass);
        }
    }
}
