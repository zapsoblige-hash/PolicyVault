//! EXPERIMENT layer — HIERARCHICAL DELEGATION PROBE
//! (docs/postlaunch/hierarchical-delegation-design.md §4).
//!
//! `contracts/experiments/HDProbe.sil` driven through the REAL Kaspa
//! TxScriptEngine (covenants enabled, real Schnorr signatures, real KCC20
//! token side). This is an EXPERIMENT: no production covenant, no SDK, no
//! encoder integration. The frozen `contracts/PolicyVault.v0.5.sil` is read
//! ONLY as the baseline and is never modified.
//!
//! Three source variants are compiled from the one probe source by removing
//! whole marked entrypoint regions:
//!   L1  = level-1 spend only (the v0.5 shape with the HD leaf format)
//!   L2  = + childSpendL2 + delegateSetChildRoot1          (MAX_LEVEL 2)
//!   L3  = + childSpendL3 + delegateSetChildRoot2          (MAX_LEVEL 3)

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
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::{pay_to_script_hash_script, post_toccata_p2sh_sig_scanner, script_builder::ScriptBuilder, EngineFlags};
use kaspa_txscript_errors::TxScriptError;

const KAS: i64 = 100_000_000;
const IDENTIFIER_PUBKEY: u8 = 0x00;
const IDENTIFIER_COVENANT_ID: u8 = 0x02;
/// NEW hierarchical-delegation leaf domain tag (v0.5's is 0x50563501).
const HD_DOMAIN: [u8; 4] = [0x50, 0x56, 0x48, 0x01];
/// The FROZEN v0.5 token-agent leaf tag — used only to prove cross-format refusal.
const V5_DOMAIN: [u8; 4] = [0x50, 0x56, 0x35, 0x01];
const RECIP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];
const VAULT_ID: [u8; 32] = [0x44; 32];
const ALT_VAULT_ID: [u8; 32] = [0x45; 32];
const DESCRIPTOR_HASH: [u8; 32] = [0xd5; 32];

const COV_CTRL: Hash = Hash::from_bytes(*b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
const COV_TOKEN: Hash = Hash::from_bytes(*b"TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT");

/* KAS shape (sompi) */
const RESERVE: i64 = 5 * KAS;
const TOKEN_CARRY: i64 = 2 * KAS;
const FUEL: i64 = 1 * KAS;
const RECIPIENT_CARRY: i64 = KAS / 10;
const FEE: i64 = 100_000;
const RESERVE_CONSUMED: i64 = 30_000;
const PREV_TOKEN_AMOUNT: i64 = 3000;

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
/* token side (upstream KCC20 example) — identical to the v0.5 suite  */
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
/* HD leaf + delegation tree                                          */
/* ---------------------------------------------------------------- */

#[derive(Clone, Debug, PartialEq)]
struct HdLeaf {
    pk: [u8; 32],
    max_per_spend: i64,
    period_budget: i64,
    period_length_daa: i64,
    period_start_daa: i64,
    period_spent: i64,
    max_fee_per_tx: i64,
    max_carry_kas: i64,
    expiry_daa: i64,
    recipient_root: [u8; 32],
    child_root: [u8; 32],
    level: i64,
}

/// The canonical 160-byte HD leaf BODY carried as ONE covenant argument.
fn hd_leaf_body(l: &HdLeaf) -> Vec<u8> {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(&l.pk);
    for v in [
        l.max_per_spend,
        l.period_budget,
        l.period_length_daa,
        l.period_start_daa,
        l.period_spent,
        l.max_fee_per_tx,
        l.max_carry_kas,
        l.expiry_daa,
    ] {
        b.extend_from_slice(&num8(v));
    }
    b.extend_from_slice(&l.recipient_root);
    b.extend_from_slice(&l.child_root);
    assert_eq!(b.len(), 160);
    b
}

/// leaf hash = sha256(0x50564801 || body || num8(level) || 0x00) — 173 B.
fn hd_leaf_hash(l: &HdLeaf) -> [u8; 32] {
    sha256(&[&HD_DOMAIN, &hd_leaf_body(l), &num8(l.level), &[0x00]])
}

/// The FROZEN v0.5 token-agent leaf over the SAME policy fields — used to
/// prove that the two leaf formats can never be substituted for each other.
fn v5_leaf_hash(l: &HdLeaf) -> [u8; 32] {
    sha256(&[
        &V5_DOMAIN,
        &l.pk,
        &num8(l.max_per_spend),
        &num8(l.period_budget),
        &num8(l.period_length_daa),
        &num8(l.period_start_daa),
        &num8(l.period_spent),
        &num8(l.max_fee_per_tx),
        &num8(l.max_carry_kas),
        &l.recipient_root,
        &[0x00],
    ])
}

fn hd_leaf_arg(l: &HdLeaf) -> Expr<'static> {
    Expr::bytes(hd_leaf_body(l))
}

/// One node of the delegation tree. `l.child_root` is IGNORED and always
/// recomputed from `kids` (so the committed tree is always self-consistent).
#[derive(Clone)]
struct TNode {
    l: HdLeaf,
    kids: Vec<TNode>,
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

fn kids_root(n: &TNode) -> [u8; 32] {
    if n.kids.is_empty() {
        return ZERO32;
    }
    let leaves: Vec<[u8; 32]> = n.kids.iter().map(|k| hd_leaf_hash(&resolved(k))).collect();
    merkle(&leaves, 0).0
}
fn resolved(n: &TNode) -> HdLeaf {
    let mut l = n.l.clone();
    l.child_root = kids_root(n);
    l
}

/// The committed forest root (the vault's `agentRoot`).
fn forest_root(tree: &[TNode]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = tree.iter().map(|n| hd_leaf_hash(&resolved(n))).collect();
    merkle(&leaves, 0).0
}

/// Resolve the ancestor chain along `path`, returning per level the committed
/// leaf, its co-path siblings and path bits.
fn chain_proofs(tree: &[TNode], path: &[usize]) -> Vec<(HdLeaf, Vec<u8>, u64)> {
    let mut out = Vec::new();
    let leaves: Vec<[u8; 32]> = tree.iter().map(|n| hd_leaf_hash(&resolved(n))).collect();
    let (_root, sibs, bits) = merkle(&leaves, path[0]);
    let mut node = &tree[path[0]];
    out.push((resolved(node), sibs, bits));
    for step in &path[1..] {
        let leaves: Vec<[u8; 32]> = node.kids.iter().map(|k| hd_leaf_hash(&resolved(k))).collect();
        let (_r, sibs, bits) = merkle(&leaves, *step);
        node = &node.kids[*step];
        out.push((resolved(node), sibs, bits));
    }
    out
}

fn advance(l: &HdLeaf, spend: i64, periods_elapsed: i64) -> (i64, i64) {
    if periods_elapsed >= 1 {
        (l.period_start_daa + periods_elapsed * l.period_length_daa, spend)
    } else {
        (l.period_start_daa, l.period_spent + spend)
    }
}

/// The nested refold the covenant performs: bottom-up, every level's own
/// counters advanced and every level's childRoot replaced by the refolded
/// subtree below it.
fn nested_refold(chain: &[(HdLeaf, Vec<u8>, u64)], spend: i64, pe: &[i64]) -> [u8; 32] {
    let k = chain.len();
    let mut carried = chain[k - 1].0.child_root;
    for i in (0..k).rev() {
        let (l, sibs, bits) = &chain[i];
        let (ns, nsp) = advance(l, spend, pe[i]);
        let mut nl = l.clone();
        nl.period_start_daa = ns;
        nl.period_spent = nsp;
        nl.child_root = carried;
        carried = fold(hd_leaf_hash(&nl), sibs, *bits);
    }
    carried
}

/// Like `nested_refold` but leaves ONE level's counters unadvanced — the
/// "child spends without consuming the parent's budget" forgery.
fn nested_refold_skipping(chain: &[(HdLeaf, Vec<u8>, u64)], spend: i64, pe: &[i64], skip: usize) -> [u8; 32] {
    let k = chain.len();
    let mut carried = chain[k - 1].0.child_root;
    for i in (0..k).rev() {
        let (l, sibs, bits) = &chain[i];
        let mut nl = l.clone();
        if i != skip {
            let (ns, nsp) = advance(l, spend, pe[i]);
            nl.period_start_daa = ns;
            nl.period_spent = nsp;
        }
        nl.child_root = carried;
        carried = fold(hd_leaf_hash(&nl), sibs, *bits);
    }
    carried
}

fn recip_tree(depth: u32, target: &[u8; 32], salt: u64) -> ([u8; 32], Vec<u8>, u64) {
    if depth == 0 {
        return (sha256(&[&RECIP_DOMAIN, target]), vec![], 0);
    }
    let n = 1usize << depth;
    let mut leaves: Vec<[u8; 32]> =
        (0..n).map(|i| sha256(&[&RECIP_DOMAIN, &((i as u64) + 900 + salt * 1_000_000).to_le_bytes()])).collect();
    leaves[1] = sha256(&[&RECIP_DOMAIN, target]);
    merkle(&leaves, 1)
}

/* ---------------------------------------------------------------- */
/* controller source variants                                         */
/* ---------------------------------------------------------------- */

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Variant {
    L1,
    L2,
    L3,
}

fn probe_source_raw() -> String {
    let path = format!("{}/../../contracts/experiments/HDProbe.sil", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).expect("read HDProbe.sil")
}
fn frozen_v5_source() -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.5.sil", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).expect("read PolicyVault.v0.5.sil")
}
fn strip_region(s: &str, tag: &str) -> String {
    let b = format!("/* @{tag}-BEGIN */");
    let e = format!("/* @{tag}-END */");
    let i = s.find(&b).unwrap_or_else(|| panic!("missing {b}"));
    let j = s.find(&e).unwrap_or_else(|| panic!("missing {e}")) + e.len();
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..i]);
    out.push_str(&s[j..]);
    out
}
fn hd_source(v: Variant) -> String {
    let raw = probe_source_raw();
    match v {
        Variant::L3 => raw,
        Variant::L2 => strip_region(&raw, "HD-L3"),
        Variant::L1 => strip_region(&strip_region(&raw, "HD-L3"), "HD-L2"),
    }
}

/// MEASUREMENT / STACK-ACCOUNTING SOURCE ONLY — never a candidate covenant.
/// Removes the v0.5 token dual-binding block (`requireTokenTransfer`) from
/// every spend entrypoint so the HIERARCHICAL part of the covenant can be
/// executed and measured on its own. Used to (a) prove the level-3 chain
/// LOGIC on the real engine and (b) compute the exact MAX_STACK_SIZE budget
/// the token block needs on top of it. Any transaction built against this
/// source is NOT policy-complete and is never treated as an acceptance.
fn hd_source_stack_accounting(v: Variant) -> String {
    let src = hd_source(v);
    let mut out = String::with_capacity(src.len());
    let mut rest = src.as_str();
    while let Some(i) = rest.find("        requireTokenTransfer(") {
        let j = rest[i..].find(");").expect("call terminator") + i + 2;
        out.push_str(&rest[..i]);
        out.push_str("        require(recipientNew.amount > 0);");
        rest = &rest[j..];
    }
    out.push_str(rest);
    assert!(!out.contains("        requireTokenTransfer("), "every call site must be removed");
    out
}

#[derive(Clone, Debug, PartialEq)]
struct S {
    reserve: i64,
    paused: i64,
    agent_root: [u8; 32],
    policy_nonce: i64,
}

fn templated(src: &str, s: &S) -> String {
    let mut src = src.to_string();
    let mut r = |from: &str, to: String| {
        assert!(src.contains(from), "anchor missing: {from}");
        src = src.replacen(from, &to, 1);
    };
    r("int feeReserve = initFeeReserve;", format!("int feeReserve = {};", s.reserve));
    r("int paused = 0;", format!("int paused = {};", s.paused));
    r("byte[32] agentRoot = initAgentRoot;", format!("byte[32] agentRoot = 0x{};", hx(&s.agent_root)));
    r("int policyNonce = 0;", format!("int policyNonce = {};", s.policy_nonce));
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

fn compile_ctrl(src: &str, owner: &[u8; 32], pin: &Pin, s: &S, vault_id: &[u8; 32]) -> CompiledContract<'static> {
    let src: &'static str = leak(templated(src, s));
    compile_contract(
        src,
        &[
            Expr::bytes(owner.to_vec()),
            Expr::bytes(vault_id.to_vec()),
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
    .unwrap_or_else(|e| panic!("HD probe compile: {e:?}"))
}
fn state_arg(s: &S, vault_id: &[u8; 32]) -> Expr<'static> {
    struct_object(vec![
        ("boundVaultId", Expr::bytes(vault_id.to_vec())),
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
fn cov_call_opt(c: &CompiledContract<'_>, f: &str, args: Vec<Expr<'_>>, is_leader: bool) -> Vec<u8> {
    let mut s = c.build_sig_script_for_covenant_decl(f, args, CovenantDeclCallOptions { is_leader }).expect("call encoding");
    s.extend_from_slice(&push_redeem(&c.script));
    s
}
fn input(id: u8, index: u32, sigscript: Vec<u8>, budget: u16) -> TransactionInput {
    TransactionInput::new_with_compute_budget(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([id; 32]), index },
        sigscript,
        0,
        budget,
    )
}
fn cov_out(value: i64, c: &CompiledContract<'_>, auth: u16, covid: Hash) -> TransactionOutput {
    TransactionOutput {
        value: value as u64,
        script_public_key: pay_to_script_hash_script(&c.script),
        covenant: Some(CovenantBinding { authorizing_input: auth, covenant_id: covid }),
    }
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
fn sign_typed(tx: &Transaction, entries: &[UtxoEntry], idx: usize, kp: &Keypair, ty: SigHashType) -> Vec<u8> {
    let m = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    let h = calc_schnorr_signature_hash(&m.as_verifiable(), idx, ty, &reused);
    let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice()).unwrap();
    let mut out = kp.sign_schnorr(msg).as_ref().to_vec();
    out.push(ty.to_u8());
    out
}
fn p2pk_sigscript(sig: Vec<u8>) -> Vec<u8> {
    ScriptBuilder::new().add_data(&sig).unwrap().drain()
}

/* ---------------------------------------------------------------- */
/* scenario                                                           */
/* ---------------------------------------------------------------- */

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Spend,
    Dsc,
    OwnerControl(i64),
    OwnerRecover,
}

#[derive(Clone, Copy)]
struct RecipSpec {
    depth: u32,
    target: [u8; 32],
    salt: u64,
}

#[derive(Clone)]
struct Scen {
    variant: Variant,
    op: Op,
    /// entrypoint level: 1..=3 for spends, 1..=2 for delegation
    entry: usize,
    /// true: the presented chain ENDS at the committed leaf (spends);
    /// false: it STARTS at level 1 (delegation ops)
    slice_end_anchored: bool,
    tree: TreeSpec,
    recip: Vec<RecipSpec>,
    /// presented-leaf overrides, by absolute chain index
    claim: Vec<(usize, HdLeaf)>,
    periods_elapsed: Vec<i64>,
    lock_time: u64,
    /// MEASUREMENT ONLY: drive the stack-accounting source (no token block)
    no_token_binding: bool,
    /// SABOTAGE ONLY: (anchor, replacement) applied to the probe source to
    /// prove a specific guard is load-bearing
    src_mutation: Option<(&'static str, &'static str)>,
    /// commit a DIFFERENT agentRoot than the presented tree implies
    /// (revocation / stale leaf / removed ancestor probes)
    prev_root_override: Option<[u8; 32]>,
    prev_paused: i64,
    prev_reserve: i64,
    prev_nonce: i64,
    spend: i64,
    recipient_override: Option<[u8; 32]>,
    recipient_type: u8,
    new_root_override: Option<[u8; 32]>,
    /// build the successor root WITHOUT advancing this slice level's counters
    cheat_unadvanced_level: Option<usize>,
    self_amount_delta: i64,
    recipient_carry: i64,
    self_carry_override: Option<i64>,
    reserve_consumed: i64,
    succ_reserve_override: Option<i64>,
    succ_value_override: Option<i64>,
    succ_paused_override: Option<i64>,
    succ_nonce_override: Option<i64>,
    succ_vault_id_override: Option<[u8; 32]>,
    fee: i64,
    signer_seed: u8,
    sighash: SigHashType,
    mutate_after_sign: bool,
    stack_pad: usize,
    budgets: (u16, u16, u16),
    /* delegation */
    dsc_new_child_root: [u8; 32],
    dsc_tokens_ride: bool,
    /* owner ops */
    owner_new: Option<S>,
    /* cross-format: commit the tree with FROZEN v0.5 leaf hashes */
    v5_format_tree: bool,
}

fn kp(seed: u8) -> Keypair {
    deterministic_keypair(seed)
}
/* owner 0x61, A1 0x62, B 0x63, C 0x64, recipient 0x65, fuel 0x66,
 * sibling-of-B 0x67, other level-1 agent 0x68, outsider 0x69 */
fn owner_kp() -> Keypair {
    kp(0x61)
}
fn recipient_kp() -> Keypair {
    kp(0x65)
}
fn fuel_kp() -> Keypair {
    kp(0x66)
}

fn base_leaf(pk: [u8; 32], level: i64) -> HdLeaf {
    HdLeaf {
        pk,
        max_per_spend: 250,
        period_budget: 400,
        period_length_daa: 1000,
        period_start_daa: 5000,
        period_spent: 0,
        max_fee_per_tx: 60_000,
        max_carry_kas: KAS / 4,
        expiry_daa: 9_000_000,
        recipient_root: ZERO32,
        child_root: ZERO32,
        level,
    }
}
fn filler_leaf(tag: u32, level: i64) -> TNode {
    let mut pk = [0u8; 32];
    pk[..4].copy_from_slice(&tag.to_le_bytes());
    pk[31] = 0x77;
    let mut l = base_leaf(pk, level);
    l.recipient_root = [0xee; 32];
    TNode { l, kids: vec![] }
}

/// The committed delegation tree, level by level. Siblings and fillers are
/// explicit so revocation, sibling double-counting and depth probes are all
/// exact rather than implied.
#[derive(Clone)]
struct TreeSpec {
    l1: Vec<HdLeaf>,
    l1_target: usize,
    l2: Vec<HdLeaf>,
    l2_target: usize,
    l3: Vec<HdLeaf>,
    l3_target: usize,
    l4: Vec<HdLeaf>,
    l4_target: usize,
    /// how deep the committed path goes (1..=4)
    depth: usize,
    /// pad the level-1 forest with filler leaves to this count (proof depth)
    l1_pad: usize,
    /// pad each committed child list to this count (child proof depth)
    kid_pad: usize,
}

impl TreeSpec {
    fn materialize(&self) -> (Vec<TNode>, Vec<usize>) {
        let pad = |v: &Vec<HdLeaf>, to: usize, tag: u32, level: i64| -> Vec<HdLeaf> {
            let mut out = v.clone();
            let mut i = 0u32;
            while out.len() < to {
                out.push(filler_leaf(tag + i, level).l);
                i += 1;
            }
            out
        };
        let l4 = pad(&self.l4, if self.depth >= 4 { self.kid_pad } else { 0 }, 4_000_000, 4);
        let n4: Vec<TNode> = l4.iter().map(|l| TNode { l: l.clone(), kids: vec![] }).collect();
        let l3 = pad(&self.l3, if self.depth >= 3 { self.kid_pad } else { 0 }, 3_000_000, 3);
        let n3: Vec<TNode> = l3
            .iter()
            .enumerate()
            .map(|(i, l)| TNode { l: l.clone(), kids: if i == self.l3_target && self.depth >= 4 { n4.clone() } else { vec![] } })
            .collect();
        let l2 = pad(&self.l2, if self.depth >= 2 { self.kid_pad } else { 0 }, 2_000_000, 2);
        let n2: Vec<TNode> = l2
            .iter()
            .enumerate()
            .map(|(i, l)| TNode { l: l.clone(), kids: if i == self.l2_target && self.depth >= 3 { n3.clone() } else { vec![] } })
            .collect();
        let l1 = pad(&self.l1, self.l1_pad, 1_000_000, 1);
        let n1: Vec<TNode> = l1
            .iter()
            .enumerate()
            .map(|(i, l)| TNode { l: l.clone(), kids: if i == self.l1_target && self.depth >= 2 { n2.clone() } else { vec![] } })
            .collect();
        let mut path = vec![self.l1_target];
        if self.depth >= 2 {
            path.push(self.l2_target);
        }
        if self.depth >= 3 {
            path.push(self.l3_target);
        }
        if self.depth >= 4 {
            path.push(self.l4_target);
        }
        (n1, path)
    }
}

/// Cross-format probe: commit the level-1 forest using the FROZEN v0.5 leaf
/// hash instead of the HD leaf hash.
fn forest_root_v5_format(tree: &[TNode]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = tree.iter().map(|n| v5_leaf_hash(&resolved(n))).collect();
    merkle(&leaves, 0).0
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    ctrl_redeem_len: usize,
    /// the resolved presented chain (after claim overrides)
    presented: Vec<HdLeaf>,
    /// the successor agentRoot the builder committed
    new_root: [u8; 32],
    /// the committed prev agentRoot
    prev_root: [u8; 32],
}

fn function_name(op: Op, entry: usize) -> &'static str {
    match (op, entry) {
        (Op::Spend, 1) => "hdSpend",
        (Op::Spend, 2) => "childSpendL2",
        (Op::Spend, 3) => "childSpendL3",
        (Op::Dsc, 1) => "delegateSetChildRoot1",
        (Op::Dsc, 2) => "delegateSetChildRoot2",
        (Op::OwnerControl(_), _) => "ownerControl",
        (Op::OwnerRecover, _) => "ownerRecover",
        _ => panic!("no entrypoint for {op:?}/{entry}"),
    }
}

fn dsc_refold(chain: &[(HdLeaf, Vec<u8>, u64)], new_child_root: [u8; 32]) -> [u8; 32] {
    let mut carried = new_child_root;
    for i in (0..chain.len()).rev() {
        let (l, sibs, bits) = &chain[i];
        let mut nl = l.clone();
        nl.child_root = carried;
        carried = fold(hd_leaf_hash(&nl), sibs, *bits);
    }
    carried
}

fn build(c: &Scen) -> Built {
    let owner = owner_kp();
    let owner_pk = xonly(&owner);
    let signer = kp(c.signer_seed);
    let fuel = fuel_kp();
    let fuel_pk = xonly(&fuel);
    let honest_recipient = xonly(&recipient_kp());
    let recipient_pk = c.recipient_override.unwrap_or(honest_recipient);
    let mut src = if c.no_token_binding { hd_source_stack_accounting(c.variant) } else { hd_source(c.variant) };
    if let Some((anchor, replacement)) = c.src_mutation {
        assert!(src.contains(anchor), "sabotage anchor missing: {anchor}");
        src = src.replace(anchor, replacement);
    }
    let src = src;

    /* --- token template pin --- */
    let tok_ref = compile_kcc20(COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
    let tpl = template_of(&tok_ref);
    let pin = Pin {
        token_covid: COV_TOKEN,
        template_hash: tpl.hash,
        prefix_len: tpl.prefix.len() as i64,
        state_len: tpl.state_len as i64,
        suffix_len: tpl.suffix.len() as i64,
    };

    /* --- committed tree, chain proofs, presented chain --- */
    let (tree, path) = c.tree.materialize();
    let prev_root = c
        .prev_root_override
        .unwrap_or(if c.v5_format_tree { forest_root_v5_format(&tree) } else { forest_root(&tree) });
    let full_chain = chain_proofs(&tree, &path);
    let mut presented: Vec<(HdLeaf, Vec<u8>, u64)> = full_chain.clone();
    for (idx, leaf) in &c.claim {
        presented[*idx].0 = leaf.clone();
    }
    let k = presented.len();
    assert!(c.entry <= k, "entry level {} exceeds committed chain depth {k}", c.entry);
    let (slice, abs_base): (Vec<(HdLeaf, Vec<u8>, u64)>, usize) =
        if c.slice_end_anchored { (presented[k - c.entry..].to_vec(), k - c.entry) } else { (presented[..c.entry].to_vec(), 0) };

    /* recipient proofs, one per presented level */
    let recip_proofs: Vec<(Vec<u8>, u64)> = (0..c.entry)
        .map(|i| {
            let r = c.recip[abs_base + i];
            let (_root, sibs, bits) = recip_tree(r.depth, &r.target, r.salt);
            (sibs, bits)
        })
        .collect();

    let prev = S { reserve: c.prev_reserve, paused: c.prev_paused, agent_root: prev_root, policy_nonce: c.prev_nonce };
    let ctrl_prev = compile_ctrl(&src, &owner_pk, &pin, &prev, &VAULT_ID);

    let mut inputs = vec![input(1, 0, vec![], c.budgets.0)];
    let mut entries = vec![cov_utxo(prev.reserve, &ctrl_prev, COV_CTRL)];
    let mut outputs: Vec<TransactionOutput> = Vec::new();
    let mut token_sigscript: Option<Vec<u8>> = None;
    let ctrl_args: Vec<Expr<'static>>;
    let mut new_root = ZERO32;
    let succ_vault_id = c.succ_vault_id_override.unwrap_or(VAULT_ID);

    match c.op {
        Op::Spend => {
            let spend = c.spend;
            let pe: Vec<i64> = (0..c.entry).map(|i| c.periods_elapsed[abs_base + i]).collect();
            let honest_root = match c.cheat_unadvanced_level {
                None => nested_refold(&slice, spend, &pe),
                Some(skip) => nested_refold_skipping(&slice, spend, &pe, skip),
            };
            new_root = c.new_root_override.unwrap_or(honest_root);
            let succ_reserve = c.succ_reserve_override.unwrap_or(prev.reserve - c.reserve_consumed);
            let new_state = S {
                reserve: succ_reserve,
                paused: c.succ_paused_override.unwrap_or(prev.paused),
                agent_root: new_root,
                policy_nonce: c.succ_nonce_override.unwrap_or(prev.policy_nonce),
            };
            let ctrl_next = compile_ctrl(&src, &owner_pk, &pin, &new_state, &succ_vault_id);

            let self_after = PREV_TOKEN_AMOUNT - spend + c.self_amount_delta;
            let self_id: [u8; 32] = COV_CTRL.as_bytes().try_into().unwrap();
            let tok_prev = compile_kcc20(self_id, IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
            let tok_self = compile_kcc20(self_id, IDENTIFIER_COVENANT_ID, self_after, false, 2);
            let tok_recipient = compile_kcc20(recipient_pk, c.recipient_type, spend, false, 2);

            let self_carry = c.self_carry_override.unwrap_or(TOKEN_CARRY - c.recipient_carry);
            let change = FUEL - (c.fee - c.reserve_consumed);
            let succ_value = c.succ_value_override.unwrap_or(succ_reserve);

            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(cov_out(self_carry, &tok_self, 1, COV_TOKEN));
            outputs.push(cov_out(c.recipient_carry, &tok_recipient, 1, COV_TOKEN));
            outputs.push(p2pk_out(&fuel_pk, change));

            inputs.push(input(2, 0, vec![], c.budgets.1));
            entries.push(cov_utxo(TOKEN_CARRY, &tok_prev, COV_TOKEN));
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

            token_sigscript = Some(cov_call_opt(
                &tok_prev,
                "transfer",
                vec![
                    vec![
                        kcc20_state(self_id, IDENTIFIER_COVENANT_ID, self_after, false),
                        kcc20_state(recipient_pk, c.recipient_type, spend, false),
                    ]
                    .into(),
                    Vec::<Expr>::new().into(),
                    Expr::bytes(vec![0u8]),
                ],
                true,
            ));

            let mut args: Vec<Expr<'static>> = vec![
                state_arg(&new_state, &succ_vault_id),
                kcc20_state(self_id, IDENTIFIER_COVENANT_ID, self_after, false),
                kcc20_state(recipient_pk, c.recipient_type, spend, false),
            ];
            for i in 0..c.entry {
                let (l, sibs, bits) = &slice[i];
                args.push(hd_leaf_arg(l));
                args.push(Expr::bytes(sibs.clone()));
                args.push(Expr::int(*bits as i64));
                args.push(Expr::int(pe[i]));
                args.push(Expr::bytes(recip_proofs[i].0.clone()));
                args.push(Expr::int(recip_proofs[i].1 as i64));
            }
            args.push(Expr::bytes(recipient_pk.to_vec()));
            args.push(Expr::bytes(vec![])); // signature placeholder
            ctrl_args = args;
        }
        Op::Dsc => {
            new_root = c.new_root_override.unwrap_or(dsc_refold(&slice, c.dsc_new_child_root));
            let new_state = S {
                reserve: c.succ_reserve_override.unwrap_or(prev.reserve),
                paused: c.succ_paused_override.unwrap_or(prev.paused),
                agent_root: new_root,
                policy_nonce: c.succ_nonce_override.unwrap_or(prev.policy_nonce),
            };
            let ctrl_next = compile_ctrl(&src, &owner_pk, &pin, &new_state, &succ_vault_id);
            let succ_value = c.succ_value_override.unwrap_or(new_state.reserve);
            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            if c.dsc_tokens_ride {
                let self_id: [u8; 32] = COV_CTRL.as_bytes().try_into().unwrap();
                let tok_prev = compile_kcc20(self_id, IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
                let tok_out = compile_kcc20(xonly(&signer), IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false, 2);
                inputs.push(input(2, 0, vec![], c.budgets.1));
                entries.push(cov_utxo(TOKEN_CARRY, &tok_prev, COV_TOKEN));
                outputs.push(cov_out(TOKEN_CARRY, &tok_out, 1, COV_TOKEN));
                token_sigscript = Some(cov_call_opt(
                    &tok_prev,
                    "transfer",
                    vec![
                        vec![kcc20_state(xonly(&signer), IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false)].into(),
                        Vec::<Expr>::new().into(),
                        Expr::bytes(vec![0u8]),
                    ],
                    true,
                ));
            }
            let top_up = new_state.reserve - prev.reserve;
            outputs.push(p2pk_out(&fuel_pk, FUEL - c.fee - top_up.max(0)));
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

            let mut args: Vec<Expr<'static>> = vec![state_arg(&new_state, &succ_vault_id)];
            for (l, sibs, bits) in slice.iter() {
                args.push(hd_leaf_arg(l));
                args.push(Expr::bytes(sibs.clone()));
                args.push(Expr::int(*bits as i64));
            }
            args.push(Expr::bytes(c.dsc_new_child_root.to_vec()));
            args.push(Expr::bytes(vec![]));
            ctrl_args = args;
        }
        Op::OwnerControl(sel) => {
            let new_state = c
                .owner_new
                .clone()
                .map(|n| if n.agent_root == ZERO32 { S { agent_root: prev_root, ..n } } else { n })
                .unwrap_or(prev.clone());
            let ctrl_next = compile_ctrl(&src, &owner_pk, &pin, &new_state, &succ_vault_id);
            let succ_value = c.succ_value_override.unwrap_or(new_state.reserve);
            let top_up = new_state.reserve - prev.reserve;
            outputs.push(cov_out(succ_value, &ctrl_next, 0, COV_CTRL));
            outputs.push(p2pk_out(&fuel_pk, FUEL - c.fee - top_up.max(0)));
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            new_root = new_state.agent_root;
            ctrl_args = vec![state_arg(&new_state, &succ_vault_id), Expr::int(sel), Expr::bytes(vec![])];
        }
        Op::OwnerRecover => {
            outputs.push(p2pk_out(&owner_pk, prev.reserve));
            let self_id: [u8; 32] = COV_CTRL.as_bytes().try_into().unwrap();
            let tok_prev = compile_kcc20(self_id, IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
            let tok_out = compile_kcc20(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false, 2);
            inputs.push(input(2, 0, vec![], c.budgets.1));
            entries.push(cov_utxo(TOKEN_CARRY, &tok_prev, COV_TOKEN));
            outputs.push(cov_out(TOKEN_CARRY, &tok_out, 1, COV_TOKEN));
            token_sigscript = Some(cov_call_opt(
                &tok_prev,
                "transfer",
                vec![
                    vec![kcc20_state(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false)].into(),
                    Vec::<Expr>::new().into(),
                    Expr::bytes(vec![0u8]),
                ],
                true,
            ));
            inputs.push(input(3, 0, vec![], c.budgets.2));
            entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));
            outputs.push(p2pk_out(&fuel_pk, FUEL - c.fee));
            ctrl_args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(vec![]), kcc20_state(owner_pk, IDENTIFIER_PUBKEY, PREV_TOKEN_AMOUNT, false)];
        }
    }

    /* --- sign (all outputs and budgets fixed) --- */
    let unsigned = Transaction::new(1, inputs.clone(), outputs.clone(), c.lock_time, SubnetworkId::default(), 0, vec![]);
    let ctrl_sig = sign_typed(&unsigned, &entries, 0, &signer, c.sighash);
    let fuel_idx = inputs.iter().position(|i| i.previous_outpoint.transaction_id == TransactionId::from_bytes([3; 32])).unwrap();

    let mut args = ctrl_args;
    let sig_slot = match c.op {
        Op::OwnerRecover => 1,
        _ => args.len() - 1,
    };
    args[sig_slot] = Expr::bytes(ctrl_sig.clone());
    let mut ctrl_sigscript = cov_call_opt(&ctrl_prev, function_name(c.op, c.entry), args, false);
    if c.stack_pad > 0 {
        let mut pad = ScriptBuilder::new();
        for _ in 0..c.stack_pad {
            pad.add_data(&[0x01u8]).unwrap();
        }
        let mut padded = pad.drain();
        padded.extend_from_slice(&ctrl_sigscript);
        ctrl_sigscript = padded;
    }

    /* post-sign mutation: shrink the (unbound) change output by 1 sompi */
    if c.mutate_after_sign {
        let last = outputs.len() - 1;
        outputs[last].value -= 1;
    }
    let fuel_sig = sign_typed(&unsigned, &entries, fuel_idx, &fuel, SIG_HASH_ALL);

    let mut signed_inputs = inputs.clone();
    signed_inputs[0].signature_script = ctrl_sigscript;
    for inp in signed_inputs.iter_mut() {
        let id = inp.previous_outpoint.transaction_id;
        if id == TransactionId::from_bytes([2; 32]) {
            inp.signature_script = token_sigscript.clone().expect("token sigscript");
        } else if id == TransactionId::from_bytes([3; 32]) {
            inp.signature_script = p2pk_sigscript(fuel_sig.clone());
        }
    }
    let tx = Transaction::new(1, signed_inputs, outputs, c.lock_time, SubnetworkId::default(), 0, vec![]);
    Built {
        tx,
        entries,
        ctrl_redeem_len: ctrl_prev.script.len(),
        presented: slice.iter().map(|(l, _, _)| l.clone()).collect(),
        new_root,
        prev_root,
    }
}

fn run(c: &Scen) -> (Result<(), TxScriptError>, Vec<Result<(), TxScriptError>>) {
    let b = build(c);
    let (ctrl, _) = execute_input_measured(b.tx.clone(), b.entries.clone(), 0);
    let others: Vec<_> = (1..b.tx.inputs.len()).map(|i| execute_input_measured(b.tx.clone(), b.entries.clone(), i).0).collect();
    (ctrl, others)
}

fn accepts(label: &str, c: &Scen) -> Built {
    let b = build(c);
    execute_input_measured(b.tx.clone(), b.entries.clone(), 0)
        .0
        .unwrap_or_else(|e| panic!("{label}: controller must ACCEPT: {e:?}"));
    for i in 1..b.tx.inputs.len() {
        execute_input_measured(b.tx.clone(), b.entries.clone(), i)
            .0
            .unwrap_or_else(|e| panic!("{label}: input {i} must ACCEPT: {e:?}"));
    }
    b
}

/* ---------------------------------------------------------------- */
/* scenario constructors                                              */
/* ---------------------------------------------------------------- */

const A1_SEED: u8 = 0x62;
const B_SEED: u8 = 0x63;
const C_SEED: u8 = 0x64;
const BSIB_SEED: u8 = 0x67;
const OTHER_L1_SEED: u8 = 0x68;
const OUTSIDER_SEED: u8 = 0x69;

fn chain_templates() -> [HdLeaf; 4] {
    let a1 = HdLeaf {
        pk: xonly(&kp(A1_SEED)),
        max_per_spend: 250,
        period_budget: 400,
        period_length_daa: 1000,
        period_start_daa: 5000,
        period_spent: 0,
        max_fee_per_tx: 60_000,
        max_carry_kas: KAS / 4,
        expiry_daa: 9_000_000,
        recipient_root: ZERO32,
        child_root: ZERO32,
        level: 1,
    };
    let b = HdLeaf {
        pk: xonly(&kp(B_SEED)),
        max_per_spend: 200,
        period_budget: 300,
        period_length_daa: 700,
        period_start_daa: 5200,
        max_fee_per_tx: 50_000,
        max_carry_kas: KAS / 5,
        expiry_daa: 8_000_000,
        level: 2,
        ..a1.clone()
    };
    let c = HdLeaf {
        pk: xonly(&kp(C_SEED)),
        max_per_spend: 150,
        period_budget: 200,
        period_length_daa: 500,
        period_start_daa: 5400,
        max_fee_per_tx: 40_000,
        max_carry_kas: KAS / 8,
        expiry_daa: 7_000_000,
        level: 3,
        ..a1.clone()
    };
    /* a hypothetical level-4 leaf (only used to prove > MAX_LEVEL refusal) */
    let d = HdLeaf { pk: xonly(&kp(0x6a)), max_per_spend: 100, period_budget: 150, level: 4, ..c.clone() };
    [a1, b, c, d]
}

fn with_recip(mut l: HdLeaf, r: &RecipSpec) -> HdLeaf {
    l.recipient_root = recip_tree(r.depth, &r.target, r.salt).0;
    l
}

/// Honest scenario: a spend by the leaf at `levels` (1, 2 or 3), at the
/// intersection boundary (amount == the minimum cap over the whole chain).
fn honest_spend(variant: Variant, levels: usize) -> Scen {
    let honest_recipient = xonly(&recipient_kp());
    let recip: Vec<RecipSpec> = (0..4).map(|i| RecipSpec { depth: 0, target: honest_recipient, salt: i as u64 }).collect();
    let t = chain_templates();
    let a1 = with_recip(t[0].clone(), &recip[0]);
    let b = with_recip(t[1].clone(), &recip[1]);
    let c = with_recip(t[2].clone(), &recip[2]);
    let d = with_recip(t[3].clone(), &recip[3]);
    let other_l1 = with_recip(HdLeaf { pk: xonly(&kp(OTHER_L1_SEED)), ..t[0].clone() }, &recip[0]);
    let bsib = with_recip(HdLeaf { pk: xonly(&kp(BSIB_SEED)), ..t[1].clone() }, &recip[1]);
    let spend = match levels {
        1 => 250,
        2 => 200,
        _ => 150,
    };
    let signer_seed = match levels {
        1 => A1_SEED,
        2 => B_SEED,
        _ => C_SEED,
    };
    Scen {
        variant,
        op: Op::Spend,
        entry: levels,
        slice_end_anchored: true,
        tree: TreeSpec {
            l1: vec![a1, other_l1],
            l1_target: 0,
            l2: vec![b, bsib],
            l2_target: 0,
            l3: vec![c],
            l3_target: 0,
            l4: vec![d],
            l4_target: 0,
            depth: levels,
            l1_pad: 0,
            kid_pad: 0,
        },
        recip,
        claim: vec![],
        periods_elapsed: vec![0; 4],
        lock_time: 0,
        no_token_binding: false,
        src_mutation: None,
        prev_root_override: None,
        prev_paused: 0,
        prev_reserve: RESERVE,
        prev_nonce: 0,
        spend,
        recipient_override: None,
        recipient_type: IDENTIFIER_PUBKEY,
        new_root_override: None,
        cheat_unadvanced_level: None,
        self_amount_delta: 0,
        recipient_carry: RECIPIENT_CARRY,
        self_carry_override: None,
        reserve_consumed: RESERVE_CONSUMED,
        succ_reserve_override: None,
        succ_value_override: None,
        succ_paused_override: None,
        succ_nonce_override: None,
        succ_vault_id_override: None,
        fee: FEE,
        signer_seed,
        sighash: SIG_HASH_ALL,
        mutate_after_sign: false,
        stack_pad: 0,
        budgets: (6000, 200, 20),
        dsc_new_child_root: ZERO32,
        dsc_tokens_ride: false,
        owner_new: None,
        v5_format_tree: false,
    }
}

/// Honest delegation: the parent at `level` names a child set.
fn honest_dsc(variant: Variant, level: usize) -> (Scen, [u8; 32]) {
    let mut c = honest_spend(variant, level);
    c.op = Op::Dsc;
    c.entry = level;
    c.slice_end_anchored = false;
    c.signer_seed = if level == 1 { A1_SEED } else { B_SEED };
    /* the committed tree stops ONE level above the new child set */
    c.tree.depth = level;
    /* the child set the parent is about to commit = the same tree one level deeper */
    let mut deeper = c.tree.clone();
    deeper.depth = level + 1;
    let (dtree, dpath) = deeper.materialize();
    let node = {
        let mut n = &dtree[dpath[0]];
        for step in &dpath[1..level] {
            n = &n.kids[*step];
        }
        n
    };
    let new_child_root = kids_root(node);
    c.dsc_new_child_root = new_child_root;
    let expected_successor = forest_root(&dtree);
    (c, expected_successor)
}

fn owner_case(variant: Variant, op: Op) -> Scen {
    let mut c = honest_spend(variant, 1);
    c.op = op;
    c.signer_seed = 0x61;
    c
}

fn refuse(label: &str, c: &Scen, failures: &mut Vec<String>, refusals: &mut Vec<(String, String)>) {
    let (ctrl, _) = run(c);
    match ctrl {
        Ok(()) => failures.push(format!("{label}: controller ACCEPTED — must REFUSE")),
        Err(e) => {
            let s = format!("{e:?}");
            println!("  REFUSED {label:<72} {s}");
            refusals.push((label.to_string(), s));
        }
    }
}

/* ---------------------------------------------------------------- */
/* HONEST PATHS                                                       */
/* ---------------------------------------------------------------- */

#[test]
fn hd_honest_level1_spend_accepts() {
    let b = accepts("level-1 spend (HD leaf format)", &honest_spend(Variant::L1, 1));
    assert_eq!(b.presented.len(), 1);
    assert_eq!(b.presented[0].level, 1);
    /* the same level-1 spend must also be accepted by the L2 and L3 variants */
    accepts("level-1 spend under MAX_LEVEL 2", &honest_spend(Variant::L2, 1));
    accepts("level-1 spend under MAX_LEVEL 3", &honest_spend(Variant::L3, 1));
}

#[test]
fn hd_honest_level2_spend_at_the_intersection_boundary_accepts() {
    let mut c = honest_spend(Variant::L2, 2);
    /* budget exactly exhausted at the TIGHTEST level (the child): 100 + 200 = 300 */
    c.tree.l2[0].period_spent = 100;
    let b = accepts("level-2 spend at the intersection boundary", &c);
    assert_eq!(b.presented.len(), 2);
    assert_eq!(b.presented[0].level, 1);
    assert_eq!(b.presented[1].level, 2);
    /* one more sompi of budget at the tightest level must be refused */
    let mut over = c.clone();
    over.tree.l2[0].period_spent = 101;
    assert!(run(&over).0.is_err(), "budget+1 at the tightest level must refuse");
    /* and the same spend must be accepted by the MAX_LEVEL 3 variant */
    let mut c3 = c.clone();
    c3.variant = Variant::L3;
    accepts("level-2 spend under MAX_LEVEL 3", &c3);
}

#[test]
fn hd_honest_level3_spend_at_the_intersection_boundary_accepts() {
    let mut c = honest_spend(Variant::L3, 3);
    /* amount == min cap over the chain (150) AND budget exactly exhausted at
     * the tightest level: 50 + 150 == 200 */
    c.tree.l3[0].period_spent = 50;
    let b = accepts("level-3 spend at the intersection boundary", &c);
    assert_eq!(b.presented.iter().map(|l| l.level).collect::<Vec<_>>(), vec![1, 2, 3]);
    let mut over = c.clone();
    over.tree.l3[0].period_spent = 51;
    assert!(run(&over).0.is_err(), "budget+1 at the tightest level must refuse");
}

#[test]
fn hd_honest_rollover_at_one_level_only_accepts() {
    let mut c = honest_spend(Variant::L3, 3);
    /* the CHILD's own period is exhausted and has elapsed; the two ancestors
     * keep their own (different) clocks and simply accumulate */
    c.tree.l3[0].period_spent = 200;
    c.periods_elapsed[2] = 1;
    c.lock_time = 5900; // C: start 5400 + 1 * 500
    accepts("rollover at level 3 only", &c);
    /* premature rollover at that level is refused */
    let mut early = c.clone();
    early.lock_time = 5899;
    assert!(run(&early).0.is_err(), "premature rollover must refuse");
    /* rollover claimed at the PARENT without its period having elapsed */
    let mut bad_parent = c.clone();
    bad_parent.periods_elapsed[0] = 1; // A1: start 5000 + 1000 = 6000 > lock_time 5900
    assert!(run(&bad_parent).0.is_err(), "premature parent rollover must refuse");
}

#[test]
fn hd_honest_delegate_set_child_root_level1_and_level2_accept() {
    for (level, variant) in [(1usize, Variant::L2), (2usize, Variant::L3)] {
        let (c, expected) = honest_dsc(variant, level);
        let b = accepts(&format!("delegateSetChildRoot{level}"), &c);
        assert_eq!(
            b.new_root, expected,
            "level-{level} delegation must refold to exactly the agentRoot of the tree WITH the new child set"
        );
        assert_ne!(b.new_root, b.prev_root);
    }
}

#[test]
fn hd_honest_revocation_then_child_spend_refused() {
    /* the parent zeroes its childRoot (pure authority reduction) */
    let mut c = honest_spend(Variant::L2, 2);
    c.op = Op::Dsc;
    c.entry = 1;
    c.slice_end_anchored = false;
    c.signer_seed = A1_SEED;
    c.dsc_new_child_root = ZERO32;
    let revoked = accepts("revocation (parent zeroes childRoot)", &c);
    /* the revoked tree's agentRoot: A1 with no children at all */
    let mut bare = c.tree.clone();
    bare.depth = 1;
    let (bare_tree, _) = bare.materialize();
    assert_eq!(revoked.new_root, forest_root(&bare_tree), "revocation must refold to the childless agentRoot");
    /* the child's spend under the revoked state must now be refused */
    let mut spend = honest_spend(Variant::L2, 2);
    spend.prev_root_override = Some(forest_root(&bare_tree));
    let (ctrl, _) = run(&spend);
    assert!(ctrl.is_err(), "a revoked child must not be able to spend: {ctrl:?}");
    println!("  REFUSED revoked-child spend                                             {:?}", ctrl.unwrap_err());
}

#[test]
fn hd_honest_owner_ops_still_accept() {
    let mut pause = owner_case(Variant::L3, Op::OwnerControl(2));
    pause.owner_new = Some(S { reserve: RESERVE, paused: 1, agent_root: ZERO32, policy_nonce: 0 });
    accepts("ownerControl(pause)", &pause);
    let mut rec = owner_case(Variant::L3, Op::OwnerRecover);
    rec.fee = FEE;
    accepts("ownerRecover", &rec);
}

#[test]
fn hd_honest_parent_budget_is_shared_across_siblings() {
    /* A1 budget 300 with 200 already spent by child B; the SIBLING may still
     * spend 100 (the parent's remaining budget) — and no more. */
    let mut c = honest_spend(Variant::L2, 2);
    c.tree.l1[0].period_budget = 300;
    c.tree.l1[0].period_spent = 200;
    c.tree.l2[0].period_spent = 200;
    c.tree.l2_target = 1; // spend as the SIBLING
    c.signer_seed = BSIB_SEED;
    c.spend = 100;
    accepts("sibling spends the parent's remaining budget", &c);
    let mut over = c.clone();
    over.spend = 101;
    assert!(run(&over).0.is_err(), "sibling must not exceed the parent's remaining budget");
}

/* ---------------------------------------------------------------- */
/* HOSTILE MATRIX (design record §3, every row a real-engine refusal) */
/* ---------------------------------------------------------------- */

fn set_recip(c: &mut Scen, level: usize, depth: u32, target: [u8; 32]) {
    let salt = c.recip[level].salt;
    c.recip[level] = RecipSpec { depth, target, salt };
    let root = recip_tree(depth, &target, salt).0;
    let list = match level {
        0 => &mut c.tree.l1,
        1 => &mut c.tree.l2,
        2 => &mut c.tree.l3,
        _ => &mut c.tree.l4,
    };
    for l in list.iter_mut() {
        l.recipient_root = root;
    }
}

/// The exact leaf the tree COMMITS at chain position `idx` (child roots
/// resolved), so a claim override differs from it in exactly one field.
fn committed_leaf(spec: &TreeSpec, idx: usize) -> HdLeaf {
    let (t, p) = spec.materialize();
    chain_proofs(&t, &p)[idx].0.clone()
}

fn forest_root_of(spec: &TreeSpec) -> [u8; 32] {
    let (t, _) = spec.materialize();
    forest_root(&t)
}

#[test]
fn hd_hostile_matrix_refuses_every_class() {
    let mut failures: Vec<String> = Vec::new();
    let mut refusals: Vec<(String, String)> = Vec::new();
    let outsider = xonly(&kp(OUTSIDER_SEED));

    /* ---- AUTHORITY MAY NEVER INCREASE DESCENDING ---- */

    {
        /* child CAP broader than the parent; the spend is inside the child's
         * own cap and budget but beyond the level-1 cap */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].max_per_spend = 400;
        c.tree.l3[0].period_budget = 1000;
        c.tree.l2[0].max_per_spend = 400;
        c.tree.l2[0].period_budget = 1000;
        c.spend = 300; // <= child cap 400, > A1 cap 250
        refuse("child cap > parent cap (spend inside the child's own cap)", &c, &mut failures, &mut refusals);
    }
    {
        /* child BUDGET broader than the parent; the parent's budget is what
         * actually binds because the parent's counter also advances */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].period_budget = 1000;
        c.tree.l2[0].period_budget = 1000;
        c.tree.l1[0].period_spent = 350; // 350 + 150 = 500 > 400
        refuse("child budget > parent budget (parent counter binds)", &c, &mut failures, &mut refusals);
    }
    {
        /* child ALLOWLIST broader than the parent's */
        let mut c = honest_spend(Variant::L3, 3);
        set_recip(&mut c, 0, 0, outsider); // A1 allows only the outsider
        refuse("recipient allowed by the child but NOT by the grandparent", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        set_recip(&mut c, 1, 0, outsider); // B allows only the outsider
        refuse("recipient allowed by the child but NOT by the parent", &c, &mut failures, &mut refusals);
    }
    {
        /* child FEE cap broader than the parent's */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].max_fee_per_tx = 100_000;
        c.tree.l1[0].max_fee_per_tx = 20_000;
        c.reserve_consumed = 30_000; // <= child cap, > the chain minimum
        refuse("child fee cap > parent fee cap (min over the chain binds)", &c, &mut failures, &mut refusals);
    }
    {
        /* child CARRY cap broader than the parent's */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].max_carry_kas = KAS;
        c.tree.l1[0].max_carry_kas = KAS / 20;
        c.recipient_carry = KAS / 10; // <= child cap, > the chain minimum
        refuse("child carry cap > parent carry cap (min over the chain binds)", &c, &mut failures, &mut refusals);
    }

    /* ---- refold / counter forgeries ---- */

    for skip in [0usize, 1] {
        let mut c = honest_spend(Variant::L3, 3);
        c.cheat_unadvanced_level = Some(skip);
        refuse(
            &format!("spend without advancing the level-{} counter in the refold", skip + 1),
            &c,
            &mut failures,
            &mut refusals,
        );
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.new_root_override = Some([0x55; 32]);
        refuse("successor agentRoot misreport", &c, &mut failures, &mut refusals);
    }
    {
        /* sibling double-count beyond the parent's budget */
        let mut c = honest_spend(Variant::L2, 2);
        c.tree.l1[0].period_budget = 300;
        c.tree.l1[0].period_spent = 200;
        c.tree.l2[0].period_spent = 200;
        c.tree.l2_target = 1;
        c.signer_seed = BSIB_SEED;
        c.spend = 200; // 200 + 200 > the parent's 300
        refuse("sibling double-count beyond the shared parent budget", &c, &mut failures, &mut refusals);
    }
    {
        /* period accounting misreport: present a parent leaf whose counters
         * are lower than the committed ones */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l1[0].period_spent = 200;
        let mut stale = committed_leaf(&c.tree, 0);
        stale.period_spent = 0;
        c.claim.push((0, stale));
        refuse("parent period-accounting misreport (claimed spent 0)", &c, &mut failures, &mut refusals);
    }

    /* ---- membership / structural revocation ---- */

    {
        /* stale parent leaf: the committed tree has moved on */
        let mut c = honest_spend(Variant::L3, 3);
        let mut moved = c.tree.clone();
        moved.l1[0].period_spent += 50;
        c.prev_root_override = Some(forest_root_of(&moved));
        refuse("stale parent leaf (committed counters already advanced)", &c, &mut failures, &mut refusals);
    }
    {
        /* removed grandparent, parent chain reused */
        let mut c = honest_spend(Variant::L3, 3);
        let mut removed = c.tree.clone();
        removed.l1 = vec![removed.l1[1].clone()];
        removed.l1_target = 0;
        removed.depth = 1;
        c.prev_root_override = Some(forest_root_of(&removed));
        refuse("removed grandparent with a reused parent chain", &c, &mut failures, &mut refusals);
    }
    {
        /* revoked parent: its childRoot is zero in the committed tree */
        let mut c = honest_spend(Variant::L3, 3);
        let mut bare = c.tree.clone();
        bare.depth = 2; // B has no children any more
        c.prev_root_override = Some(forest_root_of(&bare));
        refuse("revoked subtree (parent childRoot zeroed)", &c, &mut failures, &mut refusals);
    }
    {
        /* presenting a zero childRoot for an ancestor is refused outright */
        let mut c = honest_spend(Variant::L3, 3);
        let mut z = committed_leaf(&c.tree, 1);
        z.child_root = ZERO32;
        c.claim.push((1, z));
        refuse("ancestor presented with a zero childRoot", &c, &mut failures, &mut refusals);
    }

    /* ---- level / chain-shape forgeries ---- */

    {
        let mut c = honest_spend(Variant::L3, 2);
        c.entry = 1; // a level-2 key presented through the level-1 entrypoint
        refuse("level-2 key presented as level-1 (hdSpend)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.entry = 2; // chain SHORTER than the leaf's level
        refuse("chain shorter than the leaf level (childSpendL2 with a level-3 leaf)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].level = 2; // committed at level 2 but presented in the level-3 position
        refuse("leaf committed at a different level than its chain position", &c, &mut failures, &mut refusals);
    }
    {
        /* a level-4 leaf presented through the level-3 entrypoint */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.depth = 4;
        c.entry = 3;
        c.signer_seed = 0x6a;
        c.spend = 100;
        refuse("> MAX_LEVEL chain (level-4 leaf through childSpendL3)", &c, &mut failures, &mut refusals);
    }
    {
        /* self-parenting: the same key at two levels */
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l2[0].pk = xonly(&kp(A1_SEED));
        refuse("self-parenting (parent key reused as the child key)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].pk = xonly(&kp(A1_SEED));
        c.signer_seed = A1_SEED;
        refuse("grandparent key reused as the spending leaf key", &c, &mut failures, &mut refusals);
    }

    /* ---- leaf-format (domain) separation ---- */

    {
        let mut c = honest_spend(Variant::L3, 1);
        c.v5_format_tree = true;
        refuse("v0.5 leaf tag committed, HD leaf presented (hdSpend)", &c, &mut failures, &mut refusals);
    }

    /* ---- expiry consistency (NOT a consensus time check — §1.4) ---- */

    {
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l3[0].expiry_daa = 9_500_000; // child outlives its parent
        refuse("expiry inversion (child expiryDaa > parent expiryDaa)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.tree.l2[0].expiry_daa = 9_500_000; // parent outlives the grandparent
        refuse("expiry inversion (parent expiryDaa > grandparent expiryDaa)", &c, &mut failures, &mut refusals);
    }

    /* ---- signature / sighash ---- */

    for (label, seed) in [("outsider key", OUTSIDER_SEED), ("the PARENT's key on the child's spend", B_SEED), ("the owner key", 0x61u8)] {
        let mut c = honest_spend(Variant::L3, 3);
        c.signer_seed = seed;
        refuse(&format!("wrong signer ({label})"), &c, &mut failures, &mut refusals);
    }
    for (label, ty) in [("NONE", SIG_HASH_NONE), ("SINGLE", SIG_HASH_SINGLE), ("ANYONECANPAY", SIG_HASH_ANY_ONE_CAN_PAY)] {
        let mut c = honest_spend(Variant::L3, 3);
        c.sighash = ty;
        refuse(&format!("SIGHASH_{label} on a level-3 spend"), &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.mutate_after_sign = true;
        refuse("post-sign mutation of an output value", &c, &mut failures, &mut refusals);
    }

    /* ---- fee / value leakage, pause ---- */

    {
        let mut c = honest_spend(Variant::L3, 3);
        c.reserve_consumed = FEE + 1;
        refuse("fee-reserve consumed above the exact network fee", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.succ_value_override = Some(RESERVE - RESERVE_CONSUMED - 1_000_000);
        refuse("controller KAS drain (successor value below the declared reserve)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.succ_reserve_override = Some(RESERVE + 1);
        refuse("declared successor reserve inflated", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.self_carry_override = Some(TOKEN_CARRY - RECIPIENT_CARRY - 1);
        refuse("token-family KAS leaked to change", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.self_amount_delta = 1;
        refuse("token conservation (+1)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.prev_paused = 1;
        refuse("paused vault (level-3 spend)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.succ_paused_override = Some(1);
        refuse("spend flipping the vault to paused", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.succ_nonce_override = Some(1);
        refuse("spend bumping the owner policy nonce", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.succ_vault_id_override = Some(ALT_VAULT_ID);
        refuse("spend rebinding the vault id", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.recipient_type = IDENTIFIER_COVENANT_ID;
        refuse("recipient owned by the covenant-id scheme instead of p2pk", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = honest_spend(Variant::L3, 3);
        c.recipient_override = Some(outsider);
        refuse("recipient outside every allowlist", &c, &mut failures, &mut refusals);
    }

    assert!(failures.is_empty(), "hierarchical-delegation hostile matrix failures:\n{}", failures.join("\n"));
    println!("\n  hostile spend rows refused: {}", refusals.len());
}

#[test]
fn hd_hostile_matrix_delegation_refuses_every_class() {
    let mut failures: Vec<String> = Vec::new();
    let mut refusals: Vec<(String, String)> = Vec::new();

    let base1 = || honest_dsc(Variant::L3, 1).0;
    let base2 = || honest_dsc(Variant::L3, 2).0;

    for (label, seed) in [
        ("a sibling level-1 leaf's key", OTHER_L1_SEED),
        ("the child's key", B_SEED),
        ("a grandchild's key", C_SEED),
        ("the vault owner's key", 0x61u8),
        ("an outsider key", OUTSIDER_SEED),
    ] {
        let mut c = base1();
        c.signer_seed = seed;
        refuse(&format!("delegateSetChildRoot1 signed by {label}"), &c, &mut failures, &mut refusals);
    }
    {
        let mut c = base2();
        c.signer_seed = A1_SEED; // the grandparent, not the level-2 parent
        refuse("delegateSetChildRoot2 signed by the grandparent", &c, &mut failures, &mut refusals);
    }
    let field_mutators: Vec<(&str, fn(&mut Scen))> = vec![
        ("feeReserve", |c: &mut Scen| c.succ_reserve_override = Some(RESERVE - 1)),
        ("paused", |c: &mut Scen| c.succ_paused_override = Some(1)),
        ("policyNonce", |c: &mut Scen| c.succ_nonce_override = Some(1)),
        ("boundVaultId", |c: &mut Scen| c.succ_vault_id_override = Some(ALT_VAULT_ID)),
        ("successor output value", |c: &mut Scen| c.succ_value_override = Some(RESERVE - 1)),
    ];
    for (label, f) in field_mutators {
        let mut c = base1();
        f(&mut c);
        refuse(&format!("delegateSetChildRoot1 also changing {label}"), &c, &mut failures, &mut refusals);
    }
    {
        /* the parent tries to raise its OWN cap while re-rooting its children */
        let mut c = base1();
        let (tree, path) = c.tree.materialize();
        let chain = chain_proofs(&tree, &path);
        let mut raised = chain[0].0.clone();
        raised.max_per_spend = 100_000;
        raised.child_root = c.dsc_new_child_root;
        c.new_root_override = Some(fold(hd_leaf_hash(&raised), &chain[0].1, chain[0].2));
        refuse("delegateSetChildRoot1 raising the parent's own cap in the refold", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = base1();
        c.new_root_override = Some([0x33; 32]);
        refuse("delegateSetChildRoot1 successor root misreport", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = base1();
        c.dsc_new_child_root = ZERO32;
        c.tree.depth = 1; // the parent already has no children -> no-op
        refuse("delegateSetChildRoot1 no-op (childRoot unchanged)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = base1();
        c.prev_paused = 1;
        c.succ_paused_override = Some(1);
        refuse("delegation while the vault is PAUSED (OQ-HD-3)", &c, &mut failures, &mut refusals);
    }
    {
        let mut c = base1();
        c.dsc_tokens_ride = true;
        refuse("tokens riding a delegation op", &c, &mut failures, &mut refusals);
    }
    {
        /* a level-2 leaf presented to the LEVEL-1 delegation entrypoint */
        let mut c = base2();
        c.entry = 1;
        c.slice_end_anchored = true; // present the LEVEL-2 leaf to the level-1 entrypoint
        refuse("level-2 parent presented to delegateSetChildRoot1", &c, &mut failures, &mut refusals);
    }
    {
        /* a level-3 leaf trying to delegate at all (no entrypoint accepts it) */
        let mut c = honest_spend(Variant::L3, 3);
        c.op = Op::Dsc;
        c.entry = 2;
        c.slice_end_anchored = true; // present [B, C] so the level-3 leaf is the "parent"
        c.signer_seed = C_SEED;
        c.dsc_new_child_root = [0x9a; 32];
        refuse("level-3 leaf attempting delegateSetChildRoot2 (> MAX_LEVEL delegation)", &c, &mut failures, &mut refusals);
    }
    for (label, ty) in [("NONE", SIG_HASH_NONE), ("SINGLE", SIG_HASH_SINGLE), ("ANYONECANPAY", SIG_HASH_ANY_ONE_CAN_PAY)] {
        let mut c = base1();
        c.sighash = ty;
        refuse(&format!("SIGHASH_{label} on delegateSetChildRoot1"), &c, &mut failures, &mut refusals);
    }
    {
        let mut c = base1();
        c.mutate_after_sign = true;
        refuse("post-sign mutation on delegateSetChildRoot1", &c, &mut failures, &mut refusals);
    }
    {
        /* stale parent leaf on the delegation path */
        let mut c = base1();
        let mut moved = c.tree.clone();
        moved.l1[0].period_spent += 50;
        c.prev_root_override = Some(forest_root_of(&moved));
        refuse("delegateSetChildRoot1 against a stale parent leaf", &c, &mut failures, &mut refusals);
    }
    {
        /* the grandparent's membership must hold on the level-2 path */
        let mut c = base2();
        let mut removed = c.tree.clone();
        removed.l1 = vec![removed.l1[1].clone()];
        removed.l1_target = 0;
        removed.depth = 1;
        c.prev_root_override = Some(forest_root_of(&removed));
        refuse("delegateSetChildRoot2 with a removed grandparent", &c, &mut failures, &mut refusals);
    }

    assert!(failures.is_empty(), "hierarchical-delegation delegation matrix failures:\n{}", failures.join("\n"));
    println!("\n  hostile delegation rows refused: {}", refusals.len());
}

/* ---------------------------------------------------------------- */
/* CROSS-FORMAT: the FROZEN v0.5 covenant must refuse an HD tree      */
/* ---------------------------------------------------------------- */

/// Drive the FROZEN `contracts/PolicyVault.v0.5.sil` with an agentRoot that
/// was committed with HD-format leaves. The v0.5 covenant recomputes the
/// 125-byte 0x50563501 leaf, so membership can never succeed — the two leaf
/// domains are disjoint in BOTH directions.
#[test]
fn hd_cross_format_frozen_v5_refuses_an_hd_committed_tree() {
    let owner_pk = xonly(&owner_kp());
    let fuel = fuel_kp();
    let fuel_pk = xonly(&fuel);
    let recipient_pk = xonly(&recipient_kp());
    let src = frozen_v5_source();

    let tok_ref = compile_kcc20(COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
    let tpl = template_of(&tok_ref);
    let pin = Pin {
        token_covid: COV_TOKEN,
        template_hash: tpl.hash,
        prefix_len: tpl.prefix.len() as i64,
        state_len: tpl.state_len as i64,
        suffix_len: tpl.suffix.len() as i64,
    };

    let scen = honest_spend(Variant::L1, 1);
    let (tree, path) = scen.tree.materialize();
    let chain = chain_proofs(&tree, &path);
    let (leaf, sibs, bits) = chain[0].clone();
    let (_rroot, rsibs, rbits) = recip_tree(scen.recip[0].depth, &scen.recip[0].target, scen.recip[0].salt);
    let hd_root = forest_root(&tree);
    /* the SAME forest committed with the frozen v0.5 leaf hash (its own co-path) */
    let v5_leaves: Vec<[u8; 32]> = tree.iter().map(|n| v5_leaf_hash(&resolved(n))).collect();
    let (v5_root, v5_sibs, v5_bits) = merkle(&v5_leaves, path[0]);
    assert_eq!(v5_root, forest_root_v5_format(&tree));
    assert_ne!(hd_root, v5_root, "the two leaf domains must produce different roots");

    let spend = scen.spend;
    let self_id: [u8; 32] = COV_CTRL.as_bytes().try_into().unwrap();
    let self_after = PREV_TOKEN_AMOUNT - spend;

    let run_with_root = |root: [u8; 32], sibs: &[u8], bits: u64| -> Result<(), TxScriptError> {
        let prev = S { reserve: RESERVE, paused: 0, agent_root: root, policy_nonce: 0 };
        let ctrl_prev = compile_ctrl(&src, &owner_pk, &pin, &prev, &VAULT_ID);
        /* the v0.5 successor root is the v0.5-format refold */
        let mut advanced = leaf.clone();
        advanced.period_spent = leaf.period_spent + spend;
        let new_root = fold(v5_leaf_hash(&advanced), sibs, bits);
        let new_state = S { reserve: RESERVE - RESERVE_CONSUMED, agent_root: new_root, ..prev.clone() };
        let ctrl_next = compile_ctrl(&src, &owner_pk, &pin, &new_state, &VAULT_ID);

        let tok_prev = compile_kcc20(self_id, IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
        let tok_self = compile_kcc20(self_id, IDENTIFIER_COVENANT_ID, self_after, false, 2);
        let tok_recipient = compile_kcc20(recipient_pk, IDENTIFIER_PUBKEY, spend, false, 2);

        let outputs = vec![
            cov_out(new_state.reserve, &ctrl_next, 0, COV_CTRL),
            cov_out(TOKEN_CARRY - RECIPIENT_CARRY, &tok_self, 1, COV_TOKEN),
            cov_out(RECIPIENT_CARRY, &tok_recipient, 1, COV_TOKEN),
            p2pk_out(&fuel_pk, FUEL - (FEE - RESERVE_CONSUMED)),
        ];
        let inputs = vec![input(1, 0, vec![], 600), input(2, 0, vec![], 200), input(3, 0, vec![], 20)];
        let entries = vec![
            cov_utxo(prev.reserve, &ctrl_prev, COV_CTRL),
            cov_utxo(TOKEN_CARRY, &tok_prev, COV_TOKEN),
            UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None),
        ];
        let unsigned = Transaction::new(1, inputs.clone(), outputs.clone(), 0, SubnetworkId::default(), 0, vec![]);
        let sig = sign_typed(&unsigned, &entries, 0, &kp(A1_SEED), SIG_HASH_ALL);
        let fuel_sig = sign_typed(&unsigned, &entries, 2, &fuel, SIG_HASH_ALL);
        let args: Vec<Expr<'static>> = vec![
            state_arg(&new_state, &VAULT_ID),
            kcc20_state(self_id, IDENTIFIER_COVENANT_ID, self_after, false),
            kcc20_state(recipient_pk, IDENTIFIER_PUBKEY, spend, false),
            Expr::bytes(leaf.pk.to_vec()),
            Expr::int(leaf.max_per_spend),
            Expr::int(leaf.period_budget),
            Expr::int(leaf.period_length_daa),
            Expr::int(leaf.period_start_daa),
            Expr::int(leaf.period_spent),
            Expr::int(leaf.max_fee_per_tx),
            Expr::int(leaf.max_carry_kas),
            Expr::bytes(leaf.recipient_root.to_vec()),
            Expr::bytes(sibs.to_vec()),
            Expr::int(bits as i64),
            Expr::int(0),
            Expr::bytes(recipient_pk.to_vec()),
            Expr::bytes(rsibs.clone()),
            Expr::int(rbits as i64),
            Expr::bytes(sig),
        ];
        let mut signed = inputs.clone();
        signed[0].signature_script = cov_call_opt(&ctrl_prev, "tokenAgentSpend", args, false);
        signed[1].signature_script = cov_call_opt(
            &tok_prev,
            "transfer",
            vec![
                vec![
                    kcc20_state(self_id, IDENTIFIER_COVENANT_ID, self_after, false),
                    kcc20_state(recipient_pk, IDENTIFIER_PUBKEY, spend, false),
                ]
                .into(),
                Vec::<Expr>::new().into(),
                Expr::bytes(vec![0u8]),
            ],
            true,
        );
        signed[2].signature_script = p2pk_sigscript(fuel_sig);
        let tx = Transaction::new(1, signed, outputs, 0, SubnetworkId::default(), 0, vec![]);
        execute_input_measured(tx, entries, 0).0
    };

    /* positive control: the SAME transaction with a v0.5-format tree is accepted */
    run_with_root(v5_root, &v5_sibs, v5_bits).expect("frozen v0.5 must accept its own leaf format (positive control)");
    /* the HD-format tree is refused by the frozen v0.5 covenant */
    let err = run_with_root(hd_root, &sibs, bits).expect_err("frozen v0.5 must REFUSE an HD-format committed tree");
    println!("  REFUSED frozen v0.5 driven with an HD-format agentRoot                  {err:?}");
}

/* ---------------------------------------------------------------- */
/* MEASUREMENT                                                        */
/* ---------------------------------------------------------------- */

fn priced(b: &Built, i: usize) -> (u64, u16, u16) {
    let (r, u) = execute_input_measured_priced(b.tx.clone(), b.entries.clone(), i, 1000);
    r.unwrap_or_else(|e| panic!("priced input {i} must accept: {e:?}"));
    let budget = ComputeBudget::checked_covering_script_units(ScriptUnits(u)).expect("budget").0;
    let sigops = post_toccata_p2sh_sig_scanner(&b.tx.inputs[i].signature_script, &b.entries[i].script_public_key);
    (u, budget, sigops as u16)
}

fn padded_run(b: &Built, pad: usize) -> Result<(), TxScriptError> {
    let mut tx = b.tx.clone();
    let mut pushes = ScriptBuilder::new();
    for _ in 0..pad {
        pushes.add_data(&[0x01u8]).unwrap();
    }
    let mut ss = pushes.drain();
    ss.extend_from_slice(&tx.inputs[0].signature_script);
    tx.inputs[0].signature_script = ss;
    execute_input_measured(tx, b.entries.clone(), 0).0
}

/// Smallest front-padding that turns acceptance into StackSizeExceeded;
/// peak combined stack = 245 - that count (v0.7 phase-2 method).
fn measure_peak_stack(label: &str, b: &Built) -> usize {
    padded_run(b, 0).unwrap_or_else(|e| panic!("{label}: unpadded run must accept: {e:?}"));
    let exceeds = |pad: usize| matches!(padded_run(b, pad), Err(TxScriptError::StackSizeExceeded(_, _)));
    assert!(exceeds(244), "{label}: padding by 244 must exceed MAX_STACK_SIZE");
    let (mut lo, mut hi) = (1usize, 244usize);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if exceeds(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    /* below the threshold the padded run fails for OTHER reasons (the pad
     * items are left on the stack -> CleanStack); only the FIRST pad that
     * turns the failure into StackSizeExceeded marks the peak. */
    let peak = 245 - lo;
    println!("  {label:<52} peak combined stack {peak:>4} / 244  -> headroom {:>4}", 244 - peak);
    peak
}

/// Two-pass compute-budget selection (the v0.5 measurement method): price
/// the inputs, commit the smallest covering budget, rebuild, and confirm the
/// consumed units do not depend on the committed budget. Without this the
/// measured mass reflects an over-declared budget, not the real cost.
fn with_covering_budgets(mut c: Scen) -> Scen {
    let b0 = build(&c);
    let n = b0.tx.inputs.len();
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        let (r, u) = execute_input_measured_priced(b0.tx.clone(), b0.entries.clone(), i, 1000);
        r.unwrap_or_else(|e| panic!("budget pass 1: input {i} must accept: {e:?}"));
        units.push(u);
    }
    let bud = |u: u64| ComputeBudget::checked_covering_script_units(ScriptUnits(u)).expect("covering budget").0;
    c.budgets = (bud(units[0]), if n > 2 { bud(units[1]) } else { 200 }, bud(units[n - 1]));
    let b1 = build(&c);
    for i in 0..n {
        let (r, u) = execute_input_measured_priced(b1.tx.clone(), b1.entries.clone(), i, 1000);
        r.unwrap_or_else(|e| panic!("budget pass 2: input {i} must accept: {e:?}"));
        assert_eq!(u, units[i], "script units must not depend on the committed compute budget");
    }
    c
}

fn mass_of(tx: &Transaction) -> (u64, u64, u64, u64) {
    let mc = MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER);
    let m = mc.calc_non_contextual_masses(tx);
    let size = transaction_estimated_serialized_size(tx);
    let normalized_transient = (m.transient_mass * 500_000).div_ceil(1_000_000);
    (size, m.compute_mass, m.transient_mass, m.compute_mass.max(normalized_transient))
}

fn deep(mut c: Scen) -> Scen {
    /* agent proof depth 12 (4096 level-1 leaves), child proof depth 8 (256
     * children per level), recipient proof depth 16 at EVERY level */
    c.tree.l1_pad = 4096;
    c.tree.kid_pad = 256;
    for lvl in 0..4 {
        let target = c.recip[lvl].target;
        set_recip(&mut c, lvl, 16, target);
    }
    c.budgets = (60000, 200, 20);
    c
}

#[test]
fn hd_measurement_redeem_units_mass_sigops_and_stack() {
    println!("\n===== HIERARCHICAL DELEGATION PROBE — MEASUREMENT (real TxScriptEngine, rusty-kaspa 2.0.1) =====");

    /* ---- 1. redeem geometry per MAX_LEVEL, against the FROZEN v0.5 ---- */
    let owner_pk = xonly(&owner_kp());
    let tok_ref = compile_kcc20(COV_CTRL.as_bytes().try_into().unwrap(), IDENTIFIER_COVENANT_ID, PREV_TOKEN_AMOUNT, false, 2);
    let tpl = template_of(&tok_ref);
    let pin = Pin {
        token_covid: COV_TOKEN,
        template_hash: tpl.hash,
        prefix_len: tpl.prefix.len() as i64,
        state_len: tpl.state_len as i64,
        suffix_len: tpl.suffix.len() as i64,
    };
    let st = S { reserve: RESERVE, paused: 0, agent_root: [0x11; 32], policy_nonce: 0 };
    let v5 = compile_ctrl(&frozen_v5_source(), &owner_pk, &pin, &st, &VAULT_ID);
    let v5_len = v5.script.len();
    println!("\n[1] REDEEM GEOMETRY (identical template pins and state)");
    println!("  {:<34} | {:>10} | {:>12} | {:>10}", "covenant", "redeem B", "vs frozen v0.5", "state B");
    println!("  {:<34} | {:>10} | {:>12} | {:>10}", "FROZEN PolicyVault.v0.5.sil", v5_len, "-", v5.state_layout.len);
    let mut redeem: Vec<(Variant, usize)> = vec![];
    for v in [Variant::L1, Variant::L2, Variant::L3] {
        let c = compile_ctrl(&hd_source(v), &owner_pk, &pin, &st, &VAULT_ID);
        println!(
            "  {:<34} | {:>10} | {:>+12} | {:>10}",
            format!("HDProbe {v:?} (MAX_LEVEL {})", if v == Variant::L1 { 1 } else if v == Variant::L2 { 2 } else { 3 }),
            c.script.len(),
            c.script.len() as i64 - v5_len as i64,
            c.state_layout.len
        );
        redeem.push((v, c.script.len()));
    }
    assert_eq!(v5.state_layout.len, 93, "the v0.5 state region must be the 93-byte shape");

    /* ---- 2. per-operation cost ---- */
    println!("\n[2] PER-OPERATION COST (shallow proofs: agent depth 1, child depth 1, recipient depth 0)");
    println!(
        "  {:<40} | {:>9} | {:>11} | {:>12} | {:>6} | {:>7} | {:>9} | {:>9} | {:>9} | {:>7}",
        "operation", "sigscr B", "units", "priced units", "budget", "tx B", "compute", "transient", "fee mass", "sig-ops"
    );
    let mut rows: Vec<(String, usize, u64, u16)> = vec![];
    let cases: Vec<(String, Scen)> = vec![
        ("L1 variant: level-1 spend".into(), honest_spend(Variant::L1, 1)),
        ("L2 variant: level-1 spend".into(), honest_spend(Variant::L2, 1)),
        ("L2 variant: level-2 spend".into(), honest_spend(Variant::L2, 2)),
        ("L2 variant: delegateSetChildRoot1".into(), honest_dsc(Variant::L2, 1).0),
        ("L3 variant: level-1 spend".into(), honest_spend(Variant::L3, 1)),
        ("L3 variant: level-2 spend".into(), honest_spend(Variant::L3, 2)),
        ("L3 variant: level-3 spend".into(), honest_spend(Variant::L3, 3)),
        ("L3 variant: delegateSetChildRoot1".into(), honest_dsc(Variant::L3, 1).0),
        ("L3 variant: delegateSetChildRoot2".into(), honest_dsc(Variant::L3, 2).0),
        ("L3 variant: ownerRecover".into(), {
            let mut c = owner_case(Variant::L3, Op::OwnerRecover);
            c.budgets = (6000, 200, 20);
            c
        }),
    ];
    for (label, c) in cases {
        let c = with_covering_budgets(c);
        let b = accepts(&label, &c);
        let (units, budget, sigops) = priced(&b, 0);
        let (_r, plain) = execute_input_measured(b.tx.clone(), b.entries.clone(), 0);
        let (size, cm, tm, fee_mass) = mass_of(&b.tx);
        println!(
            "  {:<40} | {:>9} | {:>11} | {:>12} | {:>6} | {:>7} | {:>9} | {:>9} | {:>9} | {:>7}",
            label,
            b.tx.inputs[0].signature_script.len(),
            plain,
            units,
            budget,
            size,
            cm,
            tm,
            fee_mass,
            sigops
        );
        assert!(sigops <= 15, "{label}: static sig-ops must stay inside MAX_STANDARD_P2SH_SIG_OPS");
        assert!(fee_mass <= 500_000, "{label}: fee mass must fit the 500,000 block compute-mass limit");
        rows.push((label, b.tx.inputs[0].signature_script.len(), plain, sigops));
    }

    /* ---- 3. maximum-depth shapes ---- */
    println!("\n[3] MAXIMUM-DEPTH SHAPES (agent depth 12, child depth 8 per level, recipient depth 16 per level)");
    println!(
        "  {:<40} | {:>9} | {:>11} | {:>12} | {:>6} | {:>7} | {:>9} | {:>9} | {:>9} | {:>7}",
        "operation", "sigscr B", "units", "priced units", "budget", "tx B", "compute", "transient", "fee mass", "sig-ops"
    );
    let deep_cases: Vec<(String, Scen)> = vec![
        ("L1 variant: level-1 spend (deep)".into(), deep(honest_spend(Variant::L1, 1))),
        ("L3 variant: level-2 spend (deep)".into(), deep(honest_spend(Variant::L3, 2))),
        ("L3 variant: level-3 spend (deep)".into(), deep(honest_spend(Variant::L3, 3))),
        ("L3 variant: delegateSetChildRoot2 (deep)".into(), deep(honest_dsc(Variant::L3, 2).0)),
    ];
    let mut deep_built: Vec<(String, Built)> = vec![];
    for (label, c) in deep_cases {
        let c = with_covering_budgets(c);
        let b = accepts(&label, &c);
        let (units, budget, sigops) = priced(&b, 0);
        let (_r, plain) = execute_input_measured(b.tx.clone(), b.entries.clone(), 0);
        let (size, cm, tm, fee_mass) = mass_of(&b.tx);
        println!(
            "  {:<40} | {:>9} | {:>11} | {:>12} | {:>6} | {:>7} | {:>9} | {:>9} | {:>9} | {:>7}",
            label,
            b.tx.inputs[0].signature_script.len(),
            plain,
            units,
            budget,
            size,
            cm,
            tm,
            fee_mass,
            sigops
        );
        assert!(sigops <= 15, "{label}: static sig-ops must stay standard");
        assert!(fee_mass <= 500_000, "{label}: fee mass must fit the 500,000 block compute-mass limit");
        deep_built.push((label, b));
    }

    /* ---- 4. MAX_STACK_SIZE headroom ---- */
    println!("\n[4] MAX_STACK_SIZE (244) HEADROOM");
    for (label, b) in deep_built.iter() {
        measure_peak_stack(label, b);
    }
    let shallow3 = accepts("L3 shallow for stack", &honest_spend(Variant::L3, 3));
    measure_peak_stack("L3 variant: level-3 spend (shallow)", &shallow3);

    /* ---- 5. static sig-op accounting per variant ---- */
    println!("\n[5] STATIC SIG-OPS PER VARIANT (MAX_STANDARD_P2SH_SIG_OPS = 15)");
    for (v, entrypoints) in [(Variant::L1, "hdSpend, ownerControl, ownerRecover"), (Variant::L2, "+ childSpendL2, delegateSetChildRoot1"), (Variant::L3, "+ childSpendL3, delegateSetChildRoot2")] {
        let c = honest_spend(v, 1);
        let b = accepts("sigop sample", &c);
        let (_u, _bud, sigops) = priced(&b, 0);
        println!("  {v:?}: {sigops} static sig-ops   ({entrypoints})");
        assert!(sigops <= 15);
    }
    println!("\n===============================================================================================\n");
}

/// MAX_STACK_SIZE accounting: the peak combined stack of every entrypoint,
/// and the marginal cost of one delegation level, measured on the real
/// engine. This is what decides MAX_LEVEL.
#[test]
fn hd_measurement_stack_accounting_per_level() {
    println!("\n[STACK] peak combined stack per entrypoint (MAX_STACK_SIZE = 244)");
    let mut rows: Vec<(String, usize)> = vec![];
    for (label, c) in [
        ("full: level-1 spend".to_string(), honest_spend(Variant::L3, 1)),
        ("full: level-2 spend".to_string(), honest_spend(Variant::L3, 2)),
        ("full: level-3 spend".to_string(), honest_spend(Variant::L3, 3)),
        ("full: delegateSetChildRoot1".to_string(), honest_dsc(Variant::L3, 1).0),
        ("full: delegateSetChildRoot2".to_string(), honest_dsc(Variant::L3, 2).0),
        ("stack-accounting: level-1 spend".to_string(), { let mut c = honest_spend(Variant::L3, 1); c.no_token_binding = true; c }),
        ("stack-accounting: level-2 spend".to_string(), { let mut c = honest_spend(Variant::L3, 2); c.no_token_binding = true; c }),
        ("stack-accounting: level-3 spend".to_string(), { let mut c = honest_spend(Variant::L3, 3); c.no_token_binding = true; c }),
    ] {
        let b = build(&c);
        match execute_input_measured(b.tx.clone(), b.entries.clone(), 0).0 {
            Err(e) => println!("  {label}: does not accept ({e:?})"),
            Ok(()) => rows.push((label.clone(), measure_peak_stack(&label, &b))),
        }
    }
    let get = |k: &str| rows.iter().find(|(l, _)| l == k).map(|(_, p)| *p);
    let (f1, f2) = (get("full: level-1 spend").unwrap(), get("full: level-2 spend").unwrap());
    let f3 = get("full: level-3 spend").unwrap();
    let (s2, s3) = (get("stack-accounting: level-2 spend").unwrap(), get("stack-accounting: level-3 spend").unwrap());
    println!("  token dual-binding block costs {} stack items on top of the chain logic", f2 - s2);
    println!("  marginal cost of one delegation level: L1->L2 {} items, L2->L3 {} items", f2 - f1, f3 - f2);
    let l4 = f3 + (f3 - f2);
    println!("  extrapolated level-4 spend: {l4} items -> {} MAX_STACK_SIZE 244", if l4 <= 244 { "WITHIN" } else { "OVER" });
    println!("  chain logic alone: level-2 {s2}, level-3 {s3}");
    assert!(f3 <= 244, "a full level-3 spend must fit MAX_STACK_SIZE");
    assert!(l4 > 244, "the MAX_LEVEL 3 recommendation rests on level 4 NOT fitting");
}

/* ---------------------------------------------------------------- */
/* SABOTAGE SENSITIVITY — each NEW hierarchical guard is load-bearing */
/* ---------------------------------------------------------------- */

/// For every guard: with the covenant INTACT the attack is refused, and with
/// exactly that guard removed the SAME attack is accepted by the real engine.
/// Without this, a matrix of refusals proves only that something failed.
#[test]
fn hd_sabotage_hierarchical_guards_are_load_bearing() {
    let outsider = xonly(&kp(OUTSIDER_SEED));
    type Mut = fn(&mut Scen);
    let cases: Vec<(&str, (&'static str, &'static str), Mut)> = vec![
        (
            "per-level cap intersection",
            ("        require(amount <= OpBin2Num(body.slice(32, 40)));\n", ""),
            |c: &mut Scen| {
                c.tree.l3[0].max_per_spend = 400;
                c.tree.l3[0].period_budget = 1000;
                c.tree.l2[0].max_per_spend = 400;
                c.tree.l2[0].period_budget = 1000;
                c.spend = 300; // beyond the level-1 cap of 250
            },
        ),
        (
            "per-level recipient allowlist intersection",
            (
                "        requireRecipientMember(body.slice(96, 128), recipientPk, recipientSiblings, recipientPathBits);\n",
                "        require(recipientSiblings.length >= 0);\n",
            ),
            |c: &mut Scen| set_recip(c, 0, 0, xonly(&kp(OUTSIDER_SEED))),
        ),
        (
            "nested refold pins the successor agentRoot (parent counter must advance)",
            (
                "        require(bytes(newState.agentRoot) == levelStep(a1, recipientNew.amount, periodsElapsed1, bytes(prevState.agentRoot), siblings1, pathBits1, sub, recipientPk, recipientSiblings1, recipientPathBits1, 1));",
                "        require(levelStep(a1, recipientNew.amount, periodsElapsed1, bytes(prevState.agentRoot), siblings1, pathBits1, sub, recipientPk, recipientSiblings1, recipientPathBits1, 1).length == 32);",
            ),
            |c: &mut Scen| c.cheat_unadvanced_level = Some(0),
        ),
        /* NOTE: the chain-position level pin is STRUCTURAL — the level is a
         * covenant constant inside the leaf preimage, not a removable
         * `require` — so it is proven by the four hostile rows that present
         * a leaf at the wrong position, not by guard removal. */
        (
            "fee cap = minimum over the chain",
            (
                "            OpBin2Num(a1.slice(72, 80)) < OpBin2Num(a2.slice(72, 80)) ? (OpBin2Num(a1.slice(72, 80)) < OpBin2Num(leaf.slice(72, 80)) ? OpBin2Num(a1.slice(72, 80)) : OpBin2Num(leaf.slice(72, 80))) : (OpBin2Num(a2.slice(72, 80)) < OpBin2Num(leaf.slice(72, 80)) ? OpBin2Num(a2.slice(72, 80)) : OpBin2Num(leaf.slice(72, 80))),",
                "            OpBin2Num(leaf.slice(72, 80)),",
            ),
            |c: &mut Scen| {
                c.tree.l3[0].max_fee_per_tx = 100_000;
                c.tree.l1[0].max_fee_per_tx = 20_000;
                c.reserve_consumed = 30_000;
            },
        ),
        (
            "carry cap = minimum over the chain",
            (
                "            OpBin2Num(a1.slice(80, 88)) < OpBin2Num(a2.slice(80, 88)) ? (OpBin2Num(a1.slice(80, 88)) < OpBin2Num(leaf.slice(80, 88)) ? OpBin2Num(a1.slice(80, 88)) : OpBin2Num(leaf.slice(80, 88))) : (OpBin2Num(a2.slice(80, 88)) < OpBin2Num(leaf.slice(80, 88)) ? OpBin2Num(a2.slice(80, 88)) : OpBin2Num(leaf.slice(80, 88))));",
                "            OpBin2Num(leaf.slice(80, 88)));",
            ),
            |c: &mut Scen| {
                c.tree.l3[0].max_carry_kas = KAS;
                c.tree.l1[0].max_carry_kas = KAS / 20;
                c.recipient_carry = KAS / 10;
            },
        ),
        (
            "expiry consistency (child may not outlive its parent)",
            ("        require(OpBin2Num(leaf.slice(88, 96)) <= OpBin2Num(a2.slice(88, 96)));\n", ""),
            |c: &mut Scen| c.tree.l3[0].expiry_daa = 9_500_000,
        ),
        (
            "delegation may change ONLY the parent's childRoot",
            (
                "        require(newState.policyNonce == prevState.policyNonce);\n        require(bytes(descriptorHash) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));\n        require(computeMerkleRoot(hdLeafHash(parentLeaf, 1), siblings1, pathBits1) == bytes(prevState.agentRoot));",
                "        require(bytes(descriptorHash) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));\n        require(computeMerkleRoot(hdLeafHash(parentLeaf, 1), siblings1, pathBits1) == bytes(prevState.agentRoot));",
            ),
            |c: &mut Scen| {
                c.op = Op::Dsc;
                c.entry = 1;
                c.slice_end_anchored = false;
                c.signer_seed = A1_SEED;
                c.tree.depth = 1;
                c.dsc_new_child_root = [0x7c; 32];
                c.succ_nonce_override = Some(1);
            },
        ),
    ];
    let _ = outsider;
    for (label, (anchor, replacement), m) in cases {
        let mut intact = honest_spend(Variant::L3, 3);
        m(&mut intact);
        let (r, _) = run(&intact);
        assert!(r.is_err(), "{label}: the INTACT covenant must refuse the attack");
        let mut sabotaged = intact.clone();
        sabotaged.src_mutation = Some((anchor, replacement));
        let (r2, _) = run(&sabotaged);
        r2.unwrap_or_else(|e| panic!("{label}: with the guard removed the SAME attack must pass (else the guard is not what refuses it): {e:?}"));
        println!("  LOAD-BEARING {label}");
    }
}
