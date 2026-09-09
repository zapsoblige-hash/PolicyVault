//! INDEPENDENT ADVERSARIAL REVIEW of the v0.7 organizational M-of-N owner
//! root byte-freeze candidates, on the REAL TxScriptEngine (covenants
//! enabled, real Schnorr signatures), exactly as the existing production
//! suites do. This suite is ADDITIVE: it reads
//! `contracts/PolicyVault.v0.7-root.sil` (`PolicyVaultOrgRoot`) and
//! `contracts/PolicyVault.v0.7-payment.sil` (`PolicyVaultRootedToken`)
//! READ-ONLY and never modifies them, `tools/gen_v7_*.js`, `pv_call_encoder`,
//! or the existing `v7_root_production.rs` / `v7_payment_production.rs` /
//! `v7_sdk_integration.rs` suites.
//!
//! It also reads the measurement-only
//! `contracts/experiments/V7ReviewNoD1.sil` — the candidate root with
//! deviation D1 ("rootSuccession must install a different primary key")
//! deliberately removed — to measure what D1 protects against. That file is
//! NEVER an acceptance candidate.
//!
//! Goal: FALSIFY the freeze, not confirm it. Every row here is a NEW hostile
//! knob not already exercised by `v7_root_production.rs` /
//! `v7_payment_production.rs` (their existing 47/50 root-side and 37/38
//! vault-side rows, the threshold sweep, and the D2/D6 rows are NOT
//! reproduced here). See `docs/postlaunch/v0.7-adversarial-review.md` for
//! the verdict and the classified findings list.

use std::sync::OnceLock;

use secp256k1::Keypair;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CompiledContract, CovenantDeclCallOptions};

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL};
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::{pay_to_script_hash_script, script_builder::ScriptBuilder, EngineFlags};
use kaspa_txscript_errors::TxScriptError;
use policyvault_vm_tests::execute_input_measured;

/* ================================================================== */
/* constants                                                           */
/* ================================================================== */

const N_SLOTS: usize = 12;
const SIG_BLOB_LEN: usize = N_SLOTS * 65; // 780

const COV_ROOT: Hash = Hash::from_bytes(*b"RRVWRRVWRRVWRRVWRRVWRRVWRRVWRRVW");
const COV_VAULT: Hash = Hash::from_bytes(*b"VVLAVVLAVVLAVVLAVVLAVVLAVVLAVVLA");
const COV_VAULT_B: Hash = Hash::from_bytes(*b"VVLBVVLBVVLBVVLBVVLBVVLBVVLBVVLB");
const COV_TOKEN_DUMMY: Hash = Hash::from_bytes(*b"TTKNTTKNTTKNTTKNTTKNTTKNTTKNTTKN");

const ZERO32: [u8; 32] = [0u8; 32];
const ORG_ID: [u8; 32] = [0xa7u8; 32];
const VAULT_ID: [u8; 32] = [0x44u8; 32];
const DESCRIPTOR_HASH: [u8; 32] = [0xd5u8; 32];

const KAS: i64 = 100_000_000;
const ROOT_KAS: i64 = 3 * KAS;
const ROOT_MAX_FEE: i64 = 200_000;
const ROOT_FEE_PAID: i64 = 50_000;
const RECOVERY_DELAY: i64 = 1_000;
const SUCCESSION_DELAY: i64 = 2_000;

const RESERVE: i64 = 5 * KAS;
const FUEL: i64 = KAS;
const FEE: i64 = 100_000;

const OWNER_SEEDS: [u8; N_SLOTS] = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c];
const SUCCESSOR_SEED: u8 = 0x7f;

/* ================================================================== */
/* shared low-level helpers (mirrors v7_root_production.rs /            */
/* v7_payment_production.rs; duplicated here since integration test     */
/* binaries cannot share a module, and the existing suites are          */
/* off-limits to edit)                                                  */
/* ================================================================== */

fn kp(seed: u8) -> Keypair {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).expect("seed key");
    Keypair::from_secret_key(&secp, &sk)
}
fn xonly32(k: &Keypair) -> [u8; 32] {
    k.x_only_public_key().0.serialize()
}
fn num8(v: i64) -> [u8; 8] {
    (v as u64).to_le_bytes()
}
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
fn load(rel: &str) -> String {
    let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}
/// THE PRODUCTION CANDIDATE root.
fn src_root() -> &'static str {
    static S: OnceLock<&'static str> = OnceLock::new();
    S.get_or_init(|| leak(load("../../contracts/PolicyVault.v0.7-root.sil")))
}
/// THE PRODUCTION CANDIDATE rooted payment profile.
fn src_vault_raw() -> &'static str {
    static S: OnceLock<&'static str> = OnceLock::new();
    S.get_or_init(|| leak(load("../../contracts/PolicyVault.v0.7-payment.sil")))
}
/// The FROZEN v0.5 controller — READ-ONLY, used only as an impostor "root"
/// for the cross-generation-substitution probe.
fn src_v5_raw() -> &'static str {
    static S: OnceLock<&'static str> = OnceLock::new();
    S.get_or_init(|| leak(load("../../contracts/PolicyVault.v0.5.sil")))
}
/// MEASUREMENT-ONLY: the candidate root with deviation D1 removed. Never an
/// acceptance candidate; see the file's own header comment.
fn src_no_d1() -> &'static str {
    static S: OnceLock<&'static str> = OnceLock::new();
    S.get_or_init(|| leak(load("../../contracts/experiments/V7ReviewNoD1.sil")))
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

fn push_redeem(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() }).add_data(script).unwrap().drain()
}
fn cov_call(c: &CompiledContract<'_>, f: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut s = c
        .build_sig_script_for_covenant_decl(f, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|e| panic!("call {f}: {e:?}"));
    s.extend_from_slice(&push_redeem(&c.script));
    s
}
fn tx_input(id: u8, sigscript: Vec<u8>, sequence: u64, budget: u16) -> TransactionInput {
    TransactionInput::new_with_mass(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([id; 32]), index: 0 },
        sigscript,
        sequence,
        ComputeCommit::ComputeBudget(ComputeBudget(budget)),
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
fn p2pk_sigscript(sig: Vec<u8>) -> Vec<u8> {
    ScriptBuilder::new().add_data(&sig).unwrap().drain()
}
fn build_tx(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
    Transaction::new(1, inputs, outputs, 0, SubnetworkId::default(), 0, vec![])
}
fn sign_type(tx: &Transaction, entries: &[UtxoEntry], idx: usize, k: &Keypair, ht: SigHashType) -> Vec<u8> {
    let m = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    let h = calc_schnorr_signature_hash(&m.as_verifiable(), idx, ht, &reused);
    let msg = secp256k1::Message::from_digest_slice(h.as_bytes().as_slice()).unwrap();
    let mut out = k.sign_schnorr(msg).as_ref().to_vec();
    out.push(ht.to_u8());
    out
}
fn sign(tx: &Transaction, entries: &[UtxoEntry], idx: usize, k: &Keypair) -> Vec<u8> {
    sign_type(tx, entries, idx, k, SIG_HASH_ALL)
}
/// The canonical abstaining slot: 64 zero bytes + the SIGHASH_ALL gate byte.
fn placeholder_slot() -> Vec<u8> {
    let mut v = vec![0u8; 64];
    v.push(0x01);
    v
}

/* ================================================================== */
/* root covenant (parameterized over SOURCE, so the same helpers serve  */
/* the real candidate and the measurement-only D1 sabotage)             */
/* ================================================================== */

#[derive(Clone, PartialEq, Debug)]
struct RootState {
    org_id: [u8; 32],
    owners: [[u8; 32]; N_SLOTS],
    owner_m: i64,
    emergency_k: i64,
    recovery_m: i64,
    frozen: i64,
    nonce: i64,
}
impl RootState {
    fn with(n: usize, m: i64, k: i64, r: i64) -> RootState {
        let mut owners = [ZERO32; N_SLOTS];
        for (i, o) in owners.iter_mut().enumerate().take(n) {
            *o = xonly32(&kp(OWNER_SEEDS[i]));
        }
        RootState { org_id: ORG_ID, owners, owner_m: m, emergency_k: k, recovery_m: r, frozen: 0, nonce: 0 }
    }
    fn advanced(&self) -> RootState {
        RootState { nonce: self.nonce + 1, ..self.clone() }
    }
}

#[derive(Clone)]
struct RootTemplate {
    recovery_delay: i64,
    successor_pk: [u8; 32],
    succession_delay: i64,
    max_fee: i64,
}
impl Default for RootTemplate {
    fn default() -> Self {
        RootTemplate {
            recovery_delay: RECOVERY_DELAY,
            successor_pk: xonly32(&kp(SUCCESSOR_SEED)),
            succession_delay: SUCCESSION_DELAY,
            max_fee: ROOT_MAX_FEE,
        }
    }
}

fn compile_root(src: &'static str, s: &RootState, t: &RootTemplate) -> CompiledContract<'static> {
    let mut args: Vec<Expr<'static>> = vec![Expr::bytes(s.org_id.to_vec())];
    for o in s.owners.iter() {
        args.push(Expr::bytes(o.to_vec()));
    }
    for v in [s.owner_m, s.emergency_k, s.recovery_m] {
        args.push(Expr::int(v));
    }
    args.push(Expr::byte(s.frozen as u8));
    args.push(Expr::bytes(num8(s.nonce).to_vec()));
    args.push(Expr::int(t.recovery_delay));
    args.push(Expr::bytes(t.successor_pk.to_vec()));
    args.push(Expr::int(t.succession_delay));
    args.push(Expr::int(t.max_fee));
    compile_contract(src, &args, CompileOptions::default()).unwrap_or_else(|e| panic!("compile root: {e:?}"))
}

const ROOT_SLOT_NAMES: [&str; N_SLOTS] =
    ["owner1", "owner2", "owner3", "owner4", "owner5", "owner6", "owner7", "owner8", "owner9", "owner10", "owner11", "owner12"];

fn root_state_arg(s: &RootState) -> Expr<'static> {
    let mut f: Vec<(&'static str, Expr<'static>)> = vec![("boundOrgId", Expr::bytes(s.org_id.to_vec()))];
    for (i, n) in ROOT_SLOT_NAMES.iter().enumerate() {
        f.push((n, Expr::bytes(s.owners[i].to_vec())));
    }
    f.push(("ownerM", Expr::int(s.owner_m)));
    f.push(("emergencyK", Expr::int(s.emergency_k)));
    f.push(("recoveryM", Expr::int(s.recovery_m)));
    f.push(("frozen", Expr::byte(s.frozen as u8)));
    f.push(("rootNonce", Expr::bytes(num8(s.nonce).to_vec())));
    struct_object(f)
}

fn root_owner_blob(tx: &Transaction, entries: &[UtxoEntry], idx: usize, signers: &[usize]) -> Vec<u8> {
    let mut slots: Vec<Vec<u8>> = (0..N_SLOTS).map(|_| placeholder_slot()).collect();
    for i in signers.iter() {
        slots[*i] = sign(tx, entries, idx, &kp(OWNER_SEEDS[*i]));
    }
    let blob: Vec<u8> = slots.into_iter().flatten().collect();
    assert_eq!(blob.len(), SIG_BLOB_LEN);
    blob
}

/* ---------------- root-only transactions ---------------- */

#[derive(Clone)]
struct RootCase {
    src: &'static str,
    prev: RootState,
    new: RootState,
    tmpl: RootTemplate,
    action: i64,
    signers: Vec<usize>,
    sequence: u64,
    hash_type: SigHashType,
    succ_value: Option<i64>,
    /// use rootSuccession instead of rootAction; value = signing key seed
    succession: Option<u8>,
    /// override the successor-signature blob length (default 65)
    succ_sig_len: Option<usize>,
    budget: u16,
}
impl RootCase {
    fn authorize(prev: RootState, signers: &[usize]) -> RootCase {
        let new = prev.advanced();
        RootCase {
            src: src_root(),
            prev,
            new,
            tmpl: RootTemplate::default(),
            action: 0,
            signers: signers.to_vec(),
            sequence: 0,
            hash_type: SIG_HASH_ALL,
            succ_value: None,
            succession: None,
            succ_sig_len: None,
            budget: 400,
        }
    }
    /// A well-formed OWNER-RECOVER (decision D6: lands FROZEN).
    fn recover(prev: RootState, signers: &[usize]) -> RootCase {
        let mut c = RootCase::authorize(prev.clone(), signers);
        c.action = 4;
        c.sequence = RECOVERY_DELAY as u64;
        let mut n = prev.advanced();
        n.owners[2] = ZERO32;
        n.owners[3] = ZERO32;
        n.owner_m = 2;
        n.recovery_m = 2;
        n.frozen = 1;
        c.new = n;
        c
    }
    /// A well-formed SUCCESSION (D1: primary key must change; lands frozen).
    fn succeed(prev: RootState, seed: u8) -> RootCase {
        let mut c = RootCase::authorize(prev.clone(), &[]);
        c.succession = Some(seed);
        c.sequence = SUCCESSION_DELAY as u64;
        let mut n = prev.advanced();
        n.owners[0] = xonly32(&kp(0x91));
        n.frozen = 1;
        c.new = n;
        c
    }
}

struct RootOutcome {
    result: Result<(), TxScriptError>,
}

fn run_root(c: &RootCase) -> RootOutcome {
    let prev_c = compile_root(c.src, &c.prev, &c.tmpl);
    let next_c = compile_root(c.src, &c.new, &c.tmpl);
    let entries = vec![cov_utxo(ROOT_KAS, &prev_c, COV_ROOT)];
    let succ_value = c.succ_value.unwrap_or(ROOT_KAS - ROOT_FEE_PAID);
    let outputs = vec![cov_out(succ_value, &next_c, 0, COV_ROOT)];

    let unsigned = build_tx(vec![tx_input(1, vec![], c.sequence, c.budget)], outputs.clone());
    let sigscript = match c.succession {
        Some(seed) => {
            let mut s = sign_type(&unsigned, &entries, 0, &kp(seed), c.hash_type);
            if let Some(n) = c.succ_sig_len {
                s.resize(n, 0u8);
            }
            cov_call(&prev_c, "rootSuccession", vec![root_state_arg(&c.new), Expr::bytes(s)])
        }
        None => {
            let blob = root_owner_blob(&unsigned, &entries, 0, &c.signers);
            cov_call(&prev_c, "rootAction", vec![root_state_arg(&c.new), Expr::int(c.action), Expr::bytes(blob)])
        }
    };
    let tx = build_tx(vec![tx_input(1, sigscript, c.sequence, c.budget)], outputs);
    let (result, _units) = execute_input_measured(tx.clone(), entries.clone(), 0);
    RootOutcome { result }
}

/* ================================================================== */
/* ROOT-ONLY ADVERSARIAL REVIEW MATRIX — new hostile/coverage rows      */
/* NOT already exercised by v7_root_production.rs                      */
/* ================================================================== */

fn root_review_rows() -> Vec<(&'static str, RootCase, bool /* expect_accept */)> {
    let base = RootState::with(3, 2, 1, 2);
    let mut rows: Vec<(&'static str, RootCase, bool)> = vec![];

    rows.push((
        "[F] OWNER-RECOVER accepted while the root is ALREADY frozen (action 4 has no prevState.frozen==0 guard, unlike actions 0/2 — coverage gap, not previously probed)",
        {
            let prev = RootState { frozen: 1, ..RootState::with(4, 4, 1, 2) };
            RootCase::recover(prev, &[0, 1])
        },
        true,
    ));

    rows.push((
        "[G1] succession signature blob too short (64 bytes, missing the trailing SIGHASH_ALL gate byte)",
        {
            let mut c = RootCase::succeed(base.clone(), SUCCESSOR_SEED);
            c.succ_sig_len = Some(64);
            c
        },
        false,
    ));
    rows.push((
        "[G2] succession signature blob too long (66 bytes)",
        {
            let mut c = RootCase::succeed(base.clone(), SUCCESSOR_SEED);
            c.succ_sig_len = Some(66);
            c
        },
        false,
    ));

    rows.push((
        "[L] SUCCESSION installing a new owner set with a hole in the active slots (non-contiguous)",
        {
            let mut c = RootCase::succeed(base.clone(), SUCCESSOR_SEED);
            c.new.owners[1] = ZERO32; // owner2 inactive, owner3 (unchanged from prev) stays active -> hole
            c
        },
        false,
    ));
    rows.push((
        "[M] SUCCESSION installing a new owner set with a duplicate key (owner2 == the newly-installed owner1)",
        {
            let mut c = RootCase::succeed(base.clone(), SUCCESSOR_SEED);
            c.new.owners[1] = c.new.owners[0];
            c
        },
        false,
    ));

    rows.push((
        "[N] OWNER-RECOVER installing a new owner set with a hole in the active slots",
        {
            let prev = RootState::with(4, 4, 1, 2);
            let mut c = RootCase::recover(prev.clone(), &[0, 1]);
            let mut n = prev.advanced();
            n.owners[1] = ZERO32; // owner2 inactive
            n.owners[3] = xonly32(&kp(OWNER_SEEDS[3])); // owner4 stays active (unchanged) -> hole at owner2/owner3
            n.owner_m = 3;
            n.recovery_m = 2;
            n.frozen = 1; // D6
            c.new = n;
            c
        },
        false,
    ));

    rows.push((
        "[AA] SUCCESSION against a malformed (duplicate-key) predecessor — proves requireWellFormed(prevState) is NOT skipped on the rootSuccession entrypoint",
        {
            let mut prev = RootState::with(3, 2, 1, 2);
            prev.owners[2] = prev.owners[0]; // malformed genesis
            RootCase::succeed(prev, SUCCESSOR_SEED)
        },
        false,
    ));

    rows.push((
        "[D] duplicate owner key straddling the low/high half-split counting boundary (owner6 == owner7, the exact boundary between the two countSixOwners() call frames)",
        {
            let big8 = RootState::with(8, 5, 2, 3);
            let mut c = RootCase::authorize(big8.clone(), &[0, 1, 2, 3, 4]);
            c.action = 1;
            let mut n = big8.advanced();
            n.owners[6] = n.owners[5]; // owner7 (idx6, first of the HIGH half) duplicates owner6 (idx5, last of the LOW half)
            c.new = n;
            c
        },
        false,
    ));

    rows.push((
        "[P6] SUCCESSION with the root value drained beyond rootMaxFeePerTx",
        {
            let mut c = RootCase::succeed(base.clone(), SUCCESSOR_SEED);
            c.succ_value = Some(ROOT_KAS - ROOT_MAX_FEE - 1);
            c
        },
        false,
    ));
    rows.push((
        "[P7] AUTHORIZE with ZERO value loss (successor value == input value exactly; the rule is a lower bound, not an exact-fee requirement)",
        {
            let mut c = RootCase::authorize(base.clone(), &[0, 1]);
            c.succ_value = Some(ROOT_KAS);
            c
        },
        true,
    ));

    rows.push((
        "[K0] ROTATE to emergencyK = 0 (lower-bound WF violation; only the upper bound emergencyK>ownerM is in the existing matrix)",
        {
            let mut c = RootCase::authorize(base.clone(), &[0, 1]);
            c.action = 1;
            c.new = RootState { emergency_k: 0, ..base.advanced() };
            c
        },
        false,
    ));
    rows.push((
        "[RNeg] ROTATE to recoveryM = -1 (negative; lower-bound WF violation; only the upper bound recoveryM>ownerM is in the existing matrix)",
        {
            let mut c = RootCase::authorize(base.clone(), &[0, 1]);
            c.action = 1;
            c.new = RootState { recovery_m: -1, ..base.advanced() };
            c
        },
        false,
    ));

    rows.push((
        "[Q] AUTHORIZE with an EXTRA real signature deposited in a nominally INACTIVE slot (index 5, owner6) -- confirms sentinel-zero slots are unconditionally skipped regardless of slot content, not merely uncounted by coincidence",
        {
            let mut c = RootCase::authorize(base.clone(), &[0, 1]);
            // a REAL signature under OWNER_SEEDS[5]'s key, deposited at slot
            // index 5, which is sentinel-zero (inactive) in `base` (only 3
            // active owners) -- not a forged/outsider key, just extra content
            // in a slot the covenant should never inspect.
            c.signers = vec![0, 1, 5];
            c
        },
        true,
    ));

    rows
}

#[test]
fn rev_root_review_matrix() {
    let rows = root_review_rows();
    println!("ADVERSARIAL REVIEW — ROOT MATRIX, {} NEW rows (not in v7_root_production.rs)", rows.len());
    for (label, case, expect_accept) in rows.iter() {
        let o = run_root(case);
        if *expect_accept {
            o.result.as_ref().unwrap_or_else(|e| panic!("{label}: expected ACCEPT, engine refused: {e:?}"));
            println!("  ACCEPT   {label}");
        } else {
            match &o.result {
                Ok(()) => panic!("{label}: expected REFUSE, engine ACCEPTED — POSSIBLE FALSIFICATION"),
                Err(e) => println!("  REFUSED  {label}\n           -> {e:?}"),
            }
        }
    }
}

/* ================================================================== */
/* rooted payment covenant (parameterized over the ROOT PIN it is       */
/* compiled against, so the same helpers serve the honest chain, the    */
/* geometry-misconfiguration probes, and the D1 cross-covenant chain)   */
/* ================================================================== */

#[derive(Clone)]
struct VaultState {
    reserve: i64,
    paused: i64,
    agent_root: [u8; 32],
    policy_nonce: i64,
}

#[derive(Clone)]
struct TokenPin {
    covid: Hash,
    hash: [u8; 32],
    prefix_len: i64,
    state_len: i64,
    suffix_len: i64,
}
#[derive(Clone)]
struct RootPin {
    covid: Hash,
    hash: [u8; 32],
    prefix_len: i64,
    state_len: i64,
    suffix_len: i64,
}

/// A template-constant-only placeholder: none of the probes in this suite
/// exercise a real KCC20 token position (that surface is exhaustively
/// covered by the existing `v7_payment_production.rs`), so the pin never
/// needs to resolve against a real compiled token.
fn dummy_token_pin(covid: Hash) -> TokenPin {
    TokenPin { covid, hash: [0x22u8; 32], prefix_len: 10, state_len: 90, suffix_len: 10 }
}

fn root_pin(covid: Hash, src: &'static str, tmpl: &RootTemplate) -> RootPin {
    let sample = compile_root(src, &RootState::with(1, 1, 1, 0), tmpl);
    let t = template_of(&sample);
    RootPin { covid, hash: t.hash, prefix_len: t.prefix.len() as i64, state_len: t.state_len as i64, suffix_len: t.suffix.len() as i64 }
}

/// Exact-live-state templating (same anchors the production suite uses).
fn vault_templated(src: &str, s: &VaultState) -> String {
    let mut src = src.to_string();
    let mut r = |from: String, to: String| {
        assert!(src.contains(&from), "anchor missing: {from}");
        src = src.replacen(&from, &to, 1);
    };
    r("int feeReserve = initFeeReserve;".into(), format!("int feeReserve = {};", s.reserve));
    r("int paused = 0;".into(), format!("int paused = {};", s.paused));
    r("byte[32] agentRoot = initAgentRoot;".into(), format!("byte[32] agentRoot = 0x{};", s.agent_root.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    r("int policyNonce = 0;".into(), format!("int policyNonce = {};", s.policy_nonce));
    src
}

fn compile_vault_v7(tok: &TokenPin, root: &RootPin, recovery_pk: &[u8; 32], s: &VaultState) -> CompiledContract<'static> {
    let src: &'static str = leak(vault_templated(src_vault_raw(), s));
    let args: Vec<Expr<'static>> = vec![
        Expr::bytes(VAULT_ID.to_vec()),
        Expr::bytes(DESCRIPTOR_HASH.to_vec()),
        Expr::bytes(tok.covid.as_bytes().to_vec()),
        Expr::bytes(tok.hash.to_vec()),
        Expr::int(tok.prefix_len),
        Expr::int(tok.state_len),
        Expr::int(tok.suffix_len),
        Expr::bytes(root.covid.as_bytes().to_vec()),
        Expr::bytes(root.hash.to_vec()),
        Expr::int(root.prefix_len),
        Expr::int(root.state_len),
        Expr::int(root.suffix_len),
        Expr::bytes(recovery_pk.to_vec()),
        Expr::bytes(s.agent_root.to_vec()),
        Expr::int(s.reserve),
    ];
    compile_contract(src, &args, CompileOptions::default()).unwrap_or_else(|e| panic!("compile v0.7-payment: {e:?}"))
}

fn vault_state_arg(s: &VaultState) -> Expr<'static> {
    struct_object(vec![
        ("boundVaultId", Expr::bytes(VAULT_ID.to_vec())),
        ("feeReserve", Expr::int(s.reserve)),
        ("paused", Expr::int(s.paused)),
        ("agentRoot", Expr::bytes(s.agent_root.to_vec())),
        ("policyNonce", Expr::int(s.policy_nonce)),
    ])
}

/// Compile a REAL FROZEN v0.5 controller instance — used only as an
/// impostor at the "root" input position (cross-generation substitution
/// probe). `contracts/PolicyVault.v0.5.sil` is opened READ-ONLY.
fn compile_v05_impostor(owner_pk: [u8; 32], s: &VaultState) -> CompiledContract<'static> {
    let tok = dummy_token_pin(COV_TOKEN_DUMMY);
    let args: Vec<Expr<'static>> = vec![
        Expr::bytes(owner_pk.to_vec()),
        Expr::bytes(VAULT_ID.to_vec()),
        Expr::bytes(DESCRIPTOR_HASH.to_vec()),
        Expr::bytes(tok.covid.as_bytes().to_vec()),
        Expr::bytes(tok.hash.to_vec()),
        Expr::int(tok.prefix_len),
        Expr::int(tok.state_len),
        Expr::int(tok.suffix_len),
        Expr::bytes(s.agent_root.to_vec()),
        Expr::int(s.reserve),
    ];
    compile_contract(src_v5_raw(), &args, CompileOptions::default()).unwrap_or_else(|e| panic!("compile v0.5 impostor: {e:?}"))
}

/* ================================================================== */
/* [B] vault genesis pinned with a MISCONFIGURED root geometry          */
/* (off-by-one prefix/state/suffix length against the REAL root) —      */
/* robustness of the byte-level pin, not just malicious substitution    */
/* ================================================================== */

fn run_owner_control_with_geometry_delta(delta: (i64, i64, i64)) -> Result<(), TxScriptError> {
    let tmpl = RootTemplate::default();
    let mut rpin = root_pin(COV_ROOT, src_root(), &tmpl);
    rpin.prefix_len += delta.0;
    rpin.state_len += delta.1;
    rpin.suffix_len += delta.2;
    let recovery_pk = xonly32(&kp(0x51));
    let tok = dummy_token_pin(COV_TOKEN_DUMMY);

    let vault_prev = VaultState { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 };
    let vault_new = VaultState { agent_root: [0x99; 32], policy_nonce: 1, ..vault_prev.clone() };
    let vault_prev_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_prev);
    let vault_next_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_new);

    let root_prev = RootState::with(3, 2, 1, 2);
    let root_new = root_prev.advanced(); // honest AUTHORIZE, stays unfrozen
    let root_prev_c = compile_root(src_root(), &root_prev, &tmpl);
    let root_next_c = compile_root(src_root(), &root_new, &tmpl);

    let mut entries = vec![cov_utxo(RESERVE, &vault_prev_c, COV_VAULT), cov_utxo(ROOT_KAS, &root_prev_c, COV_ROOT)];
    let fuel = kp(0x63);
    let fuel_pk = xonly32(&fuel);
    entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

    let outputs = vec![
        cov_out(vault_new.reserve, &vault_next_c, 0, COV_VAULT),
        cov_out(ROOT_KAS - ROOT_FEE_PAID, &root_next_c, 1, COV_ROOT),
        p2pk_out(&fuel_pk, FUEL - FEE),
    ];
    let input_ids = [(1u8, 0u64), (2, 0), (3, 0)];
    let unsigned = build_tx(input_ids.iter().map(|(id, seq)| tx_input(*id, vec![], *seq, 400)).collect(), outputs.clone());
    let fuel_sig = sign(&unsigned, &entries, 2, &fuel);

    let blob = root_owner_blob(&unsigned, &entries, 1, &[0, 1]);
    let vault_ss = cov_call(&vault_prev_c, "ownerControl", vec![vault_state_arg(&vault_new), Expr::int(0)]);
    let root_ss = cov_call(&root_prev_c, "rootAction", vec![root_state_arg(&root_new), Expr::int(0), Expr::bytes(blob)]);

    let sigscripts = vec![vault_ss, root_ss, p2pk_sigscript(fuel_sig)];
    let inputs: Vec<TransactionInput> = input_ids.iter().zip(sigscripts).map(|((id, seq), ss)| tx_input(*id, ss, *seq, 400)).collect();
    let tx = build_tx(inputs, outputs);
    let (vault_r, _) = execute_input_measured(tx.clone(), entries.clone(), 0);
    vault_r
}

#[test]
fn rev_vault_geometry_prefix_len_off_by_one() {
    let r = run_owner_control_with_geometry_delta((1, 0, 0));
    assert!(r.is_err(), "vault must REFUSE an honest owner op when rootPrefixLen is pinned 1 byte too large at genesis");
    println!("[B1] rootPrefixLen+1 (misconfigured genesis) -> vault refused: {:?}", r.unwrap_err());
}
#[test]
fn rev_vault_geometry_state_len_off_by_one() {
    let r = run_owner_control_with_geometry_delta((0, -1, 0));
    assert!(r.is_err(), "vault must REFUSE an honest owner op when rootStateLen is pinned 1 byte too small at genesis");
    println!("[B2] rootStateLen-1 (misconfigured genesis) -> vault refused: {:?}", r.unwrap_err());
}
#[test]
fn rev_vault_geometry_suffix_len_off_by_one() {
    let r = run_owner_control_with_geometry_delta((0, 0, 1));
    assert!(r.is_err(), "vault must REFUSE an honest owner op when rootSuffixLen is pinned 1 byte too large at genesis");
    println!("[B3] rootSuffixLen+1 (misconfigured genesis) -> vault refused: {:?}", r.unwrap_err());
}

/* ================================================================== */
/* [C] cross-generation substitution: a REAL FROZEN v0.5 controller      */
/* impersonating the pinned v0.7 organizational root                    */
/* ================================================================== */

#[test]
fn rev_v05_controller_impersonating_the_root() {
    let tmpl = RootTemplate::default();
    let rpin = root_pin(COV_ROOT, src_root(), &tmpl); // the vault's GENUINE pin (real root)
    let recovery_pk = xonly32(&kp(0x51));
    let tok = dummy_token_pin(COV_TOKEN_DUMMY);

    let vault_prev = VaultState { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 };
    let vault_new = VaultState { paused: 1, ..vault_prev.clone() };
    let vault_prev_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_prev);
    let vault_next_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_new);

    // the impostor at the "root" position: a REAL v0.5 controller instance,
    // tagged with the covenant id the vault expects for its root.
    let impostor_owner = xonly32(&kp(0x40));
    let impostor_state = VaultState { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 };
    let impostor_c = compile_v05_impostor(impostor_owner, &impostor_state);

    let mut entries = vec![cov_utxo(RESERVE, &vault_prev_c, COV_VAULT), cov_utxo(ROOT_KAS, &impostor_c, COV_ROOT)];
    let fuel = kp(0x63);
    let fuel_pk = xonly32(&fuel);
    entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

    let outputs = vec![
        cov_out(vault_new.reserve, &vault_next_c, 0, COV_VAULT),
        cov_out(ROOT_KAS - ROOT_FEE_PAID, &impostor_c, 1, COV_ROOT),
        p2pk_out(&fuel_pk, FUEL - FEE),
    ];
    let input_ids = [(1u8, 0u64), (2, 0), (3, 0)];
    let unsigned = build_tx(input_ids.iter().map(|(id, seq)| tx_input(*id, vec![], *seq, 400)).collect(), outputs.clone());
    let fuel_sig = sign(&unsigned, &entries, 2, &fuel);

    let vault_ss = cov_call(&vault_prev_c, "ownerControl", vec![vault_state_arg(&vault_new), Expr::int(2)]);
    // v0.5's ownerControl(State prevState, State newState, int opSelector, sig
    // ownerSig) takes prevState IMPLICITLY from the spent UTXO's own state (as
    // every covenant.singleton entrypoint in this codebase does); the explicit
    // call args are newState, opSelector, ownerSig only.
    let impostor_ss =
        cov_call(&impostor_c, "ownerControl", vec![vault_state_arg(&impostor_state), Expr::int(2), Expr::bytes(placeholder_slot())]);
    let sigscripts = vec![vault_ss, impostor_ss, p2pk_sigscript(fuel_sig)];
    let inputs: Vec<TransactionInput> = input_ids.iter().zip(sigscripts).map(|((id, seq), ss)| tx_input(*id, ss, *seq, 400)).collect();
    let tx = build_tx(inputs, outputs);
    let (vault_r, _) = execute_input_measured(tx.clone(), entries.clone(), 0);
    assert!(vault_r.is_err(), "the vault must REFUSE a real v0.5 controller impersonating its pinned organizational root");
    println!("[C1] a v0.5 controller presented as the v0.7 root -> vault refused: {:?}", vault_r.unwrap_err());
}

/* ================================================================== */
/* [E] MULTI-VAULT FREEZE composition. The design record claims this is */
/* "architecturally permitted (the covenant's per-vault check is        */
/* satisfied by one shared root input ...)" and separately records it   */
/* as NOT built by the SDK and NOT measured                             */
/* (v0.7-organizational-root-design.md section 14.5;                    */
/* v0.7-byte-freeze-readiness.md section 5 item 3). This probe measures  */
/* it for the first time on the real engine. Result: the claim does NOT */
/* hold for `ownerControl` as implemented — see the test below.         */
/* ================================================================== */

fn run_two_vault_freeze(vault_b_selector: i64) -> (Result<(), TxScriptError>, Result<(), TxScriptError>, Result<(), TxScriptError>) {
    let tmpl = RootTemplate::default();
    let rpin = root_pin(COV_ROOT, src_root(), &tmpl);
    let recovery_pk = xonly32(&kp(0x51));
    let tok = dummy_token_pin(COV_TOKEN_DUMMY);

    let vault_a_prev = VaultState { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 };
    let vault_a_new = VaultState { paused: 1, ..vault_a_prev.clone() };
    let vault_b_prev = VaultState { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 };
    let vault_b_new = if vault_b_selector == 4 {
        VaultState { paused: 1, ..vault_b_prev.clone() }
    } else {
        VaultState { agent_root: [0x77; 32], policy_nonce: 1, ..vault_b_prev.clone() }
    };

    let vault_a_prev_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_a_prev);
    let vault_a_next_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_a_new);
    let vault_b_prev_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_b_prev);
    let vault_b_next_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_b_new);

    let root_prev = RootState::with(3, 2, 1, 2); // emergencyK = 1
    let root_new = RootState { frozen: 1, ..root_prev.advanced() };
    let root_prev_c = compile_root(src_root(), &root_prev, &tmpl);
    let root_next_c = compile_root(src_root(), &root_new, &tmpl);

    let mut entries =
        vec![cov_utxo(RESERVE, &vault_a_prev_c, COV_VAULT), cov_utxo(RESERVE, &vault_b_prev_c, COV_VAULT_B), cov_utxo(ROOT_KAS, &root_prev_c, COV_ROOT)];
    let fuel = kp(0x63);
    let fuel_pk = xonly32(&fuel);
    entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

    let outputs = vec![
        cov_out(vault_a_new.reserve, &vault_a_next_c, 0, COV_VAULT),
        cov_out(vault_b_new.reserve, &vault_b_next_c, 1, COV_VAULT_B),
        cov_out(ROOT_KAS - ROOT_FEE_PAID, &root_next_c, 2, COV_ROOT),
        p2pk_out(&fuel_pk, FUEL - FEE),
    ];
    let input_ids = [(1u8, 0u64), (2, 0), (3, 0), (4, 0)];
    let unsigned = build_tx(input_ids.iter().map(|(id, seq)| tx_input(*id, vec![], *seq, 400)).collect(), outputs.clone());
    let fuel_sig = sign(&unsigned, &entries, 3, &fuel);

    let blob = root_owner_blob(&unsigned, &entries, 2, &[0]); // emergencyK = 1
    let vault_a_ss = cov_call(&vault_a_prev_c, "ownerControl", vec![vault_state_arg(&vault_a_new), Expr::int(4)]);
    let vault_b_ss = cov_call(&vault_b_prev_c, "ownerControl", vec![vault_state_arg(&vault_b_new), Expr::int(vault_b_selector)]);
    let root_ss = cov_call(&root_prev_c, "rootAction", vec![root_state_arg(&root_new), Expr::int(2), Expr::bytes(blob)]);

    let sigscripts = vec![vault_a_ss, vault_b_ss, root_ss, p2pk_sigscript(fuel_sig)];
    let inputs: Vec<TransactionInput> = input_ids.iter().zip(sigscripts).map(|((id, seq), ss)| tx_input(*id, ss, *seq, 400)).collect();
    let tx = build_tx(inputs, outputs);
    let (a_r, _) = execute_input_measured(tx.clone(), entries.clone(), 0);
    let (b_r, _) = execute_input_measured(tx.clone(), entries.clone(), 1);
    let (root_r, _) = execute_input_measured(tx.clone(), entries.clone(), 2);
    (a_r, b_r, root_r)
}

#[test]
fn rev_multi_vault_freeze_finding_batching_is_refused_by_each_vaults_own_input_closure() {
    // Source-level root cause (contracts/PolicyVault.v0.7-payment.sil,
    // requireOnlyRootCovenantInputs, called once from ownerControl): "every
    // input other than THIS covenant and the pinned ROOT family must be a
    // PLAIN input (zero covenant id)". A second vault's input carries a
    // REAL, non-zero, non-root covenant id (its own family) -- so from
    // vault A's perspective vault B is an unaccounted-for foreign covenant
    // rider, and symmetrically from vault B's perspective vault A is one.
    let (a, b, r) = run_two_vault_freeze(4); // both vaults request the SAME selector 4 (EMERGENCY pause) -- the most permissive case possible
    r.as_ref().unwrap_or_else(|e| panic!("the root's OWN FREEZE (K=1) must still be accepted -- it does not enumerate vault siblings: {e:?}"));
    assert!(a.is_err(), "FINDING: vault A must be REFUSED -- vault B (a real, non-zero, non-root covenant id) is an unaccounted foreign rider");
    assert!(b.is_err(), "FINDING: vault B must be REFUSED -- symmetrically, vault A is an unaccounted foreign rider from vault B's perspective");
    println!(
        "[E] FINDING (DOCUMENTATION): even the MOST PERMISSIVE multi-vault case (both vaults requesting the identical \
         selector 4 EMERGENCY pause under the SAME root FREEZE successor) is REFUSED by ownerControl's own \
         requireOnlyRootCovenantInputs, which treats a sibling vault's non-zero covenant id as a foreign rider. \
         vault A refused: {:?} | vault B refused: {:?} | root itself still accepted (it never enumerates vault \
         siblings): {:?}. This CONTRADICTS docs/postlaunch/v0.7-organizational-root-design.md section 14.5's claim \
         that multi-vault batching is 'architecturally permitted (the covenant's per-vault check is satisfied by \
         one shared root input ...)' for the ownerControl entrypoint as implemented in the byte-frozen candidate. \
         Direction is SAFE (over-restrictive, fails closed) -- no authority escalation, no funds movement follows \
         from this refusal -- but the documented capability does not exist for this entrypoint today.",
        a.unwrap_err(),
        b.unwrap_err(),
        r
    );
}

/* ================================================================== */
/* [A] IS DEVIATION D1 LOAD-BEARING? — cross-covenant chain proving      */
/* what D1 (rootSuccession must install a different primary key)        */
/* protects against: WITHOUT it, a lone successor key (ZERO owner       */
/* quorum participation) can produce a root successor that is           */
/* byte-identical to what an emergency-quorum FREEZE produces, and a    */
/* real (unmodified) v0.7-payment vault's byte-level pin — which never  */
/* inspects WHICH root entrypoint ran, only the resulting bytes — would */
/* accept it as authorization for an EMERGENCY pause.                   */
/* ================================================================== */

/// Build: vault ownerControl(selector=4, EMERGENCY pause) + root
/// rootSuccession(TRIVIAL: owner set UNCHANGED, only frozen 0->1, signed
/// ONLY by the pinned successor key -- ZERO owner quorum participation) +
/// fuel, for the root compiled from `root_src`. Returns (vault result, root
/// result), each executed independently.
fn run_d1_chain(root_src: &'static str) -> (Result<(), TxScriptError>, Result<(), TxScriptError>) {
    let tmpl = RootTemplate::default();
    let rpin = root_pin(COV_ROOT, root_src, &tmpl);
    let recovery_pk = xonly32(&kp(0x51));
    let tok = dummy_token_pin(COV_TOKEN_DUMMY);

    let vault_prev = VaultState { reserve: RESERVE, paused: 0, agent_root: ZERO32, policy_nonce: 0 };
    let vault_new = VaultState { paused: 1, ..vault_prev.clone() };
    let vault_prev_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_prev);
    let vault_next_c = compile_vault_v7(&tok, &rpin, &recovery_pk, &vault_new);

    let root_prev = RootState::with(3, 2, 1, 2);
    // TRIVIAL succession: owner set UNCHANGED, only frozen 0->1 + nonce+1 --
    // exactly the shape a legitimate FREEZE produces, but here authorized by
    // NOTHING but the lone successor key.
    let root_new = RootState { frozen: 1, ..root_prev.advanced() };
    let root_prev_c = compile_root(root_src, &root_prev, &tmpl);
    let root_next_c = compile_root(root_src, &root_new, &tmpl);

    let mut entries = vec![cov_utxo(RESERVE, &vault_prev_c, COV_VAULT), cov_utxo(ROOT_KAS, &root_prev_c, COV_ROOT)];
    let fuel = kp(0x63);
    let fuel_pk = xonly32(&fuel);
    entries.push(UtxoEntry::new(FUEL as u64, p2pk_spk(&fuel_pk), 0, false, None));

    let outputs = vec![
        cov_out(vault_new.reserve, &vault_next_c, 0, COV_VAULT),
        cov_out(ROOT_KAS - ROOT_FEE_PAID, &root_next_c, 1, COV_ROOT),
        p2pk_out(&fuel_pk, FUEL - FEE),
    ];
    // the root input's sequence must clear successionDelayDaa, or the age
    // guard (unrelated to D1) would refuse first and confound the result.
    let input_ids = [(1u8, 0u64), (2, SUCCESSION_DELAY as u64), (3, 0)];
    let unsigned = build_tx(input_ids.iter().map(|(id, seq)| tx_input(*id, vec![], *seq, 400)).collect(), outputs.clone());
    let fuel_sig = sign(&unsigned, &entries, 2, &fuel);

    // ZERO owner quorum participation: only the successor key signs.
    let succ_sig = sign(&unsigned, &entries, 1, &kp(SUCCESSOR_SEED));
    let root_ss = cov_call(&root_prev_c, "rootSuccession", vec![root_state_arg(&root_new), Expr::bytes(succ_sig)]);
    let vault_ss = cov_call(&vault_prev_c, "ownerControl", vec![vault_state_arg(&vault_new), Expr::int(4)]);

    let sigscripts = vec![vault_ss, root_ss, p2pk_sigscript(fuel_sig)];
    let inputs: Vec<TransactionInput> = input_ids.iter().zip(sigscripts).map(|((id, seq), ss)| tx_input(*id, ss, *seq, 400)).collect();
    let tx = build_tx(inputs, outputs);
    let (vault_r, _) = execute_input_measured(tx.clone(), entries.clone(), 0);
    let (root_r, _) = execute_input_measured(tx.clone(), entries.clone(), 1);
    (vault_r, root_r)
}

#[test]
fn rev_d1_without_the_guard_zero_owner_participation_pauses_a_vault() {
    // MEASUREMENT-ONLY: contracts/experiments/V7ReviewNoD1.sil, D1 removed.
    let (vault_r, root_r) = run_d1_chain(src_no_d1());
    root_r.as_ref().unwrap_or_else(|e| {
        panic!("expected the SABOTAGED (no-D1) root to ACCEPT the trivial succession -- that IS the measurement: {e:?}")
    });
    vault_r.as_ref().unwrap_or_else(|e| {
        panic!(
            "AUTHORITY-CRITICAL MEASUREMENT: without D1, a REAL (unmodified) v0.7-payment vault pinned to that root \
             was expected to ACCEPT an EMERGENCY pause authorized by ONLY the successor key (zero owner signatures) -- \
             it did not reproduce: {e:?}"
        )
    });
    println!(
        "[A] WITHOUT D1: the sabotaged root ACCEPTED a trivial succession (owner set unchanged, only frozen 0->1) \
         signed by NOTHING but the successor key; the REAL v0.7-payment vault ACCEPTED the resulting EMERGENCY pause. \
         D1 is the ONLY thing that prevents a lone successor key from producing this shape in the real candidate."
    );
}

#[test]
fn rev_d1_real_candidate_closes_the_gap() {
    let (vault_r, root_r) = run_d1_chain(src_root());
    assert!(root_r.is_err(), "the REAL candidate (D1 present) must REFUSE the identical trivial-succession attempt");
    println!(
        "[A] the FROZEN CANDIDATE's D1 refuses the same shape at the ROOT: {:?} \
         (the vault's OWN independent result on this input is informational, not the security boundary: {:?})",
        root_r.unwrap_err(),
        vault_r
    );
}
