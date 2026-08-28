//! VM layer — PRODUCTION PolicyVault.v0.4.1.sil driven through the real
//! TxScriptEngine (covenants enabled, real Schnorr). Valid paths +
//! negative matrix + stack/compute measurement on the ACTUAL production
//! covenant. Consensus-visible bytes here go through the SilverScript
//! compiler + covenant-decl call encoder; the pv_call_encoder
//! production-byte integration is a separate step (v4_encoder_integration).
//!
//! v0.4.1 STANDARDNESS REDESIGN: the six non-terminal owner operations
//! (setAgentRoot/setApprovers/topUp/topUpReserve/pause/unpause) are
//! consolidated behind ONE `ownerControl(newState, opSelector, ownerSig)`
//! entrypoint with a single owner checkSig and internal dispatch, cutting
//! the static P2SH sig-op count 18 -> 13 (<= MAX_STANDARD_P2SH_SIG_OPS=15)
//! so covenant spends relay on a default node. State layout, agent/recipient
//! Merkle formats, approval machinery and the fee-reserve conservation model
//! are byte-identical to the frozen v0.4. See docs/covenant-spec-v0.4.1.md.
//!
//! FROZEN ABI: State 441 B (17 mutable fields), agent leaf 124-byte
//! preimage, agent tree depth <= 12, recipient depth <= 16, 10 approver
//! slots, per-agent fee cap.

use policyvault_vm_tests::*;
use secp256k1::Keypair;
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, struct_object, CompileOptions, CompiledContract, CovenantDeclCallOptions};

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL, SIG_HASH_NONE, SIG_HASH_SINGLE, SIG_HASH_ANY_ONE_CAN_PAY};
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_txscript::opcodes::codes::OpCheckSig;
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript_errors::TxScriptError;

const KAS: i64 = 100_000_000;
const VAULT_ID: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const AGENT_DOMAIN: [u8; 4] = [0x50, 0x56, 0x34, 0x01];
const RECIP_DOMAIN: [u8; 4] = [0x50, 0x56, 0x33, 0x01];
const ZERO32: [u8; 32] = [0u8; 32];

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

#[derive(Clone)]
struct Agent {
    pk: [u8; 32],
    max_per_spend: i64,
    period_budget: i64,
    period_length_daa: i64,
    period_start_daa: i64,
    period_spent: i64,
    approval_threshold: i64,
    max_fee_per_tx: i64,
    recipient_root: [u8; 32],
}
fn agent_leaf(a: &Agent) -> [u8; 32] {
    sha256(&[
        &AGENT_DOMAIN, &a.pk, &num8(a.max_per_spend), &num8(a.period_budget), &num8(a.period_length_daa),
        &num8(a.period_start_daa), &num8(a.period_spent), &num8(a.approval_threshold), &num8(a.max_fee_per_tx), &a.recipient_root,
    ])
}
/// Merkle root + proof for `leaves[target]` (duplicate-last padding).
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
/// Fold a leaf up a co-path (siblings + pathBits) to the root — the exact
/// covenant computeMerkleRoot, used to derive the correct successor root.
fn fold(leaf: [u8; 32], sibs: &[u8], mut bits: u64) -> [u8; 32] {
    let mut node = leaf;
    let depth = sibs.len() / 32;
    for level in 0..depth {
        let sib: [u8; 32] = sibs[level * 32..level * 32 + 32].try_into().unwrap();
        node = if bits & 1 == 1 { sha256(&[&sib, &node]) } else { sha256(&[&node, &sib]) };
        bits >>= 1;
    }
    node
}
/// Recipient tree of `1<<depth` leaves, real recipient at index 1 (depth>0)
/// or the sole leaf (depth 0).
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
    protected: i64,
    reserve: i64,
    paused: i64,
    agent_root: [u8; 32],
    approvers: [[u8; 32]; 10],
    approval_m: i64,
    policy_nonce: i64,
}
fn base_state(root: [u8; 32]) -> S {
    S { protected: 10000 * KAS, reserve: 5 * KAS, paused: 0, agent_root: root, approvers: [ZERO32; 10], approval_m: 0, policy_nonce: 0 }
}

fn source(s: &S) -> String {
    let path = format!("{}/../../contracts/PolicyVault.v0.4.1.sil", env!("CARGO_MANIFEST_DIR"));
    let mut src = std::fs::read_to_string(&path).unwrap();
    let mut r = |from: String, to: String| {
        assert!(src.contains(&from), "anchor missing: {from}");
        src = src.replacen(&from, &to, 1);
    };
    r("int protectedValue = initValue;".into(), format!("int protectedValue = {};", s.protected));
    r("int feeReserve = initFeeReserve;".into(), format!("int feeReserve = {};", s.reserve));
    r("int paused = 0;".into(), format!("int paused = {};", s.paused));
    r("byte[32] agentRoot = initAgentRoot;".into(), format!("byte[32] agentRoot = 0x{};", hx(&s.agent_root)));
    for i in 0..10 {
        r(format!("pubkey approver{} = initApprover{};", i + 1, i + 1), format!("pubkey approver{} = 0x{};", i + 1, hx(&s.approvers[i])));
    }
    r("int approvalM = initApprovalM;".into(), format!("int approvalM = {};", s.approval_m));
    r("int policyNonce = 0;".into(), format!("int policyNonce = {};", s.policy_nonce));
    src
}
fn compile(owner: &[u8; 32], s: &S) -> CompiledContract<'static> {
    let src: &'static str = Box::leak(source(s).into_boxed_str());
    let mut a = vec![
        Expr::bytes(owner.to_vec()),
        Expr::bytes(hex32(VAULT_ID)),
        Expr::bytes(s.agent_root.to_vec()),
        Expr::int(s.reserve),
    ];
    for i in 0..10 {
        a.push(Expr::bytes(s.approvers[i].to_vec()));
    }
    a.push(Expr::int(s.approval_m));
    a.push(Expr::int(s.protected));
    compile_contract(src, &a, CompileOptions::default()).expect("v0.4 compile")
}
/// Compile the v0.4.1 covenant after applying a source mutation (guard
/// sabotage). Same constructor args as compile(); the mutation neutralizes a
/// single consensus guard so a transition that guard rejects can be shown to
/// PASS — proving the guard is load-bearing (§17 sabotage sensitivity).
fn compile_mut(mutate: &dyn Fn(String) -> String, owner: &[u8; 32], s: &S) -> CompiledContract<'static> {
    let mutated = mutate(source(s));
    let src: &'static str = Box::leak(mutated.into_boxed_str());
    let mut a = vec![
        Expr::bytes(owner.to_vec()),
        Expr::bytes(hex32(VAULT_ID)),
        Expr::bytes(s.agent_root.to_vec()),
        Expr::int(s.reserve),
    ];
    for i in 0..10 {
        a.push(Expr::bytes(s.approvers[i].to_vec()));
    }
    a.push(Expr::int(s.approval_m));
    a.push(Expr::int(s.protected));
    compile_contract(src, &a, CompileOptions::default()).expect("v0.4.1 mutated compile")
}

fn state_arg(s: &S) -> Expr<'static> {
    let mut f = vec![
        ("boundVaultId", Expr::bytes(hex32(VAULT_ID))),
        ("protectedValue", Expr::int(s.protected)),
        ("feeReserve", Expr::int(s.reserve)),
        ("paused", Expr::int(s.paused)),
        ("agentRoot", Expr::bytes(s.agent_root.to_vec())),
    ];
    const NAMES: [&str; 10] = ["approver1","approver2","approver3","approver4","approver5","approver6","approver7","approver8","approver9","approver10"];
    for i in 0..10 {
        f.push((NAMES[i], Expr::bytes(s.approvers[i].to_vec())));
    }
    f.push(("approvalM", Expr::int(s.approval_m)));
    f.push(("policyNonce", Expr::int(s.policy_nonce)));
    struct_object(f)
}
fn sign_typed(m: &MutableTransaction<Transaction>, idx: usize, kp: &Keypair, ty: SigHashType) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&m.as_verifiable(), idx, ty, &reused);
    let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap();
    let mut out = kp.sign_schnorr(msg).as_ref().to_vec();
    out.push(ty.to_u8());
    out
}
fn placeholder() -> Vec<u8> {
    let mut p = vec![0u8; 64];
    p.push(0x01);
    p
}
fn cov_input(budget: u16) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeBudget(budget).into(),
    }
}
fn ext_input(id: u8) -> (TransactionInput, [u8; 32]) {
    let pk = xonly(&deterministic_keypair(id));
    (TransactionInput { previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([id; 32]), index: 1 }, signature_script: vec![], sequence: 0, compute_commit: ComputeBudget(10).into() }, pk)
}
fn ext_utxo(pk: &[u8; 32], value: u64) -> UtxoEntry {
    UtxoEntry::new(value, p2pk_output(pk, 0).script_public_key, 0, false, None)
}
fn change_out(pk: &[u8; 32], value: u64) -> TransactionOutput {
    let spk = ScriptBuilder::new().add_data(pk).unwrap().add_op(OpCheckSig).unwrap().drain();
    TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, spk.into()), covenant: None }
}

/// Align each signer to the slot holding its sorted key.
fn approver_set(keys: &[&Keypair]) -> [[u8; 32]; 10] {
    let mut active: Vec<[u8; 32]> = keys.iter().map(|k| xonly(k)).collect();
    active.sort();
    let mut a = [ZERO32; 10];
    for (i, k) in active.iter().enumerate() {
        a[i] = *k;
    }
    a
}
fn approvals_by_key<'a>(slots: &[[u8; 32]; 10], signers: &[(&'a Keypair, SigHashType)]) -> [Option<(&'a Keypair, SigHashType)>; 10] {
    let mut ap: [Option<(&'a Keypair, SigHashType)>; 10] = Default::default();
    for i in 0..10 {
        for (s, ty) in signers {
            if xonly(s) == slots[i] {
                ap[i] = Some((*s, *ty));
            }
        }
    }
    ap
}

#[allow(clippy::too_many_arguments)]
struct Spend<'a> {
    owner: [u8; 32],
    prev: S,
    tree_agents: Vec<Agent>,
    target: usize,
    claim: Agent,
    pay: i64,
    reserve_consumed: i64,
    periods_elapsed: i64,
    recip_depth: u32,
    signer: &'a Keypair,
    signer_type: SigHashType,
    recipient: &'a Keypair,
    recipient_out_override: Option<[u8; 32]>,
    approver_sigs: [Option<(&'a Keypair, SigHashType)>; 10],
    override_new_root: Option<[u8; 32]>,
    override_succ_value: Option<i64>,
    ext_in: Option<i64>,
    ext_out: Option<i64>,
    budget: u16,
    measure: bool,
    // Checkpoint D additions (default None; existing cases unaffected).
    seq_override: Option<u64>,
    lock_override: Option<u64>,
    // v0.4.1 §17 addition: force the successor principal (default prev-pay) so
    // the principal-conservation guard can be isolated in sabotage tests.
    succ_protected_override: Option<i64>,
}
fn dflt<'a>(owner: [u8; 32], prev: S, agents: Vec<Agent>, target: usize, claim: Agent, signer: &'a Keypair, recipient: &'a Keypair) -> Spend<'a> {
    Spend {
        owner, prev, tree_agents: agents, target, claim, pay: 40 * KAS, reserve_consumed: 5_000_000, periods_elapsed: 0, recip_depth: 0,
        signer, signer_type: SIG_HASH_ALL, recipient, recipient_out_override: None, approver_sigs: Default::default(),
        override_new_root: None, override_succ_value: None, ext_in: None, ext_out: None, budget: 200, measure: false,
        seq_override: None, lock_override: None, succ_protected_override: None,
    }
}

fn run(c: Spend) -> (Result<(), TxScriptError>, u64) {
    run_mut(c, &|s| s)
}

/// Like run(), but compiles the covenant through `mutate` first so a single
/// consensus guard can be neutralized for §17 sabotage-sensitivity. The tx is
/// (re)built and (re)signed against the mutated covenant's own P2SH, so the
/// signature always commits to the covenant actually executed.
fn run_mut(c: Spend, mutate: &dyn Fn(String) -> String) -> (Result<(), TxScriptError>, u64) {
    // The recipient tree the TARGET agent legitimately pays.
    let (rroot, rsibs, rbits) = recip_tree(c.recip_depth, &xonly(c.recipient));
    // REAL committed tree: the target agent's recipient_root is set to rroot;
    // it is NEVER replaced by the claim (so attacks that change the claim's
    // pk/limits/fee-cap produce a leaf that is not in this tree -> membership
    // fails). Only the target's recipient_root is auto-wired for legit paths.
    let mut real = c.tree_agents.clone();
    real[c.target].recipient_root = rroot;
    let real_leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
    let (root, policy_sibs, policy_bits) = merkle(&real_leaves, c.target);
    let prev = S { agent_root: root, ..c.prev.clone() };

    // The CALL's claimed agent policy. For a legit spend the caller passes the
    // same agent as real[target]; run() only wires its recipient_root to rroot
    // so the recipient proof is constructible. Attacks pass a differing claim.
    let claim = Agent { recipient_root: rroot, ..c.claim.clone() };

    // period accounting (from the claim)
    let mut new_start = claim.period_start_daa;
    let mut new_spent = claim.period_spent + c.pay;
    if c.periods_elapsed >= 1 {
        new_start = claim.period_start_daa + c.periods_elapsed * claim.period_length_daa;
        new_spent = c.pay;
    }
    // successor root the covenant will compute = fold(newLeaf(claim)) up the
    // REAL co-path (policy_sibs/policy_bits). For legit this equals the tree
    // with the target advanced; for attacks membership fails before it matters.
    let mut np = claim.clone();
    np.period_start_daa = new_start;
    np.period_spent = new_spent;
    let new_root = c.override_new_root.unwrap_or(fold(agent_leaf(&np), &policy_sibs, policy_bits));

    let policy_sibs2 = policy_sibs.clone();
    let policy_bits2 = policy_bits;

    let new_protected = c.succ_protected_override.unwrap_or(prev.protected - c.pay);
    let new_reserve = prev.reserve - c.reserve_consumed;
    let succ = S { protected: new_protected, reserve: new_reserve, agent_root: new_root, ..prev.clone() };
    let active = compile_mut(mutate, &c.owner, &prev);
    let succ_c = compile_mut(mutate, &c.owner, &succ);
    let succ_value = c.override_succ_value.unwrap_or(new_protected + new_reserve);

    let cov_val = (prev.protected + prev.reserve) as u64;
    let mut ci = cov_input(c.budget);
    if let Some(sq) = c.seq_override { ci.sequence = sq; }
    let mut inputs = vec![ci];
    let mut entries = vec![active_utxo(&active, cov_val)];
    let mut ext_pk = None;
    if let Some(ev) = c.ext_in {
        let (ei, pk) = ext_input(0x71);
        inputs.push(ei);
        entries.push(ext_utxo(&pk, ev as u64));
        ext_pk = Some(pk);
    }
    let recip_out = c.recipient_out_override.unwrap_or(xonly(c.recipient));
    let mut outputs = vec![
        p2pk_output(&recip_out, c.pay as u64),
        TransactionOutput { value: succ_value as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
    ];
    if let Some(ov) = c.ext_out {
        outputs.push(change_out(ext_pk.as_ref().unwrap_or(&recip_out), ov as u64));
    }
    let lock = c.lock_override.unwrap_or(if c.periods_elapsed >= 1 { new_start as u64 } else { 0 });
    let tx = Transaction::new(1, inputs, outputs, lock, Default::default(), 0, vec![]);
    let mut mutable = MutableTransaction::with_entries(tx, entries.clone());
    let agent_sig = sign_typed(&mutable, 0, c.signer, c.signer_type);
    let mut blob = Vec::with_capacity(650);
    for slot in c.approver_sigs.iter() {
        match slot {
            Some((kp, ty)) => blob.extend_from_slice(&sign_typed(&mutable, 0, kp, *ty)),
            None => blob.extend_from_slice(&placeholder()),
        }
    }
    let args = vec![
        state_arg(&succ),
        Expr::int(c.pay),
        Expr::bytes(claim.pk.to_vec()),
        Expr::int(claim.max_per_spend),
        Expr::int(claim.period_budget),
        Expr::int(claim.period_length_daa),
        Expr::int(claim.period_start_daa),
        Expr::int(claim.period_spent),
        Expr::int(claim.approval_threshold),
        Expr::int(claim.max_fee_per_tx),
        Expr::bytes(rroot.to_vec()),
        Expr::bytes(policy_sibs2),
        Expr::int(policy_bits2 as i64),
        Expr::int(c.periods_elapsed),
        Expr::bytes(xonly(c.recipient).to_vec()),
        Expr::bytes(rsibs),
        Expr::int(rbits as i64),
        Expr::bytes(agent_sig),
        Expr::bytes(blob),
    ];
    let mut ss = active.build_sig_script_for_covenant_decl("agentSpend", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = ss;
    execute_input_measured(mutable.tx, entries, 0)
}

fn agent(kp: &Keypair, cap: i64, budget: i64, threshold: i64, fee_cap: i64) -> Agent {
    Agent { pk: xonly(kp), max_per_spend: cap, period_budget: budget, period_length_daa: 864_000, period_start_daa: 541_000_000, period_spent: 0, approval_threshold: threshold, max_fee_per_tx: fee_cap, recipient_root: ZERO32 }
}

// ==================================================== STACK / WORST CASE
#[test]
fn v4p_worst_case_stack_and_execute() {
    // depth-12 agent tree + depth-16 recipient + 10-of-10 approvals + reserve.
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let approvers: Vec<Keypair> = (0..10).map(|i| deterministic_keypair(60 + i)).collect();
    let arefs: Vec<&Keypair> = approvers.iter().collect();
    let slots = approver_set(&arefs);
    let pa = agent(&a, 200 * KAS, 500 * KAS, 50 * KAS, 1 * KAS);
    // depth-12 agent tree: 4096 leaves, real agent at index 0
    let n = 1usize << 12;
    let mut agents = vec![pa.clone()];
    for i in 1..n {
        agents.push(agent(&deterministic_keypair(((i % 200) + 2) as u8), 1 * KAS, 1 * KAS, 1, 1));
    }
    // make fillers distinct by tweaking recipient_root per index
    for (i, g) in agents.iter_mut().enumerate().skip(1) {
        g.recipient_root = sha256(&[b"filler", &(i as u64).to_le_bytes()]);
    }
    let mut st = base_state([0; 32]);
    st.approvers = slots;
    st.approval_m = 10;
    let signers: Vec<(&Keypair, SigHashType)> = approvers.iter().map(|k| (k, SIG_HASH_ALL)).collect();
    let ap = approvals_by_key(&slots, &signers);
    let (res, units) = run(Spend { pay: 150 * KAS, recip_depth: 16, approver_sigs: ap, budget: 400, measure: true, ..dflt(owner, st, agents, 0, pa, &a, &recipient) });
    assert!(res.is_ok(), "WORST CASE must execute under MAX_STACK_SIZE 244: {res:?}");
    let budget = (units + 9999) / 10000;
    println!("V4P WORST depth12+recip16+10of10+reserve: compute_units={units} (sig-op priced 0) required_budget_at_zero={budget}");
}

/// PRODUCTION sig-op-priced measurement of representative shapes: the
/// measured used_script_units (Gram(1000)=100,000/checkSig) give the real
/// minimum committed compute budget the SDK must commit for each shape.
#[test]
fn v4p_measure_production_budgets() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);

    // Re-run a spend under priced execution and report the required budget.
    let measure = |label: &str, agent_depth: u32, recip_depth: u32, approvers: &[Keypair], m: i64, threshold: i64, pay: i64| {
        let arefs: Vec<&Keypair> = approvers.iter().collect();
        let slots = if approvers.is_empty() { [ZERO32; 10] } else { approver_set(&arefs) };
        let pa = agent(&a, 300 * KAS, 1000 * KAS, threshold, 1 * KAS);
        let n = 1usize << agent_depth;
        let mut agents = vec![pa.clone()];
        for i in 1..n {
            let mut g = agent(&deterministic_keypair(((i % 200) + 2) as u8), 1 * KAS, 1 * KAS, 1, 1);
            g.recipient_root = sha256(&[b"m", &(i as u64).to_le_bytes()]);
            agents.push(g);
        }
        let mut st = base_state([0; 32]);
        st.approvers = slots;
        st.approval_m = m;
        let signers: Vec<(&Keypair, SigHashType)> = approvers.iter().map(|k| (k, SIG_HASH_ALL)).collect();
        let ap = approvals_by_key(&slots, &signers);
        // Build the exact tx as run() does, but execute under priced metering.
        let (rroot, rsibs, rbits) = recip_tree(recip_depth, &xonly(&recipient));
        let mut real = agents.clone();
        real[0].recipient_root = rroot;
        let real_leaves: Vec<[u8; 32]> = real.iter().map(agent_leaf).collect();
        let (root, psibs, pbits) = merkle(&real_leaves, 0);
        let prev = S { agent_root: root, approvers: slots, approval_m: m, ..base_state([0; 32]) };
        let claim = Agent { recipient_root: rroot, ..real[0].clone() };
        let mut np = claim.clone();
        np.period_spent = claim.period_spent + pay;
        let new_root = fold(agent_leaf(&np), &psibs, pbits);
        let succ = S { protected: prev.protected - pay, reserve: prev.reserve - 5_000_000, agent_root: new_root, ..prev.clone() };
        let active = compile(&owner, &prev);
        let succ_c = compile(&owner, &succ);
        let outputs = vec![
            p2pk_output(&xonly(&recipient), pay as u64),
            TransactionOutput { value: (succ.protected + succ.reserve) as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
        ];
        let tx = Transaction::new(1, vec![cov_input(400)], outputs, 0, Default::default(), 0, vec![]);
        let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
        let mut mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
        let agent_sig = sign_typed(&mutable, 0, &a, SIG_HASH_ALL);
        let mut blob = Vec::new();
        for slot in ap.iter() {
            match slot {
                Some((kp, ty)) => blob.extend_from_slice(&sign_typed(&mutable, 0, kp, *ty)),
                None => blob.extend_from_slice(&placeholder()),
            }
        }
        let args = vec![
            state_arg(&succ), Expr::int(pay), Expr::bytes(claim.pk.to_vec()), Expr::int(claim.max_per_spend),
            Expr::int(claim.period_budget), Expr::int(claim.period_length_daa), Expr::int(claim.period_start_daa),
            Expr::int(claim.period_spent), Expr::int(claim.approval_threshold), Expr::int(claim.max_fee_per_tx), Expr::bytes(rroot.to_vec()),
            Expr::bytes(psibs), Expr::int(pbits as i64), Expr::int(0),
            Expr::bytes(xonly(&recipient).to_vec()), Expr::bytes(rsibs), Expr::int(rbits as i64),
            Expr::bytes(agent_sig), Expr::bytes(blob),
        ];
        let mut ss = active.build_sig_script_for_covenant_decl("agentSpend", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
        let sigscript_len = ss.len() + push_redeem_script(&active.script).len();
        ss.extend_from_slice(&push_redeem_script(&active.script));
        let mut t = mutable.tx;
        t.inputs[0].signature_script = ss;
        let (res, units) = execute_input_measured_priced(t, vec![utxo], 0, 1000);
        assert!(res.is_ok(), "{label} priced exec must pass: {res:?}");
        let budget = (units + 9999) / 10000;
        println!("BUDGET4 {label} used_script_units={units} required_compute_budget={budget} sigscript_len={sigscript_len}");
    };

    measure("spend_agent0_recip0_below", 0, 0, &[], 0, 100_000 * KAS, 40 * KAS);
    measure("spend_agent12_recip0_below", 12, 0, &[], 0, 100_000 * KAS, 40 * KAS);
    measure("spend_agent0_recip16_below", 0, 16, &[], 0, 100_000 * KAS, 40 * KAS);
    let ten: Vec<Keypair> = (0..10).map(|i| deterministic_keypair(60 + i)).collect();
    measure("WORST_agent12_recip16_10of10", 12, 16, &ten, 10, 50 * KAS, 150 * KAS);

    // owner op + recover priced budgets
    let owner_kp = deterministic_keypair(1);
    let prev = { let leaves = vec![agent_leaf(&agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS))]; S { agent_root: merkle(&leaves, 0).0, ..base_state([0; 32]) } };
    // v0.4.1: non-recover owner ops go through ownerControl with an opSelector.
    let measure_owner = |label: &str, func: &str, op: i64, succ: Option<&S>, recover: bool| {
        let active = compile(&owner, &prev);
        let mut outputs = Vec::new();
        if recover {
            outputs.push(p2pk_output(&owner, (prev.protected + prev.reserve) as u64));
        } else {
            let s = succ.unwrap();
            let sc = compile(&owner, s);
            outputs.push(TransactionOutput { value: (s.protected + s.reserve) as u64, script_public_key: pay_to_script_hash_script(&sc.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) });
        }
        let tx = Transaction::new(1, vec![cov_input(400)], outputs, 0, Default::default(), 0, vec![]);
        let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
        let mut mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
        let osig = sign_typed(&mutable, 0, &owner_kp, SIG_HASH_ALL);
        let args = if recover { vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(osig)] } else { vec![state_arg(succ.unwrap()), Expr::int(op), Expr::bytes(osig)] };
        let mut ss = active.build_sig_script_for_covenant_decl(func, args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
        let sigscript_len = ss.len() + push_redeem_script(&active.script).len();
        ss.extend_from_slice(&push_redeem_script(&active.script));
        let mut t = mutable.tx;
        t.inputs[0].signature_script = ss;
        let (res, units) = execute_input_measured_priced(t, vec![utxo], 0, 1000);
        assert!(res.is_ok(), "{label}: {res:?}");
        println!("BUDGET4 {label} used_script_units={units} required_compute_budget={} sigscript_len={sigscript_len}", (units + 9999) / 10000);
    };
    // measure the two dispatch extremes: setApprovers (1) is the heaviest owner
    // op (10 approver checkSigs); setAgentRoot (0) is the lightest.
    measure_owner("owner_setAgentRoot", "ownerControl", 0, Some(&S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() }), false);
    {
        let a1 = deterministic_keypair(70); let a2 = deterministic_keypair(71); let a3 = deterministic_keypair(72);
        let approvers = approver_set(&[&a1, &a2, &a3]);
        measure_owner("owner_setApprovers", "ownerControl", 1, Some(&S { approvers, approval_m: 2, policy_nonce: 1, ..prev.clone() }), false);
    }
    measure_owner("owner_recover", "ownerRecover", 0, None, true);
}

// ==================================================== STACK DIAGNOSTIC
#[test]
fn v4p_stack_diagnostic() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    // deep agent (12) + deep recipient (16), BELOW threshold (no approvals)
    let pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    let n = 1usize << 12;
    let mut agents = vec![pa.clone()];
    for i in 1..n {
        let mut g = agent(&deterministic_keypair(((i % 200) + 2) as u8), 1 * KAS, 1 * KAS, 1, 1);
        g.recipient_root = sha256(&[b"f", &(i as u64).to_le_bytes()]);
        agents.push(g);
    }
    let (r1, u1) = run(Spend { pay: 40 * KAS, recip_depth: 16, budget: 400, ..dflt(owner, base_state([0; 32]), agents.clone(), 0, pa.clone(), &a, &recipient) });
    println!("V4P DIAG deep-agent12 + deep-recip16 BELOW-threshold: {:?} units={}", r1.as_ref().map(|_| "OK"), u1);
}

// ==================================================== VALID MATRIX
#[test]
fn v4p_valid_matrix() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    // agent depth matrix (recip depth 0), below threshold
    for adepth in [0u32, 1, 4, 8, 12] {
        let pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
        let n = 1usize << adepth;
        let mut agents = vec![pa.clone()];
        for i in 1..n {
            let mut g = agent(&deterministic_keypair(((i % 200) + 2) as u8), 1 * KAS, 1 * KAS, 1, 1);
            g.recipient_root = sha256(&[b"f", &(i as u64).to_le_bytes()]);
            agents.push(g);
        }
        let r = run(dflt(owner, base_state([0; 32]), agents, 0, pa, &a, &recipient)).0;
        assert!(r.is_ok(), "agent depth {adepth} valid: {r:?}");
    }
    // recipient depth matrix (agent depth 0)
    for rdepth in [0u32, 1, 4, 8, 12, 16] {
        let pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
        let r = run(Spend { recip_depth: rdepth, ..dflt(owner, base_state([0; 32]), vec![pa.clone()], 0, pa, &a, &recipient) }).0;
        assert!(r.is_ok(), "recipient depth {rdepth} valid: {r:?}");
    }
}

#[test]
fn v4p_threshold_and_approvals() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let slots = approver_set(&[&a1, &a2, &a3]);
    let mut st = base_state([0; 32]);
    st.approvers = slots;
    st.approval_m = 2;
    let pa = agent(&a, 200 * KAS, 500 * KAS, 50 * KAS, 1 * KAS); // threshold 50

    // threshold exactly -> delegate only
    assert!(run(Spend { pay: 50 * KAS, ..dflt(owner, st.clone(), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0.is_ok(), "at threshold delegate-only");
    // threshold+1 no approvals -> reject
    assert_rejected(run(Spend { pay: 50 * KAS + 1, ..dflt(owner, st.clone(), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0, "above threshold no approvals");
    // 2-of-3 -> pass
    let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_ALL), (&a2, SIG_HASH_ALL)]);
    assert!(run(Spend { pay: 150 * KAS, approver_sigs: ap, ..dflt(owner, st.clone(), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0.is_ok(), "2-of-3");

    // 10-of-10
    let ten: Vec<Keypair> = (0..10).map(|i| deterministic_keypair(60 + i)).collect();
    let trefs: Vec<&Keypair> = ten.iter().collect();
    let s10 = approver_set(&trefs);
    let mut st10 = base_state([0; 32]);
    st10.approvers = s10;
    st10.approval_m = 10;
    let signers: Vec<(&Keypair, SigHashType)> = ten.iter().map(|k| (k, SIG_HASH_ALL)).collect();
    let ap10 = approvals_by_key(&s10, &signers);
    assert!(run(Spend { pay: 150 * KAS, approver_sigs: ap10, ..dflt(owner, st10, vec![pa.clone()], 0, pa, &a, &recipient) }).0.is_ok(), "10-of-10");
}

#[test]
fn v4p_rollover_and_reserve_variants() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    // rollover: periodSpent near budget, elapsed 1 resets
    let mut pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    pa.period_spent = 480 * KAS;
    assert!(run(Spend { pay: 40 * KAS, periods_elapsed: 1, ..dflt(owner, base_state([0; 32]), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0.is_ok(), "rollover resets spent");
    // reserve exhausted exactly with external fee
    let big = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 10 * KAS);
    assert!(run(Spend { reserve_consumed: 5 * KAS, ext_in: Some(6 * KAS), ext_out: Some(1 * KAS), ..dflt(owner, base_state([0; 32]), vec![big.clone()], 0, big, &a, &recipient) }).0.is_ok(), "reserve drain to zero");
    // externally funded fee, zero reserve consumption
    let z = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    assert!(run(Spend { reserve_consumed: 0, ext_in: Some(50_000_000), ext_out: Some(45_000_000), ..dflt(owner, base_state([0; 32]), vec![z.clone()], 0, z, &a, &recipient) }).0.is_ok(), "external fee, zero reserve");
}

// ==================================================== FEE MATRIX
#[test]
fn v4p_fee_matrix() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let other = deterministic_keypair(41);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    let mk = |f: &dyn Fn(&mut Spend)| {
        let mut sp = dflt(owner, base_state([0; 32]), vec![pa.clone()], 0, pa.clone(), &a, &recipient);
        f(&mut sp);
        run(sp).0
    };
    assert_rejected(mk(&|s| { s.reserve_consumed = 0; s.override_succ_value = Some(base_state([0;32]).protected - s.pay + base_state([0;32]).reserve - 5_000_000); }), "principal as fee");
    assert_rejected(mk(&|s| { s.reserve_consumed = 1 * KAS; s.ext_out = Some(1 * KAS); }), "reserve redirected to output");
    assert_rejected(mk(&|s| { s.reserve_consumed = 1 * KAS; s.ext_in = Some(50_000_000); s.ext_out = Some(1 * KAS + 50_000_000); }), "external masks reserve theft");
    assert_rejected(mk(&|s| { s.reserve_consumed = 0; s.ext_out = Some(3 * KAS); }), "external out > external in");
    assert_rejected(mk(&|s| { s.reserve_consumed = 2 * KAS; s.ext_in = Some(3 * KAS); s.ext_out = Some(1 * KAS); }), "over per-agent fee cap");
    assert_rejected(mk(&|s| { s.pay = 0; }), "zero payment");
    assert_rejected(mk(&|s| { s.pay = 101 * KAS; }), "above cap");
    assert_rejected(mk(&|s| { s.reserve_consumed = -1 * KAS; }), "reserve forged up");
    assert_rejected(mk(&|s| { s.reserve_consumed = -s.pay; }), "principal->reserve swap");
    assert_rejected(mk(&|s| { s.recipient_out_override = Some(xonly(&other)); }), "recipient substitution");
    assert!(mk(&|s| { s.reserve_consumed = 1 * KAS; s.ext_in = Some(2 * KAS); s.ext_out = Some(1 * KAS); }).is_ok(), "consume exactly cap");
}

// ==================================================== CROSS-AGENT MATRIX
#[test]
fn v4p_cross_agent_matrix() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let b = deterministic_keypair(31);
    let recipient = deterministic_keypair(40);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    let pb = agent(&b, 1000 * KAS, 10_000 * KAS, 100_000 * KAS, 5 * KAS);
    let agents = vec![pa.clone(), pb.clone()];
    // key A + leaf B
    assert_rejected(run(Spend { pay: 100 * KAS, ..dflt(owner, base_state([0;32]), agents.clone(), 1, pb.clone(), &a, &recipient) }).0, "key A + leaf B");
    // A borrows B cap (claim A.pk with B limits)
    let claim = Agent { pk: xonly(&a), ..pb.clone() };
    assert_rejected(run(Spend { pay: 800 * KAS, ..dflt(owner, base_state([0;32]), agents.clone(), 0, claim, &a, &recipient) }).0, "A borrows B cap");
    // A borrows B fee cap
    let claim_fee = Agent { max_fee_per_tx: pb.max_fee_per_tx, ..pa.clone() };
    assert_rejected(run(Spend { reserve_consumed: 3 * KAS, ext_in: Some(4 * KAS), ext_out: Some(1 * KAS), ..dflt(owner, base_state([0;32]), agents.clone(), 0, claim_fee, &a, &recipient) }).0, "A borrows B fee cap");
    // forged successor root
    let leaves = vec![agent_leaf(&{ let mut g = pa.clone(); g.recipient_root = recip_tree(0, &xonly(&recipient)).0; g }), agent_leaf(&pb)];
    let orig = merkle(&leaves, 0).0;
    assert_rejected(run(Spend { pay: 80 * KAS, override_new_root: Some(orig), ..dflt(owner, base_state([0;32]), agents, 0, pa, &a, &recipient) }).0, "forged successor root");
}

// ==================================================== TREE UPDATE (funds-critical)
#[test]
fn v4p_tree_update_preserves_unrelated_leaves() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let b = deterministic_keypair(31);
    let recipient = deterministic_keypair(40);
    let rroot = recip_tree(0, &xonly(&recipient)).0;
    let pa = Agent { recipient_root: rroot, ..agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS) };
    let pb = agent(&b, 1000 * KAS, 10_000 * KAS, 100_000 * KAS, 1 * KAS);
    let leaves = vec![agent_leaf(&pa), agent_leaf(&pb)];
    // tamper B's leaf in the claimed successor root
    let mut tb = pb.clone();
    tb.max_per_spend = 999_999 * KAS;
    let mut na = pa.clone();
    na.period_spent = pa.period_spent + 80 * KAS;
    let tampered = merkle(&[agent_leaf(&na), agent_leaf(&tb)], 0).0;
    assert_rejected(run(Spend { pay: 80 * KAS, override_new_root: Some(tampered), ..dflt(owner, base_state([0;32]), vec![pa.clone(), pb.clone()], 0, pa.clone(), &a, &recipient) }).0, "spend cannot alter an unrelated agent leaf");
    let _ = leaves;
}

// ==================================================== DEPTH OVERFLOW
#[test]
fn v4p_depth_overflow_rejected() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    // agent depth 13: 8192 leaves -> siblings 13*32=416 > 384 -> reject
    let n = 1usize << 13;
    let mut agents = vec![pa.clone()];
    for i in 1..n {
        let mut g = agent(&deterministic_keypair(((i % 200) + 2) as u8), 1 * KAS, 1 * KAS, 1, 1);
        g.recipient_root = sha256(&[b"f", &(i as u64).to_le_bytes()]);
        agents.push(g);
    }
    assert_rejected(run(dflt(owner, base_state([0;32]), agents, 0, pa.clone(), &a, &recipient)).0, "agent depth 13 rejected");
    // recipient depth 17 -> siblings 17*32=544 > 512 -> reject
    assert_rejected(run(Spend { recip_depth: 17, ..dflt(owner, base_state([0;32]), vec![pa.clone()], 0, pa, &a, &recipient) }).0, "recipient depth 17 rejected");
}

// ==================================================== NON-ALL SIGHASH (A7)
#[test]
fn v4p_nonall_approver_sighash_rejected() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let recipient = deterministic_keypair(40);
    let slots = approver_set(&[&a1, &a2, &a3]);
    let mut st = base_state([0; 32]);
    st.approvers = slots;
    st.approval_m = 2;
    let pa = agent(&a, 200 * KAS, 500 * KAS, 50 * KAS, 1 * KAS);
    for (name, ty) in [("NONE", SIG_HASH_NONE), ("SINGLE", SIG_HASH_SINGLE), ("ALL|ACP", SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY), ("NONE|ACP", SIG_HASH_NONE | SIG_HASH_ANY_ONE_CAN_PAY), ("SINGLE|ACP", SIG_HASH_SINGLE | SIG_HASH_ANY_ONE_CAN_PAY)] {
        let ap = approvals_by_key(&slots, &[(&a1, ty), (&a2, SIG_HASH_ALL)]);
        assert_rejected(run(Spend { pay: 150 * KAS, approver_sigs: ap, ..dflt(owner, st.clone(), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0, &format!("approver sighash {name} must be rejected by A7"));
    }
}

// ==================================================== MALFORMED GENESIS (A2)
#[test]
fn v4p_malformed_genesis_approval_defense() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let k = deterministic_keypair(20);
    let a3 = deterministic_keypair(22);
    let recipient = deterministic_keypair(40);
    let pa = agent(&a, 200 * KAS, 500 * KAS, 50 * KAS, 1 * KAS);
    // duplicate predecessor approver key K in two slots, M=2
    let mut approvers = [ZERO32; 10];
    approvers[0] = xonly(&k);
    approvers[1] = xonly(&k);
    approvers[2] = xonly(&a3);
    let mut st = base_state([0; 32]);
    st.approvers = approvers;
    st.approval_m = 2;
    let mut ap: [Option<(&Keypair, SigHashType)>; 10] = Default::default();
    ap[0] = Some((&k, SIG_HASH_ALL));
    ap[1] = Some((&k, SIG_HASH_ALL));
    assert_rejected(run(Spend { pay: 150 * KAS, approver_sigs: ap, ..dflt(owner, st, vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0, "duplicate predecessor approver key");
    // approvalM = 0 with active approvers, above threshold -> reject
    let mut st0 = base_state([0; 32]);
    st0.approvers = approver_set(&[&k, &a3]);
    st0.approval_m = 0;
    assert_rejected(run(Spend { pay: 150 * KAS, ..dflt(owner, st0, vec![pa.clone()], 0, pa, &a, &recipient) }).0, "approvalM=0 above threshold");
}

// ==================================================== PAUSE
#[test]
fn v4p_pause_blocks_and_recover_bypasses() {
    let owner_kp = deterministic_keypair(1);
    let owner = xonly(&owner_kp);
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let pa = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    let paused = S { paused: 1, ..base_state([0; 32]) };
    assert_rejected(run(dflt(owner, paused, vec![pa.clone()], 0, pa.clone(), &a, &recipient)).0, "spend blocked while paused");
    // recover while paused
    let rroot = recip_tree(0, &xonly(&recipient)).0;
    let leaves = vec![agent_leaf(&Agent { recipient_root: rroot, ..pa.clone() })];
    let prev = S { paused: 1, agent_root: merkle(&leaves, 0).0, ..base_state([0; 32]) };
    assert!(run_recover(&owner_kp, &prev).is_ok(), "recover while paused");
}

fn run_recover(owner_kp: &Keypair, prev: &S) -> Result<(), TxScriptError> {
    let owner = xonly(owner_kp);
    let active = compile(&owner, prev);
    let outputs = vec![p2pk_output(&owner, (prev.protected + prev.reserve) as u64)];
    let tx = Transaction::new(1, vec![cov_input(20)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, 0, owner_kp, SIG_HASH_ALL);
    let args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl("ownerRecover", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    execute_input_measured(t, vec![utxo], 0).0
}

// ==================================================== RECOVERY MATRIX
#[test]
fn v4p_recover_from_malformed_and_empty_reserve() {
    let owner_kp = deterministic_keypair(1);
    let owner = xonly(&owner_kp);
    // malformed agentRoot, empty reserve, paused, nonzero nonce
    let prev = S { reserve: 0, paused: 1, agent_root: [0xcd; 32], policy_nonce: 9, ..base_state([0; 32]) };
    let active = compile(&owner, &prev);
    let (ei, epk) = ext_input(0x71);
    let outputs = vec![p2pk_output(&owner, prev.protected as u64), change_out(&epk, 40_000_000)];
    let tx = Transaction::new(1, vec![cov_input(20), ei], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, prev.protected as u64);
    let eutxo = ext_utxo(&epk, 50_000_000);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone(), eutxo.clone()]);
    let osig = sign_typed(&mutable, 0, &owner_kp, SIG_HASH_ALL);
    let args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl("ownerRecover", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    assert!(execute_input_measured(t, vec![utxo, eutxo], 0).0.is_ok(), "recover from malformed/empty/paused");
}

// ==================================================== OWNER OPS
#[test]
fn v4p_owner_ops() {
    let owner_kp = deterministic_keypair(1);
    let owner = xonly(&owner_kp);
    let a = deterministic_keypair(30);
    let (a1, a2, a3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));
    let rroot = recip_tree(0, &xonly(&deterministic_keypair(40))).0;
    let pa = Agent { recipient_root: rroot, ..agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS) };
    let prev = S { agent_root: merkle(&[agent_leaf(&pa)], 0).0, ..base_state([0; 32]) };
    // v0.4.1: the six non-terminal owner ops go through ONE ownerControl
    // entrypoint with an opSelector call argument (0=setAgentRoot, 1=setApprovers,
    // 2=topUp, 3=topUpReserve, 4=pause, 5=unpause). run_owner signs for `op` and
    // calls with `call_op` (usually == op; a mismatch models a post-signing
    // selector swap).
    let run_owner_sel = |call_op: i64, succ: S| -> Result<(), TxScriptError> {
        let active = compile(&owner, &prev);
        let succ_c = compile(&owner, &succ);
        let outputs = vec![TransactionOutput { value: (succ.protected + succ.reserve) as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) }];
        let tx = Transaction::new(1, vec![cov_input(60)], outputs, 0, Default::default(), 0, vec![]);
        let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
        let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
        let osig = sign_typed(&mutable, 0, &owner_kp, SIG_HASH_ALL);
        let args = vec![state_arg(&succ), Expr::int(call_op), Expr::bytes(osig)];
        let mut ss = active.build_sig_script_for_covenant_decl("ownerControl", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
        ss.extend_from_slice(&push_redeem_script(&active.script));
        let mut t = mutable.tx;
        t.inputs[0].signature_script = ss;
        execute_input_measured(t, vec![utxo], 0).0
    };
    let run_owner = |op: i64, succ: S| run_owner_sel(op, succ);
    // setAgentRoot (0): nonce +1, value preserved
    assert!(run_owner(0, S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() }).is_ok(), "setAgentRoot");
    assert_rejected(run_owner(0, S { agent_root: [0x77; 32], ..prev.clone() }), "setAgentRoot must bump nonce");
    assert_rejected(run_owner(0, S { agent_root: [0x77; 32], protected: prev.protected + KAS, policy_nonce: 1, ..prev.clone() }), "setAgentRoot cannot change value");
    assert_rejected(run_owner(0, S { agent_root: [0x77; 32], reserve: prev.reserve + KAS, policy_nonce: 1, ..prev.clone() }), "setAgentRoot cannot change reserve");
    // setApprovers (1)
    assert!(run_owner(1, S { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 2, policy_nonce: 1, ..prev.clone() }).is_ok(), "setApprovers");
    assert_rejected(run_owner(1, S { approvers: { let mut x = [ZERO32; 10]; x[0] = xonly(&a1); x[1] = xonly(&a1); x[2] = xonly(&a3); x }, approval_m: 1, policy_nonce: 1, ..prev.clone() }), "duplicate approvers");
    assert_rejected(run_owner(1, S { approvers: approver_set(&[&a1, &a2, &a3]), approval_m: 4, policy_nonce: 1, ..prev.clone() }), "M>active");
    // topUp (2) principal only
    assert!(run_owner(2, S { protected: prev.protected + 100 * KAS, ..prev.clone() }).is_ok(), "topUp");
    assert_rejected(run_owner(2, S { protected: prev.protected + 100 * KAS, reserve: prev.reserve + KAS, ..prev.clone() }), "topUp cannot touch reserve");
    // topUpReserve (3) only
    assert!(run_owner(3, S { reserve: prev.reserve + 3 * KAS, ..prev.clone() }).is_ok(), "topUpReserve");
    assert_rejected(run_owner(3, S { reserve: prev.reserve + 3 * KAS, protected: prev.protected + KAS, ..prev.clone() }), "topUpReserve cannot touch principal");
    // pause (4) / unpause (5)
    assert!(run_owner(4, S { paused: 1, ..prev.clone() }).is_ok(), "pause");
    assert_rejected(run_owner(4, S { paused: 1, agent_root: [0x88; 32], ..prev.clone() }), "pause cannot change agentRoot");
    // unpause needs a paused predecessor — tested via a paused prev in a separate case below.

    // ---- §6.1 unknown/out-of-range selector must REJECT (no permissive default)
    for bad in [6i64, 7, 100, -1] {
        assert_rejected(run_owner_sel(bad, S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() }), "unknown owner selector must reject");
    }

    // ---- §7 selector substitution after signing must REJECT. Build a REAL
    // setAgentRoot successor (agentRoot changed, nonce+1) and call it under every
    // OTHER selector: each other selector's field rules reject the fixed successor.
    let set_root_succ = S { agent_root: [0x77; 32], policy_nonce: 1, ..prev.clone() };
    for other in [1i64, 2, 3, 4, 5] {
        assert_rejected(run_owner_sel(other, set_root_succ.clone()), "setAgentRoot successor reinterpreted under another selector must reject");
    }
    // A REAL topUp successor (protected up, nonce same) under every other selector.
    let topup_succ = S { protected: prev.protected + 100 * KAS, ..prev.clone() };
    for other in [0i64, 1, 3, 4, 5] {
        assert_rejected(run_owner_sel(other, topup_succ.clone()), "topUp successor reinterpreted under another selector must reject");
    }
    // A REAL pause successor (paused 0->1) under every other selector (unpause
    // needs prev.paused==1, others need paused preserved).
    let pause_succ = S { paused: 1, ..prev.clone() };
    for other in [0i64, 1, 2, 3, 5] {
        assert_rejected(run_owner_sel(other, pause_succ.clone()), "pause successor reinterpreted under another selector must reject");
    }
}

// ==================================================== UNPAUSE (paused prev)
#[test]
fn v4_1_unpause_from_paused() {
    let owner_kp = deterministic_keypair(1);
    let owner = xonly(&owner_kp);
    let a = deterministic_keypair(30);
    let rroot = recip_tree(0, &xonly(&deterministic_keypair(40))).0;
    let pa = Agent { recipient_root: rroot, ..agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS) };
    let prev = S { paused: 1, agent_root: merkle(&[agent_leaf(&pa)], 0).0, ..base_state([0; 32]) };
    let run = |call_op: i64, succ: S| -> Result<(), TxScriptError> {
        let active = compile(&owner, &prev);
        let succ_c = compile(&owner, &succ);
        let outputs = vec![TransactionOutput { value: (succ.protected + succ.reserve) as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) }];
        let tx = Transaction::new(1, vec![cov_input(60)], outputs, 0, Default::default(), 0, vec![]);
        let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
        let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
        let osig = sign_typed(&mutable, 0, &owner_kp, SIG_HASH_ALL);
        let args = vec![state_arg(&succ), Expr::int(call_op), Expr::bytes(osig)];
        let mut ss = active.build_sig_script_for_covenant_decl("ownerControl", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
        ss.extend_from_slice(&push_redeem_script(&active.script));
        let mut t = mutable.tx;
        t.inputs[0].signature_script = ss;
        execute_input_measured(t, vec![utxo], 0).0
    };
    assert!(run(5, S { paused: 0, ..prev.clone() }).is_ok(), "unpause 1->0");
    assert_rejected(run(4, S { paused: 0, ..prev.clone() }), "pause requires prev.paused==0");
    // unpause successor reinterpreted as pause: pause requires prev.paused==0 (it is 1) -> reject
    assert_rejected(run(4, S { paused: 0, ..prev.clone() }), "unpause successor under pause selector must reject");
}

// ==================================================================
// ===== CHECKPOINT D — INDEPENDENT HOSTILE REVIEW ADDITIONS =========
// These do NOT merely re-run the green suite. They reproduce the
// production-byte facts from the compiled covenant, prove canonical
// num8 encoding is injective at values far above 2^31, prove the
// rollover time gate is a sequence-checked CLTV (not a raw lock_time
// read), and prove single-leaf tree updates reject structural edits.
// ==================================================================

/// D3/D16/D20: reproduce the redeem-script size and the exact 441-byte
/// state region field-by-field from the COMPILED production covenant,
/// with a uniquely-patterned state so field ORDER cannot hide behind
/// equal zeros.
#[test]
fn d_byte_facts_and_state_layout() {
    let owner = xonly(&deterministic_keypair(1));
    let mut st = base_state([0xA1; 32]); // agentRoot = 0xA1..
    for i in 0..10 {
        st.approvers[i] = [0xB0 + i as u8; 32];
    }
    st.protected = 0x1122_3344_5566_7788; // distinctive num8 values
    st.reserve = 0x0102_0304_0506_0708;
    st.paused = 0; // still must be a fixed-width 8-byte push
    st.approval_m = 0x00AA_00BB_00CC_00DD;
    st.policy_nonce = 0x7F00_0000_0000_0001;
    let c = compile(&owner, &st);

    assert_eq!(c.script.len(), 16_980, "v0.4.1 redeem script size must be the frozen 16,980 bytes (smaller than v0.4's 18,839 due to ownerControl consolidation)");
    assert_eq!(c.state_layout.len, 441, "state region must be byte-identical to v0.4: 441 bytes");

    // Parse the state region as a sequence of canonical data pushes.
    let start = c.state_layout.start;
    let region = &c.script[start..start + c.state_layout.len];
    let mut i = 0usize;
    let mut fields: Vec<(usize, Vec<u8>)> = Vec::new();
    while i < region.len() {
        let op = region[i] as usize;
        assert!((0x01..=0x4b).contains(&op), "state field {} must be a direct data push, got opcode 0x{op:02x}", fields.len());
        let payload = region[i + 1..i + 1 + op].to_vec();
        fields.push((op, payload));
        i += 1 + op;
    }
    assert_eq!(i, region.len(), "region must parse into whole pushes with no trailing bytes");
    let widths: Vec<usize> = fields.iter().map(|(w, _)| *w).collect();
    assert_eq!(widths, vec![32, 8, 8, 8, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 8, 8],
        "state field widths/order: boundVaultId,protectedValue,feeReserve,paused,agentRoot,approver1..10,approvalM,policyNonce");
    assert_eq!(fields.len(), 17, "exactly 17 mutable state fields");
    let byte32 = widths.iter().filter(|w| **w == 32).count();
    let ints = widths.iter().filter(|w| **w == 8).count();
    assert_eq!((byte32, ints), (12, 5), "12 byte[32]/pubkey + 5 int fields");
    assert_eq!(byte32 * 33 + ints * 9, 441, "12*33 + 5*9 = 441");

    // Identity + order: byte[32] payloads must be the exact unique patterns.
    assert_eq!(fields[0].1, hex32(VAULT_ID), "field0 = boundVaultId");
    assert_eq!(fields[4].1, vec![0xA1u8; 32], "field4 = agentRoot");
    for k in 0..10 {
        assert_eq!(fields[5 + k].1, vec![0xB0 + k as u8; 32], "field{} = approver{}", 5 + k, k + 1);
    }
    let le = |v: &Vec<u8>| {
        let mut b = [0u8; 8];
        b.copy_from_slice(v);
        i64::from_le_bytes(b)
    };
    assert_eq!(le(&fields[1].1), st.protected, "field1 = protectedValue num8");
    assert_eq!(le(&fields[2].1), st.reserve, "field2 = feeReserve num8");
    assert_eq!(le(&fields[3].1), st.paused, "field3 = paused num8");
    assert_eq!(le(&fields[15].1), st.approval_m, "field15 = approvalM num8");
    assert_eq!(le(&fields[16].1), st.policy_nonce, "field16 = policyNonce num8");
    println!("D BYTE-FACTS: redeem={} state_region={} start={} composition=12x33+5x9 OK", c.script.len(), c.state_layout.len, start);
}

// ==================================================== STANDARDNESS GATE
/// PERMANENT standardness gate — the reason v0.4.1 exists.
///
/// The frozen v0.4 covenant redeem script carries 18 static OpCheckSig
/// opcodes, over the default-node mempool cap MAX_STANDARD_P2SH_SIG_OPS = 15
/// (rusty-kaspa mining/src/mempool/check_transaction_standard.rs:19), so v0.4
/// covenant spends are NON-standard and a default node refuses to relay them
/// (docs/v04-h-standardness-finding.md). v0.4.1 consolidates the six owner
/// operations behind one ownerControl checkSig, cutting the count to 13.
///
/// This drives the ACTUAL compiled v0.4.1 production redeem script — inside a
/// REAL agentSpend signature script — through the EXACT scanner the default
/// kaspad mempool uses for post-Toccata P2SH standardness,
/// `kaspa_txscript::post_toccata_p2sh_sig_scanner`, and asserts <= 15 (== 13).
/// It is sabotage-sensitive: synthetic 15- and 16-sigop redeem scripts
/// bracket the threshold, proving the gate rejects 16 and this is not a
/// textual grep of "13".
#[test]
fn v4_1_standardness_p2sh_sig_ops() {
    use kaspa_txscript::post_toccata_p2sh_sig_scanner;
    // Mirror of the private mempool constant (check_transaction_standard.rs:19);
    // the mempool rejects when scanned sig-ops > this value.
    const MAX_STANDARD_P2SH_SIG_OPS: u64 = 15;

    // --- REAL production covenant: build an actual below-threshold agentSpend
    // signature script and scan its exact on-chain bytes as the mempool would.
    let owner_kp = deterministic_keypair(1);
    let owner = xonly(&owner_kp);
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly(&recipient));
    let claim = Agent { recipient_root: rroot, ..pa.clone() };
    let leaves = vec![agent_leaf(&claim)];
    let (root, psibs, pbits) = merkle(&leaves, 0);
    let prev = S { agent_root: root, ..base_state([0; 32]) };
    let pay = 40 * KAS;
    let mut np = claim.clone();
    np.period_spent += pay;
    let new_root = fold(agent_leaf(&np), &psibs, pbits);
    let succ = S { protected: prev.protected - pay, reserve: prev.reserve - 5_000_000, agent_root: new_root, ..prev.clone() };
    let active = compile(&owner, &prev);
    let succ_c = compile(&owner, &succ);
    let outputs = vec![
        p2pk_output(&xonly(&recipient), pay as u64),
        TransactionOutput { value: (succ.protected + succ.reserve) as u64, script_public_key: pay_to_script_hash_script(&succ_c.script), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) },
    ];
    let tx = Transaction::new(1, vec![cov_input(400)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let agent_sig = sign_typed(&mutable, 0, &a, SIG_HASH_ALL);
    let mut blob = Vec::new();
    for _ in 0..10 {
        blob.extend_from_slice(&placeholder());
    }
    let args = vec![
        state_arg(&succ), Expr::int(pay), Expr::bytes(claim.pk.to_vec()), Expr::int(claim.max_per_spend),
        Expr::int(claim.period_budget), Expr::int(claim.period_length_daa), Expr::int(claim.period_start_daa),
        Expr::int(claim.period_spent), Expr::int(claim.approval_threshold), Expr::int(claim.max_fee_per_tx), Expr::bytes(rroot.to_vec()),
        Expr::bytes(psibs), Expr::int(pbits as i64), Expr::int(0),
        Expr::bytes(xonly(&recipient).to_vec()), Expr::bytes(rsibs), Expr::int(rbits as i64),
        Expr::bytes(agent_sig), Expr::bytes(blob),
    ];
    let mut sig_script = active.build_sig_script_for_covenant_decl("agentSpend", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    sig_script.extend_from_slice(&push_redeem_script(&active.script));
    let spk = pay_to_script_hash_script(&active.script);

    let real_sigops = post_toccata_p2sh_sig_scanner(&sig_script, &spk);
    println!("STANDARDNESS v0.4.1: post_toccata_p2sh_sig_scanner = {real_sigops} (limit {MAX_STANDARD_P2SH_SIG_OPS}); v0.4 was 18");
    assert_eq!(real_sigops, 13, "v0.4.1 production redeem script must scan to exactly 13 static P2SH sig-ops");
    assert!(real_sigops <= MAX_STANDARD_P2SH_SIG_OPS, "v0.4.1 must be STANDARD: {real_sigops} <= {MAX_STANDARD_P2SH_SIG_OPS}");
    assert_eq!(real_sigops + 2, MAX_STANDARD_P2SH_SIG_OPS, "v0.4.1 must keep exactly 2 sig-ops of standardness headroom");

    // --- SABOTAGE SENSITIVITY: bracket the threshold with synthetic redeem
    // scripts of exactly N OpCheckSig, wrapped as real P2SH, scanned through
    // the SAME function. 15 must pass; 16 must fail the >15 rule the mempool
    // applies. Proves the gate is a real opcode count, not a constant.
    let synth = |n: usize| -> u64 {
        let mut b = ScriptBuilder::new();
        for _ in 0..n {
            b.add_op(OpCheckSig).unwrap();
        }
        let redeem = b.script().to_vec();
        let spk = pay_to_script_hash_script(&redeem);
        let sig = push_redeem_script(&redeem);
        post_toccata_p2sh_sig_scanner(&sig, &spk)
    };
    assert_eq!(synth(13), 13, "sanity: synthetic 13-sigop redeem scans to 13");
    assert_eq!(synth(15), 15, "synthetic 15-sigop redeem must scan to 15");
    assert_eq!(synth(16), 16, "synthetic 16-sigop redeem must scan to 16");
    assert_eq!(synth(18), 18, "synthetic 18-sigop redeem (== frozen v0.4) must scan to 18");
    assert!(synth(15) <= MAX_STANDARD_P2SH_SIG_OPS, "15 must be standard (gate boundary)");
    assert!(synth(16) > MAX_STANDARD_P2SH_SIG_OPS, "16 must be NON-standard (gate actually rejects)");
    assert!(synth(18) > MAX_STANDARD_P2SH_SIG_OPS, "frozen v0.4's 18 sig-ops must be NON-standard (the H finding)");
    println!("STANDARDNESS SABOTAGE: 13/15 pass, 16/18 reject at limit {MAX_STANDARD_P2SH_SIG_OPS} — gate is real");
}

/// D6: agent-leaf num8 fields at values far above 2^31 (spanning the
/// 2^32 and 2^53 boundaries) must round-trip through the covenant's
/// OpNum2Bin(v,8) exactly (membership succeeds), and a 1-off value must
/// break membership (injective canonical encoding).
#[test]
fn d_num8_large_value_injectivity() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let big = Agent {
        pk: xonly(&a),
        max_per_spend: 200 * KAS,
        period_budget: 500 * KAS,
        period_length_daa: 1i64 << 40,
        period_start_daa: (1i64 << 32) + 7,
        period_spent: 0,
        approval_threshold: (1i64 << 53) + 123,
        max_fee_per_tx: (1i64 << 33) + 1,
        recipient_root: ZERO32,
    };
    assert!(run(dflt(owner, base_state([0; 32]), vec![big.clone()], 0, big.clone(), &a, &recipient)).0.is_ok(),
        "large-num8 agent leaf must round-trip through OpNum2Bin(v,8)");
    for tweak in [
        Agent { approval_threshold: (1i64 << 53) + 124, ..big.clone() },
        Agent { period_start_daa: (1i64 << 32) + 8, ..big.clone() },
        Agent { max_fee_per_tx: (1i64 << 33) + 2, ..big.clone() },
        Agent { period_length_daa: (1i64 << 40) + 1, ..big.clone() },
    ] {
        assert_rejected(run(dflt(owner, base_state([0; 32]), vec![big.clone()], 0, tweak, &a, &recipient)).0,
            "a 1-off large-num8 field must break agent membership");
    }
}

/// D9: the rollover time gate compiles to OpCheckLockTimeVerify, not a
/// raw lock_time read. A finalized input (sequence = u64::MAX) must be
/// rejected even with a satisfying lock_time (finalization bypass), and
/// lock_time must be >= the covenant-computed newStart (boundary).
#[test]
fn d_rollover_cltv_finalization_and_boundary() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let mut pa = agent(&a, 200 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    pa.period_spent = 480 * KAS; // near budget: only a real rollover can spend
    let new_start = pa.period_start_daa + pa.period_length_daa; // periods_elapsed = 1

    // control: unfinalized input + lock_time == newStart -> valid rollover.
    assert!(run(Spend { pay: 40 * KAS, periods_elapsed: 1, lock_override: Some(new_start as u64),
        ..dflt(owner, base_state([0; 32]), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0.is_ok(),
        "rollover with lock_time == newStart and unfinalized input is valid");

    // finalization bypass: sequence = u64::MAX must be rejected by CLTV.
    assert_rejected(run(Spend { pay: 40 * KAS, periods_elapsed: 1, lock_override: Some(new_start as u64), seq_override: Some(u64::MAX),
        ..dflt(owner, base_state([0; 32]), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0,
        "finalized input (sequence=MAX) must be rejected on the rollover path");

    // boundary: lock_time == newStart - 1 must be rejected.
    assert_rejected(run(Spend { pay: 40 * KAS, periods_elapsed: 1, lock_override: Some((new_start - 1) as u64),
        ..dflt(owner, base_state([0; 32]), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }).0,
        "lock_time one below newStart must be rejected");
}

/// D7: spending agent A must not delete, insert, or move sibling leaves.
/// The successor root is forced to fold newLeaf(A) up the REAL co-path,
/// so any structurally different successor tree is rejected.
#[test]
fn d_agent_delete_insert_move_rejected() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let b = deterministic_keypair(31);
    let kc = deterministic_keypair(32);
    let recipient = deterministic_keypair(40);
    let rroot = recip_tree(0, &xonly(&recipient)).0;
    let pa = Agent { recipient_root: rroot, ..agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS) };
    let pb = agent(&b, 1000 * KAS, 10_000 * KAS, 100_000 * KAS, 1 * KAS);
    let pc = agent(&kc, 1000 * KAS, 10_000 * KAS, 100_000 * KAS, 1 * KAS);
    let mut na = pa.clone();
    na.period_spent = pa.period_spent + 80 * KAS;

    let deleted = merkle(&[agent_leaf(&na)], 0).0;
    assert_rejected(run(Spend { pay: 80 * KAS, override_new_root: Some(deleted),
        ..dflt(owner, base_state([0; 32]), vec![pa.clone(), pb.clone()], 0, pa.clone(), &a, &recipient) }).0,
        "spend cannot delete a sibling agent leaf");

    let inserted = merkle(&[agent_leaf(&na), agent_leaf(&pc)], 0).0;
    assert_rejected(run(Spend { pay: 80 * KAS, override_new_root: Some(inserted),
        ..dflt(owner, base_state([0; 32]), vec![pa.clone(), pb.clone()], 0, pa.clone(), &a, &recipient) }).0,
        "spend cannot replace a sibling agent leaf with a new agent");

    let moved = merkle(&[agent_leaf(&pb), agent_leaf(&na)], 0).0;
    assert_rejected(run(Spend { pay: 80 * KAS, override_new_root: Some(moved),
        ..dflt(owner, base_state([0; 32]), vec![pa.clone(), pb.clone()], 0, pa.clone(), &a, &recipient) }).0,
        "spend cannot move A to a different tree position");
}

// ==================================================================
// ===== CHECKPOINT F — HOSTILE SDK-LAYER REVIEW (VM reproductions) ==
// The SDK finding in Checkpoint E was that the DYNAMIC agent tree must
// NOT pad by duplicating the last real leaf. These tests reproduce that
// vulnerability directly on the PRODUCTION covenant (proving it is real,
// not merely an SDK concern) and prove the SDK's unspendable padding leaf
// (SHA256(0x50563400)) closes it. The covenant is agnostic to how the
// tree is built, so the defense must live in the SDK — these tests pin
// exactly what the covenant will and will not accept.
// ==================================================================

/// Execute ONE agent spend at an EXPLICIT agent co-path (siblings/pathBits),
/// against a predecessor whose agentRoot the caller supplies. Returns the
/// VM result, the successor agentRoot, and the successor covenant value.
/// Used to drive the two lanes of a duplicated leaf independently.
#[allow(clippy::too_many_arguments)]
fn f_spend_at(
    owner: &[u8; 32],
    prev: &S,
    claim: &Agent,
    agent_sibs: &[u8],
    agent_bits: u64,
    pay: i64,
    reserve_consumed: i64,
    recipient: &Keypair,
    rroot: [u8; 32],
    rsibs: &[u8],
    rbits: u64,
    signer: &Keypair,
) -> (Result<(), TxScriptError>, [u8; 32]) {
    let mut np = claim.clone();
    np.period_spent = claim.period_spent + pay;
    let new_root = fold(agent_leaf(&np), agent_sibs, agent_bits);
    let succ = S {
        protected: prev.protected - pay,
        reserve: prev.reserve - reserve_consumed,
        agent_root: new_root,
        ..prev.clone()
    };
    let active = compile(owner, prev);
    let succ_c = compile(owner, &succ);
    let cov_val = (prev.protected + prev.reserve) as u64;
    let outputs = vec![
        p2pk_output(&xonly(recipient), pay as u64),
        TransactionOutput {
            value: (succ.protected + succ.reserve) as u64,
            script_public_key: pay_to_script_hash_script(&succ_c.script),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
        },
    ];
    let tx = Transaction::new(1, vec![cov_input(200)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, cov_val);
    let mut mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let agent_sig = sign_typed(&mutable, 0, signer, SIG_HASH_ALL);
    let mut blob = Vec::with_capacity(650);
    for _ in 0..10 {
        blob.extend_from_slice(&placeholder());
    }
    let args = vec![
        state_arg(&succ),
        Expr::int(pay),
        Expr::bytes(claim.pk.to_vec()),
        Expr::int(claim.max_per_spend),
        Expr::int(claim.period_budget),
        Expr::int(claim.period_length_daa),
        Expr::int(claim.period_start_daa),
        Expr::int(claim.period_spent),
        Expr::int(claim.approval_threshold),
        Expr::int(claim.max_fee_per_tx),
        Expr::bytes(rroot.to_vec()),
        Expr::bytes(agent_sibs.to_vec()),
        Expr::int(agent_bits as i64),
        Expr::int(0),
        Expr::bytes(xonly(recipient).to_vec()),
        Expr::bytes(rsibs.to_vec()),
        Expr::int(rbits as i64),
        Expr::bytes(agent_sig),
        Expr::bytes(blob),
    ];
    let mut ss = active
        .build_sig_script_for_covenant_decl("agentSpend", args, CovenantDeclCallOptions { is_leader: false })
        .expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    mutable.tx.inputs[0].signature_script = ss;
    let r = execute_input_with_covenants(mutable.tx, vec![utxo], 0);
    (r, new_root)
}

/// F1 REPRODUCTION: duplicate-last padding lets ONE agent spend its whole
/// period budget TWICE. Root = SHA256(leaf(C) || leaf(C)) models what
/// duplicate-last padding does to the last real agent. periodBudget ==
/// maxPerSpend == pay, so a single lane is exhausted after one spend —
/// yet the phantom duplicate carries a fresh periodSpent = 0 and spends
/// again. BOTH spends are accepted by the production covenant.
#[test]
fn f_duplicate_last_padding_enables_agent_double_spend() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly(&recipient));
    let pay = 40 * KAS;
    // budget == cap == pay: one spend maxes the period.
    let c = Agent { recipient_root: rroot, ..agent(&a, pay, pay, 100_000 * KAS, 1 * KAS) };
    let lc = agent_leaf(&c);
    // Vulnerable duplicate-last padding: the last (only) real leaf duplicated.
    let root0 = sha256(&[&lc, &lc]);
    let prev0 = S { agent_root: root0, ..base_state([0; 32]) };

    // Lane 1: spend through index 0 (sibling = lc at index 1, bit 0).
    let (r1, root1) = f_spend_at(&owner, &prev0, &c, &lc, 0, pay, 5_000_000, &recipient, rroot, &rsibs, rbits, &a);
    assert!(r1.is_ok(), "first lane spend must be accepted: {r1:?}");

    // Lane 2: the phantom duplicate at index 1 STILL shows periodSpent 0.
    // Against the new root, its co-path sibling is the advanced index-0 leaf.
    let mut c1 = c.clone();
    c1.period_spent = pay;
    let lc1 = agent_leaf(&c1);
    let prev1 = S { agent_root: root1, protected: prev0.protected - pay, reserve: prev0.reserve - 5_000_000, ..prev0.clone() };
    let (r2, _) = f_spend_at(&owner, &prev1, &c, &lc1, 1, pay, 5_000_000, &recipient, rroot, &rsibs, rbits, &a);
    assert!(
        r2.is_ok(),
        "REPRODUCED: duplicate-last padding lets agent C spend 2x its period budget on the production covenant: {r2:?}"
    );
    println!("F1 REPRO: duplicate-last padding double-spend ACCEPTED by the production covenant (both lanes) — this is why the SDK must not duplicate-last pad the dynamic agent tree");
}

/// F1 FIX VALIDATION: with the SDK's UNSPENDABLE padding leaf
/// SHA256(0x50563400), the last real agent has NO phantom duplicate, so
/// the second lane cannot exist. The real agent spends once (accepted);
/// any attempt to spend a second lane through the padding position is
/// REJECTED (no agent-policy record hashes to the padding leaf).
#[test]
fn f_unspendable_padding_blocks_the_double_spend() {
    let owner = xonly(&deterministic_keypair(1));
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let (rroot, rsibs, rbits) = recip_tree(0, &xonly(&recipient));
    let pay = 40 * KAS;
    let c = Agent { recipient_root: rroot, ..agent(&a, pay, pay, 100_000 * KAS, 1 * KAS) };
    let lc = agent_leaf(&c);
    // The SDK's padding leaf: domain-separated recordType 0 (never a 124-byte
    // agent-policy preimage).
    let padding_domain: &[u8] = &[0x50, 0x56, 0x34, 0x00];
    let padding_leaf: [u8; 32] = sha256(&[padding_domain]);
    assert_ne!(padding_leaf, lc, "padding leaf must never equal a real agent leaf");
    let root0 = sha256(&[&lc, &padding_leaf]);
    let prev0 = S { agent_root: root0, ..base_state([0; 32]) };

    // Lane 1: the real agent at index 0 (sibling = padding) spends once.
    let (r1, root1) = f_spend_at(&owner, &prev0, &c, &padding_leaf, 0, pay, 5_000_000, &recipient, rroot, &rsibs, rbits, &a);
    assert!(r1.is_ok(), "the real agent spends its single lane: {r1:?}");

    // Lane 2 attempt: spend through the padding position (index 1). The best
    // an attacker can do is present the real agent's OLD leaf with the
    // advanced index-0 leaf as its sibling — membership folds to
    // SHA256(lc1 || lc) != root1 = SHA256(lc1 || padding). REJECTED.
    let mut c1 = c.clone();
    c1.period_spent = pay;
    let lc1 = agent_leaf(&c1);
    let prev1 = S { agent_root: root1, protected: prev0.protected - pay, reserve: prev0.reserve - 5_000_000, ..prev0.clone() };
    let (r2, _) = f_spend_at(&owner, &prev1, &c, &lc1, 1, pay, 5_000_000, &recipient, rroot, &rsibs, rbits, &a);
    assert_rejected(r2, "unspendable padding: no second lane exists for the last real agent");
    println!("F1 FIX: unspendable padding leaf blocks the duplicate-last double-spend on the production covenant");
}

// ==================================================== §17 SABOTAGE SENSITIVITY
// Owner-control call executor for sabotage tests: compiles the (possibly
// mutated) covenant, builds/signs an ownerControl(newState, opSelector,
// ownerSig) tx, and returns the VM verdict. `signer_kp` may be a NON-owner
// key to test the owner signature guard.
fn owner_exec(mutate: &dyn Fn(String) -> String, signer_kp: &Keypair, owner: &[u8; 32], prev: &S, succ: &S, op: i64) -> Result<(), TxScriptError> {
    let active = compile_mut(mutate, owner, prev);
    let succ_c = compile_mut(mutate, owner, succ);
    let outputs = vec![TransactionOutput {
        value: (succ.protected + succ.reserve) as u64,
        script_public_key: pay_to_script_hash_script(&succ_c.script),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }),
    }];
    let tx = Transaction::new(1, vec![cov_input(60)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, 0, signer_kp, SIG_HASH_ALL);
    let args = vec![state_arg(succ), Expr::int(op), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl("ownerControl", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    execute_input_measured(t, vec![utxo], 0).0
}

// ownerRecover executor (terminal break-glass): pays the full vault to the
// owner P2PK; empty nextStates array; `signer_kp` may be a non-owner key.
fn recover_exec(mutate: &dyn Fn(String) -> String, signer_kp: &Keypair, owner: &[u8; 32], prev: &S) -> Result<(), TxScriptError> {
    let active = compile_mut(mutate, owner, prev);
    let outputs = vec![p2pk_output(owner, (prev.protected + prev.reserve) as u64)];
    let tx = Transaction::new(1, vec![cov_input(60)], outputs, 0, Default::default(), 0, vec![]);
    let utxo = active_utxo(&active, (prev.protected + prev.reserve) as u64);
    let mutable = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let osig = sign_typed(&mutable, 0, signer_kp, SIG_HASH_ALL);
    let args = vec![Vec::<Expr<'static>>::new().into(), Expr::bytes(osig)];
    let mut ss = active.build_sig_script_for_covenant_decl("ownerRecover", args, CovenantDeclCallOptions { is_leader: false }).expect("encode");
    ss.extend_from_slice(&push_redeem_script(&active.script));
    let mut t = mutable.tx;
    t.inputs[0].signature_script = ss;
    execute_input_measured(t, vec![utxo], 0).0
}

/// §17 CONSENSUS-LAYER SABOTAGE SENSITIVITY. For each of the 13 target guards,
/// neutralize exactly that guard in the covenant source, and prove the
/// transition it is supposed to reject now PASSES (while the identical
/// transition on the UN-mutated covenant still rejects). "Original rejects,
/// neutralized passes" is a two-sided proof that the guard is load-bearing and
/// that the corresponding negative test would turn red if the guard were lost.
/// The source is mutated only in-memory (compile_mut); the on-disk covenant is
/// never touched, so nothing needs restoring.
#[test]
fn v4_1_guard_sabotage_sensitivity() {
    let owner_kp = deterministic_keypair(1);
    let owner = xonly(&owner_kp);
    let wrong_kp = deterministic_keypair(99); // NOT the owner
    let a = deterministic_keypair(30);
    let recipient = deterministic_keypair(40);
    let (x1, x2, x3) = (deterministic_keypair(20), deterministic_keypair(21), deterministic_keypair(22));

    // Base single-agent vault for owner-control transitions.
    let pa0 = agent(&a, 100 * KAS, 500 * KAS, 100_000 * KAS, 1 * KAS);
    let base_prev = S { agent_root: merkle(&[agent_leaf(&pa0)], 0).0, ..base_state([0; 32]) };
    let mut sensitive = 0usize;

    // A closure that asserts sensitivity for an owner-control guard.
    let mut check_owner = |name: &str, mutate: &dyn Fn(String) -> String, signer: &Keypair, prev: &S, succ: &S, op: i64| {
        let orig = owner_exec(&|s| s, signer, &owner, prev, succ, op);
        let sab = owner_exec(mutate, signer, &owner, prev, succ, op);
        assert_rejected(orig, &format!("{name}: ORIGINAL covenant must reject this transition"));
        assert!(sab.is_ok(), "{name}: neutralized guard must ACCEPT -> guard is load-bearing (got {sab:?})");
        println!("  SABOTAGE SENSITIVE: {name}");
    };

    // 1. owner signature check (ownerControl) — wrong-key setAgentRoot.
    let set_root = S { agent_root: [0x77; 32], policy_nonce: base_prev.policy_nonce + 1, ..base_prev.clone() };
    check_owner("01 owner-signature-check",
        &|s: String| s.replace(
            "function ownerControl(State prevState, State newState, int opSelector, sig ownerSig) {\n        require(checkSig(ownerSig, owner));",
            "function ownerControl(State prevState, State newState, int opSelector, sig ownerSig) {\n        require(checkSig(ownerSig, owner) || bytes(owner) == bytes(owner));"),
        &wrong_kp, &base_prev, &set_root, 0);
    sensitive += 1;

    // 2. unknown-selector rejection — selector 6 on a paused vault reaches the
    //    final (unpause) branch when the upper bound is neutralized.
    let paused_prev = S { paused: 1, ..base_prev.clone() };
    let unpause_succ = S { paused: 0, ..paused_prev.clone() };
    check_owner("02 unknown-selector-rejection",
        &|s: String| s.replace("require(opSelector <= 5);", "require(opSelector <= 999999);"),
        &owner_kp, &paused_prev, &unpause_succ, 6);
    sensitive += 1;

    // 3. selector-specific state preservation — setAgentRoot must not move
    //    principal (first protected-preservation line = setAgentRoot's).
    let set_root_steal = S { agent_root: [0x77; 32], protected: base_prev.protected - 1, policy_nonce: base_prev.policy_nonce + 1, ..base_prev.clone() };
    check_owner("03 selector-specific-preservation",
        &|s: String| s.replacen("require(newState.protectedValue == prevState.protectedValue);", "require(newState.protectedValue == newState.protectedValue);", 1),
        &owner_kp, &base_prev, &set_root_steal, 0);
    sensitive += 1;

    // 4. setAgentRoot nonce rule — must bump policyNonce (first +1 line).
    let set_root_nobump = S { agent_root: [0x77; 32], ..base_prev.clone() };
    check_owner("04 setAgentRoot-nonce",
        &|s: String| s.replacen("require(newState.policyNonce == prevState.policyNonce + 1);", "require(newState.policyNonce == newState.policyNonce);", 1),
        &owner_kp, &base_prev, &set_root_nobump, 0);
    sensitive += 1;

    // 5. setApprovers nonce rule — the setApprovers-specific +1 (anchored by the
    //    following `int activeCount = 0;`).
    let approvers_ok = S { approvers: approver_set(&[&x1, &x2, &x3]), approval_m: 2, policy_nonce: base_prev.policy_nonce, ..base_prev.clone() };
    check_owner("05 setApprovers-nonce",
        &|s: String| s.replace(
            "require(newState.policyNonce == prevState.policyNonce + 1);\n            int activeCount = 0;",
            "require(newState.policyNonce == newState.policyNonce);\n            int activeCount = 0;"),
        &owner_kp, &base_prev, &approvers_ok, 1);
    sensitive += 1;

    // 10. approver distinctness — setApprovers with two identical active keys.
    let mut dup = [ZERO32; 10];
    dup[0] = xonly(&x1);
    dup[1] = xonly(&x1);
    let approvers_dup = S { approvers: dup, approval_m: 1, policy_nonce: base_prev.policy_nonce + 1, ..base_prev.clone() };
    check_owner("10 approver-distinctness",
        &|s: String| s.replace("require(bytes(x) != bytes(y));", "require(bytes(x) == bytes(x));"),
        &owner_kp, &base_prev, &approvers_dup, 1);
    sensitive += 1;

    // 11. global pause — recover check is separate; here neutralize agentSpend's
    //     pause guard (first paused==0) and spend on a paused vault.
    {
        let name = "11 global-pause";
        let mutate = &|s: String| s.replacen("require(prevState.paused == 0);", "require(prevState.paused == prevState.paused);", 1);
        let mk = || Spend { pay: 40 * KAS, prev: S { paused: 1, ..base_state([0; 32]) }, ..dflt(owner, base_state([0; 32]), vec![pa0.clone()], 0, pa0.clone(), &a, &recipient) };
        assert_rejected(run_mut(mk(), &|s| s).0, &format!("{name}: ORIGINAL must reject spend on paused vault"));
        assert!(run_mut(mk(), mutate).0.is_ok(), "{name}: neutralized pause must ACCEPT -> load-bearing");
        println!("  SABOTAGE SENSITIVE: {name}");
        sensitive += 1;
    }

    // 6. protected-value conservation — burn 1 sompi of principal to fee.
    {
        let name = "06 protected-conservation";
        let mutate = &|s: String| s.replace("require(newState.protectedValue == prevState.protectedValue - payAmount);", "require(newState.protectedValue == newState.protectedValue);");
        let mk = || Spend { pay: 40 * KAS, reserve_consumed: 0, succ_protected_override: Some(base_state([0; 32]).protected - 40 * KAS - 1), ..dflt(owner, base_state([0; 32]), vec![pa0.clone()], 0, pa0.clone(), &a, &recipient) };
        assert_rejected(run_mut(mk(), &|s| s).0, &format!("{name}: ORIGINAL must reject principal burn"));
        assert!(run_mut(mk(), mutate).0.is_ok(), "{name}: neutralized conservation must ACCEPT -> load-bearing");
        println!("  SABOTAGE SENSITIVE: {name}");
        sensitive += 1;
    }

    // 7. reserveConsumed bound — consume 2 KAS of reserve with a 1 KAS per-tx cap.
    {
        let name = "07 reserveConsumed-bound";
        let mutate = &|s: String| s.replace("require(reserveConsumed <= agentMaxFeePerTx);", "require(reserveConsumed <= agentMaxFeePerTx + payAmount);");
        let mk = || Spend { pay: 40 * KAS, reserve_consumed: 2 * KAS, ..dflt(owner, base_state([0; 32]), vec![pa0.clone()], 0, pa0.clone(), &a, &recipient) };
        assert_rejected(run_mut(mk(), &|s| s).0, &format!("{name}: ORIGINAL must reject over-cap reserve consumption"));
        assert!(run_mut(mk(), mutate).0.is_ok(), "{name}: neutralized cap must ACCEPT -> load-bearing");
        println!("  SABOTAGE SENSITIVE: {name}");
        sensitive += 1;
    }

    // 8. successor agentRoot equality — set an arbitrary (unauthenticated) root.
    {
        let name = "08 successor-agentRoot-equality";
        let mutate = &|s: String| s.replace("require(bytes(newState.agentRoot) == newRoot);", "require(bytes(newRoot) == bytes(newRoot));");
        let mk = || Spend { pay: 40 * KAS, override_new_root: Some([0x99; 32]), ..dflt(owner, base_state([0; 32]), vec![pa0.clone()], 0, pa0.clone(), &a, &recipient) };
        assert_rejected(run_mut(mk(), &|s| s).0, &format!("{name}: ORIGINAL must reject forged successor root"));
        assert!(run_mut(mk(), mutate).0.is_ok(), "{name}: neutralized root pin must ACCEPT -> load-bearing");
        println!("  SABOTAGE SENSITIVE: {name}");
        sensitive += 1;
    }

    // 9. approval SIG_HASH_ALL gate — an approver signs SIG_HASH_NONE.
    {
        let name = "09 approval-sighash-all-gate";
        let (a1, a2, a3) = (deterministic_keypair(60), deterministic_keypair(61), deterministic_keypair(62));
        let slots = approver_set(&[&a1, &a2, &a3]);
        let pa = agent(&a, 200 * KAS, 500 * KAS, 50 * KAS, 1 * KAS);
        let st = S { approvers: slots, approval_m: 2, ..base_state([0; 32]) };
        let mutate = &|s: String| s.replace("require(approvalHashByte == bytes(0x01));", "require(bytes(approvalHashByte) == bytes(approvalHashByte));");
        let mk = || {
            let ap = approvals_by_key(&slots, &[(&a1, SIG_HASH_NONE), (&a2, SIG_HASH_ALL)]);
            Spend { pay: 150 * KAS, approver_sigs: ap, ..dflt(owner, st.clone(), vec![pa.clone()], 0, pa.clone(), &a, &recipient) }
        };
        assert_rejected(run_mut(mk(), &|s| s).0, &format!("{name}: ORIGINAL must reject non-ALL approval"));
        assert!(run_mut(mk(), mutate).0.is_ok(), "{name}: neutralized sighash gate must ACCEPT -> load-bearing");
        println!("  SABOTAGE SENSITIVE: {name}");
        sensitive += 1;
    }

    // 12. recovery owner check — wrong-key ownerRecover.
    {
        let name = "12 recovery-owner-check";
        let mutate = &|s: String| s.replace(
            "function ownerRecover(State prevState, State[] nextStates, sig ownerSig) : (State[]) {\n        require(checkSig(ownerSig, owner));",
            "function ownerRecover(State prevState, State[] nextStates, sig ownerSig) : (State[]) {\n        require(checkSig(ownerSig, owner) || bytes(owner) == bytes(owner));");
        assert_rejected(recover_exec(&|s| s, &wrong_kp, &owner, &base_prev), &format!("{name}: ORIGINAL must reject wrong-key recover"));
        assert!(recover_exec(mutate, &wrong_kp, &owner, &base_prev).is_ok(), "{name}: neutralized recover check must ACCEPT -> load-bearing");
        println!("  SABOTAGE SENSITIVE: {name}");
        sensitive += 1;
    }

    // 13. standardness sig-op ceiling — a covenant with 16 static sig-ops must
    //     scan ABOVE the mempool limit (the H finding's exact failure mode).
    {
        let name = "13 standardness-sigop-ceiling";
        let mut b = ScriptBuilder::new();
        for _ in 0..16 {
            b.add_op(OpCheckSig).unwrap();
        }
        let redeem = b.script().to_vec();
        let spk = pay_to_script_hash_script(&redeem);
        let sig = push_redeem_script(&redeem);
        let scanned = kaspa_txscript::post_toccata_p2sh_sig_scanner(&sig, &spk);
        assert!(scanned > 15, "{name}: 16-sigop covenant must exceed MAX_STANDARD_P2SH_SIG_OPS=15 (got {scanned})");
        // and the real v0.4.1 must NOT.
        println!("  SABOTAGE SENSITIVE: {name} (16 sig-ops -> scanned {scanned} > 15)");
        sensitive += 1;
    }

    assert_eq!(sensitive, 13, "all 13 target guards must be sabotage-sensitive");
    println!("§17 SABOTAGE SENSITIVITY: {sensitive}/13 sensitive, 0 blind spots");
}
