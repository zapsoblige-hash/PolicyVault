//! VM layer — v0.5 PRODUCTION-BYTE FIXTURE for the shared deterministic
//! core (`core/assets/`). Captures, from the REAL silverscript compiler and
//! the REAL rusty-kaspa v2.0.1 crates, the bytes the JS core must reproduce
//! exactly (production-byte rule): KCC20 template geometry, prefix/suffix,
//! the in-VM blake2b-256(prefix || suffix) identity, the KCC-0001 BLAKE3
//! LE64-framed identity, canonical `kcc20-state/1` state encodings, the
//! P2SH script-public-key envelope, and the post-Toccata static P2SH
//! sig-op scan per family bound.
//!
//! WRITE-OR-ASSERT: if the fixture file is absent it is written; if present
//! the regenerated JSON must be byte-identical (anti-drift). The JS suite
//! (core/assets/test) pins its codec/hash/scanner against this file.

use std::fs;

use kaspa_txscript::{pay_to_script_hash_script, post_toccata_p2sh_sig_scanner, script_builder::ScriptBuilder, EngineFlags};
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load_kcc20_source() -> String {
    let path = format!("{}/../../../silverscript/silverscript-lang/tests/examples/kcc20.sil", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).expect("read sibling kcc20.sil example")
}

fn compile_kcc20<'a>(source: &'a str, owner: [u8; 32], id_type: u8, amount: i64, is_minter: bool, max_cov: i64) -> CompiledContract<'a> {
    compile_contract(
        source,
        &[Expr::bytes(owner.to_vec()), Expr::int(amount), Expr::byte(id_type), Expr::bool(is_minter), Expr::int(max_cov), Expr::int(max_cov)],
        CompileOptions::default(),
    )
    .expect("compile kcc20")
}

fn blake2b256(parts: &[&[u8]]) -> Vec<u8> {
    let mut st = blake2b_simd::Params::new().hash_length(32).to_state();
    for p in parts {
        st.update(p);
    }
    st.finalize().as_bytes().to_vec()
}

fn kcc1_blake3(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    h.finalize().as_bytes().to_vec()
}

fn push_redeem(script: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() }).add_data(script).expect("push").drain()
}

#[test]
fn v5_capture_kcc20_template_fixture() {
    let source = load_kcc20_source();
    let source_sha256 = hx(&Sha256::digest(source.as_bytes()));

    // Sample states: (owner, identifierType, amount, isMinter)
    let states: Vec<([u8; 32], u8, i64, bool)> = vec![
        ([0x00; 32], 0x02, 300, false),
        ([0xff; 32], 0x00, 0, false),
        ([0x11; 32], 0x01, 1, true),
        ([0x22; 32], 0x02, (1i64 << 40) + 7, false),
        ([0x33; 32], 0x00, i64::MAX, true),
        ([0x44; 32], 0x00, 127, false),
        ([0x55; 32], 0x00, 128, false),
        ([0x66; 32], 0x00, 255, false),
        ([0x77; 32], 0x00, 256, false),
        ([0x88; 32], 0x00, 65535, false),
        ([0x99; 32], 0x00, 4294967296, false),
    ];

    let mut bounds_json = Vec::new();
    for max_cov in [2i64, 4, 8, 15, 16] {
        let reference = compile_kcc20(&source, [0x00; 32], 0x02, 300, false, max_cov);
        let layout = reference.state_layout;
        let prefix = &reference.script[..layout.start];
        let suffix = &reference.script[layout.start + layout.len..];
        let vm_hash = blake2b256(&[prefix, suffix]);
        let kcc1 = kcc1_blake3(prefix, suffix);
        let spk = pay_to_script_hash_script(&reference.script);
        let sigops = post_toccata_p2sh_sig_scanner(&push_redeem(&reference.script), &spk);

        let mut state_json = Vec::new();
        for (owner, ty, amount, minter) in &states {
            let c = compile_kcc20(&source, *owner, *ty, *amount, *minter, max_cov);
            let l = c.state_layout;
            assert_eq!(l.start, layout.start, "prefix length must not depend on state values");
            assert_eq!(l.len, layout.len, "encoded state length must be fixed for kcc20-state/1");
            assert_eq!(&c.script[..l.start], prefix, "prefix must not depend on state values");
            assert_eq!(&c.script[l.start + l.len..], suffix, "suffix must not depend on state values");
            state_json.push(format!(
                "      {{\"ownerIdentifier\": \"{}\", \"identifierType\": {}, \"amount\": \"{}\", \"isMinter\": {}, \"stateHex\": \"{}\", \"p2shSpkHex\": \"{}\", \"redeemSha256\": \"{}\"}}",
                hx(owner),
                ty,
                amount,
                minter,
                hx(&c.script[l.start..l.start + l.len]),
                hx(pay_to_script_hash_script(&c.script).script()),
                hx(&Sha256::digest(&c.script))
            ));
        }
        bounds_json.push(format!(
            "    {{\n      \"familyBound\": {max_cov},\n      \"prefixLen\": {},\n      \"stateLen\": {},\n      \"suffixLen\": {},\n      \"prefixHex\": \"{}\",\n      \"suffixHex\": \"{}\",\n      \"templateVmHashBlake2b256\": \"{}\",\n      \"templateKcc1HashBlake3\": \"{}\",\n      \"staticP2shSigOps\": {sigops},\n      \"referenceP2shSpkHex\": \"{}\",\n      \"states\": [\n{}\n      ]\n    }}",
            layout.start,
            layout.len,
            suffix.len(),
            hx(prefix),
            hx(suffix),
            hx(&vm_hash),
            hx(&kcc1),
            hx(spk.script()),
            state_json.join(",\n")
        ));
    }

    let json = format!(
        "{{\n  \"fixture\": \"policyvault-kcc20-template-fixture/1\",\n  \"source\": \"silverscript-lang/tests/examples/kcc20.sil\",\n  \"sourceSha256\": \"{source_sha256}\",\n  \"stateLayout\": \"kcc20-state/1\",\n  \"vmHashConvention\": \"blake2b-256(prefix || suffix)\",\n  \"kcc1HashConvention\": \"blake3-256(LE64(len(prefix)) || prefix || LE64(len(suffix)) || suffix)\",\n  \"p2shEnvelope\": \"OpBlake2b OpData32 <blake2b-256(redeem)> OpEqual\",\n  \"bounds\": [\n{}\n  ]\n}}\n",
        bounds_json.join(",\n")
    );

    let out = format!("{}/../../core/assets/test/fixtures/kcc20-template-v1.json", env!("CARGO_MANIFEST_DIR"));
    if let Ok(existing) = fs::read_to_string(&out) {
        assert_eq!(existing, json, "fixture drift: core/assets/test/fixtures/kcc20-template-v1.json no longer matches the real compiler/engine output");
    } else {
        fs::write(&out, &json).expect("write fixture");
        println!("wrote {out}");
    }
}

/* ------------------------------------------------------------------
 * Token-agent leaf vectors (core/model/agent-merkle-v5.js must reproduce
 * these byte-for-byte; the SAME function is what PolicyVault.v0.5.sil
 * accepted on the real engine in tests/vm/tests/v5_production.rs).
 * ---------------------------------------------------------------- */
fn leaf_v5(pk: &[u8; 32], vals: [i64; 7], root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x50, 0x56, 0x35, 0x01]);
    h.update(pk);
    for v in vals {
        h.update((v as u64).to_le_bytes());
    }
    h.update(root);
    h.update([0x00]);
    h.finalize().into()
}

#[test]
fn v5_capture_token_agent_leaf_fixture() {
    let vectors: Vec<([u8; 32], [i64; 7], [u8; 32])> = vec![
        ([0x22; 32], [250, 400, 1000, 5000, 0, 60_000, 25_000_000], [0x00; 32]),
        ([0x11; 32], [1, 1, 1, 0, 0, 0, 0], [0xff; 32]),
        ([0xab; 32], [i64::MAX, i64::MAX, 4_294_967_296, 123_456_789, 987_654_321, 1_000_000_000, 100_000_000], [0x5a; 32]),
        ([0x01; 32], [127, 128, 255, 256, 65535, 65536, 2_147_483_648], [0x7e; 32]),
    ];
    let mut items = Vec::new();
    for (pk, vals, root) in &vectors {
        let leaf = leaf_v5(pk, *vals, root);
        // depth-2 fold: siblings s0, s1 with pathBits 0b10 (left at level 0, right at level 1)
        let s0 = [0xc0; 32];
        let s1 = [0xc1; 32];
        let n0: [u8; 32] = Sha256::digest([leaf.as_slice(), s0.as_slice()].concat()).into();
        let n1: [u8; 32] = Sha256::digest([s1.as_slice(), n0.as_slice()].concat()).into();
        items.push(format!(
            "    {{\"agentPk\": \"{}\", \"tokenMaxPerSpend\": \"{}\", \"tokenPeriodBudget\": \"{}\", \"periodLengthDaa\": \"{}\", \"periodStartDaa\": \"{}\", \"tokenPeriodSpent\": \"{}\", \"agentMaxFeePerTx\": \"{}\", \"agentMaxCarryKas\": \"{}\", \"agentRecipientRoot\": \"{}\", \"leafHex\": \"{}\", \"foldSiblingsHex\": \"{}{}\", \"foldPathBits\": 2, \"foldRootHex\": \"{}\"}}",
            hx(pk), vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], hx(root), hx(&leaf), hx(&s0), hx(&s1), hx(&n1)
        ));
    }
    let json = format!(
        "{{\n  \"fixture\": \"policyvault-token-agent-leaf-fixture/5\",\n  \"leafDomain\": \"50563501\",\n  \"preimageLen\": 125,\n  \"recipientSchemeByte\": \"00\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
        items.join(",\n")
    );
    let out = format!("{}/../../core/model/test/fixtures/token-agent-leaf-v5.json", env!("CARGO_MANIFEST_DIR"));
    if let Ok(existing) = fs::read_to_string(&out) {
        assert_eq!(existing, json, "fixture drift: token-agent-leaf-v5.json");
    } else {
        fs::write(&out, &json).expect("write fixture");
        println!("wrote {out}");
    }
}
