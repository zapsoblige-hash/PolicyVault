//! Capture the v0.6 leaf fixtures from the SAME Rust leaf functions the
//! real-engine v0.6 production suite accepts (tests/vm/tests/v6_production.rs),
//! so the JS core (core/model/agent-merkle-v6.js, swap-policy-v6.js) is
//! pinned byte-for-byte to what PolicyVault.v0.6.sil computes in-VM.

use std::fs;

use sha2::{Digest, Sha256};

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn fold2(leaf: [u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let s0 = [0xc0; 32];
    let s1 = [0xc1; 32];
    let n0: [u8; 32] = Sha256::digest([leaf.as_slice(), s0.as_slice()].concat()).into();
    let n1: [u8; 32] = Sha256::digest([s1.as_slice(), n0.as_slice()].concat()).into();
    (s0, s1, n1)
}
fn write_or_assert(rel: &str, json: String) {
    let out = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    if let Ok(existing) = fs::read_to_string(&out) {
        assert_eq!(existing, json, "fixture drift: {rel}");
    } else {
        fs::write(&out, &json).expect("write fixture");
        println!("wrote {out}");
    }
}

fn leaf_agent_v6(pk: &[u8; 32], vals: [i64; 10], root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x50, 0x56, 0x36, 0x01]);
    h.update(pk);
    for v in vals {
        h.update((v as u64).to_le_bytes());
    }
    h.update(root);
    h.update([0x00]);
    h.finalize().into()
}

#[test]
fn v6_capture_token_agent_leaf_fixture() {
    let names = ["tokenMaxPerSpend", "tokenPeriodBudget", "periodLengthDaa", "periodStartDaa", "tokenPeriodSpent", "agentMaxFeePerTx", "agentMaxCarryKas", "kasMaxPerSwap", "kasPeriodBudget", "kasPeriodSpent"];
    let vectors: Vec<([u8; 32], [i64; 10], [u8; 32])> = vec![
        ([0x62; 32], [600, 1000, 1000, 5000, 0, 60_000, 25_000_000, 50_000, 80_000, 0], [0x00; 32]),
        ([0x11; 32], [1, 1, 1, 0, 0, 0, 0, 0, 0, 0], [0xff; 32]),
        ([0xab; 32], [i64::MAX, i64::MAX, 4_294_967_296, 123_456_789, 987_654_321, 2_000_000_000_000_000_000, 100_000_000, 2_000_000_000_000_000_000, 2_000_000_000_000_000_000, 41_877], [0x5a; 32]),
        ([0x01; 32], [127, 128, 255, 256, 65535, 65536, 2_147_483_648, 4_294_967_295, 4_294_967_296, 1], [0x7e; 32]),
    ];
    let mut items = Vec::new();
    for (pk, vals, root) in &vectors {
        let leaf = leaf_agent_v6(pk, *vals, root);
        let (s0, s1, r) = fold2(leaf);
        let fields: Vec<String> = names.iter().zip(vals.iter()).map(|(n, v)| format!("\"{n}\": \"{v}\"")).collect();
        items.push(format!(
            "    {{\"agentPk\": \"{}\", {}, \"agentRecipientRoot\": \"{}\", \"leafHex\": \"{}\", \"foldSiblingsHex\": \"{}{}\", \"foldPathBits\": 2, \"foldRootHex\": \"{}\"}}",
            hx(pk),
            fields.join(", "),
            hx(root),
            hx(&leaf),
            hx(&s0),
            hx(&s1),
            hx(&r)
        ));
    }
    let json = format!(
        "{{\n  \"fixture\": \"policyvault-token-agent-leaf-fixture/6\",\n  \"leafDomain\": \"50563601\",\n  \"preimageLen\": 149,\n  \"recipientSchemeByte\": \"00\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
        items.join(",\n")
    );
    write_or_assert("core/model/test/fixtures/token-agent-leaf-v6.json", json);
}

struct SwapVec {
    profile: [u8; 32],
    pool_id: [u8; 32],
    pool_hash: [u8; 32],
    prefix_len: i64,
    suffix_len: i64,
    fee_pk: [u8; 32],
    max_proto: i64,
    floor: (i64, i64),
    ceil: (i64, i64),
    mask: i64,
    scheme: u8,
    dest: [u8; 32],
}
fn leaf_swap_v6(v: &SwapVec) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x50, 0x56, 0x36, 0x02]);
    h.update(v.profile);
    h.update(v.pool_id);
    h.update(v.pool_hash);
    h.update((v.prefix_len as u64).to_le_bytes());
    h.update((v.suffix_len as u64).to_le_bytes());
    h.update(v.fee_pk);
    h.update((v.max_proto as u64).to_le_bytes());
    h.update((v.floor.0 as u64).to_le_bytes());
    h.update((v.floor.1 as u64).to_le_bytes());
    h.update((v.ceil.0 as u64).to_le_bytes());
    h.update((v.ceil.1 as u64).to_le_bytes());
    h.update((v.mask as u64).to_le_bytes());
    h.update([v.scheme]);
    h.update(v.dest);
    h.finalize().into()
}

#[test]
fn v6_capture_swap_policy_leaf_fixture() {
    let vectors = vec![
        SwapVec { profile: [0xaa; 32], pool_id: [0x50; 32], pool_hash: [0x70; 32], prefix_len: 1, suffix_len: 10565, fee_pk: [0x66; 32], max_proto: 200, floor: (90, 1), ceil: (110, 1), mask: 3, scheme: 0x02, dest: [0x00; 32] },
        SwapVec { profile: [0xaa; 32], pool_id: [0x50; 32], pool_hash: [0x70; 32], prefix_len: 1, suffix_len: 10565, fee_pk: [0x66; 32], max_proto: 200, floor: (90, 1), ceil: (110, 1), mask: 1, scheme: 0x00, dest: [0x63; 32] },
        SwapVec { profile: [0x01; 32], pool_id: [0x02; 32], pool_hash: [0x03; 32], prefix_len: 65535, suffix_len: 1_000_000, fee_pk: [0x04; 32], max_proto: 2_000_000_000_000_000_000, floor: (1_000_000_000, 999_999_999), ceil: (1, 1_000_000_000), mask: 2, scheme: 0x02, dest: [0x00; 32] },
    ];
    let mut items = Vec::new();
    for v in &vectors {
        let leaf = leaf_swap_v6(v);
        let (s0, s1, r) = fold2(leaf);
        items.push(format!(
            "    {{\"profileHash\": \"{}\", \"poolCovenantId\": \"{}\", \"poolTemplateVmHash\": \"{}\", \"poolPrefixLen\": {}, \"poolSuffixLen\": {}, \"poolFeePk\": \"{}\", \"maxProtocolFeeKas\": \"{}\", \"sellFloorNum\": \"{}\", \"sellFloorDen\": \"{}\", \"buyCeilNum\": \"{}\", \"buyCeilDen\": \"{}\", \"directionMask\": \"{}\", \"destScheme\": {}, \"destIdentity\": \"{}\", \"leafHex\": \"{}\", \"foldSiblingsHex\": \"{}{}\", \"foldPathBits\": 2, \"foldRootHex\": \"{}\"}}",
            hx(&v.profile),
            hx(&v.pool_id),
            hx(&v.pool_hash),
            v.prefix_len,
            v.suffix_len,
            hx(&v.fee_pk),
            v.max_proto,
            v.floor.0,
            v.floor.1,
            v.ceil.0,
            v.ceil.1,
            v.mask,
            v.scheme,
            hx(&v.dest),
            hx(&leaf),
            hx(&s0),
            hx(&s1),
            hx(&r)
        ));
    }
    let json = format!(
        "{{\n  \"fixture\": \"policyvault-swap-policy-leaf-fixture/6\",\n  \"leafDomain\": \"50563602\",\n  \"preimageLen\": 229,\n  \"vectors\": [\n{}\n  ]\n}}\n",
        items.join(",\n")
    );
    write_or_assert("core/model/test/fixtures/swap-policy-leaf-v6.json", json);
}
