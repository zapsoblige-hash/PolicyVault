"use strict";
/*
 * SDK — Codex checkpoint 8 (UX-05): the STRICT node-body identity helper
 * (sdk/src/tx-identity transactionIdOfRpcBody).
 *   • every identity-relevant field is REQUIRED and read exactly: a missing
 *     lockTime / gas / payload / signatureScript, a null outpoint index, an
 *     incomplete covenant object, a float, a negative, a non-canonical
 *     string, an UNSAFE JS number (a raw JSON 9007199254740993 that already
 *     arrived as 9007199254740992) or an out-of-domain value is REFUSED —
 *     never defaulted, never coerced, never a wrong id;
 *   • bigint / safe number / canonical decimal string forms and the object /
 *     "safe string" script-public-key forms all yield the SAME id; the two
 *     documented optional non-identity fields (sigOpCount, computeBudget) do
 *     not change it (upstream: tx::id excludes the compute commit);
 *   • the id equals the REAL consensus code's answer: the upstream
 *     rusty-kaspa hashing test vector (consensus/core/src/hashing/tx.rs
 *     test #11) and, when the native probe is built, pv_tx_probe describe on
 *     the same bytes — including a value above Number.MAX_SAFE_INTEGER
 *     carried as a string (REQUIREMENT_NOT_AVAILABLE otherwise).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { loadConfig } = require("../src/config");
const { transactionIdOfRpcBody, blockHashOfRpcHeader } = require("../src/tx-identity");
const { TX_PROBE_PATH, describeFrozenTx, normalizeFrozenTxV3 } = require("../src/frozen-tx-v3");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-txid-")) });
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const clone = (x) => JSON.parse(JSON.stringify(x, (k, v) => (typeof v === "bigint" ? v.toString() : v)));
const base = () => ({
  version: 1,
  inputs: [
    { previousOutpoint: { transactionId: H(0x11), index: 0 }, signatureScript: "", sequence: "0", sigOpCount: 0, computeBudget: 10 },
    { previousOutpoint: { transactionId: H(0x12), index: 3 }, signatureScript: "41" + "ab".repeat(64) + "01", sequence: "18446744073709551615", sigOpCount: 1, computeBudget: 0 }
  ],
  outputs: [
    { value: "9007199254740993", scriptPublicKey: { version: 0, script: "20" + H(0x22) + "ac" }, covenant: { authorizingInput: 1, covenantId: H(0x33) } },
    { value: "5", scriptPublicKey: "000020" + H(0x44) + "ac" }
  ],
  lockTime: "123456789",
  subnetworkId: "00".repeat(20),
  gas: "0",
  payload: ""
});
const idOf = (b) => transactionIdOfRpcBody(config, b).transactionId;

test("refusals: every missing, null, incomplete, coerced, unsafe or out-of-domain identity field throws (never a default, never a wrong id)", () => {
  const cases = {
    "missing lockTime": (b) => { delete b.lockTime; },
    "null lockTime": (b) => { b.lockTime = null; },
    "missing gas": (b) => { delete b.gas; },
    "missing payload": (b) => { delete b.payload; },
    "missing subnetworkId": (b) => { delete b.subnetworkId; },
    "subnetworkId of the wrong length": (b) => { b.subnetworkId = "00".repeat(19); },
    "missing version": (b) => { delete b.version; },
    "version above u16": (b) => { b.version = 65536; },
    "inputs not an array": (b) => { b.inputs = {}; },
    "outputs not an array": (b) => { b.outputs = null; },
    "input null": (b) => { b.inputs[0] = null; },
    "input without previousOutpoint": (b) => { delete b.inputs[0].previousOutpoint; },
    "previousOutpoint.index null (never 0)": (b) => { b.inputs[0].previousOutpoint.index = null; },
    "previousOutpoint.index missing": (b) => { delete b.inputs[0].previousOutpoint.index; },
    "previousOutpoint.index above u32": (b) => { b.inputs[0].previousOutpoint.index = 4294967296; },
    "previousOutpoint.index float": (b) => { b.inputs[0].previousOutpoint.index = 1.5; },
    "previousOutpoint.transactionId short": (b) => { b.inputs[0].previousOutpoint.transactionId = "ab"; },
    "sequence missing": (b) => { delete b.inputs[0].sequence; },
    "sequence above u64": (b) => { b.inputs[0].sequence = "18446744073709551616"; },
    "sequence negative": (b) => { b.inputs[0].sequence = -1; },
    "signatureScript missing": (b) => { delete b.inputs[0].signatureScript; },
    "signatureScript odd hex": (b) => { b.inputs[0].signatureScript = "abc"; },
    "sigOpCount above u8 (optional field, validated when present)": (b) => { b.inputs[0].sigOpCount = 256; },
    "computeBudget above u16 (optional field, validated when present)": (b) => { b.inputs[0].computeBudget = 65536; },
    "output value missing": (b) => { delete b.outputs[1].value; },
    "output value UNSAFE JS number (9007199254740993 already arrived as 9007199254740992)": (b) => { b.outputs[1].value = 9007199254740993; },
    "output value float": (b) => { b.outputs[1].value = 1.5; },
    "output value negative string": (b) => { b.outputs[1].value = "-1"; },
    "output value non-canonical string": (b) => { b.outputs[1].value = "007"; },
    "output value above u64": (b) => { b.outputs[1].value = "18446744073709551616"; },
    "output scriptPublicKey missing": (b) => { delete b.outputs[1].scriptPublicKey; },
    "object scriptPublicKey with null version": (b) => { b.outputs[0].scriptPublicKey = { version: null, script: "51" }; },
    "object scriptPublicKey without script": (b) => { b.outputs[0].scriptPublicKey = { version: 0 }; },
    "string scriptPublicKey shorter than its version prefix": (b) => { b.outputs[1].scriptPublicKey = "00"; },
    "covenant object without covenantId (an incomplete covenant is never 'no covenant')": (b) => { b.outputs[0].covenant = { authorizingInput: 1 }; },
    "covenant object without authorizingInput": (b) => { b.outputs[0].covenant = { covenantId: H(0x33) }; },
    "covenant.authorizingInput naming no input": (b) => { b.outputs[0].covenant = { authorizingInput: 2, covenantId: H(0x33) }; },
    "covenant.covenantId malformed": (b) => { b.outputs[0].covenant = { authorizingInput: 1, covenantId: "zz" }; },
    "covenant not an object": (b) => { b.outputs[0].covenant = "x"; }
  };
  for (const [label, mutate] of Object.entries(cases)) {
    const b = base(); mutate(b);
    assert.throws(() => idOf(b), (e) => e.code === "TX_IDENTITY_INVALID", label);
  }
  assert.throws(() => idOf(null), (e) => e.code === "TX_IDENTITY_INVALID");
  assert.throws(() => idOf([]), (e) => e.code === "TX_IDENTITY_INVALID");
});

test("equivalences: bigint / safe number / canonical string and object / safe-string script forms give ONE id; the optional non-identity fields never change it; a covenant binding does", () => {
  const ref = idOf(base());
  const b1 = base(); b1.lockTime = 123456789n; b1.gas = 0n; b1.inputs[0].sequence = 0n; b1.inputs[1].sequence = 18446744073709551615n; b1.outputs[0].value = 9007199254740993n; b1.outputs[1].value = 5n;
  assert.equal(idOf(b1), ref, "bigint forms");
  const b2 = base(); b2.lockTime = 123456789; b2.gas = 0; b2.inputs[0].sequence = 0; b2.outputs[1].value = 5;
  assert.equal(idOf(b2), ref, "safe-number forms");
  const b3 = base(); b3.outputs[0].scriptPublicKey = "000020" + H(0x22) + "ac"; b3.outputs[1].scriptPublicKey = { version: 0, script: "20" + H(0x44) + "ac" };
  assert.equal(idOf(b3), ref, "script-public-key forms swapped");
  const b4 = base(); delete b4.inputs[0].sigOpCount; delete b4.inputs[0].computeBudget; b4.inputs[1].computeBudget = 65535; b4.inputs[1].sigOpCount = 255;
  assert.equal(idOf(b4), ref, "sigOpCount / computeBudget are not identity (upstream: tx::id excludes the compute commit)");
  const b5 = base(); b5.inputs[0].signatureScript = "41" + "cd".repeat(64) + "01";
  assert.equal(idOf(b5), ref, "signature scripts are not identity");
  const b6 = base(); b6.outputs[1].covenant = null;
  assert.equal(idOf(b6), ref, "covenant: null == absent");
  const b7 = base(); delete b7.outputs[0].covenant;
  assert.notEqual(idOf(b7), ref, "the covenant binding IS identity");
  const b8 = base(); b8.outputs[0].value = "9007199254740992";
  assert.notEqual(idOf(b8), ref, "the exact value IS identity (one unit below the string value)");
  const b9 = base(); b9.lockTime = "123456788";
  assert.notEqual(idOf(b9), ref, "lockTime IS identity");
});

test("upstream vector: rusty-kaspa consensus/core/src/hashing/tx.rs test #11 (version 1, default outpoint, compute budget 111, no outputs) reproduces exactly; the compute budget does not enter the id (test #12)", () => {
  const vector = { version: 1, inputs: [{ previousOutpoint: { transactionId: "00".repeat(32), index: 0 }, signatureScript: "", sequence: 0, sigOpCount: 0, computeBudget: 111 }], outputs: [], lockTime: 0, subnetworkId: "00".repeat(20), gas: 0, payload: "" };
  assert.equal(idOf(vector), "5978e7aa1a9ba8fdf12dae6aa39aa198a91985e91192b291e207d4d6246349e6");
  assert.equal(idOf({ ...vector, inputs: [{ ...vector.inputs[0], computeBudget: 222 }] }), "5978e7aa1a9ba8fdf12dae6aa39aa198a91985e91192b291e207d4d6246349e6");
});

test("native cross-check: pv_tx_probe describe (real rusty-kaspa consensus code) agrees with the strict helper on the same bytes — two inputs, a covenant output, a non-zero lockTime and a value above Number.MAX_SAFE_INTEGER carried as a string; the unsafe JS-number form of that value is refused, never mis-identified", { skip: !fs.existsSync(TX_PROBE_PATH) && "REQUIREMENT_NOT_AVAILABLE: pv_tx_probe not built" }, () => {
  const body = base(); body.inputs[1].sequence = "42"; // the frozen-form normalizer bounds sequences to the sompi domain; the identity helper's own u64 domain is covered above
  const frozen = normalizeFrozenTxV3({
    version: 1,
    inputs: body.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, computeBudget: i.computeBudget, utxo: { amount: "1", scriptPublicKey: { version: 0, scriptHex: "20" + H(0x55) + "ac" }, covenantId: null, blockDaaScore: "0" } })),
    outputs: [
      { value: "9007199254740993", scriptPublicKey: { version: 0, scriptHex: "20" + H(0x22) + "ac" }, covenant: { authorizingInput: 1, covenantId: H(0x33) } },
      { value: "5", scriptPublicKey: { version: 0, scriptHex: "20" + H(0x44) + "ac" } }
    ],
    lockTime: "123456789",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  });
  const native = describeFrozenTx(frozen).txId;
  assert.equal(idOf(body), native, "helper == native consensus id");
  const unsafe = base(); unsafe.outputs[0].value = 9007199254740993; // the JS number is already 9007199254740992
  assert.throws(() => idOf(unsafe), (e) => e.code === "TX_IDENTITY_INVALID");
  const lost = base(); lost.outputs[0].value = "9007199254740992";
  assert.notEqual(idOf(lost), native, "the value the unsafe number would have silently become has a DIFFERENT id");
});

test("blockHashOfRpcHeader: a well-formed header hashes deterministically; a tampered nonce differs; a missing header throws", () => {
  const header = { version: 1, parentsByLevel: [["00".repeat(32)]], hashMerkleRoot: "00".repeat(32), acceptedIdMerkleRoot: "00".repeat(32), utxoCommitment: "00".repeat(32), timestamp: 0n, bits: 0, nonce: 7n, daaScore: 0n, blueWork: 0n, blueScore: 0n, pruningPoint: "00".repeat(32) };
  const h = blockHashOfRpcHeader(config, header);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(blockHashOfRpcHeader(config, clone(header) && { ...header }), h);
  assert.notEqual(blockHashOfRpcHeader(config, { ...header, nonce: 8n }), h);
  assert.throws(() => blockHashOfRpcHeader(config, null), (e) => e.code === "TX_IDENTITY_INVALID");
  assert.throws(() => blockHashOfRpcHeader(config, {}), (e) => e.code === "TX_IDENTITY_INVALID");
});
