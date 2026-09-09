"use strict";

/*
 * Capture CLI for the v0.7 ROOT STATE LAYOUT fixture
 * (core/model/test/fixtures/v7-root-state-layout.json).
 *
 * The fixture pins core/model/vault-state-v7-root.js's byte serializer to
 * the REAL silverc compiler's own `state_layout` region for the PRODUCTION
 * candidate contracts/PolicyVault.v0.7-root.sil — the exact bytes a rooted
 * vault slices in-VM. Capturing it here (rather than asserting a
 * hand-written constant) means the fixture is REGENERABLE evidence: if the
 * compiler's encoding ever moves, this tool reproduces the new bytes and the
 * unit test fails loudly instead of the SDK silently building a state region
 * consensus would read differently.
 *
 * Usage: node capture-v7-root-layout.js [outFile]
 * Requires silverc (config.silvercPath). Writes canonical JSON.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const { loadConfig } = require("../../../sdk/src/config");
const { normalizeOwnerSetV7, OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../owner-set-v7");
const { serializeRootStateHexV7, normalizeRootStateV7, ROOT_STATE_LEN_V7, ROOT_TAIL_LEN_V7 } = require("../vault-state-v7-root");

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = "a7".repeat(32);

function owners(n) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < n ? K(0x71 + i) : INACTIVE_SLOT_KEY);
  return out;
}

/* The four reachable-state corners the VM production suite also asserts. */
const CASES = [
  { name: "1-of-1 unfrozen nonce 0", owners: owners(1), ownerM: 1, emergencyK: 1, recoveryM: 0, frozen: 0, rootNonce: 0 },
  { name: "12-of-12 unfrozen nonce 0", owners: owners(12), ownerM: 12, emergencyK: 1, recoveryM: 6, frozen: 0, rootNonce: 0 },
  { name: "7 active 4-of-7 FROZEN nonce 1", owners: owners(7), ownerM: 4, emergencyK: 2, recoveryM: 3, frozen: 1, rootNonce: 1 },
  { name: "3 active 2-of-3 nonce 2^32-1", owners: owners(3), ownerM: 2, emergencyK: 1, recoveryM: 2, frozen: 0, rootNonce: 4294967295 }
];

const TEMPLATE = { recoveryDelayDaa: 1000, successorPk: K(0x7f), successionDelayDaa: 2000, rootMaxFeePerTx: 200000 };

const bytesArg = (hex) => ({ kind: "array", data: Array.from(Buffer.from(hex, "hex")).map((d) => ({ kind: "byte", data: d })) });
const intArg = (n) => ({ kind: "int", data: n });
const byteArg = (n) => ({ kind: "byte", data: n });

function constructorArgs(state) {
  const nonce = Buffer.alloc(8);
  nonce.writeBigUInt64LE(BigInt(state.rootNonce));
  const args = [bytesArg(ORG_ID)];
  for (const o of state.owners) args.push(bytesArg(o));
  args.push(intArg(state.ownerM), intArg(state.emergencyK), intArg(state.recoveryM));
  args.push(byteArg(state.frozen));
  args.push(bytesArg(nonce.toString("hex")));
  args.push(intArg(TEMPLATE.recoveryDelayDaa), bytesArg(TEMPLATE.successorPk), intArg(TEMPLATE.successionDelayDaa), intArg(TEMPLATE.rootMaxFeePerTx));
  return args;
}

function compile(config, state, dir) {
  const argsPath = path.join(dir, "args.json");
  const outPath = path.join(dir, "artifact.json");
  fs.writeFileSync(argsPath, JSON.stringify(constructorArgs(state), null, 1));
  const source = path.join(config.repoRoot, "contracts/PolicyVault.v0.7-root.sil");
  const r = spawnSync(config.silvercPath, [source, "--constructor-args", argsPath, "--output", outPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`silverc failed: ${r.stderr || r.status}`);
  const artifact = JSON.parse(fs.readFileSync(outPath, "utf8"));
  fs.rmSync(outPath, { force: true });
  const script = Buffer.from(artifact.script);
  const layout = artifact.state_layout;
  return {
    contractName: artifact.contract_name,
    scriptLen: script.length,
    stateLayout: { start: layout.start, len: layout.len },
    stateRegionHex: script.subarray(layout.start, layout.start + layout.len).toString("hex")
  };
}

function main() {
  const outFile = process.argv[2];
  const config = loadConfig({});
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv7-root-layout-"));
  try {
    const cases = CASES.map((c) => {
      const compiled = compile(config, c, dir);
      const state = normalizeRootStateV7({ boundOrgId: ORG_ID, ...c });
      void normalizeOwnerSetV7(c);
      return { name: c.name, state: { boundOrgId: ORG_ID, owners: c.owners, ownerM: String(c.ownerM), emergencyK: String(c.emergencyK), recoveryM: String(c.recoveryM), frozen: String(c.frozen), rootNonce: String(c.rootNonce) }, compiled, coreSerializedHex: serializeRootStateHexV7(state) };
    });
    const fixture = {
      fixtureVersion: "policyvault-v7-root-state-layout/1",
      contract: "contracts/PolicyVault.v0.7-root.sil",
      rootStateLen: ROOT_STATE_LEN_V7,
      rootTailLen: ROOT_TAIL_LEN_V7,
      template: TEMPLATE,
      cases
    };
    const json = JSON.stringify(fixture, null, 1) + "\n";
    if (outFile) fs.writeFileSync(outFile, json);
    else process.stdout.write(json);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

main();
