"use strict";

/*
 * LIVE TESTNET: the v0.7 org-root positive attestation vector
 * (`core/attest/testutil/vectors-v7.js`, built read-only from
 * docs/testnet-v7-org-root-evidence.json) RE-CHECKED against a REAL
 * testnet-10 node — the SAME shared `core/attest/verify.js` chain-facts
 * layer (`checkChainFacts`) every generation's live re-check uses, and the
 * SAME read-only pattern `tools/attestation-verify.js --chain` follows
 * (`sdk/src/chain.js`'s `connectVerified` + `getAddressUtxos`; NOTHING is
 * built, signed, or broadcast here).
 *
 * The declared output is the ORGANIZATIONAL ROOT's own continuation from
 * the LAST step of the real v0.7 lifecycle run
 * ("19-vault-owner-recover-terminal"), which the transcript's own
 * `VERIFIED_OUTCOME.rootStillLive` names as still live at the end of that
 * run. Whether it is STILL live on whichever node this test happens to
 * run against is exactly what this test asks the node — never assumed:
 * CHAIN_CONFIRMED is a genuine "yes, and it matches exactly, right now";
 * CHAIN_UNCONFIRMED is an equally honest "it is no longer in the current
 * UTXO set" (legitimately possible if a LATER, unrecorded transition has
 * since spent it) — never treated as a failure of this test, only of the
 * PRESENCE assumption. CHAIN_CONTRADICTED (an output present but
 * disagreeing on value/covenant id) WOULD fail the test: that is a real
 * defect this suite exists to catch, not an acceptable outcome.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * when no local testnet-10 node answers ws://127.0.0.1:18210 within a
 * short timeout, or answers on the wrong network / unsynced / without a
 * UTXO index.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const { connectVerified, getAddressUtxos, getVirtualDaaScore } = require("../src/chain");
const attest = require("../../core/attest");
const { liveTestnetV7RootAttestation } = require("../../core/attest/testutil/vectors-v7");

const RPC_URL = process.env.POLICYVAULT_TESTNET10_RPC_URL || "ws://127.0.0.1:18210";
const CONNECT_TIMEOUT_MS = 10000;

async function tryConnect(config) {
  const attempt = connectVerified(config);
  const timeout = new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), CONNECT_TIMEOUT_MS));
  const result = await Promise.race([attempt.then((r) => ({ ok: true, ...r })), timeout]);
  if (result.timedOut) return { ok: false, reason: `no response from ${RPC_URL} within ${CONNECT_TIMEOUT_MS}ms` };
  return result;
}

let gate = null;
async function availability() {
  if (gate !== null) return gate;
  const config = loadConfig({ dataRoot: require("fs").mkdtempSync(require("path").join(require("os").tmpdir(), "pv7-live-attest-")), networkId: "testnet-10", rpcUrl: RPC_URL });
  try {
    const result = await tryConnect(config);
    if (!result.ok) {
      gate = { available: false, reason: result.reason, config };
      return gate;
    }
    gate = { available: true, config, rpc: result.rpc, serverInfo: result.serverInfo };
    return gate;
  } catch (e) {
    gate = { available: false, reason: e.message, config };
    return gate;
  }
}

test("v0.7 execution attestation: the positive live-evidence vector structurally verifies offline (no node needed)", () => {
  const rec = liveTestnetV7RootAttestation();
  assert.equal(rec.subject.contractVersion, "policyvault-0.7-root");
  assert.equal(rec.outcome.state, "CHAIN_VERIFIED", "never claims VERIFIED_OUTCOME from a transcript alone");
  assert.equal(rec.outcome.chain.outputs.length, 1);
  const v = attest.verifyAttestation(rec);
  assert.equal(v.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, JSON.stringify(v.structural.failures));
  assert.equal(v.chain.status, attest.CHAIN_STATUS.NOT_CHECKED, "no chain observation was supplied to this offline pass");
  /* determinism: rebuilding from the SAME evidence file yields the SAME
   * record hash, on any machine */
  const again = liveTestnetV7RootAttestation();
  assert.equal(again.attestationHash, rec.attestationHash);
});

test("v0.7 execution attestation: RE-CHECKED against a REAL testnet-10 node, read-only, never broadcasting", async (t) => {
  const g = await availability();
  if (!g.available) {
    t.skip(`REQUIREMENT_NOT_AVAILABLE: no synced testnet-10 node with a UTXO index answered ${RPC_URL} (${g.reason})`);
    return;
  }
  const rec = liveTestnetV7RootAttestation();
  const addresses = attest.addressesToQuery(rec);
  assert.equal(addresses.length, 1);

  const utxos = {};
  for (const address of addresses) {
    const entries = await getAddressUtxos(g.rpc, address);
    utxos[address] = entries.map((u) => ({
      outpoint: u.outpoint,
      amountSompi: u.amount.toString(),
      covenantId: u.covenantId,
      blockDaaScore: u.blockDaaScore !== null ? u.blockDaaScore.toString() : null
    }));
  }
  const virtualDaaScore = (await getVirtualDaaScore(g.rpc)).toString();
  await g.rpc.disconnect();
  gate = null; /* the connection is now closed; force a fresh connect for any later test in this file */

  const chainObservation = {
    available: true,
    reason: null,
    node: { networkId: g.serverInfo.networkId, isSynced: g.serverInfo.isSynced, hasUtxoIndex: g.serverInfo.hasUtxoIndex, virtualDaaScore },
    utxos
  };
  const v = attest.verifyAttestation(rec, { chainObservation });
  assert.equal(v.structural.ok, true, JSON.stringify(v.structural.failures));
  /* CHAIN_CONTRADICTED is the one outcome that would indicate a real
   * defect (an output present with the wrong value/covenant); it is
   * never an acceptable result. CONFIRMED and UNCONFIRMED are both
   * honest, acceptable live-node answers — see the file header. */
  assert.notEqual(v.verdict, attest.VERDICTS.CHAIN_CONTRADICTED, `the node disagrees with the transcript: ${JSON.stringify(v.chain.findings)}`);
  assert.ok(
    [attest.VERDICTS.CHAIN_CONFIRMED, attest.VERDICTS.CHAIN_UNCONFIRMED].includes(v.verdict),
    `unexpected verdict ${v.verdict}: ${JSON.stringify(v.chain)}`
  );
  console.log(`v0.7 live re-check against ${RPC_URL}: ${v.verdict} (chainConfirmed=${v.chainConfirmed})`, JSON.stringify(v.chain.checks));
});
