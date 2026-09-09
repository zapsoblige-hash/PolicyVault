"use strict";

/*
 * ADVERSARIAL UNIT — the opt-in chain re-check.
 *
 * checkChainFacts() is PURE: the caller supplies a node observation, so
 * this suite can drive every disagreement case deterministically without
 * a node. The one invariant it exists to protect:
 *
 *   A NODE THAT IS UNAVAILABLE, ON THE WRONG NETWORK, UNSYNCED, WITHOUT A
 *   UTXO INDEX, SILENT ABOUT AN OUTPUT, OR IN DISAGREEMENT WITH THE
 *   RECORD CAN NEVER PRODUCE A CONFIRMATION.
 *
 * CHAIN_CONFIRMED is the only confirming verdict in the vocabulary and is
 * reachable only by exact agreement on every declared output.
 *
 * Layer: ADVERSARIAL UNIT (pure core; no node, no store, no network).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const A = require("../index");
const V = require("../testutil/vectors");

const REC = V.syntheticSpendAttestation();
const HEALTHY_NODE = { networkId: "testnet-10", isSynced: true, hasUtxoIndex: true, virtualDaaScore: "560488241" };

function utxosFor(record, overrides = {}) {
  const map = {};
  for (const o of record.outcome.chain.outputs) {
    map[o.address] = [
      {
        outpoint: { transactionId: record.outcome.txId, index: o.index },
        amountSompi: o.valueSompi,
        covenantId: o.covenantId,
        blockDaaScore: o.blockDaaScore
      }
    ];
  }
  return { ...map, ...overrides };
}

const observe = (utxos, node = HEALTHY_NODE) => ({ available: true, reason: null, node, utxos });

test("addressesToQuery names exactly the addresses an independent verifier must read, deduplicated and sorted", () => {
  assert.deepEqual(A.addressesToQuery(REC), ["kaspatest:qqrecipient", "kaspatest:qqsuccessor"]);
  assert.deepEqual(A.addressesToQuery(V.refusedAttestation()), []);
  assert.equal(A.addressesToQuery(V.liveTestnetSellAttestation()).length, 5);
});

test("exact agreement on every declared output is the ONLY path to CHAIN_CONFIRMED", () => {
  const r = A.verifyAttestation(REC, { chainObservation: observe(utxosFor(REC)) });
  assert.equal(r.verdict, A.VERDICTS.CHAIN_CONFIRMED);
  assert.equal(r.chainConfirmed, true);
  assert.equal(r.chain.status, A.CHAIN_STATUS.CONFIRMED);
  assert.ok(r.chain.checks.every((c) => c.ok));
});

test("an UNAVAILABLE node yields CHAIN_UNAVAILABLE — never a confirmation", () => {
  for (const observation of [
    { available: false, reason: "connect refused", node: null, utxos: {} },
    { available: true, reason: null, node: null, utxos: {} },
    null
  ]) {
    const r = A.verifyAttestation(REC, { chainObservation: observation ?? { available: false, reason: "no observation", node: null, utxos: {} } });
    assert.equal(r.verdict, A.VERDICTS.CHAIN_UNAVAILABLE);
    assert.equal(r.chainConfirmed, false);
  }
});

test("an unsynced node or one without a UTXO index can never confirm", () => {
  for (const node of [
    { ...HEALTHY_NODE, isSynced: false },
    { ...HEALTHY_NODE, hasUtxoIndex: false }
  ]) {
    const r = A.verifyAttestation(REC, { chainObservation: observe(utxosFor(REC), node) });
    assert.equal(r.verdict, A.VERDICTS.CHAIN_UNAVAILABLE);
    assert.equal(r.chainConfirmed, false);
    assert.ok(r.chain.findings.some((f) => f.code === "NODE_NOT_USABLE"));
  }
});

test("a node on another network can never confirm", () => {
  const r = A.verifyAttestation(REC, { chainObservation: observe(utxosFor(REC), { ...HEALTHY_NODE, networkId: "mainnet" }) });
  assert.equal(r.verdict, A.VERDICTS.CHAIN_UNAVAILABLE);
  assert.ok(r.chain.findings.some((f) => f.code === "NODE_WRONG_NETWORK"));
});

test("an output the node does not show is UNCONFIRMED — never confirmed, and never called falsified", () => {
  const utxos = utxosFor(REC);
  delete utxos["kaspatest:qqrecipient"];
  const r = A.verifyAttestation(REC, { chainObservation: observe(utxos) });
  assert.equal(r.verdict, A.VERDICTS.CHAIN_UNCONFIRMED);
  assert.equal(r.chainConfirmed, false);
  assert.ok(r.chain.findings.some((f) => f.code === "OUTPUT_ADDRESS_NOT_QUERIED"));

  /* the ordinary, innocent case: the covenant successor was legitimately
   * spent by the NEXT transition, so it is no longer in the UTXO set. */
  const spent = utxosFor(REC, { "kaspatest:qqsuccessor": [] });
  const r2 = A.verifyAttestation(REC, { chainObservation: observe(spent) });
  assert.equal(r2.verdict, A.VERDICTS.CHAIN_UNCONFIRMED);
  assert.ok(r2.chain.findings.some((f) => f.code === "OUTPUT_NOT_IN_UTXO_SET"));
});

test("a node that DISAGREES about a value, a covenant id, or an accepting DAA score CONTRADICTS the record", () => {
  const cases = [
    ["value", { "kaspatest:qqrecipient": [{ outpoint: { transactionId: REC.outcome.txId, index: 1 }, amountSompi: "1", covenantId: null, blockDaaScore: "560488141" }] }],
    ["covenant id", { "kaspatest:qqsuccessor": [{ outpoint: { transactionId: REC.outcome.txId, index: 0 }, amountSompi: "98500000000", covenantId: V.H("99"), blockDaaScore: "560488141" }] }],
    ["daa score", { "kaspatest:qqsuccessor": [{ outpoint: { transactionId: REC.outcome.txId, index: 0 }, amountSompi: "98500000000", covenantId: V.H("cc"), blockDaaScore: "1" }] }]
  ];
  for (const [label, override] of cases) {
    const r = A.verifyAttestation(REC, { chainObservation: observe(utxosFor(REC, override)) });
    assert.equal(r.verdict, A.VERDICTS.CHAIN_CONTRADICTED, label);
    assert.equal(r.chainConfirmed, false, label);
    assert.ok(r.chain.findings.some((f) => f.code === "OUTPUT_CONTRADICTED"), label);
  }
});

test("a record with no declared chain observations reports NOT_APPLICABLE, never a confirmation", () => {
  const r = A.verifyAttestation(V.refusedAttestation(), { chainObservation: observe({}) });
  assert.equal(r.chain.status, A.CHAIN_STATUS.NOT_APPLICABLE);
  assert.equal(r.verdict, A.VERDICTS.STRUCTURE_VERIFIED);
  assert.equal(r.chainConfirmed, false);
});

test("a structurally INVALID record is never chain-checked at all", () => {
  const rec = V.clone(REC);
  rec.amounts.amount = "1";
  const r = A.verifyAttestation(rec, { chainObservation: observe(utxosFor(REC)) });
  assert.equal(r.verdict, A.VERDICTS.INVALID);
  assert.equal(r.chain.status, A.CHAIN_STATUS.NOT_CHECKED);
  assert.equal(r.chainConfirmed, false);
});

test("the live testnet SELL vector confirms against its own recorded observations and nothing weaker", () => {
  const live = V.liveTestnetSellAttestation();
  const node = { networkId: "testnet-10", isSynced: true, hasUtxoIndex: true, virtualDaaScore: "560488241" };
  const ok = A.verifyAttestation(live, { chainObservation: observe(utxosFor(live), node) });
  assert.equal(ok.verdict, A.VERDICTS.CHAIN_CONFIRMED);

  /* drop the protocol-fee output the venue paid: no longer confirmable */
  const partial = utxosFor(live);
  const feeAddress = live.outcome.chain.outputs[4].address;
  partial[feeAddress] = [];
  const degraded = A.verifyAttestation(live, { chainObservation: observe(partial, node) });
  assert.equal(degraded.verdict, A.VERDICTS.CHAIN_UNCONFIRMED);
  assert.equal(degraded.chainConfirmed, false);
});
