"use strict";

/*
 * BROWSER-LOCAL PRE-SIGN VERIFICATION — unit + adversarial matrix.
 *
 * Drives web/verify-intent.js (with the browser core bundle injected —
 * the EXACT code the browser executes) over server-document-shaped
 * scenarios. The hostile cases are policy-invalid adversarial test
 * transactions modeling a HOSTILE SERVER that builds a transaction
 * differing from the user's request; each one must produce a REFUSED
 * outcome with the right detector code, which blocks the wallet prompt
 * (blocking wiring proven in app-v4-gate.test.js).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");
const H = require("./helpers.js");

const vi = createVerifyIntent(core);

function run(s, extra) {
  return vi.verifyBeforeSigning({
    request: s.request,
    vault: s.vault,
    createContext: s.createContext,
    clientAction: s.clientAction,
    clientParams: s.clientParams,
    clientFuel: s.clientFuel,
    sessionNetwork: s.sessionNetwork,
    sessionXOnly: s.sessionXOnly,
    role: s.role,
    ...(extra || {})
  });
}

function expectPass(outcome, label) {
  assert.equal(outcome.ok, true, `${label}: expected PASS, got ${JSON.stringify(outcome.refusalCodes)}\n${(outcome.lines || []).join("\n")}`);
  assert.equal(outcome.verdict, "VERIFIED_EXACT");
  assert.ok(outcome.manifestHash && /^[0-9a-f]{64}$/.test(outcome.manifestHash));
  assert.ok(outcome.lines.some((l) => l.includes("THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.")), `${label}: PASS statement rendered`);
}

function expectRefusal(outcome, codes, label) {
  assert.equal(outcome.ok, false, `${label}: expected REFUSED, got PASS`);
  assert.equal(outcome.verdict, "REFUSED");
  assert.equal(outcome.unsignedSafeJson, null, `${label}: a refused outcome must never carry a signable payload binding`);
  assert.equal(outcome.lines[0], "!! DO NOT SIGN !!", `${label}: refusal lines must lead with DO NOT SIGN`);
  for (const code of codes) {
    assert.ok(outcome.refusalCodes.includes(code), `${label}: expected refusal code ${code}, got ${JSON.stringify(outcome.refusalCodes)}`);
  }
}

/* =================== PASS paths (every real flow) =================== */

test("PASS: fresh below-threshold agentSpend verifies and explains from the client's own intent", () => {
  const s = H.spendScenario();
  const out = run(s);
  expectPass(out, "agentSpend");
  assert.equal(out.unsignedSafeJson, s.request.transaction.unsignedSafeJson, "the outcome binds the exact signed payload");
  assert.equal(out.txId, H.HEX("0a"));
  // full-value explanation: complete recipient key, exact amounts, budget, fee
  const text = out.lines.join("\n");
  assert.ok(text.includes(`Send exactly 10 KAS to recipient public key ${H.RECIPIENT}`), "requested action line");
  assert.ok(text.includes("Payment of exactly 10 KAS"), "payment output line");
  assert.ok(text.includes(`Fee: ${s.request.review.feeKas} KAS`), "exact fee line (the TRUE recomputed reserve-funded fee)");
  assert.ok(out.notes.some((n) => n.includes("Independently recomputed") && n.includes("network-fee lower bound")), "fee-bound recomputation note present");
  assert.ok(out.notes.some((n) => n.includes("Independently recomputed") && n.includes("compute budgets")), "compute-budget recomputation note present");
  assert.ok(out.notes.some((n) => n.includes("Independently recomputed") && n.includes("successor state id")), "successor state-id recomputation note present");
  assert.ok(text.includes("Protected value after: 490 KAS (was 500 KAS)"), "budget before/after");
  assert.ok(text.includes("15 KAS of the 50 KAS period budget used"), "period budget line");
  assert.ok(text.includes("at or below the approval threshold (15 KAS)"), "approvals line");
  assert.ok(!/…/.test(text), "no truncation ellipsis in explanation lines");
  assert.ok(out.notes.some((n) => n.includes("own action context")), "intent-source note present");
});

test("PASS: explanation output is deterministic (same inputs => identical lines)", () => {
  const a = run(H.spendScenario());
  const b = run(H.spendScenario());
  assert.deepEqual(a.lines, b.lines);
  assert.equal(a.manifestHash, b.manifestHash);
});

test("PASS: ownerTopUp (fuel-funded) with client-picked fuel binding", () => {
  const out = run(H.topUpScenario());
  expectPass(out, "ownerTopUp");
  assert.ok(out.lines.join("\n").includes("Add exactly 50 KAS to the protected value"), "top-up summary");
});

test("PASS: ownerPause preserves value and policy nonce", () => {
  const out = run(H.pauseScenario());
  expectPass(out, "ownerPause");
  assert.ok(out.lines.join("\n").includes("Vault paused"), "pause policy line");
});

test("PASS: ownerSetApprovers derives the canonical sorted slot layout client-side", () => {
  const out = run(H.setApproversScenario());
  expectPass(out, "ownerSetApprovers");
  assert.ok(out.lines.join("\n").includes("Policy nonce advances 7 -> 8"), "nonce line");
});

test("PASS: addAgent (high-level) — value-preserving, successor root INDEPENDENTLY RECOMPUTED from the typed agent params", () => {
  const out = run(H.addAgentScenario());
  expectPass(out, "addAgent");
  const text = out.lines.join("\n");
  assert.ok(text.includes("Add an agent to vault"), "high-level summary");
  assert.ok(text.includes("BROWSER_SERVER_CLAIMED_FIELDS"), "server-claim warning rendered in the signing lines");
  assert.ok(!text.includes("the browser cannot recompute Merkle roots"), "the old cannot-recompute residual is gone");
  assert.ok(
    out.notes.some((n) => n.includes("Independently recomputed in this browser") && n.includes("addAgent")),
    "the recomputed successor-root note is present"
  );
  assert.ok(
    !out.notes.some((n) => n.includes("Server-claimed") && n.includes("agent-registry Merkle commitment")),
    "the successor agent root is no longer listed as a server claim"
  );
});

test("HOSTILE: addAgent server substitutes a different successor root than the typed agent produces (agent substitution)", () => {
  const s = H.clone(H.addAgentScenario());
  s.request.review.successorAgentRoot = H.AGENT_ROOT_1; // pretend nothing changed / different registry
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "lifecycle root substitution");
  // and a claim that is a valid root of a DIFFERENT agent set also refuses
  const s2 = H.clone(H.addAgentScenario());
  s2.request.review.successorAgentRoot = H.AGENT_ROOT_2;
  expectRefusal(run(s2), ["REVIEW_MISMATCH"], "lifecycle root substitution (other set)");
});

test("FAIL-CLOSED: addAgent without the full typed agent policy cannot recompute and refuses", () => {
  const s = H.clone(H.addAgentScenario());
  s.clientParams = { agent: { agentPk: H.NEW_AGENT_PARAM.agentPk } }; // missing limits + recipients
  expectRefusal(run(s), ["VALUE_INVALID"], "partial lifecycle params");
  const s2 = H.clone(H.addAgentScenario());
  s2.clientParams = {}; // no agent at all
  expectRefusal(run(s2), ["VALUE_INVALID"], "missing lifecycle params");
});

test("FAIL-CLOSED: addAgent duplicating an existing agent key cannot derive a successor and refuses", () => {
  const s = H.clone(H.addAgentScenario());
  s.clientParams = { agent: { ...H.clone(H.NEW_AGENT_PARAM), agentPk: H.AGENT } }; // key already in the registry
  expectRefusal(run(s), ["MERKLE_RECOMPUTE_FAILED"], "duplicate-agent lifecycle");
});

test("PASS: ownerRecover pays the full protected value + reserve to the owner", () => {
  const out = run(H.recoverScenario());
  expectPass(out, "ownerRecover");
  assert.ok(out.lines.join("\n").includes("CLOSE vault"), "terminal summary");
});

test("PASS: createVault genesis against the client's own form context", () => {
  const s = H.createScenario();
  const out = run(s);
  expectPass(out, "createVault");
  const text = out.lines.join("\n");
  assert.ok(text.includes("Create vault"), "genesis summary");
  assert.ok(text.includes("500 KAS protected value and 1 KAS fee reserve"), "exact genesis amounts");
  assert.ok(!text.includes("BROWSER_PSEUDO_STATE_ID"), "the pseudo-state-id placeholder is gone — the real commitment formula is recomputed");
  assert.ok(out.notes.some((n) => n.includes("Independently recomputed") && n.includes("network fee (EXACT")), "genesis fee is EXACT-recomputed (all-ordinary-input shape)");
  assert.ok(out.notes.some((n) => n.includes("Independently recomputed") && n.includes("genesis state id")), "genesis state id recomputed by the canonical formula");
  // the manifest's stateAfter carries the REAL canonical commitment of the initial state
  assert.equal(out.manifest.stateAfter.stateId, H.stateIdOf({ ...H.BASE_STATE, policyNonce: "0" }), "genesis stateId equals the canonical computeStateIdV4 commitment");
});

test("PASS: resumed approver flow verifies the durable request and labels the intent source", () => {
  const s = H.aboveSpendScenario();
  const out = run({ ...s, sessionXOnly: H.K1, role: "approver" });
  expectPass(out, "approver");
  assert.ok(out.lines.join("\n").includes("ABOVE the approval threshold (15 KAS): 2 approver signature(s)"), "approval tier line");
  assert.ok(out.notes.some((n) => n.includes("durable server request")), "resumed-intent provenance note");
});

test("PASS: resumed acting-agent flow (after approvals) verifies the durable request", () => {
  const s = H.aboveSpendScenario();
  const out = run({ ...s, role: "agent" });
  expectPass(out, "agent-sign-after-approvals");
});

/* ============ HOSTILE MATRIX (policy-invalid adversarial test ============
 * ============  transactions from a hostile server/builder)   ============ */

test("HOSTILE: recipient substitution — the frozen tx pays the attacker instead of the requested recipient", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[0].scriptPublicKey = H.spkWire(H.p2pk(H.ATTACKER));
  });
  expectRefusal(run(s), ["HIDDEN_RECIPIENT"], "recipient substitution");
});

test("HOSTILE: payment amount inflation — tx pays the recipient more than requested (drains the vault)", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[0].value = "5000000000"; // 50 KAS instead of the requested 10
    tx.outputs[1].value = "45099995000";
  });
  expectRefusal(run(s), ["HIDDEN_RECIPIENT"], "payment inflation"); // no output pays the REQUESTED amount
});

test("HOSTILE: hidden extra output funded from the covenant — refused as an impossible reserve drawdown", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[1].value = "48099995000"; // successor shrunk by 10 KAS...
    tx.outputs.push({ value: "1000000000", scriptPublicKey: H.spkWire(H.p2pk(H.ATTACKER)), covenant: null }); // ...leaking here
  });
  // the covenant drawdown beyond the requested payment can only be reserve
  // consumption, and 10 KAS exceeds both the agent's fee cap and the reserve
  expectRefusal(run(s), ["RESERVE_RULE_VIOLATION"], "covenant-funded extra output");
});

test("HOSTILE: hidden extra output funded from fuel — UNEXPECTED_OUTPUT + HIDDEN_RECIPIENT", () => {
  let biggerFuel;
  const s = H.withTamperedTx(H.topUpScenario(), (tx) => {
    biggerFuel = (BigInt(tx.inputs[1].utxo.amount) + 1000000000n).toString(); // 10 KAS more fuel...
    tx.inputs[1].utxo.amount = biggerFuel;
    tx.outputs.push({ value: "1000000000", scriptPublicKey: H.spkWire(H.p2pk(H.ATTACKER)), covenant: null }); // ...leaking here
  });
  s.clientFuel = { outpoint: { transactionId: H.FUEL_TXID, index: 1 }, amount: biggerFuel };
  const out = run(s);
  expectRefusal(out, ["HIDDEN_RECIPIENT", "UNEXPECTED_OUTPUT"], "fuel-funded extra output");
});

test("HOSTILE: fee inflation beyond the client's expectation (owner op)", () => {
  // fuel 250 KAS, tiny change -> ~200 KAS network fee
  const s = H.withTamperedTx(H.topUpScenario(), (tx) => {
    tx.inputs[1].utxo.amount = "25000010000";
  });
  s.clientFuel = { outpoint: { transactionId: H.FUEL_TXID, index: 1 }, amount: "25000010000" };
  s.request = H.clone(s.request);
  // even an honest review of the inflated fee refuses
  s.request.review.feeSompi = (25000010000n - 5000000000n - H.OWNER_OP_CHANGE).toString();
  expectRefusal(run(s), ["EXCESSIVE_FEE"], "fee inflation");
});

test("HOSTILE: reserve overdraw — spend consumes more reserve than the agent's per-tx fee cap", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[1].value = "49050000000"; // drawdown = pay + 50000000 (0.5 KAS) reserve consumption
  });
  s.request = H.clone(s.request);
  s.request.review.reserveConsumedKas = "0.5";
  s.request.review.reserveAfterKas = "0.5";
  s.request.review.feeSompi = "50000000";
  const out = run(s);
  expectRefusal(out, ["RESERVE_RULE_VIOLATION"], "reserve overdraw"); // 0.5 KAS > agentMaxFeePerTx 0.001 KAS
});

test("HOSTILE: wrong successor value — the covenant keeps less than the client-derived successor state", () => {
  let smallerFuel;
  const s = H.withTamperedTx(H.topUpScenario(), (tx) => {
    tx.outputs[0].value = "54100000000"; // 1 KAS short of the derived successor total
    smallerFuel = (BigInt(tx.inputs[1].utxo.amount) - 1000000000n).toString(); // fee stays the fixture fee
    tx.inputs[1].utxo.amount = smallerFuel;
  });
  s.clientFuel = { outpoint: { transactionId: H.FUEL_TXID, index: 1 }, amount: smallerFuel };
  expectRefusal(run(s), ["WRONG_SUCCESSOR"], "wrong successor value");
});

test("HOSTILE: wrong nonce claim — a policy-neutral action claiming a nonce advance", () => {
  const s = H.clone(H.pauseScenario());
  s.request.review.policyNonceAfter = "8"; // pause must preserve the nonce
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "nonce smuggling");
});

test("HOSTILE: policy mutation smuggled into an ordinary owner op — review claims a new agent root under ownerTopUp", () => {
  const s = H.clone(H.topUpScenario());
  s.request.review.successorAgentRoot = H.AGENT_ROOT_2; // top-up must preserve the agent registry
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "smuggled agent-root change");
});

test("HOSTILE: wrong network — the request/vault claim a different network than the wallet session", () => {
  const s = H.clone(H.spendScenario());
  s.sessionNetwork = "mainnet";
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "network mismatch"); // request.networkId testnet-10 != session mainnet
  const s2 = H.clone(H.spendScenario());
  s2.sessionNetwork = "testnet-11";
  expectRefusal(run(s2), ["NETWORK_MISMATCH"], "non-operational network");
});

test("HOSTILE: wrong vault — the transaction spends a different covenant outpoint than the vault the user is looking at", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.inputs[0].transactionId = H.HEX("f9"); // the request still CLAIMS the right outpoint
  });
  expectRefusal(run(s), ["PREDECESSOR_MISMATCH"], "wrong vault outpoint");
  // and when the request document itself claims the foreign outpoint, the
  // claim/knowledge cross-check refuses instead
  const s2 = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.inputs[0].transactionId = H.HEX("f9");
  });
  s2.request.predecessorOutpoint = { transactionId: H.HEX("f9"), index: 0 };
  expectRefusal(run(s2), ["REVIEW_MISMATCH"], "foreign outpoint claim");
});

test("HOSTILE: stale/foreign state — the request was built against a state the client has never seen", () => {
  const s = H.clone(H.spendScenario());
  s.request.predecessorStateId = H.HEX("f7");
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "stale predecessor state");
});

test("HOSTILE: requested action != serialized transaction — an ownerTopUp request whose bytes drain value", () => {
  // the tx is a value-decreasing transition while the client asked for a top-up
  const s = H.withTamperedTx(H.topUpScenario(), (tx) => {
    tx.outputs[0].value = "45100000000"; // covenant loses 5 KAS instead of gaining 50
  });
  // an "honest" review of the divergent bytes (fee matches the real spread)
  // still refuses: the successor value contradicts the CLIENT-derived state
  s.request.review.feeSompi = (10000000000n + H.OWNER_OP_FEE_SOMPI).toString();
  const out = run(s);
  expectRefusal(out, ["WRONG_SUCCESSOR"], "action/bytes divergence");
  assert.ok(out.refusalCodes.includes("EXCESSIVE_FEE"), `the drained value also surfaces as an excessive fee: ${JSON.stringify(out.refusalCodes)}`);
  // and with the original (now false) 5000-sompi fee claim, the review
  // binding itself refuses first
  const s2 = H.withTamperedTx(H.topUpScenario(), (tx) => {
    tx.outputs[0].value = "45100000000";
  });
  expectRefusal(run(s2), ["REVIEW_MISMATCH"], "false fee claim over drained bytes");
});

test("txId semantics (F2-1 resolved): the REQUIRED claim is EQUALITY-BOUND to the payload-embedded id", () => {
  // Since the F2-1 follow-up the SDK finalize()s the unsigned wasm
  // transaction before serializeToSafeJSON — Kaspa txids exclude
  // signature scripts, so the embedded id IS the consensus id and any
  // divergence from the claim must refuse: the wallet must never sign a
  // transaction whose id differs from the recorded/audited one.
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.id = H.HEX("0f");
  }, { keepTxIdClaim: false });
  expectRefusal(run(s), ["TXID_MISMATCH"], "embedded-id divergence from the claim");
  // The honest document (embedded id == claim) passes and carries the id
  const honest = H.spendScenario();
  const out = run(honest);
  assert.equal(out.ok, true, JSON.stringify(out.refusalCodes));
  assert.equal(out.txId, honest.request.txId);
  // The claim itself is REQUIRED (previously optional — tightened)
  const missing = H.clone(H.spendScenario());
  delete missing.request.txId;
  expectRefusal(run(missing), ["SERVER_CLAIM_INVALID"], "missing txId claim");
  const malformed = H.clone(H.spendScenario());
  malformed.request.txId = "zz".repeat(32);
  expectRefusal(run(malformed), ["SERVER_CLAIM_INVALID"], "malformed txId claim");
});

test("HOSTILE: displayed allowlist inconsistent with the covenant-committed root (view/commitment disagreement)", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents[0].recipients = [H.K4]; // displayed list no longer matches the committed agentRecipientRoot
  expectRefusal(run(s), ["ALLOWLIST_ROOT_MISMATCH"], "allowlist view/commitment mismatch");
});

test("HOSTILE: recipient outside a ROOT-CONSISTENT allowlist (genuinely not allowlisted)", () => {
  const s = H.clone(H.spendScenario());
  s.vault = H.vaultWithConsistentRecipients([H.K4]); // consistent commitments; the requested recipient simply is not in the set
  // keep the request's claims consistent with the modified registry: the
  // predecessor/successor roots AND their canonical state ids
  const am = require("../../core/model/agent-merkle-v4.js");
  const rm = require("../../core/model/recipient-merkle-v3.js");
  const tree = am.buildAgentTreeV4([{ ...H.AGENT_POLICY_1, agentRecipientRoot: rm.buildRecipientTree([H.K4]).root }]);
  const succRoot = am.applyAgentSpendV4(tree, H.AGENT, { newPeriodStartDaa: "1000000", newPeriodSpent: "1500000000" }).tree.root;
  s.request.review.successorAgentRoot = succRoot;
  s.request.predecessorStateId = s.vault.live.stateId;
  s.request.review.predecessorStateId = s.vault.live.stateId;
  const succStateId = H.stateIdOf({ ...H.SPEND_SUCC_STATE, agentRoot: succRoot });
  s.request.successorStateId = succStateId;
  s.request.review.successorStateId = succStateId;
  expectRefusal(run(s), ["ALLOWLIST_NOT_PROVEN"], "recipient not allowlisted");
});

test("FAIL-CLOSED: an EMPTY displayed allowlist cannot be proven under any root and refuses", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents[0].recipients = [];
  expectRefusal(run(s), ["MERKLE_RECOMPUTE_FAILED"], "empty allowlist");
});

test("HOSTILE: lockTime games — a lockTime that is not a whole-period rollover", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.lockTime = "1000123"; // not periodStart + k*periodLength
  });
  expectRefusal(run(s), ["LOCKTIME_RULE_VIOLATION"], "lockTime rule");
});

test("HOSTILE: pre-signed payload — a signatureScript smuggled into the 'unsigned' transaction", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.inputs[0].signatureScript = "41" + "00".repeat(65);
  });
  expectRefusal(run(s), ["SAFE_JSON_INVALID"], "pre-signed payload");
});

test("HOSTILE: unknown field smuggled into the Safe JSON payload", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.extraAuthority = { grant: "all" };
  });
  expectRefusal(run(s), ["SAFE_JSON_INVALID"], "unknown payload field");
  const s2 = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[0].hidden = "1";
  });
  expectRefusal(run(s2), ["SAFE_JSON_INVALID"], "unknown output field");
});

test("HOSTILE: non-zero payload / gas / storage mass refuse", () => {
  for (const mutate of [
    (tx) => { tx.payload = "deadbeef"; },
    (tx) => { tx.gas = "1"; },
    (tx) => { tx.storageMass = "1000"; }
  ]) {
    const s = H.withTamperedTx(H.spendScenario(), mutate);
    expectRefusal(run(s), ["SAFE_JSON_INVALID"], "payload/gas/mass");
  }
});

test("HOSTILE: genesis deposit mismatch — the server commits a different initial state than the form", () => {
  const s = H.clone(H.createScenario());
  s.request.initialState.protectedValue = "40000000000"; // 400 KAS instead of the typed 500
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "genesis deposit mismatch");
});

test("HOSTILE: genesis vault output underfunded relative to the typed deposit", () => {
  // a bare 100-KAS shortfall inflates the actual fee, so the EXACT genesis
  // fee recomputation catches it FIRST (fee/state recomputation wave)
  const s = H.withTamperedTx(H.createScenario(), (tx) => {
    tx.outputs[0].value = "40100000000"; // 100 KAS short of the typed deposit
  });
  expectRefusal(run(s), ["FEE_MISMATCH"], "genesis underfunding (fee-visible)");
  // fee-preserving variant: the shortfall moved into the change output in an
  // amount below the exact fee — the fee equality holds, and the successor
  // value check refuses instead (the vault output is not the typed deposit)
  const shift = 100000n; // < CREATE_FEE_SOMPI, so the typed-fee equation stays non-negative
  const s3 = H.withTamperedTx(H.createScenario(), (tx) => {
    tx.outputs[0].value = (BigInt(tx.outputs[0].value) - shift).toString();
    tx.outputs[1].value = (BigInt(tx.outputs[1].value) + shift).toString();
  });
  expectRefusal(run(s3), ["WRONG_SUCCESSOR"], "genesis underfunding (fee-preserving)");
  // variant: the shortfall siphoned into an oversized "change" output —
  // caught as a value-conservation violation before any manifest is built
  const s2 = H.withTamperedTx(H.createScenario(), (tx) => {
    tx.outputs[0].value = "40100000000";
    tx.outputs[1].value = "10000001000";
  });
  expectRefusal(run(s2), ["VALUE_CONSERVATION_VIOLATION"], "genesis siphon via change");
});

test("HOSTILE: genesis agent substitution — the committed initial agent differs from the one the user entered", () => {
  const s = H.clone(H.createScenario());
  s.request.review.agents = [{ agentPk: H.ATTACKER, maxPerSpendKas: "20", recipients: [H.RECIPIENT] }];
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "genesis agent substitution");
});

test("HOSTILE: genesis owner substitution — the server template names a different owner", () => {
  const s = H.clone(H.createScenario());
  s.request.template = { owner: H.ATTACKER, vaultId: H.VAULT_ID };
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "genesis owner substitution");
});

test("HOSTILE: change rerouted — an owner op whose 'change' pays a third party", () => {
  const s = H.withTamperedTx(H.pauseScenario(), (tx) => {
    tx.outputs[1].scriptPublicKey = H.spkWire(H.p2pk(H.ATTACKER));
  });
  expectRefusal(run(s), ["HIDDEN_RECIPIENT"], "change rerouted");
});

test("HOSTILE: identity confusion — the connected wallet is not the acting agent", () => {
  const s = H.clone(H.spendScenario());
  s.sessionXOnly = H.ATTACKER;
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "wrong signer identity");
});

test("HOSTILE: approver flow with a non-approver wallet refuses", () => {
  const s = H.aboveSpendScenario();
  const out = run({ ...s, sessionXOnly: H.ATTACKER, role: "approver" });
  expectRefusal(out, ["IDENTITY_UNRESOLVED"], "non-approver identity");
});

test("HOSTILE: fuel substitution — the tx spends a different fuel UTXO than the client selected", () => {
  const s = H.clone(H.topUpScenario());
  s.clientFuel = { outpoint: { transactionId: H.HEX("f8"), index: 9 }, amount: "5000010000" };
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "fuel substitution");
});

/* ========= INDEPENDENT MERKLE RECOMPUTATION — adversarial matrix ========= */

test("HOSTILE: tampered agent policy leaf — the displayed limits differ from the covenant-committed policy", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents[0].maxPerSpendKas = "2000"; // display shows a 100x higher cap than the committed leaf
  expectRefusal(run(s), ["AGENT_REGISTRY_ROOT_MISMATCH"], "tampered policy leaf");
});

test("HOSTILE: tampered covenant state root — live.agentRoot altered relative to the displayed registry", () => {
  const s = H.clone(H.spendScenario());
  s.vault.live.agentRoot = H.HEX("9c");
  expectRefusal(run(s), ["AGENT_REGISTRY_ROOT_MISMATCH"], "tampered state root");
});

test("HOSTILE: hidden agent lane — the view shows an extra agent the committed root does not contain", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents.push({ ...H.clone(s.vault.agents[0]), agentPk: H.ATTACKER, agentAddress: "kaspatest:attacker0" });
  expectRefusal(run(s), ["AGENT_REGISTRY_ROOT_MISMATCH"], "hidden extra agent");
});

test("HOSTILE: removed agent leaf — the view hides the registry the committed root contains", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents = []; // root still commits one agent
  expectRefusal(run(s), ["AGENT_REGISTRY_ROOT_MISMATCH"], "hidden registry");
});

test("HOSTILE: duplicated agent entry in the view — ambiguous registry refuses before any recompute", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents.push(H.clone(s.vault.agents[0]));
  expectRefusal(run(s), ["VAULT_KNOWLEDGE_MISSING"], "duplicated agent display");
});

test("PASS-PRESERVING: displayed agent ORDER is canonicalized — permuted views produce the identical verified manifest", () => {
  const am = require("../../core/model/agent-merkle-v4.js");
  const secondPolicy = { ...H.AGENT_POLICY_1, agentPk: H.HEX("07"), periodSpent: "0" };
  const tree2 = am.buildAgentTreeV4([H.AGENT_POLICY_1, secondPolicy]);
  const succ2 = am.applyAgentSpendV4(tree2, H.AGENT, { newPeriodStartDaa: "1000000", newPeriodSpent: "1500000000" }).tree.root;
  const secondView = {
    agentPk: secondPolicy.agentPk,
    agentAddress: "kaspatest:second0",
    maxPerSpendKas: "20",
    periodBudgetKas: "50",
    periodSpentKas: "0",
    remainingBudgetKas: "50",
    periodLengthDaa: "86400",
    periodStartDaa: "1000000",
    approvalThresholdKas: "15",
    agentMaxFeePerTxKas: "0.1",
    agentRecipientRoot: H.clone(H.spendScenario()).vault.agents[0].agentRecipientRoot,
    recipients: [H.RECIPIENT],
    recipientAddresses: ["kaspatest:recipient0"]
  };
  const stateId2 = H.stateIdOf({ ...H.BASE_STATE, agentRoot: tree2.root });
  const succStateId2 = H.stateIdOf({ ...H.SPEND_SUCC_STATE, agentRoot: succ2 });
  const mk = (order) => {
    const s = H.clone(H.spendScenario());
    const first = s.vault.agents[0];
    s.vault.agents = order === "forward" ? [first, H.clone(secondView)] : [H.clone(secondView), first];
    s.vault.live.agentRoot = tree2.root;
    s.vault.live.stateId = stateId2; // the TRUE commitment of the two-agent state
    s.request.predecessorStateId = stateId2;
    s.request.review.predecessorStateId = stateId2;
    s.request.review.successorAgentRoot = succ2;
    s.request.successorStateId = succStateId2;
    s.request.review.successorStateId = succStateId2;
    return s;
  };
  const a = run(mk("forward"));
  const b = run(mk("reversed"));
  expectPass(a, "two-agent forward order");
  expectPass(b, "two-agent reversed order");
  assert.equal(a.manifestHash, b.manifestHash, "insertion order must not change the verified manifest");
});

test("FAIL-CLOSED: empty displayed registry with the CONSISTENT padding root still cannot authorize a spend (acting agent unknown)", () => {
  const am = require("../../core/model/agent-merkle-v4.js");
  const s = H.clone(H.spendScenario());
  s.vault.agents = [];
  s.vault.live.agentRoot = am.PADDING_LEAF_HEX; // canonical empty-registry root — view IS consistent
  s.vault.live.stateId = H.stateIdOf({ ...H.BASE_STATE, agentRoot: am.PADDING_LEAF_HEX }); // ...including its state id
  s.request.predecessorStateId = s.vault.live.stateId;
  expectRefusal(run(s), ["AGENT_POLICY_MISMATCH"], "empty consistent registry");
});

test("FAIL-CLOSED: unknown covenant versions never route to a default recompute rule", () => {
  for (const version of ["policyvault-0.3", "policyvault-9.9", "totally-unknown"]) {
    const s = H.clone(H.spendScenario());
    s.vault.contractVersion = version;
    s.request.contractVersion = version; // even a consistent claim pair refuses
    expectRefusal(run(s), ["UNSUPPORTED_COVENANT_VERSION"], `version ${version}`);
  }
});

test("HOSTILE: spend successor-root claim substitution — the request claims a root the recomputation contradicts", () => {
  const s = H.clone(H.spendScenario());
  s.request.review.successorAgentRoot = H.AGENT_ROOT_1; // pretend the registry does not advance
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "spend successor-root substitution");
  const s2 = H.clone(H.spendScenario());
  s2.request.review.successorAgentRoot = H.HEX("9d"); // arbitrary foreign root
  expectRefusal(run(s2), ["REVIEW_MISMATCH"], "spend successor-root foreign");
});

test("FAIL-CLOSED: oversized displayed registry (4097 agents) cannot be recomputed and refuses", () => {
  const s = H.clone(H.spendScenario());
  const template = s.vault.agents[0];
  const agents = [];
  for (let i = 0; i < 4097; i++) {
    agents.push({ ...template, agentPk: i.toString(16).padStart(8, "0").repeat(8) });
  }
  s.vault.agents = agents;
  expectRefusal(run(s), ["MERKLE_RECOMPUTE_FAILED"], "oversized registry");
});

test("FAIL-CLOSED: malformed allowlist-root field in the view refuses before any recompute", () => {
  const s = H.clone(H.spendScenario());
  s.vault.agents[0].agentRecipientRoot = "zz".repeat(32);
  expectRefusal(run(s), ["VALUE_INVALID"], "malformed committed root");
});

test("PASS + HOSTILE: raw ownerSetAgentRoot is pinned to the CLIENT'S own root parameter", () => {
  const newRoot = H.ADD_AGENT_SUCC_ROOT; // any well-formed 32-byte commitment
  const mk = () => {
    const s = H.clone(H.addAgentScenario());
    s.clientAction = "ownerSetAgentRoot";
    s.clientParams = { newAgentRoot: newRoot };
    s.request.action = "ownerSetAgentRoot";
    s.request.review.action = "ownerSetAgentRoot";
    s.request.review.successorAgentRoot = newRoot;
    delete s.request.highLevel;
    return s;
  };
  expectPass(run(mk()), "raw set-root with client-pinned commitment");
  // server substitutes a different root than the client pinned
  const s2 = mk();
  s2.request.review.successorAgentRoot = H.AGENT_ROOT_1;
  expectRefusal(run(s2), ["REVIEW_MISMATCH"], "set-root substitution");
  // and WITHOUT the client's own root parameter the action cannot be verified at all
  const s3 = mk();
  s3.clientParams = {};
  expectRefusal(run(s3), ["VALUE_INVALID"], "set-root without client pin");
});

/* ====== INDEPENDENT FEE/BUDGET/STATE RECOMPUTATION — adversarial matrix ====== */

test("HOSTILE: genesis fee off by ONE SOMPI in either direction — the EXACT recomputation refuses (no claim to hide behind)", () => {
  // genesis reviews carry no fee claim at all: the only thing binding the
  // fee is the browser's own recomputation of the consensus requirement
  const inflated = H.withTamperedTx(H.createScenario(), (tx) => {
    tx.outputs[1].value = (BigInt(tx.outputs[1].value) - 1n).toString(); // change shaved -> fee +1
  });
  expectRefusal(run(inflated), ["FEE_MISMATCH"], "genesis fee +1 sompi");
  const deflated = H.withTamperedTx(H.createScenario(), (tx) => {
    tx.outputs[1].value = (BigInt(tx.outputs[1].value) + 1n).toString(); // change padded -> fee -1
  });
  expectRefusal(run(deflated), ["FEE_MISMATCH"], "genesis fee -1 sompi");
});

test("HOSTILE: transition fee deflated below the recomputed floor — refused even with a FULLY consistent hostile document", () => {
  // the adversary rewrites every claim consistently (fee, reserve figures,
  // successor state id) — the independent fee floor still refuses, because
  // even the UNSIGNED shape requires more fee than the transaction pays
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    const drop = H.COVENANT_FEE_HEADROOM + 1n; // 1 sompi below the recomputed floor
    tx.outputs[1].value = (BigInt(tx.outputs[1].value) + drop).toString();
  });
  const newFee = H.SPEND_FEE_SOMPI - H.COVENANT_FEE_HEADROOM - 1n;
  s.request.review.feeSompi = newFee.toString();
  s.request.review.feeKas = undefined;
  s.request.review.reserveConsumedKas = undefined; // kas strings for odd sompi values are elided by the hostile doc
  s.request.review.reserveAfterKas = undefined;
  const succState = { ...H.SPEND_SUCC_STATE, feeReserve: (100000000n - newFee).toString() };
  const succId = H.stateIdOf(succState);
  s.request.successorStateId = succId;
  s.request.review.successorStateId = succId;
  expectRefusal(run(s), ["FEE_RULE_VIOLATION"], "fee below the recomputed floor");
});

test("HOSTILE: transition fee inflated by 1 sompi over the review claim — the claim binding refuses", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[1].value = (BigInt(tx.outputs[1].value) - 1n).toString(); // drawdown +1 -> fee +1
  });
  expectRefusal(run(s), ["REVIEW_MISMATCH"], "fee +1 vs claim");
});

test("HOSTILE: fee between the structural cap and the old 1-KAS ceiling — the recomputed structural cap refuses (tightening)", () => {
  // 0.8 KAS fee: below the previous 1-KAS default ceiling (would have
  // passed before this wave), above the recomputed 0.5-KAS structural
  // maximum any standard transaction can be REQUIRED to pay
  const feeSompi = 80000000n;
  let fuel;
  const s = H.withTamperedTx(H.topUpScenario(), (tx) => {
    fuel = (5000000000n + feeSompi + H.OWNER_OP_CHANGE).toString();
    tx.inputs[1].utxo.amount = fuel;
  });
  s.clientFuel = { outpoint: { transactionId: H.FUEL_TXID, index: 1 }, amount: fuel };
  s.request.review.feeSompi = feeSompi.toString(); // honest review of the inflated fee
  expectRefusal(run(s), ["EXCESSIVE_FEE"], "structural fee cap");
});

test("HOSTILE: committed compute budget manipulated — every input is pinned to the canonical proven-safe tier", () => {
  // covenant input under-committed (strands the tx on a live node)
  const under = H.withTamperedTx(H.spendScenario(), (tx) => { tx.inputs[0].computeBudget = 31; });
  under.request.review.computeBudget = 31; // even a consistent claim refuses
  expectRefusal(run(under), ["COMPUTE_BUDGET_MISMATCH"], "under-committed covenant budget");
  // covenant input over-committed (inflates the compute mass the fee pays for)
  const over = H.withTamperedTx(H.spendScenario(), (tx) => { tx.inputs[0].computeBudget = 65535; });
  over.request.review.computeBudget = 65535;
  expectRefusal(run(over), ["COMPUTE_BUDGET_MISMATCH"], "over-committed covenant budget");
  // above-threshold tier confusion: a below-threshold spend committing the approval tier
  const confused = H.withTamperedTx(H.spendScenario(), (tx) => { tx.inputs[0].computeBudget = 134; });
  confused.request.review.computeBudget = 134;
  expectRefusal(run(confused), ["COMPUTE_BUDGET_MISMATCH"], "wrong tier for the approval class");
  // ordinary fuel input not at the ordinary tier
  const fuelBudget = H.withTamperedTx(H.topUpScenario(), (tx) => { tx.inputs[1].computeBudget = 100; });
  expectRefusal(run(fuelBudget), ["COMPUTE_BUDGET_MISMATCH"], "fuel input budget");
  // review claiming a different budget than the payload commits
  const lyingReview = H.clone(H.spendScenario());
  lyingReview.request.review.computeBudget = 134;
  expectRefusal(run(lyingReview), ["REVIEW_MISMATCH"], "budget claim vs payload");
});

test("HOSTILE: budget-exceeding spend presented as within budget — the canonical transition module refuses on the covenant's own arithmetic", () => {
  const am = require("../../core/model/agent-merkle-v4.js");
  // a ROOT-CONSISTENT view: the agent has genuinely used 45 of its 50-KAS
  // period budget; a further 10-KAS spend violates newSpent <= periodBudget
  const tiredPolicy = { ...H.AGENT_POLICY_1, periodSpent: "4500000000" };
  const tiredTree = am.buildAgentTreeV4([tiredPolicy]);
  const s = H.clone(H.spendScenario());
  s.vault.agents[0].periodSpentKas = "45";
  s.vault.agents[0].remainingBudgetKas = "5";
  s.vault.live.agentRoot = tiredTree.root;
  s.vault.live.stateId = H.stateIdOf({ ...H.BASE_STATE, agentRoot: tiredTree.root });
  s.request.predecessorStateId = s.vault.live.stateId;
  // the hostile document claims a perfectly consistent successor for the
  // over-budget advance — consistency cannot make the arithmetic legal
  const succRoot = am.applyAgentSpendV4(tiredTree, H.AGENT, { newPeriodStartDaa: "1000000", newPeriodSpent: "5500000000" }).tree.root;
  s.request.review.successorAgentRoot = succRoot;
  const succId = H.stateIdOf({ ...H.SPEND_SUCC_STATE, agentRoot: succRoot });
  s.request.successorStateId = succId;
  s.request.review.successorStateId = succId;
  expectRefusal(run(s), ["TRANSITION_RULE_VIOLATION"], "over-budget spend");
});

test("HOSTILE: spend against a PAUSED vault view refuses through the canonical transition rules", () => {
  const s = H.clone(H.spendScenario());
  s.vault.live.paused = true;
  s.vault.live.stateId = H.stateIdOf({ ...H.BASE_STATE, paused: "1" });
  s.request.predecessorStateId = s.vault.live.stateId;
  expectRefusal(run(s), ["TRANSITION_RULE_VIOLATION"], "spend while paused");
});

test("HOSTILE: pause of an already-paused vault refuses (canonical transition rule)", () => {
  const s = H.clone(H.pauseScenario());
  s.vault.live.paused = true;
  s.vault.live.stateId = H.stateIdOf({ ...H.BASE_STATE, paused: "1" });
  s.request.predecessorStateId = s.vault.live.stateId;
  expectRefusal(run(s), ["TRANSITION_RULE_VIOLATION"], "redundant pause");
});

test("HOSTILE: successor state id tampered by a single hex digit — the recomputed commitment refuses", () => {
  const s = H.clone(H.spendScenario());
  const id = s.request.successorStateId;
  const flipped = (id[0] === "0" ? "1" : "0") + id.slice(1);
  s.request.successorStateId = flipped;
  s.request.review.successorStateId = flipped; // fully consistent hostile claims
  expectRefusal(run(s), ["STATE_ID_MISMATCH"], "successor state-id flip");
});

test("HOSTILE: vault view state id inconsistent with the displayed state — the predecessor commitment recomputation refuses", () => {
  const s = H.clone(H.spendScenario());
  const id = s.vault.live.stateId;
  s.vault.live.stateId = (id[0] === "0" ? "1" : "0") + id.slice(1);
  s.request.predecessorStateId = s.vault.live.stateId; // request agrees with the tampered view
  expectRefusal(run(s), ["STATE_ID_MISMATCH"], "predecessor state-id flip");
});

test("HOSTILE: genesis under an unknown covenant version never routes to the v4 recomputation rules", () => {
  for (const version of ["policyvault-0.3", "policyvault-9.9", "totally-unknown"]) {
    const s = H.clone(H.createScenario());
    s.request.contractVersion = version;
    expectRefusal(run(s), ["UNSUPPORTED_COVENANT_VERSION"], `genesis version ${version}`);
  }
});

test("FAIL-CLOSED: a missing successorStateId cannot be verified and refuses", () => {
  const s = H.clone(H.spendScenario());
  delete s.request.successorStateId;
  expectRefusal(run(s), ["SERVER_CLAIM_INVALID"], "missing successorStateId");
});

test("HOSTILE: outputs reordered against the builder's pinned shape — refused (fee/shape games via ordering are impossible)", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs = [tx.outputs[1], tx.outputs[0]]; // [successor, payment] — the builder emits [payment, successor]
  });
  expectRefusal(run(s), ["ACTION_TX_SHAPE_MISMATCH"], "reordered outputs");
});

test("FAIL-CLOSED: an ownerSetApprovers targeting the zero-approver configuration refuses (genesis-only tier)", () => {
  const s = H.clone(H.setApproversScenario());
  s.clientParams = { newApprovers: { approvers: [], approvalM: "0" } };
  // the canonical rule refuses before any successor claim is even reached
  const out = run(s);
  assert.equal(out.ok, false);
  assert.ok(
    out.refusalCodes.includes("TRANSITION_RULE_VIOLATION") || out.refusalCodes.includes("STATE_RECOMPUTE_FAILED"),
    `zero-approver transition refused: ${JSON.stringify(out.refusalCodes)}`
  );
});

/* =================== fail-closed environment cases =================== */

test("FAIL-CLOSED: missing core bundle refuses every verification", () => {
  const noCore = createVerifyIntent(null);
  const s = H.spendScenario();
  const out = noCore.verifyBeforeSigning({ request: s.request, vault: s.vault, clientAction: s.clientAction, clientParams: s.clientParams, sessionNetwork: s.sessionNetwork, sessionXOnly: s.sessionXOnly });
  expectRefusal(out, ["CORE_UNAVAILABLE"], "core unavailable");
});

test("FAIL-CLOSED: a STALE core bundle without the Merkle modules refuses every verification (recompute is mandatory)", () => {
  const staleCore = { intent: core.intent, intentExplain: core.intentExplain }; // pre-F1 bundle shape
  const noMerkle = createVerifyIntent(staleCore);
  const s = H.spendScenario();
  const out = noMerkle.verifyBeforeSigning({ request: s.request, vault: s.vault, clientAction: s.clientAction, clientParams: s.clientParams, sessionNetwork: s.sessionNetwork, sessionXOnly: s.sessionXOnly });
  expectRefusal(out, ["CORE_UNAVAILABLE"], "stale core without merkle");
});

test("FAIL-CLOSED: a STALE core bundle without the fee/state modules refuses every verification (F1-era bundle shape)", () => {
  const f1EraCore = {
    intent: core.intent,
    intentExplain: core.intentExplain,
    recipientMerkle: core.recipientMerkle,
    agentMerkle: core.agentMerkle
    // no feeMass / frozenTx / computeBudgetV4 / vaultStateV4 / vaultTransitionsV4
  };
  const noFee = createVerifyIntent(f1EraCore);
  const s = H.spendScenario();
  const out = noFee.verifyBeforeSigning({ request: s.request, vault: s.vault, clientAction: s.clientAction, clientParams: s.clientParams, sessionNetwork: s.sessionNetwork, sessionXOnly: s.sessionXOnly });
  expectRefusal(out, ["CORE_UNAVAILABLE"], "stale core without fee/state modules");
});

test("FAIL-CLOSED: missing vault knowledge refuses (no guessing)", () => {
  const s = H.spendScenario();
  const out = run({ ...s, vault: undefined });
  expectRefusal(out, ["VAULT_KNOWLEDGE_MISSING"], "no vault knowledge");
});

test("FAIL-CLOSED: unresolved wallet identity refuses", () => {
  const s = H.spendScenario();
  const out = run({ ...s, sessionXOnly: null });
  expectRefusal(out, ["IDENTITY_UNRESOLVED"], "identity unresolved");
});

test("FAIL-CLOSED: unknown client action refuses", () => {
  const s = H.spendScenario();
  const out = run({ ...s, clientAction: "ownerGrantEverything", clientParams: {} });
  expectRefusal(out, ["UNKNOWN_ACTION"], "unknown action");
});

test("FAIL-CLOSED: an internal error is never a pass", () => {
  const s = H.clone(H.spendScenario());
  // poison the vault view so a deep derivation step throws a plain error
  Object.defineProperty(s.vault.live, "protectedValueKas", { get() { throw new Error("boom"); } });
  const out = run(s);
  assert.equal(out.ok, false);
  assert.equal(out.lines[0], "!! DO NOT SIGN !!");
});

test("Safe JSON decoder: exact decode of the wire form (spk version split, covenant classification by client knowledge)", () => {
  const s = H.spendScenario();
  const res = vi.decodeUnsignedSafeTransaction(s.request.transaction.unsignedSafeJson, {
    outpoint: { transactionId: H.PREV_TXID, index: 0 },
    covenantId: H.COVENANT_ID
  });
  assert.equal(res.ok, true);
  const tx = res.transaction;
  assert.equal(tx.txId, H.HEX("0a"));
  assert.equal(tx.version, 1);
  assert.equal(tx.inputs[0].utxo.covenantId, H.COVENANT_ID, "covenant input classified from CLIENT knowledge");
  assert.equal(tx.inputs[0].utxo.scriptPublicKey.version, 0, "u16 script version split from the wire form");
  assert.equal(tx.inputs[0].utxo.scriptPublicKey.scriptHex, H.COV_SPK);
  assert.equal(tx.outputs[0].scriptPublicKey.scriptHex, H.p2pk(H.RECIPIENT));
  assert.deepEqual(tx.outputs[1].covenant, { authorizingInput: 0, covenantId: H.COVENANT_ID });
  // and with NO matching client outpoint the input stays external
  const res2 = vi.decodeUnsignedSafeTransaction(s.request.transaction.unsignedSafeJson, {
    outpoint: { transactionId: H.HEX("f9"), index: 0 },
    covenantId: H.COVENANT_ID
  });
  assert.equal(res2.transaction.inputs[0].utxo.covenantId, null);
});

test("Safe JSON decoder: a non-zero script version is preserved (and later refused by the manifest layer)", () => {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[0].scriptPublicKey = "0001" + H.p2pk(H.RECIPIENT);
  });
  const res = vi.decodeUnsignedSafeTransaction(s.request.transaction.unsignedSafeJson, null);
  assert.equal(res.ok, true);
  assert.equal(res.transaction.outputs[0].scriptPublicKey.version, 1);
  // end to end: the payment-script match fails closed (payment not found)
  expectRefusal(run(s), ["HIDDEN_RECIPIENT"], "script-version game");
});

/* ============ GENESIS agent-registry recomputation (residuals wave) ============
 * The genesis initialState.agentRoot is NO LONGER a cross-checked claim:
 * the browser rebuilds it from the request's disclosed initialRegistry
 * leaf tuples (per-tuple allowlist roots rebuilt from disclosed recipient
 * keys too) and holds initialState.agentRoot to equality. */

const { buildAgentTreeV4: gTree } = require("../../core/model/agent-merkle-v4.js");
const { buildRecipientTree: gRecipTree } = require("../../core/model/recipient-merkle-v3.js");

test("GENESIS PASS: the registry root is recomputed (not claimed) and the claim warning no longer names it", () => {
  const out = run(H.createScenario());
  expectPass(out, "genesis recompute");
  assert.ok(
    out.notes.some((n) => n.includes("Independently recomputed") && n.includes("genesis agent-registry root")),
    "genesis registry-root recomputation note present: " + JSON.stringify(out.notes)
  );
  const claimWarning = out.lines.join("\n");
  assert.ok(
    !claimWarning.includes("initialState.agentRoot (agent-registry Merkle commitment"),
    "the old agentRoot claim disclosure must be gone from the rendered warnings"
  );
});

test("GENESIS HOSTILE: missing / empty / malformed initialRegistry refuses (SERVER_CLAIM_INVALID — required for new-schema documents)", () => {
  const missing = H.clone(H.createScenario());
  delete missing.request.initialRegistry;
  expectRefusal(run(missing), ["SERVER_CLAIM_INVALID"], "initialRegistry missing");

  const empty = H.clone(H.createScenario());
  empty.request.initialRegistry = [];
  expectRefusal(run(empty), ["SERVER_CLAIM_INVALID"], "initialRegistry empty");

  const malformed = H.clone(H.createScenario());
  malformed.request.initialRegistry[0].maxPerSpend = "12.5";
  expectRefusal(run(malformed), ["SERVER_CLAIM_INVALID"], "non-canonical tuple value");

  const noRecips = H.clone(H.createScenario());
  noRecips.request.initialRegistry[0].recipients = [];
  expectRefusal(run(noRecips), ["SERVER_CLAIM_INVALID"], "tuple without recipient keys");
});

test("GENESIS HOSTILE: a tampered tuple no longer hashing to the committed root refuses (AGENT_REGISTRY_ROOT_MISMATCH)", () => {
  const s = H.clone(H.createScenario());
  s.request.initialRegistry[0].maxPerSpend = "9999999999"; // root left as served
  expectRefusal(run(s), ["AGENT_REGISTRY_ROOT_MISMATCH"], "tampered tuple");
});

test("GENESIS HOSTILE: an EXTRA (hidden) agent tuple refuses (AGENT_REGISTRY_ROOT_MISMATCH)", () => {
  const s = H.clone(H.createScenario());
  const extraRecipRoot = gRecipTree([H.ATTACKER]).root;
  s.request.initialRegistry.push({
    agentPk: H.ATTACKER,
    maxPerSpend: "2000000000",
    periodBudget: "5000000000",
    periodLengthDaa: "86400",
    periodStartDaa: "1000000",
    periodSpent: "0",
    approvalThreshold: "1500000000",
    agentMaxFeePerTx: "10000000",
    agentRecipientRoot: extraRecipRoot,
    recipients: [H.ATTACKER]
  });
  expectRefusal(run(s), ["AGENT_REGISTRY_ROOT_MISMATCH"], "extra tuple vs committed root");
});

test("GENESIS HOSTILE: duplicate agentPk tuples refuse (MERKLE_RECOMPUTE_FAILED — duplicate budget lanes)", () => {
  const s = H.clone(H.createScenario());
  s.request.initialRegistry.push(H.clone(s.request.initialRegistry[0]));
  expectRefusal(run(s), ["MERKLE_RECOMPUTE_FAILED"], "duplicate agentPk");
});

test("GENESIS HOSTILE: a tuple whose disclosed recipients do not hash to its own agentRecipientRoot refuses (ALLOWLIST_ROOT_MISMATCH)", () => {
  const s = H.clone(H.createScenario());
  s.request.initialRegistry[0].recipients = [H.ATTACKER]; // root left as served
  expectRefusal(run(s), ["ALLOWLIST_ROOT_MISMATCH"], "inconsistent tuple allowlist");
});

test("GENESIS HOSTILE: FULLY CONSISTENT per-spend-cap substitution (tuple + root all rewritten) refuses on the typed-value pin (REVIEW_MISMATCH)", () => {
  // The strongest hostile server: it discloses an internally consistent
  // registry (tuple, allowlist root, tree root all agree) that simply is
  // NOT the policy the user typed. Only the client-held form context can
  // catch this — and must.
  const s = H.clone(H.createScenario());
  const tampered = { ...s.request.initialRegistry[0] };
  tampered.maxPerSpend = "50000000000"; // 500 KAS — the whole vault per spend
  const { recipients, ...leaf } = tampered;
  s.request.initialRegistry = [tampered];
  s.request.initialState.agentRoot = gTree([leaf]).root;
  const out = run(s);
  expectRefusal(out, ["REVIEW_MISMATCH"], "consistent cap substitution");
  assert.ok(
    out.lines.some((l) => l.includes("per-spend cap differs from the one you entered")),
    "must be caught by the TYPED-VALUE pin specifically: " + out.lines.join("\n")
  );
});

test("GENESIS HOSTILE: FULLY CONSISTENT recipient-allowlist substitution refuses on the client's resolved recipient set (REVIEW_MISMATCH)", () => {
  const s = H.clone(H.createScenario());
  const substitutedRecipRoot = gRecipTree([H.ATTACKER]).root;
  const tampered = { ...s.request.initialRegistry[0], recipients: [H.ATTACKER], agentRecipientRoot: substitutedRecipRoot };
  const { recipients, ...leaf } = tampered;
  s.request.initialRegistry = [tampered];
  s.request.initialState.agentRoot = gTree([leaf]).root;
  if (s.request.review && Array.isArray(s.request.review.agents)) s.request.review.agents[0].recipients = [H.ATTACKER];
  const out = run(s);
  expectRefusal(out, ["REVIEW_MISMATCH"], "consistent allowlist substitution");
  assert.ok(
    out.lines.some((l) => l.includes("recipient allowlist differs from the recipient addresses you entered")),
    "must be caught by the CLIENT-RESOLVED recipient-set pin specifically: " + out.lines.join("\n")
  );
});

test("GENESIS PASS-pair: reordered tuples are canonicalized by the tree builder — identical outcome, identical manifest hash", () => {
  // Two-agent genesis WITHOUT the single-agent form context (the API's
  // canonical multi-agent schema): ordering of the disclosed list cannot
  // change the committed SET, so both orders verify identically.
  const secondRecipRoot = gRecipTree([H.K4]).root;
  const second = {
    agentPk: H.ATTACKER, // any distinct key
    maxPerSpend: "1000000000",
    periodBudget: "2000000000",
    periodLengthDaa: "86400",
    periodStartDaa: "1000000",
    periodSpent: "0",
    approvalThreshold: "1500000000",
    agentMaxFeePerTx: "10000000",
    agentRecipientRoot: secondRecipRoot,
    recipients: [H.K4]
  };
  const make = (order) => {
    const s = H.clone(H.createScenario());
    const first = s.request.initialRegistry[0];
    const both = order === "ab" ? [first, second] : [second, first];
    s.request.initialRegistry = both;
    const leaves = both.map(({ recipients, ...leaf }) => leaf);
    s.request.initialState.agentRoot = gTree(leaves).root;
    // two agents: drop the single-agent form pins (identity, typed policy,
    // recipient set) — the canonical multi-agent schema has no form context
    delete s.createContext.agentXOnly;
    delete s.createContext.agentMaxPerSpendKas;
    delete s.createContext.agentBudgetKas;
    delete s.createContext.agentApprovalThresholdKas;
    delete s.createContext.agentMaxFeePerTxKas;
    delete s.createContext.agentRecipientXOnlys;
    return s;
  };
  const a = run(make("ab"));
  const b = run(make("ba"));
  expectPass(a, "order ab");
  expectPass(b, "order ba");
  assert.equal(a.manifestHash, b.manifestHash, "reordering the disclosed tuples must not change the verified manifest");
});
