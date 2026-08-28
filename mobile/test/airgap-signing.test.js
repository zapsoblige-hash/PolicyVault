"use strict";

/*
 * PolicyVault mobile — QR/AIR-GAP SIGNING FLOW: framing codec + document
 * binding.
 *
 * Claim label: UNIT-TESTED. The DOCUMENTS and the FRAMING are exercised
 * here against the app's own packaged modules. What is NOT exercised, and
 * is not claimed anywhere: optical capture (no QR encoder or decoder
 * ships in this build), the share sheet, and an end-to-end exchange with
 * a real `core/signer/adapters/cli` process. See
 * docs/postlaunch/mobile-v1-scaffold.md.
 *
 * The security property under test is the one the architecture calls the
 * "independent second refusal" (§6.3 rule 3): a signature request cannot
 * be built, and a scanned signature cannot be accepted, unless a PASSING
 * on-device verification exists that is bound to the exact transaction
 * bytes involved. A defect in the interface alone must not be able to
 * produce a signature.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const S = require("./sandbox.js");
const H = require("../../web/test/helpers.js");

function loaded() {
  const g = S.loadAppPayload();
  return {
    g,
    QR: g.PolicyVaultMobileQrFrames,
    AIRGAP: g.PolicyVaultMobileAirgap,
    service: S.createVerificationService(g),
    sha256Hex: S.sandboxSha256Hex(g)
  };
}

function passingOutcome(env, scenario) {
  const args = S.intoSandbox(env.g, {
    request: scenario.request,
    vault: scenario.vault,
    clientAction: scenario.clientAction,
    clientParams: scenario.clientParams,
    sessionNetwork: scenario.sessionNetwork,
    sessionXOnly: scenario.sessionXOnly
  });
  const outcome = env.service.verify(args);
  assert.equal(outcome.ok, true, "fixture must verify before the air-gap tests can mean anything");
  return outcome;
}

/* ==================================================================== */
/* QR framing codec                                                      */
/* ==================================================================== */

test("QR FRAMING: a document round-trips through frames scanned in shuffled order with duplicates", () => {
  const { QR, sha256Hex } = loaded();

  /* Deliberately awkward content: astral-plane characters, a lone-looking
   * surrogate pair, quotes, and newlines — the framing must be lossless
   * for anything JSON.stringify can produce. */
  const doc = JSON.stringify({ a: "𝄞 astral", b: "quote\" and \\ backslash", c: "line\nbreak", d: "ünïcödé", e: "0".repeat(4000) });

  const framed = QR.encodeFrames(doc, { sha256Hex, chunkChars: 200 });
  assert.equal(framed.ok, true, framed.detail);
  assert.ok(framed.count > 20, "the fixture should need many frames");
  assert.equal(framed.docSha256, sha256Hex(doc));

  const shuffled = framed.frames.slice().reverse();
  const withDupes = shuffled.concat(shuffled.slice(0, 5));

  const re = QR.createReassembler({ sha256Hex });
  for (const f of withDupes) {
    const r = re.accept(f);
    assert.equal(r.ok, true, `${r.code}: ${r.detail}`);
  }
  const done = re.finish();
  assert.equal(done.ok, true, `${done.code}: ${done.detail}`);
  assert.equal(done.text, doc, "the reassembled document must be byte-identical to the original");
});

test("QR FRAMING: an incomplete scan is never a document", () => {
  const { QR, sha256Hex } = loaded();
  const framed = QR.encodeFrames("x".repeat(3000), { sha256Hex, chunkChars: 100 });
  assert.equal(framed.ok, true);

  const re = QR.createReassembler({ sha256Hex });
  for (const f of framed.frames.slice(0, framed.count - 1)) assert.equal(re.accept(f).ok, true);

  const done = re.finish();
  assert.equal(done.ok, false);
  assert.equal(done.code, "QR_INCOMPLETE");
  assert.equal(re.status().complete, false);
});

test("QR FRAMING: a tampered frame body is caught by the document digest", () => {
  const { QR, sha256Hex } = loaded();
  const doc = JSON.stringify({ payload: "y".repeat(1200) });
  const framed = QR.encodeFrames(doc, { sha256Hex, chunkChars: 300 });
  assert.equal(framed.ok, true);

  /* Swap one character of one frame's payload while keeping the claimed
   * digest — the reassembly must refuse rather than hand back a document
   * that "looks fine". */
  const parts = framed.frames[1].split("|");
  parts[4] = (parts[4][0] === "A" ? "B" : "A") + parts[4].slice(1);
  const tampered = framed.frames.slice();
  tampered[1] = parts.join("|");

  const re = QR.createReassembler({ sha256Hex });
  for (const f of tampered) assert.equal(re.accept(f).ok, true);
  const done = re.finish();
  assert.equal(done.ok, false);
  assert.equal(done.code, "QR_DIGEST_MISMATCH");
});

test("QR FRAMING: frames from two different documents cannot be mixed into one scan", () => {
  const { QR, sha256Hex } = loaded();
  const a = QR.encodeFrames(JSON.stringify({ doc: "A".repeat(900) }), { sha256Hex, chunkChars: 300 });
  const b = QR.encodeFrames(JSON.stringify({ doc: "B".repeat(900) }), { sha256Hex, chunkChars: 300 });

  const re = QR.createReassembler({ sha256Hex });
  assert.equal(re.accept(a.frames[0]).ok, true);
  const mixed = re.accept(b.frames[0]);
  assert.equal(mixed.ok, false);
  assert.equal(mixed.code, "QR_FRAME_DOCUMENT_MISMATCH");
});

test("QR FRAMING: an unknown frame version fails closed", () => {
  const { QR } = loaded();
  const r = QR.parseFrame("PVQR2|" + "0".repeat(64) + "|1|1|AAAA");
  assert.equal(r.ok, false);
  assert.equal(r.code, "QR_FRAME_VERSION_UNSUPPORTED");
});

test("QR FRAMING: an oversized document is refused with the file-transport alternative, not silently truncated", () => {
  const { QR, sha256Hex } = loaded();
  const r = QR.encodeFrames("z".repeat(400000), { sha256Hex, chunkChars: 100 });
  assert.equal(r.ok, false);
  assert.equal(r.code, "QR_TOO_LARGE");
  assert.match(r.detail, /file transport/);
});

/* ==================================================================== */
/* Signing-request document                                              */
/* ==================================================================== */

test("AIRGAP: a signing request is built only from a PASS, in the CLI signer's own closed schema", () => {
  const env = loaded();
  const scenario = H.spendScenario();
  const outcome = passingOutcome(env, scenario);

  const built = env.AIRGAP.buildSigningRequestDocument({
    request: S.intoSandbox(env.g, scenario.request),
    verification: outcome,
    network: scenario.sessionNetwork,
    expectedSignerAddress: H.AGENT_ADDR
  });
  assert.equal(built.ok, true, `${built.code}: ${built.detail}`);

  const doc = S.outOfSandbox(built.document);
  /* The CLI signer's schema is CLOSED at exactly these six keys — an
   * extra one would be refused by the signer itself. */
  assert.deepEqual(Object.keys(doc), ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
  assert.equal(doc.format, "policyvault-cli-signing-request/1");
  assert.equal(doc.kind, "sign-transaction");
  assert.equal(doc.network, scenario.sessionNetwork);
  assert.equal(doc.expectedSignerAddress, H.AGENT_ADDR);
  assert.equal(doc.unsignedSafeJson, scenario.request.transaction.unsignedSafeJson, "the document must carry the exact verified bytes");

  /* signInputs are re-asserted canonical, never invented or trimmed. */
  assert.ok(doc.signInputs.length > 0);
  for (const si of doc.signInputs) {
    assert.deepEqual(Object.keys(si), ["index", "sighashType"]);
    assert.equal(si.sighashType, 1);
    assert.ok(Number.isInteger(si.index) && si.index >= 0);
  }
});

test("AIRGAP: the second refusal blocks a signing request with no PASS, a refusal, or a mismatched binding", () => {
  const env = loaded();
  const scenario = H.spendScenario();
  const outcome = passingOutcome(env, scenario);
  const request = S.intoSandbox(env.g, scenario.request);

  const cases = [
    { name: "no outcome at all", verification: undefined, code: "VERIFICATION_REQUIRED" },
    { name: "a refused outcome", verification: S.intoSandbox(env.g, { ok: false, verdict: "REFUSED", refusalCodes: ["HIDDEN_RECIPIENT"], unsignedSafeJson: null }), code: "VERIFICATION_REFUSED" },
    {
      name: "a PASS bound to other bytes",
      verification: S.intoSandbox(env.g, {
        ok: true,
        verdict: "VERIFIED_EXACT",
        refusalCodes: [],
        unsignedSafeJson: "{\"id\":\"" + "9".repeat(64) + "\"}"
      }),
      code: "VERIFICATION_TX_BINDING_MISMATCH"
    }
  ];

  for (const c of cases) {
    const r = env.AIRGAP.buildSigningRequestDocument({
      request,
      verification: c.verification,
      network: scenario.sessionNetwork,
      expectedSignerAddress: H.AGENT_ADDR
    });
    assert.equal(r.ok, false, `${c.name}: expected a refusal`);
    assert.equal(r.code, c.code, `${c.name}: expected ${c.code}, got ${r.code}`);
  }

  /* And the control: with the real PASS it builds. */
  const good = env.AIRGAP.buildSigningRequestDocument({
    request,
    verification: outcome,
    network: scenario.sessionNetwork,
    expectedSignerAddress: H.AGENT_ADDR
  });
  assert.equal(good.ok, true);
});

test("AIRGAP: a request whose signInputs are missing or non-canonical is refused, never repaired", () => {
  const env = loaded();
  const scenario = H.spendScenario();
  const outcome = passingOutcome(env, scenario);

  const variants = [
    { name: "absent", signInputs: undefined },
    { name: "empty", signInputs: [] },
    { name: "missing sighashType", signInputs: [{ index: 0 }] },
    { name: "wrong sighashType", signInputs: [{ index: 0, sighashType: 2 }] },
    { name: "negative index", signInputs: [{ index: -1, sighashType: 1 }] }
  ];

  for (const v of variants) {
    const req = JSON.parse(JSON.stringify(scenario.request));
    if (v.signInputs === undefined) delete req.transaction.signInputs;
    else req.transaction.signInputs = v.signInputs;

    const r = env.AIRGAP.buildSigningRequestDocument({
      request: S.intoSandbox(env.g, req),
      verification: outcome,
      network: scenario.sessionNetwork,
      expectedSignerAddress: H.AGENT_ADDR
    });
    assert.equal(r.ok, false, `${v.name}: expected a refusal`);
    assert.equal(r.code, "AIRGAP_SIGNINPUTS_INVALID", `${v.name}: got ${r.code}`);
  }
});

/* ==================================================================== */
/* Signed-response document                                              */
/* ==================================================================== */

function signedResponse(overrides, unsignedSafeJson) {
  const tx = JSON.parse(unsignedSafeJson);
  return JSON.stringify(Object.assign({
    format: "policyvault-cli-signer-signed-transaction/1",
    requestId: "sr_" + "0".repeat(16),
    kind: "sign-transaction",
    network: "testnet-10",
    address: H.AGENT_ADDR,
    /* A real signer returns the same transaction with signature scripts
     * filled in; the id is unchanged, because Kaspa txids exclude
     * signature scripts. */
    signedSafeJson: JSON.stringify(Object.assign({}, tx, {
      inputs: tx.inputs.map((i) => Object.assign({}, i, { signatureScript: "41" + "ab".repeat(64) + "01" }))
    }))
  }, overrides || {}));
}

test("AIRGAP: a well-formed signed response is accepted and bound to the verified transaction id", () => {
  const env = loaded();
  const scenario = H.spendScenario();
  const outcome = passingOutcome(env, scenario);
  const payload = scenario.request.transaction.unsignedSafeJson;

  const parsed = env.AIRGAP.parseSignedResponseDocument(signedResponse(null, payload), S.intoSandbox(env.g, {
    expectedNetwork: "testnet-10",
    expectedSignerAddress: H.AGENT_ADDR,
    verification: S.outOfSandbox(outcome)
  }));

  assert.equal(parsed.ok, true, `${parsed.code}: ${parsed.detail}`);
  assert.equal(parsed.txId, JSON.parse(payload).id);
  assert.equal(parsed.address, H.AGENT_ADDR);
  assert.ok(parsed.signedSafeJson.includes("signatureScript"));
});

test("AIRGAP: a hostile or mismatched signed response is refused with a specific code", () => {
  const env = loaded();
  const scenario = H.spendScenario();
  const outcome = S.outOfSandbox(passingOutcome(env, scenario));
  const payload = scenario.request.transaction.unsignedSafeJson;

  const otherTx = JSON.stringify(Object.assign(JSON.parse(payload), { id: "b".repeat(64) }));

  const cases = [
    { name: "unknown format", doc: signedResponse({ format: "policyvault-cli-signer-signed-transaction/2" }, payload), code: "AIRGAP_RESPONSE_FORMAT_UNSUPPORTED" },
    { name: "wrong kind", doc: signedResponse({ kind: "sign-message" }, payload), code: "AIRGAP_RESPONSE_KIND_MISMATCH" },
    { name: "wrong network", doc: signedResponse({ network: "mainnet" }, payload), code: "AIRGAP_NETWORK_MISMATCH" },
    { name: "different signer", doc: signedResponse({ address: H.OWNER_ADDR }, payload), code: "AIRGAP_SIGNER_MISMATCH" },
    { name: "a signature for a different transaction", doc: signedResponse({ signedSafeJson: otherTx }, payload), code: "AIRGAP_TXID_MISMATCH" },
    { name: "an unknown extra key", doc: signedResponse({ extra: "surprise" }, payload), code: "AIRGAP_RESPONSE_INVALID" },
    { name: "not JSON", doc: "PVQR1 not a document", code: "AIRGAP_RESPONSE_INVALID" }
  ];

  for (const c of cases) {
    const r = env.AIRGAP.parseSignedResponseDocument(c.doc, S.intoSandbox(env.g, {
      expectedNetwork: "testnet-10",
      expectedSignerAddress: H.AGENT_ADDR,
      verification: outcome
    }));
    assert.equal(r.ok, false, `${c.name}: expected a refusal`);
    assert.equal(r.code, c.code, `${c.name}: expected ${c.code}, got ${r.code} (${r.detail})`);
  }
});

test("AIRGAP: a signed response is refused outright when no passing verification is available", () => {
  const env = loaded();
  const payload = H.spendScenario().request.transaction.unsignedSafeJson;

  const r = env.AIRGAP.parseSignedResponseDocument(signedResponse(null, payload), S.intoSandbox(env.g, {
    expectedNetwork: "testnet-10",
    expectedSignerAddress: H.AGENT_ADDR
  }));
  assert.equal(r.ok, false);
  assert.equal(r.code, "VERIFICATION_REQUIRED");
});

test("AIRGAP: the full document survives the QR round trip unchanged", () => {
  const env = loaded();
  const scenario = H.spendScenario();
  const outcome = passingOutcome(env, scenario);

  const built = env.AIRGAP.buildSigningRequestDocument({
    request: S.intoSandbox(env.g, scenario.request),
    verification: outcome,
    network: scenario.sessionNetwork,
    expectedSignerAddress: H.AGENT_ADDR
  });
  assert.equal(built.ok, true);

  const framed = env.QR.encodeFrames(built.documentText, { sha256Hex: env.sha256Hex });
  assert.equal(framed.ok, true, framed.detail);

  const re = env.QR.createReassembler({ sha256Hex: env.sha256Hex });
  for (const f of framed.frames) assert.equal(re.accept(f).ok, true);
  const done = re.finish();
  assert.equal(done.ok, true);
  assert.equal(done.text, built.documentText, "the signing request must arrive at the signer byte-identical");

  /* And it still parses under the CLI signer's own closed schema rules. */
  const reparsed = JSON.parse(done.text);
  assert.deepEqual(Object.keys(reparsed), ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
});
