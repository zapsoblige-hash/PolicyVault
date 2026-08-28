"use strict";

/*
 * HOSTILE-AI SURFACE 26 — PROBE GROUP S: CAN AN AGENT PATH REACH A
 * SIGNATURE WITHOUT INDEPENDENT VERIFICATION?
 * (layer: UNIT / ADVERSARIAL; docs/postlaunch/hostile-ai-review.md §S.)
 *
 * The completion standard's client-side claim is precise: "intent
 * manifest wired into real transaction flows + browser signing UX (client
 * independently detects server/frontend manipulation before signing)",
 * and "KasWare refactored behind the Universal Signer Interface + at
 * least one materially different reference signer (offline/CLI)".
 *
 * The hostile-AI question is therefore NOT "can the MCP surface sign?"
 * (it cannot — proved in mcp-agent-boundary.test.js M2) but: taking the
 * WHOLE agent-reachable path — Agent API build, reference signer,
 * Agent API submit — is there a point where nothing independently
 * verifies what is about to be signed?
 *
 * RESULT: FINDING H-2. The offline reference signer's request document
 * `policyvault-cli-signing-request/1` is CLOSED at six keys, none of
 * which can carry an intent manifest or a verification outcome. The
 * signer therefore CANNOT verify what it signs — not "does not", but
 * structurally cannot — and it prints nothing about what the transaction
 * does. The verification gate lives entirely in the PRODUCERS
 * (web/verify-intent.js, mobile/www/js/portable/airgap.js). A producer
 * that is not one of those two — e.g. an autonomous agent driving the
 * REST/Agent API and then invoking the signer — reaches a real signature
 * with no client-side verification anywhere in the path.
 *
 * These probes drive the REAL CLI (child processes, real kaspa-wasm
 * BIP-340 signing) with TEST keys only.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { SIGNING_REQUEST_FORMAT } = require("../../core/signer/adapters/cli/cli");
const { loadKaspaOrExplain, makeTempDir, buildUnsignedTxSafeJson, runCli } = require("../../core/signer/adapters/cli/testkit");
const AIRGAP = require("../../mobile/www/js/portable/airgap.js");

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-hostile-ai-signer-");
const keyfile = path.join(dir, "probe-key.json");

let identity = null;

function cli(args) {
  return runCli(args, {});
}

function writeRequest(doc, name) {
  const p = path.join(dir, `${name}.json`);
  fs.writeFileSync(p, JSON.stringify(doc));
  return p;
}

test("S0 setup: generate a throwaway testnet keyfile through the real CLI", () => {
  const result = cli(["generate", "--out", keyfile, "--network", "testnet-10", "--label", "hostile-ai probe"]);
  assert.equal(result.status, 0, result.stderr);
  identity = JSON.parse(result.stdout);
  assert.equal(identity.network, "testnet-10");
  assert.match(identity.address, /^kaspatest:/);
});

/* ------------------------------------------------------------------ */
/* S1 — the structural gap                                             */
/* ------------------------------------------------------------------ */

const { agentSpendFixture } = require("../../core/intent/testutil/fixtures");

test("S1a H-2 FIXED: the additive /2 request format carries an intent `manifest` slot (the /1 format stays verification-blind by design)", () => {
  // /1 is intentionally unchanged (no manifest slot): back-compat, and
  // documented as verification-blind.
  assert.deepEqual(AIRGAP.SIGNING_REQUEST_KEYS, ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
  // /2 is the fix: it adds exactly the `manifest` slot the signer needs to
  // verify what it signs.
  assert.equal(AIRGAP.SIGNING_REQUEST_FORMAT_V2, "policyvault-cli-signing-request/2");
  assert.deepEqual(AIRGAP.SIGNING_REQUEST_KEYS_V2, ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs", "manifest"]);
  assert.ok(AIRGAP.SIGNING_REQUEST_KEYS_V2.includes("manifest"), "H-2 FIXED: /2 carries the intent manifest");
});

test("S1b H-2 FIXED: the CLI signer now imports the portable verifier + explainer for the /2 path (and still nothing from server/ or sdk/)", () => {
  const cliSrc = fs.readFileSync(path.join(__dirname, "..", "..", "core/signer/adapters/cli/cli.js"), "utf8");
  // The signer can now verify + explain what it signs.
  for (const symbol of ["verifyIntentManifest", "intentExplain", "../../../intent", "../../../explain"]) {
    assert.ok(cliSrc.includes(symbol), `H-2 FIXED: the /2 signer references ${symbol}`);
  }
  // The OFFLINE guarantee is preserved: still no server/ or sdk/ imports.
  assert.ok(!/require\((['"])(\.\.\/)*(server|sdk)\//.test(cliSrc), "the signer imports nothing from server/ or sdk/");
});

test("S1c H-2 FIXED: /1 still refuses an extra manifest key (closed schema), and /2 ACCEPTS it (the additive verifying format)", () => {
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);
  // /1 + manifest is still refused — the closed schema is unchanged.
  const v1WithManifest = writeRequest(
    {
      format: SIGNING_REQUEST_FORMAT,
      kind: "sign-transaction",
      network: "testnet-10",
      expectedSignerAddress: identity.address,
      unsignedSafeJson,
      signInputs: [{ index: 0, sighashType: 1 }],
      manifest: { manifestVersion: "policyvault-intent-manifest/1" }
    },
    "v1-with-manifest"
  );
  const r1 = cli(["sign-tx", "--key", keyfile, "--request-file", v1WithManifest]);
  assert.notEqual(r1.status, 0, "/1 still refuses the extra key");
  assert.match(r1.stderr, /unknown key/, "the /1 refusal names the closed schema");

  // /2 ACCEPTS the manifest key — it gets PAST schema parsing (and then
  // fails closed on the junk manifest at the verification step, not the
  // schema step: a different, deeper refusal).
  const v2WithManifest = writeRequest(
    {
      format: AIRGAP.SIGNING_REQUEST_FORMAT_V2,
      kind: "sign-transaction",
      network: "testnet-10",
      expectedSignerAddress: identity.address,
      unsignedSafeJson,
      signInputs: [{ index: 0, sighashType: 1 }],
      manifest: { manifestVersion: "policyvault-intent-manifest/1" }
    },
    "v2-with-manifest"
  );
  const r2 = cli(["sign-tx", "--key", keyfile, "--request-file", v2WithManifest]);
  assert.notEqual(r2.status, 0, "/2 still refuses a junk manifest — but at verification, not schema");
  assert.ok(!/unknown key/.test(r2.stderr), "H-2 FIXED: /2 does not reject the manifest key itself");
  assert.match(r2.stderr, /DO NOT SIGN/, "H-2 FIXED: /2 renders a DO-NOT-SIGN refusal for an unverifiable manifest");
});

test("S1d H-2 FIXED: /2 REFUSES to sign a transaction the manifest does not describe (txId binding), rendering DO-NOT-SIGN", () => {
  // A genuinely VERIFIED manifest, but paired with a DIFFERENT transaction
  // than it describes — the exact substitution the signer must catch.
  const manifest = agentSpendFixture().manifest;
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);
  // The synthetic tx's embedded id is NOT the manifest's txId.
  const mismatched = writeRequest(
    {
      format: AIRGAP.SIGNING_REQUEST_FORMAT_V2,
      kind: "sign-transaction",
      network: "testnet-10",
      expectedSignerAddress: identity.address,
      unsignedSafeJson,
      signInputs: [{ index: 0, sighashType: 1 }],
      manifest
    },
    "v2-mismatch"
  );
  const result = cli(["sign-tx", "--key", keyfile, "--request-file", mismatched]);
  assert.notEqual(result.status, 0, "H-2 FIXED: the signer refuses when the tx to sign is not the one the manifest describes");
  assert.match(result.stderr, /DO NOT SIGN/, "H-2 FIXED: a human-readable DO-NOT-SIGN reaches the operator");
  assert.match(result.stderr, /NOT the one the manifest describes|txId/i, "H-2 FIXED: the refusal explains the txId-binding failure");
  // No signature was produced.
  assert.equal(result.stdout.trim(), "", "H-2 FIXED: nothing is signed on a binding mismatch");
});

test("S1e H-2 FIXED: /2 with a VERIFIED manifest bound to the exact transaction renders the intent to the operator and signs", () => {
  // Pair the fixture manifest with a signable tx whose embedded id is the
  // manifest's txId, so both the verification AND the txId binding pass.
  const manifest = agentSpendFixture().manifest;
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);
  const bound = JSON.parse(unsignedSafeJson);
  bound.id = manifest.transaction.txId; // the id the /2 binding checks
  const boundReq = writeRequest(
    {
      format: AIRGAP.SIGNING_REQUEST_FORMAT_V2,
      kind: "sign-transaction",
      network: "testnet-10",
      expectedSignerAddress: identity.address,
      unsignedSafeJson: JSON.stringify(bound),
      signInputs: [{ index: 0, sighashType: 1 }],
      manifest
    },
    "v2-bound"
  );
  const result = cli(["sign-tx", "--key", keyfile, "--request-file", boundReq]);
  assert.equal(result.status, 0, `H-2 FIXED: a verified+bound /2 request signs; stderr:\n${result.stderr}`);
  // The operator SAW the intent (rendered to stderr) — no longer blind.
  assert.match(result.stderr, /Send exactly|Payment of exactly/, "H-2 FIXED: the human-readable intent reaches the operator before signing");
  assert.ok(!result.stderr.includes("DO NOT SIGN"), "a verified+bound request is not a refusal");
  const signed = JSON.parse(result.stdout);
  assert.equal(signed.format, "policyvault-cli-signer-signed-transaction/1");
  assert.ok(JSON.parse(signed.signedSafeJson).inputs[0].signatureScript.length > 0, "a real signature exists");
});

/* ------------------------------------------------------------------ */
/* S2 — what DOES hold: the producer-side second refusal               */
/* ------------------------------------------------------------------ */

test("S2 HOLDS: the mobile air-gap producer cannot emit a signing request without a PASS bound to the exact bytes", () => {
  const payload = JSON.stringify({ id: "ab".repeat(32) });
  const passing = { ok: true, verdict: "VERIFIED_EXACT", unsignedSafeJson: payload };

  assert.equal(AIRGAP.authorizeSigning({ verification: passing, unsignedSafeJson: payload }).ok, true);

  const refusals = [
    [{ verification: undefined, unsignedSafeJson: payload }, "VERIFICATION_REQUIRED"],
    [{ verification: null, unsignedSafeJson: payload }, "VERIFICATION_REQUIRED"],
    [{ verification: {}, unsignedSafeJson: payload }, "VERIFICATION_REFUSED"],
    [{ verification: { ok: false, verdict: "REFUSED", refusalCodes: ["X"] }, unsignedSafeJson: payload }, "VERIFICATION_REFUSED"],
    // ok:true but the WRONG verdict string — a half-forged outcome.
    [{ verification: { ok: true, verdict: "OK", unsignedSafeJson: payload }, unsignedSafeJson: payload }, "VERIFICATION_REFUSED"],
    // a PASS for DIFFERENT bytes: the substitution the gate exists for.
    [{ verification: { ok: true, verdict: "VERIFIED_EXACT", unsignedSafeJson: JSON.stringify({ id: "cd".repeat(32) }) }, unsignedSafeJson: payload }, "VERIFICATION_TX_BINDING_MISMATCH"],
    [{ verification: passing, unsignedSafeJson: "" }, "AIRGAP_INPUT_INVALID"]
  ];
  for (const [args, code] of refusals) {
    const out = AIRGAP.authorizeSigning(args);
    assert.equal(out.ok, false, `${code}: must refuse`);
    assert.equal(out.code, code);
  }
});

test("S2b HOLDS: buildSigningRequestDocument refuses without a passing outcome, so a UI defect alone cannot produce a signature", () => {
  const payload = JSON.stringify({ id: "ab".repeat(32) });
  const request = { transaction: { unsignedSafeJson: payload }, signInputs: [{ index: 0, sighashType: 1 }] };
  const refused = AIRGAP.buildSigningRequestDocument({
    request,
    verification: { ok: false, verdict: "REFUSED", refusalCodes: ["RECIPIENT_MISMATCH"] },
    network: "testnet-10",
    expectedSignerAddress: "kaspatest:qqq"
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, "VERIFICATION_REFUSED");
  assert.ok(!("document" in refused), "no document is produced at all — not a disabled one");
});

/* ------------------------------------------------------------------ */
/* S3 — the signer's OWN fail-closed properties (which do hold)        */
/* ------------------------------------------------------------------ */

test("S3 HOLDS: the signer fails closed on version, kind, network, and signer-identity mismatches", () => {
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);
  const base = {
    format: SIGNING_REQUEST_FORMAT,
    kind: "sign-transaction",
    network: "testnet-10",
    expectedSignerAddress: identity.address,
    unsignedSafeJson,
    signInputs: [{ index: 0, sighashType: 1 }]
  };
  const cases = [
    // A genuinely unknown version fails closed (/1 and /2 are the known
    // versions now; /99 is not).
    [{ format: "policyvault-cli-signing-request/99" }, /unknown versions fail closed/],
    [{ kind: "sign-anything" }, /is not .{0,2}sign-transaction/],
    [{ network: "mainnet" }, /mainnet|network/i],
    [{ expectedSignerAddress: "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" }, /./]
  ];
  for (const [override, pattern] of cases) {
    const p = writeRequest({ ...base, ...override }, `neg-${Math.random().toString(16).slice(2)}`);
    const result = cli(["sign-tx", "--key", keyfile, "--request-file", p]);
    assert.notEqual(result.status, 0, `${JSON.stringify(override)} must refuse`);
    // Refusals are machine-readable: a coded JSON document, so an agent
    // consumer classifies them without parsing prose.
    assert.match(`${result.stdout}${result.stderr}`, pattern, JSON.stringify(override));
    if (result.stdout.trim().startsWith("{")) {
      const doc = JSON.parse(result.stdout);
      assert.ok(typeof doc.error.code === "string" && doc.error.code.length > 0, "every refusal carries a machine code");
    }
  }
});

test("S3b HOLDS: no secret material appears in any CLI output across the whole probe session", () => {
  const secret = JSON.parse(fs.readFileSync(keyfile, "utf8")).privateKeyHex;
  assert.match(secret, /^[0-9a-f]{64}$/);
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);
  const p = writeRequest(
    {
      format: SIGNING_REQUEST_FORMAT,
      kind: "sign-transaction",
      network: "testnet-10",
      expectedSignerAddress: identity.address,
      unsignedSafeJson,
      signInputs: [{ index: 0, sighashType: 1 }]
    },
    "secret-scan"
  );
  const outputs = [cli(["identity", "--key", keyfile]), cli(["sign-tx", "--key", keyfile, "--request-file", p]), cli(["sign-tx", "--key", keyfile, "--request-file", "/nonexistent"])];
  for (const o of outputs) {
    assert.ok(!`${o.stdout}${o.stderr}`.includes(secret), "the private key must never appear in CLI output");
  }
});

test("S9 cleanup: remove the throwaway key material", () => {
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(fs.existsSync(dir), false);
});
