"use strict";

/*
 * PolicyVault mobile — ON-DEVICE VERIFICATION PROOF, WITHOUT THE MOBILE
 * TOOLCHAIN.
 *
 * Claim label for what this file establishes: UNIT-TESTED. It does NOT
 * establish TESTNET-VERIFIED, and it establishes nothing about iOS or
 * Android: no `.ipa`/`.aab` has been built and no WebView has executed
 * this payload (see mobile/test/sandbox.js and
 * docs/postlaunch/mobile-v1-scaffold.md).
 *
 * What it DOES prove, which is the load-bearing claim of the whole
 * architecture decision:
 *
 *   A. BYTE IDENTITY — the artifacts the app packages are the repository
 *      artifacts, not a rebuild, a translation, or a bundler's output.
 *   B. WIRING — loading the app's own scripts, in the app's own order,
 *      into a browser-like context with no Node escape hatches produces
 *      exactly the globals index.html expects.
 *   C. PASS — a real flow verifies through the app's OWN service and
 *      yields the SAME manifest hash and the SAME explanation lines as
 *      the direct Node path over the repository originals.
 *   D. DO-NOT-SIGN — policy-invalid adversarial test transactions refuse
 *      with the right detector codes, lead with "!! DO NOT SIGN !!", and
 *      carry NO signable payload binding.
 *   E. FAIL-CLOSED PACKAGING — a payload missing the core bundle refuses
 *      every verification instead of silently skipping it.
 *
 * Fixtures come from `web/test/helpers.js` — the SAME fixtures the web
 * verifier suite uses. That coupling is deliberate: a mobile-only copy of
 * the fixtures could drift from the flows the web client actually proves,
 * and a divergence between the two clients is precisely what this suite
 * exists to detect.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const S = require("./sandbox.js");
const sync = require("../tools/sync-portable.js");

const REPO_ROOT = path.join(__dirname, "..", "..");
const H = require("../../web/test/helpers.js");

/* The direct Node path over the REPOSITORY ORIGINALS — the reference the
 * packaged copies must agree with. */
const repoCore = require("../../web/core-bundle.js");
const { createVerifyIntent: repoCreateVerifyIntent } = require("../../web/verify-intent.js");
const repoVerifier = repoCreateVerifyIntent(repoCore);

function verifyArgs(scenario) {
  return {
    request: scenario.request,
    vault: scenario.vault,
    createContext: scenario.createContext,
    clientAction: scenario.clientAction,
    clientParams: scenario.clientParams,
    clientFuel: scenario.clientFuel,
    sessionNetwork: scenario.sessionNetwork,
    sessionXOnly: scenario.sessionXOnly,
    role: scenario.role
  };
}

/* ==================================================================== */
/* A. BYTE IDENTITY with the repository artifacts                        */
/* ==================================================================== */

test("BYTE IDENTITY: the packaged core bundle and verifier are the repository files, byte for byte", () => {
  const pairs = [
    ["web/core-bundle.js", "mobile/www/vendor/core-bundle.js"],
    ["web/verify-intent.js", "mobile/www/vendor/verify-intent.js"]
  ];
  for (const [srcRel, dstRel] of pairs) {
    const src = fs.readFileSync(path.join(REPO_ROOT, srcRel), "utf8");
    const dst = fs.readFileSync(path.join(REPO_ROOT, dstRel), "utf8");
    assert.equal(
      sync.sha256Hex(dst),
      sync.sha256Hex(src),
      `${dstRel} is not byte-identical to ${srcRel} — the mobile app would be running a verifier the review never covered`
    );
    assert.equal(dst, src, `${dstRel} differs from ${srcRel}`);
  }
});

test("BYTE IDENTITY: the host-wrapped API client embeds sdk/src/http-client.js verbatim and recoverably", () => {
  const src = fs.readFileSync(path.join(REPO_ROOT, "sdk/src/http-client.js"), "utf8");
  const wrapped = fs.readFileSync(path.join(REPO_ROOT, "mobile/www/vendor/http-client.js"), "utf8");

  const begin = "  /* ---- BEGIN VERBATIM sdk/src/http-client.js ---- */\n";
  const end = "\n  /* ---- END VERBATIM sdk/src/http-client.js ---- */";
  const from = wrapped.indexOf(begin);
  const to = wrapped.indexOf(end);
  assert.ok(from >= 0 && to > from, "the verbatim markers are missing from the wrapped client");

  const embedded = wrapped.slice(from + begin.length, to);
  assert.equal(embedded, src.replace(/\n$/, ""), "the embedded client is not the repository source verbatim");
  /* The header pins the source digest so the packaged file can be checked
   * against the repository without re-running the generator. */
  assert.ok(wrapped.includes("sha256:" + sync.sha256Hex(src)), "the wrapper header does not pin the source digest");
});

test("BYTE IDENTITY: the committed vendor tree passes the build gate", () => {
  assert.deepEqual(sync.checkAll(), [], "the committed mobile/www/vendor tree does not match the repository sources");
});

/*
 * A green gate proves nothing unless the gate can also go red, so these
 * two probes drive `--check` against a SCRATCH COPY of the payload. The
 * committed payload is never mutated: other suites in this directory read
 * it concurrently, and a test that edits shared state to prove a point is
 * a race, not a proof.
 */
function scratchPayload(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mobile-gate-"));
  const vendorDir = path.join(dir, "vendor");
  const pinsPath = path.join(dir, "vendor-pins.json");
  sync.writeAll({ vendorDir, pinsPath });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { vendorDir, pinsPath };
}

test("BYTE IDENTITY: a single modified byte in the payload fails the gate", (t) => {
  const scratch = scratchPayload(t);
  assert.deepEqual(sync.checkAll(scratch), [], "the freshly written scratch payload should be clean");

  const victim = path.join(scratch.vendorDir, "core-bundle.js");
  fs.writeFileSync(victim, fs.readFileSync(victim, "utf8") + "\n/* injected drift */\n");

  const problems = sync.checkAll(scratch);
  assert.ok(
    problems.some((p) => p.startsWith("DRIFT: www/vendor/core-bundle.js")),
    `expected a DRIFT report for the modified bundle, got ${JSON.stringify(problems)}`
  );
});

test("BYTE IDENTITY: an unlisted file in the payload fails the gate", (t) => {
  const scratch = scratchPayload(t);
  fs.writeFileSync(path.join(scratch.vendorDir, "not-reviewed.js"), "window.x = 1;\n");

  const problems = sync.checkAll(scratch);
  assert.ok(
    problems.some((p) => p.startsWith("UNLISTED: mobile/www/vendor/not-reviewed.js")),
    `expected an UNLISTED report, got ${JSON.stringify(problems)}`
  );
});

test("BYTE IDENTITY: the packaged-payload gate checks what `cap copy` actually deposited", (t) => {
  /* `cap copy` is the LAST step that could substitute the verifier, after
   * every source-side check has already passed. The gate therefore has to
   * be able to read a native project's copied payload and judge it. Native
   * projects are generated on demand and are not committed, so this test
   * builds a payload copy the way `cap copy` does and drives the real gate
   * over it — including the failing direction. */
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mobile-copied-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const vendorDir = path.join(dir, "vendor");
  const pinsPath = path.join(dir, "vendor-pins.json");
  fs.mkdirSync(vendorDir, { recursive: true });
  for (const a of sync.ARTIFACTS) {
    fs.copyFileSync(path.join(sync.VENDOR_DIR, a.dest), path.join(vendorDir, a.dest));
  }
  fs.copyFileSync(sync.PINS_PATH, pinsPath);

  assert.deepEqual(sync.checkAll({ vendorDir, pinsPath }), [], "a faithful copy of the payload must pass the gate");

  const victim = path.join(vendorDir, "verify-intent.js");
  fs.writeFileSync(victim, fs.readFileSync(victim, "utf8") + "\n/* substituted verifier */\n");
  const problems = sync.checkAll({ vendorDir, pinsPath });
  assert.ok(
    problems.some((p) => p.startsWith("DRIFT: www/vendor/verify-intent.js")),
    `a substituted verifier in the copied payload must fail the gate, got ${JSON.stringify(problems)}`
  );
});

test("BYTE IDENTITY: checkPackaged reports each native platform, skipping ones that are not added", () => {
  /* Never a false PASS for a platform that does not exist, and never a
   * failure for one that was simply not generated. */
  const results = sync.checkPackaged();
  assert.deepEqual(results.map((r) => r.label).sort(), ["android", "ios"]);
  for (const r of results) {
    if (!r.present) {
      assert.deepEqual(r.problems, [], "an absent platform reports no problems, it does not invent a pass");
    } else {
      assert.deepEqual(r.problems, [], `${r.label}: the copied payload does not match the repository sources`);
    }
  }
});

test("BYTE IDENTITY: a stale pin file fails the gate", (t) => {
  const scratch = scratchPayload(t);
  const pins = JSON.parse(fs.readFileSync(scratch.pinsPath, "utf8"));
  pins.artifacts[0].sourceSha256 = "0".repeat(64);
  fs.writeFileSync(scratch.pinsPath, JSON.stringify(pins, null, 2) + "\n");

  const problems = sync.checkAll(scratch);
  assert.ok(
    problems.some((p) => p.startsWith("DRIFT: mobile/www/vendor-pins.json")),
    `expected a pin-file report, got ${JSON.stringify(problems)}`
  );
});

/* ==================================================================== */
/* B. WIRING — the app's own scripts in a browser-like context           */
/* ==================================================================== */

test("WIRING: the app payload loads through the BROWSER branch, with no Node escape hatches present", () => {
  const g = S.loadAppPayload();

  assert.equal(g.window, g, "window must alias the global scope, as in a real WebView");
  for (const nodeGlobal of ["require", "module", "process", "Buffer"]) {
    assert.equal(typeof g[nodeGlobal], "undefined", `${nodeGlobal} must not exist in the simulated WebView global`);
  }

  /* Exactly the globals mobile/www/index.html depends on. */
  for (const name of [
    "PolicyVaultCore",
    "PolicyVaultVerifyIntent",
    "PolicyVaultHttpClient",
    "PolicyVaultMobileQrFrames",
    "PolicyVaultMobileAirgap",
    "PolicyVaultMobileVerification",
    "PolicyVaultMobileApi",
    "PolicyVaultMobileSignerCapabilities",
    "PolicyVaultMobileBuildIntegrity"
  ]) {
    assert.ok(g[name], `${name} was not installed by the packaged scripts`);
  }

  /* The vendored API client works under the core bundle's own crypto
   * shim — the wrapper's closed require resolved "crypto" correctly. */
  assert.equal(typeof g.PolicyVaultHttpClient.createClient, "function");
  assert.match(g.PolicyVaultHttpClient.randomIdempotencyKey(), /^pvsdk-[0-9a-f]{32}$/);
});

test("WIRING: the app's service is available and reports the reviewed client fee ceiling", () => {
  const g = S.loadAppPayload();
  const service = S.createVerificationService(g);
  assert.equal(service.available, true, service.unavailableReason || "");
  assert.equal(service.unavailableReason, null);
  assert.deepEqual(S.outOfSandbox(service.missingCoreModules), []);
  assert.equal(service.clientMaxFeeSompi, "100000000", "the packaged verifier's 1 KAS client fee ceiling must be the reviewed one");
});

/* ==================================================================== */
/* C. PASS — through the app's own wiring, identical to the reference    */
/* ==================================================================== */

test("PASS: a real agentSpend verifies through the app's own service and matches the repository verifier exactly", () => {
  const g = S.loadAppPayload();
  const service = S.createVerificationService(g);

  const scenario = H.spendScenario();
  const args = verifyArgs(scenario);

  const mobile = S.outOfSandbox(service.verify(S.intoSandbox(g, args)));
  const reference = repoVerifier.verifyBeforeSigning(args);

  assert.equal(mobile.ok, true, `expected PASS, got ${JSON.stringify(mobile.refusalCodes)}\n${(mobile.lines || []).join("\n")}`);
  assert.equal(mobile.verdict, "VERIFIED_EXACT");

  /* The equality that matters: same commitment, same bytes bound, same
   * human-readable text. A mobile-only divergence in ANY of these would
   * mean the two clients disagree about what a transaction does. */
  assert.equal(mobile.manifestHash, reference.manifestHash, "the packaged verifier produced a different manifest hash than the repository verifier");
  assert.equal(mobile.txId, reference.txId);
  assert.equal(mobile.unsignedSafeJson, scenario.request.transaction.unsignedSafeJson, "the outcome must bind the exact payload that will be signed");
  assert.deepEqual(mobile.lines, reference.lines, "the explanation text differs between the packaged and repository verifiers");

  /* §6.3 rule 8: no truncation of value-bearing text anywhere in the
   * rendering the human reads. */
  const text = mobile.lines.join("\n");
  assert.ok(!/…/.test(text), "the explanation must contain no truncation ellipsis");
  assert.ok(text.includes(`Send exactly 10 KAS to recipient public key ${H.RECIPIENT}`), "the full recipient key must appear");
  assert.ok(
    text.includes("THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE."),
    "a PASS must carry the exact pass statement"
  );
});

test("PASS: every fixture flow agrees line-for-line with the repository verifier", () => {
  const g = S.loadAppPayload();
  const service = S.createVerificationService(g);

  const flows = {
    agentSpend: H.spendScenario(),
    aboveThresholdSpend: H.aboveSpendScenario(),
    ownerTopUp: H.topUpScenario(),
    pause: H.pauseScenario(),
    setApprovers: H.setApproversScenario(),
    addAgent: H.addAgentScenario(),
    recover: H.recoverScenario(),
    createVault: H.createScenario()
  };

  for (const [name, scenario] of Object.entries(flows)) {
    const args = verifyArgs(scenario);
    const mobile = S.outOfSandbox(service.verify(S.intoSandbox(g, args)));
    const reference = repoVerifier.verifyBeforeSigning(args);
    assert.equal(mobile.ok, true, `${name}: expected PASS, got ${JSON.stringify(mobile.refusalCodes)}`);
    assert.equal(mobile.manifestHash, reference.manifestHash, `${name}: manifest hash differs`);
    assert.deepEqual(mobile.lines, reference.lines, `${name}: explanation lines differ`);
    assert.deepEqual(mobile.refusalCodes, reference.refusalCodes, `${name}: refusal codes differ`);
  }
});

/* ==================================================================== */
/* D. DO-NOT-SIGN                                                        */
/* ==================================================================== */

/*
 * Authorized negative-validation cases: policy-invalid adversarial test
 * transactions modeling a hostile server that builds a transaction
 * differing from what the user asked for. Each must refuse on device.
 */
const NEGATIVE_CASES = [
  {
    name: "recipient substitution",
    code: "HIDDEN_RECIPIENT",
    mutate: (tx) => { tx.outputs[0].scriptPublicKey = H.spkWire(H.p2pk(H.ATTACKER)); }
  },
  {
    name: "amount inflation",
    code: "VALUE_CONSERVATION_VIOLATION",
    mutate: (tx) => { tx.outputs[0].value = "2000000000"; }
  }
];

for (const c of NEGATIVE_CASES) {
  test(`DO-NOT-SIGN: ${c.name} refuses on device with ${c.code}`, () => {
    const g = S.loadAppPayload();
    const service = S.createVerificationService(g);

    const scenario = H.withTamperedTx(H.spendScenario(), c.mutate);
    const args = verifyArgs(scenario);

    const mobile = S.outOfSandbox(service.verify(S.intoSandbox(g, args)));
    const reference = repoVerifier.verifyBeforeSigning(args);

    assert.equal(mobile.ok, false, `${c.name}: expected a refusal, got a PASS`);
    assert.equal(mobile.verdict, "REFUSED");
    assert.ok(mobile.refusalCodes.includes(c.code), `expected ${c.code}, got ${JSON.stringify(mobile.refusalCodes)}`);
    assert.equal(mobile.lines[0], "!! DO NOT SIGN !!", "a refusal must lead with the DO NOT SIGN line");
    assert.equal(mobile.unsignedSafeJson, null, "a refused outcome must never carry a signable payload binding");
    assert.equal(mobile.manifestHash, null);

    /* Identical refusal to the repository verifier, code for code and
     * line for line. */
    assert.deepEqual(mobile.refusalCodes, reference.refusalCodes, `${c.name}: refusal codes differ from the repository verifier`);
    assert.deepEqual(mobile.lines, reference.lines, `${c.name}: refusal text differs from the repository verifier`);
  });
}

test("DO-NOT-SIGN: a wrong-network session refuses before anything else is considered", () => {
  const g = S.loadAppPayload();
  const service = S.createVerificationService(g);

  const args = verifyArgs(H.spendScenario());
  args.sessionNetwork = "testnet-11";

  const mobile = S.outOfSandbox(service.verify(S.intoSandbox(g, args)));
  assert.equal(mobile.ok, false);
  assert.ok(mobile.refusalCodes.includes("NETWORK_MISMATCH"), JSON.stringify(mobile.refusalCodes));
  assert.equal(mobile.unsignedSafeJson, null);
});

test("DO-NOT-SIGN: a malformed verification input is a refusal, never a neutral verdict", () => {
  const g = S.loadAppPayload();
  const service = S.createVerificationService(g);

  for (const bad of [undefined, null, {}, { request: {} }]) {
    const outcome = S.outOfSandbox(service.verify(bad === undefined ? undefined : S.intoSandbox(g, bad)));
    assert.equal(outcome.ok, false, `${JSON.stringify(bad)} must refuse`);
    assert.equal(outcome.verdict, "REFUSED");
    assert.equal(outcome.lines[0], "!! DO NOT SIGN !!");
    assert.equal(outcome.unsignedSafeJson, null);
  }
});

/* ==================================================================== */
/* E. FAIL-CLOSED PACKAGING                                              */
/* ==================================================================== */

test("FAIL CLOSED: a payload packaged WITHOUT the core bundle refuses every verification", () => {
  /* The real failure mode of a mis-packaged release: the verifier ships,
   * the core does not. verify-intent.js installs a permanently-refusing
   * instance in that case rather than being absent — which is what makes
   * verification MANDATORY rather than best-effort. */
  const g = S.loadAppPayload([
    "vendor/verify-intent.js",
    "js/portable/qr-frames.js",
    "js/portable/airgap.js",
    "js/portable/verification.js"
  ]);

  assert.equal(typeof g.PolicyVaultCore, "undefined", "this probe must run with no core bundle loaded");
  assert.ok(g.PolicyVaultVerifyIntent, "the verifier must still install itself so verification cannot be skipped");

  const service = S.createVerificationService(g);
  assert.equal(service.available, false);
  assert.match(service.unavailableReason, /core bundle/);

  const outcome = S.outOfSandbox(service.verify(S.intoSandbox(g, verifyArgs(H.spendScenario()))));
  assert.equal(outcome.ok, false);
  assert.deepEqual(outcome.refusalCodes, ["CORE_UNAVAILABLE"]);
  assert.equal(outcome.lines[0], "!! DO NOT SIGN !!");
  assert.equal(outcome.unsignedSafeJson, null);
});

test("FAIL CLOSED: a core bundle missing required modules is treated as no core at all", () => {
  const g = S.loadAppPayload();
  const wiring = g.PolicyVaultMobileVerification;

  /* Build the service against a deliberately partial core, in the
   * sandbox realm so the module sees its own plain objects. */
  const partial = S.intoSandbox(g, { intent: {}, intentExplain: {} });
  const service = wiring.createMobileVerification({
    core: partial,
    verifyIntent: g.PolicyVaultVerifyIntent,
    airgap: g.PolicyVaultMobileAirgap
  });

  assert.equal(service.available, false);
  assert.match(service.unavailableReason, /partial core is treated as no core/);
  const outcome = S.outOfSandbox(service.verify(S.intoSandbox(g, verifyArgs(H.spendScenario()))));
  assert.equal(outcome.ok, false);
  assert.deepEqual(outcome.refusalCodes, ["CORE_UNAVAILABLE"]);
});
