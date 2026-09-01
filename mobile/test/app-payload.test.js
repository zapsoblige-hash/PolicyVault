"use strict";

/*
 * PolicyVault mobile — PAYLOAD + HONEST-UX GATES.
 *
 * Three things this file keeps true, all of which are easy to break by
 * accident and hard to notice by review:
 *
 *   1. The page loads exactly the scripts the test harness loads, in the
 *      same order. Script order is load-bearing here — verify-intent.js
 *      binds to whatever core exists AT LOAD TIME, and the wrapped API
 *      client needs the core bundle's crypto shim to already be present.
 *      If index.html and mobile/test/sandbox.js ever disagree, every
 *      other test in this directory is testing something the app does not
 *      actually do.
 *
 *   2. NO FAKE AFFORDANCES. Anything this build cannot do reports
 *      UNAVAILABLE with a reason, and nothing is offered next to it.
 *      Since this scaffold has neither camera capture nor a share sheet,
 *      NO signing transport may be offered — and the tests assert that,
 *      so a future edit that flips a capability to `true` without
 *      building it fails here.
 *
 *   3. Fail-closed build integrity: an unreadable or mismatched artifact
 *      is a FAILURE, never an "unknown" that renders as neutral.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const S = require("./sandbox.js");
const sync = require("../tools/sync-portable.js");

/* ==================================================================== */
/* 1. Payload shape                                                      */
/* ==================================================================== */

function indexScriptSrcs() {
  const html = fs.readFileSync(path.join(S.WWW, "index.html"), "utf8");
  const out = [];
  const re = /<script\s+src="([^"]+)"\s*><\/script>/g;
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return out;
}

test("PAYLOAD: index.html loads exactly the harness's script list, in order, then the platform layer and the app", () => {
  const srcs = indexScriptSrcs();
  const expected = S.SCRIPT_ORDER.concat(["js/platform/native-http.js", "js/platform/env.js", "js/platform/ui.js", "js/app.js"]);
  assert.deepEqual(srcs, expected, "index.html and mobile/test/sandbox.js disagree about what the app loads");
});

test("PAYLOAD: every script the page references exists, and every shipped script is referenced", () => {
  const srcs = indexScriptSrcs();
  for (const src of srcs) {
    assert.ok(fs.existsSync(path.join(S.WWW, src)), `index.html references ${src}, which does not exist`);
  }

  const shipped = [];
  for (const dir of ["vendor", "js/portable", "js/platform", "js"]) {
    const abs = path.join(S.WWW, dir);
    for (const f of fs.readdirSync(abs)) {
      if (f.endsWith(".js")) shipped.push(`${dir}/${f}`);
    }
  }
  for (const file of shipped) {
    assert.ok(srcs.includes(file), `${file} ships in the payload but index.html never loads it — dead code in a security payload is not acceptable`);
  }
});

test("PAYLOAD: every script in the page parses", () => {
  /* The portable and vendored scripts are EXECUTED by the sandbox in the
   * other suites; the platform scripts cannot be (they need a real DOM),
   * so at minimum every file the page loads must parse. A syntax error in
   * js/app.js or js/platform/*.js would otherwise only surface on a
   * device. */
  for (const src of indexScriptSrcs()) {
    const source = fs.readFileSync(path.join(S.WWW, src), "utf8");
    assert.doesNotThrow(() => new vm.Script(source, { filename: src }), `${src} does not parse`);
  }
});

test("PAYLOAD: the app shell mentions no signing path that bypasses verification", () => {
  const appSource = fs.readFileSync(path.join(S.WWW, "js", "app.js"), "utf8");

  /* The signing screen must route through the portable gate. */
  assert.match(appSource, /AIRGAP\.authorizeSigning\(/, "the sign screen must call the independent authorization gate");
  assert.match(appSource, /AIRGAP\.buildSigningRequestDocument\(/, "the sign screen must build the document through the portable module");
  /* And the verify screen must only ever offer to continue on a pass. */
  assert.match(appSource, /if \(outcome\.ok === true\) \{[\s\S]{0,240}Continue to signing/, "the continue-to-signing control must exist only inside the pass branch");
});

/*
 * Extract one top-level `function NAME(...) { ... }` from a source file by
 * brace-counting from its opening `{`, rather than a length-capped regex
 * window — precise regardless of how long the function grows, and it is
 * what lets the next test assert an ABSENCE (no mutation call anywhere in
 * screenAgents) without also matching text outside that function.
 */
function extractFunctionSource(source, functionName) {
  const marker = `function ${functionName}(`;
  const start = source.indexOf(marker);
  assert.ok(start >= 0, `${functionName} not found in js/app.js`);
  const braceStart = source.indexOf("{", start);
  assert.ok(braceStart >= 0, `${functionName}: no function body found`);
  let depth = 0;
  for (let i = braceStart; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") {
      depth--;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`${functionName}: unbalanced braces — could not find the matching close`);
}

test("PAYLOAD: the Agents screen reads through the real client and stays read-only", () => {
  const appSource = fs.readFileSync(path.join(S.WWW, "js", "app.js"), "utf8");
  const fnSource = extractFunctionSource(appSource, "screenAgents");

  /* Real reads through the same vendored API client every other remote
   * screen uses — no second, hand-rolled fetch, no fabricated agent data. */
  assert.match(fnSource, /state\.api\.client\.listVaults\(\)/, "screenAgents must list vaults through the real client");
  assert.match(fnSource, /state\.api\.client\.getVault\(/, "screenAgents must read agent data through the real client's getVault");

  /* Server refusal vs transport failure discipline — same as remoteScreen,
   * never a hand-rolled error path that could blur the two. */
  assert.match(fnSource, /state\.api\.describeError\(/, "screenAgents must use the shared describeError discipline");

  /* NO MUTATION in this phase: read-only listing + status only. A future
   * edit that adds a suspend/rotate/pause/revoke control must fail here
   * until that is a deliberate, separately-reviewed change. */
  const forbiddenMutations = [/suspendAgent/, /rotateAgent/, /pauseVault/, /revokeAgent/, /\.suspend\s*\(/, /\.rotate\s*\(/, /\.pause\s*\(/, /\.revoke\s*\(/];
  for (const re of forbiddenMutations) {
    assert.doesNotMatch(fnSource, re, `screenAgents must stay read-only in this phase — found a match for ${re}`);
  }
});

/* ==================================================================== */
/* 2. Honest capability UX                                               */
/* ==================================================================== */

test("HONEST UX: with no camera and no file transport, NO signing transport is offered, each with a stated reason", () => {
  const g = S.loadAppPayload();
  const CAPS = g.PolicyVaultMobileSignerCapabilities;

  /* The platform layer's real report for this build. */
  const platform = S.intoSandbox(g, {
    camera: { available: false, reason: "this build has no QR decoder" },
    file: { available: false, reason: "this build has no share-sheet integration" },
    injectedProvider: { present: false }
  });

  const roster = S.outOfSandbox(CAPS.buildSignerRoster({ platform }));
  assert.equal(roster.anyOffered, false, "a scaffold with no working transport must offer no signer");

  for (const a of roster.adapters) {
    assert.equal(a.offered, false, `${a.id} was offered without a working transport`);
    assert.equal(typeof a.unavailableReason, "string");
    assert.ok(a.unavailableReason.length > 20, `${a.id}'s unavailable reason must be a real sentence, not a shrug`);
  }
});

test("HONEST UX: a working transport is offered only when the platform actually reports one", () => {
  const g = S.loadAppPayload();
  const CAPS = g.PolicyVaultMobileSignerCapabilities;

  const roster = S.outOfSandbox(CAPS.buildSignerRoster({
    platform: S.intoSandbox(g, { camera: { available: true }, file: { available: false, reason: "no share sheet" } })
  }));

  const qr = roster.adapters.find((a) => a.id === "qr-airgap");
  assert.equal(qr.offered, true);
  assert.equal(qr.unavailableReason, null);
  assert.equal(roster.adapters.find((a) => a.id === "qr-airgap-file").offered, false);
});

test("HONEST UX: a missing or malformed platform report yields everything unavailable", () => {
  const g = S.loadAppPayload();
  const CAPS = g.PolicyVaultMobileSignerCapabilities;

  for (const bad of [undefined, {}, { platform: null }, { platform: { camera: "yes" } }]) {
    const roster = S.outOfSandbox(CAPS.buildSignerRoster(bad === undefined ? undefined : S.intoSandbox(g, bad)));
    assert.equal(roster.anyOffered, false, `${JSON.stringify(bad)} must fail closed`);
  }
});

test("HONEST UX: unsupported wallets are LISTED with a concrete reason and a supported alternative", () => {
  const g = S.loadAppPayload();
  const CAPS = g.PolicyVaultMobileSignerCapabilities;
  const limitations = S.outOfSandbox(CAPS.LIMITATIONS);

  const ids = limitations.map((l) => l.id).sort();
  assert.deepEqual(ids, ["kaspium", "kasware-extension", "ledger", "tangem", "walletconnect"]);

  for (const l of limitations) {
    assert.ok(l.status && l.status.length > 5, `${l.id} has no status`);
    assert.ok(l.body && l.body.length > 60, `${l.id}'s explanation is too thin to be useful`);
    assert.ok(l.alternative && /offline CLI signer/.test(l.alternative), `${l.id} must end at the supported alternative, never a dead end`);
  }

  /* Tangem's refusal is enforced by scheme negotiation, so the copy must
   * name the concrete technical reason rather than sounding like a
   * preference. */
  const tangem = limitations.find((l) => l.id === "tangem");
  assert.match(tangem.body, /ECDSA/);
  assert.match(tangem.body, /Schnorr/);

  /* And the rule that no limitation may ever soften. */
  assert.match(S.outOfSandbox(CAPS.VERIFICATION_IS_NEVER_OPTIONAL), /never downgrades verification/);
});

test("HONEST UX: injected-provider negotiation fails closed on a partial surface or an unknown network", () => {
  const g = S.loadAppPayload();
  const CAPS = g.PolicyVaultMobileSignerCapabilities;

  const cases = [
    { name: "absent", found: { present: false }, negotiated: false },
    { name: "missing signPskt", found: { present: true, methods: ["requestAccounts", "getPublicKey", "getNetwork"], network: "mainnet" }, negotiated: false },
    { name: "unknown network", found: { present: true, methods: ["requestAccounts", "getPublicKey", "getNetwork", "signPskt"], network: "kaspa-test-99" }, negotiated: false },
    { name: "null network (the synchronous probe)", found: { present: true, methods: ["requestAccounts", "getPublicKey", "getNetwork", "signPskt"], network: null }, negotiated: false },
    { name: "complete", found: { present: true, methods: ["requestAccounts", "getPublicKey", "getNetwork", "signPskt"], network: "testnet-10" }, negotiated: true }
  ];

  for (const c of cases) {
    const r = S.outOfSandbox(CAPS.negotiateInjectedProvider(S.intoSandbox(g, c.found)));
    assert.equal(r.negotiated, c.negotiated, `${c.name}: expected negotiated=${c.negotiated}`);
    if (!c.negotiated) assert.ok(r.reason && r.reason.length > 10, `${c.name}: a refusal must state why`);
    else assert.match(r.caveat, /claims no general KasWare-mobile support/);
  }
});

test("HONEST UX: the session bootstrap reports the FROZEN design's real status — QR login v1 implemented, desktop hand-off deferred — never a fabricated working sign-in", () => {
  // Session-bootstrap DESIGN FREEZE (mobile/docs/session-bootstrap-
  // DESIGN.md, commit 917c2a5) §3 picked QR login as bootstrap v1; §5
  // defers desktop-handoff. This test asserts that frozen decision is
  // reflected honestly, not that "some bootstrap exists" in the abstract.
  const g = S.loadAppPayload();
  const boot = S.outOfSandbox(g.PolicyVaultMobileApi.SESSION_BOOTSTRAP);
  assert.notEqual(boot.status, "UNDECIDED", "the design is frozen — status must no longer claim an open decision");
  assert.equal(boot.candidates.length, 2);
  assert.equal(boot.candidates.filter((c) => c.recommended).length, 1);

  const qr = boot.candidates.find((c) => c.id === "qr-login");
  assert.equal(qr.recommended, true);
  assert.equal(qr.implemented, true, "QR login is DESIGN §3 bootstrap v1 — it must be reported as implemented");

  // The credential-transfer candidate must still carry its warning and
  // must NOT be reported as implemented — DESIGN §5 defers it.
  const handoff = boot.candidates.find((c) => c.id === "desktop-handoff");
  assert.equal(handoff.implemented, false);
  assert.match(handoff.note, /CREDENTIAL TRANSFER|DEFERRED/);
});

test("HONEST UX: the API layer refuses to invent a server, and never silently defaults one", () => {
  const g = S.loadAppPayload();
  const APIMOD = g.PolicyVaultMobileApi;

  /* No arguments at all: the vendored client is what is missing. */
  const nothing = APIMOD.createMobileApi();
  assert.equal(nothing.configured, false);
  assert.match(nothing.unconfiguredReason, /vendored API client/);
  assert.equal(nothing.client, null);

  /* Client present, but no server configured — the case that matters:
   * there is no default and none is invented. */
  const noUrl = APIMOD.createMobileApi({ httpClient: g.PolicyVaultHttpClient, fetchImpl: function () {} });
  assert.equal(noUrl.configured, false);
  assert.match(noUrl.unconfiguredReason, /no PolicyVault server URL/);
  assert.equal(noUrl.client, null);
  assert.equal(noUrl.baseUrl, null);

  /* Server configured, but no transport injected. */
  const noFetch = APIMOD.createMobileApi({ httpClient: g.PolicyVaultHttpClient, baseUrl: "https://example.invalid" });
  assert.equal(noFetch.configured, false);
  assert.match(noFetch.unconfiguredReason, /no HTTP transport/);

  const wired = APIMOD.createMobileApi({
    httpClient: g.PolicyVaultHttpClient,
    baseUrl: "https://example.invalid",
    fetchImpl: function () { throw new Error("unused"); }
  });
  assert.equal(wired.configured, true);
  assert.equal(wired.baseUrl, "https://example.invalid");
  assert.ok(wired.client);
  /* The vendored client's credential guarantee survives the wrapping. */
  assert.equal(wired.client.authenticated, false);
  assert.equal(JSON.stringify(wired.client).includes("token"), false);
});

test("HONEST UX: a transport failure is never reported as a refusal", () => {
  const g = S.loadAppPayload();
  const api = g.PolicyVaultMobileApi.createMobileApi({
    httpClient: g.PolicyVaultHttpClient,
    baseUrl: "https://example.invalid",
    fetchImpl: function () { throw new Error("unused"); }
  });

  const netErr = new g.PolicyVaultHttpClient.PolicyVaultNetworkError({
    method: "POST", path: "/wallet/v4/requests", cause: new Error("connect ECONNREFUSED"), idempotencyKey: "pvsdk-abc"
  });
  const d = S.outOfSandbox(api.describeError(netErr));
  assert.equal(d.kind, "TRANSPORT_FAILURE");
  assert.equal(d.retrySafe, true);
  assert.match(d.text, /UNKNOWN/);
  assert.equal(d.idempotencyKey, "pvsdk-abc");

  const apiErr = new g.PolicyVaultHttpClient.PolicyVaultApiError({
    status: 403, body: { error: { code: "FORBIDDEN", message: "nope" } }, method: "GET", path: "/vaults", idempotencyKey: null
  });
  const d2 = S.outOfSandbox(api.describeError(apiErr));
  assert.equal(d2.kind, "SERVER_REFUSAL");
  assert.equal(d2.code, "FORBIDDEN");
  assert.equal(d2.text, "nope", "the server's own message must be carried verbatim");
  assert.equal(d2.retrySafe, false);
});

/* ==================================================================== */
/* 2b. QR-login bootstrap v1 (mobile session-bootstrap DESIGN §3)        */
/* ==================================================================== */

test("QR LOGIN: fetchAuthChallenge never invents a client or a wallet address", async () => {
  const g = S.loadAppPayload();
  const APIMOD = g.PolicyVaultMobileApi;

  const noClient = await APIMOD.fetchAuthChallenge({ walletAddress: "kaspatest:x" });
  assert.equal(noClient.ok, false);
  assert.match(noClient.reason, /no API client/);

  const noAddr = await APIMOD.fetchAuthChallenge({ client: { request: function () { throw new Error("must not be called"); } } });
  assert.equal(noAddr.ok, false);
  assert.match(noAddr.reason, /wallet address/);
});

test("QR LOGIN: fetchAuthChallenge calls POST /auth/challenge with exactly {walletAddress} and returns the server's challenge unmodified", async () => {
  const g = S.loadAppPayload();
  const APIMOD = g.PolicyVaultMobileApi;
  let seen = null;
  const client = {
    request: function (method, path, opts) {
      seen = { method: method, path: path, opts: opts };
      return Promise.resolve({ challenge: { nonce: "ab".repeat(32), message: "the challenge text", walletAddress: "kaspatest:x", networkId: "testnet-10" } });
    }
  };
  const r = await APIMOD.fetchAuthChallenge({ client: client, walletAddress: "kaspatest:x" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(seen.method, "POST");
  assert.equal(seen.path, "/auth/challenge");
  assert.deepEqual(S.outOfSandbox(seen.opts.body), { walletAddress: "kaspatest:x" });
  assert.equal(r.challenge.nonce, "ab".repeat(32));
  assert.equal(r.challenge.message, "the challenge text");
});

test("QR LOGIN: fetchAuthChallenge reports a malformed response, or a thrown transport/server error, as a refusal — never throws, never fabricates a challenge", async () => {
  const g = S.loadAppPayload();
  const APIMOD = g.PolicyVaultMobileApi;

  const malformed = await APIMOD.fetchAuthChallenge({
    client: { request: function () { return Promise.resolve({ notAChallenge: true }); } },
    walletAddress: "kaspatest:x"
  });
  assert.equal(malformed.ok, false);
  assert.match(malformed.reason, /no readable challenge/);

  const thrown = await APIMOD.fetchAuthChallenge({
    client: { request: function () { return Promise.reject(new Error("connect ECONNREFUSED")); } },
    walletAddress: "kaspatest:x"
  });
  assert.equal(thrown.ok, false);
  assert.match(thrown.reason, /ECONNREFUSED/);
});

test("QR LOGIN: completeAuthVerifyBearer requires nonce/signature/publicKey/walletAddress and requests bearer transport explicitly", async () => {
  const g = S.loadAppPayload();
  const APIMOD = g.PolicyVaultMobileApi;

  const missing = await APIMOD.completeAuthVerifyBearer({ client: { request: function () { throw new Error("must not be called"); } } });
  assert.equal(missing.ok, false);

  let seen = null;
  const client = {
    request: function (method, path, opts) {
      seen = { method: method, path: path, opts: opts };
      return Promise.resolve({ session: { authenticated: true, walletAddress: "kaspatest:x", networkId: "testnet-10" }, token: "cd".repeat(32) });
    }
  };
  const r = await APIMOD.completeAuthVerifyBearer({
    client: client, nonce: "ab".repeat(32), signature: "ef".repeat(64), publicKey: "02" + "11".repeat(32), walletAddress: "kaspatest:x"
  });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(seen.path, "/auth/verify");
  assert.equal(seen.opts.body.transport, "bearer");
  assert.equal(seen.opts.body.nonce, "ab".repeat(32));
  assert.equal(r.token, "cd".repeat(32));
  assert.equal(r.session.walletAddress, "kaspatest:x");
});

test("QR LOGIN: completeAuthVerifyBearer reports 'no bearer token' as a refusal, never a fabricated success, when the server answers with the cookie-only shape (bearer sessions not enabled there)", async () => {
  const g = S.loadAppPayload();
  const APIMOD = g.PolicyVaultMobileApi;
  const client = {
    request: function () { return Promise.resolve({ session: { authenticated: true, walletAddress: "kaspatest:x" } }); } // no `token` field
  };
  const r = await APIMOD.completeAuthVerifyBearer({
    client: client, nonce: "ab".repeat(32), signature: "ef".repeat(64), publicKey: "02" + "11".repeat(32), walletAddress: "kaspatest:x"
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /bearer session token|not be enabled/);
});

/* ==================================================================== */
/* 3. Build integrity, fail-closed                                       */
/* ==================================================================== */

test("BUILD INTEGRITY: the real packaged artifacts verify against the committed pins", async () => {
  const g = S.loadAppPayload();
  const INTEGRITY = g.PolicyVaultMobileBuildIntegrity;
  const sha256Hex = S.sandboxSha256Hex(g);
  const pins = JSON.parse(fs.readFileSync(sync.PINS_PATH, "utf8"));

  const result = S.outOfSandbox(await INTEGRITY.verifyPackagedArtifacts(S.intoSandbox(g, { pins })
    && { pins: S.intoSandbox(g, pins), sha256Hex, readText: (dest) => Promise.resolve(fs.readFileSync(path.join(S.MOBILE_ROOT, dest), "utf8")) }));

  assert.equal(result.ok, true, JSON.stringify(result.artifacts, null, 2));
  assert.equal(result.artifacts.length, sync.ARTIFACTS.length);
  for (const a of result.artifacts) {
    assert.equal(a.ok, true, `${a.dest}: ${a.problem}`);
    assert.equal(a.actualSha256, a.expectedSha256);
    assert.match(a.sourceSha256, /^[0-9a-f]{64}$/);
  }
});

test("BUILD INTEGRITY: a tampered artifact, an unreadable artifact, and an unknown pins version all FAIL", async () => {
  const g = S.loadAppPayload();
  const INTEGRITY = g.PolicyVaultMobileBuildIntegrity;
  const sha256Hex = S.sandboxSha256Hex(g);
  const pins = JSON.parse(fs.readFileSync(sync.PINS_PATH, "utf8"));

  const tampered = S.outOfSandbox(await INTEGRITY.verifyPackagedArtifacts({
    pins: S.intoSandbox(g, pins),
    sha256Hex,
    readText: () => Promise.resolve("/* not the reviewed bytes */")
  }));
  assert.equal(tampered.ok, false);
  assert.equal(tampered.code, "INTEGRITY_MISMATCH");
  assert.ok(tampered.artifacts.every((a) => a.ok === false));

  const unreadable = S.outOfSandbox(await INTEGRITY.verifyPackagedArtifacts({
    pins: S.intoSandbox(g, pins),
    sha256Hex,
    readText: () => Promise.reject(new Error("HTTP 404"))
  }));
  assert.equal(unreadable.ok, false, "an unreadable artifact must be a failure, never an unknown that renders as neutral");
  assert.ok(unreadable.artifacts.every((a) => /could not read or hash/.test(a.problem)));

  for (const badPins of [null, {}, { pinsVersion: "policyvault-mobile-vendor-pins/2", artifacts: [] }]) {
    const r = S.outOfSandbox(await INTEGRITY.verifyPackagedArtifacts({
      pins: badPins === null ? null : S.intoSandbox(g, badPins),
      sha256Hex,
      readText: () => Promise.resolve("")
    }));
    assert.equal(r.ok, false, `${JSON.stringify(badPins)} must fail closed`);
    assert.equal(r.code, "INTEGRITY_PINS_UNSUPPORTED");
  }
});

test("BUILD INTEGRITY: the pins name a real repository source for every packaged artifact", () => {
  const pins = JSON.parse(fs.readFileSync(sync.PINS_PATH, "utf8"));
  assert.equal(pins.pinsVersion, "policyvault-mobile-vendor-pins/1");
  for (const a of pins.artifacts) {
    const abs = path.join(sync.REPO_ROOT, a.source);
    assert.ok(fs.existsSync(abs), `${a.source} does not exist in the repository`);
    assert.equal(sync.sha256Hex(fs.readFileSync(abs, "utf8")), a.sourceSha256, `${a.source}'s pinned digest is stale`);
    assert.ok(a.why && a.why.length > 40, `${a.dest} has no recorded reason for being in the payload`);
  }
});
