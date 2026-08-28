"use strict";

/*
 * PRODUCTION AUTOMATED ACCEPTANCE (network-aware successor of
 * tools/staging-acceptance.js; created for the fullscale-rc3 deployment
 * per the 2026-08-27 owner superseding directive §5).
 *
 * Drives the REAL deployment from the OUTSIDE (normally the public edge
 * https://app.policy-vault.org) and verifies the externally observable
 * security posture: static app, health/readiness, production identity
 * (expected network + buildId, NO staging banner), security headers,
 * Origin/CSRF gate, REAL Schnorr wallet authentication (deterministic
 * throwaway TEST keys used ONLY for message-signing auth — never funded,
 * never transaction-signing), session cookies, tenant isolation with two
 * wallets, STRICTLY READ-ONLY foreign-data isolation probes against
 * designated real records (list absence + by-id 404 non-disclosure; no
 * mutation attempted on real data), body caps, API cache posture, edge
 * cache posture, and rate limiting + trusted-proxy spoof resistance.
 *
 * Usage:
 *   node tools/prod-acceptance.js <baseUrl> --network <networkId>
 *        --expect-build <buildId> [--edge]
 *        [--foreign-vault <vaultId>] [--foreign-request <requestId>]
 *
 *   --network        REQUIRED expected /api/v1/health networkId (fail-closed:
 *                    the tool never adapts to an unexpected network)
 *   --expect-build   REQUIRED expected buildId on /health and /health/ready
 *   --edge           expect Cloudflare in front (adds edge checks, skips
 *                    direct-socket checks the edge absorbs)
 *   --foreign-vault  a REAL vault id the test wallets are NOT participants
 *                    of: must be absent from lists and 404 by id (read-only)
 *   --foreign-request  a REAL request id equally invisible (read-only)
 *
 * Exit 0 = all checks passed; 1 = failures (listed).
 */

const fs = require("fs");
const net = require("net");
const path = require("path");
const { URL } = require("url");

const args = process.argv.slice(2);
const BASE = args[0];
if (!BASE || !/^https?:\/\//.test(BASE)) {
  console.error("usage: node tools/prod-acceptance.js <baseUrl> --network <networkId> --expect-build <buildId> [--edge] [--foreign-vault id] [--foreign-request id]");
  process.exit(2);
}
const EDGE = args.includes("--edge");
const flagValue = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};
const NETWORK = flagValue("--network");
const EXPECT_BUILD = flagValue("--expect-build");
const FOREIGN_VAULT = flagValue("--foreign-vault");
const FOREIGN_REQUEST = flagValue("--foreign-request");
if (!NETWORK || !EXPECT_BUILD) {
  console.error("prod-acceptance: --network and --expect-build are REQUIRED (fail-closed identity gate)");
  process.exit(2);
}
const baseUrl = new URL(BASE);
const ORIGIN = baseUrl.origin;

const { loadConfig } = require(path.join(__dirname, "..", "sdk", "src", "config"));
const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(require("os").tmpdir(), "pv-acc-")) });
const kaspa = require(config.rustyKaspaModule);

/* Deterministic TEST wallets (throwaway, publicly-derivable, NEVER funded;
 * used exclusively for challenge/verify message-signing auth). */
function wallet(hexDigit) {
  const priv = new kaspa.PrivateKey(hexDigit.repeat(64));
  const pub = priv.toPublicKey();
  return {
    priv,
    publicKeyHex: pub.toString(),
    address: pub.toAddress(NETWORK).toString()
  };
}
const A = wallet("7");
const B = wallet("8");

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}
function skip(name, why) {
  results.push({ name, ok: true, skipped: true });
  console.log(`SKIP  ${name} — ${why}`);
}

async function req(pathname, { method = "GET", headers = {}, body, cookie, origin } = {}) {
  const h = { ...headers };
  if (body !== undefined) h["content-type"] = "application/json";
  if (cookie) h["cookie"] = cookie;
  if (origin !== undefined) h["origin"] = origin;
  const res = await fetch(`${ORIGIN}${pathname}`, {
    method,
    headers: h,
    body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
    redirect: "manual"
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON */
  }
  return { status: res.status, headers: res.headers, text, json, setCookie: res.headers.getSetCookie ? res.headers.getSetCookie() : [] };
}

/* Full Schnorr sign-in for a wallet; returns its session cookie pair. */
async function signIn(w) {
  const ch = await req("/api/v1/auth/challenge", { method: "POST", origin: ORIGIN, body: { walletAddress: w.address } });
  if (ch.status !== 200) throw new Error(`challenge failed: ${ch.status} ${ch.text.slice(0, 200)}`);
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  const ver = await req("/api/v1/auth/verify", {
    method: "POST",
    origin: ORIGIN,
    body: { nonce: ch.json.challenge.nonce, signature, publicKey: w.publicKeyHex, walletAddress: w.address }
  });
  if (ver.status !== 200) throw new Error(`verify failed: ${ver.status} ${ver.text.slice(0, 200)}`);
  const sc = ver.setCookie.find((c) => c.includes("pv_session"));
  if (!sc) throw new Error("no session Set-Cookie");
  const cookie = sc.split(";")[0];
  return { cookie, setCookie: sc, session: ver.json.session };
}

(async () => {
  /* 1. static application */
  {
    const r = await req("/");
    check("static: GET / serves the application", r.status === 200 && /PolicyVault/i.test(r.text), `status ${r.status}`);
    check("static: CSP self (no inline scripts)", (r.headers.get("content-security-policy") || "").includes("script-src 'self'"));
    check("static: nosniff + no-referrer + COOP + CORP", r.headers.get("x-content-type-options") === "nosniff" && r.headers.get("referrer-policy") === "no-referrer" && r.headers.get("cross-origin-opener-policy") === "same-origin" && r.headers.get("cross-origin-resource-policy") === "same-origin");
    check("static: Cache-Control no-cache (stale-build protection)", (r.headers.get("cache-control") || "").includes("no-cache"));
    if (ORIGIN.startsWith("https:")) {
      check("static: HSTS declared on the https origin", (r.headers.get("strict-transport-security") || "").includes("max-age="));
    }
  }

  /* 2. health + readiness + PRODUCTION identity */
  {
    const h = await req("/api/v1/health");
    check(`health: ok on ${NETWORK} with hosted auth`, h.status === 200 && h.json.ok === true && h.json.networkId === NETWORK && h.json.authMode === "enabled", JSON.stringify(h.json));
    check("health: production identity (no staging banner)", h.json.staging !== true, `staging=${h.json.staging}`);
    check(`health: exact build identity ${EXPECT_BUILD}`, h.json.buildId === EXPECT_BUILD, `buildId=${h.json.buildId}`);
    const rd = await req("/api/v1/health/ready");
    check("readiness: ready:true (DB reachable, schema current, stamp ok)", rd.status === 200 && rd.json.ready === true && rd.json.persistence === "postgres", JSON.stringify(rd.json));
    check(`readiness: exact build identity ${EXPECT_BUILD}`, rd.json && rd.json.buildId === EXPECT_BUILD, `buildId=${rd.json && rd.json.buildId}`);
  }

  /* 3. API security headers */
  {
    const r = await req("/api/v1/health");
    check("api: Cache-Control no-store", r.headers.get("cache-control") === "no-store");
    check("api: CSP none + frame deny", (r.headers.get("content-security-policy") || "").includes("default-src 'none'") && r.headers.get("x-frame-options") === "DENY");
    check("api: NO CORS grants", r.headers.get("access-control-allow-origin") === null);
  }

  /* 4. Origin / CSRF gate (state-changing requests) */
  {
    const foreign = await req("/api/v1/identity/resolve-address", { method: "POST", origin: "https://evil.example", body: { address: A.address } });
    check("origin: foreign Origin refused (403)", foreign.status === 403, `status ${foreign.status}`);
    const nullOrigin = await req("/api/v1/identity/resolve-address", { method: "POST", origin: "null", body: { address: A.address } });
    check("origin: Origin null refused (403)", nullOrigin.status === 403, `status ${nullOrigin.status}`);
    const none = await req("/api/v1/identity/resolve-address", { method: "POST", body: { address: A.address } });
    check("origin: absent Origin without Sec-Fetch refused (403 ORIGIN_REQUIRED)", none.status === 403 && none.json?.error?.code === "ORIGIN_REQUIRED", `status ${none.status} code ${none.json?.error?.code}`);
    const good = await req("/api/v1/identity/resolve-address", { method: "POST", origin: ORIGIN, body: { address: A.address } });
    check("origin: correct application Origin accepted", good.status === 200, `status ${good.status}`);
    const mismatchSecFetch = await req("/api/v1/identity/resolve-address", { method: "POST", origin: "https://evil.example", headers: { "sec-fetch-site": "same-origin" }, body: { address: A.address } });
    check("origin: mismatched Origin never rescued by Sec-Fetch", mismatchSecFetch.status === 403, `status ${mismatchSecFetch.status}`);
  }

  /* 5. REAL Schnorr wallet authentication + cookie posture */
  let sessA;
  {
    sessA = await signIn(A);
    const sc = sessA.setCookie;
    const httpsOrigin = ORIGIN.startsWith("https:");
    check("auth: real Schnorr sign-in issues a session", Boolean(sessA.cookie), sessA.session && sessA.session.walletAddress === A.address ? "wallet bound" : "UNBOUND");
    check("auth: cookie HttpOnly + SameSite=Strict + Path=/api", /httponly/i.test(sc) && /samesite=strict/i.test(sc) && /path=\/api/i.test(sc), sc.replace(/pv_session=[0-9a-f]+/i, "pv_session=<redacted>"));
    if (httpsOrigin) {
      check("auth: Secure + __Secure- prefix on the https origin", /secure/i.test(sc) && sc.startsWith("__Secure-pv_session="), sc.split("=")[0]);
    }
    const restore = await req("/api/v1/auth/session", { cookie: sessA.cookie });
    check("auth: session restore returns the bound wallet", restore.status === 200 && restore.json.authenticated === true && restore.json.walletAddress === A.address);
    const noCookie = await req("/api/v1/auth/session");
    check("auth: no cookie -> unauthenticated (no cache reuse of A's session)", noCookie.status === 200 && noCookie.json.authenticated === false);
  }

  /* 6. tenant isolation: A's organization is invisible to B */
  {
    const created = await req("/api/v1/organizations", { method: "POST", origin: ORIGIN, cookie: sessA.cookie, body: { name: `prod-acc-${Date.now()}` } });
    check("tenancy: authenticated org create succeeds", created.status === 201, `status ${created.status}`);
    const orgId = created.json?.organization?.orgId;
    const unauth = await req(`/api/v1/organizations/${orgId}`);
    check("tenancy: unauthenticated read refused", unauth.status === 401 || unauth.status === 404, `status ${unauth.status}`);
    const sessB = await signIn(B);
    const foreign = await req(`/api/v1/organizations/${orgId}`, { cookie: sessB.cookie });
    check("tenancy: foreign tenant gets 404 (existence hidden)", foreign.status === 404, `status ${foreign.status}`);
    const mine = await req(`/api/v1/organizations/${orgId}`, { cookie: sessA.cookie });
    check("tenancy: owner still reads its own org", mine.status === 200, `status ${mine.status}`);
    const listB = await req("/api/v1/organizations", { cookie: sessB.cookie });
    const leaked = (listB.json?.organizations || []).some((o) => o.orgId === orgId);
    check("tenancy: B's listing never contains A's org", listB.status === 200 && !leaked);
    // edge cache cross-tenant: same PATH, different cookies, different bodies
    const aView = await req("/api/v1/auth/session", { cookie: sessA.cookie });
    const bView = await req("/api/v1/auth/session", { cookie: sessB.cookie });
    check("cache: same path returns per-user bodies (no cross-tenant cache)", aView.json.walletAddress === A.address && bView.json.walletAddress === B.address);
    // logout then private route: no stale authenticated content
    await req("/api/v1/auth/logout", { method: "POST", origin: ORIGIN, cookie: sessB.cookie });
    const afterLogout = await req("/api/v1/auth/session", { cookie: sessB.cookie });
    check("cache: logout leaves no stale authenticated response", afterLogout.json.authenticated === false);
  }

  /* 6b. STRICTLY READ-ONLY foreign-data isolation probes on real records.
   *     The test wallet is NOT a participant of the designated vault, so
   *     hosted tenancy must hide the vault and its request entirely:
   *     absent from every list, 404 by id (existence hidden). GET only —
   *     no mutation is ever attempted on real production data. */
  if (FOREIGN_VAULT || FOREIGN_REQUEST) {
    const vl = await req("/api/v1/vaults", { cookie: sessA.cookie });
    check("isolation: authenticated vault list serves (200)", vl.status === 200, `status ${vl.status}`);
    if (FOREIGN_VAULT) {
      const seen = JSON.stringify(vl.json || {}).includes(FOREIGN_VAULT);
      check("isolation: foreign vault ABSENT from unrelated wallet's vault list", vl.status === 200 && !seen, `${(vl.json?.vaults || []).length} vaults listed`);
      const byId = await req(`/api/v1/vaults/${FOREIGN_VAULT}`, { cookie: sessA.cookie });
      check("isolation: foreign vault by-id 404 (existence hidden)", byId.status === 404, `status ${byId.status}`);
    }
    const rl = await req("/api/v1/wallet/v4/requests?open=1", { cookie: sessA.cookie });
    check("isolation: open-request inbox serves (200)", rl.status === 200, `status ${rl.status}`);
    if (FOREIGN_REQUEST) {
      const seenR = JSON.stringify(rl.json || {}).includes(FOREIGN_REQUEST);
      check("isolation: foreign request ABSENT from unrelated wallet's inbox", rl.status === 200 && !seenR);
      const rById = await req(`/api/v1/wallet/v4/requests/${FOREIGN_REQUEST}`, { cookie: sessA.cookie });
      check("isolation: foreign request by-id 404 (non-disclosing)", rById.status === 404, `status ${rById.status}`);
    }
  } else {
    skip("foreign-data isolation probes", "no --foreign-vault/--foreign-request designated");
  }

  /* 7. body caps */
  {
    let bigDetail;
    let bigRefused = false;
    try {
      const big = await req("/api/v1/identity/resolve-address", { method: "POST", origin: ORIGIN, body: JSON.stringify({ address: "x".repeat(1_100_000) }) });
      bigRefused = big.status === 413 || big.status === 400 || (EDGE && (big.status === 502 || big.status === 520));
      bigDetail = `status ${big.status}`;
    } catch {
      bigRefused = true;
      bigDetail = "connection destroyed mid-upload (refusal)";
    }
    check("caps: >1MB body refused", bigRefused, bigDetail);
    const aliveAfterBig = await req("/api/v1/health");
    check("caps: app healthy after oversize-body refusal", aliveAfterBig.status === 200 && aliveAfterBig.json?.ok === true, `status ${aliveAfterBig.status}`);
    let deep = "1";
    for (let i = 0; i < 80; i++) deep = `{"a":${deep}}`;
    const deepR = await req("/api/v1/identity/resolve-address", { method: "POST", origin: ORIGIN, body: deep });
    check("caps: deep JSON refused (BODY_TOO_DEEP)", deepR.status === 400 && deepR.json?.error?.code === "BODY_TOO_DEEP", `status ${deepR.status} code ${deepR.json?.error?.code}`);
  }

  /* 8. edge cache posture (Cloudflare) */
  if (EDGE) {
    const api1 = await req("/api/v1/health");
    const cfApi = api1.headers.get("cf-cache-status");
    check("edge: API not cached (cf-cache-status DYNAMIC/BYPASS/absent)", cfApi === null || /DYNAMIC|BYPASS|MISS/i.test(cfApi), `cf-cache-status=${cfApi}`);
    check("edge: served via Cloudflare (cf-ray present)", api1.headers.get("cf-ray") !== null, `cf-ray=${api1.headers.get("cf-ray")}`);
    const s1 = await req("/");
    const s2 = await req("/");
    const cfS = s2.headers.get("cf-cache-status");
    check("edge: app HTML revalidated, never HIT-served stale", cfS === null || !/^HIT$/i.test(cfS), `cf-cache-status=${cfS}`);
  } else {
    skip("edge cache posture", "not running behind the edge (--edge not set)");
  }

  /* 9. rate limiting + trusted-proxy spoof resistance (see
   *    staging-acceptance.js for the measured edge semantics). LAST among
   *    authenticated stages: the spray exhausts the auth budget. */
  if (EDGE) {
    let got429 = null;
    let attempts = 0;
    for (let i = 0; i < 140 && !got429; i++) {
      attempts += 1;
      const r = await req("/api/v1/auth/challenge", { method: "POST", origin: ORIGIN, body: { walletAddress: A.address } });
      if (r.status === 429) got429 = r;
    }
    check("rate limit: clean spray hits 429 through the edge", Boolean(got429), `429 after ${attempts} attempts`);
    if (got429) {
      check("rate limit: Retry-After present", got429.headers.get("retry-after") !== null, `retry-after=${got429.headers.get("retry-after")}`);
    }
    const spoof = await req("/api/v1/auth/challenge", {
      method: "POST",
      origin: ORIGIN,
      headers: { "cf-connecting-ip": "203.0.113.7" },
      body: { walletAddress: A.address }
    });
    check("rate limit: spoofed CF-Connecting-IP cannot escape the throttle (403 edge refusal or 429; never 200)", spoof.status === 403 || spoof.status === 429, `status ${spoof.status}`);
  } else {
    let got429 = null;
    let attempts = 0;
    for (let i = 0; i < 140 && !got429; i++) {
      attempts += 1;
      const r = await req("/api/v1/auth/challenge", {
        method: "POST",
        origin: ORIGIN,
        headers: { "cf-connecting-ip": `203.0.113.${i % 250}` },
        body: { walletAddress: A.address }
      });
      if (r.status === 429) got429 = r;
    }
    check("rate limit: spray hits 429 despite spoofed CF-Connecting-IP", Boolean(got429), `429 after ${attempts} attempts`);
    if (got429) {
      check("rate limit: Retry-After present", got429.headers.get("retry-after") !== null, `retry-after=${got429.headers.get("retry-after")}`);
    }
  }

  /* 10. direct-socket checks (local origin only — the edge absorbs these) */
  if (!EDGE && baseUrl.protocol === "http:") {
    const port = Number(baseUrl.port || 80);
    const hostResp = await new Promise((resolve) => {
      const sock = net.connect(port, baseUrl.hostname, () => {
        sock.write(`GET /api/v1/health HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n`);
      });
      let buf = "";
      sock.on("data", (d) => (buf += d));
      sock.on("close", () => resolve(buf));
      sock.on("error", () => resolve(""));
      setTimeout(() => sock.destroy(), 5000);
    });
    check("host gate: foreign Host refused on a direct connection (421)", hostResp.includes("421") && hostResp.includes("HOST_FORBIDDEN"), hostResp.split("\r\n")[0]);
    const t0 = Date.now();
    const slowKilled = await new Promise((resolve) => {
      const sock = net.connect(port, baseUrl.hostname, () => {
        sock.write("GET /api/v1/health HTTP/1.1\r\nHos"); // never finish headers
      });
      sock.on("close", () => resolve(true));
      sock.on("error", () => resolve(true));
      setTimeout(() => {
        sock.destroy();
        resolve(false);
      }, 25_000);
    });
    check("slow client: stalled headers connection destroyed by deadline", slowKilled, `${Date.now() - t0}ms`);
  } else {
    skip("direct-socket host/slow-client checks", "running through the edge (tested against the local origin instead)");
  }

  const failures = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failures.length}/${results.length} checks passed${failures.length ? ` — ${failures.length} FAILED` : ""}`);
  process.exit(failures.length ? 1 : 0);
})().catch((e) => {
  console.error(`prod-acceptance: ${e.message}`);
  process.exit(1);
});
