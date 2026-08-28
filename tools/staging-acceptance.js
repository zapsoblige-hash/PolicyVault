"use strict";

/*
 * PHASE E AUTOMATED STAGING ACCEPTANCE (directive §54).
 *
 * Drives the REAL hosted deployment from the OUTSIDE — either the local
 * hosted simulation (http://127.0.0.1:3080) or the external staging URL
 * (https://<name>.trycloudflare.com) — and verifies the externally
 * observable security posture: static app, health/readiness, security
 * headers, Origin/CSRF gate, REAL Schnorr wallet authentication (test
 * harness identities; NOT Phase G human KasWare acceptance), session
 * cookies, tenant isolation with two wallets, rate limiting, body caps,
 * API cache posture, and trusted-proxy spoof resistance.
 *
 * TESTNET-10 ONLY. The two wallet identities are deterministic
 * throwaway TEST keys (never funded mainnet keys).
 *
 * Usage:
 *   node tools/staging-acceptance.js <baseUrl> [--edge] [--save-session FILE] [--check-session FILE]
 *     --edge          expect Cloudflare in front (adds edge-specific checks,
 *                     skips direct-socket checks that the edge absorbs)
 *     --save-session  after the auth flow, save wallet A's cookie to FILE
 *                     (used by the restart-persistence stage test)
 *     --check-session verify a previously saved cookie is STILL a valid
 *                     session (app-restart persistence proof), then exit
 * Exit 0 = all checks passed; 1 = failures (listed).
 */

const fs = require("fs");
const net = require("net");
const path = require("path");
const { URL } = require("url");

const args = process.argv.slice(2);
const BASE = args[0];
if (!BASE || !/^https?:\/\//.test(BASE)) {
  console.error("usage: node tools/staging-acceptance.js <baseUrl> [--edge] [--save-session FILE] [--check-session FILE]");
  process.exit(2);
}
const EDGE = args.includes("--edge");
const flagValue = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};
const SAVE_SESSION = flagValue("--save-session");
const CHECK_SESSION = flagValue("--check-session");
const baseUrl = new URL(BASE);
const ORIGIN = baseUrl.origin;

const { loadConfig } = require(path.join(__dirname, "..", "sdk", "src", "config"));
const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(require("os").tmpdir(), "pv-acc-")) });
const kaspa = require(config.rustyKaspaModule);

/* Deterministic TEST wallets (throwaway; testnet only). */
function wallet(hexDigit) {
  const priv = new kaspa.PrivateKey(hexDigit.repeat(64));
  const pub = priv.toPublicKey();
  return {
    priv,
    publicKeyHex: pub.toString(),
    address: pub.toAddress("testnet-10").toString()
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
  /* --check-session mode: restart-persistence verification only. */
  if (CHECK_SESSION) {
    const saved = fs.readFileSync(CHECK_SESSION, "utf8").trim();
    const r = await req("/api/v1/auth/session", { cookie: saved });
    check("app-restart session persistence (PG-backed)", r.status === 200 && r.json && r.json.authenticated === true, `status ${r.status} authenticated=${r.json && r.json.authenticated}`);
    const bad = results.filter((r2) => !r2.ok);
    process.exit(bad.length ? 1 : 0);
  }

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

  /* 2. health + readiness + staging identity */
  {
    const h = await req("/api/v1/health");
    check("health: ok on testnet-10 with hosted auth", h.status === 200 && h.json.ok === true && h.json.networkId === "testnet-10" && h.json.authMode === "enabled", JSON.stringify(h.json));
    check("health: staging identity declared", h.json.staging === true, "POLICYVAULT_STAGING_BANNER");
    check("health: build identity present", typeof h.json.buildId === "string" && h.json.buildId.length > 0, `buildId=${h.json.buildId}`);
    const rd = await req("/api/v1/health/ready");
    check("readiness: ready:true (DB reachable, schema current, stamp ok)", rd.status === 200 && rd.json.ready === true && rd.json.persistence === "postgres", JSON.stringify(rd.json));
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
    const created = await req("/api/v1/organizations", { method: "POST", origin: ORIGIN, cookie: sessA.cookie, body: { name: `staging-acc-${Date.now()}` } });
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

  /* 7. body caps */
  {
    // The origin refuses an oversize body with 413 AND destroys the
    // socket (it will not keep receiving) — depending on timing the
    // client observes the 413 or a connection reset. Both are refusals.
    let bigDetail;
    let bigRefused = false;
    try {
      const big = await req("/api/v1/identity/resolve-address", { method: "POST", origin: ORIGIN, body: JSON.stringify({ address: "x".repeat(1_100_000) }) });
      // Through the edge the origin's 413 + mid-upload socket destroy is
      // translated by Cloudflare into a 5xx toward the client (502
      // observed on the real Phase E-R tunnel) — the refusal still
      // happened at the origin, which never drains hostile oversize
      // bodies. Accept the edge translation ONLY in edge mode; the app
      // must prove it stayed healthy right after (next check).
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

  /* 9. rate limiting + trusted-proxy spoof resistance.
   *    The auth class budget is 60/10min. Spray challenges while VARYING
   *    a client-supplied CF-Connecting-IP: if the platform lets a client
   *    spoof its identity, the per-IP bucket resets and no 429 appears
   *    within a bounded spray. Through Cloudflare the header is
   *    overwritten by the edge; locally the proxy header must be
   *    UNCONFIGURED (no proxy) — both must yield a deterministic 429.
   */
  if (EDGE) {
    /* Measured on the real tunnel (Phase E header probe + Phase E-R):
     * Cloudflare REFUSES a request carrying a client-supplied
     * CF-Connecting-IP at the edge (403) — the spoof never reaches the
     * origin at all, so a spoofed spray can never produce an origin
     * 429. Through the edge the limiter is therefore proven in two
     * sharp steps: (1) a CLEAN spray from the real client identity
     * terminates in 429 (limits operate through Cloudflare on the
     * trusted identity); (2) with the bucket exhausted, a
     * spoofed-header attempt must STILL not obtain a 200 — it is
     * either 403 (edge refusal, this edge's behavior) or 429 (an edge
     * that overwrites the header lands the spoof in the same real-IP
     * bucket). Either way, spoofing the trusted client-IP identity
     * cannot escape the throttle. */
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
    // foreign Host on a direct connection
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
    // slow client: stalled headers get destroyed by the deadline
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

  if (SAVE_SESSION && sessA) {
    fs.writeFileSync(SAVE_SESSION, sessA.cookie + "\n", { mode: 0o600 });
    console.log(`session cookie saved for restart-persistence check: ${SAVE_SESSION}`);
  }

  const failures = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failures.length}/${results.length} checks passed${failures.length ? ` — ${failures.length} FAILED` : ""}`);
  process.exit(failures.length ? 1 : 0);
})().catch((e) => {
  console.error(`staging-acceptance: ${e.message}`);
  process.exit(1);
});
