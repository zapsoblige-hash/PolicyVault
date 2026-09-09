"use strict";

/*
 * FRESH-BROWSER first-run acceptance for the onboarding walkthrough + the
 * Refresh-button removal (owner directive 2026-09-03, successor from the
 * rc8 lineage). Drives the SERVED BYTES of a running PolicyVault origin
 * (a real local server started from this tree, or --base-url <origin> for
 * a running candidate container) inside jsdom with a GENUINELY FRESH
 * localStorage per browser instance — first-run behaviour is proven, not
 * assumed. Nothing here signs, spends, or touches auth/financial state:
 * it is a presentation acceptance.
 *
 *   node tools/web-first-run-acceptance.js                    # spawns a real server from this tree
 *   node tools/web-first-run-acceptance.js --base-url http://127.0.0.1:3080   # running candidate
 */

const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { JSDOM, VirtualConsole } = require(require.resolve("jsdom", { paths: [path.join(__dirname, "..", "sdk")] }));

const REPO = path.join(__dirname, "..");
const args = process.argv.slice(2);
const baseArg = args.indexOf("--base-url");
let baseUrl = baseArg >= 0 ? args[baseArg + 1] : null;
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: Boolean(ok), detail: detail ?? null });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startLocalServer() {
  const { loadConfig } = require(path.join(REPO, "sdk/src/config"));
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-firstrun-"));
  const config = loadConfig({ dataRoot, networkId: "testnet-10" });
  const { createServer } = require(path.join(REPO, "server/src/server"));
  const server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

/* One "browser": fresh jsdom window; `seedStorage` simulates a RETURNING
 * browser whose localStorage persisted (jsdom instances never share storage). */
async function browser({ html, seedStorage = null, width = 1280 }) {
  const fetchLog = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", () => {});
  const dom = new JSDOM(html, {
    url: `${baseUrl}/`,
    runScripts: "dangerously",
    resources: "usable",
    pretendToBeVisual: true,
    virtualConsole,
    beforeParse(window) {
      Object.defineProperty(window, "innerWidth", { value: width, configurable: true });
      window.matchMedia = (q) => ({ matches: q.includes("max-width") ? width <= 720 : false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
      window.fetch = async (input, init) => {
        const u = typeof input === "string" ? input : input.url;
        const abs = u.startsWith("http") ? u : `${baseUrl}${u.startsWith("/") ? "" : "/"}${u}`;
        fetchLog.push(new URL(abs).pathname);
        const r = await fetch(abs, init);
        const text = await r.text();
        return { ok: r.ok, status: r.status, headers: r.headers, json: async () => JSON.parse(text), text: async () => text };
      };
      if (seedStorage) for (const [k, v] of Object.entries(seedStorage)) window.localStorage.setItem(k, v);
    }
  });
  await new Promise((resolve) => dom.window.addEventListener("load", resolve));
  await sleep(1500); // boot + banner verification round trips
  return { dom, window: dom.window, document: dom.window.document, fetchLog };
}

async function main() {
  let local = null;
  if (!baseUrl) {
    local = await startLocalServer();
    baseUrl = local.url;
  }
  const html = await (await fetch(`${baseUrl}/`)).text();
  const appJs = await (await fetch(`${baseUrl}/app.js`)).text();
  const health = await (await fetch(`${baseUrl}/api/v1/health`)).json();
  console.log(`origin ${baseUrl} buildId ${health.buildId ?? "?"} network ${health.networkId ?? health.network ?? "?"}`);

  // ---- served-bytes facts (independent of any browser state) ----
  check("served index.html has NO Refresh button", !/id="refresh"/.test(html) && !/>Refresh</.test(html));
  check("served app.js has NO refresh click handler (no orphan listener)", !/\$\("refresh"\)/.test(appJs) && !/getElementById\("refresh"\)/.test(appJs));
  check("served app.js still loads orgs/vaults on navigation (loaders intact)", /loadOrgs\(\)/.test(appJs) && /loadVaults\(\)/.test(appJs));
  check("Docs link remains (top bar)", /href="https:\/\/docs\.policy-vault\.org"[^>]*>Docs</.test(html));
  check("Help menu with 'How PolicyVault works' replay + Documentation", /id="pv-help-replay"/.test(html) && /pv-help-menu/.test(html) && /docs\.policy-vault\.org/.test(html));
  check("persistent discovery entry on the home view", /id="pv-onb-home-btn"/.test(html));
  check("reduced-motion rule shipped", /prefers-reduced-motion: reduce/.test(html));
  check("responsive/mobile rules shipped (dialog max-height dvh + media queries)", /max-height: 90dvh/.test(html) && /@media \(max-width/.test(html));
  // v0.7 ON-CHAIN ORGANIZATIONAL ROOT (Wave 2, Track B-web): the module is
  // served, and app-v4.js degrades gracefully — never crashes, never a
  // broken half-render — when the server has no /org-roots route yet (the
  // server lane's own contract §2 build lands on a separate track).
  check("served org-root-ui.js is reachable", (await fetch(`${baseUrl}/org-root-ui.js`)).ok);
  check("index.html loads org-root-ui.js before app-v4.js", (() => {
    const i1 = html.indexOf('src="/org-root-ui.js"');
    const i2 = html.indexOf('src="/app-v4.js"');
    return i1 > -1 && i2 > -1 && i1 < i2;
  })());

  // ---- browser 1: GENUINELY FRESH localStorage → first-run walkthrough ----
  const b1 = await browser({ html });
  const dlg = b1.document.getElementById("pv-onboarding");
  const shown1 = dlg && !dlg.hidden;
  check("FRESH browser: first-run walkthrough opens automatically", shown1, `hidden=${dlg ? dlg.hidden : "no element"}`);
  const text1 = dlg ? dlg.textContent : "";
  check("walkthrough explains wallet vs PolicyVault", /not a wallet/i.test(text1) || /never holds your funds/i.test(text1));
  const stepsSeen = [];
  let allText = "";
  for (let i = 0; i < 8; i++) {
    allText += ` ${dlg.textContent}`;
    const next = [...dlg.querySelectorAll("button")].find((b) => /^(Next|Continue|Finish|Done|Got it)/i.test(b.textContent.trim()));
    stepsSeen.push(dlg.textContent.slice(0, 80));
    if (!next) break;
    if (/Finish|Done|Got it/i.test(next.textContent)) break;
    next.click();
    await sleep(50);
  }
  check("walkthrough shows accepted / refused / needs-approval examples (across all steps)", /Accepted/i.test(allText) && /Refused/i.test(allText) && /approv/i.test(allText), `${stepsSeen.length} steps walked`);
  check("FRESH browser: Refresh button absent (desktop 1280px)", b1.document.getElementById("refresh") === null);
  check("FRESH browser: Docs link present in DOM", Boolean(b1.document.querySelector('a.btnlink[href="https://docs.policy-vault.org"]')));
  const bannerEl = b1.document.querySelector("[data-network-banner], #network-banner, #net-banner, .network-banner") || b1.document.body;
  const bannerText = (b1.window.PolicyVaultNetworkBanner && b1.window.PolicyVaultNetworkBanner.state ? JSON.stringify(b1.window.PolicyVaultNetworkBanner.state()) : bannerEl.textContent).slice(0, 200);
  const statusCalls1 = b1.fetchLog.filter((p) => p.endsWith("/network/status")).length;
  check("network/status indicator verified on boot (real /network/status fetched)", statusCalls1 >= 1, `calls=${statusCalls1}`);
  if (b1.window.PolicyVaultNetworkBanner && typeof b1.window.PolicyVaultNetworkBanner.refresh === "function") {
    b1.window.PolicyVaultNetworkBanner.refresh();
    await sleep(800);
    const statusCalls2 = b1.fetchLog.filter((p) => p.endsWith("/network/status")).length;
    check("network/status indicator keeps updating (explicit banner refresh re-fetches)", statusCalls2 > statusCalls1, `calls ${statusCalls1}→${statusCalls2}`);
  } else {
    check("network banner API present", false, "PolicyVaultNetworkBanner.refresh missing");
  }
  check("no request to /wallet/dev-accounts and no privileged reads while signed out", !b1.fetchLog.some((p) => p.includes("dev-accounts")), b1.fetchLog.join(","));
  // Skip → closes; record written without dontShowAgain
  const skip = [...b1.document.querySelectorAll("#pv-onboarding button")].find((b) => b.textContent.trim() === "Skip");
  if (skip) skip.click();
  await sleep(50);
  const rec1 = JSON.parse(b1.window.localStorage.getItem("pv.onboarding") || "null");
  check("Skip closes the walkthrough and persists a record (not dontShowAgain)", skip && b1.document.getElementById("pv-onboarding").hidden && rec1 && rec1.dontShowAgain === false, JSON.stringify(rec1));
  // Help → replay works after skip
  const help = b1.document.getElementById("pv-help-btn");
  if (help) help.click();
  await sleep(30);
  const replay = b1.document.getElementById("pv-help-replay");
  if (replay) replay.click();
  await sleep(50);
  check("Help → 'How PolicyVault works' replays the walkthrough", replay && !b1.document.getElementById("pv-onboarding").hidden);
  const homeBtn = b1.document.getElementById("pv-onb-home-btn");
  check("persistent discovery entry present after first run", Boolean(homeBtn));
  b1.dom.window.close();

  // ---- browser 2: returning browser with "Don't show again" persisted ----
  const seeded = { "pv.onboarding": JSON.stringify({ onboardingVersion: rec1 ? rec1.onboardingVersion : 1, completed: true, dontShowAgain: true }) };
  const b2 = await browser({ html, seedStorage: seeded });
  check("RETURNING browser with Don't-show-again: walkthrough NOT auto-shown", b2.document.getElementById("pv-onboarding").hidden === true);
  const help2 = b2.document.getElementById("pv-help-btn");
  if (help2) help2.click();
  await sleep(30);
  const replay2 = b2.document.getElementById("pv-help-replay");
  if (replay2) replay2.click();
  await sleep(50);
  check("RETURNING browser: replay via Help still works", replay2 && !b2.document.getElementById("pv-onboarding").hidden);
  b2.dom.window.close();

  // ---- browser 3: fresh again, mobile width; Don't-show-again checkbox path ----
  const b3 = await browser({ html, width: 375 });
  check("FRESH mobile browser (375px): walkthrough opens", !b3.document.getElementById("pv-onboarding").hidden);
  check("FRESH mobile browser: Refresh button absent", b3.document.getElementById("refresh") === null);
  const dsa = b3.document.getElementById("pv-onb-dsa");
  if (dsa) {
    dsa.checked = true;
    dsa.dispatchEvent(new b3.window.Event("change", { bubbles: true }));
  }
  await sleep(30);
  const rec3 = JSON.parse(b3.window.localStorage.getItem("pv.onboarding") || "null");
  check("'Don't show this again' checkbox persists dontShowAgain=true", dsa && rec3 && rec3.dontShowAgain === true, JSON.stringify(rec3));
  b3.dom.window.close();

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (local) local.server.close();
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => {
  console.error("FAILED:", e.stack ?? e.message);
  process.exit(1);
});
