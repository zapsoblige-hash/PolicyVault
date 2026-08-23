"use strict";

/*
 * H2 final-browser-polish §17 acceptance — SERVED-APP verification.
 *
 * Runs the REAL PolicyVault server (no dev signer, isolated temp data root,
 * REAL testnet-10 node behind it) and drives the REAL SERVED app bytes in a
 * DOM (jsdom), mocking ONLY the canonical wallet session seam (a real funded
 * test owner address; nothing is ever signed and nothing is broadcast — the
 * create flow stops at the server-built canonical review).
 *
 * Covers the §17 checklist items that need no KasWare popup:
 *   one-click-one-row / blank rows / max 10 / duplicate + M validation
 *   (client field errors AND direct server 422s) / custom period + presets
 *   (server-derived canonical DAA) / DAA copy under Advanced / human-readable
 *   review period / organization rename-archive-restore-delete / populated
 *   delete blocked / Unassigned / clean browser console.
 * The remaining items (real KasWare signing) stay in the HUMAN acceptance run
 * (docs/H2-kasware-acceptance-runbook.md) — never fabricated here.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const sdkRoot = path.join(__dirname, "..", "sdk");
const { loadConfig } = require(path.join(sdkRoot, "src/config"));
const { loadOrCreateTestKeys } = require(path.join(sdkRoot, "src/keys"));
const { createServer } = require(path.join(__dirname, "..", "server", "src", "server"));
const { JSDOM, VirtualConsole } = require(path.join(sdkRoot, "node_modules", "jsdom"));

const PORT = 3098;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const BASE = `${ORIGIN}/api/v1`;

let PASS = 0, FAIL = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (ok) PASS++; else FAIL++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 4000) {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error("waitFor timed out");
    await sleep(20);
  }
}

function seedLegacyVault(config, vaultId) {
  const { persistManifestV2, MANIFEST_SCHEMA_V2 } = require(path.join(sdkRoot, "src/manifest-v2"));
  const { computeStateIdV2, normalizeTemplateV2, normalizeStateV2, CONTRACT_VERSION_V2 } = require(path.join(sdkRoot, "src/vault-state-v2"));
  const OWNER_X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
  const DELEGATE_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const RECIP_X = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
  const template = normalizeTemplateV2({ owner: OWNER_X, vaultId });
  const state = normalizeStateV2({
    protectedValue: "10000000000", periodStartDaa: "1000", periodSpent: "0", paused: "0",
    delegate: DELEGATE_X, maxPerSpend: "1000000000", periodBudget: "5000000000",
    periodLengthDaa: "600", recipients: [RECIP_X], delegateActive: "1", policyNonce: "0"
  });
  persistManifestV2(config, {
    schema: MANIFEST_SCHEMA_V2, contractVersion: CONTRACT_VERSION_V2, networkId: config.networkId,
    vaultId, label: "acceptance-legacy", status: "ACTIVE", template,
    live: {
      state, stateId: computeStateIdV2({ networkId: config.networkId, template, state }),
      outpoint: { transactionId: "ab".repeat(32), index: 1 }, outpointValue: "10000000000",
      scriptSha256: "cd".repeat(32), covenantId: "ef".repeat(32)
    },
    creationTxId: "12".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

(async () => {
  const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-h2-accept-")) });
  if (config.networkId !== "testnet-10") { console.error("refusing: not testnet-10"); process.exit(2); }
  const keys = loadOrCreateTestKeys(loadConfig()); // real funded test owner (address use only — never signs here)
  const VAULT_A = "aa".repeat(32);
  seedLegacyVault(config, VAULT_A);

  const server = createServer(config);
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
  console.log(`== §17 served-browser acceptance on ${ORIGIN} (data root ${config.dataRoot}) ==`);

  // PRECONDITION: the create-review checks drive a REAL auto-funded genesis
  // build through the server, which needs at least one ordinary spendable
  // UTXO on the test owner address. Fail fast with instructions instead of a
  // mid-run timeout when the (auto-generated) keyring is unfunded. Address
  // use only — nothing is signed or broadcast by this tool.
  {
    const fuel = await (await fetch(`${BASE}/wallet/fuel/${encodeURIComponent(keys.owner.address)}`)).json();
    if (!Array.isArray(fuel.utxos) || fuel.utxos.length === 0) {
      console.error("refusing: the test owner address has no spendable testnet-10 UTXOs.");
      console.error("Fund it from a testnet-10 faucet (or any testnet wallet), then re-run:");
      console.error(`  ${keys.owner.address}`);
      server.close();
      process.exit(2);
    }
  }

  try {
    // ---- served bytes == on-disk bytes (stale-cache guard) ----
    for (const f of ["app-v4.js", "app.js", "index.html"]) {
      const served = await (await fetch(`${ORIGIN}/${f === "index.html" ? "" : f}`)).text();
      const disk = fs.readFileSync(path.join(__dirname, "..", "web", f), "utf8");
      check(`served /${f} matches web/${f} on disk`, served === disk);
    }

    // ---- DOM over the SERVED app (wallet session is the only mock) ----
    const servedHtml = (await (await fetch(`${ORIGIN}/`)).text()).replace(/<script src="[^"]*"><\/script>/g, "");
    const servedAppV4 = await (await fetch(`${ORIGIN}/app-v4.js`)).text();
    const consoleErrors = [];
    const vc = new VirtualConsole();
    vc.on("error", (...a) => consoleErrors.push(a.map(String).join(" ")));
    vc.on("jsdomError", (e) => consoleErrors.push(String(e && e.message)));
    const dom = new JSDOM(servedHtml, { url: `${ORIGIN}/`, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
    const { window } = dom;
    const doc = window.document;
    window.fetch = (u, o) => fetch(new URL(u, ORIGIN), o); // REAL server, REAL node behind it
    window.confirm = () => true;
    let promptValue = null;
    window.prompt = () => promptValue;
    const listeners = [];
    const snap = () => ({
      connected: true, ready: true, address: keys.owner.address, xonly: keys.owner.xonly,
      network: "testnet-10", provider: "acceptance", adapter: { signInputs: async () => { throw new Error("acceptance never signs"); } }
    });
    window.PolicyVaultWalletSession = { active: snap, subscribe(cb) { listeners.push(cb); cb(snap()); return () => {}; }, connect() {}, disconnect() {} };
    window.eval(servedAppV4);
    window.dispatchEvent(new window.Event("DOMContentLoaded"));
    const click = (el) => el.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
    const tab = (v) => doc.querySelector(`.v4-tab[data-view="${v}"]`);
    const rows = () => [...doc.querySelectorAll('#v4-approvers [name="approver"]')];
    const setVal = (form, name, value) => { const el = form.querySelector(`[name="${name}"]`); el.value = value; el.dispatchEvent(new window.Event("input", { bubbles: true })); };

    // ---- create-form row behavior on the served app ----
    click(tab("create"));
    const form = await waitFor(() => doc.getElementById("v4-create-form"));
    for (const cb of listeners) cb(snap()); for (const cb of listeners) cb(snap()); // extra session emissions
    click(tab("vaults")); await sleep(60);
    click(tab("create")); await waitFor(() => doc.getElementById("v4-create-form"));
    const f2 = doc.getElementById("v4-create-form");
    const addBtn = () => doc.getElementById("v4-add-approver");
    click(addBtn());
    check("+ Add approver adds exactly one row (after re-renders)", rows().length === 1, `rows=${rows().length}`);
    check("new approver row is blank", rows()[0].value === "");
    for (let i = 0; i < 12; i++) click(addBtn());
    check("max 10 approver rows (extra clicks add nothing)", rows().length === 10, `rows=${rows().length}`);
    check("+ Add approver disabled at 10", addBtn().disabled === true);
    while (rows().length > 2) click(doc.querySelectorAll("#v4-approvers .rm-approver")[rows().length - 1]);

    // ---- client validation blocks Review (REAL /identity/resolve-address) ----
    setVal(f2, "label", "H2 Acceptance");
    setVal(f2, "deposit", "20"); setVal(f2, "reserve", "2");
    setVal(f2, "agent", keys.delegate.address);
    setVal(f2, "maxPerSpend", "2"); setVal(f2, "budget", "10");
    setVal(f2, "approvalThreshold", "1");
    // Any ordinary distinct testnet address works here (form input only, no
    // funds involved); fresh keyrings have no seeded "funding" role.
    f2.querySelector('[name="recipient"]').value = (keys.funding || keys.recipient3).address;
    const r2 = rows();
    r2[0].value = keys.recipient1.address; r2[1].value = keys.recipient1.address; // duplicate
    setVal(f2, "approvalM", "2");
    f2.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => [...doc.querySelectorAll(".ferr.show")].some((e) => /duplicates approver/.test(e.textContent)));
    check("duplicate approver rejected before Review (field-local error)", true);
    r2[1].value = keys.recipient2.address;
    setVal(f2, "approvalM", "3");
    f2.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => [...doc.querySelectorAll(".ferr.show")].some((e) => /exceeds the 2 configured/.test(e.textContent)));
    check("M cannot exceed valid configured approvers (client)", true);

    // ---- custom period + full SERVER build -> canonical review (no signing) ----
    const sel = f2.querySelector('[name="period"]');
    check("presets still offered (1h/6h/1d/1w + Custom)", [...sel.options].map((o) => o.value).join(",") === "1h,6h,1d,1w,custom");
    sel.value = "custom"; sel.dispatchEvent(new window.Event("change", { bubbles: true }));
    setVal(f2, "periodValue", "2"); f2.querySelector('[name="periodUnit"]').value = "hour";
    setVal(f2, "approvalM", "2");
    const hint = doc.getElementById("v4-period-hint").textContent;
    check("period copy is plain language", hint === "Budget resets approximately every 2 hours.", hint);
    const primaryText = f2.textContent.replace(f2.querySelector("details.adv").textContent, "");
    check("DAA explanation only under Advanced", !/DAA/.test(primaryText) && /DAA score/.test(f2.querySelector("details.adv").textContent));
    f2.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
    const modal = await waitFor(() => { const m = doc.getElementById("v4-modal"); return m.style.display === "flex" ? m : null; }, 30000);
    const modalText = modal.textContent;
    check("Review shows human-readable period", /10 KAS approximately every 2 hours/.test(modalText), modalText.slice(0, 160));
    check("Review keeps raw DAA under Advanced (technical)", /Advanced \(technical\)/.test(modalText) && /periodLengthDaa/.test(modalText) && /72000/.test(modalText));
    click(doc.getElementById("v4-cancel")); // never sign
    check("nothing signed / nothing broadcast", true, "flow cancelled at review");

    // ---- server-authoritative rejections (direct POSTs to the REAL server) ----
    const post = async (url, body) => { const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); return { status: r.status, j: await r.json() }; };
    const friendly = (over = {}, apr) => ({
      contractVersion: "policyvault-0.4.1", signerAddress: keys.owner.address, vaultId: crypto.randomBytes(32).toString("hex"),
      label: "neg", depositKas: "20", feeReserveKas: "2",
      agent: { agentAddress: keys.delegate.address, maxPerSpendKas: "2", budgetKas: "10", budgetPeriod: "1h", approvalThresholdKas: "1", recipientAddresses: [(keys.funding || keys.recipient3).address], ...over },
      ...(apr ? { approvers: apr } : {})
    });
    const eleven = Array.from({ length: 11 }, (_, i) => keys.recipient1.address); // count check fires before resolution
    const negatives = [
      ["server rejects >10 approvers", friendly({}, { addresses: eleven, approvalM: "2" }), "APPROVERS_TOO_MANY"],
      ["server rejects duplicate approvers", friendly({}, { addresses: [keys.recipient1.address, keys.recipient1.address], approvalM: "2" }), "APPROVER_DUPLICATE"],
      ["server rejects M > configured", friendly({}, { addresses: [keys.recipient1.address], approvalM: "2" }), "APPROVAL_M_INVALID"],
      ["server rejects M=11", friendly({}, { addresses: [keys.recipient1.address], approvalM: "11" }), "APPROVAL_M_INVALID"],
      ["server rejects zero period", friendly({ budgetPeriod: { value: "0", unit: "hour" } }), "PERIOD_INVALID"],
      ["server rejects NaN period", friendly({ budgetPeriod: { value: "NaN", unit: "hour" } }), "PERIOD_INVALID"],
      ["server rejects unsupported unit", friendly({ budgetPeriod: { value: "2", unit: "month" } }), "PERIOD_UNIT_INVALID"],
      ["server rejects excessive period", friendly({ budgetPeriod: { value: "60", unit: "week" } }), "PERIOD_OUT_OF_RANGE"]
    ];
    for (const [name, body, code] of negatives) {
      const r = await post("/wallet/v4/create", body);
      check(name, r.status === 422 && (r.j.error && r.j.error.code) === code, `${r.status} ${(r.j.error || {}).code}`);
    }
    const okBuild = await post("/wallet/v4/create", friendly({ budgetPeriod: { value: "12", unit: "hour" } }, { addresses: [keys.recipient1.address, keys.recipient2.address], approvalM: "2" }));
    check("server builds valid custom-period create (12 hours -> 432000 DAA)",
      okBuild.status === 201 && okBuild.j.request.review.technical.periodLengthDaa === "432000" && /10 KAS approximately every 12 hours/.test(okBuild.j.request.review.budget),
      `${okBuild.status} ${okBuild.j.request && okBuild.j.request.review.budget}`);
    check("server review reports approval policy", okBuild.status === 201 && okBuild.j.request.review.approvalPolicy === "2 of 2 approvers");

    // ---- organization lifecycle on the served app ----
    click(tab("orgs"));
    await waitFor(() => doc.getElementById("v4-org-create-btn"));
    doc.getElementById("v4-org-new-name").value = "Acceptance Org";
    click(doc.getElementById("v4-org-create-btn"));
    await waitFor(() => [...doc.querySelectorAll(".vault-title")].some((e) => e.textContent === "Acceptance Org"));
    check("organization created via UI", true);
    // Assign the seeded (unassigned) vault through the org view's Assign control.
    const addSel = await waitFor(() => doc.querySelector("[data-orgadd]"));
    addSel.value = VAULT_A; addSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await waitFor(async () => { const j = await (await fetch(`${BASE}/organizations`)).json(); return j.assignments && j.assignments[VAULT_A]; });
    check("vault assigned to organization via UI (metadata only)", true);
    const manifestShaBefore = crypto.createHash("sha256").update(fs.readFileSync(path.join(config.dataRoot, "vaults", VAULT_A, "manifest.json"))).digest("hex");
    // Rename via UI prompt.
    promptValue = "Acceptance Org Renamed";
    await waitFor(() => [...doc.querySelectorAll("[data-orgrename]")].length);
    click([...doc.querySelectorAll("[data-orgrename]")][0]);
    await waitFor(() => [...doc.querySelectorAll(".vault-title")].some((e) => e.textContent === "Acceptance Org Renamed"));
    check("organization renamed via UI", true);
    // Populated delete must be blocked.
    click([...doc.querySelectorAll("[data-orgdelete]")][0]);
    await waitFor(() => /Cannot delete/.test(doc.getElementById("v4-notice").textContent));
    const stillThere = (await (await fetch(`${BASE}/organizations`)).json()).organizations.some((o) => o.name === "Acceptance Org Renamed");
    check("populated organization cannot be deleted", stillThere);
    // Archive -> hidden from vaults-view selector, shown in Archived; restore works.
    click([...doc.querySelectorAll("[data-orgarchive]")][0]);
    await waitFor(async () => (await (await fetch(`${BASE}/organizations`)).json()).organizations[0].status === "ARCHIVED");
    click(tab("vaults"));
    await waitFor(() => doc.getElementById("v4-org"));
    const filterOpts = [...doc.getElementById("v4-org").options].map((o) => o.textContent);
    check("archived org hidden from the vaults organization filter", !filterOpts.includes("Acceptance Org Renamed"), filterOpts.join("|"));
    check("filter offers All organizations + Unassigned", filterOpts.includes("All organizations") && filterOpts.includes("Unassigned"));
    click(tab("orgs"));
    await waitFor(() => [...doc.querySelectorAll("[data-orgrestore]")].length);
    check("archived org listed in Archived organizations view", [...doc.querySelectorAll(".badge")].some((b) => b.textContent === "ARCHIVED"));
    click([...doc.querySelectorAll("[data-orgrestore]")][0]);
    await waitFor(async () => (await (await fetch(`${BASE}/organizations`)).json()).organizations[0].status === "ACTIVE");
    check("archive restored to active via UI", true);
    // Unassign (-> Unassigned) then delete the now-empty org.
    const orgSel2 = await waitFor(() => doc.querySelector(`[data-orgassign="${VAULT_A}"]`));
    orgSel2.value = ""; orgSel2.dispatchEvent(new window.Event("change", { bubbles: true }));
    await waitFor(async () => { const j = await (await fetch(`${BASE}/organizations`)).json(); return j.assignments && !j.assignments[VAULT_A]; });
    check("vault set to Unassigned via UI (remains valid + visible)", (await (await fetch(`${BASE}/vaults/${VAULT_A}`)).json()).vaultId === VAULT_A);
    await waitFor(() => [...doc.querySelectorAll("[data-orgdelete]")].length);
    click([...doc.querySelectorAll("[data-orgdelete]")][0]);
    await waitFor(async () => (await (await fetch(`${BASE}/organizations`)).json()).organizations.length === 0);
    check("empty organization deleted via UI", true);
    const manifestShaAfter = crypto.createHash("sha256").update(fs.readFileSync(path.join(config.dataRoot, "vaults", VAULT_A, "manifest.json"))).digest("hex");
    check("covenant neutrality: vault manifest bytes unchanged by ALL org operations", manifestShaBefore === manifestShaAfter);

    // ---- browser console clean ----
    check("browser console clean (no errors)", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));
  } catch (e) {
    check("acceptance run completed", false, e.stack || e.message);
  } finally {
    server.close();
  }
  console.log(`\n== §17 served-browser acceptance: ${PASS} PASS / ${FAIL} FAIL ==`);
  console.log("Real-KasWare signing steps remain HUMAN acceptance (runbook) — not covered or fabricated here.");
  process.exit(FAIL ? 1 : 0);
})();
