#!/usr/bin/env node
"use strict";

/*
 * BROWSER-layer acceptance of the guided setups (owner UX directive
 * 2026-09-05 §9) — REAL rendering and interaction in headless Chromium
 * (playwright-core), never source-string assertions.
 *
 * What it drives, against a RUNNING testnet-10 PolicyVault server that has
 * the TEST-ONLY dev signer enabled (POLICYVAULT_DEV_SIGNER=1, self-hosted
 * auth-disabled mode; the hosted image the owner accepts on is exercised by
 * the owner with KasWare — this harness never claims human acceptance):
 *
 *   1. Create vault — desktop (1280 px) and phone (375 px): stepper,
 *      validation errors beside fields, Back/Continue preserving values,
 *      custom budget period + live effect line, approvals select never
 *      lowered when a row is removed, review with Edit links, then
 *      "Build & review exact transaction" → the exact review with the
 *      funding breakdown and this browser's verification (no signing unless
 *      PV_UX_SIGN=1 — signing spends test KAS on testnet-10).
 *   2. Wallet rejection (simulated by failing the dev-sign route) → the user
 *      returns to a recoverable state with the built request kept.
 *   3. Create organizational root — the five steps, owner rows with
 *      "Use connected wallet", 2-of-3 selects, recovery toggle + custom
 *      waiting period, cancel-and-resume, review, build → CHECKED review.
 *   4. Layout/accessibility: no horizontal page overflow at 375 px and at
 *      200 % zoom, ≥ 44 px controls in the setup at phone width, every
 *      input labelled, visible focus ring on keyboard focus, stepper
 *      aria-current, keyboard operation of Continue.
 *
 * Output: screenshots + a JSON result under --out (default
 * docs/postlaunch/ux-evidence/<buildId>/). Exit 1 on any failed check.
 *
 *   PV_UX_URL=http://127.0.0.1:3082 node tools/ux-browser-acceptance.js --out <dir>
 *   env: PW_CHROMIUM (chrome-headless-shell path), PV_UX_INJECT_PAGE_ERROR=1
 *   (self-test: inject one uncaught page error; the run must fail), PV_UX_SIGN=1 (complete a
 *   real testnet-10 vault genesis with the dev signer — spends test KAS).
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const URL_BASE = process.env.PV_UX_URL || "http://127.0.0.1:3082";
const SIGN = process.env.PV_UX_SIGN === "1";
const args = process.argv.slice(2);
const outIdx = args.indexOf("--out");
const OUT = outIdx >= 0 ? args[outIdx + 1] : path.join(__dirname, "..", "docs", "postlaunch", "ux-evidence", "local");
fs.mkdirSync(OUT, { recursive: true });

let playwright;
try {
  playwright = require("playwright-core");
} catch {
  const alt = process.env.PW_MODULE || "";
  playwright = require(alt || "playwright-core");
}
const chromiumBin = process.env.PW_CHROMIUM || execSync("find ~/.cache/ms-playwright -name chrome-headless-shell 2>/dev/null | head -1").toString().trim();

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail === undefined ? null : String(detail).slice(0, 400) });
  process.stdout.write(`${ok ? "PASS" : "FAIL"}  ${name}${detail !== undefined && !ok ? ` — ${String(detail).slice(0, 300)}` : ""}\n`);
}
async function shot(page, name) {
  const file = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  return file;
}
async function noHorizontalOverflow(page, name) {
  const r = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, iw: window.innerWidth }));
  check(`${name}: no horizontal page overflow (scrollWidth ${r.sw} <= innerWidth ${r.iw})`, r.sw <= r.iw + 1, JSON.stringify(r));
}
async function controlsAtLeast44(page, scope, name) {
  const r = await page.evaluate((sel) => {
    const els = [...document.querySelectorAll(`${sel} input:not([type="checkbox"]):not([hidden]), ${sel} select, ${sel} button`)].filter((e) => e.offsetParent !== null);
    const small = els.filter((e) => e.getBoundingClientRect().height < 43.5).map((e) => `${e.tagName.toLowerCase()}[name=${e.getAttribute("name") || e.id || e.textContent.trim().slice(0, 20)}]=${Math.round(e.getBoundingClientRect().height)}`);
    return { total: els.length, small };
  }, scope);
  check(`${name}: visible setup controls are >= 44 px tall (${r.total} checked)`, r.total > 0 && r.small.length === 0, r.small.join(", "));
}
async function inputsLabelled(page, scope, name) {
  const r = await page.evaluate((sel) => {
    const els = [...document.querySelectorAll(`${sel} input:not([hidden]), ${sel} select`)].filter((e) => e.offsetParent !== null);
    const bad = els.filter((e) => !(e.getAttribute("aria-label") || (e.id && document.querySelector(`label[for="${e.id}"]`)) || e.closest("label")));
    return { total: els.length, bad: bad.map((e) => e.getAttribute("name") || e.id) };
  }, scope);
  check(`${name}: every visible input/select has a label (${r.total} checked)`, r.total > 0 && r.bad.length === 0, r.bad.join(", "));
}
const pageErrors = [];
const consoleErrors = [];
function watch(page) {
  /* Only UNCAUGHT exceptions count as page errors. Console "error" lines
   * are recorded for the report but expected here: the harness deliberately
   * provokes a 422 (invalid address) and a 500 (simulated wallet rejection),
   * and app-v4.js logs a wallet-stage diagnostic through console.error. */
  page.on("pageerror", (e) => pageErrors.push(`PAGEERROR ${e.message}\n${e.stack || ""}`));
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(`CONSOLE ${m.text()}`); });
  return page;
}
/* ---------- Codex checkpoint 2 evidence helpers (node side) ---------- */
const REPO_ROOT = path.join(__dirname, "..");
function sdkConfig() {
  const { loadConfig } = require(path.join(REPO_ROOT, "sdk", "src", "config"));
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(require("os").tmpdir(), "pv-ux-harness-")) });
}
/* Owner 2 signs its slot OUT OF BAND with its own TEST key (an independent
 * signer that never touches the browser); the response envelope is what the
 * owner pastes into "Import another owner's signed approval". */
function signSlotOutOfBand(envelope, role, signerAddress) {
  const config = sdkConfig();
  const kaspa = require(config.rustyKaspaModule);
  const keys = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "keys", "policyvault_test_keys.json"), "utf8")); // TEST keys only
  const key = new kaspa.PrivateKey(keys.secrets[role]);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(envelope.unsignedSafeJson);
  const sigHex = kaspa.createInputSignature(tx, Number(envelope.root.inputIndex), key).slice(2);
  return { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: envelope.requestVersion, requestId: envelope.requestId, network: envelope.network, manifestHash: envelope.manifestHash, txId: envelope.txId, root: envelope.root, slot: envelope.slot, signerAddress, signatureHex: sigHex, sighashType: 1, signedAtMs: Date.now() };
}
/* A governance approval signed OUT OF BAND with the TEST owner key (the mock
 * signer cannot sign auth messages): Schnorr over the server-reconstructed
 * canonical approval message, posted to the approvals route. */
function signGovernanceApprovalOutOfBand(approvalMessage, role) {
  const config = sdkConfig();
  const kaspa = require(config.rustyKaspaModule);
  const keys = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "keys", "policyvault_test_keys.json"), "utf8")); // TEST keys only
  return kaspa.signMessage({ message: approvalMessage, privateKey: keys.secrets[role] });
}
/* INDEPENDENT chain observation: ask the local kaspad directly (never the
 * app) whether the successor root outpoint exists with the expected value and
 * the predecessor outpoint is gone. */
async function independentRootCheck({ rootScriptWireHex, predecessorScriptWireHex, predecessor, successorTxId, expectedValue, extraOutpoints = [] }) {
  const config = sdkConfig();
  const kaspa = require(config.rustyKaspaModule);
  const { connectVerified, getAddressUtxos } = require(path.join(REPO_ROOT, "sdk", "src", "chain"));
  const addrOf = (wire) => kaspa.addressFromScriptPublicKey({ version: parseInt(String(wire).slice(0, 4), 16), script: String(wire).slice(4) }, config.networkId).toString();
  const address = addrOf(rootScriptWireHex);
  /* rc18 review R3-08: a root transition changes the root SCRIPT (state region), so the
   * predecessor outpoint lives at the PREDECESSOR address (the request's root INPUT script),
   * never at the successor address — the earlier check looked at the wrong address. */
  const predecessorAddress = predecessorScriptWireHex ? addrOf(predecessorScriptWireHex) : address;
  const { rpc, serverInfo } = await connectVerified(config);
  try {
    const utxos = await getAddressUtxos(rpc, address);
    const predUtxos = predecessorAddress === address ? utxos : await getAddressUtxos(rpc, predecessorAddress);
    const succ = successorTxId ? utxos.find((u) => u.outpoint.transactionId === successorTxId.toLowerCase() && u.outpoint.index === 0) : null;
    const pred = predUtxos.find((u) => u.outpoint.transactionId === String(predecessor.transactionId).toLowerCase() && u.outpoint.index === Number(predecessor.index));
    const extra = {};
    for (const x of extraOutpoints) {
      const list = await getAddressUtxos(rpc, addrOf(x.scriptWireHex));
      extra[x.label] = !!list.find((u) => u.outpoint.transactionId === String(x.outpoint.transactionId).toLowerCase() && u.outpoint.index === Number(x.outpoint.index));
    }
    return { networkId: serverInfo.networkId, address, predecessorAddress, predecessorAddressDiffers: predecessorAddress !== address, successorFound: !!succ, successorAmount: succ ? succ.amount.toString() : null, expectedValue: String(expectedValue), predecessorStillUnspent: !!pred, utxoCount: utxos.length, extra };
  } finally { await rpc.disconnect(); }
}
/* An ordinary (fee / fuel) input signed OUT OF BAND with a TEST key: the full
 * signature script (length prefix + 64-byte Schnorr signature + sighash byte). */
function signInputOutOfBand(unsignedSafeJson, index, role) {
  const config = sdkConfig();
  const kaspa = require(config.rustyKaspaModule);
  const keys = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "keys", "policyvault_test_keys.json"), "utf8")); // TEST keys only
  const key = new kaspa.PrivateKey(keys.secrets[role]);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  return kaspa.createInputSignature(tx, Number(index), key).toLowerCase();
}
/* ---------- R7-05 / F-6 (launch scope 2026-09-08) node-side helpers ---------- */
/* A KCC20 TEST token issued on testnet-10 with a TEST key (the same recipe as
 * the RC27F live-recovery demonstration; the OWNER role funds it because the
 * former `funding` role is empty). ONE broadcast, node-side, direct RPC. The
 * token exists only so a policyvault-0.7-payment vault can be created for
 * the browser's owner-operation evidence; nothing is deposited into it. */
async function issueTestToken({ role, ownerXOnly, supply = 100000n, valueSompi = 200000000n }) {
  const config = sdkConfig();
  const chain = require(path.join(REPO_ROOT, "sdk", "src", "chain"));
  const kaspa = chain.loadKaspa(config);
  const model = require(path.join(REPO_ROOT, "core", "model", "frozen-tx-v3"));
  const txutil = require(path.join(REPO_ROOT, "sdk", "src", "frozen-tx-v3"));
  const { compileKcc20Program } = require(path.join(REPO_ROOT, "sdk", "src", "token-program-kcc20"));
  const { calculateRequiredFee } = require(path.join(REPO_ROOT, "sdk", "src", "fee-mass"));
  const accounts = await devAccounts();
  const me = accounts.find((a) => a.role === role);
  const fuelList = ((await (await fetch(`${URL_BASE}/api/v1/wallet/fuel/${encodeURIComponent(me.address)}`)).json()).utxos) || [];
  const input = fuelList.filter((u) => BigInt(u.amount) > valueSompi + 100000000n && /^20[0-9a-f]{64}ac$/.test(u.scriptPublicKeyHex)).sort((a, b) => (BigInt(a.amount) < BigInt(b.amount) ? -1 : 1))[0];
  if (!input) throw new Error(`${role} holds no ordinary UTXO able to fund the test-token issuance`);
  const tokenState = { ownerIdentifier: ownerXOnly, identifierType: 0, amount: supply, isMinter: false };
  const program = compileKcc20Program({ config, state: tokenState, familyBound: 2 });
  const tokenCovenantId = kaspa.covenantId(input.outpoint, [{ index: 0, output: new kaspa.TransactionOutput(valueSompi, kaspa.payToScriptHashScript(program.scriptHex)) }]).toString().toLowerCase();
  const draft = { version: 1, inputs: [{ previousOutpoint: input.outpoint, sequence: 0n, computeBudget: 10, utxo: { amount: BigInt(input.amount), scriptPublicKey: { version: 0, scriptHex: input.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }], outputs: [{ value: valueSompi, scriptPublicKey: { version: 0, scriptHex: program.p2shSpkHex }, covenant: { authorizingInput: 0, covenantId: tokenCovenantId } }, { value: 1n, scriptPublicKey: { version: 0, scriptHex: input.scriptPublicKeyHex }, covenant: null }], lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = calculateRequiredFee(model.feeDescriptorFromFrozen(model.normalizeFrozenTxV3(draft), [66])).minimumRequiredFee;
  draft.outputs[1].value = BigInt(input.amount) - valueSompi - fee;
  const frozen = model.normalizeFrozenTxV3(draft);
  const txId = txutil.describeFrozenTx(frozen).txId;
  const unsigned = txutil.frozenToWasmTransaction(config, frozen);
  unsigned.finalize();
  const safe = JSON.parse(unsigned.serializeToSafeJSON());
  safe.inputs[0].signatureScript = signInputOutOfBand(JSON.stringify(safe), 0, role);
  const signed = kaspa.Transaction.deserializeFromSafeJSON(JSON.stringify(safe));
  if (signed.finalize().toString().toLowerCase() !== txId) throw new Error("issuance txid drifted after signing");
  const { rpc } = await chain.connectVerified(config);
  try {
    const res = await rpc.submitTransaction({ transaction: signed, allowOrphan: false });
    if (String(res.transactionId ?? res).toLowerCase() !== txId) throw new Error("node returned a different issuance txid");
    const tokenAddress = kaspa.addressFromScriptPublicKey({ version: 0, script: program.p2shSpkHex }, config.networkId).toString();
    let seen = false;
    for (let i = 0; i < 45 && !seen; i++) {
      const rows = await chain.getAddressUtxos(rpc, tokenAddress);
      seen = rows.some((u) => u.outpoint.transactionId === txId && u.outpoint.index === 0 && String(u.amount) === String(valueSompi));
      if (!seen) await new Promise((r) => setTimeout(r, 1000));
    }
    if (!seen) throw new Error("issuance output not observed within the wait");
  } finally { await rpc.disconnect(); }
  return { txId, tokenCovenantId, program, valueSompi: valueSompi.toString(), supply: supply.toString(), funderAddress: me.address, fuelOutpoint: input.outpoint };
}
/* INDEPENDENT chain observation of a transaction's outputs and consumed inputs from its Safe JSON (asks kaspad directly). */
async function independentOutputsObserved({ unsignedSafeJson, txId, indices }) {
  const config = sdkConfig();
  const chain = require(path.join(REPO_ROOT, "sdk", "src", "chain"));
  const kaspa = chain.loadKaspa(config);
  const safe = JSON.parse(unsignedSafeJson);
  const addrOf = (wire) => kaspa.addressFromScriptPublicKey({ version: parseInt(String(wire).slice(0, 4), 16), script: String(wire).slice(4) }, config.networkId).toString();
  const { rpc } = await chain.connectVerified(config);
  try {
    const outputs = {};
    for (const i of indices) {
      const o = safe.outputs[i];
      const address = addrOf(o.scriptPublicKey);
      const hit = (await chain.getAddressUtxos(rpc, address)).find((u) => u.outpoint.transactionId === String(txId).toLowerCase() && u.outpoint.index === i);
      outputs[i] = { address, found: !!hit, amount: hit ? hit.amount.toString() : null, expected: String(o.value), amountMatches: !!hit && hit.amount.toString() === String(o.value), covenantId: hit ? hit.covenantId || null : null, expectedCovenantId: o.covenant ? o.covenant.covenantId : null };
    }
    const inputs = [];
    for (const inp of safe.inputs) {
      const rows = await chain.getAddressUtxos(rpc, addrOf(inp.utxo.scriptPublicKey));
      inputs.push({ outpoint: { transactionId: inp.transactionId, index: inp.index }, unspent: rows.some((u) => u.outpoint.transactionId === inp.transactionId && u.outpoint.index === inp.index) });
    }
    return { outputs, inputs, allOutputsFound: indices.every((i) => outputs[i].found && outputs[i].amountMatches), allInputsSpent: inputs.every((x) => !x.unspent) };
  } finally { await rpc.disconnect(); }
}
/* Fill the guided create flow up to "Build & review exact transaction". */
async function fillVaultToBuild(page, A, label) {
  await page.click('.v4-tab[data-view="create"]');
  await page.waitForSelector("#v4-create-form");
  await page.fill('[name="label"]', label);
  await page.click("[data-setup-step='basics'] [data-setup-next]");
  await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
  await page.fill('[name="agent"]', A.delegate);
  await page.fill('[data-rows="recipient"] [name="recipient"]', A.recipient1);
  await page.click("[data-setup-step='agent'] [data-setup-next]");
  await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
  await page.fill('[name="maxPerSpend"]', "0.5");
  await page.fill('[name="budget"]', "1");
  await page.fill('[name="approvalThreshold"]', "0.3");
  await page.click("[data-setup-step='rules'] [data-setup-next]");
  await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
  await page.fill('[name="deposit"]', "1.2");
  await page.fill('[name="reserve"]', "0.2");
  await page.click("[data-setup-build]");
}

async function connectMock(page) {
  watch(page);
  await page.goto(`${URL_BASE}/`, { waitUntil: "networkidle" });
  /* UX-11 self-test: PV_UX_INJECT_PAGE_ERROR=1 throws one uncaught error in the
   * page; the run MUST then exit non-zero (proves the accounting). */
  if (process.env.PV_UX_INJECT_PAGE_ERROR === "1") { await page.evaluate(() => setTimeout(() => { throw new Error("PV_UX_INJECT_PAGE_ERROR"); }, 0)); await page.waitForTimeout(50); }
  const onb = page.locator("#pv-onboarding:not([hidden])");
  if (await onb.count()) { const skip = page.locator("#pv-onboarding .pv-onb-skip, #pv-onboarding .pv-onb-close").first(); if (await skip.count()) await skip.click().catch(() => {}); }
  await page.waitForSelector("#btn-connect-mock", { state: "visible", timeout: 20000 });
  await page.click("#btn-connect-mock");
  await page.waitForFunction(() => window.PolicyVaultV4 && window.PolicyVaultV4._state.ready === true, null, { timeout: 30000 });
  return page.evaluate(() => window.PolicyVaultV4._state.address);
}
async function devAccounts() {
  const r = await fetch(`${URL_BASE}/api/v1/wallet/dev-accounts`);
  return (await r.json()).accounts;
}
async function step(page) {
  return page.evaluate(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step"));
}

(async () => {
  const health = await (await fetch(`${URL_BASE}/api/v1/health`)).json();
  check("server is testnet-10 with the dev signer enabled (self-hosted harness mode)", health.networkId === "testnet-10" && health.devSigner === true, JSON.stringify(health));
  const accounts = await devAccounts();
  const A = Object.fromEntries(accounts.map((a) => [a.role, a.address]));
  const AX = Object.fromEntries(accounts.map((a) => [a.role, a.xonly]));
  const browser = await playwright.chromium.launch({ executablePath: chromiumBin, headless: true, args: ["--no-sandbox"] });

  /* PV_UX_SKIP_BASE=1 skips sections 1-4 (layout/flow checks) to iterate on the signed follow-through only. */
  const SKIP_BASE = process.env.PV_UX_SKIP_BASE === "1";
  if (!SKIP_BASE) {
  /* =================== 1. CREATE VAULT — desktop =================== */
  {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const owner = await connectMock(page);
    check("mock signer connected as the owner test key", owner === A.owner, owner);
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("#v4-create-form");
    check("create: guided setup renders with the stepper on step 1", (await step(page)) === "basics");
    await shot(page, "vault-desktop-step1");
    check("create: owner statement is scoped to this vault type and names the on-chain organizational root as the shared-ownership path", await page.evaluate(() => /This vault type \(protocol v0\.4\.1\)/.test(document.querySelector("[data-owner-authority]").textContent) && /on-chain organizational root/.test(document.querySelector("[data-owner-authority]").textContent)));
    // Continue with an empty name -> field-local error, stays on step 1
    await page.click("[data-setup-step='basics'] [data-setup-next]");
    await page.waitForTimeout(200);
    check("create: empty name is refused beside the field and the step does not advance", (await step(page)) === "basics" && (await page.locator('.ferr[data-err="label"]').innerText()).length > 0);
    await shot(page, "vault-desktop-step1-error");
    await page.fill('[name="label"]', "Operations Treasury");
    await page.click("[data-setup-step='basics'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
    // agent step: invalid address -> error; then valid
    await page.fill('[name="agent"]', "kaspatest:notanaddress");
    await page.fill('[data-rows="recipient"] [name="recipient"]', A.recipient1);
    await page.click("[data-setup-step='agent'] [data-setup-next]");
    await page.waitForFunction(() => (document.querySelector('.ferr[data-err="agent"]')?.textContent || "").length > 0);
    check("create: an invalid agent address is refused through the server's address boundary, beside the field", /rejected/.test(await page.locator('.ferr[data-err="agent"]').innerText()));
    await page.fill('[name="agent"]', A.delegate);
    await page.click("#v4-add-recipient");
    await page.waitForSelector('[data-rows="recipient"] .addr-row[data-row="1"]');
    await page.fill('[data-rows="recipient"] .addr-row[data-row="1"] [name="recipient"]', A.recipient2);
    await page.click("[data-setup-step='agent'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    await shot(page, "vault-desktop-step3-rules");
    // Back preserves values
    await page.click("[data-setup-step='rules'] [data-setup-back]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
    check("create: Back preserves the entered agent and both recipient rows", (await page.inputValue('[name="agent"]')) === A.delegate && (await page.locator('[data-rows="recipient"] .addr-row').count()) === 2 && (await page.inputValue('[data-rows="recipient"] .addr-row[data-row="1"] [name="recipient"]')) === A.recipient2);
    await page.click("[data-setup-step='agent'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    // spending rules: custom period
    await page.fill('[name="maxPerSpend"]', "2");
    await page.fill('[name="budget"]', "10");
    await page.selectOption('[name="period"]', "custom");
    await page.waitForFunction(() => !document.querySelector('[data-duration-custom="period"]').hidden);
    await page.fill('[name="periodValue"]', "1.5");
    await page.selectOption('[name="periodUnit"]', "day");
    await page.waitForFunction(() => /36 hours/.test(document.querySelector('[data-duration-effect="period"]').textContent));
    check("create: a decimal custom period is refused live with the whole-number equivalent (36 hours)", true);
    await page.fill('[name="periodValue"]', "36");
    await page.selectOption('[name="periodUnit"]', "hour");
    await page.waitForFunction(() => /About 1 day 12 hours\./.test(document.querySelector('[data-duration-effect="period"]').textContent) && /Exactly 1296000 DAA score/.test(document.querySelector('[data-duration-exact="period"]').textContent));
    check("create: the custom period's effect line shows the approximate duration; the exact DAA value sits under Technical detail", !/DAA/.test(await page.locator('[data-duration-effect="period"]').innerText()));
    await shot(page, "vault-desktop-step3-custom-duration");
    await page.fill('[name="approvalThreshold"]', "1");
    // approvers: two rows, choose 2 of 2, remove one -> select flags impossible, never lowered
    await page.click("#v4-add-approver");
    await page.waitForSelector('[data-rows="approver"] .addr-row[data-row="0"]');
    await page.fill('[data-rows="approver"] .addr-row[data-row="0"] [name="approver"]', A.recipient1);
    await page.click("#v4-add-approver");
    await page.waitForSelector('[data-rows="approver"] .addr-row[data-row="1"]');
    await page.fill('[data-rows="approver"] .addr-row[data-row="1"] [name="approver"]', A.recipient2);
    await page.dispatchEvent('[data-rows="approver"] .addr-row[data-row="1"] [name="approver"]', "input");
    await page.waitForFunction(() => [...document.querySelectorAll('[name="approvalM"] option')].some((o) => o.textContent === "2 of 2 approvers"));
    await page.selectOption('[name="approvalM"]', "2");
    await page.click('[data-rows="approver"] .addr-row[data-row="1"] .rm-approver');
    await page.waitForFunction(() => document.querySelectorAll('[data-rows="approver"] .addr-row').length === 1);
    const mAfter = await page.evaluate(() => ({ value: document.querySelector('[name="approvalM"]').value, text: document.querySelector('[name="approvalM"] option:checked').textContent, err: document.querySelector('.ferr[data-err="approvalM"]').textContent }));
    check("create: removing an approver never lowers 'Approvals needed' — it is flagged as impossible and requires an explicit choice", mAfter.value === "2" && /impossible/.test(mAfter.text) && /impossible|choose/i.test(mAfter.err), JSON.stringify(mAfter));
    await shot(page, "vault-desktop-step3-threshold-preserved");
    await page.click("[data-setup-step='rules'] [data-setup-next]");
    await page.waitForTimeout(300);
    check("create: Continue is refused while the approval count is impossible (draft kept)", (await step(page)) === "rules");
    await page.selectOption('[name="approvalM"]', "1");
    await page.click("[data-setup-step='rules'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
    await page.fill('[name="deposit"]', "2");
    await page.fill('[name="reserve"]', "0.5");
    await page.dispatchEvent('[name="reserve"]', "input");
    await page.waitForTimeout(200);
    check("create: the review lists every section with Edit links, the approximate period, and the exact DAA under Technical detail", (await page.locator("#v4-create-review .review-sec").count()) === 4 && (await page.locator("#v4-create-review [data-edit-step]").count()) === 4 && /about 1 day 12 hours \(approximate\)/.test(await page.locator("#v4-create-review").innerText()) && /1296000 DAA score/.test(await page.locator("#v4-create-review").evaluate((e) => e.textContent)));
    await shot(page, "vault-desktop-step4-review");
    // Edit link jumps back and keeps values
    await page.click('#v4-create-review [data-edit-step="2"]');
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    check("create: an Edit link returns to the step with values intact", (await page.inputValue('[name="budget"]')) === "10" && (await page.inputValue('[name="periodValue"]')) === "36");
    await page.click("[data-setup-step='rules'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
    // Build & review the exact transaction (server build + browser verification)
    await page.click("[data-setup-build]");
    await page.waitForSelector("#v4-modal [data-verify]", { timeout: 120000 });
    const modal = await page.evaluate(() => ({ verify: document.querySelector("#v4-modal [data-verify]")?.getAttribute("data-verify"), funding: document.querySelector("#v4-modal [data-funding]")?.innerText || "", confirm: document.querySelector("#v4-confirm")?.textContent || "", cancel: document.querySelector("#v4-cancel")?.textContent || "", labels: [...document.querySelectorAll("#v4-modal table.review td.rk")].map((e) => e.textContent) }));
    check("create: the exact review is VERIFIED by this browser and offers 'Approve in wallet' / 'Back to edit'", modal.verify === "pass" && /Approve in wallet/.test(modal.confirm) && /Back to edit/.test(modal.cancel), JSON.stringify(modal));
    check("create: the funding breakdown shows deposit, fee reserve, the exact network fee and the total leaving the wallet", /Deposit/.test(modal.funding) && /Fee reserve/.test(modal.funding) && /Network fee for creating the vault[\s\S]*\d+\.\d+ KAS/.test(modal.funding) && /Total leaving your wallet/.test(modal.funding), modal.funding.slice(0, 300));
    check("create: review rows use plain labels (no raw keys like depositKas)", modal.labels.includes("Deposit (protected)") && modal.labels.includes("Spending budget") && !modal.labels.some((l) => /Kas$/.test(l)), modal.labels.join("|"));
    await shot(page, "vault-desktop-exact-review");
    /* 2. wallet rejection -> recoverable state (simulated: dev-sign fails) */
    await page.route("**/api/v1/wallet/dev-sign", (route) => route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: { code: "USER_REJECTED", message: "simulated wallet rejection" } }) }));
    await page.click("#v4-confirm");
    await page.waitForFunction(() => /Signing did not complete — nothing was sent/.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 30000 });
    const recover = await page.evaluate(() => ({ pending: !!document.querySelector("[data-built-pending]"), reopen: !!document.querySelector("#v4-create-reopen"), name: document.querySelector('[name="label"]')?.value }));
    check("wallet rejection: nothing was sent, the draft is intact and the built transaction can be reopened without rebuilding", recover.pending && recover.reopen && recover.name === "Operations Treasury", JSON.stringify(recover));
    await shot(page, "vault-desktop-wallet-rejected");
    await page.unroute("**/api/v1/wallet/dev-sign");
    /* 2b. Edit after a build (rc15 review F-02): the abandoned UNSIGNED request is
     * withdrawn on the server (REJECTED), never left open toward the quota. */
    const abandonedId = await page.evaluate(() => window.PolicyVaultV4._vaultSetup().built.request.requestId);
    await page.click('#v4-create-review [data-edit-step="2"]');
    await page.waitForFunction(() => !document.querySelector("[data-built-pending]") && document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    await page.waitForTimeout(600);
    const abandonedState = await page.evaluate(async (id) => (await (await fetch(`/api/v1/wallet/v4/requests/${id}`)).json()).request.state, abandonedId);
    check("create: editing after a build withdraws the abandoned unsigned request on the server (closed as WALLET_REJECTED — never orphaned toward the quota) and returns to the step with values intact", abandonedState === "WALLET_REJECTED" && (await page.inputValue('[name="budget"]')) === "10", `state=${abandonedState}`);
    await page.click("[data-setup-step='rules'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
    await page.click("[data-setup-build]");
    await page.waitForSelector("#v4-confirm", { timeout: 120000 });
    if (SIGN) {
      await page.click("#v4-confirm");
      await page.waitForFunction(() => !!document.querySelector("#v4-notice [data-outcome]") || /failed|uncertain|refused/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 180000 });
      const outcome = await page.evaluate(() => ({ state: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome"), level: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome-level"), text: document.querySelector("#v4-notice")?.innerText }));
      check("SIGN: genesis submitted with the dev signer on testnet-10; outcome reported truthfully (a known state with its meaning; pending never rendered as success)", ["CHAIN_VERIFIED", "BROADCAST", "CHAIN_SEEN"].includes(outcome.state) && (outcome.state === "CHAIN_VERIFIED" ? outcome.level === "verified" : outcome.level !== "verified"), JSON.stringify(outcome).slice(0, 300));
      await shot(page, "vault-desktop-genesis-outcome");
    } else {
      await page.click("#v4-cancel");
      await page.waitForTimeout(300);
      check("create: 'Back to edit' withdraws the unsigned build and keeps the draft", !(await page.locator("[data-built-pending]").count()) && (await page.inputValue('[name="label"]')) === "Operations Treasury");
    }
    await page.close();
  }

  /* =================== 1b. CREATE VAULT — phone 375 px =================== */
  {
    const page = await browser.newPage({ viewport: { width: 375, height: 740 }, deviceScaleFactor: 2 });
    await connectMock(page);
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("#v4-create-form");
    await noHorizontalOverflow(page, "phone 375: create step 1");
    await controlsAtLeast44(page, "#v4-create-form section[data-setup-step='basics']", "phone 375: create step 1");
    await inputsLabelled(page, "#v4-create-form section[data-setup-step='basics']", "phone 375: create step 1");
    await shot(page, "vault-phone-step1");
    await page.fill('[name="label"]', "Phone vault");
    await page.click("[data-setup-step='basics'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
    await page.fill('[name="agent"]', A.delegate);
    await page.fill('[data-rows="recipient"] [name="recipient"]', A.recipient1);
    await page.click("[data-setup-step='agent'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    await page.selectOption('[name="period"]', "custom");
    await page.waitForFunction(() => !document.querySelector('[data-duration-custom="period"]').hidden);
    await noHorizontalOverflow(page, "phone 375: rules step with the custom duration expanded");
    await controlsAtLeast44(page, "#v4-create-form section[data-setup-step='rules']", "phone 375: rules step");
    await inputsLabelled(page, "#v4-create-form section[data-setup-step='rules']", "phone 375: rules step");
    await shot(page, "vault-phone-step3-custom-duration");
    // long address in a recipient row must not clip the page
    await page.click("[data-setup-step='rules'] [data-setup-back]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
    await noHorizontalOverflow(page, "phone 375: agent step with a full-length address");
    // keyboard: focus ring visible on the first input; Tab reaches Continue and Enter/Space activates it
    await page.focus('[name="agent"]');
    const ring = await page.evaluate(() => { const el = document.activeElement; const cs = getComputedStyle(el); return { name: el.getAttribute("name"), outline: cs.outlineStyle, width: cs.outlineWidth }; });
    check("keyboard: a focused input shows a visible focus ring", ring.name === "agent" && ring.outline !== "none" && parseFloat(ring.width) >= 1, JSON.stringify(ring));
    let guard = 0;
    while (guard++ < 12) { await page.keyboard.press("Tab"); const isNext = await page.evaluate(() => document.activeElement && document.activeElement.hasAttribute("data-setup-next")); if (isNext) break; }
    check("keyboard: Tab reaches the Continue button within the step", guard < 12);
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules", null, { timeout: 15000 });
    check("keyboard: Enter on Continue advances the step (values preserved)", (await page.inputValue('[name="agent"]')) === A.delegate);
    await page.close();
  }

  /* =================== 1c. 200 % zoom (desktop 1280 at 200 % = a 640 px layout) =================== */
  {
    const page = await browser.newPage({ viewport: { width: 640, height: 900 }, deviceScaleFactor: 2 });
    await connectMock(page);
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("#v4-create-form");
    await page.fill('[name="label"]', "Zoom vault");
    await page.click("[data-setup-step='basics'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
    await page.fill('[name="agent"]', A.delegate);
    await page.fill('[data-rows="recipient"] [name="recipient"]', A.recipient1);
    await page.click("[data-setup-step='agent'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    await page.selectOption('[name="period"]', "custom");
    await page.waitForFunction(() => !document.querySelector('[data-duration-custom="period"]').hidden);
    await noHorizontalOverflow(page, "desktop at 200% zoom (640 px layout): rules step with the custom duration expanded");
    await shot(page, "vault-200pct-zoom-rules");
    await page.close();
  }

  /* =================== 3. CREATE ORGANIZATIONAL ROOT =================== */
  for (const [label, viewport] of [["desktop", { width: 1280, height: 900 }], ["phone", { width: 375, height: 740 }]]) {
    const page = await browser.newPage({ viewport, deviceScaleFactor: label === "phone" ? 2 : 1 });
    const owner = await connectMock(page);
    await page.click('.v4-tab[data-view="orgs"]');
    await page.waitForSelector("#v4-orgroot-create-btn", { timeout: 30000 });
    await page.click("#v4-orgroot-create-btn");
    await page.waitForSelector("[data-orgroot-wizard]");
    check(`root ${label}: the guided setup opens on Owners with the connected wallet prefilled`, (await step(page)) === "owners" && (await page.inputValue('[data-rows="owner"] .addr-row[data-row="0"] [name="owner"]')) === owner);
    await noHorizontalOverflow(page, `root ${label}: owners step`);
    if (label === "phone") { await controlsAtLeast44(page, "[data-orgroot-wizard] section[data-setup-step='owners']", "root phone: owners step"); await inputsLabelled(page, "[data-orgroot-wizard] section[data-setup-step='owners']", "root phone: owners step"); }
    await shot(page, `root-${label}-step1-owners`);
    // three owners (connected + two test keys), a name each
    await page.fill('[data-rows="owner"] .addr-row[data-row="0"] [name="ownerLabel"]', "Alice");
    await page.click("#v4-add-owner");
    await page.waitForSelector('[data-rows="owner"] .addr-row[data-row="1"]');
    await page.fill('[data-rows="owner"] .addr-row[data-row="1"] [name="owner"]', A.delegate);
    await page.fill('[data-rows="owner"] .addr-row[data-row="1"] [name="ownerLabel"]', "Bob");
    await page.click("#v4-add-owner");
    await page.waitForSelector('[data-rows="owner"] .addr-row[data-row="2"]');
    await page.fill('[data-rows="owner"] .addr-row[data-row="2"] [name="owner"]', A.recipient1);
    // duplicate: same wallet twice -> refused beside the row
    await page.click("#v4-add-owner");
    await page.waitForSelector('[data-rows="owner"] .addr-row[data-row="3"]');
    await page.fill('[data-rows="owner"] .addr-row[data-row="3"] [name="owner"]', A.delegate);
    await page.click("[data-setup-step='owners'] [data-setup-next]");
    await page.waitForFunction(() => /Same wallet as owner 2/.test(document.querySelector('[data-rows="owner"] .addr-row[data-row="3"]')?.textContent || ""), null, { timeout: 15000 });
    check(`root ${label}: a duplicate owner wallet is refused beside its row`, true);
    await shot(page, `root-${label}-step1-duplicate`);
    await page.click('[data-rows="owner"] .addr-row[data-row="3"] .rm-owner');
    await page.waitForFunction(() => document.querySelectorAll('[data-rows="owner"] .addr-row').length === 3);
    await page.click("[data-setup-step='owners'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "approvals", null, { timeout: 20000 });
    const opts = await page.evaluate(() => [...document.querySelectorAll('[name="ownerM"] option')].map((o) => o.textContent));
    check(`root ${label}: 'Owners needed to approve changes' reads k of 3 owners`, opts.join("|") === "1 of 3 owners|2 of 3 owners|3 of 3 owners", opts.join("|"));
    await page.selectOption('[name="ownerM"]', "2");
    await page.dispatchEvent('[name="ownerM"]', "change");
    await page.waitForFunction(() => /Any 2 of the 3 owners must sign/.test(document.querySelector("[data-live-summary]")?.textContent || ""));
    check(`root ${label}: the live summary restates the rule in plain language`, true);
    await shot(page, `root-${label}-step2-approvals`);
    await page.click("[data-setup-step='approvals'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "emergency");
    const kOpts = await page.evaluate(() => [...document.querySelectorAll('[name="emergencyK"] option')].map((o) => o.textContent));
    check(`root ${label}: emergency freeze offers 1..M (never above the approval quorum)`, kOpts.join("|") === "1 of 3 owners|2 of 3 owners", kOpts.join("|"));
    const freezeCopy = await page.locator('[data-field="emergencyK"] .f-help').innerText();
    check(`root ${label}: freeze help says agent payments continue and at most one vault can be emergency-paused`, /does NOT stop agent payments/.test(freezeCopy) && /at most ONE vault/.test(freezeCopy));
    const offHelp = await page.locator('[data-help="recovery"]').innerText();
    await page.check('[name="recoveryEnabled"]');
    await page.waitForFunction(() => !document.querySelector("[data-recovery-fields]").hidden);
    await page.waitForFunction(() => /no governance transaction touches this root/.test(document.querySelector('[data-help="recovery"]').textContent));
    check(`root ${label}: the recovery explanation follows the toggle (off: consequence; on: how the wait works)`, /no one can regain control/.test(offHelp));
    await page.selectOption('[name="recoveryDelay"]', "custom");
    await page.waitForFunction(() => !document.querySelector('[data-duration-custom="recoveryDelay"]').hidden);
    await page.fill('[name="recoveryDelayValue"]', "45");
    await page.selectOption('[name="recoveryDelayUnit"]', "day");
    await page.waitForFunction(() => /About 45 days\./.test(document.querySelector('[data-duration-effect="recoveryDelay"]').textContent) && /Exactly 38880000 DAA score/.test(document.querySelector('[data-duration-exact="recoveryDelay"]').textContent));
    check(`root ${label}: a custom recovery waiting period shows the approximate duration; the exact DAA sits under Technical detail`, true);
    await noHorizontalOverflow(page, `root ${label}: emergency step with recovery expanded`);
    await shot(page, `root-${label}-step3-emergency`);
    await page.click("[data-setup-step='emergency'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
    const funderShown = await page.evaluate(() => document.querySelector("[data-setup-step='funding'] .addr-display .mono")?.textContent);
    check(`root ${label}: the funding wallet is the connected wallet (not a free-text field) and the copy says paying grants no ownership`, funderShown === owner && /grants no ownership/.test(await page.locator("[data-setup-step='funding']").innerText()));
    await page.fill('[name="label"]', "Acme Treasury");
    await shot(page, `root-${label}-step4-funding`);
    await page.click("[data-setup-step='funding'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "review");
    const review = await page.locator("#v4-orgroot-review").innerText();
    check(`root ${label}: the draft review names 2 of 3 owners, the freeze quorum, recovery after about 45 days, no successor, funding locked`, /2 of 3 owners/.test(review) && /about 45 days/.test(review) && /none \(permanent\)/.test(review) && /locked for the life/.test(review), review.slice(0, 300));
    check(`root ${label}: the review has Edit links for every section`, (await page.locator("#v4-orgroot-review [data-edit-step]").count()) === 4);
    await shot(page, `root-${label}-step5-review`);
    if (label === "desktop") {
      // Build → CHECKED exact review (server genesis summary cross-checked)
      await page.click("[data-setup-build]");
      await page.waitForSelector("#v4-orgroot-confirm, #v4-orgroot-review-back2", { timeout: 120000 });
      const built = await page.evaluate(() => ({ checked: /CHECKED — PolicyVault's description of the built transaction matches/.test(document.querySelector("#v4-modal").textContent), fee: /Network fee for creating the root/.test(document.querySelector("#v4-modal").textContent), tech: /EXACT ROOT POLICY BEFORE SIGNING/.test(document.querySelector("#v4-modal").textContent), confirm: !!document.querySelector("#v4-orgroot-confirm") }));
      check("root desktop: the exact governance review is CHECKED against the server's genesis summary, shows the exact fee and keeps the technical exact-policy panel, and offers Approve in wallet", built.checked && built.fee && built.tech && built.confirm, JSON.stringify(built));
      await shot(page, "root-desktop-exact-review");
      // simulated wallet rejection (dev-sign fails) -> recoverable state, the built request kept
      await page.route("**/api/v1/wallet/dev-sign", (route) => route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: { code: "USER_REJECTED", message: "simulated wallet rejection" } }) }));
      await page.click("#v4-orgroot-confirm");
      await page.waitForFunction(() => /Signing did not complete — nothing was sent/.test(document.querySelector("#v4-notice")?.textContent || "") && !!document.querySelector("#v4-orgroot-reopen"), null, { timeout: 60000 });
      await page.unroute("**/api/v1/wallet/dev-sign");
      const rootBuilt = await page.evaluate(() => ({ rootId: window.PolicyVaultV4._state.rootSetup.built.request.rootCovenantId, id: window.PolicyVaultV4._state.rootSetup.built.request.id }));
      check("root desktop: wallet rejection leaves a recoverable state (built request kept, reopen offered, draft intact)", !!rootBuilt.id && (await page.inputValue('[name="label"]')) === "Acme Treasury", JSON.stringify(rootBuilt));
      // rc15 review F-02: Edit after the build withdraws the abandoned genesis request on the server
      await page.click('#v4-orgroot-review [data-edit-step="1"]');
      await page.waitForFunction(() => !document.querySelector("#v4-orgroot-reopen") && document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "approvals");
      await page.waitForTimeout(600);
      const rootAbandoned = await page.evaluate(async ({ rootId, id }) => (await (await fetch(`/api/v1/org-roots/${rootId}/requests/${id}`)).json()).request.state, rootBuilt);
      check("root desktop: editing after a build withdraws the abandoned unsigned genesis request (closed as REFUSED)", rootAbandoned === "REFUSED", `state=${rootAbandoned}`);
      for (const st of ["approvals", "emergency", "funding"]) { await page.click(`[data-setup-step='${st}'] [data-setup-next]`); await page.waitForTimeout(300); }
      await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "review");
      await page.click("[data-setup-build]");
      await page.waitForSelector("#v4-orgroot-confirm, #v4-orgroot-review-back2", { timeout: 120000 });
      await page.click("#v4-orgroot-review-back");
      await page.waitForSelector("[data-orgroot-wizard]");
      check("root desktop: 'Back to edit' returns to the review step with the draft intact", (await step(page)) === "review" && (await page.inputValue('[name="label"]')) === "Acme Treasury");
    }
    await page.click("section[data-setup-step]:not([hidden]) [data-setup-cancel]");
    await page.waitForFunction(() => document.querySelector("#v4-modal").style.display === "none");
    check(`root ${label}: Cancel closes the setup and discards the draft`, await page.evaluate(() => document.querySelector("#v4-modal").style.display === "none" && !window.PolicyVaultV4._state.rootSetup));
    await page.close();
  }

  }
  /* =================== 5. SIGN mode: real testnet-10 follow-through =================== */
  if (SIGN) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const owner = await connectMock(page);
    // (a) vault genesis end to end, then the vault card + the prefilled Change-rules form
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("#v4-create-form");
    await page.fill('[name="label"]', "UX evidence vault");
    await page.click("[data-setup-step='basics'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "agent");
    await page.fill('[name="agent"]', A.delegate);
    await page.fill('[data-rows="recipient"] [name="recipient"]', A.recipient1);
    await page.click("[data-setup-step='agent'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "rules");
    await page.fill('[name="maxPerSpend"]', "0.5");
    await page.fill('[name="budget"]', "1");
    await page.selectOption('[name="period"]', "custom");
    await page.fill('[name="periodValue"]', "36");
    await page.selectOption('[name="periodUnit"]', "hour");
    await page.fill('[name="approvalThreshold"]', "0.3");
    await page.click("[data-setup-step='rules'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
    await page.fill('[name="deposit"]', "1.5");
    await page.fill('[name="reserve"]', "0.3");
    await page.click("[data-setup-build]");
    await page.waitForSelector("#v4-confirm", { timeout: 120000 });
    await page.click("#v4-confirm");
    await page.waitForFunction(() => !!document.querySelector("#v4-notice [data-outcome]") || /failed|uncertain|refused/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 240000 });
    const genesisOut = await page.evaluate(() => ({ state: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome"), level: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome-level"), text: document.querySelector("#v4-notice")?.innerText }));
    check("SIGN: vault genesis approved by the test signer and submitted on testnet-10 — outcome reported truthfully (CHAIN_VERIFIED / pending, never 'success' for pending)", ["CHAIN_VERIFIED", "BROADCAST", "CHAIN_SEEN"].includes(genesisOut.state), JSON.stringify(genesisOut).slice(0, 240));
    await shot(page, "sign-vault-genesis-outcome");
    await page.click('.v4-tab[data-view="vaults"]');
    await page.waitForSelector('[data-vault]', { timeout: 60000 });
    const cardLoc = page.locator('[data-vault]', { hasText: "UX evidence vault" }).first();
    await cardLoc.waitFor({ timeout: 60000 });
    const card = await cardLoc.innerText();
    check("SIGN: the vault card speaks the same language (max per payment, budget left per about 1 day 12 hours, extra approval above)", /max 0\.5 KAS per payment/.test(card) && /per about 1 day 12 hours/.test(card) && /extra approval above 0\.3 KAS/.test(card), card.slice(0, 300));
    await shot(page, "sign-vault-card");
    await cardLoc.locator("[data-repolicy]").click();
    await page.waitForSelector("#v4-agent-form");
    const keep = await page.evaluate(() => document.querySelector('#v4-agent-form [name="period"] option:checked')?.textContent);
    check("SIGN: Change rules is prefilled from the live agent and offers the EXACT current budget period as 'Keep current value'", /Keep current value \(about 1 day 12 hours, exact\)/.test(keep || ""), keep);
    check("SIGN: Change rules prefill carries the live limits", (await page.inputValue('#v4-agent-form [name="maxPerSpend"]')) === "0.5" && (await page.inputValue('#v4-agent-form [name="budget"]')) === "1");
    await shot(page, "sign-change-rules-prefilled");
    await page.click("#v4-agent-cancel");
    // (b) a 1-of-1 organizational root: genesis → detail → heartbeat authorization → approve → finalize → submit
    await page.click('.v4-tab[data-view="orgs"]');
    await page.waitForSelector("#v4-orgroot-create-btn", { timeout: 30000 });
    await page.click("#v4-orgroot-create-btn");
    await page.waitForSelector("[data-orgroot-wizard]");
    await page.fill('[data-rows="owner"] .addr-row[data-row="0"] [name="ownerLabel"]', "Solo owner");
    for (const stepId of ["owners", "approvals", "emergency"]) {
      await page.click(`[data-setup-step='${stepId}'] [data-setup-next]`);
      await page.waitForFunction((next) => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === next, { owners: "approvals", approvals: "emergency", emergency: "funding" }[stepId], { timeout: 20000 });
    }
    const rootLabel = `UX evidence root ${Date.now().toString(36)}`;
    await page.fill('[name="label"]', rootLabel);
    await page.click("[data-setup-step='funding'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "review");
    await page.click("[data-setup-build]");
    await page.waitForSelector("#v4-orgroot-confirm", { timeout: 120000 });
    await page.click("#v4-orgroot-confirm");
    await page.waitForFunction(() => !!document.querySelector("#v4-notice [data-outcome]") || /failed|uncertain|refused/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 240000 });
    const rootOut = await page.evaluate(() => ({ state: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome"), level: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome-level"), text: document.querySelector("#v4-notice")?.innerText }));
    check("SIGN: root genesis approved and submitted — outcome reported truthfully", ["CHAIN_VERIFIED", "BROADCAST", "CHAIN_SEEN", "VERIFIED_OUTCOME"].includes(rootOut.state), JSON.stringify(rootOut).slice(0, 240));
    await shot(page, "sign-root-genesis-outcome");
    // open the root; Verify state until the live outpoint is recorded
    await page.waitForSelector('[data-viewroot]', { timeout: 60000 });
    const rootRow = page.locator('[data-org-root-section="on-chain"] tr', { hasText: rootLabel }).first();
    await rootRow.waitFor({ timeout: 60000 });
    let live = false;
    for (let i = 0; i < 12 && !live; i++) {
      await rootRow.locator('[data-viewroot]').click();
      await page.waitForSelector('[data-org-root-detail]', { timeout: 30000 });
      live = await page.evaluate(() => /live outpoint/.test(document.querySelector('[data-org-root-detail]')?.textContent || ""));
      if (!live) { await page.click('[data-rootreconcile]'); await page.waitForTimeout(5000); await page.click("#v4-orgroot-detail-close").catch(() => {}); await page.waitForTimeout(500); }
    }
    check("SIGN: the root reconciles to a live outpoint (proven chain readback) within the wait", live);
    const detail = await page.locator('[data-org-root-detail]').innerText();
    check("SIGN: root detail states the viewer's role, plain-language governance and that a freeze does not stop agent payments", /You hold owner slot 1 \(Solo owner\)/.test(detail) && /1 of 1 owners/.test(detail) && /agent payments continue/.test(detail) && /off — if too many keys are lost/.test(detail), detail.slice(0, 300));
    await shot(page, "sign-root-detail");
    await page.click('[data-rootaction="authorize"]');
    await page.waitForSelector('[data-org-root-request]', { timeout: 60000 });
    const req1 = await page.locator('[data-org-root-request]').innerText();
    check("SIGN: a heartbeat authorization request shows 0 of 1 collected, the owner's role and the next step", /0 of 1 collected/.test(req1) && /your approval is needed/.test(req1) && /Collect 1 more owner approval/.test(req1), req1.slice(0, 300));
    await shot(page, "sign-root-request-pending");
    await page.click("#v4-orgroot-signmyslot");
    await page.waitForFunction(() => /1 of 1 collected/.test(document.querySelector('[data-org-root-request]')?.textContent || ""), null, { timeout: 120000 });
    check("SIGN: after approving in the wallet the request shows 1 of 1 collected and offers Finalize", await page.evaluate(() => !document.querySelector("[data-rootfinalize]").disabled));
    await page.click("[data-rootfinalize]");
    await page.waitForFunction(() => !document.querySelector("[data-rootsubmit]").disabled, null, { timeout: 120000 });
    check("SIGN: Finalize assembles the transaction; Submit to network becomes available (not yet broadcast)", /Not yet broadcast/.test(await page.locator("#v4-notice").innerText()));
    await shot(page, "sign-root-request-finalized");
    await page.click("[data-rootsubmit]");
    await page.waitForFunction(() => !!document.querySelector("#v4-notice [data-outcome]") || /failed|uncertain|refused/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 240000 });
    const subOut = await page.evaluate(() => ({ state: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome"), level: document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome-level"), text: document.querySelector("#v4-notice")?.innerText }));
    check("SIGN: the heartbeat authorization was submitted; outcome reported truthfully", ["CHAIN_VERIFIED", "BROADCAST", "CHAIN_SEEN", "VERIFIED_OUTCOME"].includes(subOut.state), JSON.stringify(subOut).slice(0, 240));
    await shot(page, "sign-root-request-submitted");

    /* ===== (c) UX-04: an agent change is validated against the vault's ACTUAL approver configuration ===== */
    const waitOutcome = () => page.waitForFunction(() => !!document.querySelector("#v4-notice [data-outcome]") || /failed|uncertain|refused/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 180000 });
    const outcomeState = () => page.evaluate(() => document.querySelector("#v4-notice [data-outcome]")?.getAttribute("data-outcome"));
    const noticeText = () => page.locator("#v4-notice").innerText();
    await page.click("#v4-orgroot-request-close").catch(() => {}); // the 1-of-1 request modal is still open
    await page.waitForFunction(() => document.querySelector("#v4-modal")?.style.display === "none", null, { timeout: 15000 }).catch(() => {});
    await page.click('.v4-tab[data-view="vaults"]');
    await page.waitForSelector('[data-vault]', { timeout: 60000 });
    const noApprCard = page.locator('[data-vault]', { hasText: "UX evidence vault" }).first();
    await noApprCard.locator("[data-repolicy]").click();
    await page.waitForSelector("#v4-agent-form");
    await page.fill('#v4-agent-form [name="approvalThreshold"]', "0");
    await page.click('#v4-agent-form button[type="submit"]');
    await page.waitForTimeout(1000);
    const thrErr = await page.locator('#v4-agent-form .ferr[data-err="approvalThreshold"]').innerText().catch(() => "");
    check("UX-04: on a vault WITHOUT payment approvers a 0 KAS threshold is refused against the vault's real configuration (every payment would be impossible), before any request is built", /no payment approvers/.test(thrErr), thrErr);
    await page.click("#v4-agent-cancel");
    const opsCard = page.locator('[data-vault]', { hasText: "Operations Treasury" }).first();
    const opsId = await opsCard.getAttribute("data-vault");
    const vaultById = async (id) => (((await (await fetch(`${URL_BASE}/api/v1/vaults`)).json()).vaults) || []).find((v) => v.vaultId === id) || {};
    const opsBefore = await vaultById(opsId);
    await opsCard.locator("[data-repolicy]").click();
    await page.waitForSelector("#v4-agent-form");
    await page.fill('#v4-agent-form [name="approvalThreshold"]', "0");
    await page.click('#v4-agent-form button[type="submit"]');
    // lowering a threshold is an AUTHORITY EXPANSION under the hosted governance controls:
    // the product requires an approved proposal first (existing ceremony), then the retry builds the transaction
    await page.waitForSelector("[data-gov-createproposal], #v4-confirm", { timeout: 120000 });
    if (await page.locator("[data-gov-createproposal]").count()) {
      await page.click("[data-gov-createproposal]");
      await page.waitForSelector("[data-gov-approve]", { timeout: 60000 });
      const proposalId = await page.getAttribute("[data-gov-approve]", "data-gov-approve");
      check("UX-04: the threshold change is validated against the real approver configuration and reaches the governance ceremony (a proposal is created; nothing built yet)", !!proposalId);
      const prop = (await (await fetch(`${URL_BASE}/api/v1/governance/proposals/${proposalId}`)).json()).proposal;
      const signature = signGovernanceApprovalOutOfBand(prop.approvalMessage, "owner");
      const appr = await fetch(`${URL_BASE}/api/v1/governance/proposals/${proposalId}/approvals`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approverAddress: A.owner, signature }) });
      check("UX-04: the owner's governance approval (signed with the test owner key outside the browser) is accepted by the server", appr.status === 200, `status ${appr.status}`);
      await page.click("[data-gov-close]");
      await page.click('.v4-tab[data-view="vaults"]');
      await page.waitForSelector(`[data-govopen="${proposalId}"]`, { timeout: 60000 });
      await page.click(`[data-govopen="${proposalId}"]`);
      await page.waitForSelector("[data-gov-retry]", { timeout: 60000 });
      await page.click("[data-gov-retry]");
    }
    await page.waitForSelector("#v4-confirm", { timeout: 120000 });
    await page.click("#v4-confirm");
    await waitOutcome();
    const rpOut = await outcomeState();
    await page.waitForTimeout(1500);
    const opsAfter = await vaultById(opsId);
    check("UX-04: Change rules with a 0 KAS threshold on a vault WITH approvers is CHAIN_VERIFIED (through the governance ceremony), the approval policy (approvalM + approver slots) is identical before and after, and the agent's threshold is now 0", rpOut === "CHAIN_VERIFIED" && String(opsAfter.approvalM) === String(opsBefore.approvalM) && Number(opsBefore.approvalM) >= 1 && JSON.stringify(opsAfter.approverSlots) === JSON.stringify(opsBefore.approverSlots) && (opsAfter.agents || []).some((a) => a.approvalThresholdKas === "0"), JSON.stringify({ rpOut, before: { m: opsBefore.approvalM, active: opsBefore.activeApproverCount }, after: { m: opsAfter.approvalM, active: opsAfter.activeApproverCount, thresholds: (opsAfter.agents || []).map((a) => a.approvalThresholdKas) } }));
    await shot(page, "sign-ux04-threshold-zero");

    /* ===== (d) UX-07: the approver form never promises a zero-approver transition ===== */
    await page.click('.v4-tab[data-view="vaults"]');
    await page.waitForSelector('[data-vault]', { timeout: 60000 });
    await page.locator('[data-vault]', { hasText: "Operations Treasury" }).first().locator("[data-setapprovers]").click();
    await page.waitForSelector("#v4-appr-form");
    const apprHelp = await page.locator("#v4-appr-form").innerText();
    check("UX-07: the approver form states that the protocol cannot take a vault back to no approvers (the 'leave empty to remove every approver' promise is gone)", /cannot take it back to having none/.test(apprHelp) && !/Leave the list empty to remove every approver/.test(apprHelp));
    while ((await page.locator('#v4-appr-form [data-rows="approver"] .addr-row').count()) > 1) { await page.locator('#v4-appr-form .rm-approver').last().click(); await page.waitForTimeout(200); }
    await page.locator('#v4-appr-form .rm-approver').first().click();
    await page.waitForTimeout(300);
    check("UX-07: removing the last approver row is refused with the reason (one row stays)", (await page.locator('#v4-appr-form [data-rows="approver"] .addr-row').count()) === 1 && /At least one approver must remain/.test(await page.locator("#v4-appr-form").innerText()));
    await page.fill('#v4-appr-form [data-rows="approver"] [name="approver"]', "");
    await page.click('#v4-appr-form button[type="submit"]');
    await page.waitForTimeout(800);
    check("UX-07: submitting an empty approver list is refused before any request is built", /At least one approver is required/.test(await page.locator("#v4-appr-form").innerText()));
    await shot(page, "sign-ux07-empty-approvers-refused");
    await page.click("#v4-appr-cancel");

    /* ===== (e) UX-03: a 2-of-3 root — two independent owner keys approve (one out of band), the starting owner signs the fee input, finalize, submit, INDEPENDENT node check ===== */
    await page.click('.v4-tab[data-view="orgs"]');
    await page.waitForSelector("#v4-orgroot-create-btn", { timeout: 30000 });
    await page.click("#v4-orgroot-create-btn");
    await page.waitForSelector("[data-orgroot-wizard]");
    await page.fill('[data-rows="owner"] .addr-row[data-row="0"] [name="ownerLabel"]', "Owner 1 (browser)");
    await page.click("#v4-add-owner"); await page.waitForSelector('[data-rows="owner"] .addr-row[data-row="1"]');
    await page.fill('[data-rows="owner"] .addr-row[data-row="1"] [name="owner"]', A.recipient1);
    await page.fill('[data-rows="owner"] .addr-row[data-row="1"] [name="ownerLabel"]', "Owner 2 (independent key)");
    await page.click("#v4-add-owner"); await page.waitForSelector('[data-rows="owner"] .addr-row[data-row="2"]');
    await page.fill('[data-rows="owner"] .addr-row[data-row="2"] [name="owner"]', A.recipient2);
    await page.fill('[data-rows="owner"] .addr-row[data-row="2"] [name="ownerLabel"]', "Owner 3");
    await page.click("[data-setup-step='owners'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "approvals");
    await page.selectOption('[name="ownerM"]', "2");
    await page.click("[data-setup-step='approvals'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "emergency");
    await page.click("[data-setup-step='emergency'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "funding");
    const root23Label = `UX 2-of-3 root ${Date.now().toString(36)}`;
    await page.fill('[name="label"]', root23Label);
    await page.click("[data-setup-step='funding'] [data-setup-next]");
    await page.waitForFunction(() => document.querySelector(".stepper-item[aria-current='step']")?.getAttribute("data-step") === "review");
    await page.click("[data-setup-build]");
    await page.waitForSelector("#v4-orgroot-confirm", { timeout: 120000 });
    await page.click("#v4-orgroot-confirm");
    await waitOutcome();
    const r23Out = await outcomeState();
    check("UX-03: 2-of-3 root genesis (three distinct owner keys) approved by the funder and submitted — CHAIN_VERIFIED", r23Out === "CHAIN_VERIFIED", String(r23Out));
    await page.waitForSelector('[data-viewroot]', { timeout: 60000 });
    const row23 = page.locator('[data-org-root-section="on-chain"] tr', { hasText: root23Label }).first();
    await row23.waitFor({ timeout: 60000 });
    let live23 = false;
    for (let i = 0; i < 12 && !live23; i++) {
      await row23.locator('[data-viewroot]').click();
      await page.waitForSelector('[data-org-root-detail]', { timeout: 30000 });
      live23 = await page.evaluate(() => /live outpoint/.test(document.querySelector('[data-org-root-detail]')?.textContent || ""));
      if (!live23) { await page.click('[data-rootreconcile]'); await page.waitForTimeout(5000); await page.click("#v4-orgroot-detail-close").catch(() => {}); await page.waitForTimeout(500); }
    }
    check("UX-03: the 2-of-3 root reconciles to a live outpoint", live23);
    const root23 = ((await (await fetch(`${URL_BASE}/api/v1/org-roots`)).json()).orgRoots || []).find((r) => r.label === root23Label);
    const pred23 = root23 && root23.live ? root23.live.outpoint : null;
    check("UX-03: the root record carries 3 owner slots, 2 of 3 required, and a live predecessor outpoint", !!root23 && Number(root23.ownerSlotsActive) === 3 && String(root23.ownerM) === "2" && !!pred23, JSON.stringify(root23 && { n: root23.ownerSlotsActive, m: root23.ownerM, live: root23.live }));
    await page.click('[data-rootaction="authorize"]');
    await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
    const req23 = await page.evaluate(() => document.querySelector("[data-org-root-request]")?.getAttribute("data-org-root-request"));
    check("UX-03: a fresh heartbeat request shows 0 of 2 collected and offers owner 1's approval", /0 of 2 collected/.test(await page.locator("#v4-modal").innerText()) && !!req23);
    await page.click("#v4-orgroot-signmyslot");
    await page.waitForFunction(() => /1 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
    check("UX-03: owner 1 approved in the browser wallet — 1 of 2 collected; Finalize stays disabled under quorum", await page.evaluate(() => !!document.querySelector("[data-rootfinalize]")?.disabled));
    const envRes = await (await fetch(`${URL_BASE}/api/v1/org-roots/${root23.rootCovenantId}/requests/${req23}/slot-request/2`)).json();
    const env2 = envRes.slotRequest || envRes;
    check("UX-03: owner 2's slot signing request is bound to this request's transaction and manifest", env2 && env2.slot && Number(env2.slot.number) === 2 && String(env2.slot.publicKey).toLowerCase() === String(AX.recipient1).toLowerCase() && typeof env2.unsignedSafeJson === "string" && JSON.parse(env2.unsignedSafeJson).id === env2.txId, JSON.stringify(env2 && { slot: env2.slot, txId: env2.txId }).slice(0, 200));
    const owner2Approval = signSlotOutOfBand(env2, "recipient1", A.recipient1);
    await page.evaluate(() => { const d = document.querySelector("#v4-orgroot-import")?.closest("details"); if (d) d.open = true; }); // the import box lives under a disclosure
    await page.fill("#v4-orgroot-import", JSON.stringify(owner2Approval));
    await page.click("#v4-orgroot-import-btn");
    await page.waitForFunction(() => /2 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
    check("UX-03: owner 2's approval — signed OUTSIDE the browser by an independent key and imported as JSON — brings the request to 2 of 2; Finalize is offered to the starting owner", await page.evaluate(() => !document.querySelector("[data-rootfinalize]")?.disabled));
    await shot(page, "sign-ux03-two-of-three-collected");
    const req23Doc = (await (await fetch(`${URL_BASE}/api/v1/org-roots/${root23.rootCovenantId}/requests/${req23}`)).json()).request;
    const req23Tx = JSON.parse(req23Doc.transaction.unsignedSafeJson);
    const pred23Spk = req23Tx.inputs[0].utxo.scriptPublicKey; // the root INPUT's script = the predecessor address (R3-08)
    try {
      const before = await independentRootCheck({ rootScriptWireHex: req23Tx.outputs[0].scriptPublicKey, predecessorScriptWireHex: pred23Spk, predecessor: pred23, successorTxId: "", expectedValue: req23Tx.outputs[0].value });
      check("UX-03 INDEPENDENT CHAIN CHECK before submit (R3-08): the predecessor root outpoint is UNSPENT at the PREDECESSOR address (which differs from the successor address) and no successor exists yet", before.networkId === "testnet-10" && before.predecessorStillUnspent && before.predecessorAddressDiffers && !before.successorFound, JSON.stringify(before));
    } catch (e) { check("UX-03 INDEPENDENT CHAIN CHECK before submit (R3-08)", false, `node query failed: ${e.message}`); }
    await page.click("[data-rootfinalize]");
    await page.waitForFunction(() => { const b = document.querySelector("[data-rootsubmit]"); return !!b && !b.disabled; }, null, { timeout: 120000 });
    check("UX-03: the starting owner's wallet signed the fee input (last, non-root input) and the request is finalized (SIGNED); Submit becomes available", /Not yet broadcast/.test(await noticeText()) && req23Tx.inputs.length === 2);
    await page.click("[data-rootsubmit]");
    await waitOutcome();
    const sub23 = await outcomeState();
    const sub23Txid = ((await noticeText()).match(/txid ([0-9a-f]{64})/) || [])[1] || null;
    check("UX-03: the 2-of-3 heartbeat authorization was submitted — CHAIN_VERIFIED with a txid", sub23 === "CHAIN_VERIFIED" && !!sub23Txid, JSON.stringify({ sub23, sub23Txid }));
    await shot(page, "sign-ux03-two-of-three-submitted");
    try {
      const ind = await independentRootCheck({ rootScriptWireHex: req23Tx.outputs[0].scriptPublicKey, predecessorScriptWireHex: pred23Spk, predecessor: pred23, successorTxId: sub23Txid || "", expectedValue: req23Tx.outputs[0].value });
      check("UX-03 INDEPENDENT CHAIN CHECK (kaspad RPC, not the app): the successor root outpoint exists at the root address with the exact root value and the predecessor outpoint is SPENT at the predecessor address (R3-08)", ind.networkId === "testnet-10" && ind.successorFound && ind.successorAmount === ind.expectedValue && !ind.predecessorStillUnspent && ind.predecessorAddressDiffers, JSON.stringify(ind));
    } catch (e) { check("UX-03 INDEPENDENT CHAIN CHECK (kaspad RPC, not the app)", false, `node query failed: ${e.message}`); }
    await page.click("#v4-orgroot-request-close").catch(() => {});

    /* ===== (e2) Codex checkpoint 3 / UX-13: DISTINCT FEE PAYER — owner 3 (an independent key, NOT the browser wallet) starts the
     * request and pays the fee with its own funds; owner 1 (browser) + owner 2 (out of band) approve; owner 3 signs the fee input
     * out of band; the browser submits; INDEPENDENT node check incl. owner 3's fuel consumed and change returned. ===== */
    const openRoot = async (label) => {
      await page.click('.v4-tab[data-view="orgs"]');
      await page.waitForSelector('[data-viewroot]', { timeout: 60000 });
      await page.locator('[data-org-root-section="on-chain"] tr', { hasText: label }).first().locator('[data-viewroot]').click();
      await page.waitForSelector('[data-org-root-detail]', { timeout: 30000 });
    };
    const rootByLabel = async (label) => (((await (await fetch(`${URL_BASE}/api/v1/org-roots`)).json()).orgRoots) || []).find((r) => r.label === label);
    const root23b = await rootByLabel(root23Label);
    const predFee = root23b && root23b.live ? root23b.live.outpoint : null;
    check("fee-payer: after the heartbeat the root has a NEW live outpoint and no pending request", !!predFee && !root23b.pendingRequestId && JSON.stringify(predFee) !== JSON.stringify(pred23), JSON.stringify({ predFee, pred23, pending: root23b && root23b.pendingRequestId }));
    const createFee = await fetch(`${URL_BASE}/api/v1/org-roots/${root23b.rootCovenantId}/requests`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "authorize", params: {}, signerAddress: A.recipient2 }) });
    const createFeeJ = await createFee.json();
    const reqFee = createFeeJ.request || null;
    const reqFeeTx = reqFee ? JSON.parse(reqFee.transaction.unsignedSafeJson) : null;
    const feeInput = reqFeeTx ? reqFeeTx.inputs[reqFeeTx.inputs.length - 1] : null;
    check("fee-payer: owner 3 (recipient2 — not the browser wallet) created the heartbeat request with ITS OWN fuel: the last input is owner 3's P2PK output", createFee.status === 201 && !!reqFee && reqFee.createdBy === A.recipient2 && reqFee.state === "AUTHORIZED" && !!feeInput && String(feeInput.utxo.scriptPublicKey).toLowerCase() === `000020${String(AX.recipient2).toLowerCase()}ac`, `${createFee.status} ${JSON.stringify(createFeeJ).slice(0, 200)}`);
    await openRoot(root23Label);
    await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
    await page.click('[data-vieworequest]');
    await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
    check("fee-payer: owner 1 opens the request started by owner 3 — 0 of 2 collected; Finalize is not offered to owner 1 (owner 3's wallet pays the fee)", /0 of 2 collected/.test(await page.locator("#v4-modal").innerText()) && (await page.evaluate(() => !!document.querySelector("[data-rootfinalize]")?.disabled)));
    await page.click("#v4-orgroot-signmyslot");
    await page.waitForFunction(() => /1 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
    const envFee2Res = await (await fetch(`${URL_BASE}/api/v1/org-roots/${root23b.rootCovenantId}/requests/${reqFee.id}/slot-request/2`)).json();
    const envFee2 = envFee2Res.slotRequest || envFee2Res;
    const owner2FeeApproval = signSlotOutOfBand(envFee2, "recipient1", A.recipient1);
    await page.evaluate(() => { const d = document.querySelector("#v4-orgroot-import")?.closest("details"); if (d) d.open = true; });
    await page.fill("#v4-orgroot-import", JSON.stringify(owner2FeeApproval));
    await page.click("#v4-orgroot-import-btn");
    await page.waitForFunction(() => /2 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
    const finTitle = await page.evaluate(() => document.querySelector("[data-rootfinalize]")?.getAttribute("title") || "");
    check("fee-payer: quorum reached (owners 1 + 2 approved) yet owner 1's browser still cannot finalize — the control names owner 3 as the wallet that pays the fee", (await page.evaluate(() => !!document.querySelector("[data-rootfinalize]")?.disabled)) && finTitle.includes(A.recipient2), finTitle);
    await shot(page, "sign-feepayer-quorum-owner3-pays");
    const fuelSigHex = signInputOutOfBand(reqFee.transaction.unsignedSafeJson, reqFeeTx.inputs.length - 1, "recipient2");
    const finRes = await fetch(`${URL_BASE}/api/v1/org-roots/${root23b.rootCovenantId}/requests/${reqFee.id}/finalize`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fuelSignatureScriptHex: fuelSigHex }) });
    const finJ = await finRes.json();
    check("fee-payer: owner 3's fee-input signature (made OUTSIDE the browser with owner 3's key) finalizes the request — SIGNED, not yet broadcast", finRes.status === 200 && !!finJ.request && finJ.request.state === "SIGNED", `${finRes.status} ${JSON.stringify(finJ).slice(0, 160)}`);
    const predSpkFee = reqFeeTx.inputs[0].utxo.scriptPublicKey;
    try {
      const before = await independentRootCheck({ rootScriptWireHex: reqFeeTx.outputs[0].scriptPublicKey, predecessorScriptWireHex: predSpkFee, predecessor: predFee, successorTxId: "", expectedValue: reqFeeTx.outputs[0].value });
      check("fee-payer INDEPENDENT CHAIN CHECK before submit: the predecessor root outpoint is still unspent at the predecessor address; no successor yet", before.predecessorStillUnspent && !before.successorFound, JSON.stringify(before));
    } catch (e) { check("fee-payer INDEPENDENT CHAIN CHECK before submit", false, `node query failed: ${e.message}`); }
    await page.click("#v4-orgroot-request-close").catch(() => {});
    await openRoot(root23Label);
    await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
    await page.click('[data-vieworequest]');
    await page.waitForFunction(() => { const b = document.querySelector("[data-rootsubmit]"); return !!b && !b.disabled; }, null, { timeout: 60000 });
    const reopenText = await page.locator("#v4-modal").innerText();
    check("fee-payer: reopening the request shows it finalized by owner 3 (SIGNED, not yet broadcast) and offers Submit to owner 1", /SIGNED|not yet broadcast|finalized/i.test(reopenText) && !(await page.evaluate(() => !!document.querySelector("[data-rootsubmit]")?.disabled)), reopenText.replace(/\s+/g, " ").slice(0, 380));
    await page.click("[data-rootsubmit]");
    await waitOutcome();
    const subFee = await outcomeState();
    const subFeeTxid = ((await noticeText()).match(/txid ([0-9a-f]{64})/) || [])[1] || null;
    check("fee-payer: submitted from owner 1's browser — CHAIN_VERIFIED with a txid", subFee === "CHAIN_VERIFIED" && !!subFeeTxid, JSON.stringify({ subFee, subFeeTxid }));
    await shot(page, "sign-feepayer-submitted");
    try {
      const ind = await independentRootCheck({ rootScriptWireHex: reqFeeTx.outputs[0].scriptPublicKey, predecessorScriptWireHex: predSpkFee, predecessor: predFee, successorTxId: subFeeTxid || "", expectedValue: reqFeeTx.outputs[0].value, extraOutpoints: [{ label: "owner3Fuel", scriptWireHex: feeInput.utxo.scriptPublicKey, outpoint: { transactionId: feeInput.transactionId, index: feeInput.index } }, { label: "owner3Change", scriptWireHex: reqFeeTx.outputs[1].scriptPublicKey, outpoint: { transactionId: subFeeTxid || "", index: 1 } }] });
      check("fee-payer INDEPENDENT CHAIN CHECK (kaspad RPC, not the app): successor root outpoint at the root address with the exact value; predecessor SPENT at the predecessor address; owner 3's fuel outpoint consumed and its change returned to owner 3's address", ind.successorFound && ind.successorAmount === ind.expectedValue && !ind.predecessorStillUnspent && ind.extra.owner3Fuel === false && ind.extra.owner3Change === true && String(reqFeeTx.outputs[1].scriptPublicKey).toLowerCase() === `000020${String(AX.recipient2).toLowerCase()}ac`, JSON.stringify(ind));
    } catch (e) { check("fee-payer INDEPENDENT CHAIN CHECK", false, `node query failed: ${e.message}`); }
    await page.click("#v4-orgroot-request-close").catch(() => {});

    /* ===== (e3) Codex checkpoint 6 / UX-03: CREATOR A != FEE PAYER B, completed through the BROWSER — owner 1 (the browser wallet)
     * STARTS the heartbeat request with fuel EXPLICITLY supplied from owner 3's wallet (the SDK's supported explicit-fuel path; the
     * request is created through the API because the browser's own action forms auto-select fuel from the connected wallet);
     * owner 1 approves in the browser and owner 2 out of band; owner 1 (the creator) is NOT offered Finalize at quorum; the browser
     * wallet switches to owner 3 (the mock signer's account switch), which IS offered Finalize, signs the fee input IN THE BROWSER
     * and submits; INDEPENDENT node check: owner 3's fuel consumed, change returned to owner 3. ===== */
    const switchWallet = async (addr) => {
      await page.evaluate((a) => window.PolicyVaultWalletSession.active().adapter.setAccount(a), addr);
      await page.waitForFunction((a) => window.PolicyVaultV4 && window.PolicyVaultV4._state.address === a && !!window.PolicyVaultV4._state.xonly && window.PolicyVaultV4._state.ready === true, addr, { timeout: 60000 });
      await page.evaluate(() => { const m = document.querySelector("#v4-modal"); if (m && m.style.display !== "none") m.style.display = "none"; });
    };
    const root23c = await rootByLabel(root23Label);
    const pred23c = root23c && root23c.live ? root23c.live.outpoint : null;
    check("creator≠payer: after owner 3's transition the root has a NEW live outpoint and no pending request", !!pred23c && !root23c.pendingRequestId && JSON.stringify(pred23c) !== JSON.stringify(predFee), JSON.stringify({ pred23c, predFee }));
    const fuelListB = ((await (await fetch(`${URL_BASE}/api/v1/wallet/fuel/${encodeURIComponent(A.recipient2)}`)).json()).utxos) || [];
    const fuelB = fuelListB.find((u) => BigInt(u.amount) > 1000000n) || null;
    check("creator≠payer: owner 3 (recipient2) holds an ordinary UTXO able to fund the network fee", !!fuelB, JSON.stringify(fuelListB.slice(0, 2)));
    const createAB = await fetch(`${URL_BASE}/api/v1/org-roots/${root23c.rootCovenantId}/requests`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "authorize", params: { fuel: fuelB }, signerAddress: A.owner }) });
    const createABJ = await createAB.json();
    const reqAB = createABJ.request || null;
    const reqABTx = reqAB ? JSON.parse(reqAB.transaction.unsignedSafeJson) : null;
    const feeInB = reqABTx ? reqABTx.inputs[reqABTx.inputs.length - 1] : null;
    const changeOutB = reqABTx ? reqABTx.outputs[reqABTx.outputs.length - 1] : null;
    check("creator≠payer: owner 1 (the browser wallet) STARTED the request (createdBy) while the fee input is owner 3's P2PK output and the change returns to OWNER 3 (SDK explicit-fuel semantics, rc21 review R6-06)", createAB.status === 201 && !!reqAB && reqAB.createdBy === A.owner && reqAB.state === "AUTHORIZED" && !!feeInB && String(feeInB.utxo.scriptPublicKey).toLowerCase() === `000020${String(AX.recipient2).toLowerCase()}ac` && !!changeOutB && String(changeOutB.scriptPublicKey).toLowerCase() === `000020${String(AX.recipient2).toLowerCase()}ac`, `${createAB.status} ${JSON.stringify(createABJ).slice(0, 200)}`);
    await openRoot(root23Label);
    await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
    await page.click('[data-vieworequest]');
    await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
    const titleAB0 = await page.evaluate(() => document.querySelector("[data-rootfinalize]")?.getAttribute("title") || "");
    check("creator≠payer: owner 1 opens the request it STARTED — 0 of 2 collected; Finalize is NOT offered under quorum (the control explains the missing approvals; the fee-owner rule is shown once quorum is met)", /0 of 2 collected/.test(await page.locator("#v4-modal").innerText()) && (await page.evaluate(() => !!document.querySelector("[data-rootfinalize]")?.disabled)) && /0 of 2 slot signatures collected/.test(titleAB0), titleAB0);
    await page.click("#v4-orgroot-signmyslot");
    await page.waitForFunction(() => /1 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
    const envAB2Res = await (await fetch(`${URL_BASE}/api/v1/org-roots/${root23c.rootCovenantId}/requests/${reqAB.id}/slot-request/2`)).json();
    const envAB2 = envAB2Res.slotRequest || envAB2Res;
    const owner2ABApproval = signSlotOutOfBand(envAB2, "recipient1", A.recipient1);
    await page.evaluate(() => { const d = document.querySelector("#v4-orgroot-import")?.closest("details"); if (d) d.open = true; });
    await page.fill("#v4-orgroot-import", JSON.stringify(owner2ABApproval));
    await page.click("#v4-orgroot-import-btn");
    await page.waitForFunction(() => /2 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
    const titleAB = await page.evaluate(() => document.querySelector("[data-rootfinalize]")?.getAttribute("title") || "");
    const nextAB = await page.locator("#v4-modal").innerText();
    check("creator≠payer: at quorum (owners 1 + 2) the CREATOR's browser still cannot finalize — finalization authority is the fee input's owner (owner 3), not `createdBy`; the next step names owner 3 and keeps the creator as metadata", (await page.evaluate(() => !!document.querySelector("[data-rootfinalize]")?.disabled)) && titleAB.includes(A.recipient2) && /funds the network fee/.test(titleAB) && new RegExp(`started by ${A.owner.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(nextAB), `${titleAB} | ${nextAB.replace(/\s+/g, " ").slice(0, 300)}`);
    await shot(page, "sign-ux03-creator-a-quorum-payer-b");
    await page.click("#v4-orgroot-request-close").catch(() => {});
    await switchWallet(A.recipient2);
    check("creator≠payer: the browser wallet switched to owner 3 (mock signer account switch; a REAL wallet account change takes the same session path)", (await page.evaluate(() => window.PolicyVaultV4._state.address)) === A.recipient2);
    await openRoot(root23Label);
    await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
    await page.click('[data-vieworequest]');
    await page.waitForFunction(() => { const b = document.querySelector("[data-rootfinalize]"); return !!b && !b.disabled; }, null, { timeout: 60000 });
    check("creator≠payer: connected as owner 3 (the fee payer, NOT the creator) the request offers Finalize with quorum met", /2 of 2 collected/.test(await page.locator("#v4-modal").innerText()) && /your wallet funds the network fee and signs the fee input/.test(await page.locator("#v4-modal").innerText()));
    const predSpkAB = reqABTx.inputs[0].utxo.scriptPublicKey;
    try {
      const before = await independentRootCheck({ rootScriptWireHex: reqABTx.outputs[0].scriptPublicKey, predecessorScriptWireHex: predSpkAB, predecessor: pred23c, successorTxId: "", expectedValue: reqABTx.outputs[0].value });
      check("creator≠payer INDEPENDENT CHAIN CHECK before finalize: the predecessor root outpoint is still unspent; no successor yet", before.predecessorStillUnspent && !before.successorFound, JSON.stringify(before));
    } catch (e) { check("creator≠payer INDEPENDENT CHAIN CHECK before finalize", false, `node query failed: ${e.message}`); }
    await page.click("[data-rootfinalize]");
    await page.waitForFunction(() => { const b = document.querySelector("[data-rootsubmit]"); return !!b && !b.disabled; }, null, { timeout: 120000 });
    check("creator≠payer: owner 3's wallet signed the fee input IN THE BROWSER (through the same signing boundary) — SIGNED, not yet broadcast; Submit offered", /Not yet broadcast/.test(await noticeText()) && (await page.evaluate(() => !document.querySelector("[data-rootsubmit]")?.disabled)));
    await shot(page, "sign-ux03-payer-b-finalized-in-browser");
    await page.click("[data-rootsubmit]");
    await waitOutcome();
    const subAB = await outcomeState();
    const subABTxid = ((await noticeText()).match(/txid ([0-9a-f]{64})/) || [])[1] || null;
    check("creator≠payer: submitted from owner 3's browser — CHAIN_VERIFIED with a txid", subAB === "CHAIN_VERIFIED" && !!subABTxid, JSON.stringify({ subAB, subABTxid }));
    await shot(page, "sign-ux03-payer-b-submitted");
    try {
      const ind = await independentRootCheck({ rootScriptWireHex: reqABTx.outputs[0].scriptPublicKey, predecessorScriptWireHex: predSpkAB, predecessor: pred23c, successorTxId: subABTxid || "", expectedValue: reqABTx.outputs[0].value, extraOutpoints: [{ label: "owner3Fuel", scriptWireHex: feeInB.utxo.scriptPublicKey, outpoint: { transactionId: feeInB.transactionId, index: feeInB.index } }, { label: "owner3Change", scriptWireHex: changeOutB.scriptPublicKey, outpoint: { transactionId: subABTxid || "00".repeat(32), index: reqABTx.outputs.length - 1 } }] });
      check("creator≠payer INDEPENDENT CHAIN CHECK (kaspad RPC, not the app): successor root outpoint at the root address with the exact value; predecessor SPENT at the predecessor address; owner 3's fuel outpoint consumed and its change returned to owner 3", ind.successorFound && ind.successorAmount === ind.expectedValue && !ind.predecessorStillUnspent && ind.extra.owner3Fuel === false && ind.extra.owner3Change === true, JSON.stringify(ind));
    } catch (e) { check("creator≠payer INDEPENDENT CHAIN CHECK", false, `node query failed: ${e.message}`); }
    await page.click("#v4-orgroot-request-close").catch(() => {});
    await switchWallet(A.owner);
    check("creator≠payer: the browser wallet switched back to owner 1", (await page.evaluate(() => window.PolicyVaultV4._state.address)) === A.owner);

    /* ===== (g) rc18 review R3-02: "Change owners and rules" builds a REAL durable rotate request (the server accepts the
     * browser's params.newOwnerSet); it is then withdrawn so the root stays unchanged. ===== */
    await openRoot(root23Label);
    await page.waitForSelector('[data-rootaction="rotate"]:not([disabled])', { timeout: 30000 });
    await page.click('[data-rootaction="rotate"]');
    await page.waitForSelector('[data-orgroot-newset]', { timeout: 30000 });
    await page.selectOption('[data-orgroot-newset] [name="ownerM"]', "3");
    await page.click('[data-orgroot-newset] button[type="submit"]');
    await page.waitForSelector("#v4-orgroot-typed", { timeout: 30000 });
    await page.fill("#v4-orgroot-typed", "CONFIRM ROTATE");
    await page.click("#v4-orgroot-danger-confirm");
    await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
    const rootRot = await rootByLabel(root23Label);
    const rotReq = rootRot && rootRot.pendingRequestId ? (await (await fetch(`${URL_BASE}/api/v1/org-roots/${root23b.rootCovenantId}/requests/${rootRot.pendingRequestId}`)).json()).request : null;
    const rotAfter = rotReq && rotReq.manifest && rotReq.manifest.ownerSet ? rotReq.manifest.ownerSet.after : null;
    check("R3-02: 'Change owners and rules' (same owners, 3 of 3) built a REAL durable rotate request through the server — the browser's new-owner-set shape reached the SDK builder; 0 of 2 collected", !!rotReq && rotReq.action === "rotate" && rotReq.state === "AUTHORIZED" && !!rotAfter && String(rotAfter.ownerM) === "3" && /0 of 2 collected/.test(await page.locator("#v4-modal").innerText()), JSON.stringify(rotReq && { action: rotReq.action, state: rotReq.state, ownerM: rotAfter && rotAfter.ownerM }));
    await shot(page, "sign-r302-rotate-request-built");
    page.once("dialog", (d) => d.accept());
    await page.click("[data-rootreject]");
    await page.waitForFunction(() => /withdrawn/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 30000 });
    const rootRot2 = await rootByLabel(root23Label);
    check("R3-02: the rotate request was withdrawn — the root has no pending request and its live outpoint is unchanged", !!rootRot2 && !rootRot2.pendingRequestId && JSON.stringify(rootRot2.live && rootRot2.live.outpoint) === JSON.stringify({ transactionId: subABTxid, index: 0 }), JSON.stringify(rootRot2 && { pending: rootRot2.pendingRequestId, live: rootRot2.live }));

    /* ===== (h) UX-10: a root whose DESIGNATED SUCCESSOR is the browser wallet (its owners are two independent keys). The successor
     * builds and signs a succession installing a MULTI-OWNER replacement through the pinned-successor path. The young-root
     * submission reaches the node's relative-age gate; public reconciliation verifies rejection and retains the original request. ===== */
    const succLabel = `UX-10 succession root ${Date.now().toString(36)}`;
    const genRes = await fetch(`${URL_BASE}/api/v1/org-roots`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ label: succLabel, owners: [{ slot: 1, publicKey: AX.recipient1 }, { slot: 2, publicKey: AX.recipient2 }], ownerM: 1, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: A.owner, rootValueKas: "1", rootMaxFeePerTxKas: "0.01", signerAddress: A.owner }) });
    const genJ = await genRes.json();
    const genReq = genJ.request || null;
    const genSuccessorPk = genReq && genReq.manifest && genReq.manifest.template ? String(genReq.manifest.template.successorPk || "").toLowerCase() : "";
    check("UX-10: a root with two independent owner keys and the browser wallet as DESIGNATED SUCCESSOR is built (funded by the browser wallet, which owns no slot)", genRes.status === 201 && !!genReq && genSuccessorPk === String(AX.owner).toLowerCase(), `${genRes.status} successorPk=${genSuccessorPk} slots=${JSON.stringify(genReq && genReq.slots && genReq.slots.map((x) => x.publicKey))}`);
    let succRoot = null;
    if (genReq) {
      const ds = await (await fetch(`${URL_BASE}/api/v1/wallet/dev-sign`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ address: A.owner, unsignedSafeJson: genReq.transaction.unsignedSafeJson, signInputs: genReq.transaction.signInputs }) })).json();
      const sigRes = await fetch(`${URL_BASE}/api/v1/org-roots/${genReq.rootCovenantId}/requests/${genReq.id}/signature`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ signedSafeJson: ds.signedSafeJson }) });
      const subRes = sigRes.status === 200 ? await fetch(`${URL_BASE}/api/v1/org-roots/${genReq.rootCovenantId}/requests/${genReq.id}/submit`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }) : null;
      const subJ = subRes ? await subRes.json() : null;
      check("UX-10: the succession root genesis was signed by the funder (TEST dev signer) and submitted — CHAIN_VERIFIED", !!subJ && subJ.request && subJ.request.state === "CHAIN_VERIFIED", `${sigRes.status} ${subRes && subRes.status} ${JSON.stringify(subJ).slice(0, 160)}`);
      for (let i = 0; i < 12 && !(succRoot && succRoot.live); i++) {
        await fetch(`${URL_BASE}/api/v1/org-roots/${genReq.rootCovenantId}/reconcile`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).catch(() => {});
        succRoot = await rootByLabel(succLabel);
        if (!(succRoot && succRoot.live)) await page.waitForTimeout(5000);
      }
    }
    check("UX-10: the succession root reconciles to a live outpoint", !!(succRoot && succRoot.live), JSON.stringify(succRoot && { live: succRoot.live }));
    if (succRoot && succRoot.live) {
      await openRoot(succLabel);
      const roleText = await page.locator('[data-org-root-detail]').innerText();
      check("UX-10: the root detail tells the connected wallet it is the DESIGNATED SUCCESSOR (not an owner) and offers Succession", /successor/i.test(roleText) && (await page.locator('[data-rootaction="succession"]:not([disabled])').count()) === 1 && (await page.locator('[data-rootaction="authorize"]:not([disabled])').count()) === 0, roleText.slice(0, 300));
      await page.click('[data-rootaction="succession"]');
      await page.waitForSelector('[data-orgroot-newset]', { timeout: 30000 });
      /* replacement set: the successor plus owner 2 (recipient1) — a MULTI-owner replacement, 2 of 2 */
      await page.click("#v4-add-owner").catch(() => {});
      await page.waitForSelector('[data-orgroot-newset] [data-rows="owner"] .addr-row[data-row="1"]', { timeout: 10000 }).catch(() => {});
      await page.fill('[data-orgroot-newset] [data-rows="owner"] .addr-row[data-row="0"] [name="owner"]', A.owner);
      await page.fill('[data-orgroot-newset] [data-rows="owner"] .addr-row[data-row="1"] [name="owner"]', A.recipient1);
      await page.selectOption('[data-orgroot-newset] [name="ownerM"]', "2").catch(() => {});
      await page.click('[data-orgroot-newset] button[type="submit"]');
      await page.waitForSelector("#v4-orgroot-typed", { timeout: 30000 });
      const dangerText = await page.locator("#v4-modal").innerText();
      check("UX-10: the succession confirmation states the waiting period (age gate) — this is the successor's own path, not an owner approval", /untouched|waiting period|idle/i.test(dangerText), dangerText.slice(0, 300));
      await shot(page, "sign-ux10-succession-confirm");
      await page.fill("#v4-orgroot-typed", "CONFIRM SUCCESSION");
      const successionSubmission = page.waitForResponse((r) => r.request().method() === "POST" && r.url().includes(`/org-roots/${succRoot.rootCovenantId}/requests/`) && r.url().endsWith("/submit"), { timeout: 180000 });
      await page.click("#v4-orgroot-danger-confirm");
      /* the successor's wallet signs through the pinned-successor binding and the app submits; a YOUNG root cannot be
       * succeeded — consensus (the relative-age sequence lock) rejects the transaction at the node: the AGE GATE. */
      await successionSubmission;
      await page.waitForSelector("[data-org-root-request]", { timeout: 30000 });
      const succNotice = await noticeText();
      const succReqs = ((await (await fetch(`${URL_BASE}/api/v1/org-roots/${succRoot.rootCovenantId}/requests`)).json()).requests) || [];
      let succReq = succReqs.find((r) => r.action === "succession") || null;
      // A first node refusal is retained until public reconciliation proves
      // the negative outcome. Exercise the browser's existing recovery path;
      // never try to withdraw an attempted request or rebuild around its guard.
      if (succReq && succReq.state === "RECONCILIATION_REQUIRED") {
        const original = { id: succReq.id, txId: succReq.txId };
        const pending = await rootByLabel(succLabel);
        check("F-1 browser: an attempted succession remains the root's original pending request before outcome verification", pending && pending.pendingRequestId === original.id, JSON.stringify(original));
        await page.click("#v4-orgroot-request-close").catch(() => {});
        await openRoot(succLabel);
        const response = page.waitForResponse((r) => r.request().method() === "POST" && r.url().endsWith(`/org-roots/${succRoot.rootCovenantId}/reconcile`), { timeout: 180000 });
        await page.click("[data-rootreconcile]");
        const reconciled = await (await response).json();
        const refreshed = ((await (await fetch(`${URL_BASE}/api/v1/org-roots/${succRoot.rootCovenantId}/requests`)).json()).requests) || [];
        succReq = refreshed.find((r) => r.id === original.id) || null;
        const settled = reconciled.reconcile && reconciled.reconcile.root && reconciled.reconcile.root.status === "CLAIM_RELEASED" && succReq && succReq.txId === original.txId && succReq.state === "SUBMISSION_REJECTED";
        check("F-1 browser: Verify state settles the SAME rejected succession request through public reconciliation", settled, JSON.stringify({ reconcile: reconciled.reconcile, requestId: succReq && succReq.id, state: succReq && succReq.state }));
        if (!settled) throw Error(`original succession request ${original.id} remains unresolved; preserve it without withdrawal or replacement`);
        await page.waitForFunction((rootId) => document.querySelector(`[data-org-root-detail="${rootId}"]`) && !document.querySelector("[data-vieworequest]"), succRoot.rootCovenantId, { timeout: 30000 });
        await page.click("#v4-orgroot-detail-close");
      }
      const succAfter = succReq && succReq.manifest && succReq.manifest.ownerSet ? succReq.manifest.ownerSet.after : null;
      const installed = succAfter && Array.isArray(succAfter.slots) ? succAfter.slots.filter((sl) => sl && sl.publicKey && !/^0+$/.test(sl.publicKey)).length : 0;
      const pinnedOk = !!succReq && String(succReq.manifest && succReq.manifest.root && succReq.manifest.root.template && succReq.manifest.root.template.successorPk).toLowerCase() === String(AX.owner).toLowerCase();
      check("UX-10: the browser built a REAL succession request (no params error) installing a MULTI-owner replacement (2 owners, 2 of 2), created by the PINNED successor (not by an owner slot)", !!succReq && succReq.createdBy === A.owner && installed === 2 && String(succAfter && succAfter.ownerM) === "2" && pinnedOk, JSON.stringify(succReq && { action: succReq.action, state: succReq.state, installed, ownerM: succAfter && succAfter.ownerM, error: succReq.error }));
      const ageGated = !!succReq && succReq.state === "SUBMISSION_REJECTED" && /sequence|lock|mature|age|immature|not yet|too young|relative/i.test(String(succReq.submissionAttempt && succReq.submissionAttempt.error || (succReq.error && (succReq.error.message || succReq.error)) || succNotice));
      check("UX-10 (age gate): the successor's wallet signed it (pinned-successor binding, real payload) and the SUBMISSION was refused by the node's relative-age sequence lock — the root is young; nothing changed on-chain", ageGated, `state=${succReq && succReq.state} error=${JSON.stringify(succReq && succReq.error).slice(0, 200)} notice=${succNotice.slice(0, 200)}`);
      await shot(page, "sign-ux10-succession-age-gate");
      const succRoot3 = await rootByLabel(succLabel);
      try {
        const live = await independentRootCheck({ rootScriptWireHex: succReq ? JSON.parse(succReq.transaction.unsignedSafeJson).inputs[0].utxo.scriptPublicKey : genReq.transaction && JSON.parse(genReq.transaction.unsignedSafeJson).outputs[0].scriptPublicKey, predecessor: succRoot.live.outpoint, successorTxId: "", expectedValue: succRoot.live.value || "0" });
        check("UX-10 INDEPENDENT CHAIN CHECK: the succession root's live outpoint is still unspent at its address and the root has no pending request", live.predecessorStillUnspent && !!succRoot3 && !succRoot3.pendingRequestId && JSON.stringify(succRoot3.live && succRoot3.live.outpoint) === JSON.stringify(succRoot.live.outpoint), JSON.stringify({ live, pending: succRoot3 && succRoot3.pendingRequestId }));
      } catch (e) { check("UX-10 INDEPENDENT CHAIN CHECK", false, `node query failed: ${e.message}`); }
    }
    /* ===== (h2) Codex checkpoint 6 / UX-09: a succession request's DETAIL is described by its successor-signature role — the
     * successor is never "read-only" nor told to collect owner approvals; another viewer gets no owner-approval guidance. A fresh
     * succession request is created through the API on the clean succession root (the browser's own flow signs and submits at once),
     * opened AUTHORIZED as the successor and as owner 2, then withdrawn so the root stays clean. ===== */
    {
      const succRootH = await rootByLabel(succLabel);
      if (succRootH && succRootH.live && !succRootH.pendingRequestId) {
        const zero = "00".repeat(32);
        const newOwnerSet = { owners: [AX.recipient2, AX.recipient1, ...Array(10).fill(zero)], ownerM: "2", emergencyK: "1", recoveryM: "1" }; // D1: owner 1 must change (the previous owner 1 is recipient1)
        const cs = await fetch(`${URL_BASE}/api/v1/org-roots/${succRootH.rootCovenantId}/requests`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "succession", params: { newOwnerSet }, signerAddress: A.owner }) });
        const csJ = await cs.json();
        const succReqH = csJ.request || null;
        check("UX-09: a succession request (no owner slots, required 1, 0 owner signatures) is created by the pinned successor (browser wallet) through the API", cs.status === 201 && !!succReqH && succReqH.state === "AUTHORIZED" && Array.isArray(succReqH.slots) && succReqH.slots.length === 0 && String(succReqH.requiredApprovals) === "1", `${cs.status} ${JSON.stringify(csJ).slice(0, 200)}`);
        if (succReqH) {
          /* the previous section may leave the age-gate outcome modal open — it would intercept the tab click */
          await page.click("#v4-orgroot-request-close").catch(() => {});
          await page.evaluate(() => { const m = document.querySelector("#v4-modal"); if (m && m.style.display !== "none") m.style.display = "none"; });
          await openRoot(succLabel);
          await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
          await page.click('[data-vieworequest]');
          await page.waitForSelector("#v4-orgroot-signsuccession", { timeout: 60000 });
          const t1 = (await page.locator("#v4-modal").innerText()).replace(/\s+/g, " ");
          check("UX-09 (successor, AUTHORIZED): the detail says the succession is authorized by the successor's own signature, shows 'not yet signed by the designated successor', offers 'Approve in wallet (designated successor)', and NEVER says read-only / collect owner approvals / 0 of 1 collected; no Finalize control", /authorized by YOUR signature alone/.test(t1) && /not yet signed by the designated successor/.test(t1) && /awaiting the designated successor's signature/.test(t1) && !/read-only/.test(t1) && !/Collect \d+ more owner approval/.test(t1) && !/0 of 1 collected/.test(t1) && (await page.evaluate(() => !document.querySelector("[data-rootfinalize]") && !!document.querySelector("#v4-orgroot-signsuccession"))), t1.slice(0, 400));
          await shot(page, "sign-ux09-succession-authorized-successor-view");
          await page.click("#v4-orgroot-request-close").catch(() => {});
          await switchWallet(A.recipient1);
          await openRoot(succLabel);
          await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
          await page.click('[data-vieworequest]');
          await page.waitForSelector("[data-org-root-request]", { timeout: 60000 });
          const t2 = (await page.locator("#v4-modal").innerText()).replace(/\s+/g, " ");
          check("UX-09 (owner 2 viewing, AUTHORIZED): the detail says the succession is authorized by the designated successor's signature alone and is waiting for the successor — no owner-approval guidance, no 'your approval is needed', no Finalize", /authorized by the designated successor's signature alone/.test(t2) && /Waiting for the designated successor to sign/.test(t2) && !/Collect \d+ more owner approval/.test(t2) && !/your approval is needed/.test(t2) && (await page.evaluate(() => !document.querySelector("[data-rootfinalize]") && !document.querySelector("#v4-orgroot-signsuccession"))), t2.slice(0, 400));
          await shot(page, "sign-ux09-succession-authorized-owner-view");
          await page.click("#v4-orgroot-request-close").catch(() => {});
          await switchWallet(A.owner);
          await openRoot(succLabel);
          await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
          await page.click('[data-vieworequest]');
          await page.waitForSelector("[data-rootreject]", { timeout: 60000 });
          page.once("dialog", (d) => d.accept());
          await page.click("[data-rootreject]");
          await page.waitForFunction(() => /withdrawn/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 30000 });
          const succRootH2 = await rootByLabel(succLabel);
          check("UX-09: the succession request was withdrawn — the succession root has no pending request and its live outpoint is unchanged", !!succRootH2 && !succRootH2.pendingRequestId && JSON.stringify(succRootH2.live && succRootH2.live.outpoint) === JSON.stringify(succRootH.live.outpoint));
        }
      } else {
        check("UX-09: the succession root is live with no pending request (precondition for the detail-rendering checks)", false, JSON.stringify(succRootH && { live: !!succRootH.live, pending: succRootH.pendingRequestId }));
      }
    }
    /* leave no modal open before the rooted-vault sections */
    await page.click("#v4-orgroot-request-close").catch(() => {});
    await page.evaluate(() => { const m = document.querySelector("#v4-modal"); if (m && m.style.display !== "none") m.style.display = "none"; });

    /* ===== (i) R7-05 / F-6 (owner-approved; launch scope 2026-09-08): rooted-vault OWNER OPERATIONS started IN THE BROWSER from the
     * root detail, one vault operation per root request, through the ordinary M-of-N path (owner 1 in the browser, owner 2 out of
     * band, owner 1 pays and finalizes, the browser submits), with INDEPENDENT kaspad checks; and the reservation / withdrawal
     * guidance: an unsigned request reserves the root and guards the vault, a dismissed wallet prompt releases nothing, only an
     * UNSIGNED never-attempted request is withdrawn, a signed one is finalized/submitted, a partially signed one cannot be
     * withdrawn (server CANNOT_REJECT), reload/reopen returns to the SAME request. Bounded unique transactions in this section:
     * issuance 1 + rooted-vault genesis 1 + top-up 1 + pause 1 + unpause 1 + agent rules 1 + close&recover 1 = 7. ===== */
    {
      const rootR = await rootByLabel(root23Label);
      const rootIdR = rootR.rootCovenantId;
      check("R7-05: precondition — the 2-of-3 root is live with no pending request", !!rootR && !!rootR.live && !rootR.pendingRequestId, JSON.stringify(rootR && { live: rootR.live, pending: rootR.pendingRequestId }));
      const daaNow = String((await (await fetch(`${URL_BASE}/api/v1/network/status`)).json()).virtualDaaScore);
      /* (i.1) node-side: issue a TEST token (owner key), then create the rooted vault THROUGH THE API, signed by the dev signer */
      let issued = null;
      try { issued = await issueTestToken({ role: "owner", ownerXOnly: AX.owner }); } catch (e) { check("R7-05: test-token issuance (node-side, TEST key, 1 broadcast)", false, e.message); }
      check("R7-05: a KCC20 test token was issued on testnet-10 for the rooted vault (node-side, owner TEST key; 1 broadcast)", !!issued && /^[0-9a-f]{64}$/.test(issued.txId), JSON.stringify(issued && { txId: issued.txId, tokenCovenantId: issued.tokenCovenantId }));
      const descriptor = issued ? { schema: "policyvault-asset-descriptor/1", assetId: require("crypto").randomBytes(32).toString("hex"), displayName: "UX launch test token", tokenStandard: "kcc20/1", tokenCovenantId: issued.tokenCovenantId, acceptedTransferTemplates: [{ templateVmHashBlake2b256: issued.program.templateVmHashBlake2b256, prefixLen: issued.program.geometry.prefixLen, suffixLen: issued.program.geometry.suffixLen, stateLayout: "kcc20-state/1" }], decimalsDisplay: 2, issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false } } : null;
      const policy0 = { agentPk: AX.delegate, tokenMaxPerSpend: "250", tokenPeriodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: daaNow, tokenPeriodSpent: "0", agentMaxFeePerTx: "100000000", agentMaxCarryKas: "25000000", recipients: [AX.recipient1] };
      const vaultLabel = `UX launch rooted vault ${Date.now().toString(36)}`;
      let vaultId = null;
      if (descriptor) {
        const cv = await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/vaults`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ profile: "policyvault-0.7-payment", label: vaultLabel, descriptor, templateIndex: 0, agents: [policy0], recoveryAddress: A.recipient3, feeReserveKas: "1", signerAddress: A.owner }) });
        const cvJ = await cv.json();
        const gq = cvJ.request || null;
        check("R7-05: rooted-vault genesis request built through the API under the 2-of-3 root (1 KAS fee reserve, delegate rule for the test agent, recovery key = recipient3)", cv.status === 201 && !!gq && gq.kind === "rootedVaultGenesis" && gq.state === "AUTHORIZED", `${cv.status} ${JSON.stringify(cvJ).slice(0, 200)}`);
        if (gq) {
          const ds = await (await fetch(`${URL_BASE}/api/v1/wallet/dev-sign`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ address: A.owner, unsignedSafeJson: gq.transaction.unsignedSafeJson, signInputs: gq.transaction.signInputs }) })).json();
          const sg = await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests/${gq.id}/signature`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ signedSafeJson: ds.signedSafeJson }) });
          const sb = sg.status === 200 ? await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests/${gq.id}/submit`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }) : null;
          const sbJ = sb ? await sb.json() : null;
          check("R7-05: the rooted-vault genesis was signed by the funder (TEST dev signer) and submitted — CHAIN_VERIFIED", !!sbJ && sbJ.request && sbJ.request.state === "CHAIN_VERIFIED", `${sg.status} ${sb && sb.status} ${JSON.stringify(sbJ).slice(0, 160)}`);
          vaultId = gq.manifest && gq.manifest.vaultId ? gq.manifest.vaultId : null;
        }
      }
      const vaultsOf = async () => (((await (await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/vaults`)).json()).vaults) || []);
      let vaultRec = null;
      for (let i = 0; i < 12 && !(vaultRec && vaultRec.live); i++) {
        await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/reconcile`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).catch(() => {});
        vaultRec = (await vaultsOf()).find((v) => v.vaultId === vaultId) || null;
        if (!(vaultRec && vaultRec.live)) await page.waitForTimeout(5000);
      }
      check("R7-05: the rooted vault reconciles to a live outpoint and its presented summary carries the installed delegate rule, the pinned recovery key and the fee reserve", !!vaultRec && !!vaultRec.live && vaultRec.contractVersion === "policyvault-0.7-payment" && vaultRec.live.feeReserveKas === "1" && vaultRec.live.paused === false && Array.isArray(vaultRec.agents) && vaultRec.agents.length === 1 && vaultRec.agents[0].agentPk === AX.delegate && JSON.stringify(vaultRec.agents[0].recipients) === JSON.stringify([AX.recipient1]) && vaultRec.recoveryPk === AX.recipient3, JSON.stringify(vaultRec && { live: vaultRec.live, agents: vaultRec.agents, recoveryPk: vaultRec.recoveryPk }).slice(0, 400));
      if (vaultRec && vaultRec.live) {
        const vaultSel = `[data-rooted-vault-owner-ops="${vaultId}"]`;
        const opBtn = (op) => `${vaultSel} [data-rootvaultop="${op}"]`;
        const requestOf = async (id) => (await (await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests/${id}`)).json()).request;
        const pendingIdOf = async () => (await rootByLabel(root23Label)).pendingRequestId || null;
        const txidFromNotice = async () => (((await noticeText()).match(/txid ([0-9a-f]{64})/) || [])[1] || null);
        /* an open modal intercepts the tab click openRoot() starts with — always close it first (lane-01 harness sequencing lesson) */
        const closeModal = () => page.evaluate(() => { const m = document.querySelector("#v4-modal"); if (m && m.style.display !== "none") m.style.display = "none"; });
        const reopenRoot = async () => { await closeModal(); await openRoot(root23Label); };
        /* owner 1 (browser) approves, owner 2 (recipient1, OUT OF BAND) imports, owner 1 finalizes (its wallet funds the fee) and submits */
        const approveFinalizeSubmit = async (reqId, label) => {
          await page.click("#v4-orgroot-signmyslot");
          await page.waitForFunction(() => /1 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
          const envRes = await (await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests/${reqId}/slot-request/2`)).json();
          const env = envRes.slotRequest || envRes;
          const approval = signSlotOutOfBand(env, "recipient1", A.recipient1);
          await page.evaluate(() => { const d = document.querySelector("#v4-orgroot-import")?.closest("details"); if (d) d.open = true; });
          await page.fill("#v4-orgroot-import", JSON.stringify(approval));
          await page.click("#v4-orgroot-import-btn");
          await page.waitForFunction(() => /2 of 2 collected/.test(document.querySelector("#v4-modal")?.textContent || ""), null, { timeout: 60000 });
          const atQuorum = await page.locator("#v4-modal").innerText();
          check(`${label}: at quorum (owner 1 in the browser + owner 2 imported) Withdraw is NOT offered — the reservation row says a signed request is not withdrawn`, !(await page.locator("[data-rootreject]").count()) && /a request carrying a signature is not withdrawn|finalized/i.test(atQuorum), atQuorum.replace(/\s+/g, " ").slice(0, 200));
          const rj = await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests/${reqId}/reject`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: "hostile: withdraw a signed request" }) });
          const rjJ = await rj.json();
          check(`${label}: the server itself refuses to withdraw a request carrying owner signatures (409 CANNOT_REJECT)`, rj.status === 409 && rjJ.error && rjJ.error.code === "CANNOT_REJECT", `${rj.status} ${JSON.stringify(rjJ).slice(0, 160)}`);
          await page.click("[data-rootfinalize]");
          await page.waitForFunction(() => { const b = document.querySelector("[data-rootsubmit]"); return !!b && !b.disabled; }, null, { timeout: 120000 });
          const finalizedText = await page.locator("#v4-modal").innerText();
          check(`${label}: owner 1's wallet signed the fee input — SIGNED, not yet broadcast; Submit offered; Withdraw NOT offered; the reservation row says a finalized request resumes its original submission`, /Not yet broadcast/.test(await noticeText()) && !(await page.locator("[data-rootreject]").count()) && /finalized request is never withdrawn|resume/i.test(finalizedText), finalizedText.replace(/\s+/g, " ").slice(0, 200));
          await reopenRoot();
          await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
          const banner = await page.locator("[data-root-reservation]").innerText();
          check(`${label}: reopening the root shows the reservation banner naming this request and 'Submit' as the authorized next step (resume)`, (await page.getAttribute("[data-root-reservation]", "data-reservation-next")) === "resume" && /ORIGINAL finalized transaction is resumed/.test(banner), banner.slice(0, 200));
          await page.click('[data-vieworequest]');
          await page.waitForFunction(() => { const b = document.querySelector("[data-rootsubmit]"); return !!b && !b.disabled; }, null, { timeout: 60000 });
          const reqBefore = await requestOf(reqId);
          await page.click("[data-rootsubmit]");
          await waitOutcome();
          const st = await outcomeState();
          const txid = await txidFromNotice();
          check(`${label}: submitted from the browser — CHAIN_VERIFIED with a txid; the request id is unchanged`, st === "CHAIN_VERIFIED" && !!txid && txid === reqBefore.txId, JSON.stringify({ st, txid, reqTx: reqBefore.txId }));
          await page.click("#v4-orgroot-request-close").catch(() => {});
          return { txid, unsignedSafeJson: reqBefore.transaction.unsignedSafeJson };
        };
        const startOp = async (op, label) => {
          await reopenRoot();
          await page.waitForSelector(opBtn(op), { timeout: 30000 });
          const disabled = await page.evaluate((s) => document.querySelector(s)?.disabled, opBtn(op));
          check(`${label}: the '${op}' control is offered and enabled on the vault panel for the connected OWNER`, disabled === false, `disabled=${disabled}`);
          await page.click(opBtn(op));
          await page.waitForSelector(`[data-vaultop-form="${op}"]`, { timeout: 30000 });
        };
        let createPosts = 0;
        page.on("request", (rq) => { if (rq.method() === "POST" && rq.url() === `${URL_BASE}/api/v1/org-roots/${rootIdR}/requests`) createPosts++; });

        /* (i.2) the panel */
        await reopenRoot();
        await page.waitForSelector(vaultSel, { timeout: 30000 });
        const panel = await page.locator(vaultSel).innerText();
        const ops = await page.evaluate((s) => [...document.querySelectorAll(`${s} [data-rootvaultop]`)].map((b) => ({ op: b.getAttribute("data-rootvaultop"), disabled: b.disabled, title: b.getAttribute("title") })), vaultSel);
        check("R7-05: the root detail shows the rooted vault's panel — live state, installed delegate rule, pinned recovery key — with the six owner-operation controls; Unpause is disabled (vault not paused) with its reason", /Fee reserve 1 KAS/.test(panel) && /1 delegate rule installed/.test(panel) && new RegExp(AX.recipient3).test(panel) && ops.length === 6 && ops.filter((o) => o.disabled).length === 1 && ops.find((o) => o.op === "ownerUnpause").disabled && /not paused/.test(ops.find((o) => o.op === "ownerUnpause").title), JSON.stringify(ops));
        await shot(page, "sign-r705-vault-panel");
        /* (i.3) phone-width usability of the operation form (375 px) + keyboard */
        {
          const phone = await browser.newPage({ viewport: { width: 375, height: 740 }, deviceScaleFactor: 2 });
          await connectMock(phone);
          await phone.click('.v4-tab[data-view="orgs"]');
          await phone.waitForSelector('[data-viewroot]', { timeout: 60000 });
          await phone.locator('[data-org-root-section="on-chain"] tr', { hasText: root23Label }).first().locator('[data-viewroot]').click();
          await phone.waitForSelector(opBtn("ownerSetAgentRoot"), { timeout: 30000 });
          await noHorizontalOverflow(phone, "phone 375: root detail with the rooted-vault panel");
          await phone.click(opBtn("ownerSetAgentRoot"));
          await phone.waitForSelector('[data-vaultop-form="ownerSetAgentRoot"]', { timeout: 30000 });
          await noHorizontalOverflow(phone, "phone 375: change-agent-rules form");
          await controlsAtLeast44(phone, '[data-vaultop-form="ownerSetAgentRoot"]', "phone 375: change-agent-rules form");
          await inputsLabelled(phone, '[data-vaultop-form="ownerSetAgentRoot"]', "phone 375: change-agent-rules form");
          const prefill = await phone.evaluate(() => ({ key: document.querySelector('[name="agent-0-agentKey"]')?.value, cap: document.querySelector('[name="agent-0-tokenMaxPerSpend"]')?.value, rec: document.querySelector('[name="agent-0-recipients"]')?.value, start: document.querySelector('[name="agent-0-periodStartDaa"]')?.value }));
          check("R7-05 phone: the change-agent-rules form is prefilled EXACTLY from the installed rule (agent key, cap 250, the recipient, the exact period start)", prefill.key === AX.delegate && prefill.cap === "250" && prefill.rec === AX.recipient1 && prefill.start === daaNow, JSON.stringify(prefill));
          await shot(phone, "sign-r705-phone-agent-rules-form");
          await phone.focus('[name="agent-0-tokenMaxPerSpend"]');
          let guard = 0;
          while (guard++ < 40) { await phone.keyboard.press("Tab"); const isSubmit = await phone.evaluate(() => document.activeElement && document.activeElement.matches('[data-vaultop-form] button[type="submit"]')); if (isSubmit) break; }
          check("R7-05 phone keyboard: Tab reaches the form's submit control", guard < 40);
          await phone.click("[data-vaultop-cancel]");
          await phone.waitForSelector("[data-org-root-detail]", { timeout: 30000 });
          check("R7-05 phone: Cancel returns to the root detail without creating a request", (await pendingIdOf()) === null);
          await phone.close();
        }
        /* (i.4) TOP UP the fee reserve from the browser; F-6 unsigned-request semantics; withdraw; then the real transition */
        await startOp("ownerTopUpReserve", "R7-05 top-up");
        await page.fill('[data-vaultop-form="ownerTopUpReserve"] [name="amount"]', "0");
        await page.click('[data-vaultop-form="ownerTopUpReserve"] button[type="submit"]');
        await page.waitForFunction(() => (document.querySelector('.ferr[data-err="amount"]')?.textContent || "").length > 0, null, { timeout: 15000 });
        check("R7-05 top-up: a zero amount is refused beside the field before any request is built", /greater than 0/.test(await page.locator('.ferr[data-err="amount"]').innerText()) && createPosts === 0);
        await page.fill('[data-vaultop-form="ownerTopUpReserve"] [name="amount"]', "0.5");
        const postsBefore = createPosts;
        await page.dblclick('[data-vaultop-form="ownerTopUpReserve"] button[type="submit"]');
        await page.waitForSelector("[data-org-root-request]", { timeout: 60000 });
        await page.waitForTimeout(500);
        const topReqId = await page.getAttribute("[data-org-root-request]", "data-org-root-request");
        const topReq = await requestOf(topReqId);
        check("R7-05 top-up: a DOUBLE click created exactly ONE root request carrying ONE vaultOperations entry (ownerTopUpReserve, exact 50000000 sompi) under root action authorize", createPosts - postsBefore === 1 && !!topReq && topReq.action === "authorize" && topReq.state === "AUTHORIZED" && Array.isArray(topReq.vaultOperations) && topReq.vaultOperations.length === 1 && topReq.vaultOperations[0].action === "ownerTopUpReserve" && topReq.vaultOperations[0].vaultId === vaultId && topReq.vaultOperations[0].params.topUpReserveAmountSompi === "50000000", JSON.stringify({ posts: createPosts - postsBefore, ops: topReq && topReq.vaultOperations }));
        const topDetail = await page.locator("#v4-modal").innerText();
        check("R7-05 top-up: the request detail describes the operation from the VERIFIED manifest (Top up fee reserve on the vault; fee reserve 1 KAS → 1.5 KAS), the review is VERIFIED, the reservation row offers the safe withdrawal", /Top up fee reserve on vault/.test(topDetail) && /Fee reserve: 1 KAS → 1\.5 KAS/.test(topDetail) && (await page.getAttribute("[data-org-root-review]", "data-org-root-review")) === "verified" && (await page.getAttribute("[data-vault-operation-summary]", "data-vault-operation-summary")) === "verified" && (await page.locator("[data-rootreject]").count()) === 1 && /does not release it/.test(topDetail), topDetail.replace(/\s+/g, " ").slice(0, 300));
        await shot(page, "sign-r705-topup-request");
        /* F-6: the root is reserved and the vault guarded; the server refuses another root request; a dismissed wallet prompt keeps it */
        await reopenRoot();
        await page.waitForSelector("[data-root-reservation]", { timeout: 30000 });
        const resBanner = await page.locator("[data-root-reservation]").innerText();
        const guardedOps = await page.evaluate((s) => [...document.querySelectorAll(`${s} [data-rootvaultop]`)].map((b) => b.disabled), vaultSel);
        check("F-6: the root detail names the pending top-up request as the holder of the reservation, says it guards this vault, that a dismissed wallet prompt releases nothing, and offers Withdraw as the next step; every operation control is disabled; the vault panel points at the request", new RegExp(topReqId).test(resBanner) && /guards vault/.test(resBanner) && /does NOT release it/.test(resBanner) && (await page.getAttribute("[data-root-reservation]", "data-reservation-next")) === "withdraw" && guardedOps.length === 6 && guardedOps.every(Boolean) && (await page.locator(`[data-vault-guarded-by="${topReqId}"]`).count()) === 1, resBanner.slice(0, 300));
        await shot(page, "sign-r705-f6-reserved-root");
        const other = await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "authorize", params: {}, signerAddress: A.recipient2 }) });
        const otherJ = await other.json();
        check("F-6: while the unsigned request is pending the server refuses ANY other root request from another owner (409 ROOT_PENDING_REQUEST) — the reservation is durable and server-side", other.status === 409 && otherJ.error && otherJ.error.code === "ROOT_PENDING_REQUEST", `${other.status} ${JSON.stringify(otherJ).slice(0, 160)}`);
        await page.click(`[data-vault-guarded-by="${topReqId}"] [data-vieworequest]`);
        await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
        await page.route("**/api/v1/wallet/dev-sign", (route) => route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: { code: "USER_REJECTED", message: "simulated wallet rejection" } }) }));
        await page.click("#v4-orgroot-signmyslot");
        await page.waitForFunction(() => /Approval did not complete — nothing was sent/.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 60000 });
        await page.unroute("**/api/v1/wallet/dev-sign");
        const afterCancel = await requestOf(topReqId);
        check("F-6: the wallet prompt was cancelled — the durable request is unchanged (AUTHORIZED, 0 signatures) and still holds the reservation", afterCancel.state === "AUTHORIZED" && Number(afterCancel.signaturesPresent) === 0 && (await pendingIdOf()) === topReqId, JSON.stringify({ state: afterCancel.state, present: afterCancel.signaturesPresent, pending: await pendingIdOf() }));
        /* reload the page: the SAME request is reached again from the durable state */
        await connectMock(page);
        await openRoot(root23Label);
        await page.waitForSelector('[data-vieworequest]', { timeout: 30000 });
        await page.locator('[data-vieworequest]').first().click();
        await page.waitForSelector("[data-org-root-request]", { timeout: 60000 });
        check("F-6: after a full page reload the root reopens the SAME pending request (durable state, not browser memory)", (await page.getAttribute("[data-org-root-request]", "data-org-root-request")) === topReqId);
        /* the safe withdrawal of the UNSIGNED request */
        page.once("dialog", (d) => d.accept());
        await page.click("[data-rootreject]");
        await page.waitForFunction(() => /withdrawn/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 30000 });
        const withdrawn = await requestOf(topReqId);
        const rootAfterWithdraw = await rootByLabel(root23Label);
        check("F-6: the unsigned request was withdrawn durably (REFUSED) — the root has no pending request and its live outpoint is unchanged; the vault is no longer guarded", withdrawn.state === "REFUSED" && !rootAfterWithdraw.pendingRequestId && JSON.stringify(rootAfterWithdraw.live.outpoint) === JSON.stringify(rootR.live.outpoint), JSON.stringify({ state: withdrawn.state, pending: rootAfterWithdraw.pendingRequestId }));
        await reopenRoot();
        await page.waitForSelector(opBtn("ownerTopUpReserve"), { timeout: 30000 });
        check("F-6: after the withdrawal the vault panel offers the operations again (no guard, controls enabled)", (await page.locator("[data-vault-guarded-by]").count()) === 0 && (await page.evaluate((s) => document.querySelector(s)?.disabled, opBtn("ownerTopUpReserve"))) === false);
        /* the REAL top-up: build again, approve (browser + out of band), finalize (owner 1 pays), submit, independent check */
        await startOp("ownerTopUpReserve", "R7-05 top-up (real)");
        await page.fill('[data-vaultop-form="ownerTopUpReserve"] [name="amount"]', "0.5");
        await page.click('[data-vaultop-form="ownerTopUpReserve"] button[type="submit"]');
        await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
        const topReq2Id = await page.getAttribute("[data-org-root-request]", "data-org-root-request");
        const topDone = await approveFinalizeSubmit(topReq2Id, "R7-05 top-up (real)");
        const vaultAfterTop = (await vaultsOf()).find((v) => v.vaultId === vaultId);
        check("R7-05 top-up: the vault's presented fee reserve is now 1.5 KAS and the vault advanced one generation", !!vaultAfterTop && vaultAfterTop.live && vaultAfterTop.live.feeReserveKas === "1.5" && Number(vaultAfterTop.generation) === Number(vaultRec.generation) + 1, JSON.stringify(vaultAfterTop && { reserve: vaultAfterTop.live && vaultAfterTop.live.feeReserveKas, gen: vaultAfterTop.generation }));
        try {
          const safeTop = JSON.parse(topDone.unsignedSafeJson);
          const covIdx = safeTop.outputs.map((o, i) => (o.covenant ? i : -1)).filter((i) => i >= 0);
          const ind = await independentOutputsObserved({ unsignedSafeJson: topDone.unsignedSafeJson, txId: topDone.txid, indices: covIdx });
          check("R7-05 top-up INDEPENDENT CHAIN CHECK (kaspad RPC, not the app): every covenant output of the transition (vault successor with the raised reserve + root continuation) exists with its exact value and every input (vault, root, owner 1's fuel) is spent", ind.allOutputsFound && ind.allInputsSpent && covIdx.length === 2, JSON.stringify(ind));
        } catch (e) { check("R7-05 top-up INDEPENDENT CHAIN CHECK", false, `node query failed: ${e.message}`); }
        await shot(page, "sign-r705-topup-done");
        /* (i.5) PAUSE then UNPAUSE from the browser */
        await startOp("ownerPause", "R7-05 pause");
        const pauseForm = await page.locator("#v4-modal").innerText(); // the authority line renders ABOVE the form element (lane-02 harness scoping lesson)
        check("R7-05 pause: the confirmation states the consequence (agent payments refused by the covenant until unpaused; nothing moves) and the 2-of-2 authorize quorum", /agent payment from this vault is refused by the covenant/.test(pauseForm) && /Authorized by 2 of 3 owners/.test(pauseForm), pauseForm.replace(/\s+/g, " ").slice(0, 200));
        await page.click('[data-vaultop-form="ownerPause"] button[type="submit"]');
        await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
        const pauseReqId = await page.getAttribute("[data-org-root-request]", "data-org-root-request");
        check("R7-05 pause: the request detail describes 'Pause vault' from the verified manifest", /Pause vault on vault/.test(await page.locator("#v4-modal").innerText()) && (await page.getAttribute("[data-vault-operation-summary]", "data-vault-operation-summary")) === "verified");
        await approveFinalizeSubmit(pauseReqId, "R7-05 pause");
        const paused = (await vaultsOf()).find((v) => v.vaultId === vaultId);
        check("R7-05 pause: the vault is presented PAUSED (live.paused=true) after chain verification", !!paused && paused.live && paused.live.paused === true, JSON.stringify(paused && paused.live));
        await reopenRoot();
        await page.waitForSelector(opBtn("ownerUnpause"), { timeout: 30000 });
        const pausedOps = await page.evaluate((s) => Object.fromEntries([...document.querySelectorAll(`${s} [data-rootvaultop]`)].map((b) => [b.getAttribute("data-rootvaultop"), b.disabled])), vaultSel);
        check("R7-05: on a PAUSED vault the panel enables Unpause and disables Pause / Emergency-pause (with reasons); rules, top-up and close stay available", pausedOps.ownerUnpause === false && pausedOps.ownerPause === true && pausedOps.ownerEmergencyPause === true && pausedOps.ownerSetAgentRoot === false && pausedOps.ownerTopUpReserve === false && pausedOps.ownerRecover === false, JSON.stringify(pausedOps));
        await startOp("ownerUnpause", "R7-05 unpause");
        await page.click('[data-vaultop-form="ownerUnpause"] button[type="submit"]');
        await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
        await approveFinalizeSubmit(await page.getAttribute("[data-org-root-request]", "data-org-root-request"), "R7-05 unpause");
        const unpaused = (await vaultsOf()).find((v) => v.vaultId === vaultId);
        check("R7-05 unpause: the vault is presented unpaused again after chain verification", !!unpaused && unpaused.live && unpaused.live.paused === false, JSON.stringify(unpaused && unpaused.live));
        /* (i.6) CHANGE AGENT RULES from the browser: raise the cap 250 → 300 and add recipient2 */
        await startOp("ownerSetAgentRoot", "R7-05 agent rules");
        await page.fill('[name="agent-0-tokenMaxPerSpend"]', "300");
        await page.fill('[name="agent-0-recipients"]', `${AX.recipient1}\n${A.recipient2}`);
        await page.click('[data-vaultop-form="ownerSetAgentRoot"] button[type="submit"]');
        await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
        const rulesReqId = await page.getAttribute("[data-org-root-request]", "data-org-root-request");
        const rulesDetail = await page.locator("#v4-modal").innerText();
        const rulesReq = await requestOf(rulesReqId);
        check("R7-05 agent rules: the request carries the FULL new delegate set (1 policy: cap 300, 2 recipients — the address was resolved to its key) and the detail lists the rules and the exact recipients being installed", !!rulesReq && rulesReq.vaultOperations[0].action === "ownerSetAgentRoot" && rulesReq.vaultOperations[0].params.agents.length === 1 && rulesReq.vaultOperations[0].params.agents[0].tokenMaxPerSpend === "300" && JSON.stringify(rulesReq.vaultOperations[0].params.agents[0].recipients) === JSON.stringify([AX.recipient1, AX.recipient2]) && /New delegate rules: 1 agent policy/.test(rulesDetail) && /up to 300 per payment/.test(rulesDetail) && /may pay ONLY 2 recipients/.test(rulesDetail) && new RegExp(AX.recipient2).test(rulesDetail), JSON.stringify(rulesReq && rulesReq.vaultOperations[0].params).slice(0, 300));
        await shot(page, "sign-r705-agent-rules-request");
        await approveFinalizeSubmit(rulesReqId, "R7-05 agent rules");
        const ruled = (await vaultsOf()).find((v) => v.vaultId === vaultId);
        check("R7-05 agent rules: the vault's presented registry now carries the installed rule (cap 300, both recipients) — the durable registry advanced only on chain verification", !!ruled && ruled.agents.length === 1 && ruled.agents[0].tokenMaxPerSpend === "300" && JSON.stringify(ruled.agents[0].recipients) === JSON.stringify([AX.recipient1, AX.recipient2]), JSON.stringify(ruled && ruled.agents));
        /* (i.7) EMERGENCY PAUSE — built under the root's FREEZE action (K of N), then withdrawn UNSIGNED so the root stays unfrozen */
        await startOp("ownerEmergencyPause", "R7-05 emergency pause");
        const emForm = await page.locator("#v4-modal").innerText(); // whole modal: the quorum/root-action line renders above the form
        check("R7-05 emergency pause: the confirmation says the root is FROZEN in the same transaction, only this vault is paused, and names the emergency quorum through the root's freeze action", /root is FROZEN/.test(emForm) && /Only this one vault is paused/.test(emForm) && /emergency quorum/.test(emForm) && /freeze/.test(emForm), emForm.replace(/\s+/g, " ").slice(0, 200));
        await page.click('[data-vaultop-form="ownerEmergencyPause"] button[type="submit"]');
        await page.waitForSelector("[data-org-root-request]", { timeout: 60000 });
        const emReqId = await page.getAttribute("[data-org-root-request]", "data-org-root-request");
        const emReq = await requestOf(emReqId);
        check("R7-05 emergency pause: a REAL durable request was built under root action FREEZE with ONE vault operation (ownerEmergencyPause), required approvals = the emergency quorum (1)", !!emReq && emReq.action === "freeze" && emReq.vaultOperations[0].action === "ownerEmergencyPause" && String(emReq.requiredApprovals) === String(rootR.emergencyK) && /requires the root to run freeze/.test(await page.locator("#v4-modal").innerText()), JSON.stringify(emReq && { action: emReq.action, required: emReq.requiredApprovals, ops: emReq.vaultOperations }));
        page.once("dialog", (d) => d.accept());
        await page.click("[data-rootreject]");
        await page.waitForFunction(() => /withdrawn/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 30000 });
        const rootAfterEm = await rootByLabel(root23Label);
        check("R7-05 emergency pause: withdrawn unsigned — the root is NOT frozen, has no pending request and its live outpoint is unchanged", (await requestOf(emReqId)).state === "REFUSED" && rootAfterEm.frozen === false && !rootAfterEm.pendingRequestId, JSON.stringify({ frozen: rootAfterEm.frozen, pending: rootAfterEm.pendingRequestId }));
        /* (i.8) WRONG ROLE: a wallet that holds no owner slot sees every control disabled with the reason */
        await switchWallet(A.recipient3);
        await openRoot(root23Label);
        await page.waitForSelector(vaultSel, { timeout: 30000 });
        const strangerOps = await page.evaluate((s) => [...document.querySelectorAll(`${s} [data-rootvaultop]`)].map((b) => ({ disabled: b.disabled, title: b.getAttribute("title") })), vaultSel);
        check("R7-05 wrong role: connected as recipient3 (the recovery key holder, NOT an owner) every owner-operation control is disabled with 'Only an owner of this root can start this'", strangerOps.length === 6 && strangerOps.every((o) => o.disabled && /Only an owner of this root/.test(o.title)), JSON.stringify(strangerOps).slice(0, 200));
        const strangerBuild = await fetch(`${URL_BASE}/api/v1/org-roots/${rootIdR}/requests`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "authorize", params: {}, vaultOperations: [{ vaultId, action: "ownerPause", params: {} }], signerAddress: A.recipient3 }) });
        const strangerJ = await strangerBuild.json();
        check("R7-05 wrong role: the server refuses a vault operation initiated by a non-owner signer (NOT_AN_ACTIVE_SLOT) — the browser control was never the gate", strangerBuild.status === 403 && strangerJ.error && strangerJ.error.code === "NOT_AN_ACTIVE_SLOT", `${strangerBuild.status} ${JSON.stringify(strangerJ).slice(0, 160)}`);
        await switchWallet(A.owner);
        /* (i.9) CLOSE & RECOVER (terminal) from the browser: typed phrase, terminal payout to the pinned recovery key, independent check */
        await startOp("ownerRecover", "R7-05 close & recover");
        await page.fill("#v4-vaultop-typed", "confirm close vault");
        await page.click('[data-vaultop-form="ownerRecover"] button[type="submit"]');
        await page.waitForFunction(() => (document.querySelector('.ferr[data-err="typed"]')?.textContent || "").length > 0, null, { timeout: 15000 });
        check("R7-05 close & recover: a wrong phrase is refused beside the field and nothing is built", /CONFIRM CLOSE VAULT/.test(await page.locator('.ferr[data-err="typed"]').innerText()) && (await pendingIdOf()) === null);
        await page.fill("#v4-vaultop-typed", "CONFIRM CLOSE VAULT");
        await page.click('[data-vaultop-form="ownerRecover"] button[type="submit"]');
        await page.waitForSelector("#v4-orgroot-signmyslot", { timeout: 60000 });
        const recReqId = await page.getAttribute("[data-org-root-request]", "data-org-root-request");
        const recDetail = await page.locator("#v4-modal").innerText();
        check("R7-05 close & recover: the request detail states TERMINAL, the 1.5 KAS payout to the pinned recovery key (recipient3) and the closed vault", /TERMINAL: this vault is CLOSED; 1\.5 KAS is paid to the pinned recovery key/.test(recDetail) && new RegExp(AX.recipient3).test(recDetail), recDetail.replace(/\s+/g, " ").slice(0, 300));
        await shot(page, "sign-r705-recover-request");
        const recDone = await approveFinalizeSubmit(recReqId, "R7-05 close & recover");
        const closed = (await vaultsOf()).find((v) => v.vaultId === vaultId);
        check("R7-05 close & recover: the vault is presented RECOVERED with no live outpoint", !!closed && closed.status === "RECOVERED" && closed.live === null, JSON.stringify(closed && { status: closed.status, live: closed.live }));
        try {
          const safeRec = JSON.parse(recDone.unsignedSafeJson);
          const ind = await independentOutputsObserved({ unsignedSafeJson: recDone.unsignedSafeJson, txId: recDone.txid, indices: [0] });
          const payoutToRecovery = String(safeRec.outputs[0].scriptPublicKey).toLowerCase() === `000020${AX.recipient3}ac` && String(safeRec.outputs[0].value) === "150000000";
          check("R7-05 close & recover INDEPENDENT CHAIN CHECK (kaspad RPC, not the app): output 0 pays exactly the 1.5 KAS reserve to recipient3's P2PK (the pinned recovery key) and exists on chain; every input (vault, root, fuel) is spent", payoutToRecovery && ind.allOutputsFound && ind.allInputsSpent, JSON.stringify({ payoutToRecovery, ind }));
        } catch (e) { check("R7-05 close & recover INDEPENDENT CHAIN CHECK", false, `node query failed: ${e.message}`); }
        await reopenRoot();
        await page.waitForSelector(vaultSel, { timeout: 30000 });
        const closedPanel = await page.evaluate((s) => ({ text: document.querySelector(s)?.innerText || "", enabled: [...document.querySelectorAll(`${s} [data-rootvaultop]`)].filter((b) => !b.disabled).length }), vaultSel);
        check("R7-05: a RECOVERED vault's panel states it holds nothing and accepts no further owner operation; every control is disabled", /RECOVERED/.test(closedPanel.text) && /no further owner operation/.test(closedPanel.text) && closedPanel.enabled === 0, closedPanel.text.slice(0, 200));
        await shot(page, "sign-r705-vault-recovered");
        await page.click("#v4-orgroot-detail-close").catch(() => {});
      }
    }
    /* leave no modal open before the create-flow sections */
    await page.click("#v4-orgroot-request-close").catch(() => {});
    await page.evaluate(() => { const m = document.querySelector("#v4-modal"); if (m && m.style.display !== "none") m.style.display = "none"; });

    /* ===== (f) UX-05: response lost after broadcast; repeated clicks; reload; reconciliation by chain proof ===== */
    let submitPosts = 0, createPosts = 0;
    page.on("request", (rq) => { if (rq.method() === "POST" && /\/genesis-submit$/.test(rq.url())) submitPosts++; if (rq.method() === "POST" && /\/wallet\/v4\/create$/.test(rq.url())) createPosts++; });
    const lossLabel = `UX-05 loss vault ${Date.now().toString(36)}`; // unique per run: the dev store accumulates across runs
    await fillVaultToBuild(page, A, lossLabel);
    await page.waitForSelector("#v4-confirm", { timeout: 120000 });
    await page.route("**/genesis-submit", async (route) => { try { await route.fetch(); } catch { /* the server processed (or refused) it */ } await route.abort("failed"); });
    await page.dblclick("#v4-confirm");
    await page.waitForFunction(() => /Submission outcome uncertain/.test(document.querySelector("#v4-notice")?.textContent || "") || !!document.querySelector("#v4-notice [data-outcome]"), null, { timeout: 180000 });
    await page.unroute("**/genesis-submit");
    await page.waitForTimeout(2000);
    const lossVaultId = await page.evaluate(() => (window.PolicyVaultV4._vaultSetup().built || {}).request?.requestId || null);
    const panelNow = (await page.locator("[data-unresolved-create]").count()) > 0;
    check("UX-05 (real lost response): a double-click on Approve sent exactly ONE genesis-submit; the browser never treated the lost response as a result", submitPosts === 1, `posts=${submitPosts}`);
    if (panelNow) {
      /* the chain had not settled when the browser re-read the durable state: the unresolved gate is live */
      check("UX-05 (real lost response, slow settle): the create flow shows the UNRESOLVED durable creation and disables building a replacement", await page.locator("[data-setup-step='funding'] [data-setup-build]").isDisabled());
      await shot(page, "sign-ux05-unresolved");
      const lossReqId = await page.evaluate(() => document.querySelector("[data-unresolved-create]")?.getAttribute("data-unresolved-create"));
      const direct = await fetch(`${URL_BASE}/api/v1/wallet/v4/create`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ signerAddress: A.owner, vaultId: "ee".repeat(32), label: "replacement", depositKas: "1", feeReserveKas: "0", agent: { agentAddress: A.delegate, maxPerSpendKas: "1", budgetKas: "1", budgetPeriod: "1d", approvalThresholdKas: "1", recipientAddresses: [A.recipient1] } }) });
      const directJ = await direct.json();
      check("UX-05 (real lost response, slow settle): the server itself refuses a replacement creation while the first is unresolved (409 CREATION_UNRESOLVED)", direct.status === 409 && directJ.error && directJ.error.code === "CREATION_UNRESOLVED", `${direct.status} ${JSON.stringify(directJ).slice(0, 160)}`);
      let settled = null;
      for (let i = 0; i < 40 && !settled; i++) { const st = (await (await fetch(`${URL_BASE}/api/v1/wallet/v4/requests/${lossReqId}`)).json()).request.state; if (st === "CHAIN_VERIFIED" || st === "RECONCILIATION_REQUIRED" || st === "SUBMISSION_REJECTED") settled = st; else await page.waitForTimeout(3000); }
      check("UX-05 (real lost response, slow settle): the durable request settled on the server independently of the browser", settled === "CHAIN_VERIFIED", String(settled));
      await page.click("[data-reconcile-create]");
      await page.waitForFunction(() => !!document.querySelector("#v4-notice [data-outcome]") || /Still unresolved|Resolved|did not complete/.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 120000 });
      check("UX-05 (real lost response, slow settle): 'Reconcile against the chain' resolves it by chain proof (CHAIN_VERIFIED)", (await outcomeState()) === "CHAIN_VERIFIED", String(await outcomeState()));
    } else {
      /* testnet-10 settled the genesis before the browser re-read the durable state: the client showed the DURABLE terminal outcome, never a guess */
      check("UX-05 (real lost response, fast settle): the browser recovered the DURABLE outcome from the server (CHAIN_VERIFIED) instead of treating the lost response or a missing confirmation as a result", (await outcomeState()) === "CHAIN_VERIFIED", `outcome=${await outcomeState()} notice=${(await noticeText()).slice(0, 160)}`);
    }
    await page.waitForTimeout(1500);
    const lossVaults = (((await (await fetch(`${URL_BASE}/api/v1/vaults`)).json()).vaults) || []).filter((v) => v.label === lossLabel).length;
    check("UX-05 (real lost response): exactly ONE vault with this run's label exists afterwards — no replacement vault was created or funded", lossVaults === 1, `vaults=${lossVaults}`);
    /* (f2) DETERMINISTIC unresolved gate: the durable listing is stubbed to report a SUBMITTED creation, so the client
     * gate is exercised regardless of chain timing (the server's own 409 guard is proven offline by
     * sdk/test/v4-genesis-unresolved-guard.test.js against a real durable record). */
    const stubbed = { requestId: "11111111-2222-4333-8444-555555555555", action: "createVault", state: "SUBMITTED", txId: "ab".repeat(32), label: "stubbed unresolved creation", vaultId: "cd".repeat(32) };
    /* (f1) Codex checkpoint 3 / UX-05: a request BUILT BEFORE another creation became unresolved must not reach the wallet —
     * the signing step re-reads the durable state and refuses (zero dev-sign calls, zero genesis-submit posts). */
    let devSignPosts = 0;
    page.on("request", (rq) => { if (rq.method() === "POST" && /\/wallet\/dev-sign$/.test(rq.url())) devSignPosts++; });
    await fillVaultToBuild(page, A, `UX-05 prebuilt ${Date.now().toString(36)}`);
    await page.waitForSelector("#v4-confirm", { timeout: 120000 });
    await page.route("**/wallet/v4/requests?unresolved=1*", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ requests: [stubbed] }) }));
    const devSignBefore = devSignPosts, submitBefore = submitPosts;
    await page.click("#v4-confirm");
    await page.waitForFunction(() => /still unresolved/i.test(document.querySelector("#v4-notice")?.textContent || ""), null, { timeout: 30000 });
    await page.waitForTimeout(800);
    check("UX-05 (prebuilt request): approving a request built EARLIER, while the server reports another creation unresolved, is refused at the signing step — the wallet was never invoked and nothing was submitted", devSignPosts === devSignBefore && submitPosts === submitBefore && /reconcile it before signing/i.test(await noticeText()), `devSign=${devSignPosts - devSignBefore} submits=${submitPosts - submitBefore} notice=${(await noticeText()).slice(0, 160)}`);
    await shot(page, "sign-ux05-prebuilt-refused");
    await page.click('.v4-tab[data-view="vaults"]');
    await page.waitForSelector('[data-vault]', { timeout: 60000 });
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("[data-unresolved-create]", { timeout: 30000 });
    check("UX-05 (durable gate): an unresolved creation reported by the server renders the gate — its request id, state and txid are shown and building a replacement is disabled", /11111111-2222-4333-8444-555555555555/.test(await page.locator("[data-unresolved-create]").innerText()) && /SUBMITTED/.test(await page.locator("[data-unresolved-create]").innerText()) && (await page.locator("[data-setup-step='funding'] [data-setup-build]").isDisabled()));
    await shot(page, "sign-ux05-unresolved-gate");
    const createsBefore = createPosts;
    await page.evaluate(() => { const b = document.querySelector("[data-setup-step='funding'] [data-setup-build]"); if (b) { b.disabled = false; b.click(); } }); // a forced click still re-checks the durable state
    await page.waitForTimeout(1500);
    check("UX-05 (durable gate): forcing the build control does not build — the flow re-reads the durable state and refuses before any create request", createPosts === createsBefore && /still unresolved/i.test(await noticeText()), `creates=${createPosts - createsBefore}`);
    await connectMock(page);
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("[data-unresolved-create]", { timeout: 30000 });
    check("UX-05 (durable gate): after a full page reload the gate is restored from the server's durable state (not browser memory)", (await page.locator("[data-setup-step='funding'] [data-setup-build]").isDisabled()));
    await page.unroute("**/wallet/v4/requests?unresolved=1*");
    await connectMock(page);
    await page.click('.v4-tab[data-view="create"]');
    await page.waitForSelector("#v4-create-form", { timeout: 30000 });
    check("UX-05 (durable gate): once the server reports nothing unresolved, the create flow is unblocked", (await page.locator("[data-unresolved-create]").count()) === 0 && !(await page.locator("[data-setup-step='funding'] [data-setup-build]").isDisabled()));
    await shot(page, "sign-ux05-resolved");
    await page.close();
  }

  await browser.close();
  /* UX-11 (Codex checkpoint 2): the uncaught-page-error result is recorded
   * BEFORE the totals, the failure count and the exit status are computed —
   * an uncaught page error makes the run fail (self-test: PV_UX_INJECT_PAGE_ERROR=1). */
  check("no uncaught page errors during the run", pageErrors.length === 0, pageErrors.join(" | "));
  const failed = results.filter((r) => !r.ok);
  const summary = { url: URL_BASE, buildId: health.buildId, networkId: health.networkId, at: new Date().toISOString(), signed: SIGN, total: results.length, passed: results.length - failed.length, failed: failed.length, results };
  summary.pageErrors = pageErrors;
  summary.consoleErrors = consoleErrors;
  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(summary, null, 2));
  process.stdout.write(`\n${summary.passed}/${summary.total} checks passed; evidence in ${OUT}\n`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  process.stderr.write(`HARNESS ERROR: ${e && e.stack ? e.stack : e}\n`);
  if (pageErrors.length) process.stderr.write(`PAGE ERRORS:\n${pageErrors.join("\n")}\n`);
  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify({ error: String(e && e.message ? e.message : e), results }, null, 2));
  process.exit(2);
});
