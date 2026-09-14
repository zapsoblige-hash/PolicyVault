"use strict";
/*
 * EXACT-TARBALL KAS CONSUMER PROOF for policyvault-mcp (RC32-04 closure, 2026-09-10). Usage:
 *   node mcp/tools/candidate-proof-kas.js /abs/path/policyvault-mcp-<ver>.tgz [--out /abs/path/evidence.json]
 * Complements candidate-proof.js (install / initialize / scoped discovery / bogus credential / malformed discovery /
 * resolution audit). This proof installs the EXACT tarball in a fresh consumer directory OUTSIDE the repository, binds
 * the installed implementation bytes to the reviewed source (sha256 of src/tools.js, server.js, src/*, core/*), boots a
 * REAL PolicyVault server (conformance harness: hosted auth, real wallet sign-in, real machine identities, JSON store,
 * NO kaspad) whose data root is seeded — through the SDK's real builders against an in-process MOCK node — with a v0.7
 * organizational root and a rooted native-KAS treasury, then drives the installed executable over real MCP stdio:
 *   1. full tools/list for an all-scope credential: the exact catalog with the FULL input schemas (sha256 recorded) —
 *      `agentSpend` present on policyvault_create_v7_request, `ownerSetApprovers` + `ownerTopUp` present on the
 *      root-carried vault operations, `ownerRecover` absent (never exposed to machine callers);
 *   2. honest KAS mapping: with the OWNER credential policyvault_org_roots / policyvault_org_root list and read the seeded
 *      root + treasury; with the DELEGATE credential (not a root participant: its root read is a non-oracle 404)
 *      policyvault_create_v7_request agentSpend on the treasury BUILDS an unsigned durable request (BUILT, CANDIDATE,
 *      ON_CHAIN_ORGANIZATIONAL_ROOT, no signature, nothing broadcast) whose amount / recipient / signer are exactly the
 *      arguments given; policyvault_create_org_root_request with ownerTopUp / ownerSetApprovers vault operations BUILDS
 *      the root-carried request (profile policyvault-0.7-kas, per-slot signer envelopes, no signature);
 *   3. refusals: a float amount and an unknown action are SCHEMA_REFUSED before any HTTP; a token action on the KAS
 *      treasury and an HD action on it are server REFUSALS (excluded generation / wrong family); a read:network-only
 *      credential sees two tools and its exact-name KAS call meets the server's 403 SCOPE_FORBIDDEN; a delegate
 *      credential cannot build a root-carried owner operation (server refusal);
 *   4. backward compatibility: the v0.4 tools keep working for the documented six-scope profile (list vaults, vault
 *      detail, dry-run simulation ok:true on the seeded v0.4 vault);
 *   5. runtime-resolution audit of the installed server (builtins + the installed package only).
 * Exit 0 only when every step passed. Nothing is published, signed or broadcast; TEST keys only.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, execSync } = require("node:child_process");

const argv = process.argv.slice(2);
const TGZ = path.resolve(argv[0] || "");
const outIdx = argv.indexOf("--out");
const OUT = outIdx >= 0 ? path.resolve(argv[outIdx + 1]) : null;
if (!fs.existsSync(TGZ)) { console.error("usage: candidate-proof-kas.js <tarball> [--out file]"); process.exit(2); }
const REPO = path.resolve(__dirname, "..", "..");
const { ConformanceHarness, VAULT_A } = require(path.join(REPO, "conformance/lib/server-harness"));
const { SCOPES } = require(path.join(REPO, "server/src/scopes"));
const { createHarness } = require(path.join(REPO, "sdk/test/helpers/v7-kas-mock-harness"));
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const shaFile = (p) => sha(fs.readFileSync(p));
const evidence = { schema: "policyvault-mcp-candidate-proof-kas/1", at: new Date().toISOString(), tarball: { path: TGZ, sha256: shaFile(TGZ), bytes: fs.statSync(TGZ).size }, steps: [] };
const step = (name, data) => { evidence.steps.push({ step: name, ...data }); console.error(`[${name}] ${JSON.stringify(data).slice(0, 400)}`); };
const finish = (code) => { if (OUT) fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2) + "\n"); console.log(JSON.stringify(evidence, null, 2)); process.exit(code); };
const fail = (msg) => { step("FAIL", { message: msg }); evidence.result = "FAIL"; finish(1); };

function runMcp({ dir, env, messages, preloadLog, settleMs = 6000 }) {
  return new Promise((resolve) => {
    const child = spawn("npx", ["--no-install", "policyvault-mcp"], { cwd: dir, env: { ...process.env, ...env, NODE_PATH: "", ...(preloadLog ? { NODE_OPTIONS: `--require ${path.join(dir, "preload.js")}`, PV_RESOLVE_LOG: preloadLog } : {}) }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120000);
    child.on("exit", (code) => { clearTimeout(timer); resolve({ code, out, err }); });
    setTimeout(() => { for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n"); setTimeout(() => child.stdin.end(), settleMs); }, 2500);
  });
}
const parse = (out) => out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return { PARSE_ERROR: l.slice(0, 80) }; } });
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "candidate-proof-kas", version: "0" } } };
const INITED = { jsonrpc: "2.0", method: "notifications/initialized" };
const LIST = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };
const call = (id, name, args) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const sc = (m) => (m && m.result && m.result.structuredContent) || null;

(async () => {
  /* 1. fresh consumer directory OUTSIDE the repository; exact tarball; installed bytes bound to the reviewed source */
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-kas-proof-"));
  execSync("npm init -y", { cwd: dir, stdio: "ignore" });
  execSync(`npm install --no-audit --no-fund --loglevel=error ${JSON.stringify(TGZ)}`, { cwd: dir, stdio: "ignore" });
  const pkgDir = path.join(dir, "node_modules", "policyvault-mcp");
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.relative(pkgDir, path.join(d, e.name))]));
  const installed = walk(pkgDir).sort();
  const installedHashes = Object.fromEntries(installed.map((f) => [f, shaFile(path.join(pkgDir, f))]));
  const bound = ["server.js", "src/tools.js", "src/schema.js", "src/envelope.js", "src/http.js", "src/config.js", "src/idempotency.js", "core/model/canonical-json.js", "core/MANIFEST.json", "server.json", "README.md", "LICENSE", "NOTICE"];
  const mismatched = bound.filter((f) => installedHashes[f] !== shaFile(path.join(REPO, "mcp", f)));
  if (!fs.existsSync(path.join(dir, "node_modules", ".bin", "policyvault-mcp"))) fail("bin mapping missing");
  if (mismatched.length) fail(`installed bytes differ from the reviewed source: ${mismatched.join(",")}`);
  if (installedHashes["core/model/canonical-json.js"] !== shaFile(path.join(REPO, "core/model/canonical-json.js"))) fail("packaged shared-core copy is not the canonical core bytes");
  step("install", { consumerDir: dir, version: pkg.version, files: installed.length, installedHashes, boundToReviewedSource: bound, siblingCore: fs.existsSync(path.join(dir, "core")) });
  fs.writeFileSync(path.join(dir, "preload.js"), `"use strict";const Module=require("module");const fs=require("fs");const seen=new Set();const orig=Module._resolveFilename;Module._resolveFilename=function(r,p,i,o){const x=orig.call(this,r,p,i,o);seen.add(x);return x;};process.on("exit",()=>{try{fs.writeFileSync(process.env.PV_RESOLVE_LOG+"."+process.pid,JSON.stringify([...seen]))}catch(_){}});`);

  /* 2. REAL server; the data root is seeded BEFORE the server starts with a root + a KAS treasury (SDK builders, mock node) */
  const harness = new ConformanceHarness();
  const H = createHarness(harness.config);
  const c = H.ctx();
  c.owner1 = harness.key("OWNER"); // owner slot 1 = the harness OWNER wallet (signs in, mints the owner credential)
  const rpc = H.mockRpc();
  const rootId = await H.rootGenesis(harness.config, c, rpc);
  const { vaultId } = await H.kasGenesis(harness.config, c, rpc, rootId);
  step("seed", { rootId, vaultId, delegate: H.XO(c.agentKey), delegateIsHarnessAgent: H.XO(c.agentKey) === harness.xonly("AGENT"), owner1IsHarnessOwner: H.XO(c.owner1) === harness.xonly("OWNER"), network: harness.config.networkId, node: "in-process mock only" });
  await harness.start();
  try {
    const agentCookie = await harness.signIn("AGENT");
    await harness.mintIdentity(harness.ownerCookie, "kasowner", ["read:org-roots", "write:org-roots"], "candidate-proof-kas-owner");
    await harness.mintIdentity(agentCookie, "kasagent", ["read:org-roots", "write:org-roots", "read:requests"], "candidate-proof-kas-delegate");
    await harness.mintIdentity(harness.ownerCookie, "netonly", ["read:network"], "candidate-proof-kas-read-network");
    await harness.mintIdentity(harness.ownerCookie, "all", [...SCOPES], "candidate-proof-kas-all-scopes");
    step("server", { baseUrl: harness.baseUrl, credentials: ["kasowner(read:org-roots,write:org-roots)", "kasagent(delegate wallet; read/write:org-roots,read:requests)", "netonly(read:network)", `all(${SCOPES.length} scopes)`, "six(conformance v0.4 agent profile)"] });

    /* 3. full catalog + full schemas (all-scope credential) */
    const a = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.all }, messages: [INIT, INITED, LIST] });
    const ma = parse(a.out); const init = ma.find((m) => m.id === 1); const list = ma.find((m) => m.id === 2);
    if (!init || !init.result || init.result.serverInfo.version !== pkg.version) fail(`initialize: ${JSON.stringify(init).slice(0, 200)}`);
    const tools = list && list.result ? list.result.tools : null;
    if (!tools) fail("no tools/list result");
    const names = tools.map((t) => t.name).sort();
    const expectedFull = [...new Set((fs.readFileSync(path.join(REPO, "mcp/src/tools.js"), "utf8").match(/name: "policyvault_[a-z0-9_]+"/g) || []).map((s) => s.slice(7, -1)))].sort();
    if (JSON.stringify(names) !== JSON.stringify(expectedFull)) fail(`catalog ${JSON.stringify(names)} != source ${JSON.stringify(expectedFull)}`);
    const v7 = tools.find((t) => t.name === "policyvault_create_v7_request"); const rootReq = tools.find((t) => t.name === "policyvault_create_org_root_request");
    const v7Actions = v7.inputSchema.properties.action.enum; const vaultOps = rootReq.inputSchema.properties.vaultOperations.items.properties.action.enum; const vaultOpParams = Object.keys(rootReq.inputSchema.properties.vaultOperations.items.properties.params.properties);
    if (!v7Actions.includes("agentSpend") || !vaultOps.includes("ownerSetApprovers") || !vaultOps.includes("ownerTopUp") || vaultOps.includes("ownerRecover") || !vaultOpParams.includes("topUpAmountSompi") || !vaultOpParams.includes("approvers")) fail(`KAS schema entries: v7 ${JSON.stringify(v7Actions)} vaultOps ${JSON.stringify(vaultOps)} params ${JSON.stringify(vaultOpParams)}`);
    const schemasSha = sha(JSON.stringify(tools.map((t) => ({ name: t.name, inputSchema: t.inputSchema })).sort((x, y) => x.name.localeCompare(y.name))));
    step("full-catalog-and-schemas", { initialize: { protocolVersion: init.result.protocolVersion, serverInfo: init.result.serverInfo }, tools: names.length, names, v7Actions, vaultOperationActions: vaultOps, vaultOperationParams: vaultOpParams, ownerRecoverExposed: vaultOps.includes("ownerRecover"), toolSchemasSha256: schemasSha, exit: a.code });
    evidence.toolSchemas = tools.map((t) => ({ name: t.name, requiredScopes: t.requiredScopes, inputSchema: t.inputSchema }));

    /* 4. honest KAS mapping — OWNER credential: root reads; root-carried KAS owner operations (ownerTopUp, then ownerSetApprovers after withdrawing the unsigned top-up); a token deposit on the KAS treasury is a server refusal (wrong family) */
    const ownerAddr = H.ADDR(c.owner1);
    const cc = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.kasowner }, settleMs: 40000, messages: [INIT, INITED, LIST,
      call(10, "policyvault_org_roots", {}),
      call(11, "policyvault_org_root", { rootId }),
      call(20, "policyvault_create_org_root_request", { rootId, action: "authorize", vaultOperations: [{ vaultId, action: "ownerTopUp", params: { topUpAmountSompi: "100000000" } }], params: { fuel: H.fuelUtxoFor(c.fuelKey) }, signerAddress: ownerAddr }),
      call(21, "policyvault_org_root_requests", { rootId }),
      call(22, "policyvault_create_v7_request", { vaultId, action: "tokenDeposit", params: { depositAmount: "100000000" }, signerAddress: ownerAddr })
    ] });
    const mc = parse(cc.out); const C = (id) => mc.find((m) => m.id === id);
    const lc = C(2); const cNames = lc && lc.result ? lc.result.tools.map((t) => t.name) : null;
    const roots = sc(C(10)); const root = sc(C(11)); const topUp = sc(C(20)); const listed = sc(C(21)); const depositOnKas = sc(C(22));
    if (!cNames || !cNames.includes("policyvault_create_org_root_request") || !cNames.includes("policyvault_org_roots")) fail(`owner discovery: ${JSON.stringify(cNames)}`);
    const rootRows = (roots && roots.data && (roots.data.orgRoots || roots.data.roots)) || [];
    if (!roots || roots.status !== "OK" || !rootRows.some((r) => r.rootCovenantId === rootId)) fail(`org_roots: ${JSON.stringify(roots && roots.data).slice(0, 400)}`);
    const rootRec = root && root.data && (root.data.orgRoot || root.data);
    if (!root || root.status !== "OK" || !rootRec || rootRec.rootCovenantId !== rootId || !(rootRec.vaults || []).includes(vaultId)) fail(`org_root: ${JSON.stringify(root && root.data).slice(0, 400)}`);
    const tr = topUp && topUp.data && topUp.data.request;
    if (!topUp || topUp.status !== "OK" || topUp.httpStatus !== 201 || !tr || tr.kind !== "rootAction" || !Array.isArray(tr.vaultOperations) || tr.vaultOperations[0].action !== "ownerTopUp" || tr.vaultOperations[0].profile !== "policyvault-0.7-kas" || tr.vaultOperations[0].vaultId !== vaultId) fail(`ownerTopUp build: ${JSON.stringify(topUp).slice(0, 600)}`);
    const listedRows = (listed && listed.data && listed.data.requests) || [];
    if (!listed || listed.status !== "OK" || !listedRows.some((r) => r.id === tr.id || r.requestId === tr.id)) fail(`root requests listing lacks the built top-up: ${JSON.stringify(listed && listed.data).slice(0, 300)}`);
    if (!depositOnKas || depositOnKas.status !== "REFUSED" || depositOnKas.httpStatus < 400) fail(`tokenDeposit on the KAS treasury not refused by the server: ${JSON.stringify(depositOnKas).slice(0, 300)}`);
    if (cc.out.includes(harness.tokens.kasowner) || cc.err.includes(harness.tokens.kasowner)) fail("credential leaked to an output channel");
    step("kas-owner-mapping", { advertised: cNames, orgRoots: rootRows.length, orgRoot: { vaults: (rootRec.vaults || []).length, authorityModel: rootRec.authorityModel }, ownerTopUpBuild: { http: topUp.httpStatus, kind: tr.kind, state: tr.state, profile: tr.vaultOperations[0].profile, requestId: tr.id, signaturesPresent: tr.signaturesPresent, requiredApprovals: tr.requiredApprovals }, listedOnRoot: true, tokenDepositOnKasTreasury: { status: depositOnKas.status, http: depositOnKas.httpStatus, code: depositOnKas.data && depositOnKas.data.error && depositOnKas.data.error.code }, exit: cc.code });
    const rj = await harness.raw("POST", `/org-roots/${rootId}/requests/${tr.id}/reject`, { body: { reason: "proof: withdraw the unsigned top-up" }, cookie: harness.ownerCookie });
    /* ownerSetApprovers: the approver count travels as a DECIMAL STRING (the 1.5.0-era schema typed it as an integer, which the server
     * refuses with BUILD_FAILED "state.approvalM must be a BigInt or decimal string" — RC33 MCP finding; the integer form is now
     * SCHEMA_REFUSED before any HTTP, the string form BUILDS) */
    const dd = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.kasowner }, settleMs: 40000, messages: [INIT, INITED,
      call(29, "policyvault_create_org_root_request", { rootId, action: "authorize", vaultOperations: [{ vaultId, action: "ownerSetApprovers", params: { approvers: [H.XO(c.approver1), H.XO(c.approver2)], approvalM: 2 } }], params: { fuel: H.fuelUtxoFor(c.fuelKey) }, signerAddress: ownerAddr }),
      call(30, "policyvault_create_org_root_request", { rootId, action: "authorize", vaultOperations: [{ vaultId, action: "ownerSetApprovers", params: { approvers: [H.XO(c.approver1), H.XO(c.approver2)], approvalM: "2" } }], params: { fuel: H.fuelUtxoFor(c.fuelKey) }, signerAddress: ownerAddr })
    ] });
    const md = parse(dd.out); const integerForm = sc(md.find((m) => m.id === 29)); const setApprovers = sc(md.find((m) => m.id === 30)); const sr = setApprovers && setApprovers.data && setApprovers.data.request;
    if (!integerForm || integerForm.status !== "SCHEMA_REFUSED") fail(`integer approvalM not SCHEMA_REFUSED: ${JSON.stringify(integerForm).slice(0, 300)}`);
    if (rj.status !== 200 || !setApprovers || setApprovers.status !== "OK" || setApprovers.httpStatus !== 201 || !sr || sr.vaultOperations[0].action !== "ownerSetApprovers" || sr.vaultOperations[0].profile !== "policyvault-0.7-kas") fail(`ownerSetApprovers build: reject ${rj.status} ${JSON.stringify(setApprovers).slice(0, 700)}`);
    /* the unsigned set-approvers request occupies the root's single pending slot and reserves the vault; withdraw it so the delegate's own payment can be built (a pending root request naming the vault refuses delegate builds — VAULT_PENDING_REQUEST) */
    const rj2 = await harness.raw("POST", `/org-roots/${rootId}/requests/${sr.id}/reject`, { body: { reason: "proof: withdraw the unsigned set-approvers" }, cookie: harness.ownerCookie });
    if (rj2.status !== 200) fail(`withdrawing the unsigned set-approvers request failed: http ${rj2.status}`);
    step("kas-owner-set-approvers", { unsignedTopUpWithdrawn: rj.status === 200, integerApprovalM: integerForm.status, ownerSetApproversBuild: { http: setApprovers.httpStatus, kind: sr.kind, state: sr.state, profile: sr.vaultOperations[0].profile, requestId: sr.id }, unsignedSetApproversWithdrawn: rj2.status === 200, exit: dd.code });

    /* 5. honest KAS mapping — DELEGATE credential: not a root participant (root read is a non-oracle 404), builds its OWN payment; float / unknown action SCHEMA_REFUSED before HTTP; token action on the KAS treasury and an owner operation are server refusals */
    const amount = "150000000", recipient = H.XO(c.recipientKey), signer = H.ADDR(c.agentKey);
    const b = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.kasagent }, settleMs: 40000, messages: [INIT, INITED, LIST,
      call(11, "policyvault_org_root", { rootId }),
      call(12, "policyvault_create_v7_request", { vaultId, action: "agentSpend", params: { payAmountSompi: amount, recipient }, signerAddress: signer }),
      call(13, "policyvault_create_v7_request", { vaultId, action: "agentSpend", params: { payAmountSompi: 1.5, recipient }, signerAddress: signer }),
      call(14, "policyvault_create_v7_request", { vaultId, action: "kasSpend", params: { payAmountSompi: amount, recipient }, signerAddress: signer }),
      call(15, "policyvault_create_v7_request", { vaultId, action: "tokenAgentSpend", params: { spendAmount: amount, recipient }, signerAddress: signer }),
      call(16, "policyvault_create_org_root_request", { rootId, action: "authorize", vaultOperations: [{ vaultId, action: "ownerTopUp", params: { topUpAmountSompi: "100000000" } }], params: { fuel: H.fuelUtxoFor(c.fuelKey) }, signerAddress: signer })
    ] });
    const mb = parse(b.out); const R = (id) => mb.find((m) => m.id === id);
    const lb = R(2); const bNames = lb && lb.result ? lb.result.tools.map((t) => t.name) : null;
    const strangerRoot = sc(R(11)); const built = sc(R(12)); const floatArg = sc(R(13)); const unknownAction = sc(R(14)); const tokenOnKas = sc(R(15)); const delegateOwnerOp = sc(R(16));
    if (!bNames || !bNames.includes("policyvault_create_v7_request")) fail(`delegate discovery: ${JSON.stringify(bNames)}`);
    if (!strangerRoot || strangerRoot.status !== "REFUSED" || strangerRoot.httpStatus !== 404) fail(`a delegate is not a root participant — expected a non-oracle 404 on the root read: ${JSON.stringify(strangerRoot).slice(0, 300)}`);
    const req = built && built.data && built.data.request;
    if (!built || built.status !== "OK" || built.httpStatus !== 201 || !req || req.kind !== "agentSpend" || req.state !== "BUILT" || req.contractVersion !== "policyvault-0.7-kas" || req.candidateStatus !== "CANDIDATE" || req.authorityModel !== "ON_CHAIN_ORGANIZATIONAL_ROOT" || req.vaultId !== vaultId || req.signerAddress !== signer || typeof (req.transaction && req.transaction.unsignedSafeJson) !== "string" || req.signedSafeJson !== undefined) fail(`agentSpend build: ${JSON.stringify(built).slice(0, 600)}`);
    const frozen = req.transaction.frozenCanonicalJson ? JSON.parse(req.transaction.frozenCanonicalJson) : null;
    const paysRecipient = !!frozen && frozen.outputs.some((o) => String(o.value) === amount && String(o.scriptPublicKey.scriptHex || o.scriptPublicKey).toLowerCase().endsWith(`20${recipient}ac`));
    if (!paysRecipient) fail(`the built payment does not pay exactly ${amount} sompi to the given recipient: ${JSON.stringify(frozen && frozen.outputs).slice(0, 400)}`);
    if (!floatArg || floatArg.status !== "SCHEMA_REFUSED") fail(`float amount not SCHEMA_REFUSED: ${JSON.stringify(floatArg).slice(0, 300)}`);
    if (!unknownAction || unknownAction.status !== "SCHEMA_REFUSED") fail(`unknown action not SCHEMA_REFUSED: ${JSON.stringify(unknownAction).slice(0, 300)}`);
    if (!tokenOnKas || tokenOnKas.status !== "REFUSED" || tokenOnKas.httpStatus < 400) fail(`token action on the KAS treasury not refused by the server: ${JSON.stringify(tokenOnKas).slice(0, 300)}`);
    if (!delegateOwnerOp || delegateOwnerOp.status !== "REFUSED" || delegateOwnerOp.httpStatus < 400) fail(`delegate credential built an owner operation: ${JSON.stringify(delegateOwnerOp).slice(0, 300)}`);
    if (b.out.includes(harness.tokens.kasagent) || b.err.includes(harness.tokens.kasagent)) fail("credential leaked to an output channel");
    step("kas-delegate-mapping", { advertised: bNames, rootReadByDelegate: { status: strangerRoot.status, http: strangerRoot.httpStatus, code: strangerRoot.data && strangerRoot.data.error && strangerRoot.data.error.code }, agentSpendBuild: { http: built.httpStatus, kind: req.kind, state: req.state, contractVersion: req.contractVersion, candidateStatus: req.candidateStatus, requestId: req.requestId, txId: req.txId, paysExactAmountToRecipient: paysRecipient, signatureAbsent: req.signedSafeJson === undefined, approvalProgress: req.approvalProgress }, floatAmount: floatArg.status, unknownAction: unknownAction.status, tokenActionOnKasTreasury: { status: tokenOnKas.status, http: tokenOnKas.httpStatus, code: tokenOnKas.data && tokenOnKas.data.error && tokenOnKas.data.error.code }, delegateOwnerOperation: { status: delegateOwnerOp.status, http: delegateOwnerOp.httpStatus, code: delegateOwnerOp.data && delegateOwnerOp.data.error && delegateOwnerOp.data.error.code }, exit: b.code });

    /* 6. insufficient scope: read:network only — two tools advertised; exact-name KAS call meets the server's 403 */
    const e = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.netonly }, messages: [INIT, INITED, LIST, call(40, "policyvault_create_v7_request", { vaultId, action: "agentSpend", params: { payAmountSompi: amount, recipient }, signerAddress: signer })] });
    const me = parse(e.out); const le = me.find((m) => m.id === 2); const hidden = sc(me.find((m) => m.id === 40));
    const eNames = le && le.result ? le.result.tools.map((t) => t.name) : null;
    if (!eNames || eNames.join(",") !== "policyvault_capabilities,policyvault_network_status") fail(`read:network tools/list = ${JSON.stringify(eNames)}`);
    if (!hidden || hidden.status !== "REFUSED" || hidden.httpStatus !== 403 || hidden.data.error.code !== "SCOPE_FORBIDDEN") fail(`hidden KAS call: ${JSON.stringify(hidden).slice(0, 300)}`);
    step("insufficient-scope", { advertised: eNames, hiddenExactNameKasCall: { status: hidden.status, http: hidden.httpStatus, code: hidden.data.error.code }, exit: e.code });

    /* 7. backward compatibility: the documented v0.4 six-scope agent profile on the seeded v0.4 vault */
    const logF = path.join(dir, "resolved-six");
    const f = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.six }, preloadLog: logF, settleMs: 40000, messages: [INIT, INITED, LIST,
      call(50, "policyvault_list_vaults", {}), call(51, "policyvault_vault", { vaultId: VAULT_A }),
      call(52, "policyvault_simulate_request", { vaultId: VAULT_A, action: "agentSpend", signerAddress: harness.address("AGENT"), params: { agentPk: harness.xonly("AGENT"), payAmountSompi: "100000000", recipient: harness.xonly("RECIPIENT") } })
    ] });
    const mf = parse(f.out); const lv = sc(mf.find((m) => m.id === 50)); const vd = sc(mf.find((m) => m.id === 51)); const sim = sc(mf.find((m) => m.id === 52));
    if (!lv || lv.status !== "OK" || !(lv.data.vaults || []).some((v) => v.vaultId === VAULT_A)) fail(`v4 list_vaults: ${JSON.stringify(lv).slice(0, 300)}`);
    if (!vd || vd.status !== "OK" || vd.data.vaultId !== VAULT_A) fail(`v4 vault detail: ${JSON.stringify(vd).slice(0, 300)}`);
    if (!sim || sim.status !== "OK" || !sim.data.simulation || sim.data.simulation.ok !== true) fail(`v4 simulate: ${JSON.stringify(sim).slice(0, 400)}`);
    step("v4-backward-compatibility", { advertised: (mf.find((m) => m.id === 2).result.tools || []).length, listVaults: lv.data.vaults.length, vaultDetail: vd.data.vaultId, simulation: { ok: sim.data.simulation.ok, vaultId: sim.data.simulation.vaultId }, exit: f.code });

    /* 8. runtime-resolution audit (the six-scope run) */
    const logs = fs.readdirSync(dir).filter((x) => x.startsWith("resolved-six."));
    const pkgReal = fs.realpathSync(pkgDir); let audited = 0; const escaped = [];
    for (const x of logs) { const seen = JSON.parse(fs.readFileSync(path.join(dir, x), "utf8")); const abs = seen.filter((s) => path.isAbsolute(s)); if (!abs.some((s) => s.startsWith(pkgReal))) continue; audited++; for (const s of abs) if (!s.startsWith(pkgReal)) escaped.push(s); }
    if (audited === 0 || escaped.length) fail(`resolution audit: audited=${audited} escaped=${JSON.stringify(escaped.slice(0, 5))}`);
    step("resolution-audit", { processesAudited: audited, escapedModules: 0 });
  } finally {
    await harness.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  evidence.result = "PASS";
  finish(0);
})().catch((e) => fail(`unexpected: ${e && e.stack ? e.stack.split("\n").slice(0, 4).join(" | ") : e}`));
