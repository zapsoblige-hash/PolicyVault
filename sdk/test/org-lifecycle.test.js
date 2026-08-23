"use strict";

/*
 * API layer — H2 organization lifecycle (§16): Rename / Archive / Restore /
 * safe Delete over the REAL server handler (api.handle) on a temp data root.
 * Organizations are OFF-CHAIN APPLICATION METADATA: every operation here must
 * leave vault manifests (covenant identity, owner, state, outpoints) BYTE
 * IDENTICAL, and deleting an organization must never touch a vault.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const api = require("../../server/src/api");
const org = require("../src/organization");
const { persistManifestV2, MANIFEST_SCHEMA_V2 } = require("../src/manifest-v2");
const { computeStateIdV2, normalizeTemplateV2, normalizeStateV2, CONTRACT_VERSION_V2 } = require("../src/vault-state-v2");

const OWNER_X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const DELEGATE_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECIP_X = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

function tempConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-orglc-")) });
}

function seedVault(config, vaultId) {
  const template = normalizeTemplateV2({ owner: OWNER_X, vaultId });
  const state = normalizeStateV2({
    protectedValue: "10000000000", periodStartDaa: "1000", periodSpent: "0", paused: "0",
    delegate: DELEGATE_X, maxPerSpend: "1000000000", periodBudget: "5000000000",
    periodLengthDaa: "600", recipients: [RECIP_X], delegateActive: "1", policyNonce: "0"
  });
  persistManifestV2(config, {
    schema: MANIFEST_SCHEMA_V2, contractVersion: CONTRACT_VERSION_V2, networkId: config.networkId,
    vaultId, label: `vault-${vaultId.slice(0, 4)}`, status: "ACTIVE", template,
    live: {
      state, stateId: computeStateIdV2({ networkId: config.networkId, template, state }),
      outpoint: { transactionId: "ab".repeat(32), index: 1 }, outpointValue: "10000000000",
      scriptSha256: "cd".repeat(32), covenantId: "ef".repeat(32)
    },
    creationTxId: "12".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const manifestSha = (config, vaultId) =>
  crypto.createHash("sha256").update(fs.readFileSync(path.join(config.dataRoot, "vaults", vaultId, "manifest.json"))).digest("hex");

const call = (config, method, pathStr, body) =>
  api.handle(config, method, pathStr.split("/").filter(Boolean), {}, body ?? null);

async function expectApiError(promise, status, code) {
  try {
    await promise;
    assert.fail(`expected ${status} ${code}`);
  } catch (e) {
    assert.equal(e.status, status, e.message);
    if (code) assert.equal(e.code, code);
    return e;
  }
}

test("§16 rename: name changes; vault association + covenant data untouched", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  seedVault(config, VA);
  const before = manifestSha(config, VA);

  const o = (await call(config, "POST", "/organizations", { name: "Ops" })).body.organization;
  assert.equal(o.status, "ACTIVE");
  await call(config, "POST", `/organizations/${o.orgId}/vaults`, { vaultId: VA, expectedVersion: 0 });
  const renamed = (await call(config, "POST", `/organizations/${o.orgId}/rename`, { name: "Operations", expectedVersion: 1 })).body.organization;
  assert.equal(renamed.name, "Operations");
  assert.equal(renamed.status, "ACTIVE");

  const vault = (await call(config, "GET", `/vaults/${VA}`)).body;
  assert.equal(vault.organization.orgId, o.orgId, "association preserved");
  assert.equal(vault.organization.name, "Operations");
  // COVENANT NEUTRALITY: the manifest file is byte-identical after the rename.
  assert.equal(manifestSha(config, VA), before, "manifest bytes unchanged by org metadata ops");
});

test("§16 archive/restore: visibility metadata only; archived orgs refuse NEW assignments; associations survive", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  const VB = "bb".repeat(32);
  seedVault(config, VA);
  seedVault(config, VB);
  const beforeA = manifestSha(config, VA);

  const o = (await call(config, "POST", "/organizations", { name: "Seasonal" })).body.organization;
  await call(config, "POST", `/organizations/${o.orgId}/vaults`, { vaultId: VA, expectedVersion: 0 });

  const archived = (await call(config, "POST", `/organizations/${o.orgId}/archive`, { expectedVersion: 1 })).body.organization;
  assert.equal(archived.status, "ARCHIVED");
  // Still listed (an Archived view can show it), still resolvable, association intact.
  const listed = (await call(config, "GET", "/organizations")).body.organizations;
  assert.equal(listed.find((x) => x.orgId === o.orgId).status, "ARCHIVED");
  assert.equal((await call(config, "GET", `/vaults/${VA}`)).body.organization.orgId, o.orgId, "vault association preserved while archived");
  // Archiving twice fails loudly; stale version fails loudly.
  await expectApiError(call(config, "POST", `/organizations/${o.orgId}/archive`, { expectedVersion: 2 }), 422, "ORG_ALREADY_ARCHIVED");
  await expectApiError(call(config, "POST", `/organizations/${o.orgId}/archive`, { expectedVersion: 1 }), 409, "VERSION_CONFLICT");
  // NEW assignments to an archived organization are refused.
  await expectApiError(call(config, "POST", `/organizations/${o.orgId}/vaults`, { vaultId: VB, expectedVersion: 1 }), 422, "ORG_ARCHIVED");

  // Restore returns it to active; restore of a non-archived org is refused.
  const restored = (await call(config, "POST", `/organizations/${o.orgId}/restore`, { expectedVersion: 2 })).body.organization;
  assert.equal(restored.status, "ACTIVE");
  await expectApiError(call(config, "POST", `/organizations/${o.orgId}/restore`, { expectedVersion: 3 }), 422, "ORG_NOT_ARCHIVED");

  assert.equal(manifestSha(config, VA), beforeA, "manifest bytes unchanged across archive/restore");
});

test("§16 delete: empty org deletes; populated org is BLOCKED with its vault list; vaults never touched", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  seedVault(config, VA);
  const before = manifestSha(config, VA);

  const full = (await call(config, "POST", "/organizations", { name: "Busy" })).body.organization;
  const empty = (await call(config, "POST", "/organizations", { name: "Idle" })).body.organization;
  await call(config, "POST", `/organizations/${full.orgId}/vaults`, { vaultId: VA, expectedVersion: 0 });

  // Populated -> 409 ORG_NOT_EMPTY, with the assigned vault ids for the UI's
  // "move or unassign" offer; the org and the vault both survive unchanged.
  const err = await expectApiError(call(config, "POST", `/organizations/${full.orgId}/delete`, { expectedVersion: 1 }), 409, "ORG_NOT_EMPTY");
  assert.deepEqual(err.extra.assignedVaultIds, [VA]);
  assert.equal((await call(config, "GET", `/organizations/${full.orgId}`)).body.organization.name, "Busy");
  assert.equal((await call(config, "GET", `/vaults/${VA}`)).body.status, "ACTIVE");

  // Empty -> delete succeeds and the record is gone (metadata only).
  const del = (await call(config, "POST", `/organizations/${empty.orgId}/delete`, { expectedVersion: 1 })).body;
  assert.equal(del.deleted, true);
  await expectApiError(call(config, "GET", `/organizations/${empty.orgId}`), 404, "ORG_NOT_FOUND");

  // Reassign VA -> Unassigned (metadata only), then org A becomes deletable.
  const assignments = (await call(config, "GET", "/organizations")).body;
  await call(config, "POST", `/organizations/${full.orgId}/vaults/${VA}/unassign`, { expectedVersion: assignments.assignmentsVersion });
  assert.equal((await call(config, "GET", `/vaults/${VA}`)).body.organization, null, "vault is Unassigned and still fully visible");
  const del2 = (await call(config, "POST", `/organizations/${full.orgId}/delete`, { expectedVersion: 1 })).body;
  assert.equal(del2.deleted, true);

  // The vault manifest never changed through ANY of the above.
  assert.equal(manifestSha(config, VA), before, "manifest bytes unchanged by assign/unassign/delete");
  assert.equal((await call(config, "GET", `/vaults/${VA}`)).body.status, "ACTIVE", "vault untouched by org deletion");
  // Audit trail recorded the lifecycle as metadata events.
  const audit = require("../../server/src/audit").readAudit(config, { limit: 100 });
  for (const action of ["org_created", "org_deleted", "vault_assigned", "vault_unassigned"]) {
    assert.ok(audit.some((e) => e.kind === "metadata" && e.action === action), `audit has ${action}`);
  }
});

test("§16 module-level fail-closed: unknown org status rejected; pre-lifecycle records default ACTIVE", () => {
  const config = tempConfig();
  const rec = org.createOrganization(config, { name: "Legacy" });
  // Simulate a pre-lifecycle record (no status field): loads as ACTIVE.
  const p = path.join(config.dataRoot, "orgs", `${rec.orgId}.json`);
  const raw = JSON.parse(fs.readFileSync(p, "utf8"));
  delete raw.status;
  fs.writeFileSync(p, JSON.stringify(raw));
  assert.equal(org.loadOrganization(config, rec.orgId).status, "ACTIVE");
  // Unknown status fails closed.
  raw.status = "SOFT_DELETED";
  fs.writeFileSync(p, JSON.stringify(raw));
  assert.throws(() => org.loadOrganization(config, rec.orgId), (e) => e.code === "ORG_INVALID");
});
