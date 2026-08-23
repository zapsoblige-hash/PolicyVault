"use strict";

/*
 * API layer — organization isolation and the metadata/authority boundary,
 * driven through the REAL server handler (api.handle) over a temp data
 * root. Proves: org A cannot read/mutate org B's scoped metadata through
 * org APIs; org metadata grants ZERO covenant authority; real covenant
 * authority works without any org membership; metadata corruption never
 * hides vaults.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { loadKaspa } = require("../src/chain");
const api = require("../../server/src/api");
const {
  persistManifestV2,
  MANIFEST_SCHEMA_V2
} = require("../src/manifest-v2");
const { computeStateIdV2, normalizeTemplateV2, normalizeStateV2, CONTRACT_VERSION_V2 } = require("../src/vault-state-v2");
const { buildWalletRequestV2, assertSignerAuthorized } = require("../src/wallet-requests-v2");
const { addressForXOnlyPubkey } = require("../src/address-identity");

const kaspa = loadKaspa(loadConfig());
void kaspa;

const OWNER_X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const DELEGATE_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECIP_X = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const UNRELATED_X = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

function tempConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-orgapi-")) });
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

const call = (config, method, pathStr, body) =>
  api.handle(config, method, pathStr.split("/").filter(Boolean), {}, body ?? null);

async function expectApiError(promise, status, code) {
  try {
    await promise;
    assert.fail(`expected ${status} ${code}`);
  } catch (e) {
    assert.equal(e.status, status, e.message);
    if (code) assert.equal(e.code, code);
  }
}

test("org APIs: create/list/get/rename/members/vaults/audit round trip", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  seedVault(config, VA);

  const created = (await call(config, "POST", "/organizations", { name: "Acme" })).body.organization;
  const got = (await call(config, "GET", `/organizations/${created.orgId}`)).body;
  assert.equal(got.organization.name, "Acme");
  assert.deepEqual(got.vaultIds, []);

  await call(config, "POST", `/organizations/${created.orgId}/rename`, { name: "Acme Treasury", expectedVersion: 1 });

  const addr = addressForXOnlyPubkey(config, UNRELATED_X);
  const member = (await call(config, "POST", `/organizations/${created.orgId}/members`, {
    displayName: "Carol", address: addr, roles: ["administrator", "approver"], expectedVersion: 2
  })).body.member;
  assert.equal(member.xOnlyPubkey, UNRELATED_X);

  await call(config, "POST", `/organizations/${created.orgId}/vaults`, { vaultId: VA, group: "Payroll", expectedVersion: 0 });
  const vaults = (await call(config, "GET", `/organizations/${created.orgId}/vaults`)).body.vaults;
  assert.equal(vaults.length, 1);
  assert.equal(vaults[0].organization.orgId, created.orgId);
  assert.equal(vaults[0].organization.group, "Payroll");

  const audit = (await call(config, "GET", `/organizations/${created.orgId}/audit`)).body.events;
  const kinds = new Set(audit.map((e) => e.eventType));
  assert.ok(kinds.has("APPLICATION METADATA EVENT"));
  assert.ok(audit.some((e) => e.action === "org_renamed"));
  assert.ok(audit.some((e) => e.action === "vault_assigned"));
  assert.ok(!audit.some((e) => e.eventType === "APPLICATION METADATA EVENT" && e.txId), "metadata events are not chain transactions");
});

test("isolation: org A never exposes org B members/vaults/audit; mismatched ids fail cleanly", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  const VB = "bb".repeat(32);
  seedVault(config, VA);
  seedVault(config, VB);

  const a = (await call(config, "POST", "/organizations", { name: "Org A" })).body.organization;
  const b = (await call(config, "POST", "/organizations", { name: "Org B" })).body.organization;

  await call(config, "POST", `/organizations/${a.orgId}/members`, { displayName: "Alice", roles: ["treasurer"], expectedVersion: 1 });
  await call(config, "POST", `/organizations/${b.orgId}/members`, { displayName: "Bob", roles: ["auditor"], expectedVersion: 1 });
  await call(config, "POST", `/organizations/${a.orgId}/vaults`, { vaultId: VA, expectedVersion: 0 });
  await call(config, "POST", `/organizations/${b.orgId}/vaults`, { vaultId: VB, expectedVersion: 1 });

  const aMembers = (await call(config, "GET", `/organizations/${a.orgId}/members`)).body.members;
  assert.deepEqual(aMembers.map((m) => m.displayName), ["Alice"], "A's member list must not contain B's members");
  const aVaults = (await call(config, "GET", `/organizations/${a.orgId}/vaults`)).body.vaults;
  assert.deepEqual(aVaults.map((v) => v.vaultId), [VA]);

  const aAudit = (await call(config, "GET", `/organizations/${a.orgId}/audit`)).body.events;
  assert.ok(!aAudit.some((e) => e.orgId === b.orgId), "A's audit must not include B's metadata events");
  assert.ok(!aAudit.some((e) => e.vaultId === VB), "A's audit must not include B's vault events");

  // Unassigning B's vault through A's scope must fail cleanly.
  await expectApiError(call(config, "POST", `/organizations/${a.orgId}/vaults/${VB}/unassign`, { expectedVersion: 2 }), 404, "ASSIGNMENT_NOT_FOUND");
  // Unknown / malformed org ids fail cleanly.
  await expectApiError(call(config, "GET", "/organizations/00000000-0000-0000-0000-000000000000"), 404, "ORG_NOT_FOUND");
  await expectApiError(call(config, "GET", "/organizations/.."), 422, "ORG_ID_INVALID");
  await expectApiError(call(config, "GET", "/organizations/../../etc"), 404, "NOT_FOUND"); // deep traversal dies at routing, never touches the fs
  // Rename with A's id cannot touch B (and stale versions are rejected).
  await expectApiError(call(config, "POST", `/organizations/${a.orgId}/rename`, { name: "X", expectedVersion: 999 }), 409, "VERSION_CONFLICT");
  assert.equal((await call(config, "GET", `/organizations/${b.orgId}`)).body.organization.name, "Org B");
});

test("AUTHORITY: org roles grant nothing; real covenant authority needs no membership", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  seedVault(config, VA);

  const orgRec = (await call(config, "POST", "/organizations", { name: "Authority Test" })).body.organization;
  // UNRELATED_X is 'owner'+'administrator'+'treasurer'+'approver' in org metadata…
  await call(config, "POST", `/organizations/${orgRec.orgId}/members`, {
    displayName: "Mallory",
    address: addressForXOnlyPubkey(config, UNRELATED_X),
    roles: ["owner", "administrator", "treasurer", "approver"],
    expectedVersion: 1
  });
  await call(config, "POST", `/organizations/${orgRec.orgId}/vaults`, { vaultId: VA, expectedVersion: 0 });

  // …but the funds pipeline never consults org metadata: still NOT_OWNER /
  // NOT_DELEGATE, with zero durable claims.
  const unrelatedAddr = addressForXOnlyPubkey(config, UNRELATED_X);
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VA, action: "ownerTopUp", params: { topUpAmountSompi: "100000000" }, signerAddress: unrelatedAddr }),
    (e) => e.code === "NOT_OWNER"
  );
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VA, action: "delegateSpend", params: { payAmountSompi: "100000000", recipientIndex: 1 }, signerAddress: unrelatedAddr }),
    (e) => e.code === "NOT_DELEGATE"
  );
  for (const sub of ["claims/transition", "claims/submission"]) {
    const dir = path.join(config.dataRoot, sub);
    assert.deepEqual(fs.existsSync(dir) ? fs.readdirSync(dir) : [], [], "org roles must never produce claims");
  }

  // The REAL owner and delegate have no org member records at all — their
  // covenant authority is untouched by that absence.
  const manifest = require("../src/manifest-v2").loadManifestV2(config, VA);
  assert.equal(
    assertSignerAuthorized(config, { role: "owner", signerAddress: addressForXOnlyPubkey(config, OWNER_X), template: manifest.template, state: manifest.live.state, action: "ownerTopUp" }),
    OWNER_X
  );
  assert.equal(
    assertSignerAuthorized(config, { role: "delegate", signerAddress: addressForXOnlyPubkey(config, DELEGATE_X), template: manifest.template, state: manifest.live.state, action: "delegateSpend" }),
    DELEGATE_X
  );
});

test("metadata corruption degrades gracefully: vaults stay visible, orgs marked corrupt", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  seedVault(config, VA);
  const orgRec = (await call(config, "POST", "/organizations", { name: "Fragile" })).body.organization;
  await call(config, "POST", `/organizations/${orgRec.orgId}/vaults`, { vaultId: VA, expectedVersion: 0 });

  // Corrupt the org record: listing marks it, vault presentation survives.
  fs.writeFileSync(path.join(config.dataRoot, "orgs", `${orgRec.orgId}.json`), "{ nope");
  const listed = (await call(config, "GET", "/organizations")).body.organizations;
  assert.equal(listed[0].error, "CORRUPT_METADATA");
  const vault = (await call(config, "GET", `/vaults/${VA}`)).body;
  assert.equal(vault.vaultId, VA, "vault truth is independent of org metadata");
  assert.equal(vault.organization.metadataError, "CORRUPT_METADATA");
  assert.equal(vault.operational.status, "ACTIVE", "funds operations remain governed by vault truth");

  // Corrupt assignments: orgs listing surfaces the error; vaults unaffected.
  fs.writeFileSync(path.join(config.dataRoot, "orgs", "assignments.json"), "broken");
  const withBrokenAssignments = (await call(config, "GET", "/organizations")).body;
  assert.ok(withBrokenAssignments.assignmentsError, "assignments corruption is surfaced, not hidden");
  const vault2 = (await call(config, "GET", `/vaults/${VA}`)).body;
  assert.equal(vault2.vaultId, VA);
  assert.equal(vault2.organization, null, "corrupt assignments degrade to unassigned, never hide the vault");
});

test("assignment validation through the API: unknown vault 404, closed vaults assignable", async () => {
  const config = tempConfig();
  const VA = "aa".repeat(32);
  seedVault(config, VA);
  // Mark the vault RECOVERED (closed) — still assignable for history.
  const m = require("../src/manifest-v2").loadManifestV2(config, VA);
  persistManifestV2(config, { ...m, status: "RECOVERED", live: null });

  const orgRec = (await call(config, "POST", "/organizations", { name: "Archive" })).body.organization;
  await expectApiError(
    call(config, "POST", `/organizations/${orgRec.orgId}/vaults`, { vaultId: "99".repeat(32), expectedVersion: 0 }),
    404,
    "VAULT_NOT_FOUND"
  );
  const assigned = (await call(config, "POST", `/organizations/${orgRec.orgId}/vaults`, { vaultId: VA, group: "Closed archive", expectedVersion: 0 })).body.assignment;
  assert.equal(assigned.orgId, orgRec.orgId);
  const vaults = (await call(config, "GET", `/organizations/${orgRec.orgId}/vaults`)).body.vaults;
  assert.equal(vaults[0].operational.status, "CLOSED");
});
