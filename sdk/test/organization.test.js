"use strict";

/*
 * UNIT/SDK layer — organization metadata v2 (off-chain application data,
 * fail-closed validation, optimistic concurrency). Organization roles
 * are application metadata and grant NO covenant authority — the
 * authority tests live in wallet-authz.test.js and org-api.test.js.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { loadKaspa } = require("../src/chain");
const {
  createOrganization,
  renameOrganization,
  loadOrganization,
  listOrganizations,
  addMember,
  updateMember,
  removeMember,
  loadAssignments,
  assignVault,
  unassignVault,
  assignmentFor,
  ROLE_LABELS
} = require("../src/organization");

const kaspa = loadKaspa(loadConfig());
const X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const ADDR = new kaspa.XOnlyPublicKey(X).toAddress("testnet-10").toString();
const MAINNET_ADDR = new kaspa.XOnlyPublicKey(X).toAddress("mainnet").toString();
const VAULT_A = "aa".repeat(32);
const VAULT_B = "bb".repeat(32);

function tempConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-org2-")) });
}

const code = (c) => (e) => e.code === c;

/* ---------------- organization model ---------------- */

test("create: stable UUID id, timestamps, durable reload; name is not the identifier", async () => {
  const config = tempConfig();
  const a = await createOrganization(config, { name: "Acme" });
  const b = await createOrganization(config, { name: "Acme" }); // duplicate names allowed
  assert.notEqual(a.orgId, b.orgId, "stable IDs distinguish same-named orgs");
  assert.match(a.orgId, /^[0-9a-f-]{36}$/);
  assert.ok(a.createdAt && a.version === 1);
  const reloaded = await loadOrganization(config, a.orgId);
  assert.deepEqual(reloaded, a);
});

test("create/rename: invalid names fail closed", async () => {
  const config = tempConfig();
  await assert.rejects(async () => createOrganization(config, { name: "" }), code("TEXT_REQUIRED"));
  await assert.rejects(async () => createOrganization(config, { name: "   " }), code("TEXT_REQUIRED"));
  await assert.rejects(async () => createOrganization(config, { name: 42 }), code("TEXT_INVALID"));
  await assert.rejects(async () => createOrganization(config, { name: "x".repeat(200) }), code("TEXT_TOO_LONG"));
  await assert.rejects(async () => createOrganization(config, { name: `bad${String.fromCharCode(0)}name` }), code("TEXT_INVALID"));
  await assert.rejects(async () => createOrganization(config, { name: `bad${String.fromCharCode(27)}name` }), code("TEXT_INVALID"));
});

test("rename: audited metadata-only change with optimistic concurrency", async () => {
  const config = tempConfig();
  const org = await createOrganization(config, { name: "Before" });
  await assert.rejects(async () => renameOrganization(config, org.orgId, { name: "After", expectedVersion: 9 }), code("VERSION_CONFLICT"));
  await assert.rejects(async () => renameOrganization(config, org.orgId, { name: "After" }), code("VERSION_REQUIRED"));
  const renamed = await renameOrganization(config, org.orgId, { name: "After", expectedVersion: 1 });
  assert.equal(renamed.name, "After");
  assert.equal(renamed.version, 2);
  assert.equal(renamed.orgId, org.orgId, "rename never changes the stable id");
  const events = await require("../src/audit").readAudit(config);
  assert.ok(events.some((e) => e.action === "org_renamed" && e.kind === "metadata" && e.orgId === org.orgId));
});

test("corrupted / malformed / legacy records fail closed but never break the listing or other orgs", async () => {
  const config = tempConfig();
  const good = await createOrganization(config, { name: "Good" });
  const dir = path.join(config.dataRoot, "orgs");
  const badId = "11111111-2222-3333-4444-555555555555";
  fs.writeFileSync(path.join(dir, `${badId}.json`), "{ truncated");
  const legacyId = "99999999-8888-7777-6666-555555555555";
  fs.writeFileSync(path.join(dir, `${legacyId}.json`), JSON.stringify({ schema: "policyvault-organization/v1", orgId: "legacy" }));
  const weirdId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  fs.writeFileSync(path.join(dir, `${weirdId}.json`), JSON.stringify({ schema: "policyvault-organization/v9", orgId: weirdId }));

  const listed = await listOrganizations(config);
  assert.equal(listed.length, 4);
  assert.ok(listed.find((o) => o.orgId === good.orgId && !o.error), "healthy org still listed");
  for (const id of [badId, legacyId, weirdId]) {
    const entry = listed.find((o) => o.orgId === id);
    assert.equal(entry.error, "CORRUPT_METADATA", `${id} must surface as corrupt, not vanish`);
  }
  await assert.rejects(async () => loadOrganization(config, badId));
  await assert.rejects(async () => loadOrganization(config, legacyId), code("ORG_SCHEMA_LEGACY"));
  await assert.rejects(async () => loadOrganization(config, weirdId), code("ORG_SCHEMA_UNKNOWN"));
});

test("path-traversal-like ids are rejected before touching the filesystem", async () => {
  const config = tempConfig();
  for (const evil of ["../../etc/passwd", "..%2f..", "a/../b", "", null, "x".repeat(80)]) {
    await assert.rejects(async () => loadOrganization(config, evil), code("ORG_ID_INVALID"));
  }
});

/* ---------------- members ---------------- */

test("members: add/update/remove with shared address-boundary validation", async () => {
  const config = tempConfig();
  const org = await createOrganization(config, { name: "Team" });

  const { org: v2, member } = await addMember(config, org.orgId, {
    displayName: "Alice",
    address: `  ${ADDR}  `,
    roles: ["treasurer", "approver"],
    note: "payroll",
    expectedVersion: 2 - 1
  });
  assert.equal(member.address, ADDR);
  assert.equal(member.xOnlyPubkey, X, "x-only derived through the shared boundary");
  assert.deepEqual(member.roles, ["treasurer", "approver"]);
  assert.equal(v2.version, 2);

  // contact-only member: allowed, but has NO wallet identity at all
  const { member: contact } = await addMember(config, org.orgId, {
    displayName: "Vendor Contact",
    roles: ["viewer"],
    expectedVersion: 2
  });
  assert.equal(contact.address, null);
  assert.equal(contact.xOnlyPubkey, null);

  const { member: updated } = await updateMember(config, org.orgId, member.memberId, {
    displayName: "Alice B",
    status: "INACTIVE",
    expectedVersion: 3
  });
  assert.equal(updated.displayName, "Alice B");
  assert.equal(updated.status, "INACTIVE");
  assert.equal(updated.xOnlyPubkey, X, "unchanged fields preserved");

  const after = await removeMember(config, org.orgId, contact.memberId, { expectedVersion: 4 });
  assert.equal(after.members.length, 1);
  await assert.rejects(async () => removeMember(config, org.orgId, contact.memberId, { expectedVersion: 5 }), code("MEMBER_NOT_FOUND"));
});

test("members: malformed / wrong-network addresses and bad roles fail closed", async () => {
  const config = tempConfig();
  const org = await createOrganization(config, { name: "Team" });
  await assert.rejects(async () => addMember(config, org.orgId, { displayName: "X", address: "kaspatest:qqjunk", roles: ["viewer"], expectedVersion: 1 }),
    code("ADDRESS_INVALID")
  );
  await assert.rejects(async () => addMember(config, org.orgId, { displayName: "X", address: MAINNET_ADDR, roles: ["viewer"], expectedVersion: 1 }),
    code("ADDRESS_WRONG_NETWORK")
  );
  await assert.rejects(async () => addMember(config, org.orgId, { displayName: "X", address: X, roles: ["viewer"], expectedVersion: 1 }),
    code("ADDRESS_INVALID"),
    "raw pubkeys are not addresses"
  );
  await assert.rejects(async () => addMember(config, org.orgId, { displayName: "X", roles: ["superadmin"], expectedVersion: 1 }),
    code("ROLES_INVALID")
  );
  await assert.rejects(async () => addMember(config, org.orgId, { displayName: "X", roles: [], expectedVersion: 1 }),
    code("ROLES_INVALID")
  );
  assert.equal((await loadOrganization(config, org.orgId)).members.length, 0, "failed adds leave no partial member");
  assert.ok(ROLE_LABELS.includes("approver"), "approver is a label only (v0.3 delivers consensus approvals)");
});

/* ---------------- vault assignment ---------------- */

test("assignment: assign/move/unassign, one canonical org per vault, closed vaults allowed", async () => {
  const config = tempConfig();
  const orgA = await createOrganization(config, { name: "A" });
  const orgB = await createOrganization(config, { name: "B" });
  const exists = (v) => v === VAULT_A || v === VAULT_B;

  await assignVault(config, { vaultId: VAULT_A, orgId: orgA.orgId, group: "Payroll", expectedVersion: 0, vaultExists: exists });
  assert.deepEqual((await assignmentFor(config, VAULT_A)).orgId, orgA.orgId);
  assert.equal((await assignmentFor(config, VAULT_A)).group, "Payroll");

  // move to org B — the map key guarantees a single canonical assignment
  await assignVault(config, { vaultId: VAULT_A, orgId: orgB.orgId, expectedVersion: 1, vaultExists: exists });
  const moved = await loadAssignments(config);
  assert.equal(moved.assignments[VAULT_A].orgId, orgB.orgId);
  assert.equal(Object.keys(moved.assignments).length, 1);

  // closed vaults remain assignable (business/audit history)
  await assignVault(config, { vaultId: VAULT_B, orgId: orgB.orgId, group: "Closed archive", expectedVersion: 2, vaultExists: exists });

  await unassignVault(config, { vaultId: VAULT_A, expectedVersion: 3 });
  assert.equal(await assignmentFor(config, VAULT_A), null);
  await assert.rejects(async () => unassignVault(config, { vaultId: VAULT_A, expectedVersion: 4 }), code("ASSIGNMENT_NOT_FOUND"));

  // durable reload
  const reloaded = await loadAssignments(config);
  assert.equal(reloaded.version, 4);
  assert.equal(reloaded.assignments[VAULT_B].orgId, orgB.orgId);
});

test("assignment: unknown vault / org, malformed ids, corrupt file fail closed", async () => {
  const config = tempConfig();
  const org = await createOrganization(config, { name: "A" });
  await assert.rejects(async () => assignVault(config, { vaultId: VAULT_A, orgId: org.orgId, expectedVersion: 0, vaultExists: () => false }),
    code("VAULT_NOT_FOUND")
  );
  await assert.rejects(async () => assignVault(config, { vaultId: "nothex", orgId: org.orgId, expectedVersion: 0 }),
    code("VAULT_ID_INVALID")
  );
  await assert.rejects(async () => assignVault(config, { vaultId: VAULT_A, orgId: "22222222-2222-2222-2222-222222222222", expectedVersion: 0 }),
    code("ORG_NOT_FOUND")
  );
  fs.mkdirSync(path.join(config.dataRoot, "orgs"), { recursive: true });
  fs.writeFileSync(path.join(config.dataRoot, "orgs", "assignments.json"), "{ nope");
  await assert.rejects(async () => loadAssignments(config));
  assert.equal(await assignmentFor(config, VAULT_A), null, "corrupt assignments never block vault presentation");
});

/* ---------------- concurrency ---------------- */

test("concurrency: competing writes are rejected loudly — no silent lost update", async () => {
  const config = tempConfig();
  const org = await createOrganization(config, { name: "Race" });

  // Two clients both read version 1 and try to add a member.
  const first = await addMember(config, org.orgId, { displayName: "M1", roles: ["viewer"], expectedVersion: 1 });
  assert.equal(first.org.version, 2);
  await assert.rejects(async () => addMember(config, org.orgId, { displayName: "M2", roles: ["viewer"], expectedVersion: 1 }),
    code("VERSION_CONFLICT"),
    "second writer must be told to reload, not silently clobber"
  );
  const state = await loadOrganization(config, org.orgId);
  assert.equal(state.members.length, 1);
  assert.equal(state.members[0].displayName, "M1");

  // rename racing a member edit
  await assert.rejects(async () => renameOrganization(config, org.orgId, { name: "Renamed", expectedVersion: 1 }), code("VERSION_CONFLICT"));
  await renameOrganization(config, org.orgId, { name: "Renamed", expectedVersion: 2 });

  // member removal racing a role update
  const memberId = state.members[0].memberId;
  await updateMember(config, org.orgId, memberId, { roles: ["auditor"], expectedVersion: 3 });
  await assert.rejects(async () => removeMember(config, org.orgId, memberId, { expectedVersion: 3 }), code("VERSION_CONFLICT"));
  await removeMember(config, org.orgId, memberId, { expectedVersion: 4 });

  // assignment map: same discipline
  const exists = () => true;
  await assignVault(config, { vaultId: VAULT_A, orgId: org.orgId, expectedVersion: 0, vaultExists: exists });
  await assert.rejects(async () => assignVault(config, { vaultId: VAULT_B, orgId: org.orgId, expectedVersion: 0, vaultExists: exists }),
    code("VERSION_CONFLICT")
  );
});
