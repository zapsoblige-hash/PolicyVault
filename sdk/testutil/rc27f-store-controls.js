"use strict";
const assert = require("node:assert/strict");
module.exports = async function reservationIdentityControls(store, C) {
  const records = [
    [C.TRANSITION_CLAIM, "resv-test-vault-test-agent-test-request", { schema: "policyvault-budget-reservation/v1", vaultId: "test-vault", agentPk: "test-agent", requestId: "test-request" }, ["vaultId", "agentPk", "requestId"]],
    [C.TRANSITION_CLAIM, "resvlock-test-vault", { schema: "policyvault-reservation-lock/v1", vaultId: "test-vault" }, ["vaultId"]],
    [C.GOVERNANCE_PROPOSAL, "xlock-test-proposal", { schema: "policyvault-governance-transition-lock/v1", proposalId: "test-proposal", holderToken: "test-holder", createdAtMs: 0 }, ["proposalId"]]
  ];
  for (const [category, key, valid, fields] of records) {
    await store.write(category, key, valid);
    assert.deepEqual(await store.read(category, key), valid);
    assert.ok((await store.listValues(category, { strict: true })).some((r) => r.schema === valid.schema && fields.every((field) => r[field] === valid[field])));
    for (const field of fields) for (const wrong of [null, "substituted"]) {
      await store.write(category, key, { ...valid, [field]: wrong });
      await assert.rejects(store.read(category, key), { code: "STORE_IDENTITY_MISMATCH" });
      await assert.rejects(store.listValues(category, { strict: true }), { code: "STORE_IDENTITY_MISMATCH" });
    }
    await store.remove(category, key);
  }
};
