"use strict";

/*
 * Durable append-only audit log. Every meaningful vault operation produces
 * an event. Application-layer record; never a consensus value.
 *
 * Phase C: events flow through the persistence backend (JSONL file under
 * the json backend, append-ordered audit_events rows under postgres).
 * ORDERING/ATOMICITY SEMANTICS (ported, not redesigned): the audit write
 * happens AFTER its mutation and is not atomic with it — exactly the
 * released JSON behavior (a crash between mutation and audit loses the
 * audit line, never the mutation). Both backends share that contract.
 */

const { getStore } = require("./store");

async function appendAudit(config, event) {
  const record = { at: new Date().toISOString(), ...event };
  await getStore(config).appendAudit(record);
  return record;
}

async function readAudit(config, { vaultId, limit = 200 } = {}) {
  return getStore(config).readAudit({ vaultId, limit });
}

module.exports = { appendAudit, readAudit };
