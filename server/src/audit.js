"use strict";

/*
 * Backend audit module: the SDK durable audit log, plus the platform-event
 * hook (completion-standard surface 18; docs/postlaunch/
 * webhooks-events-spec.md §5).
 *
 * appendAudit here is the SDK appendAudit CONTRACT, unchanged (same
 * arguments, same return, same durability, same audit stream) — followed
 * by server/src/events.js noteAuditRecord, which derives zero-or-one
 * closed-catalog platform events from the just-written audit record and
 * appends them to the durable outbox. The hook is FAILURE-ISOLATED BY
 * CONTRACT (noteAuditRecord never throws): a broken event store loses the
 * NOTIFICATION, never the mutation or its audit line — mirroring the
 * audit stream's own documented crash-window semantics (sdk/src/store.js
 * header). Events are observation, never authority.
 *
 * Every SERVER-side audit write flows through this module (api.js,
 * governance.js, risk.js, intent-records.js). Audit writes issued deep
 * inside sdk/src (submit/reconcile chain proofs) do NOT pass here; their
 * corresponding events are emitted explicitly at the API route layer
 * (api.js), which is the server's natural observation point for them.
 *
 * HASH CHAIN (fullscale surface 17 residual; server/src/audit-chain.js):
 * every record appended here additionally carries a tamper-evident chain
 * envelope { v, seq, nonce, prevHash, recordHash } — purely additive to
 * the record, verified via GET /audit/chain/verify. FAIL-SAFE BY
 * CONTRACT: chain bookkeeping failure falls back to the exact unchained
 * append (the chain must never cost a mutation its audit line); records
 * that do not flow through this module (sdk-internal writers, pre-chain
 * history) remain unchained and are reported as such — never silently
 * claimed chained (docs/postlaunch/audit-chain-spec.md §5).
 */

const sdkAudit = require("../../sdk/src/audit");
const { appendChainedAudit } = require("./audit-chain");

async function appendAudit(config, event) {
  const record = await appendChainedAudit(config, event);
  await require("./events").noteAuditRecord(config, record); // never throws
  return record;
}

module.exports = { appendAudit, readAudit: sdkAudit.readAudit };
