"use strict";

/*
 * Deterministic Idempotency-Key derivation for mutating MCP tool calls
 * (docs/postlaunch/mcp-interface-spec.md §7).
 *
 * key = "mcp1-" + sha256hex(canonicalJsonStringify({
 *          v: 1, tool, id: { t: typeof mcpRequestId, v: String(mcpRequestId) },
 *          args }))
 *
 * Properties (each covered by tests):
 *   - STABLE: the same MCP request id + tool + arguments always derive the
 *     same key, so a client-side retry of the SAME JSON-RPC request (crash,
 *     dropped pipe, timeout-with-retry) deduplicates server-side via the
 *     platform Idempotency-Key contract instead of creating a second
 *     durable request;
 *   - DISCRIMINATING: a different request id, tool, or ANY argument
 *     difference derives a different key (the server would additionally
 *     refuse a same-key/different-body replay with 409
 *     IDEMPOTENCY_KEY_CONFLICT — defense in depth, not the primary line);
 *   - CANONICAL: the hash preimage uses the project's canonical key-sorted
 *     JSON (core/model/canonical-json — the G-2 rule: commitment/hash
 *     preimages must NEVER depend on object key order), so two argument
 *     objects with identical values but different key insertion order are
 *     the SAME operation;
 *   - SHAPE-VALID: "mcp1-" + 64 hex = 69 chars of [A-Za-z0-9_.:-], inside
 *     the server's accepted Idempotency-Key shape (^[A-Za-z0-9_.:-]{1,200}$).
 *
 * Conservative direction: if two SEPARATE sessions of the same credential
 * ever reuse the same JSON-RPC id with byte-identical arguments, the second
 * call REPLAYS the first durable outcome (marked `replayedIdempotency` in
 * the envelope) rather than creating a duplicate spend request — the
 * funds-conservative failure mode. A genuinely new identical operation is
 * expressed with a new JSON-RPC request id (which every session-scoped id
 * allocator produces anyway).
 *
 * The id is type-tagged (1 vs "1" differ) and arguments are hashed AFTER
 * closed-schema validation, so hostile structures never reach the
 * canonical serializer.
 */

const crypto = require("node:crypto");
const { canonicalJsonStringify } = require("../../core/model/canonical-json");

function deriveIdempotencyKey({ tool, mcpRequestId, args }) {
  if (typeof tool !== "string" || tool === "") throw new Error("deriveIdempotencyKey: tool name required");
  const t = typeof mcpRequestId;
  if (t !== "string" && t !== "number") throw new Error("deriveIdempotencyKey: MCP request id must be a string or number");
  const preimage = canonicalJsonStringify({ v: 1, tool, id: { t, v: String(mcpRequestId) }, args: args ?? {} });
  return `mcp1-${crypto.createHash("sha256").update(preimage, "utf8").digest("hex")}`;
}

module.exports = { deriveIdempotencyKey };
