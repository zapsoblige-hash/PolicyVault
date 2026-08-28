-- PolicyVault tamper-evident AUDIT HASH CHAIN (fullscale surface 17
-- residual: "audit log not hash-chained"; docs/postlaunch/audit-chain-spec.md).
--
-- PURELY ADDITIVE. No existing audit row is rewritten and no existing
-- column changes. Chain fields live INSIDE audit_events.value (jsonb) as a
-- `chain` object on each NEW record written through server/src/audit.js:
--   chain = { v, seq, nonce, prevHash, recordHash }
-- where recordHash = SHA-256 over the canonical (key-order-independent)
-- JSON of { content, nonce, prevHash, seq } — content being the record
-- minus its chain envelope, in storage-normal form. Records WITHOUT a
-- chain object are UNCHAINED (written before this deployment, or written
-- by sdk-internal audit paths that do not flow through server/src/audit.js)
-- and are reported as such — never silently claimed chained (spec §5).
--
-- The chain DESCRIBES the audit stream; it never grants or verifies
-- covenant authority. A broken chain is an integrity ALARM about the
-- hosted audit copy — Kaspa consensus remains the only financial truth.
--
-- audit_chain_state — the durable chain-head anchor (one row per network,
--   key = 'head'; standard (network_id, key) + jsonb category shape,
--   accessed exclusively by server/src/audit-chain.js via
--   server/src/platform-store.js). The head is an APPEND-TIME anchor and a
--   truncation tripwire; the records themselves are the verification
--   truth (a head newer than the last stored record = TAIL_TRUNCATED).

CREATE TABLE audit_chain_state (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- 'head'
  value      jsonb NOT NULL,            -- policyvault-audit-chain-head/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

-- Chained-record lookups for verification walks and append-time head
-- recovery: partial expression index over the embedded chain seq.
CREATE INDEX audit_events_chain_seq_idx
  ON audit_events (network_id, (((value -> 'chain') ->> 'seq')::bigint))
  WHERE value ? 'chain';
