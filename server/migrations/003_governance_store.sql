-- PolicyVault policy-change governance store (Program B server wiring).
-- Implements docs/postlaunch/audit-correlation-spec.md §5.3 EXACTLY.
--
-- Stored proposals/approvals are COORDINATION records, never authority:
-- every consumer recomputes the proposal digest AND the authority-delta
-- classification from content (stored labels distrusted,
-- docs/postlaunch/governance-spec.md §9.4), and every approval row is
-- re-verifiable by anyone from proposal content (Schnorr over the
-- domain-separated digest `policyvault-governance-proposal-digest/v1` —
-- permanently disjoint from TransactionSigningHash, so an approval can
-- never be replayed as a transaction signature). Tampering any proposal
-- byte invalidates every collected signature against the recomputed
-- digest. Covenant financial authority moves ONLY through owner/agent/
-- approver wallet signatures over frozen transaction bytes, verified by
-- Kaspa consensus — never through these rows.

CREATE TABLE governance_proposals (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- proposalId (uuid)
  value      jsonb NOT NULL,            -- policyvault-governance-proposal/v1
                                        -- (+ proposalDigest cached; every
                                        --  consumer recomputes digest AND
                                        --  classification from content)
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX governance_proposals_vault_idx
  ON governance_proposals (network_id, (value->>'vaultId'));
CREATE INDEX governance_proposals_digest_idx
  ON governance_proposals (network_id, (value->>'proposalDigest'));

-- One row per collected governance approval; create-only, append-only.
CREATE TABLE governance_approvals (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- "<proposalDigest>-<approverXOnly>"
  value      jsonb NOT NULL,            -- { schema, proposalId, proposalDigest,
                                        --   approverXOnly, approverAddress,
                                        --   signature, collectedAt }
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)         -- one approval per wallet per digest
);
