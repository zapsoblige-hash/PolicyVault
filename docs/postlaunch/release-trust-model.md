# PolicyVault Release Signing — Trust Model

TRACK 9 (release signing + succession governance). Status: **DESIGNED +
IMPLEMENTED + UNIT-TESTED**. This document is the authoritative trust
model for the release-signing tool family
(`tools/release-manifest.js`, `tools/release-sign.js`,
`tools/release-verify.js`, `tools/lib/release-hashes.js`,
`tools/lib/release-manifest-schema.js`, `release-signers.json`) and the
governance procedures around it (key compromise, revocation, signer
replacement, maintainer succession, second-signer onboarding).

**No cryptography is invented here.** Signing uses stock OpenSSH
(`ssh-keygen -Y sign` / `-Y verify`, the SSHSIG format, `allowed_signers`
policy files, signature namespaces) — the same mechanism `git` uses for
SSH-signed commits/tags. Hashing is plain SHA-256. Nothing in this track
is a new cryptographic primitive, and nothing in it is a funds-security
control: Kaspa L1 consensus remains the only funds-security boundary
(`SECURITY.md`), exactly as for every other PolicyVault component. This
track's job is a narrower, well-understood problem: **letting anyone who
downloads a PolicyVault release cryptographically confirm which
maintainer(s) published exactly which bytes.**

## 1. What this is not

- **Not a security review, and never claimed as one.** A valid signature proves
  authorship/publication, not correctness or security review. See §12.
- **Not the publication gate.** Publishing PolicyVault publicly remains a
  separate, explicit, owner-only HARD HUMAN GATE (`docs/product-policy.md`,
  `CLAUDE.md`, `docs/postlaunch/publication-decision-packet.md`). This
  tooling exists so that, once publication is authorized, every artifact
  the owner chooses to publish carries a verifiable identity — it grants
  no authority to publish anything, run anything, or promote anything.
- **Not a deployment or promotion mechanism.** It never touches
  production infrastructure, DNS, or the release-promotion pipeline
  (`docs/production-release.md`, `docs/postlaunch/promotion-readiness-
  packet.md`). Building and signing a manifest for a candidate is
  informational and additive; it changes nothing about the separate
  owner-gated promotion decision (`CLAUDE.md` "SOURCE CHANGE ≠ AUTOMATIC
  LIVE DEPLOYMENT").
- **Not a second real signer today.** Exactly ONE real signer (the
  maintainer) is possible right now — see §3 and §10 for why this is
  stated plainly rather than simulated.

## 2. Roles

| Role | Who | What they do | What they can NOT do |
|---|---|---|---|
| **Release maintainer** | The project owner today | Decides what becomes a release candidate, drives the build, decides when to publish (the separate hard human gate) | Cannot make a release "verified" by fiat — verification is the signature policy below, run by anyone, not asserted by the maintainer |
| **Release signer** | Today: the same person as the maintainer, holding one SSH signing key | Signs a release manifest with `tools/release-sign.js`, attesting "I am this signer id, and I attest to exactly these bytes" | Cannot move funds, cannot change covenant behavior, cannot authorize a deployment — a release signature is an authorship attestation only |
| **Verifier** | Anyone: a user, an operator, a future CI job, another maintainer | Runs `tools/release-verify.js` against a manifest, its signatures, and `release-signers.json`, optionally re-hashing a real tree/archive | Cannot be tricked into accepting fewer than `threshold` distinct signers, a revoked signer, an unfilled placeholder, a wrong namespace, or a tampered manifest — every one of those fails closed (§11, and the test suite in `tools/test/release-signing.test.js`) |

Maintainer and signer are **structurally distinct roles** even though
one person holds both today. Nothing in the tooling assumes they are the
same person — `release-signers.json` never asks "is this the maintainer,"
it asks "is this an entry in the signer policy with a valid, unrevoked,
filled-in key, and did it produce a valid signature." That is exactly
what lets the architecture grow to a real second maintainer/signer
(§9–§10) without changing any code, only the policy file.

## 3. The honest current state: ONE real signer

**Today, `release-signers.json` lists exactly one signer entry, and its
`publicKey` field is the literal placeholder string `"OWNER-TO-FILL"` —
no real key exists yet.** `tools/release-verify.js` refuses to count any
signature against a placeholder entry (`SIGNER_PLACEHOLDER_UNFILLED`),
so as shipped this policy file cannot pass verification for anyone —
including the maintainer — until the owner personally generates a real
key and fills it in (§7, an owner-only action, never performed by an
agent).

This is deliberate and stated plainly rather than worked around:

- This track does **not** generate a real signing key on the owner's
  behalf, and does **not** fill in `release-signers.json`.
- This track does **not** fabricate a second signer. There is no second
  entry in `release-signers.json`, and there will not be one until a
  real, independent second maintainer exists and completes the
  onboarding checklist in §9. Generating two keys both controlled by the
  same maintainer and labeling them "multi-signer" would misrepresent
  the trust model to every user who reads it — PolicyVault does not do
  that.
- The tooling is **multi-signer CAPABLE today** (arbitrary signer count,
  configurable `threshold`, distinct-key dedup, per-signer
  `validFrom`/`revokedAt`) precisely so that reaching a real second
  signer is a **policy change** (§9), never a **rewrite**. Artifact
  identity semantics (the manifest schema, the hash algorithms, the
  signature format) do not change when the signer count changes.

## 4. Artifact identity — what a release manifest records

A `policyvault-release-manifest/1` document (built by
`tools/release-manifest.js`) is a canonical-JSON object recording the
identity of one release candidate or release. Every hash in it is
**computed by the tool itself from real bytes on disk** — never accepted
as a bare string the caller asserts — with two narrow, explicitly labeled
exceptions (`imageDigest`, `baseImageDigest`) that come from a different
trust domain the tool cannot reach without a Docker daemon.

| Field | Meaning | Computed how |
|---|---|---|
| `schema` | `"policyvault-release-manifest/1"` (closed; unknown values fail closed) | fixed constant |
| `version` | The exact release/candidate version string (e.g. `v1.6.0`, `fullscale-rc9`) | caller-supplied |
| `releaseTimestamp` | Canonical ISO-8601 UTC build time | tool default (`Date#toISOString`), or `--timestamp` override |
| `sourceCommit` | The git commit id the release was built from | caller-supplied (validated as 40/64-hex) |
| `treeHash` | Content hash of the ENTIRE release tree | **self-computed** — see §5 |
| `archiveSha256` | sha256 of a source archive (e.g. `git archive` tarball), or `null` | **self-computed** from `--archive <path>` |
| `imageDigest` | The container image's content-addressed digest (`sha256:…`), or `null` | caller-supplied, shape-validated only (Docker's fact, not this tool's) |
| `baseImageDigest` | The resolved base OS image digest used at build time, or `null` | caller-supplied, shape-validated only |
| `covenants` | `{ "v0.3": { path, sha256, label }, … }` for every covenant `.sil` file present in the tree | **self-computed** — sha256 of each `contracts/PolicyVault.<version>.sil` file found |
| `dependencies.lockfiles` | `{ "sdk/package-lock.json": "<sha256>", … }` for every known lockfile present | **self-computed** |
| `dependencies.vendoredKaspaWasmHash` | Content hash of the staged `deploy/vendor/kaspa` directory (the pinned kaspa-wasm module — `tools/stage-vendor.sh`), or `null` if not staged in this tree | **self-computed** — same tree-hash algorithm as `treeHash`, scoped to that directory |
| `generator` | `{ tool, nodeVersion }` — provenance of the manifest generator itself | tool-recorded |

`covenants[version].label` is `"frozen"` for every version except those
listed in `--candidate-versions` (default `v0.6`, matching `CLAUDE.md`'s
current statement that v0.6 bytes are NOT frozen as of this writing). The
tool never hardcodes a freeze assertion that can silently go stale — the
candidate list is an explicit, overridable input, and the manifest is
honest about exactly what it labeled and why (§4 of this document is the
place that changes, not the tool's default, when a version's freeze
status changes).

Any top-level manifest field outside this exact closed list is refused
by the verifier (`tools/lib/release-manifest-schema.js
assertManifestShape`) — "unknown fields refused," matching the project's
standing versioning discipline (`CLAUDE.md` "Versioning / fail-closed").

## 5. The `treeHash` algorithm (self-computed, not git's internal format)

`treeHash` is deliberately **not** `git rev-parse <commit>^{tree}` — that
would make manifest generation depend on a local `git` binary and on
git's internal object encoding matching across environments. Instead
(`tools/lib/release-hashes.js hashTree`):

1. Recursively list every regular file under the tree root, excluding
   any directory literally named `.git` (the checkout mechanism, not
   content).
2. For each file, compute `sha256(fileBytes)`.
3. Build one line per file: `"<posix-relative-path>:<sha256hex>"`.
4. Sort the lines byte-wise.
5. `treeHash = sha256(utf8(lines.join("\n") + "\n"))`.

**Symlinks are refused outright** (fail closed, `RELEASE_HASH_INVALID`)
rather than silently followed or silently skipped — a symlink inside a
release tree is either a development artifact that should never have
been hashed (this was caught for real while building this track: a live
worktree's `mobile/node_modules` symlink) or a potential escape, and this
tool never guesses which. **Consequence for operators:** always point
`--tree` at a clean export — `git archive <commit> | tar -x` into a fresh
directory, or an equivalent clean checkout — never at a live development
worktree, which may carry symlinked `node_modules` or other local-only
artifacts. This matches the project's existing reproducibility procedure
(`docs/production-release.md` §10: "the release artifact is `git archive`
of the commit").

Because the algorithm is fully specified above, **any implementer can
reproduce `treeHash` independently without running this tool at all** —
that independence is the point of a self-computed identity hash.

## 6. The signed release manifest

`tools/release-manifest.js` writes the manifest as **canonical JSON plus
exactly one trailing newline** — the deterministic, storage-order-
independent serialization already used for commitment preimages
elsewhere in PolicyVault (`core/model/canonical-json.js`, `tools/lib/
release-manifest-schema.js manifestBytes`). Those exact bytes, and only
those bytes, are what gets signed and verified. A manifest re-saved with
different whitespace re-canonicalizes to the same bytes and verifies
identically; a manifest with any VALUE changed re-canonicalizes to
different bytes and invalidates every existing signature — signature
integrity tracks values, never incidental formatting.

Signing (`tools/release-sign.js`) is a thin wrapper around:

```
ssh-keygen -Y sign -n policyvault-release -f <private-key> <manifest-file>
```

producing an SSHSIG-format signature written to
`<manifest-file>.sig.<signerId>` (one file per signer — a manifest
directory can hold any number of independent signatures with no
collisions). `policyvault-release` is a fixed namespace: a signature
made for any other purpose under a different namespace can never be
mistaken for a release signature, and OpenSSH enforces this natively (a
namespace mismatch is a hard verification failure, not a warning).

Verification (`tools/release-verify.js`) discovers every
`<manifest>.sig.<signerId>` file next to (or in `--sig-dir`) the
manifest, and for each one:

1. Looks up `signerId` in `release-signers.json`. Not present →
   `SIGNER_NOT_IN_POLICY`.
2. Refuses an unfilled placeholder (`publicKey === "OWNER-TO-FILL"`) →
   `SIGNER_PLACEHOLDER_UNFILLED` (§3, §11).
3. Refuses a malformed key shape → `SIGNER_KEY_INVALID`.
4. Runs `ssh-keygen -Y verify -f <tmp-allowed_signers> -I <signerId> -n
   policyvault-release -s <sigfile>` against the canonical manifest
   bytes. A cryptographic failure (tampering, wrong key, wrong
   namespace) → `SIGNATURE_INVALID`.
5. Checks the signer's `validFrom`/`revokedAt` window against the
   verification time (`--now`, default: current time) →
   `SIGNER_NOT_YET_VALID` / `SIGNER_REVOKED` if outside it.
6. Otherwise: `VALID`.

**Distinct-key dedup:** signatures are tallied toward `threshold` by the
**actual public key bytes**, not by signer id. Two policy entries
pointing at the same physical key, or the same signer id signing twice,
count once. This is enforced in code (`keyFingerprint` in
`tools/release-verify.js`), not left to operator discipline — see the
hard boundary in §3 about never presenting one key as two signers.

**Hash re-verification** is independent of and additional to the
signature check: given `--tree`/`--archive`, the verifier recomputes
`treeHash`, every `covenants[*].sha256`, every
`dependencies.lockfiles[*]`, and `dependencies.vendoredKaspaWasmHash`
from scratch and compares byte-for-byte against the manifest's claims. A
manifest that signs correctly but whose claimed hashes disagree with the
real artifact **still fails verification overall** — a valid signature
proves who published a claim, never that the claim is true. `imageDigest`
/`baseImageDigest` are compared against caller-supplied values (`--image-
digest`, `--base-image-digest`) when given, since this tool cannot
recompute a registry digest itself.

Overall `ok = (distinct valid signers ≥ threshold) AND (every requested
hash check passed)`.

## 7. `release-signers.json` — the signer policy

```json
{
  "schema": "policyvault-release-signers/1",
  "namespace": "policyvault-release",
  "threshold": 1,
  "signers": [
    {
      "id": "maintainer-primary",
      "role": "maintainer",
      "displayName": "…",
      "publicKey": "OWNER-TO-FILL",
      "validFrom": null,
      "revokedAt": null
    }
  ],
  "updatedAt": "…"
}
```

- `threshold` is the minimum count of **distinct, currently-valid,
  non-placeholder** signers required for `ok: true`.
- `signers[].publicKey` is the exact two-field form of an SSH public key
  (`"<keytype> <base64>"`, no trailing comment — the same content
  `ssh-keygen -Y sign`'s companion `.pub` file carries, minus its
  comment) or the literal placeholder `"OWNER-TO-FILL"`.
- `validFrom`/`revokedAt` are ISO-8601 UTC or `null`. A signature is only
  counted while verification time falls inside `[validFrom, revokedAt)`.
- An unknown `schema` value fails closed
  (`RELEASE_SIGNERS_POLICY_UNKNOWN_VERSION`), never routed to a default
  parser.
- **Filling in the real key, changing `threshold`, or adding a signer
  entry are OWNER-ONLY actions.** No agent generates a maintainer's real
  signing key or edits this policy's trust-bearing fields
  autonomously — see the hard boundaries for this track.

## 8. Verification procedure (for users and operators)

Given a published release's manifest and signatures (once publication is
authorized — §1):

```
node tools/release-verify.js \
  --manifest policyvault-vX.Y.Z.policyvault-release-manifest.json \
  --policy release-signers.json \
  --tree ./policyvault-vX.Y.Z-source \
  --archive policyvault-vX.Y.Z-source.tar.gz \
  --json
```

- Exit 0 + `"ok": true` means: at least `threshold` distinct, currently
  valid signers listed in `release-signers.json` cryptographically
  attested to exactly this manifest, and every hash you asked it to
  recheck (source tree, archive) matches what the manifest claims.
- **It does not mean:** the code is secure, the code is bug-free, the
  code has been security-reviewed, or that PolicyVault is "audited"
  in any sense (`SECURITY.md`, `docs/product-policy.md`).
- A verifier who only has the manifest and a signature (no source tree)
  can still verify signature validity and threshold — omit `--tree`/
  `--archive` and the report's `hashCheck.checked` will be empty,
  clearly showing nothing was hash-reverified.
- `release-signers.json` itself should be fetched from a channel the
  verifier trusts independently of the release artifact being verified
  (e.g. the project's own git history over time, cross-checked against
  prior known-good copies) — a policy file shipped ONLY alongside the
  one release it is meant to check provides much weaker assurance than
  one with an established history. This is the same "trust on first use,
  then diff against history" posture as SSH host keys and `git`'s own
  signed-commit model, and this track does not invent a stronger one.

## 9. Second-signer onboarding checklist

This is the concrete procedure for turning today's one-real-signer
policy into a genuine two-signer policy, **once a real, independent
second maintainer exists.** No step here is performed by an agent on the
owner's behalf; this is a human governance procedure the tooling
supports.

1. **Identity verification.** The owner independently confirms who the
   second maintainer is, through a channel outside PolicyVault tooling
   (this is a human trust decision, not a cryptographic one — no tool in
   this repository can establish "this is a real, accountable person").
2. **Independent key generation.** The second maintainer generates their
   OWN SSH signing key **on their own hardware**, using their own
   `ssh-keygen` (or equivalent), and never transmits the private key to
   the first maintainer or to any PolicyVault-controlled system. This is
   the property that makes it a real second key rather than a
   maintainer-controlled duplicate (§3's hard boundary).
3. **Public key exchange.** The second maintainer shares only their
   PUBLIC key (the `ssh-keygen -Y sign`/`ssh-keygen` `.pub` output). The
   owner independently confirms the fingerprint out-of-band (a second
   channel from the one the key file arrived on) before trusting it.
4. **`allowed_signers` entry.** Add a new entry to
   `release-signers.json.signers`: a new `id`, the confirmed
   `publicKey`, and a `validFrom` no earlier than the confirmation date
   in step 3 (never `null` for a newly onboarded signer — an explicit
   start date is part of the audit trail).
5. **Threshold bump via a SIGNED policy change.** Raising `threshold`
   from 1 to 2 is itself a change to a trust-bearing file — the
   recommended discipline is that the commit changing
   `release-signers.json` is itself reviewed and, once ≥2 real signers
   exist, co-signed by both maintainers (a release-manifest-shaped
   attestation over the policy file's own bytes, or an ordinary signed
   git commit — either establishes that the threshold change was a
   joint decision, not a unilateral one). Bumping the threshold before a
   verified second key exists would only ever produce
   `THRESHOLD_NOT_MET` failures — the tooling cannot be tricked into
   accepting a threshold that has no chance of being met.
6. **Rehearsal release.** Run the full manifest → sign (both keys) →
   verify pipeline against a real (non-production) candidate tree before
   relying on the two-signer policy for a real release. Confirm: both
   signatures independently verify, `distinctValidSigners: 2`,
   `thresholdMet: true`.
7. **Revocation drill.** Before going live with the two-signer policy,
   rehearse §11's revocation procedure end-to-end: set a test
   `revokedAt` in the past on a throwaway policy copy, confirm the
   verifier correctly excludes that signer and (if it was the only
   surplus signer) correctly fails threshold — proving the revocation
   path works before it is ever needed for real.

Once this checklist is complete for a real second maintainer, PolicyVault
has a genuine multi-signer release process, and this document should be
updated to say so — the architecture supports it today; only the honest
statement of how many real signers currently exist should ever change.

## 10. Future independent signer onboarding (general case)

Section 9 describes the second-signer case concretely; the same
procedure generalizes to a third, fourth, or Nth signer, and to
raising/lowering `threshold` as the maintainer group grows — nothing
about the manifest schema, the SSHSIG mechanism, or the verifier's logic
changes as N grows. This is the concrete meaning of "the architecture
transitions to a real multi-signer threshold WITHOUT changing artifact
semantics": the bytes being signed, the namespace, the hash algorithms,
and the manifest schema version are all independent of signer count.

## 11. Key compromise procedure

If a signer's private key is known or suspected to be compromised:

1. **Immediately** set that signer's `revokedAt` in `release-signers.json`
   to the current time (or the best estimate of the compromise time, if
   earlier evidence exists — revocation should be backdated to the
   earliest time compromise is plausible, never merely to "now," so that
   any release signed after the true compromise time is correctly
   excluded even if discovered late).
2. Commit the policy change immediately — this is the single highest-
   priority edit to this file, ahead of any other pending change.
3. Any release verification run against manifests released after the
   revoked signer's `revokedAt` will now correctly show that signer as
   `SIGNER_REVOKED` and exclude it from the threshold count. Re-run
   verification of the current/most recent release(s) to check whether
   `thresholdMet` still holds with the remaining valid signers — if not,
   treat the current release as UNVERIFIED under the compromised
   period until re-signed by an uncompromised sufficient set of signers.
4. Generate a replacement key for that maintainer following the same
   independent-generation discipline as §9 step 2 (fresh hardware
   assumption if the old key's hardware is itself suspect), and onboard
   it as a **new** signer id (never reuse the old id for a new key — the
   old id's history should stay attributable to the old, compromised
   key only).
5. Investigate and document the compromise (scope, likely cause, whether
   any release was actually mis-signed during the exposure window) —
   this is a security-incident process outside this tooling's scope, but
   this document's existence should make "which releases are affected"
   mechanically answerable by re-running `tools/release-verify.js`
   against historical manifests with the updated policy.

**Compromise of a release signer's key is never a funds-security
incident by itself** — a release signature authenticates authorship of
published bytes, not covenant/funds authority (§1, `SECURITY.md`). It is
a supply-chain-trust incident: users who verify releases need to know
which historical "PASS" results are no longer trustworthy.

## 12. Key revocation (routine, non-compromise)

The same mechanic as §11 step 1 handles routine revocation (a maintainer
steps back, a key is rotated as good hygiene, etc.) — set `revokedAt`,
commit. No urgency discipline is required for a routine, non-compromise
revocation, but the same effect applies: verification of anything signed
after that date by that signer stops counting that signature.

## 13. Signer replacement

Signer replacement is key compromise (§11) or routine revocation (§12)
followed by onboarding (§9's steps 2–4) for the replacement key under a
**new** signer id. There is no separate "replace in place" operation —
replacing a key in place (reusing the same id for different key bytes)
would make historical verification results ambiguous about which
physical key produced them, so this tooling and procedure never do that.

## 14. Maintainer disappearance / succession

If the sole real signer (today: the one maintainer) becomes unavailable
with no prior second-signer onboarding completed:

- **No PolicyVault component — this tooling included — can recover or
  bypass a lost private signing key.** There is no admin bypass, no
  master key, no custodial recovery for the release-signing key, exactly
  as PolicyVault has no such mechanism for covenant funds authority
  (`CLAUDE.md` "No master keys, no admin bypass, no custodial
  recovery"). A lost sole signing key means: no NEW release can be
  verified against the existing `release-signers.json` policy until
  either the key is recovered or the policy is amended by whatever
  governance process the project has established for that situation
  (outside this tooling's scope — it is a project-governance question,
  not a cryptographic one).
- **This is precisely why §9's second-signer onboarding matters as a
  succession safeguard, not merely a security-hardening step.** A
  two-signer, threshold-1 (not threshold-2) policy would let either
  maintainer alone continue releasing if the other disappears, while
  still recording both as legitimate signers; a two-signer, threshold-2
  policy requires both and offers no succession safety by itself unless
  paired with a documented process for lowering the threshold under
  clear, pre-agreed conditions if one signer becomes permanently
  unavailable. **This document does not prescribe which of those
  tradeoffs the project should choose — that is a governance decision
  for the owner and any future co-maintainer(s) to make explicitly** —
  but it records the tradeoff so the decision is made deliberately
  rather than discovered during an actual succession event.
- Historical releases remain verifiable regardless of maintainer
  succession — a manifest and its signatures are immutable artifacts;
  losing the ability to produce NEW valid releases never invalidates
  PAST verification results (unless a compromise, §11, retroactively
  does).

## 15. Compatibility / version policy

- `policyvault-release-manifest/1` and `policyvault-release-signers/1`
  are the current schema versions. Any future breaking change to either
  gets a new version string (`/2`, …) and both the generator and
  verifier are updated together — an old verifier encountering a `/2`
  manifest fails closed with `RELEASE_MANIFEST_UNKNOWN_VERSION`, never
  guesses at a compatible reading (`CLAUDE.md` "Unknown versions FAIL
  CLOSED. Never route unknown versions to a default").
- Namespace `policyvault-release` is fixed for this schema version. A
  future schema version may choose a new namespace if that is ever
  useful (e.g. to make old and new manifests mutually unmistakable at
  the OpenSSH layer too), but that is a deliberate design decision at
  that time, not an accident of this document.
- The manifest's own `covenants[*].label` field is the single place that
  should ever assert "frozen" vs "candidate" for a covenant version in
  release identity — the underlying freeze status itself is governed
  entirely by `CLAUDE.md` and the covenant-specific freeze records, never
  by this tooling.

## 16. Emergency release procedure

An "emergency" release (e.g. a critical fix that cannot wait for the
normal candidate → review → acceptance pipeline) changes **process
speed**, never **verification strength**:

- There is no unsigned emergency release, and no "skip verification this
  once" flag anywhere in `tools/release-verify.js`. An emergency release
  still requires ≥ `threshold` valid signatures from the same
  `release-signers.json` policy as any other release. If today's
  threshold is 1 (§3), an emergency release needs exactly the one real
  signer's signature — the same as normal, not less.
- What legitimately changes under emergency conditions is which of the
  surrounding process steps (extended candidate soak time, additional
  reviewers, staged rollout) are compressed or skipped — those are
  release-ENGINEERING decisions documented elsewhere
  (`docs/production-release.md`, the promotion-readiness packet family)
  and are entirely independent of this track. This document's only
  emergency-relevant rule is: **the signature/threshold bar never moves
  for expediency.**
- If the emergency is itself a key compromise (someone else's signature
  is now suspect), follow §11 first — revoke, then re-sign with a
  verified-good key — rather than lowering the bar to work around a
  signer that should not be trusted.

## 17. Relationship to the rest of the release process

This trust model is an **additive integrity layer**, not a replacement
for anything already governing PolicyVault releases:

- The publication decision (private → public) stays the owner's separate
  hard human gate (§1).
- Production promotion stays the owner's separate explicit gate
  (`docs/production-release.md`, the promotion-readiness packets) —
  building/signing a manifest for a candidate has no bearing on whether
  that candidate is ever promoted.
- Covenant freeze status (which versions are byte-frozen) stays governed
  by `CLAUDE.md` and the covenant-specific freeze/testnet-evidence
  records; this tooling only records the frozen/candidate hashes it
  finds, honestly labeled (§4).
- The webhook-secret rotation procedure
  (`docs/postlaunch/webhook-secret-rotation-procedure.md`) is a
  DIFFERENT secret (an application runtime secret, not a release-signing
  key) with its own document — the two are unrelated except for sharing
  this track's engineering session.

## 18. Never claim "audited"

Repeating `SECURITY.md` and `docs/product-policy.md` for this track
specifically, because it is easy to mis-hear "cryptographically signed
release" as "independently reviewed release": **a PASSing
`tools/release-verify.js` result never means PolicyVault has undergone a
security review, and this track adds no such claim anywhere.** Security
reviews are the internal program (independent AI falsification review)
and are never described as audits.
