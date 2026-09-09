# x402 FACILITATOR — DESIGN FREEZE RECORD

## X402 FACILITATOR DESIGN FREEZE — OWNER AUTHORIZED + COMPLETE (2026-09-02)

**Claim label of the frozen artifact: DESIGNED (frozen).** This record
freezes the DESIGN of the PolicyVault x402 facilitator for the Kaspa
scheme `pv-x402-kaspa-exact-upfront/1`. It makes no claim that anything
is IMPLEMENTED, UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED,
PRODUCTION-HARDENED, or HUMAN-ACCEPTED; those labels are
tracked, step by step, in `x402-facilitator-program.md` (D3–D6). No production
deployment of a hosted facilitator is authorized by this record.

## 1. Authorization chain (exact)

1. Owner directive 2026-09-02 ("PUBLIC v1.5.0 RELEASE + x402 DESIGN-FREEZE
   CHECKPOINT" §3–§14): D1/D2 design-freeze checkpoint → spec revision 2 +
   `x402-facilitator-freeze-readiness.md` (verdict X402-DESIGN-FREEZE-READY;
   open items OQ-F1…F7).
2. Owner directive 2026-09-02 (third): accepted the D1/D2 review verdict;
   authorized the freeze of the revision-2 architecture subject to
   decisions A–G; rule: if ANY OQ-F item does not correspond cleanly to
   those decisions, STOP before implementation and report only that
   discrepancy. OQ-F1/F2/F4/F5/F6 mapped cleanly (A, B, G, E+F, C); OQ-F3
   and OQ-F7 were NOT covered → STOPPED (main `e2a965b`).
3. Owner decision 2026-09-02 ("RESOLVE x402 OQ-F3 + OQ-F7 AND CONTINUE
   D3–D6"): resolved OQ-F3 (network identifiers) and OQ-F7 (inbound
   authentication) as recorded below; directed the freeze record, the
   identity pins, the anti-drift guard re-run, and autonomous D3–D6 to the
   stop condition X402-FACILITATOR-PRODUCTION-READY /
   X402-FACILITATOR-NOT-PRODUCTION-READY, without further design
   decisions.

## 2. OQ-F1…F7 — ALL RESOLVED

| item | owner decision | frozen in |
|---|---|---|
| OQ-F1 `MIN_DEPTH_DAA` | **A** — default 100; HARD FLOOR 20 (20 is never described as the target); policy `pv-x402-settlement/1` is versioned; DAGKNIGHT / finality changes = a new policy version, PolicyVault authorization semantics untouched | spec §6 |
| OQ-F2 `MAX_WINDOW_DAA` | **B** — 36,000; an inclusion outside the window fails closed | spec §6 |
| OQ-F3 network identifiers | **`kaspa:mainnet`** (mainnet) and **`kaspa:testnet-10`** (testnet-10) — PolicyVault's PROVISIONAL Kaspa network identifiers in CAIP-2 syntax / profile form; the Kaspa namespace is NOT claimed to be upstream-registered unless/until that registration exists; `/1` emits, accepts, advertises (`/supported`) and digest-binds exactly these strings, rejects unknown references, independently verifies the node's actual network identity (testnet-10 by explicit netsuffix — no testnet is equivalent to another), fails closed on disagreement; the string alone is never chain evidence; different future official identifiers arrive only as an explicit successor profile / version or a separately reviewed compatibility mapping, never as a transparent alias | spec §2.1, §3 |
| OQ-F4 asset literal | **G** — `KAS` (native, sompi) or `pvad1:<descriptor-hash>` (a frozen v0.5 `policyvault-asset-descriptor/1` hash from the facilitator's CONFIGURED descriptors only; no blessed list; unknown fails closed) | spec §2.2, §3, §7.2 |
| OQ-F5 store class / hosted operation | **E + F + §12** — ONE instance; PostgreSQL unique-constraint claim storage before any horizontal scaling; durable claim storage wherever `/settle` is served; production / hosted deployment = a separate explicit owner gate | spec §9, §14 |
| OQ-F6 payload binding | **C + §1** — NOT part of `/1`; the mandatory per-requirement unique destination + DAA window + explicit outpoint IS the binding of `/1`; payload binding is a future scheme version | spec §5.7 |
| OQ-F7 inbound authentication | **FACILITATOR-ISSUED API KEY OVER HTTPS** for v1; mTLS NOT required (optional future deployment hardening, not a `/1` interoperability requirement; if ever introduced, bound to the same principal model — never a second authority system; no dual API-key-or-mTLS surface in D3); `GET /supported` PUBLIC, `POST /verify` and `POST /settle` AUTHENTICATED RESOURCE SERVER REQUIRED, no anonymous verify/settle in hosted production; dedicated credential model (never PolicyVault sessions / `pvmk_` machine credentials / wallet signatures / payer or signer credentials); ≥ 256-bit CSPRNG credentials shown only at creation, never persisted plaintext / logged / placed in URLs / returned by list-read APIs, strong verifier + metadata only, constant-time comparison; principal record with id, verifier, status, createdAt, optional expiry, allowed operations (`verify`, `settle`), allowed networks, allowed payTo destinations, optional resource-origin constraints; authority facilitator-local only; requirement binding still verified in full (digest, resourceUrl, network, scheme, asset, amount, payTo, window, policy, outpoint evidence, replay state); principal-owned payTo enforced with a mandatory cross-principal negative test; 401 with zero node acceptance / zero claim mutation / zero replay consumption / zero evidence / zero anonymous downgrade; 403 `SCOPE_FORBIDDEN`-equivalent without revealing other principals' ownership; creation / revocation / rotation with overlap, revocation immediate, rotation never alters payment authority or covenant state; per-principal rate limits as availability protection only | spec §12 (boundary 1), §13 AUTH class, §14, §14.1 |

## 3. Frozen identities (pinned by `integrations/test/x402f-design-freeze.test.js`)

| artifact | identity |
|---|---|
| design spec (revision 3) `docs/postlaunch/x402-facilitator-spec.md` | sha256 `f027a0547042b36f686beb6186ae1e910a4b55f5bde142174b873234ab47fb3b` |
| this record (sections 1–7; the pin test hashes the file as committed at the freeze) | sha256 recorded in the pin test at the freeze commit |
| scheme / version | `exact` · `extra.paymentFlow: "upfront"` · `extra.kaspaScheme: "pv-x402-kaspa-exact-upfront/1"` · `x402Version` 2 |
| settlement policy | `pv-x402-settlement/1` · `MIN_DEPTH_DAA` default 100 · hard floor 20 · `MAX_WINDOW_DAA` 36,000 |
| network identifiers | `kaspa:mainnet` ↔ kaspad `mainnet`; `kaspa:testnet-10` ↔ kaspad `testnet-10` (PROVISIONAL CAIP-2-syntax identifiers) |
| assets | `KAS` · `pvad1:<64-hex descriptor hash>` |
| evidence schema | `policyvault-x402-facilitator-evidence/1` |
| requirement digest domain | `policyvault-x402-facilitator-requirement/1` |
| evidence digest domain | `policyvault-x402-facilitator-evidence/1` |
| credential format | `pvx402f_` + 64 lowercase hex; verifier `sha256_hex(raw)` |
| reason codes | spec §13: 5 RETRY · 2 PENDING · 24 REFUSE · 4 AUTH (`CREDENTIAL_REQUIRED`, `CREDENTIAL_INVALID`, `SCOPE_FORBIDDEN`, `PRINCIPAL_FORBIDDEN`) — closed set |
| v0.5 covenant (unchanged, re-verified at this freeze) | `contracts/PolicyVault.v0.5.sil` sha256 `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9` |

## 4. Freeze rules

- The frozen semantics of `pv-x402-kaspa-exact-upfront/1`,
  `pv-x402-settlement/1`, the network identifiers, the closed schemas,
  the reason codes, the binding / replay rules and the evidence schema
  change ONLY through (a) a NEW additive version / profile / policy id, or
  (b) the owner's explicit freeze-reopen decision (source review →
  compatibility → hostile regression → live proof → owner decision, per
  the roadmap addendum's freeze-reopen rule). In-place edits of the spec
  that alter semantics are prohibited; editorial corrections that do not
  alter semantics require re-pinning the spec sha in the pin test with a
  commit that says so.
- Unknown versions, policies, networks, assets, owner schemes, template
  variants and capability combinations FAIL CLOSED — never a default.
- A Kaspa consensus change to a relied-upon property (UTXO-entry
  `covenantId`, `blockDaaScore`, DAA semantics, txid commitment scope,
  P2SH envelope, standardness) REOPENS this freeze per the Kaspa Protocol
  Evolution Compatibility program.

## 5. Binding boundaries carried into D3–D6 (all prior boundaries remain binding)

No signing · no broadcast authority · no custody · no escrow · no user
private keys · no PolicyVault financial credential of any kind · the
external signer retains custody · deterministic verification only ·
frozen v0.5 token semantics (never a parallel token model) · no covenant
change · no production / hosted deployment without a separate explicit
owner authorization · no DEX / swap work (the DEX / Swap Adapter Framework
remains AFTER x402) · MCP and x402 stay separate · free forever (the
facilitator never charges and PolicyVault never emits a `402`).

## 6. Anti-drift / freeze guard (what "re-run the guard" means)

1. `integrations/test/x402f-design-freeze.test.js` — spec sha, record sha,
   frozen constants in code (`integrations/x402-facilitator/constants.js`)
   equal to this record.
2. `sdk/test/covenant-freeze-v5.test.js` — v0.5 bytes, generator identity
   + byte-identical regeneration, vendored KCC20 identity.
3. `core/crossruntime/test/bundle-anti-drift.test.js` — the committed
   browser core bundle equals a fresh regeneration (no drift in the shared
   deterministic core the facilitator reuses).
4. `integrations/test/dependency-direction.test.js` — the facilitator's
   import allowlist (core, `integrations/lib`, `sdk/src/chain.js`,
   `sdk/src/tx-identity.js` only; never signer / builder / store / server
   / mutation modules; core / sdk / server / web / mcp never import it).

## 7. What this freeze does NOT do

It does not implement anything; it does not change `contracts/`,
`server/`, `web/`, `mcp/`, migrations, production configuration, the
published packages, or the public repository; it does not authorize a
hosted facilitator; it does not claim ecosystem ("x402-compatible")
status — no upstream Kaspa scheme exists and the facilitator interoperates
only with resource servers configured for the proposed scheme (adapter
spec §6.5 stays OPEN).
