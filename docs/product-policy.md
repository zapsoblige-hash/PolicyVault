# PolicyVault Product Policy (PERMANENT — authoritative)

Originally decided by the project owner, 2026-08-16. Funding wording was
updated by the owner's 2026-09-15 copy relay and hosted-access decision
OWNER-20260914-HOSTED-ACCESS-01 revision 2. The current funding explanation
below replaces earlier blanket unlimited-free-hosted commitments; software,
covenant functionality, self-hosting and owner control remain free.

## Free software and self-hosting — including commercial use

PolicyVault’s software and self-hosting are free under Apache 2.0, including
commercial use. Official hosted access is currently free. Kaspa network
transaction fees still apply. There is no separate paid commercial-use
license. Security and owner control never become paid boundaries.

Priorities, in order: (1) adoption, (2) interoperability, (3) security,
(4) neutrality as infrastructure, (5) becoming a broadly used Kaspa
delegated-spending standard. Growth and standardization take priority
over revenue extraction.

**Permanent decision rule:** if a monetization mechanism makes PolicyVault
harder to adopt, harder to integrate, less neutral, or less trustworthy
as shared Kaspa infrastructure, PolicyVault does not use that mechanism.

### Software and covenant protections

The software, self-hosting and covenant functionality retain these
protections: no subscriptions, PolicyVault transaction fees, developer fees,
percentage-of-funds fees, paid commercial licenses, paid feature gates,
paid security features, premium policy limits, paid API access for ordinary
self-hosted use, artificial usage limits intended to force payment,
one-time quality-of-life purchases or intentionally degraded free versions.
Official hosted access follows the separately stated current and deferred
policy; it does not change these software and covenant protections.

**Security must NEVER become a monetization boundary.** A user who pays
nothing receives the full normal security model and functionality.

Development may be supported voluntarily through KAS donations,
sponsorships, grants and community support. Donations do not unlock
features, increase limits, improve security or alter access. Billing stays
outside covenant enforcement and frozen contracts; payment never bypasses
protective limits or signing requirements.

All implementation specific to the approved future hosted-access model
remains deferred until full completion of the approved roadmap. This copy
introduces no billing, telemetry, quotas or enforcement and announces no
capacity price or availability. Earlier conflicting hosted-access wording
does not override that owner decision.

## Voluntary KAS donations

> **Support PolicyVault**
>
> PolicyVault’s software and self-hosting are free under Apache 2.0.
> Official hosted access is currently free. Voluntary KAS donations support
> continued development and hosting. Kaspa network transaction fees still apply.
>
> KAS: `kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn`
>
> Donations do not unlock features, increase limits, improve security, or
> alter access.

The donation address is PUBLIC receiving information only. PolicyVault
never requests or stores a seed phrase, private key, wallet backup, or
signing secret, and adds no wallet-signing logic for the donation wallet.
No donation nagging or dark patterns.

## No patents

PolicyVault will not seek patents over its protocol, covenant
architecture, delegated-spending mechanisms, approval mechanisms,
recipient authorization, fee-reserve mechanism, multi-delegate / AI-agent
authorization mechanism, SDK, or other core technology, and will not use
patents to restrict implementation, interoperability, competition, or
commercial use. This is consistent with the free-forever / free-commercial
/ open-infrastructure / voluntary-support policy above. Trademark
protection for the PolicyVault name/logo is distinct and permitted.

## License (SELECTED: Apache-2.0, owner decision 2026-08-23)

The owner selected the **Apache License 2.0** at the clean-public-release
preparation checkpoint (2026-08-23), chosen deliberately for its express
patent grant — the legal counterpart of the no-patents commitment above.
The public release tree (`~/policyvault-public`) carries `LICENSE` +
`NOTICE`. **Permanent constraint (unchanged): the license permits free
commercial use, and there will never be a separate paid commercial
license.** Never substitute a different license.

## Privacy / publication (private until explicitly authorized)

PolicyVault MUST REMAIN PRIVATE during development. The project owner has
NOT authorized public release. Until explicit future authorization, do
NOT: create a public GitHub repository; push to a public remote; publish
source, covenant source, or detailed architecture/specs; publish testnet
evidence; announce security architecture; create public packages/
releases; start a public audit contest; or publish documentation
externally.

Local git commits are allowed. A private remote/backup may be used only
if explicitly authorized separately.

Intended future sequence (release policy UPDATED by the owner,
2026-08-17): feature complete → security hardened → deployment complete →
internal production-readiness gates pass → **owner authorizes publication**
(privacy gate, unchanged) → **explicit owner mainnet authorization** (hard
human gate, unchanged) → production mainnet launch. Security assurance at
every step is the internal program (independent AI falsification review,
hostile testing, permanent regressions, frozen-byte verification, owner
human live-workflow acceptance); no external security audit is part of the
sequence at any stage (owner policy, 2026-09-05). The
privacy purpose is unchanged: prevent premature disclosure while
PolicyVault is still being built; the project stays PRIVATE until the
owner explicitly authorizes publication.
