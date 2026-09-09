# PolicyVault adoption documentation

Prepared for the first real outside user (Track J, FLAGSHIP WAVE 2).
Every claim below uses the readiness-matrix vocabulary (ABSENT ·
DESIGNED · IMPLEMENTED · UNIT-TESTED · ADVERSARIAL-TESTED · VM-VERIFIED ·
INTEGRATION-VERIFIED · TESTNET-VERIFIED · PRODUCTION-READY · DEPLOYED ·
HUMAN-ACCEPTED — see
`docs/postlaunch/flagship-readiness-matrix.md`). No external security
review has occurred anywhere in PolicyVault; none is claimed.

| file | what it covers | status |
|---|---|---|
| `what-policyvault-is.md` | one-page product explanation | LIVE product, DEPLOYED |
| `not-a-wallet.md` | architecture + the four-line authority statement | LIVE product, DEPLOYED |
| `quickstart-kas-delegated-payment.md` | 5-minute KAS delegated payment in the hosted web app (v0.4.1, KasWare) | LIVE, DEPLOYED · HUMAN-ACCEPTED |
| `quickstart-mcp-agent.md` | connecting an AI agent over MCP | LIVE, DEPLOYED (npm `policyvault-mcp@1.4.2` + MCP Registry) |
| `quickstart-x402.md` | x402 facilitator integration | code PRODUCTION-READY (pilot packet); **NOT DEPLOYED, NO DNS** — owner gate |
| `organizational-root-walkthrough.md` | v0.7 on-chain organizational M-of-N owner root, vs. today's hosted-only "Organizations" | v0.7 covenant: TESTNET-VERIFIED CANDIDATE, byte-freeze **owner-pending**; hosted UI for it: **ABSENT** (not this wave's scope) |
| `quickstart-selfhost.md` | self-hosting, equal security to hosted | IMPLEMENTED · INTEGRATION-VERIFIED, outsider re-tested 22/22 |
| `developer-integration-example.md` | the authority-boundary SDK example, walked through | RUNNABLE TODAY — `sdk/examples/adoption-authority-boundary.js` + `sdk/test/adoption-example.test.js`, 5/5 passing |
| `adoption-metrics-spec.md` | what MCP usage telemetry does/doesn't collect | IMPLEMENTED · UNIT-TESTED; **OFF by default, not enabled anywhere** |
| `first-user-feedback-template.md` | template for recording real outside-user feedback | TEMPLATE ONLY — no feedback recorded yet (`ABSENT`) |

## What "prepared for the first outside user" does and doesn't mean

This documentation set is new and has not itself been read by an actual
first-time outside user yet — it is the *preparation* for that, not
evidence that it succeeds. Use
`first-user-feedback-template.md` to record what really happens the
first time someone outside the project reads it.

## Policy this documentation follows (do not restate elsewhere; link here)

- **Free forever, including commercial use.** No subscriptions, fees,
  paid tiers, or artificial caps; security is never a monetization
  boundary. Voluntary KAS donations only:
  `kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn`.
  See `docs/product-policy.md`.
- This documentation set claims nothing about certification or
  regulatory status; security reviews are internal AI falsification
  reviews and are labeled as such, never as audits (see the standing claim-discipline rules in `CLAUDE.md` and
  `docs/postlaunch/flagship-development-program.md` §5); nothing about
  decentralization or anonymity properties PolicyVault has not
  demonstrated; and no comparative superlative about PolicyVault versus
  any alternative.
- Never market v0.6's fixture venue as a real, named external exchange
  venue, and never present a single-owner profile (v0.4.1 / v0.5 / v0.6)
  as organizational multi-owner security.
- `sdk/test/adoption-docs-truthfulness.test.js` mechanically scans every
  file in this directory for the forbidden phrases above (case-
  insensitive) and requires the exact four-line authority statement to
  appear in `not-a-wallet.md`. It passes as of this commit; keep it
  passing.

## If something here turns out to be wrong

File-and-fix, the same as any other documentation defect: correct the
specific file, keep the status label honest (moving a claim backward,
e.g. from LIVE to DESIGN TARGET, is always acceptable; moving one
forward requires the same evidence discipline as the rest of the
project), and note the correction in the commit message.
