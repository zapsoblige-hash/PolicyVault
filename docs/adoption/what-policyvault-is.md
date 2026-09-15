# What PolicyVault is

PolicyVault is a **non-custodial Kaspa L1 treasury** with
**covenant-enforced delegated spending controls**.

An owner (a person, a business, an organization) holds Kaspa (KAS) in a
vault. The owner can hand a **delegate** — an employee, a service
account, a bot, an AI agent — a legitimate spending key **without**
giving up control of the funds. The delegate can only spend inside the
policy the owner configured:

- a maximum amount per transaction;
- a cumulative budget over a recurring period;
- a fixed list of allowed recipient addresses;
- (optionally) a requirement that spends above a threshold collect
  approvals from a set of approvers before they can execute.

These rules are not enforced by PolicyVault's servers, its API, or its
web app. They are enforced by **Kaspa consensus itself**, through a
SilverScript covenant compiled into the vault's own on-chain script. A
delegate who has the legitimate spending key and bypasses PolicyVault
entirely — hand-building a transaction and submitting it straight to a
Kaspa node — still cannot violate the policy. The node itself rejects the
attempt.

The owner can also pause the vault, or recover all funds to their own
key, at any time (owner recovery is terminal — see
`not-a-wallet.md`).

## Who this is for

- **Individuals and businesses** who want to delegate day-to-day KAS
  spending (payroll, vendor payments, a support desk) without handing
  out an unrestricted wallet key.
- **AI agents and automated services** that need bounded spending
  authority — a budget and an allowlist they structurally cannot exceed,
  even if the agent misbehaves or is compromised.
- **Developers** integrating delegated Kaspa payments into an
  application, an MCP-connected AI agent, or an x402-style
  pay-per-request service.

## What PolicyVault is not

- **Not a custodian.** PolicyVault never holds a private key capable of
  moving funds. See `not-a-wallet.md`.
- **Not a DEX.** PolicyVault authorizes and verifies intent
  deterministically; it does not run pools, order books, or its own
  liquidity, and it is never the signer.
- **Security assurance is internal** (independent AI falsification review,
  hostile testing, permanent regressions); never described as an audit. See
  `not-a-wallet.md` and `SECURITY.md` for the exact security boundary and
  claim discipline.

## Free software and self-hosting

Free software and self-hosting — Apache 2.0, including commercial use.
Official hosted access is currently free. Kaspa network transaction fees
still apply. Security is never a monetization boundary. Voluntary KAS
donations support continued development and hosting:

```
kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn
```

Donations do not unlock features, increase limits, improve security, or
alter access. See `docs/product-policy.md` for the full permanent policy.

## Where to go next

- `not-a-wallet.md` — the architecture and the four-line authority
  statement.
- `quickstart-kas-delegated-payment.md` — try it in the live web app.
- `quickstart-mcp-agent.md` — connect an AI agent over MCP.
- `README.md` (this directory) — the full index with status labels.
