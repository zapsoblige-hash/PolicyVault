# Quickstart: a delegated KAS payment (~5 minutes)

**Status: LIVE.** This walks through the hosted web app running the
v0.4.1 KAS profile (single on-chain owner key; multiple independent
agents/delegates; recipient allowlist; optional approver quorum), using
the [KasWare](https://www.kasware.xyz/) browser wallet. Every step below
matches what exists today in `web/index.html` / `web/app.js` /
`web/app-v4.js` — nothing here is aspirational. Mainnet moves real KAS;
if you are new, do this on testnet-10 first.

You will need: the KasWare browser extension installed, and a small
amount of KAS/tKAS in that wallet to fund a vault and pay network fees.

## 1. Connect your wallet

Open the app. In the **Wallet** panel, click **Connect KasWare**. KasWare
prompts you to approve the connection. Once connected, the panel shows
your provider, account, and the network your wallet is on.

The banner at the top of the page shows the app's own network identity,
derived from the configured Kaspa node's live status (never assumed) —
confirm it matches the network you intend to use before funding anything.

## 2. Create a vault

Select the **Create Vault** tab. The form asks for:

- **Vault name** — a label, application data only.
- **Deposit (KAS)** — the amount that becomes the vault's protected
  principal.
- **Fee reserve (KAS)** — an optional pool that pays permitted agent
  transaction fees without reducing protected principal.
- **Owner** — your connected wallet, shown read-only. The form states
  plainly: *"This wallet becomes the vault's only owner key. There is no
  second owner, no owner quorum, and no organizational owner."* (See
  `not-a-wallet.md` and `organizational-root-walkthrough.md` for what
  would change that.)
- **Initial agent — wallet address** — the delegate's Kaspa address.
- **Maximum per transaction (KAS)** — the agent's per-spend cap,
  enforced by the covenant.
- **Budget per period (KAS)** and **reset interval** — the agent's
  cumulative budget over a recurring window, tracked by the covenant
  using Kaspa consensus time (DAA score), so wall-clock duration is
  approximate.
- **Require approval above (KAS)** — spends at or below this amount the
  agent can sign alone; above it, the approval policy below applies.
- **Allowed recipients** — one or more Kaspa addresses. The agent may
  only pay addresses on this list, enforced by the covenant.
- **Approval policy (optional)** — a set of approver addresses and a
  required-approvals count (M-of-N). Leave empty for an agent-only
  vault.
- **Advanced → Maximum network fee per transaction** — optional; the
  form provides a safe default.

Click **Review vault…**. The app shows the exact transaction it built —
review it, then your wallet (KasWare) prompts you to sign the funding
transaction. Signing is the only step that can move funds; nothing
before it does.

## 3. Watch it confirm

After signing, the app tracks the request through its states —
`BUILT → SUBMITTED → CONFIRMED` (or a specific failure). **A submitted
transaction is not a confirmed one:** PolicyVault waits for the vault's
successor state to actually appear on-chain before treating the vault as
live. Once confirmed, the vault appears under the **Vaults** tab with
its live on-chain state (protected value, fee reserve, agent policy).

## 4. Send a delegated spend

Open the vault and use the agent's **Spend** action. The spend form asks
for:

- **To** — a Kaspa address. It must resolve to an address on the vault's
  allowlist; the app derives the exact public-key representation the
  covenant needs from the address you type.
- **Amount (KAS)** — must be within the agent's per-transaction cap and
  remaining period budget.

Submit, review the built transaction, and sign with the agent's own
wallet (this can be the same KasWare session, or a separate delegate
wallet, depending on who holds the delegate key). If the amount exceeds
the approval threshold, the request instead enters
**AWAITING_APPROVALS** and waits for the configured approvers to sign
before the agent can complete it.

## 5. Try to break it (optional, and instructive)

Everything above is enforced twice: once by PolicyVault's own
pre-signing checks, and — the part that actually matters — by the Kaspa
covenant itself. To see the second layer directly, without any UI:
`developer-integration-example.md` runs an offline SDK example that
attempts to redirect a policy-valid payment to a non-allowlisted
recipient and shows the deterministic refusal, before any signature is
ever requested.

## What is not yet live

- **Organizations** (visible as a tab in the app) are a **hosted, purely
  application-level grouping/label** for vaults today — they grant no
  on-chain multi-owner authority. See
  `organizational-root-walkthrough.md` for the distinction, and for the
  v0.7 on-chain organizational root, which is a testnet-verified
  candidate, not yet part of the hosted app.
- **Tokens** (the v0.5 covenant profile) and the **v0.6 swap profile**
  have no hosted/web surface yet — KAS (v0.4.1) is the only profile the
  web app exposes today.
