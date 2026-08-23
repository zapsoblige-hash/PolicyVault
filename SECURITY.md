# PolicyVault Security

## Security model

Kaspa L1 consensus is the security boundary. Every rule PolicyVault
advertises as covenant-enforced (owner/agent identity, per-spend caps,
periodic budgets, recipient allowlists, approval thresholds, fee-reserve
caps, exact value conservation, exact successor state, owner-only
recovery) holds against a malicious actor who possesses a legitimate agent
key and submits hand-crafted transactions directly to a Kaspa node,
bypassing this application entirely.

The backend, frontend, SDK, and API are **not** security boundaries: the
browser is untrusted presentation, every security-relevant validation is
repeated server-side, and the server holds no keys and cannot move funds.

## Key handling

- PolicyVault never requests, stores, or transmits seed phrases, private
  keys, or recovery material. Signing happens exclusively in the user's
  own wallet (KasWare) against frozen transaction bytes.
- The transaction pipeline freezes exact bytes before signing; the signed
  transaction's id must equal the frozen id, immutability is re-verified at
  finalization, and success is claimed only after exact on-chain proof
  (old state consumed, expected successor observed).
- Mainnet operation requires a deliberate multi-flag opt-in
  (`KASPA_NETWORK_ID=mainnet`, `POLICYVAULT_ALLOW_MAINNET=true`, explicit
  `KASPA_RPC_URL`), keeps a separate network-stamped data root, and
  refuses to start with any development or test hook enabled.

## Verification status (honest labels)

- **Internally adversarially tested** — extensive hostile suites at every
  layer: real-VM covenant execution and negative-validation matrices,
  production-byte encoder integration, SDK/API/browser hostile tests,
  sabotage sensitivity (guard-neutralization) suites, crash/concurrency/
  reconciliation matrices.
- **Real testnet lifecycle verified** — full vault lifecycles
  chain-verified on testnet-10, including authorized testnet
  negative-validation transactions constructed independently of the
  application, verifying that consensus rejects policy-invalid
  transactions even when correctly signed by the designated agent.
- **Real KasWare verified** — full owner/agent/approver browser-wallet
  lifecycles on testnet-10.
- **Limited real-value mainnet smoke verified** — vault creation, an
  agent spend under policy with reserve-funded fees, exact-accounting
  verification, and terminal owner recovery, all chain-verified on
  mainnet with real wallets and small values.

PolicyVault has **not yet undergone an independent professional security
audit**, and no such audit is claimed. An external review is planned.
Begin with conservative values and increase them gradually.

## Deployment posture

The supported deployment is local / self-hosted, single-operator,
loopback-only. The API is same-origin with a strict CSP, refuses
cross-origin browser writes, and never serves stale application builds.
Do not expose the loopback server to the public internet; an
internet-hosted multi-user deployment has not been reviewed and is not
supported by this release.

## Reporting a vulnerability

Email **zapsoblige@gmail.com**.

- Describe the issue, reproduction steps, and impact.
- Never include seed phrases, private keys, wallet backups, or recovery
  material — PolicyVault support will never ask for them.
- Good-faith reports are welcome; there is no bug-bounty program at this
  time, but reports are taken seriously and remediated openly.
