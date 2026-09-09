# First-user feedback template

**Status: TEMPLATE — no outside-user feedback has been collected yet**
(`docs/postlaunch/flagship-readiness-matrix.md` row U:
outside-user/adoption evidence is `ABSENT`). Use this template to record
real feedback as it comes in; do not pre-fill it with imagined answers.

Copy the block below per session/user, fill it in honestly (including
"I don't know" and "N/A"), and keep it verbatim — do not summarize away
a negative finding. If a session used the MCP usage telemetry described
in `adoption-metrics-spec.md`, note only that it was on/off; never paste
raw telemetry rows into this file (they are operational aggregates, not
a feedback record).

---

## Session record

- **Date:**
- **Channel:** web app / MCP agent / x402 pilot / self-hosted / other
  (say which)
- **User type:** individual / business / AI-agent developer / other
- **Network:** testnet-10 / mainnet
- **PolicyVault build/version used:**

## What they were trying to do

(One or two sentences, in their words if possible.)

## What happened

- Did they succeed? (yes / no / partially)
- Where, exactly, did it break down or confuse them? (a specific step —
  "Create Vault form", "KasWare signing prompt", "MCP tool discovery",
  "reading the review before signing", etc.)
- Any error code or refusal they hit — record it exactly (e.g.
  `RECIPIENT_PROOF_INVALID`, `GOVERNANCE_PROPOSAL_REQUIRED`) rather than
  paraphrasing it.

## Did they understand the security model?

- Did they understand that PolicyVault itself never holds a key that
  can move funds (`not-a-wallet.md`)?
- Did they understand what the covenant enforces vs. what PolicyVault's
  application layer merely proposes?
- If they were confused, what specifically confused them? (This is the
  single most valuable thing to capture accurately — do not soften it.)

## What they said, verbatim

(Direct quotes only. Do not paraphrase a criticism into something
softer.)

## Severity / disposition

- [ ] Blocking — they could not complete their goal
- [ ] Confusing but recoverable — they got there, with friction
- [ ] Cosmetic — worked, but they'd expect it to look/read differently
- [ ] Positive — worked as intended, noted for reference

## Follow-up

- Filed as: (issue / doc fix / not actioned yet — say which, and why if
  "not actioned yet")
- Related file(s) touched, if any:

---

## Honesty rules for whoever fills this in

- Never invent a user, a quote, or a session that didn't happen. An
  empty file is more truthful than a fabricated one.
- Never edit a recorded quote to make PolicyVault look better.
- If feedback conflicts with a claim elsewhere in `docs/adoption/` or
  the readiness matrix, flag the conflict — do not quietly resolve it in
  PolicyVault's favor.
