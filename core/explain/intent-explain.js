"use strict";

/*
 * PolicyVault Transaction Intent Manifest — EXPLANATIONS (v1).
 *
 * Turns a VERIFIED v1 Transaction Intent Manifest plus its verification
 * result into:
 *
 *   structured({ manifest, verification })
 *     -> a stable, versioned, JSON-safe explanation document
 *        ("policyvault-intent-explanation/1") for APIs and agent
 *        workflows;
 *
 *   humanReadable({ manifest, verification })
 *     -> deterministic English lines a signer UI shows BEFORE signing.
 *
 * BINDING RULES (fail closed, no default route):
 *   - Explanations are derived ONLY from the verified manifest — never
 *     from unverified request data. The manifest is independently
 *     re-validated here (schema + hash), the supplied verification
 *     result must BIND to this exact manifest (same manifestHash and
 *     txId) and be a full pass, AND the manifest is independently
 *     RE-VERIFIED in-process through core/intent verifyIntentManifest.
 *     A fabricated { ok: true } verification object therefore cannot
 *     make an unverified manifest render normally.
 *   - Any manifest whose verification is not a full pass produces a
 *     prominent REFUSAL explanation listing the detector codes — never
 *     a normal rendering, and never any amount/recipient/state block.
 *   - Unknown manifest/intent/covenant versions and unknown actions
 *     refuse (the underlying validator's own codes are surfaced).
 *   - NO truncation of addresses/amounts that could hide a
 *     substitution: every key, root, id, and amount is rendered IN
 *     FULL. (A UI may add a shortened display form ONLY alongside the
 *     full value; this module never emits a shortened form.)
 *   - Identity note: the manifest's canonical identities are x-only
 *     public keys (never addresses); lines render the full 64-hex key.
 *     A UI layer that owns the address codec may append the bech32
 *     address form alongside — the key remains the verified value.
 *
 * Both entry points are TOTAL: they never throw. Malformed inputs and
 * internal errors produce a REFUSAL explanation (an error is never a
 * pass, and a signer UI always gets something safe to display).
 *
 * Portable shared core: pure CommonJS, zero external dependencies, no
 * SDK/server imports; the only module dependencies are the public
 * exports of core/intent and the local KAS renderer.
 */

const { validateManifest, verifyIntentManifest, VERIFIED_STATEMENT } = require("../intent");
const { kasAmount, sompiToKasString } = require("./kas");

const INTENT_EXPLANATION_VERSION_1 = "policyvault-intent-explanation/1";

// Failure/warning details are untrusted text (they originate from server- or
// manifest-supplied strings). When interpolated into a rendered line they
// must NOT be able to forge a structural or verdict line: a crafted detail
// carrying newlines could otherwise inject a fake "Verification: PASSED" into
// a DO-NOT-SIGN rendering, or false Fee/Payment lines into a VERIFIED one, and
// bidi/RTL controls could visually reorder the display. Collapse every control
// and bidi-override character to a single space and cap the length. The
// STRUCTURED output keeps the raw detail (it is data, not a rendered line);
// only line rendering is sanitized. (Hostile-AI review H-1.)
function sanitizeDetail(value) {
  let s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    // C0/C1 controls (incl. newline/CR/tab) and bidi overrides -> single space
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += (isControl || isBidi) ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? out.slice(0, 497) + "..." : out;
}

const EXPLANATION_VERDICTS = Object.freeze({
  VERIFIED_EXACT: "VERIFIED_EXACT",
  REFUSED: "REFUSED"
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function isHex32(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function failureEntry(code, detail) {
  return { code: String(code), detail: String(detail) };
}

/* The closed top-level key set of every explanation document — identical
 * for both verdicts (refusals carry null rendering blocks), so API
 * consumers get ONE stable shape. */
function baseDocument() {
  return {
    explanationVersion: INTENT_EXPLANATION_VERSION_1,
    verdict: null,
    statement: null,
    refusal: null,
    context: null,
    manifestHash: null,
    txId: null,
    network: null,
    vault: null,
    action: null,
    actor: null,
    fee: null,
    outputs: null,
    payment: null,
    accounting: null,
    balances: null,
    policyChanges: null,
    policyNonce: null,
    approvals: null,
    limits: null,
    warnings: null,
    verification: null
  };
}

/*
 * REFUSAL document. `failures` is [{code, detail}]; `context` (optional)
 * is the minimal identity block extractable from a manifest that at
 * least VALIDATED structurally — explicitly labeled unverified, and the
 * only manifest-derived content a refusal may carry. No amounts, no
 * recipients, no state: unverified values are never rendered.
 */
function refusalDocument({ reason, failures, context = null, manifestHash = null, txId = null, verificationSummary = null }) {
  const codes = [...new Set(failures.map((f) => f.code))].sort();
  const doc = baseDocument();
  doc.verdict = EXPLANATION_VERDICTS.REFUSED;
  doc.refusal = {
    reason: String(reason),
    codes,
    failures: failures.map((f) => failureEntry(f.code, f.detail))
  };
  doc.context = context;
  doc.manifestHash = manifestHash;
  doc.txId = txId;
  doc.verification = verificationSummary;
  return deepFreeze(doc);
}

/* Strict shape check of a caller-supplied verification result (the
 * deep-frozen object produced by core/intent verifyIntentManifest).
 * Returns null when valid, else the refusal detail string. */
function verificationShapeProblem(verification) {
  if (!isPlainObject(verification) && !(verification && typeof verification === "object" && !Array.isArray(verification))) {
    return "verification result must be the object returned by verifyIntentManifest";
  }
  if (typeof verification.ok !== "boolean") return "verification.ok must be a boolean";
  if (verification.verdict !== "VERIFIED_EXACT" && verification.verdict !== "REFUSED") {
    return `verification.verdict ${JSON.stringify(verification.verdict)} is unknown — failing closed`;
  }
  if (!Array.isArray(verification.checks)) return "verification.checks must be an array";
  for (const c of verification.checks) {
    if (!c || typeof c.id !== "string" || typeof c.ok !== "boolean" || !Array.isArray(c.failures)) {
      return "verification.checks entries must be { id, ok, failures[] }";
    }
  }
  if (!Array.isArray(verification.failures)) return "verification.failures must be an array";
  for (const f of verification.failures) {
    if (!f || typeof f.code !== "string") return "verification.failures entries must carry a code";
  }
  if (verification.ok === true) {
    if (verification.verdict !== "VERIFIED_EXACT") return "verification.ok=true requires verdict VERIFIED_EXACT";
    if (verification.statement !== VERIFIED_STATEMENT) return "verification.statement is not the canonical verified statement";
    if (!isHex32(verification.manifestHash)) return "verification.manifestHash must be 32-byte lowercase hex";
    if (!isHex32(verification.txId)) return "verification.txId must be 32-byte lowercase hex";
    if (verification.failures.length !== 0) return "verification.ok=true cannot carry failures";
  }
  return null;
}

function verificationSummaryOf(verification) {
  return {
    verdict: verification.verdict,
    ok: verification.ok,
    checks: verification.checks.map((c) => ({ id: c.id, ok: c.ok })),
    failureCodes: [...new Set(verification.failures.map((f) => f.code))].sort()
  };
}

/* ------------------------------------------------------------------ */
/* rendering helpers (VERIFIED manifests only)                         */
/* ------------------------------------------------------------------ */

const OUTPUT_DESTINATIONS = Object.freeze({
  successor: "vault-successor",
  genesisVault: "vault-genesis",
  payment: "recipient",
  change: "signer-change",
  recoverPayout: "owner-payout",
  agentFuel: "agent-fuel"
});

function destinationXOnlyFor(kind, ctx) {
  const m = ctx.manifest;
  if (kind === "payment") return m.payment.recipientXOnly;
  if (kind === "change") return m.actor.signerXOnly;
  if (kind === "recoverPayout") return m.vault.owner;
  if (kind === "agentFuel") return m.requested.params.agentFuel.xOnly;
  return null; // successor / genesisVault: the vault covenant itself
}

function outputDescription(kind, valueKas, destinationXOnly) {
  switch (kind) {
    case "successor":
      return `Vault covenant successor holding the vault's protected value + fee reserve (${valueKas} KAS).`;
    case "genesisVault":
      return `New vault covenant output holding the initial protected value + fee reserve (${valueKas} KAS).`;
    case "payment":
      return `Payment of exactly ${valueKas} KAS to recipient public key ${destinationXOnly}.`;
    case "change":
      return `Change of ${valueKas} KAS returning to the signing wallet public key ${destinationXOnly}.`;
    case "recoverPayout":
      return `Terminal recovery payout of ${valueKas} KAS to the vault owner public key ${destinationXOnly}.`;
    case "agentFuel":
      return `Agent fee-fuel of ${valueKas} KAS to agent public key ${destinationXOnly}.`;
    default:
      return `Output of ${valueKas} KAS.`; // unreachable after validation
  }
}

/* JSON-safe rendering of a parsed (BigInt-view) state tuple. */
function stateBlock(state, stateId) {
  return {
    stateId,
    protectedValue: kasAmount(state.protectedValue, "state.protectedValue"),
    feeReserve: kasAmount(state.feeReserve, "state.feeReserve"),
    paused: state.paused.toString(),
    agentRoot: state.agentRoot,
    approverSlots: state.approverSlots.slice(),
    activeApproverCount: state.activeCount,
    approvalM: state.approvalM.toString(),
    policyNonce: state.policyNonce.toString()
  };
}

function copyOutpoint(op) {
  return { transactionId: op.transactionId, index: op.index };
}

function actionSummary(ctx) {
  const m = ctx.manifest;
  const vaultId = m.vault.vaultId;
  switch (ctx.sdkAction) {
    case "agentSpend": {
      const pay = sompiToKasString(ctx.payment.amountSompi, "payment.amountSompi");
      return `Send exactly ${pay} KAS to recipient public key ${m.payment.recipientXOnly} from vault ${vaultId}.`;
    }
    case "ownerTopUp": {
      const delta = ctx.stateAfter.state.protectedValue - ctx.stateBefore.state.protectedValue;
      return `Add exactly ${sompiToKasString(delta, "topUpDelta")} KAS to the protected value of vault ${vaultId}.`;
    }
    case "ownerTopUpReserve": {
      const delta = ctx.stateAfter.state.feeReserve - ctx.stateBefore.state.feeReserve;
      return `Add exactly ${sompiToKasString(delta, "topUpReserveDelta")} KAS to the fee reserve of vault ${vaultId}.`;
    }
    case "ownerPause":
      return `Freeze vault ${vaultId} (emergency pause — agent spending stops until the owner unpauses).`;
    case "ownerUnpause":
      return `Unfreeze vault ${vaultId} (agent spending resumes under the existing policy).`;
    case "ownerSetAgentRoot": {
      const root = m.stateAfter.state.agentRoot;
      switch (m.action.highLevelAction) {
        case "addAgent":
          return `Add an agent to vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        case "removeAgent":
          return `Remove an agent from vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        case "rotateAgent":
          return `Rotate an agent key on vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        case "rePolicyAgent":
          return `Update an agent's policy on vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        default:
          return `Replace the agent registry commitment of vault ${vaultId} with ${root}.`;
      }
    }
    case "ownerSetApprovers": {
      const after = ctx.stateAfter.state;
      return `Replace the approver configuration of vault ${vaultId}: ${after.approvalM} of ${after.activeCount} listed approver key(s) must co-sign above-threshold spends.`;
    }
    case "ownerRecover": {
      const payout = sompiToKasString(ctx.accounting.terminalPayout, "accounting.terminalPayout");
      return `CLOSE vault ${vaultId}: pay its entire protected value + fee reserve (${payout} KAS) to the vault owner public key ${m.vault.owner}. This is terminal — the vault ends.`;
    }
    case "createVault": {
      const prot = sompiToKasString(ctx.accounting.successorProtected, "accounting.successorProtected");
      const res = sompiToKasString(ctx.accounting.successorFeeReserve, "accounting.successorFeeReserve");
      return `Create vault ${vaultId} with ${prot} KAS protected value and ${res} KAS fee reserve, owned by public key ${m.vault.owner}.`;
    }
    default:
      return `Unknown action.`; // unreachable: validateManifest refuses unknown actions
  }
}

/* Policy-mutation rendering. Category:
 *   funding    — protectedValue / feeReserve movement;
 *   accounting — execution-managed values (spend period accounting,
 *                policyNonce advancement);
 *   policy     — the governed policy surface (paused, approver
 *                configuration, owner agent-registry replacement). */
function policyChangeEntries(ctx) {
  const entries = [];
  for (const mut of ctx.manifest.policyMutations) {
    const { field, before, after } = mut;
    if (field === "protectedValue" || field === "feeReserve") {
      const label = field === "protectedValue" ? "Protected value" : "Fee reserve";
      entries.push({
        field,
        category: "funding",
        before,
        after,
        beforeKas: sompiToKasString(before, field),
        afterKas: sompiToKasString(after, field),
        description: `${label}: ${sompiToKasString(before, field)} KAS -> ${sompiToKasString(after, field)} KAS.`
      });
    } else if (field === "agentRoot") {
      const spend = ctx.sdkAction === "agentSpend";
      entries.push({
        field,
        category: spend ? "accounting" : "policy",
        before,
        after,
        description: spend
          ? `Agent registry commitment advances for this spend's period accounting: ${before} -> ${after}.`
          : `Agent registry commitment replaced: ${before} -> ${after}.`
      });
    } else if (field === "paused") {
      entries.push({
        field,
        category: "policy",
        before,
        after,
        description: after === "1" ? "Vault paused (spending frozen)." : "Vault unpaused (spending resumes)."
      });
    } else if (field === "approverSlots") {
      entries.push({
        field,
        category: "policy",
        before: before.slice(),
        after: after.slice(),
        description: "Approver key slots replaced (full before/after slot lists carried in this entry)."
      });
    } else if (field === "approvalM") {
      entries.push({
        field,
        category: "policy",
        before,
        after,
        description: `Approval quorum: ${before} -> ${after} required approval(s).`
      });
    } else if (field === "policyNonce") {
      entries.push({
        field,
        category: "accounting",
        before,
        after,
        description: `Policy nonce advances ${before} -> ${after} (policy-defining operation).`
      });
    } else {
      /* Unreachable after validateManifest (closed STATE_FIELDS set);
       * still rendered honestly rather than dropped. */
      entries.push({ field, category: "policy", before, after, description: `${field}: ${JSON.stringify(before)} -> ${JSON.stringify(after)}.` });
    }
  }
  return entries;
}

/* ------------------------------------------------------------------ */
/* structured explanation                                              */
/* ------------------------------------------------------------------ */

/*
 * Build the structured explanation for a manifest + verification result.
 * TOTAL: always returns an explanation document; refusal on any doubt.
 */
function structured(input) {
  // TOTAL contract: never throw. A null/non-object argument (not just a
  // missing one) must still produce a refusal, not a TypeError from
  // destructuring. (Hostile-AI review H-4.)
  const { manifest, verification } = (input && typeof input === "object") ? input : {};
  try {
    /* 1. Independent strict validation of the manifest itself (schema,
     * versions, actions, representation-independent hash). A manifest
     * that fails validation gets a refusal carrying ONLY the local
     * validation error — nothing from an unvalidated document is
     * rendered, not even identity context. */
    let ctx;
    try {
      ctx = validateManifest(manifest);
    } catch (e) {
      return refusalDocument({
        reason: "The manifest failed strict validation and cannot be rendered.",
        failures: [failureEntry(e.code ?? "SCHEMA_INVALID", e.message)]
      });
    }
    const context = {
      networkId: ctx.manifest.network.networkId,
      vaultId: ctx.manifest.vault.vaultId,
      covenantVersion: ctx.manifest.vault.covenantVersion,
      sdkAction: ctx.sdkAction,
      highLevelAction: ctx.manifest.action.highLevelAction
    };
    const manifestHash = ctx.manifest.manifestHash;
    const txId = ctx.manifest.transaction.txId;

    /* 2. The verification result is REQUIRED and must be well-formed. */
    if (verification === undefined || verification === null) {
      return refusalDocument({
        reason: "No verification result was supplied — an unverified manifest is never rendered as a normal transaction summary.",
        failures: [failureEntry("MISSING_VERIFICATION", "explanations require the verifyIntentManifest result for this exact manifest")],
        context,
        manifestHash,
        txId
      });
    }
    const shapeProblem = verificationShapeProblem(verification);
    if (shapeProblem) {
      return refusalDocument({
        reason: "The supplied verification result is malformed — failing closed.",
        failures: [failureEntry("VERIFICATION_MALFORMED", shapeProblem)],
        context,
        manifestHash,
        txId
      });
    }

    /* 3. A non-full-pass verification produces the REFUSAL rendering,
     * prominently listing every detector code. */
    if (verification.ok !== true) {
      const failures = verification.failures.map((f) => failureEntry(f.code, f.detail ?? ""));
      return refusalDocument({
        reason: "Verification REFUSED this manifest — the transaction must not be signed.",
        failures: failures.length ? failures : [failureEntry("REFUSED", "verification refused without detail")],
        context,
        manifestHash,
        txId,
        verificationSummary: verificationSummaryOf(verification)
      });
    }

    /* 4. The verification result must BIND to THIS manifest. */
    if (verification.manifestHash !== manifestHash || verification.txId !== txId) {
      return refusalDocument({
        reason: "The supplied verification result is for a DIFFERENT manifest/transaction — failing closed.",
        failures: [
          failureEntry(
            "VERIFICATION_BINDING_MISMATCH",
            `verification is bound to manifestHash ${verification.manifestHash} / txId ${verification.txId}, not this manifest`
          )
        ],
        context,
        manifestHash,
        txId,
        verificationSummary: verificationSummaryOf(verification)
      });
    }

    /* 5. Independent in-process RE-VERIFICATION (self-contained). A
     * fabricated ok:true object cannot make an unverified manifest
     * render: the explanation layer re-proves the verdict itself. */
    const reverified = verifyIntentManifest({ manifest });
    if (reverified.ok !== true) {
      const failures = [
        failureEntry("EXPLAIN_REVERIFY_REFUSED", "independent re-verification refused this manifest despite the supplied passing result"),
        ...reverified.failures.map((f) => failureEntry(f.code, f.detail ?? ""))
      ];
      return refusalDocument({
        reason: "Independent re-verification REFUSED this manifest — the supplied verification result is not trustworthy.",
        failures,
        context,
        manifestHash,
        txId,
        verificationSummary: verificationSummaryOf(reverified)
      });
    }

    /* 6. VERIFIED — build the normal rendering, from the verified
     * manifest only. */
    const m = ctx.manifest;
    const doc = baseDocument();
    doc.verdict = EXPLANATION_VERDICTS.VERIFIED_EXACT;
    doc.statement = VERIFIED_STATEMENT;
    doc.manifestHash = manifestHash;
    doc.txId = txId;
    doc.network = { networkId: m.network.networkId };
    doc.vault = {
      vaultId: m.vault.vaultId,
      owner: m.vault.owner,
      covenantVersion: m.vault.covenantVersion,
      covenantId: m.vault.covenantId
    };
    doc.action = {
      sdkAction: ctx.sdkAction,
      highLevelAction: m.action.highLevelAction,
      role: m.action.role,
      genesis: m.action.genesis,
      terminal: m.action.terminal,
      aboveThreshold: m.action.aboveThreshold,
      summary: actionSummary(ctx)
    };
    doc.actor = { role: m.actor.role, signerXOnly: m.actor.signerXOnly, agentPk: m.actor.agentPk };

    doc.fee = {
      fee: kasAmount(ctx.accounting.fee, "accounting.fee"),
      maxFee: m.requested.maxFeeSompi === null ? null : kasAmount(m.requested.maxFeeSompi, "requested.maxFeeSompi"),
      withinRequestedCap: m.requested.maxFeeSompi === null ? null : true
    };

    doc.outputs = ctx.txView.outputs.map((output, index) => {
      const kind = ctx.effects.outputKinds[index];
      const value = kasAmount(output.value, `outputs[${index}].value`);
      const destinationXOnly = destinationXOnlyFor(kind, ctx);
      return {
        index,
        kind,
        destinationKind: OUTPUT_DESTINATIONS[kind],
        destinationXOnly,
        value,
        description: outputDescription(kind, value.kas, destinationXOnly)
      };
    });

    doc.payment =
      ctx.payment === null
        ? null
        : {
            recipientXOnly: m.payment.recipientXOnly,
            amount: kasAmount(ctx.payment.amountSompi, "payment.amountSompi"),
            outputIndex: m.payment.outputIndex
          };

    doc.accounting = {};
    for (const field of Object.keys(ctx.accounting)) {
      doc.accounting[field] = kasAmount(ctx.accounting[field], `accounting.${field}`);
    }

    doc.balances = {
      before: ctx.stateBefore === null ? null : stateBlock(ctx.stateBefore.state, ctx.stateBefore.stateId),
      after: ctx.stateAfter === null ? null : stateBlock(ctx.stateAfter.state, ctx.stateAfter.stateId)
    };
    if (doc.balances.before !== null) {
      doc.balances.before.outpoint = copyOutpoint(m.stateBefore.outpoint);
    }
    if (doc.balances.after !== null) {
      doc.balances.after.expectedOutpoint = copyOutpoint(m.stateAfter.expectedOutpoint);
    }

    doc.policyChanges = policyChangeEntries(ctx);

    doc.policyNonce =
      ctx.stateBefore === null || ctx.stateAfter === null
        ? null
        : {
            before: m.stateBefore.state.policyNonce,
            after: m.stateAfter.state.policyNonce,
            rule: ctx.info.nonce
          };

    if (ctx.sdkAction === "agentSpend") {
      doc.approvals = {
        aboveThreshold: m.approvals.aboveThreshold,
        approvalThreshold: kasAmount(ctx.approvals.approvalThreshold, "approvals.approvalThreshold"),
        requiredM: ctx.approvals.requiredM.toString()
      };
      const pb = ctx.limits.policyBefore;
      const pa = ctx.limits.policyAfter;
      const rollover = ctx.limits.periodsElapsed >= 1n;
      doc.limits = {
        agentPk: m.limits.policyBefore.agentPk,
        maxPerSpend: kasAmount(pb.maxPerSpend, "policy.maxPerSpend"),
        periodBudget: kasAmount(pb.periodBudget, "policy.periodBudget"),
        periodSpentBefore: kasAmount(pb.periodSpent, "policy.periodSpent"),
        periodSpentAfter: kasAmount(pa.periodSpent, "policy.periodSpentAfter"),
        remainingAfter: kasAmount(pa.periodBudget - pa.periodSpent, "policy.remainingAfter"),
        periodLengthDaa: pb.periodLengthDaa.toString(),
        periodsElapsed: ctx.limits.periodsElapsed.toString(),
        rollover,
        periodStartAfterDaa: pa.periodStartDaa.toString(),
        lockTime: ctx.txView.lockTime.toString(),
        agentMaxFeePerTx: kasAmount(pb.agentMaxFeePerTx, "policy.agentMaxFeePerTx"),
        reserveConsumed: kasAmount(ctx.accounting.reserveConsumed, "accounting.reserveConsumed"),
        agentRecipientRoot: m.allowlist.agentRecipientRoot,
        recipientAllowlisted: m.allowlist.recipientAllowlisted,
        allowlistProofSupplied: m.allowlist.proofSupplied
      };
    }

    doc.warnings = m.warnings.map((w) => ({ code: w.code, detail: w.detail }));
    doc.verification = verificationSummaryOf(verification);
    return deepFreeze(doc);
  } catch (e) {
    /* An internal error is never a pass — refuse. */
    return refusalDocument({
      reason: "The explanation engine failed internally — failing closed.",
      failures: [failureEntry("EXPLAIN_INTERNAL", `${e.message}`)]
    });
  }
}

/* ------------------------------------------------------------------ */
/* human-readable lines                                                */
/* ------------------------------------------------------------------ */

function refusalLines(doc) {
  const lines = [];
  lines.push("!! DO NOT SIGN !!");
  lines.push("VERIFICATION REFUSED — this transaction description FAILED verification and must not be signed.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Refusal codes: ${doc.refusal.codes.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.code}: ${sanitizeDetail(f.detail)}`);
  }
  if (doc.context !== null) {
    const c = doc.context;
    const action = c.highLevelAction === null ? c.sdkAction : `${c.highLevelAction} (${c.sdkAction})`;
    lines.push(
      `Context (from the manifest, NOT verified): action ${action}, vault ${c.vaultId}, network ${c.networkId}, covenant ${c.covenantVersion}.`
    );
  }
  if (doc.txId !== null) lines.push(`Transaction id (NOT verified): ${doc.txId}.`);
  if (doc.manifestHash !== null) lines.push(`Manifest hash: ${doc.manifestHash}.`);
  lines.push("A refused manifest is never rendered as a normal transaction summary. Rebuild the request and verify again.");
  return lines;
}

function verifiedLines(doc) {
  const lines = [];
  lines.push(doc.action.summary);

  /* Every output the transaction creates, in order, with full values. */
  for (const output of doc.outputs) {
    lines.push(`Output ${output.index}: ${output.description}`);
  }

  const cap = doc.fee.maxFee === null ? "" : ` (within the requested cap of ${doc.fee.maxFee.kas} KAS)`;
  lines.push(`Fee: ${doc.fee.fee.kas} KAS${cap}.`);

  if (doc.balances.after !== null) {
    const afterProt = doc.balances.after.protectedValue.kas;
    const afterRes = doc.balances.after.feeReserve.kas;
    if (doc.balances.before !== null) {
      lines.push(
        `Protected value after: ${afterProt} KAS (was ${doc.balances.before.protectedValue.kas} KAS). Fee reserve after: ${afterRes} KAS (was ${doc.balances.before.feeReserve.kas} KAS).`
      );
    } else {
      lines.push(`Protected value: ${afterProt} KAS. Fee reserve: ${afterRes} KAS.`);
    }
  } else if (doc.action.terminal) {
    lines.push("The vault is CLOSED by this transaction — no successor state remains.");
  }

  if (doc.limits !== null) {
    lines.push(
      `Budget after: ${doc.limits.periodSpentAfter.kas} KAS of the ${doc.limits.periodBudget.kas} KAS period budget used (${doc.limits.remainingAfter.kas} KAS remaining). Per-spend cap: ${doc.limits.maxPerSpend.kas} KAS.`
    );
    if (doc.limits.rollover) {
      lines.push(
        `A new budget period starts with this spend (periods elapsed: ${doc.limits.periodsElapsed}); the transaction is not valid before DAA score ${doc.limits.lockTime}.`
      );
    }
    lines.push(`Network fee is paid from the vault fee reserve: ${doc.limits.reserveConsumed.kas} KAS (agent per-transaction fee cap ${doc.limits.agentMaxFeePerTx.kas} KAS).`);
    lines.push(`Recipient is authorized by this agent's recipient allowlist (root ${doc.limits.agentRecipientRoot}); membership proof verified upstream.`);
  }

  if (doc.approvals !== null) {
    if (doc.approvals.aboveThreshold) {
      lines.push(
        `This spend is ABOVE the approval threshold (${doc.approvals.approvalThreshold.kas} KAS): ${doc.approvals.requiredM} approver signature(s) are required by the covenant.`
      );
    } else {
      lines.push(`This spend is at or below the approval threshold (${doc.approvals.approvalThreshold.kas} KAS): no approver signatures are required.`);
    }
  }

  const policyEntries = doc.policyChanges === null ? [] : doc.policyChanges.filter((e) => e.category === "policy");
  if (doc.action.genesis) {
    lines.push("This transaction creates the vault's initial policy state.");
  } else if (doc.action.terminal) {
    lines.push("All policy for this vault ends with the vault.");
  } else if (policyEntries.length === 0) {
    const qualifier = doc.action.sdkAction === "agentSpend" ? "spend and period accounting only" : "funding only";
    lines.push(`No policy changes — ${qualifier}.`);
  } else {
    for (const e of policyEntries) {
      lines.push(`Policy change: ${e.description}`);
    }
  }
  if (doc.policyNonce !== null && doc.policyNonce.rule === "increment") {
    lines.push(`Policy nonce advances ${doc.policyNonce.before} -> ${doc.policyNonce.after}.`);
  }

  for (const w of doc.warnings) {
    lines.push(`Warning ${w.code}: ${sanitizeDetail(w.detail)}`);
  }

  lines.push(`Vault: ${doc.vault.vaultId} (network ${doc.network.networkId}, covenant ${doc.vault.covenantVersion}).`);
  lines.push(`Signer: ${doc.actor.role} public key ${doc.actor.signerXOnly}.`);
  lines.push(`Transaction id: ${doc.txId}. Manifest hash: ${doc.manifestHash}.`);
  lines.push(`Verification: PASSED — ${doc.statement}`);
  return lines;
}

/*
 * Deterministic English lines for a signer UI. TOTAL: never throws;
 * refusals render as prominent DO-NOT-SIGN lines. Same input ->
 * byte-identical output.
 */
function humanReadable(input) {
  // TOTAL contract (H-4): tolerate a null/non-object argument.
  const { manifest, verification } = (input && typeof input === "object") ? input : {};
  const doc = structured({ manifest, verification });
  const lines = doc.verdict === EXPLANATION_VERDICTS.VERIFIED_EXACT ? verifiedLines(doc) : refusalLines(doc);
  return deepFreeze(lines);
}

module.exports = {
  INTENT_EXPLANATION_VERSION_1,
  EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
