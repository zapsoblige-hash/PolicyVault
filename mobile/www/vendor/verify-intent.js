"use strict";

/*
 * PolicyVault BROWSER-LOCAL DETERMINISTIC PRE-SIGN VERIFICATION
 * (PostLaunchUpgradeOG completion-standard item 2, browser side).
 *
 * Before any wallet prompt opens, the browser INDEPENDENTLY re-derives what
 * the frozen transaction it is about to sign ACTUALLY does and proves it
 * equal to what the user asked for, using the portable shared core
 * (core/intent buildIntentManifest + verifyIntentManifest, rendered by
 * core/explain) running IN THE BROWSER via web/core-bundle.js.
 *
 * INPUT PROVENANCE (documented per field; see
 * docs/postlaunch/browser-verification.md for the full residual-trust
 * table):
 *
 *   CLIENT-HELD (independent of the signing payload):
 *     - the REQUESTED INTENT: captured from the user's own form/prompt
 *       context at request time (amounts the user typed, recipients the
 *       user entered, the acting identity from the connected wallet) —
 *       NEVER from a server description;
 *     - the covenant state the client knows: the vault presentation the
 *       user is looking at (protected value, fee reserve, live outpoint,
 *       covenantId, approver slots, agent policies) — server-served chain
 *       reads, fetched BEFORE the action (residual trust: state
 *       freshness/authenticity of chain reads; the client has no node);
 *     - the wallet session identity + network (KasWare-reported).
 *
 *   THE EXACT BYTES TO BE SIGNED:
 *     - `unsignedSafeJson` — the exact string handed to the wallet's
 *       signPskt. Decoded HERE, strictly, into the manifest's decoded-
 *       transaction document. Every value-moving fact (outputs, values,
 *       scripts, lockTime, input outpoints) is read from THIS payload.
 *
 *   SERVER CLAIMS adopted where the client cannot recompute (each one is
 *   cross-checked for internal consistency and listed in the manifest
 *   warnings + the residual-trust table): txId (consensus hashing is never
 *   reimplemented in JS), address->x-only resolution (the server's single
 *   identity boundary), the input UTXO amounts embedded in the payload,
 *   and — for covenant transitions only — the covenant input's FINAL
 *   signature-script bytes (compiled covenant + call encoding), which
 *   bound the exact network-fee requirement.
 *
 *   FEES, COMPUTE BUDGETS, SUCCESSOR STATES, AND STATE IDS ARE NOT CLAIMS
 *   (fee/state recomputation wave): the browser INDEPENDENTLY RECOMPUTES,
 *   through the bundled canonical core modules (the SAME modules the SDK
 *   builder runs — core/model/fee-mass + frozen-tx-v3 + compute-budget-v4
 *   + vault-state-v4 + vault-transitions-v4):
 *   (a) the transaction's mass and minimum consensus relay fee from the
 *   decoded payload's own structure — EXACT (equality-enforced) for
 *   all-ordinary-input transactions (genesis), and a strict enforced
 *   LOWER BOUND plus the standard-mass structural CAP for covenant
 *   transitions (the covenant signature-script bytes are the one
 *   undisclosed length); the fee the payload actually pays (inputs −
 *   outputs) is always derived from the payload itself, never adopted;
 *   (b) every input's committed compute budget, pinned to the canonical
 *   proven-safe tier for the requested operation;
 *   (c) the successor covenant state through the canonical v0.4
 *   transition builders (covenant equations: caps, period budgets,
 *   reserve rules, pause rules, nonce rules);
 *   (d) the predecessor, successor, and genesis STATE IDS via the
 *   canonical commitment formula — the vault view's stateId and the
 *   request's successorStateId must EQUAL the recomputation.
 *   Any mismatch, bound violation, unknown version, or recomputation
 *   failure REFUSES (DO-NOT-SIGN); nothing falls back to trusting a
 *   disclosed value.
 *
 *   MERKLE ROOTS ARE NOT CLAIMS (F1 wave): the browser INDEPENDENTLY
 *   RECOMPUTES, via the bundled byte-native core Merkle modules,
 *   (a) the predecessor agent-registry root from the FULL displayed agent
 *   policy set (must equal the covenant state's agentRoot),
 *   (b) the acting agent's recipient-allowlist root from the FULL
 *   displayed recipient list (must equal the policy's committed
 *   agentRecipientRoot; membership is then proven under that root), and
 *   (c) every successor agent-registry root (spend accounting advance and
 *   all agent-lifecycle changes) from the client's own typed parameters —
 *   the request's claimed root must EQUAL the recomputation. Any
 *   mismatch, missing leaf data, unknown covenant version, or inability
 *   to recompute REFUSES (DO-NOT-SIGN); nothing falls back to trusting a
 *   disclosed root. GENESIS INCLUDED (residuals wave): the genesis
 *   request document discloses the initial registry's full leaf tuples
 *   (`initialRegistry`) and the browser rebuilds every allowlist root
 *   and the whole agent tree from them — initialState.agentRoot must
 *   EQUAL the recomputation, and a v4 genesis document without
 *   well-formed tuples refuses (documented compat rule: every recorded
 *   v4 genesis document has carried them since the flow existed).
 *
 * FAIL CLOSED: every entry point is TOTAL — it never throws; any
 * derivation failure, unknown version, unknown action, missing field, or
 * internal error produces a REFUSED outcome whose lines are a prominent
 * DO-NOT-SIGN rendering. A refusal MUST block the wallet prompt (enforced
 * again inside web/app-v4.js walletSign). There is no partial verdict and
 * no proceed-anyway.
 *
 * This module contains NO cryptography (sha256 lives in the bundled core)
 * and NO wallet code. It is loadable in Node for the web/test suites
 * (createVerifyIntent(core) with an injected core bundle).
 */

(function () {
  /* The client's own fee expectation, applied as requested.maxFeeSompi on
   * every derived intent that does not carry an explicit user cap: 1 KAS.
   * Real PolicyVault transaction fees are orders of magnitude below this
   * (Phase G evidence: ~0.0001-0.001 KAS); the ceiling exists so a
   * hostile builder cannot silently reroute value into the network fee.
   * Blocking direction only: it can only ever refuse a signature. */
  var CLIENT_MAX_FEE_SOMPI = "100000000";

  var SENTINEL = "0000000000000000000000000000000000000000000000000000000000000000";
  var NATIVE_SUBNETWORK = "0000000000000000000000000000000000000000";
  var SOMPI_PER_KAS = 100000000n;
  var HEX64 = /^[0-9a-f]{64}$/;
  var DIGITS = /^(0|[1-9][0-9]*)$/;

  function createVerifyIntent(core) {
    if (
      !core ||
      !core.intent ||
      !core.intentExplain ||
      !core.recipientMerkle ||
      !core.agentMerkle ||
      !core.feeMass ||
      !core.frozenTx ||
      !core.computeBudgetV4 ||
      !core.vaultStateV4 ||
      !core.vaultTransitionsV4
    ) {
      /* A core bundle WITHOUT the Merkle modules or the fee/state
       * recomputation modules cannot perform the mandatory independent
       * recomputations — treat it as no core at all: every verification
       * below refuses with CORE_UNAVAILABLE. */
      core = null;
    }

    /* ---------------- refusal plumbing (total functions) ---------------- */

    function Refusal(code, detail) {
      this.browserRefusal = true;
      this.code = String(code);
      this.detail = String(detail);
    }

    function refuse(code, detail) {
      throw new Refusal(code, detail);
    }

    function refusalOutcome(failures, context) {
      var codes = [];
      for (var i = 0; i < failures.length; i++) {
        if (codes.indexOf(failures[i].code) < 0) codes.push(failures[i].code);
      }
      codes.sort();
      var lines = [];
      lines.push("!! DO NOT SIGN !!");
      lines.push("BROWSER VERIFICATION REFUSED — this transaction FAILED independent in-browser verification and must not be signed.");
      lines.push("Refusal codes: " + codes.join(", ") + ".");
      for (var j = 0; j < failures.length; j++) {
        lines.push("- " + failures[j].code + ": " + failures[j].detail);
      }
      if (context) lines.push("Context: " + context);
      lines.push("Nothing was signed and nothing was sent. Refresh the page, rebuild the request, and verify again.");
      return deepFreeze({
        ok: false,
        verdict: "REFUSED",
        refusalCodes: codes,
        failures: failures.slice(),
        lines: lines,
        structured: null,
        manifest: null,
        manifestHash: null,
        txId: null,
        unsignedSafeJson: null,
        checks: null,
        notes: []
      });
    }

    function deepFreeze(value) {
      if (value && typeof value === "object" && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (var k in value) {
          if (Object.prototype.hasOwnProperty.call(value, k)) deepFreeze(value[k]);
        }
      }
      return value;
    }

    /* ---------------- strict primitives ---------------- */

    function isPlainObject(v) {
      return v !== null && typeof v === "object" && !Array.isArray(v);
    }

    function requireKeys(obj, keys, path) {
      if (!isPlainObject(obj)) refuse("SAFE_JSON_INVALID", path + " must be an object");
      var k;
      for (k in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, k) && keys.indexOf(k) < 0) {
          refuse("SAFE_JSON_INVALID", path + " carries unknown key " + JSON.stringify(k) + " — failing closed (a hidden field is a hidden effect)");
        }
      }
      for (var i = 0; i < keys.length; i++) {
        if (!Object.prototype.hasOwnProperty.call(obj, keys[i])) {
          refuse("SAFE_JSON_INVALID", path + "." + keys[i] + " is required");
        }
      }
      return obj;
    }

    function digitsToBigInt(value, field, code) {
      if (typeof value !== "string" || !DIGITS.test(value)) {
        refuse(code || "VALUE_INVALID", field + " must be a canonical base-10 digit string, got " + (typeof value === "string" ? JSON.stringify(value) : typeof value));
      }
      return BigInt(value);
    }

    function hex64(value, field, code) {
      if (typeof value !== "string" || !HEX64.test(value)) {
        refuse(code || "VALUE_INVALID", field + " must be 32-byte lowercase hex");
      }
      return value;
    }

    /* Exact KAS decimal -> integer sompi digits (lossless inverse of the
     * SDK's sompiToKas; <= 8 fractional digits; BigInt math only). */
    function kasToSompi(value, field) {
      if (typeof value !== "string") refuse("VALUE_INVALID", field + " must be a KAS decimal string");
      var m = /^(\d+)(?:\.(\d{1,8}))?$/.exec(value.trim());
      if (!m) refuse("VALUE_INVALID", field + " is not a valid KAS decimal string: " + JSON.stringify(value));
      var whole = BigInt(m[1]);
      var fracDigits = m[2] || "";
      while (fracDigits.length < 8) fracDigits += "0";
      return whole * SOMPI_PER_KAS + BigInt(fracDigits);
    }

    function p2pk(xOnly) {
      return "20" + xOnly + "ac";
    }

    /* Canonical SET fingerprint of an x-only key list (unique keys,
     * sorted, joined) — order-free equality for recipient allowlists
     * (the committed Merkle set is order-free; display/entry order and
     * duplicates carry no meaning). */
    function xOnlySetFingerprint(list, field) {
      if (!Array.isArray(list) || list.length === 0) refuse("VALUE_INVALID", field + " must be a non-empty array of x-only keys");
      var uniq = [];
      for (var i = 0; i < list.length; i++) {
        var k = hex64(list[i], field + "[" + i + "]");
        if (uniq.indexOf(k) < 0) uniq.push(k);
      }
      uniq.sort();
      return uniq.join(",");
    }

    /* Canonical 10-slot approver layout from an active-key list — the
     * exact rule of sdk/src/vault-state-v4.js normalizeApprovers for the
     * `approvers` input form: distinct active keys, SORTED, sentinel-padded. */
    function approverSlotsFromList(list, field) {
      if (!Array.isArray(list) || list.length > 10) refuse("VALUE_INVALID", field + " must list at most 10 approver keys");
      var active = [];
      for (var i = 0; i < list.length; i++) {
        var key = hex64(list[i], field + "[" + i + "]");
        if (key === SENTINEL) refuse("VALUE_INVALID", field + "[" + i + "] is the sentinel");
        if (active.indexOf(key) >= 0) refuse("VALUE_INVALID", field + "[" + i + "] duplicates an earlier key");
        active.push(key);
      }
      active.sort();
      while (active.length < 10) active.push(SENTINEL);
      return active;
    }

    /* ---------------- independent Merkle recomputation ---------------- */

    /* Covenant versions whose Merkle commitments this verifier can
     * independently recompute (the v4 family — mirrors the core
     * manifest's SUPPORTED_COVENANT_VERSIONS). Anything else FAILS CLOSED
     * before any recompute: unknown versions never route to a default
     * tree construction rule. */
    var MERKLE_RECOMPUTABLE_VERSIONS = ["policyvault-0.4", "policyvault-0.4.1"];

    function rebuildAgentTree(policyList, contextLabel) {
      try {
        return core.agentMerkle.buildAgentTreeV4(policyList);
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        refuse("MERKLE_RECOMPUTE_FAILED", "could not rebuild the agent-registry Merkle tree from " + contextLabel + ": " + ((e && e.message) || String(e)));
      }
    }

    function rebuildRecipientTree(recipientList, contextLabel) {
      try {
        return core.recipientMerkle.buildRecipientTree(recipientList);
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        refuse("MERKLE_RECOMPUTE_FAILED", "could not rebuild the recipient-allowlist Merkle tree from " + contextLabel + ": " + ((e && e.message) || String(e)));
      }
    }

    /* The client's own full agent-policy intent for agent-lifecycle
     * actions (web/app-v4.js agentFromPrompts shape): every leaf field the
     * user's action determines, plus the typed recipient allowlist keys
     * (already resolved to x-only through the server's single address
     * boundary before this module sees them). */
    function agentPolicyParam(a, path) {
      if (!isPlainObject(a)) refuse("VALUE_INVALID", path + " must carry the full agent policy this browser built from your inputs — the successor registry root cannot be independently recomputed without it");
      var recips = a.recipients;
      if (!Array.isArray(recips) || recips.length === 0) refuse("VALUE_INVALID", path + ".recipients must list at least one allowed recipient key");
      var recipients = [];
      for (var i = 0; i < recips.length; i++) recipients.push(hex64(recips[i], path + ".recipients[" + i + "]"));
      return {
        agentPk: hex64(a.agentPk, path + ".agentPk"),
        maxPerSpend: digitsToBigInt(String(a.maxPerSpend), path + ".maxPerSpend").toString(),
        periodBudget: digitsToBigInt(String(a.periodBudget), path + ".periodBudget").toString(),
        periodLengthDaa: digitsToBigInt(String(a.periodLengthDaa), path + ".periodLengthDaa").toString(),
        periodStartDaa: digitsToBigInt(String(a.periodStartDaa), path + ".periodStartDaa").toString(),
        periodSpent: digitsToBigInt(String(a.periodSpent !== undefined ? a.periodSpent : "0"), path + ".periodSpent").toString(),
        approvalThreshold: digitsToBigInt(String(a.approvalThreshold), path + ".approvalThreshold").toString(),
        agentMaxFeePerTx: digitsToBigInt(String(a.agentMaxFeePerTx), path + ".agentMaxFeePerTx").toString(),
        recipients: recipients
      };
    }

    /* Recompute the successor agent-registry root for a high-level agent
     * lifecycle action from the client's OWN typed parameters + the
     * recomputed predecessor tree. Every failure refuses — a lifecycle
     * signature is never gated on a root the browser did not derive
     * itself. */
    function recomputeLifecycleRoot(action, clientParams, knowledge) {
      var am = core.agentMerkle;
      var tree = knowledge.agentTree;
      try {
        if (action === "removeAgent") {
          return am.removeAgentV4(tree, clientParams.agentPk).root;
        }
        var a = clientParams.agent;
        var newPolicy = {
          agentPk: a.agentPk,
          maxPerSpend: a.maxPerSpend,
          periodBudget: a.periodBudget,
          periodLengthDaa: a.periodLengthDaa,
          periodStartDaa: a.periodStartDaa,
          periodSpent: a.periodSpent,
          approvalThreshold: a.approvalThreshold,
          agentMaxFeePerTx: a.agentMaxFeePerTx,
          agentRecipientRoot: rebuildRecipientTree(a.recipients, "the new agent policy's typed recipient allowlist").root
        };
        if (action === "addAgent") return am.addAgentV4(tree, newPolicy).root;
        if (action === "rePolicyAgent") return am.updateAgentPolicyV4(tree, newPolicy).root;
        if (action === "rotateAgent") return am.rotateAgentV4(tree, clientParams.agentPk, newPolicy).root;
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        refuse("MERKLE_RECOMPUTE_FAILED", "could not derive the successor agent-registry root for " + action + ": " + ((e && e.message) || String(e)));
      }
      refuse("UNKNOWN_ACTION", "unknown agent-lifecycle action " + JSON.stringify(action) + " — failing closed");
    }

    /* ------- independent fee/mass + compute-budget + state recomputation ------- */

    /* 0x41 push + 65-byte Schnorr signature: the EXACT final signature-
     * script length of every ordinary (non-covenant) input — the SDK
     * finalizer refuses anything else (sdk/src/vault-builders-v4.js
     * ORDINARY_SIGSCRIPT_LEN). */
    var ORDINARY_SIGSCRIPT_LEN = 66;

    /* The maximum fee ANY standard transaction can be REQUIRED to pay:
     * fee mass is capped at STANDARD_MASS_CAP (calculateRequiredFee fails
     * closed above it — such a transaction is never relayed), and the
     * minimum fee is feeMass * MINIMUM_RELAY_TRANSACTION_FEE / 1000.
     * PolicyVault's wallet-flow builders always set the fee to the EXACT
     * requirement (no margin), so a fee above this bound cannot be a
     * legitimate network fee for any shape. Blocking direction only. */
    function structuralMaxFeeSompi() {
      return (core.feeMass.STANDARD_MASS_CAP * core.feeMass.MINIMUM_RELAY_TRANSACTION_FEE) / 1000n;
    }

    /* Normalize the decoded payload into the EXACT frozen-transaction
     * descriptor the SDK's fee path consumes (core/model/frozen-tx-v3
     * normalizeFrozenTxV3 — byte-identical module to the server's). */
    function frozenFromTxDoc(txDoc) {
      try {
        return core.frozenTx.normalizeFrozenTxV3({
          version: 1,
          inputs: txDoc.inputs.map(function (input) {
            return {
              previousOutpoint: input.previousOutpoint,
              sequence: input.sequence,
              computeBudget: input.computeBudget,
              utxo: {
                amount: input.utxo.amount,
                scriptPublicKey: input.utxo.scriptPublicKey,
                covenantId: input.utxo.covenantId,
                blockDaaScore: input.utxo.blockDaaScore
              }
            };
          }),
          outputs: txDoc.outputs.map(function (o) {
            return { value: o.value, scriptPublicKey: o.scriptPublicKey, covenant: o.covenant };
          }),
          lockTime: txDoc.lockTime,
          subnetworkId: txDoc.subnetworkId,
          gas: "0",
          payload: ""
        });
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        refuse("FEE_RECOMPUTE_FAILED", "could not normalize the signing payload into the canonical fee descriptor: " + ((e && e.message) || String(e)));
      }
    }

    /* Recompute the minimum consensus relay fee for the payload through
     * the EXACT SDK call path: calculateRequiredFee over
     * feeDescriptorFromFrozen (core/model/fee-mass + frozen-tx-v3 —
     * sdk/src/vault-builders-v4.js exactFee). Ordinary inputs enter at
     * their exact final 66-byte signature-script length; a covenant
     * input's final signature script (compiled covenant + call encoding)
     * is NOT disclosed to the browser, so it enters at length 0 and the
     * result is a strict LOWER BOUND on the final requirement — EXACT
     * when the transaction has no covenant input (genesis). */
    function recomputeFeeRequirement(txDoc) {
      var frozen = frozenFromTxDoc(txDoc);
      var exact = true;
      var sigLens = txDoc.inputs.map(function (input) {
        if (input.utxo.covenantId !== null) {
          exact = false;
          return 0;
        }
        return ORDINARY_SIGSCRIPT_LEN;
      });
      try {
        var required = core.feeMass.calculateRequiredFee(core.frozenTx.feeDescriptorFromFrozen(frozen, sigLens));
        return { requiredFee: required.minimumRequiredFee, feeMass: required.feeMass, exact: exact };
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        /* calculateRequiredFee fails closed above the standard mass cap:
         * even this unsigned shape exceeds what any node relays. */
        refuse("FEE_RULE_VIOLATION", "independent fee/mass recomputation refused this transaction shape: " + ((e && e.message) || String(e)));
      }
    }

    /* Enforce the recomputed fee facts against the fee the payload
     * ACTUALLY pays (inputs − outputs, derived from the payload itself).
     * Exact shapes (no covenant input): strict equality — the builder
     * adds no margin. Covenant transitions: actualFee >= the recomputed
     * floor (an honest build can only exceed it, never undershoot: the
     * final fee additionally pays for the covenant signature-script
     * bytes). The EXCESSIVE side is enforced through the manifest's fee
     * cap, which is tightened to the structural maximum (see
     * structuralMaxFeeSompi). */
    function enforceFeeRecomputation(txDoc, actualFee, recomputed) {
      var facts = recomputeFeeRequirement(txDoc);
      if (facts.exact) {
        if (actualFee !== facts.requiredFee) {
          refuse(
            "FEE_MISMATCH",
            "the transaction pays a " + actualFee.toString() + "-sompi network fee, but the independently recomputed EXACT requirement for this all-ordinary-input shape is " + facts.requiredFee.toString() + " sompi (canonical fee/mass rules; the builder adds no margin) — the fee is not the consensus-required fee"
          );
        }
        recomputed.push("network fee (EXACT: recomputed from the transaction's own structure via the canonical fee/mass rules — all inputs are ordinary, so the final signed shape is fully known; the fee the payload pays equals the recomputed requirement)");
      } else {
        if (actualFee < facts.requiredFee) {
          refuse(
            "FEE_RULE_VIOLATION",
            "the transaction pays a " + actualFee.toString() + "-sompi network fee, below the independently recomputed minimum of " + facts.requiredFee.toString() + " sompi for even its UNSIGNED shape (serialized size + committed compute budgets) — a fee-starved transaction can never confirm and must not be signed"
          );
        }
        recomputed.push("network-fee lower bound (recomputed from the unsigned shape + committed compute budgets via the canonical fee/mass rules; the fee the payload pays meets it — the exact requirement additionally depends on the covenant signature-script bytes, which are not disclosed to the browser)");
      }
      return facts;
    }

    /* Pin every committed compute budget to the canonical proven-safe
     * tier (core/model/compute-budget-v4 — the SAME module the SDK
     * commits from): the covenant input carries EXACTLY the tier for this
     * operation, every ordinary input EXACTLY the ordinary tier. An
     * under-committed budget strands an otherwise-valid transaction; an
     * over-committed budget inflates the compute mass the fee pays for.
     * operation === null means "no covenant input is permitted at all"
     * (genesis). */
    function enforceComputeBudgets(txDoc, operation, aboveThreshold, recomputed) {
      var expectedCovenant = null;
      if (operation !== null) {
        try {
          expectedCovenant = core.computeBudgetV4.selectComputeBudgetV4({ operation: operation, aboveThreshold: aboveThreshold });
        } catch (e) {
          if (e && e.browserRefusal) throw e;
          refuse("COMPUTE_BUDGET_MISMATCH", "no canonical compute-budget tier exists for operation " + JSON.stringify(operation) + " — failing closed: " + ((e && e.message) || String(e)));
        }
      }
      var ordinary = core.computeBudgetV4.V4_BUDGET.ORDINARY_INPUT;
      for (var i = 0; i < txDoc.inputs.length; i++) {
        var input = txDoc.inputs[i];
        if (input.utxo.covenantId !== null) {
          if (expectedCovenant === null || input.computeBudget !== expectedCovenant) {
            refuse(
              "COMPUTE_BUDGET_MISMATCH",
              "input " + i + " (covenant) commits compute budget " + input.computeBudget + ", but the canonical proven-safe tier for " + String(operation) + (aboveThreshold === true ? " (with approvals)" : "") + " is " + String(expectedCovenant) + " — a wrong committed budget strands the transaction or inflates its fee mass"
            );
          }
        } else if (input.computeBudget !== ordinary) {
          refuse("COMPUTE_BUDGET_MISMATCH", "input " + i + " (ordinary) commits compute budget " + input.computeBudget + ", but ordinary inputs commit exactly " + ordinary);
        }
      }
      recomputed.push("committed compute budgets (every input pinned to the canonical proven-safe tier for this operation)");
    }

    /* Canonical v0.4-family strict state normalization + state-id
     * recomputation (core/model/vault-state-v4 — the SAME module and
     * formula the SDK computes state ids with). Inputs are exclusively
     * the client's own knowledge/derivations. */
    function normalizeStateStrict(stateDoc, label) {
      try {
        return core.vaultStateV4.normalizeStateV4({
          protectedValue: stateDoc.protectedValue,
          feeReserve: stateDoc.feeReserve,
          paused: stateDoc.paused,
          agentRoot: stateDoc.agentRoot,
          approverSlots: stateDoc.approverSlots,
          approvalM: stateDoc.approvalM,
          policyNonce: stateDoc.policyNonce
        });
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        refuse("STATE_RECOMPUTE_FAILED", label + " is not a well-formed v0.4-family covenant state: " + ((e && e.message) || String(e)));
      }
    }

    function recomputeStateId(networkId, owner, vaultId, normalizedState, contractVersion, label) {
      try {
        return core.vaultStateV4.computeStateIdV4({
          networkId: networkId,
          template: core.vaultStateV4.normalizeTemplateV4({ owner: owner, vaultId: vaultId }),
          state: normalizedState,
          contractVersion: contractVersion
        });
      } catch (e) {
        if (e && e.browserRefusal) throw e;
        refuse("STATE_RECOMPUTE_FAILED", "could not recompute the " + label + " state id: " + ((e && e.message) || String(e)));
      }
    }

    /* Map an error thrown by the canonical transition module
     * (core/model/vault-transitions-v4 — covenant equations) onto this
     * verifier's refusal vocabulary. Never a pass; specific covenant
     * rules keep their established detector codes. */
    function refuseFromTransition(e, contextLabel) {
      if (e && e.browserRefusal) throw e;
      var code = "TRANSITION_RULE_VIOLATION";
      if (e && (e.code === "OVER_AGENT_FEE_CAP" || e.code === "INSUFFICIENT_RESERVE")) code = "RESERVE_RULE_VIOLATION";
      else if (e && e.code === "AGENT_PROOF_INVALID") code = "AGENT_REGISTRY_ROOT_MISMATCH";
      refuse(code, "the canonical covenant transition module refused " + contextLabel + ": " + ((e && e.message) || String(e)));
    }

    /* ---------------- Safe JSON decoding ---------------- */

    /*
     * Decode the EXACT unsigned Safe JSON string handed to the wallet
     * (kaspa-wasm Transaction.serializeToSafeJSON — rusty-kaspa
     * consensus/client/src/serializable/string.rs, read 2026-08-26) into
     * the manifest's decoded-transaction document. CLOSED schemas: any
     * unknown key, any signed input, any non-zero mass/gas/payload, any
     * malformed value REFUSES.
     *
     * scriptPublicKey wire form: ONE hex string = 4 hex chars of the u16
     * script version (big-endian) + the script hex (rusty-kaspa
     * ScriptPublicKey custom serde).
     *
     * Input covenant classification: the Safe JSON produced by the server
     * carries covenantId: null on input UTXOs (sdk/src/frozen-tx-v3.js
     * frozenToWasmTransaction does not populate it), so the covenant
     * predecessor is identified from CLIENT KNOWLEDGE: the input whose
     * previousOutpoint equals the vault's live outpoint the client already
     * knows gets the client-known covenantId. No matching input for a
     * transition => refusal (wrong vault / stale client state).
     */
    function decodeUnsignedSafeTransaction(unsignedSafeJson, known) {
      if (typeof unsignedSafeJson !== "string" || !unsignedSafeJson.trim()) {
        refuse("SAFE_JSON_INVALID", "unsignedSafeJson must be the frozen serialized transaction string");
      }
      var safe;
      try {
        safe = JSON.parse(unsignedSafeJson);
      } catch (e) {
        refuse("SAFE_JSON_INVALID", "unsignedSafeJson is not valid JSON");
      }
      requireKeys(safe, ["id", "version", "inputs", "outputs", "subnetworkId", "lockTime", "gas", "storageMass", "payload"], "safeTx");
      var txId = hex64(safe.id, "safeTx.id", "SAFE_JSON_INVALID");
      if (safe.version !== 1) refuse("SAFE_JSON_INVALID", "safeTx.version must be 1 (Toccata), got " + JSON.stringify(safe.version));
      if (safe.subnetworkId !== NATIVE_SUBNETWORK) refuse("SAFE_JSON_INVALID", "safeTx.subnetworkId must be the native subnetwork");
      digitsToBigInt(safe.lockTime, "safeTx.lockTime", "SAFE_JSON_INVALID");
      if (safe.gas !== "0") refuse("SAFE_JSON_INVALID", "safeTx.gas must be \"0\"");
      if (safe.storageMass !== "0") refuse("SAFE_JSON_INVALID", "safeTx.storageMass must be \"0\" for a frozen PolicyVault transaction");
      if (safe.payload !== "") refuse("SAFE_JSON_INVALID", "safeTx.payload must be empty");
      if (!Array.isArray(safe.inputs) || safe.inputs.length === 0) refuse("SAFE_JSON_INVALID", "safeTx.inputs must be a non-empty array");
      if (!Array.isArray(safe.outputs) || safe.outputs.length === 0) refuse("SAFE_JSON_INVALID", "safeTx.outputs must be a non-empty array");

      function splitSpk(value, path) {
        if (typeof value !== "string" || value.length < 4 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
          refuse("SAFE_JSON_INVALID", path + " must be the lowercase hex scriptPublicKey wire form (u16 version + script)");
        }
        var version = parseInt(value.slice(0, 4), 16);
        var scriptHex = value.slice(4);
        if (!scriptHex) refuse("SAFE_JSON_INVALID", path + " carries an empty script");
        return { version: version, scriptHex: scriptHex };
      }

      var inputs = safe.inputs.map(function (input, i) {
        var ip = "safeTx.inputs[" + i + "]";
        requireKeys(input, ["transactionId", "index", "sequence", "sigOpCount", "computeBudget", "signatureScript", "utxo"], ip);
        hex64(input.transactionId, ip + ".transactionId", "SAFE_JSON_INVALID");
        if (!Number.isInteger(input.index) || input.index < 0 || input.index > 0xffffffff) refuse("SAFE_JSON_INVALID", ip + ".index out of range");
        digitsToBigInt(input.sequence, ip + ".sequence", "SAFE_JSON_INVALID");
        if (input.sigOpCount !== 0) refuse("SAFE_JSON_INVALID", ip + ".sigOpCount must be 0 for a version-1 frozen transaction");
        if (!Number.isInteger(input.computeBudget) || input.computeBudget < 0 || input.computeBudget > 0xffff) refuse("SAFE_JSON_INVALID", ip + ".computeBudget out of range");
        if (input.signatureScript !== "") refuse("SAFE_JSON_INVALID", ip + ".signatureScript must be empty — this must be the UNSIGNED frozen transaction");
        requireKeys(input.utxo, ["address", "amount", "scriptPublicKey", "blockDaaScore", "isCoinbase", "covenantId"], ip + ".utxo");
        if (input.utxo.address !== null && typeof input.utxo.address !== "string") refuse("SAFE_JSON_INVALID", ip + ".utxo.address must be null or a string");
        if (input.utxo.isCoinbase !== false) refuse("SAFE_JSON_INVALID", ip + ".utxo.isCoinbase must be false");
        digitsToBigInt(input.utxo.amount, ip + ".utxo.amount", "SAFE_JSON_INVALID");
        digitsToBigInt(input.utxo.blockDaaScore, ip + ".utxo.blockDaaScore", "SAFE_JSON_INVALID");
        var spk = splitSpk(input.utxo.scriptPublicKey, ip + ".utxo.scriptPublicKey");
        var covenantId = null;
        if (input.utxo.covenantId !== null) {
          covenantId = hex64(input.utxo.covenantId, ip + ".utxo.covenantId", "SAFE_JSON_INVALID");
        } else if (
          known &&
          known.outpoint &&
          input.transactionId === known.outpoint.transactionId &&
          input.index === known.outpoint.index
        ) {
          covenantId = known.covenantId; // client-knowledge classification
        }
        return {
          previousOutpoint: { transactionId: input.transactionId, index: input.index },
          sequence: input.sequence,
          computeBudget: input.computeBudget,
          utxo: {
            amount: input.utxo.amount,
            scriptPublicKey: { version: spk.version, scriptHex: spk.scriptHex },
            covenantId: covenantId,
            blockDaaScore: input.utxo.blockDaaScore
          }
        };
      });

      var outputs = safe.outputs.map(function (output, i) {
        var op = "safeTx.outputs[" + i + "]";
        requireKeys(output, ["value", "scriptPublicKey", "covenant"], op);
        digitsToBigInt(output.value, op + ".value", "SAFE_JSON_INVALID");
        var spk = splitSpk(output.scriptPublicKey, op + ".scriptPublicKey");
        var covenant = null;
        if (output.covenant !== null) {
          requireKeys(output.covenant, ["authorizingInput", "covenantId"], op + ".covenant");
          if (!Number.isInteger(output.covenant.authorizingInput) || output.covenant.authorizingInput < 0 || output.covenant.authorizingInput > 0xffff) {
            refuse("SAFE_JSON_INVALID", op + ".covenant.authorizingInput out of range");
          }
          covenant = {
            authorizingInput: output.covenant.authorizingInput,
            covenantId: hex64(output.covenant.covenantId, op + ".covenant.covenantId", "SAFE_JSON_INVALID")
          };
        }
        return {
          value: output.value,
          scriptPublicKey: { version: spk.version, scriptHex: spk.scriptHex },
          covenant: covenant
        };
      });

      return {
        txId: txId,
        version: 1,
        inputs: inputs,
        outputs: outputs,
        lockTime: safe.lockTime,
        subnetworkId: NATIVE_SUBNETWORK,
        gas: "0",
        payload: ""
      };
    }

    /* ---------------- client vault knowledge ---------------- */

    /*
     * Parse the vault presentation the user is looking at (server
     * /api/v1/vaults document, presentVaultV4 shape) into the exact state
     * tuple + agent policy leaves. Server-served chain reads: this is the
     * client's PRIOR knowledge, captured before the signing payload
     * existed. KAS display strings are converted back to integer sompi
     * losslessly (sompiToKas emits canonical <=8-decimal strings).
     */
    function knowledgeFromVault(vault) {
      if (!isPlainObject(vault)) refuse("VAULT_KNOWLEDGE_MISSING", "no client-side vault knowledge is available for this action");
      if (!isPlainObject(vault.live)) refuse("VAULT_KNOWLEDGE_MISSING", "the client's vault view carries no live state (closed or unknown vault)");
      var live = vault.live;
      var slots = Array.isArray(vault.approverSlots) ? vault.approverSlots.slice() : [];
      if (slots.length !== 10) refuse("VAULT_KNOWLEDGE_MISSING", "the client's vault view carries no 10-slot approver layout");
      for (var i = 0; i < 10; i++) hex64(slots[i], "vault.approverSlots[" + i + "]");
      var state = {
        protectedValue: kasToSompi(live.protectedValueKas, "vault.live.protectedValueKas").toString(),
        feeReserve: kasToSompi(live.feeReserveKas, "vault.live.feeReserveKas").toString(),
        paused: live.paused === true ? "1" : "0",
        agentRoot: hex64(live.agentRoot, "vault.live.agentRoot"),
        approverSlots: slots,
        approvalM: digitsToBigInt(String(live.approvalM), "vault.live.approvalM").toString(),
        policyNonce: digitsToBigInt(String(live.policyNonce), "vault.live.policyNonce").toString()
      };
      var outpoint = live.outpoint;
      if (!isPlainObject(outpoint) || !Number.isInteger(outpoint.index)) refuse("VAULT_KNOWLEDGE_MISSING", "the client's vault view carries no live outpoint");
      var policies = {};
      var registries = {};
      var agents = Array.isArray(vault.agents) ? vault.agents : [];
      for (var a = 0; a < agents.length; a++) {
        var ag = agents[a];
        var pk = hex64(ag.agentPk, "vault.agents[" + a + "].agentPk");
        if (policies[pk]) {
          refuse("VAULT_KNOWLEDGE_MISSING", "the client's vault view lists agent " + pk + " twice — refusing an ambiguous registry");
        }
        policies[pk] = {
          agentPk: pk,
          maxPerSpend: kasToSompi(ag.maxPerSpendKas, "agent.maxPerSpendKas").toString(),
          periodBudget: kasToSompi(ag.periodBudgetKas, "agent.periodBudgetKas").toString(),
          periodLengthDaa: digitsToBigInt(String(ag.periodLengthDaa), "agent.periodLengthDaa").toString(),
          periodStartDaa: digitsToBigInt(String(ag.periodStartDaa), "agent.periodStartDaa").toString(),
          periodSpent: kasToSompi(ag.periodSpentKas, "agent.periodSpentKas").toString(),
          approvalThreshold: kasToSompi(ag.approvalThresholdKas, "agent.approvalThresholdKas").toString(),
          agentMaxFeePerTx: kasToSompi(ag.agentMaxFeePerTxKas, "agent.agentMaxFeePerTxKas").toString(),
          agentRecipientRoot: hex64(ag.agentRecipientRoot, "agent.agentRecipientRoot")
        };
        registries[pk] = Array.isArray(ag.recipients) ? ag.recipients.slice() : [];
      }

      /* Version gate BEFORE any recompute: tree-construction rules are
       * v4-family-specific; an unknown or older covenant version must
       * never be recomputed under a defaulted rule set. */
      var contractVersion = String(vault.contractVersion);
      if (MERKLE_RECOMPUTABLE_VERSIONS.indexOf(contractVersion) < 0) {
        refuse("UNSUPPORTED_COVENANT_VERSION", "the client's vault view carries covenant version " + JSON.stringify(contractVersion) + ", whose Merkle commitments this verifier cannot independently recompute — failing closed (unknown versions never route to a default)");
      }

      /* INDEPENDENT RECOMPUTATION: the FULL displayed agent policy set
       * must hash to EXACTLY the covenant state's agent-registry root. A
       * hidden extra agent, a missing agent, or any altered policy field
       * (limits, budgets, accounting, allowlist root) changes the
       * recomputed root and refuses. */
      var policyList = [];
      for (var pl in policies) {
        if (Object.prototype.hasOwnProperty.call(policies, pl)) policyList.push(policies[pl]);
      }
      var agentTree = rebuildAgentTree(policyList, "the client's vault view");
      if (agentTree.root !== state.agentRoot) {
        refuse("AGENT_REGISTRY_ROOT_MISMATCH", "the agent registry displayed to you (recomputed root " + agentTree.root + ") does not match the covenant state's agent-registry commitment (" + state.agentRoot + ") — the vault view and the enforced policy disagree; do not sign against this view");
      }

      /* INDEPENDENT STATE-ID RECOMPUTATION: the vault view's stateId must
       * BE the canonical commitment of the displayed state tuple
       * (recomputed with the same module + formula the SDK uses). A view
       * whose id and state disagree is stale or tampered — never sign
       * against it. (The view's networkId feeds the commitment and is
       * separately cross-checked against the wallet session network.) */
      var vaultOwner = hex64(vault.owner, "vault.owner");
      var vaultIdHex = hex64(vault.vaultId, "vault.vaultId");
      var liveStateId = hex64(live.stateId, "vault.live.stateId");
      var normalizedState = normalizeStateStrict(state, "the client's vault view state");
      var recomputedStateId = recomputeStateId(String(vault.networkId), vaultOwner, vaultIdHex, normalizedState, contractVersion, "predecessor");
      if (recomputedStateId !== liveStateId) {
        refuse("STATE_ID_MISMATCH", "the vault view's stateId (" + liveStateId + ") is not the canonical commitment of the displayed state (recomputed " + recomputedStateId + ") — the view is internally inconsistent; do not sign against it");
      }

      return {
        vaultId: vaultIdHex,
        owner: vaultOwner,
        contractVersion: contractVersion,
        networkId: String(vault.networkId),
        state: state,
        normalizedState: normalizedState,
        stateId: liveStateId,
        outpoint: { transactionId: hex64(outpoint.transactionId, "vault.live.outpoint.transactionId"), index: outpoint.index },
        covenantId: hex64(live.covenantId, "vault.live.covenantId"),
        policies: policies,
        recipientLists: registries,
        agentTree: agentTree
      };
    }

    /* ---------------- requested-intent capture ---------------- */

    var HIGH_LEVEL = { addAgent: true, removeAgent: true, rotateAgent: true, rePolicyAgent: true };

    /*
     * The intent params the CLIENT can pin from its own action context
     * (web/app-v4.js runFlow params — client-typed amounts, client-entered
     * recipients resolved through the server's single address boundary,
     * the connected wallet identity). Builder-determined operational
     * values (periodsElapsed, reserveConsumed) are DERIVED from the
     * observed transaction bytes. Merkle commitments are NEVER completed
     * from server claims: agent-lifecycle actions carry the client's full
     * typed agent policy (the successor root is recomputed from it), and a
     * raw ownerSetAgentRoot must carry the client's own newAgentRoot.
     */
    function clientParamsFor(action, params) {
      params = isPlainObject(params) ? params : {};
      if (action === "agentSpend") {
        return {
          agentPk: hex64(params.agentPk, "params.agentPk"),
          recipient: hex64(params.recipient, "params.recipient"),
          payAmountSompi: digitsToBigInt(String(params.payAmountSompi), "params.payAmountSompi").toString()
        };
      }
      if (action === "ownerTopUp") return { topUpAmountSompi: digitsToBigInt(String(params.topUpAmountSompi), "params.topUpAmountSompi").toString() };
      if (action === "ownerTopUpReserve") return { topUpReserveAmountSompi: digitsToBigInt(String(params.topUpReserveAmountSompi), "params.topUpReserveAmountSompi").toString() };
      if (action === "ownerSetApprovers") {
        var na = isPlainObject(params.newApprovers) ? params.newApprovers : {};
        return {
          newApproverSlots: approverSlotsFromList(na.approvers || [], "params.newApprovers.approvers"),
          newApprovalM: digitsToBigInt(String(na.approvalM), "params.newApprovers.approvalM").toString()
        };
      }
      if (action === "ownerPause" || action === "ownerUnpause" || action === "ownerRecover") return {};
      if (action === "ownerSetAgentRoot") {
        /* raw set-root: the new commitment must be the CLIENT'S OWN value —
         * never completed from a server claim (a substituted root would
         * re-key the entire agent registry). */
        return { newAgentRoot: hex64(params.newAgentRoot, "params.newAgentRoot") };
      }
      if (action === "addAgent") {
        return { agent: agentPolicyParam(params.agent, "params.agent") };
      }
      if (action === "removeAgent") {
        return { agentPk: hex64(params.agentPk, "params.agentPk") };
      }
      if (action === "rePolicyAgent") {
        var rp = { agentPk: hex64(params.agentPk, "params.agentPk"), agent: agentPolicyParam(params.agent, "params.agent") };
        if (rp.agent.agentPk !== rp.agentPk) refuse("VALUE_INVALID", "re-policy must keep the same agent key — params.agent.agentPk differs from params.agentPk");
        return rp;
      }
      if (action === "rotateAgent") {
        var rt = { agentPk: hex64(params.agentPk, "params.agentPk"), agent: agentPolicyParam(params.agent, "params.agent") };
        if (rt.agent.agentPk === rt.agentPk) refuse("VALUE_INVALID", "rotation requires a NEW agent key — params.agent.agentPk equals the current key");
        return rt;
      }
      refuse("UNKNOWN_ACTION", "unknown action " + JSON.stringify(action) + " — failing closed");
    }

    /* ---------------- derivation core ---------------- */

    function outIndexes(txDoc, predicate) {
      var out = [];
      for (var i = 0; i < txDoc.outputs.length; i++) if (predicate(txDoc.outputs[i], i)) out.push(i);
      return out;
    }

    function sumValues(list) {
      var total = 0n;
      for (var i = 0; i < list.length; i++) total += BigInt(list[i]);
      return total;
    }

    function claimHex64(value, field) {
      return hex64(value, field, "SERVER_CLAIM_INVALID");
    }

    function crossCheck(cond, detail) {
      if (!cond) refuse("REVIEW_MISMATCH", detail);
    }

    /*
     * Derive the manifest inputs for a TRANSITION request from:
     * client intent + client vault knowledge + the decoded frozen tx +
     * the request document's claims. Fail closed everywhere.
     */
    function deriveTransition(args) {
      var request = args.request;
      var knowledge = args.knowledge;
      var txDoc = args.txDoc;
      var sessionNetwork = args.sessionNetwork;
      var sessionXOnly = args.sessionXOnly;
      var role = args.role;
      var clientAction = args.clientAction;
      var clientParams = args.clientParams;
      var claims = [];
      var warnings = [];
      /* Facts this browser INDEPENDENTLY RECOMPUTED (rendered as outcome
       * notes; the predecessor registry-root and state-id identities were
       * already enforced inside knowledgeFromVault before any derivation
       * ran). */
      var recomputed = [
        "predecessor agent-registry Merkle root (the displayed registry hashes exactly to the covenant state's commitment)",
        "predecessor state id (the vault view's stateId equals the canonical commitment of the displayed state)"
      ];

      var sdkAction = HIGH_LEVEL[clientAction] ? "ownerSetAgentRoot" : clientAction;
      var review = isPlainObject(request.review) ? request.review : {};

      /* --- identity + binding pre-checks (client knowledge vs request doc) --- */
      crossCheck(request.vaultId === knowledge.vaultId, "the request targets vault " + request.vaultId + ", but the client context is vault " + knowledge.vaultId);
      crossCheck(request.networkId === sessionNetwork, "the request's network " + JSON.stringify(request.networkId) + " differs from the wallet session network " + JSON.stringify(sessionNetwork));
      crossCheck(knowledge.networkId === sessionNetwork, "the client's vault view is for network " + JSON.stringify(knowledge.networkId) + ", not the session network");
      crossCheck(request.contractVersion === knowledge.contractVersion, "the request's covenant version differs from the client's vault view");
      if (request.action !== undefined) crossCheck(request.action === clientAction, "the durable request records action " + JSON.stringify(request.action) + ", but the client requested " + JSON.stringify(clientAction));
      if (request.predecessorStateId !== undefined) crossCheck(request.predecessorStateId === knowledge.stateId, "the request was built against state " + request.predecessorStateId + ", but the client's vault view shows state " + knowledge.stateId + " — refresh and rebuild");
      if (request.covenantId !== undefined) crossCheck(request.covenantId === knowledge.covenantId, "the request's covenantId differs from the client's vault view");
      if (isPlainObject(request.predecessorOutpoint)) {
        crossCheck(
          request.predecessorOutpoint.transactionId === knowledge.outpoint.transactionId && request.predecessorOutpoint.index === knowledge.outpoint.index,
          "the request's predecessor outpoint differs from the vault's live outpoint the client knows"
        );
      }
      if (typeof sessionXOnly !== "string" || !HEX64.test(sessionXOnly)) {
        refuse("IDENTITY_UNRESOLVED", "the connected wallet's x-only identity is not resolved — refusing to verify a signing request without a known signer identity");
      }

      /* --- role pinning --- */
      var isSpend = sdkAction === "agentSpend";
      var signerXOnly;
      if (isSpend) {
        signerXOnly = clientParams.agentPk;
        if (role === "approver") {
          if (knowledge.state.approverSlots.indexOf(sessionXOnly) < 0) {
            refuse("IDENTITY_UNRESOLVED", "the connected wallet is not one of this vault's approver keys — refusing the approver signing path");
          }
        } else {
          crossCheck(sessionXOnly === clientParams.agentPk, "the connected wallet identity is not the acting agent of this spend");
        }
        if (request.agentPk !== undefined && request.agentPk !== null) crossCheck(request.agentPk === clientParams.agentPk, "the durable request's acting agent differs from the client context");
      } else {
        signerXOnly = knowledge.owner;
        crossCheck(sessionXOnly === knowledge.owner, "the connected wallet is not this vault's owner — owner operations require the owner key");
      }

      /* --- transaction facts --- */
      var totalIn = sumValues(txDoc.inputs.map(function (i) { return i.utxo.amount; }));
      var totalOut = sumValues(txDoc.outputs.map(function (o) { return o.value; }));
      if (totalOut > totalIn) refuse("VALUE_CONSERVATION_VIOLATION", "the transaction's outputs exceed its inputs");
      var fee = totalIn - totalOut;

      var covenantInputs = [];
      for (var ii = 0; ii < txDoc.inputs.length; ii++) if (txDoc.inputs[ii].utxo.covenantId !== null) covenantInputs.push(ii);
      if (covenantInputs.length !== 1 || covenantInputs[0] !== 0) {
        refuse("PREDECESSOR_MISMATCH", "no transaction input spends the vault's live outpoint the client knows (input 0 must be the covenant predecessor) — the transaction does not operate on the vault state you are looking at");
      }
      var predTotal = BigInt(knowledge.state.protectedValue) + BigInt(knowledge.state.feeReserve);
      var inputKinds = txDoc.inputs.map(function (input) { return input.utxo.covenantId === null ? "external" : "covenant"; });

      /* client-picked fuel binding (fresh flows carry the fuel the client selected) */
      if (args.clientFuel && isPlainObject(args.clientFuel.outpoint)) {
        var fuelFound = false;
        for (var fi = 0; fi < txDoc.inputs.length; fi++) {
          var pin = txDoc.inputs[fi].previousOutpoint;
          if (pin.transactionId === args.clientFuel.outpoint.transactionId && pin.index === args.clientFuel.outpoint.index) {
            fuelFound = true;
            crossCheck(txDoc.inputs[fi].utxo.amount === String(args.clientFuel.amount), "the fuel input's value differs from the UTXO the client selected");
          }
        }
        crossCheck(fuelFound, "the transaction does not spend the fuel UTXO the client selected");
      }

      var boundOut = outIndexes(txDoc, function (o) { return o.covenant !== null; });
      var terminal = sdkAction === "ownerRecover";

      /* --- per-action successor state + sections --- */
      var stateBeforeDoc = {
        outpoint: { transactionId: knowledge.outpoint.transactionId, index: knowledge.outpoint.index },
        stateId: knowledge.stateId,
        state: {
          protectedValue: knowledge.state.protectedValue,
          feeReserve: knowledge.state.feeReserve,
          paused: knowledge.state.paused,
          agentRoot: knowledge.state.agentRoot,
          approverSlots: knowledge.state.approverSlots.slice(),
          approvalM: knowledge.state.approvalM,
          policyNonce: knowledge.state.policyNonce
        }
      };

      var afterState = null;
      var afterStateNormalized = null;
      var spendAboveThreshold = null;
      var stateAfterDoc = null;
      var payment = null;
      var allowlist = null;
      var approvals = null;
      var limits = null;
      var outputKinds;
      var intentParams;
      var accounting;

      if (terminal) {
        /* ownerRecover: [recoverPayout, change]; payout = predTotal to the
         * owner. The payout facts are derived through the CANONICAL
         * transition module (recoverPlanV4 — the same module the SDK
         * builder uses). */
        var recoverPlan;
        try {
          recoverPlan = core.vaultTransitionsV4.recoverPlanV4(knowledge.normalizedState, knowledge.owner);
        } catch (te) {
          refuseFromTransition(te, "this recovery");
        }
        if (recoverPlan.payoutValue !== predTotal || recoverPlan.payoutXOnly !== knowledge.owner) {
          refuse("BROWSER_VERIFIER_INTERNAL", "terminal payout derivations disagree (canonical recovery plan vs client state totals) — refusing");
        }
        recomputed.push("terminal recovery payout (derived through the canonical transition module: protected value + fee reserve, paid to the owner)");
        outputKinds = txDoc.outputs.map(function (o) {
          return o.value === predTotal.toString() && o.scriptPublicKey.scriptHex === p2pk(knowledge.owner) && o.covenant === null ? "recoverPayout" : o.covenant !== null ? "successor" : "change";
        });
        if (outputKinds.indexOf("recoverPayout") < 0) {
          refuse("TERMINAL_PAYOUT_MISMATCH", "no output pays the vault owner exactly the vault's protected value + fee reserve (" + predTotal.toString() + " sompi) — the recovery does not return the funds you expect");
        }
        var extIn = 0n, extOutT = 0n;
        txDoc.inputs.forEach(function (input, idx) { if (inputKinds[idx] === "external") extIn += BigInt(input.utxo.amount); });
        txDoc.outputs.forEach(function (o, idx) { if (outputKinds[idx] === "change") extOutT += BigInt(o.value); });
        intentParams = {};
        accounting = {
          predecessorProtected: knowledge.state.protectedValue,
          predecessorFeeReserve: knowledge.state.feeReserve,
          payAmount: "0",
          reserveConsumed: "0",
          externalIn: extIn.toString(),
          externalOut: extOutT.toString(),
          fee: fee.toString(),
          successorProtected: "0",
          successorFeeReserve: "0",
          successorTotal: "0",
          terminalPayout: predTotal.toString()
        };
        if (review.recoveredKas !== undefined) crossCheck(kasToSompi(review.recoveredKas, "review.recoveredKas") === predTotal, "the review's recovered amount differs from the client-derived terminal payout");
      } else {
        if (boundOut.length !== 1) {
          refuse("WRONG_SUCCESSOR", "expected exactly one covenant-bound successor output, found " + boundOut.length);
        }
        var succValue = BigInt(txDoc.outputs[boundOut[0]].value);

        if (isSpend) {
          var pay = BigInt(clientParams.payAmountSompi);
          var policyBefore = knowledge.policies[clientParams.agentPk];
          if (!policyBefore) refuse("AGENT_POLICY_MISMATCH", "the acting agent is not present in the client's vault view — cannot independently bound this spend");
          var drawdown = predTotal - succValue;
          if (drawdown < pay) {
            refuse("VALUE_CONSERVATION_VIOLATION", "the covenant drawdown (" + drawdown.toString() + " sompi) is smaller than the requested payment — the successor keeps more than the request allows for");
          }
          var reserveConsumed = drawdown - pay;
          /* payment output: pays EXACTLY the client-requested recipient the
           * client-requested amount */
          var payIdx = -1;
          outputKinds = txDoc.outputs.map(function (o, idx) {
            if (o.covenant !== null) return "successor";
            if (payIdx < 0 && o.scriptPublicKey.version === 0 && o.scriptPublicKey.scriptHex === p2pk(clientParams.recipient) && o.value === pay.toString()) {
              payIdx = idx;
              return "payment";
            }
            return "change";
          });
          if (payIdx < 0) {
            refuse("HIDDEN_RECIPIENT", "no transaction output pays the requested recipient " + clientParams.recipient + " exactly " + pay.toString() + " sompi — the frozen transaction does not pay whom you asked");
          }
          var periodStart = BigInt(policyBefore.periodStartDaa);
          var periodLen = BigInt(policyBefore.periodLengthDaa);
          var lockTime = BigInt(txDoc.lockTime);
          var periods = 0n;
          if (lockTime !== 0n) {
            if (lockTime <= periodStart || (lockTime - periodStart) % periodLen !== 0n) {
              refuse("LOCKTIME_RULE_VIOLATION", "the transaction lockTime " + lockTime.toString() + " does not correspond to a whole number of budget periods after the client-known period start " + periodStart.toString());
            }
            periods = (lockTime - periodStart) / periodLen;
            if (periods > 1000n) refuse("LOCKTIME_RULE_VIOLATION", "derived periodsElapsed exceeds the covenant bound (1000)");
          }
          var newStart = periodStart, newSpent = BigInt(policyBefore.periodSpent) + pay;
          if (periods >= 1n) { newStart = periodStart + periods * periodLen; newSpent = pay; }

          /* INDEPENDENT SUCCESSOR-ROOT RECOMPUTATION: apply the covenant's
           * accounting advance to the RECOMPUTED predecessor tree (the
           * merkle module internally asserts canonical-rebuild ==
           * single-leaf-fold, the exact successor consensus enforces).
           * policyAfter is taken from the SAME derivation, so the limits
           * section and the recomputed root can never disagree. */
          var spendAdvance;
          try {
            spendAdvance = core.agentMerkle.applyAgentSpendV4(knowledge.agentTree, clientParams.agentPk, {
              newPeriodStartDaa: newStart.toString(),
              newPeriodSpent: newSpent.toString()
            });
          } catch (me) {
            if (me && me.browserRefusal) throw me;
            refuse("MERKLE_RECOMPUTE_FAILED", "could not derive the successor agent-registry root from the displayed registry: " + ((me && me.message) || String(me)));
          }
          var pa = spendAdvance.newPolicy;
          var policyAfter = {
            agentPk: pa.agentPk,
            maxPerSpend: pa.maxPerSpend.toString(),
            periodBudget: pa.periodBudget.toString(),
            periodLengthDaa: pa.periodLengthDaa.toString(),
            periodStartDaa: pa.periodStartDaa.toString(),
            periodSpent: pa.periodSpent.toString(),
            approvalThreshold: pa.approvalThreshold.toString(),
            agentMaxFeePerTx: pa.agentMaxFeePerTx.toString(),
            agentRecipientRoot: pa.agentRecipientRoot
          };

          var succAgentRoot = spendAdvance.tree.root;
          crossCheck(
            claimHex64(review.successorAgentRoot, "review.successorAgentRoot") === succAgentRoot,
            "the request's successor agent-registry root differs from the root this browser independently recomputed from the displayed registry and this spend's accounting advance"
          );
          recomputed.push("successor agent-registry Merkle root (recomputed from the displayed registry + this spend's accounting advance; the request's claim was required to match)");
          if (BigInt(knowledge.state.feeReserve) < reserveConsumed) {
            refuse("RESERVE_RULE_VIOLATION", "the derived reserve consumption (" + reserveConsumed.toString() + " sompi) exceeds the vault's fee reserve the client knows");
          }

          /* CANONICAL SUCCESSOR DERIVATION: re-derive the FULL spend
           * transition through core/model/vault-transitions-v4 — the
           * exact module the SDK builder uses. It enforces the covenant's
           * own equations (unpaused vault, per-spend cap, period budget,
           * reserve caps, positive successor, proof-verified single-leaf
           * registry advance) and yields the ONE covenant-permitted
           * successor state; any rule violation refuses here even when no
           * earlier cross-check caught it. */
          var canonicalSpend;
          try {
            var spendProof = core.agentMerkle.generateAgentProofV4(knowledge.agentTree, clientParams.agentPk);
            canonicalSpend = core.vaultTransitionsV4.agentSpendSuccessorV4(knowledge.normalizedState, {
              agentPolicy: policyBefore,
              agentProof: { siblingsHex: spendProof.siblingsHex, pathBits: spendProof.pathBits },
              payAmount: pay,
              periodsElapsed: periods,
              reserveConsumed: reserveConsumed
            });
          } catch (te) {
            refuseFromTransition(te, "this spend");
          }
          /* lockTime: the covenant CLTV bound the canonical derivation
           * requires must be exactly the payload's lockTime (periods were
           * derived FROM the payload's lockTime, so any disagreement is an
           * internal inconsistency). */
          if (canonicalSpend.successor.agentRoot !== succAgentRoot || canonicalSpend.lockTime !== lockTime) {
            refuse("BROWSER_VERIFIER_INTERNAL", "successor derivations disagree (accounting advance vs canonical transition) — refusing");
          }
          recomputed.push("successor covenant state (derived through the canonical v0.4 transition module from the client's vault view + this spend's parameters)");
          afterStateNormalized = canonicalSpend.successor;
          afterState = core.vaultStateV4.stateToJsonV4(canonicalSpend.successor);

          /* INDEPENDENT ALLOWLIST-ROOT RECOMPUTATION: membership is proven
           * under the COVENANT-COMMITTED recipient root, never against a
           * bare display list. An empty or unprovable list refuses. */
          var list = knowledge.recipientLists[clientParams.agentPk] || [];
          var recipientTree = rebuildRecipientTree(list, "the acting agent's displayed recipient allowlist");
          if (recipientTree.root !== policyBefore.agentRecipientRoot) {
            refuse("ALLOWLIST_ROOT_MISMATCH", "the recipient allowlist displayed to you (recomputed root " + recipientTree.root + ") does not match the covenant-committed allowlist root for this agent (" + policyBefore.agentRecipientRoot + ") — the display and the enforced allowlist disagree; do not sign against this view");
          }
          var listed = recipientTree.recipients.indexOf(clientParams.recipient) >= 0;
          allowlist = { agentRecipientRoot: policyBefore.agentRecipientRoot, recipientAllowlisted: listed, proofSupplied: listed };
          recomputed.push("acting agent's recipient-allowlist Merkle root (recomputed from the displayed allowlist; membership proven under the covenant-committed root)");
          var threshold = BigInt(policyBefore.approvalThreshold);
          var above = pay > threshold;
          if (canonicalSpend.aboveThreshold !== above) {
            refuse("BROWSER_VERIFIER_INTERNAL", "approval-tier derivations disagree (inline vs canonical transition) — refusing");
          }
          spendAboveThreshold = above;
          if (request.aboveThreshold !== undefined) crossCheck(request.aboveThreshold === above, "the request's approval tier does not match the client-known approval threshold");
          approvals = { aboveThreshold: above, approvalThreshold: policyBefore.approvalThreshold, requiredM: knowledge.state.approvalM };
          limits = { policyBefore: policyBefore, policyAfter: policyAfter, periodsElapsed: periods.toString() };
          payment = { recipientXOnly: clientParams.recipient, amountSompi: pay.toString(), outputIndex: payIdx };
          intentParams = {
            agentPk: clientParams.agentPk,
            recipient: clientParams.recipient,
            payAmountSompi: pay.toString(),
            periodsElapsed: periods.toString(),
            reserveConsumedSompi: reserveConsumed.toString()
          };
          var extInS = 0n, extOutS = 0n;
          txDoc.inputs.forEach(function (input, idx) { if (inputKinds[idx] === "external") extInS += BigInt(input.utxo.amount); });
          txDoc.outputs.forEach(function (o, idx) { if (outputKinds[idx] === "change") extOutS += BigInt(o.value); });
          accounting = {
            predecessorProtected: knowledge.state.protectedValue,
            predecessorFeeReserve: knowledge.state.feeReserve,
            payAmount: pay.toString(),
            reserveConsumed: reserveConsumed.toString(),
            externalIn: extInS.toString(),
            externalOut: extOutS.toString(),
            fee: fee.toString(),
            successorProtected: afterState.protectedValue,
            successorFeeReserve: afterState.feeReserve,
            successorTotal: succValue.toString(),
            terminalPayout: "0"
          };
          if (review.reserveConsumedKas !== undefined) crossCheck(kasToSompi(review.reserveConsumedKas, "review.reserveConsumedKas") === reserveConsumed, "the review's reserve consumption differs from the client-derived value");
          if (review.paymentKas !== undefined) crossCheck(kasToSompi(review.paymentKas, "review.paymentKas") === pay, "the review's payment amount differs from the client-requested amount");
          if (review.recipient !== undefined) crossCheck(review.recipient === clientParams.recipient, "the review's recipient differs from the client-requested recipient");
        } else {
          /* owner mutation: [covenant, external] -> [successor, change].
           * The successor state is DERIVED THROUGH THE CANONICAL v0.4
           * TRANSITION BUILDERS (core/model/vault-transitions-v4 — the
           * exact per-entrypoint builders the SDK's planOwnerOp uses):
           * each one changes ONLY the fields its entrypoint authorizes,
           * applies the exact production policyNonce rule, and re-runs
           * the strict state normalizer, so an ill-formed or
           * covenant-impossible successor refuses here. */
          outputKinds = txDoc.outputs.map(function (o) { return o.covenant !== null ? "successor" : "change"; });
          var st = knowledge.state;
          var canonicalOwner = null;
          if (sdkAction === "ownerTopUp") {
            try {
              canonicalOwner = core.vaultTransitionsV4.topUpSuccessorV4(knowledge.normalizedState, clientParams.topUpAmountSompi);
            } catch (te) {
              refuseFromTransition(te, "this top-up");
            }
            intentParams = { topUpAmountSompi: clientParams.topUpAmountSompi };
          } else if (sdkAction === "ownerTopUpReserve") {
            try {
              canonicalOwner = core.vaultTransitionsV4.topUpReserveSuccessorV4(knowledge.normalizedState, clientParams.topUpReserveAmountSompi);
            } catch (te) {
              refuseFromTransition(te, "this reserve top-up");
            }
            intentParams = { topUpReserveAmountSompi: clientParams.topUpReserveAmountSompi };
          } else if (sdkAction === "ownerPause" || sdkAction === "ownerUnpause") {
            try {
              canonicalOwner = core.vaultTransitionsV4.pauseSuccessorV4(knowledge.normalizedState, sdkAction === "ownerPause");
            } catch (te) {
              refuseFromTransition(te, sdkAction === "ownerPause" ? "this pause" : "this unpause");
            }
            intentParams = {};
          } else if (sdkAction === "ownerSetApprovers") {
            try {
              canonicalOwner = core.vaultTransitionsV4.setApproversSuccessorV4(knowledge.normalizedState, {
                approverSlots: clientParams.newApproverSlots.slice(),
                approvalM: clientParams.newApprovalM
              });
            } catch (te) {
              refuseFromTransition(te, "this approver change");
            }
            intentParams = { newApproverSlots: clientParams.newApproverSlots.slice(), newApprovalM: clientParams.newApprovalM };
          } else if (sdkAction === "ownerSetAgentRoot") {
            var newRoot;
            if (HIGH_LEVEL[clientAction]) {
              /* INDEPENDENT SUCCESSOR-ROOT RECOMPUTATION from the client's
               * own typed lifecycle parameters — a server-substituted
               * agent, policy, or allowlist changes the recomputed root
               * and refuses below. */
              newRoot = recomputeLifecycleRoot(clientAction, clientParams, knowledge);
              recomputed.push("successor agent-registry Merkle root (recomputed from the displayed registry + your requested " + clientAction + " parameters; the request's claim was required to match)");
            } else {
              /* raw ownerSetAgentRoot: the root IS the client's own pinned
               * parameter (clientParamsFor refused without it). */
              newRoot = clientParams.newAgentRoot;
              recomputed.push("successor agent-registry root pinned to the client's own newAgentRoot parameter (the request's claim was required to match)");
            }
            crossCheck(
              claimHex64(review.successorAgentRoot, "review.successorAgentRoot") === newRoot,
              "the request's successor agent-registry root differs from the root this browser independently derived for your requested agent change"
            );
            try {
              canonicalOwner = core.vaultTransitionsV4.setAgentRootSuccessorV4(knowledge.normalizedState, newRoot);
            } catch (te) {
              refuseFromTransition(te, "this agent-registry change");
            }
            intentParams = { newAgentRoot: newRoot };
          } else {
            refuse("UNKNOWN_ACTION", "unknown owner action " + JSON.stringify(sdkAction) + " — failing closed");
          }
          recomputed.push("successor covenant state (derived through the canonical v0.4 transition module from the client's vault view + your requested operation)");
          afterStateNormalized = canonicalOwner;
          afterState = core.vaultStateV4.stateToJsonV4(canonicalOwner);
          var extInO = 0n, extOutO = 0n;
          txDoc.inputs.forEach(function (input, idx) { if (inputKinds[idx] === "external") extInO += BigInt(input.utxo.amount); });
          txDoc.outputs.forEach(function (o, idx) { if (outputKinds[idx] === "change") extOutO += BigInt(o.value); });
          accounting = {
            predecessorProtected: st.protectedValue,
            predecessorFeeReserve: st.feeReserve,
            payAmount: "0",
            reserveConsumed: "0",
            externalIn: extInO.toString(),
            externalOut: extOutO.toString(),
            fee: fee.toString(),
            successorProtected: afterState.protectedValue,
            successorFeeReserve: afterState.feeReserve,
            successorTotal: (BigInt(afterState.protectedValue) + BigInt(afterState.feeReserve)).toString(),
            terminalPayout: "0"
          };
        }

        /* INDEPENDENT SUCCESSOR STATE-ID RECOMPUTATION: the successor
         * state id is the canonical commitment of the client-derived
         * successor state (same module + formula the SDK computes it
         * with); the request's claim must EQUAL the recomputation. */
        var successorStateId = recomputeStateId(knowledge.networkId, knowledge.owner, knowledge.vaultId, afterStateNormalized, knowledge.contractVersion, "successor");
        var claimedSuccessorStateId = claimHex64(request.successorStateId, "request.successorStateId");
        if (claimedSuccessorStateId !== successorStateId) {
          refuse("STATE_ID_MISMATCH", "the request's successorStateId (" + claimedSuccessorStateId + ") differs from the canonical commitment of the client-derived successor state (" + successorStateId + ") — the server's claimed successor is not the one your request produces");
        }
        recomputed.push("successor state id (canonical commitment of the client-derived successor state; the request's claim was required to match)");
        stateAfterDoc = { stateId: successorStateId, state: afterState };

        /* review claim binding for the values the review displays */
        if (review.policyNonceBefore !== undefined) crossCheck(String(review.policyNonceBefore) === knowledge.state.policyNonce, "the review's policyNonceBefore differs from the client's vault view");
        if (review.policyNonceAfter !== undefined) crossCheck(String(review.policyNonceAfter) === afterState.policyNonce, "the review's policyNonceAfter differs from the client-derived successor");
        if (review.protectedAfterKas !== undefined) crossCheck(kasToSompi(review.protectedAfterKas, "review.protectedAfterKas") === BigInt(afterState.protectedValue), "the review's protected-value-after differs from the client-derived successor");
        if (review.reserveAfterKas !== undefined) crossCheck(kasToSompi(review.reserveAfterKas, "review.reserveAfterKas") === BigInt(afterState.feeReserve), "the review's fee-reserve-after differs from the client-derived successor");
        if (review.successorStateId !== undefined) crossCheck(review.successorStateId === successorStateId, "the review's successorStateId differs from the request's successorStateId");
        if (sdkAction !== "ownerSetAgentRoot" && !isSpend && review.successorAgentRoot !== undefined) {
          crossCheck(review.successorAgentRoot === afterState.agentRoot, "the review claims an agent-registry change for an action that must preserve the agent registry");
        }
      }
      if (review.protectedBeforeKas !== undefined) crossCheck(kasToSompi(review.protectedBeforeKas, "review.protectedBeforeKas") === BigInt(knowledge.state.protectedValue), "the review's protected-value-before differs from the client's vault view");
      if (review.reserveBeforeKas !== undefined) crossCheck(kasToSompi(review.reserveBeforeKas, "review.reserveBeforeKas") === BigInt(knowledge.state.feeReserve), "the review's fee-reserve-before differs from the client's vault view");
      if (review.feeSompi !== undefined) crossCheck(digitsToBigInt(String(review.feeSompi), "review.feeSompi") === fee, "the review's network fee differs from the fee the transaction actually pays");

      /* --- INDEPENDENT COMPUTE-BUDGET + FEE/MASS RECOMPUTATION (the
       * canonical core modules — the exact SDK fee path) --- */
      enforceComputeBudgets(txDoc, sdkAction, spendAboveThreshold, recomputed);
      if (review.computeBudget !== undefined) {
        crossCheck(review.computeBudget === txDoc.inputs[0].computeBudget, "the review's committed compute budget differs from the budget in the transaction payload");
      }
      var feeFacts = enforceFeeRecomputation(txDoc, fee, recomputed);
      if (!feeFacts.exact) {
        claims.push("covenant-input final signature-script bytes (compiled covenant script + call encoding — not disclosed to the browser; the exact network-fee requirement is therefore BOUNDED by recomputation [enforced floor + standard-mass cap], not recomputed exactly)");
      }

      /* --- txId (F2-1, docs/postlaunch/f2-fee-state-recomputation.md):
       * the REQUIRED request.txId claim is computed by REAL consensus code
       * server-side (pv_tx_probe describe over the frozen form) and is
       * independently re-derived + enforced by the SDK finalizer before
       * broadcast (TXID_MISMATCH). Since the F2-1 follow-up, the server
       * finalize()s the UNSIGNED wasm transaction before serializing the
       * wallet payload — Kaspa txids exclude signature scripts, so the
       * payload-embedded id IS the consensus id and this verifier holds
       * it to STRICT EQUALITY with the claim: the id the wallet is about
       * to sign over must be exactly the id the manifest/audit chain and
       * the finalizer enforce. Any divergence = refuse. --- */
      var claimedTxId = claimHex64(request.txId, "request.txId");
      if (txDoc.txId !== claimedTxId) {
        refuse("TXID_MISMATCH", "the signing payload embeds transaction id " + txDoc.txId + " but the request claims " + claimedTxId + " — the wallet would sign a different transaction than the recorded one");
      }
      txDoc = Object.assign({}, txDoc, { txId: claimedTxId });
      claims.push("transaction.txId (server claim computed by real rusty-kaspa consensus code over the frozen transaction; EQUALITY-BOUND to the id embedded in the unsigned signing payload, and re-derived + enforced by the SDK finalizer before broadcast)");
      claims.push("stateBefore freshness (the vault's live state/outpoint are server-served chain reads the client fetched before this action; the displayed state CONTENT was verified by independent recomputation — agent-registry root AND state id both recomputed — but only the chain proves it is the LIVE state)");

      warnings.push({ code: "BROWSER_SERVER_CLAIMED_FIELDS", detail: "Fields adopted from server claims (cross-checked for consistency, not independently recomputed): " + claims.join("; ") });

      /* The manifest's fee cap: the client's own expectation (typed cap or
       * the 1-KAS default), TIGHTENED to the structural maximum any
       * standard transaction can be REQUIRED to pay (recomputed from the
       * canonical fee/mass constants — 0.5 KAS at current consensus
       * parameters). PolicyVault builders never overpay the requirement,
       * so a fee above the structural bound is provably rerouted value.
       * Blocking direction only. */
      var requestedFeeCap = args.maxFeeSompi !== undefined && args.maxFeeSompi !== null ? digitsToBigInt(String(args.maxFeeSompi), "maxFeeSompi") : BigInt(CLIENT_MAX_FEE_SOMPI);
      var structuralFeeCap = structuralMaxFeeSompi();
      var maxFee = (requestedFeeCap < structuralFeeCap ? requestedFeeCap : structuralFeeCap).toString();

      var requestedIntent = {
        intentVersion: "policyvault-requested-intent/1",
        networkId: sessionNetwork,
        vaultId: knowledge.vaultId,
        covenantVersion: knowledge.contractVersion,
        action: clientAction,
        params: intentParams,
        maxFeeSompi: maxFee
      };

      return {
        requestedIntent: requestedIntent,
        buildInputs: {
          requestedIntent: requestedIntent,
          network: { networkId: sessionNetwork },
          vault: { vaultId: knowledge.vaultId, owner: knowledge.owner, covenantVersion: knowledge.contractVersion, covenantId: knowledge.covenantId },
          signerXOnly: signerXOnly,
          transaction: txDoc,
          effects: { inputs: inputKinds, outputs: outputKinds },
          stateBefore: stateBeforeDoc,
          stateAfter: stateAfterDoc,
          accounting: accounting,
          payment: payment,
          allowlist: allowlist,
          approvals: approvals,
          limits: limits,
          warnings: warnings,
          unexpectedEffects: []
        },
        claims: claims,
        recomputed: recomputed
      };
    }

    /* Genesis (createVault) derivation: client form context + the genesis
     * request document. The client generated the vaultId itself and typed
     * every amount; the agent-registry root is RECOMPUTED from the
     * disclosed initialRegistry leaf tuples (residuals wave) and the
     * state id is RECOMPUTED over the resulting state (F2); the period
     * start (node DAA) and human-period→DAA normalization remain
     * server-side by design (disclosed inside the hashed tuples). */
    function deriveGenesis(args) {
      var request = args.request;
      var create = args.createContext;
      var txDoc = args.txDoc;
      var sessionNetwork = args.sessionNetwork;
      var sessionXOnly = args.sessionXOnly;
      var claims = [];
      var warnings = [];
      var recomputed = [];

      if (!isPlainObject(create)) refuse("VAULT_KNOWLEDGE_MISSING", "no client-side create context is available");
      if (typeof sessionXOnly !== "string" || !HEX64.test(sessionXOnly)) {
        refuse("IDENTITY_UNRESOLVED", "the connected wallet's x-only identity is not resolved — refusing to verify a signing request without a known signer identity");
      }
      var vaultId = hex64(create.vaultId, "createContext.vaultId (client-generated)");
      crossCheck(request.vaultId === vaultId, "the request's vaultId differs from the id this browser generated for the new vault");
      crossCheck(request.networkId === sessionNetwork, "the request's network differs from the wallet session network");
      var contractVersion = String(request.contractVersion);
      /* Version gate BEFORE any v4-family recomputation (state
       * normalization, state ids, compute-budget tiers, fee rules):
       * unknown versions never route to a default rule set. */
      if (MERKLE_RECOMPUTABLE_VERSIONS.indexOf(contractVersion) < 0) {
        refuse("UNSUPPORTED_COVENANT_VERSION", "the genesis request carries covenant version " + JSON.stringify(contractVersion) + ", whose commitments this verifier cannot independently recompute — failing closed (unknown versions never route to a default)");
      }
      if (isPlainObject(request.template)) {
        crossCheck(request.template.owner === sessionXOnly, "the server built the new vault for a different owner than the connected wallet");
        crossCheck(request.template.vaultId === vaultId, "the server's vault template carries a different vaultId than this browser generated");
      }
      /* the initial agent identity the user entered must be the one the
       * server committed into the genesis registry (v4 create = 1 agent) */
      if (create.agentXOnly !== undefined && create.agentXOnly !== null) {
        var reviewDoc = isPlainObject(request.review) ? request.review : {};
        var reviewAgents = Array.isArray(reviewDoc.agents) ? reviewDoc.agents : null;
        if (!reviewAgents) refuse("SERVER_CLAIM_INVALID", "the genesis request's review carries no agent registry to cross-check");
        crossCheck(reviewAgents.length === 1, "the genesis request commits " + (reviewAgents ? reviewAgents.length : 0) + " agents; this browser requested exactly one");
        crossCheck(isPlainObject(reviewAgents[0]) && reviewAgents[0].agentPk === hex64(create.agentXOnly, "createContext.agentXOnly"), "the genesis request's initial agent differs from the agent address you entered");
      }

      var protectedValue = kasToSompi(create.depositKas, "createContext.depositKas");
      var feeReserve = kasToSompi(create.feeReserveKas, "createContext.feeReserveKas");
      var approverSlots = approverSlotsFromList(create.approverXOnlys || [], "createContext.approverXOnlys");
      var approvalM = create.approvalM !== undefined && create.approvalM !== null ? digitsToBigInt(String(create.approvalM), "createContext.approvalM").toString() : "0";

      var serverState = isPlainObject(request.initialState) ? request.initialState : refuse("SERVER_CLAIM_INVALID", "the genesis request carries no initialState");

      /* --- INDEPENDENT GENESIS AGENT-REGISTRY ROOT RECOMPUTATION
       * (residuals wave — closes the F1 genesis residual). The genesis
       * request document DISCLOSES the initial registry's full leaf
       * tuples (`initialRegistry`: the exact nine fields the v4
       * agent-merkle leaf hash consumes, plus each agent's recipient
       * x-only keys). The browser rebuilds every allowlist root from the
       * disclosed recipient keys, rebuilds the whole agent tree from the
       * disclosed tuples, and requires initialState.agentRoot to EQUAL
       * the recomputation. Hidden, extra, or tampered tuples change the
       * recomputed root and refuse; tuple ORDER is canonicalized by the
       * tree builder (the committed set is order-free; duplicates
       * refuse), so reordering can never alter the enforced set.
       *
       * COMPAT RULE (documented, never silently weaker): the tuples are
       * REQUIRED — a v4-family genesis document without a well-formed
       * initialRegistry refuses SERVER_CLAIM_INVALID. This is compatible
       * with EVERY recorded document: initialRegistry has been part of
       * the stored v4 genesis request schema since the create flow
       * existed (sdk/src/wallet-requests-v4.js Checkpoint G), and genesis
       * verification only ever runs with a session-local createContext
       * (fresh documents from this server) — there is no old-document
       * resume path to stay compatible with. */
      var disclosedRegistry = request.initialRegistry;
      if (!Array.isArray(disclosedRegistry) || disclosedRegistry.length === 0) {
        refuse("SERVER_CLAIM_INVALID", "the genesis request does not disclose the initial agent registry's leaf tuples (initialRegistry) — the agent-registry commitment cannot be independently recomputed, and every well-formed v4 genesis document carries them; do not sign");
      }
      var genesisPolicies = [];
      for (var gi = 0; gi < disclosedRegistry.length; gi++) {
        var regEntry = disclosedRegistry[gi];
        var entryLabel = "request.initialRegistry[" + gi + "]";
        if (!isPlainObject(regEntry)) refuse("SERVER_CLAIM_INVALID", entryLabel + " is not an agent-policy object");
        var genesisPolicy = {
          agentPk: hex64(regEntry.agentPk, entryLabel + ".agentPk", "SERVER_CLAIM_INVALID"),
          maxPerSpend: digitsToBigInt(String(regEntry.maxPerSpend), entryLabel + ".maxPerSpend", "SERVER_CLAIM_INVALID").toString(),
          periodBudget: digitsToBigInt(String(regEntry.periodBudget), entryLabel + ".periodBudget", "SERVER_CLAIM_INVALID").toString(),
          periodLengthDaa: digitsToBigInt(String(regEntry.periodLengthDaa), entryLabel + ".periodLengthDaa", "SERVER_CLAIM_INVALID").toString(),
          periodStartDaa: digitsToBigInt(String(regEntry.periodStartDaa), entryLabel + ".periodStartDaa", "SERVER_CLAIM_INVALID").toString(),
          periodSpent: digitsToBigInt(String(regEntry.periodSpent), entryLabel + ".periodSpent", "SERVER_CLAIM_INVALID").toString(),
          approvalThreshold: digitsToBigInt(String(regEntry.approvalThreshold), entryLabel + ".approvalThreshold", "SERVER_CLAIM_INVALID").toString(),
          agentMaxFeePerTx: digitsToBigInt(String(regEntry.agentMaxFeePerTx), entryLabel + ".agentMaxFeePerTx", "SERVER_CLAIM_INVALID").toString(),
          agentRecipientRoot: hex64(regEntry.agentRecipientRoot, entryLabel + ".agentRecipientRoot", "SERVER_CLAIM_INVALID")
        };
        if (!Array.isArray(regEntry.recipients) || regEntry.recipients.length === 0) {
          refuse("SERVER_CLAIM_INVALID", entryLabel + " discloses no recipient allowlist keys — the tuple's allowlist commitment cannot be recomputed");
        }
        var regRecips = [];
        for (var ri = 0; ri < regEntry.recipients.length; ri++) {
          regRecips.push(hex64(regEntry.recipients[ri], entryLabel + ".recipients[" + ri + "]", "SERVER_CLAIM_INVALID"));
        }
        var regRecipTree = rebuildRecipientTree(regRecips, "the genesis registry's disclosed allowlist for agent " + genesisPolicy.agentPk);
        if (regRecipTree.root !== genesisPolicy.agentRecipientRoot) {
          refuse("ALLOWLIST_ROOT_MISMATCH", "the genesis registry's disclosed allowlist for agent " + genesisPolicy.agentPk + " (recomputed root " + regRecipTree.root + ") does not match that tuple's committed agentRecipientRoot (" + genesisPolicy.agentRecipientRoot + ") — the disclosure is internally inconsistent; do not sign");
        }
        genesisPolicies.push(genesisPolicy);
      }
      var genesisTree = rebuildAgentTree(genesisPolicies, "the genesis request's disclosed initialRegistry");
      var claimedGenesisRoot = claimHex64(serverState.agentRoot, "request.initialState.agentRoot");
      if (genesisTree.root !== claimedGenesisRoot) {
        refuse("AGENT_REGISTRY_ROOT_MISMATCH", "the genesis agent registry disclosed to you (recomputed root " + genesisTree.root + ") does not match the genesis state's agent-registry commitment (" + claimedGenesisRoot + ") — the vault would be created under a different agent policy than disclosed; do not sign");
      }
      var agentRoot = genesisTree.root;
      recomputed.push("genesis agent-registry root (rebuilt from the disclosed initialRegistry leaf tuples; every tuple's allowlist root is itself rebuilt from its disclosed recipient keys; initialState.agentRoot must EQUAL the recomputation)");

      /* The initial agent policy the user TYPED must be the one committed:
       * the browser create flow commits exactly one agent, whose identity,
       * limits, and allowlist are pinned to the form context wherever the
       * context carries them (period NORMALIZATION — human period to DAA,
       * node-derived periodStartDaa — stays server-side by design; those
       * two disclosed fields are bound by the root recomputation above and
       * shown under review.technical). */
      if (create.agentXOnly !== undefined && create.agentXOnly !== null) {
        crossCheck(genesisPolicies.length === 1, "the genesis request's initialRegistry commits " + genesisPolicies.length + " agents; this browser requested exactly one");
        crossCheck(genesisPolicies[0].agentPk === hex64(create.agentXOnly, "createContext.agentXOnly"), "the genesis registry's initial agent differs from the agent address you entered");
      }
      if (create.agentMaxPerSpendKas !== undefined && create.agentMaxPerSpendKas !== null) {
        crossCheck(genesisPolicies.length === 1 && genesisPolicies[0].maxPerSpend === kasToSompi(create.agentMaxPerSpendKas, "createContext.agentMaxPerSpendKas").toString(), "the genesis registry's per-spend cap differs from the one you entered");
      }
      if (create.agentBudgetKas !== undefined && create.agentBudgetKas !== null) {
        crossCheck(genesisPolicies.length === 1 && genesisPolicies[0].periodBudget === kasToSompi(create.agentBudgetKas, "createContext.agentBudgetKas").toString(), "the genesis registry's period budget differs from the one you entered");
      }
      if (create.agentApprovalThresholdKas !== undefined && create.agentApprovalThresholdKas !== null) {
        crossCheck(genesisPolicies.length === 1 && genesisPolicies[0].approvalThreshold === kasToSompi(create.agentApprovalThresholdKas, "createContext.agentApprovalThresholdKas").toString(), "the genesis registry's approval threshold differs from the one you entered");
      }
      if (create.agentMaxFeePerTxKas !== undefined && create.agentMaxFeePerTxKas !== null) {
        crossCheck(genesisPolicies.length === 1 && genesisPolicies[0].agentMaxFeePerTx === kasToSompi(create.agentMaxFeePerTxKas, "createContext.agentMaxFeePerTxKas").toString(), "the genesis registry's per-transaction fee cap differs from the one you entered");
      }
      if (create.agentRecipientXOnlys !== undefined && create.agentRecipientXOnlys !== null) {
        var typedRecipSet = xOnlySetFingerprint(create.agentRecipientXOnlys, "createContext.agentRecipientXOnlys");
        var committedRecipSet = xOnlySetFingerprint(disclosedRegistry[0].recipients, "request.initialRegistry[0].recipients");
        crossCheck(genesisPolicies.length === 1 && typedRecipSet === committedRecipSet, "the genesis registry's recipient allowlist differs from the recipient addresses you entered");
      }

      var initialState = {
        protectedValue: protectedValue.toString(),
        feeReserve: feeReserve.toString(),
        paused: "0",
        agentRoot: agentRoot,
        approverSlots: approverSlots,
        approvalM: approvalM,
        policyNonce: "0"
      };
      /* every client-derivable initialState field must match the server's document */
      crossCheck(String(serverState.protectedValue) === initialState.protectedValue, "the server's genesis protectedValue differs from the deposit you entered");
      crossCheck(String(serverState.feeReserve) === initialState.feeReserve, "the server's genesis feeReserve differs from the fee reserve you entered");
      crossCheck(String(serverState.paused) === "0", "the server's genesis state does not start unpaused");
      crossCheck(String(serverState.policyNonce) === "0", "the server's genesis state does not start at policyNonce 0");
      crossCheck(String(serverState.approvalM) === approvalM, "the server's genesis approval quorum differs from the one you entered");
      var serverSlots = Array.isArray(serverState.approverSlots) ? serverState.approverSlots : [];
      crossCheck(serverSlots.length === 10 && serverSlots.every(function (s, i) { return s === approverSlots[i]; }), "the server's genesis approver slots differ from the approvers you entered");

      var boundOut = outIndexes(txDoc, function (o) { return o.covenant !== null; });
      if (boundOut.length !== 1) refuse("WRONG_SUCCESSOR", "expected exactly one covenant-bound genesis vault output, found " + boundOut.length);
      var genesisOut = txDoc.outputs[boundOut[0]];
      var covenantId = genesisOut.covenant.covenantId;
      if (request.covenantId !== undefined) crossCheck(request.covenantId === covenantId, "the request's covenantId differs from the covenant binding in the transaction payload");

      var inputKinds = txDoc.inputs.map(function (input, idx) {
        if (input.utxo.covenantId !== null) refuse("ACTION_TX_SHAPE_MISMATCH", "genesis input " + idx + " carries a covenant — a new vault is funded only by ordinary UTXOs");
        return "external";
      });
      /* the client-side v4 create flow never requests agent fuel: every
       * non-covenant output must be change returning to the owner. */
      var outputKinds = txDoc.outputs.map(function (o) { return o.covenant !== null ? "genesisVault" : "change"; });

      var totalIn = sumValues(txDoc.inputs.map(function (i) { return i.utxo.amount; }));
      var totalOut = sumValues(txDoc.outputs.map(function (o) { return o.value; }));
      if (totalOut > totalIn) refuse("VALUE_CONSERVATION_VIOLATION", "the transaction's outputs exceed its inputs");
      var extOut = 0n;
      txDoc.outputs.forEach(function (o, idx) { if (outputKinds[idx] === "change") extOut += BigInt(o.value); });
      if (totalIn - (protectedValue + feeReserve) - extOut < 0n) {
        refuse("VALUE_CONSERVATION_VIOLATION", "the genesis funding does not cover the typed vault value plus change — value is leaking out of the funding");
      }

      /* --- INDEPENDENT COMPUTE-BUDGET + EXACT FEE RECOMPUTATION ---
       * A genesis transaction has ONLY ordinary inputs (enforced above),
       * every one finalized with a fixed 66-byte signature script, so its
       * final signed shape is FULLY known here: the committed budgets are
       * pinned to the ordinary tier and the network fee the payload pays
       * (inputs − outputs) must EQUAL the recomputed exact consensus
       * requirement — the same call path the SDK's genesis builder used
       * to set it. */
      enforceComputeBudgets(txDoc, null, null, recomputed);
      enforceFeeRecomputation(txDoc, totalIn - totalOut, recomputed);

      /* INDEPENDENT GENESIS STATE-ID RECOMPUTATION: the canonical
       * commitment formula (same module the SDK uses) over the
       * client-derived initial state — owner = the connected wallet,
       * vaultId = the client-generated id, network = the session network,
       * agentRoot = the registry root RECOMPUTED above from the disclosed
       * leaf tuples (residuals wave: no component of this id is a bare
       * claim any more). */
      var initialNormalized = normalizeStateStrict(initialState, "the genesis initial state");
      var genesisStateId = recomputeStateId(sessionNetwork, sessionXOnly, vaultId, initialNormalized, contractVersion, "genesis");
      recomputed.push("genesis state id (canonical commitment formula recomputed over the client-derived initial state, whose agentRoot component is itself recomputed from the disclosed registry tuples)");
      /* txId: REQUIRED and — since the F2-1 follow-up finalized the
       * unsigned payload — EQUALITY-BOUND to the payload-embedded id
       * (see the deriveTransition comment). */
      var claimedTxId = claimHex64(request.txId, "request.txId");
      if (txDoc.txId !== claimedTxId) {
        refuse("TXID_MISMATCH", "the signing payload embeds transaction id " + txDoc.txId + " but the request claims " + claimedTxId + " — the wallet would sign a different transaction than the recorded one");
      }
      txDoc = Object.assign({}, txDoc, { txId: claimedTxId });
      claims.push("transaction.txId (server claim computed by real rusty-kaspa consensus code over the frozen transaction; EQUALITY-BOUND to the id embedded in the unsigned signing payload, and re-derived + enforced by the SDK finalizer before broadcast)");
      warnings.push({ code: "BROWSER_SERVER_CLAIMED_FIELDS", detail: "Fields adopted from server claims (cross-checked for consistency, not independently recomputed): " + claims.join("; ") });

      /* Fee cap: the client's typed cap or the 1-KAS default, tightened
       * to the structural maximum (see deriveTransition). The genesis fee
       * was already EQUALITY-checked above; the cap stays as the
       * manifest-level blocking bound. */
      var requestedFeeCap = create.maxFeeSompi !== undefined && create.maxFeeSompi !== null ? digitsToBigInt(String(create.maxFeeSompi), "createContext.maxFeeSompi") : BigInt(CLIENT_MAX_FEE_SOMPI);
      var structuralFeeCap = structuralMaxFeeSompi();
      var maxFee = (requestedFeeCap < structuralFeeCap ? requestedFeeCap : structuralFeeCap).toString();

      var requestedIntent = {
        intentVersion: "policyvault-requested-intent/1",
        networkId: sessionNetwork,
        vaultId: vaultId,
        covenantVersion: contractVersion,
        action: "createVault",
        params: { owner: sessionXOnly, initialState: initialState, agentFuel: null },
        maxFeeSompi: maxFee
      };

      return {
        requestedIntent: requestedIntent,
        buildInputs: {
          requestedIntent: requestedIntent,
          network: { networkId: sessionNetwork },
          vault: { vaultId: vaultId, owner: sessionXOnly, covenantVersion: contractVersion, covenantId: covenantId },
          signerXOnly: sessionXOnly,
          transaction: txDoc,
          effects: { inputs: inputKinds, outputs: outputKinds },
          stateBefore: null,
          stateAfter: { stateId: genesisStateId, state: initialState },
          accounting: {
            predecessorProtected: "0",
            predecessorFeeReserve: "0",
            payAmount: "0",
            reserveConsumed: "0",
            externalIn: totalIn.toString(),
            externalOut: extOut.toString(),
            fee: (totalIn - (protectedValue + feeReserve) - extOut).toString(),
            successorProtected: protectedValue.toString(),
            successorFeeReserve: feeReserve.toString(),
            successorTotal: (protectedValue + feeReserve).toString(),
            terminalPayout: "0"
          },
          payment: null,
          allowlist: null,
          approvals: null,
          limits: null,
          warnings: warnings,
          unexpectedEffects: []
        },
        claims: claims,
        recomputed: recomputed
      };
    }

    /* ---------------- durable-request intent reconstruction ---------------- */

    /*
     * For RESUMED flows (an approver reviewing a pending spend; the acting
     * agent signing after approvals) the original form context is gone: the
     * intent is reconstructed from the DURABLE REQUEST the server shows
     * (review.paymentKas / review.recipient / request.agentPk). The
     * verification then proves "the transaction does exactly what the
     * displayed request claims and nothing else" against the client's own
     * vault knowledge — it cannot know what the original requester typed.
     * This provenance difference is stated in the outcome notes.
     */
    function clientParamsFromDurableRequest(request) {
      if (!isPlainObject(request)) refuse("SERVER_CLAIM_INVALID", "no durable request document");
      if (request.action !== "agentSpend") {
        refuse("UNKNOWN_ACTION", "durable-request verification supports agentSpend approval flows; got " + JSON.stringify(request.action));
      }
      var review = isPlainObject(request.review) ? request.review : {};
      var agentPk = claimHex64(request.agentPk, "request.agentPk");
      if (request.signerXOnly !== undefined) crossCheck(request.signerXOnly === agentPk, "the durable request's signer identity differs from its acting agent");
      var recipient = claimHex64(review.recipient, "review.recipient");
      if (review.paymentKas === undefined) refuse("SERVER_CLAIM_INVALID", "the durable request's review carries no payment amount");
      var pay = kasToSompi(review.paymentKas, "review.paymentKas");
      if (pay <= 0n) refuse("SERVER_CLAIM_INVALID", "the durable request's payment amount must be positive");
      return { agentPk: agentPk, recipient: recipient, payAmountSompi: pay.toString() };
    }

    /* ---------------- the total entry point ---------------- */

    /*
     * verifyBeforeSigning(args) -> outcome (TOTAL: never throws).
     *
     * args = {
     *   request         — the server request document (durable or fresh),
     *   vault           — the client's vault presentation (transitions),
     *   createContext   — the client's create-form context (genesis),
     *   clientAction / clientParams — the user's own action context
     *                     (fresh flows; omitted for resumed flows, which
     *                     reconstruct intent from the durable request),
     *   clientFuel      — the fuel UTXO the client selected (owner ops),
     *   sessionNetwork, sessionXOnly, role ("agent"|"owner"|"approver"),
     *   maxFeeSompi     — optional explicit client fee cap
     * }
     *
     * outcome = { ok, verdict, lines, structured, manifest, manifestHash,
     *             txId, unsignedSafeJson, refusalCodes, failures, checks,
     *             notes }
     * outcome.ok === true ONLY on a FULL core verification pass; the exact
     * verified unsignedSafeJson string is echoed for the walletSign
     * binding gate.
     */
    function verifyBeforeSigning(args) {
      try {
        if (!core) {
          return refusalOutcome([{ code: "CORE_UNAVAILABLE", detail: "the browser core bundle (web/core-bundle.js) is not loaded — independent verification cannot run" }]);
        }
        if (!isPlainObject(args)) return refusalOutcome([{ code: "VERIFY_INPUT_INVALID", detail: "verifyBeforeSigning requires an arguments object" }]);
        var request = args.request;
        if (!isPlainObject(request) || !isPlainObject(request.transaction) || typeof request.transaction.unsignedSafeJson !== "string") {
          return refusalOutcome([{ code: "VERIFY_INPUT_INVALID", detail: "the request carries no unsigned transaction payload to verify" }]);
        }
        var unsignedSafeJson = request.transaction.unsignedSafeJson;
        var sessionNetwork = args.sessionNetwork;
        if (sessionNetwork !== "testnet-10" && sessionNetwork !== "mainnet") {
          return refusalOutcome([{ code: "NETWORK_MISMATCH", detail: "the wallet session network " + JSON.stringify(sessionNetwork) + " is not an operational PolicyVault network" }]);
        }

        var derived;
        var notes = [];
        var isGenesis = request.action === "createVault" || request.kind === "genesis";
        if (isGenesis) {
          var txDocG = decodeUnsignedSafeTransaction(unsignedSafeJson, null);
          derived = deriveGenesis({ request: request, createContext: args.createContext, txDoc: txDocG, sessionNetwork: sessionNetwork, sessionXOnly: args.sessionXOnly });
        } else {
          var knowledge = knowledgeFromVault(args.vault);
          var txDoc = decodeUnsignedSafeTransaction(unsignedSafeJson, { outpoint: knowledge.outpoint, covenantId: knowledge.covenantId });
          var clientAction, clientParams;
          if (args.clientAction !== undefined) {
            clientAction = args.clientAction;
            clientParams = clientParamsFor(clientAction, args.clientParams);
            notes.push("Requested intent source: this browser's own action context (the values you entered).");
          } else {
            clientAction = "agentSpend";
            clientParams = clientParamsFromDurableRequest(request);
            notes.push("Requested intent source: the durable server request being reviewed (resumed flow) — verification proves the transaction does exactly what the displayed request claims; the original requester's typed intent is not available to this browser.");
          }
          derived = deriveTransition({
            request: request,
            knowledge: knowledge,
            txDoc: txDoc,
            sessionNetwork: sessionNetwork,
            sessionXOnly: args.sessionXOnly,
            role: args.role || (clientAction === "agentSpend" ? "agent" : "owner"),
            clientAction: clientAction,
            clientParams: clientParams,
            clientFuel: args.clientFuel,
            maxFeeSompi: args.maxFeeSompi
          });
        }

        /* build + verify through the portable core (byte-identical to Node) */
        var manifest = core.intent.buildIntentManifest(derived.buildInputs);
        var verification = core.intent.verifyIntentManifest({
          manifest: manifest,
          requestedIntent: derived.requestedIntent,
          decodedTransaction: derived.buildInputs.transaction
        });
        var structured = core.intentExplain.structured({ manifest: manifest, verification: verification });
        var lines = core.intentExplain.humanReadable({ manifest: manifest, verification: verification });

        if (verification.ok !== true || structured.verdict !== "VERIFIED_EXACT") {
          var failures = [];
          var vf = verification.failures || [];
          for (var i = 0; i < vf.length; i++) failures.push({ code: vf[i].code, detail: vf[i].detail || "" });
          if (failures.length === 0 && structured.refusal && Array.isArray(structured.refusal.failures)) {
            for (var si = 0; si < structured.refusal.failures.length; si++) {
              failures.push({ code: structured.refusal.failures[si].code, detail: structured.refusal.failures[si].detail || "" });
            }
          }
          if (failures.length === 0) failures.push({ code: "REFUSED", detail: "verification refused without detail" });
          return deepFreeze({
            ok: false,
            verdict: "REFUSED",
            refusalCodes: uniqueCodes(failures),
            failures: failures,
            lines: lines.slice(),
            structured: structured,
            manifest: manifest,
            manifestHash: verification.manifestHash || null,
            txId: verification.txId || null,
            unsignedSafeJson: null,
            checks: verification.checks,
            notes: notes
          });
        }

        return deepFreeze({
          ok: true,
          verdict: "VERIFIED_EXACT",
          refusalCodes: [],
          failures: [],
          lines: lines.slice(),
          structured: structured,
          manifest: manifest,
          manifestHash: verification.manifestHash,
          txId: verification.txId,
          unsignedSafeJson: unsignedSafeJson,
          checks: verification.checks,
          notes: notes
            .concat((derived.recomputed || []).map(function (r) { return "Independently recomputed in this browser: " + r; }))
            .concat(derived.claims.map(function (c) { return "Server-claimed (cross-checked, not recomputed): " + c; }))
        });
      } catch (e) {
        if (e && e.browserRefusal) {
          return refusalOutcome([{ code: e.code, detail: e.detail }]);
        }
        /* Coded refusals thrown by the portable core (buildIntentManifest /
         * validators: SCHEMA_INVALID, VALUE_INVALID, UNKNOWN_ACTION, ...)
         * surface their own code; anything uncoded is an internal error —
         * and an error is never a pass. */
        if (e && typeof e.code === "string" && /^[A-Z][A-Z0-9_]*$/.test(e.code)) {
          return refusalOutcome([{ code: e.code, detail: (e.message || e.code) }]);
        }
        return refusalOutcome([{ code: "BROWSER_VERIFIER_INTERNAL", detail: "in-browser verification failed internally: " + ((e && e.message) || String(e)) + " — an error is never a pass" }]);
      }
    }

    function uniqueCodes(failures) {
      var codes = [];
      for (var i = 0; i < failures.length; i++) if (codes.indexOf(failures[i].code) < 0) codes.push(failures[i].code);
      return codes.sort();
    }

    return Object.freeze({
      CLIENT_MAX_FEE_SOMPI: CLIENT_MAX_FEE_SOMPI,
      decodeUnsignedSafeTransaction: function (json, known) {
        /* thin throwing wrapper is internal; expose a total variant */
        try {
          return { ok: true, transaction: decodeUnsignedSafeTransaction(json, known) };
        } catch (e) {
          if (e && e.browserRefusal) return { ok: false, code: e.code, detail: e.detail };
          return { ok: false, code: "BROWSER_VERIFIER_INTERNAL", detail: (e && e.message) || String(e) };
        }
      },
      verifyBeforeSigning: verifyBeforeSigning
    });
  }

  var auto = null;
  if (typeof window !== "undefined" && window.PolicyVaultCore) {
    auto = createVerifyIntent(window.PolicyVaultCore);
  } else if (typeof window !== "undefined") {
    /* verify-intent loaded without the core bundle: still installed, and
     * every verification call refuses (fail closed) — the presence of this
     * module makes pre-sign verification MANDATORY in app-v4.js. */
    auto = createVerifyIntent(null);
  }
  if (typeof window !== "undefined" && auto) window.PolicyVaultVerifyIntent = auto;
  if (typeof module !== "undefined" && module.exports) module.exports = { createVerifyIntent: createVerifyIntent };
})();
