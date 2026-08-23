"use strict";
// Generator for contracts/PolicyVault.v0.3.sil — emits the repetitive
// 10-approver-slot parts exactly (10 fields, 10 preservation requires, 10
// approval counts, 45 pairwise distinctness checks) so they are correct by
// construction. NOT run at build/consensus time; a source-authoring tool.
const N = 10;
const ZERO = "0x" + "00".repeat(32);
const out = [];
const P = (s = "") => out.push(s);

P("pragma silverscript ^0.1.0;");
P("");
P("/*");
P(" * PolicyVault v0.3");
P(" *");
P(" * Extends v0.2 with (a) a scalable SHA-256 Merkle recipient allowlist");
P(" * (recipientRoot in mutable state; up to 65,536 recipients, proof depth");
P(" * <= 16) and (b) covenant-enforced M-of-N approval thresholds over up to");
P(" * 10 fixed distinct approver slots.");
P(" *");
P(" * Immutable template: owner, vaultId. Everything else is mutable");
P(" * owner-guarded state; every transition constrains EVERY state field");
P(" * explicitly (Phase 3.5 transition table). No owner/governance path");
P(" * resets period accounting; principal moves only through spend/top-up/");
P(" * terminal recovery.");
P(" *");
P(" * Phase 3.5 funds-critical rules (VM-proven):");
P(" *  - A7 sighash gate: every approval is a byte[] required to be exactly");
P(" *    65 bytes ending in 0x01 (SIG_HASH_ALL) before checkSig, so an");
P(" *    approval binds the exact transaction (a SIG_HASH_NONE approval");
P(" *    cannot authorize an unseen payment).");
P(" *  - A2 distinctness: ownerSetApprovers rejects any duplicate active");
P(" *    approver key (all 45 pairs checked); sentinel slots (all-zero");
P(" *    pubkey) never count and never collide.");
P(" *");
P(" * Security boundary: Kaspa consensus. A holder of the real delegate key");
P(" * bypassing the app and submitting directly to a node must still be");
P(" * bounded by every rule below.");
P(" */");

// ---- constructor params
const ctor = [
  "pubkey owner",
  "byte[32] vaultId",
  "pubkey initDelegate",
  "int initMaxPerSpend",
  "int initPeriodBudget",
  "int initPeriodLengthDaa",
  "byte[32] initRecipientRoot",
];
for (let i = 1; i <= N; i++) ctor.push(`pubkey initApprover${i}`);
ctor.push("int initApprovalM");
ctor.push("int initApprovalThresholdAmount");
ctor.push("int initValue");
ctor.push("int initPeriodStartDaa");
P("contract PolicyVault(");
P("    " + ctor.join(",\n    "));
P(") {");

// ---- state fields (exact-live-state: initializers are templated by the SDK/harness)
P("    byte[32] boundVaultId = vaultId;");
P("    int protectedValue = initValue;");
P("    int periodStartDaa = initPeriodStartDaa;");
P("    int periodSpent = 0;");
P("    int paused = 0;");
P("    pubkey delegate = initDelegate;");
P("    int delegateActive = 1;");
P("    int maxPerSpend = initMaxPerSpend;");
P("    int periodBudget = initPeriodBudget;");
P("    int periodLengthDaa = initPeriodLengthDaa;");
P("    byte[32] recipientRoot = initRecipientRoot;");
for (let i = 1; i <= N; i++) P(`    pubkey approver${i} = initApprover${i};`);
P("    int approvalM = initApprovalM;");
P("    int approvalThresholdAmount = initApprovalThresholdAmount;");
P("    int policyNonce = 0;");
P("");

// ---- helpers
P("    /* Exact single authorized successor value at the auth output. */");
P("    function requireExactSuccessorValue(int exactValue) {");
P("        int successorIndex = OpAuthOutputIdx(this.activeInputIndex, 0);");
P("        require(tx.outputs[successorIndex].value == exactValue);");
P("    }");
P("");
P("    /* Identity + principal + period accounting preserved exactly. */");
P("    function requireAccountingPreserved(State prevState, State newState) {");
P("        require(newState.boundVaultId == prevState.boundVaultId);");
P("        require(newState.protectedValue == prevState.protectedValue);");
P("        require(newState.periodStartDaa == prevState.periodStartDaa);");
P("        require(newState.periodSpent == prevState.periodSpent);");
P("        requireExactSuccessorValue(newState.protectedValue);");
P("    }");
P("");
P("    /* Spend-limit policy fields preserved exactly. */");
P("    function requireLimitsPreserved(State prevState, State newState) {");
P("        require(newState.maxPerSpend == prevState.maxPerSpend);");
P("        require(newState.periodBudget == prevState.periodBudget);");
P("        require(newState.periodLengthDaa == prevState.periodLengthDaa);");
P("    }");
P("");
P("    /* Delegate identity/status preserved exactly. */");
P("    function requireDelegatePreserved(State prevState, State newState) {");
P("        require(newState.delegate == prevState.delegate);");
P("        require(newState.delegateActive == prevState.delegateActive);");
P("    }");
P("");
P("    /* Recipient commitment preserved exactly. */");
P("    function requireRecipientRootPreserved(State prevState, State newState) {");
P("        require(newState.recipientRoot == prevState.recipientRoot);");
P("    }");
P("");
P("    /* Approver configuration preserved exactly. */");
P("    function requireApproversPreserved(State prevState, State newState) {");
for (let i = 1; i <= N; i++) P(`        require(newState.approver${i} == prevState.approver${i});`);
P("        require(newState.approvalM == prevState.approvalM);");
P("        require(newState.approvalThresholdAmount == prevState.approvalThresholdAmount);");
P("    }");
P("");
P("    /* 1 if the slot holds a real (non-sentinel) approver key, else 0. */");
P("    function isActiveApprover(pubkey approver) : (int) {");
P("        int active = 0;");
P(`        if (bytes(approver) != bytes(${ZERO})) {`);
P("            active = 1;");
P("        }");
P("        return active;");
P("    }");
P("");
P("    /*");
P("     * Count the approval slot at byte `offset` in the 650-byte blob.");
P("     * Extracting the slot INSIDE this helper (rather than pre-splitting");
P("     * all 10 slots in requireApprovals) keeps the caller's stack small");
P("     * (limit 244). Sentinel slots never count. Active slots MUST carry a");
P("     * 65-byte SIG_HASH_ALL signature (trailing byte 0x01, A7 gate) or the");
P("     * canonical placeholder (…0x01, which fails verification and counts");
P("     * 0). Returns 0 or 1.");
P("     */");
P("    function countApprovalAt(pubkey approver, byte[] approvals, int offset) : (int) {");
P("        int result = 0;");
P(`        if (bytes(approver) != bytes(${ZERO})) {`);
P("            (byte[] beforeSlot, byte[] fromSlot) = approvals.split(offset);");
P("            (byte[] approval, byte[] afterSlot) = fromSlot.split(65);");
P("            (byte[] approvalBody, byte[] approvalHashByte) = approval.split(64);");
P("            require(approvalHashByte == bytes(0x01));");
P("            if (checkSig(sig(approval), approver)) {");
P("                result = 1;");
P("            }");
P("        }");
P("        return result;");
P("    }");
P("");
P("    /*");
P("     * Two approver slots must not hold the same active key (A2). Byte");
P("     * EQUALITY only — Kaspa's `<` is numeric (max 8 bytes) and aborts");
P("     * (NumberTooBig) on 32-byte keys, so ordering cannot be used; 45");
P("     * pairwise inequality checks cover all C(10,2) pairs. Sentinel");
P("     * (all-zero) slots are skipped so multiple inactive slots are fine.");
P("     */");
P("    function requireDistinctOrInactive(pubkey x, pubkey y) {");
P(`        if (bytes(x) != bytes(${ZERO})) {`);
P(`            if (bytes(y) != bytes(${ZERO})) {`);
P("                require(bytes(x) != bytes(y));");
P("            }");
P("        }");
P("    }");
P("");
P("    /*");
P("     * Verify Merkle membership of recipientPk under `root` and bind the");
P("     * exact paid output. Leaf = sha256(0x50563301 || recipientPk);");
P("     * node = sha256(left||right); depth <= 16.");
P("     */");
P("    function requireAllowedRecipient(");
P("        byte[32] root,");
P("        pubkey recipientPk,");
P("        byte[] siblings,");
P("        int pathBits,");
P("        int payAmount");
P("    ) {");
P("        require(siblings.length % 32 == 0);");
P("        require(siblings.length <= 512);");
P("        int depth = siblings.length / 32;");
P("        require(pathBits >= 0);");
P("        require(pathBits < 65536);");
P("        byte[] node = bytes(sha256(bytes(0x50563301) + bytes(recipientPk)));");
P("        byte[] rest = siblings;");
P("        int bits = pathBits;");
P("        for (level, 0, depth, 16) {");
P("            (byte[] sib, byte[] tail) = rest.split(32);");
P("            rest = tail;");
P("            if (bits % 2 == 1) {");
P("                node = bytes(sha256(sib + node));");
P("            } else {");
P("                node = bytes(sha256(node + sib));");
P("            }");
P("            bits = bits / 2;");
P("        }");
P("        require(bits == 0);");
P("        require(node == bytes(root));");
P("        require(tx.outputs[0].scriptPubKey == new ScriptPubKeyP2PK(recipientPk));");
P("        require(tx.outputs[0].value == payAmount);");
P("    }");
P("");
P("    /*");
P("     * Count approvals across all 10 slots and require >= approvalM.");
P("     * Called only when payAmount exceeds approvalThresholdAmount.");
P("     *");
P("     * SECURITY (Phase 4.5): the PREDECESSOR approver set is asserted");
P("     * well-formed here before counting, because consensus does not");
P("     * validate genesis state — a manually-created genesis UTXO could");
P("     * otherwise bake duplicate approver keys or approvalM < 1 and let one");
P("     * signer satisfy M (A2) or bypass the tier entirely. ownerSetApprovers");
P("     * enforces the same for transitions; this covers genesis too, so an");
P("     * above-threshold spend ALWAYS requires M genuinely distinct");
P("     * approver signatures regardless of how the state was created.");
P("     */");
P("    /*");
P("     * Assert the PREDECESSOR approver set is well-formed before counting:");
P("     * approvalM >= 1 and all active approver keys distinct. Consensus does");
P("     * NOT validate genesis state, so a manually-baked malformed UTXO could");
P("     * otherwise (a) carry duplicate approver keys letting one signer count");
P("     * multiple times, or (b) carry approvalM < 1 so count >= M is trivially");
P("     * true. M > activeCount needs no explicit check: the max achievable");
P("     * count is the active-approver count, so count >= M then fails closed");
P("     * (above-threshold spends become impossible; owner recovery still");
P("     * works — funds never trapped). Kept lean to stay within stack limit 244.");
P("     */");
P("    function requireApproverSetWellFormed(State prevState) {");
P("        require(prevState.approvalM >= 1);");
for (let i = 1; i <= N; i++) {
  for (let j = i + 1; j <= N; j++) {
    P(`        requireDistinctOrInactive(prevState.approver${i}, prevState.approver${j});`);
  }
}
P("    }");
P("");
P("    /*");
P("     * Count approvals and require >= approvalM. The predecessor approver");
P("     * set is asserted well-formed by the caller's early");
P("     * requireApproverSetWellFormed block (kept OUT of this heavy counting");
P("     * frame for the 244 stack limit).");
P("     */");
P("    function requireApprovals(State prevState, byte[] approvals) {");
P("        require(approvals.length == 650);");
P("        int approvals_count = 0;");
for (let i = 1; i <= N; i++) {
  P(`        (int c${i}) = countApprovalAt(prevState.approver${i}, approvals, ${(i - 1) * 65});`);
  P(`        approvals_count = approvals_count + c${i};`);
}
P("        require(approvals_count >= prevState.approvalM);");
P("    }");
P("");

// ---- delegate spend core (shared)
P("    /* Common delegate-spend successor invariants (no accounting reset). */");
P("    function requireSpendCore(State prevState, State newState, int payAmount) {");
P("        require(payAmount > 0);");
P("        require(payAmount <= prevState.maxPerSpend);");
P("        require(newState.protectedValue == prevState.protectedValue - payAmount);");
P("        require(newState.protectedValue > 0);");
P("        require(newState.paused == 0);");
P("        require(newState.boundVaultId == prevState.boundVaultId);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("    }");
P("");

// ---- delegateSpend
P("    #[covenant.singleton]");
P("    function delegateSpend(");
P("        State prevState,");
P("        State newState,");
P("        int payAmount,");
P("        pubkey recipientPk,");
P("        byte[] siblings,");
P("        int pathBits,");
P("        sig delegateSig,");
P("        byte[] approvals");
P("    ) {");
P("        require(checkSig(delegateSig, prevState.delegate));");
P("        require(prevState.delegateActive == 1);");
P("        require(prevState.paused == 0);");
P("        /* Above threshold: assert the predecessor approver set is");
P("         * well-formed EARLY (light stack frame) — genesis is not");
P("         * covenant-validated, so this guarantees M distinct approvers. */");
P("        if (payAmount > prevState.approvalThresholdAmount) {");
P("            requireApproverSetWellFormed(prevState);");
P("        }");
P("        requireSpendCore(prevState, newState, payAmount);");
P("        require(prevState.periodSpent + payAmount <= prevState.periodBudget);");
P("        require(newState.periodStartDaa == prevState.periodStartDaa);");
P("        require(newState.periodSpent == prevState.periodSpent + payAmount);");
P("        requireAllowedRecipient(prevState.recipientRoot, recipientPk, siblings, pathBits, payAmount);");
P("        if (payAmount > prevState.approvalThresholdAmount) {");
P("            requireApprovals(prevState, approvals);");
P("        }");
P("        requireExactSuccessorValue(newState.protectedValue);");
P("    }");
P("");

// ---- rolloverAndSpend
P("    #[covenant.singleton]");
P("    function rolloverAndSpend(");
P("        State prevState,");
P("        State newState,");
P("        int payAmount,");
P("        pubkey recipientPk,");
P("        byte[] siblings,");
P("        int pathBits,");
P("        int periodsElapsed,");
P("        sig delegateSig,");
P("        byte[] approvals");
P("    ) {");
P("        require(checkSig(delegateSig, prevState.delegate));");
P("        require(prevState.delegateActive == 1);");
P("        require(prevState.paused == 0);");
P("        require(periodsElapsed >= 1);");
P("        require(periodsElapsed <= 1000);");
P("        if (payAmount > prevState.approvalThresholdAmount) {");
P("            requireApproverSetWellFormed(prevState);");
P("        }");
P("        int newStart = prevState.periodStartDaa + periodsElapsed * prevState.periodLengthDaa;");
P("        require(tx.time >= newStart);");
P("        requireSpendCore(prevState, newState, payAmount);");
P("        require(payAmount <= prevState.periodBudget);");
P("        require(newState.periodStartDaa == newStart);");
P("        require(newState.periodSpent == payAmount);");
P("        requireAllowedRecipient(prevState.recipientRoot, recipientPk, siblings, pathBits, payAmount);");
P("        if (payAmount > prevState.approvalThresholdAmount) {");
P("            requireApprovals(prevState, approvals);");
P("        }");
P("        requireExactSuccessorValue(newState.protectedValue);");
P("    }");
P("");

// ---- ownerPause
P("    #[covenant.singleton]");
P("    function ownerPause(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(prevState.paused == 0);");
P("        require(newState.paused == 1);");
P("        requireAccountingPreserved(prevState, newState);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("    }");
P("");
// ---- ownerUnpause
P("    #[covenant.singleton]");
P("    function ownerUnpause(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(prevState.paused == 1);");
P("        require(newState.paused == 0);");
P("        requireAccountingPreserved(prevState, newState);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("    }");
P("");
// ---- revokeDelegate
P("    #[covenant.singleton]");
P("    function revokeDelegate(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(prevState.delegateActive == 1);");
P("        require(newState.delegateActive == 0);");
P("        require(newState.delegate == prevState.delegate);");
P("        require(newState.paused == prevState.paused);");
P("        requireAccountingPreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("    }");
P("");
// ---- rotateDelegate
P("    #[covenant.singleton]");
P("    function rotateDelegate(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(newState.delegateActive == 1);");
P("        require(newState.paused == prevState.paused);");
P("        requireAccountingPreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("    }");
P("");
// ---- ownerTopUp
P("    #[covenant.singleton]");
P("    function ownerTopUp(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(newState.protectedValue > prevState.protectedValue);");
P("        require(newState.boundVaultId == prevState.boundVaultId);");
P("        require(newState.periodStartDaa == prevState.periodStartDaa);");
P("        require(newState.periodSpent == prevState.periodSpent);");
P("        require(newState.paused == prevState.paused);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("        requireExactSuccessorValue(newState.protectedValue);");
P("    }");
P("");
// ---- migratePolicy (limits only)
P("    #[covenant.singleton]");
P("    function migratePolicy(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(newState.maxPerSpend > 0);");
P("        require(newState.periodBudget > 0);");
P("        require(newState.periodLengthDaa > 0);");
P("        require(newState.policyNonce == prevState.policyNonce + 1);");
P("        require(newState.paused == prevState.paused);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        requireAccountingPreserved(prevState, newState);");
P("    }");
P("");
// ---- ownerSetRecipientRoot
P("    #[covenant.singleton]");
P("    function ownerSetRecipientRoot(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(newState.policyNonce == prevState.policyNonce + 1);");
P("        require(newState.paused == prevState.paused);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireApproversPreserved(prevState, newState);");
P("        requireAccountingPreserved(prevState, newState);");
P("    }");
P("");
// ---- ownerSetApprovers (distinctness + M validity)
P("    #[covenant.singleton]");
P("    function ownerSetApprovers(State prevState, State newState, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(newState.policyNonce == prevState.policyNonce + 1);");
P("        require(newState.approvalThresholdAmount >= 0);");
P("        /* Active-approver count and M validity. */");
P("        int activeCount = 0;");
for (let i = 1; i <= N; i++) {
  P(`        (int active${i}) = isActiveApprover(newState.approver${i});`);
  P(`        activeCount = activeCount + active${i};`);
}
P("        require(newState.approvalM >= 1);");
P("        require(newState.approvalM <= activeCount);");
P("        /* All 45 pairs of active approver slots must be distinct (A2). */");
for (let i = 1; i <= N; i++) {
  for (let j = i + 1; j <= N; j++) {
    P(`        requireDistinctOrInactive(newState.approver${i}, newState.approver${j});`);
  }
}
P("        require(newState.paused == prevState.paused);");
P("        requireDelegatePreserved(prevState, newState);");
P("        requireLimitsPreserved(prevState, newState);");
P("        requireRecipientRootPreserved(prevState, newState);");
P("        requireAccountingPreserved(prevState, newState);");
P("    }");
P("");
// ---- ownerRecover (terminal)
P("    #[covenant.singleton(");
P("        mode = transition,");
P("        termination = allowed");
P("    )]");
P("    function ownerRecover(State prevState, State[] nextStates, sig ownerSig) : (State[]) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(nextStates.length == 0);");
P("        require(tx.outputs[0].scriptPubKey == new ScriptPubKeyP2PK(owner));");
P("        require(tx.outputs[0].value == prevState.protectedValue);");
P("        return(nextStates);");
P("    }");
P("}");

require("fs").writeFileSync(process.env.OUT, out.join("\n") + "\n");
console.log("wrote", out.length, "lines");
