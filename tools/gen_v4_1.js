"use strict";
// Deterministic generator for contracts/PolicyVault.v0.4.1.sil — the
// STANDARDNESS-REVISED covenant (docs/covenant-spec-v0.4.1.md). Same frozen
// state ABI as v0.4 (441-byte region, agent/recipient Merkle formats,
// approval machinery, fee-reserve conservation), but the six non-terminal
// owner operations (setAgentRoot/setApprovers/topUp/topUpReserve/pause/
// unpause) are consolidated behind ONE ownerControl(newState, opSelector,
// ownerSig) entrypoint with a single owner checkSig and internal dispatch.
// That cuts the static P2SH sig-op count 18 -> 13 (<= MAX_STANDARD_P2SH_SIG_
// OPS=15) so covenant spends relay on a default node. gen_v4.js remains the
// generator for the FROZEN v0.4; this file NEVER mutates v0.4 in place.
// Emits the repetitive 10-approver-slot parts (fields, preservation,
// counting, 45-pair distinctness) and the bounded Merkle walks correct by
// construction. NOT run at build/consensus time; a source-authoring tool.
// Byte-identical output (no timestamps/randomness).
// Usage: OUT=contracts/PolicyVault.v0.4.1.sil node tools/gen_v4_1.js
const N = 10;               // fixed approver slots
const AGENT_MAX_DEPTH = 12; // agent-policy tree
const AGENT_MAX_SIB = AGENT_MAX_DEPTH * 32; // 384
const RECIP_MAX_DEPTH = 16; // recipient tree (v0.3)
const RECIP_MAX_SIB = RECIP_MAX_DEPTH * 32; // 512
const ZERO = "0x" + "00".repeat(32);
const out = [];
const P = (s = "") => out.push(s);

P("pragma silverscript ^0.1.0;");
P("");
P("/*");
P(" * PolicyVault v0.4.1 — STANDARDNESS REVISION of v0.4 (docs/covenant-spec-v0.4.1.md).");
P(" *");
P(" * Identical to v0.4 EXCEPT the six non-terminal owner entrypoints are");
P(" * consolidated into ONE ownerControl(opSelector) with a single owner checkSig,");
P(" * reducing the redeem script's STATIC signature-operation count from 18 to 13");
P(" * (<= the default-node P2SH standardness limit of 15). State layout, agent/");
P(" * recipient Merkle formats, approval machinery, fee-reserve model, and the");
P(" * agentSpend + ownerRecover entrypoints are UNCHANGED. The old v0.4 covenant");
P(" * (SHA256 8f87dea...) is preserved byte-for-byte as historical evidence.");
P(" *");
P(" * Adds over v0.3, as the FINAL consensus expansion:");
P(" *  (a) a covenant-controlled FEE RESERVE — the covenant UTXO holds");
P(" *      protectedValue + feeReserve; the covenant computes the EXACT");
P(" *      network fee from full input/output value introspection and lets a");
P(" *      spend consume reserve only up to min(agentMaxFeePerTx, fee), so");
P(" *      the reserve can only ever become network fee — never a redirected");
P(" *      payment and never protected principal (FR-1);");
P(" *  (b) MULTIPLE INDEPENDENT AGENTS — each agent's full policy is one");
P(" *      authenticated Merkle leaf committed by agentRoot; per-agent");
P(" *      accounting is advanced in-covenant by recomputing agentRoot in the");
P(" *      same single-leaf Merkle update; the leaf binds the agent key so no");
P(" *      agent can inherit another's authority (MD-3).");
P(" *");
P(" * The single v0.3 delegate and its per-delegate policy move INTO the");
P(" * agent leaf, so fixed vault state shrinks. Immutable template: owner,");
P(" * vaultId. Mutable state (17 fields): boundVaultId, protectedValue,");
P(" * feeReserve, paused, agentRoot, approver1..10, approvalM, policyNonce.");
P(" *");
P(" * Reused v0.3 funds-critical rules (VM-proven), applied to v0.4:");
P(" *  - A7 sighash gate: every counted approval is a byte[] required to be");
P(" *    exactly 65 bytes ending in 0x01 (SIG_HASH_ALL) before checkSig.");
P(" *  - A2 distinctness + malformed-predecessor well-formedness on the");
P(" *    approval path (consensus does not validate genesis state).");
P(" *");
P(" * Agent-policy leaf (124-byte preimage):");
P(" *   sha256(0x50563401 || agentPk || num8(maxPerSpend) ||");
P(" *          num8(periodBudget) || num8(periodLengthDaa) ||");
P(" *          num8(periodStartDaa) || num8(periodSpent) ||");
P(" *          num8(approvalThreshold) || num8(agentMaxFeePerTx) ||");
P(" *          agentRecipientRoot)");
P(" * where num8(v) = OpNum2Bin(v, 8) (canonical fixed-width little-endian).");
P(" * Recipient leaf = sha256(0x50563301 || recipientPk) (36-byte preimage,");
P(" * v0.3). Internal node = sha256(left||right) (64-byte). Distinct preimage");
P(" * lengths (124/36/64) prevent cross-interpretation. Agent proof depth");
P(` *   <= ${AGENT_MAX_DEPTH}; recipient proof depth <= ${RECIP_MAX_DEPTH}.`);
P(" *");
P(" * Security boundary: Kaspa consensus. A holder of a legitimate agent key");
P(" * bypassing the app and submitting directly to a node is bounded by every");
P(" * rule below.");
P(" */");

// ---- constructor params (owner=0, vaultId=1 for the encoder's boundVaultId index)
const ctor = [
  "pubkey owner",
  "byte[32] vaultId",
  "byte[32] initAgentRoot",
  "int initFeeReserve",
];
for (let i = 1; i <= N; i++) ctor.push(`pubkey initApprover${i}`);
ctor.push("int initApprovalM");
ctor.push("int initValue");
P("contract PolicyVault(");
P("    " + ctor.join(",\n    "));
P(") {");

// ---- state fields (exact-live-state: initializers templated by the SDK/harness)
P("    byte[32] boundVaultId = vaultId;");
P("    int protectedValue = initValue;");
P("    int feeReserve = initFeeReserve;");
P("    int paused = 0;");
P("    byte[32] agentRoot = initAgentRoot;");
for (let i = 1; i <= N; i++) P(`    pubkey approver${i} = initApprover${i};`);
P("    int approvalM = initApprovalM;");
P("    int policyNonce = 0;");
P("");

// ---- helpers -------------------------------------------------------------
P("    /* Exact single authorized successor value at the auth output. */");
P("    function requireExactSuccessorValue(int exactValue) {");
P("        int successorIndex = OpAuthOutputIdx(this.activeInputIndex, 0);");
P("        require(tx.outputs[successorIndex].value == exactValue);");
P("    }");
P("");
P("    /* Vault-global fields preserved (all except protectedValue/feeReserve,");
P("     * which spends move, and agentRoot, which spends advance). */");
P("    function requireVaultGlobalPreserved(State prevState, State newState) {");
P("        require(newState.boundVaultId == prevState.boundVaultId);");
P("        require(newState.paused == prevState.paused);");
for (let i = 1; i <= N; i++) P(`        require(newState.approver${i} == prevState.approver${i});`);
P("        require(newState.approvalM == prevState.approvalM);");
P("        require(newState.policyNonce == prevState.policyNonce);");
P("    }");
P("");
P("    /* Approver configuration preserved exactly (owner value/pause ops). */");
P("    function requireApproversPreserved(State prevState, State newState) {");
for (let i = 1; i <= N; i++) P(`        require(newState.approver${i} == prevState.approver${i});`);
P("        require(newState.approvalM == prevState.approvalM);");
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
P("    /* Count the approval slot at byte `offset` in the 650-byte blob.");
P("     * Extracting the slot inside this helper keeps the caller's stack");
P("     * small (limit 244). Sentinel slots never count. Active slots MUST");
P("     * carry a 65-byte SIG_HASH_ALL signature (trailing 0x01, A7 gate) or");
P("     * the canonical placeholder (which fails verification, counts 0). */");
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
P("    /* Two approver slots must not hold the same active key (A2). Byte");
P("     * EQUALITY only — Kaspa's `<` is numeric (<=8 bytes) and aborts");
P("     * (NumberTooBig) on 32-byte keys, so ordering cannot be used; 45");
P("     * pairwise inequality checks cover all C(10,2) pairs. */");
P("    function requireDistinctOrInactive(pubkey x, pubkey y) {");
P(`        if (bytes(x) != bytes(${ZERO})) {`);
P(`            if (bytes(y) != bytes(${ZERO})) {`);
P("                require(bytes(x) != bytes(y));");
P("            }");
P("        }");
P("    }");
P("");
P("    /* Predecessor approver-set well-formedness (Phase 4.5 malformed-");
P("     * genesis defense): approvalM >= 1 and all active keys distinct.");
P("     * Consensus does not validate genesis state, so a manually-baked UTXO");
P("     * could otherwise let one signer satisfy M or bypass the tier. Kept in");
P("     * a light frame (called before the heavy counting frame). M >");
P("     * activeCount needs no explicit check (count caps at activeCount →");
P("     * fails closed; owner recovery still works). */");
P("    /* Distinctness checks are INLINED here (not via requireDistinctOrInactive)");
P("     * to remove one call-nesting level: this runs inside agentSpend's large");
P("     * parameter frame in the worst case, and the extra frame tipped it one");
P("     * slot over MAX_STACK_SIZE 244. Same 45-pair semantics. */");
P("    function requireApproverSetWellFormed(State prevState) {");
P("        require(prevState.approvalM >= 1);");
for (let i = 1; i <= N; i++) {
  for (let j = i + 1; j <= N; j++) {
    P(`        if (bytes(prevState.approver${i}) != bytes(${ZERO})) {`);
    P(`            if (bytes(prevState.approver${j}) != bytes(${ZERO})) {`);
    P(`                require(bytes(prevState.approver${i}) != bytes(prevState.approver${j}));`);
    P("            }");
    P("        }");
  }
}
P("    }");
P("");
P("    /* Count approvals in two 5-slot halves (each a returning helper) so");
P("     * the deepest counting frame holds 5 temporaries rather than 10 —");
P("     * required to keep the worst-case combined shape (deep agent tree +");
P("     * deep recipient proof + 10-of-10 approvals) under MAX_STACK_SIZE 244");
P("     * given agentSpend's larger parameter frame. */");
P("    function countApprovalsFirstHalf(State prevState, byte[] approvals) : (int) {");
P("        int n = 0;");
for (let i = 1; i <= N / 2; i++) {
  P(`        (int c${i}) = countApprovalAt(prevState.approver${i}, approvals, ${(i - 1) * 65});`);
  P(`        n = n + c${i};`);
}
P("        return n;");
P("    }");
P("");
P("    function countApprovalsSecondHalf(State prevState, byte[] approvals) : (int) {");
P("        int n = 0;");
for (let i = N / 2 + 1; i <= N; i++) {
  P(`        (int c${i}) = countApprovalAt(prevState.approver${i}, approvals, ${(i - 1) * 65});`);
  P(`        n = n + c${i};`);
}
P("        return n;");
P("    }");
P("");
P("    /* Count approvals across all 10 slots and require >= approvalM. */");
P("    function requireApprovals(State prevState, byte[] approvals) {");
P("        require(approvals.length == 650);");
P("        (int firstHalf) = countApprovalsFirstHalf(prevState, approvals);");
P("        (int secondHalf) = countApprovalsSecondHalf(prevState, approvals);");
P("        require(firstHalf + secondHalf >= prevState.approvalM);");
P("    }");
P("");
P("    /* Canonical agent-policy leaf (124-byte preimage, frozen). */");
P("    function agentLeaf(");
P("        pubkey agentPk,");
P("        int maxPerSpend,");
P("        int periodBudget,");
P("        int periodLengthDaa,");
P("        int periodStartDaa,");
P("        int periodSpent,");
P("        int approvalThreshold,");
P("        int agentMaxFeePerTx,");
P("        byte[32] recipientRoot");
P("    ) : (byte[]) {");
P("        byte[] leaf = bytes(sha256(");
P("            bytes(0x50563401)");
P("            + bytes(agentPk)");
P("            + OpNum2Bin(maxPerSpend, 8)");
P("            + OpNum2Bin(periodBudget, 8)");
P("            + OpNum2Bin(periodLengthDaa, 8)");
P("            + OpNum2Bin(periodStartDaa, 8)");
P("            + OpNum2Bin(periodSpent, 8)");
P("            + OpNum2Bin(approvalThreshold, 8)");
P("            + OpNum2Bin(agentMaxFeePerTx, 8)");
P("            + bytes(recipientRoot)");
P("        ));");
P("        return leaf;");
P("    }");
P("");
P("    /* Single-leaf Merkle update (FUNDS-CRITICAL), split into two");
P("     * single-node walks over the SAME co-path to bound peak stack (the");
P("     * worst-case combined shape must fit MAX_STACK_SIZE 244; a two-node");
P("     * walk holding oldNode+newNode simultaneously overflowed by one slot,");
P("     * so we walk the old leaf and the new leaf separately — identical");
P("     * computed root, lower peak). computeMerkleRoot folds `leaf` up the");
P(`     * co-path; depth <= ${AGENT_MAX_DEPTH}. */`);
P("    function computeMerkleRoot(byte[] leaf, byte[] siblings, int pathBits) : (byte[]) {");
P("        require(siblings.length % 32 == 0);");
P(`        require(siblings.length <= ${AGENT_MAX_SIB});`);
P("        int depth = siblings.length / 32;");
P("        require(pathBits >= 0);");
P(`        require(pathBits < ${1 << AGENT_MAX_DEPTH});`);
P("        byte[] node = leaf;");
P("        byte[] rest = siblings;");
P("        int bits = pathBits;");
P(`        for (level, 0, depth, ${AGENT_MAX_DEPTH}) {`);
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
P("        return node;");
P("    }");
P("");
P("    /* Verify oldLeaf is a member under `root` via the co-path. The old");
P("     * walk equalling the committed root proves the siblings are the");
P("     * authentic co-path, so reusing them for the new leaf changes exactly");
P("     * the target leaf and preserves every unrelated leaf. */");
P("    function requireAgentMembership(byte[32] root, byte[] oldLeaf, byte[] siblings, int pathBits) {");
P("        (byte[] oldRoot) = computeMerkleRoot(oldLeaf, siblings, pathBits);");
P("        require(oldRoot == bytes(root));");
P("    }");
P("");
P("    /* Authenticate the agent leaf, advance its accounting, and pin the");
P("     * successor agentRoot — all in ONE helper frame so agentSpend's own");
P("     * frame never holds the leaf/root/accounting intermediates while the");
P("     * later recipient/approval frames run (stack discipline for the 244");
P("     * worst case). Returns nothing; requires the exact successor root. */");
P("    function requireAgentTransition(");
P("        State prevState,");
P("        State newState,");
P("        int payAmount,");
P("        pubkey agentPk,");
P("        int maxPerSpend,");
P("        int periodBudget,");
P("        int periodLengthDaa,");
P("        int periodStartDaa,");
P("        int periodSpent,");
P("        int approvalThreshold,");
P("        int agentMaxFeePerTx,");
P("        byte[32] agentRecipientRoot,");
P("        byte[] policySiblings,");
P("        int policyPathBits,");
P("        int periodsElapsed");
P("    ) {");
P("        require(payAmount <= maxPerSpend);");
P("        require(periodsElapsed >= 0);");
P("        require(periodsElapsed <= 1000);");
P("        int newStart = periodStartDaa;");
P("        int newSpent = periodSpent + payAmount;");
P("        if (periodsElapsed >= 1) {");
P("            newStart = periodStartDaa + periodsElapsed * periodLengthDaa;");
P("            require(tx.time >= newStart);");
P("            newSpent = payAmount;");
P("        }");
P("        require(newSpent <= periodBudget);");
P("        (byte[] oldLeaf) = agentLeaf(agentPk, maxPerSpend, periodBudget, periodLengthDaa, periodStartDaa, periodSpent, approvalThreshold, agentMaxFeePerTx, agentRecipientRoot);");
P("        requireAgentMembership(prevState.agentRoot, oldLeaf, policySiblings, policyPathBits);");
P("        (byte[] newLeaf) = agentLeaf(agentPk, maxPerSpend, periodBudget, periodLengthDaa, newStart, newSpent, approvalThreshold, agentMaxFeePerTx, agentRecipientRoot);");
P("        (byte[] newRoot) = computeMerkleRoot(newLeaf, policySiblings, policyPathBits);");
P("        require(bytes(newState.agentRoot) == newRoot);");
P("    }");
P("");
P("    /* Recipient membership + exact output-0 binding against the LEAF's");
P("     * own recipient root (v0.3 mechanism; leaf = sha256(0x50563301||pk)).");
P(`     * Depth <= ${RECIP_MAX_DEPTH}. */`);
P("    function requireAgentRecipient(");
P("        byte[32] root,");
P("        pubkey recipientPk,");
P("        byte[] siblings,");
P("        int pathBits,");
P("        int payAmount");
P("    ) {");
P("        require(siblings.length % 32 == 0);");
P(`        require(siblings.length <= ${RECIP_MAX_SIB});`);
P("        int depth = siblings.length / 32;");
P("        require(pathBits >= 0);");
P(`        require(pathBits < ${1 << RECIP_MAX_DEPTH});`);
P("        byte[] node = bytes(sha256(bytes(0x50563301) + bytes(recipientPk)));");
P("        byte[] rest = siblings;");
P("        int bits = pathBits;");
P(`        for (level, 0, depth, ${RECIP_MAX_DEPTH}) {`);
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
P("    /* Exact network fee from full input/output value introspection.");
P("     * Bounded to <= 8 inputs and <= 8 outputs. */");
P("    function txFee() : (int) {");
P("        int inCount = tx.inputs.length;");
P("        require(inCount >= 1);");
P("        require(inCount <= 8);");
P("        int outCount = tx.outputs.length;");
P("        require(outCount >= 1);");
P("        require(outCount <= 8);");
P("        int totalIn = 0;");
P("        for (i, 0, inCount, 8) {");
P("            totalIn = totalIn + tx.inputs[i].value;");
P("        }");
P("        int totalOut = 0;");
P("        for (j, 0, outCount, 8) {");
P("            totalOut = totalOut + tx.outputs[j].value;");
P("        }");
P("        require(totalOut <= totalIn);");
P("        int fee = totalIn - totalOut;");
P("        return fee;");
P("    }");
P("");
P("    /* Principal + fee-reserve conservation (FR-1). reserveConsumed is");
P("     * bounded by the spending agent's own agentMaxFeePerTx AND by the");
P("     * actual fee; principal moves only by the exact payment. */");
P("    function requireFeeAndPrincipal(State prevState, State newState, int payAmount, int agentMaxFeePerTx) {");
P("        require(newState.protectedValue == prevState.protectedValue - payAmount);");
P("        require(newState.protectedValue > 0);");
P("        require(newState.feeReserve >= 0);");
P("        int reserveConsumed = prevState.feeReserve - newState.feeReserve;");
P("        require(reserveConsumed >= 0);");
P("        require(reserveConsumed <= agentMaxFeePerTx);");
P("        (int fee) = txFee();");
P("        require(reserveConsumed <= fee);");
P("    }");
P("");

// ---- agentSpend (the one delegate/agent path; both tiers + rollover) ----
P("    #[covenant.singleton]");
P("    function agentSpend(");
P("        State prevState,");
P("        State newState,");
P("        int payAmount,");
P("        pubkey agentPk,");
P("        int maxPerSpend,");
P("        int periodBudget,");
P("        int periodLengthDaa,");
P("        int periodStartDaa,");
P("        int periodSpent,");
P("        int approvalThreshold,");
P("        int agentMaxFeePerTx,");
P("        byte[32] agentRecipientRoot,");
P("        byte[] policySiblings,");
P("        int policyPathBits,");
P("        int periodsElapsed,");
P("        pubkey recipientPk,");
P("        byte[] recipientSiblings,");
P("        int recipientPathBits,");
P("        sig agentSig,");
P("        byte[] approvals");
P("    ) {");
P("        require(prevState.paused == 0);");
P("        /* the LEAF is the sole key->policy authority */");
P("        require(checkSig(agentSig, agentPk));");
P("        require(payAmount > 0);");
P("        /* per-agent policy authentication + period accounting + successor");
P("         * root, in one helper frame (keeps agentSpend's frame light for the");
P("         * later recipient/approval frames — 244 stack discipline). */");
P("        requireAgentTransition(prevState, newState, payAmount, agentPk, maxPerSpend, periodBudget, periodLengthDaa, periodStartDaa, periodSpent, approvalThreshold, agentMaxFeePerTx, agentRecipientRoot, policySiblings, policyPathBits, periodsElapsed);");
P("        /* recipient authorization against the LEAF's own tree */");
P("        requireAgentRecipient(agentRecipientRoot, recipientPk, recipientSiblings, recipientPathBits, payAmount);");
P("        /* vault-global approver slots above the LEAF's threshold */");
P("        if (payAmount > approvalThreshold) {");
P("            requireApproverSetWellFormed(prevState);");
P("            requireApprovals(prevState, approvals);");
P("        }");
P("        /* principal + fee-reserve conservation */");
P("        requireFeeAndPrincipal(prevState, newState, payAmount, agentMaxFeePerTx);");
P("        requireVaultGlobalPreserved(prevState, newState);");
P("        requireExactSuccessorValue(newState.protectedValue + newState.feeReserve);");
P("    }");
P("");

// ---- ownerControl (v0.4.1 STANDARDNESS FIX): the SIX non-terminal owner
// operations consolidated into ONE entrypoint with a SINGLE checkSig, to keep
// the whole redeem script within the default-node P2SH standardness limit of
// 15 static signature operations. Static sig-ops: 1 (agentSpend) + 10 (approval
// slots) + 1 (ownerControl) + 1 (ownerRecover) = 13 <= 15. The opSelector
// (0..5) is a CALL ARGUMENT (not committed by SIG_HASH_ALL); each selector's
// rule set is mutually exclusive in exactly which state fields it must change
// vs. preserve, and the successor state is pinned by the signed covenant
// output, so a selector substituted after signing cannot authorize a different
// successor (VM-proven in the v0.4.1 negative matrix). Bounds checks + an
// exhaustive dispatch reject any unknown/out-of-range selector (no permissive
// default branch). Per-selector rules are byte-for-byte the old v0.4 owner
// entrypoint bodies (minus the now-shared checkSig).
P("    #[covenant.singleton]");
P("    function ownerControl(State prevState, State newState, int opSelector, sig ownerSig) {");
P("        require(checkSig(ownerSig, owner));");
P("        require(opSelector >= 0);");
P("        require(opSelector <= 5);");
P("        if (opSelector == 0) {");
P("            /* setAgentRoot: replace agentRoot; nonce +1; all else preserved */");
P("            require(newState.boundVaultId == prevState.boundVaultId);");
P("            require(newState.protectedValue == prevState.protectedValue);");
P("            require(newState.feeReserve == prevState.feeReserve);");
P("            require(newState.paused == prevState.paused);");
P("            requireApproversPreserved(prevState, newState);");
P("            require(newState.policyNonce == prevState.policyNonce + 1);");
P("        } else {");
P("        if (opSelector == 1) {");
P("            /* setApprovers: replace approver set + M; nonce +1; A2 distinctness */");
P("            require(newState.policyNonce == prevState.policyNonce + 1);");
P("            int activeCount = 0;");
for (let i = 1; i <= N; i++) {
  P(`            (int active${i}) = isActiveApprover(newState.approver${i});`);
  P(`            activeCount = activeCount + active${i};`);
}
P("            require(newState.approvalM >= 1);");
P("            require(newState.approvalM <= activeCount);");
for (let i = 1; i <= N; i++) {
  for (let j = i + 1; j <= N; j++) {
    P(`            requireDistinctOrInactive(newState.approver${i}, newState.approver${j});`);
  }
}
P("            require(newState.boundVaultId == prevState.boundVaultId);");
P("            require(newState.protectedValue == prevState.protectedValue);");
P("            require(newState.feeReserve == prevState.feeReserve);");
P("            require(newState.paused == prevState.paused);");
P("            require(newState.agentRoot == prevState.agentRoot);");
P("        } else {");
P("        if (opSelector == 2) {");
P("            /* topUp: increase protected principal only */");
P("            require(newState.protectedValue > prevState.protectedValue);");
P("            require(newState.feeReserve == prevState.feeReserve);");
P("            require(newState.boundVaultId == prevState.boundVaultId);");
P("            require(newState.paused == prevState.paused);");
P("            require(newState.agentRoot == prevState.agentRoot);");
P("            requireApproversPreserved(prevState, newState);");
P("            require(newState.policyNonce == prevState.policyNonce);");
P("        } else {");
P("        if (opSelector == 3) {");
P("            /* topUpReserve: increase fee reserve only */");
P("            require(newState.feeReserve > prevState.feeReserve);");
P("            require(newState.protectedValue == prevState.protectedValue);");
P("            require(newState.boundVaultId == prevState.boundVaultId);");
P("            require(newState.paused == prevState.paused);");
P("            require(newState.agentRoot == prevState.agentRoot);");
P("            requireApproversPreserved(prevState, newState);");
P("            require(newState.policyNonce == prevState.policyNonce);");
P("        } else {");
P("        if (opSelector == 4) {");
P("            /* pause: paused 0 -> 1 */");
P("            require(prevState.paused == 0);");
P("            require(newState.paused == 1);");
P("            require(newState.boundVaultId == prevState.boundVaultId);");
P("            require(newState.protectedValue == prevState.protectedValue);");
P("            require(newState.feeReserve == prevState.feeReserve);");
P("            require(newState.agentRoot == prevState.agentRoot);");
P("            requireApproversPreserved(prevState, newState);");
P("            require(newState.policyNonce == prevState.policyNonce);");
P("        } else {");
P("            /* opSelector == 5 (bounded to [0,5], not 0..4): unpause 1 -> 0 */");
P("            require(prevState.paused == 1);");
P("            require(newState.paused == 0);");
P("            require(newState.boundVaultId == prevState.boundVaultId);");
P("            require(newState.protectedValue == prevState.protectedValue);");
P("            require(newState.feeReserve == prevState.feeReserve);");
P("            require(newState.agentRoot == prevState.agentRoot);");
P("            requireApproversPreserved(prevState, newState);");
P("            require(newState.policyNonce == prevState.policyNonce);");
P("        }");
P("        }");
P("        }");
P("        }");
P("        }");
P("        requireExactSuccessorValue(newState.protectedValue + newState.feeReserve);");
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
P("        require(tx.outputs[0].value == prevState.protectedValue + prevState.feeReserve);");
P("        return(nextStates);");
P("    }");
P("}");

if (!process.env.OUT) {
  console.error("set OUT to the destination path");
  process.exit(1);
}
require("fs").writeFileSync(process.env.OUT, out.join("\n") + "\n");
console.log("wrote", out.length, "lines");
