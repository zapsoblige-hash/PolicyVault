"use strict";
// Deterministic generator for contracts/PolicyVault.v0.7-kas.sil — the
// v0.7 ROOTED KAS SAFE-PAYMENT PROFILE covenant CANDIDATE (contract
// `PolicyVaultRootedKas`), docs/postlaunch/v0.7-organizational-root-design.md
// sections 3, 9, 11-13, applying the SAME rooted-successor pattern the
// payment profile probed to the FROZEN v0.4.1 plain-KAS covenant instead of
// the frozen v0.5 token controller.
//
// THIS GENERATOR IS A DELTA, NOT A REWRITE. It READS the FROZEN
// contracts/PolicyVault.v0.4.1.sil, refuses to run unless that file's
// sha256 is exactly the frozen value below, and applies an explicit,
// ordered list of EXACT-MATCH edits. Every edit must match EXACTLY ONCE or
// the generator fails closed and writes nothing, so the v0.4.1 rules that
// are not named here are carried into v0.7-kas byte-for-byte by
// construction and a reviewer only has to read the deltas. The frozen file
// is opened READ-ONLY and is never written.
//
// v0.7 is a NEW additive covenant lineage: the frozen v0.4.1 KAS vault, the
// frozen v0.5/v0.6 token controllers, and the v0.7-root/v0.7-payment
// candidates are never modified.
//
// Reference: tools/gen_v7_payment.js (the byte-level root-successor pinning
// pattern this generator reuses verbatim — requireRootAuthorization, the
// ROOT_TAIL constants, requireOnlyRootCovenantInputs — applied to a
// different frozen base). This profile has no token family, so it carries
// only ONE covenant-family closure (no `requireOnlyRootAndTokenCovenantInputs`
// variant is needed: a pure-KAS terminal recovery has nothing else to admit
// beyond this covenant and the root).
//
// NOT run at build/consensus time; a source-authoring tool. Byte-identical
// output (no timestamps, no randomness, no environment except OUT).
// Usage: OUT=contracts/PolicyVault.v0.7-kas.sil node tools/gen_v7_kas.js

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/* ---------------------------------------------------------------- *
 * 1. the frozen base, verified before a single byte is transformed
 * ---------------------------------------------------------------- */

/** contracts/PolicyVault.v0.4.1.sil — BYTE-FROZEN (docs/covenant-spec-v0.4.1.md). */
const V4_1_SHA256 = "421bfed824cf66a9e989f90c5b86fc7359faa070a5d94aace3c325f35ad1da4e";
const V4_1_PATH = path.join(__dirname, "..", "contracts", "PolicyVault.v0.4.1.sil");

const base = fs.readFileSync(V4_1_PATH); // read-only; never written by this tool
const baseSha = crypto.createHash("sha256").update(base).digest("hex");
if (baseSha !== V4_1_SHA256) {
  console.error(
    `FAIL CLOSED: ${V4_1_PATH} sha256 is ${baseSha}, expected the frozen ${V4_1_SHA256}.\n` +
      "The v0.7-kas profile is DERIVED from the frozen v0.4.1 bytes; if the base drifted, " +
      "the derivation is no longer reviewable and nothing is written."
  );
  process.exit(1);
}

const ZERO = "0x" + "00".repeat(32);

/* The pinned root version's fixed-width state TAIL (see
 * contracts/PolicyVault.v0.7-root.sil and design section 9.1), IDENTICAL to
 * the constants tools/gen_v7_payment.js pins:
 *     byte    frozen     -> 0x01 || <0x00|0x01>    2 B
 *     byte[8] rootNonce  -> 0x08 || <8 LE bytes>   9 B */
const ROOT_TAIL_LEN = 11;
const ROOT_FROZEN_PUSH_LEN = 2;
const ROOT_NONCE_HEADER_LEN = 1;
/* the two successor tails this vault will accept, as raw pushes */
const PUSH_UNFROZEN = "0x0100"; // the root ran AUTHORIZE  (full quorum)
const PUSH_FROZEN = "0x0101"; // the root ran FREEZE     (emergency quorum)

const baseText = base.toString("utf8");

/* ---------------------------------------------------------------- *
 * 2. the delta
 * ---------------------------------------------------------------- */

const EDITS = [];
const edit = (name, from, to) => EDITS.push({ name, from, to });

/* --- E1. header + contract name + REMOVAL of `pubkey owner` ---------- */

const V4_1_HEADER = `/*
 * PolicyVault v0.4.1 — STANDARDNESS REVISION of v0.4 (docs/covenant-spec-v0.4.1.md).
 *
 * Identical to v0.4 EXCEPT the six non-terminal owner entrypoints are
 * consolidated into ONE ownerControl(opSelector) with a single owner checkSig,
 * reducing the redeem script's STATIC signature-operation count from 18 to 13
 * (<= the default-node P2SH standardness limit of 15). State layout, agent/
 * recipient Merkle formats, approval machinery, fee-reserve model, and the
 * agentSpend + ownerRecover entrypoints are UNCHANGED. The old v0.4 covenant
 * (SHA256 8f87dea...) is preserved byte-for-byte as historical evidence.
 *
 * Adds over v0.3, as the FINAL consensus expansion:
 *  (a) a covenant-controlled FEE RESERVE — the covenant UTXO holds
 *      protectedValue + feeReserve; the covenant computes the EXACT
 *      network fee from full input/output value introspection and lets a
 *      spend consume reserve only up to min(agentMaxFeePerTx, fee), so
 *      the reserve can only ever become network fee — never a redirected
 *      payment and never protected principal (FR-1);
 *  (b) MULTIPLE INDEPENDENT AGENTS — each agent's full policy is one
 *      authenticated Merkle leaf committed by agentRoot; per-agent
 *      accounting is advanced in-covenant by recomputing agentRoot in the
 *      same single-leaf Merkle update; the leaf binds the agent key so no
 *      agent can inherit another's authority (MD-3).
 *
 * The single v0.3 delegate and its per-delegate policy move INTO the
 * agent leaf, so fixed vault state shrinks. Immutable template: owner,
 * vaultId. Mutable state (17 fields): boundVaultId, protectedValue,
 * feeReserve, paused, agentRoot, approver1..10, approvalM, policyNonce.
 *
 * Reused v0.3 funds-critical rules (VM-proven), applied to v0.4:
 *  - A7 sighash gate: every counted approval is a byte[] required to be
 *    exactly 65 bytes ending in 0x01 (SIG_HASH_ALL) before checkSig.
 *  - A2 distinctness + malformed-predecessor well-formedness on the
 *    approval path (consensus does not validate genesis state).
 *
 * Agent-policy leaf (124-byte preimage):
 *   sha256(0x50563401 || agentPk || num8(maxPerSpend) ||
 *          num8(periodBudget) || num8(periodLengthDaa) ||
 *          num8(periodStartDaa) || num8(periodSpent) ||
 *          num8(approvalThreshold) || num8(agentMaxFeePerTx) ||
 *          agentRecipientRoot)
 * where num8(v) = OpNum2Bin(v, 8) (canonical fixed-width little-endian).
 * Recipient leaf = sha256(0x50563301 || recipientPk) (36-byte preimage,
 * v0.3). Internal node = sha256(left||right) (64-byte). Distinct preimage
 * lengths (124/36/64) prevent cross-interpretation. Agent proof depth
 *   <= 12; recipient proof depth <= 16.
 *
 * Security boundary: Kaspa consensus. A holder of a legitimate agent key
 * bypassing the app and submitting directly to a node is bounded by every
 * rule below.
 */
contract PolicyVault(
    pubkey owner,
    byte[32] vaultId,
    byte[32] initAgentRoot,`;

const V7_KAS_HEADER = `/*
 * PolicyVault v0.7-kas — ROOTED KAS SAFE-PAYMENT PROFILE covenant CANDIDATE
 * (docs/postlaunch/v0.7-organizational-root-design.md sections 3, 9, 11-13,
 * applying the SAME rooted-successor pattern the payment profile probed to
 * the FROZEN v0.4.1 plain-KAS covenant instead of the frozen v0.5 token
 * controller).
 *
 * GENERATED by tools/gen_v7_kas.js as an EXACT-MATCH DELTA over the FROZEN
 * contracts/PolicyVault.v0.4.1.sil (sha256
 * ${V4_1_SHA256}),
 * which is never modified. Every v0.4.1 rule not named in the delta below is
 * carried here byte-for-byte: the covenant-controlled KAS fee reserve
 * (FR-1), MULTIPLE INDEPENDENT AGENTS via the agent Merkle root, per-agent
 * period budget + rollover, the recipient Merkle allowlist, the vault-level
 * M-of-N approver tier above each agent's approvalThreshold (A2/A7), and
 * exact successor-value conservation.
 *
 * WHAT CHANGES, AND ONLY THIS:
 *   - the template constant \`pubkey owner\` is REMOVED. This vault has NO
 *     owner key and NO owner signature check anywhere. Its owner AUTHORITY
 *     is the ORGANIZATIONAL ROOT covenant (contracts/PolicyVault.v0.7-root.sil):
 *     an owner operation is valid only if the same transaction ALSO spends
 *     the pinned root, whose own script proved M-of-N (or the lighter
 *     emergency quorum for a FREEZE);
 *   - added template constants pin that root: \`orgRootCovenantId\`, its
 *     template identity \`rootTemplateVmHash\` = blake2b-256(prefix || suffix),
 *     its geometry \`rootPrefixLen\` / \`rootStateLen\` / \`rootSuffixLen\`, and
 *     \`recoveryPk\`, the cold recovery destination fixed at genesis so a
 *     hijacked quorum-signing session cannot redirect recovery — the
 *     IDENTICAL byte-level root-successor pinning
 *     contracts/PolicyVault.v0.7-payment.sil uses (\`requireRootAuthorization\`
 *     is reused verbatim);
 *   - \`ownerControl\` MERGES v0.4.1's six non-terminal owner operations
 *     (setAgentRoot/setApprovers/topUp/topUpReserve/pause/unpause,
 *     opSelector 0..5) with a new EMERGENCY pause (opSelector 6) behind ONE
 *     bounded selector 0..6, so the root-authorization block is inlined
 *     ONCE on that path. Selectors 0-5 pin an AUTHORIZE root successor
 *     (full quorum, ownerM); selector 6 is the ONLY vault effect reachable
 *     from the root's LIGHTER emergency quorum (a FREEZE root successor) —
 *     AUTHORITY-REDUCING and monotone (paused 0 -> 1, every other field
 *     preserved, policyNonce included), identical in kind to the payment
 *     profile's selector 4;
 *   - \`ownerRecover\` stays a separate termination-mode entrypoint (the
 *     second and last inline site) and pays out to the GENESIS-PINNED
 *     \`recoveryPk\` instead of the removed owner key, under the root's FULL
 *     quorum (AUTHORIZE);
 *   - \`require(periodLengthDaa > 0)\` (deviation D2, the same v0.6
 *     adversarial-review hardening already applied to the payment profile)
 *     hardens the agent path in requireAgentTransition.
 *
 * WHY THIS PROFILE EXISTS SEPARATELY FROM v0.7-payment. An organization
 * that only needs covenant-level M-of-N ownership over KAS treasury spend
 * policy — per-agent caps, period budgets, a recipient allowlist, and a
 * vault-level M-of-N approval tier above a threshold — has no reason to
 * carry the TRANSACTION-DERIVED VERIFIED TEMPLATE CARRIAGE / KCC20 token
 * machinery the payment profile needs; deriving from v0.4.1 instead of v0.5
 * keeps this profile's redeem exactly as large as a rooted KAS vault
 * actually needs and nothing more.
 *
 * WHY BYTES AND NOT FIELDS. Identical reasoning to the payment profile
 * (design section 9.3): SilverScript inlines a function at every call site
 * and a P2SH spend reveals the WHOLE redeem, so anything the owner path
 * does is carried by every DELEGATE transaction forever. Treating the
 * root's head as an OPAQUE SLICE that must be reproduced verbatim pins the
 * field ENCODING as well as the values, at a fraction of the cost of
 * decoding and re-encoding the root's 18-field state.
 *
 * Static P2SH signature-operation count is measured on the compiled
 * redeem, not guessed here (docs/postlaunch/v0.7-kas-profile-readiness.md);
 * removing the owner checkSig from both ownerControl and ownerRecover only
 * ever REDUCES the v0.4.1 base's already-standard 13.
 *
 * Immutable template: vaultId, orgRootCovenantId, rootTemplateVmHash,
 * rootPrefixLen, rootStateLen, rootSuffixLen, recoveryPk. Mutable state (17
 * fields, UNCHANGED from v0.4.1): boundVaultId, protectedValue, feeReserve,
 * paused, agentRoot, approver1..10, approvalM, policyNonce.
 *
 * Reused v0.4.1 funds-critical rules (VM-proven), carried verbatim:
 *  - A7 sighash gate: every counted approval is a byte[] required to be
 *    exactly 65 bytes ending in 0x01 (SIG_HASH_ALL) before checkSig.
 *  - A2 distinctness + malformed-predecessor well-formedness on the
 *    approval path (consensus does not validate genesis state).
 *  - FR-1 fee-reserve conservation: reserveConsumed is bounded by both the
 *    spending agent's own agentMaxFeePerTx and the transaction's actual
 *    computed fee.
 *
 * Agent-policy leaf (124-byte preimage, UNCHANGED):
 *   sha256(0x50563401 || agentPk || num8(maxPerSpend) ||
 *          num8(periodBudget) || num8(periodLengthDaa) ||
 *          num8(periodStartDaa) || num8(periodSpent) ||
 *          num8(approvalThreshold) || num8(agentMaxFeePerTx) ||
 *          agentRecipientRoot)
 * where num8(v) = OpNum2Bin(v, 8) (canonical fixed-width little-endian).
 * Recipient leaf = sha256(0x50563301 || recipientPk) (36-byte preimage,
 * v0.3). Internal node = sha256(left||right) (64-byte). Distinct preimage
 * lengths (124/36/64) prevent cross-interpretation. Agent proof depth
 *   <= 12; recipient proof depth <= 16.
 *
 * Security boundary: Kaspa consensus. A holder of a legitimate agent key
 * bypassing the app and submitting directly to a node is bounded by every
 * rule below, and any rooted owner operation is additionally bounded by the
 * pinned root's own M-of-N script.
 */
contract PolicyVaultRootedKas(
    byte[32] vaultId,
    byte[32] orgRootCovenantId,
    byte[32] rootTemplateVmHash,
    int rootPrefixLen,
    int rootStateLen,
    int rootSuffixLen,
    pubkey recoveryPk,
    byte[32] initAgentRoot,`;

edit("E1 header + contract name + REMOVE `pubkey owner` + add root pins", V4_1_HEADER, V7_KAS_HEADER);

/* --- E2. the root-authorization block + the one family closure ------- */

const ROOT_BLOCK = `    /* The pinned root version's fixed-width state TAIL:
     *     byte    frozen     -> 0x01 || <0x00|0x01>   2 B
     *     byte[8] rootNonce  -> 0x08 || <8 LE bytes>  9 B
     * The tail geometry is not an independent trust input: rootTemplateVmHash
     * already pins the EXACT root script (and therefore its exact field
     * layout), so this constant only names an offset inside bytes that are
     * already proven to belong to the pinned root template. */
    int constant ROOT_TAIL_LEN = ${ROOT_TAIL_LEN};
    int constant ROOT_FROZEN_PUSH_LEN = ${ROOT_FROZEN_PUSH_LEN};
    int constant ROOT_NONCE_HEADER_LEN = ${ROOT_NONCE_HEADER_LEN};

    /* THE ONLY OWNER AUTHORITY IN THIS VAULT (identical to
     * PolicyVault.v0.7-payment.sil; design section 9.2).
     *
     * There is no owner key and no owner signature: an owner operation is
     * valid only if the transaction ALSO spends the pinned organizational
     * root, whose own covenant proved M-of-N (or the lighter emergency
     * quorum for FREEZE). The root's EXACT successor BYTES are pinned here,
     * so this vault can tell WHICH root path ran:
     *   expectFrozenPush = ${PUSH_UNFROZEN} -> the root ran AUTHORIZE (full quorum)
     *   expectFrozenPush = ${PUSH_FROZEN} -> the root ran FREEZE (emergency quorum)
     * Any other root path (ROTATE, UNFREEZE, OWNER-RECOVER, SUCCESSION)
     * changes the HEAD or the frozen byte, so the rebuilt successor redeem no
     * longer hashes to the root output's scriptPubKey and the vault operation
     * is invalid. Rotation and vault operations are therefore separate
     * transactions by construction.
     *
     * Nothing is trusted before it is proven. Steps 1-2 are exactly the two
     * checks readInputStateWithTemplate performs (the P2SH commitment of the
     * revealed redeem to the input's own scriptPubKey, then the template
     * identity); only then are the sliced tail bytes read. */
    function requireRootAuthorization(byte[] expectFrozenPush) {
        require(OpCovInputCount(orgRootCovenantId) == 1);
        require(OpCovOutputCount(orgRootCovenantId) == 1);
        int rootIn = OpCovInputIdx(orgRootCovenantId, 0);

        /* 1. slice the claimed redeem out of the root input's signature
         *    script (TRANSACTION-DERIVED VERIFIED TEMPLATE CARRIAGE, the
         *    frozen v0.5 technique) and BIND it to that input's P2SH
         *    scriptPubKey, so the bytes below are the bytes consensus is
         *    actually executing on that input. */
        int rootSigLen = OpTxInputScriptSigLen(rootIn);
        int rootRedeemStart = rootSigLen - (rootPrefixLen + rootStateLen + rootSuffixLen);
        byte[] rootRedeem = OpTxInputScriptSigSubstr(rootIn, rootRedeemStart, rootSigLen);
        require(tx.inputs[rootIn].scriptPubKey == new ScriptPubKeyP2SHFromRedeemScript(rootRedeem));

        /* 2. split the proven redeem by the pinned geometry and require the
         *    template identity blake2b-256(prefix || suffix) to be the root
         *    template pinned at this vault's genesis. */
        (byte[] rootPrefix, byte[] rootAfterPrefix) = rootRedeem.split(rootPrefixLen);
        (byte[] rootHead, byte[] rootAfterHead) = rootAfterPrefix.split(rootStateLen - ROOT_TAIL_LEN);
        (byte[] rootTailPrev, byte[] rootSuffix) = rootAfterHead.split(ROOT_TAIL_LEN);
        require(blake2b(rootPrefix + rootSuffix) == rootTemplateVmHash);

        /* 3. the root must NOT be frozen, and its nonce is read from the
         *    proven tail. */
        (byte[] prevFrozenPush, byte[] prevNoncePush) = rootTailPrev.split(ROOT_FROZEN_PUSH_LEN);
        require(prevFrozenPush == bytes(${PUSH_UNFROZEN}));
        (byte[] prevNonceHeader, byte[] prevNonceBody) = prevNoncePush.split(ROOT_NONCE_HEADER_LEN);
        require(prevNonceHeader == bytes(0x08));

        /* 4. rebuild the ONE successor redeem this vault accepts: the same
         *    prefix, the same head (so no owner slot, threshold, emergency
         *    quorum, recovery quorum or organization id may move), the
         *    demanded frozen byte, the nonce advanced by exactly one, the
         *    same suffix — and require the root's continuation output to
         *    commit to precisely those bytes. */
        byte[] rootTailNew = expectFrozenPush + bytes(0x08) + OpNum2Bin(int(prevNonceBody) + 1, 8);
        byte[] rootExpectedRedeem = rootPrefix + rootHead + rootTailNew + rootSuffix;
        int rootOut = OpCovOutputIdx(orgRootCovenantId, 0);
        require(tx.outputs[rootOut].scriptPubKey == new ScriptPubKeyP2SHFromRedeemScript(rootExpectedRedeem));
    }

    /* BINDING generalised for OWNER paths (both ownerControl and the
     * pure-KAS ownerRecover, which has no separate token family to admit):
     * every input other than this covenant and the pinned ROOT family must
     * be a PLAIN input.
     *
     * DEVIATION D9 (code size only, same as the payment profile): the two
     * 32-byte comparands are bound to locals BEFORE the loop. The compiler
     * unrolls \`for (i, 0, inCount, 8)\` to its compile-time bound, so an
     * inline literal inside the body is emitted as a 33-byte data push
     * EIGHT times; hoisting makes each reference a stack access instead.
     * The compared values and the rule are identical. */
    function requireOnlyRootCovenantInputs() {
        int inCount = tx.inputs.length;
        require(inCount >= 1);
        require(inCount <= 8);
        byte[32] rootCid = orgRootCovenantId;
        byte[32] plainCid = ${ZERO};
        for (i, 0, inCount, 8) {
            if (i != this.activeInputIndex) {
                byte[32] cid = OpInputCovenantId(i);
                if (cid != rootCid) {
                    require(bytes(cid) == bytes(plainCid));
                }
            }
        }
    }
`;

edit(
  "E2 root block insertion after state field declarations",
  `    int policyNonce = 0;

    /* Exact single authorized successor value at the auth output. */`,
  `    int policyNonce = 0;

${ROOT_BLOCK}
    /* Exact single authorized successor value at the auth output. */`
);

/* --- E3. deviation D2 — the zero-length-period hardening ------------- */

edit(
  "E3 D2 require(periodLengthDaa > 0) at the top of requireAgentTransition",
  `        int periodsElapsed
    ) {
        require(payAmount <= maxPerSpend);`,
  `        int periodsElapsed
    ) {
        /* DEVIATION D2 (v0.6 adversarial review, finding F1; carried into
         * v0.7-kas identically to v0.7-payment): a zero-length period makes
         * the period budget VACUOUS. With periodLengthDaa == 0 and
         * periodsElapsed >= 1 the rollover branch computes
         * newStart == periodStartDaa, so \`tx.time >= newStart\` holds inside
         * the SAME period and newSpent resets to spendAmount — the agent can
         * drain the vault one cap-sized spend at a time without the period
         * ever ending. The frozen v0.3/v0.4/v0.4.1 covenants lack this check
         * (their leaves are owner-committed, so it is an owner-
         * misconfiguration hazard, not a delegate escalation) and those
         * frozen files are NEVER modified; this generation rejects the
         * degenerate parameter at consensus. */
        require(periodLengthDaa > 0);
        require(payAmount <= maxPerSpend);`
);

/* --- E4. ownerControl: root authority + the extended selector 0..6 --- */

edit(
  "E4 ownerControl header: root authority replaces owner signature, selector bound 5 -> 6",
  `    #[covenant.singleton]
    function ownerControl(State prevState, State newState, int opSelector, sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(opSelector >= 0);
        require(opSelector <= 5);
        if (opSelector == 0) {`,
  `    /* ALL non-terminal owner operations behind ONE entrypoint + a bounded
     * opSelector, identical merged-inline-site pattern to
     * PolicyVault.v0.7-payment.sil (design section 9.3). Merging what would
     * otherwise be a separate emergencyPause entrypoint leaves exactly ONE
     * inline site of the root-authorization block on this path.
     *
     * In v0.7 the AUTHORITY is the organizational root input, not an owner
     * key. Owner operations NEVER move principal beyond the exact successor
     * value pinned below; no covenant input other than this one and the
     * root may be present. The successor state is pinned by the covenant
     * output; mutually exclusive per-selector rules make a substituted
     * selector reject.
     *
     *   0 setAgentRoot  1 setApprovers  2 topUp  3 topUpReserve
     *   4 pause         5 unpause                          full quorum
     *   6 EMERGENCY pause                              emergency quorum
     *
     * Selector 6 is the ONLY vault effect reachable from the root's LIGHTER
     * emergency quorum: AUTHORITY-REDUCING and monotone (paused 0 -> 1,
     * every other field preserved, policyNonce included, no value
     * movement). Selectors 0-5 pin an AUTHORIZE root successor and selector
     * 6 pins a FREEZE one, so an emergency quorum can reach nothing but the
     * pause. */
    #[covenant.singleton]
    function ownerControl(State prevState, State newState, int opSelector) {
        require(opSelector >= 0);
        require(opSelector <= 6);
        byte[] expectFrozenPush = bytes(${PUSH_UNFROZEN});
        if (opSelector == 6) {
            expectFrozenPush = bytes(${PUSH_FROZEN});
        }
        requireRootAuthorization(expectFrozenPush);
        requireOnlyRootCovenantInputs();
        if (opSelector == 0) {`
);

edit(
  "E4b selector 4 is the FULL-quorum pause; selectors 5/6 become explicit branches",
  `        if (opSelector == 4) {
            /* pause: paused 0 -> 1 */
            require(prevState.paused == 0);
            require(newState.paused == 1);
            require(newState.boundVaultId == prevState.boundVaultId);
            require(newState.protectedValue == prevState.protectedValue);
            require(newState.feeReserve == prevState.feeReserve);
            require(newState.agentRoot == prevState.agentRoot);
            requireApproversPreserved(prevState, newState);
            require(newState.policyNonce == prevState.policyNonce);
        } else {
            /* opSelector == 5 (bounded to [0,5], not 0..4): unpause 1 -> 0 */
            require(prevState.paused == 1);
            require(newState.paused == 0);
            require(newState.boundVaultId == prevState.boundVaultId);
            require(newState.protectedValue == prevState.protectedValue);
            require(newState.feeReserve == prevState.feeReserve);
            require(newState.agentRoot == prevState.agentRoot);
            requireApproversPreserved(prevState, newState);
            require(newState.policyNonce == prevState.policyNonce);
        }
        }
        }
        }
        }
        requireExactSuccessorValue(newState.protectedValue + newState.feeReserve);
    }`,
  `        if (opSelector == 4) {
            /* pause (full quorum): paused 0 -> 1 */
            require(prevState.paused == 0);
            require(newState.paused == 1);
            require(newState.boundVaultId == prevState.boundVaultId);
            require(newState.protectedValue == prevState.protectedValue);
            require(newState.feeReserve == prevState.feeReserve);
            require(newState.agentRoot == prevState.agentRoot);
            requireApproversPreserved(prevState, newState);
            require(newState.policyNonce == prevState.policyNonce);
        } else {
        if (opSelector == 5) {
            /* unpause (full quorum): paused 1 -> 0 */
            require(prevState.paused == 1);
            require(newState.paused == 0);
            require(newState.boundVaultId == prevState.boundVaultId);
            require(newState.protectedValue == prevState.protectedValue);
            require(newState.feeReserve == prevState.feeReserve);
            require(newState.agentRoot == prevState.agentRoot);
            requireApproversPreserved(prevState, newState);
            require(newState.policyNonce == prevState.policyNonce);
        } else {
            /* opSelector == 6 (bounded to [0,6], not 0..5): EMERGENCY pause
             * under a FREEZE root successor. Identical state effect to
             * selector 4, different and strictly lighter root authority
             * (emergencyK instead of ownerM). */
            require(prevState.paused == 0);
            require(newState.paused == 1);
            require(newState.boundVaultId == prevState.boundVaultId);
            require(newState.protectedValue == prevState.protectedValue);
            require(newState.feeReserve == prevState.feeReserve);
            require(newState.agentRoot == prevState.agentRoot);
            requireApproversPreserved(prevState, newState);
            require(newState.policyNonce == prevState.policyNonce);
        }
        }
        }
        }
        }
        }
        requireExactSuccessorValue(newState.protectedValue + newState.feeReserve);
    }`
);

/* --- E5. ownerRecover: root authority + the genesis-pinned destination */

edit(
  "E5 ownerRecover header, signature, authority and pinned destination",
  `    #[covenant.singleton(
        mode = transition,
        termination = allowed
    )]
    function ownerRecover(State prevState, State[] nextStates, sig ownerSig) : (State[]) {
        require(checkSig(ownerSig, owner));
        require(nextStates.length == 0);
        require(tx.outputs[0].scriptPubKey == new ScriptPubKeyP2PK(owner));
        require(tx.outputs[0].value == prevState.protectedValue + prevState.feeReserve);
        return(nextStates);
    }
}`,
  `    /* Break-glass recovery: the covenant terminates and its ENTIRE value
     * (protectedValue + feeReserve) pays out to the GENESIS-PINNED cold
     * destination recoveryPk (output 0). The destination is a template
     * constant, so a hijacked quorum-signing session cannot redirect
     * recovery. Authority is the root's FULL quorum (AUTHORIZE), identical
     * to every other ownerControl selector. No covenant family other than
     * the root may be present. TERMINAL. */
    #[covenant.singleton(
        mode = transition,
        termination = allowed
    )]
    function ownerRecover(State prevState, State[] nextStates) : (State[]) {
        requireRootAuthorization(bytes(${PUSH_UNFROZEN}));
        requireOnlyRootCovenantInputs();
        require(nextStates.length == 0);
        require(tx.outputs[0].scriptPubKey == new ScriptPubKeyP2PK(recoveryPk));
        require(tx.outputs[0].value == prevState.protectedValue + prevState.feeReserve);
        return(nextStates);
    }
}`
);

/* --- E6. agentSpend: SIGHASH_ALL gate on agentSig + refuse any covenant
 * rider on the delegate path ------------------------------------------ *
 *
 * Two candidate hardenings (owner directive, Wave 2 Track C2), for parity
 * with contracts/PolicyVault.v0.6.sil's ALREADY-PROVEN delegate-signature
 * closure (requireAgentAuthorization: byte[65] agentSig, SIGHASH_ALL gate,
 * checkSig(sig(agentSig), agentPk)):
 *   (a) `agentSig` moves from an UNGATED `sig` parameter to a `byte[]`
 *       parameter checked to be exactly 65 bytes ending in 0x01
 *       (SIG_HASH_ALL) before checkSig — the SAME A7 gate already applied
 *       to the 10 approval slots via countApprovalAt;
 *   (b) every input other than this covenant must be a PLAIN input on the
 *       delegate path — refusing a root-covenant (or any other) rider on
 *       agentSpend outright, mirroring the payment profile's family-
 *       isolation shape (requireNoForeignCovenantInputs) but with NO
 *       exception, since this profile's delegate path has no second
 *       legitimate covenant family to admit.
 *
 * Both are extracted and applied programmatically against the pristine
 * frozen v0.4.1 text (not hand-transcribed) so the "from" half of this
 * delta is mechanically guaranteed byte-exact; only the "to" half (the two
 * new helper functions, the parameter-type change, and the two new call
 * sites) is authored. */

function sliceBetween(startMarker, endMarker) {
  const s = baseText.indexOf(startMarker);
  if (s === -1) {
    console.error(`FAIL CLOSED: E6 start marker not found: ${JSON.stringify(startMarker)}`);
    process.exit(1);
  }
  const e = baseText.indexOf(endMarker, s);
  if (e === -1) {
    console.error(`FAIL CLOSED: E6 end marker not found: ${JSON.stringify(endMarker)}`);
    process.exit(1);
  }
  return baseText.slice(s, e);
}

const AGENT_SPEND_ORIGINAL = sliceBetween(
  "    #[covenant.singleton]\n    function agentSpend(",
  "\n\n    #[covenant.singleton]\n    function ownerControl("
);

const DELEGATE_AUTH_BLOCK = `    /* SIGHASH_ALL gate on the delegate's own signature (mirrors the A7
     * gate already applied to the 10 approval slots via countApprovalAt,
     * and the v0.6 adversarial-review-proven delegate-signature closure
     * requireAgentAuthorization in contracts/PolicyVault.v0.6.sil, applied
     * there to tokenAgentSpend's agent signature). Frozen v0.4.1's
     * agentSpend and the frozen v0.7-payment profile's tokenAgentSpend both
     * carry agentSig as an UNGATED \`sig\` parameter — documented,
     * VM-verified-safe inherited behavior there, because
     * requireAgentRecipient and requireExactSuccessorValue already bind
     * tx.outputs[] STRUCTURALLY regardless of what the signature's sighash
     * type covers. This profile closes the residual surface anyway, for
     * exact parity with the proven v0.6 gate. */
    function requireAgentAuthorization(byte[] agentSig, pubkey agentPk) {
        require(agentSig.length == 65);
        (byte[] sigBody, byte[] hashByte) = agentSig.split(64);
        require(hashByte == bytes(0x01));
        require(checkSig(sig(agentSig), agentPk));
    }

    /* BINDING for the DELEGATE path: unlike the owner paths (which
     * legitimately spend both this vault and the pinned root together), a
     * delegate spend never needs and must never be able to lean on the root
     * or any other covenant family. Every input other than this covenant
     * must therefore be a PLAIN input (zero covenant id), refusing a
     * root-covenant (or any other) rider on agentSpend outright. Frozen
     * v0.4.1's agentSpend has no such check (it predates multiple covenant
     * families coexisting in one PolicyVault transaction) and the frozen
     * v0.7-payment profile's tokenAgentSpend instead ADMITS its own
     * legitimate token family via requireNoForeignCovenantInputs; this
     * profile has no second legitimate family on the delegate path, so the
     * closure here is unconditional. Bounded to <= 8 inputs. */
    function requireOnlyPlainInputsOnDelegatePath() {
        int inCount = tx.inputs.length;
        require(inCount >= 1);
        require(inCount <= 8);
        byte[32] plainCid = ${ZERO};
        for (i, 0, inCount, 8) {
            if (i != this.activeInputIndex) {
                require(bytes(OpInputCovenantId(i)) == bytes(plainCid));
            }
        }
    }

`;

const AGENT_SIG_TYPE_FROM = "sig agentSig,";
const AGENT_SIG_TYPE_TO = "byte[] agentSig,";
const AGENT_AUTH_FROM =
  "        require(prevState.paused == 0);\n        /* the LEAF is the sole key->policy authority */\n        require(checkSig(agentSig, agentPk));\n";
const AGENT_AUTH_TO =
  "        require(prevState.paused == 0);\n        /* the LEAF is the sole key->policy authority; SIGHASH_ALL gated\n         * (parity with the v0.6 delegate-signature closure). */\n        requireAgentAuthorization(agentSig, agentPk);\n        requireOnlyPlainInputsOnDelegatePath();\n";

if (AGENT_SPEND_ORIGINAL.split(AGENT_SIG_TYPE_FROM).length - 1 !== 1) {
  console.error(`FAIL CLOSED: E6 expected exactly 1 occurrence of ${JSON.stringify(AGENT_SIG_TYPE_FROM)} in agentSpend.`);
  process.exit(1);
}
if (AGENT_SPEND_ORIGINAL.split(AGENT_AUTH_FROM).length - 1 !== 1) {
  console.error(`FAIL CLOSED: E6 expected exactly 1 occurrence of the paused/checkSig anchor in agentSpend.`);
  process.exit(1);
}

let agentSpendNewBody = AGENT_SPEND_ORIGINAL.split(AGENT_SIG_TYPE_FROM).join(AGENT_SIG_TYPE_TO);
agentSpendNewBody = agentSpendNewBody.split(AGENT_AUTH_FROM).join(AGENT_AUTH_TO);
if (agentSpendNewBody.includes("sig agentSig,") || agentSpendNewBody.includes("checkSig(agentSig, agentPk)")) {
  console.error("FAIL CLOSED: E6 agentSpend transform left an ungated sig-typed agentSig behind.");
  process.exit(1);
}

const AGENT_SPEND_NEW = DELEGATE_AUTH_BLOCK + agentSpendNewBody;

edit(
  "E6 agentSpend: SIGHASH_ALL gate (requireAgentAuthorization) + refuse any covenant rider on the delegate path (requireOnlyPlainInputsOnDelegatePath)",
  AGENT_SPEND_ORIGINAL,
  AGENT_SPEND_NEW
);

/* ---------------------------------------------------------------- *
 * 3. apply — every edit must match exactly once, or nothing is written
 * ---------------------------------------------------------------- */

let text = base.toString("utf8");
for (const { name, from, to } of EDITS) {
  const count = text.split(from).length - 1;
  if (count !== 1) {
    console.error(
      `FAIL CLOSED: edit "${name}" matched ${count} times, expected exactly 1.\n` +
        "A v0.7-kas delta that does not apply exactly once is not a reviewable derivation; nothing is written."
    );
    process.exit(1);
  }
  text = text.replace(from, to);
}

/* Post-conditions the delta must have achieved (cheap, mechanical, and they
 * fail closed): no owner key, no owner signature anywhere, both root call
 * sites present, the D2 hardening present. */
const MUST_BE_ABSENT = [
  ["pubkey owner,", "the removed owner template constant"],
  ["sig ownerSig", "an owner signature argument"],
  ["checkSig(ownerSig", "an owner signature check"],
  ["ScriptPubKeyP2PK(owner)", "a recovery payout to the removed owner key"],
  ["sig agentSig", "the ungated sig-typed agent-signature parameter"],
  ["checkSig(agentSig, agentPk)", "the ungated direct agent-signature check"],
];
for (const [needle, what] of MUST_BE_ABSENT) {
  if (text.includes(needle)) {
    console.error(`FAIL CLOSED: ${what} survived the delta (${JSON.stringify(needle)}).`);
    process.exit(1);
  }
}
const MUST_APPEAR = [
  ["contract PolicyVaultRootedKas(", 1],
  ["function requireRootAuthorization(byte[] expectFrozenPush) {", 1],
  ["        requireRootAuthorization(expectFrozenPush);", 1],
  [`        requireRootAuthorization(bytes(${PUSH_UNFROZEN}));`, 1],
  ["        require(periodLengthDaa > 0);", 1],
  ["    function requireOnlyRootCovenantInputs() {", 1],
  ["        requireOnlyRootCovenantInputs();", 2],
  ["opSelector <= 6", 1],
  ["opSelector == 6", 2],
  ["    function requireAgentAuthorization(byte[] agentSig, pubkey agentPk) {", 1],
  ["    function requireOnlyPlainInputsOnDelegatePath() {", 1],
  ["        requireAgentAuthorization(agentSig, agentPk);", 1],
  ["        requireOnlyPlainInputsOnDelegatePath();", 1],
  ["byte[] agentSig,", 2],
  ["checkSig(sig(agentSig), agentPk)", 1],
];
for (const [needle, want] of MUST_APPEAR) {
  const got = text.split(needle).length - 1;
  if (got !== want) {
    console.error(`FAIL CLOSED: expected ${want} occurrence(s) of ${JSON.stringify(needle)}, found ${got}.`);
    process.exit(1);
  }
}

if (!process.env.OUT) {
  console.error("set OUT to the destination path");
  process.exit(1);
}
fs.writeFileSync(process.env.OUT, text);
console.log(
  "wrote",
  text.split("\n").length - 1,
  "lines from the frozen v0.4.1 base",
  `(${V4_1_SHA256.slice(0, 8)}...)`,
  "via",
  EDITS.length,
  "exact-match edits"
);
