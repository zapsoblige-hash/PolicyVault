"use strict";
// Deterministic generator for contracts/PolicyVault.v0.7-payment-hd.sil — the
// ROOTED HIERARCHICAL DELEGATION covenant CANDIDATE (contract
// `PolicyVaultRootedTokenHD`), Wave 2 Track D. Composes two Wave-2 lines:
//   - the ROOTED vault architecture (v0.7-payment,
//     docs/postlaunch/v0.7-organizational-root-design.md);
//   - HIERARCHICAL DELEGATION, productionized from the real-engine probe
//     (contracts/experiments/HDProbe.sil, sha256
//     dbee385d117beb5ec4de5f29dbc9e19873663f8e0599625b40a59b57cf9c246d),
//     whose DESIGN (not bytes) is frozen by
//     docs/postlaunch/hierarchical-delegation-design-freeze.md.
//
// THIS GENERATOR IS A DELTA, NOT A REWRITE. It READS the CANDIDATE
// contracts/PolicyVault.v0.7-payment.sil, refuses to run unless that file's
// sha256 is exactly the pinned value below, and applies an explicit, ordered
// list of edits. Every edit must match EXACTLY ONCE (either a literal
// exact-match replace, or a SPAN delete bounded by two anchors that must each
// occur exactly once) or the generator fails closed and writes nothing — so
// the v0.7-payment rules that are not named here (dual binding, TRANSACTION-
// DERIVED VERIFIED TEMPLATE CARRIAGE, the KAS fee-reserve domain, the rooted
// owner paths: requireRootAuthorization / ownerControl / ownerRecover) are
// carried into this candidate byte-for-byte by construction. The base file
// is opened READ-ONLY and is never written.
//
// v0.7-payment-hd is a NEW additive covenant candidate. Frozen v0.5/v0.6 and
// the v0.7-root/v0.7-payment candidates are never modified.
// contracts/experiments/HDProbe.sil and tests/vm/tests/hd_experiment.rs (the
// probe this candidate productionizes) are never modified either.
//
// NOT run at build/consensus time; a source-authoring tool. Byte-identical
// output (no timestamps, no randomness, no environment except OUT).
// Usage: OUT=contracts/PolicyVault.v0.7-payment-hd.sil node tools/gen_v7_payment_hd.js

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/* ---------------------------------------------------------------- *
 * 1. the base, verified before a single byte is transformed
 * ---------------------------------------------------------------- */

/** contracts/PolicyVault.v0.7-payment.sil — the ROOTED PAYMENT PROFILE
 * candidate this file composes with hierarchical delegation. NOT byte-frozen
 * (v0.7 is never auto-frozen), but pinned here so a silent drift of that
 * candidate cannot silently change this derivation. */
const V7_PAYMENT_SHA = "09cdbb6c284d8bd6c4cd2f4aad20d9682172eea3e048631176034b517be25091";
const V7_PAYMENT_PATH = path.join(__dirname, "..", "contracts", "PolicyVault.v0.7-payment.sil");
/** contracts/experiments/HDProbe.sil — the experimental probe this candidate
 * productionizes (design freeze record section 1); documentation reference
 * only, never read as a derivation input. */
const HDPROBE_SHA = "dbee385d117beb5ec4de5f29dbc9e19873663f8e0599625b40a59b57cf9c246d";

const base = fs.readFileSync(V7_PAYMENT_PATH); // read-only; never written by this tool
const baseSha = crypto.createHash("sha256").update(base).digest("hex");
if (baseSha !== V7_PAYMENT_SHA) {
  console.error(
    `FAIL CLOSED: ${V7_PAYMENT_PATH} sha256 is ${baseSha}, expected the pinned ${V7_PAYMENT_SHA}.\n` +
      "This candidate is DERIVED from that exact base; if it drifted, the derivation is no longer reviewable and nothing is written."
  );
  process.exit(1);
}

const ZERO = "0x" + "00".repeat(32);

/* ---------------------------------------------------------------- *
 * 2. the delta
 * ---------------------------------------------------------------- */

const EDITS = [];
/** Literal exact-match edit: `from` must occur exactly once. */
function editLiteral(name, from, to) {
  EDITS.push({ name, kind: "literal", from, to });
}
/** Span edit: deletes text in [indexOf(startAnchor), indexOf(endAnchor)) and
 * replaces it with `to`. `startAnchor` may be null to mean "start of file".
 * Both anchors (when non-null) must occur exactly once, and endAnchor must
 * follow startAnchor. Used for the one large contiguous block (the flat
 * token-agent policy replaced by the HD tree) where hand-retyping the exact
 * original bytes as a literal `from` would risk a transcription mismatch. */
function editSpan(name, startAnchor, endAnchor, to) {
  EDITS.push({ name, kind: "span", startAnchor, endAnchor, to });
}

/* --- E1. rename the contract ------------------------------------ */

editLiteral("E1 contract declaration renamed to PolicyVaultRootedTokenHD", "contract PolicyVaultRootedToken(", "contract PolicyVaultRootedTokenHD(");

/* --- E2. header doc-comment replaced (span: file start .. the (now  *
 * renamed) contract declaration) ----------------------------------- */

const HD_HEADER = `/*
 * PolicyVault v0.7-payment-hd — ROOTED HIERARCHICAL DELEGATION covenant
 * CANDIDATE (contract \`PolicyVaultRootedTokenHD\`), Wave 2 Track D.
 *
 * GENERATED by tools/gen_v7_payment_hd.js as an EXACT-MATCH DELTA over the
 * CANDIDATE contracts/PolicyVault.v0.7-payment.sil (sha256
 * ${V7_PAYMENT_SHA}),
 * which is never modified. This candidate composes two Wave-2 lines: the
 * ROOTED vault architecture
 * (docs/postlaunch/v0.7-organizational-root-design.md) and HIERARCHICAL
 * DELEGATION, productionized from the real-engine probe
 * contracts/experiments/HDProbe.sil (sha256
 * ${HDPROBE_SHA},
 * never modified) whose DESIGN — not bytes — is frozen by
 * docs/postlaunch/hierarchical-delegation-design-freeze.md. NOT covenant-
 * byte-frozen, NOT production, NOT authorized for mainnet or live use.
 *
 * WHAT CHANGES, AND ONLY THIS (relative to v0.7-payment):
 *   - the FLAT token-agent policy leaf and its single entrypoint
 *     \`tokenAgentSpend\` are REMOVED and replaced by the HIERARCHICAL
 *     DELEGATION tree: a NEW HD leaf domain tag 0x50564801 over a 173-byte
 *     preimage (disjoint from every other PolicyVault leaf length), carried
 *     as ONE 160-byte canonical BODY per ancestor — the measured leaf
 *     carriage from the probe (design record section 6.2), never 11
 *     separate fields, because MAX_STACK_SIZE (244) is the binding
 *     constraint on MAX_LEVEL and the field-argument layout does not fit;
 *   - five HD entrypoints: \`hdSpend\` (level 1, owner-committed agents),
 *     \`childSpendL2\` (level 2), \`childSpendL3\` (level 3),
 *     \`delegateSetChildRoot1\` (a level-1 parent names a level-2 child),
 *     \`delegateSetChildRoot2\` (a level-2 parent names a level-3 child).
 *     Every spend presents the FULL ancestor chain with a membership proof
 *     at each level and exactly ONE signature (the spending leaf's);
 *     authority is the PER-SPEND INTERSECTION against EVERY ancestor — cap,
 *     period budget (each level its own clock, advanced in the one nested
 *     refold), recipient allowlist (k membership proofs, one per level),
 *     fee/carry bound by the MINIMUM over the chain. A delegation op is
 *     signed by the parent and can move ONLY that parent's own
 *     \`childRoot\`: the successor leaf is literally
 *     \`body[0,128) || newChildRoot\`, so no other field can move, and every
 *     other ancestor leaf and every vault global is pinned equal. CORE
 *     INVARIANT (owner, verbatim): AUTHORITY MAY NEVER INCREASE
 *     DESCENDING — a hostile or careless parent who commits a child leaf
 *     with LARGER caps gains nothing, because the child is still bounded by
 *     every ancestor at every spend (this is what makes a single parent
 *     signature, with no owner ceremony, a safe delegation rule);
 *   - the ROOTED owner paths (\`ownerControl\` selectors 0-4,
 *     \`ownerRecover\`) are carried over BYTE-IDENTICAL in substance from
 *     v0.7-payment: the organizational-root input is the ONLY owner
 *     authority (\`requireRootAuthorization\` pins its EXACT successor
 *     bytes), recovery pays the genesis-pinned \`recoveryPk\`. Composition
 *     point with delegation: \`delegateSetChildRoot1/2\` require
 *     \`prevState.paused == 0\`, exactly like every HD spend (carried from
 *     the probe, design freeze record section 2, OQ-HD-3). A FROZEN root
 *     therefore refuses ALL delegation (and all spending) the SAME way it
 *     refuses everything else — by riding \`ownerControl\` selector 4
 *     (EMERGENCY pause, the root's lighter emergency quorum) to set
 *     \`paused = 1\`; the org root is NOT involved directly in any HD
 *     entrypoint. Because the root machinery and the HD tree are separate
 *     call sites in one file — never mixed into one code path — the
 *     delegate/child-spend stack cost is UNCHANGED from the probe's
 *     measured numbers; see docs/postlaunch/v0.7-hd-economic-viability.md
 *     for the re-measurement on THESE exact bytes;
 *   - \`require(periodLengthDaa > 0)\` (v0.7-payment deviation D2) is NOT
 *     added inside the HD per-level accounting. Every HD leaf, at every
 *     level, is committed either by the owner (level 1, via
 *     \`setAgentRoot\`) or by a parent's signature
 *     (\`delegateSetChildRoot\`), so a zero-length period is the SAME
 *     committer-side misconfiguration hazard the v0.7-payment header
 *     describes for the frozen v0.3-v0.6 leaves, never a descendant-side
 *     escalation: the descendant still cannot exceed the per-request cap
 *     committed by its own ancestor chain, only spend that SAME
 *     already-authorized cap more often. This preserves the probe's
 *     measured level-3 stack headroom (36 of 244); it is recorded here as
 *     a deliberate, evidence-based choice, not an oversight.
 *
 * Static sig-ops in this redeem, matching the probe: 3 (hdSpend only) / 5
 * (+ childSpendL2 + delegateSetChildRoot1) / 7 (+ childSpendL3 +
 * delegateSetChildRoot2) — all <= MAX_STANDARD_P2SH_SIG_OPS (15).
 *
 * DUAL BINDING, the two accounting domains and TRANSACTION-DERIVED VERIFIED
 * TEMPLATE CARRIAGE are unchanged from v0.7-payment (see that file's header
 * for the full description); \`requireTokenTransfer\` below drives the
 * identical bytes for every HD spend entrypoint.
 *
 * HD leaf (173-byte preimage; body layout little-endian num8 ints):
 *   sha256(0x50564801 || body(160) || num8(level) || 0x00)
 *   body: pk[0,32) maxPerSpend[32,40) periodBudget[40,48)
 *         periodLengthDaa[48,56) periodStartDaa[56,64) periodSpent[64,72)
 *         maxFeePerTx[72,80) maxCarryKas[80,88) expiryDaa[88,96)
 *         recipientRoot[96,128) childRoot[128,160)
 *   \`level\` is a covenant CONSTANT substituted at every call site, never a
 *   caller argument: a leaf committed at level k fails membership anywhere
 *   else. \`expiryDaa\` is a CONSISTENCY field only (child <= parent down the
 *   chain, enforced at delegateSetChildRoot/childSpend time by the caller
 *   discipline the SDK enforces) — Kaspa \`lockTime\` is a LOWER bound, so
 *   this is NEVER a consensus expiry; the real retirement mechanisms are
 *   revocation (a zeroed/re-policied \`childRoot\` fails membership) and the
 *   periodic budget. See the design record section 1.4 and the freeze
 *   record section 2.
 * Recipient leaf = sha256(0x50563301 || recipientPk) (v0.3, 36 bytes).
 * Agent proof depth <= 12; child-subtree proof depth <= 8 per level;
 * recipient proof depth <= 16 per level.
 *
 * Security boundary: Kaspa consensus. A holder of a legitimate leaf key at
 * ANY level, bypassing the app and submitting directly to a node, is bounded
 * by every rule below and by the intersection of every ancestor in its
 * chain — never merely by its own leaf's advertised caps.
 */
`;

editSpan("E2 header doc-comment replaced by the HD composition header", null, "contract PolicyVaultRootedTokenHD(", HD_HEADER);

/* --- E3. HD_LEAF_BODY_LEN joins the template constants ----------- */

editLiteral(
  "E3 HD_LEAF_BODY_LEN constant",
  `    byte constant IDENTIFIER_COVENANT_ID = 0x02;

    /* The pinned root version's fixed-width state TAIL:`,
  `    byte constant IDENTIFIER_COVENANT_ID = 0x02;
    int constant HD_LEAF_BODY_LEN = 160;

    /* The pinned root version's fixed-width state TAIL:`
);

/* --- E4. the flat token-agent policy (tokenAgentLeaf .. tokenAgentSpend) *
 * replaced by the HD leaf machinery + five HD entrypoints (span delete).  *
 * computeMerkleRoot, txFee and requireKasDomains are carried through      *
 * UNCHANGED (reproduced verbatim inside the replacement block below,     *
 * because the whole contiguous region between the anchors is replaced    *
 * as one unit — the exact-match discipline is preserved because this     *
 * span itself is verified to occur exactly once before any byte moves). */

const HD_POLICY_BLOCK = `    /* HD leaf format (contracts/experiments/HDProbe.sil, VM-VERIFIED
     * experimental probe — docs/postlaunch/hierarchical-delegation-design.md
     * sections 6.2-6.3). \`level\` is a covenant CONSTANT substituted at
     * every call site, never a caller argument: a leaf committed at level k
     * fails membership anywhere else. */
    function hdLeafHash(byte[] body, int level) : byte[] {
        require(body.length == HD_LEAF_BODY_LEN);
        return bytes(sha256(bytes(0x50564801) + body + OpNum2Bin(level, 8) + bytes(0x00)));
    }

    /* The successor body of a leaf whose period accounting advanced and
     * whose childRoot may have been refolded — a byte-level splice, so no
     * other field of the leaf can possibly move. */
    function advancedBody(byte[] body, int newStart, int newSpent, byte[] newChildRoot) : byte[] {
        require(newChildRoot.length == 32);
        return body.slice(0, 56) + OpNum2Bin(newStart, 8) + OpNum2Bin(newSpent, 8) + body.slice(72, 128) + newChildRoot;
    }

    /* SIGHASH gate (v0.6 / v0.7-payment pattern): 65 bytes, hash type byte
     * 0x01 (SIGHASH_ALL) only — NONE / SINGLE / ANYONECANPAY are refused
     * inside the covenant, not merely by convention. */
    function requireLeafAuthorization(byte[] leafSig, pubkey leafPk) {
        require(leafSig.length == 65);
        (byte[] sigBody, byte[] hashByte) = leafSig.split(64);
        require(hashByte == bytes(0x01));
        require(checkSig(sig(leafSig), leafPk));
    }

    /* Single-leaf Merkle fold over a co-path (FUNDS-CRITICAL; v0.4
     * mechanism, VM-proven). Used for the level-1 agent tree and for every
     * childRoot subtree. depth <= 12. */
    function computeMerkleRoot(byte[] leaf, byte[] siblings, int pathBits) : byte[] {
        require(siblings.length % 32 == 0);
        require(siblings.length <= 384);
        int depth = siblings.length / 32;
        require(pathBits >= 0);
        require(pathBits < 4096);
        byte[] node = leaf;
        byte[] rest = siblings;
        int bits = pathBits;
        for (level, 0, depth, 12) {
            (byte[] sib, byte[] tail) = rest.split(32);
            rest = tail;
            if (bits % 2 == 1) {
                node = bytes(sha256(sib + node));
            } else {
                node = bytes(sha256(node + sib));
            }
            bits = bits / 2;
        }
        require(bits == 0);
        return node;
    }

    /* Recipient membership under ONE level's recipientRoot (v0.3 leaf).
     * depth <= 16. Called once PER LEVEL: the destination must be allowed by
     * EVERY ancestor, never only by the spending leaf. */
    function requireRecipientMember(byte[] root, pubkey recipientPk, byte[] siblings, int pathBits) {
        require(root.length == 32);
        require(siblings.length % 32 == 0);
        require(siblings.length <= 512);
        int depth = siblings.length / 32;
        require(pathBits >= 0);
        require(pathBits < 65536);
        byte[] node = bytes(sha256(bytes(0x50563301) + bytes(recipientPk)));
        byte[] rest = siblings;
        int bits = pathBits;
        for (level, 0, depth, 16) {
            (byte[] sib, byte[] tail) = rest.split(32);
            rest = tail;
            if (bits % 2 == 1) {
                node = bytes(sha256(sib + node));
            } else {
                node = bytes(sha256(node + sib));
            }
            bits = bits / 2;
        }
        require(bits == 0);
        require(node == root);
    }

    /* ONE LEVEL of the per-spend intersection (design record section 1.3,
     * items 1,2,3,5,6): the level pin is the CONSTANT expectedLevel fed
     * into the leaf hash; the amount is bounded by THIS level's own cap;
     * the recipient must be a member of THIS level's own allowlist; THIS
     * level's own period clock advances (its own rollover), and the
     * advanced counters go into the refold — so a child can never spend
     * without also consuming its parent's budget; the CURRENT leaf must be
     * a member of expectedRoot (the parent's childRoot, or the vault
     * agentRoot at level 1) — any stale, revoked or re-policied leaf fails
     * here; returns the refolded subtree root for the level above.
     *
     * STACK DISCIPLINE: every field is read from the body at its point of
     * use and no intermediate leaf/root local survives its own statement
     * (probe measurement, design record section 6.5). */
    function levelStep(
        byte[] body,
        int amount,
        int periodsElapsed,
        byte[] expectedRoot,
        byte[] siblings,
        int pathBits,
        byte[] newChildRoot,
        pubkey recipientPk,
        byte[] recipientSiblings,
        int recipientPathBits,
        int expectedLevel
    ) : byte[] {
        require(amount <= OpBin2Num(body.slice(32, 40)));
        requireRecipientMember(body.slice(96, 128), recipientPk, recipientSiblings, recipientPathBits);
        require(periodsElapsed >= 0);
        require(periodsElapsed <= 1000);
        int newStart = periodsElapsed >= 1 ? OpBin2Num(body.slice(56, 64)) + periodsElapsed * OpBin2Num(body.slice(48, 56)) : OpBin2Num(body.slice(56, 64));
        int newSpent = periodsElapsed >= 1 ? amount : OpBin2Num(body.slice(64, 72)) + amount;
        if (periodsElapsed >= 1) {
            require(tx.time >= newStart);
        }
        require(newSpent <= OpBin2Num(body.slice(40, 48)));
        require(computeMerkleRoot(hdLeafHash(body, expectedLevel), siblings, pathBits) == expectedRoot);
        return computeMerkleRoot(hdLeafHash(advancedBody(body, newStart, newSpent, newChildRoot), expectedLevel), siblings, pathBits);
    }

    /* Exact network fee from full input/output value introspection.
     * Bounded to <= 8 inputs and <= 8 outputs. */
    function txFee() : (int) {
        int inCount = tx.inputs.length;
        require(inCount >= 1);
        require(inCount <= 8);
        int outCount = tx.outputs.length;
        require(outCount >= 1);
        require(outCount <= 8);
        int totalIn = 0;
        for (i, 0, inCount, 8) {
            totalIn = totalIn + tx.inputs[i].value;
        }
        int totalOut = 0;
        for (j, 0, outCount, 8) {
            totalOut = totalOut + tx.outputs[j].value;
        }
        require(totalOut <= totalIn);
        int fee = totalIn - totalOut;
        return fee;
    }

    /* KAS domain, unchanged in substance from v0.7-payment except that the
     * two caps handed in are the MINIMUM over the whole ancestor chain
     * (design record section 1.3 item 4). */
    function requireKasDomains(State prevState, State newState, int tokIn, int agentMaxFeePerTx, int agentMaxCarryKas) {
        int selfOut = OpCovOutputIdx(tokenCovenantId, 0);
        int recipientOut = OpCovOutputIdx(tokenCovenantId, 1);
        require(tx.outputs[selfOut].value + tx.outputs[recipientOut].value >= tx.inputs[tokIn].value);
        require(tx.outputs[recipientOut].value <= agentMaxCarryKas);
        require(newState.feeReserve >= 0);
        int reserveConsumed = prevState.feeReserve - newState.feeReserve;
        require(reserveConsumed >= 0);
        require(reserveConsumed <= agentMaxFeePerTx);
        (int fee) = txFee();
        require(reserveConsumed <= fee);
        requireExactSuccessorValue(newState.feeReserve);
    }

    /* The whole token dual binding + conservation + KAS domain, factored so
     * every HD spend entrypoint (level 1, 2, 3) drives the IDENTICAL bytes. */
    function requireTokenTransfer(
        State prevState,
        State newState,
        KCC20State selfNew,
        KCC20State recipientNew,
        pubkey recipientPk,
        int spendAmount,
        int maxFeePerTx,
        int maxCarryKas
    ) {
        require(OpCovInputCount(tokenCovenantId) == 1);
        require(OpCovOutputCount(tokenCovenantId) == 2);
        int tokIn = OpCovInputIdx(tokenCovenantId, 0);
        requireNoForeignCovenantInputs(tokIn);

        KCC20State prevTok = readInputStateWithTemplate(
            tokIn,
            templatePrefixLen,
            templateSuffixLen,
            templateVmHash
        );
        int sigLen = OpTxInputScriptSigLen(tokIn);
        int redeemStart = sigLen - (templatePrefixLen + templateStateLen + templateSuffixLen);
        byte[] templatePrefix = OpTxInputScriptSigSubstr(tokIn, redeemStart, redeemStart + templatePrefixLen);
        byte[] templateSuffix = OpTxInputScriptSigSubstr(tokIn, sigLen - templateSuffixLen, sigLen);

        byte[32] selfId = OpInputCovenantId(this.activeInputIndex);
        require(prevTok.ownerIdentifier == selfId);
        require(prevTok.identifierType == IDENTIFIER_COVENANT_ID);
        require(!prevTok.isMinter);
        require(selfNew.ownerIdentifier == selfId);
        require(selfNew.identifierType == IDENTIFIER_COVENANT_ID);
        require(!selfNew.isMinter);
        require(bytes(selfNew.ownerIdentifier) != bytes(recipientPk));
        require(bytes(recipientNew.ownerIdentifier) == bytes(recipientPk));
        require(recipientNew.identifierType == IDENTIFIER_PUBKEY);
        require(!recipientNew.isMinter);

        require(spendAmount > 0);
        require(selfNew.amount >= 0);
        require(selfNew.amount == prevTok.amount - spendAmount);

        validateOutputStateWithTemplate(
            OpCovOutputIdx(tokenCovenantId, 0),
            selfNew,
            templatePrefix,
            templateSuffix,
            templateVmHash
        );
        validateOutputStateWithTemplate(
            OpCovOutputIdx(tokenCovenantId, 1),
            recipientNew,
            templatePrefix,
            templateSuffix,
            templateVmHash
        );

        requireKasDomains(prevState, newState, tokIn, maxFeePerTx, maxCarryKas);
        requireVaultGlobalPreserved(prevState, newState);
    }

    /* ---------------------------------------------------------------- */
    /* LEVEL 1 — owner-committed agents (setAgentRoot).                   */
    /* ---------------------------------------------------------------- */
    #[covenant.singleton]
    function hdSpend(
        State prevState,
        State newState,
        KCC20State selfNew,
        KCC20State recipientNew,
        byte[] leaf,
        byte[] siblings1,
        int pathBits1,
        int periodsElapsed1,
        byte[] recipientSiblings1,
        int recipientPathBits1,
        pubkey recipientPk,
        byte[] leafSig
    ) {
        require(prevState.paused == 0);
        require(leaf.length == HD_LEAF_BODY_LEN);
        requireLeafAuthorization(leafSig, pubkey(leaf.slice(0, 32)));
        require(bytes(newState.agentRoot) == levelStep(leaf, recipientNew.amount, periodsElapsed1, bytes(prevState.agentRoot), siblings1, pathBits1, leaf.slice(128, 160), recipientPk, recipientSiblings1, recipientPathBits1, 1));
        requireTokenTransfer(prevState, newState, selfNew, recipientNew, recipientPk, recipientNew.amount, OpBin2Num(leaf.slice(72, 80)), OpBin2Num(leaf.slice(80, 88)));
    }

    /* ---------------------------------------------------------------- */
    /* LEVEL 2 — one delegated level. Still ONE signature (the child's).  */
    /* ---------------------------------------------------------------- */
    #[covenant.singleton]
    function childSpendL2(
        State prevState,
        State newState,
        KCC20State selfNew,
        KCC20State recipientNew,
        byte[] a1,
        byte[] siblings1,
        int pathBits1,
        int periodsElapsed1,
        byte[] recipientSiblings1,
        int recipientPathBits1,
        byte[] leaf,
        byte[] siblings2,
        int pathBits2,
        int periodsElapsed2,
        byte[] recipientSiblings2,
        int recipientPathBits2,
        pubkey recipientPk,
        byte[] leafSig
    ) {
        require(prevState.paused == 0);
        require(a1.length == HD_LEAF_BODY_LEN);
        require(leaf.length == HD_LEAF_BODY_LEN);
        requireLeafAuthorization(leafSig, pubkey(leaf.slice(0, 32)));
        /* no self-parenting; a revoked parent (zero childRoot) has no members */
        require(a1.slice(0, 32) != leaf.slice(0, 32));
        require(a1.slice(128, 160) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));
        /* expiry CONSISTENCY (never a consensus time check — header note) */
        require(OpBin2Num(leaf.slice(88, 96)) <= OpBin2Num(a1.slice(88, 96)));
        /* ONE nested refold: the child's advanced leaf becomes the parent's
         * childRoot, and the parent's own advanced leaf becomes the vault's
         * agentRoot. Only ONE intermediate value is ever live. */
        (byte[] sub) = levelStep(leaf, recipientNew.amount, periodsElapsed2, a1.slice(128, 160), siblings2, pathBits2, leaf.slice(128, 160), recipientPk, recipientSiblings2, recipientPathBits2, 2);
        require(bytes(newState.agentRoot) == levelStep(a1, recipientNew.amount, periodsElapsed1, bytes(prevState.agentRoot), siblings1, pathBits1, sub, recipientPk, recipientSiblings1, recipientPathBits1, 1));
        requireTokenTransfer(prevState, newState, selfNew, recipientNew, recipientPk, recipientNew.amount,
            OpBin2Num(a1.slice(72, 80)) < OpBin2Num(leaf.slice(72, 80)) ? OpBin2Num(a1.slice(72, 80)) : OpBin2Num(leaf.slice(72, 80)),
            OpBin2Num(a1.slice(80, 88)) < OpBin2Num(leaf.slice(80, 88)) ? OpBin2Num(a1.slice(80, 88)) : OpBin2Num(leaf.slice(80, 88)));
    }

    /* ---------------------------------------------------------------- */
    /* DELEGATION at level 1: the parent signs; ONLY its childRoot moves. */
    /* Delegation NEVER moves tokens and requires prevState.paused == 0   */
    /* exactly like a spend — a FROZEN root reaches this via the vault's  */
    /* EMERGENCY pause (ownerControl selector 4), never directly.         */
    /* ---------------------------------------------------------------- */
    #[covenant.singleton]
    function delegateSetChildRoot1(
        State prevState,
        State newState,
        byte[] parentLeaf,
        byte[] siblings1,
        int pathBits1,
        byte[32] newChildRoot,
        byte[] parentSig
    ) {
        require(prevState.paused == 0);
        require(parentLeaf.length == HD_LEAF_BODY_LEN);
        requireLeafAuthorization(parentSig, pubkey(parentLeaf.slice(0, 32)));
        require(bytes(newChildRoot) != parentLeaf.slice(128, 160));
        /* a delegation op NEVER moves tokens: no other covenant input */
        requireNoForeignCovenantInputs(this.activeInputIndex);
        /* every vault global preserved; ONLY agentRoot moves */
        require(newState.boundVaultId == prevState.boundVaultId);
        require(newState.feeReserve == prevState.feeReserve);
        require(newState.paused == prevState.paused);
        require(newState.policyNonce == prevState.policyNonce);
        require(bytes(descriptorHash) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));
        require(computeMerkleRoot(hdLeafHash(parentLeaf, 1), siblings1, pathBits1) == bytes(prevState.agentRoot));
        require(bytes(newState.agentRoot) == computeMerkleRoot(hdLeafHash(parentLeaf.slice(0, 128) + bytes(newChildRoot), 1), siblings1, pathBits1));
        requireExactSuccessorValue(newState.feeReserve);
    }

    /* ---------------------------------------------------------------- */
    /* LEVEL 3 — two delegated levels. Still ONE signature (the child's). */
    /* ---------------------------------------------------------------- */
    #[covenant.singleton]
    function childSpendL3(
        State prevState,
        State newState,
        KCC20State selfNew,
        KCC20State recipientNew,
        byte[] a1,
        byte[] siblings1,
        int pathBits1,
        int periodsElapsed1,
        byte[] recipientSiblings1,
        int recipientPathBits1,
        byte[] a2,
        byte[] siblings2,
        int pathBits2,
        int periodsElapsed2,
        byte[] recipientSiblings2,
        int recipientPathBits2,
        byte[] leaf,
        byte[] siblings3,
        int pathBits3,
        int periodsElapsed3,
        byte[] recipientSiblings3,
        int recipientPathBits3,
        pubkey recipientPk,
        byte[] leafSig
    ) {
        require(prevState.paused == 0);
        require(a1.length == HD_LEAF_BODY_LEN);
        require(a2.length == HD_LEAF_BODY_LEN);
        require(leaf.length == HD_LEAF_BODY_LEN);
        requireLeafAuthorization(leafSig, pubkey(leaf.slice(0, 32)));
        require(a1.slice(0, 32) != a2.slice(0, 32));
        require(a2.slice(0, 32) != leaf.slice(0, 32));
        require(a1.slice(0, 32) != leaf.slice(0, 32));
        require(a1.slice(128, 160) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));
        require(a2.slice(128, 160) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));
        require(OpBin2Num(leaf.slice(88, 96)) <= OpBin2Num(a2.slice(88, 96)));
        require(OpBin2Num(a2.slice(88, 96)) <= OpBin2Num(a1.slice(88, 96)));
        /* ONE nested refold, bottom-up. STACK DISCIPLINE: exactly ONE
         * intermediate subtree root is live at a time. */
        (byte[] sub) = levelStep(leaf, recipientNew.amount, periodsElapsed3, a2.slice(128, 160), siblings3, pathBits3, leaf.slice(128, 160), recipientPk, recipientSiblings3, recipientPathBits3, 3);
        sub = levelStep(a2, recipientNew.amount, periodsElapsed2, a1.slice(128, 160), siblings2, pathBits2, sub, recipientPk, recipientSiblings2, recipientPathBits2, 2);
        require(bytes(newState.agentRoot) == levelStep(a1, recipientNew.amount, periodsElapsed1, bytes(prevState.agentRoot), siblings1, pathBits1, sub, recipientPk, recipientSiblings1, recipientPathBits1, 1));
        requireTokenTransfer(prevState, newState, selfNew, recipientNew, recipientPk, recipientNew.amount,
            OpBin2Num(a1.slice(72, 80)) < OpBin2Num(a2.slice(72, 80)) ? (OpBin2Num(a1.slice(72, 80)) < OpBin2Num(leaf.slice(72, 80)) ? OpBin2Num(a1.slice(72, 80)) : OpBin2Num(leaf.slice(72, 80))) : (OpBin2Num(a2.slice(72, 80)) < OpBin2Num(leaf.slice(72, 80)) ? OpBin2Num(a2.slice(72, 80)) : OpBin2Num(leaf.slice(72, 80))),
            OpBin2Num(a1.slice(80, 88)) < OpBin2Num(a2.slice(80, 88)) ? (OpBin2Num(a1.slice(80, 88)) < OpBin2Num(leaf.slice(80, 88)) ? OpBin2Num(a1.slice(80, 88)) : OpBin2Num(leaf.slice(80, 88))) : (OpBin2Num(a2.slice(80, 88)) < OpBin2Num(leaf.slice(80, 88)) ? OpBin2Num(a2.slice(80, 88)) : OpBin2Num(leaf.slice(80, 88))));
    }

    /* ---------------------------------------------------------------- */
    /* DELEGATION at level 2: a level-2 parent signs; the grandparent is  */
    /* proven by membership only (never by signature).                    */
    /* ---------------------------------------------------------------- */
    #[covenant.singleton]
    function delegateSetChildRoot2(
        State prevState,
        State newState,
        byte[] a1,
        byte[] siblings1,
        int pathBits1,
        byte[] parentLeaf,
        byte[] siblings2,
        int pathBits2,
        byte[32] newChildRoot,
        byte[] parentSig
    ) {
        require(prevState.paused == 0);
        require(a1.length == HD_LEAF_BODY_LEN);
        require(parentLeaf.length == HD_LEAF_BODY_LEN);
        requireLeafAuthorization(parentSig, pubkey(parentLeaf.slice(0, 32)));
        require(a1.slice(0, 32) != parentLeaf.slice(0, 32));
        require(a1.slice(128, 160) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));
        require(bytes(newChildRoot) != parentLeaf.slice(128, 160));
        requireNoForeignCovenantInputs(this.activeInputIndex);
        require(newState.boundVaultId == prevState.boundVaultId);
        require(newState.feeReserve == prevState.feeReserve);
        require(newState.paused == prevState.paused);
        require(newState.policyNonce == prevState.policyNonce);
        require(bytes(descriptorHash) != bytes(0x0000000000000000000000000000000000000000000000000000000000000000));
        require(computeMerkleRoot(hdLeafHash(parentLeaf, 2), siblings2, pathBits2) == a1.slice(128, 160));
        require(computeMerkleRoot(hdLeafHash(a1, 1), siblings1, pathBits1) == bytes(prevState.agentRoot));
        (byte[] newSub) = computeMerkleRoot(hdLeafHash(parentLeaf.slice(0, 128) + bytes(newChildRoot), 2), siblings2, pathBits2);
        require(bytes(newState.agentRoot) == computeMerkleRoot(hdLeafHash(a1.slice(0, 128) + newSub, 1), siblings1, pathBits1));
        requireExactSuccessorValue(newState.feeReserve);
    }

`;

editSpan(
  "E4 flat token-agent policy replaced by the HD leaf machinery + five HD entrypoints",
  "    /* Canonical token-agent policy leaf (125-byte preimage, frozen). */\n    function tokenAgentLeaf(",
  "\n\n    /* ALL non-terminal owner operations behind ONE entrypoint",
  HD_POLICY_BLOCK
);

/* ---------------------------------------------------------------- *
 * 3. apply — every edit must match exactly once, or nothing is written
 * ---------------------------------------------------------------- */

let text = base.toString("utf8");
for (const e of EDITS) {
  if (e.kind === "literal") {
    const count = text.split(e.from).length - 1;
    if (count !== 1) {
      console.error(`FAIL CLOSED: edit "${e.name}" matched ${count} times, expected exactly 1.`);
      process.exit(1);
    }
    text = text.replace(e.from, e.to);
  } else {
    const startCount = e.startAnchor === null ? 1 : text.split(e.startAnchor).length - 1;
    const endCount = text.split(e.endAnchor).length - 1;
    if (startCount !== 1) {
      console.error(`FAIL CLOSED: span edit "${e.name}" start anchor matched ${startCount} times, expected exactly 1.`);
      process.exit(1);
    }
    if (endCount !== 1) {
      console.error(`FAIL CLOSED: span edit "${e.name}" end anchor matched ${endCount} times, expected exactly 1.`);
      process.exit(1);
    }
    const s = e.startAnchor === null ? 0 : text.indexOf(e.startAnchor);
    const en = text.indexOf(e.endAnchor);
    if (en <= s) {
      console.error(`FAIL CLOSED: span edit "${e.name}" end anchor precedes start anchor.`);
      process.exit(1);
    }
    text = text.slice(0, s) + e.to + text.slice(en);
  }
}

/* Post-conditions the delta must have achieved (cheap, mechanical, fail
 * closed): the flat policy is entirely gone, the HD machinery and every
 * entrypoint (HD and the unchanged rooted owner paths) are present exactly
 * once, no owner key survived (defense in depth — it was never in the base
 * either). */
const MUST_BE_ABSENT = [
  ["function tokenAgentSpend(", "the removed flat token-agent spend entrypoint"],
  ["function tokenAgentLeaf(", "the removed flat token-agent leaf constructor"],
  ["function requireAgentMembership(", "the removed flat agent-membership helper"],
  ["function requireTokenAgentTransition(", "the removed flat token-agent transition helper"],
  ["function requireAgentRecipient(", "the removed flat agent-recipient helper"],
  ["pubkey owner,", "an owner template constant"],
  ["sig ownerSig", "an owner signature argument"],
  ["checkSig(ownerSig", "an owner signature check"],
];
for (const [needle, what] of MUST_BE_ABSENT) {
  if (text.includes(needle)) {
    console.error(`FAIL CLOSED: ${what} survived the delta (${JSON.stringify(needle)}).`);
    process.exit(1);
  }
}
const MUST_APPEAR = [
  ["contract PolicyVaultRootedTokenHD(", 1],
  ["int constant HD_LEAF_BODY_LEN = 160;", 1],
  ["function hdLeafHash(byte[] body, int level) : byte[] {", 1],
  ["function advancedBody(byte[] body, int newStart, int newSpent, byte[] newChildRoot) : byte[] {", 1],
  ["function requireLeafAuthorization(byte[] leafSig, pubkey leafPk) {", 1],
  ["function requireRecipientMember(byte[] root, pubkey recipientPk, byte[] siblings, int pathBits) {", 1],
  ["function levelStep(", 1],
  ["function requireTokenTransfer(", 1],
  ["function hdSpend(", 1],
  ["function childSpendL2(", 1],
  ["function delegateSetChildRoot1(", 1],
  ["function childSpendL3(", 1],
  ["function delegateSetChildRoot2(", 1],
  ["function requireRootAuthorization(byte[] expectFrozenPush) {", 1],
  ["function ownerControl(State prevState, State newState, int opSelector) {", 1],
  ["function ownerRecover(State prevState, State[] nextStates, KCC20State recipientNew) : (State[]) {", 1],
  ["        require(prevState.paused == 0);", 7], // hdSpend, childSpendL2, delegateSetChildRoot1, childSpendL3, delegateSetChildRoot2 (+2 in the unchanged ownerControl pause/emergency-pause selectors)
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
  "lines from the v0.7-payment base",
  `(${V7_PAYMENT_SHA.slice(0, 8)}...)`,
  "via",
  EDITS.length,
  "edits"
);
