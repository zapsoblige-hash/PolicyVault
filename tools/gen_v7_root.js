"use strict";
// Deterministic generator for contracts/PolicyVault.v0.7-root.sil — the v0.7
// ORGANIZATIONAL M-of-N OWNER ROOT covenant CANDIDATE
// (docs/postlaunch/v0.7-organizational-root-design.md sections 2, 9.1 and 11).
//
// v0.7 is a NEW additive covenant lineage. The FROZEN v0.5 controller
// (contracts/PolicyVault.v0.5.sil, sha256 c693aeff...) and the v0.6 candidate
// (contracts/PolicyVault.v0.6.sil, sha256 c7c5f22c...) are NEVER touched by
// this file, and neither are the phase-1/phase-2 probe covenants, which stay
// on disk as the experimental record.
//
// Reference semantics: contracts/experiments/V7OrgRootProbe2.sil
// (VM-PROBED, 22 tests / 97 engine refusals, section 10). The candidate
// differs from that probe ONLY by naming, comments, and coordinator decision
// D6 of section 11 (root action 4 OWNER-RECOVER MUST land frozen = 1).
//
// NOT run at build/consensus time; a source-authoring tool. Byte-identical
// output (no timestamps, no randomness, no environment except OUT).
// Usage: OUT=contracts/PolicyVault.v0.7-root.sil node tools/gen_v7_root.js

/* ---------------------------------------------------------------- *
 * generation parameters (every repetition below is derived from these)
 * ---------------------------------------------------------------- */
const N_SLOTS = 12; // owner slots; N_MAX = 12 keeps static sig-ops at 13 <= 15
const SLOT_LEN = 65; // 64-byte Schnorr signature + the SIGHASH_ALL gate byte
const SIG_BLOB_LEN = N_SLOTS * SLOT_LEN; // 780
const HALF = N_SLOTS / 2; // one counting frame handles half the slots
const HALF_FN = "countSixOwners"; // the half-split counting frame (HALF == 6)
const ZERO = "0x" + "00".repeat(32);

/* Measured state geometry (tests/vm/tests/v7_root_production.rs asserts every
 * number against the compiler's own layout; see section 10.2):
 *   byte[32] -> data_prefix(32)=0x20 + 32 =  33 B
 *   pubkey   -> data_prefix(32)=0x20 + 32 =  33 B
 *   int      -> data_prefix(8)=0x08  +  8 =   9 B   (always 8 B, never minimal)
 *   byte     -> data_prefix(1)=OpData1 + 1 =   2 B
 *   byte[8]  -> data_prefix(8)=0x08  +  8 =   9 B                              */
const STATE_LEN = 33 + N_SLOTS * 33 + 3 * 9 + 2 + 9; // 467
const TAIL_LEN = 2 + 9; // byte frozen (2 B) + byte[8] rootNonce (9 B) = 11

const out = [];
const P = (s = "") => out.push(s);

const owner = (i) => `owner${i}`;
const initOwner = (i) => `initOwner${i}`;

P("pragma silverscript ^0.1.0;");
P("");
P("/*");
P(" * PolicyVault v0.7-root — ORGANIZATIONAL M-of-N OWNER ROOT covenant");
P(" * CANDIDATE (docs/postlaunch/v0.7-organizational-root-design.md).");
P(" *");
P(" * WHY THIS EXISTS. Until v0.7 the ultimate authority over a PolicyVault");
P(" * vault was ONE key. An organization must be able to hold that authority");
P(" * without any single private key being the unilateral financial root, and");
P(" * hosted roles, delegate approvals and application permissions are NOT");
P(" * substitutes: they are not the security boundary. Kaspa consensus is.");
P(" *");
P(" * ONE root covenant per organization holds the owner set, the threshold,");
P(" * the emergency and recovery quorums, the freeze flag and a monotone");
P(" * nonce. A ROOTED VAULT (contracts/PolicyVault.v0.7-payment.sil) has NO");
P(" * owner key at all: its owner operations are valid only when the same");
P(" * transaction ALSO spends this root, whose own script proved M-of-N, and");
P(" * the vault pins this root's EXACT successor bytes so it can tell WHICH");
P(" * root path ran. Rotation, threshold change, freeze, recovery and");
P(" * succession therefore happen ONCE for the whole organization, and a");
P(" * DELEGATE spend never touches the root at all.");
P(" *");
P(" * A NEW additive lineage: the frozen v0.5 controller and the v0.6");
P(" * candidate are never modified and no old vault mode is migrated.");
P(" *");
P(" * ---------------------------------------------------------------- *");
P(" * STATE LAYOUT (18 fields; the region length is a CONSTANT so a rooted");
P(" * vault can slice it by fixed offsets — section 9.1)");
P(" * ---------------------------------------------------------------- *");
P(" *");
P(" *   HEAD (never moves on an AUTHORIZE or a FREEZE):");
P(" *     byte[32] boundOrgId                  33 B");
P(` *     pubkey   owner1 .. owner${N_SLOTS}          ${N_SLOTS} x 33 B  (zero = inactive slot)`);
P(" *     int      ownerM                       9 B");
P(" *     int      emergencyK                   9 B");
P(" *     int      recoveryM                    9 B");
P(" *   TAIL (fixed width, LAST — the only two fields AUTHORIZE/FREEZE move):");
P(" *     byte     frozen      -> 0x01 || <0x00|0x01>            2 B");
P(" *     byte[8]  rootNonce   -> 0x08 || <8 little-endian B>    9 B");
P(" *");
P(` *   rootStateLen = 33 + ${N_SLOTS}x33 + 3x9 + 2 + 9 = ${STATE_LEN} B (constant for every`);
P(" *                  reachable state and every threshold)");
P(` *   TAIL_LEN     = 2 + 9 = ${TAIL_LEN} B`);
P(" *");
P(" * Encoded field chunks are `data_prefix(fixed_type_size) || payload`");
P(" * (~/silverscript/silverscript-lang/src/compiler/compile.rs), and an `int`");
P(" * is ALWAYS serialize_i64(n, Some(8)) — a fixed 8-byte sign-magnitude");
P(" * little-endian encoding, zero-padded, never minimal — so the three small");
P(" * ints are already constant-width and are deliberately NOT retyped");
P(" * (deviation D7). The tail is retyped only so a rooted vault can rebuild");
P(" * it with ONE OpNum2Bin instead of decoding 18 fields (deviation D8 adds");
P(" * the byte-domain well-formedness that retyping makes necessary).");
P(" *");
P(" * ---------------------------------------------------------------- *");
P(" * SIGNATURE BLOB AND COUNTING");
P(" * ---------------------------------------------------------------- *");
P(" *");
P(` * ownerSigs is exactly ${N_SLOTS} x ${SLOT_LEN} = ${SIG_BLOB_LEN} bytes. Slot i (0-based) is bytes`);
P(` * [${SLOT_LEN}i, ${SLOT_LEN}i+${SLOT_LEN}). An ACTIVE slot MUST carry a 64-byte Schnorr signature`);
P(" * plus the trailing 0x01 SIGHASH_ALL gate byte and counts 1 iff it");
P(" * verifies under that slot's key; the canonical abstention placeholder (64");
P(" * zero bytes + 0x01) passes the gate, fails verification and counts 0.");
P(" * Inactive (sentinel-zero) slots are never inspected.");
P(" *");
P(" * A signature cannot be counted twice: every active key is pairwise");
P(" * distinct on the predecessor AND on every new set, each slot is verified");
P(" * against exactly one key, and one signature verifies under exactly one");
P(" * key. A stale approval cannot replay: every counted signature is");
P(" * SIGHASH_ALL over the whole transaction, which commits to this root's");
P(" * outpoint (single-use by consensus) and to every output, and rootNonce");
P(" * strictly increases. Kaspa lockTime is a lower bound only, so freshness");
P(" * is outpoint binding + SIGHASH_ALL + nonce, NEVER an expiry.");
P(" *");
P(" * STATIC P2SH SIG-OPS: SilverScript inlines a function at every call site");
P(" * and a P2SH spend reveals the WHOLE redeem, so every checkSig in this");
P(` * file counts against the standardness budget of 15 regardless of the path`);
P(" * taken. Counting therefore exists at exactly ONE call site:");
P(` *     ${N_SLOTS} (owner counting, one site) + 1 (succession) = 13 <= 15   headroom 2`);
P(" * That budget is why N_MAX is 12: a 13-slot root is a different template,");
P(" * a different covenant id and a different (future) root version.");
P(" *");
P(" * ---------------------------------------------------------------- *");
P(" * MUTATION CLASSES (recorded for governance manifests; section 2.4)");
P(" * ---------------------------------------------------------------- *");
P(" *");
P(" *   0 AUTHORIZE     NEUTRAL              full quorum   (ownerM)");
P(" *   1 ROTATE        AUTHORITY-EXPANDING  full quorum   (ownerM)");
P(" *   2 FREEZE        AUTHORITY-REDUCING   emergency     (emergencyK)");
P(" *   3 UNFREEZE      AUTHORITY-EXPANDING  full quorum   (ownerM)");
P(" *   4 OWNER-RECOVER AUTHORITY-EXPANDING  recovery      (recoveryM) + idle age");
P(" *     SUCCESSION    AUTHORITY-EXPANDING  successorPk   + idle age");
P(" *");
P(" * FREEZE is the ONLY effect the lighter emergency quorum can reach, and it");
P(" * is monotone: its sole effect is frozen 0 -> 1; while frozen, actions 0");
P(" * and 2 are refused and every rooted vault's general owner path is");
P(" * refused; the root has one input and one action per transaction, so a");
P(" * FREEZE cannot be composed into an authority expansion.");
P(" *");
P(" * ---------------------------------------------------------------- *");
P(" * TERMINALITY — EXPLICIT RULE: THE ROOT HAS NO TERMINAL TRANSITION.");
P(" * ---------------------------------------------------------------- *");
P(" *");
P(" * Every entrypoint is #[covenant.singleton] with exactly one authorized");
P(" * continuation output; none permits termination and none can pay anyone.");
P(" * A dissolved root would permanently strand the owner path of every vault");
P(" * pinned to it (a self-locking transition), so dissolution is refused by");
P(" * construction. Organizational wind-down = recover every vault through");
P(" * that vault's OWN terminal path, after which this root's dust simply");
P(" * remains. Root MIGRATION = a new root genesis plus per-vault migration");
P(" * authorized by the OLD root; the old root persists and is harmless.");
P(" *");
P(" * If keys are lost below ownerM: (a) recoveryM > 0 lets recoveryM surviving");
P(" * owners install a new set after recoveryDelayDaa of idleness; (b)");
P(" * successorPk != 0 lets the pinned successor install a new set after");
P(" * successionDelayDaa; (c) neither means the root is permanently stuck and");
P(" * vault recovery is impossible — the deliberate, documented consequence of");
P(" * opting out, identical in kind to losing a single owner key today.");
P(" *");
P(" * Security boundary: Kaspa consensus. Every rule below must hold against a");
P(" * holder of legitimate owner keys submitting transactions directly to a");
P(" * node, bypassing the application entirely.");
P(" */");
P("contract PolicyVaultOrgRoot(");
P("    byte[32] orgId,");
for (let i = 1; i <= N_SLOTS; i++) {
  P(`    pubkey ${initOwner(i)},`);
}
P("    int initOwnerM,");
P("    int initEmergencyK,");
P("    int initRecoveryM,");
P("    byte initFrozen,");
P("    byte[8] initRootNonce,");
P("    int recoveryDelayDaa,");
P("    pubkey successorPk,");
P("    int successionDelayDaa,");
P("    int rootMaxFeePerTx");
P(") {");
P("    byte[32] boundOrgId = orgId;");
for (let i = 1; i <= N_SLOTS; i++) {
  P(`    pubkey ${owner(i)} = ${initOwner(i)};`);
}
P("    int ownerM = initOwnerM;");
P("    int emergencyK = initEmergencyK;");
P("    int recoveryM = initRecoveryM;");
P("    /* TAIL (fixed width, LAST): the only two fields an AUTHORIZE or a");
P("     * FREEZE changes, laid out so a rooted vault can slice and rebuild them");
P("     * without decoding the head. */");
P("    byte frozen = initFrozen;");
P("    byte[8] rootNonce = initRootNonce;");
P("");
P("    byte constant FROZEN_NO = 0x00;");
P("    byte constant FROZEN_YES = 0x01;");
P("");
P("    /* ---------------------------------------------------------------- *");
P("     * M-of-N counting (ONE call site; the v0.4.1 proven approval pattern)");
P("     * ---------------------------------------------------------------- */");
P("");
P("    /* Count the owner slot at byte `offset` of the " + SIG_BLOB_LEN + "-byte blob.");
P("     * Extracting the slot inside this helper keeps the caller's stack");
P("     * small (MAX_STACK_SIZE 244). Sentinel (zero) slots never count and");
P("     * are never inspected. An ACTIVE slot MUST carry a " + SLOT_LEN + "-byte");
P("     * SIGHASH_ALL signature (trailing 0x01 — the in-covenant sighash gate)");
P("     * or the canonical placeholder (which fails verification and counts 0). */");
P("    function countOwnerAt(pubkey ownerKey, byte[] ownerSigs, int offset) : (int) {");
P("        int result = 0;");
P(`        if (bytes(ownerKey) != bytes(${ZERO})) {`);
P("            (byte[] beforeSlot, byte[] fromSlot) = ownerSigs.split(offset);");
P(`            (byte[] slot, byte[] afterSlot) = fromSlot.split(${SLOT_LEN});`);
P("            (byte[] slotBody, byte[] slotHashByte) = slot.split(64);");
P("            require(slotHashByte == bytes(0x01));");
P("            if (checkSig(sig(slot), ownerKey)) {");
P("                result = 1;");
P("            }");
P("        }");
P("        return result;");
P("    }");
P("");
P(`    /* ${HALF} slots per frame (half split) so the deepest counting frame holds`);
P(`     * ${HALF} temporaries rather than ${N_SLOTS}. */`);
P(
  `    function ${HALF_FN}(${Array.from({ length: HALF }, (_, j) => `pubkey k${j + 1}`).join(", ")}, byte[] ownerSigs, int base) : (int) {`
);
P("        int n = 0;");
for (let j = 1; j <= HALF; j++) {
  P(`        (int c${j}) = countOwnerAt(k${j}, ownerSigs, base + ${(j - 1) * SLOT_LEN});`);
  P(`        n = n + c${j};`);
}
P("        return n;");
P("    }");
P("");
P(`    /* Total approvals over the ${N_SLOTS} slots. ONE call site in the whole`);
P(`     * contract: ${N_SLOTS} static sig-ops, counted once. */`);
P("    function countOwnerApprovals(State s, byte[] ownerSigs) : (int) {");
P(`        require(ownerSigs.length == ${SIG_BLOB_LEN});`);
const lowKeys = Array.from({ length: HALF }, (_, j) => `s.${owner(j + 1)}`).join(", ");
const highKeys = Array.from({ length: HALF }, (_, j) => `s.${owner(HALF + j + 1)}`).join(", ");
P(`        (int lowHalf) = ${HALF_FN}(${lowKeys}, ownerSigs, 0);`);
P(`        (int highHalf) = ${HALF_FN}(${highKeys}, ownerSigs, ${HALF * SLOT_LEN});`);
P("        int total = lowHalf + highHalf;");
P("        return total;");
P("    }");
P("");
P("    /* ---------------------------------------------------------------- *");
P("     * Well-formedness WF(S) (design section 2.2)");
P("     * ---------------------------------------------------------------- */");
P("");
P("    /* Consensus never validates genesis state, so a hand-baked root UTXO");
P("     * could otherwise let one key satisfy M, hold a duplicate key in two");
P("     * slots, or set an emergency quorum above the full quorum. WF is");
P("     * therefore checked on the PREDECESSOR of every root spend and on");
P("     * every NEW set.");
P("     *");
P("     * Distinctness guards only the LATER slot because contiguity is");
P("     * enforced in the same block: owner_j active implies owner_i active");
P(`     * for every i < j, so C(${N_SLOTS},2) = ${(N_SLOTS * (N_SLOTS - 1)) / 2} inequalities need only ${N_SLOTS - 1} guards.`);
P("     * Kaspa's `<` aborts (NumberTooBig) on 32-byte values, so ordering is");
P("     * unavailable and byte inequality is the only distinctness tool. */");
P("    function requireWellFormed(State s) {");
P("        int active = 0;");
for (let i = 1; i <= N_SLOTS; i++) {
  P(`        if (bytes(s.${owner(i)}) != bytes(${ZERO})) {`);
  P("            active = active + 1;");
  P("        }");
}
P("        require(active >= 1);");
for (let j = 2; j <= N_SLOTS; j++) {
  P(`        if (bytes(s.${owner(j)}) != bytes(${ZERO})) {`);
  P(`            require(bytes(s.${owner(j - 1)}) != bytes(${ZERO}));`);
  for (let i = 1; i < j; i++) {
    P(`            require(bytes(s.${owner(i)}) != bytes(s.${owner(j)}));`);
  }
  P("        }");
}
P("        require(s.ownerM >= 1);");
P("        require(s.ownerM <= active);");
P("        require(s.emergencyK >= 1);");
P("        require(s.emergencyK <= s.ownerM);");
P("        require(s.recoveryM >= 0);");
P("        require(s.recoveryM <= s.ownerM);");
P("        /* DEVIATION D8: `frozen` is a raw byte, so its domain is checked as");
P("         * BYTES. A numeric range check would accept 0x80, which Kaspa's");
P("         * deserialize_i64 reads as negative zero (= 0) while it equals");
P("         * NEITHER canonical byte — permanently self-locking the root, since");
P("         * AUTHORIZE/FREEZE want 0x00 and UNFREEZE wants 0x01. */");
P("        int frozenDomainOk = 0;");
P("        if (s.frozen == FROZEN_NO) {");
P("            frozenDomainOk = 1;");
P("        }");
P("        if (s.frozen == FROZEN_YES) {");
P("            frozenDomainOk = 1;");
P("        }");
P("        require(frozenDomainOk == 1);");
P("        require(int(s.rootNonce) >= 0);");
P("    }");
P("");
P("    /* The owner set, threshold, emergency quorum and recovery quorum are");
P("     * carried across verbatim (every action except ROTATE / OWNER-RECOVER). */");
P("    function requireSetPreserved(State prevState, State newState) {");
for (let i = 1; i <= N_SLOTS; i++) {
  P(`        require(newState.${owner(i)} == prevState.${owner(i)});`);
}
P("        require(newState.ownerM == prevState.ownerM);");
P("        require(newState.emergencyK == prevState.emergencyK);");
P("        require(newState.recoveryM == prevState.recoveryM);");
P("    }");
P("");
P("    /* The ONLY value the root may lose per transition is rootMaxFeePerTx");
P("     * (a flat bound per transition). The root can never pay anyone: its");
P("     * single authorized continuation output carries the value. */");
P("    function requireRootValueRule() {");
P("        int successorIndex = OpAuthOutputIdx(this.activeInputIndex, 0);");
P("        require(rootMaxFeePerTx >= 0);");
P("        require(tx.outputs[successorIndex].value >= tx.inputs[this.activeInputIndex].value - rootMaxFeePerTx);");
P("    }");
P("");
P("    /* ---------------------------------------------------------------- *");
P("     * Entrypoints (design section 2.4 as amended by coordinator decision D6)");
P("     * ---------------------------------------------------------------- */");
P("");
P("    /* action 0 AUTHORIZE  (full quorum)      — the only shape a rooted");
P("     *                                          vault accepts for general");
P("     *                                          owner operations");
P("     * action 1 ROTATE     (full quorum)      — new set; allowed while frozen");
P("     * action 2 FREEZE     (emergency quorum) — AUTHORITY-REDUCING, monotone");
P("     * action 3 UNFREEZE   (full quorum)");
P("     * action 4 OWNER-RECOVER (recovery quorum + relative idle age), and it");
P("     *                        MUST LAND FROZEN (decision D6)");
P("     *");
P("     * The root has NO terminal transition: a dissolved root would strand");
P("     * the owner path of every vault pinned to it. */");
P("    #[covenant.singleton]");
P("    function rootAction(State prevState, State newState, int action, byte[] ownerSigs) {");
P("        require(action >= 0);");
P("        require(action <= 4);");
P(`        require(ownerSigs.length == ${SIG_BLOB_LEN});`);
P("        requireWellFormed(prevState);");
P("        require(newState.boundOrgId == prevState.boundOrgId);");
P("        require(bytes(newState.rootNonce) == OpNum2Bin(int(bytes(prevState.rootNonce)) + 1, 8));");
P("        requireRootValueRule();");
P("");
P("        (int approvals) = countOwnerApprovals(prevState, ownerSigs);");
P("");
P("        int required = 0;");
P("        int setMayChange = 0;");
P("        if (action == 0) {");
P("            /* AUTHORIZE: pure heartbeat / vault-operation authorization */");
P("            require(prevState.frozen == FROZEN_NO);");
P("            require(newState.frozen == prevState.frozen);");
P("            required = prevState.ownerM;");
P("        }");
P("        if (action == 1) {");
P("            /* ROTATE: AUTHORITY-EXPANDING, full quorum, allowed while frozen */");
P("            require(newState.frozen == prevState.frozen);");
P("            required = prevState.ownerM;");
P("            setMayChange = 1;");
P("        }");
P("        if (action == 2) {");
P("            /* FREEZE: the ONLY lighter-quorum effect; monotone */");
P("            require(prevState.frozen == FROZEN_NO);");
P("            require(newState.frozen == FROZEN_YES);");
P("            required = prevState.emergencyK;");
P("        }");
P("        if (action == 3) {");
P("            /* UNFREEZE: AUTHORITY-EXPANDING, full quorum */");
P("            require(prevState.frozen == FROZEN_YES);");
P("            require(newState.frozen == FROZEN_NO);");
P("            required = prevState.ownerM;");
P("        }");
P("        if (action == 4) {");
P("            /* OWNER-RECOVER: explicit opt-in (recoveryM > 0) plus a");
P("             * RELATIVE INPUT-AGE lock — active owners defeat it simply by");
P("             * touching the root (dead-man's switch).");
P("             *");
P("             * COORDINATOR DECISION D6 (section 11), the ONE rule this");
P("             * candidate adds to the probed semantics: the recovered set");
P("             * MUST LAND FROZEN, exactly as a succession does. Otherwise a");
P("             * recovery that leaves the head unchanged produces a successor");
P("             * BYTE-IDENTICAL to an AUTHORIZE successor, so a rooted vault's");
P("             * GENERAL owner path could be satisfied by a recovery in the");
P("             * same transaction. Landing frozen makes a recovery reachable");
P("             * only alongside the AUTHORITY-REDUCING emergency pause, and");
P("             * forces the recovered set to UNFREEZE under its own full");
P("             * quorum before any general vault owner operation — one");
P("             * explicit step that surfaces the recovery in every vault's");
P("             * manifest. Every other action-4 rule is exactly ROTATE's. */");
P("            require(prevState.recoveryM >= 1);");
P("            require(this.age >= recoveryDelayDaa);");
P("            require(newState.frozen == FROZEN_YES);");
P("            required = prevState.recoveryM;");
P("            setMayChange = 1;");
P("        }");
P("        require(required >= 1);");
P("        require(approvals >= required);");
P("");
P("        if (setMayChange == 1) {");
P("            requireWellFormed(newState);");
P("        } else {");
P("            requireSetPreserved(prevState, newState);");
P("        }");
P("    }");
P("");
P("    /* Succession: a pinned successor key installs a new set after the root");
P("     * has been idle for successionDelayDaa. The installed set lands FROZEN");
P("     * so it must deliberately unfreeze under the full quorum — one extra");
P("     * step that surfaces the succession in every vault's manifest. */");
P("    #[covenant.singleton]");
P("    function rootSuccession(State prevState, State newState, byte[] successorSig) {");
P(`        require(bytes(successorPk) != bytes(${ZERO}));`);
P(`        require(successorSig.length == ${SLOT_LEN});`);
P("        (byte[] successorBody, byte[] successorHashByte) = successorSig.split(64);");
P("        require(successorHashByte == bytes(0x01));");
P("        require(checkSig(sig(successorSig), successorPk));");
P("        require(this.age >= successionDelayDaa);");
P("        requireWellFormed(prevState);");
P("        requireWellFormed(newState);");
P("        require(newState.boundOrgId == prevState.boundOrgId);");
P("        require(bytes(newState.rootNonce) == OpNum2Bin(int(bytes(prevState.rootNonce)) + 1, 8));");
P("        require(newState.frozen == FROZEN_YES);");
P("        /* DEVIATION D1: the successor MUST install a different primary key.");
P("         * Without it a succession that re-installs the SAME set produces a");
P("         * successor BYTE-IDENTICAL to the one a FREEZE produces, so a rooted");
P("         * vault's emergency-pause pin could not tell the two root paths");
P("         * apart. The rule costs a legitimate successor nothing (it installs");
P("         * its own key) and makes every root path's successor shape");
P("         * distinguishable. */");
P(`        require(bytes(newState.${owner(1)}) != bytes(prevState.${owner(1)}));`);
P("        requireRootValueRule();");
P("    }");
P("}");

if (!process.env.OUT) {
  console.error("set OUT to the destination path");
  process.exit(1);
}
require("fs").writeFileSync(process.env.OUT, out.join("\n") + "\n");
console.log("wrote", out.length, "lines");
