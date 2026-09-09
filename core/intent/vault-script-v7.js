"use strict";
/*
 * PolicyVault v0.7 ROOTED PAYMENT VAULT — exact successor locking-script
 * reconstruction from the vault's own revealed redeem script
 * (Codex checkpoint 6, UX-02 / UX-13: "derive and validate ... and
 * reconstruct/bind the declared vault continuation script").
 *
 * The frozen payment covenant (contracts/PolicyVault.v0.7-payment.sil,
 * sha256 09cdbb6c…) compiles, for ANY template + state, to
 *
 *     prefix (1 byte) || STATE REGION (93 bytes) || suffix (template code)
 *
 * where the STATE REGION is silverc's field prolog for the five mutable
 * contract fields, in declaration order, each as a fixed-width push:
 *
 *     0x20 boundVaultId[32]   0x08 feeReserve[8 LE]   0x08 paused[8 LE]
 *     0x20 agentRoot[32]      0x08 policyNonce[8 LE]
 *
 * and the prefix + suffix are the vault's TEMPLATE: constant across every
 * state of one vault (the covenant itself rebuilds its successor in-VM from
 * exactly these bytes — validateOutputStateWithTemplate). The template is
 * vault-specific (its constructor pins are compiled into the suffix), so
 * the portable core cannot synthesize it without the compiler; what it CAN
 * do — and what this module does — is take the PREDECESSOR redeem script
 * the SDK captured at build time, bind it to the transaction (P2SH of the
 * redeem == the vault input's locking script, which the signature hash
 * covers) and to the reviewed predecessor state (the region decodes to
 * exactly stateBefore), and rebuild the ONE successor script the reviewed
 * stateAfter can produce: prefix || region(stateAfter) || suffix. The
 * successor output must carry the P2SH of that script, or nothing is
 * signed.
 *
 * The layout constant and the region encoding are PROVEN against the real
 * vendored compiler by sdk/test/vault-script-v7-reconstruction.test.js
 * (compiles a state matrix with silverc and compares byte for byte). Pure
 * data + pure functions: runs unchanged in the browser bundle and the
 * mobile vendor copy. No covenant bytes change here; nothing is recompiled.
 *
 * Codex checkpoint 7 (UX-02 / UX-13, "bind relevant geometry and immutable
 * operation pins to verified predecessor/root/token evidence"): the suffix is
 * NOT opaque to the core after all. Like the root's (root-script-v7.js), it is
 * a generation-constant SKELETON with holes — the vault's TEMPLATE CONSTANTS
 * (tokenCovenantId, descriptorHash, templateVmHash, templatePrefixLen /
 * templateSuffixLen, orgRootCovenantId, rootTemplateVmHash, rootPrefixLen /
 * rootSuffixLen, recoveryPk) pushed as minimal script numbers / 32-byte
 * pushes wherever the covenant uses them (142 holes), plus the script's own
 * TOTAL LENGTH (6 holes). templateStateLen (46, kcc20-state/1) and
 * rootStateLen (467) are fixed by the frozen generation and folded into the
 * constant chunks; vaultId lives only in the state region. So the core can
 * REBUILD THE WHOLE PREDECESSOR SCRIPT from the DECLARED pins + the reviewed
 * predecessor state (reconstructVaultScriptHexV7) and require it to be the
 * carried redeem byte for byte AND to hash to the vault input's P2SH (which
 * every signature covers): a declared geometry, recovery key, template hash
 * or predecessor state that is not the one compiled into the vault the
 * transaction actually spends rebuilds a DIFFERENT script and is refused
 * before any wallet is asked to sign. The skeleton was extracted
 * mechanically from real silverc output (three templates whose constants all
 * differ, token-aligned) and is proven byte for byte across a constant-
 * encoding matrix by sdk/test/vault-script-v7-reconstruction.test.js.
 */
const { normalizeStateV7, normalizeTemplateV7 } = require("../model/vault-state-v7");
const { blake2bHex } = require("../assets/blake2b");

/* silverc's state_layout for the frozen v0.7-payment generation (start = the
 * 1-byte selector prefix, len = 33 + 9 + 9 + 33 + 9). */
const VAULT_SCRIPT_PREFIX_LEN_V7 = 1;
const VAULT_STATE_REGION_LEN_V7 = 93;
const HEX64 = /^[0-9a-f]{64}$/;

/* ---- the frozen v0.7-payment TEMPLATE skeleton (Codex checkpoint 7) ---- */
const VAULT_SCRIPT_PREFIX_HEX_V7 = "6b";
const VAULT_SCRIPT_HOLES_V7 = Object.freeze(["tokenCovenantId","tokenCovenantId","tokenCovenantId","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templateVmHash","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templateVmHash","tokenCovenantId","templateVmHash","tokenCovenantId","tokenCovenantId","tokenCovenantId","descriptorHash","scriptLen","scriptLen","orgRootCovenantId","orgRootCovenantId","orgRootCovenantId","rootPrefixLen","rootSuffixLen","rootPrefixLen","rootPrefixLen","rootTemplateVmHash","orgRootCovenantId","orgRootCovenantId","descriptorHash","scriptLen","scriptLen","orgRootCovenantId","orgRootCovenantId","orgRootCovenantId","rootPrefixLen","rootSuffixLen","rootPrefixLen","rootPrefixLen","rootTemplateVmHash","orgRootCovenantId","recoveryPk","descriptorHash","tokenCovenantId","tokenCovenantId","tokenCovenantId","orgRootCovenantId","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templateSuffixLen","templateVmHash","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","templatePrefixLen","templatePrefixLen","templateSuffixLen","recoveryPk","templatePrefixLen","templateSuffixLen","templateVmHash","templatePrefixLen","templateSuffixLen","tokenCovenantId","orgRootCovenantId","scriptLen","scriptLen"]);
/* generation-constant suffix chunks between the holes (hex), extracted from real silverc output of the frozen v0.7-payment covenant */
const VAULT_SCRIPT_CHUNKS_V7 = Object.freeze([
  "6c76009c637554795479547954795479012679012679012679012679012679012679012679012679012679012679012679012679012679012679012179012179012179011e79011479009c69011c795579ac69",
  "d0519c69",
  "d2529c69",
  "00d176b37651a2697658a1690078009458a1697652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577687652799f637676b99e637654799e6376cf200000000000000000000000000000000000000000000000000000000000000000876968687651937b7577685379bf54795579c9",
  "012e93",
  "93945679c9",
  "012e93",
  "9394",
  "012e93",
  "9393bcaa02000001aa7e01207e7c7e01877e876953795479c9",
  "012e93",
  "93945579c9",
  "012e93",
  "9394",
  "93bc54795579c9",
  "012e93",
  "9394",
  "93012e935679c9",
  "012e93",
  "9394",
  "93012e93",
  "93bc7e",
  "7caa876953795479c9",
  "012e93",
  "9394",
  "5193935579c9",
  "012e93",
  "9394",
  "519393012093bc54795579c9",
  "012e93",
  "9394",
  "012293935679c9",
  "012e93",
  "9394",
  "012293935193bc55795679c9",
  "012e93",
  "9394",
  "012493935779c9",
  "012e93",
  "9394",
  "012493935893bc56795779c9",
  "012e93",
  "9394",
  "012d93935879c9",
  "012e93",
  "9394",
  "012d93935193bc5779c976",
  "012e93",
  "93945979785279",
  "93bc5a795379",
  "945479bcb9cf5879788769577901028769557991690119797887690118790102876901167991690119795e798791690115795e7987690114790100876901127991690113797600a06901187900a26901187958795279949c6976011379013a79013a79013a79013a79013a79011879011879011879013a79013a79013a79587900a0695c795b79a1697600a2697602e803a169577957795e7993527951a263597953795c7995937b7576b05e797b7568765c79a1695479547978827c755196012097009c6978827c755196028001a16978827c7551960120967800a269780200109f6904505635010111797e607958cd7e5f7958cd7e5e7958cd7e5d7958cd7e5c7958cd7e5b7958cd7e5a7958cd7e59797e01007ea85379537900547900945ca1697655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c6878009c695379760139798769597959795e795e7978827c755196012097009c6978827c755196028001a16978827c7551960120967800a269780200109f690450563501011b797e011a7958cd7e01197958cd7e01187958cd7e557958cd7e547958cd7e01157958cd7e01147958cd7e0113797e01007ea85379537900547900945ca1697655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c6878009c695379013d79788769014d79014d7978827c755196012097009c6978827c755196020002a16978827c7551960120967800a26978030000019f6904505633010133797ea853795379005479009460a1697655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c687655799f637653790120007c7f54798201207c7f76567a7555795297519c63527957797ea8577a7567567953797ea8577a756856795296577a7555795193577a75547a75547a75547a756b6b7c6b6c6c6c6878009c6953790138798769012b79012b797e",
  "7caa876901427901207c7e01427901017c7e01427958cd01087c7e01427951cd01017c7e7e7e7e012c797c7e012b797eaa02000001aa7e01207e7c7e01877e",
  "00d3c38769012b79012b797e",
  "7caa8769013e7901207c7e013e7901017c7e013e7958cd01087c7e013e7951cd01017c7e7e7e7e012c797c7e012b797eaa02000001aa7e01207e7c7e01877e",
  "51d3c38769014679",
  "51d3",
  "00d3c278c293013879bea26976c2013b79a1697800a269014d795279947600a26976013d79a169b37651a2697658a169b47651a2697658a16900005379009458a1697654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b75687654799f6376527978be93537a75785193537a757b756800005479009458a1697655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b75687655799f6376527978c293537a75785193537a757b7568785479a1695379527994577978a169b900ccc25a799c690151790157798769014f790155799c69014d790153799c69",
  "200000000000000000000000000000000000000000000000000000000000000000879169b9cb519c6901787901207c7e01787958cd01087c7e01787958cd01087c7e01787901207c7e01787958cd01087c7e7e7e7e7eb976c9",
  "94765193bc7c7eb976c976",
  "94015e937cbc7eaa02000001aa7e01207e7c7e01877eb900ccc38769007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a7575757575757575757575757575757575757575757575757575757575757575757575516776519c637553795379537953795d795d795d795d795d797600a2697654a16902010078549c63020101776876",
  "d0519c69",
  "d2519c69",
  "00d176c97878",
  "02d30193",
  "93945279bc5279bf78aa02000001aa7e01207e7c7e01877e876976",
  "007c7f7882",
  "7c7f7602d3015b94007c7f788202d3015b947c7f765b007c7f78825b7c7f5579787eaa",
  "87697852007c7f527982527c7f7802010087697651007c7f7882517c7f7801088769",
  "00d3c35a7959797e5f7901087e5379519358cd7e7e56797eaa02000001aa7e01207e7c7e01877e8769b37651a2697658a169",
  "200000000000000000000000000000000000000000000000000000000000000000005379009458a1697654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577680126790121798769",
  "200000000000000000000000000000000000000000000000000000000000000000879169011379009c63011779011c799c69011679011b799c6901147901197951939c6967011379519c63011779011c79a069011679011b799c69011579011a7987690114790119799c6967011379529c63011a79009c69011679519c69011779011c799c69011579011a7987690114790119799c6967011379539c63011a79519c69011679009c69011779011c799c69011579011a7987690114790119799c6967011a79009c69011679519c69011779011c799c69011579011a7987690114790119799c6968686868b900ccc20118799c69b9cb519c6901267901207c7e01267958cd01087c7e01267958cd01087c7e01267901207c7e01267958cd01087c7e7e7e7e7eb976c9",
  "94765193bc7c7eb976c976",
  "94015e937cbc7eaa02000001aa7e01207e7c7e01877eb900ccc38769007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a757575757575757575757575516776529c6375b9cb5e795a795a795a795a79",
  "d0519c69",
  "d2519c69",
  "00d176c97878",
  "02d30193",
  "93945279bc5279bf78aa02000001aa7e01207e7c7e01877e876976",
  "007c7f7882",
  "7c7f7602d3015b94007c7f788202d3015b947c7f765b007c7f78825b7c7f5579787eaa",
  "87697852007c7f527982527c7f7802010087697651007c7f7882517c7f7801088769",
  "00d3c35a7959797e02010001087e5379519358cd7e7e56797eaa02000001aa7e01207e7c7e01877e8769011179827c75012096009c6900c3",
  "030000207c7e01ac7e876900c20117799c69",
  "200000000000000000000000000000000000000000000000000000000000000000879169",
  "d07651a16976519c63",
  "d2519c69",
  "00d176b37651a2697658a169",
  "200000000000000000000000000000000000000000000000000000000000000000005379009458a1697654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577687654799f637676b99e637656799e6376cf7655798791637654798769687568687651937b7577685579bf56795779c9",
  "012e93",
  "93945879c9",
  "012e93",
  "9394",
  "012e93",
  "9393bcaa02000001aa7e01207e7c7e01877e876955795679c9",
  "012e93",
  "93945779c9",
  "012e93",
  "9394",
  "93bc56795779c9",
  "012e93",
  "9394",
  "93012e935879c9",
  "012e93",
  "9394",
  "93012e93",
  "93bc7e",
  "7caa876955795679c9",
  "012e93",
  "9394",
  "5193935779c9",
  "012e93",
  "9394",
  "519393012093bc56795779c9",
  "012e93",
  "9394",
  "012293935879c9",
  "012e93",
  "9394",
  "012293935193bc57795879c9",
  "012e93",
  "9394",
  "012493935979c9",
  "012e93",
  "9394",
  "012493935893bc58795979c9",
  "012e93",
  "9394",
  "012d93935a79c9",
  "012e93",
  "9394",
  "012d93935193bc5979c976",
  "012e93",
  "93945579b9cf8769547901028769011d79",
  "8769011c7901008769011a799169011b7954799c695b79785279",
  "93bc5c795379",
  "945479bc7e",
  "7caa8769011d7901207c7e011d7901017c7e011d7958cd01087c7e011d7951cd01017c7e7e7e7e5c7952795379",
  "93bc7c7e5c795379",
  "945479bc7eaa02000001aa7e01207e7c7e01877e",
  "00d3c3876975757575757575757575757567b37651a2697658a169",
  "200000000000000000000000000000000000000000000000000000000000000000005379009458a1697654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b7577687654799f637676b99e6376cf76557987916376547987696875687651937b757768757575756801127901147951a16901147978827c750120969c6900011579009451a169760116799f6376527978012095760120937f01207c7e012479527958957658937f58cd01087c7e012479537958957658937f58cd01087c7e0124795479012095760120937f01207c7e012479557958957658937f58cd01087c7e7e7e7e7eb976c9",
  "94765193bc7c7eb976c976",
  "94015e937cbc7eaa02000001aa7e01207e7c7e01877eb95279ccc387697651937b757768007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a75007a7575757575757575757575757575755167750069686868",
]);
const VAULT_SCRIPT_SKELETON_SHA256_V7 = "b67f8ce8a4e6459dc6b62bc3afa0ddcee25b9f4c93b91543021818a81a3d64fc"; // sha256(chunks.join("|") + "#" + holes.join(","))

const VAULT_SCRIPT_PIN_HOLES_V7 = Object.freeze(["tokenCovenantId", "descriptorHash", "templateVmHash", "templatePrefixLen", "templateSuffixLen", "orgRootCovenantId", "rootTemplateVmHash", "rootPrefixLen", "rootSuffixLen", "recoveryPk"]);
const VAULT_SCRIPT_INT_HOLES_V7 = new Set(["templatePrefixLen", "templateSuffixLen", "rootPrefixLen", "rootSuffixLen"]);

function fail(message, code) {
  const e = new Error(`vault-script-v7: ${message}`);
  e.code = code || "VAULT_SCRIPT_INVALID";
  throw e;
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function le8Hex(value, field) {
  const v = BigInt(value);
  if (v < 0n || v > 0xffffffffffffffffn) fail(`${field} outside the 8-byte domain`);
  let out = "";
  let x = v;
  for (let i = 0; i < 8; i++) { out += Number(x & 0xffn).toString(16).padStart(2, "0"); x >>= 8n; }
  return out;
}
function hex64(value, field) {
  const h = String(value || "").toLowerCase();
  if (!HEX64.test(h)) fail(`${field} must be 32 bytes of hex`);
  return h;
}

/* The exact 93-byte state region (hex) for a vault id + mutable state. */
function serializeVaultStateRegionHexV7({ vaultId, state }) {
  const s = normalizeStateV7(state);
  return "20" + hex64(vaultId, "vaultId") + "08" + le8Hex(s.feeReserve, "feeReserve") + "08" + le8Hex(s.paused, "paused") + "20" + s.agentRoot + "08" + le8Hex(s.policyNonce, "policyNonce");
}

/* Strict inverse: decode a 93-byte region (hex) or fail closed. */
function parseVaultStateRegionHexV7(regionHex) {
  const r = String(regionHex || "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(r) || r.length !== VAULT_STATE_REGION_LEN_V7 * 2) fail("state region must be exactly 93 bytes of hex");
  let p = 0;
  const take = (n) => { const out = r.slice(p, p + n * 2); p += n * 2; return out; };
  const opcode = (expected, what) => { if (take(1) !== expected) fail(`${what}: unexpected push opcode`); };
  const le8 = (what) => { const h = take(8); let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(parseInt(h.substr(i * 2, 2), 16)); return v; };
  opcode("20", "boundVaultId"); const vaultId = take(32);
  opcode("08", "feeReserve"); const feeReserve = le8("feeReserve");
  opcode("08", "paused"); const paused = le8("paused");
  opcode("20", "agentRoot"); const agentRoot = take(32);
  opcode("08", "policyNonce"); const policyNonce = le8("policyNonce");
  return Object.freeze({ vaultId, state: Object.freeze({ feeReserve: feeReserve.toString(), paused: paused.toString(), agentRoot, policyNonce: policyNonce.toString() }) });
}

/* Split a revealed v0.7-payment redeem script into prefix / region / suffix. */
function splitVaultRedeemHexV7(redeemHex) {
  const h = String(redeemHex || "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(h) || h.length % 2 !== 0) fail("redeem script must be hex", "VAULT_SCRIPT_INVALID");
  const minLen = VAULT_SCRIPT_PREFIX_LEN_V7 + VAULT_STATE_REGION_LEN_V7 + 1;
  if (h.length / 2 < minLen) fail("redeem script is shorter than prefix + state region + suffix", "VAULT_SCRIPT_INVALID");
  const prefixHex = h.slice(0, VAULT_SCRIPT_PREFIX_LEN_V7 * 2);
  const regionHex = h.slice(VAULT_SCRIPT_PREFIX_LEN_V7 * 2, (VAULT_SCRIPT_PREFIX_LEN_V7 + VAULT_STATE_REGION_LEN_V7) * 2);
  const suffixHex = h.slice((VAULT_SCRIPT_PREFIX_LEN_V7 + VAULT_STATE_REGION_LEN_V7) * 2);
  return Object.freeze({ prefixHex, regionHex, suffixHex, decoded: parseVaultStateRegionHexV7(regionHex) });
}

/* Version-0 P2SH scriptPublicKey (script hex, no wire version prefix). */
function p2shSpkHexOf(redeemHex) { return "aa20" + blake2bHex(hexToBytes(String(redeemHex).toLowerCase()), 32) + "87"; }

/* The successor redeem script: the predecessor's template around the successor state. */
function reconstructVaultSuccessorHexV7({ redeemHex, vaultId, state }) {
  const parts = splitVaultRedeemHexV7(redeemHex);
  return parts.prefixHex + serializeVaultStateRegionHexV7({ vaultId, state }) + parts.suffixHex;
}
function reconstructVaultSuccessorSpkHexV7(args) { return p2shSpkHexOf(reconstructVaultSuccessorHexV7(args)); }

/* Minimal script-number push (the encoding silverc emits for integer
 * constants): 0 -> OP_0 (0x00), 1..16 -> OP_1..OP_16, otherwise
 * OP_DATA_n + little-endian magnitude with a sign-bit pad byte. */
function pushScriptNumHex(value) {
  let v = BigInt(value);
  if (v < 0n) fail("negative constants are not used by the rooted vault covenant");
  if (v === 0n) return "00";
  if (v <= 16n) return (0x50 + Number(v)).toString(16);
  const bytes = [];
  while (v > 0n) { bytes.push(Number(v & 0xffn)); v >>= 8n; }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
  if (bytes.length > 75) fail("constant too large for a direct push");
  return bytes.length.toString(16).padStart(2, "0") + bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/*
 * The exact frozen v0.7-payment SUFFIX (template code) for a set of template
 * pins. `template` is normalized by the model (well-formed pins only). The
 * script's own length is pushed inside the suffix, so the length is solved as
 * a fixed point (the push width can change the length it encodes).
 */
function reconstructVaultSuffixHexV7(template) {
  const t = normalizeTemplateV7(template);
  const constants = {};
  for (const name of VAULT_SCRIPT_PIN_HOLES_V7) constants[name] = VAULT_SCRIPT_INT_HOLES_V7.has(name) ? pushScriptNumHex(t[name]) : "20" + hex64(t[name], name);
  const assemble = (lenPush) => {
    let out = "";
    for (let i = 0; i < VAULT_SCRIPT_HOLES_V7.length; i++) {
      out += VAULT_SCRIPT_CHUNKS_V7[i];
      const h = VAULT_SCRIPT_HOLES_V7[i];
      out += h === "scriptLen" ? lenPush : constants[h];
    }
    return out + VAULT_SCRIPT_CHUNKS_V7[VAULT_SCRIPT_CHUNKS_V7.length - 1];
  };
  let lenPush = pushScriptNumHex(VAULT_SCRIPT_PREFIX_LEN_V7 + VAULT_STATE_REGION_LEN_V7 + assemble("020000").length / 2);
  for (let round = 0; round < 4; round++) {
    const suffix = assemble(lenPush);
    const next = pushScriptNumHex(VAULT_SCRIPT_PREFIX_LEN_V7 + VAULT_STATE_REGION_LEN_V7 + suffix.length / 2);
    if (next === lenPush) return suffix;
    lenPush = next;
  }
  return fail("the script length did not converge");
}

/* The exact redeem script (hex) for template pins + a vault state:
 * prefix || region(vaultId, state) || suffix(pins). */
function reconstructVaultScriptHexV7({ template, state }) {
  const t = normalizeTemplateV7(template);
  return VAULT_SCRIPT_PREFIX_HEX_V7 + serializeVaultStateRegionHexV7({ vaultId: t.vaultId, state }) + reconstructVaultSuffixHexV7(t);
}
function reconstructVaultScriptSpkHexV7(args) { return p2shSpkHexOf(reconstructVaultScriptHexV7(args)); }

/*
 * Read the template pins OUT OF a revealed redeem script by walking the
 * frozen skeleton: every constant chunk must appear verbatim at its place and
 * every hole must hold a well-formed push of the expected kind; all holes of
 * one constant must agree and the six length holes must be the script's own
 * length. Returns { vaultId, state, pins } or throws — so a script of ANOTHER
 * generation (an HD candidate, a KAS profile, a foreign covenant) is never
 * mistaken for a v0.7-payment vault, and a v0.7-payment vault can never be
 * presented under another generation label.
 */
function decodeVaultTemplatePinsV7(redeemHex) {
  const parts = splitVaultRedeemHexV7(redeemHex);
  const s = parts.suffixHex;
  let p = 0;
  const holes = {}; // decoded hole contents (script geometry lengths + 32-byte pins) — NOT amounts
  const readIntPush = (what) => {
    const op = parseInt(s.slice(p, p + 2), 16);
    if (Number.isNaN(op)) fail(`${what}: truncated push`, "VAULT_GENERATION_MISMATCH");
    if (op === 0x00) { p += 2; return 0n; }
    if (op >= 0x51 && op <= 0x60) { p += 2; return BigInt(op - 0x50); }
    if (op >= 0x01 && op <= 0x4b) {
      const data = s.slice(p + 2, p + 2 + op * 2);
      if (data.length !== op * 2) fail(`${what}: truncated push`, "VAULT_GENERATION_MISMATCH");
      let v = 0n;
      for (let i = op - 1; i >= 0; i--) v = (v << 8n) | BigInt(parseInt(data.substr(i * 2, 2), 16));
      if (pushScriptNumHex(v) !== s.slice(p, p + 2 + op * 2)) fail(`${what}: non-minimal integer push`, "VAULT_GENERATION_MISMATCH");
      p += 2 + op * 2;
      return v;
    }
    return fail(`${what}: not an integer push`, "VAULT_GENERATION_MISMATCH");
  };
  const readBytes32Push = (what) => {
    if (s.slice(p, p + 2) !== "20") fail(`${what}: not a 32-byte push`, "VAULT_GENERATION_MISMATCH");
    const v = s.slice(p + 2, p + 66);
    if (!HEX64.test(v)) fail(`${what}: truncated 32-byte push`, "VAULT_GENERATION_MISMATCH");
    p += 66;
    return v;
  };
  for (let i = 0; i < VAULT_SCRIPT_HOLES_V7.length; i++) {
    const chunk = VAULT_SCRIPT_CHUNKS_V7[i];
    if (s.slice(p, p + chunk.length) !== chunk) fail(`the script is not the frozen v0.7-payment generation (chunk ${i} differs)`, "VAULT_GENERATION_MISMATCH");
    p += chunk.length;
    const h = VAULT_SCRIPT_HOLES_V7[i];
    const v = h === "scriptLen" || VAULT_SCRIPT_INT_HOLES_V7.has(h) ? readIntPush(h) : readBytes32Push(h);
    if (Object.prototype.hasOwnProperty.call(holes, h)) { if (holes[h] !== v) fail(`the script's ${h} constants disagree`, "VAULT_GENERATION_MISMATCH"); } else holes[h] = v;
  }
  const last = VAULT_SCRIPT_CHUNKS_V7[VAULT_SCRIPT_CHUNKS_V7.length - 1];
  if (s.slice(p) !== last) fail("the script is not the frozen v0.7-payment generation (tail differs)", "VAULT_GENERATION_MISMATCH");
  if (holes.scriptLen !== BigInt(String(redeemHex).length / 2)) fail("the script's own length constant is not its length", "VAULT_GENERATION_MISMATCH");
  const pins = {
    vaultId: parts.decoded.vaultId,
    descriptorHash: holes.descriptorHash,
    tokenCovenantId: holes.tokenCovenantId,
    templateVmHash: holes.templateVmHash,
    templatePrefixLen: Number(holes.templatePrefixLen),
    templateStateLen: 46,
    templateSuffixLen: Number(holes.templateSuffixLen),
    orgRootCovenantId: holes.orgRootCovenantId,
    rootTemplateVmHash: holes.rootTemplateVmHash,
    rootPrefixLen: Number(holes.rootPrefixLen),
    rootStateLen: 467,
    rootSuffixLen: Number(holes.rootSuffixLen),
    recoveryPk: holes.recoveryPk
  };
  return Object.freeze({ vaultId: parts.decoded.vaultId, state: parts.decoded.state, pins: Object.freeze(pins) });
}
function isPaymentGenerationScriptV7(redeemHex) {
  try { decodeVaultTemplatePinsV7(redeemHex); return true; } catch { return false; }
}

/* The template pins a rooted-vault manifest declares, in the model's shape
 * (the verifier hands its declared `vault` block here; nothing is trusted
 * until the rebuilt script is the one the transaction spends). */
function templatePinsFromManifestVault(vault) {
  return {
    vaultId: vault.vaultId,
    descriptorHash: vault.descriptorHash,
    tokenCovenantId: vault.tokenCovenantId,
    templateVmHash: vault.templateVmHashBlake2b256,
    templatePrefixLen: vault.templateGeometry.prefixLen,
    templateStateLen: vault.templateGeometry.stateLen,
    templateSuffixLen: vault.templateGeometry.suffixLen,
    orgRootCovenantId: vault.orgRootCovenantId,
    rootTemplateVmHash: vault.rootTemplateVmHash,
    rootPrefixLen: vault.rootGeometry.prefixLen,
    rootStateLen: vault.rootGeometry.stateLen,
    rootSuffixLen: vault.rootGeometry.suffixLen,
    recoveryPk: vault.recoveryPk
  };
}

module.exports = Object.freeze({
  VAULT_SCRIPT_PREFIX_LEN_V7,
  VAULT_STATE_REGION_LEN_V7,
  VAULT_SCRIPT_PREFIX_HEX_V7,
  VAULT_SCRIPT_HOLES_V7,
  VAULT_SCRIPT_CHUNKS_V7,
  VAULT_SCRIPT_SKELETON_SHA256_V7,
  VAULT_SCRIPT_PIN_HOLES_V7,
  serializeVaultStateRegionHexV7,
  parseVaultStateRegionHexV7,
  splitVaultRedeemHexV7,
  p2shSpkHexOf,
  reconstructVaultSuccessorHexV7,
  reconstructVaultSuccessorSpkHexV7,
  pushScriptNumHex,
  reconstructVaultSuffixHexV7,
  reconstructVaultScriptHexV7,
  reconstructVaultScriptSpkHexV7,
  decodeVaultTemplatePinsV7,
  isPaymentGenerationScriptV7,
  templatePinsFromManifestVault
});
