"use strict";

/*
 * Shared-core extraction step 2 — golden determinism battery.
 *
 * computeGolden2(mods) exercises the DETERMINISTIC surface of the nine
 * step-2 modules (vault-state-v2/-v3/-v4, vault-transitions-v3/-v4,
 * recipient-merkle-v3, fee-mass, compute-budget-v3/-v4) and returns a
 * plain-JSON-safe object (BigInt/Buffer encoded via step 1's `encode`).
 * The SAME battery runs against the original sdk implementations
 * (fixture capture, BEFORE the step-2 extraction refactor) and against
 * core/model + the sdk re-export shims (AFTER) — byte-identical results
 * prove the move changed nothing.
 *
 * `mods` = { vaultStateV2, vaultStateV3, vaultStateV4,
 *            vaultTransitionsV3, vaultTransitionsV4, recipientMerkle,
 *            feeMass, computeBudgetV3, computeBudgetV4, agentMerkle } —
 * module objects are passed IN so this file has no implementation
 * dependency direction (agentMerkle, moved in step 1, is needed to build
 * the agent trees/proofs the v4 transition battery consumes; it is taken
 * from the SAME require root as everything else).
 */

const { encode } = require("./golden");

const HEX = (b) => b.repeat(32); // "ab" -> 64-hex

/* Capture a thrown error's observable identity (message + code). */
function threw(fn) {
  try {
    const v = fn();
    return { threw: false, value: encode(v) };
  } catch (error) {
    return { threw: true, message: error.message, code: error.code ?? null };
  }
}

function apiSurface(mod) {
  const keys = Object.keys(mod).sort();
  const types = {};
  for (const k of keys) types[k] = typeof mod[k];
  return { keys, types };
}

/* ------------------------------------------------------------ v0.2 state */
function goldenVaultStateV2(m) {
  const {
    CONTRACT_VERSION_V2,
    normalizeTemplateV2,
    normalizeStateV2,
    computeStateIdV2,
    spendSuccessorV2,
    rolloverSuccessorV2,
    pauseSuccessorV2,
    revokeSuccessorV2,
    rotateSuccessorV2,
    topUpSuccessorV2,
    migrateSuccessorV2,
    stateToJson
  } = m;

  const template = normalizeTemplateV2({ owner: HEX("11"), vaultId: HEX("33") });
  const stateIn = (over = {}) => ({
    protectedValue: "5000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: HEX("22"),
    maxPerSpend: "100000000",
    periodBudget: "1000000000",
    periodLengthDaa: "86400",
    recipients: [HEX("aa"), HEX("bb"), HEX("cc")],
    delegateActive: "1",
    policyNonce: "0",
    ...over
  });
  const s1 = normalizeStateV2(stateIn());
  const sOne = normalizeStateV2(stateIn({ recipients: [HEX("aa")] }));
  const sTwo = normalizeStateV2(stateIn({ recipients: [HEX("bb"), HEX("aa")] }));

  return {
    constants: { CONTRACT_VERSION_V2 },
    template: encode(template),
    normalizeState: {
      three: encode(s1),
      onePadded: encode(sOne),
      twoPadded: encode(sTwo),
      rejects: {
        zeroRecipients: threw(() => normalizeStateV2(stateIn({ recipients: [] }))),
        fourRecipients: threw(() => normalizeStateV2(stateIn({ recipients: [HEX("aa"), HEX("bb"), HEX("cc"), HEX("dd")] }))),
        budgetBelowMax: threw(() => normalizeStateV2(stateIn({ periodBudget: "1" }))),
        pausedTwo: threw(() => normalizeStateV2(stateIn({ paused: "2" }))),
        daaOverThreshold: threw(() => normalizeStateV2(stateIn({ periodStartDaa: "500000000000" }))),
        zeroProtected: threw(() => normalizeStateV2(stateIn({ protectedValue: "0" }))),
        nonceOverflow: threw(() => normalizeStateV2(stateIn({ policyNonce: "1000000001" }))),
        missing: threw(() => normalizeStateV2(null))
      }
    },
    stateIds: {
      testnet: computeStateIdV2({ networkId: "testnet-10", template, state: s1 }),
      mainnet: computeStateIdV2({ networkId: "mainnet", template, state: s1 }),
      onePadded: computeStateIdV2({ networkId: "testnet-10", template, state: sOne }),
      rejects: { emptyNetwork: threw(() => computeStateIdV2({ networkId: "", template, state: s1 })) }
    },
    successors: {
      spend: encode(spendSuccessorV2(s1, "100000000")),
      rollover: encode(rolloverSuccessorV2(s1, "100000000", "3")),
      pause: encode(pauseSuccessorV2(s1, true)),
      unpauseAfterPause: encode(pauseSuccessorV2(pauseSuccessorV2(s1, true), false)),
      revoke: encode(revokeSuccessorV2(s1)),
      rotate: encode(rotateSuccessorV2(s1, HEX("44"))),
      topUp: encode(topUpSuccessorV2(s1, "250000000")),
      migrate: encode(migrateSuccessorV2(s1, { maxPerSpend: "200000000", recipients: [HEX("dd")] })),
      rejects: {
        spendOverMax: threw(() => spendSuccessorV2(s1, "100000001")),
        spendOverBudget: threw(() => spendSuccessorV2({ ...s1, periodSpent: 950000000n }, "100000000")),
        spendAll: threw(() => spendSuccessorV2({ ...s1, protectedValue: 100000000n }, "100000000")),
        spendPaused: threw(() => spendSuccessorV2(pauseSuccessorV2(s1, true), "1")),
        spendRevoked: threw(() => spendSuccessorV2(revokeSuccessorV2(s1), "1")),
        rolloverZeroPeriods: threw(() => rolloverSuccessorV2(s1, "100000000", "0")),
        rolloverTooMany: threw(() => rolloverSuccessorV2(s1, "100000000", "1001")),
        pauseAgain: threw(() => pauseSuccessorV2(pauseSuccessorV2(s1, true), true)),
        revokeAgain: threw(() => revokeSuccessorV2(revokeSuccessorV2(s1)))
      }
    },
    stateToJson: stateToJson(s1)
  };
}

/* ------------------------------------------------------------ v0.3 state */
function goldenVaultStateV3(m) {
  const {
    CONTRACT_VERSION_V3,
    MAX_APPROVERS,
    APPROVER_SENTINEL,
    normalizeTemplateV3,
    normalizeStateV3,
    normalizeStateV3ForRecovery,
    normalizeApprovers,
    normalizeRecipientRoot,
    computeStateIdV3,
    stateToJsonV3
  } = m;

  const template = normalizeTemplateV3({ owner: HEX("11"), vaultId: HEX("33") });
  const stateIn = (over = {}) => ({
    protectedValue: "5000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: HEX("22"),
    delegateActive: "1",
    maxPerSpend: "100000000",
    periodBudget: "1000000000",
    periodLengthDaa: "86400",
    recipientRoot: HEX("ee"),
    approvers: [HEX("a3"), HEX("a1"), HEX("a2")],
    approvalM: "2",
    approvalThresholdAmount: "50000000",
    policyNonce: "0",
    ...over
  });
  const s3 = normalizeStateV3(stateIn());
  const sNoApprovers = normalizeStateV3(stateIn({ approvers: [], approvalM: "0", approvalThresholdAmount: "100000000" }));
  const slotLayout = [APPROVER_SENTINEL, HEX("a2"), APPROVER_SENTINEL, HEX("a1"), ...Array(6).fill(APPROVER_SENTINEL)];
  const sSlots = normalizeStateV3(stateIn({ approvers: undefined, approverSlots: slotLayout, approvalM: "1" }));
  const recovered = normalizeStateV3ForRecovery(
    stateIn({ approvers: [HEX("a1"), HEX("a1")], approvalM: "99", paused: "7", delegateActive: "0", periodBudget: "1" })
  );

  return {
    constants: { CONTRACT_VERSION_V3, MAX_APPROVERS, APPROVER_SENTINEL },
    template: encode(template),
    normalizeApprovers: {
      canonicalized: encode(normalizeApprovers({ approvers: [HEX("a3"), HEX("a1"), HEX("a2")] })),
      slotsPreserved: encode(normalizeApprovers({ approverSlots: slotLayout })),
      rejects: {
        tooMany: threw(() => normalizeApprovers({ approvers: Array.from({ length: 11 }, (_, i) => HEX((10 + i).toString(16))) })),
        duplicate: threw(() => normalizeApprovers({ approvers: [HEX("a1"), HEX("a1")] })),
        sentinelActive: threw(() => normalizeApprovers({ approvers: [APPROVER_SENTINEL] })),
        slotsWrongLength: threw(() => normalizeApprovers({ approverSlots: [HEX("a1")] })),
        slotsDuplicate: threw(() => normalizeApprovers({ approverSlots: [HEX("a1"), HEX("a1"), ...Array(8).fill(APPROVER_SENTINEL)] }))
      }
    },
    normalizeRecipientRoot: {
      accepts: normalizeRecipientRoot(HEX("EE")),
      rejects: threw(() => normalizeRecipientRoot("1234"))
    },
    normalizeState: {
      withApprovers: encode(s3),
      noApproverTier: encode(sNoApprovers),
      slotLayoutPreserved: encode(sSlots),
      rejects: {
        mZeroWithApprovers: threw(() => normalizeStateV3(stateIn({ approvalM: "0" }))),
        mOverActive: threw(() => normalizeStateV3(stateIn({ approvalM: "4" }))),
        noApproversThresholdBelowMax: threw(() =>
          normalizeStateV3(stateIn({ approvers: [], approvalM: "0", approvalThresholdAmount: "99999999" }))
        ),
        budgetBelowMax: threw(() => normalizeStateV3(stateIn({ periodBudget: "1" }))),
        daaOverThreshold: threw(() => normalizeStateV3(stateIn({ periodStartDaa: "500000000000" }))),
        missingNonce: threw(() => normalizeStateV3(stateIn({ policyNonce: undefined }))),
        missing: threw(() => normalizeStateV3(null))
      }
    },
    recoveryParse: {
      malformedAccepted: encode(recovered),
      rejects: {
        tooManySlots: threw(() =>
          normalizeStateV3ForRecovery(stateIn({ approvers: Array.from({ length: 11 }, (_, i) => HEX((10 + i).toString(16))) }))
        ),
        badHex: threw(() => normalizeStateV3ForRecovery(stateIn({ approvers: ["zz"] })))
      }
    },
    stateIds: {
      testnet: computeStateIdV3({ networkId: "testnet-10", template, state: s3 }),
      mainnet: computeStateIdV3({ networkId: "mainnet", template, state: s3 }),
      slots: computeStateIdV3({ networkId: "testnet-10", template, state: sSlots }),
      rejects: {
        emptyNetwork: threw(() => computeStateIdV3({ networkId: "", template, state: s3 })),
        missingNonce: threw(() => computeStateIdV3({ networkId: "testnet-10", template, state: { ...s3, policyNonce: "0" } }))
      }
    },
    stateToJson: stateToJsonV3(s3)
  };
}

/* ------------------------------------------------------ v0.3 transitions */
function goldenVaultTransitionsV3(m, stateMod) {
  const {
    spendSuccessorV3,
    rolloverSuccessorV3,
    pauseSuccessorV3,
    revokeSuccessorV3,
    rotateSuccessorV3,
    topUpSuccessorV3,
    migrateSuccessorV3,
    setRecipientRootSuccessorV3,
    setApproversSuccessorV3,
    recoverPlanV3,
    MAX_APPROVERS
  } = m;
  const { normalizeStateV3, normalizeStateV3ForRecovery } = stateMod;

  const stateIn = (over = {}) => ({
    protectedValue: "5000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: HEX("22"),
    delegateActive: "1",
    maxPerSpend: "100000000",
    periodBudget: "1000000000",
    periodLengthDaa: "86400",
    recipientRoot: HEX("ee"),
    approvers: [HEX("a3"), HEX("a1"), HEX("a2")],
    approvalM: "2",
    approvalThresholdAmount: "50000000",
    policyNonce: "5",
    ...over
  });
  const s = normalizeStateV3(stateIn());
  const paused = normalizeStateV3(stateIn({ paused: "1" }));
  const recovered = normalizeStateV3ForRecovery(stateIn());

  return {
    constants: { MAX_APPROVERS },
    successors: {
      spend: encode(spendSuccessorV3(s, "100000000")),
      rollover: encode(rolloverSuccessorV3(s, "100000000", "3")),
      pause: encode(pauseSuccessorV3(s, true)),
      unpause: encode(pauseSuccessorV3(paused, false)),
      revoke: encode(revokeSuccessorV3(s)),
      rotate: encode(rotateSuccessorV3(s, HEX("44"))),
      topUp: encode(topUpSuccessorV3(s, "250000000")),
      migrate: encode(migrateSuccessorV3(s, { maxPerSpend: "200000000", periodBudget: "2000000000" })),
      setRecipientRoot: encode(setRecipientRootSuccessorV3(s, HEX("ff"))),
      setApprovers: encode(setApproversSuccessorV3(s, { approvers: [HEX("b2"), HEX("b1")], approvalM: "1", approvalThresholdAmount: "0" })),
      recoverStrict: encode(recoverPlanV3(s, HEX("11"))),
      recoverFromRecoveryParse: encode(recoverPlanV3(recovered, HEX("11")))
    },
    rejects: {
      spendPaused: threw(() => spendSuccessorV3(paused, "1")),
      spendRevoked: threw(() => spendSuccessorV3(revokeSuccessorV3(s), "1")),
      spendOverMax: threw(() => spendSuccessorV3(s, "100000001")),
      spendOverBudget: threw(() => spendSuccessorV3(rolloverSuccessorV3(s, "100000000", "1"), "1000000000")),
      spendAll: threw(() => spendSuccessorV3(normalizeStateV3(stateIn({ protectedValue: "100000000" })), "100000000")),
      rolloverZeroPeriods: threw(() => rolloverSuccessorV3(s, "100000000", "0")),
      rolloverTooMany: threw(() => rolloverSuccessorV3(s, "100000000", "1001")),
      pauseAgain: threw(() => pauseSuccessorV3(paused, true)),
      revokeAgain: threw(() => revokeSuccessorV3(revokeSuccessorV3(s))),
      migrateForeignKey: threw(() => migrateSuccessorV3(s, { recipientRoot: HEX("ff") })),
      setApproversEmpty: threw(() => setApproversSuccessorV3(s, { approvers: [], approvalM: "0", approvalThresholdAmount: "100000000" })),
      setApproversMissingM: threw(() => setApproversSuccessorV3(s, { approvers: [HEX("b1")], approvalThresholdAmount: "0" })),
      recoveryParseRefused: threw(() => spendSuccessorV3(recovered, "1")),
      recoverBadState: threw(() => recoverPlanV3({}, HEX("11")))
    }
  };
}

/* ------------------------------------------------------------ v0.4 state */
function goldenVaultStateV4(m) {
  const {
    CONTRACT_VERSION_V4,
    CONTRACT_VERSION_V4_1,
    V4_ABIS,
    OWNER_OP_SELECTOR_V4_1,
    resolveV4Abi,
    MAX_APPROVERS,
    APPROVER_SENTINEL,
    normalizeTemplateV4,
    normalizeStateV4,
    normalizeStateV4ForRecovery,
    normalizeApprovers,
    computeStateIdV4,
    stateToJsonV4
  } = m;

  const template = normalizeTemplateV4({ owner: HEX("11"), vaultId: HEX("33") });
  const stateIn = (over = {}) => ({
    protectedValue: "5000000000",
    feeReserve: "300000000",
    paused: "0",
    agentRoot: HEX("e7"),
    approvers: [HEX("a3"), HEX("a1"), HEX("a2")],
    approvalM: "2",
    policyNonce: "0",
    ...over
  });
  const s4 = normalizeStateV4(stateIn());
  const sZero = normalizeStateV4(stateIn({ approvers: [], approvalM: "0" }));
  const slotLayout = [APPROVER_SENTINEL, HEX("a2"), APPROVER_SENTINEL, HEX("a1"), ...Array(6).fill(APPROVER_SENTINEL)];
  const sSlots = normalizeStateV4(stateIn({ approvers: undefined, approverSlots: slotLayout, approvalM: "1" }));
  const recovered = normalizeStateV4ForRecovery(stateIn({ approvers: [HEX("a1"), HEX("a1")], approvalM: "99", paused: "7" }));

  return {
    constants: encode({ CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1, V4_ABIS, OWNER_OP_SELECTOR_V4_1, MAX_APPROVERS, APPROVER_SENTINEL }),
    resolveAbi: {
      v4: encode(resolveV4Abi(CONTRACT_VERSION_V4)),
      v41: encode(resolveV4Abi(CONTRACT_VERSION_V4_1)),
      defaultUndefined: encode(resolveV4Abi(undefined)),
      defaultNull: encode(resolveV4Abi(null)),
      rejects: {
        unknown: threw(() => resolveV4Abi("policyvault-9.9")),
        v3NotInFamily: threw(() => resolveV4Abi("policyvault-0.3"))
      }
    },
    template: encode(template),
    normalizeState: {
      withApprovers: encode(s4),
      zeroApprovers: encode(sZero),
      slotLayoutPreserved: encode(sSlots),
      rejects: {
        mZeroWithApprovers: threw(() => normalizeStateV4(stateIn({ approvalM: "0" }))),
        mOverActive: threw(() => normalizeStateV4(stateIn({ approvalM: "4" }))),
        mNonZeroNoApprovers: threw(() => normalizeStateV4(stateIn({ approvers: [], approvalM: "1" }))),
        pausedTwo: threw(() => normalizeStateV4(stateIn({ paused: "2" }))),
        zeroProtected: threw(() => normalizeStateV4(stateIn({ protectedValue: "0" }))),
        negativeReserve: threw(() => normalizeStateV4(stateIn({ feeReserve: "-1" }))),
        badAgentRoot: threw(() => normalizeStateV4(stateIn({ agentRoot: "1234" }))),
        duplicateApprovers: threw(() => normalizeStateV4(stateIn({ approvers: [HEX("a1"), HEX("a1")] }))),
        missing: threw(() => normalizeStateV4(null))
      }
    },
    normalizeApprovers: {
      canonicalized: encode(normalizeApprovers({ approvers: [HEX("a3"), HEX("a1")] })),
      slotsPreserved: encode(normalizeApprovers({ approverSlots: slotLayout }))
    },
    recoveryParse: {
      malformedAccepted: encode(recovered),
      rejects: { tooManySlots: threw(() => normalizeStateV4ForRecovery(stateIn({ approvers: Array.from({ length: 11 }, (_, i) => HEX((10 + i).toString(16))) }))) }
    },
    stateIds: {
      v4Testnet: computeStateIdV4({ networkId: "testnet-10", template, state: s4, contractVersion: CONTRACT_VERSION_V4 }),
      v41Testnet: computeStateIdV4({ networkId: "testnet-10", template, state: s4, contractVersion: CONTRACT_VERSION_V4_1 }),
      defaultIsV4: computeStateIdV4({ networkId: "testnet-10", template, state: s4 }),
      v4Mainnet: computeStateIdV4({ networkId: "mainnet", template, state: s4, contractVersion: CONTRACT_VERSION_V4 }),
      rejects: {
        emptyNetwork: threw(() => computeStateIdV4({ networkId: "", template, state: s4 })),
        missingNonce: threw(() => computeStateIdV4({ networkId: "testnet-10", template, state: { ...s4, policyNonce: "0" } }))
      }
    },
    stateToJson: stateToJsonV4(s4)
  };
}

/* ------------------------------------------------------ v0.4 transitions */
function goldenVaultTransitionsV4(m, stateMod, agentMerkle) {
  const {
    MAX_PERIODS_ELAPSED,
    agentSpendSuccessorV4,
    setAgentRootSuccessorV4,
    setApproversSuccessorV4,
    topUpSuccessorV4,
    topUpReserveSuccessorV4,
    pauseSuccessorV4,
    recoverPlanV4,
    MAX_APPROVERS
  } = m;
  const { normalizeStateV4, normalizeStateV4ForRecovery } = stateMod;
  const { buildAgentTreeV4, generateAgentProofV4 } = agentMerkle;

  const mkPolicy = (pkByte, over = {}) => ({
    agentPk: HEX(pkByte),
    maxPerSpend: "20000000000",
    periodBudget: "100000000000",
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: "5000000000",
    agentMaxFeePerTx: "100000000",
    agentRecipientRoot: HEX("f" + pkByte[0]),
    ...over
  });
  const A = mkPolicy("aa");
  const B = mkPolicy("bb", { periodSpent: "1500000000" });
  const C = mkPolicy("cc", { maxPerSpend: "1", periodBudget: "2", periodSpent: "2", approvalThreshold: "0", agentMaxFeePerTx: "0" });
  const tree = buildAgentTreeV4([A, B, C]);
  const proofA = generateAgentProofV4(tree, A.agentPk);
  const proofC = generateAgentProofV4(tree, C.agentPk);

  const stateIn = (over = {}) => ({
    protectedValue: "50000000000",
    feeReserve: "300000000",
    paused: "0",
    agentRoot: tree.root,
    approvers: [HEX("a3"), HEX("a1"), HEX("a2")],
    approvalM: "2",
    policyNonce: "7",
    ...over
  });
  const s = normalizeStateV4(stateIn());
  const sPaused = normalizeStateV4(stateIn({ paused: "1" }));
  const sNoApprovers = normalizeStateV4(stateIn({ approvers: [], approvalM: "0" }));
  const recovered = normalizeStateV4ForRecovery(stateIn());

  const spendArgs = (over = {}) => ({
    agentPolicy: A,
    agentProof: { siblingsHex: proofA.siblingsHex, pathBits: proofA.pathBits },
    payAmount: "1000000000",
    periodsElapsed: 0n,
    reserveConsumed: 0n,
    ...over
  });

  return {
    constants: encode({ MAX_PERIODS_ELAPSED, MAX_APPROVERS }),
    agentSpend: {
      belowThreshold: encode(agentSpendSuccessorV4(s, spendArgs())),
      withRollover: encode(agentSpendSuccessorV4(s, spendArgs({ periodsElapsed: 3n }))),
      aboveThreshold: encode(agentSpendSuccessorV4(s, spendArgs({ payAmount: "6000000000" }))),
      withReserve: encode(agentSpendSuccessorV4(s, spendArgs({ reserveConsumed: "50000000" }))),
      rejects: {
        paused: threw(() => agentSpendSuccessorV4(sPaused, spendArgs())),
        wrongRoot: threw(() =>
          agentSpendSuccessorV4(normalizeStateV4(stateIn({ agentRoot: HEX("00") })), spendArgs())
        ),
        forgedProof: threw(() =>
          agentSpendSuccessorV4(s, spendArgs({ agentProof: { siblingsHex: proofC.siblingsHex, pathBits: proofC.pathBits } }))
        ),
        overMaxPerSpend: threw(() => agentSpendSuccessorV4(s, spendArgs({ payAmount: "20000000001" }))),
        overBudget: threw(() =>
          agentSpendSuccessorV4(s, {
            agentPolicy: C,
            agentProof: { siblingsHex: proofC.siblingsHex, pathBits: proofC.pathBits },
            payAmount: "1",
            periodsElapsed: 0n,
            reserveConsumed: 0n
          })
        ),
        tooManyPeriods: threw(() => agentSpendSuccessorV4(s, spendArgs({ periodsElapsed: 1001n }))),
        drainsVault: threw(() => agentSpendSuccessorV4(normalizeStateV4(stateIn({ protectedValue: "1000000000" })), spendArgs())),
        overAgentFeeCap: threw(() => agentSpendSuccessorV4(s, spendArgs({ reserveConsumed: "100000001" }))),
        overReserve: threw(() =>
          agentSpendSuccessorV4(normalizeStateV4(stateIn({ feeReserve: "10000000" })), spendArgs({ reserveConsumed: "20000000" }))
        ),
        noApproverTier: threw(() => agentSpendSuccessorV4(sNoApprovers, spendArgs({ payAmount: "6000000000" }))),
        recoveryParseRefused: threw(() => agentSpendSuccessorV4(recovered, spendArgs())),
        missingProof: threw(() => agentSpendSuccessorV4(s, spendArgs({ agentProof: null })))
      }
    },
    ownerOps: {
      setAgentRoot: encode(setAgentRootSuccessorV4(s, HEX("dd"))),
      setApprovers: encode(setApproversSuccessorV4(s, { approvers: [HEX("b2"), HEX("b1")], approvalM: "1" })),
      setApproversSlots: encode(
        setApproversSuccessorV4(s, { approverSlots: [HEX("b1"), ...Array(9).fill("00".repeat(32))], approvalM: "1" })
      ),
      topUp: encode(topUpSuccessorV4(s, "250000000")),
      topUpReserve: encode(topUpReserveSuccessorV4(s, "70000000")),
      pause: encode(pauseSuccessorV4(s, true)),
      unpause: encode(pauseSuccessorV4(sPaused, false)),
      rejects: {
        setApproversEmpty: threw(() => setApproversSuccessorV4(s, { approvers: [], approvalM: "0" })),
        setApproversMissingM: threw(() => setApproversSuccessorV4(s, { approvers: [HEX("b1")] })),
        setApproversMissingSet: threw(() => setApproversSuccessorV4(s, { approvalM: "1" })),
        topUpZero: threw(() => topUpSuccessorV4(s, "0")),
        pauseAgain: threw(() => pauseSuccessorV4(sPaused, true)),
        unpauseActive: threw(() => pauseSuccessorV4(s, false)),
        recoveryParseRefused: threw(() => setAgentRootSuccessorV4(recovered, HEX("dd")))
      }
    },
    recover: {
      strict: encode(recoverPlanV4(s, HEX("11"))),
      fromRecoveryParse: encode(recoverPlanV4(recovered, HEX("11"))),
      rejects: { badState: threw(() => recoverPlanV4({}, HEX("11"))) }
    }
  };
}

/* --------------------------------------------------- recipient merkle v3 */
function goldenRecipientMerkle(m) {
  const { MAX_DEPTH, MAX_RECIPIENTS, LEAF_DOMAIN, leafHash, buildRecipientTree, generateRecipientProof, verifyRecipientProof } = m;

  const R = ["aa", "bb", "cc", "dd", "ee"].map(HEX);
  const t1 = buildRecipientTree([R[0]]);
  const t2 = buildRecipientTree([R[1], R[0]]);
  const t2dup = buildRecipientTree([R[0], R[1], R[0]]);
  const t3 = buildRecipientTree([R[2], R[0], R[1]]);
  const t5 = buildRecipientTree(R);

  const treeShape = (t) => ({ root: t.root, recipients: [...t.recipients], leafCount: t.leafCount, depth: t.depth });

  const proofs = {};
  for (const r of R) {
    const p = generateRecipientProof(t5, r);
    proofs[r] = {
      siblingsHex: p.siblingsHex,
      pathBits: p.pathBits.toString(),
      depth: p.depth,
      verifies: verifyRecipientProof({ root: t5.root, recipient: r, siblingsHex: p.siblingsHex, pathBits: p.pathBits }),
      wrongRoot: verifyRecipientProof({ root: HEX("00"), recipient: r, siblingsHex: p.siblingsHex, pathBits: p.pathBits })
    };
  }
  const pA = generateRecipientProof(t5, R[0]);

  return {
    constants: encode({ MAX_DEPTH, MAX_RECIPIENTS, LEAF_DOMAIN }),
    leafHashHex: leafHash(R[0]).toString("hex"),
    trees: {
      one: treeShape(t1),
      singleRootIsLeaf: t1.root === leafHash(R[0]).toString("hex"),
      two: treeShape(t2),
      dupCollapsed: t2dup.root === t2.root,
      three: treeShape(t3),
      five: treeShape(t5),
      rejects: {
        empty: threw(() => buildRecipientTree([])),
        notArray: threw(() => buildRecipientTree("nope")),
        badKey: threw(() => buildRecipientTree(["zz"]))
      }
    },
    proofs,
    verify: {
      excessPathBits: verifyRecipientProof({
        root: t5.root,
        recipient: R[0],
        siblingsHex: pA.siblingsHex,
        pathBits: pA.pathBits + (1n << BigInt(pA.depth))
      }),
      rejects: {
        notInTree: threw(() => generateRecipientProof(t5, HEX("77"))),
        oddHex: threw(() => verifyRecipientProof({ root: t5.root, recipient: R[0], siblingsHex: "abc", pathBits: 0n })),
        notMultipleOf32: threw(() => verifyRecipientProof({ root: t5.root, recipient: R[0], siblingsHex: "ab".repeat(31), pathBits: 0n })),
        tooDeep: threw(() => verifyRecipientProof({ root: t5.root, recipient: R[0], siblingsHex: "ab".repeat(32 * 17), pathBits: 0n })),
        pathBitsOutOfRange: threw(() => verifyRecipientProof({ root: t5.root, recipient: R[0], siblingsHex: pA.siblingsHex, pathBits: 65536n }))
      }
    }
  };
}

/* --------------------------------------------------------------- fee-mass */
function goldenFeeMass(m) {
  const {
    MINIMUM_RELAY_TRANSACTION_FEE,
    STANDARD_MASS_CAP,
    estimatedSerializedSize,
    computeMass,
    feeMass,
    calculateRequiredFee,
    describeWasmTransaction,
    validateComputeBudget,
    finalizeWithExactFee
  } = m;

  const smallTx = {
    version: 1,
    payloadHex: "",
    inputs: [{ signatureScriptHex: "ab".repeat(66), computeBudget: 10 }],
    outputs: [{ scriptHex: "cd".repeat(34), hasCovenant: false }]
  };
  const covenantTx = {
    version: 1,
    payloadHex: "beef",
    inputs: [
      { signatureScriptHex: "ab".repeat(2100), computeBudget: 134 },
      { signatureScriptHex: "ab".repeat(66), computeBudget: 10 }
    ],
    outputs: [
      { scriptHex: "cd".repeat(3000), hasCovenant: true },
      { scriptHex: "cd".repeat(34), hasCovenant: false },
      { scriptHex: "cd".repeat(34), hasCovenant: false }
    ]
  };

  /* Plain-object stand-in for a WASM Transaction (structural read only). */
  const wasmish = {
    version: 1,
    payload: "beef",
    inputs: [{ signatureScript: "ab".repeat(66), computeBudget: 10 }],
    outputs: [
      { value: 5n, scriptPublicKey: "cd".repeat(34), covenant: { id: "x" } },
      { value: 6n, scriptPublicKey: { script: "cd".repeat(34) } }
    ]
  };

  const mkFinalizable = () => ({
    version: 1,
    payload: "",
    inputs: [
      { signatureScript: "", computeBudget: 100 },
      { signatureScript: "", computeBudget: 10 }
    ],
    outputs: [
      { value: 700000000n, scriptPublicKey: "cd".repeat(34) },
      { value: 1n, scriptPublicKey: "cd".repeat(34) }
    ]
  });
  const signAllFixed = (tx) => {
    for (const input of tx.inputs) input.signatureScript = "ee".repeat(120);
    return tx;
  };
  const finalized = (() => {
    const tx = mkFinalizable();
    const r = finalizeWithExactFee({ transaction: tx, signAll: signAllFixed, changeIndex: 1, totalInputValue: 1000000000n, relayMargin: 5000n });
    return { result: encode(r), outputValues: tx.outputs.map((o) => o.value.toString()) };
  })();

  let flip = 0;
  const signAllDrifting = (tx) => {
    flip += 1;
    for (const input of tx.inputs) input.signatureScript = "ee".repeat(flip === 1 ? 120 : 121);
    return tx;
  };

  return {
    constants: encode({ MINIMUM_RELAY_TRANSACTION_FEE, STANDARD_MASS_CAP }),
    small: {
      size: estimatedSerializedSize(smallTx).toString(),
      computeMass: encode(computeMass(smallTx)),
      feeMass: encode(feeMass(smallTx)),
      requiredFee: encode(calculateRequiredFee(smallTx))
    },
    covenantShaped: {
      size: estimatedSerializedSize(covenantTx).toString(),
      feeMass: encode(feeMass(covenantTx)),
      requiredFee: encode(calculateRequiredFee(covenantTx))
    },
    describeWasm: encode(describeWasmTransaction(wasmish)),
    validateComputeBudget: {
      accepts: encode(validateComputeBudget(100, 100, "covenant input")),
      rejects: threw(() => validateComputeBudget(99, 100, "covenant input"))
    },
    finalize: {
      fixed: finalized,
      rejects: {
        cannotCover: threw(() =>
          finalizeWithExactFee({ transaction: mkFinalizable(), signAll: signAllFixed, changeIndex: 1, totalInputValue: 700000100n })
        ),
        lengthDrift: threw(() =>
          finalizeWithExactFee({ transaction: mkFinalizable(), signAll: signAllDrifting, changeIndex: 1, totalInputValue: 1000000000n })
        )
      }
    },
    rejects: {
      versionZero: threw(() => estimatedSerializedSize({ version: 0, inputs: [], outputs: [], payloadHex: "" })),
      oddHex: threw(() => estimatedSerializedSize({ version: 1, inputs: [{ signatureScriptHex: "abc", computeBudget: 10 }], outputs: [], payloadHex: "" })),
      nonHex: threw(() => estimatedSerializedSize({ version: 1, inputs: [], outputs: [{ scriptHex: "zz", hasCovenant: false }], payloadHex: "" })),
      missingBudget: threw(() => computeMass({ version: 1, inputs: [{ signatureScriptHex: "" }], outputs: [], payloadHex: "" })),
      overMassCap: threw(() =>
        calculateRequiredFee({
          version: 1,
          payloadHex: "",
          inputs: [{ signatureScriptHex: "ab".repeat(300000), computeBudget: 10 }],
          outputs: [{ scriptHex: "cd".repeat(34), hasCovenant: false }]
        })
      )
    }
  };
}

/* --------------------------------------------------------- budgets v3/v4 */
function goldenComputeBudgetV3(m) {
  const { V3_BUDGET, selectComputeBudgetV3, assertBudgetSufficient } = m;
  const select = {};
  for (const op of ["delegateSpend", "rolloverAndSpend"]) {
    select[`${op}.below`] = selectComputeBudgetV3({ operation: op, aboveThreshold: false });
    select[`${op}.above`] = selectComputeBudgetV3({ operation: op, aboveThreshold: true });
  }
  for (const op of [
    "ownerPause",
    "ownerUnpause",
    "revokeDelegate",
    "rotateDelegate",
    "ownerTopUp",
    "migratePolicy",
    "ownerSetRecipientRoot",
    "ownerSetApprovers",
    "ownerRecover"
  ]) {
    select[op] = selectComputeBudgetV3({ operation: op });
  }
  return {
    table: encode(V3_BUDGET),
    select,
    assert: {
      exact: assertBudgetSufficient({ operation: "ownerRecover", committed: 16 }),
      over: assertBudgetSufficient({ operation: "ownerRecover", committed: 20 }),
      rejects: {
        below: threw(() => assertBudgetSufficient({ operation: "delegateSpend", aboveThreshold: true, committed: 134 })),
        nonInteger: threw(() => assertBudgetSufficient({ operation: "ownerRecover", committed: 16.5 })),
        unknownOp: threw(() => selectComputeBudgetV3({ operation: "createVaultX" })),
        missingThreshold: threw(() => selectComputeBudgetV3({ operation: "delegateSpend" }))
      }
    }
  };
}

function goldenComputeBudgetV4(m) {
  const { V4_BUDGET, selectComputeBudgetV4, assertBudgetSufficientV4 } = m;
  const select = {
    "agentSpend.below": selectComputeBudgetV4({ operation: "agentSpend", aboveThreshold: false }),
    "agentSpend.above": selectComputeBudgetV4({ operation: "agentSpend", aboveThreshold: true })
  };
  for (const op of ["ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerRecover"]) {
    select[op] = selectComputeBudgetV4({ operation: op });
  }
  return {
    table: encode(V4_BUDGET),
    select,
    assert: {
      exact: assertBudgetSufficientV4({ operation: "ownerRecover", committed: 15 }),
      over: assertBudgetSufficientV4({ operation: "ownerRecover", committed: 40 }),
      rejects: {
        below: threw(() => assertBudgetSufficientV4({ operation: "agentSpend", aboveThreshold: true, committed: 133 })),
        nonInteger: threw(() => assertBudgetSufficientV4({ operation: "ownerRecover", committed: 15.5 })),
        unknownOp: threw(() => selectComputeBudgetV4({ operation: "delegateSpend" })),
        missingThreshold: threw(() => selectComputeBudgetV4({ operation: "agentSpend" }))
      }
    }
  };
}

/*
 * The full step-2 battery.
 * `mods` = { vaultStateV2, vaultStateV3, vaultStateV4, vaultTransitionsV3,
 *            vaultTransitionsV4, recipientMerkle, feeMass, computeBudgetV3,
 *            computeBudgetV4, agentMerkle }.
 */
function computeGolden2(mods) {
  return {
    schema: "policyvault-core-model-golden/v2",
    apiSurface: {
      vaultStateV2: apiSurface(mods.vaultStateV2),
      vaultStateV3: apiSurface(mods.vaultStateV3),
      vaultStateV4: apiSurface(mods.vaultStateV4),
      vaultTransitionsV3: apiSurface(mods.vaultTransitionsV3),
      vaultTransitionsV4: apiSurface(mods.vaultTransitionsV4),
      recipientMerkle: apiSurface(mods.recipientMerkle),
      feeMass: apiSurface(mods.feeMass),
      computeBudgetV3: apiSurface(mods.computeBudgetV3),
      computeBudgetV4: apiSurface(mods.computeBudgetV4)
    },
    vaultStateV2: goldenVaultStateV2(mods.vaultStateV2),
    vaultStateV3: goldenVaultStateV3(mods.vaultStateV3),
    vaultStateV4: goldenVaultStateV4(mods.vaultStateV4),
    vaultTransitionsV3: goldenVaultTransitionsV3(mods.vaultTransitionsV3, mods.vaultStateV3),
    vaultTransitionsV4: goldenVaultTransitionsV4(mods.vaultTransitionsV4, mods.vaultStateV4, mods.agentMerkle),
    recipientMerkle: goldenRecipientMerkle(mods.recipientMerkle),
    feeMass: goldenFeeMass(mods.feeMass),
    computeBudgetV3: goldenComputeBudgetV3(mods.computeBudgetV3),
    computeBudgetV4: goldenComputeBudgetV4(mods.computeBudgetV4)
  };
}

module.exports = { computeGolden2 };
