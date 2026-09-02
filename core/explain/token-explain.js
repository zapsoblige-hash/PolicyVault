"use strict";

/*
 * Deterministic, template-driven explanation of a v0.5 token-controller
 * intent manifest — SEPARATE sections for token identity, token amount and
 * policy impact, KAS fee/reserve impact, issuer trust properties,
 * descriptor/template identity, and the verification result. No natural-
 * language model anywhere; every line is derived from verified fields.
 * Amounts are shown in atomic units (and a display-scaled string using the
 * descriptor's DISPLAY-ONLY decimals, clearly labeled).
 */

const { verifyTokenIntentManifest } = require("../intent/token-manifest-v5");
const { sompiToKasString } = require("./kas");

function scaled(atomic, decimals) {
  const s = BigInt(atomic).toString();
  if (decimals === 0) return s;
  const pad = s.padStart(decimals + 1, "0");
  return `${pad.slice(0, -decimals)}.${pad.slice(-decimals)}`;
}

function explainTokenIntent({ manifest, descriptor }) {
  const v = verifyTokenIntentManifest({ manifest, descriptor });
  const a = manifest.asset;
  const k = manifest.accounting.kas;
  const t = manifest.accounting.token;
  const dec = a.decimalsDisplay;
  const sections = [];
  sections.push({
    title: "VERIFICATION",
    lines: [`Result: ${v.verdict}`, ...(v.verdict === "VERIFIED" ? [v.statement] : v.failures.map((f) => `REFUSED: ${f.name}${f.detail ? ` — ${f.detail}` : ""}`))]
  });
  sections.push({
    title: "TOKEN ASSET IDENTITY",
    lines: [
      `Asset: ${a.displayName} (assetId ${a.assetId})`,
      `Token family covenant id: ${manifest.controller.tokenCovenantId}`,
      `Accepted template (in-VM blake2b-256): ${a.templateVmHashBlake2b256}`,
      `KCC-0001 template identity (interoperability only): ${a.templateKcc1HashBlake3 ?? "not declared"}`,
      `Descriptor hash (pinned in the controller): ${a.descriptorHash}`
    ]
  });
  if (manifest.action.sdkAction === "tokenDeposit") {
    sections.push({
      title: "TOKEN DEPOSIT (user position -> controller)",
      lines: [
        `Position before: ${t.positionBefore} atomic units (display: ${scaled(t.positionBefore, dec)})`,
        `Deposit to the controller: ${t.deposit} atomic units (display: ${scaled(t.deposit, dec)})`,
        `Remainder back to you: ${t.remainderToUser} atomic units (display: ${scaled(t.remainderToUser, dec)})`,
        `Signer: your own wallet key ${manifest.policy.userPk} signs the token input — PolicyVault never holds it`
      ]
    });
    sections.push({
      title: "KAS FEE AND CARRY (separate domain)",
      lines: [
        `Network fee: ${sompiToKasString(k.fee)} KAS (fuel in ${sompiToKasString(k.externalIn)} / change ${sompiToKasString(k.externalOut)})`,
        `Token family KAS: position ${sompiToKasString(k.positionKas)}; deposit carry ${sompiToKasString(k.depositCarryKas)}; remainder carry ${sompiToKasString(k.remainderCarryKas)}`
      ]
    });
    const powersD = Object.entries(a.issuerPowers).filter(([, on]) => on).map(([n]) => n);
    sections.push({
      title: "ISSUER / CONTROLLER TRUST PROPERTIES (declared by the asset, not guaranteed by PolicyVault)",
      lines: [powersD.length ? `Declared issuer powers: ${powersD.join(", ")} — this asset is ISSUER-CONTROLLED` : "No declared issuer powers (declared-only; PolicyVault cannot discover undeclared powers)"]
    });
    return Object.freeze({ verdict: v.verdict, sections, checks: v.checks });
  }
  sections.push({
    title: "TOKEN AMOUNT AND POLICY IMPACT",
    lines: [
      `Action: ${manifest.action.sdkAction} (${manifest.action.role})`,
      `Position before: ${t.positionBefore ?? "n/a"} atomic units${t.positionBefore != null ? ` (display: ${scaled(t.positionBefore, dec)})` : ""}`,
      `Spend: ${t.spendAmount} atomic units (display: ${scaled(t.spendAmount, dec)})${t.recipient ? ` to ${t.recipient}` : ""}`,
      `Position after: ${t.positionAfter ?? "n/a"} atomic units${t.positionAfter != null ? ` (display: ${scaled(t.positionAfter, dec)})` : ""}`,
      ...(t.recoveredToOwner !== "0" ? [`Recovered to owner: ${t.recoveredToOwner} atomic units`] : []),
      ...(manifest.policy?.agentPolicy ? [`Agent cap per spend: ${manifest.policy.agentPolicy.tokenMaxPerSpend}; period budget: ${manifest.policy.agentPolicy.tokenPeriodBudget}; spent before: ${manifest.policy.agentPolicy.tokenPeriodSpent}; periods elapsed: ${manifest.policy.periodsElapsed}`] : [])
    ]
  });
  sections.push({
    title: "KAS FEE AND RESERVE IMPACT (separate domain)",
    lines: [
      `Fee reserve before: ${sompiToKasString(k.predecessorFeeReserve)} KAS; after: ${sompiToKasString(k.successorFeeReserve)} KAS; consumed: ${sompiToKasString(k.reserveConsumed)} KAS`,
      `Network fee: ${sompiToKasString(k.fee)} KAS (fuel in ${sompiToKasString(k.externalIn)} / change ${sompiToKasString(k.externalOut)})`,
      `Token family KAS: input ${sompiToKasString(k.tokenInputKas)}; self carry ${sompiToKasString(k.tokenSelfCarryKas)}; recipient carry ${sompiToKasString(k.tokenRecipientCarryKas)}`,
      ...(k.terminalPayout !== "0" ? [`Terminal payout to owner: ${sompiToKasString(k.terminalPayout)} KAS`] : [])
    ]
  });
  const powers = Object.entries(a.issuerPowers).filter(([, on]) => on).map(([n]) => n);
  sections.push({
    title: "ISSUER / CONTROLLER TRUST PROPERTIES (declared by the asset, not guaranteed by PolicyVault)",
    lines: [powers.length ? `Declared issuer powers: ${powers.join(", ")} — this asset is ISSUER-CONTROLLED` : "No declared issuer powers (declared-only; PolicyVault cannot discover undeclared powers)"]
  });
  return Object.freeze({ verdict: v.verdict, sections, checks: v.checks });
}

module.exports = { explainTokenIntent, scaled };
