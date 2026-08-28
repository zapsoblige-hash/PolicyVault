#!/usr/bin/env node
"use strict";

/*
 * PolicyVault CLI keyfile signer — offline command-line front end for
 * core/signer/adapters/cli/adapter.js.
 *
 * Commands (stdout is ALWAYS a single JSON document; diagnostics go to
 * stderr as {"error":{"code","message"}}; exit 0 ok / 1 refused / 2 usage):
 *
 *   generate     --out FILE [--network N] [--label L] [--allow-mainnet]
 *       Create a NEW keyfile (mode 600, never overwrites) and print the
 *       PUBLIC identity. Default network: testnet-10 (TEST keys).
 *       Mainnet needs BOTH --allow-mainnet AND PV_CLI_SIGNER_ALLOW_MAINNET=1.
 *
 *   identity     --key FILE
 *       Validate the keyfile and print its PUBLIC identity.
 *
 *   sign-message --key FILE --message-file F [--allow-mainnet]
 *       Sign the EXACT UTF-8 bytes of F as a personal message (Kaspa
 *       PersonalMessageSigningHash domain, BIP-340 Schnorr) and print the
 *       signature JSON. The bytes are signed VERBATIM — no trimming, no
 *       newline normalization (a server-issued auth challenge must be
 *       stored byte-exactly).
 *
 *   sign-tx      --key FILE --request-file F [--allow-mainnet]
 *       Consume a frozen signing-request JSON produced elsewhere (format
 *       "policyvault-cli-signing-request/1", closed schema below), sign
 *       exactly the named inputs of the frozen transaction, and print the
 *       signed serialization. Malformed / unknown-version requests are
 *       refused fail-closed.
 *
 * Every signing command drives the REAL interface pipeline
 * (createMessageSigningRequest / createTransactionSigningRequest +
 * executeSigning from core/signer) — the CLI is a consumer of the
 * Universal Signer Interface, not a bypass of it.
 *
 * OFFLINE: this program performs LOCAL file operations and local
 * cryptography only. It opens no sockets, loads no network transport,
 * and imports nothing from server/ or sdk/. Secret material never
 * reaches stdout, stderr, or argv.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  generateKeyfile,
  readKeyfileIdentity,
  createCliSignerAdapter,
  KEYFILE_FORMAT,
  MAINNET_UNLOCK_ENV
} = require("./adapter");
const { createMessageSigningRequest, createTransactionSigningRequest, executeSigning, isSignerError } = require("../../index");
// core/intent + core/explain are portable, dependency-free, and import
// nothing from server/ or sdk/ — the OFFLINE guarantee above holds. They
// give the /2 request format an INDEPENDENT verify-before-sign step so the
// signer is no longer blind to what it authorizes. (Hostile-AI review H-2.)
const { verifyIntentManifest } = require("../../../intent");
const { intentExplain } = require("../../../explain");

/* Frozen signing-request file format consumed by sign-tx. Exact-equality
 * version match; closed schema; unknown anything fails closed.
 *   /1 — legacy, VERIFICATION-BLIND: signs unsignedSafeJson as given.
 *   /2 — VERIFYING: additionally carries the intent `manifest`; the signer
 *        independently re-verifies it (verifyIntentManifest), binds it to
 *        the exact transaction being signed (manifest txId == the id
 *        embedded in the finalized unsignedSafeJson), renders the intent to
 *        the operator, and REFUSES to sign on any failure. */
const SIGNING_REQUEST_FORMAT = "policyvault-cli-signing-request/1";
const SIGNING_REQUEST_FORMAT_V2 = "policyvault-cli-signing-request/2";
const SIGNING_REQUEST_KEYS = Object.freeze(["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
const SIGNING_REQUEST_KEYS_V2 = Object.freeze([...SIGNING_REQUEST_KEYS, "manifest"]);

const USAGE = [
  "usage: cli.js <command> [flags]",
  "  generate     --out FILE [--network N] [--label L] [--allow-mainnet]",
  "  identity     --key FILE",
  "  sign-message --key FILE --message-file F [--allow-mainnet]",
  "  sign-tx      --key FILE --request-file F [--allow-mainnet]",
  `mainnet is refused unless BOTH --allow-mainnet and ${MAINNET_UNLOCK_ENV}=1 are present`
].join("\n");

class UsageError extends Error {}

function usageFail(message) {
  throw new UsageError(message);
}

/* Strict flag parser: only declared flags; every flag except booleans
 * takes exactly one value; unknown flags fail closed. */
function parseFlags(argv, spec) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    const rule = spec[token];
    if (!rule) usageFail(`unknown flag ${JSON.stringify(token)}`);
    const name = rule.name;
    if (out[name] !== undefined) usageFail(`duplicate flag ${token}`);
    if (rule.boolean) {
      out[name] = true;
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) usageFail(`flag ${token} requires a value`);
    out[name] = value;
    i += 1;
  }
  for (const [flag, rule] of Object.entries(spec)) {
    if (rule.required && out[rule.name] === undefined) usageFail(`missing required flag ${flag}`);
  }
  return out;
}

function printJson(doc) {
  process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
}

/* Read a file that must be EXACT, losslessly-decodable UTF-8 text.
 * A lossy decode would silently sign different bytes than the file
 * holds — refused. */
function readUtf8Exact(filePath, what) {
  let buf;
  try {
    buf = fs.readFileSync(path.resolve(filePath));
  } catch {
    throw new Error(`${what} ${JSON.stringify(path.resolve(filePath))} cannot be read`);
  }
  if (buf.length === 0) throw new Error(`${what} is empty — nothing to sign`);
  const text = buf.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(buf)) {
    throw new Error(`${what} is not valid UTF-8 — refusing a lossy decoding`);
  }
  return text;
}

/* Peek the keyfile's own (public) network field so the adapter can be
 * constructed for the right network; full validation still happens inside
 * connect(). Malformed files surface their precise refusal there. */
function peekKeyfileNetwork(keyfilePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.resolve(keyfilePath), "utf8"));
    if (parsed && typeof parsed === "object" && typeof parsed.network === "string") return parsed.network;
  } catch {
    /* fall through — connect() reports the exact fault */
  }
  return "testnet-10";
}

async function connectedAdapter(flags) {
  const adapter = createCliSignerAdapter({
    keyfilePath: flags.key,
    network: peekKeyfileNetwork(flags.key),
    allowMainnet: flags.allowMainnet === true
  });
  const session = await adapter.connect();
  return { adapter, session };
}

/* Closed-schema validation of the sign-tx request FILE. The interface's
 * own request constructor re-validates every field it owns. */
function parseSigningRequestFile(filePath) {
  const text = readUtf8Exact(filePath, "signing-request file");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("signing-request file is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("signing-request file must contain a JSON object");
  }
  const isV2 = parsed.format === SIGNING_REQUEST_FORMAT_V2;
  if (parsed.format !== SIGNING_REQUEST_FORMAT && !isV2) {
    const claimed = typeof parsed.format === "string" ? parsed.format.slice(0, 64) : typeof parsed.format;
    throw new Error(`signing-request format ${JSON.stringify(claimed)} is not ${JSON.stringify(SIGNING_REQUEST_FORMAT)} or ${JSON.stringify(SIGNING_REQUEST_FORMAT_V2)} — unknown versions fail closed`);
  }
  if (parsed.kind !== "sign-transaction") {
    throw new Error(`signing-request kind ${JSON.stringify(String(parsed.kind).slice(0, 32))} is not "sign-transaction" — failing closed`);
  }
  const allowedKeys = isV2 ? SIGNING_REQUEST_KEYS_V2 : SIGNING_REQUEST_KEYS;
  for (const key of Object.keys(parsed)) {
    if (!allowedKeys.includes(key)) {
      throw new Error(`signing-request carries unknown key ${JSON.stringify(key)} — the schema is closed; failing closed`);
    }
  }
  for (const key of allowedKeys) {
    if (!(key in parsed)) throw new Error(`signing-request is missing required key ${JSON.stringify(key)}`);
  }
  return parsed;
}

/*
 * /2 verify-before-sign. Independently re-verify the carried manifest and
 * bind it to the EXACT transaction the signer is about to sign, then render
 * the intent to the operator (stderr — stdout stays machine-JSON only).
 * Any failure THROWS: the signer refuses. The txId binding is the crux —
 * the finalized unsignedSafeJson embeds the consensus id (txids exclude
 * signature scripts), so a manifest whose txId differs describes a
 * DIFFERENT transaction than the bytes being signed.
 */
function verifyV2ManifestOrRefuse(fileRequest) {
  const verification = verifyIntentManifest({ manifest: fileRequest.manifest });
  const renderRefusal = (extraFailure) => {
    let lines;
    try {
      lines = intentExplain.humanReadable({ manifest: fileRequest.manifest, verification });
    } catch {
      lines = ["!! DO NOT SIGN !!", "the intent manifest could not be rendered"];
    }
    if (extraFailure) lines = ["!! DO NOT SIGN !!", extraFailure, ...lines];
    process.stderr.write(lines.join("\n") + "\n");
  };

  if (!verification.ok || verification.verdict !== "VERIFIED_EXACT") {
    renderRefusal();
    const err = new Error("manifest verification refused — the signer will not sign an unverified intent");
    err.signerCode = "MANIFEST_VERIFICATION_REFUSED";
    throw err;
  }

  let embeddedId;
  try {
    embeddedId = JSON.parse(fileRequest.unsignedSafeJson).id;
  } catch {
    embeddedId = null;
  }
  if (typeof embeddedId !== "string" || embeddedId !== verification.txId) {
    renderRefusal(`the transaction to sign (id ${JSON.stringify(String(embeddedId))}) is NOT the one the manifest describes (txId ${JSON.stringify(verification.txId)})`);
    const err = new Error("transaction/manifest txId mismatch — refusing to sign a transaction the manifest does not describe");
    err.signerCode = "TXID_MISMATCH";
    throw err;
  }

  // Verified and bound: show the operator exactly what they are authorizing.
  process.stderr.write(intentExplain.humanReadable({ manifest: fileRequest.manifest, verification }).join("\n") + "\n");
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (!command) usageFail("no command given");

  if (command === "generate") {
    const flags = parseFlags(rest, {
      "--out": { name: "out", required: true },
      "--network": { name: "network" },
      "--label": { name: "label" },
      "--allow-mainnet": { name: "allowMainnet", boolean: true }
    });
    const identity = generateKeyfile({
      out: flags.out,
      network: flags.network === undefined ? "testnet-10" : flags.network,
      label: flags.label,
      allowMainnet: flags.allowMainnet === true
    });
    printJson(identity);
    return 0;
  }

  if (command === "identity") {
    const flags = parseFlags(rest, { "--key": { name: "key", required: true } });
    printJson(readKeyfileIdentity(flags.key));
    return 0;
  }

  if (command === "sign-message") {
    const flags = parseFlags(rest, {
      "--key": { name: "key", required: true },
      "--message-file": { name: "messageFile", required: true },
      "--allow-mainnet": { name: "allowMainnet", boolean: true }
    });
    const message = readUtf8Exact(flags.messageFile, "message file");
    const { adapter, session } = await connectedAdapter(flags);
    const request = createMessageSigningRequest({
      message,
      scheme: "schnorr",
      network: session.network,
      expectedSignerAddress: session.address
    });
    const outcome = await executeSigning(adapter, request);
    printJson({
      format: "policyvault-cli-signer-signature/1",
      requestId: outcome.requestId,
      kind: "sign-message",
      network: session.network,
      address: session.address,
      publicKey: await adapter.getPublicKey(),
      scheme: "schnorr",
      messageSha256: crypto.createHash("sha256").update(message, "utf8").digest("hex"),
      signature: outcome.result.signature
    });
    await adapter.disconnect();
    return 0;
  }

  if (command === "sign-tx") {
    const flags = parseFlags(rest, {
      "--key": { name: "key", required: true },
      "--request-file": { name: "requestFile", required: true },
      "--allow-mainnet": { name: "allowMainnet", boolean: true }
    });
    const fileRequest = parseSigningRequestFile(flags.requestFile);
    // /2 requests VERIFY before signing (refuses on any failure); /1 remains
    // verification-blind by construction (documented). (Hostile-AI H-2.)
    if (fileRequest.format === SIGNING_REQUEST_FORMAT_V2) {
      verifyV2ManifestOrRefuse(fileRequest);
    }
    const { adapter, session } = await connectedAdapter(flags);
    const request = createTransactionSigningRequest({
      unsignedSafeJson: fileRequest.unsignedSafeJson,
      signInputs: fileRequest.signInputs,
      network: fileRequest.network,
      expectedSignerAddress: fileRequest.expectedSignerAddress
    });
    const outcome = await executeSigning(adapter, request);
    printJson({
      format: "policyvault-cli-signer-signed-transaction/1",
      requestId: outcome.requestId,
      kind: "sign-transaction",
      network: fileRequest.network,
      address: session.address,
      /* No txid claim is printed: the downstream finalizer independently
       * re-derives the frozen txid (sdk/src/wallet-submit-v4.js). */
      signedSafeJson: outcome.result.signedSafeJson
    });
    await adapter.disconnect();
    return 0;
  }

  usageFail(`unknown command ${JSON.stringify(command)}`);
}

/* Entrypoint: JSON-only streams, never secret material. SignerError codes
 * pass through; other faults are reported by message only. */
if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      if (e instanceof UsageError) {
        process.stderr.write(JSON.stringify({ error: { code: "USAGE", message: e.message } }) + "\n" + USAGE + "\n");
        process.exit(2);
      }
      const code = isSignerError(e) ? e.signerCode : "CLI_ERROR";
      process.stderr.write(JSON.stringify({ error: { code, message: e.message || String(e) } }) + "\n");
      process.exit(1);
    }
  );
}

module.exports = { main, SIGNING_REQUEST_FORMAT, SIGNING_REQUEST_FORMAT_V2, SIGNING_REQUEST_KEYS, SIGNING_REQUEST_KEYS_V2, KEYFILE_FORMAT, USAGE };
