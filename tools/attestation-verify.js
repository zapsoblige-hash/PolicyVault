#!/usr/bin/env node
"use strict";

/*
 * attestation-verify — INDEPENDENT verifier for
 * policyvault-execution-attestation/1 records.
 *
 * Spec: docs/postlaunch/execution-attestation-spec.md
 *
 * WHY THIS EXISTS. An attestation whose only verifier is the service that
 * issued it is worth nothing. This CLI needs no PolicyVault server, no
 * hosted session, no credential and no network access at all for its
 * structural pass — it reads a file and runs the SAME core/attest verifier
 * the server, the browser and the mobile app run. With --chain it
 * additionally re-reads the record's declared outputs from a Kaspa node
 * you choose, through the SDK's existing read-only chain helpers
 * (sdk/src/chain.js): connectVerified enforces exact network id + synced +
 * utxoindex, and nothing in this tool builds, signs, or broadcasts
 * anything.
 *
 * DEPENDENCIES: none of its own. The structural path uses node builtins
 * only. The --chain path lazily loads sdk/src/{config,chain}.js so that a
 * checkout without the rusty-kaspa WASM bindings can still verify
 * structure offline.
 *
 * USAGE
 *   node tools/attestation-verify.js <file> [options]
 *
 *   <file>                 a canonical-JSON attestation, or an NDJSON batch
 *   --batch                read <file> as NDJSON (auto-detected otherwise)
 *   --chain                ALSO re-check the declared chain facts on a node
 *   --rpc <url>            node wRPC URL (default: KASPA_RPC_URL or the
 *                          local testnet-10 endpoint ws://127.0.0.1:18210)
 *   --network <id>         node network id (default: KASPA_NETWORK_ID or
 *                          testnet-10). Mainnet additionally requires the
 *                          usual explicit unlock; this tool never switches
 *                          networks on its own.
 *   --expect-vault <hex>   pin the vault identity   (64-hex)
 *   --expect-network <id>  pin the network id
 *   --expect-request <id>  pin the request id       (uuid)
 *   --expect-txid <hex>    pin the transaction id   (64-hex)
 *   --expect-contract <v>  pin the covenant generation
 *   --summary              also print the human-readable summary
 *   --json                 machine-readable report on stdout
 *   --quiet                report only failures
 *
 * EXIT CODES
 *   0  every record passed the requested level
 *      (without --chain: STRUCTURE_VERIFIED; with --chain: CHAIN_CONFIRMED)
 *   1  at least one record is ATTESTATION_INVALID or CHAIN_CONTRADICTED
 *   3  --chain requested and no record was contradicted, but at least one
 *      could not be confirmed (UNCONFIRMED / UNAVAILABLE) — "I could not
 *      check", never "it is fine"
 *   2  usage / input error
 */

const fs = require("fs");
const path = require("path");

const A = require(path.join(__dirname, "..", "core", "attest"));

const USAGE_EXIT = 2;
const FAIL_EXIT = 1;
const UNCONFIRMED_EXIT = 3;

function die(message) {
  process.stderr.write(`attestation-verify: ${message}\n`);
  process.exit(USAGE_EXIT);
}

function parseArgs(argv) {
  const opts = {
    file: null,
    batch: false,
    chain: false,
    rpc: null,
    network: null,
    expect: {},
    summary: false,
    json: false,
    quiet: false
  };
  const expectFlags = {
    "--expect-vault": "vaultId",
    "--expect-network": "networkId",
    "--expect-request": "requestId",
    "--expect-txid": "txId",
    "--expect-contract": "contractVersion"
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) die(`${arg} needs a value`);
      return v;
    };
    if (arg === "--batch") opts.batch = true;
    else if (arg === "--chain") opts.chain = true;
    else if (arg === "--summary") opts.summary = true;
    else if (arg === "--json") opts.json = true;
    else if (arg === "--quiet") opts.quiet = true;
    else if (arg === "--rpc") opts.rpc = next();
    else if (arg === "--network") opts.network = next();
    else if (arg === "--help" || arg === "-h") {
      /* The usage block is the file header itself, so it can never drift
       * from the tool. Comment markers are stripped for readability. */
      const header = fs.readFileSync(__filename, "utf8").split("\n").slice(2, 62);
      const usage = header
        .filter((l) => !/^\s*\/\*|^\s*\*\/$/.test(l))
        .map((l) => l.replace(/^ \* ?/, "").replace(/^ \*$/, ""));
      process.stdout.write(`${usage.join("\n").trim()}\n`);
      process.exit(0);
    } else if (expectFlags[arg]) opts.expect[expectFlags[arg]] = next();
    else if (arg.startsWith("-")) die(`unknown option ${arg}`);
    else if (opts.file === null) opts.file = arg;
    else die("exactly one input file is accepted");
  }
  if (opts.file === null) die("an attestation file is required (--help for usage)");
  return opts;
}

function readRecords(opts) {
  let text;
  try {
    text = fs.readFileSync(opts.file, "utf8");
  } catch (e) {
    die(`cannot read ${opts.file}: ${e.message}`);
  }
  const trimmed = text.trim();
  const looksBatch = opts.batch || (trimmed.includes("\n") && trimmed.split("\n").filter((l) => l.trim()).length > 1);
  try {
    return looksBatch ? A.parseAttestationBatchNdjson(text) : [A.parseAttestationJson(text)];
  } catch (e) {
    /* A single pretty-printed JSON document contains newlines too: retry
     * once as a single record before refusing, but never the other way
     * round (silently reading a batch as one record would drop lines). */
    if (looksBatch && !opts.batch) {
      try {
        return [A.parseAttestationJson(text)];
      } catch {
        /* fall through to the batch error, which is the accurate one */
      }
    }
    die(`${e.code ?? "PARSE_ERROR"}: ${e.message}`);
  }
  return [];
}

/*
 * Read-only node observation for one record: connect with the SDK's
 * verified connector (exact network + synced + utxoindex or it refuses),
 * then read exactly the addresses the record itself names. No other RPC
 * is issued and nothing is written anywhere.
 */
async function observeChain(records, opts) {
  const { loadConfig } = require(path.join(__dirname, "..", "sdk", "src", "config"));
  const chain = require(path.join(__dirname, "..", "sdk", "src", "chain"));
  const networkId = opts.network ?? process.env.KASPA_NETWORK_ID ?? "testnet-10";
  const config = loadConfig({
    networkId,
    ...(opts.rpc ? { rpcUrl: opts.rpc } : {}),
    ...(networkId === "mainnet" ? { allowMainnet: true } : {})
  });

  let connection;
  try {
    connection = await chain.connectVerified(config);
  } catch (e) {
    return () => ({ available: false, reason: `${e.message}`, node: null, utxos: {} });
  }
  const { rpc, serverInfo } = connection;
  try {
    const addresses = [...new Set(records.flatMap((r) => A.addressesToQuery(r)))];
    const utxos = {};
    for (const address of addresses) {
      try {
        utxos[address] = (await chain.getAddressUtxos(rpc, address)).map((u) => ({
          outpoint: u.outpoint,
          amountSompi: u.amount.toString(),
          covenantId: u.covenantId,
          blockDaaScore: u.blockDaaScore === null ? null : u.blockDaaScore.toString()
        }));
      } catch (e) {
        /* An address that cannot be read is NOT an empty address: leaving
         * it out of the map yields OUTPUT_ADDRESS_NOT_QUERIED, i.e.
         * UNCONFIRMED — never a false confirmation. */
        process.stderr.write(`attestation-verify: could not read ${address}: ${e.message}\n`);
      }
    }
    const node = {
      networkId: serverInfo.networkId,
      isSynced: serverInfo.isSynced === true,
      hasUtxoIndex: serverInfo.hasUtxoIndex === true,
      virtualDaaScore: (await chain.getVirtualDaaScore(rpc)).toString()
    };
    return () => ({ available: true, reason: null, node, utxos });
  } finally {
    await rpc.disconnect();
  }
}

function renderText(report, opts) {
  const lines = [];
  for (const entry of report.records) {
    const bad = entry.verdict !== (opts.chain ? A.VERDICTS.CHAIN_CONFIRMED : A.VERDICTS.STRUCTURE_VERIFIED);
    if (opts.quiet && !bad) continue;
    lines.push(`${entry.verdict}  ${entry.attestationHash ?? "(no hash)"}  ${entry.subject}`);
    for (const f of entry.failures) lines.push(`    FAILURE ${f.code} at ${f.path}: ${f.message}`);
    for (const w of entry.warnings) lines.push(`    note    ${w.code} at ${w.path}: ${w.message}`);
    for (const f of entry.chainFindings) lines.push(`    chain   ${f.code}: ${f.detail}`);
    if (opts.summary && entry.summary) lines.push(entry.summary.split("\n").map((l) => `    ${l}`).join("\n"));
  }
  lines.push(
    `${report.total} record(s): ${report.confirmed} chain-confirmed, ${report.structureOnly} structurally verified, ` +
      `${report.unconfirmed} unconfirmed/unavailable, ${report.contradicted} contradicted, ${report.invalid} invalid`
  );
  if (report.batchDigest) lines.push(`batch digest ${report.batchDigest}`);
  return lines.join("\n");
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const records = readRecords(opts);
  if (records.length === 0) die("the input contains no attestation records");

  let observationFor = () => null;
  if (opts.chain) {
    try {
      observationFor = await observeChain(records, opts);
    } catch (e) {
      die(`chain check could not start: ${e.message}`);
    }
  }

  const expect = Object.keys(opts.expect).length > 0 ? opts.expect : null;
  const report = {
    reportVersion: "policyvault-attestation-verify-report/1",
    verifierVersion: A.VERIFIER_VERSION_1,
    file: opts.file,
    chainChecked: opts.chain,
    total: records.length,
    confirmed: 0,
    structureOnly: 0,
    unconfirmed: 0,
    contradicted: 0,
    invalid: 0,
    batchDigest: null,
    records: []
  };
  try {
    report.batchDigest = A.computeBatchDigest(records);
  } catch {
    report.batchDigest = null; // an invalid record has no batch identity
  }

  for (const record of records) {
    const observation = observationFor(record);
    const result = A.verifyAttestation(record, { expect, ...(observation ? { chainObservation: observation } : {}) });
    if (result.verdict === A.VERDICTS.CHAIN_CONFIRMED) report.confirmed += 1;
    else if (result.verdict === A.VERDICTS.STRUCTURE_VERIFIED) report.structureOnly += 1;
    else if (result.verdict === A.VERDICTS.CHAIN_CONTRADICTED) report.contradicted += 1;
    else if (result.verdict === A.VERDICTS.INVALID) report.invalid += 1;
    else report.unconfirmed += 1;

    report.records.push({
      attestationHash: record?.attestationHash ?? null,
      subject: `${record?.subject?.vaultId ?? "?"} ${record?.action?.type ?? "?"} ${record?.outcome?.state ?? "?"}`,
      verdict: result.verdict,
      chainConfirmed: result.chainConfirmed,
      failures: result.structural.failures,
      warnings: result.structural.warnings,
      chainStatus: result.chain.status,
      chainFindings: result.chain.findings,
      summary: opts.summary && result.structural.ok ? A.attestationSummary.humanReadable(record, result) : null
    });
  }

  process.stdout.write(`${opts.json ? JSON.stringify(report, null, 2) : renderText(report, opts)}\n`);

  if (report.invalid > 0 || report.contradicted > 0) process.exit(FAIL_EXIT);
  if (opts.chain && report.unconfirmed > 0) process.exit(UNCONFIRMED_EXIT);
  if (!opts.chain && report.structureOnly + report.confirmed !== report.total) process.exit(FAIL_EXIT);
  process.exit(0);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`attestation-verify: ${e.stack ?? e.message}\n`);
    process.exit(FAIL_EXIT);
  });
}

module.exports = { parseArgs, readRecords };
