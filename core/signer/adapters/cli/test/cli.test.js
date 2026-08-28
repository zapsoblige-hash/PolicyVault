"use strict";

/*
 * UNIT — CLI keyfile signer: the command-line front end, driven as real
 * child processes.
 *
 * Covers: generate / identity / sign-message / sign-tx happy paths;
 * malformed and unknown-version signing-request refusals; the mainnet
 * dual unlock at the CLI surface; NO-SECRET-IN-OUTPUT scans over every
 * captured stdout/stderr byte; and a static offline scan asserting the
 * adapter + CLI sources load no network transport. TEST keys only.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { KEYFILE_FORMAT } = require("../adapter");
const { SIGNING_REQUEST_FORMAT } = require("../cli");
const { loadKaspaOrExplain, makeTempDir, buildUnsignedTxSafeJson, runCli, CLI_PATH } = require("../testkit");

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-cli-signer-cli-");

/* Every CLI interaction is recorded so the no-secret scan at the bottom
 * covers the ENTIRE session's outputs. */
const allOutputs = [];
function cli(args, opts) {
  const result = runCli(args, opts);
  allOutputs.push({ args: [...args], stdout: result.stdout, stderr: result.stderr });
  return result;
}

const keyfile = path.join(dir, "cli-test-key.json");
let identityDoc; // from generate

function requestFileWith(overrides, base) {
  const doc = { ...base, ...overrides };
  for (const [k, v] of Object.entries(doc)) if (v === undefined) delete doc[k];
  const p = path.join(dir, `request-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(p, JSON.stringify(doc));
  return p;
}

test("generate creates a testnet keyfile and prints public identity JSON only", () => {
  const result = cli(["generate", "--out", keyfile, "--network", "testnet-10", "--label", "cli suite key"]);
  assert.equal(result.status, 0, result.stderr);
  identityDoc = JSON.parse(result.stdout);
  assert.equal(identityDoc.format, "policyvault-cli-signer-identity/1");
  assert.match(identityDoc.address, /^kaspatest:/);
  assert.match(identityDoc.publicKey, /^0[23][0-9a-f]{64}$/);
  assert.equal(identityDoc.network, "testnet-10");
  const record = JSON.parse(fs.readFileSync(keyfile, "utf8"));
  assert.equal(record.format, KEYFILE_FORMAT);
  if (process.platform !== "win32") assert.equal(fs.statSync(keyfile).mode & 0o777, 0o600);
});

test("generate refuses to overwrite and exits nonzero with a structured error", () => {
  const result = cli(["generate", "--out", keyfile]);
  assert.equal(result.status, 1);
  const err = JSON.parse(result.stderr.split("\n")[0]);
  assert.equal(err.error.code, "PROVIDER_ERROR");
  assert.match(err.error.message, /refusing to overwrite/);
});

test("identity prints the same public identity the generate step reported", () => {
  const result = cli(["identity", "--key", keyfile]);
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(result.stdout);
  assert.equal(doc.address, identityDoc.address);
  assert.equal(doc.publicKey, identityDoc.publicKey);
  assert.equal(doc.network, "testnet-10");
  assert.equal(doc.label, "cli suite key");
});

test("sign-message signs the EXACT file bytes and the signature verifies via kaspa-wasm", () => {
  const messageFile = path.join(dir, "message.txt");
  const message = "PolicyVault CLI signer test message\nline two, signed verbatim (no trailing newline)";
  fs.writeFileSync(messageFile, message); // exact bytes, no trailing LF
  const result = cli(["sign-message", "--key", keyfile, "--message-file", messageFile]);
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(result.stdout);
  assert.equal(doc.format, "policyvault-cli-signer-signature/1");
  assert.equal(doc.address, identityDoc.address);
  assert.equal(doc.scheme, "schnorr");
  assert.match(doc.signature, /^[0-9a-f]{128}$/);
  assert.match(doc.requestId, /^[0-9a-f]{32}$/);
  /* verify with the authoritative verifier against the x-only key */
  assert.equal(
    kaspa.verifyMessage({ message, signature: doc.signature, publicKey: identityDoc.xOnlyPublicKey }),
    true
  );
  /* and the signature is bound to those exact bytes */
  assert.equal(
    kaspa.verifyMessage({ message: message + "\n", signature: doc.signature, publicKey: identityDoc.xOnlyPublicKey }),
    false
  );
});

test("sign-message refuses an empty message file and a non-UTF-8 message file", () => {
  const empty = path.join(dir, "empty.txt");
  fs.writeFileSync(empty, "");
  const r1 = cli(["sign-message", "--key", keyfile, "--message-file", empty]);
  assert.equal(r1.status, 1);
  assert.match(JSON.parse(r1.stderr.split("\n")[0]).error.message, /empty/);

  const binary = path.join(dir, "binary.bin");
  fs.writeFileSync(binary, Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x41]));
  const r2 = cli(["sign-message", "--key", keyfile, "--message-file", binary]);
  assert.equal(r2.status, 1);
  assert.match(JSON.parse(r2.stderr.split("\n")[0]).error.message, /not valid UTF-8/);
});

test("sign-tx consumes a frozen signing-request file and returns the signed serialization (txid frozen)", () => {
  const { unsignedSafeJson, unsignedId } = buildUnsignedTxSafeJson(kaspa, identityDoc.address);
  const requestFile = requestFileWith(
    {},
    {
      format: SIGNING_REQUEST_FORMAT,
      kind: "sign-transaction",
      network: "testnet-10",
      expectedSignerAddress: identityDoc.address,
      unsignedSafeJson,
      signInputs: [{ index: 0, sighashType: 1 }]
    }
  );
  const result = cli(["sign-tx", "--key", keyfile, "--request-file", requestFile]);
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(result.stdout);
  assert.equal(doc.format, "policyvault-cli-signer-signed-transaction/1");
  assert.equal(doc.address, identityDoc.address);
  const signed = kaspa.Transaction.deserializeFromSafeJSON(doc.signedSafeJson);
  assert.equal(String(signed.id), unsignedId);
  assert.match(signed.inputs[0].signatureScript, /^41[0-9a-f]{130}$/);
});

test("sign-tx refuses unknown request-file versions, kinds, and keys fail-closed", () => {
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identityDoc.address);
  const base = {
    format: SIGNING_REQUEST_FORMAT,
    kind: "sign-transaction",
    network: "testnet-10",
    expectedSignerAddress: identityDoc.address,
    unsignedSafeJson,
    signInputs: [{ index: 0, sighashType: 1 }]
  };
  const cases = [
    // /1 and /2 are the KNOWN versions now; a genuinely unknown one fails closed.
    [{ format: "policyvault-cli-signing-request/99" }, /unknown versions fail closed/],
    [{ format: undefined }, /unknown versions fail closed/],
    [{ kind: "sign-message" }, /not "sign-transaction"/],
    [{ broadcast: true }, /unknown key "broadcast"/],
    [{ network: undefined }, /missing required key "network"/]
  ];
  for (const [overrides, expected] of cases) {
    const result = cli(["sign-tx", "--key", keyfile, "--request-file", requestFileWith(overrides, base)]);
    assert.equal(result.status, 1, `expected refusal for ${JSON.stringify(overrides)}`);
    assert.match(JSON.parse(result.stderr.split("\n")[0]).error.message, expected);
  }
});

test("sign-tx refuses malformed signInputs and a foreign expectedSignerAddress through the interface gates", () => {
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identityDoc.address);
  const base = {
    format: SIGNING_REQUEST_FORMAT,
    kind: "sign-transaction",
    network: "testnet-10",
    expectedSignerAddress: identityDoc.address,
    unsignedSafeJson,
    signInputs: [{ index: 0, sighashType: 1 }]
  };
  const badSighash = cli(["sign-tx", "--key", keyfile, "--request-file", requestFileWith({ signInputs: [{ index: 0, sighashType: 2 }] }, base)]);
  assert.equal(badSighash.status, 1);
  assert.equal(JSON.parse(badSighash.stderr.split("\n")[0]).error.code, "REQUEST_INVALID");

  const extraKey = cli(["sign-tx", "--key", keyfile, "--request-file", requestFileWith({ signInputs: [{ index: 0, sighashType: 1, redeemScript: "aa" }] }, base)]);
  assert.equal(extraKey.status, 1);
  assert.equal(JSON.parse(extraKey.stderr.split("\n")[0]).error.code, "REQUEST_INVALID");

  const foreign = cli(["sign-tx", "--key", keyfile, "--request-file", requestFileWith({ expectedSignerAddress: "kaspatest:notthissignersaddress" }, base)]);
  assert.equal(foreign.status, 1);
  assert.equal(JSON.parse(foreign.stderr.split("\n")[0]).error.code, "ACCOUNT_CHANGED");
});

test("CLI enforces the mainnet dual unlock (flag alone and env alone both refuse)", () => {
  const out = path.join(dir, "never-mainnet.json");
  const flagOnly = cli(["generate", "--out", out, "--network", "mainnet", "--allow-mainnet"], { env: { PV_CLI_SIGNER_ALLOW_MAINNET: "" } });
  assert.equal(flagOnly.status, 1);
  assert.equal(JSON.parse(flagOnly.stderr.split("\n")[0]).error.code, "WRONG_NETWORK");

  const envOnly = cli(["generate", "--out", out, "--network", "mainnet"], { env: { PV_CLI_SIGNER_ALLOW_MAINNET: "1" } });
  assert.equal(envOnly.status, 1);
  assert.equal(JSON.parse(envOnly.stderr.split("\n")[0]).error.code, "WRONG_NETWORK");
  assert.equal(fs.existsSync(out), false);
});

test("usage errors exit 2 with structured JSON (unknown command / flag / missing flag)", () => {
  for (const args of [[], ["explode"], ["identity"], ["identity", "--key", keyfile, "--verbose"]]) {
    const result = cli(args);
    assert.equal(result.status, 2, `args ${JSON.stringify(args)}`);
    assert.equal(JSON.parse(result.stderr.split("\n")[0]).error.code, "USAGE");
  }
});

test("NO-SECRET-IN-OUTPUT: every byte of stdout/stderr from every CLI call is free of key material", () => {
  const record = JSON.parse(fs.readFileSync(keyfile, "utf8"));
  const secretHex = record.privateKeyHex;
  assert.match(secretHex, /^[0-9a-f]{64}$/);
  assert.ok(allOutputs.length >= 10, "the scan must cover the whole session");
  for (const { args, stdout, stderr } of allOutputs) {
    const combined = stdout + "\n" + stderr;
    assert.ok(!combined.includes(secretHex), `private key hex leaked by ${JSON.stringify(args)}`);
    assert.ok(!combined.toLowerCase().includes(secretHex.slice(0, 32)), `private key prefix leaked by ${JSON.stringify(args)}`);
    assert.ok(!/privateKeyHex/.test(stdout), `stdout of ${JSON.stringify(args)} mentions privateKeyHex`);
    assert.ok(!/seed/i.test(stdout), `stdout of ${JSON.stringify(args)} mentions seed material`);
  }
});

test("OFFLINE static scan: adapter + CLI sources load no network transport module", () => {
  const sources = [fs.readFileSync(path.join(__dirname, "..", "adapter.js"), "utf8"), fs.readFileSync(CLI_PATH, "utf8")];
  const forbidden = [
    /require\(\s*["'](?:node:)?https?["']\s*\)/,
    /require\(\s*["'](?:node:)?net["']\s*\)/,
    /require\(\s*["'](?:node:)?tls["']\s*\)/,
    /require\(\s*["'](?:node:)?dgram["']\s*\)/,
    /require\(\s*["']websocket["']\s*\)/,
    /require\(\s*["']ws["']\s*\)/,
    /\bfetch\s*\(/,
    /WebSocket\s*\(/
  ];
  for (const source of sources) {
    for (const pattern of forbidden) {
      assert.ok(!pattern.test(source), `forbidden network usage matched: ${pattern}`);
    }
    /* comments may CITE sdk/server paths (design lineage); requiring them is forbidden */
    assert.ok(!/require\(\s*["'][^"']*\bsdk\/[^"']*["']\s*\)/.test(source), "must not require sdk modules");
    assert.ok(!/require\(\s*["'][^"']*\bserver\/[^"']*["']\s*\)/.test(source), "must not require server modules");
  }
});
