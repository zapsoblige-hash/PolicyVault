"use strict";

/*
 * UNIT — CLI keyfile signer: mainnet dual-unlock matrix + wrong-network
 * fail-close.
 *
 * Mainnet operation requires BOTH { allowMainnet: true } AND
 * PV_CLI_SIGNER_ALLOW_MAINNET=1 (the product's dual-flag unlock spirit).
 * Every partial combination refuses, fail closed. NO mainnet keyfile is
 * ever generated in tests (only construction-level gating and
 * tampered-label refusal fixtures are exercised — the keys themselves
 * are throwaway testnet test keys).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { SignerErrorCodes } = require("../../../index");
const { createCliSignerAdapter, generateKeyfile, assertOperatingNetwork, MAINNET_UNLOCK_ENV } = require("../adapter");
const { loadKaspaOrExplain, makeTempDir } = require("../testkit");

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-cli-signer-net-");
const testnetKeyfile = path.join(dir, "testnet-key.json");
generateKeyfile({ out: testnetKeyfile, network: "testnet-10", kaspaModule: kaspa });

function withEnv(value, fn) {
  const saved = process.env[MAINNET_UNLOCK_ENV];
  if (value === undefined) delete process.env[MAINNET_UNLOCK_ENV];
  else process.env[MAINNET_UNLOCK_ENV] = value;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env[MAINNET_UNLOCK_ENV];
    else process.env[MAINNET_UNLOCK_ENV] = saved;
  }
}

const isMainnetLocked = (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK && /mainnet operation is locked/.test(e.message);

test("dual-unlock matrix: neither option nor env -> mainnet construction refused", () => {
  withEnv(undefined, () => {
    assert.throws(() => createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet" }), isMainnetLocked);
  });
});

test("dual-unlock matrix: option only (no env) -> refused", () => {
  withEnv(undefined, () => {
    assert.throws(() => createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet", allowMainnet: true }), isMainnetLocked);
  });
});

test("dual-unlock matrix: env only (no option) -> refused", () => {
  withEnv("1", () => {
    assert.throws(() => createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet" }), isMainnetLocked);
  });
});

test("dual-unlock matrix: env set to a non-'1' value does not unlock", () => {
  withEnv("true", () => {
    assert.throws(() => createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet", allowMainnet: true }), isMainnetLocked);
  });
});

test("dual-unlock matrix: allowMainnet must be exactly boolean true", () => {
  withEnv("1", () => {
    assert.throws(() => createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet", allowMainnet: "yes" }), isMainnetLocked);
  });
});

test("dual-unlock matrix: BOTH present -> the construction gate opens (no mainnet key involved)", () => {
  withEnv("1", () => {
    /* Construction succeeds; the adapter still holds only a path to a
     * TESTNET keyfile, so any actual mainnet operation fails closed at
     * connect() with WRONG_NETWORK (network binding, next test). */
    const adapter = createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet", allowMainnet: true });
    assert.equal(adapter.describe().networks[0], "mainnet");
  });
});

test("network binding: an unlocked mainnet adapter refuses a testnet keyfile (WRONG_NETWORK)", async () => {
  await withEnv("1", async () => {
    const adapter = createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "mainnet", allowMainnet: true, kaspaModule: kaspa });
    await assert.rejects(adapter.connect(), (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK && /bound to network "testnet-10"/.test(e.message));
  });
});

test("generate: mainnet keyfile generation refused in every locked combination", () => {
  const out = path.join(dir, "never-created-mainnet.json");
  withEnv(undefined, () => {
    assert.throws(() => generateKeyfile({ out, network: "mainnet", kaspaModule: kaspa }), isMainnetLocked);
    assert.throws(() => generateKeyfile({ out, network: "mainnet", allowMainnet: true, kaspaModule: kaspa }), isMainnetLocked);
  });
  withEnv("1", () => {
    assert.throws(() => generateKeyfile({ out, network: "mainnet", kaspaModule: kaspa }), isMainnetLocked);
  });
  assert.equal(fs.existsSync(out), false); // nothing was written by refused attempts
});

test("unknown network values fail closed at construction and generation (closed vocabulary)", () => {
  assert.throws(
    () => createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "testnet-11" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown network/.test(e.message)
  );
  assert.throws(
    () => generateKeyfile({ out: path.join(dir, "never.json"), network: "devnet", kaspaModule: kaspa }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown network/.test(e.message)
  );
  assert.throws(() => assertOperatingNetwork("simnet", false), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
});

test("tampered network label: a testnet key relabeled 'mainnet' is refused by a testnet adapter (WRONG_NETWORK)", async () => {
  /* Adversarial fixture: the KEY is a throwaway testnet test key; the
   * test corrupts the file's network FIELD to prove the fail-closed
   * binding. No mainnet key material is generated. */
  const tamperedPath = path.join(dir, "tampered-network-label.json");
  generateKeyfile({ out: tamperedPath, network: "testnet-10", kaspaModule: kaspa });
  const record = JSON.parse(fs.readFileSync(tamperedPath, "utf8"));
  record.network = "mainnet";
  fs.writeFileSync(tamperedPath, JSON.stringify(record), { mode: 0o600 });
  fs.chmodSync(tamperedPath, 0o600);

  const adapter = createCliSignerAdapter({ keyfilePath: tamperedPath, network: "testnet-10", kaspaModule: kaspa });
  await assert.rejects(adapter.connect(), (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK);
});

test("getNetwork() reports the configured network claim without connecting", async () => {
  const adapter = createCliSignerAdapter({ keyfilePath: testnetKeyfile, network: "testnet-10", kaspaModule: kaspa });
  assert.equal(await adapter.getNetwork(), "testnet-10");
});
