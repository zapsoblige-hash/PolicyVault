"use strict";

/*
 * UNIT — CLI keyfile signer: keyfile custody hardening.
 *
 * Generation invariants (mode 600, no overwrite, no secret in the
 * returned identity) and fail-closed refusal of every malformed /
 * tampered / mis-permissioned keyfile. Throwaway testnet TEST keys only.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { SignerErrorCodes } = require("../../../index");
const { generateKeyfile, readKeyfileIdentity, createCliSignerAdapter, KEYFILE_FORMAT } = require("../adapter");
const { loadKaspaOrExplain, makeTempDir, throwawayTestSecretHex } = require("../testkit");

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-cli-signer-keyfile-");

function freshPath(name) {
  return path.join(dir, name);
}

function writeKeyfileVariant(name, mutate) {
  const p = freshPath(name);
  const base = generateKeyfile({ out: p, network: "testnet-10", kaspaModule: kaspa });
  const record = JSON.parse(fs.readFileSync(p, "utf8"));
  mutate(record);
  fs.writeFileSync(p, typeof record === "string" ? record : JSON.stringify(record));
  fs.chmodSync(p, 0o600);
  return { path: p, identity: base };
}

async function expectConnectRefusal(keyfilePath, check) {
  const adapter = createCliSignerAdapter({ keyfilePath, network: "testnet-10", kaspaModule: kaspa });
  await assert.rejects(adapter.connect(), check);
  assert.equal(await adapter.getActiveAccount(), null); // refusal leaves no session
}

test("generate creates an owner-only (600) keyfile and returns PUBLIC identity only", () => {
  const p = freshPath("gen-basic.json");
  const identity = generateKeyfile({ out: p, network: "testnet-10", label: "unit test key", kaspaModule: kaspa });
  const stat = fs.statSync(p);
  if (process.platform !== "win32") assert.equal(stat.mode & 0o777, 0o600);

  const record = JSON.parse(fs.readFileSync(p, "utf8"));
  assert.equal(record.format, KEYFILE_FORMAT);
  assert.equal(record.network, "testnet-10");
  assert.match(record.privateKeyHex, /^[0-9a-f]{64}$/);
  assert.equal(record.address, identity.address);

  /* the returned identity carries NO secret material */
  const serialized = JSON.stringify(identity);
  assert.ok(!serialized.includes(record.privateKeyHex));
  assert.equal(identity.publicKey, record.publicKeyHex);
  assert.match(identity.xOnlyPublicKey, /^[0-9a-f]{64}$/);
  assert.equal(identity.publicKey.slice(2), identity.xOnlyPublicKey);
});

test("generate refuses to overwrite an existing file", () => {
  const p = freshPath("gen-no-overwrite.json");
  generateKeyfile({ out: p, network: "testnet-10", kaspaModule: kaspa });
  const before = fs.readFileSync(p, "utf8");
  assert.throws(
    () => generateKeyfile({ out: p, network: "testnet-10", kaspaModule: kaspa }),
    (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /refusing to overwrite/.test(e.message)
  );
  assert.equal(fs.readFileSync(p, "utf8"), before); // untouched
});

test("generate refuses unknown options and malformed labels (closed options)", () => {
  assert.throws(() => generateKeyfile({ out: freshPath("never1.json"), seedPhrase: "abc", kaspaModule: kaspa }), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown generateKeyfile option/.test(e.message));
  assert.throws(() => generateKeyfile({ out: freshPath("never2.json"), label: "x".repeat(65), kaspaModule: kaspa }), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(() => generateKeyfile({ kaspaModule: kaspa }), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /output file path/.test(e.message));
});

test("readKeyfileIdentity round-trips the public identity of a valid keyfile", () => {
  const p = freshPath("identity-roundtrip.json");
  const generated = generateKeyfile({ out: p, network: "testnet-10", label: "identity key", kaspaModule: kaspa });
  const identity = readKeyfileIdentity(p, { kaspaModule: kaspa });
  assert.equal(identity.address, generated.address);
  assert.equal(identity.publicKey, generated.publicKey);
  assert.equal(identity.network, "testnet-10");
  assert.equal(identity.label, "identity key");
  assert.ok(!JSON.stringify(identity).match(/[0-9a-f]{64}/) || !JSON.stringify(identity).includes(JSON.parse(fs.readFileSync(p, "utf8")).privateKeyHex));
});

test("missing keyfile: detect false, connect fails closed with SIGNER_NOT_FOUND", async () => {
  const adapter = createCliSignerAdapter({ keyfilePath: freshPath("missing.json"), network: "testnet-10", kaspaModule: kaspa });
  assert.equal(adapter.detect(), false);
  await assert.rejects(adapter.connect(), (e) => e.signerCode === SignerErrorCodes.SIGNER_NOT_FOUND);
});

test("group/other-readable keyfile is refused (mode gate) until chmod 600", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX mode bits only");
  const p = freshPath("mode-gate.json");
  generateKeyfile({ out: p, network: "testnet-10", kaspaModule: kaspa });
  fs.chmodSync(p, 0o644);
  await expectConnectRefusal(p, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /chmod 600/.test(e.message));
  fs.chmodSync(p, 0o600);
  const adapter = createCliSignerAdapter({ keyfilePath: p, network: "testnet-10", kaspaModule: kaspa });
  const session = await adapter.connect(); // recovers once owner-only
  assert.ok(session.address.startsWith("kaspatest:"));
});

test("non-JSON keyfile content is refused without echoing the content", async () => {
  const p = freshPath("not-json.json");
  fs.writeFileSync(p, "this is not json { ", { mode: 0o600 });
  fs.chmodSync(p, 0o600);
  await expectConnectRefusal(p, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /not valid JSON/.test(e.message) && !e.message.includes("this is not json"));
});

test("unknown keyfile format version fails closed (never routed to a default)", async () => {
  const variant = writeKeyfileVariant("format-v2.json", (r) => {
    r.format = "policyvault-cli-signer-keyfile/2";
  });
  await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /unknown versions fail closed/.test(e.message));
});

test("keyfile with an unknown extra key is refused (closed schema)", async () => {
  const variant = writeKeyfileVariant("extra-key.json", (r) => {
    r.seedPhrase = "never accepted anywhere";
  });
  await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /unknown key "seedPhrase"/.test(e.message));
});

test("keyfile missing a required key is refused", async () => {
  const variant = writeKeyfileVariant("missing-created.json", (r) => {
    delete r.createdAt;
  });
  await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /missing required key "createdAt"/.test(e.message));
});

test("malformed private key shapes are refused with SHAPE-ONLY diagnostics", async () => {
  const cases = [
    ["priv-short.json", "abcd"],
    ["priv-upper.json", "A".repeat(64)],
    ["priv-nonhex.json", "z".repeat(64)]
  ];
  for (const [name, value] of cases) {
    const variant = writeKeyfileVariant(name, (r) => {
      r.privateKeyHex = value;
    });
    await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /value not shown/.test(e.message) && !e.message.includes(value));
  }
});

test("tampered public-key claim is refused (identity re-derivation)", async () => {
  const variant = writeKeyfileVariant("tampered-pub.json", (r) => {
    r.publicKeyHex = "02" + throwawayTestSecretHex("other-key").slice(0, 64);
  });
  await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /possible tampering/.test(e.message));
});

test("tampered address claim is refused (identity re-derivation)", async () => {
  const other = generateKeyfile({ out: freshPath("other-for-address.json"), network: "testnet-10", kaspaModule: kaspa });
  const variant = writeKeyfileVariant("tampered-address.json", (r) => {
    r.address = other.address; // a REAL address, but not this key's
  });
  await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /possible tampering/.test(e.message));
});

test("swapped-in private key (valid shape, different key) is caught by the identity re-derivation", async () => {
  const variant = writeKeyfileVariant("swapped-priv.json", (r) => {
    r.privateKeyHex = throwawayTestSecretHex("swapped"); // parses fine, derives a different identity
  });
  await expectConnectRefusal(variant.path, (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /possible tampering/.test(e.message));
});

test("directory at the keyfile path is refused as not-a-file", async () => {
  const p = freshPath("a-directory");
  fs.mkdirSync(p);
  const adapter = createCliSignerAdapter({ keyfilePath: p, network: "testnet-10", kaspaModule: kaspa });
  assert.equal(adapter.detect(), false);
  await assert.rejects(adapter.connect(), (e) => e.signerCode === SignerErrorCodes.SIGNER_NOT_FOUND && /not a regular file/.test(e.message));
});

test("adapter construction refuses unknown options and a missing keyfilePath (closed options)", () => {
  assert.throws(() => createCliSignerAdapter({}), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /requires keyfilePath/.test(e.message));
  assert.throws(
    () => createCliSignerAdapter({ keyfilePath: freshPath("x.json"), autoApprove: true }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown createCliSignerAdapter option/.test(e.message)
  );
});

test("connect() re-validates on every call — a keyfile corrupted after a good connect refuses the next connect", async () => {
  const p = freshPath("revalidate.json");
  generateKeyfile({ out: p, network: "testnet-10", kaspaModule: kaspa });
  const adapter = createCliSignerAdapter({ keyfilePath: p, network: "testnet-10", kaspaModule: kaspa });
  await adapter.connect();
  await adapter.disconnect();
  const record = JSON.parse(fs.readFileSync(p, "utf8"));
  record.privateKeyHex = throwawayTestSecretHex("corrupted-after-connect");
  fs.writeFileSync(p, JSON.stringify(record));
  fs.chmodSync(p, 0o600);
  await assert.rejects(adapter.connect(), (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /possible tampering/.test(e.message));
  assert.equal(await adapter.getActiveAccount(), null);
});
