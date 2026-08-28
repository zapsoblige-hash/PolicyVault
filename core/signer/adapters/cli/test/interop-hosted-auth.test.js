"use strict";

/*
 * UNIT — SIGNER INDEPENDENCE INTEROP PROOF.
 *
 * A challenge signed by the OFFLINE CLI keyfile signer must authenticate
 * against the SAME verification code path the hosted product uses — no
 * KasWare, no browser, no DOM anywhere in the flow.
 *
 * The verifier here is the REAL server/src/auth.js HostedAuthService
 * (the production hosted-auth class), constructed with its real
 * MemoryAuthStore and the real kaspa-wasm module:
 *   - createChallenge() issues the production 7-line challenge text;
 *   - the CLI adapter signs it through executeSigning (the full v1
 *     lifecycle: capability/scheme/network/identity gates);
 *   - verify() reconstructs the message server-side, re-derives the
 *     x-only key from the submitted 66-hex compressed provider key,
 *     binds it to the challenge address, and calls kaspa.verifyMessage
 *     (BIP-340 Schnorr over PersonalMessageSigningHash) — the exact
 *     call at server/src/auth.js:437.
 *
 * The ONLY substitution: `require("websocket")` (pulled in at module
 * load by sdk/src/chain.js for RPC transport, unused by auth) resolves
 * to an offline stub whose constructor THROWS — so the test doubles as
 * proof that the whole flow constructs no network transport. Everything
 * else — HostedAuthService, MemoryAuthStore, resolveAddressIdentity,
 * kaspa-wasm — is the real production code, unmodified.
 *
 * Throwaway TEST keys on testnet-10 only.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const { createMessageSigningRequest, executeSigning } = require("../../../index");
const { generateKeyfile, createCliSignerAdapter } = require("../adapter");
const { loadKaspaOrExplain, makeTempDir, kaspaModulePath, installOfflineWebsocketStub, runCli, REPO_ROOT } = require("../testkit");

const fs = require("fs");

/* Install the offline stub BEFORE the real server module is required. */
installOfflineWebsocketStub();
const { HostedAuthService, AuthErrorCodes } = require(path.join(REPO_ROOT, "server/src/auth.js"));

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-cli-signer-interop-");
const keyfilePath = path.join(dir, "interop-test-key.json");
const identity = generateKeyfile({ out: keyfilePath, network: "testnet-10", label: "interop proof key", kaspaModule: kaspa });

/* Production-shaped hosted-auth config (the fields HostedAuthService
 * reads); rustyKaspaModule points at the same vendored module the
 * adapter uses — exactly loadConfig()'s field. */
const authConfig = {
  authMode: "enabled",
  appOrigin: "http://127.0.0.1:8080",
  networkId: "testnet-10",
  authChallengeTtlMs: 120_000,
  authSessionInactivityMs: 3_600_000,
  authSessionAbsoluteMs: 86_400_000,
  rustyKaspaModule: kaspaModulePath()
};

async function cliSign(message) {
  const adapter = createCliSignerAdapter({ keyfilePath, network: "testnet-10", kaspaModule: kaspa });
  const session = await adapter.connect();
  const request = createMessageSigningRequest({
    message,
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: session.address
  });
  const outcome = await executeSigning(adapter, request);
  const publicKey = await adapter.getPublicKey();
  await adapter.disconnect();
  return { signature: outcome.result.signature, publicKey, address: session.address };
}

test("INTEROP: a CLI-signed challenge authenticates through the REAL HostedAuthService.verify", async () => {
  const svc = new HostedAuthService(authConfig);
  const challenge = await svc.createChallenge(identity.address);
  assert.equal(challenge.walletAddress, identity.address);
  assert.equal(challenge.message.split("\n").length, 7); // the production 7-line challenge
  assert.match(challenge.message, /This signature only signs you in\. It cannot move funds\.$/);

  const signed = await cliSign(challenge.message);
  const { token, session } = await svc.verify({
    nonce: challenge.nonce,
    signature: signed.signature,
    publicKey: signed.publicKey, // provider-native 66-hex compressed — same as KasWare's getPublicKeyRaw path
    walletAddress: identity.address
  });

  assert.match(token, /^[0-9a-f]{64}$/);
  assert.equal(session.walletAddress, identity.address);
  assert.equal(session.networkId, "testnet-10");
});

test("INTEROP: the session created from a CLI signature validates like any hosted session", async () => {
  const svc = new HostedAuthService(authConfig);
  const challenge = await svc.createChallenge(identity.address);
  const signed = await cliSign(challenge.message);
  const { token } = await svc.verify({ nonce: challenge.nonce, signature: signed.signature, publicKey: signed.publicKey });
  const principal = await svc.resolveSession(token);
  assert.equal(principal.walletAddress, identity.address);
  assert.equal(principal.xOnlyPubkey, identity.xOnlyPublicKey);
});

test("INTEROP negative: a tampered signature is refused by the real verifier (AUTH_SIGNATURE_INVALID)", async () => {
  const svc = new HostedAuthService(authConfig);
  const challenge = await svc.createChallenge(identity.address);
  const signed = await cliSign(challenge.message);
  const flipped = (signed.signature[0] === "0" ? "1" : "0") + signed.signature.slice(1);
  await assert.rejects(
    svc.verify({ nonce: challenge.nonce, signature: flipped, publicKey: signed.publicKey }),
    (e) => e.code === AuthErrorCodes.AUTH_SIGNATURE_INVALID
  );
});

test("INTEROP negative: a different key's public key cannot claim this challenge (AUTH_ADDRESS_MISMATCH)", async () => {
  const otherKeyfile = path.join(dir, "other-key.json");
  const other = generateKeyfile({ out: otherKeyfile, network: "testnet-10", kaspaModule: kaspa });
  const svc = new HostedAuthService(authConfig);
  const challenge = await svc.createChallenge(identity.address);
  const signed = await cliSign(challenge.message);
  await assert.rejects(
    svc.verify({ nonce: challenge.nonce, signature: signed.signature, publicKey: other.publicKey }),
    (e) => e.code === AuthErrorCodes.AUTH_ADDRESS_MISMATCH
  );
});

test("INTEROP negative: challenge single-use survives — a second verify with the same nonce is refused", async () => {
  const svc = new HostedAuthService(authConfig);
  const challenge = await svc.createChallenge(identity.address);
  const signed = await cliSign(challenge.message);
  await svc.verify({ nonce: challenge.nonce, signature: signed.signature, publicKey: signed.publicKey });
  await assert.rejects(
    svc.verify({ nonce: challenge.nonce, signature: signed.signature, publicKey: signed.publicKey }),
    (e) => e.code === AuthErrorCodes.AUTH_CHALLENGE_UNKNOWN || e.code === AuthErrorCodes.AUTH_CHALLENGE_USED
  );
});

test("INTEROP via the CLI BINARY: a challenge-format message file signed by cli.js verifies with kaspa.verifyMessage (auth.js:437 call shape)", async () => {
  const svc = new HostedAuthService(authConfig);
  const challenge = await svc.createChallenge(identity.address);

  /* the CLI signs the EXACT challenge bytes from a file, offline */
  const messageFile = path.join(dir, "challenge-message.txt");
  fs.writeFileSync(messageFile, challenge.message); // byte-exact, no added newline
  const result = runCli(["sign-message", "--key", keyfilePath, "--message-file", messageFile]);
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(result.stdout);

  /* the exact verification call the server makes (server/src/auth.js:437) */
  const xOnly = new kaspa.PublicKey(doc.publicKey).toXOnlyPublicKey().toString().toLowerCase();
  assert.equal(xOnly, identity.xOnlyPublicKey);
  assert.equal(kaspa.verifyMessage({ message: challenge.message, signature: doc.signature, publicKey: xOnly }), true);

  /* and end-to-end: the binary's signature creates a real hosted session */
  const { session } = await svc.verify({ nonce: challenge.nonce, signature: doc.signature, publicKey: doc.publicKey });
  assert.equal(session.walletAddress, identity.address);
});

test("INTEROP domain separation: an auth signature is NOT a transaction signature (different message => fails)", async () => {
  /* Personal messages live in the PersonalMessageSigningHash domain; the
   * verifier refuses the same signature over any other message — the
   * structural reason a sign-in can never move funds. */
  const signed = await cliSign("PolicyVault authentication\ndomain separation probe");
  assert.equal(
    kaspa.verifyMessage({ message: "completely different bytes", signature: signed.signature, publicKey: identity.xOnlyPublicKey }),
    false
  );
});
