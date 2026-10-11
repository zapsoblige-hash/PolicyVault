"use strict";
/*
 * RC45 F6 test kit (fix item F6 RC45-L5-RECOVER-EVIDENCE; plan
 * rc45-simplified-plan-r2 §1 O3 (3), §2.2 step 9, §2.5(3) owner-pasted
 * recover, §5 A5, §7 L-12, §8 rules and T5/T8 pasted-recover legs, §8.2
 * sabotage n). Internal RED-first regression material for the RC45 candidate;
 * not an audit.
 *
 * Used by sdk/test/rc45-t5-recover-evidence.test.js and
 * sdk/test/rc45-t8-recover-evidence-route.test.js, on top of the F5 kit
 * (sdk/testutil/rc45-f5-kit.js, reused unchanged for vaults, wallets, the
 * explicit chain model, snapshots and install). It adds:
 *
 *   - safeJsonOf: the Safe JSON of a signed final transaction (the form the
 *     owner pastes; WEB-3), from the engine's own serializer after finalize()
 *     stamps the consensus id.
 *   - construct: a REAL out-of-app owner transaction with a shape the hosted
 *     builder never produces (the vault input at index 1 of a recover; the
 *     dangerous ownerControl shape with outputs[0] = P2PK(owner) worth pv+fr
 *     paid from fuel and the C successor at index 1, CR-I3). It starts from a
 *     candidate SDK build (real v0.4.1 compiler, successor state, encoder
 *     paths), re-arranges the frozen draft, takes the consensus txid and the
 *     per-input sighash from pv_tx_probe (describeFrozenTx), signs every
 *     input with the TEST owner key (rusty-kaspa createInputSignature over
 *     the frozen form), encodes the real covenant call through
 *     pv_call_encoder, assembles the covenant signature script and runs
 *     pv_vm_preflight on EVERY input. The caller asserts the VM verdict, so
 *     each such transaction is VM-verified; fee and mass policy are not
 *     evaluated (the chain model accepts what the test confirms).
 *   - the Verify child (this file run as a script): the candidate
 *     reconcileVaultV4(config, vaultId, { rpc, outOfAppTransaction }) in a
 *     FRESH process against the same JSON root or PostgreSQL database, with a
 *     serialized chain model; the payload travels on stdin (a real recover
 *     Safe JSON is about 35 KB). Used with POLICYVAULT_PV_VM_PREFLIGHT_PATH
 *     on a failing TEST harness (vm-preflight.js reads it at load).
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node
 * observation comes from the explicit chain model passed as `rpc`. TEST keys
 * only.
 */
const path = require("node:path"), fs = require("node:fs"), cp = require("node:child_process");
const assert = require("node:assert/strict");
const K = require("./rc45-f5-kit");

const SDK_SRC = path.join(__dirname, "..", "src");
const CHILD_MODE = "rc45-f6-verify-child", CHILD_TAG = "RC45-F6-VERIFY-CHILD-RESULT ";
const src = (name) => require(path.join(SDK_SRC, name));

/* The Safe JSON of a signed final transaction (canonical frozen JSON + signature scripts). */
function safeJsonOf(config, finalTransaction) {
  const tx = src("wallet-submit-v4.js").finalTxToWasm(config, finalTransaction);
  tx.finalize(); // stamps the consensus id (covenant bindings included) into the serialized document
  return tx.serializeToSafeJSON();
}
/* The consensus id the engine recomputes from a Safe JSON document (never its embedded `id`). */
function consensusIdOf(config, safe) { return src("tx-identity.js").parseSignedTransactionSafeJson(config, safe).transactionId; }

/* The 65-byte SIG_HASH_ALL Schnorr signature inside a P2PK-style signature script push (0x41 || sig || 0x01). */
function sig65(scriptHex) {
  assert.ok(typeof scriptHex === "string" && scriptHex.length === 132 && scriptHex.startsWith("41") && scriptHex.endsWith("01"), "a 65-byte SIG_HASH_ALL signature push");
  return scriptHex.slice(2);
}

/*
 * A real TEST-key signed transaction from a candidate build and a re-arranged frozen draft. `covenantInput` is the
 * index of the vault input, `fuelInput` the index of the owner's fuel; both are signed by `secretHex` (the TEST owner).
 * Returns { frozen, txId, finalTransaction, verdict, safe } with the pv_vm_preflight verdict over every input.
 */
function construct(config, build, draft, { covenantInput, fuelInput, secretHex }) {
  const FT = src("frozen-tx-v3.js"), B4 = src("vault-builders-v4.js");
  const kaspa = require(config.rustyKaspaModule), priv = new kaspa.PrivateKey(secretHex);
  const frozen = FT.normalizeFrozenTxV3(draft);
  const described = FT.describeFrozenTx(frozen);
  const wtx = FT.frozenToWasmTransaction(config, frozen);
  const covenantSig = sig65(kaspa.createInputSignature(wtx, covenantInput, priv));
  const fuelScript = kaspa.createInputSignature(wtx, fuelInput, priv);
  const call = { function: build.encoderFunction ?? build.action, ...(build.encoderExtra ?? {}), signature: covenantSig, ...(build.callExtra ?? {}) };
  if (build.action !== "ownerRecover") call.successor = B4.successorCallJsonV4(build.successorState);
  const callHex = B4.runEncoderV4({ sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"), call, contractVersion: build.contractVersion });
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const finalTransaction = JSON.parse(FT.canonicalFrozenTxJson(frozen));
  finalTransaction.inputs[covenantInput].signatureScript = src("spend-vault.js").covenantSigscript(callHex, Buffer.from(artifact.script));
  finalTransaction.inputs[fuelInput].signatureScript = fuelScript;
  const verdict = src("vm-preflight.js").preflightAllInputs(finalTransaction);
  const safe = safeJsonOf(config, finalTransaction);
  assert.equal(consensusIdOf(config, safe), described.txId, "the engine recomputes the probe's consensus id from the Safe JSON");
  return { frozen, txId: described.txId, finalTransaction, verdict, safe };
}

/* A SYNTHETIC variant of a signed transaction: `mutate(json)` edits the canonical frozen JSON (values, bindings); the
 * signature scripts are kept (the id excludes them), so the result is NOT consensus-valid. Returns { frozen, txId, safe }. */
function synthetic(config, finalTransaction, mutate) {
  const FT = src("frozen-tx-v3.js");
  const json = JSON.parse(JSON.stringify(finalTransaction));
  mutate(json);
  const unsigned = JSON.parse(JSON.stringify(json));
  for (const input of unsigned.inputs) delete input.signatureScript;
  const frozen = FT.normalizeFrozenTxV3(unsigned);
  const txId = FT.describeFrozenTx(frozen).txId;
  const safe = safeJsonOf(config, json);
  assert.equal(consensusIdOf(config, safe), txId);
  return { frozen, txId, safe };
}

/* ---------------- the Verify child (paste) ---------------- */
async function verifyChild(input) {
  const cand = K.modulesOf(SDK_SRC);
  let config;
  if (input.pg) {
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: input.pg.host, pgPort: input.pg.port, pgUser: input.pg.user, pgDatabase: input.pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot: input.dataRoot, rpcUrl: K.LOOPBACK });
    await cand.store.openPgStore(config, { migrate: false });
  } else config = cand.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: K.LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const store = cand.store.getStore(config);
  const model = K.chainModel(config, input.model);
  let result;
  try {
    const out = await cand.reconcile4.reconcileVaultV4(config, input.vaultId, { rpc: model.rpc, outOfAppTransaction: input.outOfAppTransaction });
    result = { ok: true, value: K.jsonSafe(out), calls: model.calls.length };
  } catch (error) {
    result = { ok: false, code: error.code ?? null, message: String(error.message), calls: model.calls.length };
  }
  if (input.pg) await store.close();
  return result;
}
/* Run the candidate Verify with `outOfAppTransaction` in a fresh child against `x` (a case from a suite's fresh()). */
function verifyPasteInChild(x, v, outOfAppTransaction, { env = {}, pg = null } = {}) {
  const payload = { vaultId: v.vaultId, dataRoot: x.config.dataRoot, pg: x.pgDatabase ? { ...pg, database: x.pgDatabase } : null, model: x.model.serialize(), outOfAppTransaction };
  const child = cp.spawnSync(process.execPath, [__filename, CHILD_MODE], { input: JSON.stringify(payload), encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, ...env } });
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(CHILD_TAG));
  return { signal: child.signal, status: child.status, stderr: (child.stderr || "").slice(-4000), result: line ? JSON.parse(line.slice(CHILD_TAG.length)) : null };
}
/* The harness-failure environment for a Verify child: a TEST pv_vm_preflight that cannot run the engine. */
function failingHarness(dir) {
  const harness = path.join(dir, "pv_vm_preflight_failing");
  fs.writeFileSync(harness, "#!/bin/sh\necho 'TEST harness: engine unavailable' 1>&2\nexit 3\n", { mode: 0o755 });
  return { POLICYVAULT_PV_VM_PREFLIGHT_PATH: harness };
}

if (require.main === module && process.argv[2] === CHILD_MODE) {
  const chunks = [];
  process.stdin.on("data", (d) => chunks.push(d));
  process.stdin.on("end", () => {
    verifyChild(JSON.parse(Buffer.concat(chunks).toString("utf8"))).then(
      (result) => { process.stdout.write(`${CHILD_TAG}${JSON.stringify(result)}\n`); },
      (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
    );
  });
}

module.exports = { SDK_SRC, safeJsonOf, consensusIdOf, construct, synthetic, verifyPasteInChild, failingHarness };
