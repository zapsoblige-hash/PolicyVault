"use strict";
// The preserved public, real SDK-built spend fixture, with persistence/RPC/
// compiler/transaction-ID stubs. Product modules are loaded without edits.
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const fixture = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../docs/postlaunch/ux-evidence/cp13-codex/probes/delegate-recovery-fixture.json")));
const helperPath = path.join(__dirname, "cp13-memory.js");
const source = fs.readFileSync(helperPath, "utf8");
if (!source.includes("finalize:()=>txid")) throw Error("inspect changed CP13 transaction stub before adapting");
const mod = { exports: {} };
const scripts = require("../../core/intent/vault-script-v7"), crypto = require("node:crypto");
const compile = ({ template, state }) => {
  const scriptHex = scripts.reconstructVaultScriptHexV7({ template, state });
  return { scriptHex, scriptSha256: crypto.createHash("sha256").update(Buffer.from(scriptHex, "hex")).digest("hex") };
};
const adapted = source.replace("finalize:()=>txid", "finalize:()=>probeTxId").replace("function sourceFor(file)", "shared['./contract-compiler-v7'] = { compileExactStateV7: probeCompile }; chain.covenantAddress = (_config, bytes) => 'spk:' + probeP2sh(bytes.toString('hex')); function sourceFor(file)");
vm.compileFunction(adapted, ["module", "exports", "require", "__dirname", "probeTxId", "probeCompile", "probeP2sh"])(mod, mod.exports, require, __dirname, fixture.request.txId, compile, scripts.p2shSpkHexOf);
module.exports = async function delegateMemory() {
  const x = mod.exports(); await x.reset();
  const q = structuredClone(fixture.request), doc = structuredClone(fixture.manifest);
  // Register only the preserved honest transaction. Mutated bytes must still
  // fail the current fixture's explicit transaction-ID lookup.
  x.registerTransaction?.(q.finalTransaction, q.txId);
  // The historical diagnostic used H('aa') with its compiler stub. These
  // controls bind the real frozen-generation script instead, in memory only.
  doc.live.scriptSha256 = compile({ template: q.build.template, state: q.build.stateJson }).scriptSha256;
  await x.manifestModule.persistManifestV7(x.cfg, doc);
  await x.wr.saveV7WalletRequest(x.cfg, q);
  let submits = 0, mode = "honest", landed = true;
  const rpc = {
    async query(address) {
      if (mode === "query-error") throw Error("STUB RPC read failure");
      if (!landed) return [];
      return q.finalTransaction.outputs.flatMap((o, index) => address === "spk:" + o.scriptPublicKey.scriptHex ? [{ outpoint: { transactionId: q.txId, index }, amount: BigInt(o.value), covenantId: o.covenant?.covenantId ?? null, scriptPublicKeyHex: o.scriptPublicKey.scriptHex }] : []);
    },
    async submitTransaction() { submits++; if (mode === "timeout") throw Error("STUB RPC timeout after accepted transaction"); return { transactionId: q.txId }; }
  };
  const config = x.cfg;
  return { ...x, q, doc, rpc, config, setMode: (v) => { mode = v; }, setLanded: (v) => { landed = v; }, submits: () => submits,
    submit: () => x.wr.submitV7WalletRequest({ config, requestId: q.requestId, rpc, pollAttempts: 1, pollDelayMs: 0 }),
    reconcile: () => x.rec.reconcileVault(config, rpc, q.vaultId, { allowClaimRelease: true, stalePendingMinimumMs: 0 }),
    request: () => x.wr.loadV7WalletRequest(config, q.requestId),
    vault: async () => x.manifestModule.manifestToJsonV7(await x.manifestModule.loadManifestV7(config, q.vaultId)) };
};
