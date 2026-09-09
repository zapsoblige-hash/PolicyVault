"use strict";
// One-time provenance generator: executes the actual df68 public APIs. No
// network calls; outputs are durable legacy records, not upgraded fixtures.
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
const root = process.argv[2], dest = process.argv[3];
const terminalOnly = process.argv.includes("--terminal-only");
const depositTerminalOnly = process.argv.includes("--deposit-terminal-only");
const head = require("node:child_process").execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
assert.equal(head, "df68a1fd64775948e799935759d08b549181100c");
require("./rc27f-gate-env");
const dep = (p) => require(path.join(root, p));
const d = dep("sdk/testutil/cp13e-delegate-fixture"), { fx } = d;
async function main() {
  const base = await d.baseFixture(), config = base.config, o = base.o, table = {};
  const rpc = { seed: (a, e) => { table[a] = [...(table[a] || []), e]; }, clear: (a) => { table[a] = []; },
    getUtxosByAddresses: async ({ addresses }) => ({ entries: addresses.flatMap((a) => table[a] || []) }),
    submitTransaction: async ({ transaction }) => ({ transactionId: transaction.finalize().toString().toLowerCase() }) };
  d.settle(config, rpc, base.first); d.settle(config, rpc, base.deposit);
  const ids = { rootCovenantId: o.rootCovenantId, vaultId: o.vaultId, first: base.first.id, deposit: base.deposit.requestId, spend: base.q.requestId };
  async function snapshot(name) {
    if (terminalOnly && name !== "terminal-with-retained-token") return;
    const store = fx.getStore(config), records = {};
    for (const c of [fx.Categories.ORG_ROOT, fx.Categories.ORG_ROOT_REQUEST, fx.Categories.VAULT, fx.Categories.REQUEST, fx.Categories.RECEIPT, fx.Categories.TRANSITION_CLAIM, fx.Categories.SUBMISSION_CLAIM]) {
      records[c] = {}; for (const k of await store.listKeys(c)) records[c][k] = await store.read(c, k);
    }
    assert.ok(Object.values(records[fx.Categories.RECEIPT]).every((r) => !r.proof?.requestId));
    fs.mkdirSync(dest, { recursive: true });
    const file = path.join(dest, name + ".json");
    fs.writeFileSync(file, JSON.stringify({ producedBy: head, scenario: name, createdAt: new Date().toISOString(), ids, records, audit: await store.readAudit({ limit: 1000 }), rpc: table }, (_k, v) => typeof v === "bigint" ? { $big: v.toString() } : v, 1), { flag: "wx" });
    console.log(JSON.stringify({ scenario: name, file, bytes: fs.statSync(file).size, producedBy: head }));
  }
  if (depositTerminalOnly) {
    const terminal = await fx.signedTerminalRecover(config, o);
    assert.equal(terminal.build.hasTokenInput, false);
    d.settle(config, rpc, terminal); await fx.wr7.submitOrgRootRequest({ config, requestId: terminal.id, rpc });
    delete ids.spend; ids.terminal = terminal.id;
    await snapshot("deposit-terminal-with-retained-token"); return;
  }
  d.settle(config, rpc, base.q); await fx.wr7.submitV7WalletRequest({ config, requestId: base.q.requestId, rpc });
  await snapshot("latest-delegate");
  const secondAgent = { ...o, agentKey: fx.KEY(config, 0x66) };
  const second = await d.signedSpend(config, secondAgent, { spendAmount: "25" });
  d.settle(config, rpc, second); await fx.wr7.submitV7WalletRequest({ config, requestId: second.requestId, rpc });
  ids.secondSpend = second.requestId; await snapshot("interleaved-agents");
  const recipient = fx.XO(config, fx.KEY(config, 0x67));
  const tree = dep("sdk/src/recipient-merkle-v3").buildRecipientTree([recipient]);
  const entries = [{ ...o.policy, agentPk: fx.XO(config, secondAgent.agentKey), agentRecipientRoot: tree.root, recipients: [recipient] }];
  const change = await fx.signedRootAction(config, o, { vaultOperations: [{ vaultId: o.vaultId, action: "ownerSetAgentRoot", params: { agents: entries } }] });
  await fx.spendPredecessors(config, rpc, o); fx.settle(config, rpc, change);
  await fx.wr7.submitOrgRootRequest({ config, requestId: change.id, rpc });
  ids.change = change.id; await snapshot("replaced-agent-and-recipients");
  if (terminalOnly) {
    const terminal = await fx.signedTerminalRecover(config, o);
    assert.equal(terminal.build.hasTokenInput, false, "actual old public builder omitted the token input");
    d.settle(config, rpc, terminal); await fx.wr7.submitOrgRootRequest({ config, requestId: terminal.id, rpc });
    ids.terminal = terminal.id; await snapshot("terminal-with-retained-token");
  }
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
