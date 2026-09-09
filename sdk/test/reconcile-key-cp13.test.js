"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const memoryGenesis = require("../testutil/cp13-genesis-memory");

test("CP13 R7-07/A: decorated aliases are refused before lookup; canonical reconciliation completes", async () => {
  for (const decorate of [(id) => "./" + id, (id) => "directory/../" + id]) {
    const x = memoryGenesis(); x.reset();
    const alias = decorate(x.id), args = { config: x.cfg, requestId: x.id, rpc: x.rpc };
    const before = x.loads();
    const refused = x.mod.reconcileCreateWalletRequestV4({ ...args, requestId: alias });
    await assert.rejects(refused, (e) => e.code === "STORE_KEY_INVALID");
    assert.equal(x.loads(), before); assert.equal(x.queries(), 0);
    const [a, b] = await Promise.allSettled([x.mod.reconcileCreateWalletRequestV4(args), x.mod.reconcileCreateWalletRequestV4({ ...args, requestId: alias })]);
    assert.equal(a.value.outcome, "CHAIN_VERIFIED"); assert.equal(b.reason.code, "STORE_KEY_INVALID");
    assert.equal((await x.WR.loadRequest(x.cfg, x.id)).state, "CHAIN_VERIFIED");
    assert.equal(x.queries(), 1); assert.equal(x.manifests.size, 1);
  }
});

test("CP13 actual store contract: valid key families retained; JSON/PG aliases fail before IO", async () => {
  const x = memoryGenesis(); x.reset();
  const json = new x.actualStore.JsonStore(x.cfg);
  let queries = 0;
  const pg = new x.actualStore.PgStore(x.cfg, { query: async () => { queries++; return { rows: [], rowCount: 0 }; } });
  for (const id of [x.id, "ab".repeat(32), "ab".repeat(32) + "-0", "ab".repeat(32) + "-" + "cd".repeat(32), "assignments", "legacy-id", ".legacy-id"]) {
    await json.write(x.actualStore.Categories.REQUEST, id, { id });
    assert.deepEqual(await json.read(x.actualStore.Categories.REQUEST, id), { id });
    await pg.read(x.actualStore.Categories.REQUEST, id);
  }
  const before = queries;
  for (const store of [json, pg]) for (const id of ["./id", "directory/../id", "a\\id", ".", "..", "", "a\0b", null, 1, ["id"]]) {
    for (const method of ["read", "write", "createExclusive", "remove"]) {
      await assert.rejects(store[method](x.actualStore.Categories.REQUEST, id, {}), (e) => e.code === "STORE_KEY_INVALID", method);
    }
  }
  assert.equal(queries, before);
});

test("CP13 request queue: aliases of stores, failure cleanup, and distinct-store ownership", async () => {
  const x = memoryGenesis();
  const pg = (host) => ({ ...x.cfg, persistenceBackend: "postgres", pg: { host, port: 5432, database: "probe" } });
  for (const [a, b, mode] of [[pg("127.0.0.1"), pg("localhost"), "actual"], [{ ...x.cfg, dataRoot: "/var/run/cp13-in-memory" }, { ...x.cfg, dataRoot: "/var/run/cp13-in-memory" }, "appearing"]]) {
    x.reset([a,b]); x.setRealpathMode(mode);
    const result = await Promise.all([a,b].map((config) => x.mod.reconcileCreateWalletRequestV4({ config, requestId: x.id, rpc: x.rpc })));
    assert.deepEqual(result.map((r) => r.outcome), ["CHAIN_VERIFIED", "CHAIN_VERIFIED"]);
    assert.equal(x.queries(), 1);
  }
  x.setRealpathMode("actual"); x.reset(); x.failRead();
  const args = { config: x.cfg, requestId: x.id, rpc: x.rpc };
  const first = await Promise.allSettled([x.mod.reconcileCreateWalletRequestV4(args), x.mod.reconcileCreateWalletRequestV4(args)]);
  assert.equal(first[0].status, "rejected"); assert.equal(first[1].value.outcome, "CHAIN_VERIFIED");
  assert.equal((await x.mod.reconcileCreateWalletRequestV4(args)).outcome, "CHAIN_VERIFIED");
  const other = { ...x.cfg, dataRoot: "/memory/other" }; x.reset([x.cfg, other]);
  const [a,b] = await Promise.all([x.mod.reconcileCreateWalletRequestV4(args), x.mod.reconcileCreateWalletRequestV4({ ...args, config: other })]);
  assert.equal(a.outcome, "CHAIN_VERIFIED"); assert.equal(b.outcome, "PENDING");
  assert.equal((await x.WR.loadRequest(x.cfg, x.id)).state, "CHAIN_VERIFIED");
  assert.equal((await x.WR.loadRequest(other, x.id)).state, "RECONCILIATION_REQUIRED");
  assert.equal(x.manifests.has(x.rootKey(other)), false);
});
