"use strict";

const { assertStoreKey } = require("./store");

// In-process exclusion only. Equivalent stores share a conservative queue;
// each callback re-reads its own store. Public wrappers acquire it once and
// call unlocked implementations, so nested recovery never waits on itself.
const queues = new Map();
async function withOrgRootLock(rootId, work) {
  assertStoreKey(rootId);
  const previous = queues.get(rootId) ?? Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const tail = previous.then(() => gate, () => gate);
  queues.set(rootId, tail);
  try {
    await previous.catch(() => {});
    return await work();
  } finally {
    release();
    if (queues.get(rootId) === tail) queues.delete(rootId);
  }
}

module.exports = { withOrgRootLock };
