"use strict";

/*
 * TEST SEAM (not a test file, not an image member): the node DAA reads of the
 * delegate period-start rule (RC45 R2-13).
 *
 *   useAnchorDaa(value | fn) -> restore()
 *     Replaces chain.readAnchorDaa, the build/check-time read of the
 *     configured synced node's canonical virtual DAA score that the hosted
 *     builders and check points reach as require("./chain").readAnchorDaa at
 *     call time. A value (a non-negative bigint, a non-negative safe integer
 *     or a digit string; anything else is refused here) is answered as a
 *     BigInt. A function is called with the read's arguments and its result
 *     or its throw is the answer (a thrower models a node that is down or
 *     unsynced). restore() puts back exactly what was there before, removing
 *     the property when there was none. restore.calls() counts the reads made
 *     through this installation.
 *
 *   withDaa(rpc, value) -> rpc
 *     Gives a mock rpc a getBlockDagInfo answering { virtualDaaScore: value },
 *     plus the sink its existing getBlockDagInfo reports, when it has one (an
 *     existing getBlockDagInfo that throws still throws). The value is passed
 *     through as given, so a test may also hand a non-canonical score to the
 *     code under test.
 *
 * Legacy fixtures install useAnchorDaa at or below their own fixture starts
 * (so max(start, DAA) is the start they already commit) and give a submit-time
 * mock rpc a DAA consistent with their depth logic. No node is contacted and
 * no key is used.
 */

const chain = require("../src/chain");

function canonicalDaa(value, what) {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^[0-9]+$/.test(value)) return BigInt(value);
  throw new TypeError(`${what}: a DAA score must be a non-negative bigint, safe integer or digit string (use a function to model a failing read)`);
}

function useAnchorDaa(valueOrFn) {
  const had = Object.prototype.hasOwnProperty.call(chain, "readAnchorDaa");
  const previous = chain.readAnchorDaa;
  const answer = typeof valueOrFn === "function" ? null : canonicalDaa(valueOrFn, "useAnchorDaa");
  let calls = 0;
  chain.readAnchorDaa = async function readAnchorDaa(...args) {
    calls += 1;
    if (answer === null) return valueOrFn(...args);
    return answer;
  };
  function restore() {
    if (had) chain.readAnchorDaa = previous;
    else delete chain.readAnchorDaa;
  }
  restore.calls = () => calls;
  return restore;
}

function withDaa(rpc, value) {
  if (!rpc || (typeof rpc !== "object" && typeof rpc !== "function")) throw new TypeError("withDaa: a mock rpc object is required");
  const existing = typeof rpc.getBlockDagInfo === "function" ? rpc.getBlockDagInfo : null;
  rpc.getBlockDagInfo = async function getBlockDagInfo(...args) {
    const answer = { virtualDaaScore: value };
    if (existing) {
      const dag = await existing.apply(this, args);
      if (dag && dag.sink !== undefined) answer.sink = dag.sink;
    }
    return answer;
  };
  return rpc;
}

module.exports = { useAnchorDaa, withDaa };
