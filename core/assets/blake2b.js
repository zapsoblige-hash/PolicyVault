"use strict";

/*
 * BLAKE2b (RFC 7693) with a configurable digest length — pure, portable
 * JavaScript (no Node crypto dependency: OpenSSL exposes only the fixed
 * 512-bit variant, and blake2b-256 is a DIFFERENT parameterization, not a
 * truncation). PolicyVault needs the 32-byte digest because it is the
 * consensus/VM template identity (`OpBlake2b` in the Kaspa engine hashes
 * with hash_length 32; the P2SH envelope commits to blake2b-256 of the
 * redeem script; `readInputStateWithTemplate` / `validateOutputStateWithTemplate`
 * verify blake2b-256(prefix || suffix)).
 *
 * Status: IMPLEMENTED + UNIT-TESTED against RFC 7693 vectors AND against
 * the real-engine fixture core/assets/test/fixtures/kcc20-template-v1.json
 * (production-byte rule: the JS digest of the real template bytes equals
 * the digest the VM verifies).
 *
 * Unkeyed only (PolicyVault never uses keyed BLAKE2b at the financial
 * boundary). Inputs are Uint8Array/Buffer; output is a Uint8Array.
 */

const BLOCK_BYTES = 128;

/* IV as 16 x 32-bit words (little-endian halves: lo, hi) */
const IV32 = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19
]);

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
];
/* SIGMA entries doubled (index into the 32-bit-word message array). */
const SIGMA2 = SIGMA.map((row) => row.map((x) => x * 2));

/* 64-bit add on (lo, hi) pairs inside the v array. */
function add64AA(v, a, b) {
  const o0 = v[a] + v[b];
  let o1 = v[a + 1] + v[b + 1];
  if (o0 >= 0x100000000) o1++;
  v[a] = o0 >>> 0;
  v[a + 1] = o1 >>> 0;
}

function add64AC(v, a, b0, b1) {
  let o0 = v[a] + b0;
  if (b0 < 0) o0 += 0x100000000;
  let o1 = v[a + 1] + b1;
  if (o0 >= 0x100000000) o1++;
  v[a] = o0 >>> 0;
  v[a + 1] = o1 >>> 0;
}

function B2B_G(v, m, a, b, c, d, ix, iy) {
  const x0 = m[ix];
  const x1 = m[ix + 1];
  const y0 = m[iy];
  const y1 = m[iy + 1];

  add64AA(v, a, b);
  add64AC(v, a, x0, x1);

  let xor0 = v[d] ^ v[a];
  let xor1 = v[d + 1] ^ v[a + 1];
  v[d] = xor1;
  v[d + 1] = xor0;

  add64AA(v, c, d);

  xor0 = v[b] ^ v[c];
  xor1 = v[b + 1] ^ v[c + 1];
  v[b] = ((xor0 >>> 24) ^ (xor1 << 8)) >>> 0;
  v[b + 1] = ((xor1 >>> 24) ^ (xor0 << 8)) >>> 0;

  add64AA(v, a, b);
  add64AC(v, a, y0, y1);

  xor0 = v[d] ^ v[a];
  xor1 = v[d + 1] ^ v[a + 1];
  v[d] = ((xor0 >>> 16) ^ (xor1 << 16)) >>> 0;
  v[d + 1] = ((xor1 >>> 16) ^ (xor0 << 16)) >>> 0;

  add64AA(v, c, d);

  xor0 = v[b] ^ v[c];
  xor1 = v[b + 1] ^ v[c + 1];
  v[b] = ((xor1 >>> 31) ^ (xor0 << 1)) >>> 0;
  v[b + 1] = ((xor0 >>> 31) ^ (xor1 << 1)) >>> 0;
}

function compress(ctx, last) {
  const v = new Uint32Array(32);
  const m = new Uint32Array(32);
  for (let i = 0; i < 16; i++) {
    v[i] = ctx.h[i];
    v[i + 16] = IV32[i];
  }
  v[24] ^= ctx.t0;
  v[25] ^= ctx.t1;
  v[26] ^= ctx.t2;
  v[27] ^= ctx.t3;
  if (last) {
    v[28] = ~v[28] >>> 0;
    v[29] = ~v[29] >>> 0;
  }
  for (let i = 0; i < 32; i++) {
    const o = i * 4;
    m[i] = (ctx.b[o] | (ctx.b[o + 1] << 8) | (ctx.b[o + 2] << 16) | (ctx.b[o + 3] << 24)) >>> 0;
  }
  for (let r = 0; r < 12; r++) {
    const s = SIGMA2[r];
    B2B_G(v, m, 0, 8, 16, 24, s[0], s[1]);
    B2B_G(v, m, 2, 10, 18, 26, s[2], s[3]);
    B2B_G(v, m, 4, 12, 20, 28, s[4], s[5]);
    B2B_G(v, m, 6, 14, 22, 30, s[6], s[7]);
    B2B_G(v, m, 0, 10, 20, 30, s[8], s[9]);
    B2B_G(v, m, 2, 12, 22, 24, s[10], s[11]);
    B2B_G(v, m, 4, 14, 16, 26, s[12], s[13]);
    B2B_G(v, m, 6, 8, 18, 28, s[14], s[15]);
  }
  for (let i = 0; i < 16; i++) {
    ctx.h[i] = (ctx.h[i] ^ v[i] ^ v[i + 16]) >>> 0;
  }
}

function toBytes(input, label) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === "string") {
    if (input.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(input)) {
      throw new Error(`blake2b: ${label ?? "input"} must be Uint8Array or even-length hex`);
    }
    const out = new Uint8Array(input.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(input.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  throw new Error(`blake2b: ${label ?? "input"} must be Uint8Array or hex string`);
}

/*
 * blake2b(parts, outlen) — `parts` is one Uint8Array/hex or an array of
 * them (hashed as one concatenated message, without copying the whole
 * message). outlen defaults to 32 (the Kaspa VM/P2SH parameterization).
 */
function blake2b(parts, outlen = 32) {
  if (!Number.isInteger(outlen) || outlen < 1 || outlen > 64) {
    throw new Error("blake2b: outlen must be an integer in 1..64");
  }
  const chunks = Array.isArray(parts) ? parts.map((p, i) => toBytes(p, `parts[${i}]`)) : [toBytes(parts)];
  const ctx = { b: new Uint8Array(BLOCK_BYTES), h: new Uint32Array(16), t0: 0, t1: 0, t2: 0, t3: 0, c: 0 };
  for (let i = 0; i < 16; i++) ctx.h[i] = IV32[i];
  /* parameter block: digest length, key length 0, fanout 1, depth 1 */
  ctx.h[0] ^= 0x01010000 ^ outlen;

  const incCounter = (n) => {
    ctx.t0 += n;
    if (ctx.t0 >= 0x100000000) {
      ctx.t0 -= 0x100000000;
      ctx.t1 += 1;
      if (ctx.t1 >= 0x100000000) {
        ctx.t1 -= 0x100000000;
        ctx.t2 += 1;
      }
    }
  };

  for (const chunk of chunks) {
    for (let i = 0; i < chunk.length; i++) {
      if (ctx.c === BLOCK_BYTES) {
        incCounter(BLOCK_BYTES);
        compress(ctx, false);
        ctx.c = 0;
      }
      ctx.b[ctx.c++] = chunk[i];
    }
  }

  incCounter(ctx.c);
  while (ctx.c < BLOCK_BYTES) ctx.b[ctx.c++] = 0;
  compress(ctx, true);

  const out = new Uint8Array(outlen);
  for (let i = 0; i < outlen; i++) {
    out[i] = (ctx.h[i >> 2] >> (8 * (i & 3))) & 0xff;
  }
  return out;
}

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

function blake2bHex(parts, outlen = 32) {
  return bytesToHex(blake2b(parts, outlen));
}

module.exports = { blake2b, blake2bHex, BLOCK_BYTES };
