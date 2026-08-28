"use strict";

/*
 * Webhook payload signing (versioned scheme "pv1") + the CONSUMER-SIDE
 * reference verifier (docs/postlaunch/webhooks-events-spec.md §8 carries
 * this exact recipe; the tests drive this implementation).
 *
 * Scheme pv1:
 *   signedInput = `${timestampSeconds}.${rawBody}`   (rawBody = the exact
 *   UTF-8 request body bytes as sent — never a re-serialization)
 *   signature   = HMAC-SHA256(secret, signedInput), lowercase hex
 *
 * Header (X-PolicyVault-Signature):
 *   v=pv1,t=<unixSeconds>,s=<hex>[,s=<hex>]
 * Multiple s= entries appear during secret rotation (current secret first,
 * previous-secret co-signature during its grace window): a consumer
 * holding EITHER valid secret verifies with the one it has.
 *
 * Replay protection is the CONSUMER's verification recipe (spec §8):
 *   1. reject unless some s= entry HMAC-matches (timingSafeEqual);
 *   2. reject unless |now - t| <= tolerance (default 300 s);
 *   3. dedup on X-PolicyVault-Event-Id (at-least-once delivery means
 *      legitimate redeliveries share the same eventId).
 * An unknown v= version MUST be rejected (fail closed), never ignored.
 */

const crypto = require("crypto");

const SIGNATURE_SCHEME = "pv1";
const SIGNATURE_HEADER = "x-policyvault-signature";
const EVENT_ID_HEADER = "x-policyvault-event-id";
const DELIVERY_ID_HEADER = "x-policyvault-delivery-id";
const DEFAULT_TOLERANCE_SECONDS = 300;

function hmacHex(secret, timestampSeconds, rawBody) {
  return crypto.createHmac("sha256", secret).update(`${timestampSeconds}.${rawBody}`, "utf8").digest("hex");
}

/* SERVER side: build the signature header for one delivery. `secrets` is
 * the currently valid signing secrets (current first; previous during its
 * rotation grace window — server/src/webhooks.js signingSecretsFor). */
function signWebhookPayload({ secrets, timestampSeconds, rawBody }) {
  if (!Array.isArray(secrets) || secrets.length === 0) {
    const e = new Error("no signing secret available — refusing to send an unsigned webhook (fail closed)");
    e.code = "WEBHOOK_SECRET_UNAVAILABLE";
    throw e;
  }
  if (!Number.isSafeInteger(timestampSeconds) || timestampSeconds < 0) {
    const e = new Error("timestampSeconds must be a non-negative integer");
    e.code = "WEBHOOK_SIGNING_INVALID";
    throw e;
  }
  if (typeof rawBody !== "string" || !rawBody) {
    const e = new Error("rawBody must be the exact non-empty payload string");
    e.code = "WEBHOOK_SIGNING_INVALID";
    throw e;
  }
  const parts = [`v=${SIGNATURE_SCHEME}`, `t=${timestampSeconds}`];
  for (const secret of secrets) parts.push(`s=${hmacHex(secret, timestampSeconds, rawBody)}`);
  return parts.join(",");
}

/*
 * CONSUMER side (the reference verification recipe — reproduced verbatim
 * in the spec). Returns { ok:true, timestampSeconds } or
 * { ok:false, reason } with a machine-readable reason:
 *   MALFORMED_HEADER | UNSUPPORTED_SCHEME | SIGNATURE_MISMATCH |
 *   TIMESTAMP_OUT_OF_TOLERANCE
 * Deliberately never throws on hostile input.
 */
function verifyWebhookSignature({ header, rawBody, secret, nowSeconds = Math.floor(Date.now() / 1000), toleranceSeconds = DEFAULT_TOLERANCE_SECONDS }) {
  if (typeof header !== "string" || typeof rawBody !== "string" || typeof secret !== "string" || !secret) {
    return { ok: false, reason: "MALFORMED_HEADER" };
  }
  let version = null;
  let timestamp = null;
  const signatures = [];
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 1) return { ok: false, reason: "MALFORMED_HEADER" };
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === "v") version = v;
    else if (k === "t") timestamp = v;
    else if (k === "s") signatures.push(v);
    // unknown keys are ignored (additive header evolution), unknown
    // VERSIONS are not (checked below).
  }
  if (version !== SIGNATURE_SCHEME) return { ok: false, reason: "UNSUPPORTED_SCHEME" };
  if (typeof timestamp !== "string" || !/^\d{1,12}$/.test(timestamp) || signatures.length === 0) {
    return { ok: false, reason: "MALFORMED_HEADER" };
  }
  const timestampSeconds = Number(timestamp);
  const expected = Buffer.from(hmacHex(secret, timestampSeconds, rawBody), "hex");
  let matched = false;
  for (const s of signatures) {
    if (!/^[0-9a-f]{64}$/.test(s)) continue;
    const candidate = Buffer.from(s, "hex");
    if (candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected)) matched = true;
  }
  if (!matched) return { ok: false, reason: "SIGNATURE_MISMATCH" };
  if (Math.abs(nowSeconds - timestampSeconds) > toleranceSeconds) {
    return { ok: false, reason: "TIMESTAMP_OUT_OF_TOLERANCE" };
  }
  return { ok: true, timestampSeconds };
}

module.exports = {
  SIGNATURE_SCHEME,
  SIGNATURE_HEADER,
  EVENT_ID_HEADER,
  DELIVERY_ID_HEADER,
  DEFAULT_TOLERANCE_SECONDS,
  signWebhookPayload,
  verifyWebhookSignature
};
