"use strict";

/*
 * PolicyVault mobile — PORTABLE LAYER: QR/air-gap signing documents.
 *
 * The v1 mobile signer is the EXISTING offline reference signer
 * `core/signer/adapters/cli` reached across an optical (QR) or file
 * (share-sheet) gap — a new TRANSPORT, not new cryptography and not a new
 * document format (mobile-architecture-decision.md §4.1). This module
 * therefore:
 *
 *   - builds the CLI signer's OWN existing request document
 *     `policyvault-cli-signing-request/1`, whose schema is CLOSED at
 *     exactly ["format","kind","network","expectedSignerAddress",
 *     "unsignedSafeJson","signInputs"] (core/signer/adapters/cli/cli.js
 *     SIGNING_REQUEST_KEYS) — an extra key would be REFUSED by the signer,
 *     so this builder emits those six keys and nothing else;
 *
 *   - validates the CLI signer's OWN existing response document
 *     `policyvault-cli-signer-signed-transaction/1` scanned back in.
 *
 * WHAT THIS MODULE ENFORCES, AND WHY EACH CHECK EXISTS
 *
 *  1. A signing request is BUILT ONLY FROM A PASSING LOCAL VERIFICATION
 *     OUTCOME that is bound to the exact `unsignedSafeJson` being sent.
 *     There is no path from a refused, absent, or differently-bound
 *     outcome to a QR frame. This is the independent SECOND refusal the
 *     architecture requires (§6.3 rule 3): a UI defect alone cannot
 *     produce a signature, because the document that reaches the signer
 *     cannot be constructed without the outcome.
 *
 *  2. `signInputs` are TAKEN FROM THE DURABLE REQUEST AND RE-ASSERTED,
 *     never invented, trimmed, or reconstructed. Every entry must be
 *     exactly `{ index: integer >= 0, sighashType: 1 }`. (Motivating
 *     incident, recorded in core/signer/interface.js: a reconstructed
 *     entry without `sighashType` panicked kaspa-wasm AFTER the human had
 *     already clicked Sign.)
 *
 *  3. A scanned RESPONSE is bound back to the verified transaction:
 *     format, kind, and network must match exactly, the signing address
 *     must be the address the request named, and the signed payload must
 *     carry the SAME transaction id as the payload that was verified.
 *     The id equality is the load-bearing binding — `web/verify-intent.js`
 *     already proves the request's `txId` EQUALS the id embedded in the
 *     bytes it verified, so an id match ties the returned signature to
 *     the exact transaction the human was shown.
 *
 *  4. Every failure is a CODED REFUSAL, never an exception and never a
 *     neutral "couldn't check" state.
 *
 * HONEST LIMITS OF (3), stated rather than papered over: this module does
 * NOT verify the Schnorr signature bytes, does not re-derive the sighash,
 * and does not confirm that the signed payload differs from the unsigned
 * one only in signature scripts. It confirms provenance and transaction
 * identity. The authoritative checks remain where they already are — the
 * server's finalizer re-derives the frozen txid and runs a VM preflight
 * before broadcast, and the covenant is the only security boundary. A
 * future wave can add local signature verification here; v1 does not
 * claim it.
 *
 * PORTABLE-LAYER RULE: no DOM, no platform imports, no ambient globals,
 * no cryptography of its own (sha256 is injected where framing needs it).
 */

(function (globalScope) {
  var SIGNING_REQUEST_FORMAT = "policyvault-cli-signing-request/1";
  var SIGNING_REQUEST_FORMAT_V2 = "policyvault-cli-signing-request/2";
  var SIGNED_TX_FORMAT = "policyvault-cli-signer-signed-transaction/1";
  /* The CLI's schema is CLOSED — these six keys, in this order, and no
   * others. Order is fixed so the emitted document is deterministic.
   * /2 additionally carries the intent `manifest` so the offline signer can
   * INDEPENDENTLY verify what it signs (Hostile-AI review H-2). */
  var SIGNING_REQUEST_KEYS = ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"];
  var SIGNING_REQUEST_KEYS_V2 = ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs", "manifest"];
  var SIGNED_TX_KEYS = ["format", "requestId", "kind", "network", "address", "signedSafeJson"];

  var SIGHASH_ALL = 1;
  /* Same ceiling the Universal Signer Interface enforces
   * (core/signer/interface.js MAX_SAFE_JSON_CHARS). */
  var MAX_SAFE_JSON_CHARS = 1048576;
  var NETWORKS = ["testnet-10", "mainnet"];

  function fail(code, detail) { return { ok: false, code: code, detail: detail }; }
  function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function shortStr(v, n) { return typeof v === "string" ? JSON.stringify(v.slice(0, n)) : typeof v; }

  /* ------------------------------------------------------------------ */
  /* Build: verified request  ->  CLI signing-request document           */
  /* ------------------------------------------------------------------ */

  /**
   * buildSigningRequestDocument({ request, verification, network, expectedSignerAddress })
   *
   * `verification` is the outcome returned by the packaged verifier
   * (mobile/www/js/portable/verification.js -> verify()).
   *
   * ok:   { ok: true, document, documentText, unsignedSafeJson, txId }
   * fail: { ok: false, code, detail }
   */
  function buildSigningRequestDocument(args) {
    if (!isPlainObject(args)) return fail("AIRGAP_INPUT_INVALID", "buildSigningRequestDocument requires an arguments object");

    var request = args.request;
    if (!isPlainObject(request) || !isPlainObject(request.transaction) || typeof request.transaction.unsignedSafeJson !== "string") {
      return fail("AIRGAP_INPUT_INVALID", "the durable request carries no unsigned transaction payload");
    }
    var unsignedSafeJson = request.transaction.unsignedSafeJson;
    if (unsignedSafeJson.length > MAX_SAFE_JSON_CHARS) {
      return fail("AIRGAP_PAYLOAD_TOO_LARGE", "the unsigned payload is " + unsignedSafeJson.length + " characters, above the signer interface limit of " + MAX_SAFE_JSON_CHARS);
    }

    /* (1) The verification gate. A signing document cannot exist without a
     * PASS bound to these exact bytes. */
    var gate = authorizeSigning({ verification: args.verification, unsignedSafeJson: unsignedSafeJson });
    if (!gate.ok) return gate;

    var network = args.network;
    if (NETWORKS.indexOf(network) < 0) {
      return fail("AIRGAP_NETWORK_INVALID", "network " + shortStr(network, 32) + " is not an operational PolicyVault network");
    }

    var expectedSignerAddress = args.expectedSignerAddress;
    if (typeof expectedSignerAddress !== "string" || expectedSignerAddress.length === 0) {
      return fail("AIRGAP_SIGNER_UNKNOWN", "no expected signer address — a signing request must name the signer it is for");
    }

    /* (2) signInputs come from the durable request and are re-asserted. */
    var signInputs = canonicalSignInputs(request.transaction.signInputs);
    if (!signInputs.ok) return signInputs;

    var txId = transactionIdOf(unsignedSafeJson);
    if (!txId.ok) return txId;

    /* Prefer the VERIFYING /2 format when the caller supplies the intent
     * manifest (from the durable request or explicitly): it lets the offline
     * signer independently re-verify and bind the intent before signing.
     * Falls back to the legacy /1 (verification-blind) when no manifest is
     * available, so existing producers keep working. Deterministic key
     * order, exactly the CLI's closed key set for the chosen version. */
    var manifest = isPlainObject(args.manifest) ? args.manifest
      : (isPlainObject(request.manifest) ? request.manifest : null);
    var doc, keys;
    if (manifest !== null) {
      doc = {
        format: SIGNING_REQUEST_FORMAT_V2,
        kind: "sign-transaction",
        network: network,
        expectedSignerAddress: expectedSignerAddress,
        unsignedSafeJson: unsignedSafeJson,
        signInputs: signInputs.value,
        manifest: manifest
      };
      keys = SIGNING_REQUEST_KEYS_V2;
    } else {
      doc = {
        format: SIGNING_REQUEST_FORMAT,
        kind: "sign-transaction",
        network: network,
        expectedSignerAddress: expectedSignerAddress,
        unsignedSafeJson: unsignedSafeJson,
        signInputs: signInputs.value
      };
      keys = SIGNING_REQUEST_KEYS;
    }

    return {
      ok: true,
      document: doc,
      documentText: JSON.stringify(doc, keys, 2) + "\n",
      unsignedSafeJson: unsignedSafeJson,
      txId: txId.value
    };
  }

  /* ------------------------------------------------------------------ */
  /* The independent second refusal                                      */
  /* ------------------------------------------------------------------ */

  /**
   * authorizeSigning({ verification, unsignedSafeJson })
   *
   * The same three refusal codes the browser client uses, checked here
   * INDEPENDENTLY of whatever the UI believes it rendered:
   *   VERIFICATION_REQUIRED             — no outcome at all
   *   VERIFICATION_REFUSED              — an outcome that is not a PASS
   *   VERIFICATION_TX_BINDING_MISMATCH  — a PASS bound to different bytes
   */
  function authorizeSigning(args) {
    var a = isPlainObject(args) ? args : {};
    var v = a.verification;
    var payload = a.unsignedSafeJson;

    if (typeof payload !== "string" || payload.length === 0) {
      return fail("AIRGAP_INPUT_INVALID", "authorizeSigning requires the exact unsigned payload string");
    }
    if (!isPlainObject(v)) {
      return fail("VERIFICATION_REQUIRED", "no on-device verification outcome exists for this transaction — a signature is impossible without one");
    }
    if (v.ok !== true || v.verdict !== "VERIFIED_EXACT") {
      var codes = Array.isArray(v.refusalCodes) && v.refusalCodes.length ? v.refusalCodes.join(", ") : "no code reported";
      return fail("VERIFICATION_REFUSED", "on-device verification refused this transaction (" + codes + ") — refusing to build a signing request");
    }
    if (typeof v.unsignedSafeJson !== "string" || v.unsignedSafeJson !== payload) {
      return fail(
        "VERIFICATION_TX_BINDING_MISMATCH",
        "the verification outcome is bound to different transaction bytes than the ones about to be sent to the signer — refusing"
      );
    }
    return { ok: true };
  }

  /* ------------------------------------------------------------------ */
  /* Validate: scanned CLI response  ->  submittable signedSafeJson      */
  /* ------------------------------------------------------------------ */

  /**
   * parseSignedResponseDocument(text, { expectedNetwork, expectedSignerAddress, verification })
   *
   * ok:   { ok: true, signedSafeJson, txId, address, requestId }
   * fail: { ok: false, code, detail }
   */
  function parseSignedResponseDocument(text, expectations) {
    var exp = isPlainObject(expectations) ? expectations : {};
    if (typeof text !== "string" || text.length === 0) {
      return fail("AIRGAP_RESPONSE_INVALID", "the scanned response is empty");
    }

    var parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      return fail("AIRGAP_RESPONSE_INVALID", "the scanned response is not valid JSON");
    }
    if (!isPlainObject(parsed)) return fail("AIRGAP_RESPONSE_INVALID", "the scanned response is not a JSON object");

    if (parsed.format !== SIGNED_TX_FORMAT) {
      return fail(
        "AIRGAP_RESPONSE_FORMAT_UNSUPPORTED",
        "response format " + shortStr(parsed.format, 64) + " is not " + JSON.stringify(SIGNED_TX_FORMAT) + " — unknown versions fail closed"
      );
    }
    if (parsed.kind !== "sign-transaction") {
      return fail("AIRGAP_RESPONSE_KIND_MISMATCH", "response kind " + shortStr(parsed.kind, 32) + " is not \"sign-transaction\"");
    }
    /* Closed schema in both directions: no missing key, no unknown key. */
    for (var i = 0; i < SIGNED_TX_KEYS.length; i++) {
      if (!(SIGNED_TX_KEYS[i] in parsed)) return fail("AIRGAP_RESPONSE_INVALID", "response is missing required key " + JSON.stringify(SIGNED_TX_KEYS[i]));
    }
    var keys = Object.keys(parsed);
    for (var k = 0; k < keys.length; k++) {
      if (SIGNED_TX_KEYS.indexOf(keys[k]) < 0) {
        return fail("AIRGAP_RESPONSE_INVALID", "response carries unknown key " + JSON.stringify(keys[k]) + " — the schema is closed; failing closed");
      }
    }
    if (typeof parsed.signedSafeJson !== "string" || parsed.signedSafeJson.length === 0) {
      return fail("AIRGAP_RESPONSE_INVALID", "response carries no signedSafeJson");
    }
    if (parsed.signedSafeJson.length > MAX_SAFE_JSON_CHARS) {
      return fail("AIRGAP_PAYLOAD_TOO_LARGE", "the signed payload is " + parsed.signedSafeJson.length + " characters, above the signer interface limit of " + MAX_SAFE_JSON_CHARS);
    }

    if (exp.expectedNetwork !== undefined && parsed.network !== exp.expectedNetwork) {
      return fail(
        "AIRGAP_NETWORK_MISMATCH",
        "the signature was produced for network " + shortStr(parsed.network, 32) + " but this request is for " + JSON.stringify(String(exp.expectedNetwork)) + " — refusing"
      );
    }
    if (exp.expectedSignerAddress !== undefined && parsed.address !== exp.expectedSignerAddress) {
      return fail(
        "AIRGAP_SIGNER_MISMATCH",
        "the signature was produced by a different address than the one this request names — refusing"
      );
    }

    /* (3) Bind the response to the exact transaction that was verified. */
    var signedId = transactionIdOf(parsed.signedSafeJson);
    if (!signedId.ok) return fail("AIRGAP_RESPONSE_INVALID", "the signed payload has no readable transaction id: " + signedId.detail);

    var v = exp.verification;
    if (!isPlainObject(v) || v.ok !== true || typeof v.unsignedSafeJson !== "string") {
      return fail("VERIFICATION_REQUIRED", "no passing on-device verification outcome is available to bind this signature to — refusing");
    }
    var verifiedId = transactionIdOf(v.unsignedSafeJson);
    if (!verifiedId.ok) return fail("AIRGAP_RESPONSE_INVALID", "the verified payload has no readable transaction id: " + verifiedId.detail);
    if (signedId.value !== verifiedId.value) {
      return fail(
        "AIRGAP_TXID_MISMATCH",
        "the scanned signature is for transaction " + signedId.value + " but this device verified transaction " + verifiedId.value + " — refusing"
      );
    }
    /* verify-intent already proved outcome.txId === the id embedded in the
     * verified bytes; re-checking here means a defect in either place is
     * caught rather than cancelling out. */
    if (typeof v.txId === "string" && v.txId !== signedId.value) {
      return fail("AIRGAP_TXID_MISMATCH", "the scanned signature's transaction id does not equal the verified outcome's txId — refusing");
    }

    return {
      ok: true,
      signedSafeJson: parsed.signedSafeJson,
      txId: signedId.value,
      address: parsed.address,
      requestId: parsed.requestId
    };
  }

  /* ------------------------------------------------------------------ */
  /* helpers                                                             */
  /* ------------------------------------------------------------------ */

  function canonicalSignInputs(list) {
    if (!Array.isArray(list) || list.length === 0) {
      return fail("AIRGAP_SIGNINPUTS_INVALID", "the durable request carries no signing metadata — this device never invents it");
    }
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var si = list[i];
      if (!isPlainObject(si) || typeof si.index !== "number" || !isFinite(si.index) || Math.floor(si.index) !== si.index || si.index < 0 || si.sighashType !== SIGHASH_ALL) {
        return fail(
          "AIRGAP_SIGNINPUTS_INVALID",
          "signing entry " + JSON.stringify(si) + " is not the canonical frozen { index, sighashType: " + SIGHASH_ALL + " } — refusing"
        );
      }
      /* Rebuilt with exactly the two canonical keys, in fixed order — an
       * extra key on the wire would be refused by the signer's own closed
       * schema, and silently dropping one is how sighash defects happen. */
      out.push({ index: si.index, sighashType: SIGHASH_ALL });
    }
    return { ok: true, value: out };
  }

  function transactionIdOf(safeJson) {
    var parsed;
    try {
      parsed = JSON.parse(safeJson);
    } catch (e) {
      return fail("AIRGAP_PAYLOAD_INVALID", "payload is not valid JSON");
    }
    if (!isPlainObject(parsed)) return fail("AIRGAP_PAYLOAD_INVALID", "payload is not a JSON object");
    if (typeof parsed.id !== "string" || !/^[0-9a-f]{64}$/.test(parsed.id)) {
      return fail("AIRGAP_PAYLOAD_INVALID", "payload carries no 64-hex transaction id");
    }
    return { ok: true, value: parsed.id };
  }

  var api = {
    SIGNING_REQUEST_FORMAT: SIGNING_REQUEST_FORMAT,
    SIGNING_REQUEST_FORMAT_V2: SIGNING_REQUEST_FORMAT_V2,
    SIGNED_TX_FORMAT: SIGNED_TX_FORMAT,
    SIGNING_REQUEST_KEYS: SIGNING_REQUEST_KEYS,
    SIGNING_REQUEST_KEYS_V2: SIGNING_REQUEST_KEYS_V2,
    SIGNED_TX_KEYS: SIGNED_TX_KEYS,
    MAX_SAFE_JSON_CHARS: MAX_SAFE_JSON_CHARS,
    buildSigningRequestDocument: buildSigningRequestDocument,
    parseSignedResponseDocument: parseSignedResponseDocument,
    authorizeSigning: authorizeSigning
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileAirgap = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
