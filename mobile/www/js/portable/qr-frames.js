"use strict";

/*
 * PolicyVault mobile — PORTABLE LAYER: QR frame codec.
 *
 * Chunks an arbitrary UTF-8 document into a deterministic, integrity-
 * checked sequence of ASCII frames for animated multi-frame QR display,
 * and reassembles frames scanned back in an ARBITRARY ORDER with
 * duplicates tolerated (a camera re-reads the same frame constantly).
 *
 * SCOPE. This file is TRANSPORT FRAMING ONLY. It knows nothing about
 * signing, keys, covenants, policy, or PolicyVault documents — it moves a
 * string across an optical gap and proves the string that came out is the
 * string that went in. The signing documents it carries are the CLI
 * signer's own existing formats; see ./airgap.js.
 *
 * PORTABLE-LAYER RULE (mobile-architecture-decision.md §3.6): no DOM, no
 * platform imports, no ambient globals. Even TextEncoder/TextDecoder are
 * avoided in favour of explicit UTF-8 code (the same choice the reviewed
 * core bundle's crypto shim documents), so behaviour cannot vary with the
 * host's Encoding-API implementation. sha256 is INJECTED — this file
 * contains no cryptography and never introduces a second hash
 * implementation.
 *
 * FRAME GRAMMAR (fixed, versioned, unknown versions fail closed):
 *
 *     PVQR1|<docSha256:64 hex>|<seq:1-based>|<count>|<base64url chunk>
 *
 * `|` is outside the base64url alphabet, so the split is unambiguous. The
 * document is UTF-8 encoded and base64url-encoded BEFORE chunking, which
 * (a) keeps every frame pure ASCII — safe for any QR encoder — and
 * (b) makes it impossible for a chunk boundary to fall inside a UTF-16
 * surrogate pair or a multi-byte UTF-8 sequence.
 *
 * FAIL CLOSED, TOTALLY. Every exported function is TOTAL: it returns an
 * `{ ok: false, code, detail }` result rather than throwing. Reassembly
 * REFUSES unless every frame agreed on the same document digest and frame
 * count, every sequence number 1..count arrived exactly once, and the
 * sha256 of the reassembled text EQUALS the digest the frames claimed.
 * A partially-scanned document is not a document.
 */

(function (globalScope) {
  var FRAME_VERSION = "PVQR1";
  var SEP = "|";
  var HEX64 = /^[0-9a-f]{64}$/;
  var DIGITS = /^[1-9][0-9]{0,6}$/;
  var B64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var B64URL_RE = /^[A-Za-z0-9_-]*$/;

  /* Conservative default: QR version 20-ish at error-correction level M in
   * byte mode holds well over 800 ASCII characters, and smaller frames scan
   * far more reliably on a phone camera at arm's length. Callers may lower
   * it; the framing is correct at any positive size. */
  var DEFAULT_CHUNK_CHARS = 700;

  /* Refuse to build an unscannable number of frames rather than silently
   * producing a flow no human can complete. The file/share-sheet transport
   * is the designed fallback (mobile-architecture-decision.md §4.1). */
  var MAX_FRAMES = 512;

  /* ---------------- UTF-8 (explicit, no ambient Encoding API) --------- */

  function utf8Encode(text) {
    var out = [];
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
        var lo = text.charCodeAt(i + 1);
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
          i++;
        }
      }
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
  }

  /* Returns null on malformed UTF-8 (over-long forms, truncated sequences,
   * lone surrogates, out-of-range code points) — the caller turns null into
   * a coded refusal. Nothing is repaired or substituted. */
  function utf8Decode(bytes) {
    var out = "";
    var i = 0;
    while (i < bytes.length) {
      var b0 = bytes[i++];
      var cp;
      var need;
      if (b0 < 0x80) { out += String.fromCharCode(b0); continue; }
      else if (b0 >= 0xc2 && b0 <= 0xdf) { cp = b0 & 0x1f; need = 1; }
      else if (b0 >= 0xe0 && b0 <= 0xef) { cp = b0 & 0x0f; need = 2; }
      else if (b0 >= 0xf0 && b0 <= 0xf4) { cp = b0 & 0x07; need = 3; }
      else return null;
      if (i + need > bytes.length) return null;
      for (var n = 0; n < need; n++) {
        var b = bytes[i++];
        if ((b & 0xc0) !== 0x80) return null;
        cp = (cp << 6) | (b & 0x3f);
      }
      if (need === 2 && cp < 0x800) return null;
      if (need === 3 && cp < 0x10000) return null;
      if (cp > 0x10ffff) return null;
      if (cp >= 0xd800 && cp <= 0xdfff) return null;
      if (cp < 0x10000) out += String.fromCharCode(cp);
      else {
        cp -= 0x10000;
        out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
      }
    }
    return out;
  }

  /* ---------------- base64url, unpadded ------------------------------- */

  function b64urlEncode(bytes) {
    var out = "";
    var i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64URL_CHARS[(n >> 18) & 63] + B64URL_CHARS[(n >> 12) & 63] + B64URL_CHARS[(n >> 6) & 63] + B64URL_CHARS[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) {
      var a = bytes[i] << 16;
      out += B64URL_CHARS[(a >> 18) & 63] + B64URL_CHARS[(a >> 12) & 63];
    } else if (rem === 2) {
      var b = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += B64URL_CHARS[(b >> 18) & 63] + B64URL_CHARS[(b >> 12) & 63] + B64URL_CHARS[(b >> 6) & 63];
    }
    return out;
  }

  /* Returns null on any character outside the alphabet or on a length
   * (mod 4 === 1) that no unpadded base64 string can have. */
  function b64urlDecode(text) {
    if (!B64URL_RE.test(text)) return null;
    if (text.length % 4 === 1) return null;
    var bytes = [];
    var acc = 0;
    var bits = 0;
    for (var i = 0; i < text.length; i++) {
      var v = B64URL_CHARS.indexOf(text.charAt(i));
      if (v < 0) return null;
      acc = (acc << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((acc >> bits) & 0xff);
      }
    }
    /* Leftover bits of a well-formed unpadded base64 string are always
     * zero; anything else is a malformed encoding, not a byte. */
    if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null;
    return bytes;
  }

  /* ---------------- deps ---------------------------------------------- */

  function needSha256(deps) {
    return deps && typeof deps.sha256Hex === "function" ? deps.sha256Hex : null;
  }

  /* ---------------- encode -------------------------------------------- */

  /**
   * encodeFrames(text, { sha256Hex, chunkChars }) -> total result
   *   ok:   { ok: true, docSha256, count, frames: [string], chunkChars }
   *   fail: { ok: false, code, detail }
   */
  function encodeFrames(text, options) {
    var opts = options || {};
    var sha256Hex = needSha256(opts);
    if (!sha256Hex) return fail("QR_DEPENDENCY_MISSING", "encodeFrames requires an injected sha256Hex function — this module contains no cryptography");
    if (typeof text !== "string") return fail("QR_INPUT_INVALID", "encodeFrames takes the document as a string");
    if (text.length === 0) return fail("QR_INPUT_INVALID", "refusing to frame an empty document");

    var chunkChars = opts.chunkChars === undefined ? DEFAULT_CHUNK_CHARS : opts.chunkChars;
    if (!isPositiveInt(chunkChars)) return fail("QR_INPUT_INVALID", "chunkChars must be a positive integer");

    var digest;
    try {
      digest = sha256Hex(text);
    } catch (e) {
      return fail("QR_DIGEST_FAILED", "the injected sha256Hex threw: " + msg(e));
    }
    if (typeof digest !== "string" || !HEX64.test(digest)) {
      return fail("QR_DIGEST_FAILED", "the injected sha256Hex did not return 64 lowercase hex characters");
    }

    var body = b64urlEncode(utf8Encode(text));
    var count = Math.ceil(body.length / chunkChars);
    if (count > MAX_FRAMES) {
      return fail(
        "QR_TOO_LARGE",
        "this document needs " + count + " QR frames at " + chunkChars + " characters each, above the " + MAX_FRAMES +
          "-frame limit — use the file transport instead (it carries the identical document)"
      );
    }

    var frames = [];
    for (var i = 0; i < count; i++) {
      frames.push(
        FRAME_VERSION + SEP + digest + SEP + String(i + 1) + SEP + String(count) + SEP + body.slice(i * chunkChars, (i + 1) * chunkChars)
      );
    }
    return { ok: true, docSha256: digest, count: count, frames: frames, chunkChars: chunkChars };
  }

  /* ---------------- parse one frame ----------------------------------- */

  /**
   * parseFrame(frameText) -> total result
   *   ok:   { ok: true, docSha256, seq, count, chunk }
   *   fail: { ok: false, code, detail }
   */
  function parseFrame(frameText) {
    if (typeof frameText !== "string") return fail("QR_FRAME_INVALID", "a scanned frame must be text");
    var parts = frameText.split(SEP);
    if (parts.length !== 5) return fail("QR_FRAME_INVALID", "a PolicyVault QR frame has exactly 5 " + JSON.stringify(SEP) + "-separated fields; this one has " + parts.length);
    if (parts[0] !== FRAME_VERSION) {
      return fail("QR_FRAME_VERSION_UNSUPPORTED", "frame version " + JSON.stringify(parts[0].slice(0, 16)) + " is not " + JSON.stringify(FRAME_VERSION) + " — unknown versions fail closed");
    }
    if (!HEX64.test(parts[1])) return fail("QR_FRAME_INVALID", "the frame's document digest is not 64 lowercase hex characters");
    if (!DIGITS.test(parts[2]) || !DIGITS.test(parts[3])) return fail("QR_FRAME_INVALID", "frame sequence and count must be positive decimal integers");
    var seq = Number(parts[2]);
    var count = Number(parts[3]);
    if (seq > count) return fail("QR_FRAME_INVALID", "frame " + seq + " claims to be part of a " + count + "-frame document");
    if (count > MAX_FRAMES) return fail("QR_FRAME_INVALID", "frame claims a " + count + "-frame document, above the " + MAX_FRAMES + "-frame limit");
    if (!B64URL_RE.test(parts[4])) return fail("QR_FRAME_INVALID", "the frame payload is not base64url");
    return { ok: true, docSha256: parts[1], seq: seq, count: count, chunk: parts[4] };
  }

  /* ---------------- reassemble ---------------------------------------- */

  /**
   * createReassembler({ sha256Hex }) -> {
   *   accept(frameText) -> { ok, code?, detail?, accepted, duplicate, received, count, docSha256, complete }
   *   status()          -> { started, received, count, docSha256, missing: [seq], complete }
   *   finish()          -> { ok: true, text, docSha256 } | { ok: false, code, detail }
   *   reset()
   * }
   *
   * The reassembler locks onto the FIRST document digest it sees. A frame
   * from a different document is REFUSED (QR_FRAME_DOCUMENT_MISMATCH)
   * rather than silently starting a new scan — mixing two documents in one
   * capture session is exactly the confusion an attacker would want.
   */
  function createReassembler(deps) {
    var sha256Hex = needSha256(deps);
    var docSha256 = null;
    var count = 0;
    var chunks = null;
    var received = 0;

    function reset() {
      docSha256 = null;
      count = 0;
      chunks = null;
      received = 0;
    }

    function missing() {
      var out = [];
      if (!chunks) return out;
      for (var i = 0; i < count; i++) if (chunks[i] === null) out.push(i + 1);
      return out;
    }

    function status() {
      return {
        started: docSha256 !== null,
        received: received,
        count: count,
        docSha256: docSha256,
        missing: missing(),
        complete: docSha256 !== null && received === count
      };
    }

    function accept(frameText) {
      if (!sha256Hex) return fail("QR_DEPENDENCY_MISSING", "createReassembler requires an injected sha256Hex function");
      var parsed = parseFrame(frameText);
      if (!parsed.ok) return parsed;

      if (docSha256 === null) {
        docSha256 = parsed.docSha256;
        count = parsed.count;
        chunks = [];
        for (var i = 0; i < count; i++) chunks.push(null);
      } else if (parsed.docSha256 !== docSha256 || parsed.count !== count) {
        return fail(
          "QR_FRAME_DOCUMENT_MISMATCH",
          "this frame belongs to a different document (" + parsed.docSha256.slice(0, 12) + "…, " + parsed.count + " frames) than the scan already in progress (" +
            docSha256.slice(0, 12) + "…, " + count + " frames) — start a new scan"
        );
      }

      var idx = parsed.seq - 1;
      if (chunks[idx] !== null) {
        if (chunks[idx] !== parsed.chunk) {
          return fail("QR_FRAME_CONFLICT", "frame " + parsed.seq + " was scanned twice with different contents — refusing");
        }
        return { ok: true, accepted: false, duplicate: true, received: received, count: count, docSha256: docSha256, complete: received === count };
      }
      chunks[idx] = parsed.chunk;
      received++;
      return { ok: true, accepted: true, duplicate: false, received: received, count: count, docSha256: docSha256, complete: received === count };
    }

    function finish() {
      if (!sha256Hex) return fail("QR_DEPENDENCY_MISSING", "createReassembler requires an injected sha256Hex function");
      if (docSha256 === null) return fail("QR_INCOMPLETE", "no frames have been scanned yet");
      if (received !== count) {
        var m = missing();
        return fail("QR_INCOMPLETE", "still missing frame(s) " + m.slice(0, 12).join(", ") + (m.length > 12 ? ", …" : "") + " of " + count);
      }
      var bytes = b64urlDecode(chunks.join(""));
      if (bytes === null) return fail("QR_DECODE_FAILED", "the reassembled frames are not valid base64url");
      var text = utf8Decode(bytes);
      if (text === null) return fail("QR_DECODE_FAILED", "the reassembled bytes are not valid UTF-8");
      var actual;
      try {
        actual = sha256Hex(text);
      } catch (e) {
        return fail("QR_DIGEST_FAILED", "the injected sha256Hex threw: " + msg(e));
      }
      if (actual !== docSha256) {
        return fail("QR_DIGEST_MISMATCH", "the reassembled document hashes to " + actual + " but the frames claimed " + docSha256 + " — the scan is corrupt or was tampered with");
      }
      return { ok: true, text: text, docSha256: docSha256 };
    }

    return { accept: accept, status: status, finish: finish, reset: reset };
  }

  /* ---------------- small helpers ------------------------------------- */

  function fail(code, detail) { return { ok: false, code: code, detail: detail }; }
  function msg(e) { return (e && e.message) || String(e); }
  function isPositiveInt(n) { return typeof n === "number" && isFinite(n) && Math.floor(n) === n && n > 0; }

  var api = {
    FRAME_VERSION: FRAME_VERSION,
    DEFAULT_CHUNK_CHARS: DEFAULT_CHUNK_CHARS,
    MAX_FRAMES: MAX_FRAMES,
    encodeFrames: encodeFrames,
    parseFrame: parseFrame,
    createReassembler: createReassembler,
    /* exported for the test suite's round-trip vectors only */
    _utf8Encode: utf8Encode,
    _utf8Decode: utf8Decode,
    _b64urlEncode: b64urlEncode,
    _b64urlDecode: b64urlDecode
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileQrFrames = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
