"use strict";

/*
 * Hardened JSON intake for the x402 / AP2 interoperability adapters
 * (docs/postlaunch/x402-adapter-spec.md §3.3 "Everything else";
 * ap2-adapter-spec.md §3.3 "Envelope hygiene"; adversarial cases X-16 /
 * A-24). Every byte parsed here is UNTRUSTED protocol input.
 *
 * Why not JSON.parse: the specs REQUIRE refusals JSON.parse cannot give —
 * duplicate object keys (JSON.parse silently keeps the last), prototype-
 * pollution key names (`__proto__` / `constructor` / `prototype` at any
 * depth), a nesting-depth cap enforced DURING parsing (not after a
 * possibly huge tree already exists), lexical number discipline (the
 * difference between `2` and `2.0` is a required refusal, X-18), and
 * byte-verbatim capture of selected subtrees (the §4.6 `accepted`
 * byte-verbatim echo). This parser is a strict RFC 8259 subset reader:
 * anything it is unsure about REFUSES — it never "repairs" input.
 *
 * Outputs:
 *   parseStrictJson(text, opts) -> {
 *     value,                       plain-object tree (arrays/objects/strings/
 *                                  booleans/null/plain-integer numbers)
 *     numberTokens: Map path->raw  the EXACT lexical token of every number
 *     rawSlices:    Map path->raw  exact substrings for opts.rawPaths matches
 *   }
 * Throws GuardError { code, message } — machine-readable, deterministic.
 *
 * Number policy: only numbers whose token is a plain integer within the
 * IEEE-754 safe range become JS numbers. Any other numeric token
 * (fractions, exponents, -0, leading zeros, beyond 2^53-1) is preserved
 * ONLY when opts.tolerateNonIntegerNumbers is true (audit-only subtrees;
 * value becomes the raw token STRING, marked in numberTokens) and refused
 * otherwise. Decision-path fields always re-check the lexical token via
 * numberTokens, so `2.0`, `1e3`, `007` can never impersonate an integer.
 */

class GuardError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "GuardError";
    this.code = code;
  }
}

function guardFail(code, message) {
  throw new GuardError(code, message);
}

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
/* Canonical integer tokens only: "0", "7", "-12" — never "-0" (negative
 * zero is not a canonical encoding), never fractions/exponents/leading
 * zeros. */
const PLAIN_INT_RE = /^(0|-?[1-9][0-9]*)$/;

const DEFAULTS = Object.freeze({
  maxBytes: 65536, // callers pass their spec cap; this is a hard backstop
  maxDepth: 8, // both specs recommend 8
  maxStringBytes: 65536,
  rawPaths: null, // (pathString) => boolean
  tolerateNonIntegerNumbers: false
});

function parseStrictJson(text, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  if (typeof text !== "string") guardFail("JSON_NOT_TEXT", "input must be a string");
  // Byte cap FIRST, on the exact input, before any scanning (X-16: an
  // oversized payload is rejected without ever being parsed).
  if (Buffer.byteLength(text, "utf8") > opts.maxBytes) {
    guardFail("JSON_TOO_LARGE", `input exceeds ${opts.maxBytes} bytes — refusing before parse`);
  }
  if (text.includes("\u0000")) guardFail("JSON_NUL_BYTE", "NUL byte in input — refusing");
  // A lone surrogate means the bytes were never valid Unicode text.
  if (typeof text.isWellFormed === "function" && !text.isWellFormed()) {
    guardFail("JSON_INVALID_UTF8", "malformed Unicode in input — refusing");
  }

  const numberTokens = new Map();
  const rawSlices = new Map();
  let i = 0;

  const ws = () => {
    while (i < text.length) {
      const c = text[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i += 1;
      else break;
    }
  };
  const expect = (ch) => {
    if (text[i] !== ch) guardFail("JSON_SYNTAX", `expected '${ch}' at offset ${i}`);
    i += 1;
  };

  function parseString(path) {
    expect('"');
    let out = "";
    while (true) {
      if (i >= text.length) guardFail("JSON_SYNTAX", "unterminated string");
      const c = text[i];
      if (c === '"') {
        i += 1;
        if (Buffer.byteLength(out, "utf8") > opts.maxStringBytes) {
          guardFail("JSON_STRING_TOO_LARGE", `string at ${path} exceeds ${opts.maxStringBytes} bytes`);
        }
        return out;
      }
      if (c === "\\") {
        const e = text[i + 1];
        i += 2;
        if (e === '"') out += '"';
        else if (e === "\\") out += "\\";
        else if (e === "/") out += "/";
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) guardFail("JSON_SYNTAX", `bad \\u escape at offset ${i}`);
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else guardFail("JSON_SYNTAX", `bad escape at offset ${i}`);
      } else {
        const code = c.charCodeAt(0);
        if (code < 0x20) guardFail("JSON_SYNTAX", `raw control character in string at offset ${i}`);
        out += c;
        i += 1;
      }
    }
  }

  function parseNumber(path) {
    const start = i;
    if (text[i] === "-") i += 1;
    if (!/[0-9]/.test(text[i] ?? "")) guardFail("JSON_SYNTAX", `bad number at offset ${start}`);
    while (/[0-9]/.test(text[i] ?? "")) i += 1;
    if (text[i] === ".") {
      i += 1;
      if (!/[0-9]/.test(text[i] ?? "")) guardFail("JSON_SYNTAX", `bad number at offset ${start}`);
      while (/[0-9]/.test(text[i] ?? "")) i += 1;
    }
    if (text[i] === "e" || text[i] === "E") {
      i += 1;
      if (text[i] === "+" || text[i] === "-") i += 1;
      if (!/[0-9]/.test(text[i] ?? "")) guardFail("JSON_SYNTAX", `bad number at offset ${start}`);
      while (/[0-9]/.test(text[i] ?? "")) i += 1;
    }
    const token = text.slice(start, i);
    numberTokens.set(path, token);
    if (PLAIN_INT_RE.test(token)) {
      const n = Number(token);
      if (Number.isSafeInteger(n)) return n;
    }
    if (opts.tolerateNonIntegerNumbers) return token; // audit-only carriage as the raw token string
    guardFail("JSON_NUMBER_UNSUPPORTED", `number token ${JSON.stringify(token)} at ${path} is not a plain safe integer — refusing (no float ever constructed)`);
  }

  function parseValue(path, depth) {
    if (depth > opts.maxDepth) guardFail("JSON_TOO_DEEP", `nesting exceeds ${opts.maxDepth} at ${path}`);
    ws();
    const start = i;
    const c = text[i];
    let value;
    if (c === "{") {
      i += 1;
      value = {};
      const seen = new Set();
      ws();
      if (text[i] === "}") i += 1;
      else {
        while (true) {
          ws();
          const key = parseString(`${path}.<key>`);
          if (FORBIDDEN_KEYS.has(key)) guardFail("JSON_FORBIDDEN_KEY", `forbidden key ${JSON.stringify(key)} at ${path} — prototype-pollution refusal`);
          if (seen.has(key)) guardFail("JSON_DUPLICATE_KEY", `duplicate key ${JSON.stringify(key)} at ${path}`);
          seen.add(key);
          ws();
          expect(":");
          value[key] = parseValue(`${path}.${key}`, depth + 1);
          ws();
          if (text[i] === ",") {
            i += 1;
            continue;
          }
          expect("}");
          break;
        }
      }
    } else if (c === "[") {
      i += 1;
      value = [];
      ws();
      if (text[i] === "]") i += 1;
      else {
        let idx = 0;
        while (true) {
          value.push(parseValue(`${path}[${idx}]`, depth + 1));
          idx += 1;
          ws();
          if (text[i] === ",") {
            i += 1;
            continue;
          }
          expect("]");
          break;
        }
      }
    } else if (c === '"') {
      value = parseString(path);
    } else if (c === "t") {
      if (text.slice(i, i + 4) !== "true") guardFail("JSON_SYNTAX", `bad literal at offset ${i}`);
      i += 4;
      value = true;
    } else if (c === "f") {
      if (text.slice(i, i + 5) !== "false") guardFail("JSON_SYNTAX", `bad literal at offset ${i}`);
      i += 5;
      value = false;
    } else if (c === "n") {
      if (text.slice(i, i + 4) !== "null") guardFail("JSON_SYNTAX", `bad literal at offset ${i}`);
      i += 4;
      value = null;
    } else if (c === "-" || /[0-9]/.test(c ?? "")) {
      value = parseNumber(path);
    } else {
      guardFail("JSON_SYNTAX", `unexpected token at offset ${i}`);
    }
    if (opts.rawPaths && opts.rawPaths(path)) {
      rawSlices.set(path, text.slice(start, i));
    }
    return value;
  }

  const value = parseValue("$", 1);
  ws();
  if (i !== text.length) guardFail("JSON_SYNTAX", `trailing content at offset ${i}`);
  return { value, numberTokens, rawSlices };
}

/*
 * Strict base64 (RFC 4648 §4, x402 headers) and base64url (RFC 4648 §5
 * unpadded, JWS/SD-JWT) decoding. Node's Buffer.from(_, "base64") accepts
 * garbage silently (it skips invalid characters), which is exactly the
 * parser-differential the A-24/X-16 cases target — so the charset and
 * shape are enforced BEFORE Buffer.from ever runs, and the decode is
 * round-tripped to prove no character was silently dropped.
 */
function decodeBase64Strict(input, { maxEncodedBytes }) {
  if (typeof input !== "string" || input.length === 0) guardFail("BASE64_INVALID", "base64 input must be a non-empty string");
  if (maxEncodedBytes !== undefined && input.length > maxEncodedBytes) {
    guardFail("BASE64_TOO_LARGE", `encoded input exceeds ${maxEncodedBytes} bytes — refusing before decode`);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(input) || input.length % 4 !== 0) {
    guardFail("BASE64_INVALID", "input is not canonical base64");
  }
  const buf = Buffer.from(input, "base64");
  if (buf.toString("base64") !== input) guardFail("BASE64_INVALID", "non-canonical base64 encoding — refusing");
  return buf;
}

function decodeBase64UrlStrict(input, { maxEncodedBytes } = {}) {
  if (typeof input !== "string" || input.length === 0) guardFail("BASE64URL_INVALID", "base64url input must be a non-empty string");
  if (maxEncodedBytes !== undefined && input.length > maxEncodedBytes) {
    guardFail("BASE64URL_TOO_LARGE", `encoded input exceeds ${maxEncodedBytes} bytes — refusing before decode`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(input)) guardFail("BASE64URL_INVALID", "input is not unpadded base64url");
  if (input.length % 4 === 1) guardFail("BASE64URL_INVALID", "impossible base64url length");
  const buf = Buffer.from(input, "base64url");
  if (buf.toString("base64url") !== input) guardFail("BASE64URL_INVALID", "non-canonical base64url encoding — refusing");
  return buf;
}

function utf8TextOf(buf, code) {
  const text = buf.toString("utf8");
  if (Buffer.byteLength(text, "utf8") !== buf.length || text.includes("�")) {
    // A replacement character after decode means invalid UTF-8 bytes
    // (unless the original genuinely contained U+FFFD, which no sane
    // protocol document does — refuse either way, deterministically).
    guardFail(code ?? "JSON_INVALID_UTF8", "decoded bytes are not valid UTF-8 — refusing");
  }
  return text;
}

module.exports = { GuardError, parseStrictJson, decodeBase64Strict, decodeBase64UrlStrict, utf8TextOf, PLAIN_INT_RE };
