"use strict";

/*
 * PolicyVault mobile — PORTABLE LAYER: on-device build integrity.
 *
 * Backs the Settings -> Build integrity screen
 * (mobile-architecture-decision.md §6.4). The screen exists so a user, or
 * the owner during acceptance, can compare the verifier digest this app
 * is ACTUALLY RUNNING against the digest published for the release and
 * present in the repository.
 *
 * This is a REAL check, not a display of a constant: the app re-reads the
 * packaged artifact bytes off its own payload and re-hashes them with the
 * sha256 inside the packaged core bundle, then compares against the pin
 * file that mobile/tools/sync-portable.js generated from the repository
 * sources. A tampered payload therefore shows as tampered ON THE DEVICE,
 * not only in CI.
 *
 * WHAT IT PROVES, AND WHAT IT DOES NOT (stated because the difference
 * matters): it proves the packaged files match their pins as read by this
 * running code. It is NOT an attestation and cannot defend against an
 * attacker who replaced the app binary wholesale — a compromised build
 * can lie about anything, including this screen. Its real value is
 * catching accidental drift, a mis-packaged release, and a served payload
 * that is not the reviewed payload; the covenant remains the only
 * security boundary. Play Integrity / App Attest are anti-tamper
 * attestations, are not implemented here, and must never be described as
 * reproducibility.
 *
 * PORTABLE-LAYER RULE (§3.6): `readText` and `sha256Hex` are INJECTED.
 * This module performs no I/O and contains no cryptography.
 */

(function (globalScope) {
  var HEX64 = /^[0-9a-f]{64}$/;
  var PINS_VERSION = "policyvault-mobile-vendor-pins/1";

  function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function fail(code, detail) { return { ok: false, code: code, detail: detail }; }

  /**
   * verifyPackagedArtifacts({ pins, readText, sha256Hex })
   *
   *   pins      — the parsed mobile/vendor-pins.json document.
   *   readText  — (destPath) => Promise<string>, injected by the platform
   *               layer (it fetches the file out of the app payload).
   *   sha256Hex — (string) => 64 lowercase hex, from the packaged core
   *               bundle's own crypto shim.
   *
   * Resolves to
   *   { ok, code?, detail?, artifacts: [ { dest, source, mode,
   *     expectedSha256, actualSha256, sourceSha256, ok, problem } ] }
   *
   * TOTAL: never rejects. Any read failure, hash failure, or mismatch is
   * reported as a failing artifact and makes the overall result `false`.
   * An unreadable artifact is a FAILURE, never an "unknown" that renders
   * as neutral.
   */
  function verifyPackagedArtifacts(args) {
    var a = isPlainObject(args) ? args : {};
    var pins = a.pins;
    var readText = a.readText;
    var sha256Hex = a.sha256Hex;

    if (typeof readText !== "function" || typeof sha256Hex !== "function") {
      return Promise.resolve(Object.assign(fail("INTEGRITY_DEPENDENCY_MISSING", "build-integrity requires injected readText and sha256Hex"), { artifacts: [] }));
    }
    if (!isPlainObject(pins) || pins.pinsVersion !== PINS_VERSION || !Array.isArray(pins.artifacts)) {
      return Promise.resolve(Object.assign(
        fail("INTEGRITY_PINS_UNSUPPORTED", "the pin document is missing or is not " + JSON.stringify(PINS_VERSION) + " — unknown versions fail closed"),
        { artifacts: [] }
      ));
    }
    if (pins.artifacts.length === 0) {
      return Promise.resolve(Object.assign(fail("INTEGRITY_PINS_EMPTY", "the pin document lists no artifacts"), { artifacts: [] }));
    }

    var checks = pins.artifacts.map(function (entry) {
      var dest = isPlainObject(entry) ? entry.dest : null;
      var expected = isPlainObject(entry) ? entry.emittedSha256 : null;
      var base = {
        dest: dest,
        source: isPlainObject(entry) ? entry.source : null,
        mode: isPlainObject(entry) ? entry.mode : null,
        sourceSha256: isPlainObject(entry) ? entry.sourceSha256 : null,
        expectedSha256: expected,
        actualSha256: null,
        ok: false,
        problem: null
      };

      if (typeof dest !== "string" || !dest) {
        base.problem = "the pin entry names no packaged file";
        return Promise.resolve(base);
      }
      if (typeof expected !== "string" || !HEX64.test(expected)) {
        base.problem = "the pin entry carries no valid sha256 for " + dest;
        return Promise.resolve(base);
      }

      return Promise.resolve()
        .then(function () { return readText(dest); })
        .then(function (text) {
          if (typeof text !== "string") throw new Error("the packaged file did not read back as text");
          var actual = sha256Hex(text);
          base.actualSha256 = actual;
          base.ok = actual === expected;
          if (!base.ok) base.problem = "the packaged bytes hash to " + actual + " but the release pins " + expected;
          return base;
        })
        .catch(function (e) {
          base.problem = "could not read or hash " + dest + ": " + ((e && e.message) || String(e));
          return base;
        });
    });

    return Promise.all(checks).then(function (artifacts) {
      var bad = artifacts.filter(function (x) { return !x.ok; });
      if (bad.length === 0) return { ok: true, artifacts: artifacts };
      return {
        ok: false,
        code: "INTEGRITY_MISMATCH",
        detail: bad.length + " of " + artifacts.length + " packaged artifacts do not match the release pins — this build is NOT the reviewed build",
        artifacts: artifacts
      };
    });
  }

  /**
   * summarize(pins) — the constant facts the screen shows even when the
   * live re-hash has not finished (or failed): which repository source
   * each artifact came from and its source digest, so the digest can be
   * compared against the repository by hand.
   */
  function summarize(pins) {
    if (!isPlainObject(pins) || !Array.isArray(pins.artifacts)) return [];
    return pins.artifacts.map(function (e) {
      return {
        dest: isPlainObject(e) ? e.dest : null,
        source: isPlainObject(e) ? e.source : null,
        mode: isPlainObject(e) ? e.mode : null,
        sourceSha256: isPlainObject(e) ? e.sourceSha256 : null,
        emittedSha256: isPlainObject(e) ? e.emittedSha256 : null,
        why: isPlainObject(e) ? e.why : null
      };
    });
  }

  var api = {
    PINS_VERSION: PINS_VERSION,
    verifyPackagedArtifacts: verifyPackagedArtifacts,
    summarize: summarize
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileBuildIntegrity = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
