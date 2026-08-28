"use strict";

/*
 * PolicyVault Universal Signer Interface v1 — OFFLINE CLI keyfile signer
 * adapter (kind "cli").
 *
 * This is the first materially different reference signer behind the
 * interface: unlike KasWare (browser extension, injected provider,
 * human prompt per signature) it is a headless, offline, operator-run
 * local-keyfile signer. It proves the interface supports a signer class
 * genuinely unlike a browser wallet while passing the SAME conformance
 * gates.
 *
 * CUSTODY MODEL (the non-custodial invariant, applied): signers custody
 * keys — that is their role. The keyfile this adapter reads is the
 * SIGNER OPERATOR'S key, held on the operator's machine, mode 600.
 * PolicyVault-the-service never sees it: the adapter's outward surface
 * is exactly the v1 interface (claims in, signatures out) and secret
 * material never appears in any return value, error message, or log.
 * This module NEVER accepts a seed phrase — raw 32-byte private key hex
 * inside the versioned keyfile only, created by generateKeyfile().
 *
 * REAL CRYPTOGRAPHY, BORROWED — NEVER HOMEMADE: signing uses the repo's
 * vendored rusty-kaspa WASM module (the same authoritative module the
 * SDK/server load via loadConfig().rustyKaspaModule — sdk/src/chain.js
 * loadKaspa). BIP-340 Schnorr over Kaspa's PersonalMessageSigningHash /
 * TransactionSigningHash domains, so signatures verify against the
 * EXISTING server-side verification path (server/src/auth.js
 * kaspa.verifyMessage) and the existing transaction pipeline. The load
 * is isolated behind a lazy injection point (options.kaspaModule /
 * options.kaspaModulePath / PV_CLI_SIGNER_KASPA_MODULE / the same
 * default path as sdk/src/config.js), deliberately WITHOUT importing
 * sdk/ or server/ modules — sdk/src/chain.js installs a global
 * WebSocket transport at require time and this adapter must stay
 * OFFLINE (no network transport is ever loaded here).
 *
 * NETWORK MODEL (dual-unlock, mirroring the product's mainnet posture):
 * the adapter operates on exactly ONE configured network per instance
 * (default "testnet-10"). "mainnet" is REFUSED unless BOTH a
 * { allowMainnet: true } construction/generation option AND the
 * environment variable PV_CLI_SIGNER_ALLOW_MAINNET=1 are present —
 * the same dual-flag spirit as POLICYVAULT_ALLOW_MAINNET + explicit
 * mainnet KASPA_RPC_URL. Wrong-network requests fail closed with the
 * interface's WRONG_NETWORK error.
 *
 * APPROVAL MODEL: synchronous. The operator's act of running the signer
 * with their keyfile IS the approval; there is no out-of-band consent
 * channel (asynchronousApproval: false), no account switching, no
 * events. Capabilities: schnorr only; messageSigning +
 * transactionSigning with specificInputSigning; no networkSwitching.
 *
 * Pure Node CommonJS. No external packages. No imports from server/ or
 * sdk/ (only core/signer/errors + core/signer/interface, node built-ins,
 * and the injected/lazily-required kaspa-wasm module). NO network I/O
 * anywhere in this file.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { SIGNER_INTERFACE_VERSION, SignerErrorCodes, signerError } = require("../../errors");
const { SIGNER_NETWORKS, SIGHASH_ALL } = require("../../interface");

/* Versioned keyfile format. Exact-equality match only: any other value —
 * older, newer, absent, malformed — fails closed (same rule as the
 * interface version). */
const KEYFILE_FORMAT = "policyvault-cli-signer-keyfile/1";

/* Dual-unlock environment variable for mainnet operation. */
const MAINNET_UNLOCK_ENV = "PV_CLI_SIGNER_ALLOW_MAINNET";

/* Module-path environment override (CLI convenience; construction options
 * take precedence). Default mirrors sdk/src/config.js rustyKaspaModule. */
const KASPA_MODULE_ENV = "PV_CLI_SIGNER_KASPA_MODULE";

const DEFAULT_PROVIDER_ID = "cli-keyfile";
const DEFAULT_LABEL = "PolicyVault CLI keyfile signer";
const PRIVATE_KEY_HEX_RE = /^[0-9a-f]{64}$/;
const COMPRESSED_PUBKEY_HEX_RE = /^0[23][0-9a-f]{64}$/;
const MAX_KEYFILE_BYTES = 65536;
const MAX_LABEL_CHARS = 64;

/* Keyfile schema: exactly these keys ("label" optional). Unknown keys are
 * refused — a keyfile is trusted key custody, never a grab bag. */
const KEYFILE_REQUIRED_KEYS = Object.freeze(["format", "network", "privateKeyHex", "publicKeyHex", "address", "createdAt"]);
const KEYFILE_OPTIONAL_KEYS = Object.freeze(["label"]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function invalid(message) {
  return signerError(SignerErrorCodes.REQUEST_INVALID, message);
}

/* Keyfile-store faults (unreadable / malformed / tampered) are classified
 * as PROVIDER_ERROR: the keyfile is this adapter's "provider". Messages
 * carry SHAPE-ONLY diagnostics — never key material, never file content. */
function keyfileFault(message) {
  return signerError(SignerErrorCodes.PROVIDER_ERROR, `keyfile: ${message}`);
}

/* ------------------------------------------------------------------ */
/* kaspa-wasm loading (lazy, injectable, offline)                      */
/* ------------------------------------------------------------------ */

/* The exact default location loadConfig() uses for rustyKaspaModule
 * (sdk/src/config.js): path.join(HOME, "rusty-kaspa/wasm/nodejs/kaspa").
 * Restated here instead of importing sdk/src/config.js, which reads
 * process-wide environment configuration and whose chain loader installs
 * a global WebSocket transport — side effects an OFFLINE signer must not
 * inherit. */
function defaultKaspaModulePath() {
  return path.join(os.homedir(), "rusty-kaspa/wasm/nodejs/kaspa");
}

/*
 * Resolve the kaspa-wasm module handle, in fixed precedence:
 *   1. options.kaspaModule      — an already-loaded module handle (tests,
 *                                 embedding consumers)
 *   2. options.kaspaModulePath  — explicit path to require
 *   3. PV_CLI_SIGNER_KASPA_MODULE environment variable
 *   4. the loadConfig() default path (above)
 * The module is required lazily (first cryptographic use), never at
 * adapter construction, and the handle is validated to expose the exact
 * functions this adapter drives — anything else fails closed.
 */
function resolveKaspaModule(options = {}) {
  let mod = options.kaspaModule;
  if (mod === undefined) {
    const modulePath = options.kaspaModulePath || process.env[KASPA_MODULE_ENV] || defaultKaspaModulePath();
    if (typeof modulePath !== "string" || !modulePath.trim()) {
      throw invalid("kaspa module path must be a non-empty string");
    }
    try {
      mod = require(modulePath);
    } catch (e) {
      throw signerError(
        SignerErrorCodes.PROVIDER_ERROR,
        `cannot load the kaspa-wasm module from ${JSON.stringify(modulePath)} — install/point ${KASPA_MODULE_ENV} at the rusty-kaspa wasm nodejs build`,
        { cause: e }
      );
    }
  }
  for (const name of ["signMessage", "createInputSignature", "PrivateKey", "Keypair", "Transaction", "SighashType"]) {
    if (!mod || (typeof mod[name] !== "function" && typeof mod[name] !== "object")) {
      throw signerError(SignerErrorCodes.PROVIDER_ERROR, `kaspa module handle is missing ${JSON.stringify(name)} — refusing (wrong or partial module)`);
    }
  }
  return mod;
}

/* ------------------------------------------------------------------ */
/* Network + dual-unlock gate                                          */
/* ------------------------------------------------------------------ */

/*
 * Validate a network id against the closed v1 vocabulary and enforce the
 * mainnet dual unlock: "mainnet" requires BOTH allowMainnet === true
 * (explicit option) AND PV_CLI_SIGNER_ALLOW_MAINNET=1 (environment).
 * Either alone refuses, fail closed, with WRONG_NETWORK — this signer
 * will not operate on mainnet as configured.
 */
function assertOperatingNetwork(network, allowMainnet) {
  if (typeof network !== "string" || !SIGNER_NETWORKS.includes(network)) {
    throw invalid(`unknown network ${JSON.stringify(network)} — the ${SIGNER_INTERFACE_VERSION} network vocabulary is closed; failing closed`);
  }
  if (network === "mainnet") {
    const optionPresent = allowMainnet === true;
    const envPresent = process.env[MAINNET_UNLOCK_ENV] === "1";
    if (!optionPresent || !envPresent) {
      throw signerError(
        SignerErrorCodes.WRONG_NETWORK,
        `mainnet operation is locked for the CLI signer — it requires BOTH { allowMainnet: true } and ${MAINNET_UNLOCK_ENV}=1 ` +
          `(present: option=${optionPresent}, env=${envPresent}); failing closed`
      );
    }
  }
  return network;
}

/* ------------------------------------------------------------------ */
/* Keyfile create / load                                               */
/* ------------------------------------------------------------------ */

function assertLabel(label) {
  if (label === undefined) return undefined;
  if (typeof label !== "string" || !label.trim() || label.length > MAX_LABEL_CHARS) {
    throw invalid(`label must be a non-empty string of at most ${MAX_LABEL_CHARS} characters when provided`);
  }
  return label;
}

/*
 * Generate a NEW local keyfile at `out` (refusing to overwrite anything)
 * and return the PUBLIC identity only. TEST/testnet keys by default; a
 * mainnet keyfile requires the full dual unlock. Entropy and scalar
 * validity come from the authoritative kaspa-wasm Keypair.random() —
 * never a homemade scheme. The file is created 0600 (owner-only) and
 * re-chmodded to 0600 after writing (umask-proof).
 *
 * Options: { out, network = "testnet-10", label?, allowMainnet?,
 *            kaspaModule?, kaspaModulePath? }
 * Returns: { format, address, publicKey, xOnlyPublicKey, network,
 *            keyfile } — NO secret material, ever.
 */
function generateKeyfile(options = {}) {
  if (!isPlainObject(options)) throw invalid("generateKeyfile options must be a plain object");
  const ALLOWED = ["out", "network", "label", "allowMainnet", "kaspaModule", "kaspaModulePath"];
  for (const key of Object.keys(options)) {
    if (!ALLOWED.includes(key)) throw invalid(`unknown generateKeyfile option ${JSON.stringify(key)} — failing closed`);
  }
  const out = options.out;
  if (typeof out !== "string" || !out.trim()) throw invalid("generateKeyfile requires an output file path (out)");
  const network = assertOperatingNetwork(options.network === undefined ? "testnet-10" : options.network, options.allowMainnet);
  const label = assertLabel(options.label);

  const kaspa = resolveKaspaModule(options);
  const keypair = kaspa.Keypair.random();
  const privateKeyHex = String(keypair.privateKey).toLowerCase();
  const publicKeyHex = String(keypair.publicKey).toLowerCase();
  const xOnly = String(keypair.xOnlyPublicKey).toLowerCase();
  if (!PRIVATE_KEY_HEX_RE.test(privateKeyHex) || !COMPRESSED_PUBKEY_HEX_RE.test(publicKeyHex)) {
    throw signerError(SignerErrorCodes.PROVIDER_ERROR, "kaspa key generation returned unexpected key shapes — refusing");
  }
  const address = keypair.toAddress(network).toString();

  const record = {
    format: KEYFILE_FORMAT,
    network,
    privateKeyHex,
    publicKeyHex,
    address,
    createdAt: new Date().toISOString()
  };
  if (label !== undefined) record.label = label;

  const absolute = path.resolve(out);
  let fd;
  try {
    /* "wx": fail if the path already exists — a signer never silently
     * overwrites a key. mode 0600 at creation; chmod again afterwards so
     * an unusual umask cannot widen it (umask can only remove bits, but
     * we assert the end state rather than reason about it). */
    fd = fs.openSync(absolute, "wx", 0o600);
  } catch (e) {
    if (e && e.code === "EEXIST") {
      throw keyfileFault(`refusing to overwrite existing file ${JSON.stringify(absolute)} — move it away first`);
    }
    throw keyfileFault(`cannot create ${JSON.stringify(absolute)} (${e && e.code ? e.code : "unwritable"})`);
  }
  try {
    fs.writeSync(fd, JSON.stringify(record, null, 2) + "\n", null, "utf8");
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(absolute, 0o600);

  return Object.freeze({
    format: "policyvault-cli-signer-identity/1",
    address,
    publicKey: publicKeyHex,
    xOnlyPublicKey: xOnly,
    network,
    keyfile: absolute
  });
}

/*
 * Load + fully validate a keyfile. Fail-closed order:
 *   existence -> POSIX permission gate (owner-only) -> size -> JSON ->
 *   closed schema -> exact format version -> network vocabulary ->
 *   network binding (must equal expectedNetwork) -> secret shape ->
 *   key parse -> identity re-derivation (stored address/public key must
 *   EXACTLY match what the private key derives — stored claims are never
 *   trusted; a mismatch is treated as tampering).
 * Returns the in-memory key material for the adapter closure. Secret hex
 * is NOT kept as a string on the returned record — only the parsed
 * kaspa PrivateKey handle plus public identity.
 */
function loadKeyfile(keyfilePath, expectedNetwork, kaspa) {
  const absolute = path.resolve(keyfilePath);
  let stat;
  try {
    stat = fs.statSync(absolute);
  } catch {
    throw signerError(SignerErrorCodes.SIGNER_NOT_FOUND, `no keyfile at ${JSON.stringify(absolute)}`);
  }
  if (!stat.isFile()) {
    throw signerError(SignerErrorCodes.SIGNER_NOT_FOUND, `keyfile path ${JSON.stringify(absolute)} is not a regular file`);
  }
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
    throw keyfileFault(
      `${JSON.stringify(absolute)} is readable by group/others (mode ${(stat.mode & 0o777).toString(8)}) — a signing key must be owner-only; run: chmod 600`
    );
  }
  if (stat.size > MAX_KEYFILE_BYTES) {
    throw keyfileFault(`${JSON.stringify(absolute)} is too large to be a signer keyfile — refusing`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(absolute, "utf8"));
  } catch {
    throw keyfileFault(`${JSON.stringify(absolute)} is not valid JSON`);
  }
  if (!isPlainObject(parsed)) throw keyfileFault("keyfile content must be a JSON object");

  for (const key of Object.keys(parsed)) {
    if (!KEYFILE_REQUIRED_KEYS.includes(key) && !KEYFILE_OPTIONAL_KEYS.includes(key)) {
      throw keyfileFault(`unknown key ${JSON.stringify(key)} — the keyfile schema is closed; refusing`);
    }
  }
  for (const key of KEYFILE_REQUIRED_KEYS) {
    if (!(key in parsed)) throw keyfileFault(`missing required key ${JSON.stringify(key)}`);
  }

  if (parsed.format !== KEYFILE_FORMAT) {
    const claimed = typeof parsed.format === "string" ? parsed.format.slice(0, 64) : typeof parsed.format;
    throw keyfileFault(`format ${JSON.stringify(claimed)} is not ${JSON.stringify(KEYFILE_FORMAT)} — unknown versions fail closed`);
  }
  if (typeof parsed.network !== "string" || !SIGNER_NETWORKS.includes(parsed.network)) {
    throw keyfileFault(`unknown network ${JSON.stringify(String(parsed.network).slice(0, 32))} — failing closed`);
  }
  if (parsed.network !== expectedNetwork) {
    throw signerError(
      SignerErrorCodes.WRONG_NETWORK,
      `keyfile is bound to network ${JSON.stringify(parsed.network)} but this signer is configured for ${JSON.stringify(expectedNetwork)} — failing closed`
    );
  }
  if (typeof parsed.createdAt !== "string" || !parsed.createdAt.trim()) {
    throw keyfileFault("createdAt must be a non-empty string");
  }
  if ("label" in parsed && (typeof parsed.label !== "string" || !parsed.label.trim() || parsed.label.length > MAX_LABEL_CHARS)) {
    throw keyfileFault("label is malformed");
  }
  /* Secret shape — diagnostics are SHAPE-ONLY; the value is never echoed. */
  if (typeof parsed.privateKeyHex !== "string" || !PRIVATE_KEY_HEX_RE.test(parsed.privateKeyHex)) {
    throw keyfileFault("privateKeyHex is not 64 lowercase hex characters — refusing (value not shown)");
  }
  if (typeof parsed.publicKeyHex !== "string" || !COMPRESSED_PUBKEY_HEX_RE.test(parsed.publicKeyHex)) {
    throw keyfileFault("publicKeyHex is not 66-hex compressed (02/03 prefix) — refusing");
  }
  if (typeof parsed.address !== "string" || !parsed.address.trim() || parsed.address.length > 256) {
    throw keyfileFault("address is malformed");
  }

  let privateKey;
  try {
    privateKey = new kaspa.PrivateKey(parsed.privateKeyHex);
  } catch {
    throw keyfileFault("privateKeyHex does not parse as a secp256k1 private key — refusing (value not shown)");
  }
  /* Identity re-derivation: stored claims are NEVER trusted. */
  const derivedPub = privateKey.toPublicKey().toString().toLowerCase();
  const derivedAddress = privateKey.toPublicKey().toAddress(parsed.network).toString();
  if (derivedPub !== parsed.publicKeyHex || derivedAddress !== parsed.address) {
    throw keyfileFault("stored identity claims do not match the key they accompany — refusing (possible tampering)");
  }

  return {
    privateKey,
    address: derivedAddress,
    publicKeyHex: derivedPub,
    network: parsed.network,
    label: parsed.label,
    keyfile: absolute
  };
}

/*
 * PUBLIC identity of a keyfile (full validation, no unlock needed —
 * displaying the operator's own public address/key signs nothing and
 * touches no network; every SIGNING use of a mainnet keyfile still goes
 * through the dual unlock at adapter construction). Never returns or
 * logs secret material.
 */
function readKeyfileIdentity(keyfilePath, options = {}) {
  if (!isPlainObject(options)) throw invalid("readKeyfileIdentity options must be a plain object");
  for (const key of Object.keys(options)) {
    if (key !== "kaspaModule" && key !== "kaspaModulePath") {
      throw invalid(`unknown readKeyfileIdentity option ${JSON.stringify(key)} — failing closed`);
    }
  }
  const kaspa = resolveKaspaModule(options);
  /* Peek the network so validation binds the file to its OWN network. */
  let network;
  try {
    const peek = JSON.parse(fs.readFileSync(path.resolve(keyfilePath), "utf8"));
    network = isPlainObject(peek) ? peek.network : undefined;
  } catch {
    network = undefined; /* loadKeyfile re-reads and reports precisely */
  }
  const material = loadKeyfile(keyfilePath, typeof network === "string" ? network : "testnet-10", kaspa);
  return Object.freeze({
    format: "policyvault-cli-signer-identity/1",
    address: material.address,
    publicKey: material.publicKeyHex,
    network: material.network,
    label: material.label,
    keyfile: material.keyfile
  });
}

/* ------------------------------------------------------------------ */
/* The adapter                                                         */
/* ------------------------------------------------------------------ */

/*
 * createCliSignerAdapter(options):
 *   keyfilePath      — REQUIRED path to the operator's keyfile
 *   network          — operating network (default "testnet-10");
 *                      "mainnet" needs the dual unlock
 *   allowMainnet     — half of the mainnet dual unlock
 *   provider, label  — descriptor identity overrides
 *   kaspaModule / kaspaModulePath — kaspa-wasm injection (see above)
 *
 * Returns a v1-conformant adapter. The keyfile is loaded lazily at
 * connect() (validated in full on every connect); until then the
 * adapter holds no key material. disconnect() drops the in-memory key
 * handle (best-effort — see the reference doc's honest gaps).
 */
function createCliSignerAdapter(options = {}) {
  if (!isPlainObject(options)) throw invalid("createCliSignerAdapter options must be a plain object");
  const ALLOWED = ["keyfilePath", "network", "allowMainnet", "provider", "label", "kaspaModule", "kaspaModulePath"];
  for (const key of Object.keys(options)) {
    if (!ALLOWED.includes(key)) throw invalid(`unknown createCliSignerAdapter option ${JSON.stringify(key)} — failing closed`);
  }
  if (typeof options.keyfilePath !== "string" || !options.keyfilePath.trim()) {
    throw invalid("createCliSignerAdapter requires keyfilePath");
  }
  const keyfilePath = path.resolve(options.keyfilePath);
  const network = assertOperatingNetwork(options.network === undefined ? "testnet-10" : options.network, options.allowMainnet);
  const providerId = options.provider === undefined ? DEFAULT_PROVIDER_ID : options.provider;
  const label = options.label === undefined ? DEFAULT_LABEL : options.label;

  const state = {
    kaspa: null, // lazy module handle
    material: null, // loaded key material while connected
    connected: false
  };

  function kaspaHandle() {
    if (state.kaspa === null) state.kaspa = resolveKaspaModule(options);
    return state.kaspa;
  }

  function requireConnected() {
    if (!state.connected || state.material === null) {
      throw signerError(SignerErrorCodes.SIGNER_DISCONNECTED, "CLI signer is not connected — call connect() first");
    }
    return state.material;
  }

  /* Defense-in-depth request binding (executeSigning enforces the same
   * gates upstream; a standalone caller gets identical refusals). */
  function assertRequestBindings(request, kind, material) {
    if (!isPlainObject(request) || request.kind !== kind) {
      throw invalid(`CLI signer received a malformed ${kind} request — refusing`);
    }
    if (request.interfaceVersion !== SIGNER_INTERFACE_VERSION) {
      throw signerError(
        SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
        `request interface version ${JSON.stringify(request.interfaceVersion)} is not ${JSON.stringify(SIGNER_INTERFACE_VERSION)} — failing closed`
      );
    }
    if (request.network !== undefined && request.network !== network) {
      throw signerError(
        SignerErrorCodes.WRONG_NETWORK,
        `request network ${JSON.stringify(request.network)} does not match this signer's network ${JSON.stringify(network)} — failing closed`
      );
    }
    if (request.expectedSignerAddress !== undefined && request.expectedSignerAddress !== material.address) {
      throw signerError(
        SignerErrorCodes.ACCOUNT_CHANGED,
        "request is bound to a different signer identity than this keyfile — refusing"
      );
    }
  }

  return {
    describe() {
      return {
        interfaceVersion: SIGNER_INTERFACE_VERSION,
        provider: providerId,
        label,
        kind: "cli",
        schemes: ["schnorr"],
        networks: [network],
        features: {
          messageSigning: true,
          transactionSigning: true,
          specificInputSigning: true,
          multiAccount: false,
          networkSwitching: false,
          accountEvents: false,
          asynchronousApproval: false,
          airGapped: false,
          hardwareDisplay: false
        }
      };
    },

    /* Presence claim: is there a regular file at the keyfile path?
     * Never throws for absence (interface contract). Full validation
     * happens at connect(). */
    detect() {
      try {
        return fs.statSync(keyfilePath).isFile();
      } catch {
        return false;
      }
    },

    /* Loading the keyfile IS the provider session. Every connect()
     * re-reads and re-validates the file in full (permission bits,
     * schema, version, network binding, identity re-derivation). */
    async connect() {
      const material = loadKeyfile(keyfilePath, network, kaspaHandle());
      state.material = material;
      state.connected = true;
      return { address: material.address, network };
    },

    async disconnect() {
      state.connected = false;
      state.material = null; /* drop the key handle (best-effort — see doc) */
    },

    async getActiveAccount() {
      return state.connected && state.material ? { address: state.material.address } : null;
    },

    async getNetwork() {
      return network; /* static configuration CLAIM — consumers verify */
    },

    async getPublicKey() {
      const material = requireConnected();
      return material.publicKeyHex; /* provider-native: 66-hex compressed */
    },

    /*
     * Personal-message signing: kaspa-wasm signMessage — BIP-340 Schnorr
     * in the PersonalMessageSigningHash domain, the exact function
     * KasWare passes through to (and the counterpart of the server's
     * kaspa.verifyMessage). The message is signed VERBATIM.
     */
    async signMessage(request) {
      const material = requireConnected();
      assertRequestBindings(request, "sign-message", material);
      if (request.scheme !== "schnorr") {
        throw signerError(SignerErrorCodes.UNSUPPORTED_SCHEME, `CLI signer offers schnorr only — refusing scheme ${JSON.stringify(request.scheme)}`);
      }
      if (typeof request.message !== "string" || !request.message) {
        throw invalid("sign-message request carries no message");
      }
      const kaspa = kaspaHandle();
      const signature = String(kaspa.signMessage({ message: request.message, privateKey: material.privateKey })).toLowerCase();
      if (!/^[0-9a-f]{128}$/.test(signature)) {
        throw signerError(SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, "kaspa signMessage returned an unexpected signature shape — refusing");
      }
      return signature;
    },

    /*
     * Frozen-transaction signing: deserialize the EXACT Safe JSON handed
     * in, add a signature script for exactly the named inputs
     * (SIG_HASH_ALL via kaspa createInputSignature — the same call the
     * SDK's own signing paths use), and return the re-serialized
     * transaction. The transaction id is re-derived after signing and
     * MUST equal the unsigned id — any drift refuses (signature scripts
     * are not txid-visible in Kaspa; drift would mean this adapter
     * altered consensus-visible bytes, which it must never do).
     */
    async signTransaction(request) {
      const material = requireConnected();
      assertRequestBindings(request, "sign-transaction", material);
      if (request.scheme !== undefined && request.scheme !== "schnorr") {
        throw signerError(SignerErrorCodes.UNSUPPORTED_SCHEME, `CLI signer offers schnorr only — refusing scheme ${JSON.stringify(request.scheme)}`);
      }
      if (typeof request.unsignedSafeJson !== "string" || !request.unsignedSafeJson) {
        throw invalid("sign-transaction request carries no unsignedSafeJson");
      }
      if (!Array.isArray(request.signInputs) || request.signInputs.length === 0) {
        throw invalid("sign-transaction request carries no signInputs");
      }
      const kaspa = kaspaHandle();
      let tx;
      try {
        tx = kaspa.Transaction.deserializeFromSafeJSON(request.unsignedSafeJson);
      } catch (e) {
        throw signerError(SignerErrorCodes.REQUEST_INVALID, "unsignedSafeJson does not deserialize as a Kaspa transaction — refusing", { cause: e });
      }
      const unsignedId = String(tx.id);
      const inputCount = tx.inputs.length;
      for (const entry of request.signInputs) {
        if (!isPlainObject(entry) || !Number.isInteger(entry.index) || entry.index < 0 || entry.sighashType !== SIGHASH_ALL) {
          throw invalid("signing entry is not the canonical frozen { index, sighashType: 1 } — refusing");
        }
        if (entry.index >= inputCount) {
          throw invalid(`signing entry index ${entry.index} is out of range for a transaction with ${inputCount} input(s)`);
        }
      }
      for (const entry of request.signInputs) {
        const signatureScript = kaspa.createInputSignature(tx, entry.index, material.privateKey, kaspa.SighashType.All);
        const inputs = tx.inputs;
        inputs[entry.index].signatureScript = signatureScript;
        tx.inputs = inputs;
      }
      const signedSafeJson = tx.serializeToSafeJSON();
      let signedId;
      try {
        signedId = String(kaspa.Transaction.deserializeFromSafeJSON(signedSafeJson).id);
      } catch (e) {
        throw signerError(SignerErrorCodes.PROTOCOL_VIOLATION, "signed serialization does not round-trip — refusing to return it", { cause: e });
      }
      if (signedId !== unsignedId) {
        throw signerError(
          SignerErrorCodes.PROTOCOL_VIOLATION,
          "signing altered the transaction identity — refusing to return drifted bytes (frozen-txid discipline)"
        );
      }
      return signedSafeJson;
    }
  };
}

module.exports = {
  KEYFILE_FORMAT,
  MAINNET_UNLOCK_ENV,
  KASPA_MODULE_ENV,
  defaultKaspaModulePath,
  resolveKaspaModule,
  assertOperatingNetwork,
  generateKeyfile,
  readKeyfileIdentity,
  createCliSignerAdapter
};
