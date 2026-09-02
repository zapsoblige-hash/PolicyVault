/*
 * PolicyVault browser wallet / signer abstraction.
 *
 * Application code depends ONLY on the generic WalletAdapter surface below —
 * never on KasWare globals. KasWare is the first concrete adapter; the mock
 * adapter proves the dashboard is not coupled to any single provider. A new
 * wallet = a new adapter implementing this contract, nothing else.
 *
 * The adapter supplies authorization material only (it signs transaction
 * inputs and returns signed Safe JSON — the KasWare signPskt contract). It
 * is NEVER the funds-security boundary; the hardened SDK/covenant is.
 */

/* Stable, provider-independent error categories. */
const WalletError = {
  WALLET_NOT_FOUND: "WALLET_NOT_FOUND",
  WALLET_DISCONNECTED: "WALLET_DISCONNECTED",
  USER_REJECTED: "USER_REJECTED",
  WRONG_NETWORK: "WRONG_NETWORK",
  ACCOUNT_CHANGED: "ACCOUNT_CHANGED",
  SIGNING_UNSUPPORTED: "SIGNING_UNSUPPORTED",
  INVALID_SIGNATURE_RESPONSE: "INVALID_SIGNATURE_RESPONSE",
  INVALID_PUBLIC_KEY: "INVALID_PUBLIC_KEY",
  PROVIDER_ERROR: "PROVIDER_ERROR",
  // The Universal Signer Interface adapter module (web/signer-kasware-
  // adapter.js) failed to load — see createSigningUnavailableAdapter below.
  // Never produced by a real wallet provider.
  USI_UNAVAILABLE: "USI_UNAVAILABLE"
};

function walletError(category, message, cause) {
  const e = new Error(message || category);
  e.walletCategory = category;
  if (cause) e.cause = cause;
  return e;
}

const WalletState = {
  NOT_DETECTED: "WALLET_NOT_DETECTED",
  DISCONNECTED: "DISCONNECTED",
  CONNECTING: "CONNECTING",
  CONNECTED: "CONNECTED",
  WRONG_NETWORK: "WRONG_NETWORK",
  READY: "READY",
  ERROR: "ERROR"
};

/*
 * Canonical provider-pubkey normalization — the ONE shared implementation
 * for every adapter (no scattered slice(2) calls). Exactly two provider
 * encodings are supported:
 *   - 64-hex x-only (BIP340)                 -> canonicalized (trim, lowercase)
 *   - 66-hex compressed secp256k1 (02/03+X)  -> X (KasWare's getPublicKey
 *     returns this form per its vendor docs)
 * Uppercase hex is accepted and canonicalized to lowercase, matching the
 * SDK's normalizeHex rule. Everything else fails closed with
 * INVALID_PUBLIC_KEY: missing value, non-hex, wrong length, uncompressed
 * 04-prefixed keys. Error messages carry only the value's shape, never the
 * raw malformed string.
 */
/* Opt-in wallet diagnostics (never secrets): localStorage "pv.debug" = "1".
 * Every access is guarded — storage may be unavailable or throw. */
function walletDebugEnabled() {
  try {
    return typeof localStorage !== "undefined" && localStorage !== null && localStorage.getItem("pv.debug") === "1";
  } catch (_) {
    return false;
  }
}

function normalizePublicKeyToXOnly(value, source) {
  const label = source || "wallet provider";
  if (typeof value !== "string" || !value.trim()) {
    throw walletError(WalletError.INVALID_PUBLIC_KEY, `${label} returned no public key`);
  }
  const hex = value.trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(hex)) return hex;
  if (/^0[23][0-9a-f]{64}$/.test(hex)) return hex.slice(2);
  if (/^04[0-9a-f]{128}$/.test(hex)) {
    throw walletError(WalletError.INVALID_PUBLIC_KEY, `${label} returned an uncompressed 65-byte secp256k1 public key — unsupported encoding`);
  }
  const shape = /^[0-9a-f]+$/.test(hex) ? `${hex.length}-char hex` : "non-hex data";
  throw walletError(WalletError.INVALID_PUBLIC_KEY, `${label} returned an unsupported public key (${shape}); expected 64-hex x-only or 66-hex compressed (02/03 prefix)`);
}

/* Normalize a network label to PolicyVault's canonical form. */
function normalizeNetwork(n) {
  if (!n) return null;
  const s = String(n).toLowerCase();
  if (s.includes("testnet") && (s.includes("10") || s.includes("tn10"))) return "testnet-10";
  if (s === "kaspa_testnet_10" || s === "testnet-10") return "testnet-10";
  if (s.includes("mainnet") || s === "kaspa_mainnet") return "mainnet";
  return s;
}

/*
 * TEST-FIXTURE / REFERENCE ONLY as of the USI fail-closed change
 * (PostLaunchUpgradeOG completion-standard item 4, 2026-08). Production
 * code must NEVER construct this class for live signing: web/app.js's
 * makeKasWareAdapter() connects through the Universal Signer Interface
 * adapter (web/signer-kasware-adapter.js) exclusively and fails closed
 * (createSigningUnavailableAdapter, below) if that module is absent —
 * it no longer falls back here. This implementation is retained solely
 * as the byte-identical-behavior reference fixture for
 * web/test/signer-kasware-adapter.test.js, which proves the USI adapter
 * reproduces this historically-proven implementation's exact provider
 * invocations (signMessage/signPskt arguments, public-key normalization,
 * network normalization, error taxonomy) rather than inventing new
 * KasWare-facing behavior.
 */
/* ---- KasWare adapter (first concrete browser wallet) ---- */
class KasWareAdapter {
  constructor() {
    this.provider = "kasware";
    this.label = "KasWare";
    this._account = null;
    this._network = null;
    this._listeners = { account: [], network: [] };
  }
  _kw() {
    const kw = typeof window !== "undefined" ? window.kasware : undefined;
    if (!kw) throw walletError(WalletError.WALLET_NOT_FOUND, "KasWare extension not detected");
    return kw;
  }
  detect() {
    return typeof window !== "undefined" && !!window.kasware;
  }
  getCapabilities() {
    return {
      canSignTransaction: true,
      canSignSpecificInputs: true,
      canReturnRawSignedTx: true,
      canSwitchNetwork: false,
      canExposeXOnlyPubkey: true,
      supportsAccountChangeEvents: true
    };
  }
  async connect() {
    const kw = this._kw();
    let accounts;
    try {
      accounts = await kw.requestAccounts();
    } catch (e) {
      if (e && (e.code === 4001 || /reject/i.test(e.message || ""))) {
        throw walletError(WalletError.USER_REJECTED, "You declined the connection", e);
      }
      throw walletError(WalletError.PROVIDER_ERROR, e.message || "connect failed", e);
    }
    if (!Array.isArray(accounts) || !accounts.length) {
      throw walletError(WalletError.PROVIDER_ERROR, "KasWare returned no accounts");
    }
    this._account = accounts[0];
    try {
      this._network = normalizeNetwork(await kw.getNetwork());
    } catch (e) {
      this._network = null;
    }
    this._subscribe(kw);
    return { address: this._account, network: this._network };
  }
  async disconnect() {
    try {
      const kw = this._kw();
      if (typeof kw.disconnect === "function") await kw.disconnect(window.location.origin);
    } catch {
      /* best-effort */
    }
    this._account = null;
    this._network = null;
  }
  async reconnect() {
    const kw = this._kw();
    const accounts = typeof kw.getAccounts === "function" ? await kw.getAccounts() : [];
    if (Array.isArray(accounts) && accounts.length) {
      this._account = accounts[0];
      this._network = normalizeNetwork(await kw.getNetwork());
      this._subscribe(kw);
      return { address: this._account, network: this._network };
    }
    return null;
  }
  getActiveAddress() {
    return this._account;
  }
  async getNetwork() {
    this._network = normalizeNetwork(await this._kw().getNetwork());
    return this._network;
  }
  /*
   * Connected-wallet identity as canonical 32-byte x-only hex. KasWare's
   * getPublicKey() returns the 33-byte compressed key (66 hex, 02/03 + X);
   * it is normalized HERE, at the adapter boundary, so downstream
   * template/state validation stays strict x-only. The diagnostic log is
   * PUBLIC key material only.
   */
  async getPublicKeyXOnly() {
    const kw = this._kw();
    if (typeof kw.getPublicKey !== "function") {
      throw walletError(WalletError.INVALID_PUBLIC_KEY, "KasWare does not expose getPublicKey");
    }
    let raw;
    try {
      raw = await kw.getPublicKey();
    } catch (e) {
      throw walletError(WalletError.PROVIDER_ERROR, e.message || "getPublicKey failed", e);
    }
    const xonly = normalizePublicKeyToXOnly(raw, "KasWare");
    // Wallet-identity diagnostic (PUBLIC key material only) is OPT-IN:
    // production consoles stay quiet; set localStorage "pv.debug" = "1"
    // to see the raw -> x-only normalization while debugging.
    if (typeof console !== "undefined" && walletDebugEnabled()) {
      console.info(`[PolicyVault] KasWare public key ${raw} (${raw.trim().length} hex chars) -> x-only ${xonly}`);
    }
    return xonly;
  }
  /*
   * Hosted sign-in only: Kaspa personal-message signature over the
   * server-issued challenge text. The Schnorr type is FORCED explicitly
   * (never "auto" — auto could silently change the cryptographic scheme
   * on Tangem-class accounts; the server refuses ECDSA regardless).
   * This is authentication, not transaction signing: the message lives
   * in the PersonalMessageSigningHash domain and cannot move funds.
   */
  async signAuthMessage(message) {
    const kw = this._kw();
    if (typeof kw.signMessage !== "function") {
      throw walletError(WalletError.SIGNING_UNSUPPORTED, "KasWare does not support signMessage");
    }
    let sig;
    try {
      sig = await kw.signMessage(message, { type: "schnorr" });
    } catch (e) {
      if (e && (e.code === 4001 || /reject|denied/i.test(e.message || ""))) {
        throw walletError(WalletError.USER_REJECTED, "You declined the sign-in signature", e);
      }
      throw walletError(WalletError.PROVIDER_ERROR, e.message || "signMessage failed", e);
    }
    if (typeof sig !== "string" || !/^[0-9a-f]{128}$/i.test(sig.trim())) {
      throw walletError(WalletError.PROVIDER_ERROR, "wallet returned an unexpected sign-in signature format");
    }
    return sig.trim().toLowerCase();
  }
  /* Raw provider public key (66-hex compressed) for the auth verify call;
   * transaction paths keep using the x-only normalization above. */
  async getPublicKeyRaw() {
    const kw = this._kw();
    if (typeof kw.getPublicKey !== "function") {
      throw walletError(WalletError.INVALID_PUBLIC_KEY, "KasWare does not expose getPublicKey");
    }
    const raw = await kw.getPublicKey();
    if (typeof raw !== "string" || !raw.trim()) {
      throw walletError(WalletError.INVALID_PUBLIC_KEY, "KasWare returned an empty public key");
    }
    return raw.trim().toLowerCase();
  }
  on(event, cb) {
    if (this._listeners[event]) this._listeners[event].push(cb);
  }
  _subscribe(kw) {
    if (this._subscribed) return;
    this._subscribed = true;
    if (typeof kw.on === "function") {
      kw.on("accountsChanged", (accts) => {
        this._account = Array.isArray(accts) && accts.length ? accts[0] : null;
        this._listeners.account.forEach((cb) => cb(this._account));
      });
      kw.on("networkChanged", (n) => {
        this._network = normalizeNetwork(n);
        this._listeners.network.forEach((cb) => cb(this._network));
      });
    }
  }
  /*
   * Sign the named inputs of the unsigned Safe JSON, returning signed Safe
   * JSON. Mirrors PolicyVault's signer contract exactly.
   */
  async signInputs(unsignedSafeJson, signInputs) {
    const kw = this._kw();
    if (typeof kw.signPskt !== "function") {
      throw walletError(WalletError.SIGNING_UNSUPPORTED, "KasWare does not support signPskt");
    }
    let signed;
    try {
      signed = await kw.signPskt({ txJsonString: unsignedSafeJson, options: { signInputs } });
    } catch (e) {
      if (e && (e.code === 4001 || /reject|denied/i.test(e.message || ""))) {
        throw walletError(WalletError.USER_REJECTED, "You declined the signature", e);
      }
      throw walletError(WalletError.PROVIDER_ERROR, e.message || "signPskt failed", e);
    }
    if (typeof signed !== "string" || !signed.trim()) {
      throw walletError(WalletError.INVALID_SIGNATURE_RESPONSE, "KasWare returned no signed Safe JSON");
    }
    return signed;
  }
}

/*
 * The FAIL-CLOSED replacement for the old silent-bypass fallback
 * (PostLaunchUpgradeOG completion-standard item 4). Constructed by
 * web/app.js's makeKasWareAdapter() ONLY when the Universal Signer
 * Interface adapter module (web/signer-kasware-adapter.js) failed to
 * load — never a normal operating state for a correctly served page.
 *
 * `detect()` still reports whether the KasWare extension itself is
 * present (`win.kasware`), so the UI never lies and claims "wallet not
 * installed" when the real problem is this app's own module failing to
 * load. Every method that could move toward a signature — connect,
 * getNetwork, the public-key getters, and both signing methods — refuses
 * synchronously with WalletError.USI_UNAVAILABLE before touching
 * `window.kasware` at all: there is no code path in this object that
 * reaches a real provider call. disconnect/reconnect are inert no-ops
 * (nothing was ever connected); getActiveAddress always returns null.
 *
 * `win` is injectable (mirrors signer-kasware-adapter.js's `options.win`
 * convention) so this is unit-testable without mutating the global
 * `window`; it defaults to the real `window` in the browser.
 */
function createSigningUnavailableAdapter(options = {}) {
  const win = options.win !== undefined ? options.win : (typeof window !== "undefined" ? window : undefined);
  const message =
    "The secure signer module (Universal Signer Interface) failed to load — signing is unavailable on this page load. " +
    "This is a build/deployment defect, not a problem with your wallet. Reload the page; if it persists, contact support.";
  const refuse = async () => {
    throw walletError(WalletError.USI_UNAVAILABLE, message);
  };
  return {
    provider: "kasware-signing-unavailable",
    label: "KasWare (signing unavailable)",
    detect() {
      return !!(win && win.kasware);
    },
    getCapabilities() {
      return {
        canSignTransaction: false,
        canSignSpecificInputs: false,
        canReturnRawSignedTx: false,
        canSwitchNetwork: false,
        canExposeXOnlyPubkey: false,
        supportsAccountChangeEvents: false
      };
    },
    connect: refuse,
    async disconnect() {},
    async reconnect() {
      return null;
    },
    getActiveAddress() {
      return null;
    },
    getNetwork: refuse,
    getPublicKeyXOnly: refuse,
    getPublicKeyRaw: refuse,
    signAuthMessage: refuse,
    signInputs: refuse,
    on() {}
  };
}

/*
 * Mock adapter (architecture/extensibility test only — directive §17). It
 * implements the identical generic contract and produces signatures via a
 * TEST-ONLY backend dev-sign endpoint (testnet-only, env-gated). It exists
 * to prove the dashboard has no KasWare-specific branch in funds-critical
 * logic — NOT as a production wallet.
 */
class MockAdapter {
  constructor({ apiBase, address, network = "testnet-10" } = {}) {
    this.provider = "mock";
    this.label = "Mock signer (test only)";
    this._apiBase = apiBase || "/api/v1";
    this._address = address || null;
    this._network = network;
    this._connected = false;
    this._listeners = { account: [], network: [] };
  }
  detect() {
    return true;
  }
  getCapabilities() {
    return { canSignTransaction: true, canSignSpecificInputs: true, canReturnRawSignedTx: true, canSwitchNetwork: true, canExposeXOnlyPubkey: true, supportsAccountChangeEvents: false };
  }
  async connect() {
    const r = await fetch(`${this._apiBase}/wallet/dev-accounts`);
    if (!r.ok) throw walletError(WalletError.PROVIDER_ERROR, "dev signer endpoint unavailable (set POLICYVAULT_DEV_SIGNER=1)");
    const { accounts } = await r.json();
    this._accounts = accounts;
    this._address = this._address || accounts[0]?.address;
    this._connected = true;
    return { address: this._address, network: this._network };
  }
  async disconnect() {
    this._connected = false;
  }
  async reconnect() {
    return this._connected ? { address: this._address, network: this._network } : null;
  }
  getActiveAddress() {
    return this._address;
  }
  async getNetwork() {
    return this._network;
  }
  async getPublicKeyXOnly() {
    if (!this._connected) {
      throw walletError(WalletError.WALLET_DISCONNECTED, "mock signer is not connected");
    }
    const acct = (this._accounts || []).find((a) => a.address === this._address);
    if (!acct || !acct.xonly) {
      throw walletError(WalletError.INVALID_PUBLIC_KEY, "mock signer account exposes no public key");
    }
    return normalizePublicKeyToXOnly(acct.xonly, "mock signer");
  }
  setAccount(address) {
    this._address = address;
    this._listeners.account.forEach((cb) => cb(address));
  }
  listAccounts() {
    return this._accounts || [];
  }
  on(event, cb) {
    if (this._listeners[event]) this._listeners[event].push(cb);
  }
  async signInputs(unsignedSafeJson, signInputs) {
    const r = await fetch(`${this._apiBase}/wallet/dev-sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address: this._address, unsignedSafeJson, signInputs })
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw walletError(WalletError.PROVIDER_ERROR, err.error?.message || "dev-sign failed");
    }
    const { signedSafeJson } = await r.json();
    if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) {
      throw walletError(WalletError.INVALID_SIGNATURE_RESPONSE, "dev signer returned no signed Safe JSON");
    }
    return signedSafeJson;
  }
}

const PolicyVaultWallet = { WalletError, WalletState, KasWareAdapter, MockAdapter, createSigningUnavailableAdapter, normalizeNetwork, normalizePublicKeyToXOnly };
if (typeof window !== "undefined") window.PolicyVaultWallet = PolicyVaultWallet;
if (typeof module !== "undefined" && module.exports) module.exports = PolicyVaultWallet;
