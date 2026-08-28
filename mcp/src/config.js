"use strict";

/*
 * MCP adapter configuration (environment only — never CLI arguments, which
 * leak into process listings; never config files, which get committed).
 *
 * SECRET HANDLING RULES (docs/postlaunch/mcp-interface-spec.md §5):
 *   - the machine credential is read ONCE from POLICYVAULT_MCP_TOKEN, held
 *     in a closure, and deleted from process.env so no later code path
 *     (debug dumps, child processes, error reporters) can see it;
 *   - the token value NEVER appears in any error message, log line, stdout
 *     protocol message, or thrown Error — configuration failures describe
 *     the RULE that failed, never the value;
 *   - a URL carrying userinfo (user:pass@host) is refused outright: URLs
 *     routinely end up in diagnostics, so credentials are never allowed to
 *     ride inside one.
 *
 * TRANSPORT SECURITY: plaintext http:// is allowed ONLY for loopback hosts
 * (127.0.0.1 / ::1 / localhost). Anything else requires https:// unless the
 * operator explicitly sets POLICYVAULT_MCP_ALLOW_INSECURE_HTTP=1 — the
 * documented use is a private, already-encrypted operator transport
 * (e.g. WireGuard) where TLS termination happens elsewhere; on an open
 * network the override would expose the bearer credential, so it is never
 * the default and the refusal message says exactly which rule fired.
 */

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);

/* Server-side pre-filter shape for machine bearer credentials
 * (server/src/limits.js: /^Bearer\s+\S{20,300}$/). Enforcing the same
 * shape here means a malformed value fails fast locally without ever
 * being transmitted. */
const TOKEN_SHAPE = /^\S{20,300}$/;

function configError(code, message) {
  const e = new Error(`policyvault-mcp config: ${message}`);
  e.code = code;
  return e;
}

/*
 * loadMcpConfig(env) -> {
 *   baseUrl,            // normalized origin string, no trailing slash
 *   targetLabel,        // host:port — safe to include in diagnostics
 *   authorizationHeader,// () => "Bearer <token>" (closure; never a field)
 *   httpTimeoutMs,
 *   advertisedScopes,   // string[] | null (advisory narrowing only)
 *   debug
 * }
 * Throws (never partially succeeds) on any invalid input. The returned
 * object carries the credential ONLY behind the authorizationHeader
 * closure so accidental JSON.stringify / console.log of the config object
 * cannot leak it.
 */
function loadMcpConfig(env = process.env) {
  const rawUrl = env.POLICYVAULT_MCP_SERVER_URL;
  const rawToken = env.POLICYVAULT_MCP_TOKEN;
  // Remove the secret from the ambient environment immediately, even if
  // validation below fails — nothing after this line reads process.env.
  if (env === process.env) delete process.env.POLICYVAULT_MCP_TOKEN;

  if (typeof rawUrl !== "string" || rawUrl.trim() === "") {
    throw configError("CONFIG_URL_MISSING", "POLICYVAULT_MCP_SERVER_URL is required (e.g. https://app.example.org or http://127.0.0.1:8080)");
  }
  let url;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw configError("CONFIG_URL_INVALID", "POLICYVAULT_MCP_SERVER_URL is not a parseable URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw configError("CONFIG_URL_SCHEME", "POLICYVAULT_MCP_SERVER_URL must use http:// (loopback only) or https://");
  }
  if (url.username || url.password) {
    throw configError("CONFIG_URL_CREDENTIALS", "POLICYVAULT_MCP_SERVER_URL must not embed credentials (user:pass@) — use POLICYVAULT_MCP_TOKEN");
  }
  if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw configError("CONFIG_URL_PATH", "POLICYVAULT_MCP_SERVER_URL must be a bare origin (scheme://host[:port]) — the /api/v1 prefix is added by the adapter");
  }
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname) && env.POLICYVAULT_MCP_ALLOW_INSECURE_HTTP !== "1") {
    throw configError(
      "CONFIG_URL_PLAINTEXT_FORBIDDEN",
      "plaintext http:// to a non-loopback host would transmit the bearer credential unencrypted — use https://, or set POLICYVAULT_MCP_ALLOW_INSECURE_HTTP=1 ONLY for a private, separately-encrypted operator transport (e.g. WireGuard)"
    );
  }

  if (typeof rawToken !== "string" || rawToken === "") {
    throw configError("CONFIG_TOKEN_MISSING", "POLICYVAULT_MCP_TOKEN is required (a machine-identity bearer credential minted via POST /api/v1/identities)");
  }
  if (!TOKEN_SHAPE.test(rawToken)) {
    // Deliberately does NOT echo the value or say how it differs.
    throw configError("CONFIG_TOKEN_SHAPE", "POLICYVAULT_MCP_TOKEN does not match the machine-credential shape (20..300 non-whitespace characters)");
  }
  const token = rawToken;

  let httpTimeoutMs = 60000;
  if (env.POLICYVAULT_MCP_HTTP_TIMEOUT_MS !== undefined) {
    const n = Number(env.POLICYVAULT_MCP_HTTP_TIMEOUT_MS);
    if (!Number.isInteger(n) || n < 1000 || n > 600000) {
      throw configError("CONFIG_TIMEOUT_INVALID", "POLICYVAULT_MCP_HTTP_TIMEOUT_MS must be an integer between 1000 and 600000");
    }
    httpTimeoutMs = n;
  }

  let advertisedScopes = null;
  if (env.POLICYVAULT_MCP_SCOPES !== undefined && env.POLICYVAULT_MCP_SCOPES.trim() !== "") {
    advertisedScopes = env.POLICYVAULT_MCP_SCOPES.split(",").map((s) => s.trim()).filter(Boolean);
    for (const s of advertisedScopes) {
      if (!/^[a-z][a-z0-9:-]{1,63}$/.test(s)) {
        throw configError("CONFIG_SCOPES_INVALID", "POLICYVAULT_MCP_SCOPES must be a comma-separated list of scope names (e.g. read:vaults,request:build)");
      }
    }
  }

  return {
    baseUrl: url.origin,
    targetLabel: url.host,
    authorizationHeader: () => `Bearer ${token}`,
    httpTimeoutMs,
    advertisedScopes,
    debug: env.POLICYVAULT_MCP_DEBUG === "1"
  };
}

module.exports = { loadMcpConfig };
