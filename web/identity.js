/*
 * PolicyVault browser identity flow.
 *
 * Normal users work with Kaspa wallet addresses (kaspatest:...). This
 * module resolves them to the canonical covenant identities by calling the
 * backend's single address->pubkey boundary (which uses the authoritative
 * rusty-kaspa parser) — the browser performs NO address decoding of its
 * own. All errors are user-facing and fail closed BEFORE any transaction
 * request is built.
 */

function identityError(code, message) {
  const e = new Error(message || "Enter a valid Kaspa wallet address.");
  e.identityCode = code;
  return e;
}

/* Resolve one wallet address -> { address, xOnlyPubkey, network, addressType }. */
async function resolveAddress(apiBase, addressInput) {
  const trimmed = String(addressInput ?? "").trim();
  if (!trimmed) {
    throw identityError("ADDRESS_REQUIRED", "Enter a valid Kaspa wallet address.");
  }
  let r, j;
  try {
    r = await fetch(`${apiBase}/identity/resolve-address`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address: trimmed })
    });
    j = await r.json();
  } catch (e) {
    throw identityError("RESOLVE_UNAVAILABLE", "Could not validate the address (server unreachable). Try again.");
  }
  if (!r.ok || !j.identity) {
    throw identityError(j?.error?.code || "ADDRESS_INVALID", j?.error?.message || "Enter a valid Kaspa wallet address.");
  }
  return j.identity;
}

/*
 * Resolve every identity needed to create a vault. The OWNER is never
 * typed: it comes from the connected wallet — and the wallet's own pubkey
 * (adapter.getPublicKeyXOnly) must match the connected address's payload,
 * else fail closed (account-switch race / provider mismatch).
 */
async function resolveCreateIdentities(apiBase, adapter, { delegateAddress, recipientAddresses }) {
  const ownerAddress = adapter.getActiveAddress();
  if (!ownerAddress) {
    throw identityError("OWNER_DISCONNECTED", "Connect a wallet first — the connected wallet is the vault owner.");
  }
  const owner = await resolveAddress(apiBase, ownerAddress);
  const walletXOnly = await adapter.getPublicKeyXOnly();
  if (owner.xOnlyPubkey !== walletXOnly) {
    throw identityError("OWNER_MISMATCH", "The connected wallet account and its public key do not match — reconnect the wallet and try again.");
  }

  let delegate;
  try {
    delegate = await resolveAddress(apiBase, delegateAddress);
  } catch (e) {
    throw identityError(e.identityCode, `Delegate wallet address: ${e.message}`);
  }

  const list = (recipientAddresses || []).map((a) => String(a ?? "").trim()).filter(Boolean);
  if (list.length < 1 || list.length > 3) {
    throw identityError("RECIPIENTS_REQUIRED", "Enter 1 to 3 allowed recipient wallet addresses.");
  }
  const recipients = [];
  for (let i = 0; i < list.length; i++) {
    try {
      recipients.push(await resolveAddress(apiBase, list[i]));
    } catch (e) {
      throw identityError(e.identityCode, `Allowed recipient ${i + 1}: ${e.message}`);
    }
  }

  return { owner, delegate, recipients };
}

const PolicyVaultIdentity = { resolveAddress, resolveCreateIdentities, identityError };
if (typeof window !== "undefined") window.PolicyVaultIdentity = PolicyVaultIdentity;
if (typeof module !== "undefined" && module.exports) module.exports = PolicyVaultIdentity;
