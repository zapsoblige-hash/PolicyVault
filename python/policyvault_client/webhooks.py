"""Reference CONSUMER-side verifier for PolicyVault signed webhooks.

Port of the RULES in ``server/src/events-signing.js verifyWebhookSignature``
(the ``pv1`` scheme) and the exact recipe published in
``docs/postlaunch/webhooks-events-spec.md`` §8 — the VECTORS in
``tests/test_webhooks_verify.py`` are copied from
``sdk/test/postlaunch-webhooks-events.test.js`` / the JS reference
implementation, so agreeing on them is evidence, not a tautology (same
discipline as ``amounts.py`` vs. ``sdk/test/amounts.test.js`` — see that
module's docstring).

This is deliberately **outside** the "no transaction verification, no
financial authority" boundary in ``docs/postlaunch/python-client-spec.md``:
a webhook is an OBSERVATION notification, never authority
(``docs/postlaunch/webhooks-events-spec.md`` §1 — "The truth about hosted
state lives at the PolicyVault API; the truth about anything
consensus-visible lives at the Kaspa covenant. No PolicyVault component
consumes webhook data as input to any decision."). Verifying an HMAC over a
notification body carries none of the cross-runtime-disagreement hazard a
second consensus-relevant implementation would (§2 of that spec doc) — it is
a generic, well-understood integrity check, not a policy/financial
computation, so a Python port of it does not violate the "ONE authoritative
core" rule.

**PolicyVault never asks a consumer to trust a webhook body as authority.**
A successful verification here proves only "this delivery's bytes were
signed by someone holding the shared secret for this endpoint, recently" —
re-read the PolicyVault API (or the covenant) for anything that actually
matters for funds or policy state.
"""

from __future__ import annotations

import hmac
import re
import time
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "SIGNATURE_SCHEME",
    "DEFAULT_TOLERANCE_SECONDS",
    "WebhookVerifyResult",
    "verify_webhook_signature",
]

SIGNATURE_SCHEME = "pv1"
DEFAULT_TOLERANCE_SECONDS = 300

_TIMESTAMP_RE = re.compile(r"^\d{1,12}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class WebhookVerifyResult:
    """Mirrors the JS reference's ``{ ok, reason? , timestampSeconds? }``.

    ``reason`` (only set when ``ok`` is ``False``) is one of:
    ``MALFORMED_HEADER`` | ``UNSUPPORTED_SCHEME`` | ``SIGNATURE_MISMATCH`` |
    ``TIMESTAMP_OUT_OF_TOLERANCE`` — the same machine-readable set the JS
    implementation uses, so logs/alerts can be written once for both.
    """

    ok: bool
    reason: Optional[str] = None
    timestamp_seconds: Optional[int] = None


def _hmac_hex(secret: str, timestamp_seconds: int, raw_body: str) -> str:
    signed_input = f"{timestamp_seconds}.{raw_body}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), signed_input, "sha256").hexdigest()


def verify_webhook_signature(
    header: Optional[str],
    raw_body: str,
    secret: str,
    now_seconds: Optional[int] = None,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
) -> WebhookVerifyResult:
    """Verify one ``X-PolicyVault-Signature`` delivery header.

    ``raw_body`` MUST be the exact bytes received, decoded as UTF-8 — never
    a re-serialization of parsed JSON (the signature covers the literal
    bytes on the wire; re-serializing before verifying is exactly the
    storage-representation hazard ``core/model/canonical-json.js`` exists to
    avoid elsewhere in this project, and this function refuses to paper over
    it by re-encoding anything itself).

    This performs step 1 of the consumer recipe (webhooks-events-spec.md
    §8) only: authenticate + bound replay in time. Step 3 (dedup on
    ``X-PolicyVault-Event-Id``) is the caller's responsibility — at-least-
    once delivery makes legitimate redeliveries of the same event id
    normal, and this function has no notion of "already processed."
    """
    if not isinstance(header, str) or not isinstance(raw_body, str) or not isinstance(secret, str) or not secret:
        return WebhookVerifyResult(ok=False, reason="MALFORMED_HEADER")

    version: Optional[str] = None
    timestamp: Optional[str] = None
    signatures: list[str] = []
    for part in header.split(","):
        eq = part.find("=")
        if eq < 1:
            return WebhookVerifyResult(ok=False, reason="MALFORMED_HEADER")
        key = part[:eq].strip()
        value = part[eq + 1 :].strip()
        if key == "v":
            version = value
        elif key == "t":
            timestamp = value
        elif key == "s":
            signatures.append(value)
        # unknown keys are ignored (additive header evolution); unknown
        # VERSIONS are not (checked below).

    if version != SIGNATURE_SCHEME:
        return WebhookVerifyResult(ok=False, reason="UNSUPPORTED_SCHEME")
    if timestamp is None or not _TIMESTAMP_RE.match(timestamp) or not signatures:
        return WebhookVerifyResult(ok=False, reason="MALFORMED_HEADER")

    timestamp_seconds = int(timestamp)
    expected = _hmac_hex(secret, timestamp_seconds, raw_body)
    matched = False
    for candidate in signatures:
        if not _SIGNATURE_RE.match(candidate):
            continue
        # hmac.compare_digest is constant-time for equal-length strings —
        # the same property crypto.timingSafeEqual gives the JS side.
        if len(candidate) == len(expected) and hmac.compare_digest(candidate, expected):
            matched = True

    if not matched:
        return WebhookVerifyResult(ok=False, reason="SIGNATURE_MISMATCH")

    effective_now = int(time.time()) if now_seconds is None else now_seconds
    if abs(effective_now - timestamp_seconds) > tolerance_seconds:
        return WebhookVerifyResult(ok=False, reason="TIMESTAMP_OUT_OF_TOLERANCE")

    return WebhookVerifyResult(ok=True, timestamp_seconds=timestamp_seconds)
