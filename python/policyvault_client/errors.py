"""Typed exceptions for the PolicyVault Python client.

Every server refusal reaches the caller as an ``ApiError`` (or a subclass)
that carries the server's ``{"error": {"code", "message", ...}}`` envelope
**verbatim** in ``.envelope`` — including route-specific extras such as
``request``, ``intent``, and ``idempotency``. The client never rewrites,
summarises, or re-classifies a server decision; it only picks a Python
class so callers can branch with ``except``.

Nothing in this module ever contains a bearer credential: the token travels
only in a request header, and no exception here is constructed from request
headers.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

__all__ = [
    "PolicyVaultError",
    "ValidationError",
    "TransportError",
    "ProtocolError",
    "ApiError",
    "AuthenticationError",
    "ScopeError",
    "NotFoundError",
    "ConflictError",
    "IdempotencyConflictError",
    "IdempotencyInProgressError",
    "SchemaVersionError",
    "UnprocessableError",
    "RateLimitError",
    "ServerError",
    "api_error_from_response",
]


class PolicyVaultError(Exception):
    """Base class for every error this client raises."""


class ValidationError(PolicyVaultError):
    """A request was refused locally, before any network I/O.

    Closed-schema violation, unknown field, bad amount, bad hex. Nothing was
    sent; nothing durable happened anywhere.
    """


class TransportError(PolicyVaultError):
    """No HTTP response was obtained (DNS, connect, TLS, timeout, reset).

    IMPORTANT: a transport failure on a mutating POST is *ambiguous* — the
    server may or may not have executed it. This client does not retry
    (see the README). Retry only with the SAME ``Idempotency-Key`` you
    originally sent, which is exactly what makes the retry safe.
    """


class ProtocolError(PolicyVaultError):
    """A response arrived but was not a well-formed PolicyVault answer.

    Non-JSON body, a JSON body that is not an object, a non-2xx without an
    ``error`` envelope, or a redirect (which this client always refuses so
    an ``Authorization`` header can never be replayed to another host).
    """


class ApiError(PolicyVaultError):
    """A structured refusal from the PolicyVault API."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        envelope: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
        method: str = "",
        path: str = "",
    ) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        #: The server's ``error`` object, verbatim (extras included).
        self.envelope: Mapping[str, Any] = dict(envelope or {})
        #: The full parsed response body, verbatim.
        self.body: Mapping[str, Any] = dict(body or {})
        self.method = method
        self.path = path

    @property
    def extra(self) -> Mapping[str, Any]:
        """Route-specific fields the server attached to the envelope.

        e.g. ``request`` / ``intent`` on a v4 build refusal, ``idempotency``
        on a replayed error.
        """
        return {k: v for k, v in self.envelope.items() if k not in ("code", "message")}

    @property
    def replayed(self) -> bool:
        """True when this error is an idempotent replay of an earlier attempt."""
        idem = self.envelope.get("idempotency")
        return bool(isinstance(idem, Mapping) and idem.get("replayed") is True)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"{type(self).__name__}(status={self.status!r}, code={self.code!r}, "
            f"message={self.message!r})"
        )


class AuthenticationError(ApiError):
    """401 — no credential, or a credential that did not resolve."""


class ScopeError(ApiError):
    """403 — the credential resolved but is not permitted this operation.

    Covers ``SCOPE_FORBIDDEN``, ``MACHINE_IDENTITY_ROUTE_FORBIDDEN``, and
    the origin-wall refusals (``ORIGIN_REQUIRED`` / ``ORIGIN_FORBIDDEN``).
    """


class NotFoundError(ApiError):
    """404 — no such route, or an object this principal may not observe.

    PolicyVault deliberately hides the existence of foreign objects, so a
    404 does not prove the object does not exist.
    """


class ConflictError(ApiError):
    """409 — a state conflict (stale predecessor, claim conflict, ...)."""


class IdempotencyConflictError(ConflictError):
    """409 ``IDEMPOTENCY_KEY_CONFLICT`` — this key was already used for a
    *different* request. The handler was never called."""


class IdempotencyInProgressError(ConflictError):
    """409 ``IDEMPOTENCY_IN_PROGRESS`` — an identical request holding this
    key is still executing. The handler was never called a second time."""


class SchemaVersionError(ApiError):
    """422 ``SCHEMA_VERSION_UNSUPPORTED`` — the server fails closed rather
    than reinterpreting a version string it does not know."""


class UnprocessableError(ApiError):
    """422 — a well-formed request the server refuses on its merits."""


class RateLimitError(ApiError):
    """429 — a rate limit or concurrency bound. Refusals are pure."""


class ServerError(ApiError):
    """5xx — an infrastructure failure.

    On a POST carrying an ``Idempotency-Key``, the server RELEASES the claim
    for these (transient) outcomes, so retrying with the same key gets a
    genuinely fresh attempt.
    """


_BY_CODE = {
    "IDEMPOTENCY_KEY_CONFLICT": IdempotencyConflictError,
    "IDEMPOTENCY_IN_PROGRESS": IdempotencyInProgressError,
    "SCHEMA_VERSION_UNSUPPORTED": SchemaVersionError,
}


def _class_for(status: int, code: str) -> type:
    by_code = _BY_CODE.get(code)
    if by_code is not None:
        return by_code
    if status == 401:
        return AuthenticationError
    if status == 403:
        return ScopeError
    if status == 404:
        return NotFoundError
    if status == 409:
        return ConflictError
    if status == 422:
        return UnprocessableError
    if status == 429:
        return RateLimitError
    if status >= 500:
        return ServerError
    return ApiError


def api_error_from_response(
    status: int,
    body: Any,
    *,
    method: str = "",
    path: str = "",
) -> PolicyVaultError:
    """Build the right exception from a non-2xx response body.

    A non-2xx WITHOUT a well-formed ``error`` envelope is a ``ProtocolError``:
    the client refuses to invent a code for something the server did not say.
    """
    if not isinstance(body, Mapping):
        return ProtocolError(
            f"{method} {path} answered {status} with a non-object body — refusing to interpret it"
        )
    envelope = body.get("error")
    if not isinstance(envelope, Mapping):
        return ProtocolError(
            f"{method} {path} answered {status} without an 'error' envelope — refusing to interpret it"
        )
    code = envelope.get("code")
    message = envelope.get("message")
    if not isinstance(code, str) or not isinstance(message, str):
        return ProtocolError(
            f"{method} {path} answered {status} with a malformed 'error' envelope — refusing to interpret it"
        )
    cls = _class_for(status, code)
    return cls(
        status,
        code,
        message,
        envelope=envelope,
        body=body,
        method=method,
        path=path,
    )
