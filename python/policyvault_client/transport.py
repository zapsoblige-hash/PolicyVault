"""stdlib-only HTTP transport for the PolicyVault API.

Zero third-party runtime dependencies: ``urllib.request`` + ``json`` +
``secrets``. Deliberate properties, each of them a security decision rather
than an implementation detail:

* **Redirects are refused.** ``urllib`` would otherwise follow a 3xx and
  re-send the ``Authorization`` header to whatever host the redirect names.
  A PolicyVault API never redirects, so a redirect is treated as a protocol
  violation, not a hop to follow.
* **Environment proxies are ignored by default.** ``urllib`` honours
  ``http_proxy``/``https_proxy`` implicitly; a proxy would see the bearer
  credential. Opt in with ``trust_env_proxy=True`` if you actually run one.
* **No retries.** A retry of a mutating POST without the original
  ``Idempotency-Key`` can duplicate a spend. Retrying is the caller's
  explicit decision (see the README).
* **No logging.** This package never writes to ``logging``, stdout, or
  stderr, so a credential can never reach a log sink through it.
* **Floats can never reach the wire.** ``json_body`` walks the whole payload
  and refuses any float/complex/Decimal anywhere in it — PolicyVault bodies
  legitimately contain only strings, ints, bools, ``None``, lists, and
  objects.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, Optional

from .amounts import AmountError
from .errors import (
    ProtocolError,
    TransportError,
    ValidationError,
    api_error_from_response,
)

__all__ = [
    "Secret",
    "HttpTransport",
    "Response",
    "new_idempotency_key",
    "json_body",
    "DEFAULT_TIMEOUT_SECONDS",
    "USER_AGENT",
]

DEFAULT_TIMEOUT_SECONDS = 30.0
USER_AGENT = "policyvault-client/0.1.0 (python; stdlib-only)"

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class Secret:
    """A string that never appears in a repr, str, log line, or traceback.

    Used for machine bearer credentials. ``reveal()`` is the single, explicit
    way to read the value; it is called exactly once per request, when the
    ``Authorization`` header is assembled.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ValidationError("a credential must be a non-empty string")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<policyvault Secret: redacted>"

    def __str__(self) -> str:
        return "<policyvault Secret: redacted>"

    def __format__(self, spec: str) -> str:
        return self.__str__()

    def _digest(self) -> bytes:
        # Compared as digests so the comparison is constant-time and works for
        # any string (compare_digest refuses non-ASCII str inputs).
        return hashlib.sha256(self._value.encode("utf-8")).digest()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return secrets.compare_digest(self._digest(), other._digest())
        return NotImplemented

    def __hash__(self) -> int:  # pragma: no cover - not used as a key in practice
        return hash(("policyvault.Secret", len(self._value)))

    def __bool__(self) -> bool:
        return True


def new_idempotency_key() -> str:
    """A fresh 256-bit random ``Idempotency-Key``.

    Generate ONE key per logical operation and reuse it across every retry of
    that operation — that is what makes a retry safe. A new random key per
    attempt provides no replay protection at all.
    """
    return secrets.token_hex(32)


def _reject_floats(value: Any, path: str) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return
    if isinstance(value, (float, complex)):
        raise AmountError(
            f"amounts: {path} must never be a floating-point value (got {value!r}) — "
            "PolicyVault request bodies carry integers and exact decimal strings only"
        )
    module = type(value).__module__
    if module in ("decimal", "fractions"):
        raise AmountError(
            f"amounts: {path} must not be a {module}.{type(value).__name__} — "
            "use an int or an exact decimal string"
        )
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"{path}: JSON object keys must be strings, got {key!r}")
            _reject_floats(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")
        return
    raise ValidationError(
        f"{path}: {type(value).__name__} is not JSON-encodable in a PolicyVault request body"
    )


def json_body(payload: Mapping[str, Any]) -> bytes:
    """Encode a request body, refusing any inexact numeric anywhere inside it."""
    _reject_floats(payload, "body")
    return json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect so an Authorization header is never replayed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, N802
        raise ProtocolError(
            f"the API answered {code} with a redirect to {newurl!r}; PolicyVault never "
            "redirects and this client refuses to re-send credentials to another location"
        )


class Response:
    """A completed HTTP exchange: status, headers, parsed JSON body."""

    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: Mapping[str, str], body: Any) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"Response(status={self.status!r})"


class HttpTransport:
    """Minimal JSON-over-HTTP transport bound to one PolicyVault API root."""

    def __init__(
        self,
        base_url: str,
        *,
        token: Optional[Secret] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        api_version: str = "v1",
        user_agent: str = USER_AGENT,
        trust_env_proxy: bool = False,
    ) -> None:
        self.api_root = self._resolve_api_root(base_url, api_version)
        self._token = token
        self.timeout = self._check_timeout(timeout)
        self.user_agent = user_agent
        handlers: list[urllib.request.BaseHandler] = [_NoRedirects()]
        if not trust_env_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    # -- construction helpers -------------------------------------------------

    @staticmethod
    def _check_timeout(timeout: float) -> float:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValidationError("timeout must be a number of seconds")
        if not (timeout > 0) or timeout != timeout or timeout == float("inf"):
            raise ValidationError("timeout must be a finite positive number of seconds")
        return float(timeout)

    @staticmethod
    def _resolve_api_root(base_url: str, api_version: str) -> str:
        """``http://host:port`` -> ``http://host:port/api/v1``.

        A base_url that ALREADY ends with the exact suffix this method would
        append is accepted as-is; anything else gets the suffix appended. No
        guessing is involved either way.
        """
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValidationError(
                "base_url is required (e.g. 'https://app.policy-vault.org' or "
                "the POLICYVAULT_API_URL environment variable)"
            )
        if not isinstance(api_version, str) or not api_version:
            raise ValidationError("api_version must be a non-empty string")
        cleaned = base_url.strip().rstrip("/")
        parsed = urllib.parse.urlsplit(cleaned)
        if parsed.scheme not in ("http", "https"):
            raise ValidationError(
                f"base_url must be an http(s) URL, got scheme {parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise ValidationError("base_url must include a host")
        if parsed.query or parsed.fragment:
            raise ValidationError("base_url must not carry a query string or fragment")
        suffix = f"/api/{api_version}"
        if cleaned.endswith(suffix):
            return cleaned
        return cleaned + suffix

    # -- request --------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        allowed_non_2xx: tuple[int, ...] = (),
    ) -> Response:
        """Perform one request. Non-2xx raises, except statuses in
        ``allowed_non_2xx`` (used only by ``/health/ready``, where 503 is a
        normal, well-formed answer rather than an error envelope)."""
        if method not in ("GET", "POST"):
            raise ValidationError(f"unsupported HTTP method {method!r} (the API serves GET and POST)")
        if not path.startswith("/"):
            raise ValidationError(f"path must start with '/', got {path!r}")

        url = self.api_root + path
        if query:
            pairs = [(k, str(v)) for k, v in query.items() if v is not None]
            if pairs:
                url = f"{url}?{urllib.parse.urlencode(pairs)}"

        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
            # Never send an ambient browser credential from this client.
            "Connection": "close",
        }
        if method == "POST":
            data = json_body(body if body is not None else {})
            headers["Content-Type"] = "application/json"
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token.reveal()}"
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ValidationError("idempotency_key must be a non-empty string")
            if len(idempotency_key) > 255 or any(ord(c) < 0x21 or ord(c) > 0x7E for c in idempotency_key):
                raise ValidationError(
                    "idempotency_key must be 1..255 printable ASCII characters with no spaces"
                )
            headers["Idempotency-Key"] = idempotency_key

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.status
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                response_headers = {k.lower(): v for k, v in response.headers.items()}
        except urllib.error.HTTPError as http_error:
            status = http_error.code
            try:
                raw = http_error.read(_MAX_RESPONSE_BYTES + 1)
            finally:
                http_error.close()
            response_headers = {k.lower(): v for k, v in (http_error.headers or {}).items()}
        except ProtocolError:
            raise
        except urllib.error.URLError as url_error:
            # Deliberately reports the reason, never the request headers.
            raise TransportError(f"{method} {path} failed before a response: {url_error.reason}") from None
        except (TimeoutError, OSError) as os_error:
            raise TransportError(f"{method} {path} failed before a response: {os_error}") from None

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ProtocolError(f"{method} {path} answered with a response larger than 8 MiB")

        parsed: Any = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ProtocolError(
                    f"{method} {path} answered {status} with a body that is not valid JSON"
                ) from None

        if 200 <= status < 300 or status in allowed_non_2xx:
            if parsed is not None and not isinstance(parsed, Mapping):
                raise ProtocolError(
                    f"{method} {path} answered {status} with a JSON body that is not an object"
                )
            return Response(status, response_headers, parsed if parsed is not None else {})

        raise api_error_from_response(status, parsed, method=method, path=path)

    def __repr__(self) -> str:
        # The credential is never part of this — see the redaction test.
        return (
            f"HttpTransport(api_root={self.api_root!r}, timeout={self.timeout!r}, "
            f"authenticated={self._token is not None})"
        )
