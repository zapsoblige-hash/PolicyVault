"""``PolicyVaultClient`` — a thin, stdlib-only client of the PolicyVault
REST/Agent API.

WHAT THIS CLIENT DOES
    Transport. Closed request schemas. Integer/amount hygiene. Typed
    exceptions carrying the server's envelope verbatim. Idempotency-Key
    plumbing. schemaVersion pinning with a fail-closed handshake.

WHAT THIS CLIENT DOES NOT DO — and must never be extended to do
    Policy evaluation, governance classification, risk composition,
    successor-state derivation, fee/mass computation, covenant or
    intent-manifest verification, signer authorisation, reconciliation
    truth, or key custody. PolicyVault has ONE authoritative deterministic
    core (``core/``, JavaScript). Python has no port of it, so a Python
    caller who needs INDEPENDENT local verification of what the server
    returned must run the JS core — see the asymmetry statement in
    ``docs/postlaunch/python-client-spec.md`` and ``python/README.md``.

    AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
    THE COVENANT ENFORCES FINANCIAL AUTHORITY. SIGNERS RETAIN CUSTODY.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Optional

from . import schemas
from .errors import ProtocolError, ValidationError
from .schemas import (
    V4_WALLET_REQUEST_SCHEMA_VERSION,
    ApprovalSpec,
    GenesisSubmitSpec,
    ProposalApprovalSpec,
    ProposalSpec,
    SignatureSpec,
    SimulateV4Spec,
    WalletRequestV4Spec,
    coerce,
    require_hex64,
    require_id,
)
from .transport import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpTransport,
    Secret,
    new_idempotency_key,
)

__all__ = ["PolicyVaultClient", "ENV_BASE_URL", "ENV_TOKEN"]

ENV_BASE_URL = "POLICYVAULT_API_URL"
ENV_TOKEN = "POLICYVAULT_API_TOKEN"


class PolicyVaultClient:
    """A client bound to one PolicyVault deployment and (optionally) one
    machine credential.

    Args:
        base_url: server origin, e.g. ``https://app.policy-vault.org``.
            Defaults to ``$POLICYVAULT_API_URL``. ``/api/<version>`` is
            appended unless already present.
        token: a machine bearer credential (``pvmk_...``). Defaults to
            ``$POLICYVAULT_API_TOKEN``. Wrapped in a ``Secret`` immediately:
            it never appears in a repr, str, exception, or log line, and
            this package never logs at all.
        timeout: per-request socket timeout in seconds.
        auto_idempotency: when True, stamp a fresh random ``Idempotency-Key``
            on mutating POSTs that were not given one. **Off by default**,
            deliberately, for two reasons: (1) a fresh key per attempt buys
            no retry safety — reuse of ONE key across retries is what buys
            it, so pass ``idempotency_key=`` explicitly; (2) an
            idempotency-keyed POST makes the server persist a claim record,
            which would quietly give the zero-persistence ``simulate`` route
            a durable side effect. ``simulate`` is never auto-keyed even
            when this is on.
        trust_env_proxy: honour ``http_proxy``/``https_proxy``. Off by
            default so a proxy never sees the bearer credential.

    Retries: there are none, at any layer. A ``TransportError`` on a
    mutating POST is genuinely ambiguous; retry it yourself with the SAME
    ``Idempotency-Key`` you originally sent.
    """

    #: The v0.4 wallet-request body schema this build speaks.
    SCHEMA_VERSION = V4_WALLET_REQUEST_SCHEMA_VERSION

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        api_version: str = "v1",
        auto_idempotency: bool = False,
        trust_env_proxy: bool = False,
    ) -> None:
        resolved_url = base_url if base_url is not None else os.environ.get(ENV_BASE_URL)
        if not resolved_url:
            raise ValidationError(
                f"base_url is required — pass it explicitly or set ${ENV_BASE_URL}"
            )
        resolved_token = token if token is not None else os.environ.get(ENV_TOKEN)
        secret = Secret(resolved_token) if resolved_token else None
        self._transport = HttpTransport(
            resolved_url,
            token=secret,
            timeout=timeout,
            api_version=api_version,
            trust_env_proxy=trust_env_proxy,
        )
        self.auto_idempotency = bool(auto_idempotency)
        self._authenticated = secret is not None

    # -- introspection --------------------------------------------------------

    @property
    def api_root(self) -> str:
        return self._transport.api_root

    @property
    def authenticated(self) -> bool:
        """Whether a credential is configured. Never exposes the credential."""
        return self._authenticated

    def __repr__(self) -> str:
        return f"PolicyVaultClient(api_root={self.api_root!r}, authenticated={self.authenticated})"

    # -- plumbing -------------------------------------------------------------

    def _get(self, path: str, *, query: Optional[Mapping[str, Any]] = None, **kw) -> dict:
        return self._transport.request("GET", path, query=query, **kw).body

    def _post(
        self,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        *,
        idempotency_key: Optional[str] = None,
        auto_key: bool = True,
    ) -> dict:
        key = idempotency_key
        if key is None and auto_key and self.auto_idempotency:
            key = new_idempotency_key()
        return self._transport.request("POST", path, body=body or {}, idempotency_key=key).body

    @staticmethod
    def new_idempotency_key() -> str:
        """A fresh 256-bit key. Reuse ONE key across every retry of an operation."""
        return new_idempotency_key()

    # -- discovery / health ---------------------------------------------------

    def health(self) -> dict:
        """``GET /health`` — liveness. Public; no credential required."""
        return self._get("/health")

    def readiness(self) -> dict:
        """``GET /health/ready`` — readiness.

        A 503 here is a *well-formed answer* (``{ready:false, reason}``), not
        an error envelope, so it is returned rather than raised. Check
        ``["ready"]``.
        """
        return self._transport.request("GET", "/health/ready", allowed_non_2xx=(503,)).body

    def capabilities(self) -> dict:
        """``GET /capabilities`` — discovery document. Public.

        Generated from server code truth: apiVersion, supported covenant
        versions, v0.4 actions, the scope enum the server actually enforces,
        every schemaVersion string this build understands, live limits, and
        feature booleans.
        """
        return self._get("/capabilities")

    def assert_compatible(self, capabilities: Optional[Mapping[str, Any]] = None) -> dict:
        """Fail closed unless the server understands this client's pinned schemas.

        Call once at start-up. Compares ``SCHEMA_VERSION`` against the
        server's ``schemas.walletV4Request``. A mismatch raises rather than
        letting a body be reinterpreted under different semantics.
        """
        doc = capabilities if capabilities is not None else self.capabilities()
        server_schemas = doc.get("schemas")
        if not isinstance(server_schemas, Mapping):
            raise ProtocolError("capabilities document has no 'schemas' object")
        server_v4 = server_schemas.get("walletV4Request")
        if server_v4 != self.SCHEMA_VERSION:
            raise ProtocolError(
                f"schema mismatch: this client speaks {self.SCHEMA_VERSION!r} but the server "
                f"speaks {server_v4!r} — failing closed rather than guessing at compatibility"
            )
        return doc

    def network_status(self) -> dict:
        """``GET /network/status`` — requires ``read:network``."""
        return self._get("/network/status")

    def fuel(self, address: str) -> dict:
        """``GET /wallet/fuel/:address`` — ordinary (non-covenant) UTXOs.

        Requires ``read:network``.
        """
        from urllib.parse import quote

        schemas.require_address(address, "address")
        return self._get(f"/wallet/fuel/{quote(address, safe='')}")

    # -- vaults / audit / manifests -------------------------------------------

    def list_vaults(self) -> list:
        """``GET /vaults`` — server-side tenant-scoped. Requires ``read:vaults``."""
        return list(self._get("/vaults").get("vaults", []))

    def get_vault(self, vault_id: str) -> dict:
        """``GET /vaults/:id``. A foreign vault answers 404 (existence hidden)."""
        return self._get(f"/vaults/{require_hex64(vault_id, 'vaultId')}")

    def vault_status(self, vault_id: str) -> dict:
        """``GET /vaults/:id/status`` — dials the node; chain-confirms the live outpoint."""
        return self._get(f"/vaults/{require_hex64(vault_id, 'vaultId')}/status")

    def vault_audit(self, vault_id: str) -> list:
        """``GET /vaults/:id/audit``."""
        body = self._get(f"/vaults/{require_hex64(vault_id, 'vaultId')}/audit")
        return list(body.get("events", []))

    def audit(self, *, limit: Optional[int] = None) -> list:
        """``GET /audit`` — the tenant-scoped activity feed. Requires ``read:audit``."""
        query = {}
        if limit is not None:
            query["limit"] = schemas.parse_bounded_int(limit, "limit", minimum=1, maximum=1000)
        return list(self._get("/audit", query=query).get("events", []))

    def get_manifest(self, manifest_hash: str) -> dict:
        """``GET /manifests/:hash`` — the recorded intent manifest + LIVE re-verification.

        The server re-hashes and re-verifies on read (a stored verdict is a
        record of what the verifier said then; the truth NOW is recomputed).
        Requires ``read:manifests``.
        """
        return self._get(f"/manifests/{require_hex64(manifest_hash, 'manifestHash')}")

    # -- v0.4 wallet requests -------------------------------------------------

    def simulate(self, spec: Any) -> dict:
        """``POST /wallet/v4/simulate`` — DRY RUN. Requires ``request:build``.

        Runs the identical governance/risk/build/intent pipeline as the real
        route but persists nothing and consumes no gate. Never broadcasts.

        A well-formed request always answers 200; read ``simulation.ok``.
        ``ok:false`` carries ``refusalReason`` — a would-be refusal, not a
        transport failure. Malformed INPUT is a real 4xx and raises.

        Note: VM preflight is skipped by design (``vmPreflight.skipped``) —
        a dry run never asks for a signature. Fee/mass/successor values are
        still exact.

        Never auto-keyed for idempotency: a claim record would give this
        zero-persistence route a durable side effect.
        """
        body = coerce(spec, SimulateV4Spec).to_body()
        return self._post("/wallet/v4/simulate", body, auto_key=False)

    def build_request(self, spec: Any, *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /wallet/v4/requests`` — build ONE unsigned transition.

        Requires ``request:build`` (plus ``request:break-glass`` for
        ``ownerPause``/``ownerRecover``). Builders never broadcast.

        Pass ``idempotency_key`` and reuse it across retries: two concurrent
        identical calls sharing one key produce exactly one durable request.
        """
        body = coerce(spec, WalletRequestV4Spec).to_body()
        return self._post("/wallet/v4/requests", body, idempotency_key=idempotency_key)

    def create_vault(self, body: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /wallet/v4/create`` — genesis.

        The create route accepts two different documented body schemas (a
        canonical one and a browser-oriented "friendly" one whose
        server-side normalisation reads live DAA score from the node). This
        client does not model either as a closed schema — modelling the
        friendly schema would mean encoding KAS→sompi/period/approver
        normalisation rules that the server owns. The mapping is stamped
        with ``schemaVersion`` and forwarded as given; validate it against
        the API spec yourself.
        """
        if not isinstance(body, Mapping):
            raise ValidationError("create_vault expects a mapping matching the documented create schema")
        payload = dict(body)
        payload.setdefault("schemaVersion", self.SCHEMA_VERSION)
        return self._post("/wallet/v4/create", payload, idempotency_key=idempotency_key)

    def list_requests(
        self,
        *,
        vault_id: Optional[str] = None,
        open_only: bool = False,
    ) -> list:
        """``GET /wallet/v4/requests`` — durable request records.

        Server-side scoped to the principal's own requests; ``vault_id`` can
        only narrow. Requires ``read:requests``.
        """
        query: dict = {}
        if vault_id is not None:
            query["vaultId"] = require_hex64(vault_id, "vaultId")
        if open_only:
            query["open"] = "1"
        return list(self._get("/wallet/v4/requests", query=query).get("requests", []))

    def get_request(self, request_id: str) -> dict:
        """``GET /wallet/v4/requests/:id``."""
        return self._get(f"/wallet/v4/requests/{require_id(request_id, 'requestId')}")

    def approve_request(
        self, request_id: str, spec: Any, *, idempotency_key: Optional[str] = None
    ) -> dict:
        """``POST /wallet/v4/requests/:id/approvals`` — attach an M-of-N approval.

        Requires ``request:sign``. The signature comes from an external
        signer; this client holds no keys.
        """
        body = coerce(spec, ApprovalSpec).to_body()
        return self._post(
            f"/wallet/v4/requests/{require_id(request_id, 'requestId')}/approvals",
            body,
            idempotency_key=idempotency_key,
        )

    def finalize_request(
        self, request_id: str, spec: Any, *, idempotency_key: Optional[str] = None
    ) -> dict:
        """``POST /wallet/v4/requests/:id/signature`` — FINALIZE + VM preflight.

        Requires ``request:sign``. Finalizing does not broadcast and does not
        mark chain state changed.
        """
        body = coerce(spec, SignatureSpec).to_body()
        return self._post(
            f"/wallet/v4/requests/{require_id(request_id, 'requestId')}/signature",
            body,
            idempotency_key=idempotency_key,
        )

    def submit_request(self, request_id: str, *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /wallet/v4/requests/:id/submit`` — BROADCAST. Requires ``request:submit``.

        A 200 here is not proof of settlement. Success means: txid verified,
        old state consumed, expected successor observed, durable receipt
        persisted — which the server reconciles. Read the returned request
        state; do not infer settlement from the HTTP status.
        """
        return self._post(
            f"/wallet/v4/requests/{require_id(request_id, 'requestId')}/submit",
            {},
            idempotency_key=idempotency_key,
        )

    def genesis_submit(
        self, request_id: str, spec: Any, *, idempotency_key: Optional[str] = None
    ) -> dict:
        """``POST /wallet/v4/requests/:id/genesis-submit`` — broadcast genesis funding."""
        body = coerce(spec, GenesisSubmitSpec).to_body()
        return self._post(
            f"/wallet/v4/requests/{require_id(request_id, 'requestId')}/genesis-submit",
            body,
            idempotency_key=idempotency_key,
        )

    def reject_request(self, request_id: str, *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /wallet/v4/requests/:id/reject`` — cancel an open request.

        Requires ``request:reject``.
        """
        return self._post(
            f"/wallet/v4/requests/{require_id(request_id, 'requestId')}/reject",
            {},
            idempotency_key=idempotency_key,
        )

    # -- governance -----------------------------------------------------------

    def list_proposals(self, *, vault_id: Optional[str] = None, limit: Optional[int] = None) -> list:
        """``GET /governance/proposals``. Requires ``read:governance``."""
        query: dict = {}
        if vault_id is not None:
            query["vaultId"] = require_hex64(vault_id, "vaultId")
        if limit is not None:
            query["limit"] = schemas.parse_bounded_int(limit, "limit", minimum=1, maximum=200)
        return list(self._get("/governance/proposals", query=query).get("proposals", []))

    def get_proposal(self, proposal_id: str) -> dict:
        """``GET /governance/proposals/:id``. A foreign proposal answers 404."""
        body = self._get(f"/governance/proposals/{require_id(proposal_id, 'proposalId')}")
        return body.get("proposal", body)

    def create_proposal(self, spec: Any, *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /governance/proposals``. Requires ``governance:propose``.

        Proposals gate the HOSTED workflow for authority EXPANSIONS. They are
        not covenant authority: the covenant's own signature rules are
        unchanged either way.
        """
        body = coerce(spec, ProposalSpec).to_body()
        result = self._post("/governance/proposals", body, idempotency_key=idempotency_key)
        return result.get("proposal", result)

    def approve_proposal(
        self, proposal_id: str, spec: Any, *, idempotency_key: Optional[str] = None
    ) -> dict:
        """``POST /governance/proposals/:id/approvals``. Requires ``governance:approve``."""
        body = coerce(spec, ProposalApprovalSpec).to_body()
        result = self._post(
            f"/governance/proposals/{require_id(proposal_id, 'proposalId')}/approvals",
            body,
            idempotency_key=idempotency_key,
        )
        return result.get("proposal", result)

    def cancel_proposal(self, proposal_id: str, *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /governance/proposals/:id/cancel``. Requires ``governance:cancel``."""
        result = self._post(
            f"/governance/proposals/{require_id(proposal_id, 'proposalId')}/cancel",
            {},
            idempotency_key=idempotency_key,
        )
        return result.get("proposal", result)

    # -- risk -----------------------------------------------------------------

    def get_risk_evaluation(self, evaluation_id: str) -> dict:
        """``GET /risk/evaluations/:id`` — durable evidence. Requires ``read:risk``."""
        body = self._get(f"/risk/evaluations/{require_id(evaluation_id, 'evaluationId')}")
        return body.get("evaluation", body)

    def release_risk_evaluation(
        self, evaluation_id: str, *, idempotency_key: Optional[str] = None
    ) -> dict:
        """``POST /risk/evaluations/:id/release`` — release a REVIEW hold.

        Requires ``risk:release``. The acting signer can never release their
        own hold (enforced server-side from durable facts). A DENY decision
        is final and is not releasable.
        """
        result = self._post(
            f"/risk/evaluations/{require_id(evaluation_id, 'evaluationId')}/release",
            {},
            idempotency_key=idempotency_key,
        )
        return result.get("evaluation", result)

    # -- vault reconciliation -------------------------------------------------

    def reconcile_vault(self, vault_id: str, *, idempotency_key: Optional[str] = None) -> dict:
        """``POST /vaults/:id/reconcile`` — chain reconciliation. Requires ``vaults:reconcile``.

        Only proven chain reconciliation advances the live vault manifest;
        this asks the server to do it, and reports what it found.
        """
        return self._post(
            f"/vaults/{require_hex64(vault_id, 'vaultId')}/reconcile",
            {},
            idempotency_key=idempotency_key,
        )
