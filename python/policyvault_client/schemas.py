"""Closed request schemas for the PolicyVault REST/Agent API.

Every mutating body this client sends is built from one of the dataclasses
here. There is no path that forwards an arbitrary ``dict`` to the server: a
mapping handed to a client method goes through ``from_mapping``, which
**refuses unknown fields** rather than passing them through. A field the
server does not know is a client bug or a version mismatch, and silently
forwarding it would hide both.

SCOPE OF VALIDATION — deliberately narrow (see
``docs/postlaunch/python-client-spec.md``):

* field NAMES and presence/absence (closed schema),
* carrier TYPES and integer hygiene (``amounts.py``),
* lexical SHAPE where the server's own input check is lexical too
  (64-hex vault ids and x-only keys, even-length hex, printable text).

NOT validated here, on purpose, because doing so would be a second
implementation of something the authoritative core decides:

* whether an address belongs to the server's configured network (the
  required ``kaspa:``/``kaspatest:`` prefix is derived server-side from
  ``config.networkId``; this client never decides a network),
* whether an amount is within policy, budget, threshold, or reserve,
* whether an action is governed, risk-relevant, or authorised for a signer,
* anything about successor state, fees, mass, or covenant bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field, fields as dataclass_fields
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from .amounts import parse_bounded_int, parse_index, reject_float, to_sompi_string
from .errors import ValidationError

__all__ = [
    "V4_WALLET_REQUEST_SCHEMA_VERSION",
    "V4_ACTIONS",
    "BREAK_GLASS_ACTIONS",
    "Outpoint",
    "FuelInput",
    "AgentPolicyInput",
    "AgentSpendParams",
    "AddAgentParams",
    "RemoveAgentParams",
    "RotateAgentParams",
    "RePolicyAgentParams",
    "OwnerSetAgentRootParams",
    "OwnerSetApproversParams",
    "OwnerTopUpParams",
    "OwnerTopUpReserveParams",
    "OwnerPauseParams",
    "OwnerUnpauseParams",
    "OwnerRecoverParams",
    "PARAMS_BY_ACTION",
    "WalletRequestV4Spec",
    "SimulateV4Spec",
    "ApprovalSpec",
    "SignatureSpec",
    "GenesisSubmitSpec",
    "ProposalSpec",
    "ProposalApprovalSpec",
    "coerce",
]

#: server/src/api-version.js V4_WALLET_REQUEST_SCHEMA_VERSION. Stamped on
#: every v0.4 wallet-request body this client sends. If the server does not
#: recognise it, the route fails closed with 422 SCHEMA_VERSION_UNSUPPORTED
#: — it is never reinterpreted under new semantics.
V4_WALLET_REQUEST_SCHEMA_VERSION = "policyvault-wallet-v4-request/v1"

#: sdk/src/wallet-requests-v4.js ROLE_BY_ACTION. Mirrored for closed-schema
#: dispatch only; the server re-derives the role and the authorisation.
V4_ACTIONS = {
    "agentSpend": "agent",
    "ownerSetAgentRoot": "owner",
    "ownerSetApprovers": "owner",
    "ownerTopUp": "owner",
    "ownerTopUpReserve": "owner",
    "ownerPause": "owner",
    "ownerUnpause": "owner",
    "ownerRecover": "owner",
    "addAgent": "owner",
    "removeAgent": "owner",
    "rotateAgent": "owner",
    "rePolicyAgent": "owner",
}

#: server/src/scopes.js BREAK_GLASS_ACTIONS — these additionally require the
#: ``request:break-glass`` scope on a machine credential.
BREAK_GLASS_ACTIONS = frozenset({"ownerPause", "ownerRecover"})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]*$")


# --------------------------------------------------------------------------
# lexical validators
# --------------------------------------------------------------------------


def _require_hex64(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise ValidationError(
            f"{field} must be 32-byte lowercase hex (64 chars, [0-9a-f]); got {value!r}"
        )
    return value


def _require_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) % 2 or not _HEX.match(value):
        raise ValidationError(
            f"{field} must be non-empty even-length lowercase hex; got {value!r}"
        )
    return value


def _require_address(value: Any, field: str) -> str:
    """A Kaspa bech32m address in *shape* only.

    The network prefix (``kaspa:`` vs ``kaspatest:``) is decided by the
    SERVER from its configured network; a client that decided it locally
    would be reimplementing a network gate, and would silently disagree with
    a server configured differently.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty address string")
    if value != value.strip() or any(c.isspace() for c in value):
        raise ValidationError(f"{field} must not contain whitespace; got {value!r}")
    if ":" not in value:
        raise ValidationError(
            f"{field} must be a prefixed Kaspa address (e.g. 'kaspatest:...'); got {value!r}"
        )
    return value


def _require_text(value: Any, field: str, *, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters")
    return value


def _require_id(value: Any, field: str) -> str:
    """A server-issued opaque identifier used in a URL path segment."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty identifier string")
    if not re.match(r"^[A-Za-z0-9._~-]{1,128}$", value):
        raise ValidationError(
            f"{field} must be 1..128 characters of [A-Za-z0-9._~-] (a server-issued id); got {value!r}"
        )
    return value


# --------------------------------------------------------------------------
# closed-schema base
# --------------------------------------------------------------------------


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


class ClosedSchema:
    """Base for every request body: validated on construction, closed on input."""

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:  # pragma: no cover - overridden everywhere
        raise NotImplementedError

    def to_body(self) -> dict:  # pragma: no cover - overridden everywhere
        raise NotImplementedError

    @classmethod
    def field_names(cls) -> tuple[str, ...]:
        names = []
        for f in dataclass_fields(cls):  # type: ignore[arg-type]
            names.append(f.name)
            camel = _camel(f.name)
            if camel != f.name:
                names.append(camel)
        return tuple(names)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]):
        """Build from a mapping, REFUSING any field this schema does not define.

        Accepts either the Python field name (``vault_id``) or its wire name
        (``vaultId``); anything else is a hard local refusal.
        """
        if not isinstance(mapping, Mapping):
            raise ValidationError(
                f"{cls.__name__} expects a mapping or a {cls.__name__} instance, "
                f"got {type(mapping).__name__}"
            )
        known = {f.name: f.name for f in dataclass_fields(cls)}  # type: ignore[arg-type]
        known.update({_camel(name): name for name in list(known)})
        kwargs: dict[str, Any] = {}
        unknown = []
        for key, value in mapping.items():
            target = known.get(key)
            if target is None:
                unknown.append(key)
                continue
            if target in kwargs:
                raise ValidationError(
                    f"{cls.__name__}: field {target!r} was supplied twice "
                    "(both snake_case and camelCase)"
                )
            kwargs[target] = value
        if unknown:
            raise ValidationError(
                f"{cls.__name__} refuses unknown field(s) {sorted(unknown)!r}; "
                f"accepted fields are {sorted(set(known))!r}. PolicyVault clients never "
                "forward arbitrary fields to the API."
            )
        return cls(**kwargs)


def coerce(value: Any, schema: type):
    """Return ``value`` if it is already ``schema``; otherwise close it."""
    if isinstance(value, schema):
        return value
    if isinstance(value, Mapping):
        return schema.from_mapping(value)
    raise ValidationError(
        f"expected a {schema.__name__} or a mapping of its fields, got {type(value).__name__}"
    )


def _drop_none(body: dict) -> dict:
    return {k: v for k, v in body.items() if v is not None}


# --------------------------------------------------------------------------
# shared value objects
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Outpoint(ClosedSchema):
    transaction_id: str
    index: int

    def validate(self) -> None:
        _require_hex64(self.transaction_id, "outpoint.transactionId")
        parse_index(self.index, "outpoint.index")

    def to_body(self) -> dict:
        return {"transactionId": self.transaction_id, "index": parse_index(self.index, "outpoint.index")}


@dataclass(frozen=True)
class FuelInput(ClosedSchema):
    """An ordinary (non-covenant) UTXO that pays the network fee."""

    outpoint: Any
    amount: Any
    script_public_key_hex: str

    def validate(self) -> None:
        coerce(self.outpoint, Outpoint)
        to_sompi_string(self.amount, "fuel.amount")
        _require_hex(self.script_public_key_hex, "fuel.scriptPublicKeyHex")

    def to_body(self) -> dict:
        return {
            "outpoint": coerce(self.outpoint, Outpoint).to_body(),
            "amount": to_sompi_string(self.amount, "fuel.amount"),
            "scriptPublicKeyHex": self.script_public_key_hex,
        }


@dataclass(frozen=True)
class AgentPolicyInput(ClosedSchema):
    """A delegate/AI-agent policy as the API accepts it.

    Field names and their meanings come from ``core/model/agent-merkle-v4.js``
    ``normalizeAgentPolicyV4``. This client checks carriers only: the server
    normalises, hashes, and enforces every one of these values.
    """

    agent_pk: str
    max_per_spend: Any
    period_budget: Any
    period_length_daa: Any
    period_start_daa: Any
    period_spent: Any
    approval_threshold: Any
    agent_max_fee_per_tx: Any
    recipients: Sequence[str]

    def validate(self) -> None:
        _require_hex64(self.agent_pk, "agent.agentPk")
        for name in (
            "max_per_spend",
            "period_budget",
            "period_length_daa",
            "period_start_daa",
            "period_spent",
            "approval_threshold",
            "agent_max_fee_per_tx",
        ):
            to_sompi_string(getattr(self, name), f"agent.{_camel(name)}")
        if not isinstance(self.recipients, (list, tuple)) or not self.recipients:
            raise ValidationError("agent.recipients must be a non-empty list of x-only keys")
        for i, recipient in enumerate(self.recipients):
            _require_hex64(recipient, f"agent.recipients[{i}]")

    def to_body(self) -> dict:
        body = {"agentPk": self.agent_pk}
        for name in (
            "max_per_spend",
            "period_budget",
            "period_length_daa",
            "period_start_daa",
            "period_spent",
            "approval_threshold",
            "agent_max_fee_per_tx",
        ):
            body[_camel(name)] = to_sompi_string(getattr(self, name), f"agent.{_camel(name)}")
        body["recipients"] = list(self.recipients)
        return body


# --------------------------------------------------------------------------
# per-action params (closed)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _ParamsBase(ClosedSchema):
    pass


def _fuel_body(fuel: Any) -> dict:
    return {} if fuel is None else {"fuel": coerce(fuel, FuelInput).to_body()}


@dataclass(frozen=True)
class AgentSpendParams(_ParamsBase):
    agent_pk: str
    pay_amount_sompi: Any
    recipient: str
    periods_elapsed: Optional[Any] = None
    reserve_consumed_sompi: Optional[Any] = None
    fuel: Optional[Any] = None

    def validate(self) -> None:
        _require_hex64(self.agent_pk, "params.agentPk")
        to_sompi_string(self.pay_amount_sompi, "params.payAmountSompi")
        _require_hex64(self.recipient, "params.recipient")
        if self.periods_elapsed is not None:
            to_sompi_string(self.periods_elapsed, "params.periodsElapsed")
        if self.reserve_consumed_sompi is not None:
            to_sompi_string(self.reserve_consumed_sompi, "params.reserveConsumedSompi")
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        body = {
            "agentPk": self.agent_pk,
            "payAmountSompi": to_sompi_string(self.pay_amount_sompi, "params.payAmountSompi"),
            "recipient": self.recipient,
        }
        if self.periods_elapsed is not None:
            body["periodsElapsed"] = to_sompi_string(self.periods_elapsed, "params.periodsElapsed")
        if self.reserve_consumed_sompi is not None:
            body["reserveConsumedSompi"] = to_sompi_string(
                self.reserve_consumed_sompi, "params.reserveConsumedSompi"
            )
        body.update(_fuel_body(self.fuel))
        return body


@dataclass(frozen=True)
class AddAgentParams(_ParamsBase):
    agent: Any
    fuel: Optional[Any] = None

    def validate(self) -> None:
        coerce(self.agent, AgentPolicyInput)
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return {"agent": coerce(self.agent, AgentPolicyInput).to_body(), **_fuel_body(self.fuel)}


@dataclass(frozen=True)
class RemoveAgentParams(_ParamsBase):
    agent_pk: str
    fuel: Optional[Any] = None

    def validate(self) -> None:
        _require_hex64(self.agent_pk, "params.agentPk")
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return {"agentPk": self.agent_pk, **_fuel_body(self.fuel)}


@dataclass(frozen=True)
class RotateAgentParams(_ParamsBase):
    """Replace the agent identified by ``agent_pk`` with ``agent``."""

    agent_pk: str
    agent: Any
    fuel: Optional[Any] = None

    def validate(self) -> None:
        _require_hex64(self.agent_pk, "params.agentPk")
        coerce(self.agent, AgentPolicyInput)
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return {
            "agentPk": self.agent_pk,
            "agent": coerce(self.agent, AgentPolicyInput).to_body(),
            **_fuel_body(self.fuel),
        }


@dataclass(frozen=True)
class RePolicyAgentParams(RotateAgentParams):
    """Keep the agent key, replace its policy (the server pins ``agentPk``)."""


@dataclass(frozen=True)
class OwnerSetAgentRootParams(_ParamsBase):
    """The FULL new agent set — this action replaces the registry outright."""

    new_agents: Sequence[Any]
    fuel: Optional[Any] = None

    def validate(self) -> None:
        if not isinstance(self.new_agents, (list, tuple)):
            raise ValidationError("params.newAgents must be a list of agent policies")
        for agent in self.new_agents:
            coerce(agent, AgentPolicyInput)
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return {
            "newAgents": [coerce(a, AgentPolicyInput).to_body() for a in self.new_agents],
            **_fuel_body(self.fuel),
        }


@dataclass(frozen=True)
class OwnerSetApproversParams(_ParamsBase):
    approval_m: Any
    approvers: Optional[Sequence[str]] = None
    approver_slots: Optional[Sequence[str]] = None
    fuel: Optional[Any] = None

    def validate(self) -> None:
        to_sompi_string(self.approval_m, "params.newApprovers.approvalM")
        if self.approvers is None and self.approver_slots is None:
            raise ValidationError(
                "params.newApprovers requires 'approvers' or 'approver_slots' (the new approver set)"
            )
        for name in ("approvers", "approver_slots"):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, (list, tuple)):
                raise ValidationError(f"params.newApprovers.{_camel(name)} must be a list of x-only keys")
            for i, key in enumerate(value):
                _require_hex64(key, f"params.newApprovers.{_camel(name)}[{i}]")
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        new_approvers: dict = {
            "approvalM": to_sompi_string(self.approval_m, "params.newApprovers.approvalM")
        }
        if self.approvers is not None:
            new_approvers["approvers"] = list(self.approvers)
        if self.approver_slots is not None:
            new_approvers["approverSlots"] = list(self.approver_slots)
        return {"newApprovers": new_approvers, **_fuel_body(self.fuel)}


@dataclass(frozen=True)
class OwnerTopUpParams(_ParamsBase):
    top_up_amount_sompi: Any
    fuel: Optional[Any] = None

    def validate(self) -> None:
        to_sompi_string(self.top_up_amount_sompi, "params.topUpAmountSompi")
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return {
            "topUpAmountSompi": to_sompi_string(self.top_up_amount_sompi, "params.topUpAmountSompi"),
            **_fuel_body(self.fuel),
        }


@dataclass(frozen=True)
class OwnerTopUpReserveParams(_ParamsBase):
    top_up_reserve_amount_sompi: Any
    fuel: Optional[Any] = None

    def validate(self) -> None:
        to_sompi_string(self.top_up_reserve_amount_sompi, "params.topUpReserveAmountSompi")
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return {
            "topUpReserveAmountSompi": to_sompi_string(
                self.top_up_reserve_amount_sompi, "params.topUpReserveAmountSompi"
            ),
            **_fuel_body(self.fuel),
        }


@dataclass(frozen=True)
class _FuelOnlyParams(_ParamsBase):
    fuel: Optional[Any] = None

    def validate(self) -> None:
        if self.fuel is not None:
            coerce(self.fuel, FuelInput)

    def to_body(self) -> dict:
        return _fuel_body(self.fuel)


@dataclass(frozen=True)
class OwnerPauseParams(_FuelOnlyParams):
    """BREAK GLASS — freeze. Bypasses governance and risk by construction."""


@dataclass(frozen=True)
class OwnerUnpauseParams(_FuelOnlyParams):
    pass


@dataclass(frozen=True)
class OwnerRecoverParams(_FuelOnlyParams):
    """BREAK GLASS — terminal recovery. The vault is closed afterwards."""


PARAMS_BY_ACTION: Mapping[str, type] = {
    "agentSpend": AgentSpendParams,
    "addAgent": AddAgentParams,
    "removeAgent": RemoveAgentParams,
    "rotateAgent": RotateAgentParams,
    "rePolicyAgent": RePolicyAgentParams,
    "ownerSetAgentRoot": OwnerSetAgentRootParams,
    "ownerSetApprovers": OwnerSetApproversParams,
    "ownerTopUp": OwnerTopUpParams,
    "ownerTopUpReserve": OwnerTopUpReserveParams,
    "ownerPause": OwnerPauseParams,
    "ownerUnpause": OwnerUnpauseParams,
    "ownerRecover": OwnerRecoverParams,
}


def _params_body(action: str, params: Any) -> dict:
    """Close ``params`` against the schema for ``action``.

    An action this client does not know FAILS CLOSED here rather than
    forwarding an unvalidated dict — the server would also refuse it, but a
    local refusal costs no request and leaks no intent.
    """
    schema = PARAMS_BY_ACTION.get(action)
    if schema is None:
        raise ValidationError(
            f"unknown v0.4 action {action!r} — this client build knows "
            f"{sorted(PARAMS_BY_ACTION)!r}. Unknown versions/actions fail closed."
        )
    return coerce(params, schema).to_body()


# --------------------------------------------------------------------------
# request bodies
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class WalletRequestV4Spec(ClosedSchema):
    """``POST /wallet/v4/requests`` — build one unsigned v0.4 transition."""

    vault_id: str
    action: str
    signer_address: str
    params: Any = dataclass_field(default_factory=dict)
    proposal_id: Optional[str] = None
    risk_evaluation_id: Optional[str] = None

    def validate(self) -> None:
        _require_hex64(self.vault_id, "vaultId")
        _require_text(self.action, "action", max_len=64)
        _require_address(self.signer_address, "signerAddress")
        _params_body(self.action, self.params)
        if self.proposal_id is not None:
            _require_id(self.proposal_id, "proposalId")
        if self.risk_evaluation_id is not None:
            _require_id(self.risk_evaluation_id, "riskEvaluationId")

    def to_body(self) -> dict:
        return _drop_none(
            {
                "schemaVersion": V4_WALLET_REQUEST_SCHEMA_VERSION,
                "vaultId": self.vault_id,
                "action": self.action,
                "params": _params_body(self.action, self.params),
                "signerAddress": self.signer_address,
                "proposalId": self.proposal_id,
                "riskEvaluationId": self.risk_evaluation_id,
            }
        )


@dataclass(frozen=True)
class SimulateV4Spec(ClosedSchema):
    """``POST /wallet/v4/simulate`` — the same pipeline, zero persistence."""

    vault_id: str
    action: str
    signer_address: str
    params: Any = dataclass_field(default_factory=dict)

    def validate(self) -> None:
        _require_hex64(self.vault_id, "vaultId")
        _require_text(self.action, "action", max_len=64)
        _require_address(self.signer_address, "signerAddress")
        _params_body(self.action, self.params)

    def to_body(self) -> dict:
        return {
            "schemaVersion": V4_WALLET_REQUEST_SCHEMA_VERSION,
            "vaultId": self.vault_id,
            "action": self.action,
            "params": _params_body(self.action, self.params),
            "signerAddress": self.signer_address,
        }


@dataclass(frozen=True)
class ApprovalSpec(ClosedSchema):
    """``POST /wallet/v4/requests/:id/approvals`` — an M-of-N approval.

    The signature is produced by a signer this client never touches (KasWare,
    the reference CLI signer, or any other Universal Signer Interface
    adapter). Python holds no keys and signs nothing.
    """

    approver_address: str
    signed_safe_json: Optional[str] = None
    signature_hex: Optional[str] = None

    def validate(self) -> None:
        _require_address(self.approver_address, "approverAddress")
        provided = [v is not None for v in (self.signed_safe_json, self.signature_hex)]
        if sum(provided) != 1:
            raise ValidationError(
                "supply exactly one of signed_safe_json or signature_hex"
            )
        if self.signed_safe_json is not None:
            _require_text(self.signed_safe_json, "signedSafeJson", max_len=200_000)
        if self.signature_hex is not None:
            _require_hex(self.signature_hex, "signatureHex")

    def to_body(self) -> dict:
        return _drop_none(
            {
                "schemaVersion": V4_WALLET_REQUEST_SCHEMA_VERSION,
                "approverAddress": self.approver_address,
                "signedSafeJson": self.signed_safe_json,
                "signatureHex": self.signature_hex,
            }
        )


@dataclass(frozen=True)
class SignatureSpec(ClosedSchema):
    """``POST /wallet/v4/requests/:id/signature`` — FINALIZE (+ VM preflight)."""

    signed_safe_json: str

    def validate(self) -> None:
        _require_text(self.signed_safe_json, "signedSafeJson", max_len=200_000)

    def to_body(self) -> dict:
        return {
            "schemaVersion": V4_WALLET_REQUEST_SCHEMA_VERSION,
            "signedSafeJson": self.signed_safe_json,
        }


@dataclass(frozen=True)
class GenesisSubmitSpec(SignatureSpec):
    """``POST /wallet/v4/requests/:id/genesis-submit`` — broadcast genesis."""


@dataclass(frozen=True)
class ProposalSpec(ClosedSchema):
    """``POST /governance/proposals`` — propose an authority EXPANSION."""

    vault_id: str
    action: str
    params: Any = dataclass_field(default_factory=dict)
    expires_in_ms: Optional[int] = None

    def validate(self) -> None:
        _require_hex64(self.vault_id, "vaultId")
        _require_text(self.action, "action", max_len=64)
        _params_body(self.action, self.params)
        if self.expires_in_ms is not None:
            parse_bounded_int(
                self.expires_in_ms, "expiresInMs", minimum=1, maximum=365 * 24 * 60 * 60 * 1000
            )

    def to_body(self) -> dict:
        return _drop_none(
            {
                "vaultId": self.vault_id,
                "action": self.action,
                "params": _params_body(self.action, self.params),
                "expiresInMs": self.expires_in_ms,
            }
        )


@dataclass(frozen=True)
class ProposalApprovalSpec(ClosedSchema):
    """``POST /governance/proposals/:id/approvals``.

    ``signature`` is a Schnorr signature over the SERVER-reconstructed
    canonical approval message, produced by an external signer. The hosted
    session only gates route visibility; the signature is what counts.
    """

    approver_address: str
    signature: str

    def validate(self) -> None:
        _require_address(self.approver_address, "approverAddress")
        _require_text(self.signature, "signature", max_len=4096)

    def to_body(self) -> dict:
        return {"approverAddress": self.approver_address, "signature": self.signature}


# Re-exported for callers (and the client) that build path segments themselves.
require_id = _require_id
require_hex64 = _require_hex64
require_hex = _require_hex
require_address = _require_address
reject_float_value = reject_float
