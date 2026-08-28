"""PolicyVault Python reference client — a THIN consumer of the REST/Agent API.

PolicyVault has ONE authoritative deterministic financial/policy core, and it
is not in this package. This client is transport + closed schemas + integer
hygiene. It never evaluates policy, derives successor state, computes fees or
mass, verifies covenants or intent manifests, authorises signers, or holds
keys. Read ``docs/postlaunch/python-client-spec.md`` for the full scope and
the JS/Python asymmetry statement before extending anything here.

Quick start::

    from policyvault_client import PolicyVaultClient, SimulateV4Spec, AgentSpendParams

    pv = PolicyVaultClient()            # $POLICYVAULT_API_URL / $POLICYVAULT_API_TOKEN
    pv.assert_compatible()              # fail closed on a schemaVersion mismatch

    result = pv.simulate(SimulateV4Spec(
        vault_id="7a" * 32,
        action="agentSpend",
        signer_address="kaspatest:...",
        params=AgentSpendParams(
            agent_pk="…64 hex…",
            pay_amount_sompi="100000000",   # integer sompi, never a float
            recipient="…64 hex…",
        ),
    ))
    if not result["simulation"]["ok"]:
        print(result["simulation"]["refusalReason"])
"""

from .amounts import (
    MAX_SOMPI,
    SOMPI_PER_KAS,
    AmountError,
    kas_to_sompi,
    parse_positive_sompi,
    parse_sompi,
    sompi_to_kas,
    to_sompi_string,
)
from .client import ENV_BASE_URL, ENV_TOKEN, PolicyVaultClient
from .errors import (
    ApiError,
    AuthenticationError,
    ConflictError,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    NotFoundError,
    PolicyVaultError,
    ProtocolError,
    RateLimitError,
    SchemaVersionError,
    ScopeError,
    ServerError,
    TransportError,
    UnprocessableError,
    ValidationError,
)
from .schemas import (
    BREAK_GLASS_ACTIONS,
    V4_ACTIONS,
    V4_WALLET_REQUEST_SCHEMA_VERSION,
    AddAgentParams,
    AgentPolicyInput,
    AgentSpendParams,
    ApprovalSpec,
    FuelInput,
    GenesisSubmitSpec,
    Outpoint,
    OwnerPauseParams,
    OwnerRecoverParams,
    OwnerSetAgentRootParams,
    OwnerSetApproversParams,
    OwnerTopUpParams,
    OwnerTopUpReserveParams,
    OwnerUnpauseParams,
    ProposalApprovalSpec,
    ProposalSpec,
    RePolicyAgentParams,
    RemoveAgentParams,
    RotateAgentParams,
    SignatureSpec,
    SimulateV4Spec,
    WalletRequestV4Spec,
)
from .transport import Secret, new_idempotency_key

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # client
    "PolicyVaultClient",
    "ENV_BASE_URL",
    "ENV_TOKEN",
    "new_idempotency_key",
    "Secret",
    # amounts
    "SOMPI_PER_KAS",
    "MAX_SOMPI",
    "AmountError",
    "parse_sompi",
    "parse_positive_sompi",
    "kas_to_sompi",
    "sompi_to_kas",
    "to_sompi_string",
    # errors
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
    # schemas
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
    "WalletRequestV4Spec",
    "SimulateV4Spec",
    "ApprovalSpec",
    "SignatureSpec",
    "GenesisSubmitSpec",
    "ProposalSpec",
    "ProposalApprovalSpec",
]
