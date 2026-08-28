"""Python-path conformance driver (surface 10).

Runs as a REAL subprocess (``python3 -m pv_conformance_driver``) speaking a
one-JSON-object-per-line protocol on stdin/stdout, and drives the REAL
stdlib-only ``policyvault_client`` package from this worktree against the
harness server. No mocks; no re-implementation — every op is either a typed
client method (exactly what an agent would call) or the client's own raw
transport escape hatch where the suite needs the verbatim wire view.

Configuration is environment-only (mirrors the MCP adapter's stance —
credentials never ride argv):
    PV_BASE_URL          server origin
    PV_TOKEN_<NAME>      machine credential for the named principal
Responses NEVER echo credentials; stdout is scanned by the token-hygiene
scenario and must stay clean.
"""

from __future__ import annotations

import json
import os
import sys

from policyvault_client import PolicyVaultClient
from policyvault_client.errors import ApiError, PolicyVaultError
import policyvault_client as _pkg


def _clients() -> dict:
    base_url = os.environ["PV_BASE_URL"]
    out = {"anonymous": PolicyVaultClient(base_url)}
    for key, value in os.environ.items():
        if key.startswith("PV_TOKEN_") and value:
            out[key[len("PV_TOKEN_"):].lower()] = PolicyVaultClient(base_url, value)
    return out


def _ok(body, status=None, replayed=None):
    if replayed is None:
        replayed = bool(isinstance(body, dict) and isinstance(body.get("idempotency"), dict) and body["idempotency"].get("replayed"))
    return {"ok": True, "httpStatus": status, "code": None, "body": body, "replayed": replayed, "errorType": None}


def _err(error):
    if isinstance(error, ApiError):
        return {
            "ok": False,
            "httpStatus": error.status,
            "code": error.code,
            "body": dict(error.body),
            "replayed": bool(error.replayed),
            "errorType": type(error).__name__,
        }
    if isinstance(error, PolicyVaultError):
        return {"ok": False, "httpStatus": None, "code": None, "body": None, "replayed": False,
                "errorType": type(error).__name__, "message": str(error)}
    raise error


def _introspect() -> dict:
    """Surface lock: the asymmetry statement made mechanical.

    The Python package must stay a THIN transport client: if it ever grows
    a local verifier / policy engine / successor derivation, the module
    list and attribute survey change and the conformance suite fails until
    the divergence is deliberately re-classified (spec §7).
    """
    pkg_dir = os.path.dirname(os.path.abspath(_pkg.__file__))
    modules = sorted(
        name for name in os.listdir(pkg_dir)
        if name.endswith(".py") or name == "py.typed"
    )
    client_attrs = sorted(a for a in dir(PolicyVaultClient) if not a.startswith("_"))
    package_attrs = sorted(a for a in dir(_pkg) if not a.startswith("_"))
    return {"modules": modules, "clientAttrs": client_attrs, "packageAttrs": package_attrs}


def handle(clients: dict, op: str, who: str, args: dict) -> dict:
    pv = clients[who]
    if op == "capabilities":
        return _ok(pv.capabilities())
    if op == "assert_compatible":
        return _ok(pv.assert_compatible())
    if op == "pinned_schema":
        return _ok({"schemaVersion": PolicyVaultClient.SCHEMA_VERSION})
    if op == "introspect":
        return _ok(_introspect())
    if op == "list_vaults":
        return _ok(pv.list_vaults())
    if op == "get_vault":
        return _ok(pv.get_vault(args["vaultId"]))
    if op == "vault_audit":
        return _ok(pv.vault_audit(args["vaultId"]))
    if op == "audit_feed":
        return _ok(pv.audit(limit=args.get("limit")))
    if op == "simulate":
        return _ok(pv.simulate(args["spec"]))
    if op == "build_request":
        return _ok(pv.build_request(args["spec"], idempotency_key=args.get("idempotencyKey")))
    if op == "get_request":
        return _ok(pv.get_request(args["requestId"]))
    if op == "list_requests":
        return _ok(pv.list_requests(vault_id=args.get("vaultId"), open_only=bool(args.get("openOnly"))))
    if op == "approve_request":
        return _ok(pv.approve_request(args["requestId"], args["spec"]))
    if op == "get_proposal":
        return _ok(pv.get_proposal(args["proposalId"]))
    if op == "list_proposals":
        return _ok(pv.list_proposals(vault_id=args.get("vaultId"), limit=args.get("limit")))
    if op == "get_risk_evaluation":
        return _ok(pv.get_risk_evaluation(args["evaluationId"]))
    if op == "reject_request":
        return _ok(pv.reject_request(args["requestId"], idempotency_key=args.get("idempotencyKey")))
    if op == "raw":
        # The client's own transport, verbatim: full status visibility for
        # wire-level equivalence probes (events, webhooks, hostile bodies).
        response = pv._transport.request(
            args["method"],
            args["path"],
            query=args.get("query"),
            body=args.get("body"),
            idempotency_key=args.get("idempotencyKey"),
        )
        return _ok(response.body, status=response.status)
    raise ValueError(f"unknown op {op!r}")


def main() -> None:
    clients = _clients()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        try:
            result = handle(clients, msg["op"], msg.get("client", "anonymous"), msg.get("args") or {})
        except PolicyVaultError as error:
            result = _err(error)
        except ApiError as error:  # pragma: no cover - ApiError is a PolicyVaultError
            result = _err(error)
        except Exception as error:  # deterministic driver-side failure report
            result = {"ok": False, "httpStatus": None, "code": None, "body": None, "replayed": False,
                      "errorType": type(error).__name__, "message": str(error)}
        result["id"] = msg["id"]
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
