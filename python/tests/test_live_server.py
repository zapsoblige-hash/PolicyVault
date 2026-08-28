"""INTEGRATION layer — the Python client against the REAL PolicyVault server.

No mocks anywhere. ``harness.start_server()`` spawns
``python/tests/_server_boot.js``, which starts ``server/src/server.js``
``createServer(config)`` from this worktree on an ephemeral loopback port with
the JSON backend, seeds one v0.4 vault, and mints two machine bearer
credentials through a real hosted wallet session.

Covered: health, capability discovery + fail-closed schema handshake, the
true dry run, Idempotency-Key claim/replay/conflict, the deny-by-default scope
gate, the structural wallet-session-only exclusion, versioned-schema
fail-closed, and the verbatim error envelope.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

import harness  # noqa: E402

from policyvault_client import (  # noqa: E402
    AgentSpendParams,
    ApiError,
    NotFoundError,
    PolicyVaultClient,
    ProtocolError,
    SchemaVersionError,
    ScopeError,
    SimulateV4Spec,
    ValidationError,
    WalletRequestV4Spec,
    new_idempotency_key,
)
from policyvault_client.schemas import V4_WALLET_REQUEST_SCHEMA_VERSION  # noqa: E402

SERVER = None
SKIP_REASON = None


def setUpModule():
    global SERVER, SKIP_REASON
    try:
        SERVER = harness.start_server()
    except harness.ServerUnavailable as error:
        SKIP_REASON = str(error)


def tearDownModule():
    if SERVER is not None:
        SERVER.stop()


class LiveServerTest(unittest.TestCase):
    """Base: a client per credential, plus the seeded vault's identifiers."""

    @classmethod
    def setUpClass(cls):
        if SERVER is None:
            raise unittest.SkipTest(f"PolicyVault server unavailable: {SKIP_REASON}")
        cls.server = SERVER
        cls.pv = PolicyVaultClient(SERVER.base_url, SERVER.full_token)
        cls.read_only = PolicyVaultClient(SERVER.base_url, SERVER.read_token)
        cls.anonymous = PolicyVaultClient(SERVER.base_url)

    def spend_params(self, **overrides):
        base = dict(
            agent_pk=self.server.agent_pk,
            pay_amount_sompi="100000000",  # 1 KAS, integer sompi, never a float
            recipient=self.server.recipient_pk,
        )
        base.update(overrides)
        return AgentSpendParams(**base)

    def simulate_spec(self, **overrides):
        base = dict(
            vault_id=self.server.vault_id,
            action="agentSpend",
            signer_address=self.server.agent_address,
            params=self.spend_params(),
        )
        base.update(overrides)
        return SimulateV4Spec(**base)

    def require_builder(self):
        """Skip when the REAL Rust call encoder is missing.

        Its absence is an ENVIRONMENT gap (a gitignored Cargo artifact), not a
        client defect — and substituting a stub would defeat the point of
        testing against the real pipeline.
        """
        if not self.server.encoder_available:
            raise unittest.SkipTest(self.server.encoder_remedy)


class HealthAndDiscoveryTest(LiveServerTest):
    def test_health_is_public(self):
        body = self.anonymous.health()
        self.assertTrue(body["ok"])
        self.assertEqual(body["networkId"], self.server.network_id)
        self.assertEqual(body["authMode"], "enabled")

    def test_readiness_returns_its_body_rather_than_raising(self):
        body = self.anonymous.readiness()
        self.assertIn("ready", body)
        self.assertEqual(body["networkId"], self.server.network_id)

    def test_capabilities_is_public_and_describes_the_real_enforcement(self):
        doc = self.anonymous.capabilities()
        self.assertEqual(doc["schemaVersion"], "policyvault-capabilities/v1")
        self.assertEqual(doc["apiVersion"], "v1")
        scopes = {entry["scope"] for entry in doc["scopes"]}
        # The scopes this build's tokens were minted with must be real scopes.
        self.assertTrue({"read:vaults", "request:build", "risk:release"} <= scopes)
        actions = {entry["action"] for entry in doc["actions"]["v4"]}
        self.assertIn("agentSpend", actions)
        self.assertTrue(doc["features"]["machineIdentities"])
        self.assertTrue(doc["features"]["dryRunSimulation"])

    def test_schema_handshake_passes_against_this_server(self):
        doc = self.pv.assert_compatible()
        self.assertEqual(doc["schemas"]["walletV4Request"], V4_WALLET_REQUEST_SCHEMA_VERSION)

    def test_schema_handshake_fails_closed_on_a_mismatch(self):
        with self.assertRaisesRegex(ProtocolError, "schema mismatch"):
            self.pv.assert_compatible({"schemas": {"walletV4Request": "policyvault-wallet-v4-request/v99"}})


class DryRunTest(LiveServerTest):
    def test_simulate_runs_the_real_pipeline_and_answers_ok(self):
        self.require_builder()
        body = self.pv.simulate(self.simulate_spec())
        self.assertEqual(body["schemaVersion"], V4_WALLET_REQUEST_SCHEMA_VERSION)
        simulation = body["simulation"]
        self.assertTrue(simulation["ok"], simulation)
        self.assertEqual(simulation["vaultId"], self.server.vault_id)
        self.assertEqual(simulation["action"], "agentSpend")
        # Real builder output: an exact fee, an exact successor, a real
        # intent-manifest verdict — none of it computed in Python.
        self.assertIn("review", simulation)
        self.assertIn("intent", simulation)
        self.assertIn("wouldRequire", simulation)
        # Stated honestly by the server, and surfaced unchanged.
        self.assertTrue(simulation["vmPreflight"]["skipped"])

    def test_a_would_be_refusal_is_ok_false_not_an_exception(self):
        """A dry run answers "would this succeed", so a substantive refusal is
        data (``ok:false`` + ``refusalReason``), not a transport failure."""
        self.require_builder()
        body = self.pv.simulate(
            self.simulate_spec(params=self.spend_params(pay_amount_sompi="900000000000"))
        )
        simulation = body["simulation"]
        self.assertFalse(simulation["ok"], simulation)
        self.assertIn("refusalReason", simulation)
        self.assertIn("code", simulation["refusalReason"])

    def test_an_unknown_vault_is_a_substantive_refusal(self):
        body = self.pv.simulate(self.simulate_spec(vault_id="7e" * 32))
        self.assertFalse(body["simulation"]["ok"])
        self.assertEqual(body["simulation"]["refusalReason"]["code"], "BUILD_FAILED")

    def test_a_malformed_vault_id_never_reaches_the_wire(self):
        with self.assertRaises(ValidationError):
            self.pv.simulate(self.simulate_spec(vault_id="not-hex"))

    def test_simulate_persists_nothing_observable(self):
        before = self.pv.list_requests(vault_id=self.server.vault_id)
        for _ in range(3):
            self.pv.simulate(self.simulate_spec())
        after = self.pv.list_requests(vault_id=self.server.vault_id)
        self.assertEqual(len(before), len(after))


class IdempotencyTest(LiveServerTest):
    def build_spec(self):
        return WalletRequestV4Spec(
            vault_id=self.server.vault_id,
            action="agentSpend",
            signer_address=self.server.agent_address,
            params=self.spend_params(pay_amount_sompi="200000000"),
        )

    def test_the_same_key_replays_the_original_response_verbatim(self):
        self.require_builder()
        key = new_idempotency_key()
        first = self.pv.build_request(self.build_spec(), idempotency_key=key)
        second = self.pv.build_request(self.build_spec(), idempotency_key=key)

        self.assertEqual(first["request"]["requestId"], second["request"]["requestId"])
        self.assertEqual(first["request"]["txId"], second["request"]["txId"])
        self.assertFalse(first["idempotency"]["replayed"])
        self.assertTrue(second["idempotency"]["replayed"])
        self.assertEqual(second["idempotency"]["key"], key)
        # The replay is the ORIGINAL response, not a fresh build.
        self.assertEqual(
            {k: v for k, v in first.items() if k != "idempotency"},
            {k: v for k, v in second.items() if k != "idempotency"},
        )

        # Exactly ONE durable request exists for that key — never two.
        matching = [
            r
            for r in self.pv.list_requests(vault_id=self.server.vault_id)
            if r["requestId"] == first["request"]["requestId"]
        ]
        self.assertEqual(len(matching), 1)

    def test_reusing_a_key_for_a_different_request_is_a_deterministic_conflict(self):
        self.require_builder()
        key = new_idempotency_key()
        self.pv.build_request(self.build_spec(), idempotency_key=key)
        different = WalletRequestV4Spec(
            vault_id=self.server.vault_id,
            action="agentSpend",
            signer_address=self.server.agent_address,
            params=self.spend_params(pay_amount_sompi="300000000"),
        )
        with self.assertRaises(ApiError) as caught:
            self.pv.build_request(different, idempotency_key=key)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(caught.exception.code, "IDEMPOTENCY_KEY_CONFLICT")

    def test_a_malformed_key_is_refused_locally(self):
        for bad in ("", "   ", "has space", "x" * 256):
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    self.pv.build_request(self.build_spec(), idempotency_key=bad)


class ScopeGateTest(LiveServerTest):
    def test_a_read_only_credential_may_read_vaults(self):
        vaults = self.read_only.list_vaults()
        self.assertIn(self.server.vault_id, [v["vaultId"] for v in vaults])

    def test_a_read_only_credential_may_not_build_or_simulate(self):
        with self.assertRaises(ScopeError) as caught:
            self.read_only.simulate(self.simulate_spec())
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(caught.exception.code, "SCOPE_FORBIDDEN")
        self.assertIn("request:build", caught.exception.message)

    def test_a_read_only_credential_may_not_read_the_audit_feed(self):
        with self.assertRaises(ScopeError) as caught:
            self.read_only.audit()
        self.assertEqual(caught.exception.code, "SCOPE_FORBIDDEN")

    def test_an_unmapped_or_unheld_scope_is_denied_by_default(self):
        """The full-scope test credential deliberately does NOT hold
        ``risk:release``; deny-by-default must refuse it."""
        with self.assertRaises(ScopeError) as caught:
            self.pv.release_risk_evaluation("some-evaluation-id")
        self.assertEqual(caught.exception.code, "SCOPE_FORBIDDEN")
        self.assertIn("risk:release", caught.exception.message)

    def test_machine_identity_management_is_structurally_unreachable(self):
        """No scope grants it: a token can never mint or widen its own
        authority. This client exposes no method for it — the raw transport is
        used here purely to prove the SERVER refuses."""
        with self.assertRaises(ScopeError) as caught:
            self.pv._transport.request("POST", "/identities", body={"scopes": ["read:vaults"]})
        self.assertEqual(caught.exception.code, "MACHINE_IDENTITY_ROUTE_FORBIDDEN")

    def test_an_invalid_credential_fails_authentication(self):
        bogus = PolicyVaultClient(self.server.base_url, "pvmk_" + "0" * 64)
        with self.assertRaises(ApiError) as caught:
            bogus.list_vaults()
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(caught.exception.code, "MACHINE_TOKEN_INVALID")

    def test_an_unauthenticated_mutation_is_stopped_by_the_origin_wall(self):
        """Hosted mode exempts a cookie-free BEARER request from the CSRF
        wall. A programmatic client with NO credential is not exempt, so it is
        refused at the origin wall before authentication. Documented in the
        README: a machine client must always present a credential."""
        with self.assertRaises(ApiError) as caught:
            self.anonymous.simulate(self.simulate_spec())
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(caught.exception.code, "ORIGIN_REQUIRED")


class ErrorEnvelopeTest(LiveServerTest):
    def test_a_404_carries_the_server_envelope_verbatim(self):
        with self.assertRaises(NotFoundError) as caught:
            self.pv.get_vault("7f" * 32)
        error = caught.exception
        self.assertEqual(error.status, 404)
        self.assertEqual(error.code, "VAULT_NOT_FOUND")
        self.assertEqual(error.envelope["code"], error.code)
        self.assertEqual(error.envelope["message"], error.message)
        self.assertEqual(error.body["error"], error.envelope)
        self.assertEqual(error.method, "GET")

    def test_route_specific_extras_survive_verbatim(self):
        """A v4 build refusal attaches the durable ``request`` record to the
        envelope; the client must expose it unchanged, not summarise it."""
        spec = WalletRequestV4Spec(
            vault_id=self.server.vault_id,
            action="agentSpend",
            signer_address=self.server.owner_address,  # the OWNER is not the agent
            params=self.spend_params(),
        )
        with self.assertRaises(ApiError) as caught:
            self.pv.build_request(spec)
        error = caught.exception
        self.assertIn(error.status, (403, 422))
        self.assertEqual(set(error.envelope) - {"code", "message"}, set(error.extra))

    def test_an_unsupported_schema_version_fails_closed(self):
        """The server never routes an unknown version to a default handler."""
        body = self.simulate_spec().to_body()
        body["schemaVersion"] = "policyvault-wallet-v4-request/v99"
        with self.assertRaises(SchemaVersionError) as caught:
            self.pv._transport.request("POST", "/wallet/v4/simulate", body=body)
        self.assertEqual(caught.exception.status, 422)
        self.assertEqual(caught.exception.code, "SCHEMA_VERSION_UNSUPPORTED")

    def test_a_foreign_object_is_hidden_rather_than_denied(self):
        with self.assertRaises(NotFoundError) as caught:
            self.pv.get_proposal("no-such-proposal-id")
        self.assertEqual(caught.exception.code, "GOVERNANCE_PROPOSAL_UNKNOWN")


class ReadSurfaceTest(LiveServerTest):
    def test_vault_detail_and_audit(self):
        vault = self.pv.get_vault(self.server.vault_id)
        self.assertEqual(vault["vaultId"], self.server.vault_id)
        self.assertIsInstance(self.pv.vault_audit(self.server.vault_id), list)

    def test_global_audit_feed(self):
        self.assertIsInstance(self.pv.audit(limit=10), list)

    def test_governance_listing(self):
        self.assertIsInstance(self.pv.list_proposals(vault_id=self.server.vault_id), list)

    def test_request_listing_and_detail_round_trip(self):
        self.require_builder()
        built = self.pv.build_request(
            WalletRequestV4Spec(
                vault_id=self.server.vault_id,
                action="agentSpend",
                signer_address=self.server.agent_address,
                params=self.spend_params(pay_amount_sompi="400000000"),
            )
        )
        request_id = built["request"]["requestId"]
        fetched = self.pv.get_request(request_id)
        self.assertEqual(fetched["request"]["requestId"], request_id)
        self.assertEqual(fetched["schemaVersion"], V4_WALLET_REQUEST_SCHEMA_VERSION)
        open_ids = [r["requestId"] for r in self.pv.list_requests(vault_id=self.server.vault_id, open_only=True)]
        self.assertIn(request_id, open_ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
