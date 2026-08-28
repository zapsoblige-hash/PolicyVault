"""UNIT layer — closed request schemas.

The property under test: this client never forwards an arbitrary dict. Every
body is built from a declared schema, unknown fields are refused locally, and
carriers are integer-hygienic before anything reaches the wire.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from policyvault_client import (  # noqa: E402
    AgentPolicyInput,
    AgentSpendParams,
    AmountError,
    ApprovalSpec,
    FuelInput,
    Outpoint,
    OwnerSetApproversParams,
    OwnerTopUpParams,
    ProposalSpec,
    SimulateV4Spec,
    ValidationError,
    WalletRequestV4Spec,
)
from policyvault_client.schemas import (  # noqa: E402
    V4_WALLET_REQUEST_SCHEMA_VERSION,
    coerce,
)

VAULT = "5a" * 32
PK = "ab" * 32
RECIPIENT = "cd" * 32
SIGNER = "kaspatest:qzwp7kz64qrk9705gk8ksp5h3da7ldrv0d52lqknn93s0yllrg44qwez9p35u"


def spend(**overrides):
    base = dict(agent_pk=PK, pay_amount_sompi="100000000", recipient=RECIPIENT)
    base.update(overrides)
    return AgentSpendParams(**base)


class ClosedInputTest(unittest.TestCase):
    def test_unknown_fields_are_refused_locally(self):
        with self.assertRaisesRegex(ValidationError, "unknown field"):
            WalletRequestV4Spec.from_mapping(
                {
                    "vaultId": VAULT,
                    "action": "ownerTopUp",
                    "signerAddress": SIGNER,
                    "params": {"topUpAmountSompi": "5"},
                    "sneakyExtra": "please forward me",
                }
            )

    def test_unknown_params_fields_are_refused_too(self):
        with self.assertRaisesRegex(ValidationError, "unknown field"):
            WalletRequestV4Spec(
                vault_id=VAULT,
                action="agentSpend",
                signer_address=SIGNER,
                params={"agentPk": PK, "payAmountSompi": "1", "recipient": RECIPIENT, "extra": 1},
            )

    def test_both_snake_case_and_camel_case_are_accepted(self):
        a = WalletRequestV4Spec.from_mapping(
            {"vault_id": VAULT, "action": "ownerPause", "signer_address": SIGNER, "params": {}}
        )
        b = WalletRequestV4Spec.from_mapping(
            {"vaultId": VAULT, "action": "ownerPause", "signerAddress": SIGNER, "params": {}}
        )
        self.assertEqual(a.to_body(), b.to_body())

    def test_supplying_a_field_twice_is_refused(self):
        with self.assertRaisesRegex(ValidationError, "twice"):
            WalletRequestV4Spec.from_mapping(
                {
                    "vaultId": VAULT,
                    "vault_id": VAULT,
                    "action": "ownerPause",
                    "signerAddress": SIGNER,
                }
            )

    def test_an_unknown_action_fails_closed_before_any_request(self):
        with self.assertRaisesRegex(ValidationError, "unknown v0.4 action"):
            WalletRequestV4Spec(vault_id=VAULT, action="ownerDoSomethingNew", signer_address=SIGNER)

    def test_coerce_refuses_a_foreign_object(self):
        with self.assertRaises(ValidationError):
            coerce(object(), AgentSpendParams)


class LexicalShapeTest(unittest.TestCase):
    def test_vault_id_must_be_lowercase_32_byte_hex(self):
        for bad in ["5A" * 32, "5a" * 31, "zz" * 32, 12345, None]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    SimulateV4Spec(vault_id=bad, action="ownerPause", signer_address=SIGNER)

    def test_address_shape_only_never_a_network_decision(self):
        # Refused: not address-shaped at all.
        for bad in ["", "   ", "no-prefix", "kaspatest: with space", 7]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    SimulateV4Spec(vault_id=VAULT, action="ownerPause", signer_address=bad)
        # Accepted locally: the SERVER decides whether the prefix matches its
        # configured network. A client that decided that would be a second
        # network gate, and would disagree with a differently configured server.
        SimulateV4Spec(vault_id=VAULT, action="ownerPause", signer_address="kaspa:qmainnetlike")

    def test_fuel_hex_and_index_are_shape_checked(self):
        good = FuelInput(
            outpoint=Outpoint(transaction_id="11" * 32, index=0),
            amount="500000000",
            script_public_key_hex="aabb",
        )
        self.assertEqual(good.to_body()["outpoint"], {"transactionId": "11" * 32, "index": 0})
        with self.assertRaises(ValidationError):
            FuelInput(outpoint=Outpoint("11" * 32, 0), amount="1", script_public_key_hex="abc")
        with self.assertRaises(AmountError):
            Outpoint(transaction_id="11" * 32, index=1.0)


class AmountHygieneAtTheBoundaryTest(unittest.TestCase):
    def test_float_amounts_are_refused_in_every_params_schema(self):
        with self.assertRaises(AmountError):
            spend(pay_amount_sompi=1.5)
        with self.assertRaises(AmountError):
            OwnerTopUpParams(top_up_amount_sompi=0.1)
        with self.assertRaises(AmountError):
            AgentPolicyInput(
                agent_pk=PK,
                max_per_spend=1.0,
                period_budget="1",
                period_length_daa="1",
                period_start_daa="0",
                period_spent="0",
                approval_threshold="0",
                agent_max_fee_per_tx="0",
                recipients=[RECIPIENT],
            )

    def test_amounts_are_rendered_as_decimal_strings(self):
        body = spend(pay_amount_sompi=2_800_000_000_000_000_000).to_body()
        self.assertEqual(body["payAmountSompi"], "2800000000000000000")
        self.assertIsInstance(body["payAmountSompi"], str)


class BodyShapeTest(unittest.TestCase):
    def test_v4_bodies_are_schema_version_stamped(self):
        body = WalletRequestV4Spec(
            vault_id=VAULT, action="agentSpend", signer_address=SIGNER, params=spend()
        ).to_body()
        self.assertEqual(body["schemaVersion"], V4_WALLET_REQUEST_SCHEMA_VERSION)
        self.assertEqual(
            sorted(body), ["action", "params", "schemaVersion", "signerAddress", "vaultId"]
        )

    def test_optional_fields_are_omitted_not_nulled(self):
        body = WalletRequestV4Spec(
            vault_id=VAULT, action="ownerPause", signer_address=SIGNER
        ).to_body()
        self.assertNotIn("proposalId", body)
        self.assertNotIn("riskEvaluationId", body)
        self.assertEqual(body["params"], {})

    def test_owner_set_approvers_nests_under_new_approvers(self):
        body = OwnerSetApproversParams(approval_m="2", approvers=[PK, RECIPIENT]).to_body()
        self.assertEqual(body, {"newApprovers": {"approvalM": "2", "approvers": [PK, RECIPIENT]}})
        with self.assertRaisesRegex(ValidationError, "approver set"):
            OwnerSetApproversParams(approval_m="2")

    def test_approval_requires_exactly_one_signature_carrier(self):
        with self.assertRaisesRegex(ValidationError, "exactly one"):
            ApprovalSpec(approver_address=SIGNER)
        with self.assertRaisesRegex(ValidationError, "exactly one"):
            ApprovalSpec(approver_address=SIGNER, signed_safe_json="{}", signature_hex="aa")
        self.assertIn("signedSafeJson", ApprovalSpec(SIGNER, signed_safe_json="{}").to_body())

    def test_proposal_body_carries_no_schema_version(self):
        # Governance bodies are NOT part of the v4 wallet-request schema family;
        # stamping them would assert a version the route never validates.
        body = ProposalSpec(vault_id=VAULT, action="ownerTopUp", params={"topUpAmountSompi": "1"}).to_body()
        self.assertNotIn("schemaVersion", body)
        self.assertEqual(body["params"], {"topUpAmountSompi": "1"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
