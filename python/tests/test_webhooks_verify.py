"""UNIT layer — webhook signature verification RULE parity.

The header/vector pair below was generated once from the real JS reference
implementation (``server/src/events-signing.js signWebhookPayload``) and is
copied here as a literal value, exactly the ``sdk/test/amounts.test.js`` ->
``test_amounts.py`` discipline (see ``policyvault_client/webhooks.py``'s
module docstring): agreeing on a header neither implementation generated in
this test file is evidence of real interoperability, not a tautology.

Regenerate with, if the ``pv1`` scheme ever changes::

    node -e '
      const { signWebhookPayload } = require("./server/src/events-signing");
      console.log(signWebhookPayload({ secrets: ["pvwh_test_secret_value_aaaa"],
        timestampSeconds: 1893456000, rawBody: RAW }));'
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from policyvault_client.webhooks import (  # noqa: E402
    DEFAULT_TOLERANCE_SECONDS,
    SIGNATURE_SCHEME,
    WebhookVerifyResult,
    verify_webhook_signature,
)

TIMESTAMP = 1893456000
RAW_BODY = '{"schemaVersion":"policyvault-webhook/v1","deliveryId":"d1","event":{"type":"vault.created"}}'
SECRET = "pvwh_test_secret_value_aaaa"
# Generated from the real JS signWebhookPayload — see the module docstring.
HEADER_ONE_SECRET = "v=pv1,t=1893456000,s=9293634c4e8bb4701d39e2487d7036d7b9236fa37b371f5eb30ffe5abccd6eaf"

CURRENT_SECRET = "pvwh_current_bbbb"
PREVIOUS_SECRET = "pvwh_previous_cccc"
# Generated the same way with secrets ["pvwh_current_bbbb", "pvwh_previous_cccc"]
# (rotation grace: BOTH the current and previous secret co-sign one header).
HEADER_TWO_SECRETS = "v=pv1,t=1893456000,s=b632e70e95aa11e6dd1d6e1e60fe316e071516615acceaa27fe83c9dac7687a1,s=2c3f69fa9d095b76341a7d0f356fcb0796ca66a3744a00bcc36cb4f1d389c34b"


class CrossImplementationVectorTest(unittest.TestCase):
    """The JS side signed; the Python side must independently verify."""

    def test_real_js_generated_header_verifies_in_python(self):
        result = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, SECRET, now_seconds=TIMESTAMP)
        self.assertEqual(result, WebhookVerifyResult(ok=True, timestamp_seconds=TIMESTAMP))

    def test_rotation_grace_header_verifies_against_either_secret(self):
        for secret in (CURRENT_SECRET, PREVIOUS_SECRET):
            with self.subTest(secret=secret):
                result = verify_webhook_signature(HEADER_TWO_SECRETS, RAW_BODY, secret, now_seconds=TIMESTAMP)
                self.assertTrue(result.ok)

    def test_wrong_secret_against_the_real_header_fails(self):
        result = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, "pvwh_wrong_secret", now_seconds=TIMESTAMP)
        self.assertEqual(result, WebhookVerifyResult(ok=False, reason="SIGNATURE_MISMATCH"))

    def test_tampered_body_against_the_real_header_fails(self):
        tampered = RAW_BODY.replace("vault.created", "vault.deleted")
        result = verify_webhook_signature(HEADER_ONE_SECRET, tampered, SECRET, now_seconds=TIMESTAMP)
        self.assertEqual(result, WebhookVerifyResult(ok=False, reason="SIGNATURE_MISMATCH"))


class BehaviorTest(unittest.TestCase):
    def test_replay_window(self):
        ok_inside = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, SECRET, now_seconds=TIMESTAMP + 299)
        self.assertTrue(ok_inside.ok)
        too_late = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, SECRET, now_seconds=TIMESTAMP + 301)
        self.assertEqual(too_late, WebhookVerifyResult(ok=False, reason="TIMESTAMP_OUT_OF_TOLERANCE"))
        too_early = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, SECRET, now_seconds=TIMESTAMP - 301)
        self.assertEqual(too_early, WebhookVerifyResult(ok=False, reason="TIMESTAMP_OUT_OF_TOLERANCE"))

    def test_custom_tolerance(self):
        result = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, SECRET, now_seconds=TIMESTAMP + 1000, tolerance_seconds=2000)
        self.assertTrue(result.ok)

    def test_scheme_downgrade_refused(self):
        downgraded = HEADER_ONE_SECRET.replace("v=pv1", "v=pv0")
        result = verify_webhook_signature(downgraded, RAW_BODY, SECRET, now_seconds=TIMESTAMP)
        self.assertEqual(result, WebhookVerifyResult(ok=False, reason="UNSUPPORTED_SCHEME"))

    def test_malformed_headers_fail_closed(self):
        for bad_header in ["garbage", "v=pv1,t=123", "v=pv1", "", "v=pv1,t=abc,s=" + "a" * 64]:
            with self.subTest(bad_header=bad_header):
                result = verify_webhook_signature(bad_header, RAW_BODY, SECRET, now_seconds=TIMESTAMP)
                self.assertEqual(result.reason, "MALFORMED_HEADER")

    def test_non_string_inputs_fail_closed_never_raise(self):
        for bad in (None, 123, {}, []):
            with self.subTest(bad=bad):
                result = verify_webhook_signature(bad, RAW_BODY, SECRET, now_seconds=TIMESTAMP)
                self.assertEqual(result.reason, "MALFORMED_HEADER")
        self.assertEqual(verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, "", now_seconds=TIMESTAMP).reason, "MALFORMED_HEADER")

    def test_unknown_extra_header_keys_are_ignored(self):
        with_extra = HEADER_ONE_SECRET + ",future=stuff"
        result = verify_webhook_signature(with_extra, RAW_BODY, SECRET, now_seconds=TIMESTAMP)
        self.assertTrue(result.ok)

    def test_default_tolerance_matches_the_js_default(self):
        self.assertEqual(DEFAULT_TOLERANCE_SECONDS, 300)

    def test_signature_scheme_constant(self):
        self.assertEqual(SIGNATURE_SCHEME, "pv1")

    def test_now_seconds_defaults_to_current_time(self):
        # Without an explicit now_seconds, a header timestamped "now" must
        # verify (exercises the real-clock default path).
        import time

        now = int(time.time())
        # Re-sign is not available in pure Python (HMAC key differs from the
        # module's own verification-only surface), so instead assert the
        # real header, which is far in the future relative to "now" in this
        # test suite's era, is correctly OUT of tolerance by default —
        # proving now_seconds really defaults to wall-clock time rather
        # than being silently ignored.
        result = verify_webhook_signature(HEADER_ONE_SECRET, RAW_BODY, SECRET)
        self.assertEqual(result.reason, "TIMESTAMP_OUT_OF_TOLERANCE")
        self.assertNotEqual(now, TIMESTAMP)


if __name__ == "__main__":
    unittest.main()
