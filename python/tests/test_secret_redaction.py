"""UNIT layer — a bearer credential must never appear in any client output.

CLAUDE.md: "Never request or log seed phrases, owner private keys, or
production delegate keys." A machine bearer credential is in the same class:
it is bearer authority over everything its scopes allow. This suite proves the
token cannot escape through a repr, an str, a format string, an exception
message, a traceback, or a pickled/copied client — and that the package never
writes to a logging sink at all.
"""

import copy
import io
import os
import pickle
import sys
import traceback
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from policyvault_client import PolicyVaultClient, Secret, ValidationError  # noqa: E402
from policyvault_client.transport import HttpTransport  # noqa: E402

TOKEN = "pvmk_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
BASE = "http://127.0.0.1:65500"


def _rendered_forms(value):
    return [repr(value), str(value), f"{value}", "{}".format(value), format(value)]


class SecretTest(unittest.TestCase):
    def test_secret_never_renders_its_value(self):
        secret = Secret(TOKEN)
        for form in _rendered_forms(secret):
            self.assertNotIn(TOKEN, form)
            self.assertIn("redacted", form)
        self.assertEqual(secret.reveal(), TOKEN)

    def test_secret_in_a_container_repr_stays_redacted(self):
        secret = Secret(TOKEN)
        self.assertNotIn(TOKEN, repr({"authorization": secret}))
        self.assertNotIn(TOKEN, repr([secret, secret]))

    def test_secret_requires_a_non_empty_string(self):
        for bad in ("", None, 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    Secret(bad)


class ClientRedactionTest(unittest.TestCase):
    def setUp(self):
        self.client = PolicyVaultClient(BASE, TOKEN)

    def test_client_repr_and_str_omit_the_token(self):
        for form in _rendered_forms(self.client):
            self.assertNotIn(TOKEN, form)
        self.assertTrue(self.client.authenticated)

    def test_transport_repr_omits_the_token(self):
        transport = HttpTransport(BASE, token=Secret(TOKEN))
        for form in _rendered_forms(transport):
            self.assertNotIn(TOKEN, form)

    def test_object_graph_dump_omits_the_token(self):
        """A debugger/crash dumper walking __dict__ must not surface it."""
        dumped = repr(vars(self.client))
        self.assertNotIn(TOKEN, dumped)
        self.assertNotIn(TOKEN, repr(vars(self.client._transport.__class__)))

    def test_a_transport_failure_traceback_omits_the_token(self):
        """The connection below is refused; the raised error and its full
        traceback must not carry the credential."""
        client = PolicyVaultClient(BASE, TOKEN, timeout=2.0)
        try:
            client.health()
        except Exception as error:  # noqa: BLE001 - the point is to inspect it
            rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            self.assertNotIn(TOKEN, rendered)
            for form in _rendered_forms(error):
                self.assertNotIn(TOKEN, form)
        else:  # pragma: no cover - nothing should be listening on 65500
            self.fail("expected the connection to fail")

    def test_pickling_and_copying_do_not_leak_the_token(self):
        """Secret uses __slots__ and has no __reduce__; a naive pickle of the
        client must not produce a payload containing the credential."""
        try:
            blob = pickle.dumps(self.client)
        except (TypeError, AttributeError, pickle.PicklingError):
            blob = b""  # unpicklable is an acceptable, safe outcome
        self.assertNotIn(TOKEN.encode(), blob)
        shallow = copy.copy(self.client)
        self.assertNotIn(TOKEN, repr(shallow))

    def test_validation_errors_never_echo_the_token(self):
        with self.assertRaises(ValidationError) as caught:
            PolicyVaultClient(BASE, TOKEN).get_vault("not-a-vault-id")
        self.assertNotIn(TOKEN, str(caught.exception))


class NoLoggingSinkTest(unittest.TestCase):
    def test_the_package_never_imports_logging(self):
        """No logging handler can leak what is never logged."""
        import policyvault_client
        import policyvault_client.client
        import policyvault_client.transport

        for module in (policyvault_client, policyvault_client.client, policyvault_client.transport):
            self.assertFalse(
                hasattr(module, "logging"),
                f"{module.__name__} must not hold a logging module reference",
            )

    def test_constructing_and_failing_writes_nothing_to_stdout_or_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            client = PolicyVaultClient(BASE, TOKEN, timeout=2.0)
            try:
                client.health()
            except Exception:  # noqa: BLE001
                pass
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "")


class NoThirdPartyDependenciesTest(unittest.TestCase):
    def test_only_stdlib_modules_are_imported(self):
        """Zero third-party runtime dependencies is a hard requirement."""
        import ast
        import pathlib
        import sys as _sys

        package = pathlib.Path(__file__).resolve().parents[1] / "policyvault_client"
        stdlib = set(_sys.stdlib_module_names)
        offenders = []
        for source_file in sorted(package.glob("*.py")):
            tree = ast.parse(source_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:  # relative import inside this package
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                for name in names:
                    if name and name not in stdlib:
                        offenders.append(f"{source_file.name}: {name}")
        self.assertEqual(offenders, [], f"non-stdlib imports found: {offenders}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
