"""Amounts parity — generated shared vector file (closes gap G5).

``core/model/test/fixtures/amount-vectors.json`` is GENERATED from the
canonical JS parser (``core/model/amounts.js``) by
``core/model/tools/gen-amount-vectors.js`` — every expected outcome is
COMPUTED by calling the real parser, never hand-typed — and read here AND
by ``sdk/test/amount-vectors-fixture.test.js`` over the SAME file. Unlike
``test_amounts.py`` (whose vectors are hand-copied from
``sdk/test/amounts.test.js`` — see that module's docstring), a change to
the canonical parsing RULES that regenerates the fixture changes what THIS
suite must match, so silent drift is caught mechanically instead of only
by someone remembering to update a second hand-written list. This is the
exact mechanism gap G5 (docs/postlaunch/hybrid-core-gap-analysis.md)
records as missing.

``pythonDivergence: "ascii-only-whitespace"`` marks the handful of inputs
where ``policyvault_client.amounts`` is DELIBERATELY STRICTER than the JS
parser (its own module docstring, divergence 2): JS's
``String.prototype.trim()`` strips a wider Unicode whitespace set (NBSP,
BOM, ...) than Python's ASCII-only strip. For those — and ONLY those —
inputs, the JS side may accept while the Python side refuses; every other
vector must produce an IDENTICAL accept/refuse verdict (and an identical
value where both accept).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from policyvault_client.amounts import AmountError, kas_to_sompi, parse_sompi  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
FIXTURE_PATH = os.path.join(REPO_ROOT, "core", "model", "test", "fixtures", "amount-vectors.json")


def _load_fixture():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _outcome(fn, value):
    # Compares ok/value only, never error text: the parity requirement is
    # "refuses exactly the same malformed inputs" (identical accept/refuse
    # verdict and, on acceptance, an identical value) — not identical
    # error-message prose across two different languages.
    try:
        return {"ok": True, "value": str(fn(value))}
    except AmountError:
        return {"ok": False}


def _strip_error(outcome):
    return {"ok": outcome["ok"], **({"value": outcome["value"]} if outcome["ok"] else {})}


class AmountVectorsFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _load_fixture()
        cls.assertTrue(cls, len(cls.fixture["vectors"]) > 0, "the fixture must not be empty")

    def test_fixture_schema(self):
        self.assertEqual(self.fixture["schema"], "policyvault-amount-vectors/1")
        self.assertEqual(self.fixture["sourceModule"], "core/model/amounts.js")

    def test_kas_to_sompi_agrees_with_every_non_divergent_vector(self):
        mismatches = []
        for v in self.fixture["vectors"]:
            outcome = _outcome(kas_to_sompi, v["input"])
            expected = _strip_error(v["kasToSompi"])
            if v["pythonDivergence"] == "ascii-only-whitespace":
                # documented: JS accepts (strips wider Unicode whitespace),
                # Python is stricter and MUST refuse this exact input.
                self.assertTrue(expected["ok"], f"{v['input']!r}: fixture claims JS refuses a tagged divergence vector")
                if outcome["ok"]:
                    mismatches.append((v["input"], "python accepted a documented-divergence input it must refuse"))
                continue
            if outcome != expected:
                mismatches.append((v["input"], f"python={outcome} fixture(JS)={expected}"))
        self.assertEqual(mismatches, [], f"{len(mismatches)} kasToSompi vector(s) diverged from the JS-generated fixture: {mismatches}")

    def test_parse_sompi_agrees_with_every_non_divergent_vector(self):
        # parseSompi never trims whitespace in either language (kasToSompi is
        # the only function with the ASCII-only-whitespace divergence), so
        # parseSompi vectors are compared unconditionally.
        mismatches = []
        for v in self.fixture["vectors"]:
            outcome = _outcome(parse_sompi, v["input"])
            expected = _strip_error(v["parseSompi"])
            if outcome != expected:
                mismatches.append((v["input"], f"python={outcome} fixture(JS)={expected}"))
        self.assertEqual(mismatches, [], f"{len(mismatches)} parseSompi vector(s) diverged from the JS-generated fixture: {mismatches}")

    def test_at_least_three_vectors_carry_the_documented_divergence_tag(self):
        tagged = [v for v in self.fixture["vectors"] if v["pythonDivergence"] == "ascii-only-whitespace"]
        self.assertGreaterEqual(len(tagged), 3, "expected the generator to still emit >= 3 tagged divergence vectors")


if __name__ == "__main__":
    unittest.main()
