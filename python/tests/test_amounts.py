"""UNIT layer — amount hygiene and canonical-parser RULE parity.

The vectors below are copied from ``sdk/test/amounts.test.js`` (the suite that
guards ``core/model/amounts.js``, the canonical JS parser). The VECTORS are
copied, not the code: this is an independent Python implementation of the same
RULES, so agreeing on these inputs is evidence, not a tautology.

Python-specific hazards get their own cases: Unicode digits (``\\d`` matches
them in Python but not in JS), ``bool`` (a subclass of ``int``), ``Decimal``
and ``Fraction``, and float anywhere inside a request body.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from policyvault_client.amounts import (  # noqa: E402
    MAX_SOMPI,
    SOMPI_PER_KAS,
    AmountError,
    kas_to_sompi,
    parse_bounded_int,
    parse_index,
    parse_positive_sompi,
    parse_sompi,
    sompi_to_kas,
    to_sompi_string,
)
from policyvault_client.transport import json_body  # noqa: E402


class ParseSompiTest(unittest.TestCase):
    def test_accepts_digit_strings_and_ints(self):
        """sdk/test/amounts.test.js "parseSompi accepts digit strings and BigInt"."""
        self.assertEqual(parse_sompi("0"), 0)
        self.assertEqual(parse_sompi("12345678901234567"), 12345678901234567)
        self.assertEqual(parse_sompi(5), 5)

    def test_rejects_unsafe_inputs(self):
        """sdk/test/amounts.test.js "parseSompi rejects unsafe inputs", verbatim vectors."""
        for bad in [1.5, -1, "1.5", "-1", "1e8", "0x10", "", " 1", "NaN", "Infinity", None, {}, []]:
            with self.subTest(bad=bad):
                with self.assertRaises(AmountError):
                    parse_sompi(bad)
        with self.assertRaisesRegex(AmountError, "negative"):
            parse_sompi(-1)
        with self.assertRaisesRegex(AmountError, "maximum"):
            parse_sompi(29_000_000_001 * SOMPI_PER_KAS)

    def test_accepts_exactly_the_ceiling(self):
        self.assertEqual(parse_sompi(MAX_SOMPI), MAX_SOMPI)
        with self.assertRaisesRegex(AmountError, "maximum"):
            parse_sompi(MAX_SOMPI + 1)

    def test_rejects_bool_because_python_bool_is_an_int(self):
        """Python-specific: True would otherwise silently parse as 1 sompi."""
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(AmountError, "bool"):
                    parse_sompi(bad)

    def test_rejects_unicode_digits(self):
        """Python-specific: ``\\d`` matches U+0663 but JS's ``\\d`` does not.

        Accepting it here would let a string through that the server would
        read differently (or refuse).
        """
        for bad in ("٣", "1٣", "１"):  # ARABIC-INDIC 3, FULLWIDTH 1
            with self.subTest(bad=bad):
                with self.assertRaises(AmountError):
                    parse_sompi(bad)

    def test_rejects_decimal_and_fraction_carriers(self):
        from decimal import Decimal
        from fractions import Fraction

        with self.assertRaisesRegex(AmountError, "decimal"):
            parse_sompi(Decimal("1"))
        with self.assertRaisesRegex(AmountError, "fractions"):
            parse_sompi(Fraction(1, 1))


class ParsePositiveSompiTest(unittest.TestCase):
    def test_rejects_zero(self):
        """sdk/test/amounts.test.js "parsePositiveSompi rejects zero"."""
        with self.assertRaisesRegex(AmountError, "greater than zero"):
            parse_positive_sompi("0")
        self.assertEqual(parse_positive_sompi("1"), 1)


class KasToSompiTest(unittest.TestCase):
    def test_exact_decimal_handling(self):
        """sdk/test/amounts.test.js "kasToSompi exact decimal handling"."""
        self.assertEqual(kas_to_sompi("1"), 100_000_000)
        self.assertEqual(kas_to_sompi("0.00000001"), 1)
        self.assertEqual(kas_to_sompi("1.23456789"), 123_456_789)
        self.assertEqual(kas_to_sompi("1000000"), 100_000_000_000_000)
        self.assertEqual(kas_to_sompi("0.5"), 50_000_000)

    def test_rejects_malformed_values(self):
        """sdk/test/amounts.test.js "kasToSompi rejects malformed values", verbatim."""
        for bad in ["1.234567891", "-1", "1e3", ".5", "1.", "1,5", "0x1", "", "one", "1.5.5"]:
            with self.subTest(bad=bad):
                with self.assertRaises(AmountError):
                    kas_to_sompi(bad)
        with self.assertRaisesRegex(AmountError, "string"):
            kas_to_sompi(1.5)

    def test_trims_ascii_whitespace_like_the_js_parser(self):
        self.assertEqual(kas_to_sompi(" 1 "), 100_000_000)
        self.assertEqual(kas_to_sompi("\t1.5\n"), 150_000_000)

    def test_refuses_exotic_whitespace_the_js_parser_would_trim(self):
        """Documented conservative divergence: stricter here, never looser."""
        for bad in ("\u00a01", "1\ufeff", "\u20281"):  # NBSP, BOM, LINE SEPARATOR
            with self.subTest(bad=bad):
                with self.assertRaises(AmountError):
                    kas_to_sompi(bad)

    def test_rejects_over_ceiling(self):
        with self.assertRaisesRegex(AmountError, "maximum"):
            kas_to_sompi("29000000001")


class SompiToKasTest(unittest.TestCase):
    def test_canonical_rendering(self):
        """sdk/test/amounts.test.js "sompiToKas canonical rendering"."""
        self.assertEqual(sompi_to_kas(100_000_000), "1")
        self.assertEqual(sompi_to_kas(1), "0.00000001")
        self.assertEqual(sompi_to_kas(150_000_000), "1.5")
        self.assertEqual(sompi_to_kas(0), "0")

    def test_round_trip(self):
        """sdk/test/amounts.test.js "round trip"."""
        for value in ["0.00000001", "1", "1.5", "123.456789", "9999999.99999999"]:
            with self.subTest(value=value):
                self.assertEqual(sompi_to_kas(kas_to_sompi(value)), value)


class WireEncodingTest(unittest.TestCase):
    def test_amounts_always_leave_as_strings(self):
        """JSON numbers are doubles in most parsers; sompi exceeds 2**53."""
        big = 28_000_000_000 * SOMPI_PER_KAS
        self.assertGreater(big, 2**53)
        self.assertEqual(to_sompi_string(big), str(big))
        self.assertIsInstance(to_sompi_string(big), str)

    def test_a_float_anywhere_in_a_body_is_refused(self):
        with self.assertRaises(AmountError):
            json_body({"params": {"payAmountSompi": 1.0}})
        with self.assertRaises(AmountError):
            json_body({"a": [{"b": 0.1}]})
        with self.assertRaises(AmountError):
            json_body({"expiresInMs": float("nan")})

    def test_integers_strings_bools_and_none_are_fine(self):
        encoded = json_body({"a": 1, "b": "2", "c": True, "d": None, "e": [1, "2"], "f": {"g": 3}})
        self.assertEqual(encoded, b'{"a":1,"b":"2","c":true,"d":null,"e":[1,"2"],"f":{"g":3}}')


class KnobTest(unittest.TestCase):
    def test_index_bounds(self):
        self.assertEqual(parse_index(0), 0)
        for bad in (-1, 1.0, True, "0", 2**32):
            with self.subTest(bad=bad):
                with self.assertRaises(AmountError):
                    parse_index(bad)

    def test_bounded_int(self):
        self.assertEqual(parse_bounded_int(5, "limit", minimum=1, maximum=10), 5)
        for bad in (0, 11, 5.0, True, "5"):
            with self.subTest(bad=bad):
                with self.assertRaises(AmountError):
                    parse_bounded_int(bad, "limit", minimum=1, maximum=10)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
