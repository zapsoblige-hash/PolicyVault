"""Integer-only KAS <-> sompi hygiene for the PolicyVault Python client.

WHAT THIS MODULE IS
-------------------
A faithful port of the *parsing RULES* in ``core/model/amounts.js`` (the
canonical JS/Node parser, re-exported as ``sdk/src/amounts.js``). It exists
so a Python caller cannot put a float, a lossy JSON number, or a malformed
decimal string onto the wire.

WHAT THIS MODULE IS NOT
-----------------------
It is **not** a second financial engine. It performs no policy evaluation,
no successor derivation, no fee/mass computation, and no covenant
verification. Its entire job is boundary hygiene: refuse anything that is
not an exact, in-range, well-formed integer amount, and render amounts as
the exact decimal strings the API expects. Every consequential decision is
made by the server + the authoritative deterministic core, never here.

DELIBERATE DIVERGENCES FROM THE JS PARSER (both fail *closed*, i.e. this
module is never more permissive than the server):

1. ASCII-only digits. Python's ``\\d`` matches Unicode decimal digits
   (e.g. U+0663 ARABIC-INDIC DIGIT THREE), while JavaScript's ``\\d`` in a
   non-unicode regex matches only ``[0-9]``. Every pattern here spells
   ``[0-9]`` explicitly so a Unicode digit can never be silently accepted
   and then re-encoded into a body the server would read differently.
2. ASCII-only whitespace trimming. ``kasToSompi`` in JS calls ``.trim()``
   (which strips the ECMAScript WhiteSpace set, including U+00A0 and
   U+FEFF). This port strips only ``" \\t\\n\\r\\v\\f"``, so an exotic
   whitespace character is refused here rather than accepted. Stricter,
   never looser.
3. ``bool`` is rejected everywhere an integer is expected. In Python
   ``bool`` is a subclass of ``int``, so ``True`` would otherwise parse as
   1 sompi.

AMOUNTS ALWAYS TRAVEL AS STRINGS. JSON numbers are IEEE-754 doubles in
most parsers; sompi values routinely exceed 2**53. ``to_sompi_string`` is
the only sanctioned way to put an amount into a request body.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "SOMPI_PER_KAS",
    "MAX_SOMPI",
    "AmountError",
    "parse_sompi",
    "parse_positive_sompi",
    "kas_to_sompi",
    "sompi_to_kas",
    "to_sompi_string",
    "reject_float",
    "parse_index",
    "parse_bounded_int",
]

SOMPI_PER_KAS = 100_000_000

# Kaspa max supply ~28.7B KAS; the same generous hard ceiling the canonical
# JS parser uses (core/model/amounts.js MAX_SOMPI).
MAX_SOMPI = 29_000_000_000 * SOMPI_PER_KAS

_DIGITS = re.compile(r"^[0-9]+$")
_KAS_DECIMAL = re.compile(r"^([0-9]+)(?:\.([0-9]{1,8}))?$")

# The exact whitespace set JS's String.prototype.trim() and Python's
# str.strip() agree on. See divergence note 2 in the module docstring.
_ASCII_WS = " \t\n\r\v\f"


class AmountError(ValueError):
    """A value failed integer/decimal-string hygiene at the client boundary.

    Raised entirely locally: nothing was sent, nothing was signed, nothing
    durable happened.
    """


def _fail(message: str) -> "AmountError":
    # Message prefix mirrors core/model/amounts.js ("amounts: ...") so a
    # Python traceback and a Node stack read the same way.
    return AmountError(f"amounts: {message}")


def _type_name(value: Any) -> str:
    return type(value).__name__


def reject_float(value: Any, field: str = "amount") -> None:
    """Refuse any inexact numeric carrier near a funds value.

    ``float`` and ``complex`` are rejected outright. ``decimal.Decimal`` and
    ``fractions.Fraction`` are rejected too: they *can* be exact, but they
    are not the canonical carriers, and accepting them would put a silent
    rounding/format decision inside this client. Pass an ``int`` or an exact
    decimal string instead.
    """
    if isinstance(value, (float, complex)):
        raise _fail(
            f"{field} must never be a floating-point value "
            f"(got {_type_name(value)} {value!r}) — use an int or an exact decimal string"
        )
    # Duck-typed check so importing decimal/fractions is not required.
    module = type(value).__module__
    if module in ("decimal", "fractions"):
        raise _fail(
            f"{field} must not be a {module}.{_type_name(value)} — "
            "PolicyVault amounts are integer sompi; pass an int or an exact decimal string"
        )


def parse_sompi(value: Any, field: str = "amount") -> int:
    """Parse a sompi amount into an exact ``int``.

    Accepts an ``int`` (Python ints are arbitrary precision, the analogue of
    JS ``BigInt``) or a base-10 digit ``str``. Rejects floats, ``bool``,
    signs, exponents, hex, whitespace, empty strings, negatives, and values
    above ``MAX_SOMPI``.
    """
    reject_float(value, field)

    if isinstance(value, bool):
        raise _fail(f"{field} must be an int or decimal string, got bool")
    if isinstance(value, int):
        amount = value
    elif isinstance(value, str):
        if not _DIGITS.match(value):
            raise _fail(f"{field} must be a base-10 digit string, got {value!r}")
        amount = int(value)
    else:
        raise _fail(f"{field} must be an int or decimal string, got {_type_name(value)}")

    if amount < 0:
        raise _fail(f"{field} must not be negative")
    if amount > MAX_SOMPI:
        raise _fail(f"{field} exceeds maximum representable sompi")
    return amount


def parse_positive_sompi(value: Any, field: str = "amount") -> int:
    """``parse_sompi`` plus a non-zero requirement."""
    amount = parse_sompi(value, field)
    if amount == 0:
        raise _fail(f"{field} must be greater than zero")
    return amount


def kas_to_sompi(value: Any, field: str = "amount") -> int:
    """Parse a human KAS decimal string ("12", "0.5", "1.23456789") to sompi.

    String input only. At most 8 fractional digits; no exponents, no signs,
    no thousands separators, no floats.
    """
    reject_float(value, field)
    if isinstance(value, bool) or not isinstance(value, str):
        raise _fail(f"{field} must be a string KAS amount, got {_type_name(value)}")

    match = _KAS_DECIMAL.match(value.strip(_ASCII_WS))
    if not match:
        raise _fail(f"{field} is not a valid KAS decimal string: {value!r}")

    whole = int(match.group(1))
    frac_digits = match.group(2) or ""
    frac = int(frac_digits.ljust(8, "0")) if frac_digits else 0
    amount = whole * SOMPI_PER_KAS + frac
    if amount > MAX_SOMPI:
        raise _fail(f"{field} exceeds maximum representable sompi")
    return amount


def sompi_to_kas(value: Any, field: str = "amount") -> str:
    """Render sompi as a canonical KAS decimal string, trailing zeros trimmed."""
    amount = parse_sompi(value, field)
    whole, frac = divmod(amount, SOMPI_PER_KAS)
    if frac == 0:
        return str(whole)
    frac_str = str(frac).rjust(8, "0").rstrip("0")
    return f"{whole}.{frac_str}"


def to_sompi_string(value: Any, field: str = "amount") -> str:
    """Validate an amount and render it as the decimal string the API expects.

    Always a string on the wire: JSON numbers cannot carry sompi above
    2**53 without loss, and the server does ``String(params.<amount>)``
    on these fields anyway.
    """
    return str(parse_sompi(value, field))


def parse_index(value: Any, field: str = "index") -> int:
    """A non-negative outpoint index. Emitted as a JSON number (server does
    ``Number(op.index)``); bounded well below 2**53 so it is exact."""
    reject_float(value, field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{field} must be a non-negative int, got {_type_name(value)}")
    if value < 0:
        raise _fail(f"{field} must not be negative")
    if value > 0xFFFFFFFF:
        raise _fail(f"{field} exceeds the maximum transaction output index")
    return value


def parse_bounded_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    """A plain non-negative integer knob (``limit``, ``expiresInMs``, ...).

    Not a funds value — but still integer-only, so a float can never reach
    the wire through any field of any request body.
    """
    reject_float(value, field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{field} must be an int, got {_type_name(value)}")
    if value < minimum or value > maximum:
        raise _fail(f"{field} must be between {minimum} and {maximum}")
    return value
