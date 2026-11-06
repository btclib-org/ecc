# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A private key handed over as a public key is not repeated in an exception.

What a caller passes where a public key belongs may be a private key
(btclib-org/ecc#74), and exception text is logged and printed.

"Never appears" is held here for the exception, for its `__cause__` and
for its `__context__`, recursively, `str` and `repr` of each. The default
traceback skips a `__context__` that `raise ... from None` suppresses, but
a handler of its own can still read it, so a suppressed one is not
exempt: the library raises outside the `except` block instead.

The key is looked for as hexadecimal, in any case and with the spaces
`hex_string` writes, and as a decimal integer.
"""

import re
from collections.abc import Callable
from typing import Any

import pytest

from ecc import number_theory as nt
from ecc.alias import Public
from ecc.curves import (
    mult_pub_key,
    point_from_octets_var,
    point_from_pub_key,
    secp256k1,
)
from ecc.curves.curve import is_x_coordinate_var
from ecc.curves.curve_group import signed_odd_digits
from ecc.ecc import dleq, dsa, ecies, musig2, pedersen, rangeproof, ssa
from ecc.exceptions import EccException
from tests import needs_bindings
from tests.curves.curve_test import no_bindings_anywhere

# 32 bytes, below the group order, and not an x-coordinate: the half of all
# private keys that no public-key parser can lift
PRV = bytes.fromhex("eef91d0c14949802131e35685a9f80c530bab043e056a0ed14614328dca40839")
PRV_INT = int.from_bytes(PRV, "big")
SEC = b"\x02" + PRV

VALUE = 123456789
MIN_VALUE = 200000000
# not a scalar: out of range for the blinding factor of a generator
BLIND = 2**256 - 1

_G_SEC = secp256k1.G[0].to_bytes(32, "big")
_MSG = b"a message"


def _echoes(text: str, secret: int | bytes) -> bool:
    if isinstance(secret, bytes):
        # a bytes repr is neither its hexadecimal nor its decimal
        return repr(secret)[2:-1] in text or _echoes(
            text, int.from_bytes(secret, "big")
        )
    flat = re.sub(r"[\s']", "", text).lower()
    return f"{abs(secret):x}" in flat or str(abs(secret)) in flat


def _chain(exc: BaseException) -> list[BaseException]:
    seen: dict[int, BaseException] = {}
    todo = [exc]
    while todo:
        e = todo.pop()
        if id(e) not in seen:
            seen[id(e)] = e
            todo += [x for x in (e.__cause__, e.__context__) if x is not None]
    return list(seen.values())


def _sig() -> ssa.Sig:
    return ssa.sign(_MSG, 1)


def _dleq_args() -> tuple[bytes, bytes, bytes, bytes]:
    """Return A (the key), B, C and a proof, for a = 5 and B = G."""
    B = b"\x02" + _G_SEC
    return SEC, B, B, dleq.generate_proof(5, secp256k1.G)


def _forbid(*_: object) -> bytes:  # pragma: no cover -- refused before it is asked
    raise AssertionError("a key that is no point was handed to the cipher")


_CASES: dict[str, tuple[Callable[[], Any], int | bytes]] = {
    "ssa.assert_as_valid": (lambda: ssa.assert_as_valid(_MSG, PRV, _sig()), PRV_INT),
    "ssa.assert_as_valid, int key": (
        lambda: ssa.assert_as_valid(_MSG, PRV_INT, _sig()),
        PRV_INT,
    ),
    "ssa.assert_as_valid, tuple key": (
        lambda: ssa.assert_as_valid(_MSG, (PRV_INT, PRV_INT), _sig()),
        PRV_INT,
    ),
    "point_from_pub_key": (lambda: point_from_pub_key(SEC), PRV_INT),
    "point_from_pub_key, 04": (
        lambda: point_from_pub_key(b"\x04" + PRV + PRV),
        PRV_INT,
    ),
    "point_from_pub_key, tuple": (
        lambda: point_from_pub_key((PRV_INT, PRV_INT)),
        PRV_INT,
    ),
    "point_from_octets_var, 02": (lambda: point_from_octets_var(SEC), PRV_INT),
    "point_from_octets_var, 04": (
        lambda: point_from_octets_var(b"\x04" + PRV + PRV),
        PRV_INT,
    ),
    "point_from_bip340pub_key_var": (
        lambda: ssa.point_from_bip340pub_key_var(PRV),
        PRV_INT,
    ),
    "ssa.assert_batch_as_valid": (
        lambda: ssa.assert_batch_as_valid([_MSG], [PRV], [_sig()]),
        PRV_INT,
    ),
    "mult_pub_key": (lambda: mult_pub_key(2, SEC), PRV_INT),
    "ecies.encrypt": (lambda: ecies.encrypt(b"m", SEC, _forbid), PRV_INT),
    "ecies.derive_keys": (lambda: ecies.derive_keys(1, SEC), PRV_INT),
    "musig2.key_agg_var": (
        lambda: musig2.key_agg_var([b"\x02" + _G_SEC, SEC]),
        PRV_INT,
    ),
    "pedersen.commitment_from_octets_var": (
        lambda: pedersen.commitment_from_octets_var(b"\x08" + PRV),
        PRV_INT,
    ),
    "pedersen.generator_from_octets_var": (
        lambda: pedersen.generator_from_octets_var(b"\x0a" + PRV),
        PRV_INT,
    ),
    "pedersen.generator_from_seed": (
        lambda: pedersen.generator_from_seed(bytes(32), BLIND),
        BLIND,
    ),
    "dleq.assert_proof_as_valid": (
        lambda: dleq.assert_proof_as_valid(*_dleq_args()),
        PRV_INT,
    ),
    "dsa.assert_as_valid": (
        lambda: dsa.assert_as_valid(_MSG, SEC, dsa.sign(_MSG, 1)),
        PRV_INT,
    ),
    "rangeproof.sign, committed value": (
        lambda: rangeproof.sign(1, VALUE, bytes(32), secp256k1.G, min_value=MIN_VALUE),
        VALUE,
    ),
    # a scalar or a field element the call refuses: negative, even, too
    # large, no inverse or root, or no integer at all
    "signed_odd_digits, negative": (
        lambda: signed_odd_digits(-PRV_INT, 4, 70),
        PRV_INT,
    ),
    "signed_odd_digits, even": (
        lambda: signed_odd_digits(PRV_INT & ~1, 4, 70),
        PRV_INT & ~1,
    ),
    "signed_odd_digits, too large": (
        lambda: signed_odd_digits(PRV_INT | 1, 4, 10),
        PRV_INT | 1,
    ),
    "signed_odd_digits, bytes": (
        lambda: signed_odd_digits(PRV, 4, 70),  # type: ignore[arg-type]
        PRV,
    ),
    "mod_inv, bytes": (
        lambda: nt.mod_inv(PRV, secp256k1.n),  # type: ignore[arg-type]
        PRV,
    ),
    "mod_inv_var, no inverse": (
        lambda: nt.mod_inv_var(Public(PRV_INT & ~1), 2**256),
        PRV_INT & ~1,
    ),
    "mod_inv, no inverse": (
        lambda: nt.mod_inv(PRV_INT & ~1, 2**256),
        PRV_INT & ~1,
    ),
    "mod_sqrt_var, bytes": (
        lambda: nt.mod_sqrt_var(PRV, secp256k1.p),  # type: ignore[arg-type]
        PRV,
    ),
    "mod_sqrt_var, no root": (
        lambda: nt.mod_sqrt_var(Public(PRV_INT + 1), secp256k1.p),
        PRV_INT + 1,
    ),
    "tonelli_var, no root": (
        lambda: nt.tonelli_var(Public(PRV_INT + 1), secp256k1.p),
        PRV_INT + 1,
    ),
    "legendre_symbol_var, bytes": (
        lambda: nt.legendre_symbol_var(PRV, secp256k1.p),  # type: ignore[arg-type]
        PRV,
    ),
    "rangeproof.sign, value out of range": (
        lambda: rangeproof.sign(1, 2**64, bytes(32), secp256k1.G),
        2**64,
    ),
}

_ARMS = [
    pytest.param(True, marks=needs_bindings, id="bindings"),
    pytest.param(False, id="python"),
]


def test_the_key_is_what_it_is_said_to_be() -> None:
    """The key is 32 bytes, a private key, and no x-coordinate."""
    assert len(PRV) == 32
    assert 0 < PRV_INT < secp256k1.n
    assert not is_x_coordinate_var(Public(PRV_INT))


@pytest.mark.parametrize("bindings", _ARMS)
@pytest.mark.parametrize("name", _CASES)
def test_no_exception_repeats_the_operand(
    name: str, bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Neither the exception nor anything chained to it names the operand."""
    if not bindings:
        no_bindings_anywhere(monkeypatch)
    call, secret = _CASES[name]
    with pytest.raises(EccException) as raised:
        call()
    for exc in _chain(raised.value):
        assert not _echoes(str(exc), secret), (name, "str", str(exc))
        assert not _echoes(repr(exc), secret), (name, "repr", repr(exc))
