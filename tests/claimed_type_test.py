# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A value is tested by its own class, not by the class it claims.

`ecc._utils._has_type` is the test, and its docstring says why
`isinstance` is not enough; `_libsecp256k1`, which sits below `_utils`,
spells it out. The Mock cases below drive a public function with a Mock
claiming a type its type test accepts, and the value is read as the
object it is (issue #547). The last test reads the source instead, and
fails where a module of ecc calls `isinstance`.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from ecc import (
    borromean,
    dahlias,
    dsa,
    ecdsa_adaptor,
    frost,
    musig2,
    number_theory,
    rangeproof,
    ssa,
    ssa_adaptor,
)
from ecc.curves import PreparedPoint, mult, point_from_pub_key, scalar_from_prv_key
from ecc.exceptions import EccTypeError, EccValueError
from tests.gmpy2_test import _importorskip_gmpy2

_MSG = b"ecc"
_MSG_HASH = sha256(_MSG).digest()
_Q = mult(1)
_GEN = mult(2)
_DSA_SIG = dsa.sign(_MSG, 1)
_SSA_SIG = ssa.sign(_MSG, 1)
_OCTETS = "invalid octets type"
_PUB_KEY = "not a public key"
_BIP340_KEY = "not a BIP340 public key"


# (the module whose type test decides the refusal, a public call that
# reaches it, the type the argument claims through `__class__`, the
# EccTypeError's message): put `isinstance` back in that test and its
# Mock case fails, where a Mock a scheme reads as a Sig, for one, has
# its `ec` refused and not its octets
_REFUSED: tuple[tuple[str, Callable[[Any], object], type, str], ...] = (
    ("borromean", lambda v: borromean.BorromeanSig(v, [[1]]), bytes, "e0 must be"),
    (
        "borromean",
        lambda v: borromean.assert_as_valid(_MSG, v, [[_Q]]),
        borromean.BorromeanSig,
        _OCTETS,
    ),
    # `int_from_integer` would refuse the Mock as `sec_point` let it through
    ("_utils", scalar_from_prv_key, int, _OCTETS),
    ("sec_point", point_from_pub_key, bytes, _PUB_KEY),
    ("sec_point", point_from_pub_key, tuple, _PUB_KEY),
    ("sec_point", point_from_pub_key, PreparedPoint, _PUB_KEY),
    ("sec_point", lambda v: dsa.verify(_MSG, v, _DSA_SIG), PreparedPoint, _PUB_KEY),
    ("dahlias", dahlias.nonce_agg_var, list, "invalid pub_nonces type"),
    ("frost", frost.nonce_agg_var, list, "invalid pub_nonces type"),
    ("musig2", musig2.key_agg_var, list, "invalid pub_keys type"),
    ("dsa", lambda v: dsa.assert_as_valid(_MSG, _Q, v), dsa.Sig, _OCTETS),
    ("dsa", lambda v: dsa.assert_as_valid_(_MSG_HASH, _Q, v), dsa.Sig, _OCTETS),
    ("dsa", lambda v: dsa.verify(_MSG, _Q, v), dsa.Sig, _OCTETS),
    ("dsa", lambda v: dsa.verify_(_MSG_HASH, _Q, v), dsa.Sig, _OCTETS),
    (
        "dsa",
        lambda v: dsa.anti_exfil_host_verify(_MSG_HASH, _Q, v, b"\x00" * 32, _Q),
        dsa.Sig,
        _OCTETS,
    ),
    ("dsa", lambda v: dsa.recover_pub_keys(_MSG, v), dsa.Sig, _OCTETS),
    ("dsa", lambda v: dsa.recover_pub_key(0, _MSG, v), dsa.Sig, _OCTETS),
    ("dsa", lambda v: dsa.crack_prv_key_var(_MSG, v, b"", _DSA_SIG), dsa.Sig, _OCTETS),
    ("dsa", lambda v: dsa.crack_prv_key_var(_MSG, _DSA_SIG, b"", v), dsa.Sig, _OCTETS),
    (
        "ecdsa_adaptor",
        lambda v: ecdsa_adaptor.recover(
            ecdsa_adaptor.encrypt(_MSG_HASH, 1, _GEN), v, _GEN
        ),
        dsa.Sig,
        _OCTETS,
    ),
    ("ssa", lambda v: ssa.assert_as_valid(_MSG, v, _SSA_SIG), int, _BIP340_KEY),
    ("ssa", lambda v: ssa.assert_as_valid(_MSG, v, _SSA_SIG), tuple, _BIP340_KEY),
    (
        "ssa",
        lambda v: ssa.assert_as_valid(_MSG, v, _SSA_SIG),
        PreparedPoint,
        _BIP340_KEY,
    ),
    ("ssa", lambda v: ssa.verify(_MSG, v, _SSA_SIG), PreparedPoint, _BIP340_KEY),
    ("ssa", lambda v: ssa.assert_as_valid(_MSG, _Q, v), ssa.Sig, _OCTETS),
    ("ssa", lambda v: ssa.assert_as_valid_(_MSG, _Q, v), ssa.Sig, _OCTETS),
    (
        "ssa_adaptor",
        lambda v: ssa_adaptor.extract_adaptor_var(
            v, ssa_adaptor.presign(_MSG_HASH, 1, _GEN)
        ),
        ssa.Sig,
        _OCTETS,
    ),
    (
        "rangeproof",
        lambda v: rangeproof.assert_as_valid(_Q, v, _GEN),
        rangeproof.RangeProof,
        _OCTETS,
    ),
    (
        "rangeproof",
        lambda v: rangeproof.rewind(_Q, v, b"\x00" * 32, _GEN),
        rangeproof.RangeProof,
        _OCTETS,
    ),
)


@pytest.mark.parametrize(
    "call, claimed, message",
    [case[1:] for case in _REFUSED],
    ids=[f"{i}-{case[0]}-{case[2].__name__}" for i, case in enumerate(_REFUSED)],
)
@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_a_type_is_refused(
    call: Callable[[Any], object], claimed: type, message: str, mock: type[Mock]
) -> None:
    """The Mock is refused as the object it is, never read as `claimed`."""
    with pytest.raises(EccTypeError, match=message):
        call(mock(spec=claimed))


# as `_REFUSED`, for an iterable: a MagicMock is one by its own class
_REFUSED_UNLESS_ITERABLE: tuple[tuple[str, Callable[[Any], object], type], ...] = (
    ("borromean", lambda v: borromean.BorromeanSig(b"\x01", v), list),
    ("borromean", lambda v: borromean.BorromeanSig(b"\x01", [v]), list),
    ("borromean", lambda v: borromean.BorromeanSig.parse(b"\x01" * 32, v), list),
)


@pytest.mark.parametrize(
    "call, claimed",
    [case[1:] for case in _REFUSED_UNLESS_ITERABLE],
    ids=[
        f"{i}-{case[0]}-{case[2].__name__}"
        for i, case in enumerate(_REFUSED_UNLESS_ITERABLE)
    ],
)
def test_a_value_that_claims_an_iterable_is_refused(
    call: Callable[[Any], object], claimed: type
) -> None:
    """A Mock is no iterable by its own class, whatever it claims."""
    with pytest.raises(EccTypeError):
        call(Mock(spec=claimed))


def test_a_value_that_claims_an_iterable_is_read_as_its_own() -> None:
    """A MagicMock is an empty iterable by its own class."""
    with pytest.raises(EccValueError, match="no rings"):
        borromean.BorromeanSig(b"\x01", MagicMock(spec=list))
    with pytest.raises(EccValueError, match="ring 0 has no keys"):
        borromean.BorromeanSig(b"\x01", [MagicMock(spec=list)])


@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_an_mpz_is_no_operand(mock: type[Mock]) -> None:
    """`number_theory` refuses a Mock claiming gmpy2's mpz as no integer."""
    mpz = _importorskip_gmpy2().mpz
    with pytest.raises(EccTypeError):
        number_theory.mod_inv_var(mock(spec=mpz), 7)


def test_ecc_tests_a_type_only_through_has_type() -> None:
    """No module of ecc calls `isinstance`, and `_utils` calls `_has_type`."""
    src = Path(__file__).parents[1] / "src" / "ecc"
    calls = {
        path: [
            node.func.id
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        for path in src.rglob("*.py")
    }
    assert "_has_type" in calls[src / "_utils.py"]
    offenders = [path for path, names in calls.items() if "isinstance" in names]
    assert not offenders
