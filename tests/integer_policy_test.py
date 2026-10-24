# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on integer fields: a bool is not a number.

One file rather than a case per module, because the decision is one and
`ecc._utils.is_integer` states it. What makes it worth a
refusal is the json boundary: `true` decodes to `True`, and a schema
mistake would otherwise become a scalar of one, a coordinate of one or
an index of one instead of failing beside the input that caused it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from enum import IntEnum
from typing import Any

import pytest

from ecc._utils import (
    bytes_from_octets,
    hex_string,
    int_from_integer,
    is_integer,
)
from ecc.curves import (
    PreparedPoint,
    bytes_from_point,
    mult,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
)
from ecc.ecc import dahlias, frost
from ecc.ecc.borromean import BorromeanSig
from ecc.ecc.dsa import recover_pub_key_, recover_sec_
from ecc.ecc.dsa import sign as dsa_sign
from ecc.ecc.ssa import challenge_ as ssa_challenge_
from ecc.ecc.ssa import point_from_bip340pub_key_var
from ecc.ecc.ssa import sign as ssa_sign
from ecc.ecc.ssa import verify as ssa_verify
from ecc.exceptions import EccTypeError
from ecc.number_theory import mod_inv, mod_inv_batch_var, mod_inv_var

# the key is 1, so the x-only public key it verifies under is `secp256k1.G[0]`
_SSA_SIG = ssa_sign(b"msg", 1)
# the key is 1 as well, and key_id 1 is the candidate that recovers it
_DSA_MSG_HASH = hashlib.sha256(b"msg").digest()
_DSA_SIG = dsa_sign(b"msg", 1)
# a 1-of-1 FROST session over the key 1, for `partial_sig_verify_`'s signer_id
_FROST_PUB_SHARE = bytes_from_point(secp256k1.G)
_FROST_PUB_NONCE = bytes_from_point(secp256k1.G) * 2
_FROST_SESSION = frost.SessionContext(
    1,
    1,
    [0],
    [_FROST_PUB_SHARE],
    _FROST_PUB_SHARE,
    frost.nonce_agg_var([_FROST_PUB_NONCE]),
    [],
    [],
    b"msg",
)

# a DahLIAS session of one signer, for `partial_sig_verify`'s index
_DAHLIAS_PUB_NONCE = bytes_from_point(secp256k1.G) * 2


# every field whose contract is an integer quantity, with the shortest
# call that reaches its validator
_CASES: list[tuple[str, Callable[[Any], object]]] = [
    ("output size", lambda v: bytes_from_octets(b"x", v)),
    ("output size in an iterable", lambda v: bytes_from_octets(b"x", [v])),
    ("modular operand", lambda v: mod_inv_var(v, 7)),
    ("modulus", lambda v: mod_inv_var(3, v)),
    ("blinded modular operand", lambda v: mod_inv(v, 7)),
    ("blinded modulus", lambda v: mod_inv(3, v)),
    ("modular operand in a batch", lambda v: mod_inv_batch_var([3, v], 7)),
    ("modulus of a batch", lambda v: mod_inv_batch_var([3], v)),
    # one line stands behind the key path, `int_from_integer`:
    # `scalar_from_prv_key` reads an int through it, and `mult` and the
    # signing functions reach it through that
    ("integer coercion", int_from_integer),
    ("hex string", hex_string),
    ("curve multiplier", mult),
    ("curve scalar", scalar_from_prv_key),
    ("BIP340 x-only key", point_from_bip340pub_key_var),
    # not the converter twice: `verify` answers False where it cannot
    # verify, so what this pins is that the refusal is not one of those
    # answers -- `EccTypeError` is a `TypeError` and the except
    # there takes `ValueError`, which is issue btclib-org/btclib#814's rule
    ("BIP340 verification key", lambda v: ssa_verify(b"msg", v, _SSA_SIG)),
    # the trailing-underscore layer, which takes a bare `int` without
    # `int_from_integer` or a key converter's type gate: prepared is not
    # unchecked, and `is_integer` is asked of what these are handed
    (
        "BIP340 challenge x-coordinate",
        lambda v: ssa_challenge_(b"msg", v, 1, secp256k1, hashlib.sha256),
    ),
    (
        "BIP340 challenge nonce x-coordinate",
        lambda v: ssa_challenge_(b"msg", 1, v, secp256k1, hashlib.sha256),
    ),
    (
        "dsa recovery key_id",
        lambda v: recover_pub_key_(v, _DSA_MSG_HASH, _DSA_SIG),
    ),
    (
        "dsa sec recovery key_id",
        lambda v: recover_sec_(v, _DSA_MSG_HASH, _DSA_SIG),
    ),
    (
        "FROST prepared signer id",
        lambda v: frost.partial_sig_verify_(
            bytes(32), v, _FROST_PUB_NONCE, _FROST_PUB_SHARE, _FROST_SESSION
        ),
    ),
    (
        "DahLIAS signer index",
        lambda v: dahlias.partial_sig_verify(
            bytes(32), [bytes(32)], [bytes(32)], [_DAHLIAS_PUB_NONCE], v
        ),
    ),
    # `CurveGroup.is_on_curve` is the one funnel behind a `Point` tuple,
    # `point_from_pub_key`, `PreparedPoint` and `bytes_from_point`
    # included: `Q[1] == 0` marks infinity, so a bool `False` for y would
    # read as infinity for any x. One case per funnel pins the reach;
    # `secp256k1.G[1]` is a placeholder y that only the x-coordinate cases
    # need on the curve, is_on_curve's type check running before the
    # equation it would otherwise fail
    ("point x-coordinate", lambda v: secp256k1.is_on_curve((v, secp256k1.G[1]))),
    ("point y-coordinate", lambda v: secp256k1.is_on_curve((secp256k1.G[0], v))),
    ("public key point", lambda v: point_from_pub_key((v, secp256k1.G[1]))),
    (
        "BIP340 x-only point",
        lambda v: point_from_bip340pub_key_var((v, secp256k1.G[1])),
    ),
    ("prepared point", lambda v: PreparedPoint((v, secp256k1.G[1]))),
    ("point to sec bytes", lambda v: bytes_from_point((v, secp256k1.G[1]))),
    (
        "borromean s",
        lambda v: BorromeanSig(bytes(32), [[v]], check_validity=False).assert_valid(),
    ),
]

_IDS = [case[0] for case in _CASES]
_CALLS = [case[1] for case in _CASES]


@pytest.mark.parametrize("call", _CALLS, ids=_IDS)
@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_bool_is_not_an_integer_field(
    call: Callable[[Any], object], *, value: bool
) -> None:
    """Every integer field refuses a boolean, and refuses it as a type.

    `isinstance(True, int)` is what would let each of these through as
    one or zero.
    """
    with pytest.raises(EccTypeError):
        call(value)


# the sentence each of these gives back. Whichever control reaches the
# value first writes it, so an entry point moves between these families
# by gaining or losing a check above it and never by choosing a wording
# -- which is why a caller matches on the class. `_CASES` above is the
# wider list and pins the class rather than the text
_WORDINGS = [
    ("integer coercion", int_from_integer, "non-integer: True"),
    ("hex string", hex_string, "non-integer: True"),
    ("curve multiplier", mult, "non-integer: True"),
    ("curve scalar", scalar_from_prv_key, "non-integer: True"),
    ("dsa signing key", lambda v: dsa_sign(b"msg", v), "non-integer: True"),
    ("BIP340 x-only key", point_from_bip340pub_key_var, "non-integer: True"),
    # the trailing-underscore layer's own type gate on a bare `int`, one
    # sentence per parameter and neither routed through `int_from_integer`
    (
        "BIP340 challenge x-coordinate",
        lambda v: ssa_challenge_(b"msg", v, 1, secp256k1, hashlib.sha256),
        "non-integer x-coordinate: bool",
    ),
    (
        "BIP340 challenge nonce x-coordinate",
        lambda v: ssa_challenge_(b"msg", 1, v, secp256k1, hashlib.sha256),
        "non-integer nonce x-coordinate: bool",
    ),
    (
        "dsa recovery key_id",
        lambda v: recover_pub_key_(v, _DSA_MSG_HASH, _DSA_SIG),
        "non-integer key_id: True",
    ),
    (
        "dsa sec recovery key_id",
        lambda v: recover_sec_(v, _DSA_MSG_HASH, _DSA_SIG),
        "non-integer key_id: True",
    ),
    # `is_on_curve`'s own refusal of a bool coordinate, one sentence per
    # coordinate and shared by every funnel behind it
    (
        "point x-coordinate",
        lambda v: secp256k1.is_on_curve((v, secp256k1.G[1])),
        "non-integer x-coordinate: bool",
    ),
    (
        "point y-coordinate",
        lambda v: secp256k1.is_on_curve((secp256k1.G[0], v)),
        "non-integer y-coordinate: bool",
    ),
    (
        "public key point",
        lambda v: point_from_pub_key((v, secp256k1.G[1])),
        "non-integer x-coordinate: bool",
    ),
    (
        "prepared point",
        lambda v: PreparedPoint((v, secp256k1.G[1])),
        "non-integer x-coordinate: bool",
    ),
]


@pytest.mark.parametrize(
    "call, message",
    [(case[1], case[2]) for case in _WORDINGS],
    ids=[case[0] for case in _WORDINGS],
)
def test_which_check_refuses_the_bool_decides_the_sentence(
    call: Callable[[Any], object], message: str
) -> None:
    """Each wording, held to what is raised."""
    with pytest.raises(EccTypeError, match=message):
        call(True)


def test_the_integers_a_bool_refusal_must_not_take_with_it() -> None:
    """The same calls with a number, which is what the refusal is around.

    A test that only checks refusals passes just as well when the field
    refuses everything.
    """
    assert int_from_integer(1) == 1
    assert hex_string(1) == "01"
    assert mult(1) == secp256k1.G
    assert scalar_from_prv_key(1) == 1
    assert point_from_bip340pub_key_var(secp256k1.G[0]) == secp256k1.G
    assert ssa_verify(b"msg", secp256k1.G[0], _SSA_SIG)
    assert ssa_challenge_(b"msg", 1, 1, secp256k1, hashlib.sha256)
    assert recover_pub_key_(1, _DSA_MSG_HASH, _DSA_SIG) == secp256k1.G
    assert recover_sec_(1, _DSA_MSG_HASH, _DSA_SIG) == bytes_from_point(secp256k1.G)
    assert secp256k1.is_on_curve(secp256k1.G) is True
    assert point_from_pub_key(secp256k1.G) == secp256k1.G
    assert PreparedPoint(secp256k1.G).point == secp256k1.G
    assert bytes_from_point(secp256k1.G).hex().startswith("02")
    assert bytes_from_octets(b"x", 1) == b"x"
    assert bytes_from_octets(b"xx", [1, 2]) == b"xx"
    assert mod_inv_var(3, 7) == 5
    assert mod_inv(3, 7) == 5
    assert mod_inv_batch_var([3, 2], 7) == [5, 4]


def test_what_is_no_integer_at_all_is_refused_the_same_way() -> None:
    """The policy is about integers, and a bool is only its sharpest case.

    An output size that is neither a number nor an iterable of them is
    refused through the package's exception contract, not by `tuple()`
    answering "not iterable" from underneath it.
    """
    for out_size in (1.5, object(), "1"):
        with pytest.raises(EccTypeError, match="invalid output size type"):
            bytes_from_octets(b"x", out_size)  # type: ignore[arg-type]
    with pytest.raises(EccTypeError, match="invalid output size type"):
        bytes_from_octets(b"x", [1.5])  # type: ignore[list-item]


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    `type(value) is int` would refuse every `int` subclass, where the
    policy refuses one.
    """

    class Small(IntEnum):
        ONE = 1

    assert is_integer(Small.ONE)
    assert bytes_from_octets(b"x", Small.ONE) == b"x"
    assert int_from_integer(Small.ONE) == 1

    assert is_integer(0)
    assert is_integer(-1)
    assert not is_integer(True)
    assert not is_integer(False)
    assert not is_integer(1.0)
    assert not is_integer("1")
