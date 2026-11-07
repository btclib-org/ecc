# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for BIP341's x-only tweaks in `ecc.ssa`.

The vectors are BIP341's own, bip-0341/wallet-test-vectors.json of
bitcoin/bips: `tests/_data/README.md` has the revision vendored.
"""

from collections.abc import Callable
from typing import Any

import pytest

from ecc import ssa
from ecc.alias import Public
from ecc.curves import CURVES, mult, secp256k1
from ecc.exceptions import (
    EccException,
    EccTypeError,
    EccValueError,
)
from tests import REFUSED_SCALARS, both_arms, load, refused_secret, vector_id
from tests.secret_free import assert_secret_free

_VECTORS = load("schemes", "_data", "wallet-test-vectors.json")


def script_pub_key_vectors() -> list[Any]:
    """Load BIP341's `scriptPubKey` vectors as pytest params."""
    return [
        pytest.param(vector, id=vector_id(index))
        for index, vector in enumerate(_VECTORS["scriptPubKey"])
    ]


def key_path_vectors() -> list[Any]:
    """Load BIP341's `keyPathSpending` inputs as pytest params."""
    inputs = [
        spending
        for vector in _VECTORS["keyPathSpending"]
        for spending in vector["inputSpending"]
    ]
    return [
        pytest.param(spending, id=vector_id(index))
        for index, spending in enumerate(inputs)
    ]


@pytest.mark.parametrize("vector", script_pub_key_vectors())
@both_arms
def test_bip341_output_key(vector: dict[str, Any]) -> None:
    """The output key, and the parity each control block carries."""
    x, parity = ssa.pub_key_tweak_add_var(
        vector["given"]["internalPubkey"], vector["intermediary"]["tweak"]
    )
    assert x == int(vector["intermediary"]["tweakedPubkey"], 16)
    for control_block in vector["expected"].get("scriptPathControlBlocks", []):
        assert int(control_block[:2], 16) & 1 == parity


@pytest.mark.parametrize("spending", key_path_vectors())
@both_arms
def test_bip341_key_path(spending: dict[str, Any]) -> None:
    """The tweaked private key, which is the key of the tweaked output key."""
    prv_key = spending["given"]["internalPrivkey"]
    pub_key = spending["intermediary"]["internalPubkey"]
    tweak = spending["intermediary"]["tweak"]
    tweaked = int(spending["intermediary"]["tweakedPrivkey"], 16)

    assert ssa.gen_keys(prv_key)[1] == int(pub_key, 16)
    assert ssa.prv_key_tweak_add(prv_key, tweak) == tweaked

    x, parity = ssa.pub_key_tweak_add_var(pub_key, tweak)
    assert mult(tweaked)[0] == x
    # the internal key as its point, and as the point of its private key
    # before the negation, name the one x-only key
    P = ssa.point_from_bip340pub_key_var(pub_key)
    assert ssa.pub_key_tweak_add_var(P, tweak) == (x, parity)
    assert ssa.pub_key_tweak_add_var(mult(int(prv_key, 16)), tweak) == (x, parity)


@both_arms
def test_the_tweaked_key_is_the_key_of_the_tweaked_point() -> None:
    """On secp256k1 and, on the Python arm alone, on secp256r1."""
    for ec in (secp256k1, CURVES["secp256r1"]):
        for q, t in ((1, 0), (2, 3), (ec.n - 1, ec.n - 2), (0xC0FFEE, 0xBEEF)):
            _, x_Q = ssa.gen_keys(q, ec)
            x, parity = ssa.pub_key_tweak_add_var(x_Q, Public(t), ec)
            tweaked = ssa.prv_key_tweak_add(q, t, ec)
            Q = mult(tweaked, ec=ec)
            assert (Q[0], Q[1] & 1) == (x, parity)


@both_arms
def test_the_sum_at_infinity_is_refused() -> None:
    """A tweak that is the negated key of the even point has no output key."""
    q, x_Q = ssa.gen_keys(0xC0FFEE)
    with pytest.raises(EccValueError, match="public key at infinity"):
        ssa.pub_key_tweak_add_var(x_Q, Public(secp256k1.n - q))
    with pytest.raises(EccValueError, match="private key is zero") as e:
        ssa.prv_key_tweak_add(q, secp256k1.n - q)
    assert_secret_free(e.value, [f"{q:x}", q.to_bytes(32, "big")])


@both_arms
def test_refusals() -> None:
    """An internal key that is no x-coordinate, and a tweak out of range."""
    # 5 is the x of no point of secp256k1, as is p, which is no field element
    for x in (5, secp256k1.p, -1):
        with pytest.raises(EccValueError):
            ssa.pub_key_tweak_add_var(x, Public(1))
    for t in (-1, secp256k1.n):
        with pytest.raises(EccValueError, match="tweak not in 0..n-1"):
            ssa.pub_key_tweak_add_var(1, Public(t))
        with pytest.raises(EccValueError, match="tweak not in 0..n-1"):
            ssa.prv_key_tweak_add(1, t)
    with pytest.raises(EccTypeError):
        ssa.pub_key_tweak_add_var(1.0, 1)  # type: ignore[arg-type]
    with pytest.raises(EccTypeError):
        ssa.pub_key_tweak_add_var(1, 1, "secp256k1")  # type: ignore[arg-type]


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "prv_key_tweak_add": (lambda q: ssa.prv_key_tweak_add(q, 1), REFUSED_SCALARS),
}


_SECRET_CASES = [
    (name, kind) for name, (_, kinds) in _SECRET_CALLS.items() for kind in kinds
]


@pytest.mark.parametrize("name, kind", _SECRET_CASES)
@both_arms
def test_a_refusal_carries_no_secret(name: str, kind: str) -> None:
    """No piece of the secret is in the exception or in anything it chains."""
    call, _ = _SECRET_CALLS[name]
    secret, spellings = refused_secret(kind)
    with pytest.raises(EccException) as refused:
        call(secret)
    assert_secret_free(refused.value, spellings)
