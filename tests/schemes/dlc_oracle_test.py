# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.dlc_oracle` module.

The vectors are the DLC specification's own, `test/dlc_schnorr_test.json`
of discreetlogcontracts/dlcspecs, vendored under `tests/schemes/_data/`;
`tests/_data/README.md` pins the revision.
"""

import random
from collections.abc import Callable
from typing import Any

import pytest

from ecc import dlc_oracle, ssa
from ecc.curves import bytes_from_point, mult, secp256k1
from ecc.exceptions import EccException, EccValueError
from tests import REFUSED_SCALARS, both_arms, load, refused_secret, vector_id
from tests.secret_free import assert_secret_free

random.seed(42)

_VECTORS: list[dict[str, Any]] = load("schemes", "_data", "dlc_schnorr_test.json")


@pytest.mark.parametrize(
    "vector", _VECTORS, ids=[vector_id(i) for i in range(len(_VECTORS))]
)
@both_arms
def test_vectors(vector: dict[str, Any]) -> None:
    """Each case: the keys, the signature and its point."""
    inputs = vector["inputs"]
    msg = inputs["msgHash"]
    _, x_Q = ssa.gen_keys(inputs["privKey"])
    _, x_K = ssa.gen_keys(inputs["privNonce"])
    assert x_Q.to_bytes(32, "big").hex() == vector["pubKey"]
    assert x_K.to_bytes(32, "big").hex() == vector["pubNonce"]

    sig = dlc_oracle.sign_(msg, inputs["privKey"], inputs["privNonce"])
    assert sig.serialize().hex() == vector["signature"]
    assert ssa.verify_(msg, vector["pubKey"], sig)

    S = dlc_oracle.sig_point_var_(msg, vector["pubKey"], vector["pubNonce"])
    assert bytes_from_point(S).hex() == vector["sigPoint"]


def test_sig_point_is_s_times_g() -> None:
    """The signature point is s*G of the signature made with its nonce."""
    for _ in range(32):
        prv_key = 1 + random.randrange(secp256k1.n - 1)
        nonce = 1 + random.randrange(secp256k1.n - 1)
        msg = random.randbytes(random.randrange(64))
        sig = dlc_oracle.sign_(msg, prv_key, nonce)
        _, x_Q = ssa.gen_keys(prv_key)
        _, x_K = ssa.gen_keys(nonce)
        assert sig.r == x_K
        assert dlc_oracle.sig_point_var_(msg, x_Q, x_K) == mult(sig.s)


def test_invalid_nonce() -> None:
    """A nonce outside 1..n-1 is refused."""
    for nonce in (0, secp256k1.n):
        with pytest.raises(EccValueError):
            dlc_oracle.sign_(b"", 1, nonce)


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_MSG = bytes(range(32))

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "sign_, private key": (
        lambda s: dlc_oracle.sign_(_MSG, s, 3),
        REFUSED_SCALARS,
    ),
    "sign_, nonce": (lambda s: dlc_oracle.sign_(_MSG, 5, s), REFUSED_SCALARS),
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
