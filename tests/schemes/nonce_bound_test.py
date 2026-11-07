# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the bound on the nonce derivations' retry loops.

A caller's hash function that never yields a candidate in 1..n-1 --
32 octets of 0xff, above the order of secp256k1 -- ends the derivation
with a refusal rather than a hang. `AllOnesHash` counts its digests and
raises past a limit, so an unbounded loop fails these tests.
"""

from collections.abc import Callable
from typing import Any

import pytest

from ecc import dsa, ssa
from ecc._utils import _MAX_NONCE_ATTEMPTS
from ecc.bip340_nonce import bip340_nonce_
from ecc.commit_nonce import _tweak
from ecc.curves import secp256k1
from ecc.exceptions import EccRuntimeError
from ecc.rfc6979_nonce import rfc6979_nonce_
from tests import AllOnesHash
from tests.secret_free import assert_secret_free

# fixed random values, as `assert_secret_free` asks
PRV_KEY = 0x1D2F3E4D5C6B7A8998A7B6C5D4E3F20112233445566778899AABBCCDDEEFF0A
MSG = bytes.fromhex("9f3a5c7e1b2d4f60718293a4b5c6d7e8f9011223344556677889900aabbccdde")
COMMIT_HASH = bytes.fromhex(
    "c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3"
)
RECEIPT = secp256k1.G

_CALLS: dict[str, Callable[[], Any]] = {
    "rfc6979": lambda: rfc6979_nonce_(MSG, PRV_KEY, secp256k1, AllOnesHash),
    "bip340": lambda: bip340_nonce_(MSG, PRV_KEY, None, secp256k1, AllOnesHash),
    "commit": lambda: _tweak(COMMIT_HASH, RECEIPT, b"tag", secp256k1, AllOnesHash),
    "dsa.sign_": lambda: dsa.sign_(MSG, PRV_KEY, hf=AllOnesHash),
    "ssa.sign_": lambda: ssa.sign_(MSG, PRV_KEY, hf=AllOnesHash),
}


@pytest.fixture(autouse=True)
def _reset_digests() -> None:
    AllOnesHash.digests = 0


@pytest.mark.parametrize("call", _CALLS.values(), ids=_CALLS.keys())
def test_a_hash_without_a_candidate_is_refused(call: Callable[[], Any]) -> None:
    """The derivation raises after its bound and quotes no secret."""
    with pytest.raises(EccRuntimeError) as caught:
        call()
    assert str(_MAX_NONCE_ATTEMPTS) in str(caught.value)
    assert AllOnesHash.digests > _MAX_NONCE_ATTEMPTS
    assert_secret_free(caught.value, [PRV_KEY.to_bytes(32, "big"), str(PRV_KEY), MSG])


def test_the_hash_stops_a_derivation_that_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past its limit the counting hash raises, which is what ends a hang."""
    monkeypatch.setattr(AllOnesHash, "LIMIT", 3)
    for _ in range(2):
        assert AllOnesHash().digest() == b"\xff" * 32
    assert AllOnesHash().hexdigest() == "ff" * 32
    with pytest.raises(AssertionError, match="does not stop"):
        AllOnesHash().digest()
