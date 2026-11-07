# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ECDSA key recovery against the compact signatures of Bitcoin Core.

The vectors are `key_tests.cpp`'s: the compact signature, with its recovery
flag, that `CKey::SignCompact` writes for each of its keys over one message.
Recovering from it, in each spelling, must give the key of the WIF.
`tests/_data/README.md`, in its entry for the file, says what that does and
does not establish.

Each test runs on both arithmetics, so that the Python arm is held to these
answers and not only to the bindings'.
"""

import hashlib
from typing import Any

import pytest

from ecc import dsa
from ecc.curves import mult
from ecc.curves.sec_point import bytes_from_point
from tests import b58decode, both_arms, load, vector_id

_CORE: dict[str, Any] = load("schemes", "_data", "bitcoin_core_compact_vectors.json")

# `Hash` of Core's hash.h, which `key_tests.cpp` hashes its message with
CORE_HASH = hashlib.sha256(
    hashlib.sha256(_CORE["message"].encode("ascii")).digest()
).digest()


def core_vector(vector: dict[str, str]) -> tuple[int, bool, int, dsa.Sig]:
    """Return a Core vector's key, compression, recovery id and signature.

    The flag byte of a compact signature is 27 + recid, plus 4 for a
    compressed key.
    """
    # 0x80, the key, and 0x01 where the key is compressed
    payload = b58decode(vector["wif"])
    prv_key = int.from_bytes(payload[1:33], "big")
    compact = bytes.fromhex(vector["compact"])
    flag = compact[0] - 27
    sig = dsa.Sig(
        int.from_bytes(compact[1:33], "big"), int.from_bytes(compact[33:], "big")
    )
    return prv_key, bool(flag & 4), flag & 3, sig


CORE_PARAMS = [
    pytest.param(vector, id=vector_id(i, vector["id"]))
    for i, vector in enumerate(_CORE["keys"])
]


@pytest.mark.parametrize("vector", CORE_PARAMS)
@both_arms
def test_core_recovers_the_signers_key(vector: dict[str, str]) -> None:
    """Every spelling of the recovery gives the key of the WIF."""
    prv_key, compressed, key_id, sig = core_vector(vector)
    Q = mult(prv_key)

    assert dsa.recover_pub_key_(key_id, CORE_HASH, sig) == Q
    assert Q in dsa.recover_pub_keys_(CORE_HASH, sig)

    sec = dsa.recover_sec_(key_id, CORE_HASH, sig, compressed=compressed)
    assert sec == bytes_from_point(Q, compressed=compressed)
    assert sec == dsa.recover_sec_(
        key_id, CORE_HASH, sig.serialize(), compressed=compressed
    )
