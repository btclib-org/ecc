# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Recovery against libsecp256k1's own cases, pinned in `tests/_data/README.md`.

Each recovery id must recover a key or refuse as upstream asserts. Why that
is not an authority other than the bindings is in the README, in its entry
for `secp256k1_recovery_vectors.json`.
"""

from typing import Any

import pytest

from ecc import dsa
from ecc.exceptions import EccRuntimeError, EccValueError
from tests import both_arms, load, vector_id

_LIBSECP256K1: dict[str, Any] = load(
    "schemes", "_data", "secp256k1_recovery_vectors.json"
)

_LIBSECP256K1_CASES = [
    pytest.param(case, id=vector_id(i, case["id"]))
    for i, case in enumerate(_LIBSECP256K1["cases"])
]


@pytest.mark.parametrize("case", _LIBSECP256K1_CASES)
@both_arms
def test_libsecp256k1_recovers_what_it_says_it_does(case: dict[str, Any]) -> None:
    """Each recovery id recovers a key or refuses, as upstream asserts.

    A key that is recovered verifies the signature it was recovered from.
    A zero r or s is refused: libsecp256k1 parses it and then declines to
    recover, and `recover_pub_key_` raises.
    """
    msg_hash = bytes.fromhex(_LIBSECP256K1["msg32"])
    r = int(case["r"], 16)
    s = int(case["s"], 16)
    for recid, recovers in case["recovers"].items():
        key_id = int(recid)
        if not recovers:
            with pytest.raises((EccValueError, EccRuntimeError)):
                sig = dsa.Sig(r, s, check_validity=False)
                dsa.recover_pub_key_(key_id, msg_hash, sig)
            continue
        sig = dsa.Sig(r, s)
        Q = dsa.recover_pub_key_(key_id, msg_hash, sig)
        assert dsa.verify_(msg_hash, Q, sig)
        assert Q in dsa.recover_pub_keys_(msg_hash, sig)
