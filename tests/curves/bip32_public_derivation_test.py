# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP32's public derivation vectors, walked with `PubKeyTweakChain`.

The vectors are the extended public keys of BIP32's test vectors 1, 2
and 5: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.
`tests/_data/README.md` gives the revision transcribed.

Each entry is an xpub and the unhardened indexes that lead from it to the
xpubs after it. The chain is built once per entry, so an entry of two
indexes walks two successive tweaks, the second from the child the first
returned.
"""

import hashlib
import hmac
from typing import Any

import pytest

from ecc.curves import PubKeyTweakChain
from ecc.exceptions import EccValueError
from tests import b58decode, both_arms, load

_VECTORS = load("curves", "_data", "bip32_public_derivation.json")


def _chain_code_and_key(xpub: str) -> tuple[bytes, bytes]:
    """Return the chain code and the compressed key of an xpub."""
    payload = b58decode(xpub)
    return payload[13:45], payload[45:78]


@both_arms
@pytest.mark.parametrize("vector", _VECTORS["derivations"])
def test_public_derivation(vector: dict[str, Any]) -> None:
    """Each child key and chain code is the one the vector gives."""
    chain_code, key = _chain_code_and_key(vector["xpub"])
    chain = PubKeyTweakChain(key)
    for index, child in zip(vector["indexes"], vector["children"], strict=True):
        data = key + index.to_bytes(4, "big")
        digest = hmac.new(chain_code, data, hashlib.sha512).digest()
        key = chain.tweak_add_var(digest[:32])
        chain_code = digest[32:]
        assert (chain_code, key) == _chain_code_and_key(child)


@both_arms
@pytest.mark.parametrize("vector", _VECTORS["invalid_pub_keys"])
def test_an_invalid_pub_key_is_refused(vector: dict[str, Any]) -> None:
    """A key field that is no compressed point is refused by the constructor."""
    _, key = _chain_code_and_key(vector["xpub"])
    with pytest.raises(EccValueError):
        PubKeyTweakChain(key)
