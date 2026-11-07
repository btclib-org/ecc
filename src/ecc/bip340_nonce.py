# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Generation of the ephemeral key (nonce) following BIP340.

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

BIP340 derives the nonce from the private key, the public key, and
the message, all behind a tagged hash, plus auxiliary randomness a:

nonce = TaggedHash('BIP0340/nonce', t||x_Q||msg)
with t = q xor TaggedHash('BIP0340/aux', a)

Where:

TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x)

This is the synthetic nonce: the deterministic derivation is the
security floor -- with no randomness at signing time (a counter as a,
even all zeros) a nonce still cannot repeat across different messages
-- and fresh randomness is the hardening BIP340 recommends on top,
against fault injection and side-channel attacks. The key is masked
with the hashed randomness by xor, rather than hashed together with
it, to keep the number of operations touching the actual secret low.
The dedicated tag is domain separation: RFC6979 is not reused because
sharing a derivation (and a key) with deterministic ECDSA could leak
the key through nonce reuse across the two schemes. Any deterministic
derivation, BIP340 warns, remains insecure in multi-party signing.
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from ecc._utils import _MAX_NONCE_ATTEMPTS, bytes_from_octets, int_from_bits
from ecc.alias import HashF, Integer, Octets, Point
from ecc.curves import Curve, mult, scalar_from_prv_key, secp256k1
from ecc.exceptions import EccRuntimeError
from ecc.hashes import tagged_hash

__all__ = [
    "bip340_nonce_",
]


def _stretch(tag: bytes, m: bytes, size: int, hf: HashF) -> bytes:
    """Return size bytes of TaggedHash(tag, m || I2OSP(i, 4)), i = 0, 1, ...

    MGF1's counter mode (RFC 8017 B.2.1), with the tagged hash as its hash.
    """
    blocks = -(-size // hf().digest_size)
    digests = b"".join(
        tagged_hash(tag, m + i.to_bytes(4, "big"), hf) for i in range(blocks)
    )
    return digests[:size]


def _bip340_nonce_(msg: bytes, q: int, Q: int, aux: bytes, ec: Curve, hf: HashF) -> int:
    # assume the random oracle model for the hash function,
    # i.e. hash values can be considered uniformly random

    # In general, taking a uniformly random integer modulo the
    # curve order n would produce a biased result.
    # However, if the order n is sufficiently close to 2^hf_len,
    # then the bias is not observable:
    # e.g. for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
    #
    # where one digest covers nlen bits, the loop below is the
    # unbiased implementation, which works also for
    # very-low-cardinality test curves
    hf_len = hf().digest_size
    # a hash shorter than the curve order takes the counter-mode branch,
    # for the aux mask here and for the nonce below: one digest would
    # mask only the low hlen bits of q
    stretched = hf_len * 8 < ec.nlen
    if stretched:
        randomizer = _stretch(b"BIP0340/aux", aux, ec.n_size, hf)
    else:
        randomizer = tagged_hash(b"BIP0340/aux", aux, hf)
    xor = q ^ int.from_bytes(randomizer, "big", signed=False)
    max_len = max(ec.n_size, hf_len)
    t = b"".join(
        [
            xor.to_bytes(max_len, byteorder="big", signed=False),
            Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg,
        ]
    )

    nonce_tag = b"BIP0340/nonce"
    if stretched:
        # One digest would leave every nonce below 2^hlen: a few
        # signatures then give the key away as a hidden number problem.
        # So whole digests are drawn in counter mode until they give at
        # least nlen + 64 bits, and reduced as FIPS 186-5 A.3.1 and
        # A.4.1 reduce them: the bias is below 2^-64 and the nonce is
        # never zero.
        # Whether this branch is taken depends on ec and hf alone, so
        # one pair never mixes the two derivations.
        size = -(-(ec.nlen + 64) // (hf_len * 8)) * hf_len
        digests = _stretch(nonce_tag, t, size, hf)
        return int.from_bytes(digests, "big") % (ec.n - 1) + 1

    for _ in range(_MAX_NONCE_ATTEMPTS):
        t = tagged_hash(nonce_tag, t, hf)
        # reducing the hash mod n -- whether the whole of it or its
        # leftmost nlen bits -- would introduce a bias, which is why
        # neither is done here.
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        nonce = int_from_bits(t, ec.nlen)  # candidate nonce
        if 0 < nonce < ec.n:  # acceptable value for nonce
            return nonce  # successful candidate
    reason = f"no nonce in 1..n-1 after {_MAX_NONCE_ATTEMPTS} candidates"
    raise EccRuntimeError(reason)


def bip340_nonce_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[int, int, int, int]:
    """Return a BIP340 ephemeral key (nonce), synthetic by default.

    The message is of any size: BIP340 puts no size restriction on it,
    and the nonce tagged hash absorbs any length just as the challenge
    does.

    A hash function shorter than the curve order gets as many tagged
    hashes as make at least nlen + 64 bits, reduced into 1..n-1: one
    digest would leave every nonce shorter than n. Its aux mask is
    stretched the same way to the size of n, so that it covers all of
    the key.
    """
    return _nonce_with_pub_key_(msg, prv_key, aux, ec, hf, None)


def _nonce_with_pub_key_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None,
    ec: Curve,
    hf: HashF,
    pub_key: Point | None,
) -> tuple[int, int, int, int]:
    """Return what `bip340_nonce_` returns, given prv_key's point if held.

    A given point saves the generator multiplication that derives it.
    It is not checked: a wrong one gives a signature that verifies under
    no key, which the default self-check refuses. Only `Signer` passes
    one, computed from its own scalar.
    """
    hf_len = hf().digest_size
    msg = bytes_from_octets(msg)

    q = scalar_from_prv_key(prv_key, ec)

    x_Q, y_Q = mult(q, ec=ec) if pub_key is None else pub_key
    # selected by index, not under an `if`: the parity of y_Q is not published
    q = (q, ec.n - q)[y_Q & 1]

    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux, hf_len)

    k = _bip340_nonce_(msg, q, x_Q, aux, ec, hf)
    x_K, y_K = mult(k, ec=ec)
    # selected by index, not under an `if`: the parity of y_K is not published
    k = (k, ec.n - k)[y_K & 1]

    return k, x_K, q, x_Q
