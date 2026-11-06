# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Single-signer BIP340 adaptor signatures.

A pre-signature is made for an adaptor point T = t*G. Whoever knows t
`adapt`s it into an ordinary BIP340 signature, and whoever holds both
the pre-signature and that signature recovers t with `extract_adaptor_var`.
`extract_var` returns the T a pre-signature is for.

The functions follow the `schnorr_adaptor` module that
BlockstreamResearch/secp256k1-zkp#299 proposes
(`include/secp256k1_schnorr_adaptor.h`). That pull request is open and
unmerged, so it is a reference and not an authority: its encoding and
its nonce can still change.

Apart from the `_var` suffix, one name and its argument order depart from
it: `extract_adaptor_var(sig, pre_sig)` is PR 299's `extract_sec(pre_sig,
sig)`. The name and the order are those of `musig2.extract_adaptor`, as in
secp256k1-zkp's MuSig2 module.

The reference has no pre-signature verification: its `extract` returns
the adaptor point instead. `verify` here is that `extract_var` compared with
the expected T.

**The wire format** is 65 octets, `R' || s`. R' = k*G + T is a 33-octet
compressed point, and s = k + e*d where R' has an even y, -k + e*d
where it has an odd one. d is the private key of the x-only public key,
and e the BIP340 challenge over x(R'), that key and the 32-octet
message. Adding t, or -t for an odd R', makes (x(R'), s) a BIP340
signature.

**Nonces** follow the reference's nonce function: BIP340's derivation,
under the tags `SchnorrAdaptor/aux` and `SchnorrAdaptor/nonce`, with
the compressed T between the masked key and the public key. `presign`
draws a fresh `aux` when it is not given. Passing `nonce` fixes k
instead: one k used for two pre-signatures reveals the private key.

**Timing.** k and d go through `mult`, and k, d and t through integer
arithmetic. What `extract_var` handles is public and uses the `_var`
arithmetic. As everywhere in Python here, that is not constant-time.
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from ecc._utils import bytes_from_octets
from ecc.alias import Integer, Octets, Point, Public
from ecc.curves import (
    PubKey,
    bytes_from_point,
    double_mult_var,
    mult,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
)
from ecc.curves.sec_point import point_from_octets_var
from ecc.ecc import ssa
from ecc.exceptions import EccRuntimeError, EccValueError
from ecc.hashes import tagged_hash

__all__ = [
    "adapt",
    "assert_as_valid",
    "extract_adaptor_var",
    "extract_var",
    "presign",
    "verify",
]

# the reference's tags: a different string is a different scheme, so
# they are frozen
_NONCE_TAG = b"SchnorrAdaptor/nonce"
_AUX_TAG = b"SchnorrAdaptor/aux"

_POINT_SIZE = 33
_SCALAR_SIZE = 32
_PRE_SIG_SIZE = _POINT_SIZE + _SCALAR_SIZE


def _nonce(d: int, T: Point, x_P: int, msg: bytes, aux: bytes) -> int:
    """Return k: TaggedHash(nonce tag, masked d || T || x_P || msg) mod n."""
    mask = tagged_hash(_AUX_TAG, aux)
    key = d.to_bytes(_SCALAR_SIZE, "big")
    masked = bytes(a ^ b for a, b in zip(mask, key, strict=True))
    t = b"".join(
        [
            masked,
            bytes_from_point(T, secp256k1),
            x_P.to_bytes(_SCALAR_SIZE, "big"),
            msg,
        ]
    )
    return int.from_bytes(tagged_hash(_NONCE_TAG, t), "big") % secp256k1.n


def _challenge(x_R: int, x_P: int, msg: bytes) -> int:
    return ssa.challenge_(msg, x_P, x_R, secp256k1, sha256)


def presign(
    msg: Octets,
    prv_key: Integer,
    adaptor: PubKey,
    aux: Octets | None = None,
    *,
    nonce: Integer | None = None,
) -> bytes:
    """Return the 65-octet pre-signature of msg for the adaptor point.

    `msg` is the 32-octet message, signed as it is. `aux` is 32 octets
    of auxiliary randomness, fresh when absent. `nonce` replaces k: see
    the module docstring.
    """
    m = bytes_from_octets(msg, _SCALAR_SIZE)
    d = scalar_from_prv_key(prv_key)
    T = point_from_pub_key(adaptor)
    aux_bytes = (
        secrets.token_bytes(_SCALAR_SIZE)
        if aux is None
        else bytes_from_octets(aux, _SCALAR_SIZE)
    )

    # BIP340 signs for the even-y key
    x_P, y_P = mult(d)
    # selected by index, not under an `if`: the parity of y_P is not published
    d = (d, secp256k1.n - d)[y_P & 1]

    if nonce is None:
        k = _nonce(d, T, x_P, m, aux_bytes)
        if k == 0:  # pragma: no cover -- a zero nonce is an unreachable preimage
            raise EccRuntimeError("invalid zero nonce")
    else:
        k = scalar_from_prv_key(nonce)

    # R' is public, and so is k*G = R' - T: the _var sum leaks nothing
    R1 = secp256k1.add_var(mult(k), T)
    if R1[1] == 0:
        raise EccValueError("the nonce point k*G + T is infinity")
    if R1[1] % 2:
        k = secp256k1.n - k

    s = (k + _challenge(R1[0], x_P, m) * d) % secp256k1.n
    return bytes_from_point(R1, secp256k1) + s.to_bytes(_SCALAR_SIZE, "big")


def _parse_var(pre_sig: Octets) -> tuple[Point, int]:
    """Return (R', s), refusing an R' that is no point and an s not below n."""
    data = bytes_from_octets(pre_sig, _PRE_SIG_SIZE)
    R1 = point_from_octets_var(data[:_POINT_SIZE])
    s = int.from_bytes(data[_POINT_SIZE:], "big")
    if s >= secp256k1.n:
        raise EccValueError("s not in 0..n-1")
    return R1, s


def extract_var(pre_sig: Octets, msg: Octets, pub_key: ssa.BIP340PubKey) -> Point:
    """Return the adaptor point of a pre-signature of msg by pub_key.

    Any pre-signature that parses yields a point. Where the
    pre-signature was not made for this message and key, that point is
    not the adaptor point: `verify` is the call that compares.

    An EccValueError for an R' that is no point, an s not below n,
    and an R' whose k*G or T is infinity.
    """
    R1, s = _parse_var(pre_sig)
    m = bytes_from_octets(msg, _SCALAR_SIZE)
    P = ssa.point_from_bip340pub_key_var(pub_key)

    # k*G, up to the sign the parity of R' gave k
    R = double_mult_var(Public(s), secp256k1.G, Public(-_challenge(R1[0], P[0], m)), P)
    if R[1] == 0:
        raise EccValueError("k*G is infinity")
    if R1[1] % 2 == 0:
        R = secp256k1.negate(R)
    T = secp256k1.add_var(R1, R)
    if T[1] == 0:
        raise EccValueError("the adaptor point is infinity")
    return T


def assert_as_valid(
    pre_sig: Octets, msg: Octets, pub_key: ssa.BIP340PubKey, adaptor: PubKey
) -> None:
    """Raise unless pre_sig is a pre-signature of msg by pub_key for adaptor.

    `verify` is the spelling that answers True or False; this one says
    why.
    """
    T = point_from_pub_key(adaptor)
    if extract_var(pre_sig, msg, pub_key) != T:
        raise EccValueError("pre-signature is not for this adaptor point")


def verify(
    pre_sig: Octets, msg: Octets, pub_key: ssa.BIP340PubKey, adaptor: PubKey
) -> bool:
    """Return True if pre_sig adapts, under adaptor's secret, to a signature.

    The signature is a BIP340 signature of msg by pub_key.

    Raises where an argument cannot be read as what it is: a
    pre-signature that is not 65 octets, a message not of 32 octets, a
    key that is no key. Answers False for a pre-signature of the right
    size that does not hold: an R' that is no point, an s not below n,
    or one that yields no adaptor point or another one.
    `assert_as_valid` says which.
    """
    # the structural refusals come first, outside the try that turns the
    # rest into False
    bytes_from_octets(pre_sig, _PRE_SIG_SIZE)
    bytes_from_octets(msg, _SCALAR_SIZE)
    ssa.point_from_bip340pub_key_var(pub_key)
    point_from_pub_key(adaptor)
    try:
        assert_as_valid(pre_sig, msg, pub_key, adaptor)
    except EccValueError:
        return False
    return True


def adapt(pre_sig: Octets, sec_adaptor: Integer) -> ssa.Sig:
    """Return the BIP340 signature a pre-signature adapts to under sec_adaptor.

    Nothing here checks the result: where sec_adaptor is not the secret
    of the pre-signature's adaptor point, the signature does not verify.
    `ssa.verify_` is the caller's to run.
    """
    R1, s = _parse_var(pre_sig)
    t = scalar_from_prv_key(sec_adaptor)
    if R1[1] % 2:
        t = secp256k1.n - t
    return ssa.Sig(R1[0], (s + t) % secp256k1.n)


def extract_adaptor_var(sig: ssa.Sig | Octets, pre_sig: Octets) -> int:
    """Return the adaptor secret, from a pre-signature and its adaptation.

    `sig` is an `ssa.Sig` or its 64 octets. An EccValueError where
    its r is not the x-coordinate of the pre-signature's R'. An s that
    does not come from `adapt` yields a wrong secret, and nothing here
    can tell.
    """
    R1, s_pre = _parse_var(pre_sig)
    if isinstance(sig, ssa.Sig):
        if sig.ec != secp256k1:
            raise EccValueError("not a secp256k1 signature")
        sig.assert_valid()
    else:
        sig = ssa.Sig.parse(sig)
    if sig.r != R1[0]:
        raise EccValueError("r does not match the pre-signature")

    t = sig.s - s_pre if R1[1] % 2 == 0 else s_pre - sig.s
    return t % secp256k1.n
