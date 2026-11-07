# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ECDSA adaptor signatures, according to the DLC specification.

https://github.com/discreetlogcontracts/dlcspecs/blob/master/ECDSA-adaptor.md

An adaptor signature is an ECDSA signature encrypted under a point Y:
whoever knows y, with Y = y*G, `decrypt`s it into an ordinary signature,
and whoever holds both that signature and the adaptor signature
`recover`s y. `verify` checks, without y, that the adaptor signature
decrypts to a valid signature by the signing key.

**The scheme is for DLCs.** Each adaptor signature leaks the
Diffie-Hellman key of the signing key X and of Y (the specification's
warning), and no proof of knowledge of y is attached: a DLC's Y is an
oracle's anticipated signature, which the oracle knows by construction.
Do not use it where Y comes from somebody who need not know y.

**The wire format** is the specification's 162 octets,
`R || R_a || s_a || e || s`: R = k*Y and R_a = k*G, both 33-octet
compressed points; s_a = k^-1 (m + r*x) a scalar, r being the x-coordinate
of R modulo n; and (e, s), the 64-octet proof that R_a and R share the
discrete logarithm k over G and Y. The proof is not BIP374's
(`ecc.dleq`): its tag, its challenge input and its encoding
are the specification's, which is libsecp256k1-zkp's, so it lives here.
The curve, secp256k1, and the hash, sha256, are not arguments, as in
`ecc.dleq`.

**Nonces** follow libsecp256k1-zkp's `ecdsa_adaptor` module
(`src/modules/ecdsa_adaptor/main_impl.h`), the specification leaving
`sample_nonce` open: a BIP340-style tagged hash, with `aux` masking the
key, for k and for the proof's own nonce. `encrypt` draws a fresh `aux`
when it is not given. Passing `nonce` instead fixes k, and the proof's
nonce follows from it: a k used for two messages reveals the signing key.

**Timing.** k and y go through `mult` and `mod_inv`, and x only through
integer products, as in `dsa`; what `verify` handles is public and uses
the `_var` arithmetic. As everywhere in Python here, that is not
constant-time.
"""

from __future__ import annotations

import hashlib
import secrets

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
from ecc.dsa import Sig
from ecc.exceptions import EccRuntimeError, EccValueError
from ecc.hashes import tagged_hash
from ecc.number_theory import mod_inv, mod_inv_var

__all__ = [
    "assert_as_valid",
    "decrypt",
    "encrypt",
    "recover",
    "verify",
]

# libsecp256k1-zkp's tags: a different string is a different scheme, so
# they are frozen
_NONCE_TAG = b"ECDSAadaptor/non"
_AUX_TAG = b"ECDSAadaptor/aux"
_DLEQ_TAG = b"DLEQ"

_POINT_SIZE = 33
_SCALAR_SIZE = 32
_SIG_SIZE = 2 * _POINT_SIZE + 3 * _SCALAR_SIZE

# offsets into the 162 octets
_R_END = _POINT_SIZE
_RA_END = 2 * _POINT_SIZE
_SA_END = _RA_END + _SCALAR_SIZE
_E_END = _SA_END + _SCALAR_SIZE


def _scalar(octets: bytes) -> int:
    """Return 32 octets as an integer reduced modulo n, as a hash is."""
    return int.from_bytes(octets, "big") % secp256k1.n


def _nonce(tag: bytes, msg: bytes, key: bytes, point: bytes, aux: bytes) -> int:
    """Return the nonce `tag` names: tagged_hash(masked key || point || msg).

    `aux` masks the key as BIP340's does.
    """
    mask = tagged_hash(_AUX_TAG, aux)
    masked = bytes(a ^ b for a, b in zip(mask, key, strict=True))
    return _scalar(tagged_hash(tag, masked + point + msg))


def _challenge(Ra: Point, Y: Point, R: Point, A_G: Point, A_Y: Point) -> int:
    """Return the proof's challenge, H(R_a || Y || R || A_G || A_Y)."""
    t = b"".join(bytes_from_point(p, secp256k1) for p in (Ra, Y, R, A_G, A_Y))
    return _scalar(tagged_hash(_DLEQ_TAG, t))


def _prove(k: int, Y: Point, Ra: Point, R: Point, aux: bytes) -> tuple[int, int]:
    """Return (e, s) proving R_a = k*G and R = k*Y."""
    ra33 = bytes_from_point(Ra, secp256k1)
    r33 = bytes_from_point(R, secp256k1)
    msg = hashlib.sha256(ra33 + r33).digest()
    a = _nonce(
        _DLEQ_TAG,
        msg,
        k.to_bytes(_SCALAR_SIZE, "big"),
        bytes_from_point(Y, secp256k1),
        aux,
    )
    if a == 0:  # pragma: no cover -- a zero nonce is an unreachable preimage
        raise EccRuntimeError("invalid zero proof nonce")
    e = _challenge(Ra, Y, R, mult(a), mult(a, Y))
    return e, (a + e * k) % secp256k1.n


def encrypt(
    msg_hash: Octets,
    prv_key: Integer,
    enc_key: PubKey,
    aux: Octets | None = None,
    *,
    nonce: Integer | None = None,
) -> bytes:
    """Return the 162-octet adaptor signature of msg_hash under enc_key.

    `msg_hash` is 32 octets, the digest to be signed. `aux` is 32 octets
    of auxiliary randomness, fresh when absent. `nonce` replaces k, and
    with it the derivation: see the module docstring.
    """
    m = bytes_from_octets(msg_hash, _SCALAR_SIZE)
    x = scalar_from_prv_key(prv_key)
    Y = point_from_pub_key(enc_key)
    aux_bytes = (
        secrets.token_bytes(_SCALAR_SIZE)
        if aux is None
        else bytes_from_octets(aux, _SCALAR_SIZE)
    )

    if nonce is None:
        k = _nonce(
            _NONCE_TAG,
            m,
            x.to_bytes(_SCALAR_SIZE, "big"),
            bytes_from_point(Y, secp256k1),
            aux_bytes,
        )
        if k == 0:  # pragma: no cover -- a zero nonce is an unreachable preimage
            raise EccRuntimeError("invalid zero nonce")
    else:
        k = scalar_from_prv_key(nonce)

    Ra = mult(k)
    R = mult(k, Y)
    r = R[0] % secp256k1.n
    if r == 0:  # pragma: no cover -- r is zero only for an unreachable x of R
        raise EccRuntimeError("invalid zero r")
    s_a = mod_inv(k, secp256k1.n) * (_scalar(m) + r * x) % secp256k1.n
    if s_a == 0:  # pragma: no cover -- s_a is zero only for an unreachable k
        raise EccRuntimeError("invalid zero s_a")
    e, s = _prove(k, Y, Ra, R, aux_bytes)

    return (
        bytes_from_point(R, secp256k1)
        + bytes_from_point(Ra, secp256k1)
        + s_a.to_bytes(_SCALAR_SIZE, "big")
        + e.to_bytes(_SCALAR_SIZE, "big")
        + s.to_bytes(_SCALAR_SIZE, "big")
    )


def _parse_var(adaptor_sig: Octets) -> tuple[Point, Point, int, int, int]:
    """Return (R, R_a, s_a, e, s), refusing what the specification refuses.

    A wrong length, a point that is not on the curve, an s_a or s not in
    the scalar range, a zero s_a, or an R whose x-coordinate is zero
    modulo n. R's x-coordinate may be n or above; r is that value modulo n.

    The proof's e is not refused at n or above: it is reduced modulo n,
    as libsecp256k1-zkp reduces it with `secp256k1_scalar_set_b32` and no
    overflow check. The reduction is harmless, e being a hash output.
    `dleq` refuses e >= n because BIP374 says so. The DLC specification
    says only "Parse proof as two scalars (b,c)". A second
    encoding, e + n, fits 32 bytes only for e < 2^256 - n, about 2^-128
    of proofs.
    """
    data = bytes_from_octets(adaptor_sig, _SIG_SIZE)
    R = point_from_octets_var(data[:_R_END])
    Ra = point_from_octets_var(data[_R_END:_RA_END])
    s_a = int.from_bytes(data[_RA_END:_SA_END], "big")
    e = _scalar(data[_SA_END:_E_END])
    s = int.from_bytes(data[_E_END:], "big")
    if R[0] % secp256k1.n == 0:
        raise EccValueError("R has a zero x-coordinate modulo n")
    if not 0 < s_a < secp256k1.n:
        raise EccValueError("s_a not in 1..n-1")
    if s >= secp256k1.n:
        raise EccValueError("proof s not in 0..n-1")
    return R, Ra, s_a, e, s


def assert_as_valid(
    adaptor_sig: Octets,
    msg_hash: Octets,
    pub_key: PubKey,
    enc_key: PubKey,
) -> None:
    """Raise unless adaptor_sig is a valid encryption under enc_key.

    `verify` is the spelling that answers True or False; this one says
    why. An EccValueError for a proof that does not hold or an
    equation that does not balance, and for an argument that is
    malformed.
    """
    R, Ra, s_a, e, s = _parse_var(adaptor_sig)
    m = _scalar(bytes_from_octets(msg_hash, _SCALAR_SIZE))
    X = point_from_pub_key(pub_key)
    Y = point_from_pub_key(enc_key)

    # DLEQ_verify((R_a, Y, R), proof): A_G = s*G - e*R_a, A_Y = s*Y - e*R
    A_G = double_mult_var(Public(s), secp256k1.G, Public(-e), Ra)
    A_Y = double_mult_var(Public(s), Y, Public(-e), R)
    if A_G[1] == 0 or A_Y[1] == 0:
        raise EccValueError("invalid proof: infinity commitment")
    if e != _challenge(Ra, Y, R, A_G, A_Y):
        raise EccValueError("invalid proof: challenge mismatch")

    # the equation: R_a is s_a^-1 times (m*G + r*X)
    s_a_inv = mod_inv_var(Public(s_a), secp256k1.n)
    r = R[0] % secp256k1.n
    if double_mult_var(Public(s_a_inv * m), secp256k1.G, Public(s_a_inv * r), X) != Ra:
        raise EccValueError("adaptor signature does not match")


def verify(
    adaptor_sig: Octets,
    msg_hash: Octets,
    pub_key: PubKey,
    enc_key: PubKey,
) -> bool:
    """Return True if adaptor_sig encrypts a signature of msg_hash by pub_key.

    enc_key is the encryption key: its discrete logarithm decrypts it.

    Raises where an argument cannot be read as what it is: an adaptor
    signature that is not 162 octets, a digest not of 32 octets, a key
    that is no point. Answers False for an adaptor signature of the right
    size that the specification does not accept: an R or R_a that is no
    point, an R whose x-coordinate is zero modulo n, an s_a or a proof s
    out of range, a proof or an equation that does not hold.
    `assert_as_valid` says which.
    """
    # the structural refusals come first, outside the try that turns the
    # rest into False
    bytes_from_octets(adaptor_sig, _SIG_SIZE)
    bytes_from_octets(msg_hash, _SCALAR_SIZE)
    point_from_pub_key(pub_key)
    point_from_pub_key(enc_key)
    try:
        assert_as_valid(adaptor_sig, msg_hash, pub_key, enc_key)
    except EccValueError:
        return False
    return True


def decrypt(adaptor_sig: Octets, dec_key: Integer) -> Sig:
    """Return the low-s ECDSA signature `adaptor_sig` decrypts to under dec_key.

    The result is a signature of the message only if `verify` accepted
    the adaptor signature and dec_key is the discrete logarithm of its
    enc_key: nothing here checks either.
    """
    R, _, s_a, _, _ = _parse_var(adaptor_sig)
    y = scalar_from_prv_key(dec_key)
    s = s_a * mod_inv(y, secp256k1.n) % secp256k1.n
    return Sig(R[0] % secp256k1.n, min(s, secp256k1.n - s))


def recover(adaptor_sig: Octets, sig: Sig | Octets, enc_key: PubKey) -> int:
    """Return the decryption key of enc_key, from adaptor_sig and sig.

    `sig` is the signature `decrypt` made, in either form of s, or its
    DER encoding. An EccValueError where its r is not the adaptor
    signature's, or where the key it yields is neither enc_key's nor its
    negation: the signature is not a decryption of this adaptor
    signature under this key.
    """
    R, _, s_a, _, _ = _parse_var(adaptor_sig)
    Y = point_from_pub_key(enc_key)
    if isinstance(sig, Sig):
        if sig.ec != secp256k1:
            raise EccValueError("not a secp256k1 signature")
    else:
        sig = Sig.parse(sig)
    if sig.r != R[0] % secp256k1.n:
        raise EccValueError("r does not match the adaptor signature")
    sig.assert_valid()

    y = mod_inv_var(Public(sig.s), secp256k1.n) * s_a % secp256k1.n
    implied = mult(y)
    if implied == Y:
        return y
    if implied == (Y[0], secp256k1.p - Y[1]):
        return secp256k1.n - y
    raise EccValueError("signature does not decrypt this adaptor signature")
