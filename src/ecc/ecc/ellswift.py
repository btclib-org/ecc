# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ElligatorSwift: the SwiftEC map, its inverse and BIP324's x-only ECDH.

An ElligatorSwift encoding is 64 bytes that are indistinguishable from
random: a pair of field elements (u, t) that the SwiftEC map takes to an
x-coordinate of the curve. Every 64-byte string decodes -- there is no
invalid encoding to recognize -- which is what an observer is left with,
and what BIP324's v2 handshake needs of the keys it carries.

https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki

This module stops at `xdh`, BIP324's x-only ECDH over two encodings.
What BIP324 builds on its secret -- the key schedule, the cipher and the
packet framing -- is a protocol's, and not a fact about a curve.

`decode_var` is the map, and it is deterministic. `encode_var` and
`create` are its inverse, and are not: up to eight (u, t) pairs decode to one
x-coordinate, one of them is picked at random, and the randomness is the
point -- an encoding derived from the key alone would be recognizable by
anyone who could derive it too. So there is no deterministic option here
the way `dsa.sign` takes a nonce: RFC6979 specifies the nonce it derives,
while nothing specifies a derivation for this, and one invented for
this package would be a promise the specification does not make.

**The map wants a curve with a == 0**, y^2 = x^3 + b, and every function
here refuses one with a != 0. secp256k1 is such a curve and so are the
other Koblitz curves of the catalogue, which is why these take an
`ec` at all: the Python arithmetic below is what serves them, where
secp256k1 is handed to the libsecp256k1 bindings.
"""

from __future__ import annotations

import secrets

from ecc._libsecp256k1 import ellswift as libsecp256k1_ellswift
from ecc._utils import assert_type, bytes_from_octets
from ecc.alias import Integer, Octets, Point
from ecc.curves import (
    Curve,
    PubKey,
    bytes_from_point,
    mult,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
)
from ecc.curves.curve import (
    _assert_valid_ec,
    _is_x_coordinate_var,
    _libsecp256k1_serves,
    _point_from_sec,
    _y_even_var,
)
from ecc.exceptions import (
    EccValueError,
)
from ecc.hashes import tagged_hash
from ecc.number_theory import legendre_symbol_var, mod_inv_var, mod_sqrt_var

__all__ = [
    "create",
    "decode_var",
    "encode_var",
    "xdh",
]

# sqrt(-3) and the inverse of two, per curve: the map's two constants,
# which cost a modular square root and an extended Euclid to derive and
# are the same for every call on a given curve
_CONSTANTS: dict[Curve, tuple[int, int]] = {}


def _constants(ec: Curve) -> tuple[int, int]:
    """Return (sqrt(-3), 1/2) mod ec.p, for a curve the map is defined on."""
    if ec not in _CONSTANTS:
        # a != 0 has no SwiftEC map at all, and asking for one is a
        # caller error rather than an arithmetic failure further down
        if ec._a:
            err_msg = "the ElligatorSwift map wants a curve with a == 0"
            raise EccValueError(err_msg)
        # -3 is a square whenever p == 1 mod 3, which every a == 0 curve
        # fit to carry a key is: the others have p+1 points, x -> x^3
        # being a bijection there, and mod_sqrt_var refuses them by itself
        _CONSTANTS[ec] = mod_sqrt_var(-3 % ec.p, ec.p), mod_inv_var(2, ec.p)
    return _CONSTANTS[ec]


def _is_square_var(a: int, p: int) -> bool:
    """Return True if a is a square mod p, zero included.

    Both directions ask it before an inverse or a root they might not
    need, as libsecp256k1 does with secp256k1_fe_is_square_var: a
    root of a non-square is a full exponentiation on secp256k1's p
    before it is refused, where the symbol is a gcd. Its duration is
    that of `legendre_symbol_var`.
    """
    return legendre_symbol_var(a, p) != -1


def _is_x_fraction_var(n: int, d: int, b: int, p: int) -> bool:
    """Return True if n/d is an x-coordinate of y^2 = x^3 + b, for d != 0.

    (n/d)^3 + b is a square exactly when d^4 times it is, which is
    d*n^3 + b*d^4 and takes no inverse. It is libsecp256k1's
    secp256k1_ge_x_frac_on_curve_var.
    """
    return _is_square_var((d * n**3 + b * d**4) % p, p)


def _xswiftec_var(u: int, t: int, ec: Curve) -> int:
    """Return the x-coordinate the field elements (u, t) map to.

    `xswiftec` of BIP324's reference implementation. u and t are taken
    modulo p, which is what makes every 64-byte string an encoding: the
    two 32-byte halves are read as integers that may reach past p, and
    reducing them is the first thing the map does.
    """
    p = ec.p
    b = ec._b
    minus_3_sqrt, inv2 = _constants(ec)
    u %= p
    t %= p
    # zero has no inverse, and either substitution keeps the map total
    if u == 0:
        u = 1
    s = t * t % p or 1
    g = (pow(u, 3, p) + b) % p
    # g + s == 0 would make q zero, and q is the denominator of the second
    # and third candidates
    if (g + s) % p == 0:
        s = 4 * s % p
    q = (g + s) % p
    # Each candidate is a fraction n/d, tested without an inverse; only the
    # one that returns is inverted. This is libsecp256k1's
    # secp256k1_ellswift_xswiftec_frac_var, with X and Y folded away:
    # Y^2 = -q^2/(12*s*u^2) and X/Y = sqrt(-3)*u*(g-s)/q.
    d = 3 * s * u * u % p
    n = (3 * s * pow(u, 3, p) - q * q) % p
    if _is_x_fraction_var(n, d, b, p):
        return n * mod_inv_var(d, p) % p
    # the second candidate is u*(c1*s + c2*g)/q, with c1 and c2 the
    # halves of sqrt(-3) - 1 and -sqrt(-3) - 1
    c1 = (minus_3_sqrt - 1) * inv2 % p
    c2 = (-minus_3_sqrt - 1) * inv2 % p
    n = u * (c1 * s + c2 * g) % p
    if _is_x_fraction_var(n, q, b, p):
        return n * mod_inv_var(q, p) % p
    # the third candidate, (X/Y - u)/2, is -(x2 + u)
    return -(n + u * q) * mod_inv_var(q, p) % p


def _xswiftec_inv_var(x: int, u: int, case: int, ec: Curve) -> int | None:  # noqa: PLR0911
    """Return a t with _xswiftec_var(u, t) == x, or None if this case has none.

    `xswiftec_inv` of BIP324's reference implementation. Up to eight t
    values map back to one x, and `case` in 0..7 selects which is
    attempted: each may fail, and the successful ones are distinct.
    """
    p = ec.p
    b = ec._b
    minus_3_sqrt, inv2 = _constants(ec)
    x %= p
    u %= p

    if case & 2 == 0:
        # -x-u being an x-coordinate means the pair would decode through
        # the third candidate of _xswiftec_var, which has priority: the
        # encoding would not round-trip, so this case has no answer
        if _is_x_coordinate_var((-x - u) % p, ec):
            return None
        v = x
        num = -(pow(u, 3, p) + b) % p
        den = (u * u + u * v + v * v) % p
        # s = num/den is a square exactly when num*den is, and den is not
        # zero: x being an x-coordinate and -x-u not one rules it out.
        # The test comes before the inverse, which a failing case does
        # not pay for
        if not _is_square_var(num * den % p, p):
            return None
        s = num * mod_inv_var(den, p) % p
    else:
        s = (x - u) % p
        if s == 0 or not _is_square_var(s, p):
            return None
        q = -s * (4 * (pow(u, 3, p) + b) + 3 * s * u % p * u) % p
        if not _is_square_var(q, p):
            return None
        r = mod_sqrt_var(q, p)  # a square, so a root exists
        # r == 0 makes the two cases that differ by its sign the same t,
        # and only one of them is to return it
        if case & 1 and r == 0:
            return None
        v = (-u + r * mod_inv_var(s, p)) * inv2 % p

    w = mod_sqrt_var(s, p)

    # the low and high bits of case pick the signs of the two square
    # roots, which is the encoding the paper's four branches take
    if case & 5 == 0:
        return -w * (u * ((1 - minus_3_sqrt) % p) % p * inv2 + v) % p
    if case & 5 == 1:
        return w * (u * ((1 + minus_3_sqrt) % p) % p * inv2 + v) % p
    if case & 5 == 4:
        return w * (u * ((1 - minus_3_sqrt) % p) % p * inv2 + v) % p
    return -w * (u * ((1 + minus_3_sqrt) % p) % p * inv2 + v) % p


def _x_t_from_ell_var(ell: bytes, ec: Curve) -> tuple[int, int]:
    """Return the decoded x-coordinate and the reduced t beside it."""
    size = ec.p_size
    u = int.from_bytes(ell[:size], byteorder="big", signed=False) % ec.p
    t = int.from_bytes(ell[size:], byteorder="big", signed=False) % ec.p
    return _xswiftec_var(u, t, ec), t


def _point_from_ell_var(ell: bytes, ec: Curve) -> Point:
    """Return the point the encoding decodes to, in Python."""
    x, t = _x_t_from_ell_var(ell, ec)
    # the parity of t is the y the pair names, which is the half of the
    # encoding BIP324's own reference implementation leaves out: it maps
    # to an x-coordinate and stops, where libsecp256k1's decode lifts the
    # point with secp256k1_fe_is_odd(t) as the tiebreaker
    y = _y_even_var(x, ec)
    return x, (ec.p - y if t % 2 else y)


def _ell_from_point_var(Q: Point, ec: Curve) -> bytes:
    """Return a random encoding of the point, in Python."""
    p = ec.p
    size = ec.p_size
    while True:
        # a nonzero field element and one of the eight cases; most pairs
        # have no t, and a fresh u is what the retry draws
        u = secrets.randbelow(p - 1) + 1
        t = _xswiftec_inv_var(Q[0], u, secrets.randbelow(8), ec)
        if t is None:
            continue
        # _xswiftec_inv_var pins the x-coordinate alone, so t and p-t encode
        # the two points of that x: the parity of t has to be the y's.
        # Neither Python reference has this step and neither is wrong --
        # BIP324's reference.py and Core's crypto/ellswift.py are x-only
        # end to end, so no y ever reaches them -- while libsecp256k1
        # wraps the same x-only map in the same condition, its
        # elligatorswift_var over xelligatorswift_var. It is here because
        # `decode_var` answers with a point; without it, half the encodings
        # would decode to -Q
        if t % 2 != Q[1] % 2:
            t = p - t
        return u.to_bytes(size, "big") + t.to_bytes(size, "big")


def _ell_from_octets(ell: Octets, ec: Curve) -> bytes:
    """Return the encoding as the octets the map reads, size checked."""
    # the size is the curve's, so this is where `decode_var` and `xdh`
    # first read it; `create` and `encode_var` take no encoding in
    # and reach the curve through the key converters instead
    _assert_valid_ec(ec)
    ell = bytes_from_octets(ell)
    if len(ell) != 2 * ec.p_size:
        err_msg = f"invalid ElligatorSwift size: {len(ell)}"
        err_msg += f" instead of {2 * ec.p_size} bytes"
        raise EccValueError(err_msg)
    return ell


def create(prv_key: Integer, ec: Curve = secp256k1) -> bytes:
    """Return an ElligatorSwift encoding of the private key's public key.

    The caller supplies no randomness, so it cannot hand in any that is
    derived from the key. Where the bindings serve,
    `secp256k1_ellswift_create` draws the encoding from a hash of the
    private key and fresh randomness, so the key adds entropy of its
    own. The Python path draws it from `secrets` alone, as `encode_var`
    does.

    The name is plain because the private key reaches only `mult`, whose
    algorithm does not follow its value. The variable-time encoding
    works on the public key.
    """
    q = scalar_from_prv_key(prv_key, ec)

    # the bindings hold the private key to the same 1..n-1 scalar_from_prv_key
    # does, so what reaches them is a key they take
    if _libsecp256k1_serves(ec, None):
        return libsecp256k1_ellswift.create(q)

    _constants(ec)  # the curve is refused here rather than after a mult
    return _ell_from_point_var(mult(q, ec.G, ec), ec)


def encode_var(pub_key: PubKey, ec: Curve = secp256k1) -> bytes:
    """Return an ElligatorSwift encoding of the public key.

    The randomness is drawn here and is not a function of the key, which
    is what BIP324 requires of it: two encodings of one key are
    unlinkable, and an encoding nobody can recompute is what makes them
    so. Where the private key is at hand, `create` is the call, and its
    docstring says why.
    """
    Q = point_from_pub_key(pub_key, ec)

    if _libsecp256k1_serves(ec, None):
        # uncompressed, as in `dh.diffie_hellman`: the encoding parses
        # what it is handed, and 65 octets are read where 33 are lifted,
        # which is the field square root not paid
        return libsecp256k1_ellswift.encode(bytes_from_point(Q, ec, compressed=False))

    _constants(ec)
    return _ell_from_point_var(Q, ec)


def decode_var(ell: Octets, ec: Curve = secp256k1) -> Point:
    """Return the point an ElligatorSwift encoding decodes to.

    Every encoding of the right size decodes, there being no invalid one
    to refuse: that is the property the scheme is built on.
    """
    ell = _ell_from_octets(ell, ec)

    # asked for the uncompressed form, so that both coordinates are read
    # off what the decoding already computed: the compressed one drops the
    # y and leaves it to be lifted back, which is a second parse and a
    # serialization of a point libsecp256k1 was holding
    if _libsecp256k1_serves(ec, None):
        return _point_from_sec(libsecp256k1_ellswift.decode(ell, compressed=False))

    return _point_from_ell_var(ell, ec)


def xdh(
    ell_a: Octets,
    ell_b: Octets,
    prv_key: Integer,
    initiating: bool,
    ec: Curve = secp256k1,
) -> bytes:
    """Return BIP324's shared secret of two ElligatorSwift encodings.

    `ell_a` is the initiator's encoding and `ell_b` the responder's, in
    that order whichever party calls. `prv_key` is the caller's own, and
    `initiating` says which of the two encodings is the caller's: True
    for `ell_a`. That correspondence is not checked, as libsecp256k1
    does not check it.

    The secret is the tagged hash `bip324_ellswift_xonly_ecdh` of
    `ell_a`, `ell_b` and the x-coordinate of the private key times the
    other party's point. Where the bindings serve, this is one call,
    `secp256k1_ellswift_xdh` with BIP324's hash function: the shared
    point stays in C, and only the secret comes back. The Python path
    multiplies with `mult`.

    A curve whose cofactor is not 1 is refused.

    The name is plain because the private key reaches only `mult` or
    libsecp256k1. The variable-time decoding works on the other party's
    public encoding.
    """
    ell_a = _ell_from_octets(ell_a, ec)
    ell_b = _ell_from_octets(ell_b, ec)
    q = scalar_from_prv_key(prv_key, ec)
    # a kind, not a truth: it decides which encoding is decoded, and a
    # wrong one gives a wrong secret rather than a refusal
    assert_type(initiating, bool, "initiating")
    # an encoding decodes to any point of the curve, and on a cofactor
    # above 1 most are outside the subgroup of G: the secret would then
    # tell the other party the private key modulo the cofactor. Clearing
    # the cofactor would compute a secret BIP324 does not define, and
    # refusing such a point would refuse most encodings
    if ec.cofactor != 1:
        err_msg = f"xdh wants a curve with cofactor 1: {ec.cofactor}"
        raise EccValueError(err_msg)

    # party 0 is A, the initiator, as in `secp256k1_ellswift_xdh`
    if _libsecp256k1_serves(ec, None):
        return libsecp256k1_ellswift.xdh(ell_a, ell_b, q, 0 if initiating else 1)

    theirs = ell_b if initiating else ell_a
    x = mult(q, _point_from_ell_var(theirs, ec), ec)[0]
    tag = b"bip324_ellswift_xonly_ecdh"
    return tagged_hash(tag, ell_a + ell_b + x.to_bytes(ec.p_size, "big"))
