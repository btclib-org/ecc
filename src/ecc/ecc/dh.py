# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Diffie-Hellman elliptic curve key agreement, per SEC 1 v.2.

Two parties, each holding the other's public key, compute the same
shared secret -- their key pair times the other's public point -- and
derive symmetric keying data from it through a key derivation
function. The curve and the KDF are the two things the parties must
agree on beforehand; SEC 1's KDF is `kdf.ansi_x9_63_kdf`, which
ecc.kdf holds beside RFC 5869's, and diffie_hellman is the agreement
built on it.

**Why `ecdh.shared_secret` of the bindings has no caller here, and this is the
place that says so** (issue btclib-org/btclib#909). That function multiplies and
hashes in one call, and the hash is SHA256 of the compressed shared point with
no way to change it: libsecp256k1 takes it as a C callback, so exposing it would
mean calling back into python from the middle of the computation. Each
computation listed below derives differently, so what is delegated is the
multiplication -- `ecdh.shared_point`, the same `secp256k1_ecdh` call answering
the point instead of its hash, and so the same `secp256k1_ecmult_const`,
constant time in the scalar. The derivation stays in python:

- `diffie_hellman` below runs SEC 1's ANSI-X9.63-KDF over the
  x-coordinate, under the hash function the caller passed;
- `ecc.ecc.ecies.derive_keys` hashes the *compressed point* with sha512 and
  cuts the 64 bytes three ways, which is BIE1's shape and not this one.

So the verdict is not that the function is wrong: it is that a shared
secret is a protocol's own derivation, and only a protocol agreeing with
libsecp256k1's default can hand the whole of it over. Neither of the two
here does.

`ecc.ecc.ellswift.xdh` hands its whole derivation over, through another
function: libsecp256k1 ships BIP324's hash with `secp256k1_ellswift_xdh`,
and `ellswift.xdh` of the bindings is that one call.
"""

from __future__ import annotations

from hashlib import sha256

# the module and not the function it calls: `from ecc.kdf import
# ansi_x9_63_kdf` would bind that name here too, leaving
# `ecc.ecc.dh.ansi_x9_63_kdf` a live spelling of a function this
# module does not define, where `ecc.kdf` is to be the only place
# it is defined
from ecc import kdf
from ecc._libsecp256k1 import shared_point as libsecp256k1_shared_point
from ecc.alias import HashF, Integer, Point
from ecc.curves import (
    Curve,
    bytes_from_point,
    mult,
    scalar_from_prv_key,
    secp256k1,
)
from ecc.curves.curve import _libsecp256k1_serves
from ecc.exceptions import EccRuntimeError, EccValueError

__all__ = [
    "diffie_hellman",
]


def diffie_hellman(
    dU: Integer,
    QV: Point,
    size: int,
    shared_info: bytes | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> bytes:
    """Diffie-Hellman elliptic curve key agreement scheme.

    http://www.secg.org/sec1-v2.pdf, section 6.1

    The shared point is a point that is not the generator multiplied by
    a secret, and on secp256k1 `ecdh.shared_point` of the bindings
    computes it here: `secp256k1_ecdh`, whose `secp256k1_ecmult_const` is
    constant time in dU, at a fraction of what the Python endomorphism
    path costs.

    `ecdh.shared_secret` of the bindings is a different function and not
    a substitute: it hashes the compressed shared point with SHA256,
    where this derives through ANSI-X9.63-KDF. The module docstring above
    has that verdict for both computations it lists.

    Cofactor Diffie-Hellman (SEC 1 v.2, section 3.3.2) on a curve whose
    cofactor is above 1: QV is multiplied by the cofactor before dU
    multiplies the product, so a component of QV outside ⟨G⟩ -- one
    `bytes_from_point` still serializes, nothing here confining QV to ⟨G⟩
    the way `sec_point.point_from_pub_key` does -- is annihilated by h·QV
    rather than surviving into the point dU multiplies and leaking dU's
    residue modulo that component's order (issue
    btclib-org/ecc#15). h == 1 on every curve without a
    cofactor, where this is QV unchanged.

    `dU` is read through `curves.scalar_from_prv_key`, which validates it
    into 1..n-1 before either arithmetic arm sees it, so a bool, a float, a
    negative int or a value at or above `ec.n` is refused identically
    whichever arm ends up serving the call (issue
    btclib-org/ecc#10). `QV` is refused the same way on both
    arms when it is the infinity point: nothing here otherwise confines it
    to a serializable point, but INF is the one value neither arm can turn
    into a shared secret, and checking it once ahead of the dispatch is
    what keeps the two arms agreeing on it.
    """
    d = scalar_from_prv_key(dU, ec)

    ec.require_on_curve(QV)
    if QV[1] == 0:
        err_msg = "invalid (INF) public key"
        raise EccValueError(err_msg)

    if _libsecp256k1_serves(ec, None):
        # uncompressed, which is the cheap form to hand over: parsing 65
        # octets reads both coordinates where 33 are a field square root,
        # and the point is here to be written either way, so the
        # multiplication that follows is spared the lift. The answer is
        # compressed, whose octets past the tag are the x-coordinate
        sec = libsecp256k1_shared_point(bytes_from_point(QV, ec, compressed=False), d)
        return kdf.ansi_x9_63_kdf(sec[1:], size, hf, shared_info)

    # the cofactor multiplication first and dU's second: h < n always, so
    # mult(ec.cofactor, ...)'s own reduction mod n leaves h untouched, and
    # only after it lands in ⟨G⟩ is reducing the second scalar mod n valid
    QV_in_subgroup = QV if ec.cofactor == 1 else mult(ec.cofactor, QV, ec)
    shared_secret_point = mult(d, QV_in_subgroup, ec)
    # QV is not INF, checked above, but a QV whose order divides the
    # cofactor still lands h*QV on INF, and d, in 1..n-1, cannot recover
    # from that
    if shared_secret_point[1] == 0:
        err_msg = "invalid (INF) key"
        raise EccRuntimeError(err_msg)
    shared_secret_field_element = shared_secret_point[0]
    z = shared_secret_field_element.to_bytes(ec.p_size, byteorder="big", signed=False)
    return kdf.ansi_x9_63_kdf(z, size, hf, shared_info)
