# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The type aliases of the public API, and the input conventions they name.

Octets and String below are the same union, so mypy cannot tell one
from the other: passing a text string where a hex-string is expected
is a type error this file names but no checker can catch. The distinction
is enforced at run time instead, by the converter each function calls on
its way in -- bytes_from_octets for Octets, str_from_string for String --
and it is documented here because that is the only place it can be read
as one piece.

Making Octets and String NewTypes would let mypy separate them, at the
cost of every caller having to wrap its literals: Octets("deadbeef")
instead of "deadbeef", throughout a public API whose whole style is to
accept whatever is convertible. For those two that is a different
package, not a fix to this one. Public below is a NewType because there
the wrap is the point: it is where a caller declares a value public.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from typing import Any, NewType, Protocol

__all__ = [
    "INF",
    "INFJ",
    "BinaryData",
    "CipherF",
    "HashF",
    "HashObject",
    "Integer",
    "JacPoint",
    "Octets",
    "Point",
    "Public",
    "String",
]

# hex-strings are strings that can be converted to bytes using bytes.fromhex,
# e.g.:
# "deadbeef"
# "dead beef"
# "04 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf
#     f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
# "02 cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
# "02cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
#
# Octets are used for a SEC 1 public key, a private key, a message hash,
# dsa.Sig (DER serialization of ECDSA signature),
# ssa.Sig (BIP340 serialization of Schnorr signature)
# etc.
#
# Every buffer, and not `bytes` alone: each is accepted at run time by
# every consumer of an `Octets`, `bytes_from_octets` being the one
# coercion they share and `curves.sec_point._PUB_KEY_TYPES` naming the same
# list from the other side
#: Bytes, or the hex-string that decodes to them, wherever raw bytes are
#: asked for.
Octets = bytes | str | bytearray | memoryview

# bytes or text string (not hex-string): a string that can be converted
# to bytes with encode(), e.g. a message to be signed, whose blanks are
# part of it
String = bytes | str | bytearray | memoryview

# binary data, usually to be consumed as byte stream,
# but possibly provided as Octets too
BinaryData = BytesIO | Octets

# hex-string or bytes representation of an int
#
# a str is read as a hex-string, always: int_from_integer("1234") is 4660,
# not 1234, and "9" raises rather than being nine. There is no ambiguity to
# resolve by convention here -- a decimal representation is what int itself
# is for, and int("1234") costs the caller nothing -- so the ambiguity is
# resolved the way every other str in this file resolves it
Integer = Octets | int

# CONTRIBUTING.md's "A `_var` suffix means the operand decides the work"
# says which parameters take it and what checks it
#: An integer the caller declares public, for a variable-time parameter.
Public = NewType("Public", int)


# What a HashF returns: as much of the hashlib object as this package uses,
# and no more. A Protocol rather than Any: under Any, hf().digest() and
# hf().digest_size go unchecked, and with them every expression downstream
# of a hash function -- in a mypy-strict code base a typo in either would
# be a runtime AttributeError.
#
# Not hashlib._Hash, which is what typeshed calls the class: a private
# name, and structural typing is the right tool for "whatever hashlib.new
# returns". typeshed writes this same Protocol beside it, under this very
# class's name, and marks it type_check_only, so importing that one is no
# option either.
#
# An extendable-output function is not one of these, and here is where it
# is refused: hashlib.shake_128 fails this Protocol statically, its
# digest() requiring the output length that digest() -> bytes does not
# declare, and its digest_size reading 0. Not a restriction of this package --
# typeshed derives HASHXOF from HASH through a type: ignore[override], and
# hmac.new rejects an XOF as a digestmod for the same reason, which is
# dsa.sign's answer too: rfc6979 hands hf to hmac.new, and HMAC over an
# XOF is not defined (NIST specifies KMAC instead). An XOF is a function
# of data *and* length, and the length has nowhere to live here, so what
# reads SHAKE vectors is an adapter pinning one, not a wider Protocol
class HashObject(Protocol):
    """The slice of a hashlib object this package reads, as a Protocol.

    Structural: anything hashlib.new returns satisfies it, and the
    members carry hashlib's own meanings.
    """

    @property
    def digest_size(self) -> int:
        """Return the digest length in bytes."""
        ...

    @property
    def block_size(self) -> int:
        """Return the internal block length in bytes."""
        ...

    @property
    def name(self) -> str:
        """Return the name hashlib.new would accept."""
        ...

    # Any, alone in this Protocol, and not for want of trying: hmac.new
    # takes a digestmod whose update() accepts typeshed's ReadableBuffer,
    # a union this package cannot spell before 3.12, collections.abc.Buffer
    # being 3.12 and the floor 3.11, and a narrower parameter here makes
    # the whole Protocol unassignable to hmac's -- rfc6979 hands hf to
    # hmac.new. The two members that are actually read, digest() and
    # digest_size, stay exact, which is the point of the Protocol
    def update(self, data: Any, /) -> None:
        """Absorb more data, as hashlib's update does."""
        ...

    def digest(self) -> bytes:
        """Return the digest of everything absorbed so far."""
        ...

    def hexdigest(self) -> str:
        """Return the digest as a hex string."""
        ...

    def copy(self) -> HashObject:
        """Return a clone that can absorb independently."""
        ...


# Hash digest constructor: it may be any name suitable to hashlib.new().
# Called with no argument and then fed through update(), which is how every
# hf parameter in the package is used -- digest() and digest_size are the
# whole of what it reads off the result, so no argument is the whole of the
# capability it needs. Typing a callback at the capability actually used is
# what leaves the widest set of callables able to be one: a lambda and a
# functools.partial are a HashF here, and typeshed types the same object
# the same way, hmac's digestmod being Callable[[], _HashObject].
#
# The price is that hf(data) does not type check, though hashlib.sha256 accepts
# it and that is what makes the distinction from a one-shot digest invisible at
# run time. A Protocol declaring __call__ with an optional positional parameter
# would take both spellings, and would take with the other hand: a zero-argument
# constructor would no longer be a HashF, which is contravariance and not an
# oversight. hashes.reduce_to_hlen is the one-shot digest, for whoever wants one
HashF = Callable[[], HashObject]

# A block cipher under a key and an initialization vector: (key, iv, data)
# to the transformed data. ecc.ecies takes one of these in each
# direction because it ships no cipher of its own; that module's docstring
# has the contract the two callables must honour, which this name cannot
# carry -- padding and block size are not in the signature.
#
# The three parameters are positional here and passed positionally, so a
# caller's own names for them do not have to match
CipherF = Callable[[bytes, bytes, bytes], bytes]

# Elliptic curve point in affine coordinates.
# Warning: to make Point a NamedTuple would slow down the code
Point = tuple[int, int]

# the infinity point in affine coordinates is INF = (int, 0)
# (no affine point has y=0 coordinate in a group of prime order).
# It can be checked with 'INF[1] == 0'
# The x-coordinate is arbitrary: 5 is preferred
# because it is not a valid x-coordinate in secp256k1
# (and even 5 + secp256k1.n is not a valid x-coordinate)
#
# The parenthetical is false of a curve whose full order -- cofactor
# times the prime n -- is even: such a curve has a real point at y=0,
# the group's own element of order 2, and that point has no affine
# spelling distinct from this one. curve.Curve.is_on_curve -- not the
# CurveGroup method it overrides, which has no G and no n to be
# ambiguous about -- refuses that one x-coordinate rather than reading
# it as INF (issue btclib-org/ecc#16); every catalogued
# curve of cofactor 1
# still reads any other y=0 tuple as infinity exactly as this comment
# describes.
INF = 5, 0

# Elliptic curve point in Jacobian coordinates.
JacPoint = tuple[int, int, int]

# Infinity point in Jacobian coordinates is INF = (int, int, 0).
# It can be checked with 'INF[2] == 0'
# The default x and y coordinates are arbitrary:
# 7, 0 are used because those are what one would obtain
# from the generic affine to Jacobian transformation
# of the INF Point
# which sends Q to its two coordinates followed by 1, or by 0 at infinity
INFJ = 7, 0, 0
