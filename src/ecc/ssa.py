# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Schnorr Signature Algorithm (ECSSA).

This implementation is according to BIP340-Schnorr:

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

The public key is the x-coordinate -- a field element -- of the curve
point associated to the private key 0 < q < n, so on secp256k1 a
public key is 32 bytes. Knowing q as the discrete logarithm of Q is
knowing n-q as the discrete logarithm of -Q, so {q, n-q} acts as one
private key and {Q, -Q} as the public key their shared x_Q names.

The dropped 02/03 prefix is implicit, not lost: verification needs an
unambiguous Y, so BIP340 fixes it as even, and the x-only key is the
compressed key 02||x with its prefix left unsaid. Halving the set of
valid public keys costs no security -- whoever breaks an x-only key
breaks the full key at the price of a negation -- and taking the bare
x as the key refuses a malleability: a verifier that accepted a point
and negated its odd Y would make every signature valid for two keys.

The hash function is BIP340's tagged SHA256,
TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x),
which makes a BIP340 hash invalid under any other tag and any other
scheme; the challenge uses tag 'BIP0340/challenge', the deterministic
nonce 'BIP0340/aux' and 'BIP0340/nonce'.

The challenge commits to the public key as well as to the nonce
point, c = TaggedHash('BIP0340/challenge', x_k||x_Q||msg), which
rules out public key recovery and is what makes batch verification
sound.

The challenge commits to the nonce point as well, and that dependency
is the Fiat-Shamir transform itself: hashing the commitment x_k
replaces the fresh challenge that an interactive verifier would send
only after receiving the commitment. Were c and the nonce chosen
independently, no private key would be needed: K = s*G - c*Q
satisfies verification for any Q.

The deterministic nonce is BIP340's own, not RFC6979's:

nonce = TaggedHash('BIP0340/nonce', t||x_Q||msg)
with t = q xor TaggedHash('BIP0340/aux', a), a the auxiliary randomness

The serialization is the fixed-size [r][s] -- p-size plus n-size
bytes, 64 on secp256k1 -- not the loosely specified ASN.1 DER of
ECDSA.

``sign_`` also takes a value to commit to inside the nonce,
sign-to-contract style (see ecc.commit_nonce for the tweak), and
the ``anti_exfil_*`` functions here are the protocol that construction
exists to support: the handshake bitcoin-core/secp256k1#1140 proposes
for BIP340, whose five steps and reasoning are in
``anti_exfil_host_commit``.
"""

from __future__ import annotations

import contextlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from types import TracebackType
from typing import Self, overload

from ecc._libsecp256k1 import ssa as libsecp256k1_ssa
from ecc._libsecp256k1 import (
    xonly_prvkey_tweak_add as libsecp256k1_xonly_prvkey_tweak_add,
)
from ecc._libsecp256k1 import xonly_tweak_add as libsecp256k1_xonly_tweak_add
from ecc._utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    int_from_bits,
    int_from_integer,
    is_integer,
    is_octets,
)
from ecc.alias import BinaryData, HashF, Integer, JacPoint, Octets, Point, Public
from ecc.bip340_nonce import _nonce_with_pub_key_, bip340_nonce_
from ecc.commit_nonce import (
    commit_entropy_,
    commit_nonce_,
    commit_point_var_,
)
from ecc.curves import (
    Curve,
    PreparedPoint,
    point_from_octets_var,
    scalar_from_prv_key,
    secp256k1,
)
from ecc.curves.curve import (
    _assert_in_subgroup,
    _assert_valid_ec,
    _BindingsRequiredError,
    _is_x_coordinate_var,
    _jac_double_mult_var,
    _libsecp256k1_serves,
    _multi_mult_x_only_var,
    _tweak_add_var,
    _y_even_var,
    mult,
)
from ecc.curves.sec_point import _scalar_from_tweak
from ecc.exceptions import (
    EccRuntimeError,
    EccTypeError,
    EccValueError,
)
from ecc.hashes import _assert_valid_hf, reduce_to_hlen, tagged_hash
from ecc.number_theory import mod_inv_var

__all__ = [
    "BIP340PubKey",
    "Sig",
    "Signer",
    "anti_exfil_host_commit",
    "anti_exfil_host_verify",
    "anti_exfil_sign",
    "anti_exfil_signer_commit",
    "assert_as_valid",
    "assert_as_valid_",
    "assert_batch_as_valid",
    "assert_batch_as_valid_",
    "batch_verify",
    "batch_verify_",
    "challenge_",
    "gen_keys",
    "point_from_bip340pub_key_var",
    "prv_key_tweak_add",
    "pub_key_tweak_add_var",
    "sign",
    "sign_",
    "verify",
    "verify_",
]

# bitcoin-core/secp256k1#1140 ("Schnorr sign-to-contract and anti-exfil")
# spells these `s2c/schnorr/point` and `s2c/schnorr/data`, in
# src/modules/schnorrsig/main_impl.h at its head 49c31379, and this tree
# matches it byte for byte: if it lands, a commitment made here opens
# there. bitcoin-core/secp256k1#1140 is open and unmerged, so it is a
# reference and not an authority -- its spelling can still change, and
# the pull request may never land at all. Named for the standard rather
# than for this package's `ssa`, and not under BIP0340/, which would claim the
# BIP defines this. Frozen all the same: a different string is a
# different scheme, and every signature already made would stop opening
_S2C_POINT_TAG = b"s2c/schnorr/point"
_S2C_DATA_TAG = b"s2c/schnorr/data"

# BIP340 serializes a signature as thirty-two octets of r and thirty-two
# of s, on secp256k1 and by that BIP alone: a Sig on another curve has no
# encoding here to be a length of
_REQUIRED_LENGTH = 64


@dataclass(frozen=True, init=False)
class Sig:
    """A BIP340-Schnorr signature: (r, s).

    r is a field element, 0 <= r < ec.p, the x-coordinate of the nonce
    point; s is a scalar, 0 <= s < ec.n, and zero is valid here where
    dsa.Sig refuses it, BIP340 placing no lower bound.
    """

    # 32 bytes x-coordinate field element
    r: int
    # 32 bytes scalar
    s: int
    ec: Curve = secp256k1

    # written out rather than an InitVar[bool] field and a __post_init__:
    # see the comment on dsa.Sig.__init__
    def __init__(
        self, r: int, s: int, ec: Curve = secp256k1, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "r", r)
        object.__setattr__(self, "s", s)
        object.__setattr__(self, "ec", ec)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse an r that is no x-coordinate, or an s outside 0..n-1."""
        # the curve first, as in dsa.Sig.assert_valid and for its reason:
        # both fields below are read against it
        _assert_valid_ec(self.ec)

        # Neither refusal below prints r or s: a value refused as a signature
        # may be a key put in the wrong place (section 7 of the btclib-org
        # standard, *A refusal carries no secret*).

        # r is a field element, fail if r is not a valid x-coordinate. The
        # question is existence: BIP340 fixes the y even, and verification
        # recomputes the point from the scalars rather than lifting this r, so
        # _is_x_coordinate_var and not _y_even_var (issue
        # btclib-org/btclib#622). The delegated lift is cheap on the accepting
        # path, so the reason is the refusing one: _y_even_var falls back to
        # ec.y_even_var for an x the bindings refuse, so refusing through it
        # costs the whole Python square root, several times what verifying a
        # good signature costs. That expensive answer is the one an attacker
        # picks, half of the field elements being no x-coordinate and costing
        # nothing to produce.
        #
        # A bool leaves the message here, which is where it belongs: r is
        # this signature's, and "invalid x-coordinate" does not say which
        # of the two fields is wrong. dsa.Sig phrases its own for the
        # same reason, with the congruence this one has no use for -- r
        # is a field element here, not a scalar reduced mod n
        if not _is_x_coordinate_var(Public(self.r), self.ec):
            raise EccValueError("r is not a valid x-coordinate")

        # s is a scalar, fail if s is not in [0, n-1]
        if not 0 <= self.s < self.ec.n:
            raise EccValueError("scalar s not in 0..n-1")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return BIP340's fixed-size r || s, 64 bytes on secp256k1."""
        if check_validity:
            self.assert_valid()

        out = self.r.to_bytes(self.ec.p_size, byteorder="big", signed=False)
        out += self.s.to_bytes(self.ec.n_size, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(cls: type[Sig], data: BinaryData, *, check_validity: bool = True) -> Sig:
        """Build a Sig from BIP340's r || s bytes, on secp256k1.

        The serialization does not name its curve, so parse reads the
        one BIP340 is defined over; a Sig on another curve is built
        directly.

        Sixty-four octets exactly, and a witness signature is not one:
        BIP341 appends the sighash type to it, which is a byte about the
        transaction and not part of the signature. Stripping it is the
        caller's, `signature[:64]`, as a script interpreter does
        after reading it.
        """
        stream = bytesio_from_binarydata(data)
        sig_bin = stream.read(_REQUIRED_LENGTH)

        # the length is checked whatever check_validity says, as a parse of a
        # fixed-size object checks its own: it is not an opinion about the
        # signature but what makes the two slices below mean anything. Skipped,
        # sixty-three octets would yield a Sig whose s is a thirty-one-byte
        # integer -- below the order, so valid -- and no bytes at all would
        # yield the Sig of (0, 0)
        if len(sig_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(sig_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise EccValueError(err_msg)
        assert_no_trailing(data, stream, "BIP340 signature")

        ec = secp256k1
        r = int.from_bytes(sig_bin[: ec.p_size], byteorder="big", signed=False)
        s = int.from_bytes(sig_bin[ec.p_size :], byteorder="big", signed=False)
        return cls(r, s, ec, check_validity=check_validity)


# an x-only key is an x, and these are the ways of writing one down:
# the integer itself; p-size octets or their hex, which is BIP340's own
# encoding of it; the 33 or 65 octets of a SEC point, whose x it is; and
# the point, prepared or not. An extended key is not among them: turning one
# into a key is the call of whatever reads it (issue btclib-org/btclib#1188)
BIP340PubKey = int | Octets | Point | PreparedPoint


def _x_from_bip340pub_key(x_Q: BIP340PubKey, ec: Curve) -> int:
    """Return the x-coordinate of a BIP340 public key, however spelled.

    The dispatch over the spellings, without the lift that
    `point_from_bip340pub_key_var` puts on top of it: what an x-only key is
    unlifted is an x, and a verification through the bindings has no use
    for the y -- `libsecp256k1_ssa.verify` takes the x-only octets, and
    proving x an x-coordinate is what parsing them does anyway (issue
    btclib-org/btclib#887).

    So the x that comes back here is not proved to be an x-coordinate of
    anything: it is validated as far as its spelling goes, and whoever
    lifts or parses it is what refuses the rest. Private for that reason.
    """
    # BIP340 key as integer, read through the library's one integer coercion
    # rather than taken as it comes: an x is a number, and a bool is not one
    # anywhere a number is (issue btclib-org/btclib#326). This was the last int
    # spelling of a key outside that rule; the tuple arm below is covered by
    # `is_on_curve`'s own refusal of a bool coordinate (issue
    # btclib-org/btclib#1249). `isinstance(True, int)` made `True` the key at x
    # = 1, an x-coordinate of secp256k1, so both arms lifted it and both
    # answered about it where `dsa.verify` refused the same value as a type: two
    # schemes disagreeing and not two arms, where the private side of issue
    # btclib-org/btclib#1206 had one scheme answering two ways.
    if isinstance(x_Q, int):
        return int_from_integer(x_Q)

    if isinstance(x_Q, PreparedPoint):
        x_Q = x_Q.point
    if isinstance(x_Q, tuple):
        # the same check `curves.point_from_pub_key` makes for a point,
        # which this function does not go through: on the curve,
        # and a y that is not zero -- `alias` marks infinity that way,
        # no affine point of a prime-order group having y = 0
        if ec.is_on_curve(x_Q) and x_Q[1] != 0:
            # a point of the curve is a key only where it is a point of
            # <G>, which a cofactor above 1 leaves open
            if ec.cofactor > 1:
                _assert_in_subgroup(x_Q, ec)
            return x_Q[0]
        raise EccValueError("not a valid public key")

    if is_octets(x_Q):
        # every spelling `Octets` names, which is what
        # `bytes_from_octets` takes. Accepted at all three sizes here,
        # where the dispatch this replaces took them at the SEC two and
        # refused them at the x-only one, its fallback having asked for
        # `(str, bytes)`
        #
        # the two octet spellings are told apart by length and not by
        # trying one and catching the other: p-size is BIP340's x-only
        # encoding, and the SEC sizes are a point whose x this wants.
        # `point_from_octets_var` is the parse and the proof for the second,
        # where the first is unproved here on purpose -- what an x-only
        # key is unlifted is an x, and the docstring above says who
        # proves it
        # the sizes go to `bytes_from_octets` rather than to
        # `point_from_octets_var`, which knows the SEC two: the x-only one is
        # this function's to accept, so a caller refused by the parse
        # below would be told that BIP340's own encoding is a wrong size
        sizes = (ec.p_size, ec.p_size + 1, 2 * ec.p_size + 1)
        octets = bytes_from_octets(x_Q, sizes)
        if len(octets) == ec.p_size:
            return int.from_bytes(octets, "big", signed=False)
        return point_from_octets_var(octets, ec)[0]

    raise EccTypeError("not a BIP340 public key")


def _y_even_in_subgroup_var(x: Public, ec: Curve) -> int:
    """Return the even y of an x, refusing a point outside <G>.

    `_y_even_var` and nothing more where the cofactor is 1. Where it is
    above 1 the lifted point need not be in <G>, and one of small order
    is no key and no nonce point: verification reads its multiples
    modulo n, which is wrong for such a point. The point is asked to be
    on the curve first, as `point_from_octets_var` does: the curve's real
    two-torsion x lifts to y = 0, which `_assert_in_subgroup` would read
    as infinity and accept.
    """
    y = _y_even_var(x, ec)
    if ec.cofactor > 1:
        ec.require_on_curve((x, y))
        _assert_in_subgroup((x, y), ec)
    return y


def point_from_bip340pub_key_var(x_Q: BIP340PubKey, ec: Curve = secp256k1) -> Point:
    """Return a verified-as-valid BIP340 public key as Point tuple.

    It supports:

    - an int, the x-coordinate itself
    - BIP340 Octets (bytes or hex-string, p-size Point x-coordinate)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - a PreparedPoint, read as the point it holds
    - native tuple
    """
    _assert_valid_ec(ec)

    # the lift is what validates the x, and the same one for every
    # spelling: an x-only key is an x and the even y that goes with it.
    # _y_even_var is ec.y_even_var answered by libsecp256k1 for secp256k1,
    # a fraction of the modular square root it replaces, and the Python
    # one for every other curve
    x = _x_from_bip340pub_key(x_Q, ec)
    return x, _y_even_in_subgroup_var(Public(x), ec)


def gen_keys(prv_key: Integer | None = None, ec: Curve = secp256k1) -> tuple[int, int]:
    """Return a BIP340 private/public (int, int) key-pair."""
    # as in dsa.gen_keys, and for its reason
    _assert_valid_ec(ec)

    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = scalar_from_prv_key(prv_key, ec)

    x_Q, y_Q = mult(q, ec=ec)
    # selected by index, not under an `if`: the parity of y_Q is not published
    q = (q, ec.n - q)[y_Q & 1]

    return q, x_Q


def pub_key_tweak_add_var(
    x_Q: BIP340PubKey, t: Public, ec: Curve = secp256k1
) -> tuple[int, int]:
    """Return the x-only key P + t*G, P the point of x_Q, and its y parity.

    BIP341's taproot output key: x_Q is the internal key, t the TapTweak,
    and the parity is what a script path spending commits to in its
    control block. The tweak is in 0..n-1. A sum at infinity, where t is
    the private key of -P, is refused.

    Checking a taproot commitment is this call and a comparison of what
    it answers, which is what `secp256k1_xonly_pubkey_tweak_add_check`
    does too.
    """
    _assert_valid_ec(ec)
    x = _x_from_bip340pub_key(x_Q, ec)
    tweak = _scalar_from_tweak(t, ec)

    # an x the bindings refuse, and the sum at infinity, fall through to
    # the Python arm, which says which of the two it was
    if _libsecp256k1_serves(ec, None) and 0 <= x < ec.p:
        with contextlib.suppress(ValueError):
            x_bytes, parity = libsecp256k1_xonly_tweak_add(
                x.to_bytes(ec.p_size, "big"), tweak
            )
            return int.from_bytes(x_bytes, "big", signed=False), parity

    Q = _tweak_add_var((x, _y_even_in_subgroup_var(Public(x), ec)), Public(tweak), ec)
    if Q[1] == 0:
        raise EccValueError("tweaked public key at infinity")
    return Q[0], Q[1] & 1


def prv_key_tweak_add(prv_key: Integer, t: Integer, ec: Curve = secp256k1) -> int:
    """Return the private key of the key `pub_key_tweak_add_var` answers.

    BIP341's taproot output private key: the key is negated where its
    point has an odd y, as `gen_keys` does, and the tweak is added. The
    tweak is in 0..n-1, and a sum of zero is refused.

    On secp256k1 the bindings compute it,
    `secp256k1_keypair_xonly_tweak_add`, in constant time in the key; the
    tweak is not treated as a secret, and libsecp256k1 multiplies the
    generator by it in variable time. The Python checks and conversions
    around that call are not constant time, nor is the Python arm.
    SECURITY.md's limitations name the Python steps.
    `curves.prv_key_tweak_add` is the sum without the negation.
    """
    q = scalar_from_prv_key(prv_key, ec)
    tweak = _scalar_from_tweak(t, ec)

    if _libsecp256k1_serves(ec, None):
        try:
            tweaked = libsecp256k1_xonly_prvkey_tweak_add(q, tweak)
        except ValueError as e:
            # key and tweak are in range, so the one sum refused is zero
            raise EccValueError("tweaked private key is zero") from e
        return int.from_bytes(tweaked, byteorder="big", signed=False)

    # selected by index, not under an `if`, as in gen_keys
    q = (q, ec.n - q)[mult(q, ec=ec)[1] & 1]
    q = (q + tweak) % ec.n
    if q == 0:
        raise EccValueError("tweaked private key is zero")
    return q


def challenge_(msg: Octets, x_Q: int, x_K: int, ec: Curve, hf: HashF) -> int:
    """Return the BIP340 challenge scalar over a prepared message.

    TaggedHash(BIP0340/challenge, x_K || x_Q || msg), reduced mod n.
    The message enters as it is, of any size, which is what the
    trailing underscore says throughout this module: no reduction by
    hf happens here.
    """
    _assert_valid_ec(ec)

    # prepared is not unchecked: the trailing underscore skips the reduction of
    # msg, not `is_integer`'s policy on x_K and x_Q, which `int_from_integer`
    # would refuse a bool for on the coerced spelling (issue
    # btclib-org/btclib#1248, CONTRIBUTING.md's "This repository in particular")
    if not is_integer(x_Q):
        raise EccTypeError(f"non-integer x-coordinate: {type(x_Q).__name__}")
    if not is_integer(x_K):
        raise EccTypeError(f"non-integer nonce x-coordinate: {type(x_K).__name__}")

    # the message, of any size ("Messages of Arbitrary Size" in BIP340):
    # the tagged hash below absorbs any length unambiguously, x_K and x_Q
    # being fixed at p_size each
    msg = bytes_from_octets(msg)

    t = b"".join(
        [
            x_K.to_bytes(ec.p_size, byteorder="big", signed=False),
            x_Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg,
        ]
    )
    t = tagged_hash(b"BIP0340/challenge", t, hf)

    c: int = int_from_bits(t, ec.nlen) % ec.n
    # a hash shorter than the curve order leaves c below 2^hlen, and
    # that is harmless: c is public, and a forger guessing it succeeds
    # with probability 2^-hlen, the hash function's own preimage bound
    # c = 0 removes the public key from verification, which degenerates
    # to s*G = K: anyone satisfies that with K = s*G, one signature
    # valid under every key. BIP340 does not bother rejecting it, as on
    # secp256k1 reaching c = 0 means finding a preimage of zero for the
    # tagged hash; but this Python path serves the low-cardinality test
    # curves too, where c = 0 is one challenge in n and the exhaustive
    # test shows the degenerate signature verifying under every key --
    # so refuse it here, for signing and verification alike
    if c == 0:
        raise EccRuntimeError("invalid zero challenge")
    return c


def _sign_(c: int, q: int, nonce: int, r: int, ec: Curve) -> Sig:
    # Private, for tests: it takes the challenge c as an argument, so
    # a test can explore every value of it on a low-cardinality curve.
    # That freedom is what Fiat-Shamir forbids -- the public API derives
    # c from the nonce point, committing before the challenge -- and it
    # is why this function must stay private.
    # c and q and nonce are assumed in 1..n-1
    if c == 0:  # c≠0 required as it multiplies the private key
        raise EccRuntimeError("invalid zero challenge")

    # s=0 is ok: in verification there is no inverse of s
    s = (nonce + c * q) % ec.n

    return Sig(r, s, ec)


def _checked_sign_(
    c: Public, signature: Sig, x_Q: Public, ec: Curve, verify: bool
) -> Sig:
    # the same contract as the single call into the bindings above,
    # the same default and the same refusal: a fallback answering
    # differently from the arm it stands in for is two libraries
    # wearing one name, and the answer to a check that failed is half
    # of what it answers. The challenge is passed in because the
    # commitment path recomputes it after the tweak, and it is the
    # tweaked one the signature commits to.
    #
    # The lift is the one thing this arm pays that the delegated one
    # does not: the nonce derivation answers only x_Q, so the even-y
    # point is recovered here, as `assert_as_valid_` does
    if not verify:
        return signature
    QJ = x_Q, _y_even_var(x_Q, ec), 1
    try:
        _assert_as_valid_(
            c,
            QJ,
            Public(signature.r),
            Public(signature.s),
            ec,
            ec._fixed_points,
        )
    except (ValueError, EccRuntimeError) as e:
        # its words are a verifier's -- `y_K is odd`, `signature
        # verification failed`, `INF has no y-coordinate` -- and are
        # not this caller's: they say what the check saw, where a
        # signer needs to hear what happened, which is that the
        # computation went wrong. They cannot be changed either, the
        # public `assert_as_valid_` sharing them, so the signing
        # sentence is raised over them and they are kept as the
        # cause. It is the bindings' own sentence and `dsa`'s on both
        # of its arms.
        #
        # Both hierarchies, which is the pair this file catches at
        # `verify_` and `verify` and `dsa` catches at the same
        # helper: a K that lands on infinity has no y to answer with
        # and is a ValueError, and that is the shape a nonce zeroed
        # after its point was computed takes -- s = c*q, so
        # sG - cQ is the point at infinity. `EccRuntimeError` by
        # name and not `RuntimeError`, because a RecursionError is
        # one and is not an answer about a signature
        raise EccRuntimeError(
            "signing produced a signature that does not verify"
        ) from e
    return signature


def _sign_python_(
    msg: bytes,
    prv_key: Integer,
    pub_key: Point | None,
    aux: bytes,
    ec: Curve,
    hf: HashF,
    verify: bool,
) -> Sig:
    # pub_key is prv_key's point where the caller holds it, so that the
    # nonce derivation does not multiply for it again
    # k is the nonce: an integer in the range 1..n-1.
    k, x_K, q, x_Q = _nonce_with_pub_key_(msg, prv_key, aux, ec, hf, pub_key)
    c = challenge_(msg, x_Q, x_K, ec, hf)
    return _checked_sign_(Public(c), _sign_(c, q, k, x_K, ec), Public(x_Q), ec, verify)


def _sign_commit_(
    msg: Octets,
    prv_key: Integer,
    nonce_aux: bytes,
    commit_hash: Octets,
    ec: Curve,
    hf: HashF,
    verify: bool,
) -> tuple[Sig, Point]:
    """Return the sign-to-contract signature and its receipt.

    ``nonce_aux`` is what reaches ``bip340_nonce_`` as auxiliary
    randomness. ``sign_``'s own commitment path passes its mix of the
    caller's aux and commit_hash; the anti-exfil protocol below passes
    commit_hash alone, already hashed by ``anti_exfil_host_commit``, so
    that the nonce a signature reaches depends on nothing a caller
    supplied on the side.
    """
    # k is the nonce: an integer in the range 1..n-1.
    k, x_K, q, x_Q = bip340_nonce_(msg, prv_key, nonce_aux, ec, hf)

    # the tweak moves the nonce's point, and BIP340 signs with the
    # even-y one: k comes back from bip340_nonce_ already normalized,
    # so it is the tweaked point whose parity is still to be settled --
    # and x_K, which the challenge commits to, is the tweaked one.
    # The receipt keeps the even-y point the tweak hashed
    k, receipt = commit_nonce_(commit_hash, k, _S2C_POINT_TAG, ec, hf)
    x_K, y_K = mult(k, ec=ec)
    # selected by index, not under an `if`: the parity of y_K is not published
    k = (k, ec.n - k)[y_K & 1]

    c = challenge_(msg, x_Q, x_K, ec, hf)

    # the signature is checked and the receipt is not: what opens the
    # commitment is `commit_point_var_` under the same r, which the caller
    # verifies with commit_hash and receipt in hand
    sig = _checked_sign_(Public(c), _sign_(c, q, k, x_K, ec), Public(x_Q), ec, verify)
    return sig, receipt


@overload
def sign_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit_hash: None = None,
) -> Sig: ...


@overload
def sign_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit_hash: Octets,
) -> tuple[Sig, Point]: ...


def sign_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    verify: bool = True,
    commit_hash: Octets | None = None,
) -> Sig | tuple[Sig, Point]:
    """Sign a message of any size according to BIP340 signature algorithm.

    The message is signed as it is: BIP340 puts no size restriction on
    it, so this takes the BIP340 message itself, of any length. `sign` is
    the other spelling: it reduces its argument with hf first, which is
    what this package's trailing underscore distinguishes -- whether the caller
    prepared the input or the library does it.

    If the deterministic nonce is not provided, the BIP340 specification
    (not RFC6979) is used.

    verify asks for the signature to be checked before it is answered
    with, and defaults to True. Here the default is the specification's
    and not only this library's policy: BIP340 puts the step inside
    *Default Signing* -- "If Verify(bytes(P), m, sig) returns failure,
    abort" -- where ECDSA's comes from Bitcoin Core. The flag exists for
    the caller who has measured the check against their own threat model,
    and `dsa.sign_` is where the same keyword is described at length. A
    check that fails raises EccRuntimeError saying that signing
    produced a signature that does not verify -- the words both arms use
    and `dsa`'s own -- with what the verification saw kept as the cause.

    No pub_key beside it, and that absence is a decision rather than an
    omission. What such an argument buys in `dsa` is the generator
    multiplication the check would otherwise do per signature; here there is
    none to save, the keypair holding the point already, so the check costs what
    it costs whether the caller holds the key or not --
    btclib-org/btclib-secp256k1#224 is where that is measured, and
    btclib-org/btclib#982 is where the two schemes are put side by side. It
    would buy nothing and sell one thing: a second reason a check can fail, and
    with it the discrimination step `dsa._abort_unless_checked` has to pay for.

    commit_hash is a value to commit to inside the nonce, sign-to-contract
    style: the signature is an ordinary BIP340 one, and the receipt
    returned beside it is what opens the commitment (see
    ecc.commit_nonce). Keyword-only, and the only argument that
    changes what is returned, so that neither is easy to pass by accident.
    A commitment does not displace aux: it joins it, both of them
    reaching the nonce as BIP340's auxiliary randomness.
    """
    msg = bytes_from_octets(msg)

    hf_len = hf().digest_size
    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux, hf_len)

    # the committed value has to reach the nonce derivation, or two
    # commitments over one message hand out the private key -- see
    # commit_nonce. BIP340 has the slot for it and dsa does not: `a` is
    # whatever the signer wants mixed in, so aux and the commitment are
    # hashed together into it and both still count. That is why ssa keeps
    # taking its aux where dsa refuses a nonce beside a commitment: an
    # aux is an input to the derivation, a nonce is its answer
    if commit_hash is not None:
        aux = commit_entropy_(aux + bytes_from_octets(commit_hash), _S2C_DATA_TAG, hf)

    # the curve and the hash function decide this, and the size of the
    # message does not. `libsecp256k1_ssa.sign` accepts only a 32-byte
    # message -- "the message hash must be 32 bytes", measured on
    # 0.7.1rc1 -- but `sign_custom` beside it takes BIP340's message of
    # any size, so every length reaches the constant-time C instead of
    # the Python arithmetic SECURITY.md publishes as not being constant
    # time.
    #
    # One call rather than a branch on the length: for a 32-byte message
    # the two answer the same signature octet for octet, and the
    # extraparams struct sign_custom fills costs a shade more (best of
    # nine, 3000 calls each) -- not a second code path's worth of a
    # signature.
    #
    # A commitment stays with the Python path: it tweaks the nonce, and
    # the nonce is the bindings' own to derive
    if _libsecp256k1_serves(ec, hf, commit_hash=commit_hash is not None):
        # the bindings take a scalar, and so does this module: what the
        # call buys is the range check and the octets
        q = scalar_from_prv_key(prv_key, ec)
        # the caller's `verify`, crossing with the rest: the bindings
        # perform the check and there is nothing for this arm to add,
        # BIP340's step being a bare verification under a point the
        # keypair already holds. What it costs is measured where it is
        # performed -- cheaper than ECDSA's own analogous step,
        # btclib-org/btclib-secp256k1#224 -- and is not re-measured here,
        # a figure of theirs kept in this file being one that ages when
        # they change and says nothing when it does
        try:
            signature = libsecp256k1_ssa.sign_custom(msg, q, aux, verify=verify)
        except RuntimeError as e:
            # the refusal is theirs and the hierarchy has to be this package's,
            # which is `dsa`'s rule at its own call into the bindings: a
            # caller catching EccException should not have to know
            # which arm answered. Their sentence is kept rather than
            # reworded, `_checked_sign_` raising the same one, so the two
            # arms refuse in the same words as well as under the same type
            raise EccRuntimeError(str(e)) from e
        return Sig.parse(signature)

    if commit_hash is None:
        return _sign_python_(msg, prv_key, None, aux, ec, hf, verify)

    return _sign_commit_(msg, prv_key, aux, commit_hash, ec, hf, verify)


@overload
def sign(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit: None = None,
) -> Sig: ...


@overload
def sign(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit: Octets,
) -> tuple[Sig, Point]: ...


def sign(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    verify: bool = True,
    commit: Octets | None = None,
) -> Sig | tuple[Sig, Point]:
    """Sign message according to BIP340 signature algorithm.

    The message msg is first processed by hf, yielding the value

    msg_hash = hf(msg),

    a sequence of bits of length *hf_len*.

    Normally, hf is chosen such that its output length *hf_len* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hf_len* and *nlen*; however, ECSSA supports all
    combinations of *hf_len* and *nlen*.

    The BIP340 deterministic nonce (not RFC6979) is used.

    verify asks for the signature to be checked before it is answered
    with, as in `sign_`, which is where the default and the absence of a
    pub_key beside it are explained.

    commit is a value to commit to inside the nonce, and is reduced by hf
    as msg is: `sign_` is the spelling that takes the two hashes.
    """
    msg_hash = reduce_to_hlen(msg, hf)
    if commit is None:
        return sign_(msg_hash, prv_key, aux, ec, hf, verify=verify)
    return sign_(
        msg_hash,
        prv_key,
        aux,
        ec,
        hf,
        verify=verify,
        commit_hash=reduce_to_hlen(commit, hf),
    )


class Signer:
    """Sign several messages under one key, building the keypair once.

    `sign_` builds a `secp256k1_keypair` and wipes it before returning,
    so a second signature under the same key builds it again -- and that
    keypair is a multiplication of the generator, about half of what a
    BIP340 signature costs. This holds one across calls instead, which is
    worth better than half a signature each time. The measurement per
    batch size is in btclib-org/btclib's CHANGELOG, in the entry that
    introduced this class, an entry being read as the history of a
    release where this is read as a statement about the code as it
    stands.

    The same signatures come out, `sign` here being `sign_` over the
    keypair the signer holds, with the same default aux -- 32 octets
    drawn afresh per signature where the caller names none. The octets
    are what comes back rather than a `Sig`, that being what the callers
    of this want: a psbt writes a signature into a field, and building a
    `Sig` to serialize it again is the round trip this saves beside the
    keypair.

    **What this hands the caller is the lifetime of a secret.**
    `sign_` owns a keypair for the length of a call and wipes it in a
    `finally`; a signer holds one until told to let go. `wipe` is that
    instruction and the `with` statement is how to give it without
    having to remember::

        with ssa.Signer(prv_key) as signer:
            ...

    which wipes on the way out whether the block ended in a signature or
    in an exception. A wiped signer refuses to sign rather than signing
    with the zeros, and cannot be revived. So this is for a caller that
    already holds the secret for several signatures -- `SoftwareSigner`
    signing every leaf a psbt names one key in -- and a lone signature
    that drops the key afterwards is what `sign_` already is.

    A curve or a hash function the bindings do not serve has no keypair
    to hold: there the signer holds the key's public point, computed once.
    On that arm `wipe` has no keypair to overwrite and the `with` still
    reads the same -- what it does there is drop the scalar and stop the
    signing, which is all it can. And the scalar is held on that arm
    alone: where a keypair exists it holds the same secret in memory that
    can be overwritten, so a second copy as a python int would be kept
    for nothing. What is not solved either way is the object the private
    key arrived in, nor that scalar where the Python arm needs it -- an
    int cannot be overwritten, only dropped, and SECURITY.md's limitations
    section is where that is stated for the library at large.
    """

    def __init__(
        self, prv_key: Integer, ec: Curve = secp256k1, hf: HashF = sha256
    ) -> None:
        _assert_valid_hf(hf)
        # the scalar, whatever spelling the key arrived in, and the
        # validation with it -- this is a public constructor and the
        # refusal belongs at it rather than at the first signature
        self._q = scalar_from_prv_key(prv_key, ec)
        self._ec = ec
        self._hf = hf
        self._hf_len = hf().digest_size
        self._signer = (
            libsecp256k1_ssa.Signer(self._q) if _libsecp256k1_serves(ec, hf) else None
        )
        # the Python arm's counterpart of the keypair's stored point:
        # public, and multiplied for once here rather than per signature
        self._Q = mult(self._q, ec=ec) if self._signer is None else None
        # the scalar is what the Python arm signs with, and nothing else
        # reads it: where a keypair was built it holds the same secret in
        # memory the bindings can overwrite, so keeping the int beside it
        # would be a second copy held for nothing -- and the copy that
        # cannot be erased, at that
        if self._signer is not None:
            self._q = 0
        self._wiped = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.wipe()

    def wipe(self) -> None:
        """Let go of the key, and refuse to sign afterwards.

        The keypair is overwritten where there is one, which is the half
        of this that really erases: it is libsecp256k1's own memory and
        the bindings write zeros over it. The scalar this was built from
        is a python int and is dropped rather than erased -- rebinding
        the attribute is the whole of what a caller can do about an
        immutable object, and SECURITY.md's limitations section is where
        that is stated for the library at large. So a wiped signer is one
        that cannot sign and holds no keypair, not one that has scrubbed
        every copy of the secret from the process.

        Idempotent, so that a caller may wipe a signer it is not sure
        about; the `with` statement is the customary way to run one.
        """
        if self._signer is not None:
            self._signer.wipe()
            self._signer = None
        self._q = 0
        self._Q = None
        self._wiped = True

    def sign_(
        self, msg: Octets, aux: Octets | None = None, *, verify: bool = True
    ) -> bytes:
        """Return the signature of a prepared message, as its octets.

        The message is signed as it is, of any size, which is what the
        trailing underscore says throughout this module.

        verify is the free function's, and this is the call where it is
        the largest share of what it turns off: the keypair was built
        when this signer was, so the signature is the cheap part and the
        check is not. See `sign_` for the default and for why no pub_key
        joins it.
        """
        if self._wiped:
            raise EccValueError("the signer is wiped")

        # the aux `sign_` would have drawn, drawn here for the same
        # reason: BIP340's auxiliary randomness is per signature, and a
        # signer reusing one would derive one nonce for two messages
        msg = bytes_from_octets(msg)
        aux = (
            secrets.token_bytes(self._hf_len)
            if aux is None
            else bytes_from_octets(aux, self._hf_len)
        )

        if self._signer is None:
            # `sign_` asks at each signature whether the bindings serve,
            # and so does this: a signer built while they were switched
            # off signs with them once they are switched on again. The
            # held point is used only where the Python arithmetic signs
            if _libsecp256k1_serves(self._ec, self._hf):
                return sign_(
                    msg, self._q, aux, self._ec, self._hf, verify=verify
                ).serialize()
            return _sign_python_(
                msg, self._q, self._Q, aux, self._ec, self._hf, verify
            ).serialize()

        # `sign_custom` and not `sign`, for the reason `sign_` above gives at
        # its own dispatch: `sign` is the 32-byte entry point, and BIP340 puts
        # no size on its message. Signing through it would gate the size, as
        # btclib-org/btclib did until issue btclib-org/btclib#169 -- and would
        # gate it in only one of this class's two arms, the python one signing
        # what the delegated one would refuse
        #
        # the caller's `verify`, and this is where the check is the
        # largest share of what it is added to: the keypair was built
        # when this signer was, so signing here is markedly cheaper than
        # a fresh signature, and the same check on it is 61% of the call
        # against 44% there (btclib-org/btclib-secp256k1#224). It is the
        # one of this package's signing calls a caller would most plausibly
        # want to decline, which is why the keyword reaching here is the
        # point of exposing it at all
        try:
            return self._signer.sign_custom(msg, aux, verify=verify)
        except RuntimeError as e:
            # translated as at `sign_`'s own crossing above, and for the
            # same reason: this is the second of the two calls that let
            # the bindings' bare RuntimeError out
            raise EccRuntimeError(str(e)) from e

    def sign(
        self, msg: Octets, aux: Octets | None = None, *, verify: bool = True
    ) -> bytes:
        """Return the signature of a message, reducing it with hf first."""
        return self.sign_(reduce_to_hlen(msg, self._hf), aux, verify=verify)


def _assert_as_valid_(
    c: Public, QJ: JacPoint, r: Public, s: Public, ec: Curve, fixed: frozenset[JacPoint]
) -> None:
    # Private function for test/dev purposes
    # `fixed` is dsa._assert_as_valid_'s: the points whose wNAF tables
    # are memoized, the key's among them where the caller prepared it
    # It raises Errors, while verify should always return True or False

    # Let K = sG - eQ.
    # in Jacobian coordinates, and through the dispatching double_mult_var of
    # curves.curve rather than the Python arithmetic under it. What put a
    # caller here is that caller's own guard: `assert_as_valid_` asks
    # `_libsecp256k1_serves` and nothing else, where `sign_` asks it
    # beside a commitment of its own and reaches this function anyway,
    # to check the signature it has just written. Whichever guard it was
    # settles nothing about the multiplication, `_jac_double_mult_var`
    # asking the predicate again below: on secp256k1 with the dispatch
    # on the multiplication is still theirs, some thirty-five times
    # under the Python arithmetic. The whole verification follows it,
    # the two lifts around it -- the r of the signature and the x-only
    # key -- being theirs as well
    KJ = _jac_double_mult_var(Public(ec.n - c), QJ, s, ec.GJ, ec, fixed)

    # The following check is prescribed by BIP340 but it is useless:
    # if moved after 'Fail if x_K ≠ r' it would never be executed
    # Fail if infinite(KJ).
    # Fail if y_K is odd.
    #
    # This arm names which check failed, "y_K is odd" here and "signature
    # verification failed" below, where the delegated one at assert_as_valid_'s
    # libsecp256k1_ssa.verify call always says the latter -- it has a bool to
    # work with and this function has the arithmetic. Left unequal on purpose
    # (issue btclib-org/btclib#998, dsa.py's own `_assert_as_valid_` reading the
    # same for the reason stated there)
    if ec.y_aff_from_jac_var(KJ) % 2:
        raise EccRuntimeError("y_K is odd")

    # Fail if x_K ≠ r
    if KJ[0] != KJ[2] * KJ[2] * r % ec.p:
        raise EccRuntimeError("signature verification failed")


def _assert_commitment_(
    commit_hash: Octets | None, receipt: Point | None, sig: Sig, hf: HashF
) -> None:
    # the two come together or not at all, and an EccTypeError says
    # so because verify answers False for anything that is merely an invalid
    # signature: a commitment nobody can open, or a receipt for a commitment
    # that was never named, is a caller error and has to be heard as one
    if commit_hash is None:
        if receipt is not None:
            raise EccTypeError("receipt without the commitment it opens")
    elif receipt is None:
        raise EccTypeError("commitment without the receipt that opens it")
    else:
        # sig.r is a field element, the x-coordinate itself and not a
        # scalar reduced modulo the group order, so the recomputed point
        # is compared as it comes
        W = commit_point_var_(commit_hash, receipt, _S2C_POINT_TAG, sig.ec, hf)
        if sig.r != W[0]:
            raise EccRuntimeError("commitment verification failed")


# names no value: the x may be a private key passed by mistake
_INVALID_X = "invalid x-coordinate"


def _x_only_bytes(x: int, ec: Curve) -> bytes:
    """Return the 32 octets of an x, refusing what is no field element.

    The range check `int.to_bytes` cannot make on its own -- an x at or
    above 2**256 is an OverflowError about a builtin, and one between p
    and 2**256 is octets libsecp256k1 will refuse -- and the message is
    `ec.y_var`'s, spelled here rather than reached by calling it: this
    exists not to take that square root.

    Whether the x is an x-coordinate at all is not asked. What asks is the
    verification these octets are on their way to, whose parse is that same lift
    (issue btclib-org/btclib#887); `_INVALID_X` is the message for what it
    refuses.
    """
    if not 0 <= x < ec.p:
        raise EccValueError("x-coordinate not in 0..p-1")
    return x.to_bytes(ec.p_size, byteorder="big")


def assert_as_valid_(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    """Refuse an invalid BIP340 signature over a prepared message.

    The message enters as it is, of any size; assert_as_valid is the
    spelling that reduces with hf first. Errors carry the reason,
    ``verify_`` being the boolean answer. With commit_hash and receipt the
    sign-to-contract commitment is opened as well, an independent
    check of the same r.
    """
    # ahead of everything, and the one input whose refusal has to be a
    # TypeError: verify_ below turns a ValueError into False, so an hf
    # checked any later than this would be reported as a signature that
    # does not verify. hashes._assert_valid_hf has the rest
    _assert_valid_hf(hf)

    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # ahead of the dispatch below, which returns early: opening a
    # commitment and verifying a signature are two independent checks of
    # the same r, and both have to run whichever implementation answers
    # the second one
    _assert_commitment_(commit_hash, receipt, sig, hf)

    # the x, and the y only where there is something to do with one: the
    # curve is `sig.ec`, which `sig.assert_valid` above has checked
    x_Q = _x_from_bip340pub_key(Q, sig.ec)
    msg = bytes_from_octets(msg)

    # the curve and the hash function, and not the size of the message: see
    # sign_. `libsecp256k1_ssa.verify` takes BIP340's message of any size, so
    # the four arbitrary-size vectors of issue btclib-org/btclib#169 reach it
    # like every other vector
    if _libsecp256k1_serves(sig.ec, hf):
        # x proved an x-coordinate once, by the verification itself: that parse
        # is the lift, and validating the key before it would be the same square
        # root twice (issue btclib-org/btclib#887). So nothing here proves the
        # key -- what a ValueError from below means is that it was no point,
        # which is this function's to phrase
        x_bytes = _x_only_bytes(x_Q, sig.ec)
        # check_validity=False, because assert_valid has just run above --
        # on the Sig handed in, or inside the Sig.parse that made one. What
        # it would run again is the lift of r, which is not free even
        # delegated and costs many times more where it is not
        sig_bytes = sig.serialize(check_validity=False)
        verified: bool | None
        try:
            verified = libsecp256k1_ssa.verify(msg, x_bytes, sig_bytes)
        except ValueError:
            # raised outside the handler: no cause, no context
            verified = None
        if verified is None:
            raise EccValueError(_INVALID_X)
        if not verified:
            # one fixed sentence, because libsecp256k1 answers a bool and this
            # is this package's own wording for it, not a report of which BIP340
            # check failed -- the Python arm below says that instead. Both raise
            # EccRuntimeError, which is the contract; the message is
            # diagnostic, not API, and a caller is not meant to branch on it
            # (issue btclib-org/btclib#998, deciding to leave the two arms
            # disagreeing on wording rather than making them agree at the cost
            # of the diagnosis or of a second verification pass on this path)
            raise EccRuntimeError("signature verification failed")
        return

    # the lift the branch above does not need, and the validation of x_Q
    # with it: `_x_from_bip340pub_key` reads the key and proves nothing
    y_Q = _y_even_in_subgroup_var(Public(x_Q), sig.ec)
    # the key's own memoized tables where the caller prepared it, as in
    # `dsa.assert_as_valid_`, which is a fifth off a verification under
    # one key. The negation is in that set too, which is what makes it
    # answer here -- a prepared point of odd y is this same key, and the
    # lift above is the one of the two BIP340 names
    fixed = Q.fixed if isinstance(Q, PreparedPoint) else sig.ec._fixed_points
    # Let c = int(hf(bytes(r) || bytes(Q) || msg)) mod n.
    c = challenge_(msg, x_Q, sig.r, sig.ec, hf)
    _assert_as_valid_(
        Public(c), (x_Q, y_Q, 1), Public(sig.r), Public(sig.s), sig.ec, fixed
    )


def assert_as_valid(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    """Verify the BIP340 signature of hf(msg).

    The other spelling, ``assert_as_valid_``, takes the BIP340 message
    itself, of any size. This one reduces msg with hf first, and commit
    with it.

    Double backticks because rst reads a trailing underscore as a link
    reference: bare, this name makes sphinx -W fail with 'Unknown target
    name: "assert_as_valid"'.
    """
    commit_hash = None if commit is None else reduce_to_hlen(commit, hf)
    assert_as_valid_(
        reduce_to_hlen(msg, hf), Q, sig, hf, commit_hash=commit_hash, receipt=receipt
    )


def _assert_structurally_valid_(Q: BIP340PubKey, sig: Sig | Octets, ec: Curve) -> Sig:
    """Raise for a signature or a public key that cannot possibly be one.

    Ahead of the try that turns everything else -- a scalar out of range, a key
    that does not lift, a failed equation -- into False (issue
    btclib-org/btclib#2170, and BIP340's own reference: wrong-length input
    raises, `lift_x` returning None does not).

    Sixty-three octets cannot be a BIP340 signature and thirty-one
    cannot be one of its public keys, whatever they decode to, and
    `verify_`, `verify`, `batch_verify_` and `batch_verify` all run this
    ahead of their own try so that a caller's malformed material is
    never read as a forged signature. `assert_as_valid_` checks the
    same things again right after, on the `Sig` this returns -- teaching
    that function two callers with two contracts would cost more than a
    parse with no side effect asked twice.

    A public key spelled as 33 or 65 SEC octets, or as a native
    `(x, y)` tuple, is proved a point of the curve by this same call --
    `point_from_octets_var` and `is_on_curve` do that as part of reading the
    encoding, with nothing short of the lift standing between them and
    a usable x. So `verify` raises for such a key that does not lift,
    where the 32-byte x-only spelling BIP340 itself defines does not:
    there the lift is unproven here on purpose (see
    `_x_from_bip340pub_key`) and stays deferred to the equation, so it
    answers False, matching `lift_x` returning None in the reference.
    """
    parsed_sig = sig if isinstance(sig, Sig) else Sig.parse(sig, check_validity=False)
    _x_from_bip340pub_key(Q, ec)
    return parsed_sig


def verify_(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> bool:
    """Verify the BIP340 signature of a message of any size.

    The message is taken as it is; `verify` is the spelling that reduces it
    with hf first.

    commit_hash and receipt open the commitment the nonce carries, and a
    signature that does not commit to that value is False as a forged one
    is: the answer is about this signature and this commitment, both.

    Raises where the signature or the public key is structurally
    invalid -- the wrong length, or spelled in a way BIP340 has no
    reading for -- and answers False for a well-formed one that is
    merely not authentic: a scalar at or above the group order, a key
    that does not lift, an equation that does not hold. See
    `_assert_structurally_valid_`.

    Where the bindings are required (`curves.set_libsecp256k1_serving` with
    `required=True`) and decline `hf`, it raises `EccRuntimeError`
    and does not answer False: nothing was checked.
    """
    ec = sig.ec if isinstance(sig, Sig) else secp256k1
    parsed_sig = _assert_structurally_valid_(Q, sig, ec)
    # ValueError and EccRuntimeError: a well-formed signature that is
    # not authentic is False, and so is a commitment that does not open;
    # a caller's own mistake -- an hf that is no hash constructor, a
    # signature or a key that cannot be parsed at all -- is refused
    # above rather than excluded from the except
    try:
        assert_as_valid_(
            msg, Q, parsed_sig, hf, commit_hash=commit_hash, receipt=receipt
        )
    except _BindingsRequiredError:
        raise
    except (ValueError, EccRuntimeError):
        return False

    return True


def verify(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
    receipt: Point | None = None,
) -> bool:
    """Verify the BIP340 signature of hf(msg).

    commit is reduced by hf as msg is; `verify_` is the spelling that
    takes the two hashes. Raises and answers False for the same reasons
    `verify_` does, and raises where the bindings are required and decline
    `hf`.
    """
    ec = sig.ec if isinstance(sig, Sig) else secp256k1
    parsed_sig = _assert_structurally_valid_(Q, sig, ec)
    # `assert_as_valid` and not a delegation to the prepared spelling: the
    # reduction has to be inside the try, or a message that is no octets is
    # refused here where the hash spelling answers False about it (issue
    # btclib-org/btclib#814) -- the structural check above is unaffected either
    # way, since it does not touch msg
    try:
        assert_as_valid(msg, Q, parsed_sig, hf, commit=commit, receipt=receipt)
    except _BindingsRequiredError:
        raise
    except (ValueError, EccRuntimeError):
        return False

    return True


def anti_exfil_host_commit(rho: Octets, hf: HashF = sha256) -> bytes:
    """Return the host's commitment to rho: step 1 of the anti-exfil protocol.

    The protocol is proposed for `include/secp256k1_schnorrsig.h` of
    bitcoin-core/secp256k1#1140, carrying over the ECDSA Anti-Exfil
    Protocol BlockstreamResearch/secp256k1-zkp's `secp256k1_ecdsa_s2c.h`
    specifies -- see `dsa.anti_exfil_host_commit` -- to BIP340.

    A signing device that picks its own nonce can leak the private key
    through the nonces themselves, and the protocol takes that choice
    away by having the host contribute randomness to the nonce
    derivation before the device commits to a nonce point, in a
    commit-reveal handshake of five steps:

    1. the host draws rho and sends ``anti_exfil_host_commit(rho)``
    2. the device answers with ``anti_exfil_signer_commit(msg, prv_key,
       commitment)``, the point R its nonce will have
    3. the host reveals rho
    4. the device signs, ``anti_exfil_sign(msg, prv_key, rho)``
    5. the host checks ``anti_exfil_host_verify`` against the R of step 2
       and the rho it drew in step 1

    rho is hf_len bytes from a cryptographically secure generator, and it
    stays secret until step 2 has been answered: revealed earlier it is
    the device's to grind, which is the whole of what this prevents.

    **Restarting the protocol takes exactly the same rho**, and the host
    checks that the device answers step 2 with exactly the same R -- see
    `dsa.anti_exfil_host_commit` for what a device that could dodge this
    check would buy itself.

    The commitment is the committed value as it enters the nonce
    derivation -- ``commit_entropy_`` under the sign-to-contract data
    tag, and nothing else -- which is what lets step 2 and step 4 reach
    one nonce: the device derives it from this hash, and recomputes the
    same hash from rho when it signs. ``sign_``'s own commit_hash
    argument reaches the nonce mixed with the caller's own aux instead,
    which is the right shape for an ordinary sign-to-contract commitment
    and the wrong one for this handshake: step 2 has nothing to mix in
    but the commitment, so the four functions here derive the nonce
    directly rather than going through ``sign_``.
    """
    return commit_entropy_(bytes_from_octets(rho, hf().digest_size), _S2C_DATA_TAG, hf)


def anti_exfil_signer_commit(
    msg: Octets,
    prv_key: Integer,
    host_commitment: Octets,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Point:
    """Return the signer's public nonce R: step 2 of the anti-exfil protocol.

    The point of the nonce the device is going to use, published before
    the host reveals what its commitment commits to. Nothing is signed
    here, and that is the shape the protocol needs: R is a promise, and
    step 4 is what keeps it.

    The commitment travels as BIP340's own auxiliary randomness, alone --
    exactly what it becomes inside ``anti_exfil_sign``'s nonce derivation
    -- so the two reach one nonce and the R below is the receipt that
    signature will open with.
    """
    aux = bytes_from_octets(host_commitment, hf().digest_size)
    _, x_K, _, _ = bip340_nonce_(msg, prv_key, aux, ec, hf)
    return x_K, _y_even_var(Public(x_K), ec)


def anti_exfil_sign(
    msg: Octets,
    prv_key: Integer,
    rho: Octets,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign committing to the host's rho: step 4 of the anti-exfil protocol.

    Sign-to-contract with rho as the committed value and nothing else
    reaching the nonce derivation -- ``sign_(msg, prv_key, commit_hash=rho)``
    would mix in a fresh random aux instead, breaking the property this
    function exists for. The receipt is dropped rather than passed on,
    because the host has it already -- it is the R of step 2, and a host
    taking the device's word for it here would be accepting a nonce point
    chosen *after* rho was revealed, which is the one thing the ordering
    exists to rule out.

    **The device keeps no state between step 2 and step 4.** It does not
    check rho against the commitment it was given: it re-derives the
    commitment from rho, and the nonce from that. A rho that does not
    match yields a different nonce, so the host's step 5 fails and the
    exchange is over -- and because the R of step 2 belonged to the
    commitment it was derived from, no nonce is ever used twice and the
    device's key is never the thing at risk.
    """
    rho = bytes_from_octets(rho, hf().digest_size)
    nonce_aux = commit_entropy_(rho, _S2C_DATA_TAG, hf)
    sig, _receipt = _sign_commit_(msg, prv_key, nonce_aux, rho, ec, hf, True)
    return sig


def anti_exfil_host_verify(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    rho: Octets,
    receipt: Point,
    hf: HashF = sha256,
) -> bool:
    """Check the signature against R and rho: step 5 of the anti-exfil protocol.

    Two questions answered as one, and the host needs both: that this is
    a valid signature, and that its nonce is the R of step 2 tweaked by
    the rho of step 1. Either alone is worth nothing -- a valid signature
    over a nonce nobody constrained is the exfiltration this protects
    against, and a commitment that opens under an invalid signature is
    not a signature. Which ``verify_`` already does in one call, both
    checks running against the same r.

    receipt is the R of step 2. It raises and answers False for the same
    reasons ``verify_`` does: a key or a signature that is structurally
    invalid raises, and a rho of the wrong size is False, a rho this
    commitment does not open to.
    """
    return verify_(msg, Q, sig, hf, commit_hash=rho, receipt=receipt)


def _recover_pub_key_(c: Public, r: Public, s: Public, ec: Curve) -> int:
    # Private function provided for testing purposes only.
    if c == 0:
        raise EccRuntimeError("invalid zero challenge")

    # a nonce point outside <G> is no signature's, and the key recovered
    # from it would be outside <G> as well: refused, as verification does
    KJ = r, _y_even_in_subgroup_var(r, ec), 1

    e1 = mod_inv_var(c, ec.n)
    # libsecp256k1 recovers no x-only key -- its recovery module is ECDSA
    # ("recover(msg, signature, recid)") and its xonly module has no
    # recovery in it -- so the delegated double_mult_var is the whole of what
    # there is to gain here, and it is all of the cost, the Python
    # arithmetic costing some thirty times more. Which is also why
    # this stays private, with no public spelling above it: BIP340 has
    # no recovery flag to carry the
    # candidate, x-only keys leaving nothing for one to disambiguate
    QJ = _jac_double_mult_var(
        Public(ec.n - e1), KJ, Public(e1 * s), ec.GJ, ec, ec._fixed_points
    )
    # QJ = e1*(s*G - K) is INF whenever r is the x of s*G, y even, and
    # that answer comes back from the bindings too: a libsecp256k1 pubkey
    # is never the identity, so the sum is recognized from the coordinates
    # in curves.curve and handed back as the z == 0 tested here
    if QJ[2] == 0:
        err_msg = "invalid (INF) key"
        raise EccRuntimeError(err_msg)
    return int(ec.x_aff_from_jac_var(QJ))


def _err_msg(size: int, msgs_or_sigs: str, arg2: Sequence[Octets | Sig]) -> str:
    err_msg = f"mismatch between number of pub_keys ({size}) "
    return f"{err_msg} and number of {msgs_or_sigs} ({len(arg2)})"


def _assert_batch_sequences(
    msgs: Sequence[Octets], Qs: Sequence[BIP340PubKey], sigs: Sequence[Sig]
) -> None:
    """Refuse a batch parameter that is no sequence, naming which.

    What is not one was walked untouched, so a None left the zip of
    `assert_batch_as_valid_`, or the reduction of `assert_batch_as_valid`, as
    "not iterable" -- a complaint about iteration, from underneath the library,
    about a batch (issue btclib-org/btclib#814). Both spellings ask it, the
    reduction being ahead of the prepared one.

    A `str` is a Sequence and stays one: run time cannot tell
    Sequence[Octets] from Sequence[str], so the elements are what answer
    for their own values -- that is about telling one Sequence[Octets]
    from another, though, and no Sequence at all is `msgs`'s own mistake
    to refuse: every Octets is itself a Sequence, so one message passed
    where the batch was meant would zip through its bytes and challenge
    each as its own message (issue btclib-org/btclib#1405).
    """
    if is_octets(msgs):
        raise EccTypeError(f"invalid msgs type: {type(msgs).__name__}")
    for value, what in ((msgs, "msgs"), (Qs, "Qs"), (sigs, "sigs")):
        assert_type(value, Sequence, what)


def assert_batch_as_valid_(
    msgs: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    """Refuse an invalid signature in a batch of prepared messages.

    BIP340's batch verification: one multi-scalar equation over
    random coefficients -- and which signature failed is not in the
    answer, only that one did. Messages enter as they are; every
    signature must share one curve. An empty batch is valid, as in
    BIP340.

    **It is not the fast way to verify n signatures of secp256k1.**
    Measured against n delegated `verify_` calls, the batch costs about
    twice a `verify_` a signature, both flat in n, so there is no
    crossover at any batch size. libsecp256k1 has no batch verification to
    delegate to, checked at 687155df upstream and at the tip of
    secp256k1-zkp, whose half-aggregation is a different construction; so
    what the batch saves in multiplications it spends on a Python term per
    signature, against a whole verification that is one C call.

    Where it does win is the arithmetic it was written for. With the
    bindings switched off -- every other curve, and every other hash
    function -- the equation is one multi-scalar multiplication where n
    verifications are n double multiplications, and it overtakes them
    between four signatures and eight. That is the reason it stays, beside
    its being BIP340's own algorithm and the reference the delegated path
    is read against. Both measurements per batch size are in
    btclib-org/btclib's CHANGELOG, in the entry that took them, an entry
    being read as the history of a release where this is read as a
    statement about the code as it stands.

    **Which leaves the question of why secp256k1 runs the equation at
    all, rather than a loop of `verify_`.** That loop would be twice as
    fast and would say *which* signature failed, where this says only
    that one did, so it is not obviously the wrong answer -- and it is
    not taken. What a caller asks of this function is BIP340 batch
    verification: one equation over random coefficients, the construction
    with the security argument the BIP makes, and the thing an
    implementation is compared against. A dispatch that answered it with
    n independent verifications would answer the same *verdict* by a
    different computation, and would leave nothing running the equation
    on the curve where the equation is checkable against libsecp256k1 --
    which is what `test_batch_validation_on_the_python_path` uses it for.
    A caller who wants n verifications has `verify_` and a loop, and the
    figures above are here so that the choice is an informed one.

    Every signature is asked whether it is one, this being a public
    function handed objects somebody else built: the equation below is
    not that question, and answers a different one for an s outside
    0..n-1.
    """
    # ahead of everything, as in assert_as_valid_ and for the same reason:
    # batch_verify_ turns a ValueError into False
    _assert_valid_hf(hf)

    # and the three sequences, for that reason again
    _assert_batch_sequences(msgs, Qs, sigs)

    batch_size = len(Qs)
    if len(msgs) != batch_size:
        raise EccValueError(_err_msg(batch_size, "messages", msgs))
    if len(sigs) != batch_size:
        raise EccValueError(_err_msg(batch_size, "signatures", sigs))
    if batch_size == 0:
        return
    # from two signatures up nothing hands hf to the bindings; this asks
    # so that the batch answers as its batch of one does, which raises
    # where the bindings are required and decline hf. The answer is unused
    _libsecp256k1_serves(sigs[0].ec, hf)
    if batch_size == 1:
        assert_as_valid_(msgs[0], Qs[0], sigs[0], hf)
        return

    ec = sigs[0].ec
    if any(sig.ec != ec for sig in sigs):
        raise EccValueError("not the same curve for all signatures")

    # from two upward the equation is what answers, and it is satisfied by
    # a signature BIP340 calls invalid: s and s + n are congruent modulo
    # the group order, so `mult(t)` cannot tell them apart, while
    # assert_as_valid_ -- and the batch_size == 1 shortcut above with it --
    # refuses the second. Nothing reaches this from the wire, a
    # non-canonical s not fitting in 32 bytes, so what it takes is a caller
    # building Sig objects with check_validity=False; that is supported,
    # which is why the check belongs here rather than nowhere. The half of
    # assert_valid the equation would catch anyway is r, whose lift below
    # fails for a field element that is no x-coordinate.
    # After the curve check and not before it, so a batch mixing curves is
    # still told that, rather than being asked whether one signature's r is
    # an x-coordinate of a curve the batch has no business holding
    for sig in sigs:
        sig.assert_valid()
    t = 0
    scalars: list[Public] = []
    x_coords: list[Public] = []
    for i, (msg, Q, sig) in enumerate(zip(msgs, Qs, sigs, strict=True)):
        # any size, as in sign_ and assert_as_valid_
        msg = bytes_from_octets(msg)  # noqa: PLW2901

        # the x of each term and no lift, both terms being the even-y point an x
        # names: r has been proved an x-coordinate by `sig.assert_valid` above,
        # and x_Q is proved by the multiplication these terms are on their way
        # to, whose parse is that same lift -- `assert_as_valid_` takes the
        # shape for the same reason (issue btclib-org/btclib#887). The range is
        # still this side's to refuse, `challenge_` writing x_Q into its
        # preimage and answering an OverflowError for what is no field element
        x_Q = _x_from_bip340pub_key(Q, ec)
        _x_only_bytes(x_Q, ec)

        # where a cofactor leaves room for points outside <G>: the key, and
        # the nonce point too, whose part outside <G> a random coefficient
        # of 0 mod the cofactor would annihilate while the single
        # verification refuses it. Nothing is asked on secp256k1
        if ec.cofactor > 1:
            _y_even_in_subgroup_var(Public(x_Q), ec)
            _y_even_in_subgroup_var(Public(sig.r), ec)

        c = challenge_(msg, x_Q, sig.r, ec, hf)

        # rand in 1..n-1
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        rand = 1 if i == 0 else 1 + secrets.randbelow(ec.n - 1)
        scalars.append(Public(rand))
        x_coords.append(Public(sig.r))
        scalars.append(Public(rand * c % ec.n))
        x_coords.append(Public(x_Q))
        t += rand * sig.s

    if mult(t, ec=ec) != _multi_mult_x_only_var(scalars, x_coords, ec):
        raise EccRuntimeError("signature verification failed")
    return


def assert_batch_as_valid(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    """Refuse an invalid signature in a batch, reducing each message."""
    # ahead of the reduction, which walks `ms`: the prepared spelling asks
    # the same thing, and neither can rely on the other having asked
    _assert_batch_sequences(ms, Qs, sigs)

    msgs = [reduce_to_hlen(msg, hf) for msg in ms]
    return assert_batch_as_valid_(msgs, Qs, sigs, hf)


def _assert_batch_pub_keys_structurally_valid_(
    Qs: Sequence[BIP340PubKey], sigs: Sequence[Sig]
) -> None:
    """Run the batch's own parse half, ahead of the try.

    Each public key on its own, exactly what
    `_assert_structurally_valid_` asks of one.

    A batch signature is already a `Sig` object -- the batch API takes
    no raw octets, `sigs` being `Sequence[Sig]` and not
    `Sequence[Sig | Octets]` -- so there is no encoding of one left to
    be wrong. What a mismatched length or a curve the
    signatures do not share answers is `assert_batch_as_valid_`'s own
    question and not a shape this duplicates: neither is
    about a signature's or a key's own bytes, which is the line this
    issue draws.
    """
    for Q, sig in zip(Qs, sigs, strict=False):
        _x_from_bip340pub_key(Q, sig.ec)


def batch_verify_(
    msgs: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    """Answer whether every signature in the batch verifies.

    Messages enter prepared, as in ``assert_batch_as_valid_``.

    An empty batch answers True: a caller that expects some number of
    signatures checks the count itself.

    False means an invalid batch: a failed verification and a
    well-formed key or scalar that is merely not authentic are both
    False, see `_assert_structurally_valid_`. Raises where a public key
    is structurally invalid -- spelled in a way BIP340 has no reading
    for.

    Where the bindings are required (`curves.set_libsecp256k1_serving` with
    `required=True`) and decline `hf`, a batch that is not empty raises
    `EccRuntimeError` and does not answer False: nothing was checked.
    """
    _assert_batch_sequences(msgs, Qs, sigs)
    _assert_batch_pub_keys_structurally_valid_(Qs, sigs)
    # ValueError and EccRuntimeError: a well-formed batch that is not
    # authentic is False; a caller's own mistake is refused above rather
    # than excluded from the except
    try:
        assert_batch_as_valid_(msgs, Qs, sigs, hf)
    except _BindingsRequiredError:
        raise
    except (ValueError, EccRuntimeError):
        return False

    return True


def batch_verify(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    """Batch verification of BIP340 signatures.

    Raises and answers False for the same reasons `batch_verify_` does.
    """
    _assert_batch_sequences(ms, Qs, sigs)
    _assert_batch_pub_keys_structurally_valid_(Qs, sigs)
    # `assert_batch_as_valid` and not a delegation to the prepared spelling: the
    # reduction has to be inside the try, or a message that is no octets is
    # refused here where the hash spelling answers False about it (issue
    # btclib-org/btclib#814) -- the structural check above is unaffected either
    # way, since it does not touch a message
    try:
        assert_batch_as_valid(ms, Qs, sigs, hf)
    except _BindingsRequiredError:
        raise
    except (ValueError, EccRuntimeError):
        return False

    return True
