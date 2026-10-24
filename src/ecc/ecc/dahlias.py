# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""DahLIAS fully aggregated signatures, according to BIP459.

https://github.com/bitcoin/bips/pull/2210, a draft, at head `8678edb4ad`.

Each of *u* signers signs its own 32-byte message under its own x-only
key, and the signers jointly produce one 64-byte signature for the
ordered list of (public key, message) pairs. Unlike `ecc.ecc.musig2`, no
key is aggregated: `verify` takes the whole list, and the signature
verifies with nothing else. It does not verify with `ecc.ecc.ssa`.

Signing is interactive, so this module offers one function per step:

- round 1: `nonce_gen` for each signer, then `nonce_agg_var` over the
  public nonces;
- round 2: `sign` for each signer, over a `SessionContext` holding the
  aggregate nonce and the ordered lists of keys, messages and public
  nonces; `partial_sig_verify` to find a signer whose partial signature
  is wrong; `sig_agg` for the aggregate signature.

**A secret nonce signs once.** Partial signatures from three sessions
signed with one secnonce reveal the secret key. `sign` zeroes the
bytearray it is given as soon as it has read it.

`sign` checks only the signer's own entry: its R_2 appears exactly once
among the public nonces, and the key and message at that position are
its own. Whatever the caller requires of the other entries is the
caller's to check before calling it.

A signer may use a tweaked key pair: `plain_tweak` (BIP32 unhardened
derivation) and `xonly_tweak` (BIP341 key path) answer the tweaked
secret key and the x-only key that goes in the list, and
`plain_tweak_pub_key_var` and `xonly_tweak_pub_key_var` answer the
tweaked key from the public key alone.

secp256k1 and sha256 are not parameters, as in `ecc.ecc.musig2`: BIP459
is defined for that pair alone.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256

from ecc._utils import assert_type, bytes_from_octets, is_integer, is_octets
from ecc.alias import Integer, Octets, Point
from ecc.curves import mult, multi_mult_var, scalar_from_prv_key, secp256k1
from ecc.curves.curve import _sum_var, _tweak_add_var
from ecc.curves.sec_point import bytes_from_point, point_from_octets_var
from ecc.ecc.ssa import point_from_bip340pub_key_var
from ecc.exceptions import (
    EccRuntimeError,
    EccTypeError,
    EccValueError,
    InvalidContributionError,
)
from ecc.hashes import tagged_hash

__all__ = [
    "SessionContext",
    "SessionValues",
    "assert_as_valid",
    "nonce_agg_var",
    "nonce_gen",
    "nonce_gen_",
    "partial_sig_verify",
    "plain_tweak",
    "plain_tweak_pub_key_var",
    "session_values",
    "sig_agg",
    "sign",
    "verify",
    "xonly_tweak",
    "xonly_tweak_pub_key_var",
]

_AUX_TAG = b"BIP0459/aux"
_NONCE_TAG = b"BIP0459/nonce"
_NONCE_COEFF_TAG = b"BIP0459/noncecoef"
_SIG_TAG = b"BIP0459/sig"

_SCALAR_SIZE = 32
# an x-only public key, a message, a compressed point
_PK_SIZE = 32
_MSG_SIZE = 32
_CPOINT_SIZE = 33
_NONCE_SIZE = 2 * _CPOINT_SIZE
_SIG_SIZE = 64


def _cbytes(P: Point) -> bytes:
    return bytes_from_point(P, secp256k1)


def _xbytes(P: Point) -> bytes:
    return P[0].to_bytes(_PK_SIZE, "big")


def _cpoint_var(octets: Octets) -> Point:
    """Deserialize a 33-byte compressed point, BIP459's cpoint."""
    return point_from_octets_var(bytes_from_octets(octets, _CPOINT_SIZE), secp256k1)


def _lift_x_var(octets: Octets) -> Point:
    """Return the even-y point of a 32-byte x-only key, BIP459's lift_x."""
    return point_from_bip340pub_key_var(bytes_from_octets(octets, _PK_SIZE), secp256k1)


def _bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _octets_list(value: object, size: int, what: str) -> tuple[bytes, ...]:
    """Return a Sequence of Octets as a tuple of bytes of one size.

    An Octets is itself a Sequence, so one passed where a list was meant
    is refused rather than read element by element (issue
    btclib-org/btclib#1405).
    """
    if is_octets(value) or not isinstance(value, Sequence):
        raise EccTypeError(f"invalid {what} type: {type(value).__name__}")
    return tuple(bytes_from_octets(x, size) for x in value)


def _lists(
    pub_keys: Sequence[Octets], msgs: Sequence[Octets]
) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    """Return the keys and messages, refusing an empty or uneven pair."""
    pks = _octets_list(pub_keys, _PK_SIZE, "pub_keys")
    ms = _octets_list(msgs, _MSG_SIZE, "msgs")
    if not pks:
        raise EccValueError("the lists must not be empty")
    if len(ms) != len(pks):
        raise EccValueError("pub_keys and msgs must have the same length")
    return pks, ms


def _challenges(
    pub_keys: Sequence[bytes], msgs: Sequence[bytes], r: bytes, indexes: Sequence[int]
) -> list[int]:
    """Return c_i = hash_BIP0459/sig(L || r || pk_i || m_i) mod n, for each i.

    L || r is the prefix of every input, so it is hashed once and the
    state copied for each i, as BIP459's rationale advises.
    """
    tag = sha256(_SIG_TAG).digest()
    prefix = sha256(tag + tag)
    for pk, m in zip(pub_keys, msgs, strict=True):
        prefix.update(pk + m)
    prefix.update(r)
    cs = []
    for i in indexes:
        h = prefix.copy()
        h.update(pub_keys[i] + msgs[i])
        cs.append(int.from_bytes(h.digest(), "big") % secp256k1.n)
    return cs


def _nonce_hash(rand: bytes, extra_in: bytes, i: int) -> int:
    buf = rand + extra_in + i.to_bytes(1, "big")
    return int.from_bytes(tagged_hash(_NONCE_TAG, buf), "big") % secp256k1.n


def nonce_gen_(
    rand_: Octets, prv_key: Integer | None = None, extra_in: Octets | None = None
) -> tuple[bytearray, bytes]:
    """Return the (secnonce, pubnonce) pair of one signer, given ``rand_``.

    BIP459's NonceGen, with its fresh randomness as the argument;
    `nonce_gen` is the spelling that draws it, and the one to call.

    The private key and ``extra_in`` are optional defences against a
    broken random generator; pass them where known.

    The secnonce is a 64-byte bytearray, which `sign` zeroes.
    """
    rand_ = bytes_from_octets(rand_, _SCALAR_SIZE)
    if prv_key is None:
        rand = rand_
    else:
        q = scalar_from_prv_key(prv_key, secp256k1)
        rand = _bytes_xor(q.to_bytes(_SCALAR_SIZE, "big"), tagged_hash(_AUX_TAG, rand_))
    extra = b"" if extra_in is None else bytes_from_octets(extra_in)
    r_1 = _nonce_hash(rand, extra, 0)
    r_2 = _nonce_hash(rand, extra, 1)
    # r_1 or r_2 zero is a hash landing on a multiple of n: _cbytes then
    # refuses the point at infinity, which is BIP459's failure
    pub_nonce = _cbytes(mult(r_1, ec=secp256k1)) + _cbytes(mult(r_2, ec=secp256k1))
    sec_nonce = bytearray(
        r_1.to_bytes(_SCALAR_SIZE, "big") + r_2.to_bytes(_SCALAR_SIZE, "big")
    )
    return sec_nonce, pub_nonce


def nonce_gen(
    prv_key: Integer | None = None, extra_in: Octets | None = None
) -> tuple[bytearray, bytes]:
    """Return the (secnonce, pubnonce) pair of one signer.

    Fresh randomness is drawn here; ``nonce_gen_`` takes it instead.
    """
    return nonce_gen_(secrets.token_bytes(_SCALAR_SIZE), prv_key, extra_in)


def nonce_agg_var(pub_nonces: Sequence[Octets]) -> bytes:
    """Return the 66-byte aggregate of the public nonces: BIP459's NonceAgg.

    Either half summing to infinity is refused: BIP459 has no encoding
    for it.
    """
    nonces = _octets_list(pub_nonces, _NONCE_SIZE, "pub_nonces")
    if not nonces:
        raise EccValueError("the lists must not be empty")
    halves: tuple[list[Point], list[Point]] = ([], [])
    for i, pub_nonce in enumerate(nonces):
        try:
            halves[0].append(_cpoint_var(pub_nonce[:_CPOINT_SIZE]))
            halves[1].append(_cpoint_var(pub_nonce[_CPOINT_SIZE:]))
        except EccValueError as e:
            raise InvalidContributionError(i, "pubnonce") from e
    agg_nonce = b""
    for points in halves:
        R_j = _sum_var(points, secp256k1)
        if R_j[1] == 0:
            raise EccValueError("aggregate nonce at infinity")
        agg_nonce += _cbytes(R_j)
    return agg_nonce


@dataclass(frozen=True, init=False)
class SessionContext:
    """What the signers of one session agree on.

    The aggregate nonce, and the ordered lists of x-only public keys,
    32-byte messages and public nonces, all of one length u >= 1.
    BIP459 calls these the session parameters.
    """

    agg_nonce: bytes
    pub_keys: tuple[bytes, ...]
    msgs: tuple[bytes, ...]
    pub_nonces: tuple[bytes, ...]

    # `session_values`'s memoized answer, kept out of equality as in
    # `musig2.SessionContext`
    _values: SessionValues | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __init__(
        self,
        agg_nonce: Octets,
        pub_keys: Sequence[Octets],
        msgs: Sequence[Octets],
        pub_nonces: Sequence[Octets],
    ) -> None:
        pks, ms = _lists(pub_keys, msgs)
        nonces = _octets_list(pub_nonces, _NONCE_SIZE, "pub_nonces")
        if len(nonces) != len(pks):
            raise EccValueError("pub_keys and pub_nonces must have the same length")
        object.__setattr__(self, "agg_nonce", bytes_from_octets(agg_nonce, _NONCE_SIZE))
        object.__setattr__(self, "pub_keys", pks)
        object.__setattr__(self, "msgs", ms)
        object.__setattr__(self, "pub_nonces", nonces)


@dataclass(frozen=True)
class SessionValues:
    """BIP459's session values: the nonce point R and its coefficient b."""

    R: Point
    b: int


def session_values(session_ctx: SessionContext) -> SessionValues:
    """Return (R, b) for the session: BIP459's GetSessionValues.

    Memoized on `session_ctx`. Nothing in it is secret.
    """
    assert_type(session_ctx, SessionContext, "session_ctx")
    if session_ctx._values is not None:
        return session_ctx._values
    try:
        R_1 = _cpoint_var(session_ctx.agg_nonce[:_CPOINT_SIZE])
        R_2 = _cpoint_var(session_ctx.agg_nonce[_CPOINT_SIZE:])
    except EccValueError as e:
        raise InvalidContributionError(None, "aggnonce") from e
    for i, pub_nonce in enumerate(session_ctx.pub_nonces):
        try:
            _cpoint_var(pub_nonce[_CPOINT_SIZE:])
        except EccValueError as e:
            raise InvalidContributionError(i, "pubnonce") from e
    # cbytes(cpoint(x)) is x for every x cpoint accepts, so the bytes are
    # hashed as received
    nonce_data = session_ctx.agg_nonce + b"".join(
        pk + m + pub_nonce[_CPOINT_SIZE:]
        for pk, m, pub_nonce in zip(
            session_ctx.pub_keys, session_ctx.msgs, session_ctx.pub_nonces, strict=True
        )
    )
    b = int.from_bytes(tagged_hash(_NONCE_COEFF_TAG, nonce_data), "big") % secp256k1.n
    R = secp256k1.add_var(R_1, mult(b, R_2, secp256k1))
    if R[1] == 0:  # pragma: no cover -- R_1 = -b*R_2, b a hash of both
        raise EccRuntimeError("session nonce at infinity")
    values = SessionValues(R, b)
    object.__setattr__(session_ctx, "_values", values)
    return values


def sign(
    sec_nonce: bytearray, prv_key: Integer, msg: Octets, session_ctx: SessionContext
) -> bytes:
    """Return the 32-byte partial signature of one signer: BIP459's Sign.

    The types and sizes of the arguments are checked, then the session
    values are derived, so a session that does not assemble leaves the
    secnonce untouched. Then the secnonce is read and zeroed, before
    its values, the key and the lists are checked: calling this twice
    with one bytearray raises instead of signing twice.

    The signer's R_2 must appear exactly once among the public nonces,
    and the key and message at that index must be its own.
    """
    assert_type(sec_nonce, bytearray, "sec_nonce")
    if len(sec_nonce) != 2 * _SCALAR_SIZE:
        raise EccValueError("the secnonce must be 64 bytes")
    msg = bytes_from_octets(msg, _MSG_SIZE)
    values = session_values(session_ctx)
    r_1 = int.from_bytes(sec_nonce[:_SCALAR_SIZE], "big")
    r_2 = int.from_bytes(sec_nonce[_SCALAR_SIZE:], "big")
    sec_nonce[:] = bytearray(2 * _SCALAR_SIZE)
    if not 0 < r_1 < secp256k1.n:
        raise EccValueError("first secnonce value out of range")
    if not 0 < r_2 < secp256k1.n:
        raise EccValueError("second secnonce value out of range")
    d = scalar_from_prv_key(prv_key, secp256k1)
    P = mult(d, ec=secp256k1)
    R_2 = _cbytes(mult(r_2, ec=secp256k1))
    indexes = [
        i
        for i, pub_nonce in enumerate(session_ctx.pub_nonces)
        if pub_nonce[_CPOINT_SIZE:] == R_2
    ]
    if len(indexes) != 1:
        raise EccValueError("the signer's R_2 must appear exactly once")
    j = indexes[0]
    if session_ctx.pub_keys[j] != _xbytes(P):
        raise EccValueError("the public key at the signer's index is not its own")
    if session_ctx.msgs[j] != msg:
        raise EccValueError("the message at the signer's index is not its own")
    R = values.R
    if R[1] % 2:
        r_1, r_2 = secp256k1.n - r_1, secp256k1.n - r_2
    if P[1] % 2:
        d = secp256k1.n - d
    (c,) = _challenges(session_ctx.pub_keys, session_ctx.msgs, _xbytes(R), [j])
    s = (r_1 + values.b * r_2 + c * d) % secp256k1.n
    return s.to_bytes(_SCALAR_SIZE, "big")


def sig_agg(psigs: Sequence[Octets], session_ctx: SessionContext) -> bytes:
    """Return the 64-byte aggregate signature: BIP459's SigAgg."""
    assert_type(session_ctx, SessionContext, "session_ctx")
    ss = _octets_list(psigs, _SCALAR_SIZE, "psigs")
    if len(ss) != len(session_ctx.pub_keys):
        raise EccValueError("psigs and pub_keys must have the same length")
    values = session_values(session_ctx)
    s = 0
    for i, psig in enumerate(ss):
        s_i = int.from_bytes(psig, "big")
        if s_i >= secp256k1.n:
            raise InvalidContributionError(i, "psig")
        s += s_i
    return _xbytes(values.R) + (s % secp256k1.n).to_bytes(_SCALAR_SIZE, "big")


def partial_sig_verify(
    psig: Octets,
    pub_keys: Sequence[Octets],
    msgs: Sequence[Octets],
    pub_nonces: Sequence[Octets],
    i: int,
) -> bool:
    """Verify the partial signature of signer i: BIP459's PartialSigVerify.

    The aggregate nonce is computed here from the public nonces, so the
    coordinator cannot influence the answer.

    Raises for an input of the wrong size or type. Every failure BIP459
    lists is False, lists of different or zero length and an index out
    of range included: a list declares no size.
    """
    psig = bytes_from_octets(psig, _SCALAR_SIZE)
    pks = _octets_list(pub_keys, _PK_SIZE, "pub_keys")
    ms = _octets_list(msgs, _MSG_SIZE, "msgs")
    nonces = _octets_list(pub_nonces, _NONCE_SIZE, "pub_nonces")
    if not is_integer(i):
        raise EccTypeError(f"invalid i type: {type(i).__name__}")
    if not len(ms) == len(nonces) == len(pks) or not 0 <= i < len(pks):
        return False
    s = int.from_bytes(psig, "big")
    if s >= secp256k1.n:
        return False
    try:
        R_1i = _cpoint_var(nonces[i][:_CPOINT_SIZE])
        R_2i = _cpoint_var(nonces[i][_CPOINT_SIZE:])
        P_i = _lift_x_var(pks[i])
        agg_nonce = nonce_agg_var(nonces)
        values = session_values(SessionContext(agg_nonce, pks, ms, nonces))
    except (EccValueError, InvalidContributionError):
        return False
    R = values.R
    (c,) = _challenges(pks, ms, _xbytes(R), [i])
    R_i = secp256k1.add_var(R_1i, mult(values.b, R_2i, secp256k1))
    if R[1] % 2:
        R_i = secp256k1.negate(R_i)
    rhs = secp256k1.add_var(R_i, mult(c, P_i, secp256k1))
    return mult(s, ec=secp256k1) == rhs


def assert_as_valid(
    pub_keys: Sequence[Octets], msgs: Sequence[Octets], sig: Octets
) -> None:
    """Refuse an aggregate signature that does not verify: BIP459's Verify.

    `verify` is the spelling that answers a bool.
    """
    pks, ms = _lists(pub_keys, msgs)
    sig = bytes_from_octets(sig, _SIG_SIZE)
    r = sig[:_PK_SIZE]
    s = int.from_bytes(sig[_PK_SIZE:], "big")
    if s >= secp256k1.n:
        raise EccValueError("scalar s not in 0..n-1")
    R = _lift_x_var(r)
    Ps = [_lift_x_var(pk) for pk in pks]
    cs = _challenges(pks, ms, r, range(len(pks)))
    rhs = multi_mult_var([1, *cs], [R, *Ps], secp256k1)
    if mult(s, ec=secp256k1) != rhs:
        raise EccRuntimeError("signature verification failed")


def verify(pub_keys: Sequence[Octets], msgs: Sequence[Octets], sig: Octets) -> bool:
    """Verify an aggregate signature over the ordered (key, message) list.

    BIP459's Verify. Raises for an input of the wrong size or type;
    answers False for anything else that does not verify, a key or an r
    that does not lift and lists of different or zero length included:
    a list declares no size. `assert_as_valid` says why.
    """
    _octets_list(pub_keys, _PK_SIZE, "pub_keys")
    _octets_list(msgs, _MSG_SIZE, "msgs")
    bytes_from_octets(sig, _SIG_SIZE)
    try:
        assert_as_valid(pub_keys, msgs, sig)
    except (EccValueError, EccRuntimeError):
        return False
    return True


def _tweak(tweak: Octets) -> int:
    t = int.from_bytes(bytes_from_octets(tweak, _SCALAR_SIZE), "big")
    if t >= secp256k1.n:
        raise EccValueError("the tweak must be less than n")
    return t


def _tweaked_key_pair(d: int, t: int) -> tuple[int, bytes]:
    d = (d + t) % secp256k1.n
    if d == 0:
        raise EccValueError("tweaked key at infinity")
    return d, _xbytes(mult(d, ec=secp256k1))


def plain_tweak(prv_key: Integer, tweak: Octets) -> tuple[int, bytes]:
    """Return the plainly tweaked secret key and its 32-byte x-only key.

    BIP459's plain tweaking, as in BIP32 unhardened derivation:
    sk' = sk + t. The x-only key is what goes in the list of public keys.
    """
    d = scalar_from_prv_key(prv_key, secp256k1)
    return _tweaked_key_pair(d, _tweak(tweak))


def xonly_tweak(prv_key: Integer, tweak: Octets) -> tuple[int, bytes]:
    """Return the x-only tweaked secret key and its 32-byte x-only key.

    BIP459's x-only tweaking, as in BIP341 key path spending: the secret
    key is negated where its point has odd y, then sk' = sk + t.
    """
    d = scalar_from_prv_key(prv_key, secp256k1)
    if mult(d, ec=secp256k1)[1] % 2:
        d = secp256k1.n - d
    return _tweaked_key_pair(d, _tweak(tweak))


def _tweaked_pub_key_var(P: Point, t: int) -> bytes:
    Q = _tweak_add_var(P, t, secp256k1)
    if Q[1] == 0:
        raise EccValueError("tweaked key at infinity")
    return _cbytes(Q)


def plain_tweak_pub_key_var(pub_key: Octets, tweak: Octets) -> bytes:
    """Return P + t*G for a 33-byte compressed P, as 33 bytes.

    The public half of `plain_tweak`. The parity is kept so that tweaks
    can be chained; the list of public keys takes the last 32 bytes.
    """
    P = _cpoint_var(pub_key)
    return _tweaked_pub_key_var(P, _tweak(tweak))


def xonly_tweak_pub_key_var(pub_key: Octets, tweak: Octets) -> bytes:
    """Return lift_x(P) + t*G for a 32-byte x-only P, as 33 bytes.

    The public half of `xonly_tweak`. The parity is the one BIP341's
    control block commits to; the list of public keys takes the last 32
    bytes.
    """
    P = _lift_x_var(pub_key)
    return _tweaked_pub_key_var(P, _tweak(tweak))
