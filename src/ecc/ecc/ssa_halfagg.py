# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Half-aggregation of BIP340 signatures, according to BIP458.

https://github.com/bitcoin/bips/pull/2205 (draft BIP458)

Half-aggregation turns u BIP340 signatures into one aggregate signature
of 32*(u+1) bytes: the r of each signature, in order, then one scalar s,
the sum of the signatures' s values, each weighted by a randomizer. It
needs no signer: anyone holding the signatures, the public keys and the
messages can aggregate them. The aggregate is verified against the list
of (public key, message) pairs, in the order they were aggregated.

`inc_aggregate` adds signatures to an existing aggregate, and
`aggregate` is `inc_aggregate` starting from the aggregate of no
signature. BIP458 does not specify how to merge two aggregates, and
neither does this module.

**Aggregating checks no signature.** If every input signature is valid,
the aggregate verifies. The converse does not hold: inputs that include
an invalid signature can still give an aggregate that verifies, as
BIP458 states. A caller who needs every input valid verifies each one
with `ssa.verify_` first.

Like `ecc.ecc.musig2` and `ecc.ecc.dleq`, the curve and the hash
function are not arguments: BIP458 is defined for secp256k1 and sha256
only. A public key is a 32-byte x-only key, a message is exactly 32
bytes, and a signature is BIP340's 64 bytes.
"""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256
from typing import Any

from ecc._utils import assert_type, bytes_from_octets, is_octets
from ecc.alias import Octets
from ecc.curves import secp256k1
from ecc.curves.curve import _multi_mult_x_only_var, mult
from ecc.ecc.ssa import challenge_
from ecc.exceptions import EccRuntimeError, EccTypeError, EccValueError

__all__ = [
    "aggregate",
    "assert_as_valid",
    "inc_aggregate",
    "verify",
]

# BIP458's tag: a different string is a different scheme
_RANDOMIZER_TAG = b"BIP0458/randomizer"

# an x-only public key, a message, an r and an s are 32 bytes each, and a
# BIP340 signature is an r and an s
_SIZE = 32
_SIG_SIZE = 64


def _assert_sequence(value: Any, what: str) -> None:
    """Refuse a value that is no sequence, an Octets included.

    Every Octets is itself a Sequence, so one passed where a list of
    tuples was meant would be walked byte by byte.
    """
    if is_octets(value):
        raise EccTypeError(f"invalid {what} type: {type(value).__name__}")
    assert_type(value, Sequence, what)


def _tuples(
    items: Sequence[tuple[Octets, ...]], arity: int, what: str
) -> list[tuple[Octets, ...]]:
    """Return the tuples of a sequence, each of the given arity.

    A tuple of another arity is a wrong value, as for a Point, not a wrong type.
    """
    _assert_sequence(items, what)
    out: list[tuple[Octets, ...]] = []
    for item in items:
        assert_type(item, tuple, f"{what} item")
        if len(item) != arity:
            err_msg = f"{what} item of {len(item)} elements instead of {arity}"
            raise EccValueError(err_msg)
        out.append(item)
    return out


def _pub_keys_msgs(pm: Sequence[tuple[Octets, Octets]]) -> list[bytes]:
    """Return pk || m for each (public key, message) pair."""
    return [
        bytes_from_octets(pk, _SIZE) + bytes_from_octets(m, _SIZE)
        for pk, m in _tuples(pm, 2, "pm_aggd")
    ]


def _randomizers(rpms: Sequence[bytes]) -> list[int]:
    """Return BIP458's randomizers z_0..z_{u-1}.

    rpms[i] is r_i || pk_i || m_i. z_0 is 1, and z_i, for i above 0, is
    the tagged hash of rpms[0] || ... || rpms[i], reduced mod n. Each
    input is a prefix of the next, so one hash state absorbs them all and
    a copy of it is finalized for each z, as BIP458's rationale suggests.
    """
    tag_hash = sha256(_RANDOMIZER_TAG).digest()
    h = sha256(tag_hash + tag_hash)
    zs: list[int] = []
    for i, rpm in enumerate(rpms):
        h.update(rpm)
        z = 1 if i == 0 else int.from_bytes(h.copy().digest(), "big") % secp256k1.n
        zs.append(z)
    return zs


def inc_aggregate(
    aggsig: Octets,
    pm_aggd: Sequence[tuple[Octets, Octets]],
    pms_to_agg: Sequence[tuple[Octets, Octets, Octets]],
) -> bytes:
    """Return aggsig with the signatures of pms_to_agg aggregated into it.

    BIP458's IncAggregate. pm_aggd lists the (public key, message) pairs
    aggsig already aggregates, in order; pms_to_agg lists the (public key,
    message, signature) triples to add. If aggsig verifies against pm_aggd
    and every added signature is valid, the result verifies against
    pm_aggd followed by the pairs of pms_to_agg.

    Raises EccValueError for an aggsig whose length is not 32 times the
    number of pairs plus one, for an s at or above the group order, in
    aggsig or in a signature, for a key, a message or a signature of the
    wrong size, and for a tuple in pm_aggd or pms_to_agg of the wrong
    arity. Neither aggsig nor the added signatures are verified,
    and no r or key is checked to be an x-coordinate.
    """
    pms_aggd = _pub_keys_msgs(pm_aggd)
    triples = _tuples(pms_to_agg, 3, "pms_to_agg")
    v = len(pms_aggd)
    aggsig_bytes = bytes_from_octets(aggsig, _SIZE * (v + 1))

    rpms = [aggsig_bytes[i * _SIZE : (i + 1) * _SIZE] + pms_aggd[i] for i in range(v)]
    ss: list[int] = []
    for pk, m, sig in triples:
        pm = bytes_from_octets(pk, _SIZE) + bytes_from_octets(m, _SIZE)
        sig_bytes = bytes_from_octets(sig, _SIG_SIZE)
        s = int.from_bytes(sig_bytes[_SIZE:], "big")
        if s >= secp256k1.n:
            raise EccValueError("signature s not in 0..n-1")
        ss.append(s)
        rpms.append(sig_bytes[:_SIZE] + pm)

    s_agg = int.from_bytes(aggsig_bytes[v * _SIZE :], "big")
    if s_agg >= secp256k1.n:
        raise EccValueError("aggregate s not in 0..n-1")

    zs = _randomizers(rpms)
    s_agg = (s_agg + sum(z * s for z, s in zip(zs[v:], ss, strict=True))) % secp256k1.n
    rs = b"".join(rpm[:_SIZE] for rpm in rpms)
    return rs + s_agg.to_bytes(_SIZE, "big")


def aggregate(pms: Sequence[tuple[Octets, Octets, Octets]]) -> bytes:
    """Return the aggregate of (public key, message, signature) triples.

    BIP458's Aggregate: `inc_aggregate` starting from the aggregate of no
    signature, 32 zero bytes, and raising where it raises. No input
    signature is verified.
    """
    return inc_aggregate(bytes(_SIZE), [], pms)


def _parse(
    aggsig: Octets, pm_aggd: Sequence[tuple[Octets, Octets]]
) -> tuple[list[bytes], int]:
    """Return r_i || pk_i || m_i for each pair, and the s of aggsig.

    Raises for what cannot be an aggregate signature or its pairs: no
    pair at all, a key or a message that is not 32 bytes, and an aggsig
    whose length does not match the number of pairs. s is not checked
    against the group order.
    """
    pms = _pub_keys_msgs(pm_aggd)
    # BIP458 accepts the aggregate of no signature when its s is zero;
    # this refuses it, as ssa.batch_verify refuses an empty batch:
    # CONTRIBUTING.md's "The public surface" gives the reason
    if not pms:
        raise EccValueError("empty aggregate: no signatures to verify")
    u = len(pms)
    aggsig_bytes = bytes_from_octets(aggsig, _SIZE * (u + 1))
    rpms = [aggsig_bytes[i * _SIZE : (i + 1) * _SIZE] + pms[i] for i in range(u)]
    return rpms, int.from_bytes(aggsig_bytes[u * _SIZE :], "big")


def _assert_as_valid_(rpms: list[bytes], s: int) -> None:
    """Refuse an aggregate that does not verify, its octets already parsed.

    BIP458's VerifyAggregate from its lifts on:
    s*G == sum(z_i*(R_i + e_i*P_i)), one multi-scalar multiplication over
    the even-y points of each r_i and pk_i.
    """
    if s >= secp256k1.n:
        raise EccValueError("aggregate s not in 0..n-1")

    scalars: list[int] = []
    x_coords: list[int] = []
    for z, rpm in zip(_randomizers(rpms), rpms, strict=True):
        x_R = int.from_bytes(rpm[:_SIZE], "big")
        x_P = int.from_bytes(rpm[_SIZE : 2 * _SIZE], "big")
        e = challenge_(rpm[2 * _SIZE :], x_P, x_R, secp256k1, sha256)
        scalars += [z, z * e % secp256k1.n]
        x_coords += [x_R, x_P]

    # an r or a key that is no x-coordinate is refused by the lift inside
    # the multiplication, as an EccValueError
    if mult(s) != _multi_mult_x_only_var(scalars, x_coords, secp256k1):
        raise EccRuntimeError("aggregate signature verification failed")


def assert_as_valid(aggsig: Octets, pm_aggd: Sequence[tuple[Octets, Octets]]) -> None:
    """Refuse an aggregate signature that does not verify against pm_aggd.

    BIP458's VerifyAggregate, raising where it fails. pm_aggd lists the
    (public key, message) pairs in the order they were aggregated.
    `verify` is the spelling that answers True or False.

    Unlike BIP458, an empty pm_aggd raises: see `verify`.
    """
    _assert_as_valid_(*_parse(aggsig, pm_aggd))


def verify(aggsig: Octets, pm_aggd: Sequence[tuple[Octets, Octets]]) -> bool:
    """Return True if the aggregate signature verifies against pm_aggd.

    BIP458's VerifyAggregate. pm_aggd lists the (public key, message)
    pairs in the order they were aggregated.

    Raises where the input cannot be an aggregate signature and its pairs:
    a key or a message that is not 32 bytes, a tuple of the wrong arity,
    an aggsig whose length is not 32 times the number of pairs plus one,
    and an empty pm_aggd, which BIP458 accepts with an s of zero. Answers False for well-formed input
    that does not verify: an s at or above the group order, an r or a key
    that is no x-coordinate, an equation that does not hold.
    """
    parsed = _parse(aggsig, pm_aggd)
    try:
        _assert_as_valid_(*parsed)
    except (ValueError, EccRuntimeError):
        return False
    return True
