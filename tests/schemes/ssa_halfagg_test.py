# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.ecc.ssa_halfagg` module.

The vectors are BIP458's own, the csv files of `bip-0458/vectors/` in
bitcoin/bips#2205, vendored under `tests/schemes/_data/`;
`tests/_data/README.md` pins the revision. Every vector of each file is
run.

The other tests sign with `ecc.ecc.ssa`, and check the aggregate against
BIP458's definitions recomputed here: the randomizers as the tagged hash
of each prefix, and s as their weighted sum.
"""

from hashlib import sha256
from typing import Any

import pytest

from ecc.curves import secp256k1 as ec
from ecc.ecc import ssa, ssa_halfagg
from ecc.exceptions import EccRuntimeError, EccTypeError, EccValueError
from ecc.hashes import tagged_hash
from tests import both_arms, load_csv, vector_id

_TAG = b"BIP0458/randomizer"

_AGGREGATE_VECTORS = load_csv("schemes", "_data", "test_vectors_aggregate.csv")
_INC_AGGREGATE_VECTORS = load_csv("schemes", "_data", "test_vectors_incaggregate.csv")
_VERIFY_VECTORS = load_csv("schemes", "_data", "test_vectors_verify.csv")

# the verification vectors that raise where BIP458 expects FALSE or TRUE,
# by index, with the vector's own comment: a wrong size is no aggregate to
# answer False about, and the empty aggregate is refused where BIP458
# accepts it -- both CONTRIBUTING.md's "The public surface"
_VERIFY_RAISES = {
    "0": "Empty signature list",
    "20": "Aggregate signature too short",
    "21": "Aggregate signature too long",
    "22": "Public key too short",
    "23": "Message too long",
}


def _split(column: str) -> list[str]:
    """Return the values of a column, `;`-separated, an empty one none."""
    return column.split(";") if column else []


def _triples(count: int, seed: int = 1) -> list[tuple[bytes, bytes, bytes]]:
    """Return (x-only key, message, signature) triples made with ssa."""
    triples = []
    for i in range(seed, seed + count):
        q, x_Q = ssa.gen_keys(i)
        msg = sha256(i.to_bytes(4, "big")).digest()
        sig = ssa.sign_(msg, q, bytes(32)).serialize()
        triples.append((x_Q.to_bytes(32, "big"), msg, sig))
    return triples


def _pairs(triples: list[tuple[bytes, bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    return [(pk, msg) for pk, msg, _ in triples]


# 0 is no x-coordinate of secp256k1: 0**3 + 7 is not a square mod p, which
# test_zero_is_no_x_coordinate checks
_NO_X = bytes(32)
_P = ec.p.to_bytes(32, "big")
_N = ec.n.to_bytes(32, "big")


def test_zero_is_no_x_coordinate() -> None:
    """Euler's criterion: 7 is not a square mod p."""
    assert pow(7, (ec.p - 1) // 2, ec.p) == ec.p - 1


@pytest.mark.parametrize("count", [1, 2, 3, 7])
@both_arms
def test_aggregate_verifies(count: int) -> None:
    """Signatures made by ssa aggregate into one that verifies."""
    triples = _triples(count)
    aggsig = ssa_halfagg.aggregate(triples)
    assert len(aggsig) == 32 * (count + 1)
    assert ssa_halfagg.verify(aggsig, _pairs(triples))
    ssa_halfagg.assert_as_valid(aggsig, _pairs(triples))


def test_aggregate_is_bip458s_sum() -> None:
    """The r values in order, then s = sum(z_i * s_i), z_i from each prefix.

    The randomizers are recomputed one tagged hash per prefix, not
    through the single hash state the module streams them with.
    """
    triples = _triples(4)
    aggsig = ssa_halfagg.aggregate(triples)
    assert aggsig[:-32] == b"".join(sig[:32] for _, _, sig in triples)

    prefix = b""
    s = 0
    for i, (pk, msg, sig) in enumerate(triples):
        prefix += sig[:32] + pk + msg
        z = 1 if i == 0 else int.from_bytes(tagged_hash(_TAG, prefix), "big") % ec.n
        s += z * int.from_bytes(sig[32:], "big")
    assert aggsig[-32:] == (s % ec.n).to_bytes(32, "big")


def test_one_signature_aggregates_to_itself() -> None:
    """z_0 is 1, so the aggregate of one signature is that signature."""
    triples = _triples(1)
    assert ssa_halfagg.aggregate(triples) == triples[0][2]


def test_the_empty_aggregate() -> None:
    """Aggregating nothing gives BIP458's starting aggregate, 32 zero bytes.

    Verifying it raises, where BIP458 accepts it: CONTRIBUTING.md's
    "The public surface" says why.
    """
    empty = ssa_halfagg.aggregate([])
    assert empty == bytes(32)
    assert ssa_halfagg.inc_aggregate(empty, [], []) == empty
    for function in (ssa_halfagg.verify, ssa_halfagg.assert_as_valid):
        with pytest.raises(EccValueError, match="empty aggregate"):
            function(empty, [])
        with pytest.raises(EccValueError, match="empty aggregate"):
            function(bytes(31) + b"\x01", [])


def test_incremental_aggregation_equals_one_shot() -> None:
    """Adding signatures to an aggregate, at every split, is aggregating all."""
    triples = _triples(5)
    expected = ssa_halfagg.aggregate(triples)
    for split in range(len(triples) + 1):
        head = ssa_halfagg.aggregate(triples[:split])
        aggsig = ssa_halfagg.inc_aggregate(
            head, _pairs(triples[:split]), triples[split:]
        )
        assert aggsig == expected
    # one signature at a time
    aggsig = ssa_halfagg.aggregate([])
    for i, triple in enumerate(triples):
        aggsig = ssa_halfagg.inc_aggregate(aggsig, _pairs(triples[:i]), [triple])
    assert aggsig == expected
    # nothing added: the aggregate comes back as it was
    assert ssa_halfagg.inc_aggregate(expected, _pairs(triples), []) == expected


def test_order_matters() -> None:
    """An aggregate verifies against its pairs in their order, and no other."""
    triples = _triples(3)
    aggsig = ssa_halfagg.aggregate(triples)
    reordered = [triples[1], triples[0], triples[2]]
    assert not ssa_halfagg.verify(aggsig, _pairs(reordered))
    other = ssa_halfagg.aggregate(reordered)
    assert other != aggsig
    assert ssa_halfagg.verify(other, _pairs(reordered))


def test_duplicates_aggregate() -> None:
    """The same triple twice, and two messages under one key, verify."""
    triples = _triples(2)
    twice = [triples[0], triples[0], triples[1]]
    aggsig = ssa_halfagg.aggregate(twice)
    assert ssa_halfagg.verify(aggsig, _pairs(twice))
    assert aggsig[:32] == aggsig[32:64]

    q, x_Q = ssa.gen_keys(1)
    pk = x_Q.to_bytes(32, "big")
    same_key = [
        (pk, bytes([i]) * 32, ssa.sign_(bytes([i]) * 32, q).serialize())
        for i in range(3)
    ]
    assert ssa_halfagg.verify(ssa_halfagg.aggregate(same_key), _pairs(same_key))


def test_hex_strings_are_octets() -> None:
    """Every Octets spelling is accepted, hex strings included."""
    triples = _triples(2)
    as_hex = [(pk.hex(), msg.hex(), sig.hex()) for pk, msg, sig in triples]
    aggsig = ssa_halfagg.aggregate(as_hex)
    assert aggsig == ssa_halfagg.aggregate(triples)
    assert ssa_halfagg.verify(aggsig.hex(), [(pk, msg) for pk, msg, _ in as_hex])


@both_arms
def test_tampering_answers_false() -> None:
    """A changed r, s, key or message is a False, and a raise from assert."""
    triples = _triples(3)
    pairs = _pairs(triples)
    aggsig = ssa_halfagg.aggregate(triples)
    other_pk = _triples(1, seed=99)[0][0]

    s = int.from_bytes(aggsig[-32:], "big")
    other_r = triples[0][2][:32]  # r_0 where r_1 belongs, an x-coordinate
    cases: list[tuple[bytes, list[tuple[bytes, bytes]]]] = [
        (aggsig[:-32] + ((s + 1) % ec.n).to_bytes(32, "big"), pairs),
        (aggsig[:32] + other_r + aggsig[64:], pairs),
        (aggsig, [pairs[0], (other_pk, pairs[1][1]), pairs[2]]),
        (aggsig, [pairs[0], pairs[1], (pairs[2][0], bytes(32))]),
    ]
    for bad_aggsig, bad_pairs in cases:
        assert not ssa_halfagg.verify(bad_aggsig, bad_pairs)
        with pytest.raises(EccRuntimeError, match="verification failed"):
            ssa_halfagg.assert_as_valid(bad_aggsig, bad_pairs)


@both_arms
def test_what_does_not_lift_answers_false() -> None:
    """An r or a key that is no x-coordinate, or not below p, is a False."""
    triples = _triples(2)
    pairs = _pairs(triples)
    aggsig = ssa_halfagg.aggregate(triples)
    for bad in (_NO_X, _P, b"\xff" * 32):
        bad_r = aggsig[:32] + bad + aggsig[64:]
        assert not ssa_halfagg.verify(bad_r, pairs)
        with pytest.raises(EccValueError):
            ssa_halfagg.assert_as_valid(bad_r, pairs)
        bad_key = [pairs[0], (bad, pairs[1][1])]
        assert not ssa_halfagg.verify(aggsig, bad_key)
        with pytest.raises(EccValueError):
            ssa_halfagg.assert_as_valid(aggsig, bad_key)


def test_an_s_out_of_range() -> None:
    """An s at or above n: inc_aggregate raises, verify answers False."""
    triples = _triples(2)
    pairs = _pairs(triples)
    aggsig = ssa_halfagg.aggregate(triples)
    for big_s in (_N, b"\xff" * 32):
        bad_aggsig = aggsig[:-32] + big_s
        assert not ssa_halfagg.verify(bad_aggsig, pairs)
        with pytest.raises(EccValueError, match="aggregate s not in 0..n-1"):
            ssa_halfagg.assert_as_valid(bad_aggsig, pairs)
        with pytest.raises(EccValueError, match="aggregate s not in 0..n-1"):
            ssa_halfagg.inc_aggregate(bad_aggsig, pairs, [])

        pk, msg, sig = triples[1]
        bad_triple = (pk, msg, sig[:32] + big_s)
        with pytest.raises(EccValueError, match="signature s not in 0..n-1"):
            ssa_halfagg.aggregate([triples[0], bad_triple])
        with pytest.raises(EccValueError, match="signature s not in 0..n-1"):
            ssa_halfagg.inc_aggregate(
                ssa_halfagg.aggregate(triples[:1]), pairs[:1], [bad_triple]
            )


def test_inc_aggregate_checks_no_signature() -> None:
    """Invalid inputs can aggregate into an aggregate that verifies.

    BIP458 says so, and this builds the case: s_0 raised by d and s_1
    lowered by d/z_1 leave the sum unchanged, so two invalid signatures
    give the aggregate of two valid ones. Aggregating also takes an r and
    a key that are no x-coordinate, which only verification lifts.
    """
    triples = _triples(2)
    aggsig = ssa_halfagg.aggregate(triples)
    (pk0, m0, sig0), (pk1, m1, sig1) = triples
    z1 = (
        int.from_bytes(
            tagged_hash(_TAG, sig0[:32] + pk0 + m0 + sig1[:32] + pk1 + m1), "big"
        )
        % ec.n
    )
    d = 12345
    s0 = (int.from_bytes(sig0[32:], "big") + d) % ec.n
    s1 = (int.from_bytes(sig1[32:], "big") - d * pow(z1, -1, ec.n)) % ec.n
    bad0 = (pk0, m0, sig0[:32] + s0.to_bytes(32, "big"))
    bad1 = (pk1, m1, sig1[:32] + s1.to_bytes(32, "big"))
    assert not ssa.verify_(m0, pk0, bad0[2])
    assert not ssa.verify_(m1, pk1, bad1[2])
    assert ssa_halfagg.aggregate([bad0, bad1]) == aggsig
    assert ssa_halfagg.verify(aggsig, _pairs(triples))

    unliftable = (_NO_X, m0, _NO_X + sig0[32:])
    assert ssa_halfagg.aggregate([unliftable])[:32] == _NO_X


def test_wrong_sizes_raise() -> None:
    """A key, a message, a signature or an aggsig of the wrong size raises.

    In verify too: those positions declare a size, so a wrong one is no
    aggregate to answer False about.
    """
    triples = _triples(2)
    pairs = _pairs(triples)
    aggsig = ssa_halfagg.aggregate(triples)
    pk, msg, sig = triples[1]
    for bad_triple in (
        (pk[1:], msg, sig),
        (pk, msg + b"\x00", sig),
        (pk, msg, sig[:-1]),
    ):
        with pytest.raises(EccValueError):
            ssa_halfagg.aggregate([triples[0], bad_triple])
    for bad_pairs in ([pairs[0], (b"\x02" + pk, msg)], [pairs[0], (pk, msg[:-1])]):
        with pytest.raises(EccValueError):
            ssa_halfagg.verify(aggsig, bad_pairs)
        with pytest.raises(EccValueError):
            ssa_halfagg.inc_aggregate(aggsig, bad_pairs, [])
    for bad_aggsig in (aggsig[:-1], aggsig + b"\x00", aggsig[:-32]):
        for function in (ssa_halfagg.verify, ssa_halfagg.assert_as_valid):
            with pytest.raises(EccValueError):
                function(bad_aggsig, pairs)
        with pytest.raises(EccValueError):
            ssa_halfagg.inc_aggregate(bad_aggsig, pairs, [])
    # an aggregate of two read against one pair is the wrong length
    with pytest.raises(EccValueError):
        ssa_halfagg.verify(aggsig, pairs[:1])
    with pytest.raises(EccValueError):
        ssa_halfagg.inc_aggregate(bytes(31), [], triples)


def test_wrong_types_raise() -> None:
    """What is not a sequence of tuples of octets is an EccTypeError."""
    triples = _triples(1)
    pairs = _pairs(triples)
    aggsig = ssa_halfagg.aggregate(triples)
    not_sequences: list[Any] = [None, 1.5, b"\x00" * 64, "00" * 64, bytearray(64)]
    for bad in not_sequences:
        with pytest.raises(EccTypeError):
            ssa_halfagg.aggregate(bad)
        with pytest.raises(EccTypeError):
            ssa_halfagg.inc_aggregate(bytes(32), bad, [])
        with pytest.raises(EccTypeError):
            ssa_halfagg.inc_aggregate(bytes(32), [], bad)
        with pytest.raises(EccTypeError):
            ssa_halfagg.verify(aggsig, bad)
    # a list where a tuple belongs
    with pytest.raises(EccTypeError):
        ssa_halfagg.aggregate([list(triples[0])])  # type: ignore[list-item]
    with pytest.raises(EccTypeError):
        ssa_halfagg.verify(aggsig, [list(pairs[0])])  # type: ignore[list-item]
    # an element that is no octets
    with pytest.raises(EccTypeError):
        ssa_halfagg.verify(aggsig, [(None, pairs[0][1])])  # type: ignore[list-item]
    with pytest.raises(EccTypeError):
        ssa_halfagg.verify(None, pairs)  # type: ignore[arg-type]


def test_a_tuple_of_the_wrong_arity_raises() -> None:
    """A pair where a triple belongs, and the converse, is an EccTypeError."""
    triples = _triples(1)
    aggsig = ssa_halfagg.aggregate(triples)
    with pytest.raises(EccTypeError, match="2 elements instead of 3"):
        ssa_halfagg.aggregate(_pairs(triples))  # type: ignore[arg-type]
    with pytest.raises(EccTypeError, match="3 elements instead of 2"):
        ssa_halfagg.verify(aggsig, triples)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "pubkeys,messages,signatures,result,expected",
    [row[1:-1] for row in _AGGREGATE_VECTORS],
    ids=[vector_id(int(row[0]), row[-1]) for row in _AGGREGATE_VECTORS],
)
def test_aggregate_vectors(
    pubkeys: str, messages: str, signatures: str, result: str, expected: str
) -> None:
    """BIP458's Aggregate vectors: the aggregate, or an EccValueError."""
    pms = list(zip(_split(pubkeys), _split(messages), _split(signatures), strict=True))
    if result == "TRUE":
        assert ssa_halfagg.aggregate(pms) == bytes.fromhex(expected)
    else:
        assert result == "FALSE"
        with pytest.raises(EccValueError):
            ssa_halfagg.aggregate(pms)


@pytest.mark.parametrize(
    "aggsig,pubkeys,messages,new_pubkeys,new_messages,new_signatures,result,expected",
    [row[1:-1] for row in _INC_AGGREGATE_VECTORS],
    ids=[vector_id(int(row[0]), row[-1]) for row in _INC_AGGREGATE_VECTORS],
)
def test_inc_aggregate_vectors(
    aggsig: str,
    pubkeys: str,
    messages: str,
    new_pubkeys: str,
    new_messages: str,
    new_signatures: str,
    result: str,
    expected: str,
) -> None:
    """BIP458's IncAggregate vectors: the aggregate, or an EccValueError."""
    pm_aggd = list(zip(_split(pubkeys), _split(messages), strict=True))
    pms = list(
        zip(
            _split(new_pubkeys),
            _split(new_messages),
            _split(new_signatures),
            strict=True,
        )
    )
    if result == "TRUE":
        assert ssa_halfagg.inc_aggregate(aggsig, pm_aggd, pms) == bytes.fromhex(
            expected
        )
    else:
        assert result == "FALSE"
        with pytest.raises(EccValueError):
            ssa_halfagg.inc_aggregate(aggsig, pm_aggd, pms)


@pytest.mark.parametrize(
    "index,aggsig,pubkeys,messages,result,comment",
    _VERIFY_VECTORS,
    ids=[vector_id(int(row[0]), row[-1]) for row in _VERIFY_VECTORS],
)
@both_arms
def test_verify_vectors(
    index: str, aggsig: str, pubkeys: str, messages: str, result: str, comment: str
) -> None:
    """BIP458's VerifyAggregate vectors, each pinned to its answer here.

    TRUE is True and FALSE is False, but for the vectors of
    `_VERIFY_RAISES`, which raise. Vector 0, the empty aggregate, is the
    one disagreement with BIP458: it expects TRUE.
    """
    pm_aggd = list(zip(_split(pubkeys), _split(messages), strict=True))
    if index in _VERIFY_RAISES:
        assert comment == _VERIFY_RAISES[index]
        with pytest.raises(EccValueError):
            ssa_halfagg.verify(aggsig, pm_aggd)
        with pytest.raises(EccValueError):
            ssa_halfagg.assert_as_valid(aggsig, pm_aggd)
        return
    assert ssa_halfagg.verify(aggsig, pm_aggd) is (result == "TRUE")
    assert result in {"TRUE", "FALSE"}
    if result == "TRUE":
        ssa_halfagg.assert_as_valid(aggsig, pm_aggd)
    else:
        with pytest.raises((EccValueError, EccRuntimeError)):
            ssa_halfagg.assert_as_valid(aggsig, pm_aggd)


def test_the_raising_verify_vectors_are_the_ones_named() -> None:
    """Each index `_VERIFY_RAISES` names exists; only vector 0 is TRUE."""
    rows = {row[0]: row for row in _VERIFY_VECTORS}
    assert set(_VERIFY_RAISES) <= set(rows)
    assert [i for i in _VERIFY_RAISES if rows[i][4] == "TRUE"] == ["0"]
