# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.curves.curve_group_2` module."""

import random
import secrets
from collections.abc import Callable

import pytest

from ecc.alias import INF, INFJ, JacPoint, Public
from ecc.curves import Curve, secp256k1
from ecc.curves.curve_group import (
    _double_mult_var,
    _mult,
    _odd_multiples_aff,
    _signed_odd_multiples_aff,
)

# from the module that defines them: ecc.curves does not export the
# individual multiplication implementations
from ecc.curves.curve_group_2 import (
    _BETA,
    _HALF_LEN,
    _LAM,
    _N,
    _double_mult_endomorphism_secp256k1_var,
    _double_mult_regular_window,
    _double_mult_w_NAF_var,
    _endomorphism_split_secp256k1,
    _lambda_image,
    _mult_endomorphism_secp256k1,
    _mult_endomorphism_secp256k1_var,
    _mult_sliding_window_var,
    _mult_w_NAF_var,
    _multiplier_decomposer,
)
from ecc.exceptions import EccValueError
from tests.curves.curve_group_test import _CountingGroup
from tests.curves.curve_test import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_mult_sliding_window() -> None:
    """Check the sliding-window mult on boundary scalars and against _mult."""
    for w in range(1, 6):
        for ec in low_card_curves.values():
            assert ec.is_jac_equal(
                _mult_sliding_window_var(Public(0), ec.GJ, ec, w), INFJ
            )
            assert ec.is_jac_equal(
                _mult_sliding_window_var(Public(0), INFJ, ec, w), INFJ
            )

            assert ec.is_jac_equal(
                _mult_sliding_window_var(Public(1), INFJ, ec, w), INFJ
            )
            assert ec.is_jac_equal(
                _mult_sliding_window_var(Public(1), ec.GJ, ec, w), ec.GJ
            )

            PJ = _mult_sliding_window_var(Public(2), ec.GJ, ec, w)
            assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = _mult_sliding_window_var(Public(ec.n - 1), ec.GJ, ec, w)
            assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)

            assert ec.is_jac_equal(
                _mult_sliding_window_var(Public(ec.n - 1), INFJ, ec, w), INFJ
            )
            assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.is_jac_equal(
                _mult_sliding_window_var(Public(ec.n), ec.GJ, ec, w), INFJ
            )

            with pytest.raises(EccValueError, match="negative m$"):
                _mult_sliding_window_var(Public(-1), ec.GJ, ec, w)

            with pytest.raises(EccValueError, match="non positive w: "):
                _mult_sliding_window_var(Public(1), ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_sliding_window_var(Public(k1), ec.GJ, ec, w)
            assert ec.is_jac_equal(K1, _mult(k1, ec.GJ, ec))


def test_mult_w_NAF() -> None:
    """Check the wNAF mult on boundary scalars and against _mult."""
    for w in range(1, 6):
        for ec in low_card_curves.values():
            assert ec.is_jac_equal(_mult_w_NAF_var(Public(0), ec.GJ, ec, w), INFJ)
            assert ec.is_jac_equal(_mult_w_NAF_var(Public(0), INFJ, ec, w), INFJ)

            assert ec.is_jac_equal(_mult_w_NAF_var(Public(1), INFJ, ec, w), INFJ)
            assert ec.is_jac_equal(_mult_w_NAF_var(Public(1), ec.GJ, ec, w), ec.GJ)

            PJ = _mult_w_NAF_var(Public(2), ec.GJ, ec, w)
            assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = _mult_w_NAF_var(Public(ec.n - 1), ec.GJ, ec, w)
            assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)

            assert ec.is_jac_equal(_mult_w_NAF_var(Public(ec.n - 1), INFJ, ec, w), INFJ)
            assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.is_jac_equal(_mult_w_NAF_var(Public(ec.n), ec.GJ, ec, w), INFJ)

            with pytest.raises(EccValueError, match="negative m$"):
                _mult_w_NAF_var(Public(-1), ec.GJ, ec, w)

            with pytest.raises(EccValueError, match="non positive w: "):
                _mult_w_NAF_var(Public(1), ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_w_NAF_var(Public(k1), ec.GJ, ec, w)
            assert ec.is_jac_equal(K1, _mult(k1, ec.GJ, ec))


@pytest.mark.parametrize(
    "mult_endo", [_mult_endomorphism_secp256k1, _mult_endomorphism_secp256k1_var]
)
def test_mult_endomorphism_secp256k1(
    mult_endo: Callable[[int, JacPoint, Curve, int], JacPoint],
) -> None:
    """Both double multiplications the endomorphism can be built on.

    The regular windows of the one `curves.mult` runs and the
    interleaved wNAFs of algorithm 3.77 as it is written: the same
    points, at the costs their docstrings measure, so both answer every
    case here.
    """

    def mult(m: int, QJ: JacPoint) -> JacPoint:
        return mult_endo(m, QJ, secp256k1, 4)

    ec = secp256k1
    assert ec.is_jac_equal(mult(0, ec.GJ), INFJ)
    assert ec.is_jac_equal(mult(0, INFJ), INFJ)

    assert ec.is_jac_equal(mult(1, INFJ), INFJ)
    assert ec.is_jac_equal(mult(1, ec.GJ), ec.GJ)

    PJ = mult(2, ec.GJ)
    assert ec.is_jac_equal(PJ, ec.add_jac(ec.GJ, ec.GJ))

    PJ = mult(ec.n - 1, ec.GJ)
    assert ec.is_jac_equal(ec.negate_jac(ec.GJ), PJ)

    assert ec.is_jac_equal(mult(ec.n - 1, INFJ), INFJ)
    assert ec.is_jac_equal(ec.add_jac(PJ, ec.GJ), INFJ)
    assert ec.is_jac_equal(mult(ec.n, ec.GJ), INFJ)

    with pytest.raises(EccValueError, match="negative m$"):
        mult(-1, ec.GJ)


def test_mult_endomorphism_agrees_with_mult_above_2_127() -> None:
    """The scalars a broken decomposition gets wrong (btclib-org/btclib#215).

    Every edge value -- 0, 1, 2, n-1, n -- decomposes correctly even mod p,
    because p and n share their top 128 bits and a scalar below ~2^127 never
    reaches the bits where they differ. So the test to have is agreement with
    _mult across that line: the fixed scalars stepping over it, the two cube
    roots whose decompositions are the identity ones, and a spread of full-size
    scalars. Under btclib-org/btclib's decomposition before that fix, every
    scalar of this test above 2^127 failed.
    """
    ec = secp256k1
    scalars = [
        (1 << 127) - 1,  # the last scalar the mod-p decomposition survived
        1 << 127,
        (1 << 128) - 1,  # both halves negative
        _LAM,  # decomposes to (0, 1): the endomorphism itself
        _N - _LAM,  # (0, -1): the endomorphism, negated
        _N - 2,
        # a full-size scalar with no structure: the SHA256 of b"this package"
        0x7118B2DE7044D38B8A6CCD65B64E18BCB451C61A6E2344341FC972F522B70FDA % _N,
    ] + [secrets.randbelow(_N) for _ in range(8)]
    for m in scalars:
        expected = _mult(m, ec.GJ, ec)
        for mult_endo in (
            _mult_endomorphism_secp256k1,
            _mult_endomorphism_secp256k1_var,
        ):
            got = mult_endo(Public(m), ec.GJ, ec, 4)
            assert ec.is_jac_equal(got, expected), (m, mult_endo.__name__)


def test_multiplier_decomposer() -> None:
    """Balanced length-two representation: short, signed, congruent.

    The three properties algorithm 3.74 promises, each of which the mod-p
    version broke (issue btclib-org/btclib#215), plus the five decompositions
    that are exact by construction: the identities of the lattice. A negative or
    oversized m reduces mod n first, so every integer decomposes and the caller
    owns the sign handling.
    """
    # the identity decompositions, exact values rather than properties
    assert _multiplier_decomposer(0) == (0, 0)
    assert _multiplier_decomposer(1) == (1, 0)
    assert _multiplier_decomposer(_N - 1) == (-1, 0)
    assert _multiplier_decomposer(_LAM) == (0, 1)
    assert _multiplier_decomposer(_N - _LAM) == (0, -1)
    # reduction mod n first: -7 is n - 7, whose balanced form is -7
    assert _multiplier_decomposer(-7) == (-7, 0)
    assert _multiplier_decomposer(_N + 42) == (42, 0)

    scalars = [1 << 127, (1 << 128) - 1, _N - 2, _LAM - 1, _LAM + 1] + [
        secrets.randbelow(_N) for _ in range(20)
    ]
    for m in scalars:
        m1, m2 = _multiplier_decomposer(m)
        # congruent: m1 + m2*lambda is m mod n, which is the identity
        # making m1*Q + m2*(lambda*Q) equal m*Q
        assert (m1 + m2 * _LAM - m) % _N == 0
        # short and signed: both halves fit _HALF_LEN bits, sign included,
        # against the 256 both reached when the results were % p. That
        # constant is the digit count of the regular double multiplication
        # the endomorphism runs, so a half over it would cost a window
        assert m1.bit_length() <= _HALF_LEN
        assert m2.bit_length() <= _HALF_LEN


def test_double_mult_w_NAF() -> None:
    """Interleaved-wNAF double mult against the Shamir-Strauss one.

    Exhaustive over every (u, v) pair of two low-cardinality curves --
    including u or v of 0, whose wNAF is empty -- and for w of 1, where
    the tables collapse to the points themselves and every digit is +-1.
    """
    for ec in (low_card_curves["ec13_11"], ec23_31):
        HJ = ec.GJ
        QJ = _mult(3, ec.GJ, ec)
        for w in (1, 2, 4):
            for u in range(ec.n):
                for v in range(ec.n):
                    expected = _double_mult_var(Public(u), HJ, Public(v), QJ, ec)
                    got = _double_mult_w_NAF_var(
                        Public(u), HJ, Public(v), QJ, ec, w, ec._fixed_points
                    )
                    assert ec.is_jac_equal(got, expected), (u, v, w)

    ec = secp256k1
    assert ec.is_jac_equal(
        _double_mult_w_NAF_var(
            Public(0), ec.GJ, Public(0), ec.GJ, ec, 4, ec._fixed_points
        ),
        INFJ,
    )
    with pytest.raises(EccValueError, match="negative first coefficient$"):
        _double_mult_w_NAF_var(
            Public(-1), ec.GJ, Public(1), ec.GJ, ec, 4, ec._fixed_points
        )
    with pytest.raises(EccValueError, match="negative second coefficient$"):
        _double_mult_w_NAF_var(
            Public(1), ec.GJ, Public(-1), ec.GJ, ec, 4, ec._fixed_points
        )
    with pytest.raises(EccValueError, match="non positive w: "):
        _double_mult_w_NAF_var(
            Public(1), ec.GJ, Public(1), ec.GJ, ec, 0, ec._fixed_points
        )


def test_double_mult_endomorphism_secp256k1() -> None:
    """The GLV double mult against the Shamir-Strauss one it replaces.

    secp256k1 only, the endomorphism being its own, so there is no
    low-cardinality curve to be exhaustive over and the pairs are chosen
    instead: the boundaries, the two cube roots whose decompositions are the
    lattice identities, and the 2^127 line issue btclib-org/btclib#215 was
    about, where a decomposition reduced mod p rather than mod n starts
    answering wrongly. A coefficient at or above n is reduced by the decomposer,
    so the reference is taken on the residue.

    Every w, not only the one `curve.py` passes: w=1 collapses each table
    to the point itself and is where an off-by-one in the interleaving
    would show.
    """
    ec = secp256k1
    HJ = ec.GJ
    QJ = _mult(3, ec.GJ, ec)

    def dm(u: int, v: int, H: JacPoint, Q: JacPoint, w: int = 4) -> JacPoint:
        return _double_mult_endomorphism_secp256k1_var(
            Public(u), H, Public(v), Q, ec, w, ec._fixed_points
        )

    pairs = [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (1, 2),
        (1, _N - 1),
        (_N - 1, 1),
        (_N - 1, _N - 2),
        ((1 << 127) - 1, 1 << 127),  # the last scalar the mod-p split survived
        ((1 << 128) - 1, (1 << 128) - 1),  # all four halves negative
        (_LAM, _N - _LAM),  # (0, 1) and (0, -1): the endomorphism itself
        (_N, _N + 42),  # reduced mod n before anything else
    ] + [(secrets.randbelow(_N), secrets.randbelow(_N)) for _ in range(8)]
    for u, v in pairs:
        expected = _double_mult_var(Public(u % _N), HJ, Public(v % _N), QJ, ec)
        for w in (1, 2, 4, 5):
            assert ec.is_jac_equal(dm(u, v, HJ, QJ, w), expected), (u, v, w)

    # infinity on either side, and the coefficient that contributes nothing:
    # what `curves.double_mult_var` sends down this path on secp256k1, the
    # bindings taking no zero scalar and no infinity
    for u, v in ((7, 5), (0, 5), (7, 0), (0, 0)):
        for H, Q in ((INFJ, QJ), (HJ, INFJ), (INFJ, INFJ)):
            assert ec.is_jac_equal(
                dm(u, v, H, Q), _double_mult_var(Public(u), H, Public(v), Q, ec)
            ), (
                u,
                v,
            )

    # the same point twice, and a sum that lands on infinity
    assert ec.is_jac_equal(
        dm(7, 5, HJ, HJ), _double_mult_var(Public(7), HJ, Public(5), HJ, ec)
    )
    assert ec.is_jac_equal(dm(3, _N - 3, HJ, HJ), INFJ)

    with pytest.raises(EccValueError, match="negative first coefficient$"):
        dm(-1, 1, HJ, QJ)
    with pytest.raises(EccValueError, match="negative second coefficient$"):
        dm(1, -1, HJ, QJ)
    with pytest.raises(EccValueError, match="non positive w: "):
        dm(1, 1, HJ, QJ, 0)


def test_double_mult_regular_window() -> None:
    """Regular windows against the Shamir-Strauss double mult.

    The same exhaustive pairs test_double_mult_w_NAF runs, the two
    functions being interchangeable: a zero coefficient, whose recoding is
    that of 1 with the correction taking it back, and w of 1, where each
    table is the point and its opposite and every digit is +-1.
    """
    for ec in (low_card_curves["ec13_11"], ec23_31):
        HJ = ec.GJ
        QJ = _mult(3, ec.GJ, ec)
        for w in (1, 2, 4):
            for u in range(ec.n):
                for v in range(ec.n):
                    expected = _double_mult_var(Public(u), HJ, Public(v), QJ, ec)
                    got = _double_mult_regular_window(u, HJ, v, QJ, ec, w, scalar_len=0)
                    assert ec.is_jac_equal(got, expected), (u, v, w)

    ec = secp256k1
    # the scalar_len the endomorphism passes, and coefficients that need
    # more digits than it asks for: the count is fixed, not a limit
    for u, v in ((0, 0), (1, _N - 1), (_N - 1, 1), (_N - 1, _N - 2)):
        expected = _double_mult_var(Public(u), ec.GJ, Public(v), ec.GJ, ec)
        for scalar_len in (0, _HALF_LEN):
            got = _double_mult_regular_window(u, ec.GJ, v, ec.GJ, ec, 4, scalar_len)
            assert ec.is_jac_equal(got, expected), (u, v, scalar_len)

    with pytest.raises(EccValueError, match="negative first coefficient$"):
        _double_mult_regular_window(-1, ec.GJ, 1, ec.GJ, ec, w=4, scalar_len=0)
    with pytest.raises(EccValueError, match="negative second coefficient$"):
        _double_mult_regular_window(1, ec.GJ, -1, ec.GJ, ec, w=4, scalar_len=0)
    with pytest.raises(EccValueError, match="non positive w: "):
        _double_mult_regular_window(1, ec.GJ, 1, ec.GJ, ec, 0, scalar_len=0)


def test_lambda_image_is_the_table_of_the_split_point() -> None:
    """The table of K is the image of the table of P, up to the sign.

    Against the tables built for K directly, over scalars of every pair of
    signs of the two halves, and over a point whose Z is not 1.
    """
    ec = secp256k1
    rnd = random.Random(0x1A3BDA)
    QJ = _mult(777, ec.double_jac(ec.GJ), ec)
    assert QJ[2] != 1
    signs = set()
    for m in [rnd.randrange(ec.n) for _ in range(40)] + [1, 2, ec.n - 1]:
        _, P, _, K = _endomorphism_split_secp256k1(m, QJ, ec)
        signs.add((P[1] == QJ[1], K[1] == QJ[1]))
        for w in (1, 2, 3, 4, 5):
            opposite = K[1] != P[1]

            odd = _lambda_image(_odd_multiples_aff(P, ec, w), ec)
            if opposite:
                odd = [ec.negate(R) for R in odd]
            assert odd == _odd_multiples_aff(K, ec, w), (m, w)

            signed = _lambda_image(_signed_odd_multiples_aff(P, ec, w), ec)
            if opposite:
                signed = signed[::-1]
            assert signed == _signed_odd_multiples_aff(K, ec, w), (m, w)
    assert len(signs) == 4, signs


def test_mult_endomorphism_makes_the_same_operations_for_every_scalar() -> None:
    """One count of additions and doublings (btclib-org/btclib#254).

    Over scalars that give every pair of signs of the two halves, the
    selection of the second table included.
    """
    rnd = random.Random(0x9EC0DE)
    scalars = [rnd.randrange(secp256k1.n) for _ in range(20)]
    scalars += [0, 1, 2, 3, 1 << 100, secp256k1.n >> 17, secp256k1.n - 1]

    ec = _CountingGroup()
    signs = set()
    counts = set()
    for m in scalars:
        m1, m2 = _multiplier_decomposer(m)
        signs.add((m1 < 0, m2 < 0))
        ec.additions = ec.doublings = 0
        _mult_endomorphism_secp256k1(m, secp256k1.GJ, ec, 4)
        counts.add((ec.additions, ec.doublings))
    assert len(signs) == 4, signs
    assert len(counts) == 1, counts


def test_mult_endomorphism_refuses_a_non_positive_w() -> None:
    """Both endomorphism multiplications refuse a non-positive w."""
    for w in (0, -1):
        with pytest.raises(EccValueError, match="non positive w: "):
            _mult_endomorphism_secp256k1(1, secp256k1.GJ, secp256k1, w)
        with pytest.raises(EccValueError, match="non positive w: "):
            _mult_endomorphism_secp256k1_var(Public(1), secp256k1.GJ, secp256k1, w)


def test_lambda_image_keeps_infinity() -> None:
    """An entry at infinity keeps the y of 0 that affine infinity is."""
    ec = secp256k1
    image = _lambda_image([INF, ec.G], ec)
    assert image[0][1] == 0
    assert image[1] == (ec.G[0] * _BETA % ec.p, ec.G[1])
