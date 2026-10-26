# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.curves.sec_point` module."""

from collections.abc import Callable
from typing import Any

import pytest

from ecc._libsecp256k1 import keys as libsecp256k1_keys
from ecc.alias import INF, Point
from ecc.curves import (
    Curve,
    PreparedPoint,
    bytes_from_point,
    bytes_from_prv_key_int,
    # the module, not only the names in it: `_libsecp256k1_available` is
    # an attribute of it, and switching it off is how the tests below
    # reach the Python arithmetic underneath
    curve,
    mult,
    point_from_octets_var,
    point_from_pub_key,
    prv_key_tweak_add,
    scalar_from_prv_key,
    secp256k1,
    tweak_add_var,
)
from ecc.curves.curve import CURVES
from ecc.curves.sec_point import _mult_sec, mult_pub_key
from ecc.exceptions import (
    EccException,
    EccTypeError,
    EccValueError,
)
from tests import REFUSED_SCALARS, b58encode, both_arms, needs_bindings, refused_secret
from tests.curves.curve_test import secp112r2_order_4_point, secp128r2_order_4_point
from tests.secret_free import assert_secret_free

# test curves: very low cardinality
# 13 % 4 = 1; 13 % 8 = 5
low_card_curves = {"ec13_11": Curve(13, 7, 6, (1, 1), 11, 1, False)}
low_card_curves["ec13_19"] = Curve(13, 0, 2, (1, 9), 19, 1, False)
# 17 % 4 = 1; 17 % 8 = 1
#
# cofactor 1, not 2: tests/curves/curve_test.py's own copy of this dict
# has the reason (issue btclib-org/ecc#32)
low_card_curves["ec17_13"] = Curve(17, 6, 8, (0, 12), 13, 1, False)
low_card_curves["ec17_23"] = Curve(17, 3, 5, (1, 14), 23, 1, False)
# 19 % 4 = 3; 19 % 8 = 3
low_card_curves["ec19_13"] = Curve(19, 0, 2, (4, 16), 13, 1, False)
low_card_curves["ec19_23"] = Curve(19, 2, 9, (0, 16), 23, 1, False)
# 23 % 4 = 3; 23 % 8 = 7
low_card_curves["ec23_19"] = Curve(23, 9, 7, (5, 4), 19, 1, False)
low_card_curves["ec23_31"] = Curve(23, 5, 1, (0, 1), 31, 1, False)

# the union operator, as in curves.curve and tests/curves/curve_test.py
all_curves = low_card_curves | CURVES


def test_octets2point() -> None:
    """Round-trip SEC encodings on every curve, and check the refusals."""
    for ec in all_curves.values():
        G_bytes = bytes_from_point(ec.G, ec)
        G_point = point_from_octets_var(G_bytes, ec)
        assert G_point == ec.G

        G_bytes = bytes_from_point(ec.G, ec, False)
        G_point = point_from_octets_var(G_bytes, ec)
        assert G_point == ec.G

        # just a point, not INF
        Q = ec.G

        Q_bytes = b"\x03" if Q[1] & 1 else b"\x02"
        Q_bytes += Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
        Q_point = point_from_octets_var(Q_bytes, ec)
        assert Q_point[0] == Q[0]
        assert Q_point[1] == Q[1]
        assert bytes_from_point(Q_point, ec) == Q_bytes

        Q_hex_str = Q_bytes.hex()
        Q_point = point_from_octets_var(Q_hex_str, ec)
        assert Q_point == Q

        Q_bytes = b"\x04" + Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
        Q_bytes += Q[1].to_bytes(ec.p_size, byteorder="big", signed=False)
        Q_point = point_from_octets_var(Q_bytes, ec)
        assert Q_point == Q
        assert bytes_from_point(Q_point, ec, False) == Q_bytes

        Q_hex_str = Q_bytes.hex()
        Q_point = point_from_octets_var(Q_hex_str, ec)
        assert Q_point == Q

        Q_bytes = b"\x01" + b"\x01" * ec.p_size
        with pytest.raises(EccValueError, match="not a point: "):
            point_from_octets_var(Q_bytes, ec)

        Q_bytes = b"\x01" + b"\x01" * 2 * ec.p_size
        with pytest.raises(EccValueError, match="not a point: "):
            point_from_octets_var(Q_bytes, ec)

        Q_bytes = b"\x04" + b"\x01" * ec.p_size
        with pytest.raises(
            EccValueError, match="invalid size for uncompressed point: "
        ):
            point_from_octets_var(Q_bytes, ec)

        Q_bytes = b"\x02" + b"\x01" * 2 * ec.p_size
        with pytest.raises(EccValueError, match="invalid size for compressed point: "):
            point_from_octets_var(Q_bytes, ec)

        Q_bytes = b"\x03" + b"\x01" * 2 * ec.p_size
        with pytest.raises(EccValueError, match="invalid size for compressed point: "):
            point_from_octets_var(Q_bytes, ec)

    # invalid x_Q coordinate
    ec = CURVES["secp256k1"]
    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    xstr = format(x_Q, "32X")
    with pytest.raises(EccValueError, match="invalid x-coordinate$"):
        point_from_octets_var(f"03{xstr}", ec)
    with pytest.raises(EccValueError, match="point not on curve$"):
        point_from_octets_var("04" + 2 * xstr, ec)
    with pytest.raises(EccValueError, match="point not on curve"):
        bytes_from_point((x_Q, x_Q), ec)
    with pytest.raises(EccValueError, match="point not on curve"):
        bytes_from_point((x_Q, x_Q), ec, False)


def test_hybrid_prefixes_are_admitted_only_when_asked() -> None:
    """0x06 and 0x07 are SEC 1 too, and consensus takes them.

    The bindings' ec_pubkey_parse takes all three 65-byte prefixes
    (eckey_impl.h), and Core refuses the hybrid pair only under STRICTENC, so a
    script spending to one must verify -- the script_tests.json vector "P2PK NOT
    with hybrid pubkey but no STRICTENC" is the generator with a 0x06 in front,
    and the Python path could not parse it at all (issue btclib-org/btclib#129).
    Off by default because an address, a WIF and a descriptor have no hybrid
    form to render.
    """
    ec = CURVES["secp256k1"]
    Q = ec.G
    body = Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
    body += Q[1].to_bytes(ec.p_size, byteorder="big", signed=False)
    prefix = b"\x07" if Q[1] & 1 else b"\x06"
    mismatched = b"\x06" if Q[1] & 1 else b"\x07"

    assert point_from_octets_var(prefix + body, ec, hybrid=True) == Q
    assert point_from_octets_var((prefix + body).hex(), ec, hybrid=True) == Q

    with pytest.raises(EccValueError, match="not a point: prefix "):
        point_from_octets_var(prefix + body, ec)

    # the prefix repeats the parity of the y that follows it, so the two
    # can contradict each other, and then it is not a point
    with pytest.raises(EccValueError, match="against the hybrid prefix "):
        point_from_octets_var(mismatched + body, ec, hybrid=True)

    # and 0x04 does not acquire a parity rule it never had
    assert point_from_octets_var(b"\x04" + body, ec, hybrid=True) == Q
    assert point_from_octets_var(b"\x04" + body, ec) == Q


# secp256k1 encodings with x or y at the edges of the field (issue
# btclib-org/ecc#360). Neither 0 nor p - 1 is an x-coordinate of the curve.
# p + 1 is congruent to the x-coordinate 1, and _X_Y1 is an x-coordinate
# whose point has y = 1, so p + 1 is also congruent to a y-coordinate.
_P = secp256k1.p
_TOP = 2**256 - 1
_X_Y1 = 0x146D3B65ADD9F54CCCA28533C88E2CBC63F7443E1658783AB41F8EF97C2A10B5
_Y_X1 = secp256k1.y_even_var(1)

_INVALID_X = "invalid x-coordinate$"
_X_RANGE = "x-coordinate not in 0..p-1$"
_Y_RANGE = "y-coordinate not in 1..p-1$"
_OFF_CURVE = "point not on curve$"
_INFINITY = "no bytes representation for infinity point$"
_ODD = "y is odd, against the hybrid prefix"
_EVEN = "y is even, against the hybrid prefix"

# (id, prefix, x, y, the answer with hybrid=True): a point, or the message
# of the EccValueError. A 33-byte encoding has no y.
_FIELD_EDGES: list[tuple[str, int, int, int | None, Point | str]] = [
    ("02-x0", 0x02, 0, None, _INVALID_X),
    ("03-x0", 0x03, 0, None, _INVALID_X),
    ("02-xp-1", 0x02, _P - 1, None, _INVALID_X),
    ("03-xp-1", 0x03, _P - 1, None, _INVALID_X),
    ("02-xp", 0x02, _P, None, _X_RANGE),
    ("03-xp", 0x03, _P, None, _X_RANGE),
    ("02-xp+1", 0x02, _P + 1, None, _X_RANGE),
    ("03-xp+1", 0x03, _P + 1, None, _X_RANGE),
    ("02-xtop", 0x02, _TOP, None, _X_RANGE),
    ("03-xtop", 0x03, _TOP, None, _X_RANGE),
    ("04-x0-y1", 0x04, 0, 1, _OFF_CURVE),
    ("06-x0-y1", 0x06, 0, 1, _ODD),
    ("07-x0-y1", 0x07, 0, 1, _OFF_CURVE),
    ("04-x0-y2", 0x04, 0, 2, _OFF_CURVE),
    ("06-x0-y2", 0x06, 0, 2, _OFF_CURVE),
    ("07-x0-y2", 0x07, 0, 2, _EVEN),
    ("04-xp-1-y1", 0x04, _P - 1, 1, _OFF_CURVE),
    ("06-xp-1-y1", 0x06, _P - 1, 1, _ODD),
    ("07-xp-1-y1", 0x07, _P - 1, 1, _OFF_CURVE),
    ("04-xp-1-y2", 0x04, _P - 1, 2, _OFF_CURVE),
    ("06-xp-1-y2", 0x06, _P - 1, 2, _OFF_CURVE),
    ("07-xp-1-y2", 0x07, _P - 1, 2, _EVEN),
    ("04-xp-y1", 0x04, _P, 1, _X_RANGE),
    ("06-xp-y1", 0x06, _P, 1, _ODD),
    ("07-xp-y1", 0x07, _P, 1, _X_RANGE),
    ("04-xp-y2", 0x04, _P, 2, _X_RANGE),
    ("06-xp-y2", 0x06, _P, 2, _X_RANGE),
    ("07-xp-y2", 0x07, _P, 2, _EVEN),
    ("04-xtop-y1", 0x04, _TOP, 1, _X_RANGE),
    ("06-xtop-y1", 0x06, _TOP, 1, _ODD),
    ("07-xtop-y1", 0x07, _TOP, 1, _X_RANGE),
    ("04-xtop-y2", 0x04, _TOP, 2, _X_RANGE),
    ("06-xtop-y2", 0x06, _TOP, 2, _X_RANGE),
    ("07-xtop-y2", 0x07, _TOP, 2, _EVEN),
    # x + p for a point's x, with that point's even y, then its odd y
    ("04-xp+1-yeven", 0x04, _P + 1, _Y_X1, _X_RANGE),
    ("06-xp+1-yeven", 0x06, _P + 1, _Y_X1, _X_RANGE),
    ("07-xp+1-yeven", 0x07, _P + 1, _Y_X1, _EVEN),
    ("04-xp+1-yodd", 0x04, _P + 1, _P - _Y_X1, _X_RANGE),
    ("06-xp+1-yodd", 0x06, _P + 1, _P - _Y_X1, _ODD),
    ("07-xp+1-yodd", 0x07, _P + 1, _P - _Y_X1, _X_RANGE),
    # y = 0 is refused before the hybrid prefix's parity is read
    ("04-y0", 0x04, _X_Y1, 0, _INFINITY),
    ("06-y0", 0x06, _X_Y1, 0, _INFINITY),
    ("07-y0", 0x07, _X_Y1, 0, _INFINITY),
    # 1 and p - 1 are the two y of one x: both are points
    ("04-y1", 0x04, _X_Y1, 1, (_X_Y1, 1)),
    ("06-y1", 0x06, _X_Y1, 1, _ODD),
    ("07-y1", 0x07, _X_Y1, 1, (_X_Y1, 1)),
    ("04-yp-1", 0x04, _X_Y1, _P - 1, (_X_Y1, _P - 1)),
    ("06-yp-1", 0x06, _X_Y1, _P - 1, (_X_Y1, _P - 1)),
    ("07-yp-1", 0x07, _X_Y1, _P - 1, _EVEN),
    ("04-yp", 0x04, _X_Y1, _P, _Y_RANGE),
    ("06-yp", 0x06, _X_Y1, _P, _ODD),
    ("07-yp", 0x07, _X_Y1, _P, _Y_RANGE),
    # y + p for the y = 1 point: even, where 1 is odd
    ("04-yp+1", 0x04, _X_Y1, _P + 1, _Y_RANGE),
    ("06-yp+1", 0x06, _X_Y1, _P + 1, _Y_RANGE),
    ("07-yp+1", 0x07, _X_Y1, _P + 1, _EVEN),
    ("04-ytop", 0x04, _X_Y1, _TOP, _Y_RANGE),
    ("06-ytop", 0x06, _X_Y1, _TOP, _ODD),
    ("07-ytop", 0x07, _X_Y1, _TOP, _Y_RANGE),
]


def _field_edge_octets(prefix: int, x: int, y: int | None) -> bytes:
    octets = bytes([prefix]) + x.to_bytes(32, "big")
    return octets if y is None else octets + y.to_bytes(32, "big")


def _parses(octets: bytes, *, hybrid: bool) -> bool:
    try:
        point_from_octets_var(octets, secp256k1, hybrid=hybrid)
    except EccValueError:
        return False
    return True


def test_the_field_edge_table_is_what_it_says() -> None:
    """The points the table builds its edges from are what it names."""
    assert secp256k1.is_on_curve((_X_Y1, 1))
    assert secp256k1.is_on_curve((1, _Y_X1))
    assert _Y_X1 % 2 == 0
    for x in (0, _P - 1):
        with pytest.raises(EccValueError, match=_INVALID_X):
            secp256k1.y_var(x)


@pytest.mark.parametrize(
    "prefix, x, y, expected",
    [pytest.param(*row[1:], id=row[0]) for row in _FIELD_EDGES],
)
@both_arms
def test_point_from_octets_var_at_the_field_edges(
    prefix: int, x: int, y: int | None, expected: Point | str
) -> None:
    """Pin each encoding with x or y at the field's edges, through each prefix.

    `hybrid` changes nothing for 0x02, 0x03 and 0x04. Without it, 0x06 and
    0x07 are refused for their prefix alone.
    """
    octets = _field_edge_octets(prefix, x, y)
    for hybrid in (False, True):
        if not hybrid and prefix in {0x06, 0x07}:
            with pytest.raises(EccValueError, match="not a point: prefix "):
                point_from_octets_var(octets, secp256k1, hybrid=hybrid)
        elif isinstance(expected, tuple):
            assert point_from_octets_var(octets, secp256k1, hybrid=hybrid) == expected
        else:
            with pytest.raises(EccValueError, match=expected):
                point_from_octets_var(octets, secp256k1, hybrid=hybrid)


@pytest.mark.parametrize(
    "prefix, x, y",
    [pytest.param(*row[1:4], id=row[0]) for row in _FIELD_EDGES],
)
@pytest.mark.parametrize("serving", [True, False], ids=["bindings", "python"])
@needs_bindings
def test_point_from_octets_var_at_the_field_edges_agrees_with_libsecp256k1(
    prefix: int,
    x: int,
    y: int | None,
    serving: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`keys.pubkey_verify` accepts what `hybrid=True` accepts.

    With `hybrid` off, 0x06 and 0x07 are refused even where libsecp256k1
    accepts them. The Python arm clears the dispatch flag alone, as
    `test_mult_sec` does, and so leaves `pubkey_verify` callable.
    """
    if not serving:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)
    octets = _field_edge_octets(prefix, x, y)
    verdict = libsecp256k1_keys.pubkey_verify(octets)
    assert _parses(octets, hybrid=True) is verdict
    is_hybrid = prefix in {0x06, 0x07}
    assert _parses(octets, hybrid=False) is (verdict and not is_hybrid)


def test_bytes_from_prv_key_int() -> None:
    """It composes mult and bytes_from_point, so it must answer as they do.

    For secp256k1 it does not: it calls the bindings' pubkey_from_prvkey
    directly, without ever building a point of this module's own (issue
    btclib-org/btclib#459), which is why the equality is asserted here scalar by
    scalar rather than taken as read.
    """
    ec = CURVES["secp256k1"]
    prefixes = set()
    for q in range(1, 13):
        Q = mult(q, ec.G, ec)
        assert bytes_from_prv_key_int(q) == bytes_from_point(Q, ec)
        assert bytes_from_prv_key_int(q, ec, False) == bytes_from_point(Q, ec, False)
        prefixes.add(bytes_from_prv_key_int(q)[0])
    # 6G is the first odd y of the twelve, so both prefixes are covered,
    # i.e. both answers of the parity rule and not one of them twice
    assert prefixes == {0x02, 0x03}

    # the edges of the scalar range, and the reduction mod n that mult
    # applies and this has to keep applying
    for q in (1, ec.n - 1):
        assert bytes_from_prv_key_int(q) == bytes_from_point(mult(q, ec.G, ec), ec)
        assert bytes_from_prv_key_int(q + ec.n) == bytes_from_prv_key_int(q)

    # an Integer, not an int: the octets of a scalar are that scalar
    q_bytes = (ec.n - 1).to_bytes(32, byteorder="big", signed=False)
    assert bytes_from_prv_key_int(q_bytes) == bytes_from_prv_key_int(ec.n - 1)
    assert bytes_from_prv_key_int(q_bytes.hex()) == bytes_from_prv_key_int(ec.n - 1)

    # every other curve is the Python path, which is the composition
    for ec in (CURVES["secp256r1"], low_card_curves["ec13_11"]):
        for q in range(1, min(ec.n, 13)):
            Q = mult(q, ec.G, ec)
            assert bytes_from_prv_key_int(q, ec) == bytes_from_point(Q, ec)
            assert bytes_from_prv_key_int(q, ec, False) == bytes_from_point(
                Q, ec, False
            )

    # a zero scalar is the infinity point, on either path, and the
    # bindings reject it rather than answering a serialization of it
    for ec in (CURVES["secp256k1"], low_card_curves["ec13_11"]):
        for q in (0, ec.n):
            with pytest.raises(
                EccValueError,
                match="no bytes representation for infinity point",
            ):
                bytes_from_prv_key_int(q, ec)


def test_infinity_point_bytes() -> None:
    """Refuse to serialize the point at infinity."""
    with pytest.raises(
        EccValueError, match="no bytes representation for infinity point"
    ):
        bytes_from_point(INF)


def test_infinity_point_from_octets_var() -> None:
    """Refuse an uncompressed encoding spelling the point at infinity."""
    curve_size = CURVES["secp256k1"].p_size
    inf_bytes = b"\x04"
    inf_bytes += INF[0].to_bytes(curve_size, byteorder="big", signed=False)
    inf_bytes += INF[1].to_bytes(curve_size, byteorder="big", signed=False)
    with pytest.raises(
        EccValueError, match="no bytes representation for infinity point"
    ):
        point_from_octets_var(inf_bytes)


def test_point_from_pub_key_refuses_a_point_outside_the_subgroup() -> None:
    """A point outside ⟨G⟩ is not a public key, on a curve with a cofactor.

    secp112r2 is cofactor 4, and its own order-4 point is on the curve --
    `bytes_from_point` serializes it without complaint -- but not a point
    of ⟨G⟩, `n*T` not being INF: `mult` would answer `dU*T` reduced mod n,
    a wrong point for any dU, which is the whole of issue
    btclib-org/ecc#15. Every spelling that reaches a point --
    the bare tuple, the compressed octets, the uncompressed ones -- is
    refused the same way.
    """
    ec = CURVES["secp112r2"]
    t = secp112r2_order_4_point()
    err_msg = "point not in the subgroup generated by G"

    with pytest.raises(EccValueError, match=err_msg):
        point_from_pub_key(t, ec)
    with pytest.raises(EccValueError, match=err_msg):
        point_from_octets_var(bytes_from_point(t, ec, compressed=False), ec)
    with pytest.raises(EccValueError, match=err_msg):
        point_from_octets_var(bytes_from_point(t, ec, compressed=True), ec)

    # a point of ⟨G⟩ itself is unaffected, on the very same curve
    assert point_from_pub_key(ec.G, ec) == ec.G


@pytest.mark.parametrize(
    "curve_name, order_4_point",
    [
        ("secp112r2", secp112r2_order_4_point),
        ("secp128r2", secp128r2_order_4_point),
    ],
)
def test_point_from_octets_var_refuses_the_real_two_torsion_point(
    curve_name: str, order_4_point: Callable[[], Point]
) -> None:
    """The compressed encoding of a real two-torsion x is refused too.

    `_y_even_var` lifts that x to y == 0 without complaint -- it is a
    genuine square root of `_y2(x)`, 0 included -- building exactly the
    tuple `Curve.is_on_curve` refuses as ambiguous with INF for the 0x02
    prefix, and an out-of-range `ec.p - 0 == ec.p` for 0x03's negated
    one. The compressed branch of `point_from_octets_var` used to go straight
    to `_assert_in_subgroup` without asking `is_on_curve` first, where
    the uncompressed branch a few lines below already did:
    `_assert_in_subgroup` itself does not catch either shape --
    `_jac_from_aff` reads affine y == 0 as Jacobian Z == 0 exactly as the
    convention this refuses does, and it never reduces y at all -- so
    both compressed keys passed silently (issue
    btclib-org/ecc#16). Both prefixes, and both entry points,
    are checked; the hybrid and plain uncompressed forms are refused
    already -- no bytes representation exists for a y == 0 uncompressed
    point at all, ambiguous or not -- and are checked here too so a
    regression there is caught the same way.
    """
    ec = CURVES[curve_name]
    t = order_4_point()
    t2 = ec.add_var(t, t)
    assert t2[1] == 0
    x_bytes = t2[0].to_bytes(ec.p_size, byteorder="big")

    def refused(octets: bytes, err_msg: str) -> None:
        with pytest.raises(EccValueError, match=err_msg):
            point_from_octets_var(octets, ec)
        # point_from_pub_key's octets branch translates whatever
        # point_from_octets_var raises into its own "not a public key", with no
        # cause and no context: the octets may be private material passed by
        # mistake, and what point_from_octets_var said of them is no safer
        with pytest.raises(EccValueError, match="not a public key") as exc:
            point_from_pub_key(octets, ec)
        assert exc.value.__cause__ is None
        assert exc.value.__context__ is None

    # 0x02 lifts the two-torsion x to y == 0 itself, the tuple
    # Curve.is_on_curve refuses as ambiguous with INF
    refused(b"\x02" + x_bytes, "ambiguous point")
    # 0x03 negates that same y to ec.p - 0 == ec.p, out of range rather
    # than ambiguous -- a different refusal, equally not a silent accept
    refused(b"\x03" + x_bytes, "y-coordinate not in 1..p-1")

    y_bytes = (0).to_bytes(ec.p_size, byteorder="big")
    inf_msg = "no bytes representation for infinity point"
    with pytest.raises(EccValueError, match=inf_msg):
        point_from_octets_var(b"\x04" + x_bytes + y_bytes, ec)
    with pytest.raises(EccValueError, match="not a public key") as exc:
        point_from_pub_key(b"\x04" + x_bytes + y_bytes, ec)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    # hybrid has no point_from_pub_key spelling: that function takes no
    # hybrid flag, so 0x06 there is "not a point" rather than this refusal
    with pytest.raises(EccValueError, match=inf_msg):
        point_from_octets_var(b"\x06" + x_bytes + y_bytes, ec, hybrid=True)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_mult_sec(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """m*P from the octets is m*P from the point, on every curve.

    `_mult_sec` skips the round trip `mult(m, point_from_octets_var(sec))`
    makes -- the lift on the way in and the serialization back out, of a
    point neither side reads a coordinate of -- so what has to be asserted
    is that identity, for both forms of the octets and for the scalars the
    bindings decline: zero, which is infinity and no libsecp256k1 answer,
    and the ones landing on the point itself.

    The low-cardinality curves reach the same lines with no bindings under
    them at all, which is what the `python` case then repeats for
    secp256k1.
    """
    if not bindings:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    for ec in all_curves.values():
        for Q in (ec.G, mult(2, ec.G, ec), mult(3, ec.G, ec)):
            for compressed in (True, False):
                sec = bytes_from_point(Q, ec, compressed)
                for m in (0, 1, 2, ec.n - 1):
                    assert _mult_sec(sec, m, ec) == mult(m, Q, ec)

    # every width of a secp256k1 scalar, where the bindings arm is
    # `secp256k1_ecdh`; and a scalar at or above n, which it refuses and
    # the fallthrough reduces
    ec = CURVES["secp256k1"]
    Q = mult(7, ec.G, ec)
    sec = bytes_from_point(Q, ec)
    for w in (256, 128, 64, 32, 1):
        m = (1 << (w - 1)) | (0x5A5A5A5A5A5A5A5A % (1 << (w - 1)))
        assert _mult_sec(sec, m % ec.n, ec) == mult(m, Q, ec)
    assert _mult_sec(sec, ec.n + 2, ec) == mult(2, Q, ec)

    # and octets that are no point at all are the lift's refusal, which is
    # what the fallthrough exists to keep saying
    ec = CURVES["secp256k1"]
    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    with pytest.raises(EccValueError, match="invalid x-coordinate$"):
        _mult_sec(b"\x02" + x_Q.to_bytes(ec.p_size, "big"), 2, ec)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_mult_pub_key(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """m*P for a public key of any spelling, the scalar checked and reduced.

    The two twins it composes are asserted above; what is left is the
    public spelling's own part: every form of `PubKey`, a scalar as any
    `Integer` and reduced mod n, and a key that is no point refused as an
    `EccValueError` whichever form it arrived in.
    """
    if not bindings:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    ec = CURVES["secp256k1"]
    Q = mult(3)
    for pub_key in (
        Q,
        PreparedPoint(Q),
        bytes_from_point(Q),
        bytes_from_point(Q, compressed=False),
        bytes_from_point(Q).hex(),
    ):
        assert mult_pub_key(5, pub_key) == mult(5, Q)
        assert mult_pub_key(ec.n + 5, pub_key, ec) == mult(5, Q)
        assert mult_pub_key("05", pub_key) == mult(5, Q)
        assert mult_pub_key(0, pub_key) == INF

    x_Q = 0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    for not_a_point in (
        b"\x02" + x_Q.to_bytes(ec.p_size, "big"),
        (ec.G[0], ec.G[1] + 1),
        INF,
    ):
        with pytest.raises(EccValueError):
            mult_pub_key(5, not_a_point)

    with pytest.raises(EccTypeError):
        mult_pub_key(1.5, Q)  # type: ignore[arg-type]
    with pytest.raises(EccTypeError):
        mult_pub_key(5, 7)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_a_hybrid_key_is_refused_on_both_arms(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bindings parse 0x06 and 0x07 and `point_from_octets_var` does not.

    A multiplication has to refuse a hybrid key on either arm, as
    `point_from_octets_var` does without `hybrid=True`: a key valid on one
    install and invalid on another is the defect (issue
    btclib-org/ecc#75).
    """
    if not bindings:
        monkeypatch.setattr(curve, "_libsecp256k1_available", False)

    ec = CURVES["secp256k1"]
    Q = mult(3)
    body = Q[0].to_bytes(ec.p_size, "big") + Q[1].to_bytes(ec.p_size, "big")
    hybrid = (b"\x07" if Q[1] & 1 else b"\x06") + body
    assert point_from_octets_var(hybrid, ec, hybrid=True) == Q

    for pub_key in (hybrid, hybrid.hex()):
        with pytest.raises(EccValueError, match="not a public key"):
            mult_pub_key(5, pub_key)
    for m in (0, 5):
        with pytest.raises(EccValueError, match="not a point: prefix "):
            _mult_sec(hybrid, m, ec)


def test_a_scalar_is_an_int_or_its_octets_and_nothing_else() -> None:
    """What a private key may be spelled as here (btclib-org/btclib#1188).

    The integer, its `n_size` octets, their hex, and the buffers
    `bytes_from_octets` takes beside them. A WIF and an extended key are
    not among them: each carries a network, and this file knows about a
    curve and not about bitcoin, so it could not decode one without
    importing a layer above itself.

    On secp256k1 the size alone separates a scalar from a point --
    `n_size` is 32 where a point is 33 or 65. That is a coincidence and
    not a rule: `sec_point` names the catalogued curves whose `n_size`
    is their compressed size, and there a point is refused by the range
    check instead.
    """
    q = 0xC0FFEE
    octets = q.to_bytes(32, "big")
    for spelling in (q, octets, octets.hex(), bytearray(octets), memoryview(octets)):
        assert scalar_from_prv_key(spelling) == q

    # a WIF and an xprv reach here as text, and text is hex or nothing;
    # the xprv is BIP32's root key of the seed `"5e" * 32`
    xprv = (
        "xprv9s21ZrQH143K3jDQ9kSBrkWCHhPnhmGaTk3LkDNedVbXcXMERAJzNVtb8oi8f3k"
        "mzhNe8gj7WMbGNpsRRbE59dWU27jWqmKvFsg7A4vgdAD"
    )
    for text in (b58encode(b"\x80" + q.to_bytes(32, "big") + b"\x01").decode(), xprv):
        with pytest.raises(EccValueError, match="invalid hex string"):
            scalar_from_prv_key(text)

    for out_of_range in (0, secp256k1.n):
        with pytest.raises(EccValueError, match="private key not in 1..n-1"):
            scalar_from_prv_key(out_of_range)


def test_a_public_key_is_a_point_or_its_octets_and_nothing_else() -> None:
    """What a public key may be spelled as here (btclib-org/btclib#1188).

    `scalar_from_prv_key`'s twin above, asked of the other half: the
    point as a tuple, as a `PreparedPoint`, or as the SEC octets
    `point_from_octets_var` parses. A WIF and an extended key are not among
    them for that test's reason, and neither is a scalar -- in this
    library an int is a private key and never a public one, so it is
    refused as a type rather than reported as a key that does not verify.

    What a caller does with the point afterwards -- an address, a
    verification -- is its own module's test; what is here is the parse
    itself.
    """
    q = 0xC0FFEE
    point = mult(q)
    for spelling in (
        point,
        PreparedPoint(point),
        bytes_from_point(point),
        bytes_from_point(point, compressed=False),
        bytes_from_point(point).hex(),
        bytearray(bytes_from_point(point)),
    ):
        assert point_from_pub_key(spelling) == point

    # a type no spelling has, the scalar among them: refused as a type, and
    # never echoed -- it may be the private material issue btclib-org/btclib#143
    # is about
    for wrong_type in (q, 1.5, None):
        with pytest.raises(EccTypeError, match="not a public key"):
            point_from_pub_key(wrong_type)  # type: ignore[arg-type]

    # a tuple of the right shape that is no point of the curve, and the
    # infinity point, which has no public key
    for not_a_point in ((1, 2), INF):
        with pytest.raises(EccValueError, match="not a valid public key"):
            point_from_pub_key(not_a_point)

    # octets of a declared type whose content is no point: a value error,
    # and the parse's own reason is chained under it
    with pytest.raises(EccValueError, match="not a public key"):
        point_from_pub_key(
            b58encode(b"\x80" + q.to_bytes(32, "big") + b"\x01").decode()
        )


@pytest.mark.parametrize("ec_name", ["secp256k1", "secp256r1"])
@both_arms
def test_prv_key_tweak_add(ec_name: str) -> None:
    """The sum modulo n, whose public key is the public key tweaked.

    secp256r1 is the Python arm on both runs, the bindings serving
    secp256k1 alone.
    """
    ec = CURVES[ec_name]
    for q, t in ((1, 0), (5, 7), (ec.n - 1, 2), (0xC0FFEE, ec.n - 1)):
        tweaked = prv_key_tweak_add(q, t, ec)
        assert tweaked == (q + t) % ec.n
        assert mult(tweaked, ec=ec) == tweak_add_var(mult(q, ec=ec), t, ec)
    # the tweak in its octets, as BIP32 hands it over
    assert prv_key_tweak_add(5, (7).to_bytes(32, "big"), ec) == 12


@both_arms
def test_prv_key_tweak_add_refusals() -> None:
    """A tweak out of 0..n-1, and a sum of zero, are refused on both arms."""
    for t in (-1, secp256k1.n):
        with pytest.raises(EccValueError, match="tweak not in 0..n-1"):
            prv_key_tweak_add(1, t)
    q = 0xC0FFEE
    with pytest.raises(EccValueError, match="tweaked private key is zero") as e:
        prv_key_tweak_add(q, secp256k1.n - q)
    assert_secret_free(e.value, [f"{q:x}", q.to_bytes(32, "big")])
    with pytest.raises(EccTypeError):
        prv_key_tweak_add(1, 1.0)  # type: ignore[arg-type]


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "scalar_from_prv_key": (scalar_from_prv_key, REFUSED_SCALARS),
    "prv_key_tweak_add": (lambda q: prv_key_tweak_add(q, 1), REFUSED_SCALARS),
}


_SECRET_CASES = [
    (name, kind) for name, (_, kinds) in _SECRET_CALLS.items() for kind in kinds
]


@pytest.mark.parametrize("name, kind", _SECRET_CASES)
@both_arms
def test_a_refusal_carries_no_secret(name: str, kind: str) -> None:
    """No piece of the secret is in the exception or in anything it chains."""
    call, _ = _SECRET_CALLS[name]
    secret, spellings = refused_secret(kind)
    with pytest.raises(EccException) as refused:
        call(secret)
    assert_secret_free(refused.value, spellings)
