# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.ecc.ellswift` module.

Two BIP324 vector files pin the map itself, which is deterministic, and
the key agreement columns of a third pin `xdh`. `create` and `encode` are
not -- one of up to eight preimages is picked
at random -- so what holds them is a round trip, and the bindings are the
other implementation it is held against: `decode` of libsecp256k1 accepts
what this package's Python encoded, and this package's Python decodes what
libsecp256k1 created.
"""

import random
import secrets
import sys
from collections.abc import Callable
from typing import Any

import pytest

from ecc._libsecp256k1 import ellswift as libsecp256k1_ellswift
from ecc.curves import mult, secp256k1
from ecc.curves.curve import CURVES, Curve
from ecc.curves.sec_point import bytes_from_point
from ecc.ecc import ellswift
from ecc.ecc.ellswift import _xswiftec_inv_var, _xswiftec_var
from ecc.exceptions import EccException, EccValueError
from ecc.number_theory import mod_sqrt_var
from tests import (
    REFUSED_SCALARS,
    both_arms,
    load_csv,
    needs_bindings,
    refused_secret,
    vector_id,
)
from tests.secret_free import assert_secret_free

# the other Koblitz curves of the catalogue: a == 0 and a square
# -3, which is all the map wants, so the Python path serves them and this
# is what says so. secp224k1 is the one with p % 4 == 1, i.e. the one
# whose square roots go through Tonelli-Shanks rather than a single pow
OTHER_CURVES = ("secp160k1", "secp192k1", "secp224k1")


def decode_vectors() -> list[Any]:
    """Load BIP324's ellswift_decode_test_vectors.csv as pytest params."""
    return [
        pytest.param(row, id=vector_id(index, row[2]))
        for index, row in enumerate(
            load_csv("schemes", "_data", "ellswift_decode_test_vectors.csv")
        )
    ]


def xswiftec_inv_vectors() -> list[Any]:
    """Load BIP324's xswiftec_inv_test_vectors.csv as pytest params."""
    return [
        pytest.param(row, id=vector_id(index, row[10]))
        for index, row in enumerate(
            load_csv("schemes", "_data", "xswiftec_inv_test_vectors.csv")
        )
    ]


@pytest.mark.parametrize("row", decode_vectors())
def test_ellswift_decode_vectors(row: list[str], arm: str) -> None:
    """BIP324's decode vectors, against the map, and the bindings on their arm.

    - https://github.com/bitcoin/bips/blob/master/bip-0324/ellswift_decode_test_vectors.csv

    The comment column names the branch each row exercises, and is the
    test id: `u%p=0`, `t>=p`, which of the three candidate x-coordinates
    is the valid one, and the `u^3+t^2+7=0` substitution.
    """
    ellswift_hex, x_hex, _comment = row
    ell = bytes.fromhex(ellswift_hex)
    x = int(x_hex, 16)

    u = int.from_bytes(ell[:32], byteorder="big", signed=False)
    t = int.from_bytes(ell[32:], byteorder="big", signed=False)
    assert _xswiftec_var(u, t, secp256k1) == x

    # the whole of decode: the vector pins the x-coordinate, and the parity
    # of t mod p the y. BIP324's reference.py decodes to an x and stops;
    # the y rule is libsecp256k1's, secp256k1_ellswift_swiftec_var, which
    # reads secp256k1_fe_is_odd on t after secp256k1_fe_set_b32_mod
    Q = ellswift.decode_var(ell)
    assert Q[0] == x
    assert Q[1] % 2 == t % secp256k1.p % 2
    if arm == "bindings":
        assert bytes_from_point(Q) == libsecp256k1_ellswift.decode(ell)


@pytest.mark.parametrize("row", xswiftec_inv_vectors())
@both_arms
def test_xswiftec_inv_vectors(row: list[str]) -> None:
    """BIP324's inverse vectors: eight cases per row, failures included.

    - https://github.com/bitcoin/bips/blob/master/bip-0324/xswiftec_inv_test_vectors.csv

    An empty cell is a case with no preimage, and asserting that it has
    none is the half that matters: an inverse too permissive would
    return something for it and still pass every non-empty cell.
    """
    u = int(row[0], 16)
    x = int(row[1], 16)

    for case in range(8):
        cell = row[2 + case]
        t = _xswiftec_inv_var(x, u, case, secp256k1)
        if not cell:
            assert t is None, f"case {case} should have no preimage"
        else:
            assert t == int(cell, 16), f"case {case}"
            # every preimage the inverse returns maps back to the x it
            # was asked about, which no cell of the file states
            assert _xswiftec_var(u, t, secp256k1) == x


def xdh_vectors() -> list[Any]:
    """Load BIP324's packet_encoding_test_vectors.csv as pytest params."""
    return [
        pytest.param(row, id=vector_id(index))
        for index, row in enumerate(
            load_csv("schemes", "_data", "packet_encoding_test_vectors.csv")
        )
    ]


@pytest.mark.parametrize("row", xdh_vectors())
@both_arms
def test_xdh_vectors(row: list[str]) -> None:
    """BIP324's shared secrets, from the key agreement columns of its vectors.

    - https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv

    Each row is one party: its private key and encoding, the other
    party's encoding, and whether it initiates. The rest of the row is
    the v2 transport's.
    """
    prv_key = int(row[1], 16)
    ours, theirs = bytes.fromhex(row[2]), bytes.fromhex(row[3])
    initiating = row[4] == "1"
    shared_secret = bytes.fromhex(row[12])

    ell_a, ell_b = (ours, theirs) if initiating else (theirs, ours)
    assert ellswift.xdh(ell_a, ell_b, prv_key, initiating) == shared_secret


class _LibReads:
    """Stand in for the bindings' cffi `lib`, recording each name read."""

    def __init__(self, lib: object, names: list[str]) -> None:
        self._lib = lib
        self._names = names

    def __getattr__(self, name: str) -> object:
        self._names.append(name)
        return getattr(self._lib, name)


@needs_bindings
def test_xdh_on_the_bindings_is_one_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Where the bindings serve, `xdh` makes one libsecp256k1 call.

    Every module global bound to the bindings' cffi `lib` is replaced by
    a recorder of the names read from it, and the record has to be
    `secp256k1_ellswift_xdh` and the BIP324 hash function the bindings
    pass to it. The names read are recorded, not the calls made. PyPy's
    profile hook sees no call to a cffi function. A Python wrapper cannot
    stand in for the hash function, which the bindings pass to C, and on
    PyPy it cannot be told by its type from the function they call: both
    are cdata of function type. The Python decoding and `mult` are
    replaced by a recorder that computes nothing, so a point computed in
    Python fails the test too.
    """
    q_a, _ = _key_pair()
    q_b, _ = _key_pair()
    ell_a, ell_b = ellswift.create(q_a), ellswift.create(q_b)

    lib = pytest.importorskip("btclib_secp256k1").lib
    reads: list[str] = []
    points: list[object] = []

    with monkeypatch.context() as spied:
        spied.setattr(ellswift, "mult", lambda *args: points.append(args))
        spied.setattr(
            ellswift, "_point_from_ell_var", lambda *args: points.append(args)
        )
        for module in list(sys.modules.values()):
            for name, value in list(getattr(module, "__dict__", {}).items()):
                if value is lib:
                    spied.setattr(module, name, _LibReads(lib, reads))
        secret = ellswift.xdh(ell_a, ell_b, q_b, False)

    assert reads == [
        "secp256k1_ellswift_xdh",
        "secp256k1_ellswift_xdh_hash_function_bip324",
    ]
    assert not points
    assert len(secret) == 32


@pytest.mark.parametrize("curve_name", ["secp256k1", *OTHER_CURVES])
@both_arms
def test_both_parties_derive_one_secret(curve_name: str) -> None:
    """The initiator and the responder compute the same secret.

    `initiating` names which encoding is the caller's, so the wrong value
    hands the caller's key to its own point, and the secret differs.
    """
    ec = CURVES[curve_name]
    q_a = secrets.randbelow(ec.n - 1) + 1
    q_b = secrets.randbelow(ec.n - 1) + 1
    ell_a, ell_b = ellswift.create(q_a, ec), ellswift.create(q_b, ec)

    secret = ellswift.xdh(ell_a, ell_b, q_a, True, ec)
    assert len(secret) == 32
    assert ellswift.xdh(ell_a, ell_b, q_b, False, ec) == secret
    assert ellswift.xdh(ell_a, ell_b, q_a, False, ec) != secret


@needs_bindings
def test_create_and_encode_round_trip() -> None:
    """What create and encode produce, decode takes back to the key.

    Randomized on both sides, so this runs a handful of keys rather than
    one: a case that fails once in eight is what the eight-way choice of
    a preimage could hide.
    """
    for _ in range(8):
        q, Q = _key_pair()

        for ell in (ellswift.create(q), ellswift.encode_var(Q)):
            assert len(ell) == 2 * secp256k1.p_size
            assert ellswift.decode_var(ell) == Q
            # the bindings agree about what this package produced
            assert libsecp256k1_ellswift.decode(ell) == bytes_from_point(Q)


@needs_bindings
def test_the_python_create_and_encode_are_the_bindings_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Python encoding is one libsecp256k1 decodes, and conversely.

    Equality is not the assertion available here: the encoding is a
    random choice among preimages, so the two implementations agree on
    the key rather than on the bytes. That is the whole property -- an
    encoding is not canonical.
    """
    for _ in range(8):
        q, Q = _key_pair()
        sec = bytes_from_point(Q)

        with monkeypatch.context() as no_bindings:
            no_bindings.setattr(ellswift, "_libsecp256k1_serves", lambda *_: False)
            python_create = ellswift.create(q)
            python_encode = ellswift.encode_var(Q)
            # the Python path also decodes what the bindings created
            assert ellswift.decode_var(libsecp256k1_ellswift.create(q)) == Q

        for ell in (python_create, python_encode):
            assert libsecp256k1_ellswift.decode(ell) == sec
            assert ellswift.decode_var(ell) == Q


@pytest.mark.parametrize("curve_name", OTHER_CURVES)
def test_the_other_koblitz_curves(curve_name: str) -> None:
    """The Python path on the curves the bindings do not serve.

    Not a redundant pass over the same arithmetic: these reach it without
    a monkeypatch, which is what keeps the map honest about `ec` being a
    parameter rather than a decoration.
    """
    ec = CURVES[curve_name]

    q = secrets.randbelow(ec.n - 1) + 1
    Q = mult(q, ec.G, ec)

    for ell in (ellswift.create(q, ec), ellswift.encode_var(Q, ec)):
        assert len(ell) == 2 * ec.p_size
        assert ellswift.decode_var(ell, ec) == Q


def test_a_curve_the_map_is_not_defined_on() -> None:
    """Refuse a curve with a != 0 at every entry point of the map."""
    ec = CURVES["secp256r1"]
    q, _Q = _key_pair()
    ell = bytes(2 * ec.p_size)

    err_msg = "the ElligatorSwift map wants a curve with a == 0"
    with pytest.raises(EccValueError, match=err_msg):
        ellswift.create(q, ec)
    with pytest.raises(EccValueError, match=err_msg):
        ellswift.encode_var(mult(q, ec.G, ec), ec)
    with pytest.raises(EccValueError, match=err_msg):
        ellswift.decode_var(ell, ec)
    with pytest.raises(EccValueError, match=err_msg):
        ellswift.xdh(ell, ell, q, True, ec)


def test_xdh_refuses_a_cofactor() -> None:
    """On a curve with cofactor 3, most encodings decode outside <G>.

    The curve is y^2 = x^3 + 3 over 100129, whose order is 3 * 33199.
    """
    ec = Curve(100129, 0, 3, (7, 89817), 33199, 3, weakness_check=False)
    ell = bytes(2 * ec.p_size)
    with pytest.raises(EccValueError, match="xdh wants a curve with cofactor 1"):
        ellswift.xdh(ell, ell, 12345, True, ec)


def test_wrong_size_encoding() -> None:
    """An encoding is two field elements, and nothing else is one."""
    ell = ellswift.create(secrets.randbelow(secp256k1.n - 1) + 1)

    for bad in (ell[:-1], ell + b"\x00", b""):
        with pytest.raises(EccValueError, match="invalid ElligatorSwift size"):
            ellswift.decode_var(bad)
        with pytest.raises(EccValueError, match="invalid ElligatorSwift size"):
            ellswift.xdh(bad, ell, 1, True)
        with pytest.raises(EccValueError, match="invalid ElligatorSwift size"):
            ellswift.xdh(ell, bad, 1, True)


def test_invalid_private_key() -> None:
    """A key outside 1..n-1 is refused, and by `scalar_from_prv_key`."""
    ell = bytes(2 * secp256k1.p_size)
    for prv_key in (0, secp256k1.n):
        with pytest.raises(EccValueError):
            ellswift.create(prv_key)
        with pytest.raises(EccValueError):
            ellswift.xdh(ell, ell, prv_key, True)


def _key_pair() -> tuple[int, tuple[int, int]]:
    """Return a random secp256k1 key pair."""
    q = secrets.randbelow(secp256k1.n - 1) + 1
    return q, mult(q, secp256k1.G, secp256k1)


def _x_exists(x: int, ec: Any) -> bool:
    """Say whether x is an x-coordinate by Euler's criterion, no ellswift."""
    return bool(pow(ec._y2(x), (ec.p - 1) // 2, ec.p) != ec.p - 1)


def _spec_xswiftec(u: int, t: int, ec: Any) -> int:
    """Return the map as BIP324's reference writes it: three inverses."""
    p = ec.p
    c0 = mod_sqrt_var(-3 % p, p)
    u, t = u % p or 1, t % p or 1
    if (pow(u, 3, p) + t * t + ec._b) % p == 0:
        t = 2 * t % p
    X = (pow(u, 3, p) + ec._b - t * t) * pow(2 * t, -1, p) % p
    Y = (X + t) * pow(c0 * u, -1, p) % p
    candidates = (
        (u + 4 * Y * Y) % p,
        (-X * pow(Y, -1, p) - u) * pow(2, -1, p) % p,
        (X * pow(Y, -1, p) - u) * pow(2, -1, p) % p,
    )
    return int(next(x for x in candidates if _x_exists(x, ec)))


@pytest.mark.parametrize("curve_name", ["secp256k1", *OTHER_CURVES])
def test_the_fraction_map_is_the_reference_map(curve_name: str) -> None:
    """The fraction form returns what the three-inverse form returns.

    Random pairs return through whichever candidate they reach; the pairs
    with u^3 + b + t^2 == 0 and the zero ones are built, being out of
    reach of chance.
    """
    ec = CURVES[curve_name]
    p = ec.p
    pairs = [(secrets.randbelow(p), secrets.randbelow(p)) for _ in range(100)]
    pairs += [(0, 0), (0, 5), (5, 0), (p, p + 1)]
    for u in range(1, 100):
        minus_g = -(pow(u, 3, p) + ec._b) % p
        if pow(minus_g, (p - 1) // 2, p) == 1:
            t = mod_sqrt_var(minus_g, p)
            pairs += [(u, t), (u, p - t)]
    assert len(pairs) > 104
    for u, t in pairs:
        assert _xswiftec_var(u, t, ec) == _spec_xswiftec(u, t, ec)


def _spec_xswiftec_inv(x: int, u: int, case: int, ec: Any) -> int | None:
    """Return the inverse as BIP324's reference writes it: roots first."""
    p = ec.p
    c0 = mod_sqrt_var(-3 % p, p)

    def sqrt(a: int) -> int | None:
        try:
            return int(mod_sqrt_var(a, p))
        except EccValueError:
            return None

    if case & 2 == 0:
        if _x_exists((-x - u) % p, ec):
            return None
        v = x
        s = -(pow(u, 3, p) + ec._b) * pow(u * u + u * v + v * v, -1, p) % p
    else:
        s = (x - u) % p
        r = sqrt(-s * (4 * (pow(u, 3, p) + ec._b) + 3 * s * u * u) % p)
        if s == 0 or r is None or (case & 1 and r == 0):
            return None
        v = (-u + r * pow(s, -1, p)) * pow(2, -1, p) % p
    w = sqrt(s)
    if w is None:
        return None
    sign, c = {0: (-1, 1 - c0), 1: (1, 1 + c0), 4: (1, 1 - c0), 5: (-1, 1 + c0)}[
        case & 5
    ]
    return int(sign * w * (u * c * pow(2, -1, p) + v) % p)


@pytest.mark.parametrize("curve_name", ["secp256k1", *OTHER_CURVES])
def test_the_inverse_is_the_reference_inverse(curve_name: str) -> None:
    """Every case answers what the roots-first form answers, None included.

    Each x is tried with a random u and with u = 1, u = 2 and u = -x,
    which a random u does not reach. A t that answers is not zero, and no
    two cases of one (x, u) answer the same t.

    The answers are counted for each kind of u: a test of squareness that
    refused every case would still agree on the cases the reference
    refuses.
    """
    ec = CURVES[curve_name]
    rnd = random.Random(0x324)
    answers = dict.fromkeys(("random", "1", "2", "-x"), 0)
    for _ in range(100):
        x = mult(rnd.randrange(1, ec.n), ec.G, ec)[0]
        us = {"random": rnd.randrange(1, ec.p), "1": 1, "2": 2, "-x": -x % ec.p}
        for kind, u in us.items():
            ts = []
            for case in range(8):
                t = _xswiftec_inv_var(x, u, case, ec)
                assert t == _spec_xswiftec_inv(x, u, case, ec)
                if t is not None:
                    assert t != 0
                    assert _spec_xswiftec(u, t, ec) == x
                    ts.append(t)
            assert len(set(ts)) == len(ts), f"u = {kind}: two cases answer one t"
            answers[kind] += len(ts)
    assert all(answers.values()), answers


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "create": (ellswift.create, REFUSED_SCALARS),
    "xdh": (lambda key: ellswift.xdh(bytes(64), bytes(64), key, True), REFUSED_SCALARS),
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
