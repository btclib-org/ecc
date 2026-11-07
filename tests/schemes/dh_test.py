# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.dh` module."""

from collections.abc import Callable
from hashlib import sha1, sha256
from typing import Any

import pytest

from ecc import dh, dsa
from ecc._libsecp256k1 import shared_point as libsecp256k1_shared_point
from ecc.curves import bytes_from_point, curve, mult
from ecc.curves.curve import CURVES
from ecc.dh import diffie_hellman
from ecc.exceptions import (
    EccException,
    EccRuntimeError,
    EccTypeError,
    EccValueError,
)
from ecc.kdf import ansi_x9_63_kdf
from tests import REFUSED_SCALARS, both_arms, needs_bindings, refused_secret
from tests.curves.curve_test import (
    cofactor_curves,
    secp112r2_order_4_point,
    small_order_points,
)
from tests.secret_free import assert_secret_free


def test_ecdh() -> None:
    """Check both sides derive one shared key, at sizes around the digest."""
    ec = CURVES["secp256k1"]
    hf = sha256

    a, A = dsa.gen_keys()  # Alice
    b, B = dsa.gen_keys()  # Bob

    # Alice computes the shared secret using Bob's public key
    shared_secret_a = mult(a, B)

    # Bob computes the shared secret using Alice's public key
    shared_secret_b = mult(b, A)

    assert shared_secret_a == shared_secret_b
    assert shared_secret_a == mult(a * b, ec.G)

    # hash the shared secret to remove weak bits
    shared_secret_field_element = shared_secret_a[0]
    z = shared_secret_field_element.to_bytes(ec.p_size, byteorder="big", signed=False)

    shared_info = b"deadbeef"

    hf_size = hf().digest_size
    for size in (hf_size - 1, hf_size, hf_size + 1):
        shared_key = ansi_x9_63_kdf(z, size, hf, None)
        assert len(shared_key) == size
        assert shared_key == diffie_hellman(a, B, size, None, ec, hf)
        assert shared_key == diffie_hellman(b, A, size, None, ec, hf)
        shared_key = ansi_x9_63_kdf(z, size, hf, shared_info)
        assert len(shared_key) == size
        assert shared_key == diffie_hellman(a, B, size, shared_info, ec, hf)
        assert shared_key == diffie_hellman(b, A, size, shared_info, ec, hf)

    max_size = hf_size * (2**32 - 1)
    size = max_size + 1
    with pytest.raises(EccValueError, match="cannot derive a key larger than "):
        ansi_x9_63_kdf(z, size, hf, None)


def test_gec_2() -> None:
    """GEC 2: Test Vectors for SEC 1, section 4.1.

    - http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
    """
    # 4.1.1
    ec = CURVES["secp160r1"]
    hf = sha1

    # 4.1.2
    dU = 971761939728640320549601132085879836204587084162
    assert dU == 0xAA374FFC3CE144E6B073307972CB6D57B2A4E982
    QU = mult(dU, ec.G, ec)
    assert QU == (
        466448783855397898016055842232266600516272889280,
        1110706324081757720403272427311003102474457754220,
    )
    assert (
        bytes_from_point(QU, ec).hex() == "0251b4496fecc406ed0e75a24a3c03206251419dc0"
    )

    # 4.1.3
    dV = 399525573676508631577122671218044116107572676710
    assert dV == 0x45FB58A92A17AD4B15101C66E74F277E2B460866
    QV = mult(dV, ec.G, ec)
    assert QV == (
        420773078745784176406965940076771545932416607676,
        221937774842090227911893783570676792435918278531,
    )
    assert (
        bytes_from_point(QV, ec).hex() == "0349b41e0e9c0369c2328739d90f63d56707c6e5bc"
    )

    # expected results
    z_exp = 1155982782519895915997745984453282631351432623114
    assert z_exp == 0xCA7C0F8C3FFA87A96E1B74AC8E6AF594347BB40A
    size = 20

    # 4.1.4
    z, _ = mult(dU, QV, ec)  # x coordinate only
    assert z == z_exp
    keyingdata = ansi_x9_63_kdf(
        z.to_bytes(ec.p_size, byteorder="big", signed=False), size, hf, None
    )
    assert keyingdata.hex() == "744ab703f5bc082e59185f6d049d2d367db245c2"
    # the whole scheme, on the curve the bindings do not serve: this
    # vector is what covers the Python shared point, secp256k1 having
    # been handed to libsecp256k1
    assert diffie_hellman(dU, QV, size, None, ec, hf) == keyingdata

    # 4.1.5
    z, _ = mult(dV, QU, ec)  # x coordinate only
    assert z == z_exp
    keyingdata = ansi_x9_63_kdf(
        z.to_bytes(ec.p_size, byteorder="big", signed=False), size, hf, None
    )
    assert keyingdata.hex() == "744ab703f5bc082e59185f6d049d2d367db245c2"


def test_the_python_shared_point_is_the_bindings_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One shared key, whoever multiplies the point.

    Three ways to the same bytes: libsecp256k1 for each side of the
    agreement, and the Python endomorphism path for one of them. The
    patch is how that path is reached on secp256k1 at all, `mult`
    delegating every scalar but zero once the point is a public key
    rather than the generator.
    """
    a, A = dsa.gen_keys()  # Alice
    b, B = dsa.gen_keys()  # Bob

    shared_key = diffie_hellman(a, B, 32)
    assert diffie_hellman(b, A, 32) == shared_key
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(dh, "_libsecp256k1_serves", lambda *_: False)
        assert diffie_hellman(a, B, 32) == shared_key


@needs_bindings
def test_every_width_of_dU_is_one_shared_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bindings arm and the Python one agree at every width of the key.

    `shared_point` is constant time in dU, where the call it replaced
    followed the scalar's length: a width is the one thing that could
    tell the two apart, so each is asserted against the Python arithmetic.
    """
    ec = CURVES["secp256k1"]
    QV = mult(0xC0FFEE)
    widths = (256, 128, 64, 32, 1)
    keys = [(1 << (w - 1)) | (0x5A5A5A5A5A5A5A5A % (1 << (w - 1))) for w in widths]
    shared = [diffie_hellman(dU % ec.n, QV, 32) for dU in keys]
    # the whole dispatch and not `dh`'s alone, whose fallthrough is `mult`
    monkeypatch.setattr(curve, "_libsecp256k1_available", False)
    assert [diffie_hellman(dU % ec.n, QV, 32) for dU in keys] == shared


@needs_bindings
def test_a_normal_dU_reaches_the_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ordinary key takes the direct multiplication into libsecp256k1.

    `diffie_hellman` reduces the key with `d = dU % ec.n` before the guard that
    gates the direct `shared_point` call on `d` being nonzero: a mutant of that
    one line -- `ReplaceBinaryOperator_Mod_FloorDiv` turning it to `dU // ec.n`,
    `_Mod_RShift` to `dU >> ec.n` -- makes `d` zero for every `dU` below `n`,
    which is every caller, and the guard then falls through to `mult(dU, QV,
    ec)` instead. That call still reaches libsecp256k1: it reduces `dU` on its
    own and dispatches through `curve._libsecp256k1_mult`, which is
    `shared_point` too and so the same C multiplication one wrapper further out,
    rather than the Python endomorphism arithmetic -- so the mutant costs this
    line's direct entry point and not the delegation. `ansi_x9_63_kdf` derives
    the same bytes off either binding's point, so no assertion on the shared key
    tells the two apart (issue btclib-org/btclib#975); this records the call
    `dh` makes itself instead of the answer it returns, so a mutant that skips
    the direct delegation fails here rather than matching it.
    """
    calls: list[int] = []

    def record(pubkey_bytes: bytes, prvkey: int) -> bytes:
        calls.append(prvkey)
        return libsecp256k1_shared_point(pubkey_bytes, prvkey)

    monkeypatch.setattr("ecc.dh.libsecp256k1_shared_point", record)

    a, _A = dsa.gen_keys()  # Alice
    _b, B = dsa.gen_keys()  # Bob
    diffie_hellman(a, B, 32)
    assert calls == [a % CURVES["secp256k1"].n]


def test_a_degenerate_dU_is_refused_as_a_bad_key_not_as_an_INF_secret() -> None:
    """0 mod n was never a valid private key, and is now refused as one.

    Before scalar_from_prv_key ran first, `d = dU % ec.n` folded `dU = 0`
    into a degenerate scalar that reached `mult` and answered INF -- an
    EccRuntimeError about the *secret*, as though 0 were a key that
    merely produced a bad answer. It never was a valid key, in 1..n-1, so
    it is refused as one (issue btclib-org/ecc#10).
    """
    ec = CURVES["secp256k1"]
    with pytest.raises(EccValueError, match="private key not in 1..n-1"):
        diffie_hellman(0, ec.G, 32)


@pytest.mark.parametrize(
    "bad_dU,exc",
    [
        (True, EccTypeError),
        (5.0, EccTypeError),
        (-5, EccValueError),
    ],
)
def test_a_bad_dU_is_refused_the_same_way_on_both_arithmetic_arms(
    monkeypatch: pytest.MonkeyPatch, bad_dU: object, exc: type[Exception]
) -> None:
    """A bool, a float, and a negative int, refused identically either way.

    `d = dU % ec.n` used to run before any check, so a `True` reached the
    bindings arm as `1` (1*QV, no exception at all) and `5.0 % ec.n`
    reached it as a float the C call itself refused with a bare
    `TypeError`, where the Python arm's own `mult` already refused each of
    them as an `EccTypeError` or an `EccValueError`. Both arms
    now run `scalar_from_prv_key` first and agree (issue
    btclib-org/ecc#10).
    """
    QV = mult(0xC0FFEE)
    with pytest.raises(exc):
        diffie_hellman(bad_dU, QV, 32)  # type: ignore[arg-type]
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(dh, "_libsecp256k1_serves", lambda *_: False)
        with pytest.raises(exc):
            diffie_hellman(bad_dU, QV, 32)  # type: ignore[arg-type]


def test_dU_at_or_above_n_is_refused_rather_than_silently_reduced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`n + 5` used to answer the same secret as `5`; now it is refused.

    `d = dU % ec.n` silently wrapped an out-of-range `dU` into range on
    both arithmetic arms, so `-5` and `ec.n + 5` answered the same shared
    secret as `5` either way -- consistent between the two arms, and still
    not what `scalar_from_prv_key` allows any other private key to do
    (issue btclib-org/ecc#10).
    """
    ec = CURVES["secp256k1"]
    QV = mult(0xC0FFEE)
    err_msg = "private key not in 1..n-1"
    with pytest.raises(EccValueError, match=err_msg):
        diffie_hellman(ec.n + 5, QV, 32)
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(dh, "_libsecp256k1_serves", lambda *_: False)
        with pytest.raises(EccValueError, match=err_msg):
            diffie_hellman(ec.n + 5, QV, 32)


def test_an_INF_public_key_is_refused_the_same_way_on_both_arithmetic_arms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """QV at infinity, refused identically whichever arm would serve it.

    Before the upfront check, `bytes_from_point` refused an INF `QV` as an
    `EccValueError` on the bindings arm, while the Python arm passed
    it through the cofactor multiplication and `mult` unchecked, and only
    caught it afterwards as an `EccRuntimeError` about the secret --
    the same input, two different classes (issue
    btclib-org/ecc#10).
    """
    ec = CURVES["secp256k1"]
    err_msg = r"invalid \(INF\) public key"
    with pytest.raises(EccValueError, match=err_msg):
        diffie_hellman(5, (1, 0), 32, ec=ec)
    with monkeypatch.context() as no_bindings:
        no_bindings.setattr(dh, "_libsecp256k1_serves", lambda *_: False)
        with pytest.raises(EccValueError, match=err_msg):
            diffie_hellman(5, (1, 0), 32, ec=ec)


def test_cofactor_dh_hides_a_low_order_key_parity() -> None:
    """A peer's low-order key no longer leaks dU's parity.

    T has order 4 on secp112r2, a curve of cofactor 4: before the cofactor
    multiplication, `mult(dU, T, ec)` answered a point with x == T[0] for
    every odd dU and INF for every even one, so a peer sending T learned
    dU's parity from whether the call raised. Cofactor DH multiplies T by
    the cofactor first, landing on INF regardless of dU, so every dU now
    answers alike (issue btclib-org/ecc#15).
    """
    ec = CURVES["secp112r2"]
    t = secp112r2_order_4_point()
    err_msg = r"invalid \(INF\) key"
    for d in range(1, 9):
        with pytest.raises(EccRuntimeError, match=err_msg):
            diffie_hellman(d, t, 8, ec=ec)


def test_cofactor_dh_agrees_with_ordinary_dh_where_cofactor_is_1() -> None:
    """The cofactor multiplication is a no-op on every curve without one."""
    ec = CURVES["secp160r1"]
    assert ec.cofactor == 1
    a, A = dsa.gen_keys(ec=ec)
    b, B = dsa.gen_keys(ec=ec)
    assert diffie_hellman(a, B, 32, ec=ec) == diffie_hellman(b, A, 32, ec=ec)


@pytest.mark.parametrize("name", list(cofactor_curves))
def test_cofactor_dh_on_a_cofactor_curve(name: str) -> None:
    """Keys of <G> agree, and a point of small order is refused for every dU."""
    ec = cofactor_curves[name]
    a, A = dsa.gen_keys(ec=ec)
    b, B = dsa.gen_keys(ec=ec)
    assert diffie_hellman(a, B, 32, ec=ec) == diffie_hellman(b, A, 32, ec=ec)

    _, torsion = small_order_points[name]
    err_msg = r"invalid \(INF\) key"
    for T in torsion:
        for d in range(1, ec.n):
            with pytest.raises(EccRuntimeError, match=err_msg):
                diffie_hellman(d, T, 32, ec=ec)


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "diffie_hellman": (
        lambda s: dh.diffie_hellman(s, mult(7), 32),
        REFUSED_SCALARS,
    ),
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
