# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Everything built on first use, reached by several threads at once.

A free-threaded interpreter runs the threads in parallel; the regular one
switches between them every few microseconds here, so the test is also a
check there. What is built on first use, and the test of each:

- the `functools.lru_cache`s, which hand a caller only a finished value and
  may build it more than once when threads miss together; every one in the
  package is raced, `test_every_lru_cache_is_raced` holding the list
- the dictionary `ellswift._CONSTANTS`
- the `_values` memo of `musig2.SessionContext`, `frost.SessionContext`
  and `dahlias.SessionContext`, and the `_bindings_ctx` memo of the
  first, each built into a local and published by one
  `object.__setattr__`
- the `_checked` flag of `_libsecp256k1`, set after the check has passed

What is held is the answer: the threads agree with the same calls made one
after another on empty caches. How many times something was built is not.
"""

import importlib
import inspect
import sys
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from threading import Barrier
from typing import Any

import pytest

from ecc import _libsecp256k1
from ecc.curves import curve_group, mult, secp256k1
from ecc.curves.curve import PreparedPoint, is_libsecp256k1_serving
from ecc.curves.sec_point import bytes_from_point
from ecc.ecc import dahlias, dsa, ellswift, frost, musig2, pedersen, ssa
from tests import module_names, needs_bindings
from tests.curves.curve_test import no_bindings_anywhere

THREADS = 8

# the tables the library builds on first use, to be found empty
_LRU_CACHES = (
    curve_group._cached_multiples,
    curve_group._cached_multiples_fixwind,
    curve_group._cached_odd_multiples_aff,
    curve_group._cached_fixed_base_multiples,
    pedersen.second_generator,
)

_PRV = 0x5EED0214
_PUB = mult(_PRV, secp256k1.G, secp256k1)
_MSGS = [sha256(bytes([i])).digest() for i in range(THREADS)]
_ELL = [ellswift.create(0x1000 + i, secp256k1) for i in range(THREADS)]


@pytest.fixture(autouse=True)
def cold(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Switch threads often; Python arm unless marked bindings."""
    if request.node.get_closest_marker("bindings") is None:
        no_bindings_anywhere(monkeypatch)
    monkeypatch.setattr(ellswift, "_CONSTANTS", {})
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(interval)


def _race(work: Callable[[int], Any]) -> list[Any]:
    """Return work(i) for every i, all called at the same moment."""
    ready = Barrier(THREADS)

    def go(i: int) -> Any:
        ready.wait()
        return work(i)

    with ThreadPoolExecutor(THREADS) as pool:
        return list(pool.map(go, range(THREADS)))


def _empty() -> None:
    """Empty every table."""
    for lru in _LRU_CACHES:
        lru.cache_clear()
    ellswift._CONSTANTS.clear()


def _same(work: Callable[[int], Any]) -> None:
    """Hold that threads racing on empty tables answer as one caller does."""
    _empty()
    expected = [work(i) for i in range(THREADS)]
    _empty()
    assert _race(work) == expected


def test_comb_of_the_generator() -> None:
    """Multiply the generator, which builds its comb."""
    _same(lambda i: mult(0xC0FFEE + i, secp256k1.G, secp256k1))


def test_comb_of_a_prepared_point() -> None:
    """Multiply a prepared point, which builds its own comb."""
    prepared = PreparedPoint(_PUB, secp256k1)
    _same(lambda i: prepared.mult(0xC0FFEE + i))


def test_fixed_window_tables() -> None:
    """Run the fixed-window ladders, plain and cached."""
    ec, GJ = secp256k1, secp256k1.GJ
    _same(lambda i: curve_group._mult_fixed_window_var(0xC0FFEE + i, GJ, ec, 4, True))
    _same(lambda i: curve_group._mult_fixed_window_cached_var(0xC0FFEE + i, GJ, ec, 4))


def test_wnaf_tables_of_the_fixed_points() -> None:
    """Verify signatures, which index the wide wNAF tables of G."""
    sigs = [ssa.sign(msg, _PRV) for msg in _MSGS]
    _same(lambda i: ssa.verify(_MSGS[i], _PUB, sigs[i]))
    dsigs = [dsa.sign(msg, _PRV) for msg in _MSGS]
    _same(lambda i: dsa.verify(_MSGS[i], _PUB, dsigs[i]))


def test_second_generator() -> None:
    """Derive the second generator."""
    _same(lambda _: pedersen.second_generator(secp256k1, sha256))


def test_ellswift_constants() -> None:
    """Decode and encode, which derive the map's constants."""
    _same(lambda i: ellswift.decode_var(_ELL[i], secp256k1))
    # encode picks one of its preimages at random: what it must do is round-trip
    _same(lambda _: ellswift.decode_var(ellswift.encode_var(_PUB, secp256k1)))


_SK = [
    "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
    "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
]
_MSG32 = bytes(range(32))


def _musig2_session() -> tuple[Callable[[], musig2.SessionContext], list[Any]]:
    """Return a maker of fresh session contexts, and the signers' partials."""
    pks = musig2.key_sort([musig2.individual_pub_key(sk) for sk in _SK])
    sk_of = {musig2.individual_pub_key(sk): sk for sk in _SK}
    nonces = {pk: musig2.nonce_gen(sk_of[pk], pk, None, _MSG32) for pk in pks}
    agg_nonce = musig2.nonce_agg_var([nonces[pk][1] for pk in pks])

    def fresh() -> musig2.SessionContext:
        return musig2.SessionContext(agg_nonce, pks, [], [], _MSG32)

    ctx = fresh()
    signers = [
        (musig2.sign(nonces[pk][0], sk_of[pk], ctx), nonces[pk][1], pk) for pk in pks
    ]
    return fresh, signers


def test_musig2_session_values() -> None:
    """Derive the values of one shared MuSig2 session."""
    fresh, _ = _musig2_session()
    expected = musig2.session_values(fresh())
    ctx = fresh()
    assert ctx._values is None
    assert _race(lambda _: musig2.session_values(ctx)) == [expected] * THREADS


def test_frost_session_values() -> None:
    """Derive the values of one shared FROST session."""
    pk = bytes_from_point(_PUB, secp256k1)
    agg_nonce = bytes_from_point(secp256k1.G, secp256k1) + bytes_from_point(
        mult(2, secp256k1.G, secp256k1), secp256k1
    )

    def fresh() -> frost.SessionContext:
        return frost.SessionContext(3, 2, [1, 2], None, pk, agg_nonce, [], [], _MSG32)

    expected = frost.session_values(fresh())
    ctx = fresh()
    assert ctx._values is None
    assert _race(lambda _: frost.session_values(ctx)) == [expected] * THREADS


def test_dahlias_session_values() -> None:
    """Derive the values of one shared DahLIAS session."""
    pk = _PUB[0].to_bytes(32, "big")
    pub_nonce = bytes_from_point(secp256k1.G, secp256k1) + bytes_from_point(
        mult(2, secp256k1.G, secp256k1), secp256k1
    )

    def fresh() -> dahlias.SessionContext:
        return dahlias.SessionContext(pub_nonce, [pk], [_MSG32], [pub_nonce])

    expected = dahlias.session_values(fresh())
    ctx = fresh()
    assert ctx._values is None
    assert _race(lambda _: dahlias.session_values(ctx)) == [expected] * THREADS


@needs_bindings
@pytest.mark.skipif(
    not is_libsecp256k1_serving(), reason="the bindings are not what serves"
)
def test_musig2_bindings_session() -> None:
    """Verify partial signatures against one shared session, on the bindings."""
    fresh, signers = _musig2_session()
    ctx = fresh()
    assert ctx._bindings_ctx is None

    def work(i: int) -> bool:
        psig, pub_nonce, pk = signers[i % 2]
        other_psig = signers[(i + 1) % 2][0]
        right = musig2.partial_sig_verify_(psig, pub_nonce, pk, ctx)
        return right and not musig2.partial_sig_verify_(other_psig, pub_nonce, pk, ctx)

    got = _race(work)
    assert got == [True] * THREADS
    assert ctx._bindings_ctx is not None


@needs_bindings
def test_bindings_check_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Select the bindings from every thread while they are not yet checked."""
    monkeypatch.setattr(_libsecp256k1, "_checked", False)
    _race(lambda _: _libsecp256k1._check_once(setter=False))
    assert _libsecp256k1._checked


def _is_lru_cache(obj: Any) -> bool:
    """Tell a cache by its interface: PyPy's wrapper is a plain function."""
    return callable(getattr(getattr(obj, "__func__", obj), "cache_clear", None))


def _lru_caches_of_the_package() -> set[Any]:
    """Return every lru_cache wrapper in ecc, functions and methods."""
    found = set()
    for name in module_names():
        module = importlib.import_module(name)
        members = list(vars(module).values())
        for obj in list(members):
            if inspect.isclass(obj) and obj.__module__ == module.__name__:
                members += vars(obj).values()
        found |= {getattr(m, "__func__", m) for m in members if _is_lru_cache(m)}
    return found


def test_every_lru_cache_is_raced() -> None:
    """Fail on an lru_cache that no test above races."""
    assert _lru_caches_of_the_package() == set(_LRU_CACHES)
