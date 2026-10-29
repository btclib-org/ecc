# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.ecc.dahlias` module.

The vectors are BIP459's own, the csv files of `bip-0459/vectors/`,
vendored under `tests/schemes/_data/bip459/`; `tests/_data/README.md`
pins the revision. Every case of every file is run.

A signature of the wrong size, which the verify vectors read as False,
raises `EccValueError` here: CONTRIBUTING.md's verification carve-out
covers a value of a declared size.

Sessions are also built here by hand: round trips, the checks `sign`
makes, and the failures BIP459 lists, those no vector reaches
included. The x-only tweak is checked against `ecc.ecc.ssa`'s BIP341 tweaking.
"""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
from typing import Any

import pytest

from ecc.curves import bytes_from_point, mult, secp256k1
from ecc.ecc import dahlias, ssa
from ecc.exceptions import (
    EccException,
    EccRuntimeError,
    EccTypeError,
    EccValueError,
    InvalidContributionError,
)
from ecc.hashes import tagged_hash
from tests import (
    REFUSED_AUX,
    REFUSED_EXTRA,
    both_arms,
    load_csv,
    refused_secret,
    vector_id,
)
from tests.secret_free import assert_secret_free

_N = secp256k1.n

# a key whose point has even y and one whose point has odd y
_EVEN_KEY = 1
_ODD_KEY = 6
# x = 5 is no x-coordinate of secp256k1, so these do not lift
_NOT_X = (5).to_bytes(32, "big")
_NOT_CPOINT = b"\x02" + _NOT_X


def _msg(i: int) -> bytes:
    """Return a 32-byte message."""
    return sha256(bytes([i])).digest()


def _xonly(prv_key: int) -> bytes:
    """Return the x-only public key of a private key."""
    return mult(prv_key)[0].to_bytes(32, "big")


def _rand(i: int) -> bytes:
    """Return the randomness of signer i."""
    return sha256(b"rand" + bytes([i])).digest()


Session = tuple[list[bytearray], list[bytes], dahlias.SessionContext]


def _session(
    prv_keys: list[int], msgs: list[bytes], pks: list[bytes] | None = None
) -> Session:
    """Return the secnonces, the pubnonces and the context of a session."""
    nonces = [dahlias.nonce_gen_(_rand(i), k) for i, k in enumerate(prv_keys)]
    sec_nonces = [sec for sec, _ in nonces]
    pub_nonces = [pub for _, pub in nonces]
    pks = [_xonly(k) for k in prv_keys] if pks is None else pks
    agg_nonce = dahlias.nonce_agg_var(pub_nonces)
    return (
        sec_nonces,
        pub_nonces,
        dahlias.SessionContext(agg_nonce, pks, msgs, pub_nonces),
    )


def _sign_all(prv_keys: list[int], session: Session) -> list[bytes]:
    """Return every signer's partial signature."""
    sec_nonces, _, ctx = session
    return [
        dahlias.sign(sec, k, m, ctx)
        for sec, k, m in zip(sec_nonces, prv_keys, ctx.msgs, strict=True)
    ]


def _round_trip(prv_keys: list[int], msgs: list[bytes]) -> tuple[Session, bytes]:
    """Sign, check each partial signature, aggregate and verify."""
    session = _session(prv_keys, msgs)
    _, pub_nonces, ctx = session
    psigs = _sign_all(prv_keys, session)
    for i, psig in enumerate(psigs):
        assert dahlias.partial_sig_verify(psig, ctx.pub_keys, msgs, pub_nonces, i)
    sig = dahlias.sig_agg(psigs, ctx)
    assert len(sig) == 64
    assert dahlias.verify(ctx.pub_keys, msgs, sig)
    return session, sig


# --------------------------------------------------------------------
# round trips
# --------------------------------------------------------------------


@pytest.mark.parametrize("u", [1, 2, 5])
def test_a_session_of_u_signers_verifies(u: int) -> None:
    """Every partial signature and the aggregate verify."""
    prv_keys = [_EVEN_KEY + 2 * i for i in range(u)]
    _round_trip(prv_keys, [_msg(i) for i in range(u)])


def test_keys_of_both_parities_verify() -> None:
    """A key with odd y signs beside one with even y."""
    assert mult(_EVEN_KEY)[1] % 2 == 0
    assert mult(_ODD_KEY)[1] % 2 == 1
    _round_trip([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])


def test_the_session_nonce_of_either_parity_verifies() -> None:
    """Sessions are drawn until R has had both parities."""
    parities: set[int] = set()
    i = 0
    while len(parities) < 2:
        session, _ = _round_trip([_EVEN_KEY, _ODD_KEY], [_msg(i), _msg(i + 1)])
        parities.add(dahlias.session_values(session[2]).R[1] % 2)
        i += 1


def test_a_key_twice_with_one_message_verifies() -> None:
    """The R_2 values tell apart two signers sharing a key and a message."""
    _round_trip([_ODD_KEY, _ODD_KEY], [_msg(0), _msg(0)])


def test_a_key_twice_with_two_messages_verifies() -> None:
    """A key may sign two messages in one session."""
    _round_trip([_ODD_KEY, _EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1), _msg(2)])


def test_hex_strings_are_octets() -> None:
    """Hex strings and the bytes they spell make the same session."""
    session = _session([_EVEN_KEY], [_msg(0)])
    sec_nonces, pub_nonces, ctx = session
    hex_ctx = dahlias.SessionContext(
        ctx.agg_nonce.hex(),
        [ctx.pub_keys[0].hex()],
        [_msg(0).hex()],
        [pub_nonces[0].hex()],
    )
    assert hex_ctx == ctx
    psig = dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(0).hex(), hex_ctx)
    sig = dahlias.sig_agg([psig.hex()], hex_ctx)
    assert dahlias.verify([ctx.pub_keys[0].hex()], [_msg(0).hex()], sig.hex())


def test_the_signature_depends_on_the_order_of_the_list() -> None:
    """The same pairs in another order are another list."""
    prv_keys = [_EVEN_KEY, _ODD_KEY]
    msgs = [_msg(0), _msg(1)]
    (_, _, ctx), sig = _round_trip(prv_keys, msgs)
    assert not dahlias.verify(ctx.pub_keys[::-1], msgs[::-1], sig)
    # the same pairs, signed in the other order, give another signature
    _, other = _round_trip(prv_keys[::-1], msgs[::-1])
    assert other != sig
    assert not dahlias.verify(ctx.pub_keys, msgs, other)


def test_a_signature_does_not_verify_for_another_list() -> None:
    """Another message, key or length is another list."""
    (_, _, ctx), sig = _round_trip([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    assert not dahlias.verify(ctx.pub_keys, [_msg(0), _msg(2)], sig)
    assert not dahlias.verify([ctx.pub_keys[0], _xonly(5)], ctx.msgs, sig)
    assert not dahlias.verify(ctx.pub_keys[:1], ctx.msgs[:1], sig)
    with pytest.raises(EccRuntimeError, match="signature verification failed"):
        dahlias.assert_as_valid(ctx.pub_keys[:1], ctx.msgs[:1], sig)


def test_a_partial_signature_is_the_formula_of_bip459() -> None:
    """s_j = e*(r_1 + b*r_2) + c_j*d', every value computed here."""
    prv_keys = [_ODD_KEY, _EVEN_KEY]
    msgs = [_msg(0), _msg(1)]
    sec_nonces, pub_nonces, ctx = _session(prv_keys, msgs)
    r_1 = int.from_bytes(sec_nonces[0][:32], "big")
    r_2 = int.from_bytes(sec_nonces[0][32:], "big")
    psig = dahlias.sign(sec_nonces[0], _ODD_KEY, msgs[0], ctx)

    nonce_data = ctx.agg_nonce + b"".join(
        pk + m + pub[33:]
        for pk, m, pub in zip(ctx.pub_keys, msgs, pub_nonces, strict=True)
    )
    b = int.from_bytes(tagged_hash(b"BIP0459/noncecoef", nonce_data), "big") % _N
    R = secp256k1.add_var(
        _cpoint(ctx.agg_nonce[:33]), mult(b, _cpoint(ctx.agg_nonce[33:]))
    )
    assert dahlias.session_values(ctx) == dahlias.SessionValues(R, b)
    e = 1 if R[1] % 2 == 0 else _N - 1
    d = _ODD_KEY if mult(_ODD_KEY)[1] % 2 == 0 else _N - _ODD_KEY
    L = b"".join(pk + m for pk, m in zip(ctx.pub_keys, msgs, strict=True))
    xR = R[0].to_bytes(32, "big")
    c = int.from_bytes(
        tagged_hash(b"BIP0459/sig", L + xR + ctx.pub_keys[0] + msgs[0]), "big"
    )
    s = (e * (r_1 + b * r_2) + (c % _N) * d) % _N
    assert psig == s.to_bytes(32, "big")


# --------------------------------------------------------------------
# NonceGen
# --------------------------------------------------------------------


def test_nonce_gen_is_the_formula_of_bip459() -> None:
    """The nonces are BIP459's hashes, computed here."""
    rand_ = _rand(0)
    extra = b"session 7"
    sk = (_ODD_KEY).to_bytes(32, "big")
    rand = bytes(
        x ^ y for x, y in zip(sk, tagged_hash(b"BIP0459/aux", rand_), strict=True)
    )
    r = [
        int.from_bytes(tagged_hash(b"BIP0459/nonce", rand + extra + bytes([i])), "big")
        % _N
        for i in (0, 1)
    ]
    sec_nonce, pub_nonce = dahlias.nonce_gen_(rand_, _ODD_KEY, extra)
    assert isinstance(sec_nonce, bytearray)
    assert sec_nonce == r[0].to_bytes(32, "big") + r[1].to_bytes(32, "big")
    assert pub_nonce == bytes_from_point(mult(r[0])) + bytes_from_point(mult(r[1]))


def test_nonce_gen_without_key_hashes_the_randomness_itself() -> None:
    """Without a key, rand is rand'."""
    rand_ = _rand(1)
    r_1 = int.from_bytes(tagged_hash(b"BIP0459/nonce", rand_ + b"\x00"), "big") % _N
    sec_nonce, _ = dahlias.nonce_gen_(rand_)
    assert sec_nonce[:32] == r_1.to_bytes(32, "big")
    # an absent extra_in is the empty one
    assert dahlias.nonce_gen_(rand_, None, b"") == (
        sec_nonce,
        dahlias.nonce_gen_(rand_)[1],
    )


def test_nonce_gen_binds_every_argument() -> None:
    """Each argument changes the nonce."""
    nonces = {
        dahlias.nonce_gen_(_rand(0))[1],
        dahlias.nonce_gen_(_rand(1))[1],
        dahlias.nonce_gen_(_rand(0), _EVEN_KEY)[1],
        dahlias.nonce_gen_(_rand(0), _ODD_KEY)[1],
        dahlias.nonce_gen_(_rand(0), None, b"x")[1],
    }
    assert len(nonces) == 5


def test_nonce_gen_draws_fresh_randomness() -> None:
    """Two calls give two nonces."""
    assert dahlias.nonce_gen(_EVEN_KEY) != dahlias.nonce_gen(_EVEN_KEY)
    sec_nonce, pub_nonce = dahlias.nonce_gen(extra_in=b"x")
    assert len(sec_nonce) == 64
    assert len(pub_nonce) == 66


@pytest.mark.parametrize("prv_key", [0, _N])
def test_nonce_gen_refuses_an_invalid_key(prv_key: int) -> None:
    """A key outside 1..n-1 is refused."""
    with pytest.raises(EccValueError):
        dahlias.nonce_gen_(_rand(0), prv_key)


@pytest.mark.parametrize("length", [31, 33])
def test_nonce_gen_refuses_randomness_of_the_wrong_size(length: int) -> None:
    """The randomness is 32 bytes."""
    with pytest.raises(EccValueError):
        dahlias.nonce_gen_(bytes(length))


# --------------------------------------------------------------------
# NonceAgg
# --------------------------------------------------------------------


def test_nonce_agg_sums_each_half() -> None:
    """Each half of the aggregate is the sum of the halves."""
    pub_nonces = [dahlias.nonce_gen_(_rand(i))[1] for i in range(3)]
    agg = dahlias.nonce_agg_var(pub_nonces)
    for half in (slice(0, 33), slice(33, 66)):
        points = [_cpoint(pub[half]) for pub in pub_nonces]
        total = secp256k1.add_var(secp256k1.add_var(points[0], points[1]), points[2])
        assert agg[half] == bytes_from_point(total)


def _cpoint(octets: bytes) -> tuple[int, int]:
    """Parse a compressed point."""
    x, y = ssa.point_from_bip340pub_key_var(octets[1:])
    return (x, y) if octets[0] == 2 else (x, secp256k1.p - y)


@pytest.mark.parametrize("bad", [_NOT_CPOINT, b"\x04" + bytes(32), bytes(33)])
@pytest.mark.parametrize("half", [0, 1])
def test_nonce_agg_names_the_signer_of_an_invalid_nonce(bad: bytes, half: int) -> None:
    """Either half of a nonce that is no point names its signer."""
    good = dahlias.nonce_gen_(_rand(0))[1]
    bad_nonce = bad + good[33:] if half == 0 else good[:33] + bad
    with pytest.raises(InvalidContributionError) as e:
        dahlias.nonce_agg_var([good, bad_nonce])
    assert (e.value.signer, e.value.contrib) == (1, "pubnonce")


def test_nonce_agg_blames_the_first_signer_with_an_invalid_nonce() -> None:
    """Signer 0's bad R_2 is found before signer 1's bad R_1."""
    good = dahlias.nonce_gen_(_rand(0))[1]
    nonces = [good[:33] + _NOT_CPOINT, _NOT_CPOINT + good[33:]]
    with pytest.raises(InvalidContributionError) as e:
        dahlias.nonce_agg_var(nonces)
    assert e.value.signer == 0


@pytest.mark.parametrize("half", [0, 1])
def test_nonce_agg_refuses_a_half_at_infinity(half: int) -> None:
    """A half that sums to infinity is refused."""
    pub_nonce = dahlias.nonce_gen_(_rand(0))[1]
    negated = bytearray(pub_nonce)
    negated[33 * half] ^= 1
    with pytest.raises(EccValueError, match="infinity"):
        dahlias.nonce_agg_var([pub_nonce, bytes(negated)])


def test_nonce_agg_refuses_an_empty_list() -> None:
    """There is no aggregate of no nonce."""
    with pytest.raises(EccValueError, match="empty"):
        dahlias.nonce_agg_var([])


# --------------------------------------------------------------------
# the session
# --------------------------------------------------------------------


@pytest.mark.parametrize("session_ctx", [None, "00" * 66, (bytes(66), [], [], [])])
def test_the_session_functions_refuse_what_is_no_session(session_ctx: Any) -> None:
    """A session that is no `SessionContext` is a type error."""
    sec_nonce = bytearray(dahlias.nonce_gen_(_rand(0), _EVEN_KEY)[0])
    kept = bytes(sec_nonce)
    with pytest.raises(EccTypeError, match="session_ctx"):
        dahlias.session_values(session_ctx)
    with pytest.raises(EccTypeError, match="session_ctx"):
        dahlias.sign(sec_nonce, _EVEN_KEY, _msg(0), session_ctx)
    assert sec_nonce == kept
    with pytest.raises(EccTypeError, match="session_ctx"):
        dahlias.sig_agg([bytes(32)], session_ctx)


def test_session_values_are_memoized() -> None:
    """The second call answers the first call's object."""
    _, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    values = dahlias.session_values(ctx)
    assert dahlias.session_values(ctx) is values


def test_session_values_name_an_invalid_aggnonce() -> None:
    """A half of the aggregate nonce that is no point blames the aggregator."""
    _, pub_nonces, ctx = _session([_EVEN_KEY], [_msg(0)])
    for agg_nonce in (_NOT_CPOINT + ctx.agg_nonce[33:], ctx.agg_nonce[:33] + bytes(33)):
        bad = dahlias.SessionContext(agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces)
        with pytest.raises(InvalidContributionError) as e:
            dahlias.session_values(bad)
        assert (e.value.signer, e.value.contrib) == (None, "aggnonce")


def test_session_values_name_an_invalid_r_2() -> None:
    """An R_2 that is no point names its signer."""
    _, pub_nonces, ctx = _session([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    pub_nonces[1] = pub_nonces[1][:33] + _NOT_CPOINT
    bad = dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces)
    with pytest.raises(InvalidContributionError) as e:
        dahlias.session_values(bad)
    assert (e.value.signer, e.value.contrib) == (1, "pubnonce")


def test_session_values_do_not_read_r_1_of_a_signer() -> None:
    """GetSessionValues parses only R_2 of each public nonce."""
    _, pub_nonces, ctx = _session([_EVEN_KEY], [_msg(0)])
    pub_nonces[0] = _NOT_CPOINT + pub_nonces[0][33:]
    other = dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces)
    assert dahlias.session_values(other) == dahlias.session_values(ctx)


def test_session_values_hash_the_whole_session() -> None:
    """Reordering any list changes b."""
    _, pub_nonces, ctx = _session([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    b = dahlias.session_values(ctx).b
    variants = [
        dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys[::-1], ctx.msgs, pub_nonces),
        dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys, ctx.msgs[::-1], pub_nonces),
        dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces[::-1]),
    ]
    assert all(dahlias.session_values(v).b != b for v in variants)


def test_session_context_refuses_lists_of_another_length() -> None:
    """The lists are of one length u >= 1."""
    _, pub_nonces, ctx = _session([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    with pytest.raises(EccValueError, match="msgs"):
        dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys, ctx.msgs[:1], pub_nonces)
    with pytest.raises(EccValueError, match="pub_nonces"):
        dahlias.SessionContext(ctx.agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces[:1])
    with pytest.raises(EccValueError, match="empty"):
        dahlias.SessionContext(ctx.agg_nonce, [], [], [])


@pytest.mark.parametrize(
    "position, value",
    [(0, bytes(65)), (1, [bytes(33)]), (2, [bytes(31)]), (3, [bytes(65)])],
)
def test_session_context_refuses_octets_of_the_wrong_size(
    position: int, value: Any
) -> None:
    """Every element is of its declared size."""
    _, pub_nonces, ctx = _session([_EVEN_KEY], [_msg(0)])
    args: list[Any] = [ctx.agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces]
    args[position] = value
    with pytest.raises(EccValueError):
        dahlias.SessionContext(*args)


@pytest.mark.parametrize("position", [1, 2, 3])
def test_session_context_refuses_octets_where_a_list_belongs(position: int) -> None:
    """An element alone is no list."""
    _, pub_nonces, ctx = _session([_EVEN_KEY], [_msg(0)])
    args: list[Any] = [ctx.agg_nonce, ctx.pub_keys, ctx.msgs, pub_nonces]
    args[position] = args[position][0]
    with pytest.raises(EccTypeError):
        dahlias.SessionContext(*args)


# --------------------------------------------------------------------
# Sign
# --------------------------------------------------------------------


def test_a_secnonce_signs_once() -> None:
    """Sign zeroes the secnonce, so a second call is refused."""
    sec_nonces, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    sec_nonce = sec_nonces[0]
    dahlias.sign(sec_nonce, _EVEN_KEY, _msg(0), ctx)
    assert sec_nonce == bytearray(64)
    with pytest.raises(EccValueError, match="first secnonce value out of range"):
        dahlias.sign(sec_nonce, _EVEN_KEY, _msg(0), ctx)


def test_sign_leaves_the_secnonce_of_a_session_that_does_not_assemble() -> None:
    """A session refused before the read leaves the nonce usable."""
    sec_nonces, pub_nonces, ctx = _session([_EVEN_KEY], [_msg(0)])
    kept = bytes(sec_nonces[0])
    bad = dahlias.SessionContext(bytes(66), ctx.pub_keys, ctx.msgs, pub_nonces)
    with pytest.raises(InvalidContributionError):
        dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(0), bad)
    assert sec_nonces[0] == kept
    dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(0), ctx)


@pytest.mark.parametrize("sec_nonce", [bytes(64), list(range(64)), "00" * 64])
def test_sign_refuses_a_secnonce_that_is_no_bytearray(sec_nonce: Any) -> None:
    """Only a bytearray can be zeroed."""
    _, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    with pytest.raises(EccTypeError):
        dahlias.sign(sec_nonce, _EVEN_KEY, _msg(0), ctx)


@pytest.mark.parametrize("length", [63, 65, 97])
def test_sign_refuses_a_secnonce_of_the_wrong_length(length: int) -> None:
    """The secnonce is 64 bytes."""
    _, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    with pytest.raises(EccValueError, match="64 bytes"):
        dahlias.sign(bytearray(length), _EVEN_KEY, _msg(0), ctx)


@pytest.mark.parametrize(
    "half, value, match",
    [
        (0, 0, "first"),
        (0, _N, "first"),
        (1, 0, "second"),
        (1, _N, "second"),
    ],
)
def test_sign_refuses_a_secnonce_scalar_out_of_range(
    half: int, value: int, match: str
) -> None:
    """Each half is in 1..n-1, and is zeroed anyway."""
    sec_nonces, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    sec_nonce = sec_nonces[0]
    sec_nonce[32 * half : 32 * half + 32] = value.to_bytes(32, "big")
    with pytest.raises(EccValueError, match=match):
        dahlias.sign(sec_nonce, _EVEN_KEY, _msg(0), ctx)
    assert sec_nonce == bytearray(64)


@pytest.mark.parametrize("prv_key", [0, _N])
def test_sign_refuses_an_invalid_key(prv_key: int) -> None:
    """A key outside 1..n-1 is refused."""
    sec_nonces, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    with pytest.raises(EccValueError):
        dahlias.sign(sec_nonces[0], prv_key, _msg(0), ctx)


def test_sign_refuses_a_session_without_its_r_2() -> None:
    """The signer's R_2 must be in the list."""
    sec_nonces, pub_nonces, ctx = _session([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    other = dahlias.nonce_gen_(_rand(9))[1]
    pub_nonces[0] = other
    bad = dahlias.SessionContext(
        dahlias.nonce_agg_var(pub_nonces), ctx.pub_keys, ctx.msgs, pub_nonces
    )
    with pytest.raises(EccValueError, match="exactly once"):
        dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(0), bad)


@pytest.mark.parametrize(
    "pk, msg",
    [
        # BIP459's footnote: a second index with another key or message
        (_xonly(_ODD_KEY), _msg(0)),
        (_xonly(_EVEN_KEY), _msg(1)),
        # and with the very same key and message
        (_xonly(_EVEN_KEY), _msg(0)),
    ],
)
def test_sign_refuses_its_r_2_at_two_indexes(pk: bytes, msg: bytes) -> None:
    """The signer's R_2 must be in the list once."""
    sec_nonces, pub_nonces, ctx = _session([_EVEN_KEY], [_msg(0)])
    # the second entry carries the signer's R_2 beside another R_1
    second = dahlias.nonce_gen_(_rand(9))[1][:33] + pub_nonces[0][33:]
    nonces = [pub_nonces[0], second]
    bad = dahlias.SessionContext(
        dahlias.nonce_agg_var(nonces), [ctx.pub_keys[0], pk], [_msg(0), msg], nonces
    )
    with pytest.raises(EccValueError, match="exactly once"):
        dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(0), bad)


def test_sign_refuses_another_key_at_its_index() -> None:
    """The key at the signer's index is its own."""
    sec_nonces, _, ctx = _session([_EVEN_KEY], [_msg(0)], [_xonly(_ODD_KEY)])
    with pytest.raises(EccValueError, match="public key"):
        dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(0), ctx)


def test_sign_refuses_another_message_at_its_index() -> None:
    """The message at the signer's index is its own."""
    sec_nonces, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    with pytest.raises(EccValueError, match="message"):
        dahlias.sign(sec_nonces[0], _EVEN_KEY, _msg(1), ctx)


def test_sign_compares_the_x_only_key_whatever_the_parity() -> None:
    """The odd-y key is in the list as its x, and signs as n - d."""
    _round_trip([_ODD_KEY], [_msg(0)])
    _round_trip([_N - _ODD_KEY], [_msg(0)])


def test_sign_refuses_a_message_of_the_wrong_size() -> None:
    """A message is 32 bytes."""
    sec_nonces, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    with pytest.raises(EccValueError):
        dahlias.sign(sec_nonces[0], _EVEN_KEY, bytes(31), ctx)


# --------------------------------------------------------------------
# SigAgg
# --------------------------------------------------------------------


def test_sig_agg_names_a_partial_signature_out_of_range() -> None:
    """A partial signature at or above n names its signer."""
    session = _session([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    psigs = _sign_all([_EVEN_KEY, _ODD_KEY], session)
    psigs[1] = _N.to_bytes(32, "big")
    with pytest.raises(InvalidContributionError) as e:
        dahlias.sig_agg(psigs, session[2])
    assert (e.value.signer, e.value.contrib) == (1, "psig")


def test_sig_agg_refuses_a_count_other_than_u() -> None:
    """There is one partial signature per signer."""
    session = _session([_EVEN_KEY, _ODD_KEY], [_msg(0), _msg(1)])
    psigs = _sign_all([_EVEN_KEY, _ODD_KEY], session)
    with pytest.raises(EccValueError, match="same length"):
        dahlias.sig_agg(psigs[:1], session[2])


def test_sig_agg_refuses_octets_where_a_list_belongs() -> None:
    """A partial signature alone is no list."""
    session = _session([_EVEN_KEY], [_msg(0)])
    with pytest.raises(EccTypeError):
        dahlias.sig_agg(bytes(32), session[2])  # type: ignore[arg-type]


# --------------------------------------------------------------------
# PartialSigVerify
# --------------------------------------------------------------------


def _psv_fixture() -> tuple[list[bytes], list[bytes], list[bytes], list[bytes]]:
    """Return two signers' partial signatures and their lists."""
    prv_keys = [_EVEN_KEY, _ODD_KEY]
    msgs = [_msg(0), _msg(1)]
    session = _session(prv_keys, msgs)
    psigs = _sign_all(prv_keys, session)
    return psigs, list(session[2].pub_keys), msgs, session[1]


def test_partial_sig_verify_refuses_another_signers_partial_signature() -> None:
    """A partial signature verifies only for its signer and list."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    assert not dahlias.partial_sig_verify(psigs[1], pks, msgs, pub_nonces, 0)
    assert not dahlias.partial_sig_verify(psigs[0], pks, msgs[::-1], pub_nonces, 0)


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda _psig, pks, msgs, nonces: (_N.to_bytes(32, "big"), pks, msgs, nonces),
        lambda _psig, pks, msgs, nonces: (bytes(32), pks, msgs, nonces),
        lambda psig, pks, msgs, nonces: (psig, [_NOT_X, pks[1]], msgs, nonces),
        lambda psig, pks, msgs, nonces: (
            psig,
            pks,
            msgs,
            [_NOT_CPOINT + nonces[0][33:], nonces[1]],
        ),
        lambda psig, pks, msgs, nonces: (
            psig,
            pks,
            msgs,
            [nonces[0][:33] + _NOT_CPOINT, nonces[1]],
        ),
        # another signer's nonce is unreadable, so is the session
        lambda psig, pks, msgs, nonces: (
            psig,
            pks,
            msgs,
            [nonces[0], _NOT_CPOINT + nonces[1][33:]],
        ),
        lambda psig, pks, msgs, nonces: (
            psig,
            pks,
            msgs,
            [nonces[0], nonces[1][:33] + _NOT_CPOINT],
        ),
    ],
    ids=[
        "s at n",
        "s zero",
        "key that does not lift",
        "R_1 that is no point",
        "R_2 that is no point",
        "R_1 of another signer",
        "R_2 of another signer",
    ],
)
def test_partial_sig_verify_answers_false(
    corrupt: Callable[..., tuple[Any, ...]],
) -> None:
    """Each failure BIP459 lists is False."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    psig, pks, msgs, pub_nonces = corrupt(psigs[0], pks, msgs, pub_nonces)
    assert dahlias.partial_sig_verify(psig, pks, msgs, pub_nonces, 0) is False


def test_partial_sig_verify_answers_false_for_an_aggregate_nonce_at_infinity() -> None:
    """NonceAgg failing is False."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    negated = bytearray(pub_nonces[0])
    negated[0] ^= 1
    nonces = [pub_nonces[0], bytes(negated)]
    assert dahlias.partial_sig_verify(psigs[0], pks, msgs, nonces, 0) is False


@pytest.mark.parametrize("i", [-1, 2])
def test_partial_sig_verify_answers_false_for_an_index_out_of_range(i: int) -> None:
    """An int outside 0..u-1 is a failure, not a type error."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    assert dahlias.partial_sig_verify(psigs[0], pks, msgs, pub_nonces, i) is False


@pytest.mark.parametrize("i", [True, 0.0, "0"])
def test_partial_sig_verify_refuses_an_index_that_is_no_integer(i: Any) -> None:
    """The index is an int, and a bool is not one."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    with pytest.raises(EccTypeError):
        dahlias.partial_sig_verify(psigs[0], pks, msgs, pub_nonces, i)


def test_partial_sig_verify_answers_false_for_lists_of_another_length() -> None:
    """A list declares no size, so uneven or empty lists are False."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    for args in (
        (pks, msgs, pub_nonces[:1]),
        (pks, msgs[:1], pub_nonces),
        (pks[:1], msgs, pub_nonces),
        ([], [], []),
    ):
        assert dahlias.partial_sig_verify(psigs[0], *args, 0) is False


@pytest.mark.parametrize(
    "position, value",
    [(0, bytes(31)), (1, [bytes(33)] * 2), (2, [bytes(33)] * 2), (3, [bytes(33)] * 2)],
)
def test_partial_sig_verify_refuses_octets_of_the_wrong_size(
    position: int, value: Any
) -> None:
    """Every input is of its declared size."""
    psigs, pks, msgs, pub_nonces = _psv_fixture()
    args: list[Any] = [psigs[0], pks, msgs, pub_nonces, 0]
    args[position] = value
    with pytest.raises(EccValueError):
        dahlias.partial_sig_verify(*args)


# --------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------


def _verify_fixture() -> tuple[list[bytes], list[bytes], bytes]:
    """Return the lists of two signers and their signature."""
    msgs = [_msg(0), _msg(1)]
    (_, _, ctx), sig = _round_trip([_EVEN_KEY, _ODD_KEY], msgs)
    return list(ctx.pub_keys), msgs, sig


@pytest.mark.parametrize(
    "corrupt, error",
    [
        (
            lambda pks, msgs, sig: (pks, msgs, sig[:32] + _N.to_bytes(32, "big")),
            "scalar s",
        ),
        (lambda pks, msgs, sig: (pks, msgs, _NOT_X + sig[32:]), "x-coordinate"),
        (
            lambda pks, msgs, sig: (
                pks,
                msgs,
                (secp256k1.p).to_bytes(32, "big") + sig[32:],
            ),
            None,
        ),
        (lambda pks, msgs, sig: ([pks[0], _NOT_X], msgs, sig), "x-coordinate"),
        (
            lambda pks, msgs, sig: (pks, msgs, sig[:32] + bytes(32)),
            "verification failed",
        ),
    ],
    ids=[
        "s at n",
        "r that does not lift",
        "r at p",
        "key that does not lift",
        "s zero",
    ],
)
def test_verify_answers_false_and_assert_as_valid_says_why(
    corrupt: Callable[..., tuple[Any, ...]], error: str | None
) -> None:
    """A well-formed signature that fails is False, with a reason."""
    pks, msgs, sig = corrupt(*_verify_fixture())
    assert dahlias.verify(pks, msgs, sig) is False
    with pytest.raises((EccValueError, EccRuntimeError), match=error):
        dahlias.assert_as_valid(pks, msgs, sig)


@pytest.mark.parametrize(
    "pks, msgs, sig",
    [
        ([bytes(33)], [bytes(32)], bytes(64)),
        ([bytes(32)], [bytes(33)], bytes(64)),
        ([bytes(32)], [bytes(32)], bytes(63)),
    ],
)
def test_verify_refuses_octets_of_the_wrong_size(pks: Any, msgs: Any, sig: Any) -> None:
    """A key, a message or a signature of the wrong size raises."""
    with pytest.raises(EccValueError):
        dahlias.verify(pks, msgs, sig)


@pytest.mark.parametrize(
    "pks, msgs, error",
    [
        ([bytes(32)], [], "same length"),
        ([], [], "empty"),
    ],
)
def test_verify_answers_false_for_an_empty_or_uneven_list(
    pks: Any, msgs: Any, error: str
) -> None:
    """A list declares no size; `assert_as_valid` still says why."""
    *_, sig = _verify_fixture()
    assert dahlias.verify(pks, msgs, sig) is False
    with pytest.raises(EccValueError, match=error):
        dahlias.assert_as_valid(pks, msgs, sig)


def test_verify_refuses_octets_where_a_list_belongs() -> None:
    """A key alone is no list."""
    with pytest.raises(EccTypeError):
        dahlias.verify(bytes(32), [bytes(32)], bytes(64))  # type: ignore[arg-type]


# --------------------------------------------------------------------
# key tweaking
# --------------------------------------------------------------------

_TWEAK = sha256(b"tweak").digest()


@pytest.mark.parametrize("prv_key", [_EVEN_KEY, _ODD_KEY])
def test_plain_tweak_is_a_sum(prv_key: int) -> None:
    """Plain tweaking is sk + t and P + t*G."""
    tweaked, pk = dahlias.plain_tweak(prv_key, _TWEAK)
    assert tweaked == (prv_key + int.from_bytes(_TWEAK, "big")) % _N
    assert pk == _xonly(tweaked)
    full = dahlias.plain_tweak_pub_key_var(bytes_from_point(mult(prv_key)), _TWEAK)
    assert full == bytes_from_point(mult(tweaked))
    assert full[1:] == pk


@pytest.mark.parametrize("prv_key", [_EVEN_KEY, _ODD_KEY])
def test_xonly_tweak_is_bip341_tweaking(prv_key: int) -> None:
    """X-only tweaking is BIP341's: the even-y key plus t, and ssa's key."""
    tweaked, pk = dahlias.xonly_tweak(prv_key, _TWEAK)
    d = prv_key if mult(prv_key)[1] % 2 == 0 else _N - prv_key
    assert tweaked == (d + int.from_bytes(_TWEAK, "big")) % _N
    x, parity = ssa.pub_key_tweak_add_var(_xonly(prv_key), _TWEAK)
    assert pk == x.to_bytes(32, "big")
    full = dahlias.xonly_tweak_pub_key_var(_xonly(prv_key), _TWEAK)
    assert full == bytes([2 + parity]) + pk


def test_the_two_tweaks_differ_on_an_odd_key_only() -> None:
    """An even-y key is its own normalization."""
    assert dahlias.plain_tweak(_EVEN_KEY, _TWEAK) == dahlias.xonly_tweak(
        _EVEN_KEY, _TWEAK
    )
    assert dahlias.plain_tweak(_ODD_KEY, _TWEAK) != dahlias.xonly_tweak(
        _ODD_KEY, _TWEAK
    )


def test_tweaked_keys_sign_a_session() -> None:
    """Tweaked keys sign, a chain of plain tweaks included."""
    plain, plain_pk = dahlias.plain_tweak(_ODD_KEY, _TWEAK)
    xonly, xonly_pk = dahlias.xonly_tweak(_ODD_KEY, _TWEAK)
    # a chain of two plain tweaks, as a BIP32 path, and a taproot output key
    chained, chained_pk = dahlias.plain_tweak(plain, _TWEAK)
    chained_full = dahlias.plain_tweak_pub_key_var(
        dahlias.plain_tweak_pub_key_var(bytes_from_point(mult(_ODD_KEY)), _TWEAK),
        _TWEAK,
    )
    assert chained_full[1:] == chained_pk
    (_, _, ctx), _ = _round_trip([plain, xonly, chained], [_msg(0), _msg(1), _msg(2)])
    assert list(ctx.pub_keys) == [plain_pk, xonly_pk, chained_pk]


@pytest.mark.parametrize(
    "tweak, error",
    [
        (_N.to_bytes(32, "big"), "less than n"),
        (b"\xff" * 32, "less than n"),
        (bytes(31), "size"),
        (bytes(33), "size"),
    ],
)
def test_tweaking_refuses_a_tweak_out_of_range_or_size(
    tweak: bytes, error: str
) -> None:
    """A tweak is 32 bytes and below n."""
    calls: list[Callable[[], object]] = [
        lambda: dahlias.plain_tweak(_EVEN_KEY, tweak),
        lambda: dahlias.xonly_tweak(_EVEN_KEY, tweak),
        lambda: dahlias.plain_tweak_pub_key_var(bytes_from_point(secp256k1.G), tweak),
        lambda: dahlias.xonly_tweak_pub_key_var(_xonly(_EVEN_KEY), tweak),
    ]
    for call in calls:
        with pytest.raises(EccValueError, match=error):
            call()


# plain: t = n - sk; x-only: t = n - d, d the even-y key of the point
_ODD_MINUS = (_N - _ODD_KEY).to_bytes(32, "big")
_ODD_PLUS = (_ODD_KEY).to_bytes(32, "big")


@both_arms
def test_tweaking_refuses_a_private_key_of_zero() -> None:
    """A tweak that cancels the secret key is refused."""
    with pytest.raises(EccValueError, match="tweaked private key is zero"):
        dahlias.plain_tweak(_ODD_KEY, _ODD_MINUS)
    with pytest.raises(EccValueError, match="tweaked private key is zero"):
        dahlias.xonly_tweak(_ODD_KEY, _ODD_PLUS)


def test_tweaking_refuses_a_key_at_infinity() -> None:
    """A tweak that cancels the public key is refused."""
    with pytest.raises(EccValueError, match="infinity"):
        dahlias.plain_tweak_pub_key_var(bytes_from_point(mult(_ODD_KEY)), _ODD_MINUS)
    with pytest.raises(EccValueError, match="infinity"):
        dahlias.xonly_tweak_pub_key_var(_xonly(_ODD_KEY), _ODD_PLUS)


def test_public_tweaking_refuses_a_key_that_is_no_point() -> None:
    """A public key that does not parse is refused."""
    with pytest.raises(EccValueError):
        dahlias.plain_tweak_pub_key_var(_NOT_CPOINT, _TWEAK)
    with pytest.raises(EccValueError):
        dahlias.xonly_tweak_pub_key_var(_NOT_X, _TWEAK)
    with pytest.raises(EccValueError):
        dahlias.xonly_tweak_pub_key_var(bytes_from_point(secp256k1.G), _TWEAK)


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------


def _secret_sign(sec_nonce: Any, prv_key: Any) -> object:
    """Sign in a session of one signer."""
    _, _, ctx = _session([_EVEN_KEY], [_msg(0)])
    return dahlias.sign(sec_nonce, prv_key, _msg(0), ctx)


_SECRET_NONCES = ["bytes", "bytearray", "33 bytes", "30 bytes"]
_SECRET_KEYS = [
    "int",
    "negative int",
    "0x hex string",
    "33 bytes",
    "30 bytes",
    "WIF",
    "wrong key",
]

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "nonce_gen": (dahlias.nonce_gen, _SECRET_KEYS[:-1]),
    "nonce_gen_, rand_": (dahlias.nonce_gen_, REFUSED_AUX),
    "nonce_gen, extra_in": (lambda s: dahlias.nonce_gen(extra_in=s), REFUSED_EXTRA),
    "sign, key": (
        lambda s: _secret_sign(dahlias.nonce_gen_(_rand(0), _EVEN_KEY)[0], s),
        _SECRET_KEYS,
    ),
    "sign, secret nonce": (lambda s: _secret_sign(s, _EVEN_KEY), _SECRET_NONCES),
    "sign, secret nonce refused for its value or its R_2": (
        lambda s: _secret_sign(bytearray(s), _EVEN_KEY),
        _SECRET_NONCES,
    ),
    "plain_tweak": (lambda s: dahlias.plain_tweak(s, _TWEAK), _SECRET_KEYS[:-1]),
    "xonly_tweak": (lambda s: dahlias.xonly_tweak(s, _TWEAK), _SECRET_KEYS[:-1]),
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


# --------------------------------------------------------------------
# BIP459's vectors
# --------------------------------------------------------------------


def _vectors(name: str) -> list[list[str]]:
    """Return the rows of one of BIP459's vector files."""
    return load_csv("schemes", "_data", "bip459", name)


def _hex_list(field: str) -> list[bytes]:
    """Return a ';'-separated list of hex values; empty for an empty field."""
    return [bytes.fromhex(value) for value in field.split(";")] if field else []


def _pub_nonce_of(sec_nonce: bytes) -> bytes:
    """Return r_1*G || r_2*G, compressed."""
    return b"".join(
        bytes_from_point(mult(int.from_bytes(sec_nonce[i : i + 32], "big")))
        for i in (0, 32)
    )


def _ids(rows: list[list[str]]) -> list[str]:
    return [vector_id(int(row[0]), row[-1]) for row in rows]


_SIGN = _vectors("test_vectors_sign.csv")


@pytest.mark.parametrize("row", _SIGN, ids=_ids(_SIGN))
def test_sign_vectors(row: list[str]) -> None:
    """The aggregate nonce, each partial signature and the signature match."""
    _, sks, msgs, secs, agg_nonce, psigs, sig, _ = row
    prv_keys = _hex_list(sks)
    ms = _hex_list(msgs)
    sec_nonces = _hex_list(secs)
    pub_nonces = [_pub_nonce_of(sec) for sec in sec_nonces]
    pks = [_xonly(int.from_bytes(k, "big")) for k in prv_keys]
    assert dahlias.nonce_agg_var(pub_nonces).hex() == agg_nonce.lower()
    ctx = dahlias.SessionContext(agg_nonce, pks, ms, pub_nonces)
    signed = [
        dahlias.sign(bytearray(sec), k, m, ctx)
        for sec, k, m in zip(sec_nonces, prv_keys, ms, strict=True)
    ]
    assert signed == _hex_list(psigs)
    for i, psig in enumerate(signed):
        assert dahlias.partial_sig_verify(psig, pks, ms, pub_nonces, i)
    assert dahlias.sig_agg(signed, ctx).hex() == sig.lower()
    assert dahlias.verify(pks, ms, sig)


_SIGN_ERROR = _vectors("test_vectors_sign_error.csv")


# each case's comment -> the reason it is refused for; a case missing here
# fails, and an aggregate nonce blames the aggregator
_SIGN_ERROR_REASONS = {
    "Signer's R2 appears at two indices": "R_2 must appear exactly once",
    "Signer's R2 appears at no index": "R_2 must appear exactly once",
    "Message at signer's index was substituted": "message at the signer's index",
    "Public key at signer's index was substituted": "public key at the signer's",
    "Secnonce is all zeros": "first secnonce value out of range",
    "Secret key is zero": "private key not in 1..n-1",
    "Aggregate nonce first half is all zeros": None,
    "Aggregate nonce second half is not on the curve": None,
    "Aggregate nonce second half exceeds field size": None,
}


@pytest.mark.parametrize("row", _SIGN_ERROR, ids=_ids(_SIGN_ERROR))
def test_sign_error_vectors(row: list[str]) -> None:
    """Each case is refused for its own reason."""
    _, sk, msg, sec, agg_nonce, pks, msgs, pub_nonces, comment = row
    ctx = dahlias.SessionContext(
        agg_nonce, _hex_list(pks), _hex_list(msgs), _hex_list(pub_nonces)
    )
    reason = _SIGN_ERROR_REASONS[comment]
    if reason is None:
        with pytest.raises(InvalidContributionError) as e:
            dahlias.sign(bytearray.fromhex(sec), sk, msg, ctx)
        assert (e.value.signer, e.value.contrib) == (None, "aggnonce")
    else:
        with pytest.raises(EccValueError, match=reason):
            dahlias.sign(bytearray.fromhex(sec), sk, msg, ctx)


_PARTIAL_SIG_VERIFY = _vectors("test_vectors_partial_sig_verify.csv")


@pytest.mark.parametrize("row", _PARTIAL_SIG_VERIFY, ids=_ids(_PARTIAL_SIG_VERIFY))
def test_partial_sig_verify_vectors(row: list[str]) -> None:
    """Each answer matches the file."""
    _, i, psig, pks, msgs, pub_nonces, expected, _ = row
    args = (psig, _hex_list(pks), _hex_list(msgs), _hex_list(pub_nonces), int(i))
    assert dahlias.partial_sig_verify(*args) is (expected == "TRUE")


_VERIFY = _vectors("test_vectors_verify.csv")


@pytest.mark.parametrize("row", _VERIFY, ids=_ids(_VERIFY))
def test_verify_vectors(row: list[str]) -> None:
    """Each answer matches; a signature of the wrong size raises."""
    _, pks, msgs, sig, expected, _ = row
    pub_keys, ms = _hex_list(pks), _hex_list(msgs)
    if len(sig) != 128:
        assert expected == "FALSE"
        with pytest.raises(EccValueError):
            dahlias.verify(pub_keys, ms, sig)
    else:
        assert dahlias.verify(pub_keys, ms, sig) is (expected == "TRUE")


_TWEAK_VECTORS = _vectors("test_vectors_tweak.csv")


@pytest.mark.parametrize("row", _TWEAK_VECTORS, ids=_ids(_TWEAK_VECTORS))
@both_arms
def test_tweak_vectors(row: list[str]) -> None:
    """Both halves of each tweak match, or both refuse."""
    _, sk, tweak, is_xonly, expected, tweaked_sk, tweaked_pk, _ = row
    P = mult(int(sk, 16))
    if is_xonly == "TRUE":
        calls = (
            lambda: dahlias.xonly_tweak(sk, tweak),
            lambda: dahlias.xonly_tweak_pub_key_var(_xonly(int(sk, 16)), tweak),
        )
    else:
        calls = (
            lambda: dahlias.plain_tweak(sk, tweak),
            lambda: dahlias.plain_tweak_pub_key_var(bytes_from_point(P), tweak),
        )
    if expected == "FALSE":
        for call in calls:
            with pytest.raises(EccValueError):
                call()
        return
    prv_key, x_only = calls[0]()
    assert prv_key == int(tweaked_sk, 16)
    assert calls[1]().hex() == tweaked_pk.lower()
    assert x_only.hex() == tweaked_pk[2:].lower()
