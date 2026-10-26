# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.ecc.frost` module.

The vectors are BIP445's own, every JSON file of
`siv2r/bip-frost-signing`'s `python/vectors/`, vendored under
`tests/schemes/_data/bip445/`; `tests/_data/README.md` pins the revision.
Every case of every file is exercised, the error cases included, and an
error case is checked against the exception the file names -- which
party misbehaved and how, or the message of a plain value error.

A trusted dealer generated those vectors. `chilldkg_vectors.json` is key
material from ChillDKG's reference instead, and `tests/_data/README.md`
pins it too. Each of its sessions is validated, signs and verifies, and
is refused once mutated.

There is no oracle to cross-validate against, unlike `musig2_test.py`'s
own `btclib_secp256k1.musig`: BIP445 has no C implementation this
library wraps, so every function here is the Python arithmetic and the
vectors are its only authority.
"""

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from ecc.curves import bytes_from_point, mult, secp256k1
from ecc.ecc import frost, musig2, ssa
from ecc.exceptions import (
    EccException,
    EccTypeError,
    EccValueError,
    InvalidContributionError,
)
from tests import (
    REFUSED_AUX,
    REFUSED_EXTRA,
    REFUSED_OCTETS,
    both_arms,
    load,
    refused_secret,
    vector_id,
)
from tests.secret_free import assert_secret_free

_ERRORS = (EccValueError, InvalidContributionError)


def _hex_all(values: list[str]) -> list[bytes]:
    """Convert a list of hex strings to bytes, one for one."""
    return [bytes.fromhex(value) for value in values]


def _pub_nonce_of(sec_nonce: bytes) -> bytes:
    """Recompute a public nonce from a secret one, k_1*G and k_2*G."""
    return b"".join(
        bytes_from_point(mult(int.from_bytes(sec_nonce[i : i + 32], "big")))
        for i in (0, 32)
    )


def assert_error(error: dict[str, Any], exc: Exception) -> None:
    """Check the raised exception against what the vector expects.

    BIP445's own JSON schema, not BIP327's: `"type"` spells
    `"InvalidContributionError"` and `"ValueError"`, capitalized, and the
    signer field is `"signer_index"` rather than `"signer"` --
    `tests/schemes/musig2_test.py`'s `assert_error` reads a different shape
    because BIP327's vectors are written to a different one.
    """
    if error["type"] == "InvalidContributionError":
        assert isinstance(exc, InvalidContributionError)
        assert exc.signer == error["signer_index"]
        assert exc.contrib == error["contrib"]
    else:
        assert error["type"] == "ValueError"
        assert isinstance(exc, EccValueError)
        # the message, byte for byte: the vectors compare BIP445's own
        # reference strings this way, and frost.py copies them verbatim
        assert str(exc) == error["message"]


# --------------------------------------------------------------------
# nonce_gen_vectors.json
# --------------------------------------------------------------------


def nonce_gen_vectors() -> list[Any]:
    """One param per case of nonce_gen_vectors.json."""
    test_data = load("schemes", "_data", "bip445", "nonce_gen_vectors.json")
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(test_data["valid_tests"])
    ]


@pytest.mark.parametrize("case", nonce_gen_vectors())
@both_arms
def test_nonce_gen_vectors(case: dict[str, Any]) -> None:
    """Reproduce BIP445's nonce_gen_vectors.json."""

    def value(key: str) -> bytes | None:
        return None if case[key] is None else bytes.fromhex(case[key])

    sec_nonce, pub_nonce = frost.nonce_gen_(
        bytes.fromhex(case["rand"]),
        value("secshare"),
        case["signer_id"],
        value("pubshare"),
        value("thresh_pk_xonly"),
        value("msg"),
        value("extra_in"),
    )
    expected_sec_nonce, expected_pub_nonce = case["expected"]
    assert bytes(sec_nonce) == bytes.fromhex(expected_sec_nonce)
    assert pub_nonce == bytes.fromhex(expected_pub_nonce)


@pytest.mark.parametrize("signer_id", [-1, frost.MAX_PARTICIPANTS, 2**32 - 1])
def test_nonce_gen_refuses_a_signer_id_outside_the_participants(
    signer_id: int,
) -> None:
    """`signer_id` is 0 to 127: one below and 128 and up are refused."""
    with pytest.raises(EccValueError, match="less than 128"):
        frost.nonce_gen(signer_id=signer_id)


def test_nonce_gen_binds_the_signer_id() -> None:
    """0 and 127 are ids, and each id, or none, gives its own nonce."""
    rand = bytes(32)
    nonces = {
        signer_id: frost.nonce_gen_(rand, None, signer_id, None)[1]
        for signer_id in (None, 0, 1, frost.MAX_PARTICIPANTS - 1)
    }
    assert len(set(nonces.values())) == len(nonces)


@pytest.mark.parametrize("signer_id", [True, 1.0, 1.9, "1", b"\x01"])
def test_nonce_gen_coerces_no_signer_id(signer_id: Any) -> None:
    """1.9 and "1" are refused, not read as 1."""
    with pytest.raises(EccTypeError, match="invalid signer_id type"):
        frost.nonce_gen(signer_id=signer_id)


def test_nonce_gen_draws_fresh_randomness() -> None:
    """`nonce_gen` is `nonce_gen_` with `secrets.token_bytes` for `rand_`."""
    sec_nonce, pub_nonce = frost.nonce_gen()
    assert len(sec_nonce) == 64
    assert len(pub_nonce) == 66
    assert _pub_nonce_of(bytes(sec_nonce)) == pub_nonce
    # two calls draw two different secnonces, with overwhelming probability
    sec_nonce_2, _ = frost.nonce_gen()
    assert bytes(sec_nonce) != bytes(sec_nonce_2)


# --------------------------------------------------------------------
# nonce_agg_vectors.json
# --------------------------------------------------------------------

_NONCE_AGG = load("schemes", "_data", "bip445", "nonce_agg_vectors.json")


def nonce_agg_valid_vectors() -> list[Any]:
    """One param per valid case of nonce_agg_vectors.json."""
    pub_nonces = _hex_all(_NONCE_AGG["pubnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pubnonce_indices"]],
            bytes.fromhex(case["expected"]),
            id=vector_id(index, case.get("comment")),
        )
        for index, case in enumerate(_NONCE_AGG["valid_tests"])
    ]


@pytest.mark.parametrize("pub_nonces, expected", nonce_agg_valid_vectors())
@both_arms
def test_nonce_agg_vectors(pub_nonces: list[bytes], expected: bytes) -> None:
    """Reproduce the valid cases of BIP445's nonce_agg_vectors.json."""
    assert frost.nonce_agg_var(pub_nonces) == expected


def nonce_agg_error_vectors() -> list[Any]:
    """One param per error case of nonce_agg_vectors.json."""
    pub_nonces = _hex_all(_NONCE_AGG["pubnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pubnonce_indices"]],
            case["error"],
            id=vector_id(index, case.get("comment")),
        )
        for index, case in enumerate(_NONCE_AGG["error_tests"])
    ]


@pytest.mark.parametrize("pub_nonces, error", nonce_agg_error_vectors())
@both_arms
def test_nonce_agg_error_vectors(pub_nonces: list[bytes], error: Any) -> None:
    """Reproduce the error cases of BIP445's nonce_agg_vectors.json."""
    with pytest.raises(_ERRORS) as excinfo:
        frost.nonce_agg_var(pub_nonces)
    assert_error(error, excinfo.value)


# --------------------------------------------------------------------
# sign_verify_vectors.json
# --------------------------------------------------------------------

_SIGN_VERIFY = load("schemes", "_data", "bip445", "sign_verify_vectors.json")


def _group_params(group: dict[str, Any], cases_key: str) -> list[Any]:
    return [
        pytest.param(group, case, id=vector_id(index, case.get("comment")))
        for index, case in enumerate(group[cases_key])
    ]


def _pub_shares_case(
    pub_shares: list[bytes], case: dict[str, Any]
) -> list[bytes] | None:
    """Return the pubshares a case selects, `None` where its list is absent."""
    if case["pubshare_indices"] is None:
        return None
    return [pub_shares[i] for i in case["pubshare_indices"]]


def _all_group_params(data: dict[str, Any], cases_key: str) -> list[Any]:
    params = []
    for group in data["test_groups"]:
        params.extend(_group_params(group, cases_key))
    return params


@both_arms
def test_sign_verify_vectors_consistency() -> None:
    """Each group's own cross-reference: pubshares match secshares."""
    for group in _SIGN_VERIFY["test_groups"]:
        n = group["n"]
        pub_shares = _hex_all(group["pubshares"])[:n]
        sec_shares = _hex_all(group["secshares"])[:n]
        for pub_share, sec_share in zip(pub_shares, sec_shares, strict=True):
            d = int.from_bytes(sec_share, "big")
            assert pub_share == bytes_from_point(mult(d))


@pytest.mark.parametrize("group, case", _all_group_params(_SIGN_VERIFY, "valid_tests"))
@both_arms
def test_sign_verify_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])

    ids = case["ids"]
    valid_pub_shares = (
        None
        if case["pubshare_indices"] is None
        else [pub_shares[i] for i in case["pubshare_indices"]]
    )
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    assert frost.nonce_agg_var(pub_nonces_case) == agg_nonce
    msg = bytes.fromhex(case["msg"])
    signer_id = case["signer_id"]
    signer_index = ids.index(signer_id)
    sec_share = sec_shares[case["secshare_index"]]
    expected = bytes.fromhex(case["expected"])

    session_ctx = frost.SessionContext(
        n, t, ids, valid_pub_shares, thresh_pk, agg_nonce, [], [], msg
    )
    # a copy: signing consumes the secnonce, and the vectors reuse it
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])
    assert frost.sign(sec_nonce, sec_share, signer_id, session_ctx) == expected
    if valid_pub_shares is not None:
        assert frost.partial_sig_verify(
            expected,
            pub_nonces_case,
            n,
            t,
            ids,
            valid_pub_shares,
            thresh_pk,
            [],
            [],
            msg,
            signer_index,
        )


@pytest.mark.parametrize(
    "sec_nonce",
    ["not a nonce", None],
    ids=["str", "None"],
)
def test_sign_refuses_a_secnonce_that_is_no_bytearray(sec_nonce: Any) -> None:
    """A `str` or `None` secnonce used to leak a bare builtin `TypeError`.

    `musig2.sign`'s own test has the shape this refuses: a `bytearray`
    is what nothing but this scheme can spend (issue
    btclib-org/ecc#11).
    """
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    ids = list(range(1, n + 1))
    session_ctx = frost.SessionContext(
        n, t, ids, None, thresh_pk, bytes(66), [], [], bytes(32)
    )
    with pytest.raises(EccTypeError, match="invalid sec_nonce type"):
        frost.sign(sec_nonce, bytes(32), 1, session_ctx)


@pytest.mark.parametrize("not_a_session_ctx", [None, "session", 0, b"x"])
def test_session_ctx_that_is_no_session_context_is_refused(
    not_a_session_ctx: Any,
) -> None:
    """A `None` session context used to leak an `AttributeError`.

    The same shape `musig2`'s own test refuses: every public function
    that takes a `session_ctx` read its first field unasked, so a
    caller that had not built one got a complaint about the builtin
    that read it, not about the argument it had not built (issue
    btclib-org/ecc#367).
    """
    with pytest.raises(EccTypeError, match="invalid session_ctx type"):
        frost.session_values(not_a_session_ctx)
    with pytest.raises(EccTypeError, match="invalid session_ctx type"):
        frost.sign(bytearray(64), bytes(32), 1, not_a_session_ctx)
    with pytest.raises(EccTypeError, match="invalid session_ctx type"):
        frost.partial_sig_verify_(bytes(32), 1, bytes(66), bytes(33), not_a_session_ctx)
    with pytest.raises(EccTypeError, match="invalid session_ctx type"):
        frost.partial_sig_agg([], not_a_session_ctx)


def test_session_ctx_of_the_other_module_is_refused() -> None:
    """A MuSig2 context spells a session too, but is not this module's.

    `musig2.SessionContext` carries its own `_values` cache, so without
    the type check `frost.session_values` would read past it to the
    threshold parameters, which that class does not have, and leak the
    same `AttributeError` under a more confusing shape (issue
    btclib-org/ecc#367).
    """
    other = musig2.SessionContext(bytes(66), [bytes(33)], [], [], bytes(32))
    with pytest.raises(EccTypeError, match="invalid session_ctx type"):
        frost.session_values(other)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "group, case", _all_group_params(_SIGN_VERIFY, "sign_error_tests")
)
@both_arms
def test_sign_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the sign error cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])

    ids = case["ids"]
    pub_shares_case = _pub_shares_case(pub_shares, case)
    agg_nonce = bytes.fromhex(case["aggnonce"])
    msg = bytes.fromhex(case["msg"])
    signer_id = case["signer_id"]
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])
    sec_share = sec_shares[case["secshare_index"]]

    with pytest.raises(_ERRORS) as excinfo:
        session_ctx = frost.SessionContext(
            n, t, ids, pub_shares_case, thresh_pk, agg_nonce, [], [], msg
        )
        frost.sign(sec_nonce, sec_share, signer_id, session_ctx)
    assert_error(case["error"], excinfo.value)


@pytest.mark.parametrize(
    "group, case", _all_group_params(_SIGN_VERIFY, "verify_fail_tests")
)
@both_arms
def test_verify_fail_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the verify fail cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])

    psig = bytes.fromhex(case["psig"])
    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    msg = bytes.fromhex(case["msg"])
    signer_index = case["signer_index"]
    assert not frost.partial_sig_verify(
        psig,
        pub_nonces_case,
        n,
        t,
        ids,
        pub_shares_case,
        thresh_pk,
        [],
        [],
        msg,
        signer_index,
    )


@pytest.mark.parametrize(
    "group, case", _all_group_params(_SIGN_VERIFY, "verify_error_tests")
)
@both_arms
def test_verify_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the verify error cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])

    psig = bytes.fromhex(case["psig"])
    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    msg = bytes.fromhex(case["msg"])
    signer_index = case["signer_index"]
    with pytest.raises(_ERRORS) as excinfo:
        frost.partial_sig_verify(
            psig,
            pub_nonces_case,
            n,
            t,
            ids,
            pub_shares_case,
            thresh_pk,
            [],
            [],
            msg,
            signer_index,
        )
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# tweak_vectors.json
# --------------------------------------------------------------------

_TWEAK = load("schemes", "_data", "bip445", "tweak_vectors.json")


@pytest.mark.parametrize("group, case", _all_group_params(_TWEAK, "valid_tests"))
@both_arms
def test_tweak_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's tweak_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    assert frost.nonce_agg_var(pub_nonces_case) == agg_nonce
    msg = bytes.fromhex(case["msg"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    signer_id = case["signer_id"]
    signer_index = ids.index(signer_id)
    sec_share = sec_shares[case["secshare_index"]]
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])
    expected = bytes.fromhex(case["expected"])

    session_ctx = frost.SessionContext(
        n, t, ids, pub_shares_case, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
    )
    assert frost.sign(sec_nonce, sec_share, signer_id, session_ctx) == expected
    assert frost.partial_sig_verify(
        expected,
        pub_nonces_case,
        n,
        t,
        ids,
        pub_shares_case,
        thresh_pk,
        tweaks_case,
        is_xonly,
        msg,
        signer_index,
    )


@pytest.mark.parametrize("group, case", _all_group_params(_TWEAK, "error_tests"))
@both_arms
def test_tweak_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP445's tweak_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    msg = bytes.fromhex(case["msg"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    signer_id = case["signer_id"]
    sec_share = sec_shares[case["secshare_index"]]
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])

    with pytest.raises(_ERRORS) as excinfo:
        session_ctx = frost.SessionContext(
            n, t, ids, pub_shares_case, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
        )
        frost.sign(sec_nonce, sec_share, signer_id, session_ctx)
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# det_sign_vectors.json
# --------------------------------------------------------------------

_DET_SIGN = load("schemes", "_data", "bip445", "det_sign_vectors.json")


@pytest.mark.parametrize("group, case", _all_group_params(_DET_SIGN, "valid_tests"))
@both_arms
def test_det_sign_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's det_sign_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])

    ids = case["ids"]
    valid_pub_shares = (
        None
        if case["pubshare_indices"] is None
        else [pub_shares[i] for i in case["pubshare_indices"]]
    )
    sec_share = sec_shares[case["secshare_index"]]
    agg_other_nonce = (
        bytes.fromhex(case["aggothernonce"])
        if case["aggothernonce"] is not None
        else None
    )
    tweaks = _hex_all(case["tweaks"])
    is_xonly = case["is_xonly"]
    msg = bytes.fromhex(case["msg"])
    signer_id = case["signer_id"]
    signer_index = ids.index(signer_id)
    aux_rand = bytes.fromhex(case["aux_rand"]) if case["aux_rand"] is not None else None
    expected = _hex_all(case["expected"])

    pub_nonce, psig = frost.deterministic_sign(
        sec_share,
        signer_id,
        agg_other_nonce,
        n,
        t,
        ids,
        valid_pub_shares,
        thresh_pk,
        tweaks,
        is_xonly,
        msg,
        aux_rand,
    )
    assert pub_nonce == expected[0]
    assert psig == expected[1]

    agg_nonce = (
        frost.nonce_agg_var([pub_nonce, agg_other_nonce])
        if agg_other_nonce is not None
        else pub_nonce
    )
    session_ctx = frost.SessionContext(
        n, t, ids, valid_pub_shares, thresh_pk, agg_nonce, tweaks, is_xonly, msg
    )
    # a signer always knows its own public share, even in a session whose
    # public share list is absent, so the self-check runs either way
    own_pub_share = (
        pub_shares[signer_id]
        if valid_pub_shares is None
        else valid_pub_shares[signer_index]
    )
    assert frost.partial_sig_verify_(
        psig, signer_id, pub_nonce, own_pub_share, session_ctx
    )


@pytest.mark.parametrize("group, case", _all_group_params(_DET_SIGN, "error_tests"))
@both_arms
def test_det_sign_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP445's det_sign_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])

    ids = case["ids"]
    pub_shares_case = _pub_shares_case(pub_shares, case)
    sec_share = sec_shares[case["secshare_index"]]
    agg_other_nonce = (
        bytes.fromhex(case["aggothernonce"])
        if case["aggothernonce"] is not None
        else None
    )
    tweaks = _hex_all(case["tweaks"])
    is_xonly = case["is_xonly"]
    msg = bytes.fromhex(case["msg"])
    signer_id = case["signer_id"]
    aux_rand = bytes.fromhex(case["aux_rand"]) if case["aux_rand"] is not None else None

    with pytest.raises(_ERRORS) as excinfo:
        frost.deterministic_sign(
            sec_share,
            signer_id,
            agg_other_nonce,
            n,
            t,
            ids,
            pub_shares_case,
            thresh_pk,
            tweaks,
            is_xonly,
            msg,
            aux_rand,
        )
    assert_error(case["error"], excinfo.value)


def _two_of_three_det_sign_group() -> dict[str, Any]:
    return next(g for g in _DET_SIGN["test_groups"] if (g["t"], g["n"]) == (2, 3))


def test_det_sign_nonce_differs_for_a_key_and_its_negation() -> None:
    """A threshold key and its negation do not share a nonce.

    They have one x-only key and two partial signatures that differ in
    the sign of the key's share. Over one nonce, a coordinator that
    replays a session under both keys, with no public shares for
    `deterministic_sign` to compare them with, recovers the secret share
    from the difference of the two partial signatures.
    """
    group = _two_of_three_det_sign_group()
    n, t, ids, signer_id, msg = group["n"], group["t"], [0, 1], 0, bytes(32)
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    negated_pk = bytes([thresh_pk[0] ^ 1]) + thresh_pk[1:]
    sec_share = bytes.fromhex(group["secshares"][signer_id])
    _, other_nonce = frost.nonce_gen()

    outputs = [
        frost.deterministic_sign(
            sec_share, signer_id, other_nonce, n, t, ids, None, pk, [], [], msg
        )
        for pk in (thresh_pk, negated_pk)
    ]
    (pub_nonce, psig), (negated_pub_nonce, negated_psig) = outputs
    assert pub_nonce != negated_pub_nonce

    # what the difference of the two partial signatures would give were the
    # nonce shared
    session_ctx = frost.SessionContext(
        n,
        t,
        ids,
        None,
        thresh_pk,
        frost.nonce_agg_var([pub_nonce, other_nonce]),
        [],
        [],
        msg,
    )
    values = frost.session_values(session_ctx)
    g = 1 if values.Q[1] % 2 == 0 else secp256k1.n - 1
    factor = 2 * values.e * frost._derive_interpolating_value_var(ids, signer_id) * g
    recovered = (
        (int.from_bytes(psig, "big") - int.from_bytes(negated_psig, "big"))
        * pow(factor, -1, secp256k1.n)
        % secp256k1.n
    )
    assert recovered != int.from_bytes(sec_share, "big")


@pytest.mark.parametrize("length", [65, 67])
def test_det_sign_refuses_an_aggothernonce_of_the_wrong_length(length: int) -> None:
    """With several signers, `aggothernonce` is 66 bytes and no other size."""
    group = _two_of_three_det_sign_group()
    with pytest.raises(EccValueError, match="a 66-byte array when u > 1"):
        frost.deterministic_sign(
            bytes.fromhex(group["secshares"][0]),
            0,
            bytes(length),
            group["n"],
            group["t"],
            [0, 1],
            None,
            bytes.fromhex(group["thresh_pk"]),
            [],
            [],
            bytes(32),
        )


@pytest.mark.parametrize("length", [31, 33])
def test_det_sign_refuses_an_aux_rand_of_the_wrong_length(length: int) -> None:
    """`aux_rand`, where given, is 32 bytes and no other size."""
    group = _two_of_three_det_sign_group()
    _, other_nonce = frost.nonce_gen()
    with pytest.raises(EccValueError, match="instead of 32"):
        frost.deterministic_sign(
            bytes.fromhex(group["secshares"][0]),
            0,
            other_nonce,
            group["n"],
            group["t"],
            [0, 1],
            None,
            bytes.fromhex(group["thresh_pk"]),
            [],
            [],
            bytes(32),
            bytes(length),
        )


@pytest.mark.parametrize("signer_id", [-1, 2, 2**32])
def test_det_sign_refuses_a_signer_id_outside_the_ids(signer_id: int) -> None:
    """An id the session lacks is the package's error, not an `OverflowError`.

    -1 and 2**32 cannot be written as 4 bytes, so the nonce derivation
    would overflow on them.
    """
    group = _two_of_three_det_sign_group()
    _, other_nonce = frost.nonce_gen()
    with pytest.raises(EccValueError, match="missing from the ids"):
        frost.deterministic_sign(
            bytes.fromhex(group["secshares"][0]),
            signer_id,
            other_nonce,
            group["n"],
            group["t"],
            [0, 1],
            None,
            bytes.fromhex(group["thresh_pk"]),
            [],
            [],
            bytes(32),
        )


# --------------------------------------------------------------------
# sig_agg_vectors.json
# --------------------------------------------------------------------

_SIG_AGG = load("schemes", "_data", "bip445", "sig_agg_vectors.json")


@pytest.mark.parametrize("group, case", _all_group_params(_SIG_AGG, "valid_tests"))
@both_arms
def test_sig_agg_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's sig_agg_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    valid_pub_shares = (
        None
        if case["pubshare_indices"] is None
        else [pub_shares[i] for i in case["pubshare_indices"]]
    )
    agg_nonce = bytes.fromhex(case["aggnonce"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    psigs = _hex_all(case["psigs"])
    msg = bytes.fromhex(case["msg"])
    expected = bytes.fromhex(case["expected"])

    session_ctx = frost.SessionContext(
        n, t, ids, valid_pub_shares, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
    )
    sig = frost.partial_sig_agg(psigs, session_ctx)
    assert sig.serialize() == expected
    # the aggregate is an ordinary BIP340 signature, and this package's own
    # verifier is what says so
    tweaked_pk = frost.thresh_pubkey_and_tweak_var(
        thresh_pk, tweaks_case, is_xonly
    ).x_only_pub_key
    assert ssa.verify_(msg, tweaked_pk, sig)


@pytest.mark.parametrize("group, case", _all_group_params(_SIG_AGG, "error_tests"))
@both_arms
def test_sig_agg_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP445's sig_agg_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    psigs = _hex_all(case["psigs"])
    msg = bytes.fromhex(case["msg"])

    session_ctx = frost.SessionContext(
        n, t, ids, pub_shares_case, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
    )
    with pytest.raises(_ERRORS) as excinfo:
        frost.partial_sig_agg(psigs, session_ctx)
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# threshold_info_vectors.json
# --------------------------------------------------------------------

_THRESHOLD_INFO = load("schemes", "_data", "bip445", "threshold_info_vectors.json")


def _threshold_info(group: dict[str, Any], case: dict[str, Any]) -> frost.ThresholdInfo:
    """Build the case's `ThresholdInfo`; a `None` index is an absent share."""
    pub_shares = _hex_all(group["pubshares"])
    return frost.ThresholdInfo(
        case["t"],
        bytes.fromhex(case["thresh_pk"]),
        [None if i is None else pub_shares[i] for i in case["pubshare_indices"]],
    )


@pytest.mark.parametrize(
    "group, case", _all_group_params(_THRESHOLD_INFO, "valid_tests")
)
def test_threshold_info_valid_vectors(
    group: dict[str, Any], case: dict[str, Any]
) -> None:
    """Reproduce the valid cases of BIP445's threshold_info_vectors.json."""
    frost.validate_threshold_info(_threshold_info(group, case))


@pytest.mark.parametrize(
    "group, case", _all_group_params(_THRESHOLD_INFO, "error_tests")
)
def test_threshold_info_error_vectors(
    group: dict[str, Any], case: dict[str, Any]
) -> None:
    """Reproduce the error cases of BIP445's threshold_info_vectors.json."""
    with pytest.raises(_ERRORS) as excinfo:
        frost.validate_threshold_info(_threshold_info(group, case))
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# chilldkg_vectors.json: key material from ChillDKG's reference, where the
# BIP445 vectors above come from a trusted dealer
# --------------------------------------------------------------------

_CHILLDKG = load("schemes", "_data", "chilldkg_vectors.json")

_CHILLDKG_MSG = b"ChillDKG session"


def chilldkg_sessions() -> list[Any]:
    """One param per session of chilldkg_vectors.json, named by its (t, n)."""
    return [
        pytest.param(
            session, id=vector_id(index, f"t{session['t']}", f"n{session['n']}")
        )
        for index, session in enumerate(_CHILLDKG["sessions"])
    ]


def _chilldkg(
    session: dict[str, Any],
) -> tuple[int, int, bytes, list[bytes], list[bytes]]:
    """Return a session's n, t, thresh_pk, pubshares and secshares."""
    info = session["threshold_info"]
    return (
        session["n"],
        info["t"],
        bytes.fromhex(info["thresh_pk"]),
        _hex_all(info["pubshares"]),
        _hex_all(session["secshares"]),
    )


def _chilldkg_signers(n: int, t: int) -> list[int]:
    """The last t participants: `validate_threshold_info` reads the first t."""
    return list(range(n - t, n))


def _chilldkg_nonces(
    ids: list[int], pub_shares: list[bytes], sec_shares: list[bytes], thresh_pk: bytes
) -> tuple[list[bytearray], list[bytes]]:
    """Return the secnonces and pubnonces of `ids`, from a fixed `rand_` each."""
    pairs = [
        frost.nonce_gen_(
            bytes([i]) * 32,
            sec_shares[i],
            i,
            pub_shares[i],
            thresh_pk[1:],
            _CHILLDKG_MSG,
        )
        for i in ids
    ]
    return [sec_nonce for sec_nonce, _ in pairs], [pub for _, pub in pairs]


def _negated(point: bytes) -> bytes:
    """Flip a compressed point's parity byte: a valid point, the negation."""
    return bytes([point[0] ^ 1]) + point[1:]


@pytest.mark.parametrize("session", chilldkg_sessions())
@both_arms
def test_chilldkg_threshold_info_is_valid(session: dict[str, Any]) -> None:
    """`validate_threshold_info` accepts what ChillDKG output.

    Each secshare is also checked against its pubshare, which is what the
    refusals below change.
    """
    n, t, thresh_pk, pub_shares, sec_shares = _chilldkg(session)
    assert t == session["t"]
    assert len(pub_shares) == len(sec_shares) == n
    frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, pub_shares))
    for pub_share, sec_share in zip(pub_shares, sec_shares, strict=True):
        assert pub_share == bytes_from_point(mult(int.from_bytes(sec_share, "big")))


@pytest.mark.parametrize("session", chilldkg_sessions())
@both_arms
def test_chilldkg_session_signs_and_verifies(session: dict[str, Any]) -> None:
    """t signers sign, each partial signature verifies, and so does the sum."""
    n, t, thresh_pk, pub_shares, sec_shares = _chilldkg(session)
    ids = _chilldkg_signers(n, t)
    signer_pub_shares = [pub_shares[i] for i in ids]
    sec_nonces, pub_nonces = _chilldkg_nonces(ids, pub_shares, sec_shares, thresh_pk)
    session_ctx = frost.SessionContext(
        n,
        t,
        ids,
        signer_pub_shares,
        thresh_pk,
        frost.nonce_agg_var(pub_nonces),
        [],
        [],
        _CHILLDKG_MSG,
    )
    psigs = []
    for index, (signer_id, sec_nonce) in enumerate(zip(ids, sec_nonces, strict=True)):
        psig = frost.sign(sec_nonce, sec_shares[signer_id], signer_id, session_ctx)
        assert frost.partial_sig_verify(
            psig,
            pub_nonces,
            n,
            t,
            ids,
            signer_pub_shares,
            thresh_pk,
            [],
            [],
            _CHILLDKG_MSG,
            index,
        )
        psigs.append(psig)
    sig = frost.partial_sig_agg(psigs, session_ctx)
    assert ssa.verify_(_CHILLDKG_MSG, thresh_pk[1:], sig)


@pytest.mark.parametrize("session", chilldkg_sessions())
@both_arms
def test_chilldkg_flipped_pubshare_is_refused(session: dict[str, Any]) -> None:
    """Each pubshare negated in turn is refused.

    With t = n no share is left over to check the polynomial against, so
    the threshold public key is what disagrees.
    """
    n, t, thresh_pk, pub_shares, _ = _chilldkg(session)
    message = (
        frost._KEY_MATERIAL_POLY_ERR if t < n else frost._KEY_MATERIAL_MATCH_ERR
    )
    for i in range(n):
        flipped = [*pub_shares[:i], _negated(pub_shares[i]), *pub_shares[i + 1 :]]
        with pytest.raises(EccValueError) as excinfo:
            frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, flipped))
        assert str(excinfo.value) == message


@pytest.mark.parametrize("session", chilldkg_sessions())
@both_arms
def test_chilldkg_wrong_thresh_pk_is_refused(session: dict[str, Any]) -> None:
    """The negated threshold public key is refused, at setup and in a session.

    It has the same x-only key as the right one, so only the parity byte
    tells them apart.
    """
    n, t, thresh_pk, pub_shares, _ = _chilldkg(session)
    wrong = _negated(thresh_pk)
    with pytest.raises(EccValueError) as excinfo:
        frost.validate_threshold_info(frost.ThresholdInfo(t, wrong, pub_shares))
    assert str(excinfo.value) == frost._KEY_MATERIAL_MATCH_ERR
    ids = _chilldkg_signers(n, t)
    session_ctx = frost.SessionContext(
        n, t, ids, [pub_shares[i] for i in ids], wrong, bytes(66), [], [], b""
    )
    with pytest.raises(EccValueError) as excinfo:
        frost.session_values(session_ctx)
    assert str(excinfo.value) == frost._KEY_MATERIAL_MATCH_ERR


@pytest.mark.parametrize("session", chilldkg_sessions())
@both_arms
def test_chilldkg_secshare_not_matching_its_pubshare_is_refused(
    session: dict[str, Any],
) -> None:
    """A signer holding its secshare negated is refused.

    `sign` refuses it where the session carries the pubshares. Where it
    does not, the partial signature does not verify, and the right
    secshare's does.
    """
    n, t, thresh_pk, pub_shares, sec_shares = _chilldkg(session)
    ids = _chilldkg_signers(n, t)
    signer_id = ids[0]
    d = int.from_bytes(sec_shares[signer_id], "big")
    wrong = (secp256k1.n - d).to_bytes(32, "big")
    sec_nonces, pub_nonces = _chilldkg_nonces(ids, pub_shares, sec_shares, thresh_pk)
    agg_nonce = frost.nonce_agg_var(pub_nonces)
    signer_pub_shares = [pub_shares[i] for i in ids]

    def session_ctx(with_pub_shares: list[bytes] | None) -> frost.SessionContext:
        return frost.SessionContext(
            n, t, ids, with_pub_shares, thresh_pk, agg_nonce, [], [], _CHILLDKG_MSG
        )

    with pytest.raises(EccValueError, match="does not match its entry"):
        frost.sign(
            bytearray(sec_nonces[0]), wrong, signer_id, session_ctx(signer_pub_shares)
        )

    def verifies(sec_share: bytes) -> bool:
        psig = frost.sign(
            bytearray(sec_nonces[0]), sec_share, signer_id, session_ctx(None)
        )
        return frost.partial_sig_verify(
            psig,
            pub_nonces,
            n,
            t,
            ids,
            signer_pub_shares,
            thresh_pk,
            [],
            [],
            _CHILLDKG_MSG,
            0,
        )

    assert verifies(sec_shares[signer_id])
    assert not verifies(wrong)


# --------------------------------------------------------------------
# Session-parameter refusals no vector reaches: none of the session vector
# files varies t in an error case, or asks pubshares and ids to disagree in
# length, or drives partial_sig_verify's own upfront checks.
# --------------------------------------------------------------------


def test_session_values_refuses_a_threshold_outside_1_to_n() -> None:
    """No session vector varies `t` in an error case; `SessionContext` does."""
    group = _SIGN_VERIFY["test_groups"][0]
    n = group["n"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    session_ctx = frost.SessionContext(
        n, n + 1, [0], None, thresh_pk, bytes(66), [], [], b"msg"
    )
    with pytest.raises(EccValueError, match=r"1 <= t <= n"):
        frost.session_values(session_ctx)


def test_session_values_refuses_mismatched_pubshares_and_ids_length() -> None:
    """`pub_shares` present and shorter than `ids`."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:1]
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares, thresh_pk, bytes(66), [], [], b"msg"
    )
    with pytest.raises(EccValueError, match="same length"):
        frost.session_values(session_ctx)


def test_partial_sig_verify_refuses_mismatched_list_lengths() -> None:
    """`pub_nonces`, `pub_shares` and `ids` of disagreeing lengths."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_nonces = _hex_all(group["pubnonces"])[:2]
    pub_shares = _hex_all(group["pubshares"])[:1]
    with pytest.raises(EccValueError, match="same length"):
        frost.partial_sig_verify(
            bytes(32),
            pub_nonces,
            n,
            t,
            [0, 1],
            pub_shares,
            thresh_pk,
            [],
            [],
            b"msg",
            0,
        )


def test_partial_sig_verify_refuses_a_signer_index_out_of_range() -> None:
    """`i` outside `0 <= i < len(ids)`."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_nonces = _hex_all(group["pubnonces"])[:1]
    pub_shares = _hex_all(group["pubshares"])[:1]
    with pytest.raises(EccValueError, match="signer index"):
        frost.partial_sig_verify(
            bytes(32),
            pub_nonces,
            n,
            t,
            [0],
            pub_shares,
            thresh_pk,
            [],
            [],
            b"msg",
            1,
        )


def _two_of_three_session() -> tuple[
    frost.SessionContext, bytes, bytes, list[bytes], dict[str, Any]
]:
    """Return the first valid vector's session, partial signature and nonce."""
    group = _SIGN_VERIFY["test_groups"][0]
    case = group["valid_tests"][0]
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])
    nonces = [pub_nonces[i] for i in case["pubnonce_indices"]]
    session_ctx = frost.SessionContext(
        group["n"],
        group["t"],
        case["ids"],
        [pub_shares[i] for i in case["pubshare_indices"]],
        bytes.fromhex(group["thresh_pk"]),
        frost.nonce_agg_var(nonces),
        [],
        [],
        bytes.fromhex(case["msg"]),
    )
    return session_ctx, bytes.fromhex(case["expected"]), nonces[0], pub_shares, group


def test_partial_sig_verify_internal_accepts_the_signer_of_the_session() -> None:
    """The control of the next two tests: they fail for their own reason."""
    session_ctx, psig, pub_nonce, pub_shares, _ = _two_of_three_session()
    assert frost.partial_sig_verify_(psig, 0, pub_nonce, pub_shares[0], session_ctx)


@pytest.mark.parametrize("signer_id", [2, 3, -1, secp256k1.n])
def test_partial_sig_verify_internal_refuses_an_id_outside_the_session(
    signer_id: int,
) -> None:
    """Ids the session lacks: 2, `n`, -1 and the group order are refused.

    The group order is an id `mod_inv` cannot invert.
    """
    session_ctx, psig, pub_nonce, pub_shares, _ = _two_of_three_session()
    with pytest.raises(EccValueError, match="missing from the ids"):
        frost.partial_sig_verify_(
            psig, signer_id, pub_nonce, pub_shares[2], session_ctx
        )


@pytest.mark.parametrize("length", [31, 33])
def test_partial_sig_verify_internal_refuses_a_psig_of_the_wrong_length(
    length: int,
) -> None:
    """A partial signature is 32 bytes: another size is an error."""
    session_ctx, psig, pub_nonce, pub_shares, _ = _two_of_three_session()
    assert len(psig) == 32
    wrong = psig[:length] if length < 32 else psig + b"\x00"
    with pytest.raises(EccValueError):
        frost.partial_sig_verify_(wrong, 0, pub_nonce, pub_shares[0], session_ctx)


def test_partial_sig_verify_internal_refuses_a_pub_share_the_session_lacks() -> None:
    """A valid partial signature is not valid under another signer's share."""
    session_ctx, psig, pub_nonce, pub_shares, _ = _two_of_three_session()
    assert not frost.partial_sig_verify_(psig, 0, pub_nonce, pub_shares[2], session_ctx)
    assert not frost.partial_sig_verify_(psig, 0, pub_nonce, pub_shares[1], session_ctx)


def test_partial_sig_verify_internal_refuses_a_signature_under_a_foreign_key() -> None:
    """The equation holds for a key the signer chose: the session decides.

    The same session without pubshares signs for id 0 under a secret
    share that is not the session's; the equation then holds for that
    share's public key, and only the check against the session refuses it.
    """
    session_ctx, _, pub_nonce, _, group = _two_of_three_session()
    sec_nonce = bytearray(bytes.fromhex(group["secnonces"][0]))
    assert _pub_nonce_of(bytes(sec_nonce)) == pub_nonce
    bare = replace(session_ctx, pub_shares=None)
    sec_share = (1).to_bytes(32, "big")
    foreign = bytes_from_point(mult(1))
    psig = frost.sign(sec_nonce, sec_share, 0, bare)
    assert frost.partial_sig_verify_(psig, 0, pub_nonce, foreign, bare)
    assert not frost.partial_sig_verify_(psig, 0, pub_nonce, foreign, session_ctx)


_NOT_INTEGERS = [True, 1.0, 1.9, "1", b"\x01", None]


@pytest.mark.parametrize("value", _NOT_INTEGERS)
@pytest.mark.parametrize("field_", ["n", "t", "ids", "id"])
def test_session_context_coerces_no_integer(field_: str, value: Any) -> None:
    """1.9 and "1" are refused, not read as 1: other signers would sign."""
    session_ctx, *_ = _two_of_three_session()
    args: dict[str, Any] = {
        "n": 3,
        "t": 2,
        "ids": [0, 1],
        "pub_shares": None,
        "thresh_pk": session_ctx.thresh_pk,
        "agg_nonce": session_ctx.agg_nonce,
        "tweaks": [],
        "is_xonly": [],
        "msg": b"m",
    }
    if field_ == "id":
        args["ids"] = [0, value]
    else:
        args[field_] = value
    with pytest.raises(EccTypeError, match="invalid"):
        frost.SessionContext(**args)


@pytest.mark.parametrize("value", _NOT_INTEGERS)
def test_threshold_info_coerces_no_threshold(value: Any) -> None:
    """`t` as 1.9 or "2" is refused, not read as 1 or 2."""
    group = _SIGN_VERIFY["test_groups"][0]
    with pytest.raises(EccTypeError, match="invalid t type"):
        frost.ThresholdInfo(
            value, bytes.fromhex(group["thresh_pk"]), _hex_all(group["pubshares"])
        )


@pytest.mark.parametrize("value", _NOT_INTEGERS)
def test_the_signing_functions_coerce_no_signer_id(value: Any) -> None:
    """`signer_id` of every entry point that takes one, and the signer index."""
    session_ctx, psig, pub_nonce, pub_shares, _ = _two_of_three_session()
    with pytest.raises(EccTypeError, match="invalid signer_id type"):
        frost.partial_sig_verify_(psig, value, pub_nonce, pub_shares[0], session_ctx)
    with pytest.raises(EccTypeError, match="invalid signer_id type"):
        frost.sign(bytearray(64), bytes(32), value, session_ctx)
    with pytest.raises(EccTypeError, match="invalid signer_id type"):
        frost.deterministic_sign(
            bytes(32),
            value,
            None,
            3,
            2,
            [0, 1],
            None,
            session_ctx.thresh_pk,
            [],
            [],
            b"m",
        )
    with pytest.raises(EccTypeError, match="invalid i type"):
        frost.partial_sig_verify(
            psig,
            [pub_nonce],
            3,
            2,
            [0],
            pub_shares[:1],
            session_ctx.thresh_pk,
            [],
            [],
            b"m",
            value,
        )


@pytest.mark.parametrize("value", _NOT_INTEGERS)
def test_deterministic_sign_and_verify_coerce_no_n_t_or_id(value: Any) -> None:
    """`n`, `t` and `ids` of the entry points that build no context first."""
    session_ctx, psig, pub_nonce, pub_shares, _ = _two_of_three_session()
    thresh_pk = session_ctx.thresh_pk
    for n, t, ids in ((value, 2, [0, 1]), (3, value, [0, 1]), (3, 2, [0, value])):
        with pytest.raises(EccTypeError, match="invalid"):
            frost.deterministic_sign(
                bytes(32), 0, None, n, t, ids, None, thresh_pk, [], [], b"m"
            )
        with pytest.raises(EccTypeError, match="invalid"):
            frost.partial_sig_verify(
                psig,
                [pub_nonce] * 2,
                n,
                t,
                ids,
                pub_shares[:2],
                thresh_pk,
                [],
                [],
                b"m",
                0,
            )


# --------------------------------------------------------------------
# TweakContext.plain_pub_key: no vector calls GetPlainPubkey, so this is
# a direct check against the x-only property every tweak vector already
# exercises -- the two are the same point, compressed and x-only.
# --------------------------------------------------------------------


def test_tweak_context_plain_pub_key() -> None:
    """`plain_pub_key` is the compressed point behind `x_only_pub_key`."""
    group = _TWEAK["test_groups"][0]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    tweak_ctx = frost.tweak_ctx_init_var(thresh_pk)
    assert tweak_ctx.plain_pub_key == thresh_pk
    assert tweak_ctx.plain_pub_key[1:] == tweak_ctx.x_only_pub_key


# --------------------------------------------------------------------
# A secret nonce signs once, `frost.sign`'s own module docstring promise.
# --------------------------------------------------------------------


def test_sec_nonce_signs_once() -> None:
    """Verify signing zeroes the secnonce, so a second sign raises."""
    group = next(g for g in _SIGN_VERIFY["test_groups"] if g["t"] == 1)
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    sec_share = bytes.fromhex(group["secshares"][0])
    sec_nonce, pub_nonce = frost.nonce_gen(sec_share, pub_share=pub_shares[0])
    session_ctx = frost.SessionContext(
        n,
        t,
        [0],
        pub_shares[:1],
        thresh_pk,
        frost.nonce_agg_var([pub_nonce]),
        [],
        [],
        b"m",
    )
    frost.sign(sec_nonce, sec_share, 0, session_ctx)
    # the bytearray has been zeroed in place, which is the whole defence:
    # every byte, and no byte added or taken out of it
    assert sec_nonce == bytearray(64)
    with pytest.raises(
        EccValueError, match="The first half of secnonce is out of range"
    ):
        frost.sign(sec_nonce, sec_share, 0, session_ctx)


# --------------------------------------------------------------------
# `_assert_octets_sequence`'s guard (issue btclib-org/btclib#1405, `musig2`'s
# own reason): reached from a class `__init__`, so the generic walk in
# `tests/input_validation_test.py` does not drive it -- that walk calls
# module-level functions only, never a constructor.
# --------------------------------------------------------------------


def test_threshold_info_refuses_pub_shares_that_is_not_a_sequence_of_them() -> None:
    """`pub_shares` as `Octets`, not a `Sequence` (btclib-org/btclib#1405)."""
    with pytest.raises(EccTypeError, match="invalid pub_shares type"):
        frost.ThresholdInfo(1, bytes(33), b"\xaa\xbb\xcc\xdd")  # type: ignore[arg-type]


# --------------------------------------------------------------------
# `partial_sig_verify_`'s own two parse failures: unreachable through
# the convenience `partial_sig_verify`, which validates every pubshare
# before this is ever called and aggregates every pubnonce through
# `nonce_agg_var`, which raises `InvalidContributionError` on a malformed
# one before this function sees it either -- `musig2_test.py`'s own
# "the bindings have no C equivalent" shape, here with no bindings arm
# to reach it from at all. Called directly, as `sign`'s own module
# docstring says a caller may.
# --------------------------------------------------------------------


def test_partial_sig_verify_internal_refuses_a_malformed_pub_nonce() -> None:
    """A `pub_nonce` that does not decode to two compressed points."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    pub_nonces = _hex_all(group["pubnonces"])
    agg_nonce = frost.nonce_agg_var(pub_nonces[:2])
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares[:2], thresh_pk, agg_nonce, [], [], b"m"
    )
    not_a_point = bytes.fromhex("02" + "ff" * 32) * 2
    assert not frost.partial_sig_verify_(
        bytes(32), 0, not_a_point, pub_shares[0], session_ctx
    )


def test_partial_sig_verify_internal_refuses_a_malformed_pub_share() -> None:
    """A `pub_share` that does not decode to a compressed point."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    pub_nonces = _hex_all(group["pubnonces"])
    agg_nonce = frost.nonce_agg_var(pub_nonces[:2])
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares[:2], thresh_pk, agg_nonce, [], [], b"m"
    )
    not_a_point = bytes.fromhex("02" + "ff" * 32)
    assert not frost.partial_sig_verify_(
        bytes(32), 0, pub_nonces[0], not_a_point, session_ctx
    )


# --------------------------------------------------------------------
# Boundaries the vectors leave unpinned. Each of these is a comparison
# whose two neighbours the vector files never both reach, so a check
# weakened by one step, or loosened to one side only, passes every vector.
# --------------------------------------------------------------------

_G = bytes_from_point(mult(1))


def _one_signer_session(
    sec_share: bytes, msg: bytes = b"m"
) -> tuple[frost.SessionContext, bytearray, bytes]:
    """Return a 1-of-1 session over the key `sec_share` is the secret of.

    The threshold public key is the signer's own public share, which is
    what a threshold of one is: the polynomial is a constant.
    """
    pub_share = bytes_from_point(mult(int.from_bytes(sec_share, "big")))
    sec_nonce, pub_nonce = frost.nonce_gen(sec_share, pub_share=pub_share)
    session_ctx = frost.SessionContext(
        1, 1, [0], [pub_share], pub_share, frost.nonce_agg_var([pub_nonce]), [], [], msg
    )
    return session_ctx, sec_nonce, pub_nonce


@pytest.mark.parametrize("length", [63, 65])
def test_sign_refuses_a_secnonce_of_the_wrong_length(length: int) -> None:
    """The secnonce is 64 bytes, and a refused one is left as it was."""
    sec_share = (5).to_bytes(32, "big")
    session_ctx, sec_nonce, _ = _one_signer_session(sec_share)
    buffer = (sec_nonce + b"\xab")[:length]
    unspent = bytes(buffer)
    with pytest.raises(EccValueError, match="The secnonce must be a 64-byte"):
        frost.sign(buffer, sec_share, 0, session_ctx)
    assert buffer == unspent


@pytest.mark.parametrize("length", [31, 33])
def test_sign_refuses_a_secshare_of_the_wrong_length_before_the_nonce(
    length: int,
) -> None:
    """The secshare is 32 bytes, and its refusal leaves the nonce unspent."""
    session_ctx, sec_nonce, _ = _one_signer_session((5).to_bytes(32, "big"))
    unspent = bytes(sec_nonce)
    with pytest.raises(EccValueError, match="instead of 32"):
        frost.sign(sec_nonce, (5).to_bytes(length, "big"), 0, session_ctx)
    assert sec_nonce == unspent


@pytest.mark.parametrize(
    "k_1, k_2, err_msg",
    [
        (0, 1, "The first half of secnonce is out of range"),
        (secp256k1.n, 1, "The first half of secnonce is out of range"),
        (secp256k1.n + 1, 1, "The first half of secnonce is out of range"),
        (1, 0, "The second half of secnonce is out of range"),
        (1, secp256k1.n, "The second half of secnonce is out of range"),
        (1, secp256k1.n + 1, "The second half of secnonce is out of range"),
    ],
)
def test_sign_refuses_a_secnonce_scalar_outside_the_group_order(
    k_1: int, k_2: int, err_msg: str
) -> None:
    """A secnonce scalar is in 1..n-1, so n is refused and n-1 is not."""
    sec_share = (5).to_bytes(32, "big")
    session_ctx, _, _ = _one_signer_session(sec_share)
    sec_nonce = bytearray(k_1.to_bytes(32, "big") + k_2.to_bytes(32, "big"))
    with pytest.raises(EccValueError, match=err_msg):
        frost.sign(sec_nonce, sec_share, 0, session_ctx)

    largest = bytearray(
        (secp256k1.n - 1).to_bytes(32, "big") + (secp256k1.n - 1).to_bytes(32, "big")
    )
    assert len(frost.sign(largest, sec_share, 0, session_ctx)) == 32


def test_sign_accepts_the_secret_share_one() -> None:
    """1 is the smallest secret share there is, and the key is then G.

    A whole 1-of-1 session over it, through to a BIP340 signature: the
    range of a secret share is 1..n-1 and its lower bound is a share.
    """
    sec_share = (1).to_bytes(32, "big")
    session_ctx, sec_nonce, pub_nonce = _one_signer_session(sec_share)
    assert session_ctx.thresh_pk == _G
    psig = frost.sign(sec_nonce, sec_share, 0, session_ctx)
    assert frost.partial_sig_verify(
        psig, [pub_nonce], 1, 1, [0], [_G], _G, [], [], b"m", 0
    )
    sig = frost.partial_sig_agg([psig], session_ctx)
    assert ssa.verify_(b"m", _G[1:], sig)

    for refused in (bytes(32), secp256k1.n.to_bytes(32, "big")):
        session_ctx, sec_nonce, _ = _one_signer_session(sec_share)
        with pytest.raises(EccValueError, match="The secshare is out of range"):
            frost.sign(sec_nonce, refused, 0, session_ctx)


@pytest.mark.parametrize("signer_id", [-1, 1])
def test_session_values_refuses_an_id_outside_0_to_n_minus_1(signer_id: int) -> None:
    """With `n` of 1 the only identifier is 0: one below and one above go."""
    thresh_pk = bytes.fromhex(_SIGN_VERIFY["test_groups"][0]["thresh_pk"])
    session_ctx = frost.SessionContext(
        1, 1, [signer_id], None, thresh_pk, bytes(66), [], [], b"msg"
    )
    with pytest.raises(EccValueError, match=r"The id at index 0 must satisfy"):
        frost.session_values(session_ctx)


def test_validate_threshold_info_accepts_128_participants() -> None:
    """The bound is `n <= 128`, so 128 is a group and only 129 is not."""
    pub_share = bytes.fromhex(_SIGN_VERIFY["test_groups"][0]["pubshares"][0])
    pub_shares: list[bytes | None] = [pub_share] + [None] * 127
    frost.validate_threshold_info(frost.ThresholdInfo(1, pub_share, pub_shares))


def test_session_values_accepts_128_participants() -> None:
    """The same bound, through the session's own check of `n`."""
    thresh_pk = bytes.fromhex(_SIGN_VERIFY["test_groups"][0]["thresh_pk"])
    session_ctx = frost.SessionContext(
        128, 1, [0], None, thresh_pk, bytes(66), [], [], b"msg"
    )
    assert frost.session_values(session_ctx).Q == frost.tweak_ctx_init_var(thresh_pk).Q


def test_partial_sig_verify_refuses_more_pub_nonces_than_ids() -> None:
    """A surplus pubnonce is a list that disagrees, not one that is enough."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_nonces = _hex_all(group["pubnonces"])[:3]
    pub_shares = _hex_all(group["pubshares"])[:2]
    with pytest.raises(EccValueError, match="same length"):
        frost.partial_sig_verify(
            bytes(32), pub_nonces, n, t, [0, 1], pub_shares, thresh_pk, [], [], b"m", 0
        )


@pytest.mark.parametrize(
    "tweak, err_msg",
    [
        (bytes(31), "The tweak must be a 32-byte array."),
        (bytes(33), "The tweak must be a 32-byte array."),
        (secp256k1.n.to_bytes(32, "big"), "The tweak value is out of range."),
        ((secp256k1.n + 1).to_bytes(32, "big"), "The tweak value is out of range."),
        (b"\xff" * 32, "The tweak value is out of range."),
    ],
)
def test_apply_tweak_refuses_a_tweak_of_the_wrong_size_or_range(
    tweak: bytes, err_msg: str
) -> None:
    """A tweak is 32 bytes and below the group order: n itself is out."""
    thresh_pk = bytes.fromhex(_SIGN_VERIFY["test_groups"][0]["thresh_pk"])
    with pytest.raises(EccValueError, match=err_msg):
        frost.apply_tweak_var(frost.tweak_ctx_init_var(thresh_pk), tweak, False)


def test_apply_tweak_accumulates_residues_of_the_group_order() -> None:
    """`gacc` and `tacc` are what BIP445 says they are: values mod n.

    The signatures only ever read them reduced again, so an accumulator
    left as a multiple of n off, or negative, signs identically; it is
    the context a caller reads back that would say otherwise. An x-only
    tweak of an odd-y key negates it, which is `gacc` of n-1, and the
    second tweak wraps `tacc` past n.
    """
    n = secp256k1.n
    group = next(g for g in _SIGN_VERIFY["test_groups"] if g["thresh_pk"][:2] == "03")
    tweak_ctx = frost.tweak_ctx_init_var(bytes.fromhex(group["thresh_pk"]))
    assert (tweak_ctx.gacc, tweak_ctx.tacc) == (1, 0)

    tweak_ctx = frost.apply_tweak_var(tweak_ctx, (7).to_bytes(32, "big"), True)
    assert (tweak_ctx.gacc, tweak_ctx.tacc) == (n - 1, 7)

    tweak_ctx = frost.apply_tweak_var(tweak_ctx, (n - 1).to_bytes(32, "big"), False)
    assert (tweak_ctx.gacc, tweak_ctx.tacc) == (n - 1, 6)


def test_a_session_context_is_replaced_and_not_carried_over() -> None:
    """`replace` builds another session, whose values are its own.

    The derived values are memoized on the context and are no field of
    it, so what `replace` returns starts without them: a message that
    changed is a challenge that changed, and reading the memo of the
    context it was made from would answer for the wrong session.
    """
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:2]
    agg_nonce = frost.nonce_agg_var(_hex_all(group["pubnonces"])[:2])
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares, thresh_pk, agg_nonce, [], [], b"m"
    )
    values = frost.session_values(session_ctx)

    assert replace(session_ctx, msg=b"m") == session_ctx
    other = replace(session_ctx, msg=b"another message")
    assert other != session_ctx
    assert frost.session_values(other).e != values.e
    assert frost.session_values(session_ctx) is values


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.


def _secret_sign(sec_nonce: Any, sec_share: Any) -> object:
    session_ctx, *_ = _two_of_three_session()
    return frost.sign(sec_nonce, sec_share, 0, session_ctx)


def _secret_deterministic_sign(sec_share: Any, aux_rand: Any = None) -> object:
    session_ctx, _, _, pub_shares, _ = _two_of_three_session()
    return frost.deterministic_sign(
        sec_share,
        0,
        bytes(66),
        session_ctx.n,
        session_ctx.t,
        session_ctx.ids,
        pub_shares[:2],
        session_ctx.thresh_pk,
        [],
        [],
        bytes(32),
        aux_rand,
    )


def _secret_deterministic_sign_aux(aux_rand: Any) -> object:
    return _secret_deterministic_sign((1).to_bytes(32, "big"), aux_rand)


_SECRET_NONCES = ["bytes", "bytearray", "33 bytes", "30 bytes"]

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "nonce_gen": (
        frost.nonce_gen,
        ["0x hex string", "33 bytes", "30 bytes", "WIF"],
    ),
    "sign, secret share": (
        lambda s: _secret_sign(bytearray(bytes.fromhex("01" * 64)), s),
        REFUSED_OCTETS,
    ),
    "sign, wrong secret share": (
        lambda s: _secret_sign(bytearray(bytes.fromhex("01" * 64)), s),
        ["wrong key"],
    ),
    "sign, secret nonce": (
        lambda s: _secret_sign(s, (1).to_bytes(32, "big")),
        _SECRET_NONCES,
    ),
    "sign, secret nonce refused for its value or its pubshare": (
        lambda s: _secret_sign(bytearray(s), (1).to_bytes(32, "big")),
        _SECRET_NONCES,
    ),
    "deterministic_sign": (_secret_deterministic_sign, REFUSED_OCTETS),
    "nonce_gen_, rand_": (
        lambda s: frost.nonce_gen_(s, None, None, None),
        REFUSED_AUX,
    ),
    "nonce_gen, extra_in": (lambda s: frost.nonce_gen(extra_in=s), REFUSED_EXTRA),
    "deterministic_sign, aux_rand": (_secret_deterministic_sign_aux, REFUSED_EXTRA),
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
