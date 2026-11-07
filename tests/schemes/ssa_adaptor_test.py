# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.ssa_adaptor` module.

The vectors are `test_schnorr_adaptor_spec_vectors` of the
`schnorr_adaptor` module BlockstreamResearch/secp256k1-zkp#299
proposes, transcribed into `tests/schemes/_data/`; `tests/_data/README.md`
pins the revision. Each case keeps upstream's array names, and its
`checks` are the helpers upstream calls on it, with their flags.
"""

from collections.abc import Callable
from hashlib import sha256
from typing import Any

import pytest

from ecc import ssa, ssa_adaptor
from ecc.curves import CURVES, bytes_from_point, mult, point_from_pub_key
from ecc.curves import secp256k1 as ec
from ecc.exceptions import EccException, EccValueError
from tests import (
    REFUSED_AUX,
    REFUSED_SCALARS,
    both_arms,
    load,
    refused_secret,
    vector_id,
)
from tests.secret_free import assert_secret_free

_VECTORS: list[dict[str, Any]] = load(
    "schemes", "_data", "zkp_schnorr_adaptor_vectors.json"
)

_MSG = bytes(range(32))
_D = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_X_P = mult(_D)[0]
_T_SEC = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
_T = mult(_T_SEC)
_AUX = bytes(32)


def _ids(check: str) -> dict[str, Any]:
    cases = [(i, v) for i, v in enumerate(_VECTORS) if check in v["checks"]]
    return {
        "argvalues": [v for _, v in cases],
        "ids": [vector_id(i, v["id"]) for i, v in cases],
    }


@pytest.mark.parametrize("vector", **_ids("check_presigning"))
@both_arms
def test_presign_vectors(vector: dict[str, Any]) -> None:
    """The pre-signature is upstream's, octet for octet, as is the key."""
    pre_sig = ssa_adaptor.presign(
        vector["msg"], vector["sk"], vector["adaptor"], vector["aux_rand"]
    )
    assert pre_sig.hex() == vector["pre_sig"]
    assert ssa.gen_keys(vector["sk"])[1].to_bytes(32, "big").hex() == vector["pk"]


@pytest.mark.parametrize("vector", **_ids("check_extract"))
@both_arms
def test_extract_vectors(vector: dict[str, Any]) -> None:
    """Extract succeeds or not, and finds the adaptor point or not."""
    flags = vector["checks"]["check_extract"]
    args = (vector["pre_sig"], vector["msg"], vector["pk"])
    T = point_from_pub_key(vector["adaptor"])
    if flags["extract_success"]:
        assert (ssa_adaptor.extract_var(*args) == T) is flags["extracted_val_correct"]
    else:
        with pytest.raises(EccValueError):
            ssa_adaptor.extract_var(*args)
    assert ssa_adaptor.verify(*args, T) is flags["extracted_val_correct"]


@pytest.mark.parametrize("vector", **_ids("check_adapt"))
@both_arms
def test_adapt_vectors(vector: dict[str, Any]) -> None:
    """Adapt gives upstream's octets, which verify or not as upstream says."""
    sig = ssa_adaptor.adapt(vector["pre_sig"], vector["sec_adaptor"])
    assert sig.serialize().hex() == vector["sig"]
    expected = vector["checks"]["check_adapt"]["expected"]
    assert ssa.verify_(vector["msg"], vector["pk"], sig) is expected


@pytest.mark.parametrize("vector", **_ids("check_extract_sec"))
@both_arms
def test_extract_adaptor_vectors(vector: dict[str, Any]) -> None:
    """The secret is upstream's, or not, as upstream says."""
    t = ssa_adaptor.extract_adaptor_var(vector["sig"], vector["pre_sig"])
    expected = vector["checks"]["check_extract_sec"]["expected"]
    assert (t.to_bytes(32, "big").hex() == vector["sec_adaptor"]) is expected


@pytest.mark.parametrize("vector", **_ids("xonly_pubkey_parse"))
@both_arms
def test_unparsable_key_vectors(vector: dict[str, Any]) -> None:
    """A key upstream does not parse is refused here too."""
    with pytest.raises(EccValueError):
        ssa.point_from_bip340pub_key_var(vector["pk"])


@pytest.mark.parametrize("vector", **_ids("ec_pubkey_parse"))
@both_arms
def test_unparsable_adaptor_vectors(vector: dict[str, Any]) -> None:
    """An adaptor point upstream does not parse is refused here too."""
    with pytest.raises(EccValueError):
        ssa_adaptor.presign(_MSG, _D, vector["adaptor"], _AUX)


@pytest.mark.parametrize("d", [_D, ec.n - _D])
@pytest.mark.parametrize("nonce", range(1, 9))
def test_round_trip(d: int, nonce: int) -> None:
    """Presign, verify, adapt into a BIP340 signature, extract the secret.

    Over both keys of one x-only key, and nonces whose R' has either
    parity.
    """
    pre_sig = ssa_adaptor.presign(_MSG, d, _T, _AUX, nonce=nonce)
    assert ssa_adaptor.verify(pre_sig, _MSG, _X_P, _T)
    assert ssa_adaptor.extract_var(pre_sig, _MSG, _X_P) == _T
    sig = ssa_adaptor.adapt(pre_sig, _T_SEC)
    assert ssa.verify_(_MSG, _X_P, sig)
    assert ssa_adaptor.extract_adaptor_var(sig, pre_sig) == _T_SEC
    assert ssa_adaptor.extract_adaptor_var(sig.serialize(), pre_sig) == _T_SEC


def test_round_trip_reaches_both_parities() -> None:
    """The nonces above give R' of either parity, so both branches run."""
    prefixes = {
        ssa_adaptor.presign(_MSG, _D, _T, _AUX, nonce=k)[0] for k in range(1, 9)
    }
    assert prefixes == {2, 3}


def test_presign_default_nonce() -> None:
    """The derived nonce verifies; aux changes it; no aux draws a fresh one."""
    pre_sig = ssa_adaptor.presign(_MSG, _D, _T, _AUX)
    assert pre_sig == ssa_adaptor.presign(_MSG, _D, _T, _AUX)
    assert ssa_adaptor.verify(pre_sig, _MSG, _X_P, _T)
    assert pre_sig != ssa_adaptor.presign(_MSG, _D, _T, b"\x01" * 32)
    fresh = ssa_adaptor.presign(_MSG, _D, _T)
    assert fresh != ssa_adaptor.presign(_MSG, _D, _T)
    assert ssa_adaptor.verify(fresh, _MSG, _X_P, _T)


def test_presign_nonce_fixes_k() -> None:
    """A given nonce is k: R' = k*G + T."""
    k = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    pre_sig = ssa_adaptor.presign(_MSG, _D, _T, _AUX, nonce=k)
    assert pre_sig[:33] == bytes_from_point(ec.add_var(mult(k), _T))
    with pytest.raises(EccValueError):
        ssa_adaptor.presign(_MSG, _D, _T, _AUX, nonce=0)


def test_a_reused_nonce_reveals_the_key() -> None:
    """Two pre-signatures with one k give d: the module docstring's warning."""
    k = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    other_msg = bytes(32)
    first = ssa_adaptor.presign(_MSG, _D, _T, _AUX, nonce=k)
    second = ssa_adaptor.presign(other_msg, _D, _T, _AUX, nonce=k)
    x_R = int.from_bytes(first[1:33], "big")
    e1 = ssa.challenge_(_MSG, _X_P, x_R, ec, sha256)
    e2 = ssa.challenge_(other_msg, _X_P, x_R, ec, sha256)
    s1 = int.from_bytes(first[33:], "big")
    s2 = int.from_bytes(second[33:], "big")
    d = (s1 - s2) * pow(e1 - e2, -1, ec.n) % ec.n
    assert mult(d)[0] == _X_P


def test_presign_refuses_a_nonce_point_at_infinity() -> None:
    """K = -t makes k*G + T infinity, which has no encoding."""
    with pytest.raises(EccValueError, match="infinity"):
        ssa_adaptor.presign(_MSG, _D, _T, _AUX, nonce=ec.n - _T_SEC)


def test_extract_refuses_an_adaptor_point_at_infinity() -> None:
    """A BIP340 signature written as a pre-signature has T at infinity."""
    sig = ssa.sign_(_MSG, _D, _AUX)
    pre_sig = b"\x02" + sig.serialize()
    with pytest.raises(EccValueError, match="adaptor point is infinity"):
        ssa_adaptor.extract_var(pre_sig, _MSG, _X_P)
    assert not ssa_adaptor.verify(pre_sig, _MSG, _X_P, _T)


def test_verify_is_false_for_the_wrong_statement() -> None:
    """Another message, key or adaptor point does not verify."""
    pre_sig = ssa_adaptor.presign(_MSG, _D, _T, _AUX)
    assert not ssa_adaptor.verify(pre_sig, bytes(32), _X_P, _T)
    assert not ssa_adaptor.verify(pre_sig, _MSG, mult(2), _T)
    assert not ssa_adaptor.verify(pre_sig, _MSG, _X_P, mult(2))
    with pytest.raises(EccValueError, match="not for this adaptor"):
        ssa_adaptor.assert_as_valid(pre_sig, _MSG, _X_P, mult(2))


def test_verify_refuses_what_cannot_be_read() -> None:
    """A wrong size or a key that is no key is an error, not a False."""
    pre_sig = ssa_adaptor.presign(_MSG, _D, _T, _AUX)
    with pytest.raises(EccValueError):
        ssa_adaptor.verify(pre_sig[:-1], _MSG, _X_P, _T)
    with pytest.raises(EccValueError):
        ssa_adaptor.verify(pre_sig, _MSG[:-1], _X_P, _T)
    with pytest.raises(EccValueError):
        ssa_adaptor.verify(pre_sig, _MSG, "00", _T)
    with pytest.raises(EccValueError):
        ssa_adaptor.verify(pre_sig, _MSG, _X_P, "00")


def test_adapt_with_the_wrong_secret_does_not_verify() -> None:
    """Adapt does not check its result."""
    pre_sig = ssa_adaptor.presign(_MSG, _D, _T, _AUX)
    sig = ssa_adaptor.adapt(pre_sig, _T_SEC + 1)
    assert not ssa.verify_(_MSG, _X_P, sig)
    with pytest.raises(EccValueError):
        ssa_adaptor.adapt(pre_sig, 0)


def test_extract_adaptor_refuses_what_is_not_an_adaptation() -> None:
    """Another r, an s out of range, another curve: refused."""
    pre_sig = ssa_adaptor.presign(_MSG, _D, _T, _AUX)
    sig = ssa_adaptor.adapt(pre_sig, _T_SEC)

    other = ssa.sign_(_MSG, _D, _AUX)
    with pytest.raises(EccValueError, match="r does not match"):
        ssa_adaptor.extract_adaptor_var(other, pre_sig)

    out_of_range = ssa.Sig(sig.r, sig.s + ec.n, check_validity=False)
    with pytest.raises(EccValueError, match="s not in"):
        ssa_adaptor.extract_adaptor_var(out_of_range, pre_sig)

    other_curve = ssa.Sig(sig.r, sig.s, CURVES["secp256r1"], check_validity=False)
    with pytest.raises(EccValueError, match="secp256k1"):
        ssa_adaptor.extract_adaptor_var(other_curve, pre_sig)


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_ADAPTOR = bytes_from_point(mult(7))

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "presign, private key": (
        lambda s: ssa_adaptor.presign(_MSG, s, _ADAPTOR),
        REFUSED_SCALARS,
    ),
    "presign, nonce": (
        lambda s: ssa_adaptor.presign(_MSG, 1, _ADAPTOR, nonce=s),
        REFUSED_SCALARS,
    ),
    "adapt": (
        lambda s: ssa_adaptor.adapt(ssa_adaptor.presign(_MSG, 1, _ADAPTOR), s),
        REFUSED_SCALARS,
    ),
    "presign, aux": (
        lambda s: ssa_adaptor.presign(_MSG, 1, _ADAPTOR, s),
        REFUSED_AUX,
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
