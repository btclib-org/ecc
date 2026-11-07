# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc.ecdsa_adaptor` module.

The vectors are the DLC specification's own, `test/ecdsa_adaptor.json`
of discreetlogcontracts/dlcspecs, vendored under `tests/schemes/_data/`;
`tests/_data/README.md` pins the revision. They are read as the
specification's *Specification tests* section says: a `verification`
case runs `verify`, `decrypt` and `recover`, a `recovery` case runs
`decrypt` and `recover`, and a `serialization` case asks whether the
adaptor signature parses. A case with an `error` is one that must fail.

No vector encrypts, the specification leaving the nonce open, so
`encrypt` is held to round trips and to one output of libsecp256k1-zkp,
which `_ZKP_ENCRYPT` cites. The tests marked `zkp` at the end of the file
hold all four operations to `btclib_secp256k1.zkp.ecdsa_adaptor` on random
inputs.
"""

import random
from collections.abc import Callable
from typing import Any

import pytest

from ecc import dsa, ecdsa_adaptor
from ecc.curves import CURVES, bytes_from_point, mult, secp256k1
from ecc.exceptions import EccException, EccValueError
from tests import (
    REFUSED_AUX,
    REFUSED_SCALARS,
    both_arms,
    load,
    needs_zkp,
    refused_secret,
    vector_id,
)
from tests.secret_free import assert_secret_free

# guarded module scope, the same shape `ecc._libsecp256k1` uses: this
# file is collected in every job, the no-bindings one included, and
# pytest imports every module it collects before `needs_zkp` can skip
# anything in it
try:
    from btclib_secp256k1.zkp import ecdsa_adaptor as zkp_ecdsa_adaptor
except ImportError:  # pragma: no cover -- no binding with zkp.ecdsa_adaptor
    zkp_ecdsa_adaptor = None  # type: ignore[assignment]

_VECTORS: list[dict[str, Any]] = load("schemes", "_data", "ecdsa_adaptor.json")
_N = secp256k1.n

_MSG = bytes(range(32))
_X = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_PUB = mult(_X)
_Y = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
_ENC = mult(_Y)
_AUX = bytes(32)
_NONCE = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF


def _ids(kind: str) -> dict[str, Any]:
    cases = [(i, v) for i, v in enumerate(_VECTORS) if v["kind"] == kind]
    return {
        "argvalues": [v for _, v in cases],
        "ids": [vector_id(i, v.get("comment") or v.get("error")) for i, v in cases],
    }


def _sig(vector: dict[str, Any]) -> dsa.Sig:
    # unchecked: a recovery case's r need not be an x-coordinate at all
    return dsa.Sig(
        int(vector["signature"][:64], 16),
        int(vector["signature"][64:], 16),
        check_validity=False,
    )


@pytest.mark.parametrize("vector", **_ids("verification"))
@both_arms
def test_verification_vectors(vector: dict[str, Any]) -> None:
    """Each verification case: verify, then decrypt, then recover."""
    adaptor_sig = vector["adaptor_sig"]
    args = (
        adaptor_sig,
        vector["message_hash"],
        vector["public_signing_key"],
        vector["encryption_key"],
    )
    if vector.get("error"):
        assert not ecdsa_adaptor.verify(*args)
        with pytest.raises(EccValueError, match=vector["error"].split()[0]):
            ecdsa_adaptor.assert_as_valid(*args)
        return

    assert ecdsa_adaptor.verify(*args)
    ecdsa_adaptor.assert_as_valid(*args)
    sig = _sig(vector)
    assert ecdsa_adaptor.decrypt(adaptor_sig, vector["decryption_key"]) == sig
    assert dsa.verify_(vector["message_hash"], vector["public_signing_key"], sig), (
        "the decrypted signature is a signature of the message"
    )
    key = int(vector["decryption_key"], 16)
    assert ecdsa_adaptor.recover(adaptor_sig, sig, vector["encryption_key"]) == key


@pytest.mark.parametrize("vector", **_ids("recovery"))
@both_arms
def test_recovery_vectors(vector: dict[str, Any]) -> None:
    """Each recovery case: the key comes back, or the case is refused."""
    adaptor_sig = vector["adaptor_sig"]
    sig = _sig(vector)
    if vector.get("error"):
        with pytest.raises(EccValueError, match="r does not match"):
            ecdsa_adaptor.recover(adaptor_sig, sig, vector["encryption_key"])
        return

    key = int(vector["decryption_key"], 16)
    assert ecdsa_adaptor.recover(adaptor_sig, sig, vector["encryption_key"]) == key
    decrypted = ecdsa_adaptor.decrypt(adaptor_sig, key)
    # decrypt is low-s, and the case that carries a high-s signature is
    # the one where that is the only difference
    assert decrypted.r == sig.r
    assert decrypted.s == min(sig.s, _N - sig.s)


@pytest.mark.parametrize("vector", **_ids("serialization"))
@both_arms
def test_serialization_vectors(vector: dict[str, Any]) -> None:
    """Each serialization case parses, or is refused: `verify` says False."""
    adaptor_sig = vector["adaptor_sig"]
    if vector.get("error"):
        with pytest.raises(EccValueError):
            ecdsa_adaptor.decrypt(adaptor_sig, 1)
        with pytest.raises(EccValueError):
            ecdsa_adaptor.assert_as_valid(adaptor_sig, _MSG, _PUB, _ENC)
        assert not ecdsa_adaptor.verify(adaptor_sig, _MSG, _PUB, _ENC)
        return

    ecdsa_adaptor.decrypt(adaptor_sig, 1)
    # parsed, and a proof that does not hold is False and not an error
    assert not ecdsa_adaptor.verify(adaptor_sig, _MSG, _PUB, _ENC)


def test_encrypt_round_trip() -> None:
    """An adaptor signature verifies, decrypts and gives y back."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    assert len(adaptor_sig) == 162
    assert ecdsa_adaptor.verify(adaptor_sig, _MSG, _PUB, _ENC)
    sig = ecdsa_adaptor.decrypt(adaptor_sig, _Y)
    assert sig.s <= _N // 2
    assert dsa.verify_(_MSG, _PUB, sig)
    assert ecdsa_adaptor.recover(adaptor_sig, sig, _ENC) == _Y
    assert ecdsa_adaptor.recover(adaptor_sig, sig.serialize(), _ENC) == _Y


@pytest.mark.parametrize("y", [_Y, _N - _Y])
def test_recover_gives_y_for_both_signs(y: int) -> None:
    """A decryption key and its negation make one low-s signature.

    So recovery must name the key of the encryption key it was given:
    for one of the two the signature before low-s normalization is
    the high one, which is the negation branch.
    """
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    sig = ecdsa_adaptor.decrypt(adaptor_sig, y)
    assert dsa.verify_(_MSG, _PUB, sig)
    assert ecdsa_adaptor.recover(adaptor_sig, sig, _ENC) == _Y
    negated = (_ENC[0], secp256k1.p - _ENC[1])
    assert ecdsa_adaptor.recover(adaptor_sig, sig, negated) == _N - _Y


# What libsecp256k1-zkp's `secp256k1_ecdsa_adaptor_encrypt` answers
# (BlockstreamResearch/secp256k1-zkp at 8e1f96c2, default nonce function)
# for the message `_MSG`, the key `_X`, the encryption key `_ENC` and an
# all-zero `ndata`, which is `_AUX`
_ZKP_ENCRYPT = "027ea6931e6a3362ba0fa14d23d7869b8358a85d211f763d8ec0a4b46978c029cb0320c20271fc3ba96c6a37a61d93c1ee0c89e132ff203d349a5c86e9b2f68c8f9ab83e59b7f7b407edd39cebb7848485428b9003e5dba1f56a0d33df3b59ba1ef3c997786985602c6a1f8bbbdb0d976bce42b11eadff7988d97a0d2e1331ab87022e4f915114e9fe3ab989db88e1b2dce3b4d6b55f625e05cf31efb00657b7d9e8"


def test_encrypt_matches_libsecp256k1_zkp() -> None:
    """The default nonce is zkp's: the same arguments give the same octets."""
    assert ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX).hex() == _ZKP_ENCRYPT


def test_encrypt_is_deterministic_in_aux() -> None:
    """The same arguments give the same bytes; another aux gives another."""
    first = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    assert first == ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    other = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, b"\x01" * 32)
    assert other != first
    assert ecdsa_adaptor.verify(other, _MSG, _PUB, _ENC)
    # and a fresh aux is drawn when none is given
    assert ecdsa_adaptor.encrypt(_MSG, _X, _ENC) != ecdsa_adaptor.encrypt(
        _MSG, _X, _ENC
    )


def test_encrypt_nonce_fixes_k() -> None:
    """A given nonce is k: R_a = k*G and R = k*Y."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX, nonce=_NONCE)
    assert adaptor_sig[:33] == bytes_from_point(mult(_NONCE, _ENC), secp256k1)
    assert adaptor_sig[33:66] == bytes_from_point(mult(_NONCE), secp256k1)
    assert ecdsa_adaptor.verify(adaptor_sig, _MSG, _PUB, _ENC)
    with pytest.raises(EccValueError):
        ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX, nonce=0)


def test_verify_is_false_for_the_wrong_statement() -> None:
    """Another message, signing key or encryption key does not verify."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    assert not ecdsa_adaptor.verify(adaptor_sig, bytes(32), _PUB, _ENC)
    assert not ecdsa_adaptor.verify(adaptor_sig, _MSG, mult(2), _ENC)
    assert not ecdsa_adaptor.verify(adaptor_sig, _MSG, _PUB, mult(2))
    with pytest.raises(EccValueError, match="does not match"):
        ecdsa_adaptor.assert_as_valid(adaptor_sig, _MSG, mult(2), _ENC)


def _with(adaptor_sig: bytes, start: int, field: bytes) -> bytes:
    return adaptor_sig[:start] + field + adaptor_sig[start + len(field) :]


def test_verify_false_for_a_tampered_signature() -> None:
    """A changed s_a fails the equation, a changed proof fails the proof."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    s_a = int.from_bytes(adaptor_sig[66:98], "big")
    bumped = _with(adaptor_sig, 66, (s_a % (_N - 1) + 1).to_bytes(32, "big"))
    assert not ecdsa_adaptor.verify(bumped, _MSG, _PUB, _ENC)
    with pytest.raises(EccValueError, match="does not match"):
        ecdsa_adaptor.assert_as_valid(bumped, _MSG, _PUB, _ENC)

    e = int.from_bytes(adaptor_sig[98:130], "big")
    flipped = _with(adaptor_sig, 98, (e ^ 1).to_bytes(32, "big"))
    assert not ecdsa_adaptor.verify(flipped, _MSG, _PUB, _ENC)
    with pytest.raises(EccValueError, match="challenge"):
        ecdsa_adaptor.assert_as_valid(flipped, _MSG, _PUB, _ENC)


def test_verify_false_for_a_proof_through_infinity() -> None:
    """A proof with e = 1 and s = k puts A_G at infinity; no honest one does."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX, nonce=_NONCE)
    forged = _with(
        adaptor_sig, 98, (1).to_bytes(32, "big") + _NONCE.to_bytes(32, "big")
    )
    assert not ecdsa_adaptor.verify(forged, _MSG, _PUB, _ENC)
    with pytest.raises(EccValueError, match="infinity"):
        ecdsa_adaptor.assert_as_valid(forged, _MSG, _PUB, _ENC)


def test_verify_refuses_what_cannot_be_read() -> None:
    """A wrong size or a key that is no point is an error, not a False."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    with pytest.raises(EccValueError):
        ecdsa_adaptor.verify(adaptor_sig[:-1], _MSG, _PUB, _ENC)
    with pytest.raises(EccValueError):
        ecdsa_adaptor.verify(adaptor_sig, _MSG[:-1], _PUB, _ENC)
    with pytest.raises(EccValueError):
        ecdsa_adaptor.verify(adaptor_sig, _MSG, "00", _ENC)
    with pytest.raises(EccValueError):
        ecdsa_adaptor.verify(adaptor_sig, _MSG, _PUB, "00")


def test_verify_is_false_for_an_unacceptable_adaptor_signature() -> None:
    """Of the right size but out of the specification's range: False."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    bad_point = _with(adaptor_sig, 0, b"\x05" + bytes(32))
    big_s = _with(adaptor_sig, 130, _N.to_bytes(32, "big"))
    for bad, why in ((bad_point, "point"), (big_s, "proof s")):
        assert not ecdsa_adaptor.verify(bad, _MSG, _PUB, _ENC)
        with pytest.raises(EccValueError, match=why):
            ecdsa_adaptor.assert_as_valid(bad, _MSG, _PUB, _ENC)
    for s_a in (0, _N):
        bad = _with(adaptor_sig, 66, s_a.to_bytes(32, "big"))
        assert not ecdsa_adaptor.verify(bad, _MSG, _PUB, _ENC)


def test_proof_e_is_reduced_modulo_n() -> None:
    """A proof e of n or above is read modulo n, as the reference reads it."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    for e in (_N, _N + 5):
        parsed = ecdsa_adaptor._parse_var(_with(adaptor_sig, 98, e.to_bytes(32, "big")))
        assert parsed[3] == e - _N


def test_r_of_zero_modulo_n_is_refused() -> None:
    """An R with x = n is on the curve and has r = 0, which is no ECDSA r."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    zero_r = _with(adaptor_sig, 0, b"\x02" + _N.to_bytes(32, "big"))
    assert not ecdsa_adaptor.verify(zero_r, _MSG, _PUB, _ENC)
    with pytest.raises(EccValueError, match="zero x-coordinate"):
        ecdsa_adaptor.decrypt(zero_r, 1)


def test_decrypt_refuses_a_bad_key() -> None:
    """The decryption key is a private key: 0 and n are not."""
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    for key in (0, _N):
        with pytest.raises(EccValueError):
            ecdsa_adaptor.decrypt(adaptor_sig, key)


def test_recover_refuses_what_is_not_a_decryption() -> None:
    """Refuse what is not a decryption of this adaptor signature.

    Another adaptor signature's r, another key, an s out of range, an s
    that does not decrypt to enc_key, another curve.
    """
    adaptor_sig = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX)
    sig = ecdsa_adaptor.decrypt(adaptor_sig, _Y)

    other = ecdsa_adaptor.encrypt(_MSG, _X, _ENC, _AUX, nonce=_NONCE)
    with pytest.raises(EccValueError, match="r does not match"):
        ecdsa_adaptor.recover(other, sig, _ENC)

    with pytest.raises(EccValueError, match="does not decrypt"):
        ecdsa_adaptor.recover(adaptor_sig, sig, mult(2))

    out_of_range = dsa.Sig(sig.r, sig.s + _N, check_validity=False)
    with pytest.raises(EccValueError, match="s not in"):
        ecdsa_adaptor.recover(adaptor_sig, out_of_range, _ENC)

    wrong_s = dsa.Sig(sig.r, sig.s % (_N - 1) + 1)
    with pytest.raises(EccValueError, match="does not decrypt"):
        ecdsa_adaptor.recover(adaptor_sig, wrong_s, _ENC)

    other_curve = dsa.Sig(sig.r, sig.s, CURVES["secp256r1"], check_validity=False)
    with pytest.raises(EccValueError, match="secp256k1"):
        ecdsa_adaptor.recover(adaptor_sig, other_curve, _ENC)


def _zkp_cases(count: int) -> list[tuple[bytes, int, bytes, int, bytes, bytes]]:
    """Return (msg, x, X, y, Y, aux), keys as SEC compressed octets."""
    rng = random.Random(172)
    cases = []
    for _ in range(count):
        x = 1 + rng.randrange(_N - 1)
        y = 1 + rng.randrange(_N - 1)
        pub = bytes_from_point(mult(x), secp256k1)
        enc = bytes_from_point(mult(y), secp256k1)
        cases.append((rng.randbytes(32), x, pub, y, enc, rng.randbytes(32)))
    return cases


_ZKP_CASES = _zkp_cases(32)

# `pragma: no cover` on the marker's line of each test below, as
# `tests/schemes/commit_nonce_test.py` does and for the reason it gives: an
# unflagged build skips them


@needs_zkp  # pragma: no cover -- no zkp.ecdsa_adaptor.encrypt to compare with
@pytest.mark.parametrize("case", _ZKP_CASES, ids=range(len(_ZKP_CASES)))
def test_encrypt_matches_zkp(case: tuple[bytes, int, bytes, int, bytes, bytes]) -> None:
    """The same message, keys and aux give the same 162 octets."""
    msg, x, _, _, enc, aux = case
    assert ecdsa_adaptor.encrypt(msg, x, enc, aux) == zkp_ecdsa_adaptor.encrypt(
        msg, x, enc, aux_rand32=aux
    )


@needs_zkp  # pragma: no cover -- no zkp.ecdsa_adaptor.verify to compare with
@pytest.mark.parametrize("case", _ZKP_CASES, ids=range(len(_ZKP_CASES)))
def test_verify_agrees_with_zkp(
    case: tuple[bytes, int, bytes, int, bytes, bytes],
) -> None:
    """Both accept either adaptor signature and refuse the same changes."""
    msg, x, pub, y, enc, aux = case
    for adaptor_sig in (
        ecdsa_adaptor.encrypt(msg, x, enc, aux),
        zkp_ecdsa_adaptor.encrypt(msg, x, enc, aux_rand32=aux),
    ):
        assert ecdsa_adaptor.verify(adaptor_sig, msg, pub, enc)
        assert zkp_ecdsa_adaptor.verify(adaptor_sig, pub, msg, enc)

        other_pub = bytes_from_point(mult(x + 1), secp256k1)
        other_enc = bytes_from_point(mult(y + 1), secp256k1)
        refused = [
            (adaptor_sig, bytes([msg[0] ^ 1]) + msg[1:], pub, enc),
            (adaptor_sig, msg, other_pub, enc),
            (adaptor_sig, msg, pub, other_enc),
        ]
        # a change in each field: R, R_a, s_a, e and s
        refused += [
            (_with(adaptor_sig, i, bytes([adaptor_sig[i] ^ 1])), msg, pub, enc)
            for i in (0, 33, 66, 98, 130)
        ]
        for sig_, m_, p_, e_ in refused:
            assert not ecdsa_adaptor.verify(sig_, m_, p_, e_)
            assert not zkp_ecdsa_adaptor.verify(sig_, p_, m_, e_)


@needs_zkp  # pragma: no cover -- no zkp.ecdsa_adaptor.decrypt to compare with
@pytest.mark.parametrize("case", _ZKP_CASES, ids=range(len(_ZKP_CASES)))
def test_decrypt_matches_zkp(case: tuple[bytes, int, bytes, int, bytes, bytes]) -> None:
    """The low-s signature is the same, for a key and for its negation."""
    msg, x, pub, y, enc, aux = case
    adaptor_sig = ecdsa_adaptor.encrypt(msg, x, enc, aux)
    for key in (y, _N - y):
        sig = ecdsa_adaptor.decrypt(adaptor_sig, key)
        zkp_sig = zkp_ecdsa_adaptor.decrypt(key, adaptor_sig)
        assert dsa._compact(sig) == zkp_sig
        assert dsa.verify_(msg, pub, sig)


@needs_zkp  # pragma: no cover -- no zkp.ecdsa_adaptor.recover to compare with
@pytest.mark.parametrize("case", _ZKP_CASES, ids=range(len(_ZKP_CASES)))
def test_recover_matches_zkp(case: tuple[bytes, int, bytes, int, bytes, bytes]) -> None:
    """The same key comes back for an encryption key and for its negation."""
    msg, x, _, y, enc, aux = case
    adaptor_sig = zkp_ecdsa_adaptor.encrypt(msg, x, enc, aux_rand32=aux)
    sig = ecdsa_adaptor.decrypt(adaptor_sig, y)
    zkp_sig = zkp_ecdsa_adaptor.decrypt(y, adaptor_sig)
    negated = bytes([enc[0] ^ 1]) + enc[1:]
    for key, enc_key in ((y, enc), (_N - y, negated)):
        zkp_key = zkp_ecdsa_adaptor.recover(zkp_sig, adaptor_sig, enc_key)
        assert zkp_key == key.to_bytes(32, "big")
        assert ecdsa_adaptor.recover(adaptor_sig, sig, enc_key) == key

    # both refuse a signature that is no decryption under this key
    other = bytes_from_point(mult(y + 1), secp256k1)
    with pytest.raises(ValueError, match="does not match"):
        zkp_ecdsa_adaptor.recover(zkp_sig, adaptor_sig, other)
    with pytest.raises(EccValueError):
        ecdsa_adaptor.recover(adaptor_sig, sig, other)


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.

_ENC_KEY = bytes_from_point(mult(7))

_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "encrypt, private key": (
        lambda s: ecdsa_adaptor.encrypt(_MSG, s, _ENC_KEY),
        REFUSED_SCALARS,
    ),
    "encrypt, nonce": (
        lambda s: ecdsa_adaptor.encrypt(_MSG, 1, _ENC_KEY, nonce=s),
        REFUSED_SCALARS,
    ),
    "decrypt": (
        lambda s: ecdsa_adaptor.decrypt(ecdsa_adaptor.encrypt(_MSG, 1, _ENC_KEY), s),
        REFUSED_SCALARS,
    ),
    "encrypt, aux": (
        lambda s: ecdsa_adaptor.encrypt(_MSG, 1, _ENC_KEY, s),
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
