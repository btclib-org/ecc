# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`set_libsecp256k1_serving(required=True)`: a declined call raises.

Each case is a call the bindings decline because of what the caller chose.
Without `required` it runs the Python arithmetic and answers; with it, it
raises `EccRuntimeError` and never reaches that arithmetic.
"""

import functools
from collections.abc import Callable, Iterator
from hashlib import sha256, sha512
from typing import Any

import pytest

from ecc._libsecp256k1 import ENABLED
from ecc.alias import INF
from ecc.curves import (
    CURVES,
    bytes_from_point,
    is_libsecp256k1_serving,
    mult,
    secp256k1,
    set_libsecp256k1_serving,
)
from ecc.ecc import dsa, musig2, ssa
from ecc.exceptions import (
    EccRuntimeError,
    EccTypeError,
    EccValueError,
)
from tests import needs_bindings

pytestmark = needs_bindings

_PRV_KEY = 0x1234567890ABCDEF
_MSG_HASH = sha256(b"strict").digest()
_NONCE = 0xDEADBEEF
_COMMIT_HASH = sha256(b"commit").digest()
_MSG32 = bytes(range(32))
_SK_1 = bytes(range(1, 33))


@functools.lru_cache(maxsize=1)
def _wrapped_sha256() -> Callable[[], Any]:
    return functools.partial(sha256)


def _adaptor_verify() -> bool:
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG32)
    adaptor = bytes_from_point(mult(12345, ec=secp256k1), secp256k1)
    ctx = musig2.SessionContext(
        musig2.nonce_agg_var([pub_nonce]), [pk_1], [], [], _MSG32, adaptor
    )
    psig = musig2.sign(sec_nonce, _SK_1, ctx)
    return musig2.partial_sig_verify_(psig, pub_nonce, pk_1, ctx)


_SIG = dsa.sign_(_MSG_HASH, _PRV_KEY)
_PUB_KEY = mult(_PRV_KEY)
_SSA_SIG = ssa.sign_(_MSG_HASH, _PRV_KEY)
_SSA_PUB_KEY = bytes_from_point(_PUB_KEY, secp256k1)[1:]

# built here, while the mode is off, to be used where it is on
_DSA_SIGNER = dsa.Signer(_PRV_KEY, hf=_wrapped_sha256())
_SSA_SIGNER = ssa.Signer(_PRV_KEY, hf=_wrapped_sha256())

# name -> a call the bindings decline for the caller's choice. The first
# three are the cases of the issue this mode answers (btclib-org/ecc#224)
_DECLINED: dict[str, Callable[[], Any]] = {
    "dsa.sign lower_s=False": lambda: dsa.sign(_MSG_HASH, _PRV_KEY, lower_s=False),
    "dsa.sign caller nonce": lambda: dsa.sign(
        _MSG_HASH, _PRV_KEY, nonce=_NONCE, grind=False
    ),
    "dsa.sign wrapped hf": lambda: dsa.sign(_MSG_HASH, _PRV_KEY, hf=_wrapped_sha256()),
    "dsa.Signer.sign_ built before": lambda: _DSA_SIGNER.sign_(_MSG_HASH),
    "ssa.Signer.sign_ built before": lambda: _SSA_SIGNER.sign_(_MSG_HASH),
    "dsa.recover_sec_ wrapped hf": lambda: dsa.recover_sec_(
        0, _MSG_HASH, _SIG, hf=_wrapped_sha256()
    ),
    "ssa.batch_verify_ one, wrapped hf": lambda: ssa.batch_verify_(
        [_MSG_HASH], [_SSA_PUB_KEY], [_SSA_SIG], hf=_wrapped_sha256()
    ),
    "ssa.batch_verify_ two, wrapped hf": lambda: ssa.batch_verify_(
        [_MSG_HASH] * 2, [_SSA_PUB_KEY] * 2, [_SSA_SIG] * 2, hf=_wrapped_sha256()
    ),
    "ssa.batch_verify one, wrapped hf": lambda: ssa.batch_verify(
        [b"strict"], [_SSA_PUB_KEY], [_SSA_SIG], hf=_wrapped_sha256()
    ),
    "ssa.batch_verify two, wrapped hf": lambda: ssa.batch_verify(
        [b"strict"] * 2, [_SSA_PUB_KEY] * 2, [_SSA_SIG] * 2, hf=_wrapped_sha256()
    ),
    "dsa.sign commit_hash": lambda: dsa.sign_(
        _MSG_HASH, _PRV_KEY, commit_hash=_COMMIT_HASH, grind=False
    ),
    "dsa.sign_recoverable nonce": lambda: dsa.sign_recoverable_(
        _MSG_HASH, _PRV_KEY, nonce=_NONCE
    ),
    "dsa.sign_recoverable lower_s=False": lambda: dsa.sign_recoverable_(
        _MSG_HASH, _PRV_KEY, lower_s=False
    ),
    "dsa.verify_ wrapped hf": lambda: dsa.verify_(
        _MSG_HASH, _PUB_KEY, _SIG, hf=_wrapped_sha256()
    ),
    "dsa.verify wrapped hf": lambda: dsa.verify(
        b"strict", _PUB_KEY, _SIG, hf=_wrapped_sha256()
    ),
    "dsa.Signer wrapped hf": lambda: dsa.Signer(_PRV_KEY, hf=_wrapped_sha256()),
    "dsa.recover_pub_keys wrapped hf": lambda: dsa.recover_pub_keys_(
        _MSG_HASH, _SIG, hf=_wrapped_sha256()
    ),
    "dsa.recover_pub_key wrapped hf": lambda: dsa.recover_pub_key_(
        0, _MSG_HASH, _SIG, hf=_wrapped_sha256()
    ),
    "ssa.sign commit_hash": lambda: ssa.sign_(
        _MSG_HASH, _PRV_KEY, commit_hash=_COMMIT_HASH
    ),
    "ssa.sign wrapped hf": lambda: ssa.sign_(_MSG_HASH, _PRV_KEY, hf=_wrapped_sha256()),
    "ssa.verify_ wrapped hf": lambda: ssa.verify_(
        _MSG_HASH, _SSA_PUB_KEY, _SSA_SIG, hf=_wrapped_sha256()
    ),
    "ssa.verify wrapped hf": lambda: ssa.verify(
        b"strict", _SSA_PUB_KEY, _SSA_SIG, hf=_wrapped_sha256()
    ),
    "ssa.Signer wrapped hf": lambda: ssa.Signer(_PRV_KEY, hf=_wrapped_sha256()),
    "musig2.partial_sig_verify_ adaptor": _adaptor_verify,
}


@pytest.fixture(autouse=True)
def _restore_the_switch() -> Iterator[None]:
    yield
    set_libsecp256k1_serving(serving=ENABLED)


def test_default_runs_the_python_arithmetic_silently() -> None:
    """Without `required` every declined call runs the Python arithmetic."""
    set_libsecp256k1_serving(serving=True)
    assert is_libsecp256k1_serving()
    for call in _DECLINED.values():
        call()


@pytest.mark.parametrize("name", _DECLINED)
def test_a_declined_call_raises_when_required(name: str) -> None:
    """Each declined call raises, and the message says why."""
    set_libsecp256k1_serving(serving=True, required=True)
    with pytest.raises(EccRuntimeError, match="libsecp256k1 was required"):
        _DECLINED[name]()


def test_the_message_names_what_declined() -> None:
    """Every option that declined is named."""
    set_libsecp256k1_serving(serving=True, required=True)
    with pytest.raises(EccRuntimeError, match=r"\(nonce, lower_s\)"):
        dsa.sign_recoverable_(_MSG_HASH, _PRV_KEY, nonce=_NONCE, lower_s=False)


def test_a_served_call_is_unaffected_when_required() -> None:
    """A call the bindings serve answers as without the mode."""
    set_libsecp256k1_serving(serving=True, required=True)
    sig = dsa.sign(_MSG_HASH, _PRV_KEY)
    dsa.verify(_MSG_HASH, _PUB_KEY, sig)
    ssa.verify(_MSG_HASH, _SSA_PUB_KEY, ssa.sign(_MSG_HASH, _PRV_KEY))
    dsa.recover_pub_keys(_MSG_HASH, sig)


def test_an_empty_batch_answers_when_required() -> None:
    """An empty batch checks nothing, so a declined `hf` does not raise.

    The same `hf` raises for a batch of one signature.
    """
    set_libsecp256k1_serving(serving=True, required=True)
    assert ssa.batch_verify([], [], [], hf=sha512)
    assert ssa.batch_verify_([], [], [], hf=sha512)
    ssa.assert_batch_as_valid([], [], [], hf=sha512)
    ssa.assert_batch_as_valid_([], [], [], hf=sha512)
    with pytest.raises(EccRuntimeError, match="libsecp256k1 was required"):
        ssa.batch_verify([b"strict"], [_SSA_PUB_KEY], [_SSA_SIG], hf=sha512)
    with pytest.raises(EccRuntimeError, match="libsecp256k1 was required"):
        ssa.batch_verify_([_MSG_HASH], [_SSA_PUB_KEY], [_SSA_SIG], hf=sha512)


def test_what_the_bindings_never_serve_runs_when_required() -> None:
    """Another curve and an input the bindings cannot take are no choice."""
    set_libsecp256k1_serving(serving=True, required=True)
    ec = CURVES["secp256r1"]
    sig = dsa.sign(_MSG_HASH, _PRV_KEY, ec=ec)
    dsa.verify(_MSG_HASH, mult(_PRV_KEY, ec=ec), sig)
    dsa.sign(sha512(b"x").digest(), _PRV_KEY, ec=ec, hf=sha512)
    # the point at infinity, which the bindings have no public key for
    assert mult(5, INF) == INF


def test_required_needs_serving() -> None:
    """Requiring the bindings while turning them off is refused."""
    with pytest.raises(EccValueError, match="required needs serving"):
        set_libsecp256k1_serving(serving=False, required=True)
    assert is_libsecp256k1_serving() is ENABLED


def test_required_is_set_by_each_call_of_the_setter() -> None:
    """The setter assigns both; `required` is False unless passed."""
    set_libsecp256k1_serving(serving=True, required=True)
    with pytest.raises(EccRuntimeError):
        _DECLINED["dsa.sign lower_s=False"]()
    set_libsecp256k1_serving(serving=True)
    _DECLINED["dsa.sign lower_s=False"]()
    set_libsecp256k1_serving(serving=True, required=True)
    set_libsecp256k1_serving(serving=False)
    _DECLINED["dsa.sign lower_s=False"]()


def test_required_is_a_bool() -> None:
    """A value read for its truth is refused, as `serving` is."""
    with pytest.raises(EccTypeError):
        set_libsecp256k1_serving(serving=True, required=1)  # type: ignore[arg-type]


def test_a_signer_built_with_the_bindings_off_keeps_the_python_arm() -> None:
    """Without `required` it stays there once the bindings serve."""
    set_libsecp256k1_serving(serving=False)
    signer = dsa.Signer(_PRV_KEY)
    set_libsecp256k1_serving(serving=True)
    # `None` is how the signer records the Python arm
    assert signer._pub_key_sec is None
    assert dsa.verify_(_MSG_HASH, _PUB_KEY, signer.sign_(_MSG_HASH))


def test_a_signer_built_with_the_bindings_off_is_refused_when_required() -> None:
    """Under `required` it raises where the bindings would serve it."""
    set_libsecp256k1_serving(serving=False)
    signer = dsa.Signer(_PRV_KEY)
    set_libsecp256k1_serving(serving=True, required=True)
    with pytest.raises(EccRuntimeError, match="held_python_arm"):
        signer.sign_(_MSG_HASH)
