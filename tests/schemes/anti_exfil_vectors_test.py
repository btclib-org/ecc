# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The draft anti-exfil BIP's vectors, for `dsa` and `ssa`.

AvilaLabs/anti-exfil's `spec/bip-anti-exfil.md` specifies the handshake
that `dsa` and `ssa` carry as `anti_exfil_*`. Its `vectors/` directory
publishes `bip-anti-exfil.json` and `bip-anti-exfil-boundary.json`,
vendored under `tests/schemes/_data/`; `tests/_data/README.md` pins the
revision.

The device is run on every `valid` case, step 1, step 2 and step 4 each
answering the case's octets, and on every `device_fail` case, which both
of its steps refuse. The host is run on every `valid`, `reject` and
`host_accept` case.

A case the host must accept is True. A case it must reject is refused in
one of three places. `point_from_octets_var`, this package's SEC parser,
raises `EccValueError` for an R0 that is no point,
`anti_exfil_host_verify` taking R0 as a point. The harness raises
`EccValueError` for an ECDSA signature that is not 64 octets, which the
draft's vectors README says a library with fixed-size arguments
satisfies by construction. For every other case `anti_exfil_host_verify`
answers False, or raises `EccValueError` where `verify_` raises for a
structurally invalid input.

A `forced_hash` case replaces the output of the tagged hashes it names,
and only theirs: `forced` patches `tagged_hash` where the anti-exfil
paths call it, keyed on the tag. Where the draft's step 4 or step 5
refuses a tweak t >= n, `commit_nonce`'s tweak draws a second candidate,
hashing the first under the same tag. A forced hash answers that one
too, so the draw ends in the refusal the case asks for.
"""

from collections.abc import Callable
from hashlib import sha256
from typing import Any

import pytest

from ecc import commit_nonce, dsa, hashes, ssa
from ecc.alias import HashF
from ecc.curves import bytes_from_point, mult, point_from_octets_var, secp256k1
from ecc.exceptions import EccRuntimeError, EccValueError
from tests import both_arms, load

_FILES = ("bip-anti-exfil.json", "bip-anti-exfil-boundary.json")

_SCHEMES: dict[str, Any] = {"ecdsa": dsa, "bip340": ssa}


def _cases(*classes: str) -> list[Any]:
    """Return every case of the named classes, in both files and schemes."""
    params: list[Any] = []
    for name in _FILES:
        vectors = load("schemes", "_data", name)
        for scheme in _SCHEMES:
            for class_ in classes:
                params.extend(
                    pytest.param(scheme, case, id=case["id"])
                    for case in vectors[scheme].get(class_, [])
                )
    return params


def _host_verify(scheme: str, case: dict[str, Any]) -> bool:
    """Run step 5 on the case's tuple, raising where an input cannot be held."""
    receipt = point_from_octets_var(bytes.fromhex(case["R0_bytes"]), secp256k1)
    octets = bytes.fromhex(case["sig"])
    sig: dsa.Sig | bytes = octets
    if scheme == "ecdsa":
        # r and s, 32 octets each, where `dsa` reads octets as DER. Not
        # checked here, so that the range of r and s is step 5's to refuse
        if len(octets) != 64:
            raise EccValueError("not 64 octets")
        r = int.from_bytes(octets[:32], "big")
        s = int.from_bytes(octets[32:], "big")
        sig = dsa.Sig(r, s, check_validity=False)
    host_verify: Callable[..., bool] = _SCHEMES[scheme].anti_exfil_host_verify
    return host_verify(
        bytes.fromhex(case["m"]),
        bytes.fromhex(case["pk"]),
        sig,
        bytes.fromhex(case["rho"]),
        receipt,
    )


def _rejected(scheme: str, case: dict[str, Any]) -> bool:
    """Answer whether the R0 parser, the harness or step 5 refuses the tuple."""
    try:
        return not _host_verify(scheme, case)
    except EccValueError:
        return True


def _device_commit(scheme: str, case: dict[str, Any]) -> bytes:
    """Run step 2 on the case's key, message and commitment."""
    R0 = _SCHEMES[scheme].anti_exfil_signer_commit(
        bytes.fromhex(case["m"]),
        bytes.fromhex(case["sk"]),
        bytes.fromhex(case["hc"]),
    )
    return bytes_from_point(R0, secp256k1)


def _device_sign(scheme: str, case: dict[str, Any]) -> bytes:
    """Run step 4 on the case's key, message and rho."""
    sig = _SCHEMES[scheme].anti_exfil_sign(
        bytes.fromhex(case["m"]),
        bytes.fromhex(case["sk"]),
        bytes.fromhex(case["rho"]),
    )
    if scheme == "ecdsa":
        return bytes(sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big"))
    return bytes(sig.serialize())


@both_arms
@pytest.mark.parametrize("scheme, case", _cases("valid", "host_accept"))
def test_the_host_accepts(scheme: str, case: dict[str, Any]) -> None:
    """Step 5 accepts an honest run, and step 1 commits as the draft does."""
    assert _host_verify(scheme, case)
    if "hc" in case:
        commit = _SCHEMES[scheme].anti_exfil_host_commit(bytes.fromhex(case["rho"]))
        assert commit.hex() == case["hc"]


@both_arms
@pytest.mark.parametrize("scheme, case", _cases("reject"))
def test_the_host_rejects(scheme: str, case: dict[str, Any]) -> None:
    """The R0 parser, the harness or step 5 refuses the tuple."""
    assert _rejected(scheme, case)


@both_arms
@pytest.mark.parametrize("scheme, case", _cases("valid"))
def test_the_device_answers_the_draft(scheme: str, case: dict[str, Any]) -> None:
    """Step 2 answers the case's R0, and step 4 its signature."""
    assert _device_commit(scheme, case).hex() == case["R0_bytes"]
    assert _device_sign(scheme, case).hex() == case["sig"]


@both_arms
@pytest.mark.parametrize("scheme, case", _cases("device_fail"))
def test_the_device_fails(scheme: str, case: dict[str, Any]) -> None:
    """Each step the case names refuses its key."""
    assert set(case["operations"]) == {"device_commit", "device_sign"}
    with pytest.raises(EccValueError, match="private key not in 1..n-1"):
        _device_commit(scheme, case)
    with pytest.raises(EccValueError, match="private key not in 1..n-1"):
        _device_sign(scheme, case)


@pytest.fixture
def forced(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Answer each forced tag's tagged hash with its output, counting calls.

    `commit_nonce` hashes the commitment, the base nonce and the tweak,
    and `ssa` the BIP340 challenge. Every other tag is hashed as it is.
    """
    outputs: dict[bytes, bytes] = {}
    calls: dict[bytes, int] = {}
    tagged_hash = hashes.tagged_hash

    def patched(tag: bytes, m: bytes, hf: HashF = sha256) -> bytes:
        if tag in outputs:
            calls[tag] = calls.get(tag, 0) + 1
            return outputs[tag]
        return tagged_hash(tag, m, hf)

    for module in (commit_nonce, ssa):
        monkeypatch.setattr(module, "tagged_hash", patched)
    return {"outputs": outputs, "calls": calls}


def test_the_override_reaches_the_hash(forced: dict[str, Any]) -> None:
    """A forced nonce hash moves R0, and only the forced tag is answered."""
    case = load("schemes", "_data", "bip-anti-exfil.json")["bip340"]["valid"][0]
    assert _device_commit("bip340", case).hex() == case["R0_bytes"]
    forced["outputs"][b"s2c/schnorr/nonce"] = (5).to_bytes(32, "big")
    assert _device_commit("bip340", case) == bytes_from_point(mult(5))
    assert forced["calls"] == {b"s2c/schnorr/nonce": 1}


@both_arms
@pytest.mark.parametrize("scheme, case", _cases("forced_hash"))
def test_a_forced_hash(
    scheme: str, case: dict[str, Any], forced: dict[str, Any]
) -> None:
    """Each operation the case names answers what the case expects."""
    overrides = [case["forced_hash"], *case.get("additional_forced_hashes", [])]
    for override in overrides:
        forced["outputs"][override["tag"].encode()] = bytes.fromhex(override["output"])

    expected = case["expected"]
    for operation in case["operations"]:
        if operation == "host_verify":
            assert expected in {"accept", "reject"}
            assert _rejected(scheme, case) is (expected == "reject")
            continue
        run = {"device_commit": _device_commit, "device_sign": _device_sign}
        if expected == "device_fails":
            with pytest.raises(EccRuntimeError):
                run[operation](scheme, case)
        else:
            assert expected == "device_produces"
            field = "R0_bytes" if operation == "device_commit" else "sig"
            assert run[operation](scheme, case).hex() == case[field]

    # every forced tag was asked for, so the case ran on the hash it forces,
    # unless the signature's own parse refused it before anything was hashed
    if forced["calls"]:
        assert set(forced["calls"]) == {o["tag"].encode() for o in overrides}
    else:
        assert expected == "reject"
        with pytest.raises(EccValueError):
            _SCHEMES[scheme].Sig.parse(bytes.fromhex(case["sig"]))
