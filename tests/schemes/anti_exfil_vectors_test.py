# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The host side of the draft anti-exfil BIP's vectors, for `dsa` and `ssa`.

AvilaLabs/anti-exfil's `spec/bip-anti-exfil.md` specifies the handshake
that `dsa` and `ssa` carry as `anti_exfil_*`. Its `vectors/` directory
publishes `bip-anti-exfil.json` and `bip-anti-exfil-boundary.json`,
vendored under `tests/schemes/_data/`; `tests/_data/README.md` pins the
revision.

Only the host is run: step 1, `anti_exfil_host_commit`, and step 5,
`anti_exfil_host_verify`. The draft derives the device's nonce with its
own tagged hashes, so the bytes a device must produce there are not the
ones this package's device produces, and the device cases are not run.
The `forced_hash` cases replace the output of a tagged hash, which
nothing here can do.

A case the host must accept is True. A case it must reject is refused in
one of three places. `point_from_octets_var`, this package's SEC parser,
raises `EccValueError` for an R0 that is no point,
`anti_exfil_host_verify` taking R0 as a point. The harness raises
`EccValueError` for an ECDSA signature that is not 64 octets, which the
draft's vectors README says a library with fixed-size arguments
satisfies by construction. For every other case `anti_exfil_host_verify`
answers False, or raises `EccValueError` where `verify_` raises for a
structurally invalid input.
"""

from collections.abc import Callable
from typing import Any

import pytest

from ecc.curves import point_from_octets_var, secp256k1
from ecc.ecc import dsa, ssa
from ecc.exceptions import EccValueError
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
    try:
        accepted = _host_verify(scheme, case)
    except EccValueError:
        return
    assert not accepted
