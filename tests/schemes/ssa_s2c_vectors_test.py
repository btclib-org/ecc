# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`ssa`'s sign-to-contract signer against bitcoin-core/secp256k1#1140.

`schnorrsig_s2c_vectors.json` holds what the library of that pull
request answered, in two flows: the anti-exfil handshake, and a
commitment beside an aux, which `sign_` takes. `tests/_data/README.md`
pins the revision and says how the rows were made.
"""

from itertools import product
from typing import Any

import pytest

from ecc import ssa
from ecc.alias import Point
from ecc.commit_nonce import commit_point_var_
from ecc.curves import bytes_from_point, mult
from ecc.ssa import _S2C_POINT_TAG
from tests import both_arms, load

_VECTORS = load("schemes", "_data", "schnorrsig_s2c_vectors.json")


def _rows(flow: str) -> list[Any]:
    """Return the rows of a flow, each named by its index in the inputs."""
    return [pytest.param(row, id=str(row["index"])) for row in _VECTORS[flow]]


def _assert_opening(row: dict[str, str], receipt: Point, data: bytes) -> None:
    """Assert the row's opening against the receipt and the parity of W."""
    W = commit_point_var_(data, receipt, _S2C_POINT_TAG)
    opening = bytearray(bytes_from_point(receipt))
    opening[0] |= (W[1] & 1) << 2
    assert opening.hex() == row["opening"]


@both_arms
@pytest.mark.parametrize("row", _rows("anti_exfil"))
def test_the_anti_exfil_handshake_signs_what_1140_signs(row: dict[str, str]) -> None:
    """Each step answers the octets the pull request's library answered."""
    prv_key = int(row["seckey"], 16)
    msg = bytes.fromhex(row["msg"])
    rho = bytes.fromhex(row["rho"])

    commitment = ssa.anti_exfil_host_commit(rho)
    assert commitment.hex() == row["host_commitment"]
    R0 = ssa.anti_exfil_signer_commit(msg, prv_key, commitment)
    assert bytes_from_point(R0).hex() == row["signer_commitment"]
    sig = ssa.anti_exfil_sign(msg, prv_key, rho)
    assert sig.serialize().hex() == row["sig"]
    _assert_opening(row, R0, rho)
    assert ssa.anti_exfil_host_verify(msg, bytes.fromhex(row["pk"]), sig, rho, R0)


@both_arms
@pytest.mark.parametrize("row", _rows("sign_to_contract"))
def test_a_commitment_beside_aux_signs_what_1140_signs(row: dict[str, str]) -> None:
    """`sign_` hashes the committed value first, as the pull request does."""
    prv_key = int(row["seckey"], 16)
    msg = bytes.fromhex(row["msg"])
    data = bytes.fromhex(row["s2c_data"])

    sig, receipt = ssa.sign_(msg, prv_key, bytes.fromhex(row["aux"]), commit_hash=data)
    assert sig.serialize().hex() == row["sig"]
    _assert_opening(row, receipt, data)
    assert ssa.verify_(
        msg, bytes.fromhex(row["pk"]), sig, commit_hash=data, receipt=receipt
    )


@pytest.mark.parametrize("flow", ["anti_exfil", "sign_to_contract"])
def test_the_rows_cover_every_parity(flow: str) -> None:
    """Each combination of the parities of P, R0 and W has a row."""
    cases = set()
    for row in _VECTORS[flow]:
        first = bytes.fromhex(row["opening"])[0]
        y_P = mult(int(row["seckey"], 16))[1]
        cases.add((y_P & 1, first & 1, first >> 2 & 1))
    assert cases == set(product((0, 1), repeat=3))
