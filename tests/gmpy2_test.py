# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The `gmpy2` extra, which puts the Python arm's field arithmetic on GMP.

With gmpy2 installed on CPython, every curve reduces by an mpz modulus, so
its group law computes in mpz. A caller still gets int back, which the
tests here ask of the functions that return a point or a coordinate.

The arm without the extra is asked of a child interpreter that cannot
import gmpy2, the suite being one environment: it has to answer what this
one answers.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

import pytest

from ecc import number_theory
from ecc.curves import (
    Curve,
    PreparedPoint,
    TweakChain,
    double_mult_var,
    mult,
    multi_mult_var,
    secp256k1,
    sum_var,
    tweak_add_var,
)
from ecc.curves.curve import CURVES
from ecc.curves.curve_group import BOS_COSTER_THRESHOLD
from ecc.ecc import dsa, ssa
from ecc.exceptions import EccValueError
from tests.curves.curve_test import no_bindings_anywhere

_SECP256R1 = CURVES["secp256r1"]
_M = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_MSG_HASH = bytes(range(32))
_AUX = bytes(32)


def _importorskip_gmpy2() -> Any:
    """Return gmpy2, skipping where it is absent or the package ignores it.

    The package does not use gmpy2 off CPython, so there the tests of what it
    does with gmpy2 have nothing to check, an installed gmpy2 or not.
    """
    if sys.implementation.name != "cpython":  # pragma: no cover -- PyPy only
        pytest.skip("gmpy2 is not used off CPython")
    return pytest.importorskip("gmpy2")


def _is_int(*values: object) -> bool:
    """Return whether every value is an int, and not an int-like type."""
    return all(type(value) is int for value in values)


def test_each_curve_converts_its_modulus_once() -> None:
    """`_modulus` is p as an mpz, and `p` itself stays an int."""
    mpz = _importorskip_gmpy2().mpz
    for ec in CURVES.values():
        assert type(ec._modulus) is mpz
        assert ec._modulus == ec.p
        assert _is_int(ec.p)


def test_number_theory_admits_an_mpz() -> None:
    """Each function answers an mpz what it answers the same int."""
    mpz = _importorskip_gmpy2().mpz
    p = _SECP256R1.p
    a = 0xABCDEF
    pz, az = mpz(p), mpz(a)
    assert number_theory.xgcd_var(az, pz) == number_theory.xgcd_var(a, p)
    assert number_theory.mod_inv_var(az, pz) == number_theory.mod_inv_var(a, p)
    assert number_theory.mod_inv(az, pz) == number_theory.mod_inv_var(a, p)
    assert number_theory.mod_inv_batch([az], pz) == [number_theory.mod_inv_var(a, p)]
    assert number_theory.mod_inv_batch_var([az], pz) == [
        number_theory.mod_inv_var(a, p)
    ]
    assert number_theory.legendre_symbol_var(az, pz) == (
        number_theory.legendre_symbol_var(a, p)
    )
    square = a**2 % p
    assert number_theory.mod_sqrt_var(mpz(square), pz) in {a, p - a}
    # a p of 1 mod 8, which is the one that reaches Tonelli-Shanks
    p224 = CURVES["secp224r1"].p
    assert number_theory.tonelli_var(mpz(square % p224), mpz(p224)) in {
        a,
        p224 - a,
    }

    # and a refusal is the package's own error, as it is for an int
    with pytest.raises(EccValueError, match="no inverse mod "):
        number_theory.mod_inv_var(mpz(0), pz)
    # a composite modulus above 2^32, where a blinding factor can be a zero
    # divisor: the blinded inverses answer and refuse as for an int
    m = 3 << 40
    mz = mpz(m)
    assert number_theory.mod_inv(mpz(5), mz) == pow(5, -1, m)
    assert number_theory.mod_inv_batch([mpz(5), mpz(7)], mz) == [
        pow(5, -1, m),
        pow(7, -1, m),
    ]
    with pytest.raises(EccValueError, match="no inverse mod "):
        number_theory.mod_inv(mpz(2), mz)
    with pytest.raises(EccValueError, match="no inverse mod "):
        number_theory.mod_inv_batch([mpz(5), mpz(2)], mz)
    for prime, root in (
        (p, number_theory.mod_sqrt_var),
        (p224, number_theory.tonelli_var),
    ):
        non_residue = next(
            x
            for x in range(2, 100)
            if number_theory.legendre_symbol_var(x, prime) == -1
        )
        with pytest.raises(EccValueError, match="no root mod "):
            root(mpz(non_residue), mpz(prime))
    for composite in (9, 33):
        with pytest.raises(EccValueError, match="p is not prime: "):
            number_theory.tonelli_var(mpz(4), mpz(composite))


@pytest.mark.parametrize("ec", [secp256k1, _SECP256R1], ids=["secp256k1", "secp256r1"])
def test_what_leaves_the_python_arm_is_int(
    ec: Curve, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Points and coordinates come back as int, whatever computed them."""
    no_bindings_anywhere(monkeypatch)
    P = mult(_M, ec.G, ec)
    assert _is_int(*P)
    assert _is_int(*mult(_M - 1, P, ec))
    assert _is_int(*PreparedPoint(P, ec).mult(_M))
    assert _is_int(*double_mult_var(_M, P, _M - 1, ec.G, ec))
    assert _is_int(*multi_mult_var([_M, _M - 1], [P, ec.G], ec))
    many = BOS_COSTER_THRESHOLD + 1
    assert _is_int(*multi_mult_var([_M + i for i in range(many)], [P] * many, ec))
    assert _is_int(*sum_var([P, ec.G], ec))
    assert _is_int(*tweak_add_var(P, _M, ec))
    assert _is_int(*TweakChain(P, ec).point(_M))

    # the Jacobian methods, handed what the arithmetic computes in
    QJ = ec._double_jac(ec.GJ)
    RJ = ec._add_jac(QJ, ec.GJ)
    assert _is_int(*ec.add_jac(QJ, RJ))
    assert _is_int(*ec.add_jac_aff(QJ, ec.G))
    assert _is_int(*ec.double_jac(QJ))
    assert _is_int(*ec.aff_from_jac_var(QJ))
    assert all(_is_int(*Q) for Q in ec.aff_from_jac_batch_var([QJ, RJ]))
    assert _is_int(ec.x_aff_from_jac_var(QJ), ec.y_aff_from_jac_var(QJ))

    sig = dsa.sign_(_MSG_HASH, _M, ec=ec)
    assert _is_int(sig.r, sig.s)


def test_what_leaves_ssa_is_int(monkeypatch: pytest.MonkeyPatch) -> None:
    """A BIP340 signature, whose r is an x-coordinate."""
    no_bindings_anywhere(monkeypatch)
    sig = ssa.sign_(_MSG_HASH, _M, _AUX)
    assert _is_int(sig.r, sig.s)


# the child: gmpy2 refused by a finder, the bindings by the environment, and
# the answers as json on stdout
_CHILD = """
import json, sys


class RefuseGmpy2:
    def find_spec(self, name, path=None, target=None):
        if name == {refused!r}:
            raise ModuleNotFoundError(f"{{name}} is out of reach", name=name)
        return None


sys.meta_path.insert(0, RefuseGmpy2())
if {implementation!r}:
    sys.implementation.name = {implementation!r}

from ecc.curves import double_mult_var, mult, secp256k1
from ecc.curves.curve import CURVES
from ecc.ecc import dsa, ssa

r1 = CURVES["secp256r1"]
m = {m}
print(json.dumps({{
    "modulus": type(secp256k1._modulus).__name__,
    "k1": mult(m, mult(m - 1)),
    "r1": mult(m, mult(m - 1, r1.G, r1), r1),
    "k1 G": mult(m),
    "r1 G": mult(m, r1.G, r1),
    "double": double_mult_var(m, mult(3), m - 1, secp256k1.G),
    "dsa": dsa.sign_({msg_hash!r}, m, ec=r1).serialize().hex(),
    "ssa": ssa.sign_({msg_hash!r}, m, {aux!r}).serialize().hex(),
}}))
"""


def _run_child(
    refused: str, implementation: str = ""
) -> subprocess.CompletedProcess[str]:
    """Run the child with the bindings off and one module refused.

    A non-empty implementation is the name the child's interpreter gives
    itself, `sys.implementation.name`, before `ecc` is imported.
    """
    source = _CHILD.format(
        refused=refused,
        implementation=implementation,
        m=_M,
        msg_hash=_MSG_HASH,
        aux=_AUX,
    )
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", source],
        capture_output=True,
        encoding="utf-8",
        check=False,
        # colour off, as `no_bindings_test._child_env` says why
        env={
            **{k: v for k, v in os.environ.items() if k != "FORCE_COLOR"},
            "ECC_NO_LIBSECP256K1": "1",
            "PYTHON_COLORS": "0",
        },
        timeout=120,
    )


def test_the_arm_without_gmpy2_answers_the_same(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that cannot import gmpy2 computes in int, and agrees."""
    completed = _run_child("gmpy2")
    assert completed.returncode == 0, completed.stderr
    answers: dict[str, Any] = json.loads(completed.stdout)
    assert answers.pop("modulus") == "int"

    no_bindings_anywhere(monkeypatch)
    expected = {
        "k1": mult(_M, mult(_M - 1)),
        "r1": mult(_M, mult(_M - 1, _SECP256R1.G, _SECP256R1), _SECP256R1),
        "k1 G": mult(_M),
        "r1 G": mult(_M, _SECP256R1.G, _SECP256R1),
        "double": double_mult_var(_M, mult(3), _M - 1, secp256k1.G),
        "dsa": dsa.sign_(_MSG_HASH, _M, ec=_SECP256R1).serialize().hex(),
        "ssa": ssa.sign_(_MSG_HASH, _M, _AUX).serialize().hex(),
    }
    assert {k: tuple(v) if isinstance(v, list) else v for k, v in answers.items()} == (
        expected
    )


def test_a_gmpy2_that_fails_to_import_is_not_read_as_absent() -> None:
    """A module missing inside gmpy2 raises, rather than falling back to int."""
    _importorskip_gmpy2()
    completed = _run_child("gmpy2.gmpy2")
    assert completed.returncode != 0
    assert "ModuleNotFoundError: gmpy2.gmpy2 is out of reach" in completed.stderr


def test_gmpy2_is_not_used_off_cpython() -> None:
    """A child that names itself PyPy keeps its modulus an int."""
    _importorskip_gmpy2()
    completed = _run_child("", implementation="pypy")
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["modulus"] == "int"
