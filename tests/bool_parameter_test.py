# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every `bool` parameter of the package, classified and held to its class.

A `bool` parameter is a kind or a truth, and only the first is
type-checked, which is `musig2._flag`'s reasoning: a kind written down
and read back -- json, a configuration file, a coordinator's message --
arrives as whatever it was written as, and `"false"` is true. Issue
btclib-org/btclib#868 asked for the census this file is.

## The line

A **truth** only decides whether the call refuses: `verify=False` says
do not check the signature just computed, and the signature handed back
is the same one. So a value read for its truth runs a check or skips one
and changes no answer, which is why nothing is refused there.

A **kind** decides what a non-refusing call computes or returns. `"no"`
is true, so a kind read for its truth quietly computes the other answer
-- the other signature, the other encoding -- and that is what the
refusal is for.

## The polarity a truth has to have

`CONTRIBUTING.md`'s *A truth's `True` has to be its conservative value*
is the rule, with the wrong values it does not cover. `hybrid` breaks
it, so it is in `_KINDS` under a comment of its own; issue
btclib-org/btclib#884 is the one that asked.

The two tests below are that line, one each:

- a kind refuses `"no"`, `0`, `1` and (where the annotation does not
  declare it) `None`, with an `EccTypeError`
- a truth **accepts** them, on a fixture the flag's `True` accepts: a
  truth that starts refusing fails here, and the entry has to move
  rather than the test being edited

## The walk

`_bool_parameters` reads every public function of the package and every
`bool`-annotated parameter of one, so a flag added anywhere is either in
a table here or the run is red -- there is no third table, and that is
the state to keep.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from ecc._libsecp256k1 import INSTALLED
from ecc.curves.curve import (
    Curve,
    SEC2v1_params2,
    set_libsecp256k1_serving,
)
from ecc.curves.sec_point import (
    bytes_from_point,
    bytes_from_prv_key_int,
    point_from_octets_var,
)
from ecc.ecc import dsa, ellswift, frost, musig2, ssa
from ecc.exceptions import EccTypeError

_PACKAGE = Path(__file__).parents[1] / "src" / "ecc"

# `check_validity` is the one name the walk subtracts, and this is the
# reason it may: it is a convention over many signatures rather than a
# parameter of one, and `check_validity_test.py` is the file that holds
# it -- being a truth is what that whole file is about
_OWNED_BY_ITS_OWN_FILE = "check_validity"

# a value of no bool type: a truthy string, and the two integers `bool`
# inherits from. Every one of them is a call mypy refuses
_WRONG_TYPES: tuple[Any, ...] = ("no", 0, 1)

_PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
_PUB_KEY = dsa.gen_keys(_PRV_KEY)[1]
_SEC = bytes_from_point(_PUB_KEY)
_SEC_2 = bytes_from_prv_key_int(_PRV_KEY + 1)
_MSG = b"Satoshi Nakamoto"
_MSG_HASH = sha256(_MSG).digest()
_RECOVERABLE, _KEY_ID = dsa.sign_recoverable_(_MSG_HASH, _PRV_KEY)
_DER_SIG = dsa.sign(_MSG, _PRV_KEY).serialize()
_ELL = ellswift.create(_PRV_KEY)

# the cheapest catalogued curve, and the point of it is that both
# construction-time checks pass on it: a low-cardinality one is MOV-weak,
# which is what `weakness_check=True` is there to refuse
_SMALL_CURVE = dict(
    zip(
        ("p", "a", "b", "G", "n", "cofactor"),
        SEC2v1_params2["secp112r1"][:6],
        strict=True,
    )
)

_KEY_AGG = musig2.key_agg_var([_SEC, _SEC_2])
_FROST_TWEAK_CTX = frost.tweak_ctx_init_var(_SEC)


@dataclass(frozen=True)
class _Case:
    """One `bool` parameter, and a call of its function that works."""

    dotted: str
    flag: str
    function: Any
    # every argument but the flag, by keyword
    args: dict[str, Any] = field(default_factory=dict)
    # the flag value the working call is made with: `True` unless the
    # fixture is one only `False` accepts
    valid: bool = True
    # `bool | None` declares None, so it is not a wrong value there. Read
    # off the annotation, not an exemption from anything
    optional: bool = False
    # the classification, which is prose because it is a judgement: for a
    # truth what the flag turns on and what it therefore cannot change,
    # and for a kind only where the kind is the polarity rather than the
    # answer -- the flags carrying one below are those
    reason: str = ""


_KINDS = (
    # `compressed` chooses which encoding of the public key is computed
    _Case(
        "ecc.curves.sec_point.bytes_from_point",
        "compressed",
        bytes_from_point,
        {"Q": _PUB_KEY},
    ),
    _Case(
        "ecc.curves.sec_point.bytes_from_prv_key_int",
        "compressed",
        bytes_from_prv_key_int,
        {"prv_key_int": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.recover_sec_",
        "compressed",
        dsa.recover_sec_,
        {"key_id": _KEY_ID, "msg_hash": _MSG_HASH, "sig": _RECOVERABLE},
    ),
    _Case(
        "ecc.ecc.dsa.recover_sec",
        "compressed",
        dsa.recover_sec,
        {"key_id": _KEY_ID, "msg": _MSG, "sig": _RECOVERABLE},
    ),
    # `lower_s` chooses which of the two signatures is returned, `grind`
    # whether the nonce is searched until r is short
    _Case(
        "ecc.ecc.dsa.sign_",
        "lower_s",
        dsa.sign_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.sign",
        "lower_s",
        dsa.sign,
        {"msg": _MSG, "prv_key": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.sign_recoverable_",
        "lower_s",
        dsa.sign_recoverable_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.sign_recoverable",
        "lower_s",
        dsa.sign_recoverable,
        {"msg": _MSG, "prv_key": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.anti_exfil_sign",
        "lower_s",
        dsa.anti_exfil_sign,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY, "rho": _MSG_HASH},
    ),
    _Case(
        "ecc.ecc.dsa.sign_",
        "grind",
        dsa.sign_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.sign",
        "grind",
        dsa.sign,
        {"msg": _MSG, "prv_key": _PRV_KEY},
    ),
    _Case(
        "ecc.ecc.dsa.Signer.sign_",
        "grind",
        dsa.Signer(_PRV_KEY).sign_,
        {"msg_hash": _MSG_HASH},
    ),
    _Case(
        "ecc.ecc.dsa.Signer.sign",
        "grind",
        dsa.Signer(_PRV_KEY).sign,
        {"msg": _MSG},
    ),
    _Case(
        "ecc.ecc.musig2.apply_tweak_var",
        "is_xonly",
        musig2.apply_tweak_var,
        {"key_agg_ctx": _KEY_AGG, "tweak": b"\x01" * 32},
    ),
    _Case(
        "ecc.ecc.frost.apply_tweak_var",
        "is_xonly",
        frost.apply_tweak_var,
        {"tweak_ctx": _FROST_TWEAK_CTX, "tweak": b"\x01" * 32},
    ),
    # `initiating` chooses which encoding is the other party's, and so
    # which secret is computed
    _Case(
        "ecc.ecc.ellswift.xdh",
        "initiating",
        ellswift.xdh,
        {"ell_a": _ELL, "ell_b": _ELL, "prv_key": _PRV_KEY},
    ),
    # `serving` chooses which implementation every later call reaches, so
    # it is as much a kind as `compressed` is: a value read for its truth
    # would let `serving="no"` ask for C and `serving=0` for Python, and
    # a caller that asked for one and got the other would be timing the
    # other and calling it the one. `valid=INSTALLED`, so that the call
    # this file makes leaves the state an installation is normally in
    _Case(
        "ecc.curves.curve.set_libsecp256k1_serving",
        "serving",
        set_libsecp256k1_serving,
        {},
        valid=INSTALLED,
    ),
    # `required` chooses between an answer and a raise for every call the
    # bindings decline, so `required="no"` would turn the refusal on
    # where `required=0` leaves it off. `valid=False`, so that the call
    # this file makes leaves the state an installation is normally in
    _Case(
        "ecc.curves.curve.set_libsecp256k1_serving",
        "required",
        set_libsecp256k1_serving,
        {"serving": INSTALLED},
        valid=False,
    ),
    # the one below decides no answer, which every kind above does, and
    # is here for the other half of the line: its `True` is the
    # permissive value, the refusal it was written to make, waived
    _Case(
        "ecc.curves.sec_point.point_from_octets_var",
        "hybrid",
        point_from_octets_var,
        {"pub_key": _SEC},
        reason="`True` accepts the 0x06 and 0x07 prefixes, so a true"
        " non-bool parses the very forms it was written down to keep out",
    ),
)

_TRUTHS = (
    _Case(
        "ecc.curves.curve.Curve.__init__",
        "weakness_check",
        Curve,
        _SMALL_CURVE,
        reason="whether the embedding degree is derived; a construction-time"
        " check, and no parameter of the curve built",
    ),
    _Case(
        "ecc.curves.curve.Curve.__init__",
        "order_check",
        Curve,
        _SMALL_CURVE,
        reason="whether n*G is verified to be the point at infinity",
    ),
    _Case(
        "ecc.ecc.dsa.Sig.parse",
        "strict",
        dsa.Sig.parse,
        {"data": _DER_SIG},
        reason="whether the encoding must be Bitcoin Core's canonical one,"
        " trailing bytes and non-minimal scalars alike; the signature"
        " parsed out of what both readings accept is one signature",
    ),
    _Case(
        "ecc.ecc.dsa.sign_",
        "verify",
        dsa.sign_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with;"
        " the signature is the same either way, the check being a"
        " verification of what has already been computed",
    ),
    _Case(
        "ecc.ecc.dsa.sign",
        "verify",
        dsa.sign,
        {"msg": _MSG, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "ecc.ecc.dsa.Signer.sign_",
        "verify",
        dsa.Signer(_PRV_KEY).sign_,
        {"msg_hash": _MSG_HASH},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "ecc.ecc.dsa.Signer.sign",
        "verify",
        dsa.Signer(_PRV_KEY).sign,
        {"msg": _MSG},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "ecc.ecc.ssa.sign_",
        "verify",
        ssa.sign_,
        {"msg": _MSG, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with;"
        " the signature is the same either way, the check being a"
        " verification of what has already been computed",
    ),
    _Case(
        "ecc.ecc.ssa.sign",
        "verify",
        ssa.sign,
        {"msg": _MSG, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "ecc.ecc.ssa.Signer.sign_",
        "verify",
        ssa.Signer(_PRV_KEY).sign_,
        {"msg": _MSG},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "ecc.ecc.ssa.Signer.sign",
        "verify",
        ssa.Signer(_PRV_KEY).sign,
        {"msg": _MSG},
        reason="whether the signature is checked before it is answered with",
    ),
)
_KIND_IDS = tuple(f"{case.dotted}({case.flag})" for case in _KINDS)
_TRUTH_IDS = tuple(f"{case.dotted}({case.flag})" for case in _TRUTHS)


def _flags_of(function: ast.FunctionDef) -> set[str]:
    """Return the `bool`-annotated parameters of one public function."""
    if function.name.startswith("_") and not function.name.startswith("__"):
        return set()
    if any(ast.unparse(d) == "overload" for d in function.decorator_list):
        return set()
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return {
        argument.arg
        for argument in arguments
        if argument.annotation is not None
        and ast.unparse(argument.annotation) in {"bool", "bool | None"}
        and argument.arg != _OWNED_BY_ITS_OWN_FILE
    }


def _bool_parameters() -> set[tuple[str, str]]:
    """Return every (function, `bool` parameter) pair of the public API.

    Keyed on the annotation, `bool` and `bool | None`: what a flag is
    called says nothing, and `include_witness` is spelled both ways.

    A method counts and a private function does not, as in
    `curve_parameter_test.py`; an `@overload` stub is not a function to
    drive; and a function nested in another is a closure rather than API,
    a parameter no caller can pass.
    """
    found: set[tuple[str, str]] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                dotted = f"{module}.{prefix}{child.name}"
                found.update((dotted, flag) for flag in _flags_of(child))

    for path in sorted(_PACKAGE.rglob("*.py")):
        module = ".".join(path.relative_to(_PACKAGE.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", [*_KINDS, *_TRUTHS], ids=[*_KIND_IDS, *_TRUTH_IDS])
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(**case.args, **{case.flag: case.valid})


@pytest.mark.parametrize("case", _KINDS, ids=_KIND_IDS)
def test_a_kind_refuses_a_non_bool(case: _Case) -> None:
    """A kind decides what is computed, so it is not read for its truth.

    `"no"` is the value that makes the point -- it is true, so the flag
    would be on -- and `0` and `1` are the two `bool` inherits from, which
    is what makes `isinstance(value, int)` no check at all here.
    """
    wrong = _WRONG_TYPES if case.optional else (*_WRONG_TYPES, None)
    for value in wrong:
        with pytest.raises(EccTypeError, match=f"invalid {case.flag} type"):
            case.function(**case.args, **{case.flag: value})


@pytest.mark.parametrize("case", _TRUTHS, ids=_TRUTH_IDS)
def test_a_truth_is_read_for_its_truth(case: _Case) -> None:
    """The other half of the line, and the ratchet under this file.

    A truth turns a check on or off and changes no answer, so a value of
    another type is read for whether it is true and refused by nothing.
    An entry that starts refusing fails here rather than passing quietly:
    the fix is to move it to `_KINDS`, which is a decision about the
    parameter and not about this test.
    """
    for value in _WRONG_TYPES:
        case.function(**case.args, **{case.flag: value})


def test_every_bool_parameter_is_classified() -> None:
    """No third table: a flag is a kind or a truth, and the walk says so.

    A parameter added anywhere under `src/ecc/` fails here until
    somebody decides which of the two it is -- which is the decision this file
    exists to keep from being made by default.
    """
    classified = {(case.dotted, case.flag) for case in (*_KINDS, *_TRUTHS)}
    found = _bool_parameters()
    assert classified == found, (
        f"unclassified: {sorted(found - classified)};"
        f" gone from the tree: {sorted(classified - found)}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes it must find, and the ones it must not.

    A walk that found nothing would pass the test above.
    """
    found = _bool_parameters()
    # a function, a method, and a method of a class nested in a module
    assert ("ecc.ecc.dsa.sign", "lower_s") in found
    assert ("ecc.ecc.dsa.Signer.sign", "grind") in found
    assert ("ecc.curves.curve.Curve.__init__", "order_check") in found

    # the convention with a file of its own
    assert not [pair for pair in found if pair[1] == "check_validity"]
    # a private function, and a parameter of another type
    assert ("ecc.ecc.musig2._flag", "is_xonly") not in found
    assert ("ecc.hashes.reduce_to_hlen", "hf") not in found
