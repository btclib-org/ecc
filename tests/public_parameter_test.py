# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every integer parameter of a `_var` function is `Public`, or says why not.

`CONTRIBUTING.md`'s *A `_var` suffix means the operand decides the work*
is the rule: an integer whose value decides the work is annotated
`alias.Public`, and mypy then refuses a plain `int` at every call. What
mypy cannot tell is whether a parameter that should carry the type does:
this walk reads every `_var` function, private ones and methods included,
and fails on an integer parameter that is neither `Public` nor in
`_NOT_OPERANDS` below with its reason.

A point, octets or a key is out of the walk: `Public` is an integer, and
for those the suffix alone states the contract.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_PACKAGE = Path(__file__).parents[1] / "src" / "ecc"

_PUBLIC = {"Public", "Sequence[Public]"}
# any annotation naming an integer that is not exactly `Public`: a union,
# a container or an alias of one is walked too
_INTEGER = re.compile(r"\b(int|Integer)\b")

# an integer parameter of a `_var` function that is not `Public`, by
# dotted name, with the reason why not
_NOT_OPERANDS = {
    # a window width or a radix: a constant of the algorithm
    "ecc.curves.curve_group._convert_number_to_base_var.base": "radix",
    "ecc.curves.curve_group._wNAF_of_m_var.w": "window",
    "ecc.curves.curve_group._mult_fixed_window_var.w": "window",
    "ecc.curves.curve_group._mult_fixed_window_cached_var.w": "window",
    "ecc.curves.curve_group._multi_mult_w_NAF_var.w": "window",
    "ecc.curves.curve_group_2._mult_sliding_window_var.w": "window",
    "ecc.curves.curve_group_2._mult_w_NAF_var.w": "window",
    "ecc.curves.curve_group_2._double_mult_w_NAF_var.w": "window",
    "ecc.curves.curve_group_2._mult_endomorphism_secp256k1_var.w": "window",
    "ecc.curves.curve_group_2._double_mult_endomorphism_secp256k1_var.w": "window",
    # the digits of a recoding the caller made of a Public scalar
    "ecc.curves.curve_group._additions_by_position_var.nafs": "digits",
    "ecc.curves.curve_group_2._double_and_add_var.digits": "digits",
    # a modulus or a coefficient, which the rule counts with the curve
    "ecc.ecc.ellswift._is_square_var.p": "modulus",
    "ecc.ecc.ellswift._is_x_fraction_var.b": "coefficient",
    "ecc.ecc.ellswift._is_x_fraction_var.p": "modulus",
    "ecc.number_theory.mod_inv_var.m": "modulus",
    "ecc.number_theory.mod_inv_batch_var.m": "modulus",
    "ecc.number_theory.legendre_symbol_var.p": "modulus",
    "ecc.number_theory.mod_sqrt_var.p": "modulus",
    "ecc.number_theory.tonelli_var.p": "modulus",
    "ecc.number_theory._jacobi_var.n": "modulus",
    # which of the eight preimages to try, drawn by `_ell_from_point_var`
    "ecc.ecc.ellswift._xswiftec_inv_var.case": "selector",
    # only refused when out of range: the work is the parse of the shares
    "ecc.ecc.frost._parse_session_pub_shares_var.ids": "range-checked",
    "ecc.ecc.frost._parse_session_pub_shares_var.n": "range-checked",
    # a format the output states
    "ecc.ecc.pedersen._bytes_from_point_var.tag": "format",
    "ecc.ecc.pedersen._point_from_octets_var.tag": "format",
    # header fields of a range proof: hashed, or a count the header writes
    "ecc.ecc.rangeproof._hashed_prefix_var.exp": "header",
    "ecc.ecc.rangeproof._hashed_prefix_var.mantissa": "header",
    "ecc.ecc.rangeproof._hashed_prefix_var.min_value": "header",
    "ecc.ecc.rangeproof._pub_expand_var.exp": "header",
    "ecc.ecc.rangeproof._pub_expand_var.rsizes": "header",
    "ecc.ecc.rangeproof._value_encoding_var.rsizes": "header",
    # the digits of a value recovered with a secret nonce, which is not
    # public: SECURITY.md's limitations state what this leaks
    "ecc.ecc.rangeproof._value_encoding_var.written": "not public",
    "ecc.ecc.rangeproof._value_encoding_var.drawn": "not public",
}


def _integer_parameters() -> dict[str, str]:
    """Map each integer parameter of a `_var` function to its annotation."""
    found: dict[str, str] = {}
    for path in sorted(_PACKAGE.rglob("*.py")):
        module = ".".join(path.relative_to(_PACKAGE.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions: list[tuple[str, ast.FunctionDef]] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                functions.append((node.name, node))
            elif isinstance(node, ast.ClassDef):
                functions.extend(
                    (f"{node.name}.{sub.name}", sub)
                    for sub in node.body
                    if isinstance(sub, ast.FunctionDef)
                )
        for qualname, function in functions:
            if not function.name.endswith(("_var", "_var_")):
                continue
            arguments = function.args
            for argument in [
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            ]:
                # mypy runs strict over the package: no parameter but
                # `self` lacks an annotation
                if argument.annotation is None:
                    continue
                annotation = ast.unparse(argument.annotation)
                if annotation in _PUBLIC or _INTEGER.search(annotation):
                    found[f"{module}.{qualname}.{argument.arg}"] = annotation
    return found


_FOUND = _integer_parameters()


def test_every_integer_operand_is_public() -> None:
    """An integer parameter of a `_var` function is Public or has a reason."""
    unexplained = {
        name
        for name, annotation in _FOUND.items()
        if annotation not in _PUBLIC and name not in _NOT_OPERANDS
    }
    assert not unexplained


def test_every_reason_is_still_needed() -> None:
    """A table entry names an integer parameter that is not Public."""
    stale = {name for name in _NOT_OPERANDS if _FOUND.get(name, "Public") in _PUBLIC}
    assert not stale


def test_the_walk_reaches_what_it_claims() -> None:
    """A function, a private one, a method, a sequence, and a `_var_`."""
    assert _FOUND["ecc.curves.curve.double_mult_var.u"] == "Public"
    assert _FOUND["ecc.number_theory._jacobi_var.a"] == "Public"
    assert _FOUND["ecc.curves.curve_group.CurveGroup.y_var.x"] == "Public"
    assert _FOUND["ecc.curves.curve.multi_mult_var.scalars"] == "Sequence[Public]"
    # a name ending in `_var_`, the suffix before a trailing underscore
    trailing = "ecc.curves.curve._libsecp256k1_multi_mult_var_.scalars"
    assert _FOUND[trailing] == "Sequence[Public]"
    assert _FOUND["ecc.number_theory.mod_inv_var.m"] == "int"
    # a plain name is not walked, an int operand of its own notwithstanding
    assert "ecc.number_theory.mod_inv.a" not in _FOUND
