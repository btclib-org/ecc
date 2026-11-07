# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every integer parameter of a `_var` function is `Public`, or says why not.

`CONTRIBUTING.md`'s *A `_var` suffix means the operand decides the work*
is the rule: an integer whose value decides the work is annotated
`ecc.alias.Public`, and mypy then refuses a plain `int` at every call. What
mypy cannot tell is whether a parameter that should carry the type does:
this walk reads every `_var` function at any depth of a module, private
ones, methods and `async def` included. It fails on a parameter, `*args`
and `**kwargs` included, whose annotation names `int` or `Integer` and that
is neither `Public` nor in `_NOT_OPERANDS` below with its reason.

A point, octets or a key is out of the walk: `Public` is an integer, and
for those the suffix alone states the contract.

The walk is also run on `_CONTROL`, a source holding each shape it claims
to reach, since the package need not hold each one.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_PACKAGE = Path(__file__).parents[1] / "src" / "ecc"

_PUBLIC = {"Public", "Sequence[Public]"}
# the annotation's text is matched: a union or a container of `int` or
# `Integer` is walked, an alias under another name is not
_INTEGER = re.compile(r"\b(int|Integer)\b")

# an integer parameter of a `_var` function that is not `Public`, by
# dotted name, with the reason why not
_NOT_OPERANDS: dict[str, str] = {
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

_CONTROL = """
def double_mult_var(u: Public, w: int) -> None: ...
def _jacobi_var(a: Public) -> None: ...
class CurveGroup:
    def y_var(self, x: Public) -> None: ...
def multi_mult_var(scalars: Sequence[Public]) -> None: ...
def _libsecp256k1_multi_mult_var_(scalars: Sequence[Public]) -> None: ...
def mod_inv(a: int) -> None: ...
if TYPE_CHECKING:
    def guarded_var(a: int) -> None: ...
class Outer:
    class Inner:
        def nested_var(self, a: int) -> None: ...
async def async_var(a: int) -> None: ...
def outer() -> None:
    def inner_var(a: int) -> None: ...
def star_var(*n: int, **k: int) -> None: ...
if TYPE_CHECKING:
    def redefined_var(a: int) -> None: ...
else:
    def redefined_var(a: Public) -> None: ...
if TYPE_CHECKING:
    def reversed_var(a: Public) -> None: ...
else:
    def reversed_var(a: int) -> None: ...
@overload
def overloaded_var(a: int) -> None: ...
@overload
def overloaded_var(a: bytes) -> None: ...
def overloaded_var(a: Public | bytes) -> None: ...
_Position = int
def leaf_var(p: _Position) -> None: ...
"""

_Function = ast.FunctionDef | ast.AsyncFunctionDef


def _var_functions(module: str, source: str) -> list[tuple[str, _Function]]:
    """List each `_var` function of a module, at any depth, with its name.

    A name defined twice, as an overload or in two branches, is listed twice.
    """
    functions: list[tuple[str, _Function]] = []

    # every node is visited, with the dotted name of the functions and
    # classes around it: a `def` under an `if` is the module's own
    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _Function):
                if child.name.endswith(("_var", "_var_")):
                    functions.append((f"{prefix}{child.name}", child))
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(ast.parse(source), f"{module}.")
    return functions


def _integer_parameters(functions: list[tuple[str, _Function]]) -> dict[str, str]:
    """Map each walked parameter of a `_var` function to its annotation."""
    found: dict[str, str] = {}
    for name, function in functions:
        arguments = function.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *([arguments.vararg] if arguments.vararg else []),
            *arguments.kwonlyargs,
            *([arguments.kwarg] if arguments.kwarg else []),
        ]:
            # mypy runs strict over the package: no parameter but
            # `self` lacks an annotation
            if argument.annotation is None:
                continue
            annotation = ast.unparse(argument.annotation)
            if annotation in _PUBLIC or _INTEGER.search(annotation):
                key = f"{name}.{argument.arg}"
                # a `Public` one under the same name does not hide one
                # that is not
                if annotation not in _PUBLIC or key not in found:
                    found[key] = annotation
    return found


def _package_functions() -> list[tuple[str, _Function]]:
    """List each `_var` function of the package with its name."""
    functions: list[tuple[str, _Function]] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        module = ".".join(path.relative_to(_PACKAGE.parent).with_suffix("").parts)
        functions += _var_functions(module, path.read_text(encoding="utf-8"))
    return functions


def _unexplained(found: dict[str, str], not_operands: dict[str, str]) -> set[str]:
    """Return the integer parameters neither Public nor given a reason."""
    return {
        name
        for name, annotation in found.items()
        if annotation not in _PUBLIC and name not in not_operands
    }


def _stale(found: dict[str, str], not_operands: dict[str, str]) -> set[str]:
    """Return the reasons naming no integer parameter that is not Public."""
    return {name for name in not_operands if found.get(name, "Public") in _PUBLIC}


_FUNCTIONS = _package_functions()
_FOUND = _integer_parameters(_FUNCTIONS)


def test_every_integer_operand_is_public() -> None:
    """An integer parameter of a `_var` function is Public or has a reason."""
    assert not _unexplained(_FOUND, _NOT_OPERANDS)


def test_every_reason_is_still_needed() -> None:
    """A table entry names an integer parameter that is not Public."""
    assert not _stale(_FOUND, _NOT_OPERANDS)


def test_the_walk_reaches_what_it_claims() -> None:
    """Each shape `_CONTROL` holds, and the package's own `_var` functions."""
    # the package's own: a function, a private one, and a method
    assert _FOUND["ecc.curves.curve.double_mult_var.u"] == "Public"
    assert _FOUND["ecc.number_theory._jacobi_var.a"] == "Public"
    assert _FOUND["ecc.curves.curve_group.CurveGroup.y_var.x"] == "Public"
    found = _integer_parameters(_var_functions("control", _CONTROL))
    assert found == {
        "control.double_mult_var.u": "Public",
        "control.double_mult_var.w": "int",
        "control._jacobi_var.a": "Public",
        "control.CurveGroup.y_var.x": "Public",
        "control.multi_mult_var.scalars": "Sequence[Public]",
        # a name ending in `_var_`, the suffix before a trailing underscore
        "control._libsecp256k1_multi_mult_var_.scalars": "Sequence[Public]",
        # under an `if`, in a nested class, an `async def`, in a function,
        # and `*args` and `**kwargs`
        "control.guarded_var.a": "int",
        "control.Outer.Inner.nested_var.a": "int",
        "control.async_var.a": "int",
        "control.outer.inner_var.a": "int",
        "control.star_var.n": "int",
        "control.star_var.k": "int",
        # redefined under an `else`, in either order, and overloaded: the
        # one that is not `Public` is kept
        "control.redefined_var.a": "int",
        "control.reversed_var.a": "int",
        "control.overloaded_var.a": "int",
    }
    # a plain name is not walked, an int operand of its own notwithstanding
    assert "control.mod_inv.a" not in found
    # nor is an alias of `int` under another name
    assert "control.leaf_var.p" not in found
    ints = {name for name, annotation in found.items() if annotation == "int"}
    assert _unexplained(found, {}) == ints
    assert not _unexplained(found, dict.fromkeys(ints, "window"))
    reasons = {"control.double_mult_var.w": "window", "control._jacobi_var.a": "x"}
    assert _stale(found, reasons) == {"control._jacobi_var.a"}
    # a reason naming no parameter at all is stale too
    assert _stale(found, {"control.double_mult_var.v": "x"}) == {
        "control.double_mult_var.v"
    }
