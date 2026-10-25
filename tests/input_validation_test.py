# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the two rules about a public function's inputs.

> Every public function guarantees the validation of all its inputs,
> directly or indirectly. A malformed argument leaves as
> `EccTypeError` or `EccValueError`.

CONTRIBUTING.md's "Every public function validates its inputs" states it, and
which of the two classes comes out is not a coin toss -- it is the distinction
issue btclib-org/btclib#814 settled, so this file drives the two separately:

- **a value of a type the signature does not declare** is the caller's
  own mistake, and leaves as an `EccTypeError`. Every function
  the walk can drive, without exception.
- **a value of a declared type that no valid input carries** is a fact
  about the input, and leaves as an `EccException`.

Both are `EccException`, which is what makes the second rule one
predicate instead of a tuple that has to be kept in step with the
hierarchy.

## How it calls what it calls

The package's input types are few and well bounded, most of them named in
`src/ecc/alias.py` and the key ones beside their converters.
`_WRONG_TYPE` and `_WRONG_VALUE` give each of them values of the two
kinds, and the walk finds every public module-level function whose
*required* parameters are all of those types. Those it can call with no
fixture and no knowledge of what the function does.

Every argument is wrong at once, which is not weaker than one wrong
argument among valid ones: whichever the function refuses first, the rule
says how it must refuse it. And it needs no valid values, which is what
makes the walk automatic -- a valid `Octets` is 20 bytes for one
function, 32 for another and any length for a third, so the table of
those is the hand-written thing this avoids.

## What it does not reach, and why that is not a hole to plug here

A **parameter with a default** is never driven: to reach it the
arguments before it would have to be valid, which is the table this
design is built to do without. `ec` is gated by hand this way at most of
its call sites, and the family of it that is large enough to be walked
has a file: `tests/curve_parameter_test.py` for every parameter
declaring a curve. It carries the table this walk avoids, and a walk of
its own over the parameter it is about, so the table cannot go stale
quietly. A default is not the only reason a required parameter goes
unreached, though: `ssa.challenge_` takes `ec` with none, and stays
unreached anyway, for the reason below.

A **method**, and a function taking a signature object or a callback,
needs a valid instance the vocabulary cannot build, and stays hand-read.
`test_the_walk_reaches_what_it_claims` pins what the walk does find, so a
narrowing of it fails here rather than quietly running over less.

A **plain `bytes`, `bytearray`, `int` or `HashF`** -- a builtin, rather
than one of `alias.py`'s own names -- has no coercion the way `Octets`
has `bytes_from_octets` or `Integer` has `int_from_integer`: `assert_type`
(or, for `HashF`, `_assert_valid_hf`) refuses what is not the declared
type, but refuses nothing on content, because there is no content a
valid `bytes`, a valid `bytearray`, a valid `int` or a valid callable
could not be. So there is no wrong *value* of one of these four that
every caller of it agrees is wrong, only a wrong *type* -- and
`hashes.tagged_hash`'s `tag` and `m`, both required and both nothing but
`bytes`, are the case that makes this concrete: driving a wrong-value
round over the two of them would find nothing to raise on and fail the
walk over a call with nothing wrong with it. `_WRONG_TYPE` and
`_WRONG_VALUE` are read together everywhere else in this file, so rather
than carrying four keys through only one of the two dicts, these four
stay out of both, and the functions they gate are validated and driven
by hand instead: `kdf_test.py`, `hashes_test.py`, `schemes/ecies_test.py`,
`schemes/commit_nonce_test.py`, `schemes/musig2_test.py` and
`schemes/frost_test.py` hold `kdf.ansi_x9_63_kdf`, `kdf.hkdf`,
`kdf.hkdf_expand`, `kdf.hkdf_extract`, `hashes.tagged_hash`, `ecies.encrypt`,
`commit_nonce.commit_nonce_`, `musig2.sign` and `frost.sign` to the same
`EccTypeError`/`EccValueError` contract this file drives
automatically for everything else (issue btclib-org/ecc#11).

`int` alone would also reach outside this package's input-validation
surface and into arithmetic this file has never gated:
`number_theory.xgcd_var` and its neighbours take a bare `int` operand
with no invalid value either -- `xgcd_var(-1, -1)` is a legitimate
extended Euclid, not a malformed argument.
`curves.curve_group.signed_odd_digits` refuses a non-integer `m`, `w` or
`size` of its own accord, driven by hand in `curves/curve_group_test.py`
rather than by this walk, in a module of its own (issue
btclib-org/ecc#34).

## The two lists

`_WRONG_TYPE` and `_WRONG_VALUE` are the vocabulary, and every name in
them is a type this tree still declares: a rename would otherwise shrink
the walk in silence, which `test_the_vocabulary_is_the_libraries_input_types`
is against. Which dict a value belongs in is the only judgement in this
file, and it is the annotation's to make: `1.5` is no `Octets`, `"not hex
at all"` is one that will not decode.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from ecc.exceptions import EccException, EccTypeError

_LIBRARY = Path(__file__).parents[1] / "src" / "ecc"

# a value of no type the alias declares: the caller's own mistake, and a
# call mypy refuses. The tuples are read round-robin so that a function
# taking three parameters of one type is called with three different
# wrong values. Constants and not a strategy: what this gate reports has
# to be the same on two runs, the lists below being read as statements
# about the tree
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "BinaryData": (None, 1.5),
    "Integer": (None, 1.5),
    # an Octets, beside None and 1.5: every Octets is itself iterable, so a
    # signature reading Sequence[Octets] or Iterable[Octets] accepts one as far
    # as mypy goes, and a function that does not refuse it by name zips through
    # its bytes instead (issue btclib-org/btclib#1405). All four Octets
    # spellings, a guard naming three of the four otherwise passing this walk
    # (issue btclib-org/btclib#1434)
    "Iterable[Octets]": (
        None,
        1.5,
        b"\xaa\xbb\xcc\xdd",
        bytearray(b"\xaa\xbb\xcc\xdd"),
        memoryview(b"\xaa\xbb\xcc\xdd"),
    ),
    "Octets": (None, 1.5, tuple(range(4))),
    "Point": (None, 1.5, "not a point"),
    "PubKey": (None, 1.5),
    "Sequence[Octets]": (
        None,
        1.5,
        b"\xaa\xbb\xcc\xdd",
        bytearray(b"\xaa\xbb\xcc\xdd"),
        memoryview(b"\xaa\xbb\xcc\xdd"),
    ),
    "String": (None, 1.5, 1),
}

# a value of a declared type that no valid input carries: a fact about
# the input, and the half a bool function answers False about. Every one
# of these type checks but a tuple of the wrong arity, which
# CONTRIBUTING.md's "The public surface" counts as a value: that is what
# puts it in this dict rather than in the one above
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    "BinaryData": ("not hex at all",),
    "Integer": ("not hex at all",),
    # a hex string that is not hex, and one of odd length
    "Octets": ("not hex at all", "9"),
    # a tuple of the wrong arity, and a pair of ints that is no point:
    # run time cannot tell tuple[int] from tuple[int, int], so the arity
    # is a value here and not a type
    "Iterable[Octets]": (["not hex at all"],),
    "Point": ((1,), (1, 2)),
    "PubKey": ("not a key",),
    "Sequence[Octets]": (["not hex at all"],),
    "String": ("not ascii \u00e9",),
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _WRONG_TYPE else None


def _drivable() -> dict[str, list[str]]:
    """Return every public function the vocabulary can call, by dotted name.

    Required parameters only: what carries a default is what a caller may
    leave out, so a function is driven on the arguments it insists on.
    All of them have to be in the vocabulary -- one `Tx` and the walk has
    nothing to pass.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            positional = [*node.args.posonlyargs, *node.args.args]
            required = positional[: len(positional) - len(node.args.defaults)]
            # `is not None` narrows for mypy and never filters: mypy runs
            # strict over this package, so a parameter without an
            # annotation is a state the library does not reach
            annotations = [a.annotation for a in required if a.annotation is not None]
            aliases = [_alias_of(a) for a in annotations]
            if required and len(aliases) == len(required) and all(aliases):
                found[f"{module}.{node.name}"] = [a for a in aliases if a]
    return found


_DRIVABLE = _drivable()


def _calls(
    dotted: str, vocabulary: dict[str, tuple[Any, ...]]
) -> Iterator[Callable[[], Any]]:
    """Yield one prepared call per round, every argument wrong at once.

    The vocabulary is the parameter, and it is the whole of what tells the
    two rules apart: the same walk, the same function, two kinds of wrong
    value.
    """
    module_name, _, name = dotted.rpartition(".")
    function = getattr(importlib.import_module(module_name), name)
    aliases = _DRIVABLE[dotted]
    for round_ in range(max(len(vocabulary[a]) for a in aliases)):
        args = [vocabulary[a][round_ % len(vocabulary[a])] for a in aliases]
        # partial and not a lambda, which would close over the loop
        # variables and be read on a later round
        yield partial(function, *args)


_DRIVEN = sorted(_DRIVABLE)


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_type_leaves_as_a_type_error_of_the_package(dotted: str) -> None:
    """The first rule, and it has no exceptions.

    `EccTypeError` and not `EccException`: this is
    where the class is the point. A bare `TypeError` fails here as an
    `EccValueError` does -- the first is a leak from underneath
    the package, the second is the package calling a caller's mistake a
    fact about the input.
    """
    for call in _calls(dotted, _WRONG_TYPE):
        with pytest.raises(EccTypeError):
            call()


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_value_leaves_as_an_exception_of_the_package(dotted: str) -> None:
    """The second rule, over every function the walk drives.

    `EccException` and not one of the three: which of them a
    malformed value deserves is the function's to decide -- a size is an
    `EccValueError`, a bool where a number belongs is an
    `EccTypeError` -- and the contract a caller is given is the
    base.
    """
    for call in _calls(dotted, _WRONG_VALUE):
        with pytest.raises(EccException):
            call()


def test_the_vocabulary_is_the_libraries_input_types() -> None:
    """A renamed type would narrow the walk without failing anything.

    Every name in the two vocabularies is still declared under
    `src/ecc/`, and
    every type `alias.py` declares and a public parameter is annotated
    with is either in the vocabulary or named below with the reason no
    wrong value can be built for it.
    """
    declared: set[str] = set()
    in_alias_py: set[str] = set()
    annotated: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            node.targets[0].id
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id[0].isupper()
        }
        declared |= names
        if path.name == "alias.py":
            in_alias_py = names
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            annotated |= {
                ast.unparse(a.annotation).replace(" | None", "").strip()
                for a in arguments
                if a.annotation is not None
            }

    # `Sequence[Octets]` and `Iterable[Octets]` are not declarations of
    # their own -- `Octets` is -- so a renamed `Octets` is still caught
    # by unwrapping one level before checking
    def _is_declared(alias: str) -> bool:
        for wrapper in ("Sequence[", "Iterable["):
            if alias.startswith(wrapper) and alias.endswith("]"):
                return alias[len(wrapper) : -1] in declared
        return alias in declared

    assert set(_WRONG_TYPE) == set(_WRONG_VALUE)
    assert all(_is_declared(alias) for alias in _WRONG_TYPE)

    without_a_wrong_value = {
        # not always behind a default: `ssa.challenge_` and four of
        # `kdf`'s functions take it with none (issue
        # btclib-org/ecc#11). What keeps it out of
        # `_WRONG_TYPE`/`_WRONG_VALUE` is that it has no wrong value the
        # module docstring's "What it does not reach" does not already
        # give a shared reason for -- `hashes._assert_valid_hf` is the
        # check, and tests/hashes_test.py, kdf_test.py, dsa_test.py and
        # ssa_test.py are where it is held to it by hand
        "HashF",
        # a callable, and the same reason again: its wrong values are the
        # non-callables, and it is never a required parameter
        "CipherF",
        # the internal coordinates: no public parameter takes them from a
        # caller, `curves` converting to them and back
        "JacPoint",
    }
    assert in_alias_py & annotated <= set(_WRONG_TYPE) | without_a_wrong_value


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and two it must not.

    A walk that found nothing would pass every test above. One function
    per shape it has to reach -- a single parameter, two of different
    types, one behind a default it must ignore -- and the two kinds it
    must leave alone: a private name, and a function whose required
    parameters are not all in the vocabulary.
    """
    assert _DRIVABLE["ecc.hashes.reduce_to_hlen"] == ["Octets"]
    assert _DRIVABLE["ecc.ecc.dleq.generate_proof"] == ["Integer", "PubKey"]
    # `ec` and `compressed` carry defaults and are not driven
    assert _DRIVABLE["ecc.curves.sec_point.bytes_from_point"] == ["Point"]

    assert "ecc.hashes._assert_valid_hf" not in _DRIVABLE
    # a required parameter the vocabulary cannot build: a signature object
    assert "ecc.ecc.dsa.verify" not in _DRIVABLE
