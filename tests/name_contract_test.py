# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what a public function's name promises about its answer.

CONTRIBUTING.md's "Every public function validates its inputs" states the
vocabulary: `assert_*` and `validate_*` refuse and return None, `is_*`
and `verify*` answer a bool about a value of a declared type, and
`check_*` answers a bool *and* refuses what cannot be an answer -- the
one prefix that warns a caller it still needs an `except`.

A prefix that says several things says nothing, which is what issue
btclib-org/btclib#814 found of `check_`, and a vocabulary kept as a habit
is one nothing notices drifting. So it is a rule here, read off the
annotations rather than off a list of names somebody keeps in step. What
it cannot see is the *contract*: that one `is_` is total over its values
and one `check_` is not is a promise in prose, and only the return type
is here.

There is no exemption list: every name carrying a prefix is held to it,
and every public bool carries one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIBRARY = Path(__file__).parents[1] / "src" / "ecc"

# what each prefix promises the return type is. `verify` is matched anywhere in
# the name and not only at the front: `batch_verify_`, `partial_sig_verify` and
# `anti_exfil_host_verify` are verifications, and reading the front alone is
# what left them out of issue btclib-org/btclib#814's first census. The others
# are matched at the front only, the underscore included, so a `validated_x`
# promises nothing
_PROMISED: dict[str, str] = {
    "assert_": "None",
    "check_": "bool",
    "is_": "bool",
    "validate_": "None",
    "verify": "bool",
}


def _promised_by(name: str) -> str | None:
    """Return the type the name promises, or None if it promises nothing."""
    return next(
        (
            promised
            for prefix, promised in _PROMISED.items()
            if name.startswith(prefix) or (prefix == "verify" and prefix in name)
        ),
        None,
    )


def _return_type(returns: ast.expr) -> str:
    """Return what a function's annotation promises its caller, TypeIs as bool.

    `TypeIs[Octets]` narrows a caller's type checker and answers exactly
    `True` or `False` at runtime (PEP 742), the same as the `bool` it
    replaced on `_utils.is_octets` -- so a name promising `bool` is kept
    to that promise by one, and this is the one place the annotation is
    read for both censuses below. The walks' own `node.returns is not
    None` narrows `returns` before it is passed, here and to `_answer`.
    """
    unparsed = ast.unparse(returns)
    if unparsed.startswith("TypeIs["):
        return "bool"
    return unparsed


_Function = ast.FunctionDef | ast.AsyncFunctionDef


_COROUTINE = "Coroutine["


def _answer(node: _Function, returns: ast.expr) -> str:
    """Return what a call to the function answers, as `_return_type` reads it.

    An `async def` answers a coroutine, whatever its annotation, and a
    coroutine keeps no prefix's promise: CONTRIBUTING.md's "Every public
    function validates its inputs" says why.
    """
    answer = _return_type(returns)
    if isinstance(node, ast.AsyncFunctionDef):
        return f"{_COROUTINE}{answer}]"
    return answer


def _definitions_in(source: str) -> list[_Function]:
    """Return each function of a module's body or of a class body.

    A function inside another function is a local helper: no caller can
    name it, so its name promises nothing. A class starts a body wherever
    it sits, so a method of a class inside a function is returned.
    """
    found: list[_Function] = []

    def visit(node: ast.AST, in_body: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if in_body and isinstance(child, _Function):
                found.append(child)
            if isinstance(child, ast.ClassDef):
                visit(child, in_body=True)
            elif isinstance(child, _Function):
                visit(child, in_body=False)
            else:
                visit(child, in_body)

    visit(ast.parse(source), in_body=True)
    return found


def _named_in(module: str, source: str) -> dict[str, list[str]]:
    """Map each public name of a module that promises a type to its answers.

    A name defined twice, in two classes or in two branches of an `if`,
    lists both answers, each as `_answer` reads it, so neither hides the
    other.
    """
    found: dict[str, list[str]] = {}
    for node in _definitions_in(source):
        if node.name.startswith("_"):
            continue
        if _promised_by(node.name) is None:
            continue
        # every function of this package is annotated, mypy running
        # strict over it, so an unannotated one is a state the tree
        # does not reach
        assert node.returns is not None
        answer = _answer(node, node.returns)
        found.setdefault(f"{module}.{node.name}", []).append(answer)
    return found


def _named() -> dict[str, list[str]]:
    """Map every public function whose name promises a type, as `_named_in`.

    Methods included, a property being one: an `is_` read off an object
    promises a bool as much as a module-level one does.

    The dotted name is the file's path and keeps the `__init__` of a
    package module, which is what `input_validation_test.py`'s walk does
    and is importable either way: one spelling across the two gates.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _named_in(module, path.read_text(encoding="utf-8"))
    return found


def _breaks_its_promise(dotted: str, returns: list[str]) -> bool:
    """Return whether a definition under the name breaks its promise."""
    promised = _promised_by(dotted.rpartition(".")[2])
    return any(returned != promised for returned in returns)


# an argument-less member of a public class is a read, and a read is a
# `@property`. These are the shapes that are not a read, by what they do
# rather than by a list of names -- which is what keeps the rule from
# needing one (issue btclib-org/btclib#814):
#
# - `assert_*` and `validate_*` refuse, and a property that refuses is a
#   trap: reading `obj.assert_valid` evaluates the method and throws it
#   away
# - `to_*` converts, and hands back a new object rather than a read of
#   this one
# - `wipe` is an action with a side effect
_NOT_A_READ = ("assert_", "to_", "validate_")
_AN_ACTION = frozenset({"wipe"})

# hashlib's own API, mirrored in a Protocol, and hashlib draws the line
# itself: `digest()`, `hexdigest()` and `copy()` are calls where
# `block_size`, `digest_size` and `name` are attributes. So these three
# are named one by one rather than the class being exempt -- a property
# here would stop anything `hashlib.new` returns from satisfying
# HashObject, and the other three are reads and stay properties
_MIRRORS_HASHLIB = frozenset(
    {
        "ecc.alias.HashObject.copy",
        "ecc.alias.HashObject.digest",
        "ecc.alias.HashObject.hexdigest",
    }
)


def _is_a_read(decorated: set[str]) -> bool:
    """Return whether the decorators make this a read rather than a call.

    `functools.cached_property` is one as much as `property` is -- it
    computes once and is read thereafter -- and testing the set for
    `"property"` alone would miss it.
    """
    return bool(
        decorated & {"property", "cached_property", "functools.cached_property"}
    )


def _is_not_a_read(dotted: str) -> bool:
    """Return whether a member's name says it is not a read."""
    name = dotted.rpartition(".")[2]
    return (
        name.startswith(_NOT_A_READ) or name in _AN_ACTION or dotted in _MIRRORS_HASHLIB
    )


def _misshapen(dotted: str, reads: list[bool]) -> bool:
    """Return whether a definition under the name has the wrong shape.

    A name that says it is not a read is never a property, and any other
    is always one.
    """
    if _is_not_a_read(dotted):
        return any(reads)
    return not all(reads)


def _class_members_in(module: str, source: str) -> dict[str, list[bool]]:
    """Return every argument-less member of a public class of a module.

    A member is a `def` of the class's body, one under a statement such as
    an `if` included, and not one of a nested class or function. The key
    is the member's dotted path, each enclosing class and function
    included, so two nested classes of one name are two keys. The value
    lists each definition, so a property does not hide a method of the
    same name.
    """
    found: dict[str, list[bool]] = {}

    def record(node: ast.FunctionDef, prefix: str) -> None:
        if node.name.startswith("_"):
            return
        decorated = {ast.unparse(d) for d in node.decorator_list}
        if {"staticmethod", "classmethod"} & decorated:
            return
        # no filter for a `@x.setter`: one takes the value it
        # sets, so the argument count below excludes it already
        arguments = [
            a.arg
            for a in [
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            ]
            if a.arg != "self"
        ]
        if arguments or node.args.vararg or node.args.kwarg:
            return
        found.setdefault(f"{prefix}{node.name}", []).append(_is_a_read(decorated))

    # every node is visited, with the dotted path of the classes and
    # functions around it, as `public_parameter_test.py`'s walk does. It
    # also carries whether the node is in the body of a public class; a
    # nested class sets it to its own publicity, a nested function clears it
    def visit(node: ast.AST, prefix: str, in_public_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if in_public_class and isinstance(child, ast.FunctionDef):
                record(child, prefix)
            if isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.", not child.name.startswith("_"))
            elif isinstance(child, _Function):
                visit(child, f"{prefix}{child.name}.", in_public_class=False)
            else:
                visit(child, prefix, in_public_class)

    visit(ast.parse(source), f"{module}.", in_public_class=False)
    return found


def _class_members() -> dict[str, list[bool]]:
    """Return every argument-less member of a public class, property or not.

    A property is a class thing, so a module-level function is out of
    scope however few arguments it takes. Methods of a private class
    are out too: a private class is not API. So is an `async def`: its
    caller awaits it, which makes it a call.
    """
    found: dict[str, list[bool]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _class_members_in(module, path.read_text(encoding="utf-8"))
    return found


def _public_bools_in(module: str, source: str) -> set[str]:
    """Return every public function of a module that answers a bool.

    The dotted name drops the class, as `_named` above does: a method and
    a module function of one name are one entry, which is the spelling
    `input_validation_test.py` uses too. The gate below reads the name
    alone, so one entry judges every definition under it.
    """
    found: set[str] = set()
    for node in _definitions_in(source):
        if node.name.startswith("_"):
            continue
        if node.returns is not None and _answer(node, node.returns) == "bool":
            found.add(f"{module}.{node.name}")
    return found


def _public_bools() -> list[str]:
    """Return every public function that answers a bool, however named."""
    found: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _public_bools_in(module, path.read_text(encoding="utf-8"))
    return sorted(found)


_NAMED = _named()
_PUBLIC_BOOLS = _public_bools()
_CLASS_MEMBERS = _class_members()


@pytest.mark.parametrize("dotted", sorted(_NAMED))
def test_the_name_says_what_the_answer_is(dotted: str) -> None:
    """The rule, over every public name that carries one of the prefixes."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert not _breaks_its_promise(dotted, _NAMED[dotted]), (
        f"{dotted} returns {_NAMED[dotted]} where its name promises {promised}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """One name per prefix it must find, and the two kinds it must not.

    A walk that found nothing would pass the test above.
    """
    assert _NAMED["ecc.curves.curve_group.is_on_curve"] == ["bool"]
    assert _NAMED["ecc.dsa.verify_"] == ["bool"]
    assert _NAMED["ecc.ssa.batch_verify"] == ["bool"]
    assert _NAMED["ecc.dsa.assert_as_valid"] == ["None"]
    assert _NAMED["ecc.frost.validate_threshold_info"] == ["None"]
    # `TypeIs` read as the bool it answers
    assert _NAMED["ecc._utils.is_octets"] == ["bool"]
    # a method
    assert _NAMED["ecc.dsa.assert_valid"] == ["None"]

    # a private name, and a name that promises nothing
    assert "ecc.hashes._assert_valid_hf" not in _NAMED
    assert "ecc._utils.bytes_from_octets" not in _NAMED


# a `validate_` that refuses, one that answers a bool, an `async def` one
# annotated as refusing, and two names that carry the word without the
# prefix: not followed by an underscore, and not at the front
_VALIDATE_CONTROL = """
def validate_refusal(a: int) -> None: ...
def validate_answer(a: int) -> bool: ...
async def validate_later(a: int) -> None: ...
def validated_name(a: str) -> str: ...
def revalidate_cache(a: str) -> str: ...
"""


def test_a_validate_answering_a_bool_breaks_its_promise() -> None:
    """The rule fails a `validate_` that answers a bool, or a coroutine.

    The tree's own `validate_` functions all refuse, so the rule above
    never fails on one: this source holds the cases that must.
    """
    named = _named_in("control", _VALIDATE_CONTROL)
    assert named == {
        "control.validate_refusal": ["None"],
        "control.validate_answer": ["bool"],
        "control.validate_later": ["Coroutine[None]"],
    }
    broken = {d for d, returns in named.items() if _breaks_its_promise(d, returns)}
    assert broken == {"control.validate_answer", "control.validate_later"}


# a name defined twice, in two classes and in two branches of an `if`, the
# definition that breaks the rule first, where the second would overwrite
# it; a property of a nested class, defined once; two nested classes of
# one name under two outer classes; a method and a nested class under an
# `if` of a class body, and a private class there; a member defined as a
# method and as a property in the two branches of an `if`, in both orders,
# under a read's name and under a `to_` one; a function inside a method,
# which is not a member; a class inside a function; an `async def` taking
# only `self`, which `_named_in` records as the coroutine it answers, and
# which `_public_bools_in` and `_class_members_in` do not record; and an
# `async def` under each other prefix but `validate_`, which
# `_VALIDATE_CONTROL` holds, each annotated as its prefix promises
_REDEFINED_CONTROL = """
class Block:
    def is_final(self) -> bool: ...
    async def is_ready(self) -> bool: ...
class Tx:
    @property
    def is_final(self) -> bool: ...
class Outer:
    class Inner:
        @property
        def is_inner(self) -> bool: ...
class Left:
    class Node:
        @property
        def depth(self) -> int: ...
    def walk(self, a: int) -> None:
        def step() -> int: ...
class Right:
    class Node:
        def depth(self) -> int: ...
    if TYPE_CHECKING:
        def width(self) -> int: ...
        class Leaf:
            @property
            def width(self) -> int: ...
        class _Hidden:
            def width(self) -> int: ...
class Pair:
    if TYPE_CHECKING:
        def width(self) -> int: ...
    else:
        @property
        def width(self) -> int: ...
    if TYPE_CHECKING:
        @property
        def height(self) -> int: ...
    else:
        def height(self) -> int: ...
    if TYPE_CHECKING:
        def to_dict(self) -> int: ...
    else:
        @property
        def to_dict(self) -> int: ...
    if TYPE_CHECKING:
        @property
        def to_list(self) -> int: ...
    else:
        def to_list(self) -> int: ...
def f() -> None:
    class K:
        @property
        def size(self) -> int: ...
if TYPE_CHECKING:
    def verify_tx(a: int) -> int: ...
else:
    def verify_tx(a: int) -> bool: ...
async def assert_later(a: int) -> None: ...
async def check_later(a: int) -> bool: ...
async def verify_later(a: int) -> bool: ...
"""


def test_a_second_definition_hides_no_first() -> None:
    """No definition of a name hides another one.

    `_named_in` and `_class_members_in` list each definition once, and
    `_public_bools_in` keeps the name, which is all it judges. `_named_in`
    records an `async def` as a coroutine, which breaks the promise of its
    prefix; the other walks do not record it. The tree holds no prefixed
    name whose definitions disagree, and no `async def`: this source holds
    both.
    """
    named = _named_in("control", _REDEFINED_CONTROL)
    assert named == {
        "control.is_final": ["bool", "bool"],
        "control.is_ready": ["Coroutine[bool]"],
        "control.is_inner": ["bool"],
        "control.verify_tx": ["int", "bool"],
        "control.assert_later": ["Coroutine[None]"],
        "control.check_later": ["Coroutine[bool]"],
        "control.verify_later": ["Coroutine[bool]"],
    }
    broken = {d for d, returns in named.items() if _breaks_its_promise(d, returns)}
    assert broken == {
        "control.is_ready",
        "control.verify_tx",
        "control.assert_later",
        "control.check_later",
        "control.verify_later",
    }

    assert _public_bools_in("control", _REDEFINED_CONTROL) == {
        "control.is_final",
        "control.is_inner",
        "control.verify_tx",
    }
    members = _class_members_in("control", _REDEFINED_CONTROL)
    assert members == {
        "control.Block.is_final": [False],
        "control.Tx.is_final": [True],
        "control.Outer.Inner.is_inner": [True],
        "control.Left.Node.depth": [True],
        "control.Right.Node.depth": [False],
        "control.Right.width": [False],
        "control.Right.Leaf.width": [True],
        "control.Pair.width": [False, True],
        "control.Pair.height": [True, False],
        "control.Pair.to_dict": [False, True],
        "control.Pair.to_list": [True, False],
        "control.f.K.size": [True],
    }
    # the definition of the wrong shape fails the member gate, whichever
    # branch holds it
    for pair in ("width", "height", "to_dict", "to_list"):
        assert _misshapen(f"control.Pair.{pair}", members[f"control.Pair.{pair}"])


def test_check_says_one_thing() -> None:
    """`check_` is the prefix btclib-org/btclib#814 found meaning four things.

    None is here, and pinning that keeps one from being added without
    the question being asked: a refusal is an `assert_`, a converter is
    named for what it returns, and a query for what it answers.
    """
    checks = {d for d in _NAMED if d.rpartition(".")[2].startswith("check_")}
    assert not checks


@pytest.mark.parametrize("dotted", _PUBLIC_BOOLS)
def test_every_public_bool_is_named_by_the_vocabulary(dotted: str) -> None:
    """A bool carries one of the prefixes.

    What this closes is the gap the prefixes alone leave: they promise a
    shape to a caller who sees one, and say nothing about a bool that
    carries none.
    """
    name = dotted.rpartition(".")[2]
    assert _promised_by(name) is not None, (
        f"{dotted} answers a bool and its name promises nothing"
    )


# bool helpers inside a method, inside an `async def` method and inside a
# module function, the last two under a prefix: none is a member or
# public. A class inside a method starts a body, and its argument-less
# bool is both
_NESTED_CONTROL = """
class Tx:
    def size(self, a: int) -> int:
        def ok() -> bool: ...
        class Kind:
            def is_known(self) -> bool: ...
        return 0
    async def later(self) -> None:
        def is_done() -> bool: ...
def build() -> None:
    def is_empty() -> bool: ...
"""


def test_a_nested_helper_is_neither_member_nor_public() -> None:
    """A function inside another function is neither a member nor public.

    No `@property` can make a local helper a read, so `_class_members_in`
    records only a `def` of a class body. No caller can name one either,
    so `_public_bools_in` and `_named_in` record only a `def` of a
    module's body or of a class body.
    """
    members = _class_members_in("control", _NESTED_CONTROL)
    assert members == {"control.Tx.size.Kind.is_known": [False]}
    assert _public_bools_in("control", _NESTED_CONTROL) == {"control.is_known"}
    assert _named_in("control", _NESTED_CONTROL) == {"control.is_known": ["bool"]}


@pytest.mark.parametrize("dotted", sorted(_CLASS_MEMBERS))
def test_an_argument_less_member_is_read_not_called(dotted: str) -> None:
    """Whatever it answers, a member that takes nothing is a `@property`.

    Two reads of
    one object spelled two ways, one as an attribute and one as a call,
    are one shape more than a reader should have to remember.

    What is not a read is here by shape and not by a list of names, which
    is what keeps this rule from needing one.
    """
    if _is_not_a_read(dotted):
        assert not _misshapen(dotted, _CLASS_MEMBERS[dotted]), (
            f"{dotted} is a @property and its name says it is not a read:"
            " rename it, or drop the decorator"
        )
        return
    assert not _misshapen(dotted, _CLASS_MEMBERS[dotted]), (
        f"{dotted} takes nothing but self: it is a @property, not a method"
    )


def test_the_walk_reaches_every_shape_of_member() -> None:
    """One of each, so neither branch above is running over nothing."""
    assert _CLASS_MEMBERS["ecc.rangeproof.RangeProof.max_value"] == [True]
    # and the three of HashObject that hashlib spells as attributes
    assert _CLASS_MEMBERS["ecc.alias.HashObject.digest_size"] == [True]
    # and the shapes that are not a read
    assert _CLASS_MEMBERS["ecc.dsa.Sig.assert_valid"] == [False]
    assert _CLASS_MEMBERS["ecc.dsa.Signer.wipe"] == [False]
    assert _CLASS_MEMBERS["ecc.alias.HashObject.digest"] == [False]


# a refusal that takes nothing but `self`, which the tree's own
# `validate_` functions do not, beside a read
_MEMBER_CONTROL = """
class Spend:
    def validate_inputs(self) -> None: ...
    @property
    def fee(self) -> int: ...
"""


def test_a_validate_member_is_not_a_read() -> None:
    """A self-only `validate_` member stays a method, as an `assert_` does."""
    members = _class_members_in("control", _MEMBER_CONTROL)
    assert members == {
        "control.Spend.validate_inputs": [False],
        "control.Spend.fee": [True],
    }
    # the gate above fails a member whose shape and name disagree
    assert not any(_misshapen(d, reads) for d, reads in members.items())
