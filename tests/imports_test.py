# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the import graph of the `ecc` package.

Every module must be importable *first*, with no other module of this
package in sys.modules yet. Nothing else in the suite establishes that: a
test module reaches its subject through whatever the modules imported
before it have already pulled in, so a cycle that only bites the caller
who happens to arrive from the other side stays invisible.

What a module may import is the standard library, `typing_extensions`,
the bindings, gmpy2 and this package: each module is asked in an interpreter of
its own at run time, and each file's import statements are read
statically, which is what a module the suite never imports is checked
by.
"""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, cast

import pytest

import ecc
from tests import module_names

if TYPE_CHECKING:
    from collections.abc import Iterator

_ROOT = Path(__file__).resolve().parents[1]


def _is_ours(name: str) -> bool:
    """Answer whether a dotted name is this package or one of its modules.

    `ecc` and not a bare `startswith`, which would also take in
    a sibling distribution whose name merely begins the same way.
    """
    return name == "ecc" or name.startswith("ecc.")


def loaded_modules() -> list[str]:
    """Return the modules of this package in sys.modules."""
    return [name for name in sys.modules if _is_ours(name)]


@pytest.fixture
def unimported() -> Iterator[None]:
    """Hide every module of this package, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it costs an interpreter start-up per module for
    nothing: the import machinery decides what to execute by consulting
    sys.modules and nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in loaded_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in loaded_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", module_names())
def test_import_first(module_name: str, unimported: None) -> None:
    """Import each module first, with nothing of this package loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def _loaded_after_importing(module_name: str) -> list[str]:
    """Import one module in a fresh interpreter and return sorted(sys.modules).

    A fresh subprocess rather than `unimported`: that fixture only hides
    this package's own modules from `sys.modules`, so a third-party
    package an earlier test already imported would still answer present,
    and the absence this module exists to prove would mean nothing.
    """
    probe = f"import {module_name}, sys; print(sorted(sys.modules))"
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=_ROOT,
    ).stdout
    return cast("list[str]", ast.literal_eval(stdout))


def test_the_tests_package_imports_no_submodule() -> None:
    """Importing the `tests` package alone reaches the root and no further.

    `tests/__init__.py` is imported by every test module before that
    module's own body runs -- before any fixture, `unimported` included,
    so this probe is a subprocess rather than that fixture. The coverage
    floor reads what the import itself reaches, so a helper built at the
    module scope of `tests/__init__.py` would be measured as reached by
    every module that asks it nothing.
    """
    loaded = _loaded_after_importing("tests")
    assert [m for m in loaded if _is_ours(m)] == ["ecc"]


# what is heavier than the stdlib basics, and `btclib`, which builds on this
# package and so cannot be below it. Not `socket`: the root reads `__version__`
# through `importlib.metadata`, which pulls in `email.utils` and, through it,
# `socket`, on every interpreter before 3.13, so asserting its absence would be
# a fact about the interpreter rather than about the package
_ABOVE_OR_HEAVY = ("btclib", "urllib.request", "ssl", "http.client")


@pytest.mark.parametrize("module_name", module_names())
def test_no_module_reaches_above_the_package(module_name: str) -> None:
    """Each module, imported alone, loads neither `btclib` nor a heavy module.

    A heavy module-level import here would be paid by every importer of
    this package, whatever it imported it for.
    """
    loaded = _loaded_after_importing(module_name)
    assert not set(loaded) & set(_ABOVE_OR_HEAVY)


def _loaded_within(entry_point: str) -> set[str]:
    """Return the modules of this package one import loads, the root aside."""
    return {m for m in _loaded_after_importing(entry_point) if _is_ours(m)} - {"ecc"}


def test_curves_stays_stdlib_light() -> None:
    """`ecc.curves` loads the arithmetic and the substrate alone.

    Subset rather than equal: a new edge into the package is the defect
    this exists to catch, and a removed one is not. Narrower than the
    package: it is the curve's own arithmetic, and its docstring states
    "Nothing here knows what a signature is", so `ecc.ecc` is out of it.
    """
    assert _loaded_within("ecc.curves") <= {
        "ecc._libsecp256k1",
        "ecc._utils",
        "ecc.alias",
        "ecc.curves",
        "ecc.curves.curve",
        "ecc.curves.curve_group",
        "ecc.curves.curve_group_2",
        "ecc.curves.curve_group_f",
        "ecc.curves.sec_point",
        "ecc.exceptions",
        "ecc.number_theory",
    }


def test_ecc_loads_every_scheme() -> None:
    """`ecc.ecc` binds each scheme it publishes, eagerly.

    Its `__init__` imports every module `__all__` names, which is what
    lets `ecc.ecc.dsa` answer after `import ecc.ecc`
    alone; the heavy modules are asked of it by the test above.
    """
    loaded = _loaded_within("ecc.ecc")
    schemes = {
        f"ecc.ecc.{name}"
        for name in importlib.import_module("ecc.ecc").__all__
        if isinstance(getattr(importlib.import_module("ecc.ecc"), name), ModuleType)
    }
    assert schemes
    assert schemes <= loaded


# the distributions a module of the package may import at the top level,
# beside the standard library: the typing backport, the bindings, whose
# absence `_libsecp256k1` answers for, gmpy2, whose absence
# `number_theory` answers for, and the package itself
_ALLOWED_THIRD_PARTY = frozenset(
    {"typing_extensions", "btclib_secp256k1", "gmpy2", "ecc"}
)


def _top_level_imports(source: str) -> set[str]:
    """Return the first component of every name one module's imports name.

    Relative imports name this package, so they are recorded as it.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add("ecc" if node.level else (node.module or "").split(".")[0])
    return names


def _outside(names: set[str]) -> list[str]:
    """Return what is neither the standard library nor allowed."""
    return sorted(names - set(sys.stdlib_module_names) - _ALLOWED_THIRD_PARTY)


def test_the_import_scan_finds_a_planted_import() -> None:
    """The scan names each form, and the check refuses what is outside."""
    source = (
        "import hashlib\nimport btclib.b58\nfrom btclib_wallet import bip32\n"
        "from . import kdf\nfrom typing_extensions import override\n"
    )
    names = _top_level_imports(source)
    assert names == {
        "hashlib",
        "btclib",
        "btclib_wallet",
        "ecc",
        "typing_extensions",
    }
    assert _outside(names) == ["btclib", "btclib_wallet"]


def test_no_module_imports_outside_the_stdlib_and_the_extras() -> None:
    """Every file of the package, read rather than imported.

    The static half of `test_no_module_reaches_above_the_package`: an
    import inside a function or behind `TYPE_CHECKING` is one no
    interpreter runs at import, and it would still fail the day it ran.
    """
    root = Path(ecc.__path__[0])
    found = {
        path.relative_to(root).as_posix(): _outside(
            _top_level_imports(path.read_text(encoding="utf-8"))
        )
        for path in sorted(root.rglob("*.py"))
    }
    assert "ecc/dsa.py" in found
    assert {file: names for file, names in found.items() if names} == {}


# what each unit of the package may import from the package itself, as
# ARCHITECTURE.md states. A unit is the root (`ecc`) or the first module
# below it (`ecc.kdf`), so the subpackage `ecc.ecc` is one unit and its
# schemes are free among themselves
_EXCEPTIONS = "ecc.exceptions"
_ALIAS = "ecc.alias"
_UTILS = "ecc._utils"
_NUMBER_THEORY = "ecc.number_theory"
_HASHES = "ecc.hashes"
_LIBSECP256K1 = "ecc._libsecp256k1"
_KDF = "ecc.kdf"
_CURVES = "ecc.curves"
_SCHEMES = "ecc.ecc"
_MAY_IMPORT: dict[str, frozenset[str]] = {
    "ecc": frozenset(),
    _EXCEPTIONS: frozenset(),
    _ALIAS: frozenset(),
    _UTILS: frozenset({_ALIAS, _EXCEPTIONS}),
    _NUMBER_THEORY: frozenset({_UTILS, _EXCEPTIONS}),
    _HASHES: frozenset({_UTILS, _ALIAS, _EXCEPTIONS}),
    _LIBSECP256K1: frozenset({"ecc", _EXCEPTIONS}),
    _KDF: frozenset({_UTILS, _ALIAS, _EXCEPTIONS, _HASHES}),
    _CURVES: frozenset({_LIBSECP256K1, _UTILS, _ALIAS, _EXCEPTIONS, _NUMBER_THEORY}),
    _SCHEMES: frozenset(
        {
            "ecc",
            _LIBSECP256K1,
            _UTILS,
            _ALIAS,
            _EXCEPTIONS,
            _NUMBER_THEORY,
            _HASHES,
            _KDF,
            _CURVES,
        }
    ),
}


# what `import ecc` or `import ecc.<module>`, with no `as`, reaches; no
# table entry allows it
_ANY = "ecc.*"


def _unit(module_name: str) -> str:
    """Return the root, or the first module below it, a dotted name falls in."""
    return ".".join(module_name.split(".")[:2])


def _package_imports(
    module_name: str, is_package: bool, source: str, known: set[str]
) -> set[str]:
    """Return the units of this package that one module's imports reach.

    `from ecc import kdf` reaches `ecc.kdf` when that is a module, and the
    root when it is a name the root holds, as `from ecc import name` is.
    `import ecc`, or `import ecc.kdf` with no `as`, reaches `_ANY`: the
    statement binds the root, which loads any public module on attribute
    access, so it can reach every unit. With `as` it binds only the module
    it names. A relative import is resolved against the module that makes
    it.
    """
    parts = module_name.split(".")
    package = parts if is_package else parts[:-1]
    targets: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            targets.extend(
                _ANY if a.asname is None and _is_ours(a.name) else a.name
                for a in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                kept = package[: len(package) - (node.level - 1)]
                base = ".".join([*kept, *([node.module] if node.module else [])])
            targets.extend(
                f"{base}.{alias.name}" if f"{base}.{alias.name}" in known else base
                for alias in node.names
            )
    return {_unit(t) for t in targets if _is_ours(t)}


def _imports_the_rule_refuses(
    sources: dict[str, tuple[bool, str]],
) -> dict[str, list[str]]:
    """Return, per module, the units it imports and may not.

    `sources` maps a module name to whether it is a package and its text.
    """
    known = set(sources)
    broken: dict[str, list[str]] = {}
    for name, (is_package, source) in sorted(sources.items()):
        found = _package_imports(name, is_package, source, known)
        extra = sorted(found - _MAY_IMPORT[_unit(name)] - {_unit(name)})
        if extra:
            broken[name] = extra
    return broken


def _package_sources(root: Path) -> dict[str, tuple[bool, str]]:
    """Return every file of the package, read, by module name."""
    return {
        ".".join(("ecc", *path.relative_to(root).with_suffix("").parts)).removesuffix(
            ".__init__"
        ): (path.name == "__init__.py", path.read_text(encoding="utf-8"))
        for path in root.rglob("*.py")
    }


def test_the_layers_import_only_downwards() -> None:
    """Hold the rule ARCHITECTURE.md states.

    Read statically, so an import inside a function or behind
    `TYPE_CHECKING` counts.
    """
    sources = _package_sources(Path(ecc.__path__[0]))
    assert {_unit(name) for name in sources} == set(_MAY_IMPORT)
    assert _imports_the_rule_refuses(sources) == {}


def test_the_layer_scan_finds_a_planted_import() -> None:
    """The scan resolves each import form to a unit, and the rule refuses it."""
    known = {"ecc", "ecc.kdf", "ecc.hashes", "ecc.ecc", "ecc.ecc.dsa"}
    source = "from ecc import kdf, name\nimport ecc.ecc.dsa as dsa\nimport json\n"
    assert _package_imports("ecc.curves", True, source, known) == {
        "ecc.kdf",
        "ecc",
        "ecc.ecc",
    }
    assert _package_imports("ecc._utils", False, "import ecc\n", known) == {_ANY}
    assert _package_imports("ecc._utils", False, "import ecc.kdf\n", known) == {_ANY}
    relative = "from .. import hashes\nfrom ..kdf import x\n"
    assert _package_imports("ecc.curves.curve", False, relative, known) == {
        "ecc.hashes",
        "ecc.kdf",
    }
    planted = {
        "ecc": (True, ""),
        "ecc.hashes": (False, "from ecc import kdf\n"),
        "ecc.kdf": (False, "from ecc.hashes import tagged_hash\n"),
        "ecc.curves": (True, "from ecc.kdf import hkdf\n"),
        "ecc.exceptions": (False, "import ecc\n"),
        "ecc.ecc": (True, "from ecc import hashes\n"),
    }
    assert _imports_the_rule_refuses(planted) == {
        "ecc.curves": ["ecc.kdf"],
        "ecc.exceptions": [_ANY],
        "ecc.hashes": ["ecc.kdf"],
    }
