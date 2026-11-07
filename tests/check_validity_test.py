# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `check_validity` convention.

`check_validity` is keyword-only throughout the package, which is a rule
about signatures rather than about any one of them: it is the flag the
serializable classes carry, and it is forwarded by hand from one to the
next, so the guard has to be the rule itself. A new signature spelling
it positionally is what this module fails on.

How many carry it is not written down here, because a number in prose
drifts where a walk does not: `len(_signatures())` is the count whenever
one is wanted.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib

import pytest

from ecc import dsa, ssa
from ecc.curves import secp256k1

PACKAGE = pathlib.Path(__file__).parent.parent / "src" / "ecc"


def _signatures() -> list[tuple[str, int, str, list[str], list[str]]]:
    """Return every signature of the package that takes check_validity."""
    out = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            positional = [a.arg for a in args.posonlyargs + args.args]
            keyword_only = [a.arg for a in args.kwonlyargs]
            if "check_validity" in positional + keyword_only:
                out.append(
                    (
                        path.relative_to(PACKAGE.parent).as_posix(),
                        node.lineno,
                        node.name,
                        positional,
                        keyword_only,
                    )
                )
    return out


def test_check_validity_is_keyword_only() -> None:
    """Verify no signature takes check_validity positionally."""
    signatures = _signatures()

    # not an assertion about the number, which changes: an assertion that
    # the walk found the signatures at all, a broken one passing vacuously
    found = {(path, name) for path, _, name, _, _ in signatures}
    assert ("ecc/dsa.py", "parse") in found
    assert ("ecc/ssa.py", "serialize") in found

    offenders = [
        f"{path}:{lineno} {name}"
        for path, lineno, name, pos, _ in signatures
        if "check_validity" in pos
    ]
    assert not offenders, "check_validity must be keyword-only: " + ", ".join(offenders)


def test_check_validity_positional_is_a_type_error() -> None:
    """The hazard the rule exists for.

    Were the flag positional, a signature growing a parameter before it
    would silently move it into another slot. As a TypeError it fails at
    the call, rather than wherever the wrong value landed. A dataclass's
    generated __init__ takes an InitVar positionally and no star can reach
    it, hence the written-out constructors.
    """
    with pytest.raises(TypeError, match="positional argument"):
        dsa.Sig(1, 1, secp256k1, False)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="positional argument"):
        ssa.Sig(1, 1, secp256k1, False)  # type: ignore[call-arg]


def test_check_validity_keyword_still_works() -> None:
    """The keyword switches validation off, which is the whole point of it."""
    assert dsa.Sig(0, 1, check_validity=False).r == 0
    with pytest.raises(ValueError, match="r not in 1..n-1"):
        dsa.Sig(0, 1)


def test_dsa_sig_is_still_a_dataclass() -> None:
    """The Sig classes trade InitVar for a written-out __init__.

    What the dataclass generates around it is all that is left to check,
    and it must not go too.
    """
    r = 0x2B698A0F0A4041059B5C617F42B2B90D68F0F27F8B8F1CBA0D7D8F0B4D4B7C1A
    s = 0x1BE0DFEF2E4DAB1F4BFAF0C36F9E1DDA1E92BCEA6D8D9AFB0BE1DAF9E5BE3C57
    sig = dsa.Sig(r, s)

    assert [f.name for f in dataclasses.fields(sig)] == ["r", "s", "ec"]
    assert sig == dsa.Sig(r, s)
    assert hash(sig) == hash(dsa.Sig(r, s))
    assert dataclasses.replace(sig, s=s) == sig
    assert "check_validity" not in repr(sig)

    # frozen: the hand-written __init__ assigns through
    # object.__setattr__, which must not leave the class writable
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.r = 1  # type: ignore[misc]


def test_strict_became_keyword_only_too() -> None:
    """dsa.Sig.parse is a signature with a parameter after the flag.

    Starring check_validity makes `strict` keyword-only as well. The
    alternative, `strict` in front of the star, would silently turn a
    caller's `Sig.parse(data, False)` from check_validity=False into
    strict=False -- the failure mode this whole rule is against.
    """
    sig_bytes = "3006020180020180"
    assert dsa.Sig.parse(sig_bytes, check_validity=False, strict=False).r == 0x80
    with pytest.raises(TypeError, match="positional argument"):
        dsa.Sig.parse(sig_bytes, False, False)  # type: ignore[call-arg]
