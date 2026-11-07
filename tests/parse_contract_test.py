# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the parse contract every `parse` in the package owes its caller.

One file rather than a case per module, because the rule is one and
`src/ecc/_utils.py` states it: a field is as long as its
encoding says, a complete octet string is one whole object, and a
caller's stream is the caller's. What the tests hold every parser to is
that none of the three depends on `check_validity`, which is an opinion
about what the bytes mean and not about where they end.

The inventory at the top is what those tests run over, and the last test
is what makes it a promise rather than a list: it walks the package for
every public class carrying a `parse` and fails unless each one is either
in the inventory or in a table of exclusions naming its reason. A parser
added to the package and forgotten here would otherwise be held to
nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from typing import Any

import pytest

from ecc import ssa
from ecc.borromean import BorromeanSig
from ecc.exceptions import (
    EccRuntimeError,
    EccTypeError,
    EccValueError,
)
from ecc.rangeproof import RangeProof
from tests import public_classes_with

# what the package promises to raise, and the whole of it: a truncated
# buffer has to be refused as one of these three, and never as an
# IndexError or a struct error from underneath the package
_CONTRACT_EXCEPTIONS = (
    EccValueError,
    EccRuntimeError,
    EccTypeError,
)

_RANGEPROOF = RangeProof(
    -1, 0, 100000, (), (), BorromeanSig(bytes(32), [[1]])
).serialize()

# every object with a fixed-width field in it or a length of its own,
# with the class whose `parse` reads it back: (name, class, serialization).
# The class and not the bound method, so that the inventory says which
# parsers are covered -- see the completeness test at the end of this file
_CASES: list[tuple[str, type[Any], bytes]] = [
    ("ssa_sig", ssa.Sig, ssa.sign(b"parse contract", 1).serialize()),
    # the public-value proof, which is the smallest one this format has:
    # a header, its min_value, and the single-key ring the commitment
    # itself gives. What a longer one adds is more of the same fields,
    # and `tests/schemes/rangeproof_test.py` drives those against the proofs
    # libsecp256k1-zkp signed
    ("rangeproof", RangeProof, _RANGEPROOF),
]


_IDS = [case[0] for case in _CASES]
_PARSE_AND_BYTES = [(case[1].parse, case[2]) for case in _CASES]


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_no_prefix_of_an_encoding_is_an_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Every truncation is refused, at every offset and either way.

    `BytesIO.read` answers with what is left rather than raising, and
    `int.from_bytes` takes a short answer, so an unchecked parser turns
    each of these prefixes into an object that serializes back longer
    than the buffer it came from: distinct buffers, including malformed
    ones, mapping to one canonical object.
    """
    for size in range(len(serialization)):
        with pytest.raises(_CONTRACT_EXCEPTIONS):
            parse(serialization[:size], check_validity=check_validity)


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_octets_are_one_whole_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Bytes after the object are refused, hex-string included."""
    assert parse(serialization, check_validity=check_validity)

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(EccValueError, match="bytes after the"):
            parse(serialization + trailing, check_validity=check_validity)
        with pytest.raises(EccValueError, match="bytes after the"):
            parse((serialization + trailing).hex(), check_validity=check_validity)


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
def test_a_stream_is_the_callers(
    parse: Callable[..., Any], serialization: bytes
) -> None:
    """A stream may carry more, and is left on the byte after the object.

    This is the half of the contract that makes the other half safe to
    enforce: a transaction is read out of the very stream its block is
    read from, so what follows the object in a stream is not the parser's
    to complain about -- or to consume.
    """
    stream = BytesIO(serialization + b"junk")
    assert parse(stream)
    assert stream.read() == b"junk"


def test_a_truncated_field_names_itself() -> None:
    """The diagnosis is the truncation, not whatever the short read meant.

    Without the length check the missing bytes are reported by whichever
    field they happen to fall in, or not at all: four bytes off a min
    value read as a min value four bytes smaller, which is a valid one.
    """
    with pytest.raises(
        EccValueError, match="not enough data for the rangeproof min value"
    ):
        RangeProof.parse(_RANGEPROOF[:5])
    with pytest.raises(EccValueError, match="not enough data for the borromean e0"):
        RangeProof.parse(_RANGEPROOF[:20])


def test_a_fixed_size_object_reports_its_own_length() -> None:
    """A buffer that is the object reports the buffer, not a field of it.

    The message says it whatever `check_validity` says, which is what a
    semantic check would have gated.
    """
    sig_bytes = ssa.sign(b"parse contract", 1).serialize()

    err_msg = "invalid decoded length: 63 instead of 64"
    with pytest.raises(EccValueError, match=err_msg):
        ssa.Sig.parse(sig_bytes[:63], check_validity=False)


# what a parser of this package is *not* held to, and why. A name here is
# a decision, which is the difference between an exclusion and an
# oversight -- the test below fails on either
_EXCLUDED = {
    "ecc.borromean.BorromeanSig": (
        "the wire format has no length of its own for the ring structure:"
        " e0 || s... is only as long as the caller's rsizes says it is,"
        " the same reason zkp's secp256k1_borromean_verify takes rsizes as"
        " an argument rather than reading it from the proof. The three"
        " generic properties assume a self-contained encoding, and driving"
        " them with rsizes defaulting to empty would test that default's"
        " artifact rather than a real signature's boundary; the real one is"
        " tests/schemes/borromean_test.py's own"
        " test_borromean_sig_parse_refuses_short_and_trailing_data, driven"
        " with the rsizes an actual pubk_rings carries"
    ),
    "ecc.dsa.Sig": (
        "the one parser here with a flag in front of the rule, and the flag"
        " is Bitcoin Core's: trailing octets are refused under `strict`"
        " alone, where IsValidSignatureEncoding is called, and refused in a"
        " stream as well -- no caller in this package reads a signature out"
        " of the middle of one. Sig.parse says so where it does it"
    ),
    "ecc.ecies.Envelope": (
        "BIE1 writes the ciphertext between fixed offsets with no length in"
        " front of it, so what would trail the envelope is ciphertext and a"
        " truncation of it is a shorter message: the size rule it can be"
        " held to is the minimum one it checks"
    ),
}


def test_every_parser_is_covered_or_named_an_exclusion() -> None:
    """The inventory is a promise only if omission is what fails.

    A parser added to the package and forgotten here is the failure this
    catches: the tests above would go on passing on the parsers they were
    given, and the new one would be held to nothing.

    `public_classes_with` is the walk, and it is `tests/__init__.py`'s
    because `serialization_boundary_test.py` holds these same parsers to
    a different contract -- where the bytes end is not what type the
    argument is. A private class is skipped there.
    """
    covered = {f"{cls.__module__}.{cls.__qualname__}" for _, cls, _ in _CASES}
    assert not covered & _EXCLUDED.keys()
    assert public_classes_with("parse") == covered | _EXCLUDED.keys()
