# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what `parse`, `serialize`, `b64decode` and `b64encode` take.

"Every public function validates its inputs", at the boundary where an
object meets octets or text: a value of a type the signature does not
declare leaves as an `EccTypeError`, a value of a declared
type that no valid input carries as an `EccValueError`. Issue
btclib-org/btclib#867 is where the family was measured.

**Not the contract `parse_contract_test.py` holds.** That file asks where
the bytes end -- a field is as long as its encoding says, a complete octet
string is one whole object, a caller's stream is the caller's -- and this
one asks what type the argument is. The two are different questions about
the same methods, which is why the walk that finds every one of them is
`tests/__init__.py`'s and neither file's.

**`serialize` and `b64encode` have nothing to drive**: their input is
the object, which `check_validity_test.py` owns. `_EXTRA_ARGUMENTS`
records what else the family takes, and the walk at the end is what
keeps that record honest -- one more added to the family fails there
until it is driven or given a reason.

**Parametric above the byte boundary, mono-format at it.** `ec` and
`hf` are arguments everywhere arithmetic and protocol take them --
`sign`, `verify`, `key_agg_var` -- and nowhere in this family: no `parse`
or `serialize` here declares either, and
`test_the_family_takes_no_ec_or_hf` is what turns that from an
agreement into a gate (issue btclib-org/btclib#1084). The *object* keeps
its curve regardless -- `ssa.Sig` declares `ec: Curve = secp256k1` as a
field, so a signature on `ec13_11` is built, validated, signed and
verified exactly as one on secp256k1. What it cannot do is round-trip
through a format that curve was never defined over. The encoding does
not name its curve or its hash function, so `parse(data, ec=...)` would
not be parsing -- it would be decoding under instruction, accepting in
silence a caller who names the wrong one and handing back a well-formed
object built from octets that meant something else.

`check_validity` is not driven anywhere in this file: it is a flag that
decides whether a check runs rather than what is computed, so it is read
for its truth, and `check_validity_test.py` owns that convention.
`dsa.Sig.parse`'s `strict` is the same kind of flag and the same
exemption; `bool_parameter_test.py` is where that classification is
decided, for every flag in the package and with the reason for each.
"""

from __future__ import annotations

from importlib import import_module
from inspect import signature
from typing import Any

import pytest

from ecc import dsa, ecies, ssa
from ecc.borromean import BorromeanSig
from ecc.curves import bytes_from_point, secp256k1
from ecc.exceptions import EccTypeError
from ecc.rangeproof import RangeProof
from tests import module_names, public_classes_with

# a value of no type any of these positions declares. `Any`, because
# every position they are handed to declares something narrower: what
# these tests are about is the caller who has not run mypy
_WRONG_TYPES: tuple[Any, ...] = (None, 1.5, [1, 2])

# framed rather than encrypted: the framing is all this file is about
_ENVELOPE = ecies.Envelope.from_ciphertext(
    bytes_from_point(secp256k1.G), b"\x00" * 16, b"key material"
)

# what reads octets: every class-level `parse`. The class and the method
# name, so that the walk at the end can say which decoders are covered
_OCTETS_DECODERS = (
    ("BorromeanSig.parse", BorromeanSig, "parse"),
    ("RangeProof.parse", RangeProof, "parse"),
    ("ssa.Sig.parse", ssa.Sig, "parse"),
    ("dsa.Sig.parse", dsa.Sig, "parse"),
    ("ecies.Envelope.parse", ecies.Envelope, "parse"),
)

_OCTETS_IDS = tuple(label for label, _, _ in _OCTETS_DECODERS)

# and what reads text: the base64 decoder
_TEXT_DECODERS = (("ecies.Envelope.b64decode", ecies.Envelope, "b64decode"),)

_TEXT_IDS = tuple(label for label, _, _ in _TEXT_DECODERS)

# what any of these methods takes beyond the object it is about, the
# octets it reads, and the `check_validity` that `check_validity_test.py`
# owns. `magic` is driven below. `rsizes` is
# `tests/schemes/borromean_test.py`'s, driven there with the ring sizes a
# real `pubk_rings` carries. `strict` is a flag deciding whether a check
# runs -- Bitcoin Core's IsValidSignatureEncoding, and `dsa.Sig.parse`
# says where it does it -- and is therefore read for its truth, as
# `check_validity` is
_EXTRA_ARGUMENTS = {
    ("ecc.borromean.BorromeanSig", "parse"): "rsizes",
    ("ecc.ecies.Envelope", "parse"): "magic",
    ("ecc.ecies.Envelope", "b64decode"): "magic",
    ("ecc.dsa.Sig", "parse"): "strict",
}

# the names issue btclib-org/btclib#867 measured, which is what the walk
# runs over, split by which of them is handed an encoding: a reader takes
# one as its first argument, a writer starts from the object and takes
# none. The json and Base58 pairs are in it though nothing here has one,
# so that one added is one the walk finds
_READERS = ("parse", "from_dict", "b64decode", "b58decode")
_WRITERS = ("serialize", "to_dict", "b64encode", "b58encode")
_FAMILY = (*_READERS, *_WRITERS)


@pytest.mark.parametrize("label, cls, method", _OCTETS_DECODERS, ids=_OCTETS_IDS)
def test_the_octets_boundary_refuses_what_is_no_octets(
    label: str, cls: type[Any], method: str
) -> None:
    """`bytes_from_octets` is the one coercion, and it is the one refusal."""
    for wrong in _WRONG_TYPES:
        with pytest.raises(EccTypeError, match="invalid octets type"):
            getattr(cls, method)(wrong)


@pytest.mark.parametrize("label, cls, method", _TEXT_DECODERS, ids=_TEXT_IDS)
def test_the_text_boundary_refuses_what_is_no_text(
    label: str, cls: type[Any], method: str
) -> None:
    """The same rule where the encoding is text rather than octets.

    Unguarded, a base64 decoder hands what is neither `str` nor `bytes`
    to `base64`, which answers "argument should be a bytes-like object or
    ASCII string" from underneath the package.
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(EccTypeError, match="type"):
            getattr(cls, method)(wrong)


def test_an_envelope_is_read_against_magic_bytes_that_are_bytes() -> None:
    """An argument of this family that is neither a flag nor a version.

    Compared against the first four octets of the buffer, so a magic of
    no bytes type would be unequal to whatever is there: every envelope
    refused, and for the bytes it does carry rather than for the argument
    that cannot be any.
    """
    armor = _ENVELOPE.b64encode()
    assert ecies.Envelope.b64decode(armor) == _ENVELOPE
    assert ecies.Envelope.parse(_ENVELOPE.serialize(), magic=b"BIE1") == _ENVELOPE

    for wrong in _WRONG_TYPES:
        with pytest.raises(EccTypeError, match="invalid magic type"):
            ecies.Envelope.parse(_ENVELOPE.serialize(), magic=wrong)
        with pytest.raises(EccTypeError, match="invalid magic type"):
            ecies.Envelope.b64decode(armor, magic=wrong)


def test_every_decoder_is_covered() -> None:
    """The inventory is a promise only if omission is what fails.

    No exclusion list, which is the state to keep: every decoder in the
    package takes an argument of a declared type, and refusing what is
    not of it is a rule with no exception to state.
    """
    covered = {
        f"{cls.__module__}.{cls.__qualname__}.{method}"
        for _, cls, method in (*_OCTETS_DECODERS, *_TEXT_DECODERS)
    }
    found = {
        f"{name}.{method}"
        for method in ("parse", "b64decode", "b58decode", "from_dict")
        for name in public_classes_with(method)
    }
    assert found == covered


def _module_codecs() -> dict[str, set[str]]:
    """Return every module-level member of the family, with its parameters.

    One expression and not a loop with a `continue` per rule: nothing here
    is such a function, so a loop's body would be lines no run reaches,
    and a catcher with nothing to catch must not leave a line of its own
    uncovered.
    """
    return {
        f"{module_name}.{method}": set(signature(function).parameters)
        for module_name in module_names()
        for method in _FAMILY
        if callable(function := getattr(import_module(module_name), method, None))
        and not isinstance(function, type)
        and getattr(function, "__module__", "") == module_name
    }


def test_no_codec_is_a_module_function() -> None:
    """The family lives on classes here, and the walk says so.

    A `parse` or a `serialize` added to a module of this package would be
    invisible to the class walk, so it is found here and fails until a
    test drives it.
    """
    assert not _module_codecs()


def test_the_family_takes_no_argument_this_file_does_not_drive() -> None:
    """What the methods take, beyond the object and `check_validity`.

    Read off the signatures rather than listed, which is what makes
    `_EXTRA_ARGUMENTS` a record instead of a wish: an argument added to
    any member of the family fails here until it is driven or given a
    reason of its own.

    The argument this walk does not count is the object's own: the
    encoding a reader is handed, which the tests above drive for every
    class carrying one, and which a writer does not have at all, the
    object being what it writes.
    """
    found: dict[tuple[str, str], str] = {}
    for method in _FAMILY:
        for name in public_classes_with(method):
            module_name, _, class_name = name.rpartition(".")
            cls = getattr(import_module(module_name), class_name)
            parameters = [
                parameter
                for parameter in signature(getattr(cls, method)).parameters
                # `cls` is gone already, a classmethod read off the class
                # being bound to it; `self` is not, an instance method read
                # off the class being the plain function
                if parameter not in ("self", "cls", "check_validity")
            ]
            # then the encoding, which is the first argument of a reader
            # and is not an argument at all for a writer: what a writer
            # converts is the object it is called on
            extra = parameters[1:] if method in _READERS else parameters
            assert len(extra) <= 1, f"{name}.{method} takes {extra}"
            for parameter in extra:
                found[name, method] = parameter

    assert found == _EXTRA_ARGUMENTS


def test_the_family_takes_no_ec_or_hf() -> None:
    """No member of the family takes a curve or a hash function.

    Parametric above the byte boundary, mono-format at it: `parse`
    reads the curve and the hash function the format is defined over,
    not ones a caller names, so neither is ever a parameter here -- the
    module docstring is the reason. An `ec` or an `hf` added to any
    member of this family fails here rather than waiting for a reader to
    notice.
    """
    found: dict[str, set[str]] = {}
    for method in _FAMILY:
        for name in public_classes_with(method):
            module_name, _, class_name = name.rpartition(".")
            cls = getattr(import_module(module_name), class_name)
            found[f"{name}.{method}"] = set(signature(getattr(cls, method)).parameters)
    found |= _module_codecs()

    assert found
    offenders = {name for name, params in found.items() if params & {"ec", "hf"}}
    assert not offenders
