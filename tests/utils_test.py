# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `ecc._utils` module."""

import array
import ast
import random
import sys
from collections.abc import Callable
from decimal import Decimal
from fractions import Fraction
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from typing_extensions import override

from ecc._utils import (
    _message_text,
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
    int_from_integer,
    is_integer,
    is_octets,
    read_exactly,
    str_from_string,
)
from ecc.exceptions import EccTypeError, EccValueError
from ecc.hashes import reduce_to_hlen

random.seed(42)

# the refusal of a "0x" string whose digits are not ASCII hex (issue #21)
_NOT_HEX_DIGITS = "invalid hex integer: what follows 0x is not ASCII hex digits"


def test_read_exactly() -> None:
    """The size asked for is the size returned, or it is an error."""
    stream = BytesIO(b"12345")
    assert read_exactly(stream, 2, "first field") == b"12"
    assert read_exactly(stream, 3, "second field") == b"345"
    # nothing left, and asking for nothing is not asking
    assert read_exactly(stream, 0, "no field") == b""


def test_read_exactly_refuses_a_size_that_is_no_count() -> None:
    """A size `read` cannot take, or takes as "to the end".

    Left to `read`, a size past `sys.maxsize` would raise an
    OverflowError and a float a TypeError, a negative size would read
    the whole stream, and `True` would read one octet (issue
    btclib-org/btclib#2399).
    """
    for size in (1.5, "1", None, True):
        with pytest.raises(EccTypeError, match="^invalid tx_id size type: "):
            read_exactly(BytesIO(b"12"), size, "tx_id")  # type: ignore[arg-type]
    for size in (-1, sys.maxsize + 1, 10**5000, -(10**5000)):
        with pytest.raises(EccValueError, match="^invalid tx_id size: "):
            read_exactly(BytesIO(b"12"), size, "tx_id")
    # the top of the range is a short read, not a refusal of the size
    with pytest.raises(EccValueError, match="^not enough data for the tx_id: "):
        read_exactly(BytesIO(b"12"), sys.maxsize, "tx_id")


def test_read_exactly_names_the_field_it_could_not_fill() -> None:
    """A short read is refused, and the message says which field it was.

    BytesIO.read hands back what is left rather than raising, so an
    unchecked read is not a missing check but a wrong value: the field
    would be as long as the buffer happened to be.
    """
    err_msg = "not enough data for the sequence: 3 bytes instead of 4"
    with pytest.raises(EccValueError, match=err_msg):
        read_exactly(BytesIO(b"123"), 4, "sequence")

    err_msg = "not enough data for the tx_id: 0 bytes instead of 32"
    with pytest.raises(EccValueError, match=err_msg):
        read_exactly(BytesIO(b""), 32, "tx_id")


def test_assert_no_trailing() -> None:
    """Octets are one whole object; a caller's stream is the caller's."""
    # what a parser hands over: the argument as it came, and the stream
    # it made of it, read up to the end of the object
    consumed = BytesIO(b"12")
    consumed.read(2)
    assert_no_trailing(b"12", consumed, "thing")

    consumed = BytesIO(b"12")
    consumed.read(2)
    assert_no_trailing("3132", consumed, "thing")

    stream = BytesIO(b"12junk")
    stream.read(2)
    with pytest.raises(EccValueError, match="4 bytes after the thing"):
        assert_no_trailing(b"12junk", stream, "thing")

    # the same four bytes in a stream the caller owns are the caller's,
    # and they are still there to be read
    stream = BytesIO(b"12junk")
    stream.read(2)
    assert_no_trailing(stream, stream, "thing")
    assert stream.read() == b"junk"


def test_int_from_integer() -> None:
    """Round-trip integers through int, hex-string, and bytes forms."""
    for i in (
        random.getrandbits(256 - 8),
        0x0B6CA75B7D3076C561958CCED813797F6D2275C7F42F3856D007D587769A90,
    ):
        assert i == int_from_integer(i)
        assert i == int_from_integer(f" {hex(i).upper()}")
        assert -i == int_from_integer(f"{hex(-i).upper()} ")
        assert i == int_from_integer(hex_string(i))
        assert i == int_from_integer(i.to_bytes(32, byteorder="big", signed=False))


def test_int_from_integer_rejects_empty_input() -> None:
    """Empty integer representations are invalid, not zero."""
    for value in ("", "   ", b"", bytearray()):
        with pytest.raises(EccValueError):
            int_from_integer(value)


def test_int_from_integer_reads_a_str_as_hex() -> None:
    """Check "1234" reads as 0x1234, and an odd digit count is refused."""
    # a decimal-looking str is a hex-string like any other, which the
    # docstring says out loud: 0x1234, not one thousand two hundred
    # and thirty-four
    assert int_from_integer("1234") == 4660
    assert int_from_integer("1234") == int_from_integer("0x1234")
    assert int_from_integer(1234) == 1234

    # and an odd number of digits is not a one-digit decimal either
    # (the message is bytes.fromhex's own, which Python 3.14 rephrased,
    # inside the class this library promises)
    with pytest.raises(EccValueError, match="invalid hex string: "):
        int_from_integer("9")


def test_hex_string() -> None:
    """Format int, str and bytes as spaced hex; refuse odd or negative."""
    int_ = 34492435054806958080
    assert hex_string(int_) == "01 DEADBEEF 00000000"
    assert hex_string(hex(int_).lower()) == "01 DEADBEEF 00000000"

    a_str = "01de adbeef00000000"
    assert hex_string(a_str) == "01 DEADBEEF 00000000"
    a_bytes = bytes.fromhex(a_str)
    assert hex_string(a_bytes) == "01 DEADBEEF 00000000"

    # invalid hex-string: odd number of hex digits
    # (Python 3.14 rephrased the message bytes.fromhex raises)
    a_str = "1deadbeef00000000"
    with pytest.raises(EccValueError, match="invalid hex string: "):
        hex_string(a_str)

    # the refusal says nothing of the value it refuses
    with pytest.raises(EccValueError, match="^negative integer$"):
        hex_string(-123456789)

    # zero is not negative: `< 0` weakened to `<= 0` would refuse it
    assert hex_string(0) == "00"

    # a hex length that is an exact multiple of 8 (here 16, unlike the
    # 18-digit vector above): the index loop's stop bound at 0 is what
    # keeps the top group from being an empty one -- read as -1 instead,
    # 0 itself joins the indexes and a leading space appears before "DE"
    assert hex_string(0xDEADBEEF00000000) == "DEADBEEF 00000000"


def test_int_from_bits() -> None:
    """Discard bits on the right down to nlen, or none if there are fewer.

    Every caller in this codebase hashes into exactly `ec.nlen` bits, so
    `blen == nlen` is the only case they exercise; `blen > nlen` is the
    truncation the docstring is about, and `blen < nlen` -- fewer bits
    than asked for -- is `n` weakened from `blen - nlen` to a negative
    shift count away from `i >> n` raising instead of returning `i`
    unchanged.
    """
    assert int_from_bits(b"\xff", 4) == 0b1111
    assert int_from_bits(b"\xff\x00", 4) == 0b1111
    assert int_from_bits(b"\xff", 16) == 0xFF


def test_octets_are_bytes_or_the_hex_string_of_bytes_and_nothing_else() -> None:
    """A tuple is refused rather than measured as if it were octets.

    Passed through unchanged, `len` of a tuple of 33 ints is 33, which a
    size check alone accepts as a compressed key. Every buffer is still
    taken.
    """
    assert bytes_from_octets(b"\x00\x01") == b"\x00\x01"
    assert bytes_from_octets("0001") == b"\x00\x01"
    # every buffer `Octets` names, and what reaches this is whatever a
    # field was built from rather than only what a caller writes
    assert bytes_from_octets(bytearray(b"\x00\x01")) == b"\x00\x01"
    assert bytes_from_octets(memoryview(b"\x00\x01")) == b"\x00\x01"

    for not_octets in (tuple(range(33)), [1, 2], None, 1.5):
        with pytest.raises(EccTypeError, match="invalid octets type: "):
            bytes_from_octets(not_octets)  # type: ignore[arg-type]
        with pytest.raises(EccTypeError, match="invalid octets type: "):
            int_from_integer(not_octets)  # type: ignore[arg-type]
    # an int is an `Integer` and no `Octets`, so the two differ on it
    assert int_from_integer(1) == 1
    with pytest.raises(EccTypeError, match="invalid octets type: int"):
        bytes_from_octets(1)  # type: ignore[arg-type]

    # the hex string that is not one, in both, with the message
    # `bytes.fromhex` gives: a position, and never the string itself
    for not_hex in ("9", "zz", "not hex at all"):
        with pytest.raises(EccValueError, match="invalid hex string: "):
            bytes_from_octets(not_hex)
        with pytest.raises(EccValueError, match="invalid hex string: "):
            int_from_integer(not_hex)
    with pytest.raises(EccValueError) as excinfo:
        int_from_integer("0xzz")
    assert str(excinfo.value) == _NOT_HEX_DIGITS


def test_int_from_integer_reads_ascii_hex_after_0x() -> None:
    """Only ASCII hex digits follow 0x, and only ASCII whitespace is stripped.

    Python's `int(s, 16)` takes the digit-grouping underscore and every
    Unicode decimal digit, and `str.strip()` every character `isspace`
    counts, so each of these read as a number (issue #21). The refusal
    names no part of the string, which may be a private key.
    """
    arabic_indic = chr(0x661) + chr(0x660)
    fullwidth = chr(0xFF11) + chr(0xFF10)
    for not_hex in (
        "0x1_0",
        "0x_10",
        "-0x1_0",
        f"0x{arabic_indic}",
        f"0x{fullwidth}",
        f"-0x{fullwidth}",
        "0x",
        "-0x",
        "0x 10",
        "0x-10",
        "0x+10",
        f"0x10{chr(0x3000)}1",
        # padding `isspace` counts and ASCII does not, after the digits:
        # the string still starts with 0x, so this refusal answers it
        f"0x10{chr(0x3000)}",
        f"0x10{chr(0xA0)}",
        f"-0x10{chr(0x2028)}",
        f"0x10{chr(0x1C)}",
    ):
        with pytest.raises(EccValueError) as excinfo:
            int_from_integer(not_hex)
        assert str(excinfo.value) == _NOT_HEX_DIGITS
        with pytest.raises(EccValueError) as excinfo:
            hex_string(not_hex)
        assert str(excinfo.value) == _NOT_HEX_DIGITS

    # the same padding ahead of 0x, or around a string without it, leaves
    # one that is neither "0x..." nor hex, so it is bytes.fromhex that
    # refuses it, in its own words
    for pad in (chr(0x3000), chr(0xA0), chr(0x2028), chr(0x1C)):
        for padded in (f"{pad}0x10{pad}", f"{pad}deadbeef{pad}"):
            with pytest.raises(ValueError) as fromhex:
                bytes.fromhex(padded.lower())
            with pytest.raises(EccValueError) as excinfo:
                int_from_integer(padded)
            assert str(excinfo.value) == f"invalid hex string: {fromhex.value}"

    # what stays: ASCII whitespace around either spelling, and upper case
    ascii_ws = " \t\n\r\f\v"
    assert int_from_integer(f"{ascii_ws}0x10{ascii_ws}") == 16
    assert int_from_integer(f"{ascii_ws}-0X1f{ascii_ws}") == -31
    assert int_from_integer(f"{ascii_ws}DEADBEEF{ascii_ws}") == 0xDEADBEEF
    assert int_from_integer("0x" + "0123456789abcdefABCDEF") == int(
        "0123456789abcdefABCDEF", 16
    )


def test_a_buffer_becomes_the_bytes_the_signature_promises() -> None:
    """`-> bytes`, and not the caller's own buffer handed back.

    A `bytearray` or a `memoryview` returned as it came stays the caller's, so a
    write to it afterwards rewrites whatever the library built from it. Nor is
    either the `bytes` the annotation promises: a bytearray keys no dict and a
    memoryview concatenates with nothing (issue btclib-org/btclib#1255).
    """
    for spelling in (b"\x00\x01", bytearray(b"\x00\x01"), memoryview(b"\x00\x01")):
        assert type(bytes_from_octets(spelling)) is bytes
        assert bytes_from_octets(spelling) == b"\x00\x01"

    # the size check is on the way out and copies nothing of its own, so
    # it is asked here too rather than assumed to share the arm above
    buffer = bytearray(b"\x00\x01")
    copied = bytes_from_octets(buffer, 2)
    buffer[0] = 0xFF
    assert copied == b"\x00\x01"


def test_a_non_contiguous_memoryview_is_refused_at_the_coercion() -> None:
    """A strided slice is `Octets` to the annotation, `BufferError` underneath.

    `mv[::2]` is not C-contiguous, and were `bytes_from_octets` to hand it back
    untouched, the failure would reach whichever consumer used the buffer next
    -- a hash with a bare `BufferError`, a public entry point rather than this
    module. The refusal is raised here instead, once, at the coercion every
    `Octets` parameter passes (issue btclib-org/btclib#1260).
    """
    raw = bytes(range(64))
    strided = memoryview(raw)[::2]
    assert not strided.c_contiguous

    with pytest.raises(EccValueError, match="invalid octets: non-contiguous"):
        bytes_from_octets(strided)
    with pytest.raises(EccValueError, match="invalid octets: non-contiguous"):
        reduce_to_hlen(strided)

    # a contiguous slice is taken, same as any other buffer
    contiguous = memoryview(raw)[:32]
    assert bytes_from_octets(contiguous) == raw[:32]
    assert reduce_to_hlen(contiguous) == reduce_to_hlen(raw[:32])


def test_a_memoryview_of_the_wrong_format_is_refused_at_the_coercion() -> None:
    """A memoryview cast to a non-byte format reads as elements, not octets.

    `array.array("I", [1, 2])` is 8 octets read as two 4-byte unsigned ints; a
    memoryview over it is C-contiguous, so the contiguity check alone let it
    through, and `len()` of it answers 2 where a consumer reading octets means 8
    (issue btclib-org/btclib#1430). Refused here, once, at the same coercion
    every `Octets` parameter passes.
    """
    raw = bytes(range(8))
    wide = memoryview(array.array("I", [1, 2]))
    assert wide.c_contiguous
    assert wide.format != "B"
    assert len(wide) == 2
    assert wide.nbytes == 8

    with pytest.raises(EccValueError, match="invalid octets: memoryview format"):
        bytes_from_octets(wide)
    with pytest.raises(EccValueError, match="invalid octets: memoryview format"):
        reduce_to_hlen(wide)

    # a plain memoryview, and one cast back to unsigned bytes, are format
    # "B" and taken, same as any other buffer
    plain = memoryview(raw)
    assert plain.format == "B"
    assert bytes_from_octets(plain) == raw
    cast_back = wide.cast("B")
    assert cast_back.format == "B"
    assert bytes_from_octets(cast_back) == wide.tobytes()


def test_is_octets_answers_one_octets_not_a_sequence_of_them() -> None:
    """The question `bytes_from_octets` embeds, and two other callers ask.

    Every `Octets` spelling is itself iterable, which is what makes a
    single one hard to tell from a sequence of them by shape alone; a
    `list` or a `tuple` of `Octets` is not one itself.
    """
    for one in (b"\x00\x01", "0001", bytearray(b"\x00\x01"), memoryview(b"\x00\x01")):
        assert is_octets(one)
    for many in ([b"\x00"], (b"\x00", b"\x01"), []):
        assert not is_octets(many)


def test_a_string_is_ascii_or_refused() -> None:
    """Bytes outside ascii are refused, naming what they were read as."""
    assert str_from_string(b"abc", "armor") == "abc"
    with pytest.raises(EccValueError, match="non-ascii character in armor"):
        str_from_string(b"\xe0", "armor")


def test_the_non_ascii_refusal_names_the_position_and_nothing_of_the_input() -> None:
    """The refusal carries neither the byte nor the input, nor a cause.

    The input may be secret; the `UnicodeDecodeError` that finds the byte
    names it and holds the whole input, so it must not be chained.
    """
    with pytest.raises(EccValueError) as refusal:
        str_from_string(b"ab\xe0\xe1cd", "armor")
    assert str(refusal.value) == "non-ascii character in armor at position 2"
    for text in (str(refusal.value), repr(refusal.value)):
        for echoed in ("xe0", "0xe0", "e0", "\\x", "ab", "cd"):
            assert echoed not in text
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None


def test_str_from_string_refuses_a_memoryview_of_the_wrong_shape() -> None:
    """`_assert_byte_shaped`, which `bytes_from_octets` runs, runs here too.

    Without it the copy gathers a strided view's elements, and reads a
    wide-format view's octets, into a string no buffer holds (issue
    btclib-org/btclib#2295).
    """
    raw = bytes(range(64))
    strided = memoryview(raw)[::2]
    with pytest.raises(EccValueError, match="invalid octets: non-contiguous"):
        str_from_string(strided, "label")

    wide = memoryview(array.array("I", [1, 2]))
    with pytest.raises(EccValueError, match="invalid octets: memoryview format"):
        str_from_string(wide, "label")

    # a contiguous, format-"B" memoryview is taken, same as any other buffer
    assert str_from_string(memoryview(b"abc"), "label") == "abc"


class _OwnStrip(str):
    __slots__ = ()

    @override
    def strip(self, chars: str | None = None, /) -> str:
        return "x"


def test_str_from_string_returns_a_str_subclass_as_a_plain_str() -> None:
    """A str subclass comes back as a str, so its own methods answer nothing."""
    # the override does answer, so a caller reaching it would get "x"
    assert _OwnStrip("ab").strip() == "x"
    text = str_from_string(_OwnStrip("ab"), "label")
    assert type(text) is str
    assert text == "ab"
    assert text.strip() == "ab"


def test_a_message_describes_every_int() -> None:
    """Sign and bit length for every int, its digits for none.

    An argument in the wrong place may be a key (issue
    btclib-org/btclib#2998), and `str()` refuses an int past
    `sys.get_int_max_str_digits()` digits with ValueError, which a message
    quoting one would raise instead of the refusal it was building (issue
    btclib-org/btclib#2389). A bool is no int here.
    """
    assert _message_text(10**4000) == "an int of 13288 bits"
    assert _message_text(-7) == "a negative int of 3 bits"
    assert _message_text(0) == "an int of 0 bits"
    assert _message_text(True) == "a bool"
    assert _message_text("1_0") == "a str of length 3"
    assert _message_text(10**5000) == "an int of 16610 bits"
    assert _message_text(-(10**5000)) == "a negative int of 16610 bits"


class _Unwritable:
    @override
    def __str__(self) -> str:
        raise RuntimeError


def test_a_message_describes_what_str_cannot_write() -> None:
    """A value whose `str()` raises is named by its type, never by its text."""
    assert _message_text(Fraction(10**5000)) == "a Fraction"
    assert _message_text(Fraction(1, 10**5000)) == "a Fraction"
    assert _message_text(Fraction(3, 2)) == "a Fraction"
    # the override does raise, so a description reaching it would too
    with pytest.raises(RuntimeError):
        str(_Unwritable())
    assert _message_text(_Unwritable()) == "an _Unwritable"


class _Unsized:
    def __len__(self) -> int:
        raise RuntimeError


def test_a_message_describes_every_other_value() -> None:
    """Type name, and length where `len()` gives one, for what is no int.

    A str of hex, a Decimal, a float or bytes in an int's place may hold
    a key (issue btclib-org/btclib#3002): section 7 of the organization's
    standard lets a refusal print its type name and length, and no
    character of it.
    """
    assert _message_text("") == "a str of length 0"
    assert _message_text("1") == "a str of length 1"
    assert _message_text(bytes(32)) == "a bytes of length 32"
    assert _message_text(Decimal("1.5")) == "a Decimal"
    assert _message_text(1.5) == "a float"
    assert _message_text(False) == "a bool"
    assert _message_text(None) == "a NoneType"
    assert _message_text(object()) == "an object"
    assert _message_text(Ellipsis) == "an ellipsis"
    # the override does raise, so a description reaching it would too
    with pytest.raises(RuntimeError):
        len(_Unsized())
    assert _message_text(_Unsized()) == "an _Unsized"


class _UnorderedInt(int):
    @override
    def __str__(self) -> str:
        raise RuntimeError

    @override
    def __lt__(self, other: object) -> bool:
        raise RuntimeError


def test_a_message_describes_an_int_by_int_s_own_methods() -> None:
    """A subclass overriding the comparison is described all the same."""
    # the overrides do raise, so a description reaching them would too
    with pytest.raises(RuntimeError):
        _ = _UnorderedInt(-5) < 0
    with pytest.raises(RuntimeError):
        str(_UnorderedInt(-5))
    assert _message_text(_UnorderedInt(-5)) == "a negative int of 3 bits"
    assert _message_text(_UnorderedInt(10**5000)) == "an int of 16610 bits"


class _OwnBytes(bytes):
    @override
    def __bytes__(self) -> bytes:
        return b"2"


class _OwnBytesOfBytearray(bytearray):
    def __bytes__(self) -> bytes:
        return b"2"


class _OwnBuffer(bytearray):
    # what `bytes()` and `memoryview()` read from Python 3.12 (PEP 688)
    @override
    def __buffer__(self, flags: int, /) -> memoryview:
        return memoryview(b"2")


def test_the_buffer_overrides_answer() -> None:
    """Each override answers b"2", so a read reaching one would too."""
    assert _OwnBytes(b"abc").__bytes__() == b"2"
    assert _OwnBytesOfBytearray(b"abc").__bytes__() == b"2"
    assert bytes(_OwnBuffer(b"abc").__buffer__(0)) == b"2"


@pytest.mark.parametrize("subclass", [_OwnBytes, _OwnBytesOfBytearray, _OwnBuffer])
def test_a_buffer_subclass_is_read_by_its_base_type(
    subclass: Callable[[bytes], bytes | bytearray],
) -> None:
    """A subclass's own `__bytes__` or `__buffer__` decides nothing read."""
    octets = subclass(b"abc")
    assert bytes_from_octets(octets) == b"abc"
    assert type(bytes_from_octets(octets)) is bytes
    assert str_from_string(octets, "label") == "abc"

    # a plain bytes is not copied, as `_copy_bytes` says: a copy would be
    # another object, at another address while `plain` is alive
    plain = b"abc"
    assert id(bytes_from_octets(plain)) == id(plain)


# (the call, the type its argument claims through `__class__`)
_CLAIMED: tuple[tuple[Callable[[Any], object], type], ...] = (
    (bytes_from_octets, bytes),
    (bytes_from_octets, bytearray),
    (bytes_from_octets, str),
    (lambda v: bytes_from_octets(b"ab", v), int),
    (lambda v: str_from_string(v, "label"), str),
    (lambda v: str_from_string(v, "label"), bytes),
    (lambda v: assert_type(v, bytes, "label"), bytes),
    (bytesio_from_binarydata, BytesIO),
    (lambda v: read_exactly(BytesIO(b"ab"), v, "field"), int),
    (int_from_integer, int),
    (int_from_integer, str),
)


@pytest.mark.parametrize(
    "call, claimed",
    _CLAIMED,
    ids=[f"{i}-{t.__name__}" for i, (_, t) in enumerate(_CLAIMED)],
)
@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_a_type_is_refused_as_a_type(
    call: Callable[[Any], object], claimed: type, mock: type[Mock]
) -> None:
    """A `Mock(spec=...)` sets `__class__` to the type it imitates.

    `isinstance` reads `__class__`, so a type test asking it would take
    the Mock for that type; `_has_type` reads `type()` instead.
    """
    with pytest.raises(EccTypeError):
        call(mock(spec=claimed))


def test_a_value_that_claims_a_type_is_described_by_its_own() -> None:
    """The answers of the functions that never raise, for a claimed type."""
    assert not is_integer(Mock(spec=int))
    assert not is_octets(Mock(spec=bytes))
    assert _message_text(Mock(spec=int)) == "a Mock"


def test_utils_tests_a_type_only_through_has_type() -> None:
    """`_has_type`'s docstring says every type test of the module is its."""
    source = (Path(__file__).parents[1] / "src" / "ecc" / "_utils.py").read_text()
    calls = [
        node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "_has_type" in calls
    assert "isinstance" not in calls
