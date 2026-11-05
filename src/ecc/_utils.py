# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The coercions every public function runs its inputs through.

Private: these are the conversions an `Octets`, a `String`, an `Integer`
and a `BinaryData` parameter owe their caller, and the refusals of a
short read and of trailing bytes, raised through this package's own
exceptions.

`read_exactly` and `assert_no_trailing` are the two halves of what every
`parse` owes its caller:

- a field is as long as its encoding says it is, so a short read is an
  error and not a value
- octets are one whole object, so bytes after it are refused; a caller's
  stream is not, so parsing consumes the object and leaves the stream on
  the byte after it
"""

from __future__ import annotations

import string
from collections.abc import Iterable
from io import BytesIO
from typing import Any, BinaryIO

from typing_extensions import TypeIs

from ecc.alias import BinaryData, Integer, Octets, String
from ecc.exceptions import EccTypeError, EccValueError

__all__ = [
    "NoneOneOrMoreInt",
    "assert_no_trailing",
    "assert_type",
    "bytes_from_octets",
    "bytesio_from_binarydata",
    "hex_string",
    "int_from_bits",
    "int_from_integer",
    "is_integer",
    "is_octets",
    "read_exactly",
    "str_from_string",
]

NoneOneOrMoreInt = int | Iterable[int] | None

# Candidates a nonce derivation draws before it refuses. A hash function
# behaving as a random oracle misses 1..n-1 with probability at most 1/2
# per draw on any curve this package takes, so 256 misses in a row have
# probability at most 2^-256; on secp256k1 one miss is about 2^-128.
# RFC6979 section 3.2.h.3 and libsecp256k1's signing loop set no bound,
# and BIP340 draws once. The bound turns a caller's hash function that
# never yields a candidate from a hang into a refusal.
_MAX_NONCE_ATTEMPTS = 256


def _assert_byte_shaped(octets: bytes | bytearray | memoryview) -> None:
    """Refuse a memoryview whose layout or format is not plain bytes.

    `bytes` and `bytearray` are always C-contiguous and always format
    "B" (unsigned bytes); a `memoryview` need not be either, and the
    copy `bytes_from_octets` makes takes both without a word. A strided
    slice such as `mv[::2]` is not C-contiguous, and `bytes()` of one
    gathers its strides into a run that no buffer holds.

    Contiguity is not the only property the octets a caller counts rest on: a
    `memoryview` cast to a signed `"b"`, or built over an array of a wider
    format such as `"I"`, is C-contiguous and still not the octets it looks like
    -- `len()` counts elements where `bytes()` yields `itemsize` of them each,
    so the caller's count of its own octets and the library's disagree (issue
    btclib-org/btclib#1430). Format `"B"` is the one every buffer this function
    accepts shares, `bytes`, `bytearray` and an unformatted `memoryview`
    included, so it is the property asked for rather than `itemsize == 1`, which
    a signed `"b"` view or a `"c"` one (bytes objects, not ints) would still
    pass.
    """
    if not isinstance(octets, memoryview):
        return
    if not octets.c_contiguous:
        err_msg = "invalid octets: non-contiguous memoryview"
        raise EccValueError(err_msg)
    if octets.format != "B":
        err_msg = f"invalid octets: memoryview format {octets.format!r} instead of 'B'"
        raise EccValueError(err_msg)


def bytes_from_octets(octets: Octets, out_size: NoneOneOrMoreInt = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    A `bytearray` or a `memoryview` is copied, which is what makes the
    `bytes` this promises true: handed back as it came, either is still
    the caller's own object, so a write to it afterwards reaches into
    whatever kept the return value -- a key, and every encoding of it
    computed afterwards. The copy is
    also what reads as octets everywhere the result goes: a `memoryview`
    has no `+` to concatenate with, and a `bytearray` keys no dict.

    Optionally, it also ensures required output size: one size, or any
    iterable of them, and a bool is neither -- `out_size=True` would
    accept a single octet and say it had checked a size.

    A non-contiguous `memoryview` -- what a strided slice such as
    `mv[::2]` gives -- is refused rather than copied, and so is one whose
    format is not unsigned bytes: `_assert_byte_shaped` says why neither
    is the octets it looks like. The refusal is raised through the
    exception contract at the one place every `Octets` parameter passes,
    rather than left to whichever consumer trips over it first.
    """
    if isinstance(octets, str):  # hex string
        # `bytes.fromhex` raises a bare ValueError -- the same class the
        # contract promises, so what was lost is only that it came from
        # here. This is the one coercion every `Octets` parameter of the
        # library runs through, so it is the one place worth saying it in.
        # The message is fromhex's own, which names a position and never
        # the string: an Octets parameter is candidate key material as
        # often as not (issue btclib-org/btclib#137)
        try:
            octets = bytes.fromhex(octets)
        except ValueError as e:
            raise EccValueError(f"invalid hex string: {e}") from e
    elif isinstance(octets, (bytes, bytearray, memoryview)):
        _assert_byte_shaped(octets)
        # the copy that makes the annotation true (issue
        # btclib-org/btclib#1255). `bytes(b)` is `b` itself where `b` is already
        # `bytes`, which is what nearly every call passes, so the arm every
        # `Octets` parameter of the library runs through allocates nothing
        octets = bytes(octets)
    else:
        # what is neither went through untouched and reached whatever the
        # caller went on to do with it: `len` of a tuple of 33 ints is 33,
        # so a size check alone would accept one as a compressed key
        err_msg = f"invalid octets type: {type(octets).__name__}"  # type: ignore[unreachable]
        raise EccTypeError(err_msg)

    if out_size is None:
        return octets

    # one size or an iterable of them, and nothing else: `tuple()` on
    # whatever is left would refuse a float with a bare TypeError about
    # iteration -- a complaint about the wrong thing, and from underneath
    # the library rather than through its exception contract
    if isinstance(out_size, int):
        sizes: tuple[int, ...] = (out_size,)
    elif isinstance(out_size, Iterable):
        sizes = tuple(out_size)
    else:
        err_msg = f"invalid output size type: {type(out_size).__name__}"  # type: ignore[unreachable]
        raise EccTypeError(err_msg)

    for size in sizes:
        if not is_integer(size):
            err_msg = f"invalid output size type: {type(size).__name__}"
            raise EccTypeError(err_msg)

    size = len(octets)
    if size in sizes:
        return octets

    err_msg = f"invalid size: {size} bytes instead of {out_size}"
    raise EccValueError(err_msg)


def str_from_string(s: String, what: str) -> str:
    """Return the text of a String, whether it came as text or as ascii bytes.

    What `bytes_from_octets` is to `Octets`, for text: the base64 armor
    of an envelope is ascii, so a byte outside it is an invalid character
    like any other and gets the same answer -- a UnicodeDecodeError let
    out would fly past every caller written to catch an
    EccValueError.

    `what` names the string in both messages, the caller knowing what it
    was reading and this not, exactly as `read_exactly` names a field.

    Nothing is stripped and nothing is lowered: which of those is right
    is the caller's to know.
    """
    if isinstance(s, str):
        return s

    if not isinstance(s, (bytes, bytearray, memoryview)):
        # what is neither went through untouched, to fail on `len` or on
        # a method of str that the value does not have -- a complaint
        # about a builtin rather than about the argument
        err_msg = f"invalid {what} type: {type(s).__name__}"  # type: ignore[unreachable]
        raise EccTypeError(err_msg)

    try:
        return bytes(s).decode("ascii")
    except UnicodeDecodeError as e:
        # the UnicodeDecodeError holds the whole input and names the
        # refused byte: raised here it would chain both, so the position
        # is kept and the refusal is raised after the block
        position = e.start
    raise EccValueError(f"non-ascii character in {what} at position {position}")


def bytesio_from_binarydata(stream: BinaryData) -> BytesIO:
    """Return a BytesIO stream object from a BytesIO or from Octets.

    A `BytesIO` is the caller's own and is handed back as it came, the
    position it is left at being how a transaction is read out of a
    block. Anything else is octets, and is wrapped in one.

    A `BytesIO` and not any binary stream: `deserialize_map` asks the
    result for `getbuffer()`, which a file object does not have, so
    accepting one here would only move the failure. `read_exactly` is
    the one that takes a `BinaryIO`, and its docstring says why.
    """
    if isinstance(stream, BytesIO):
        return stream

    # the refusal of what is neither a stream nor octets is
    # bytes_from_octets's to give: without it, what is neither would go
    # through untouched and be returned as it came, so `parse` would
    # answer a None with a None and the caller would fail on `.read`
    # rather than here
    return BytesIO(bytes_from_octets(stream))


def read_exactly(stream: BinaryIO, size: int, what: str) -> bytes:
    """Return size octets from the stream, or raise: a short read is truncation.

    `BytesIO.read` answers with whatever is left when the buffer holds
    less than was asked for, and `int.from_bytes` takes the short answer
    without a word. The size is what makes the field boundary, so it is
    checked whatever `check_validity` says: see this module's docstring
    for why that is not the same question.

    `what` names the field in the error message, the caller knowing which
    one it was reading and the stream not.

    `BinaryIO` and not the `BytesIO` of `alias.BinaryData`: `.read` is
    the whole of what a short read is about, so a file object is as much
    an answer here as a buffer.
    """
    data = stream.read(size)
    if len(data) != size:
        err_msg = f"not enough data for the {what}: "
        err_msg += f"{len(data)} bytes instead of {size}"
        raise EccValueError(err_msg)
    return data


def assert_no_trailing(data: BinaryData, stream: BytesIO, what: str) -> None:
    """Refuse bytes left over after a complete octet encoding.

    Octets are one whole object, so what follows the object in them is
    malleability: two buffers deserializing to the one object that
    serializes back to only the shorter of them. A caller's stream is the
    other case, and nothing is checked there -- what follows in it is the
    caller's, a transaction inside a block being read from the very stream
    the block is read from -- so `parse` leaves the stream on the byte
    after the object.

    Bitcoin Core splits the two the same way, between `Unserialize` and
    `DecodeRawPSBT`'s "extra data after PSBT".
    """
    if isinstance(data, BytesIO):
        return

    if trailing := stream.read():
        raise EccValueError(f"{len(trailing)} bytes after the {what}")


def is_integer(value: Any) -> bool:
    """Return whether the value is an integer, a bool not being one.

    `isinstance(x, int)` is True for `True` and `False`, `bool` being a
    subclass of `int` -- so every field of this library whose contract is
    an integer quantity accepted a boolean as the number one or zero, and
    `int(True) == True` slips through a conversion-and-equality check as
    well. What makes that worth a refusal rather than a shrug is the json
    boundary: `true` decodes to `True`, so a schema mistake became one
    satoshi, one virtual byte, one index or a one-sat/kvB fee rate instead
    of failing next to the input that caused it.

    A boolean is not another spelling of a number, which is the difference
    from the strings and bytes much of this library accepts: "1" is a
    number written down, `True` is a different type that Python's
    inheritance makes indistinguishable from one.

    `isinstance` and not `type(value) is int`, so an `IntEnum` -- what issue
    btclib-org/btclib#273 asks about for the sighash types -- and any other
    deliberate integer subclass stay integers. `bool` is the one subclass
    excluded, and by name.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def is_octets(value: Any) -> TypeIs[Octets]:
    """Return whether the value is one Octets, rather than a sequence of them.

    An `Octets` -- `str`, `bytes`, `bytearray` or `memoryview` -- is
    itself iterable, so a function that takes a sequence of them and
    guards against being handed one instead cannot ask `isinstance(value,
    Sequence)`: every `Octets` answers that too. The guard asks this
    question instead, once, so a spelling `Octets` gains later is refused
    at every caller of this rather than at whichever remembered to list
    it (issue btclib-org/btclib#1261).

    `TypeIs` rather than `bool`: a caller dispatching on this narrows on
    both branches, `str | bytes | bytearray | memoryview` where it is
    true and whatever is left of the wider type where it is false, which
    is what lets a site written as a hand-listed `isinstance` tuple --
    invisible to a census keyed on that tuple's own element order -- call
    this instead without losing the narrowing mypy strict mode otherwise
    needs the tuple for (issue btclib-org/btclib#1433).
    """
    return isinstance(value, Octets)


def assert_type(value: Any, expected: Any, what: str) -> None:
    """Refuse a value of a type the signature does not declare.

    `expected` is what `isinstance` takes: one type, or a tuple of them.
    `bytes_from_octets` and `str_from_string` are the two coercions this
    library has, and each refuses what it cannot convert; this is the
    refusal for a position that takes neither -- a `bool` flag deciding
    which of two serializations is written, the text of a URI or a
    descriptor, the magic bytes an envelope is read against. Every one of
    those was compared, walked or handed to a builtin unasked, and left
    as a complaint about that builtin.

    `value` is `Any` rather than the declared type, which is what makes
    the check reachable: mypy proves the argument cannot be wrong, and
    the caller who has not run mypy is who this is for.
    """
    if not isinstance(value, expected):
        raise EccTypeError(f"invalid {what} type: {type(value).__name__}")


def int_from_bits(octets: Octets, nlen: int) -> int:
    """Return the leftmost nlen bits.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5); ensuring 0 < i < n would take a
    further reduction modulo n, which is the caller's.

    int_from_bits is not the reverse of i.to_bytes, even
    for input sequences of length nlen: i.to_bytes will add some
    bits on the left, while int_from_bits will discard some bits on the
    right. i.to_bytes is the reverse of int_from_bits only when
    nlen is a multiple of 8 and bit sequences already have length nlen.
    See:
    - https://www.rfc-editor.org/rfc/rfc6979.html#section-2.3.5
    """
    octets = bytes_from_octets(octets)
    i = int.from_bytes(octets, byteorder="big", signed=False)

    blen = len(octets) * 8  # bits
    n = (blen - nlen) if blen >= nlen else 0
    return i >> n


def int_from_integer(i: Integer) -> int:
    r"""Return an int from many possible integer representations.

    A bool is not one of them, `is_integer` being where this library
    says so: every `Integer` parameter runs through here, so the refusal
    is stated once and inherited (issue btclib-org/btclib#1206).

    Allowed integer representations are:

    * 3735928559
    * -3735928559
    * "0xdeadbeef"
    * "-0xdeadbeef"
    * "deadbeef"
    * b'\xde\xad\xbe\xef'

    A str is always read as a hex-string, with or without the "0x" prefix:
    int_from_integer("1234") is 4660, not one thousand two hundred and
    thirty-four, and "9" raises ValueError for being a hex-string of odd
    length rather than evaluating to nine. A decimal representation is
    what int itself is for, so pass int("1234").

    Only ASCII hex digits follow the "0x" prefix, and only ASCII
    whitespace is stripped around the string: "0x1_0" and "0x" followed by
    fullwidth or Arabic-Indic digits are refused, where Python's own int
    reads them as numbers.

    The binary representation is not allowed because there is no way to
    discriminate it from a valid hex-string
    (e.g. "0b11011110101011011011111011101111").
    """
    if isinstance(i, int):
        # `is_integer` and not the `isinstance` above: a bool is an int to
        # Python and is not a number to this library, which is the rule issue
        # btclib-org/btclib#326 gave every integer field and issue
        # btclib-org/btclib#1206 found the key path without. Here rather than at
        # each caller, this being the one coercion every `Integer` parameter
        # runs through
        if not is_integer(i):
            raise EccTypeError(f"non-integer: {i}")
        return i

    if isinstance(i, str):
        # `string.whitespace`, not the bare `str.strip()`: that strips
        # every character `isspace` counts, U+00A0 and U+3000 included
        i = i.strip(string.whitespace).lower()
        if i.startswith(("0x", "-0x")):
            # `int(i, 16)` alone reads "0x1_0" as 16, and so every Unicode
            # decimal digit, U+0661 as readily as "1": what follows the
            # prefix is checked against ASCII hex first. The refusal does
            # not quote the string, which may be a private key
            digits = i[3:] if i[0] == "-" else i[2:]
            if not digits or any(c not in "0123456789abcdef" for c in digits):
                err_msg = "invalid hex integer: what follows 0x is not ASCII hex digits"
                raise EccValueError(err_msg)
            return int(i, 16)

    # the hex string, and the refusal of what is neither that nor bytes,
    # both being bytes_from_octets's to give
    return int.from_bytes(bytes_from_octets(i), "big", signed=False)


def hex_string(i: Integer) -> str:
    """Return a hex-string from many positive integer representations.

    Negative integers are not allowed.

    The resulting hex-string has an even number of hex-digits and
    includes a space every four bytes (i.e. every eight hex-digits).
    """
    int_ = int_from_integer(i)
    if int_ < 0:
        raise EccValueError("negative integer")
    a_str = f"{int_:x}"
    if len(a_str) % 2 != 0:
        a_str = f"0{a_str}"

    indexes = list(reversed(range(len(a_str), 0, -8)))
    lresult = [(a_str[max(0, i - 8) : i]) for i in indexes]
    result = " ".join(lresult)
    return result.upper()
