# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Mutated DER signatures, read by `Sig.parse` and by two other parsers.

`tests/schemes/der_test.py` holds one malformed encoding per rule. Here a
seeded generator mutates well-formed encodings and every result goes to
`Sig.parse(strict=True, check_validity=False)`, to Bitcoin Core's
`IsValidSignatureEncoding` written out below, and, where the bindings are
installed, to libsecp256k1's `secp256k1_ecdsa_signature_parse_der`.
"""

import random
from collections.abc import Iterator
from contextlib import suppress

from ecc._libsecp256k1 import dsa as libsecp256k1_dsa
from ecc.curves import secp256k1
from ecc.ecc.dsa import Sig
from ecc.exceptions import EccValueError
from tests import needs_bindings

ec = secp256k1

# the input set: `_encodings` below, with this seed and this many cases
_SEED = 359
_CASES = 100_000


# one `if` per test of Core's function, so that the two read side by side
def _is_valid_signature_encoding(sig: bytes) -> bool:  # noqa: C901, PLR0911, PLR0912
    """Return Bitcoin Core's `IsValidSignatureEncoding` verdict.

    A line-for-line transcription of `src/script/interpreter.cpp` at
    bitcoin/bitcoin dd9d2b919d, so that `Sig.parse` is compared with a
    reading it does not share code with. Core reads the signature with its
    sighash byte still on it, which is why its bounds are 9 and 73.
    """
    if len(sig) < 9:
        return False
    if len(sig) > 73:
        return False
    if sig[0] != 0x30:
        return False
    if sig[1] != len(sig) - 3:
        return False
    len_r = sig[3]
    if 5 + len_r >= len(sig):
        return False
    len_s = sig[5 + len_r]
    if len_r + len_s + 7 != len(sig):
        return False
    if sig[2] != 0x02:
        return False
    if len_r == 0:
        return False
    if sig[4] & 0x80:
        return False
    if len_r > 1 and sig[4] == 0x00 and not sig[5] & 0x80:
        return False
    if sig[len_r + 4] != 0x02:
        return False
    if len_s == 0:
        return False
    if sig[len_r + 6] & 0x80:
        return False
    return not (len_s > 1 and sig[len_r + 6] == 0x00 and not sig[len_r + 7] & 0x80)


def _core_scalars(der: bytes) -> tuple[int, int]:
    """Return (r, s) at the offsets Core's layout gives them."""
    len_r = der[3]
    len_s = der[5 + len_r]
    r = int.from_bytes(der[4 : 4 + len_r], "big")
    s = int.from_bytes(der[6 + len_r : 6 + len_r + len_s], "big")
    return r, s


def _element(value: bytes) -> bytes:
    """Return [0x02][size][value], with the size in one octet."""
    return b"\x02" + bytes([len(value)]) + value


def _sequence(body: bytes) -> bytes:
    """Return [0x30][size][body], with the size in one octet."""
    return b"\x30" + bytes([len(body)]) + body


def _scalar(rng: random.Random) -> int:
    """Return a scalar of any width up to 256 bits, edges included."""
    kind = rng.randrange(4)
    if kind == 0:
        return rng.getrandbits(rng.randint(1, 256))
    if kind == 1:
        return rng.choice((0, 1, 0x7F, 0x80, 0xFF, 0x100))
    if kind == 2:
        return ec.n + rng.randrange(-2, 2)
    return 2**256 - 1 - rng.randrange(4)


def _repadded(rng: random.Random, der: bytes) -> bytes:
    """Return der with r's or s's leading octets changed, sizes kept true.

    An extra 0x00 or 0xff, a random octet, or the first octet dropped:
    every size is written again afterwards, so it is the integer rules
    and the size bound that answer, not the framing.
    """
    len_r = der[3]
    values = [der[4 : 4 + len_r], der[6 + len_r :]]
    which = rng.randrange(2)
    value = values[which]
    kind = rng.randrange(4)
    if kind == 0:
        value = b"\x00" + value
    elif kind == 1:
        value = b"\xff" + value
    elif kind == 2:
        value = bytes([rng.randrange(256)]) + value
    else:
        value = value[1:]
    values[which] = value
    return _sequence(_element(values[0]) + _element(values[1]))


def _mutated(rng: random.Random, der: bytes, kinds: int) -> bytes:
    """Return der with one mutation, of the first `kinds` below.

    The first four take any non-empty octets; a wrong size and a changed
    padding read the layout, so they take a well-formed encoding.
    """
    data = bytearray(der)
    kind = rng.randrange(kinds)
    if kind == 0:
        for _ in range(rng.randint(1, 3)):
            bit = rng.randrange(len(data) * 8)
            data[bit // 8] ^= 1 << (bit % 8)
    elif kind == 1:
        cut = rng.randrange(len(data))
        data = data[:cut] if rng.randrange(2) else data[cut:]
    elif kind == 2:
        for _ in range(rng.randint(1, 3)):
            data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
    elif kind == 3:
        del data[rng.randrange(len(data))]
    elif kind == 4:
        # a wrong size: the sequence's, r's or s's
        at = rng.choice((1, 3, 5 + data[3]))
        data[at] = rng.choice(
            ((data[at] + 1) % 256, (data[at] - 1) % 256, rng.randrange(256))
        )
    else:
        return _repadded(rng, der)
    return bytes(data)


def _encodings() -> Iterator[bytes]:
    """Yield the input set: well-formed encodings and their mutations."""
    rng = random.Random(_SEED)
    for _ in range(_CASES):
        r, s = _scalar(rng), _scalar(rng)
        der = Sig(r, s, check_validity=False).serialize(check_validity=False)
        if rng.randrange(10):
            der = _mutated(rng, der, 6)
        if der and not rng.randrange(4):
            der = _mutated(rng, der, 4)
        yield der


def _parsed(der: bytes) -> Sig | str:
    """Return what `Sig.parse` reads, or the message it refuses with."""
    try:
        return Sig.parse(der, check_validity=False)
    except EccValueError as e:
        return str(e)


def test_der_parse_agrees_with_core_on_mutations() -> None:
    """`Sig.parse` accepts what Core accepts, and reads the same r and s.

    Core's rule is for the signature with its sighash byte, so each
    encoding is put to it with one appended.
    """
    for der in _encodings():
        sig = _parsed(der)
        valid = _is_valid_signature_encoding(der + b"\x01")
        assert isinstance(sig, Sig) == valid, der.hex()
        if isinstance(sig, Sig):
            assert (sig.r, sig.s) == _core_scalars(der), der.hex()


def _as_libsecp256k1_reads(scalar: int) -> bytes:
    """Return the 32 octets libsecp256k1 reads a non-negative scalar as.

    One not below n reads as zero: the overflow the `Sig` docstring names.
    """
    return (scalar if scalar < ec.n else 0).to_bytes(32, "big")


@needs_bindings
def test_der_parse_agrees_with_libsecp256k1_on_mutations() -> None:
    """libsecp256k1 accepts what `Sig.parse` accepts, outside the overflow.

    The overflow is the one the `Sig` docstring names. Where a scalar is
    out of range, either answer is accepted here, the zero or the refusal,
    for the reason `tests/schemes/der_test.py` gives in
    `test_der_agrees_with_libsecp256k1_except_where_it_is_stricter`.

    That overflow is behind both differences in the verdict:

    - a negative scalar, which `Sig.parse` refuses, is the one
      `tests/schemes/der_test.py` pins, and is not compared again here;
    - more than 70 octets of r,s data, which `Sig.parse` refuses as Core
      does, holds an integer wider than 32 octets: libsecp256k1 has no
      size bound and reads it as zero.
    """
    for der in _encodings():
        sig = _parsed(der)
        compact = None
        with suppress(ValueError):
            compact = libsecp256k1_dsa.to_compact(der)
        if isinstance(sig, Sig):
            read = _as_libsecp256k1_reads(sig.r) + _as_libsecp256k1_reads(sig.s)
            in_range = 0 < sig.r < ec.n and 0 < sig.s < ec.n
            assert compact in ((read,) if in_range else (read, None)), der.hex()
        elif sig.startswith("invalid negative scalar"):
            continue
        elif sig.startswith("invalid DER sequence length: "):
            assert compact is None or bytes(32) in (compact[:32], compact[32:])
        else:
            assert compact is None, (der.hex(), sig)
