# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The ecc test suite, and the code its modules share.

The vector files are the BIPs', Wycheproof's and a few other projects':
read them here and hand them to `pytest.mark.parametrize`, so that a
vector is a test rather than one turn of a loop inside a single test
function: a failure names the vector instead of the loop that was running
it, and the vectors after the first failure still run -- a loop stops at
the first one and reports nothing about the rest.

Here rather than in a `tests/vectors.py`: every Python file under `tests/`
is a test file except `__init__.py` and `conftest.py`, so shared test
code lives in the package `__init__`.

This package is imported by every test module, before that module's own
body runs. Whatever this file executes at import time therefore executes
inside every module's own measured reach: the suite's coverage floor
reads what the import reaches, never what a test body goes on to call. A
literal is safe to share here at module scope. Anything that calls into
the package's own arithmetic is shared as a function instead, computed
only when a caller invokes it.
"""

import copy
import csv
import hashlib
import importlib
import json
import pkgutil
import re
from dataclasses import fields
from pathlib import Path
from typing import Any, NamedTuple

import pytest

import ecc
from tests.secret_free import WINDOW, assert_secret_free, chained, text_of

_TESTS_DIR = Path(__file__).parent


def module_names() -> list[str]:
    """Return every module of the installed ecc, the root included.

    Here rather than at each site that walks the package, for the reason
    `public_classes_with` below gives. What the walk covers -- a second
    package root, a different prefix, a module it has to skip -- is
    settled here for all of them, and a copy that disagreed would be red
    nowhere: each site asserts against whatever its own walk found.
    """
    return [
        "ecc",
        *(module.name for module in pkgutil.walk_packages(ecc.__path__, "ecc.")),
    ]


def public_classes_with(method_name: str) -> set[str]:
    """Return every public class of the package offering that method.

    Found rather than listed, which is what makes an inventory a promise:
    a class added to the package has to appear in the test that holds the
    method to its contract, or be named an exclusion there. A class this
    walk cannot reach is one no caller can import either.

    The module is part of the name because two classes are called
    `Sig`. A private class is skipped, the contract being about what a
    caller can reach.

    Here rather than in the one test that first needed it: the files that
    call it hold the same classes to contracts of their own, and none of
    them owns the walk.
    """
    found = set()
    for module_name in module_names():
        module = importlib.import_module(module_name)
        for obj in vars(module).values():
            if not isinstance(obj, type):
                continue
            defined_in = getattr(obj, "__module__", "")
            if not (defined_in == "ecc" or defined_in.startswith("ecc.")):
                continue
            if obj.__qualname__.startswith("_"):
                continue
            if callable(getattr(obj, method_name, None)):
                found.add(f"{obj.__module__}.{obj.__qualname__}")
    return found


def load(*relative_path: str, encoding: str = "ascii") -> Any:
    """Read a vendored JSON vector file, named relative to `tests/`.

    Naming a vector file by its path from the test suite root, rather
    than from the test module that reads it, is what lets two packages
    share one file without the `dirname(dirname(__file__))` walk that
    breaks the moment a test module moves.
    """
    with _TESTS_DIR.joinpath(*relative_path).open(encoding=encoding) as file_:
        return json.load(file_)


def load_csv(*relative_path: str, encoding: str = "ascii") -> list[list[str]]:
    """Read a vendored csv vector file, header row dropped."""
    with _TESTS_DIR.joinpath(*relative_path).open(
        newline="", encoding=encoding
    ) as file_:
        return list(csv.reader(file_))[1:]


# what makes an id unreadable in a report and unusable in a -k expression:
# anything that is not a letter, a digit or a dash. Bitcoin Core comments
# hold spaces, quotes, parentheses and slashes; a descriptor holds a '#'
_NOT_IN_AN_ID = re.compile(r"[^0-9A-Za-z]+")


def vector_id(index: int, *description: object) -> str:
    """Name the vector at `index`: where it is, then what it is about.

    The position alone is what parametrize generates on its own, and it
    says where in the file to look but not what the case was testing;
    the description alone -- the comment of a Bitcoin Core vector, a
    script, an address -- reads well but is neither unique nor always
    there. Both, so that the red line of a report both identifies the
    vector in the file and says what it is, and `-k` can select it.

    Truncated, because a description is occasionally a whole script: an
    id is a name, and the vector file remains the place to read the
    case in full.
    """
    text = "-".join(str(d) for d in description if d)
    text = _NOT_IN_AN_ID.sub("-", text).strip("-")
    return f"{index}-{text[:60]}" if text else str(index)


def replace_unchecked(instance: Any, **changes: Any) -> Any:
    """Return `instance` with the given fields changed, validation skipped.

    `dataclasses.replace` always re-validates through `__init__` -- right
    for a modified copy meant to stay valid, wrong for a fixture built to
    fail its own `assert_valid` on purpose. Every frozen, validating
    dataclass in this project takes `check_validity` the same
    keyword-only way (`CONTRIBUTING.md`'s "The public surface"), so this
    is the one helper any of them can use in place of the direct field
    mutation a frozen instance refuses.
    """
    current = {
        field.name: getattr(instance, field.name) for field in fields(instance)
    } | changes
    return type(instance)(**current, check_validity=False)


# --------------------------------------------------------------------------
# One key pair's spellings, shared by `schemes/dsa_test.py` and
# `hashes_test.py`.
#
# Built inside a function rather than at module scope: this package is
# imported by every test module before that module's own body runs, so a
# value computed here at import time would run inside every module's own
# measured reach. `key_pair_spellings` below is not called until
# `schemes/dsa_test.py` or `hashes_test.py` calls it, so a module that asks
# no question about a key pair never reaches the curve arithmetic that
# builds one (issue btclib-org/btclib#2120).
# --------------------------------------------------------------------------


class KeyPairSpellings(NamedTuple):
    """One key pair, in every spelling dsa_test.py and hashes_test.py read.

    The WIF and the xprv are here for the refusals alone: the schemes take a
    scalar and a point, and a spelling that carries a network is read by
    whatever defines its format (issue btclib-org/btclib#1188). Each is
    written out as the Base58Check of its serialization, `b58encode`
    below, so building it asks nothing of a package that parses one.
    """

    q: int
    q_hexstring: str
    plain_prv_keys: list[bytes | str]
    wif_compressed_string: str
    wif_uncompressed_string: str
    xprv_string: str
    Q: tuple[int, int]
    Q_compressed: bytes
    net_unaware_compressed_pub_keys: list[bytes | str]
    net_unaware_uncompressed_pub_keys: list[bytes | str]


def key_pair_spellings() -> KeyPairSpellings:
    """Build one `KeyPairSpellings`, computed on call rather than at import.

    `ecc.curves` is imported inside this function rather than
    at the top of the module, for the reason the block comment above
    gives: a top-level import would run at collection, the same moment
    `Q = mult(q)` would.
    """
    from ecc.curves import mult  # noqa: PLC0415

    q = 12
    q_bytes = q.to_bytes(32, byteorder="big", signed=False)
    q_hexstring = q_bytes.hex()
    q_hexstring2 = " " + q_hexstring + " "

    # the private-key spellings a curve reads: the scalar's octets and
    # their hex, naming neither a network nor a compression
    plain_prv_keys: list[bytes | str] = [q_hexstring, q_hexstring2]

    wif_compressed_string = b58encode(b"\x80" + q_bytes + b"\x01").decode("ascii")
    wif_uncompressed_string = b58encode(b"\x80" + q_bytes).decode("ascii")

    # BIP32's serialization: version, depth, parent fingerprint, child
    # index, chain code, and the key behind a zero octet
    xprv_bytes = (
        bytes.fromhex("04 88 ad e4")
        + b"\x00"
        + 4 * b"\x00"
        + 4 * b"\x00"
        + 32 * b"\x00"
        + b"\x00"
        + q_bytes
    )
    xprv_string = b58encode(xprv_bytes).decode("ascii")

    Q = mult(q)
    x_Q_bytes = Q[0].to_bytes(32, byteorder="big", signed=False)
    Q_compressed = (b"\x03" if (Q[1] & 1) else b"\x02") + x_Q_bytes
    Q_compressed_hexstring = Q_compressed.hex()
    Q_compressed_hexstring2 = " " + Q_compressed_hexstring + " "
    Q_compressed_hexstring3 = ("03" if (Q[1] & 1) else "02") + " " + x_Q_bytes.hex()
    Q_uncompressed = (
        b"\x04" + x_Q_bytes + Q[1].to_bytes(32, byteorder="big", signed=False)
    )
    Q_uncompressed_hexstring = Q_uncompressed.hex()
    Q_uncompressed_hexstring2 = " " + Q_uncompressed_hexstring + " "
    Q_uncompressed_hexstring3 = (
        "04 "
        + x_Q_bytes.hex()
        + " "
        + Q[1].to_bytes(32, byteorder="big", signed=False).hex()
    )

    # an xpub is the only public spelling that names a network, and it is
    # not this package's to read (issue btclib-org/btclib#1188), so every
    # family here is network-unaware
    net_unaware_compressed_pub_keys: list[bytes | str] = [
        Q_compressed_hexstring,
        Q_compressed_hexstring2,
        Q_compressed_hexstring3,
    ]
    net_unaware_uncompressed_pub_keys: list[bytes | str] = [
        Q_uncompressed_hexstring,
        Q_uncompressed_hexstring2,
        Q_uncompressed_hexstring3,
    ]

    return KeyPairSpellings(
        q=q,
        q_hexstring=q_hexstring,
        plain_prv_keys=plain_prv_keys,
        wif_compressed_string=wif_compressed_string,
        wif_uncompressed_string=wif_uncompressed_string,
        xprv_string=xprv_string,
        Q=Q,
        Q_compressed=Q_compressed,
        net_unaware_compressed_pub_keys=net_unaware_compressed_pub_keys,
        net_unaware_uncompressed_pub_keys=net_unaware_uncompressed_pub_keys,
    )


# Base58Check, for the WIF and extended-key spellings the refusals above
# are asked with: a checksum of four octets of double SHA256 and the
# bitcoin alphabet. Written for the fixtures, not for use: the package
# parses no Base58, so nothing here has a counterpart to agree with
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(payload: bytes) -> bytes:
    """Return the Base58Check encoding of payload."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    i = int.from_bytes(data, "big")
    digits = bytearray()
    while i:
        i, digit = divmod(i, 58)
        digits.append(_B58_ALPHABET[digit])
    zeros = len(data) - len(data.lstrip(b"\0"))
    return b"1" * zeros + bytes(reversed(digits))


def b58decode(text: str) -> bytes:
    """Return the payload of a Base58Check string, its checksum dropped."""
    i = 0
    for char in text.encode("ascii"):
        i = i * 58 + _B58_ALPHABET.index(char)
    zeros = len(text) - len(text.lstrip("1"))
    data = b"\0" * zeros + i.to_bytes((i.bit_length() + 7) // 8, "big")
    return data[:-4]


# What a test asking libsecp256k1 for the right answer is marked with.
#
# The suite validates the package's Python arithmetic *against* the bindings, so
# a few tests hold both implementations and compare them. Those cannot run where
# only one exists, and marking them is what lets the rest of the suite -- the
# tests that ask the package a question and not libsecp256k1 -- run in the
# configuration issue btclib-org/btclib#966 is about.
#
# A marker and not a `skipif`, with `conftest.py` turning it into a skip
# where the bindings are absent. One name then does both jobs: `pytest -m
# "not bindings"` names the same set the no-bindings job runs, which is
# what a contributor wants long before a second install, and the
# registration in pyproject.toml has something to be strict about. A
# `skipif` alone skips and selects nothing; `pytest.mark.bindings` around
# one does not compose -- a MarkDecorator is not a test function, so it
# is stored as an argument of the outer mark and the skip is lost, which
# a run with the bindings uninstalled reports as 503 failures.
#
# Here rather than in `conftest.py`: conftest is pytest's to import, and
# importing it by name as well is the shape that bites when an import
# mode or a rootdir changes. This package already holds the shared
# loaders these same modules import.
needs_bindings = pytest.mark.bindings

# Runs a test once per arm: the `arm` fixture of `conftest.py`.
both_arms = pytest.mark.usefixtures("arm")


# What a refusal of a secret is fed, section 7 of the organization's standard
# (*A refusal carries no secret*): a hand-picked constant, in each spelling a
# caller passes where a private key, a nonce or a secret share belongs and
# the library refuses it, with every spelling the refusal could print.
#
# The first 16 bytes are 0xff, which puts the integer above the group order;
# the rest is picked by hand, because a run such as all zeros is a piece of
# clean messages too. A 33-byte value is an xprv's `00 || k` field, and a
# 30-byte one is a key cut short.
_REFUSED_RANDOM = bytes.fromhex("9f3a6c1e5b7d284a0c93e6f1d2b85a47")
_REFUSED_BYTES = b"\xff" * 16 + _REFUSED_RANDOM
_REFUSED_INT = int.from_bytes(_REFUSED_BYTES, "big")
_REFUSED_XPRV = b"\x00" + bytes.fromhex(
    "5d0b8e3a71f2c946ae18d73b09c5f4e26a81b7d3c0958e4f1a27d6b39c80e5f4"
)
_REFUSED_SHORT = bytes.fromhex(
    "c4a1e97b30d85f62a9170e4c8b3d6a25f1e09c7478b2d6530a1f9e8c4b7d"
)
# a private key that is a scalar and is not the one a call expects
_REFUSED_WRONG_KEY = bytes.fromhex(
    "3b8c1f6e2a97d4053c6e18fa9b2d7041e5a3c8f60d1b92a74e5f3086c1d9a27b"
)
_REFUSED_WIF = "L2hX7yQp9TnVbEa4cWm8sRjZ3uKdFgN5oPiBxYtC6vLwAeUr1HqD"


def _spellings_of(secret: bytes) -> list[str | bytes]:
    as_int = int.from_bytes(secret, "big")
    return [secret, secret.hex(), str(as_int), hex(as_int)]


REFUSED_SECRETS: dict[str, tuple[Any, list[str | bytes]]] = {
    "int": (_REFUSED_INT, _spellings_of(_REFUSED_BYTES)),
    "negative int": (-_REFUSED_INT, _spellings_of(_REFUSED_BYTES)),
    "bytes": (_REFUSED_BYTES, _spellings_of(_REFUSED_BYTES)),
    "bytearray": (bytearray(_REFUSED_BYTES), _spellings_of(_REFUSED_BYTES)),
    "hex string": (_REFUSED_BYTES.hex(), _spellings_of(_REFUSED_BYTES)),
    "0x hex string": (hex(_REFUSED_INT), _spellings_of(_REFUSED_BYTES)),
    "33 bytes": (_REFUSED_XPRV, _spellings_of(_REFUSED_XPRV)),
    "30 bytes": (_REFUSED_SHORT, _spellings_of(_REFUSED_SHORT)),
    "WIF": (_REFUSED_WIF, [_REFUSED_WIF]),
    "wrong key": (_REFUSED_WRONG_KEY, _spellings_of(_REFUSED_WRONG_KEY)),
}


def refused_secret(kind: str) -> tuple[Any, list[str | bytes]]:
    """Return a copy of the secret of that kind, and its spellings.

    A copy, because a `bytearray` secret nonce is zeroed by the call that
    reads it, and the next test would be fed zeros.
    """
    value, spellings = REFUSED_SECRETS[kind]
    return copy.copy(value), spellings


# Which of them a parameter that takes an `Integer` and one that takes
# `Octets` refuses: an integer is no octets.
#
# `wrong key` is no refusal of a scalar: it is what a call that checks a key
# against another value is fed, so it is in neither list.
REFUSED_SCALARS = [kind for kind in REFUSED_SECRETS if kind != "wrong key"]
REFUSED_OCTETS = [
    kind for kind in REFUSED_SCALARS if kind not in {"int", "negative int"}
]

# What a parameter of auxiliary randomness (`aux`, `rand_`: exactly 32 octets)
# refuses of the secrets above, and what one of extra entropy (`extra_in`,
# `extra_entropy`, `rand`: octets of any size) refuses. The 32 bytes, as
# bytes, bytearray or hex string, are 32 octets and accepted; a 33- or
# 30-byte value is accepted where the size is free.
REFUSED_AUX = ["int", "negative int", "0x hex string", "33 bytes", "30 bytes", "WIF"]
REFUSED_EXTRA = ["int", "negative int", "0x hex string", "WIF"]

# A private key a constructor accepts, in each spelling it accepts: the one
# valid scalar of the secrets above, which an object then holds.
HELD_KEYS: dict[str, Any] = {
    "int": int.from_bytes(_REFUSED_WRONG_KEY, "big"),
    "bytes": _REFUSED_WRONG_KEY,
    "bytearray": bytearray(_REFUSED_WRONG_KEY),
    "hex string": _REFUSED_WRONG_KEY.hex(),
}
HELD_KEY_SPELLINGS = _spellings_of(_REFUSED_WRONG_KEY)


def assert_repr_secret_free(
    obj: object, secrets: list[str | bytes] = HELD_KEY_SPELLINGS
) -> None:
    """Assert that neither `repr(obj)` nor `str(obj)` holds a piece of a secret.

    `assert_secret_free` reads an exception, so the two texts go in one.
    """
    assert_secret_free(Exception(repr(obj), str(obj)), secrets)


def assert_no_byte_of(
    exc: BaseException, field: bytes, secrets: list[str | bytes]
) -> None:
    """Assert that a refusal prints no part of a field, in the spellings below.

    `assert_secret_free` looks for pieces of `WINDOW // 2` bytes, and for a
    shorter secret whole, so the field's value is also looked for in both
    byte orders, and each shorter run of 2 or more of its bytes as hex, in
    either order and inside any word. Each byte is looked for as a word of
    hex or of decimal, as `0x` and its two hex digits, the way a tag or a
    length is printed, as the word `hex` writes for it, which has one digit
    below 0x10, as the escape a `repr` of bytes writes for it, and as its
    own `repr`.
    """
    values = [int.from_bytes(field, order) for order in ("big", "little")]
    spellings = [f"{value:x}" for value in values] + [str(v) for v in values]
    assert_secret_free(exc, [*secrets, *spellings])
    runs = {
        spelled
        for size in range(2, WINDOW // 2)
        for i in range(len(field) - size + 1)
        for spelled in (field[i : i + size].hex(), field[i : i + size][::-1].hex())
    }
    for e in chained(exc):
        text = text_of(e)
        for run in runs:
            assert run not in text
        for byte in field:
            assert f"0x{byte:02x}" not in text
            assert re.search(rf"\b0x{byte:x}\b", text) is None
            assert f"\\x{byte:02x}" not in text
            assert repr(bytes([byte])).lower() not in text
            assert re.search(rf"\b{byte:02x}\b", text) is None
            assert re.search(rf"\b{byte}\b", text) is None


# What a test asking the flagged `btclib_secp256k1.zkp` extension for the right
# answer is marked with. Issue btclib-org/btclib#1679 is the sentinel that
# installs btclib-secp256k1 from the sdist with `BTCLIB_LIBSECP256K1_ZKP=true`,
# which is the only environment where the extension exists at all: every
# published wheel carries the `zkp` wrapper modules and none carries
# `_btclib_secp256k1_zkp`, so this marker's own environment is narrower than
# `bindings`' and needs a probe of its own.
#
# `import btclib_secp256k1.zkp` succeeds wherever `btclib_secp256k1`
# itself does, wheel or sdist, flagged or not -- the wrapper modules bind
# their names without reaching for the extension, which is why the
# condition below is an attribute access and not the import. `zkp.lib`
# and `zkp.ffi` are what the subpackage resolves lazily, through a
# module-level `__getattr__` its own docstring names, and raise
# `ImportError` where the build the environment installed has none.
# `ImportError` and not `ModuleNotFoundError` alone, because
# `btclib_secp256k1` itself is absent in the no-bindings job, and the
# import above raises the narrower `ModuleNotFoundError` there -- a
# subclass of `ImportError`, so one `except` covers both without a
# tuple.
#
# Here rather than beside `INSTALLED` in `src/ecc/_libsecp256k1.py`:
# that module answers what the package's own run-time asks of libsecp256k1, and
# nothing in the package delegates to secp256k1-zkp -- issue
# btclib-org/btclib#1679 asks only for the comparison this suite makes to be
# runnable, not for a dispatch, so the question "is zkp available" is this
# suite's own and has no answer `_libsecp256k1.py` would ever read.
#
# Both arms below carry a pragma, the build deciding which one a run
# takes: a flagged build never raises here and an unflagged one never
# reaches the `else`, so an arm left measured is one that run cannot
# execute. Unlike `INSTALLED` above, whose arms `test.yml`'s `coverage`
# and `no-bindings` jobs measure between them and its `coverage-union`
# combines: `zkp-oracle.yml` runs `pytest -m zkp --no-cov`, which
# collects nothing for a union to combine. What the reasons name is the
# build and not the job, because a contributor who builds the extension
# to run `pytest -m zkp` measures coverage in that build too, and a
# reason true only of CI leaves that run short of the floor in files
# the contributor never touched (issue btclib-org/btclib#1885).
try:
    from btclib_secp256k1 import zkp

    # the probe itself: not assigned because nothing here reads it back,
    # `ffi` answering the same question `lib` does once either has run
    _ = zkp.lib
except ImportError:  # pragma: no cover -- the arm an unflagged build takes
    ZKP_AVAILABLE = False
else:
    ZKP_AVAILABLE = True  # pragma: no cover -- the arm a flagged build takes

needs_zkp = pytest.mark.zkp


class Sha256FirstByte:
    """sha256 cut to its first byte, a hashlib-like object.

    One octet is shorter than the order of every curve whose n has nine
    bits or more, so the paths for a hash shorter than n run on a curve
    small enough to sweep. Not collision resistant.
    """

    digest_size = 1
    block_size = 64
    name = "sha256-first-byte"

    def __init__(self, data: bytes = b"") -> None:
        """Start from data, as hashlib's constructors do."""
        self._sha256 = hashlib.sha256(data)

    def update(self, data: Any, /) -> None:
        """Absorb more data."""
        self._sha256.update(data)

    def digest(self) -> bytes:
        """Return the first byte of the sha256 of everything absorbed."""
        return self._sha256.digest()[:1]

    def hexdigest(self) -> str:
        """Return the digest as a hex string."""
        return self.digest().hex()

    def copy(self) -> "Sha256FirstByte":
        """Return a clone that absorbs independently."""
        clone = Sha256FirstByte()
        clone._sha256 = self._sha256.copy()
        return clone


class AllOnesHash:
    """A hashlib-like object whose digest is always 32 octets of 0xff.

    The digest is above the order of secp256k1, so a nonce derivation
    that draws it never gets a candidate in 1..n-1. It counts its
    digests in `digests` and raises after `LIMIT`, so that a derivation
    without a bound fails the test instead of hanging it.
    """

    digest_size = 32
    block_size = 64
    name = "all-ones"
    LIMIT = 100_000
    digests = 0

    def __init__(self, data: bytes = b"") -> None:
        """Start from data, as hashlib's constructors do."""

    def update(self, data: Any, /) -> None:
        """Absorb more data, which changes nothing."""

    def digest(self) -> bytes:
        """Return 32 octets of 0xff, or fail once the limit is passed."""
        type(self).digests += 1
        if type(self).digests > self.LIMIT:
            msg = f"more than {self.LIMIT} digests: the derivation does not stop"
            raise AssertionError(msg)
        return b"\xff" * 32

    def hexdigest(self) -> str:
        """Return the digest as a hex string."""
        return self.digest().hex()

    def copy(self) -> "AllOnesHash":
        """Return a clone, which absorbs nothing either."""
        return AllOnesHash()


# --------------------------------------------------------------------------
# AES-128, for `schemes/ecies_test.py`'s CBC vectors.
#
# **Why a test writes its own block cipher.** This package takes no
# cryptographic dependency and ships no cipher: hashlib and the
# secp256k1 bindings are the whole of it, `ecc.ecies`'s module docstring
# has the argument in full, and `ecc.dsa`/`ecc.ssa` inherit it -- a
# table-driven AES leaks its key through cache timing, and a
# timing-vulnerable cipher is a worse thing to ship than none. None of
# that reaches this file: the wheel and the sdist carry no tests, so
# nothing here is installed on a user's machine, and the keys used
# against it below are fixed published test vectors, so there is no
# secret for a timing side channel to leak. A test-only dependency would
# buy the same vectors for the price of a package neither module
# otherwise needs, and would make this reasoning invisible, since a
# dependency does not explain itself.
#
# It is written for the vectors, not for use: correct, small enough to
# read against FIPS-197, and slow. Do not import it from anywhere but
# `schemes/ecies_test.py`.
# --------------------------------------------------------------------------

_AES_BLOCK_SIZE = 16
# FIPS-197 section 5.2, the round constants a 128-bit key schedule
# reads: index `i // nk - 1` with `i < 4 * (nr + 1)`, which reaches 9
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_xtime(a: int) -> int:
    """Multiply by x in GF(2^8), modulo the AES polynomial x^8+x^4+x^3+x+1."""
    a <<= 1
    return a ^ 0x11B if a & 0x100 else a


def _aes_mul(a: int, b: int) -> int:
    """Multiply two elements of GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _aes_xtime(a)
        b >>= 1
    return result


def _aes_build_boxes() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return the S-box and its inverse, derived rather than tabulated.

    A 256-entry table copied from somewhere is a table nobody can check;
    the definition is short enough to write instead. Each byte maps to its
    multiplicative inverse in GF(2^8) -- read off the exp/log tables of the
    generator 3, with zero mapping to itself -- under the AES affine
    transform, which is the byte xored with four rotations of itself and
    with 0x63.
    """
    exp = [0] * 255
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _aes_mul(x, 3)

    sbox = []
    for i in range(256):
        inverse = 0 if i == 0 else exp[(255 - log[i]) % 255]
        rotated = inverse
        affine = inverse
        for _ in range(4):
            rotated = ((rotated << 1) | (rotated >> 7)) & 0xFF
            affine ^= rotated
        sbox.append(affine ^ 0x63)

    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i
    return tuple(sbox), tuple(inv_sbox)


_AES_SBOX, _AES_INV_SBOX = _aes_build_boxes()


def aes_expand_key(key: bytes) -> list[list[int]]:
    """Return the round keys of an AES-128 key.

    `nk`, the key length in 32-bit words, is 4 and `nr`, the number of
    rounds, is `nk + 6`, FIPS-197 table 1. AES-256's extra SubWord every
    fourth word is not here: nothing in this suite asks for a 256-bit
    key, and a branch no test reaches is one no test checks.
    """
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        word = list(words[i - 1])
        if i % nk == 0:
            word = [_AES_SBOX[b] for b in (*word[1:], word[0])]
            word[0] ^= _AES_RCON[i // nk - 1]
        words.append([a ^ b for a, b in zip(words[i - nk], word, strict=True)])
    return [
        [b for word in words[4 * r : 4 * r + 4] for b in word] for r in range(nr + 1)
    ]


# the state is 16 bytes in input order, so flat index 4*column+row: that is
# exactly how FIPS-197 fills its 4x4 array, column by column
def _aes_sub_bytes(state: list[int], box: tuple[int, ...]) -> list[int]:
    return [box[b] for b in state]


def _aes_shift_rows(state: list[int], *, inverse: bool = False) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            source = (c - r) % 4 if inverse else (c + r) % 4
            out[4 * c + r] = state[4 * source + r]
    return out


def _aes_mix_columns(state: list[int], *, inverse: bool = False) -> list[int]:
    coefficients = (14, 11, 13, 9) if inverse else (2, 3, 1, 1)
    out = [0] * 16
    for c in range(4):
        column = state[4 * c : 4 * c + 4]
        for r in range(4):
            acc = 0
            for k in range(4):
                acc ^= _aes_mul(column[k], coefficients[(k - r) % 4])
            out[4 * c + r] = acc
    return out


def _aes_add_round_key(state: list[int], round_key: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(state, round_key, strict=True)]


def aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Encrypt one 16-byte block under an expanded key, no mode, no padding."""
    nr = len(round_keys) - 1
    state = _aes_add_round_key(list(block), round_keys[0])
    for rnd in range(1, nr):
        state = _aes_mix_columns(_aes_shift_rows(_aes_sub_bytes(state, _AES_SBOX)))
        state = _aes_add_round_key(state, round_keys[rnd])
    state = _aes_shift_rows(_aes_sub_bytes(state, _AES_SBOX))
    return bytes(_aes_add_round_key(state, round_keys[nr]))


def aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Decrypt one 16-byte block under an expanded key, no mode, no padding."""
    nr = len(round_keys) - 1
    state = _aes_add_round_key(list(block), round_keys[nr])
    for rnd in range(nr - 1, 0, -1):
        state = _aes_sub_bytes(_aes_shift_rows(state, inverse=True), _AES_INV_SBOX)
        state = _aes_mix_columns(
            _aes_add_round_key(state, round_keys[rnd]), inverse=True
        )
    state = _aes_sub_bytes(_aes_shift_rows(state, inverse=True), _AES_INV_SBOX)
    return bytes(_aes_add_round_key(state, round_keys[0]))


def aes_xor(a: bytes, b: bytes) -> bytes:
    """Return the byte-wise XOR of two equal-length buffers."""
    return bytes(x ^ y for x, y in zip(a, b, strict=True))
