# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Everything this package asks of libsecp256k1, imported in one place.

The modules that delegate to the bindings import none of them directly:
they import from here, so the question "are the bindings installed" is
asked once, at one import, and answered by `INSTALLED` rather than by a
`try` block in each of them, which could drift apart. `ENABLED` is that
answer with `ECC_NO_LIBSECP256K1` applied -- installed, and not
refused -- and `curves.curve` reads it into `_libsecp256k1_available`,
which is the seam every dispatch in the package consults, so an absent
binding is a dispatch that declines rather than an `ImportError` raised
before any dispatch is reached.

Two names because the seam moves and this import does not. `ENABLED` is
only the state `curves.curve` starts in, and `set_libsecp256k1_serving`
may have moved it since; `INSTALLED` is settled here and stays, so it is
what that function reads to refuse `serving=True` where there is nothing
to serve, and what the suite skips its `bindings` marker on. The
difference is this module's and the seam's, not a caller's:
`curves.is_libsecp256k1_serving` publishes one answer -- whether the next
call goes to libsecp256k1 or to the Python arithmetic -- which is the
only difference a caller can act on.

ARCHITECTURE.md says which layer this module sits in and what it imports of
the package. What it imports from the bindings is the whole of the surface
this package uses, so this file is also the answer to "what does this
package need these bindings for", which no reader has to assemble from the
delegating modules' own imports.

The names are re-exported under the bindings' own spelling and the caller
aliases them as it always did: a caller holding `keys` and reaching
through it, and a caller naming `pubkey_sum` directly, both keep the call
they had. Neither shape costs an attribute lookup it did not cost before,
which matters where `curves.curve` counts tenths of a microsecond.

With the bindings absent every name here is None. Nothing may call one:
`_libsecp256k1_serves` is False in that configuration, and it is the
predicate in front of every delegation -- which is a rule about the
package rather than about this file, and is what `tests/no_bindings_test.py`
checks by importing this package with the bindings out of reach.

Absent and installed-but-missing-a-name are different failures, and only the
first one is this fallback (btclib-org/ecc#25). `btclib_secp256k1`
itself failing to import is `ModuleNotFoundError` with its `name` naming
the top-level package -- nothing else is. A name this module asks for that
an installed release does not have raises a plain `ImportError`
instead (the package is found; the attribute inside it is not), or a
`ModuleNotFoundError` naming a submodule rather than the top-level package
(an old package missing a whole submodule this floor needs). Reading
either of those as "absent" is the defect: it is what let
`btclib-secp256k1` 0.8.0.6, which has no `btclib_secp256k1.ecdh.shared_point`,
answer `INSTALLED = False` instead of raising. So those two raise, which is
a loud failure at import time rather than a silent, slower fallback nobody
is told about.

What they raise is an `ImportError` that says what to do about it, chained
from the one the import system raised (btclib-org/ecc#56): the
installed `btclib-secp256k1` version, the floor this package declares for it,
and the two ways to a release that meets it. The floor is read back from this
distribution's own metadata, where `pyproject.toml`'s `secp256k1` extra put
it, so no second copy of it is kept here to drift; a source tree with no
metadata beside it is told to look in the extra. Only an `ImportError` naming
`btclib_secp256k1` or one of its submodules is taken for a bindings mismatch:
a dependency of the bindings that is missing, or a shared library that will
not load, propagates as it was raised.
"""

from __future__ import annotations

import os
import re
from hashlib import sha256
from importlib import metadata

from ecc import name as _distribution
from ecc.exceptions import EccRuntimeError

# the environment variable that refuses the bindings without uninstalling
# them, read once and here, when this module is first imported. `import
# ecc` alone does not import it, the root importing lazily; the first
# import of `ecc.curves`, of `ecc.ecc` or of a module under them does, so a
# caller settling the variable after that has settled it after this module
# answered. The package's name as its prefix, and "set to ask for it": an
# empty value is not set, so `ECC_NO_LIBSECP256K1=` leaves them
# serving
NO_LIBSECP256K1 = "ECC_NO_LIBSECP256K1"

__all__ = [
    "ENABLED",
    "INSTALLED",
    "NO_LIBSECP256K1",
    "PubkeyTweakChain",
    "dsa",
    "ellswift",
    "ffi",
    "keys",
    "musig",
    "pubkey_from_prvkey",
    "pubkey_sum",
    "pubkey_tweak_add",
    "pubkey_tweak_mul_sum",
    "recovery",
    "shared_point",
    "ssa",
    "xonly_prvkey_tweak_add",
    "xonly_pubkey_verify",
    "xonly_to_pubkey",
    "xonly_tweak_add",
]

_BINDINGS_MODULE = "btclib_secp256k1"
_BINDINGS_DISTRIBUTION = "btclib-secp256k1"


def _floor() -> str | None:
    """Return the specifier the `secp256k1` extra puts on the bindings.

    Read from this distribution's own metadata, which is where
    `pyproject.toml` declares it, and `None` where there is no metadata to
    read: a source tree that was never installed, or an installed one whose
    `Requires-Dist` no longer lists the extra.
    """
    try:
        requirements = metadata.requires(_distribution)
    except metadata.PackageNotFoundError:
        return None
    for requirement in requirements or ():
        head, _, marker = requirement.partition(";")
        if not re.search(r"""extra\s*==\s*["']secp256k1["']""", marker):
            continue
        name = re.match(r"[A-Za-z0-9._-]+", head.strip())
        if name is None:
            continue
        if re.sub(r"[-_.]+", "-", name.group()).lower() != _BINDINGS_DISTRIBUTION:
            continue
        specifier = head.strip()[name.end() :].strip()
        return specifier or None
    return None


def _mismatch(exc: ImportError) -> ImportError | None:
    """Return the error to raise for a bindings mismatch, `None` for any other.

    A mismatch is an `ImportError` that names the bindings or one of their
    submodules: the package was found, and something this module asks of it
    was not there. Anything else -- a dependency of the bindings that is
    missing, a shared library that will not load -- is not this module's to
    reword, and the caller re-raises it as it came.
    """
    if exc.name != _BINDINGS_MODULE and not (exc.name or "").startswith(
        _BINDINGS_MODULE + "."
    ):
        return None
    try:
        installed = f"version {metadata.version(_BINDINGS_DISTRIBUTION)}"
    except metadata.PackageNotFoundError:
        installed = "a version it could not read"
    floor = _floor()
    required = (
        f"{_BINDINGS_DISTRIBUTION}{floor}"
        if floor
        else f"the release the `secp256k1` extra of {_distribution} names"
    )
    return ImportError(
        f"{_BINDINGS_DISTRIBUTION} is installed, {installed}, but it lacks what "
        f"{_distribution} imports from it ({exc}); {_distribution} requires {required}. "
        f"Upgrade it with `pip install --upgrade {_BINDINGS_DISTRIBUTION}` or "
        f"install `{_distribution}[secp256k1]`",
        name=exc.name,
    )


try:
    # `ffi` is the one object here that is not a wrapped call: issue
    # btclib-org/btclib#1009 is why it is needed at all -- `ecc.ecc.dsa.Signer`
    # builds its own `unsigned char[32]` with it, to hold a private key in
    # memory this package can overwrite, the way `ssa.Signer` already can
    # through the keypair `ssa` itself builds. Nothing else here needs it,
    # `dsa.sign` and every other wrapped call taking that buffer as the `prvkey`
    # a caller may already hold (btclib-org/btclib-secp256k1#253)
    from btclib_secp256k1 import (
        dsa,
        ellswift,
        ffi,
        keys,
        musig,
        recovery,
        ssa,
    )
    from btclib_secp256k1.ecdh import shared_point
    from btclib_secp256k1.keys import (
        PubkeyTweakChain,
        pubkey_from_prvkey,
        pubkey_sum,
        pubkey_tweak_add,
        pubkey_tweak_mul_sum,
    )
    from btclib_secp256k1.xonly import prvkey_tweak_add as xonly_prvkey_tweak_add
    from btclib_secp256k1.xonly import pubkey_verify as xonly_pubkey_verify
    from btclib_secp256k1.xonly import to_pubkey as xonly_to_pubkey
    from btclib_secp256k1.xonly import tweak_add as xonly_tweak_add

    INSTALLED = True
# issue btclib-org/btclib#1002 measured this branch rather than assuming it
# stays transitional: `test.yml`'s `no-bindings` job executes it every run, and
# `coverage-union` combines that run's data with the `coverage` job's. The
# combined report is 100% with this pragma removed -- so the branch is reached
# and is not dead code -- and the pragma still belongs here regardless, because
# `coverage-union` is a second gate beside the `coverage` job's, not instead of
# it: that job's own report, `pytest --cov` on this configuration alone, has
# bindings installed by construction, a `ModuleNotFoundError` only reachable by
# actually removing them, and a subprocess that does
# (`tests/no_bindings_test.py`) whose coverage that job does not collect. So
# this branch is a structural miss in that report regardless of the union, and
# removing the pragma would fail the one gate this issue chose to leave
# unchanged
except (
    ImportError
) as exc:  # pragma: no cover -- only a child interpreter or no-bindings reaches this
    # `exc.name` is the top-level package's own name, on a
    # `ModuleNotFoundError`, only when the import system never found it at
    # all. A submodule of an installed package failing to import names that
    # submodule instead (`btclib_secp256k1.ecdh`, say), and a name missing
    # from a module that *was* found is a plain `ImportError`. Either of
    # those is an installed package too old for what this module asks of it
    # (btclib-org/ecc#25), and the caller is told so and what to do
    # (btclib-org/ecc#56) rather than silently handed the slower
    # Python arithmetic
    if not (isinstance(exc, ModuleNotFoundError) and exc.name == _BINDINGS_MODULE):
        mismatch = _mismatch(exc)
        if mismatch is None:
            raise
        raise mismatch from exc
    # None and not a callable that raises: what would raise is never
    # called, so the object would be a second thing to keep true. The
    # ignore is on the assignment and not on the module: every other
    # name here keeps the type the try branch gave it
    dsa = ellswift = ffi = keys = musig = recovery = ssa = None  # type: ignore[assignment]
    shared_point = None  # type: ignore[assignment]
    # a class rather than a function, so mypy calls it an assignment to
    # a type and wants the second code as well
    PubkeyTweakChain = None  # type: ignore[misc, assignment]
    pubkey_from_prvkey = pubkey_sum = None  # type: ignore[assignment]
    pubkey_tweak_add = pubkey_tweak_mul_sum = None  # type: ignore[assignment]
    xonly_pubkey_verify = xonly_to_pubkey = None  # type: ignore[assignment]
    xonly_prvkey_tweak_add = xonly_tweak_add = None  # type: ignore[assignment]

    INSTALLED = False

# installed and not refused, which is one state and not two: a caller
# asking whether the bindings serve has no use for the difference, and
# `curves.curve` starts its seam from this
ENABLED = INSTALLED and not os.environ.get(NO_LIBSECP256K1)


def _wrong_bindings(what: str, *, setter: bool) -> EccRuntimeError:
    """Return the error for a wrong answer of the bindings.

    At import the variable is the way out; from the setter it is already
    set, and not asking for the bindings is.
    """
    pure = "keep `serving=False`" if setter else f"set {NO_LIBSECP256K1}"
    return EccRuntimeError(
        f"the libsecp256k1 bindings {what}; ecc cannot use them. "
        f"Reinstall them with `pip install --force-reinstall --no-cache-dir "
        f"{_BINDINGS_DISTRIBUTION}`, or {pure} to use the pure Python arithmetic"
    )


def _check_bindings(*, setter: bool) -> None:
    """Raise unless the bindings answer fixed vectors correctly.

    A misbuilt or mismatched wheel could derive keys or verify signatures
    wrongly with no error, so the bindings, when first selected, are asked a
    public key, one ECDSA verification and its refusal over another message,
    and one BIP340 verification. The answers are published, not taken from
    the bindings. A `raise`, not an `assert`, so
    that `python -O` keeps it.
    """
    # the public key of the private key 1 is the generator, SEC 2 section 2.4.1
    g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    if pubkey_from_prvkey(1, True).hex() != g:
        raise _wrong_bindings("derive a wrong public key", setter=setter)

    # the first valid vector of the first group of Wycheproof 0.9rc5,
    # tests/schemes/_data/ecdsa_secp256k1_sha256_bitcoin_test.json, with its key
    # compressed and its signature as r || s, as
    # `dsa.verify` passes it: `compact=True, normalize=True`
    pub_key = bytes.fromhex(
        "03b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
    )
    sig = bytes.fromhex(
        "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        "6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"
    )
    msg_hash = sha256(bytes.fromhex("313233343030")).digest()
    if not dsa.verify(msg_hash, pub_key, sig, normalize=True, compact=True):
        raise _wrong_bindings("do not verify a known ECDSA signature", setter=setter)
    if dsa.verify(
        sha256(b"another message").digest(), pub_key, sig, normalize=True, compact=True
    ):
        raise _wrong_bindings(
            "verify a known ECDSA signature over another message", setter=setter
        )

    # BIP340 test vector 0, tests/schemes/_data/bip340_test_vectors.csv
    x_only = bytes.fromhex(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    )
    sig = bytes.fromhex(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )
    if not ssa.verify(bytes(32), x_only, sig):
        raise _wrong_bindings("do not verify a known BIP340 signature", setter=setter)


_checked = False


def _check_once(*, setter: bool) -> None:
    """Run `_check_bindings` unless it has already passed."""
    global _checked  # noqa: PLW0603
    if not _checked:
        _check_bindings(setter=setter)
        _checked = True


# once, when the bindings are first selected: here, or in
# `curves.curve.set_libsecp256k1_serving`
if ENABLED:
    _check_once(setter=False)
