# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Exception classes.

These exist only to tell an exception raised by ecc from one
raised by any other code: each derives from the built-in that says what
kind of failure it is, and adds nothing to it.

`EccException` is what makes that telling apart a single
`except` rather than a tuple of three a caller has to keep in step with
this hierarchy. It is inherited *beside* the built-in and not instead of
it, which is the half that matters: `EccValueError` is a
`ValueError`, so code catching the built-in catches it, and
`json.JSONDecodeError` is the standard library doing the same.

It is caught and never raised: every raise below is one of the three,
and which one answers a question the base cannot carry -- whether the
value was wrong, the type was, or neither was and a check failed anyway.
A caller with something to do about that difference names the specific
class; `except EccException` is for the caller who only needs
to know it came from here.

The two classes carrying a field hand every constructor argument to
`BaseException.__init__` and compose their message in `__str__`, which
is what `subprocess.CalledProcessError` and `UnicodeDecodeError` do, and
what makes them picklable: `BaseException.__reduce__` returns `(cls,
self.args)`, so a class whose `args` is the composed message alone is
rebuilt by calling it with one argument, and one argument is not what it
takes. That is a TypeError out of `pickle`, out of `copy.copy` and out
of `copy.deepcopy` -- and out of a `ProcessPoolExecutor`, which cannot
send the exception back and reports a broken pool instead of the failure
the worker died of.
"""

from __future__ import annotations

from typing_extensions import override

__all__ = [
    "BorromeanRingError",
    "EccException",
    "EccRuntimeError",
    "EccTypeError",
    "EccValueError",
    "InvalidContributionError",
]


class EccException(Exception):  # noqa: N818 -- a kind, like Exception itself, not a leaf raised
    """Anything ecc raised, whatever kind of failure it is.

    The one name to catch for a caller who handles the standard library's
    exceptions anyway and needs to know which came from here. Never
    raised: the three below it are, and each says which kind of failure
    it was.
    """


class EccValueError(EccException, ValueError):
    """A value no valid input could carry; the package's usual refusal."""


class EccTypeError(EccException, TypeError):
    """An input of a type no conversion accepts: a caller error."""


class EccRuntimeError(EccException, RuntimeError):
    """A check that failed on valid inputs, e.g. a failed verification."""


class InvalidContributionError(EccRuntimeError):
    """A party to an interactive protocol sent a value that does not check out.

    Which party, and which of its contributions: `signer` is the index
    in the list the caller passed, None for the aggregator -- who has no
    index, having no key -- and `contrib` names what was wrong, one of
    "pubkey", "pubnonce", "aggnonce", "aggothernonce", "psig" or
    "adaptor". That is the whole point of the class: a multi-round
    protocol that merely fails leaves every participant a suspect, and
    the answer a caller needs is who to hold accountable and to exclude
    from the next attempt.

    An EccRuntimeError and not an EccValueError, which is
    the other obvious base and the one BIP327 keeps separate: its reference
    implementation raises ValueError for an argument that breaks a precondition
    -- the caller's own mistake, a 33-byte tweak -- and this for a peer
    misbehaving, and the MuSig2 test vectors distinguish the two case by case.
    Sharing a base would put the two beyond telling apart by `except`, and would
    let every `except ValueError` in the package swallow an accusation.
    """

    def __init__(self, signer: int | None, contrib: str) -> None:
        self.signer = signer
        self.contrib = contrib
        super().__init__(signer, contrib)

    @override
    def __str__(self) -> str:
        who = "the aggregator" if self.signer is None else f"signer {self.signer}"
        return f"invalid {self.contrib} from {who}"


class BorromeanRingError(EccRuntimeError):
    """A borromean ring signature check failed, and where names it.

    `ring` is the index into `pubk_rings` and `position` the index
    within that ring: an e-value landing on zero, and the point at
    infinity its one-in-n neighbour lands a ring's nonce or its `r` on
    instead, each happen at one ring and one position, and
    `ecc.borromean.sign` and `assert_as_valid` already have both
    in hand at every one of their raises. Naming them is what tells a
    caller building on this primitive which key rejected the signature
    rather than only that the whole thing did.

    Both are None for the one failure with no ring of its own: the
    final `e0` not matching what every ring converges on is a property
    of the whole signature, not of any single ring in it.

    An EccRuntimeError and not `InvalidContributionError`: that class
    names a party to an interactive multi-round protocol -- MuSig2 --
    and which of its contributions was wrong, where a borromean ring
    signature is not interactive and has no parties to accuse, only
    positions in a signature that either close their ring or do not.
    An EccRuntimeError still, so code catching that keeps catching
    this, as `verify` already does.
    """

    def __init__(self, message: str, ring: int | None, position: int | None) -> None:
        self.ring = ring
        self.position = position
        super().__init__(message, ring, position)

    @override
    def __str__(self) -> str:
        if self.ring is None:
            return str(self.args[0])
        return f"{self.args[0]} (ring {self.ring}, position {self.position})"
