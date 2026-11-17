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

A class carrying a field hands every constructor argument to
`BaseException.__init__` and composes its message in `__str__`, which
is what `subprocess.CalledProcessError` and `UnicodeDecodeError` do, and
what makes it picklable: `BaseException.__reduce__` returns `(cls,
self.args)`, so a class whose `args` is the composed message alone is
rebuilt by calling it with one argument, and one argument is not what it
takes. That is a TypeError out of `pickle`, out of `copy.copy` and out
of `copy.deepcopy` -- and out of a `ProcessPoolExecutor`, which cannot
send the exception back and reports a broken pool instead of the failure
the worker died of.

The classes from `HostSeckeyError` on are `ecc.chilldkg`'s, under the
names BIP-FROST-DKG's reference gives them. Its vectors name the class
each error case raises, and which participant it blames.
"""

from __future__ import annotations

from typing_extensions import override

__all__ = [
    "BorromeanRingError",
    "DuplicateHostPubkeyError",
    "EccException",
    "EccRuntimeError",
    "EccTypeError",
    "EccValueError",
    "FaultyCoordinatorError",
    "FaultyParticipantError",
    "FaultyParticipantOrCoordinatorError",
    "HostSeckeyError",
    "InvalidContributionError",
    "InvalidHostPubkeyError",
    "InvalidRecoveryAckError",
    "ProtocolError",
    "RandomnessError",
    "RecoveryDataError",
    "SessionParamsError",
    "ThresholdOrCountError",
    "UnknownFaultyParticipantOrCoordinatorError",
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


class HostSeckeyError(EccValueError):
    """A host secret key not in 1..n-1, or not the session's.

    Not the session's: its host public key is in no position of the
    session's parameters, or is not in the position the state passed
    with it holds.
    """


class SessionParamsError(EccValueError):
    """A ChillDKG session's parameters that no session can run on.

    Each subclass says what is wrong with them.
    """


class InvalidHostPubkeyError(SessionParamsError):
    """The host public key of `participant_id` is not a compressed point."""

    def __init__(self, participant_id: int) -> None:
        self.participant_id = participant_id
        super().__init__(participant_id)

    @override
    def __str__(self) -> str:
        return f"invalid host public key of participant {self.participant_id}"


class DuplicateHostPubkeyError(SessionParamsError):
    """Participant `participant_id1` and a later `participant_id2` share a key.

    Honest key generation repeats a key with negligible probability, so
    at least one of the two is faulty, where the keys reached the caller
    unaltered.
    """

    def __init__(self, participant_id1: int, participant_id2: int) -> None:
        self.participant_id1 = participant_id1
        self.participant_id2 = participant_id2
        super().__init__(participant_id1, participant_id2)

    @override
    def __str__(self) -> str:
        return (
            f"participants {self.participant_id1} and {self.participant_id2}"
            " have the same host public key"
        )


class ThresholdOrCountError(SessionParamsError):
    """A threshold and a count of host keys out of the bounds of a session.

    `ecc.chilldkg.SessionParams` states the bounds.
    """


class RandomnessError(EccValueError):
    """Randomness of 32 zero bytes, which a broken generator answers."""


class RecoveryDataError(EccValueError):
    """Recovery data that does not parse, or does not check out."""


class ProtocolError(EccRuntimeError):
    """A ChillDKG message that does not check out, and whom it accuses.

    Each subclass says whom: a participant, the coordinator, or one of
    the two. An EccRuntimeError for `InvalidContributionError`'s reason: a
    party misbehaving is not the caller's mistake, and an
    `except ValueError` must not swallow it.
    """


class FaultyParticipantError(ProtocolError):
    """The coordinator found participant `participant_id` faulty.

    Where the messages reached the coordinator unaltered, that
    participant deviated from the protocol.
    """

    def __init__(self, participant_id: int, message: str) -> None:
        self.participant_id = participant_id
        super().__init__(participant_id, message)

    @override
    def __str__(self) -> str:
        return f"participant {self.participant_id}: {self.args[1]}"


class FaultyParticipantOrCoordinatorError(ProtocolError):
    """A participant found `participant_id`, or the coordinator, faulty.

    It is no proof against that participant: a coordinator deviating from
    the protocol can make an honest one look faulty.
    """

    def __init__(self, participant_id: int, message: str) -> None:
        self.participant_id = participant_id
        super().__init__(participant_id, message)

    @override
    def __str__(self) -> str:
        return f"participant {self.participant_id}: {self.args[1]}"


class FaultyCoordinatorError(ProtocolError):
    """A participant found the coordinator faulty."""


class UnknownFaultyParticipantOrCoordinatorError(ProtocolError):
    """A participant's secret share is wrong, and the messages do not say whose.

    `ecc.chilldkg.participant_investigate`, given the coordinator's
    investigation message, names a participant or the coordinator.
    """


class InvalidRecoveryAckError(FaultyParticipantError):
    """The recovery acknowledgment of participant `participant_id` is invalid.

    The session itself succeeded: what is not confirmed is that this
    participant holds the recovery data.
    """
