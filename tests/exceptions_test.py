# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `ecc.exceptions`, and for what an exception carries.

The classes with nothing added to their base need no test of their own:
what they are is the base, and every module raising one asserts the
message it raised. The classes carrying a field are tested here, and
specifically that a field survives leaving the process it was raised in,
which is the case the field exists for and the one nothing else in the
suite exercises: pytest-xdist sends a report as text, so no exception
object crosses between workers.
"""

from __future__ import annotations

import copy
import pickle
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import pytest

from ecc import exceptions
from ecc.exceptions import (
    BorromeanRingError,
    DuplicateHostPubkeyError,
    EccException,
    EccRuntimeError,
    EccTypeError,
    EccValueError,
    FaultyParticipantError,
    FaultyParticipantOrCoordinatorError,
    InvalidContributionError,
    InvalidHostPubkeyError,
    InvalidRecoveryAckError,
)

# the exception, the `args` it is expected to carry, its message, and the
# fields a caller reads. Constructed here and shared by every test below:
# none of them mutates one, and an exception that a test could mutate is
# an exception this module would have to say more about
CASES = [
    pytest.param(
        InvalidContributionError(2, "psig"),
        (2, "psig"),
        "invalid psig from signer 2",
        {"signer": 2, "contrib": "psig"},
        id="InvalidContributionError",
    ),
    pytest.param(
        InvalidContributionError(None, "aggnonce"),
        (None, "aggnonce"),
        "invalid aggnonce from the aggregator",
        {"signer": None, "contrib": "aggnonce"},
        id="InvalidContributionError-aggregator",
    ),
    pytest.param(
        BorromeanRingError("zero e-value", 1, 3),
        ("zero e-value", 1, 3),
        "zero e-value (ring 1, position 3)",
        {"ring": 1, "position": 3},
        id="BorromeanRingError",
    ),
    pytest.param(
        BorromeanRingError("e0 does not close", None, None),
        ("e0 does not close", None, None),
        "e0 does not close",
        {"ring": None, "position": None},
        id="BorromeanRingError-whole-signature",
    ),
    pytest.param(
        InvalidHostPubkeyError(3),
        (3,),
        "invalid host public key of participant 3",
        {"participant_id": 3},
        id="InvalidHostPubkeyError",
    ),
    pytest.param(
        DuplicateHostPubkeyError(0, 2),
        (0, 2),
        "participants 0 and 2 have the same host public key",
        {"participant_id1": 0, "participant_id2": 2},
        id="DuplicateHostPubkeyError",
    ),
    pytest.param(
        FaultyParticipantError(1, "invalid VSS commitment"),
        (1, "invalid VSS commitment"),
        "participant 1: invalid VSS commitment",
        {"participant_id": 1},
        id="FaultyParticipantError",
    ),
    pytest.param(
        FaultyParticipantOrCoordinatorError(2, "invalid public nonce"),
        (2, "invalid public nonce"),
        "participant 2: invalid public nonce",
        {"participant_id": 2},
        id="FaultyParticipantOrCoordinatorError",
    ),
    pytest.param(
        InvalidRecoveryAckError(0, "invalid acknowledgment"),
        (0, "invalid acknowledgment"),
        "participant 0: invalid acknowledgment",
        {"participant_id": 0},
        id="InvalidRecoveryAckError",
    ),
]


def _assert_same(back: BaseException, error: BaseException, fields: Any) -> None:
    assert type(back) is type(error)
    assert str(back) == str(error)
    assert back.args == error.args
    for name, value in fields.items():
        assert getattr(back, name) == value


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_says_what_it_carries(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """`args` is the constructor's arguments and `str` is the message."""
    assert error.args == args
    assert str(error) == message
    for name, value in fields.items():
        assert getattr(error, name) == value
    # `repr` names the fields with the message, which is the visible half
    # of `args` holding them: rebuilding the class from what it prints is
    # what a one-tuple of the composed message could not offer
    # (a one-tuple is printed without its trailing comma)
    assert repr(error) == f"{type(error).__name__}({', '.join(map(repr, args))})"


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_survives_pickle(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """The class, the message and every field come back from `pickle`."""
    back = pickle.loads(pickle.dumps(error))  # noqa: S301
    _assert_same(back, error, fields)
    assert back.args == args
    assert str(back) == message


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_a_field_carrying_exception_survives_copy(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """`copy` and `deepcopy` need no process, and fail the same way."""
    for back in (copy.copy(error), copy.deepcopy(error)):
        _assert_same(back, error, fields)
        assert back.args == args
        assert str(back) == message


@pytest.mark.parametrize("error, args, message, fields", CASES)
def test_the_message_is_composed_once(
    error: BaseException, args: tuple[Any, ...], message: str, fields: Any
) -> None:
    """A round trip of a round trip still says what one raise said.

    The trap this pins is composing in `__init__` from an argument that is
    itself a composed message: the message grows a second `(ring 1,
    position 3)` per round trip, so a single one shows it and a second
    makes what is accumulating unmistakable.
    """
    back: BaseException = error
    for _ in range(2):
        back = pickle.loads(pickle.dumps(back))  # noqa: S301
        assert str(back) == message
    assert back.args == args
    _assert_same(back, error, fields)


def test_an_exception_adding_nothing_round_trips_too() -> None:
    """The control: a class taking a message alone round-trips as it is."""
    error = EccValueError("bad")
    for back in (pickle.loads(pickle.dumps(error)), copy.copy(error)):  # noqa: S301
        assert type(back) is type(error)
        assert str(back) == str(error)
        assert back.args == error.args


def test_every_exception_of_the_module_is_one_base_to_catch() -> None:
    """`except EccException` tells this package's failure apart.

    The classes are found rather than listed, so one added to the module
    is one this covers: a new exception that forgot the base would be a
    failure a caller catching it could not catch, and nothing else in the
    suite would say so.
    """
    classes = [
        getattr(exceptions, name)
        for name in exceptions.__all__
        if isinstance(getattr(exceptions, name), type)
    ]
    assert len(classes) == len(exceptions.__all__), "a non-class in __all__"
    uncatchable = [cls.__name__ for cls in classes if not issubclass(cls, EccException)]
    assert not uncatchable


@pytest.mark.parametrize(
    "cls, builtin",
    [
        (EccValueError, ValueError),
        (EccTypeError, TypeError),
        (EccRuntimeError, RuntimeError),
    ],
    ids=["ValueError", "TypeError", "RuntimeError"],
)
def test_the_base_is_inherited_beside_the_builtin_not_instead_of_it(
    cls: type[EccException], builtin: type[Exception]
) -> None:
    """The half that keeps every `except ValueError` already written working.

    requests, sqlalchemy and httpx derive their bases from `Exception`
    alone, so an `except ValueError` does not catch their value errors.
    Asserted on the subclasses too, since they are what modules raise:
    inheriting the base transitively must not cost them the built-in.
    """
    assert issubclass(cls, builtin)
    assert issubclass(cls, EccException)
    lost = [
        sub.__name__
        for sub in cls.__subclasses__()
        if not (issubclass(sub, builtin) and issubclass(sub, EccException))
    ]
    assert not lost


def test_the_base_carries_no_behaviour_of_its_own() -> None:
    """It adds a name to catch and nothing else, which is the whole design.

    A base that composed a message, or took a field, would be a second
    thing to keep true in every subclass -- and the subclasses that do
    carry a field compose in `__str__` for the pickling reason the module
    docstring gives, which a base doing its own would undo.
    """
    assert EccException.__init__ is Exception.__init__
    assert EccException.__str__ is Exception.__str__
    error = EccValueError("bad")
    assert str(error) == "bad"
    assert error.args == ("bad",)
    assert type(pickle.loads(pickle.dumps(error))) is EccValueError  # noqa: S301


def _raise_invalid_contribution() -> None:
    raise InvalidContributionError(2, "psig")


def test_a_field_carrying_exception_crosses_a_process_boundary() -> None:
    """What the field is for: a party to accuse, named across processes.

    A worker that cannot send its exception back does not merely lose the
    diagnosis -- `ProcessPoolExecutor` reports a `BrokenProcessPool`
    instead of the failure the worker died of. The same raise in this
    process is the control: the two have to agree on the class, the
    message and the signer.
    """
    with pytest.raises(InvalidContributionError) as local:
        _raise_invalid_contribution()

    with (
        ProcessPoolExecutor(max_workers=1) as pool,
        pytest.raises(InvalidContributionError) as remote,
    ):
        pool.submit(_raise_invalid_contribution).result()

    assert type(remote.value) is type(local.value)
    assert str(remote.value) == str(local.value)
    assert remote.value.signer == local.value.signer == 2
