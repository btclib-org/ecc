# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the bool contract, over what only a fixture can reach.

CONTRIBUTING.md's "Every public function validates its inputs" states
rules about a function that answers a `bool`, and
`input_validation_test.py` drives them automatically -- over the
functions whose every required parameter is a library input type. That
leaves out the ones this file is about, and they are the ones the rules
were argued over: a signature verification takes a valid message, key and
signature, and a `Sig | Octets` that no vocabulary of wrong values can
build.

So the calls here are hand-written, which is issue btclib-org/btclib#776's own
answer to what its walk cannot reach: "a hand-written table of name, and the
shortest call that reaches the validator". Each case names a function, a call of
it that answers True, a wrong value for each position worth driving, and a
structurally invalid one for each position where the two diverge. Three rules,
asked one position at a time with the others left valid:

- a **wrong type** leaves as an `EccTypeError`. A bool is an answer
  about a value, so a type the signature does not declare is not
  something it answers about.
- a **wrong value** of a declared type is `False`. That is what the bool
  is for, and what a caller filtering signatures off the wire relies on.
- a value of a declared type whose size or encoding makes it **structurally
  invalid** -- one no valid input could ever carry, as opposed to one that is
  merely not authentic -- is an `EccValueError`. A verification is
  not the question that value answers, so it is refused rather than read as a
  forged signature. What decides is whether the position declares a size:
  `dsa.verify_`'s digest does and `dsa.verify`'s message does not, so the same
  wrong octets are a refusal in one case and `False` in the other.

Issue btclib-org/btclib#814 settled the second against issue
btclib-org/btclib#745's "total over everything it is handed", and this is
where the decision is held to. Issue btclib-org/btclib#2170 is where the
third was carved out of the second, for the `ecc.ecc` verifications: a
signature, a key or an opening whose size or encoding makes it impossible
is refused there.

There is no list of exceptions: a finding this file makes is a red test
above, to be fixed or to be given a reason of its own.

What no case here drives, and why: `musig2`'s and `frost`'s
`partial_sig_verify` and `partial_sig_verify_` want a session and a
signing round, `dsa`'s and `ssa`'s `anti_exfil_host_verify` a
host-device exchange, and `borromean.verify` and `rangeproof.verify` a
ring signature or a proof built for them. Those are driven by the tests
of their own modules, against fixtures those modules build.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from ecc.alias import INF
from ecc.curves import bytes_from_point, mult, secp256k1
from ecc.ecc import dleq, dsa, pedersen, ssa, ssa_halfagg
from ecc.hashes import reduce_to_hlen

_Q = 12
_PUB = bytes_from_point(mult(_Q))
_X_ONLY = _PUB[1:]
_MSG = b"Satoshi Nakamoto"
_MSG_HASH = reduce_to_hlen(_MSG)
_DSA_SIG = dsa.sign(_MSG, _Q)
_SSA_SIG = ssa.sign(_MSG, _Q)
# a DLEQ triple: A = a*G and C = a*B, so the proof holds for (A, B, C)
_DLEQ_B = bytes_from_point(mult(2))
_DLEQ_C = bytes_from_point(mult(2 * _Q))
_DLEQ_PROOF = dleq.generate_proof(_Q, _DLEQ_B)
# the BIP458 aggregate of one signature over a 32-byte message
_HALFAGG_PAIRS = [(_X_ONLY, _MSG_HASH)]
_HALFAGG_SIG = ssa_halfagg.aggregate(
    [(_X_ONLY, _MSG_HASH, ssa.sign_(_MSG_HASH, _Q).serialize())]
)
# rG + vH for the very (r, v) its case opens it with
_GEN = pedersen.second_generator()
_COMMITMENT = pedersen.commit(1, 2, _GEN)

# a value of a declared type that no valid input carries. The same split
# `input_validation_test.py` makes, spelled per position because a
# hand-written call knows which alias each of its arguments is
_WRONG_OCTETS_VALUE = "not hex at all"
_WRONG_INTEGER_VALUE = "not a number"
_WRONG_KEY_VALUE = "not a key"

# a value of no type any of these positions declares
_WRONG_TYPES = (None, 1.5)


@dataclass(frozen=True)
class _Case:
    """A bool function, a call that answers True, and what to drive."""

    label: str
    function: Any
    args: tuple[Any, ...]
    # position -> a wrong value of the type that position declares, one
    # a valid input could carry -- False is the answer
    wrong_values: dict[int, Any]
    # position -> a value of the declared type whose size or encoding
    # makes the question unanswerable -- a raise is the answer (issue
    # 2170). Empty for every case this issue leaves alone
    structurally_invalid_values: dict[int, Any] = field(default_factory=dict)


_CASES = (
    _Case(
        "dsa.verify",
        dsa.verify,
        (_MSG, _PUB, _DSA_SIG),
        {0: _WRONG_OCTETS_VALUE, 2: _WRONG_OCTETS_VALUE},
        {1: _WRONG_KEY_VALUE},
    ),
    _Case(
        "dsa.verify_",
        dsa.verify_,
        (_MSG_HASH, _PUB, _DSA_SIG),
        # position 0 is a digest here and a message in `dsa.verify`
        # above, which is why the two cases differ in one position: a
        # message has no declared size to miss
        {2: _WRONG_OCTETS_VALUE},
        {0: _WRONG_OCTETS_VALUE, 1: _WRONG_KEY_VALUE},
    ),
    _Case(
        "ssa.verify",
        ssa.verify,
        (_MSG, _X_ONLY, _SSA_SIG),
        {0: _WRONG_OCTETS_VALUE},
        {1: _WRONG_KEY_VALUE, 2: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "ssa.verify_",
        ssa.verify_,
        (_MSG_HASH, _X_ONLY, _SSA_SIG),
        {0: _WRONG_OCTETS_VALUE},
        {1: _WRONG_KEY_VALUE, 2: _WRONG_OCTETS_VALUE},
    ),
    _Case(
        "ssa.batch_verify",
        ssa.batch_verify,
        ([_MSG], [_X_ONLY], [_SSA_SIG]),
        # a sequence whose element is the wrong value, the sequence being
        # what the parameter declares
        {0: [_WRONG_OCTETS_VALUE]},
        {1: [_WRONG_KEY_VALUE]},
    ),
    _Case(
        "pedersen.verify",
        pedersen.verify,
        (1, 2, _COMMITMENT, _GEN),
        # every value of an int is one, so the wrong value here is a
        # different number rather than a malformed one, and a commitment
        # those two do not open. The wrong generator is a point of the
        # curve like any other, and a commitment made under one does not
        # open under another
        {
            0: 999,
            1: 999,
            2: pedersen.commit(9, 9, _GEN),
            3: mult(2, _GEN, secp256k1),
        },
        # an `Integer` spelled as text that is no number at all: the
        # commitment is read for its type only, `assert_as_valid`
        # deliberately not reading its value (issue btclib-org/btclib#814)
        {0: _WRONG_INTEGER_VALUE, 1: _WRONG_INTEGER_VALUE},
    ),
    # a generator no commitment is made under is refused like an
    # unreadable r, one value per position and so one case each
    _Case(
        "pedersen.verify, generator at INF",
        pedersen.verify,
        (1, 2, _COMMITMENT, _GEN),
        {},
        {3: INF},
    ),
    _Case(
        "pedersen.verify, generator off the curve",
        pedersen.verify,
        (1, 2, _COMMITMENT, _GEN),
        {},
        {3: (1, 1)},
    ),
    _Case(
        "dleq.verify_proof",
        dleq.verify_proof,
        (_PUB, _DLEQ_B, _DLEQ_C, _DLEQ_PROOF),
        # a C that is a point of the curve like any other, and one the
        # proof does not relate to A and B: the proof simply does not
        # hold for it
        {2: _PUB},
        # BIP374's own line: its `dleq_verify_proof` opens with
        # `assert len(proof) == 64`, and its points arrive parsed
        {
            0: _WRONG_KEY_VALUE,
            1: _WRONG_KEY_VALUE,
            2: _WRONG_KEY_VALUE,
            3: _WRONG_OCTETS_VALUE,
        },
    ),
    _Case(
        "ssa_halfagg.verify",
        ssa_halfagg.verify,
        (_HALFAGG_SIG, _HALFAGG_PAIRS),
        # an aggregate of the right length whose s does not open it, and a
        # message of the right size that was not signed
        {
            0: _HALFAGG_SIG[:32] + bytes(32),
            1: [(_X_ONLY, bytes(32))],
        },
        # an aggregate that is no octets, and a key that is no 32 octets:
        # both positions declare a size
        {0: _WRONG_OCTETS_VALUE, 1: [(_WRONG_KEY_VALUE, _MSG_HASH)]},
    ),
)

_IDS = tuple(case.label for case in _CASES)


def _outcome(case: _Case, position: int, wrong: Any) -> str:
    """Return what came out: the class raised, or the answer given."""
    args = list(case.args)
    args[position] = wrong
    try:
        return f"answers {case.function(*args)!r}"
    # the class of what came out is the finding, so every one of them is
    # named rather than let out of the walk
    except Exception as e:  # noqa: BLE001
        return type(e).__name__


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_answers_true(case: _Case) -> None:
    """The fixture is valid, which is what makes False an answer below.

    Without this a case whose arguments had gone stale would pass every
    test in the file by answering False to everything.
    """
    assert case.function(*case.args) is True


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_type_error_of_the_package(case: _Case) -> None:
    """The first rule, one position at a time, the others left valid."""
    for position in range(len(case.args)):
        for wrong in _WRONG_TYPES:
            assert _outcome(case, position, wrong) == "EccTypeError"


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_value_answers_false(case: _Case) -> None:
    """The second rule: a value of a declared type is answered, not refused."""
    for position, wrong in sorted(case.wrong_values.items()):
        assert _outcome(case, position, wrong) == "answers False"


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_structurally_invalid_value_raises(case: _Case) -> None:
    """The third rule: an unanswerable question is refused.

    It is btclib-org/btclib#2170's.

    A signature or a public key whose size or encoding no valid input
    could carry is not a value the equation ever reaches, so it is an
    EccValueError rather than a False that would read as a forged
    signature. `dsa.verify`'s malformed DER stays under the second rule
    instead, `_assert_structurally_valid_`'s own docstring measuring why.
    """
    for position, wrong in sorted(case.structurally_invalid_values.items()):
        assert _outcome(case, position, wrong) == "EccValueError"
