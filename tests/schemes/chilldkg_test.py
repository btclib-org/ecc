# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `ecc.chilldkg`, against BIP-FROST-DKG's own vectors.

Every case of every JSON file of `BlockstreamResearch/bip-frost-dkg`'s
`vectors/`, vendored under `tests/schemes/_data/chilldkg/` and pinned in
`tests/_data/README.md`, is a param here, on both arms. Each file is run
as upstream's `python/tests.py` runs it: a group's own messages are
re-derived and checked first, a case's own host secret key or randomness
re-derives the state it is run on, and a pool is read by index. A test
per file holds its `totalTests` to the params it made.

An error case is checked against the exception the file names, by
`_assert_refused`: the class itself, `EccValueError` for upstream's plain
`ValueError`, each participant the file names, and the message where the
file gives one. A message the file does not give is not compared: a
refusal here says what it refuses where upstream's says nothing.

The recovery acknowledgments have no vector file, and are tested as
upstream's `test_recovery_acknowledgment` tests them.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ecc import chilldkg, exceptions, frost, ssa
from ecc.curves import bytes_from_point, mult, point_from_octets_var, secp256k1
from ecc.exceptions import (
    EccException,
    EccTypeError,
    EccValueError,
    FaultyCoordinatorError,
    FaultyParticipantOrCoordinatorError,
    HostSeckeyError,
    InvalidRecoveryAckError,
    RecoveryDataError,
    UnknownFaultyParticipantOrCoordinatorError,
)
from tests import (
    REFUSED_AUX,
    REFUSED_OCTETS,
    assert_repr_secret_free,
    both_arms,
    load,
    refused_secret,
    vector_id,
)
from tests.secret_free import assert_secret_free

_FIELDS = {"participantId", "participantId1", "participantId2"}


def _vectors(name: str) -> Any:
    """Load one of BIP-FROST-DKG's vector files."""
    return load("schemes", "_data", "chilldkg", name)


def _hex(values: list[str]) -> list[bytes]:
    return [bytes.fromhex(value) for value in values]


def _params(params: dict[str, Any]) -> chilldkg.SessionParams:
    return chilldkg.SessionParams(_hex(params["hostpubkeys"]), params["t"])


def _info_dict(info: frost.ThresholdInfo) -> dict[str, Any]:
    """Return a threshold info as the vectors write it."""
    return {
        "t": info.t,
        "threshPk": info.thresh_pk.hex().upper(),
        "pubshares": [
            None if share is None else share.hex().upper() for share in info.pub_shares
        ],
    }


def _params_dict(params: chilldkg.SessionParams) -> dict[str, Any]:
    return {
        "hostpubkeys": [key.hex().upper() for key in params.host_pub_keys],
        "t": params.t,
    }


def _snake(key: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in key)


def _assert_refused(call: Callable[[], object], expected: dict[str, Any]) -> None:
    """Assert that the call raises what an error case of the vectors names."""
    assert set(expected) <= {"type", "message"} | _FIELDS
    with pytest.raises(EccException) as refused:
        call()
    error = refused.value
    name = expected["type"]
    assert type(error) is (
        EccValueError if name == "ValueError" else getattr(exceptions, name)
    )
    for key in _FIELDS & set(expected):
        assert getattr(error, _snake(key)) == expected[key]
    if "message" in expected:
        assert error.args[-1] == expected["message"]


def _groups(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a file's groups; a file with none is one group of its own."""
    groups: list[dict[str, Any]] = data.get("testGroups", [data])
    return groups


def _cases(name: str) -> list[Any]:
    """One param per case of a file: its group, the case, valid or not."""
    return [
        pytest.param(
            group,
            case,
            kind == "validTestCases",
            id=vector_id(case["tcId"], group.get("tgId"), case.get("comment")),
        )
        for group in _groups(_vectors(name))
        for kind in ("validTestCases", "errorTestCases")
        for case in group.get(kind, [])
    ]


_FILES = [
    "coordinator_finalize_vectors.json",
    "coordinator_investigate_vectors.json",
    "coordinator_step1_vectors.json",
    "hostpubkey_gen_vectors.json",
    "params_hash_vectors.json",
    "participant_finalize_vectors.json",
    "participant_investigate_vectors.json",
    "participant_step1_vectors.json",
    "participant_step2_vectors.json",
    "recover_vectors.json",
]


def test_every_vector_file_is_run() -> None:
    """The files above are the vendored directory's, all of them."""
    directory = Path(__file__).parent / "_data" / "chilldkg"
    assert sorted(p.name for p in directory.glob("*.json")) == _FILES


@pytest.mark.parametrize("name", _FILES)
def test_every_case_of_a_file_is_a_param(name: str) -> None:
    """`totalTests` is the number of params, and each `tcId` is one of them."""
    params = _cases(name)
    assert _vectors(name)["totalTests"] == len(params)
    assert [p.values[1]["tcId"] for p in params] == list(range(1, len(params) + 1))


# --------------------------------------------------------------------
# the vectors, a test per file
# --------------------------------------------------------------------


@pytest.mark.parametrize("group, case, valid", _cases("hostpubkey_gen_vectors.json"))
@both_arms
def test_hostpubkey_gen_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`hostpubkey_gen` answers, or refuses, as the file says."""
    del group
    host_sec_key = bytes.fromhex(case["hostseckey"])
    if valid:
        expected = bytes.fromhex(case["expectedHostpubkey"])
        assert chilldkg.hostpubkey_gen(host_sec_key) == expected
    else:
        _assert_refused(
            lambda: chilldkg.hostpubkey_gen(host_sec_key), case["expectedError"]
        )


@pytest.mark.parametrize("group, case, valid", _cases("params_hash_vectors.json"))
@both_arms
def test_params_hash_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`params_hash_var` answers, or refuses, as the file says."""
    del group
    params = _params(case["params"])
    if valid:
        expected = bytes.fromhex(case["expectedParamsHash"])
        assert chilldkg.params_hash_var(params) == expected
    else:
        _assert_refused(lambda: chilldkg.params_hash_var(params), case["expectedError"])


@pytest.mark.parametrize("group, case, valid", _cases("participant_step1_vectors.json"))
@both_arms
def test_participant_step1_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`participant_step1_` answers, or refuses, as the file says."""
    del group
    host_sec_key = bytes.fromhex(case["hostseckey"])
    params = _params(case["params"])
    random = bytes.fromhex(case["random"])
    if valid:
        _, pmsg1 = chilldkg.participant_step1_(host_sec_key, params, random)
        assert pmsg1 == bytes.fromhex(case["expectedPmsg1"])
    else:
        _assert_refused(
            lambda: chilldkg.participant_step1_(host_sec_key, params, random),
            case["expectedError"],
        )


def _step1(
    group: dict[str, Any], case: dict[str, Any]
) -> tuple[bytes, chilldkg.ParticipantState1, bytes]:
    """Return the host secret key, the state and the message a case runs on.

    The group's, checked against its `pmsg1`; or, where the case has a
    host secret key or randomness of its own, the state they re-derive,
    checked against the case's `pmsg1`.
    """
    params = _params(group["params"])
    own = _own(group, case)
    host_sec_key = bytes.fromhex(case.get("hostseckey", group["hostseckey"]))
    random = bytes.fromhex(case.get("random", group["random"]))
    state1, pmsg1 = chilldkg.participant_step1_(host_sec_key, params, random)
    assert pmsg1 == bytes.fromhex(case["pmsg1"] if own else group["pmsg1"])
    return host_sec_key, state1, pmsg1


def _own(group: dict[str, Any], case: dict[str, Any]) -> bool:
    """Return True where a case's host secret key or randomness is its own."""
    return any(
        case.get(key, group[key]).upper() != group[key].upper()
        for key in ("hostseckey", "random")
    )


@pytest.mark.parametrize("group, case, valid", _cases("participant_step2_vectors.json"))
@both_arms
def test_participant_step2_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`participant_step2` answers, or refuses, as the file says.

    An error case runs on the group's state, with its own host secret key
    where it has one: the state is the one that key does not match.
    """
    aux = bytes.fromhex(case.get("auxRand", group["auxRand"]))
    cmsg1 = bytes.fromhex(case["cmsg1"])
    if valid:
        host_sec_key, state1, _ = _step1(group, case)
        _, pmsg2 = chilldkg.participant_step2(host_sec_key, state1, cmsg1, aux)
        assert pmsg2 == bytes.fromhex(case["expectedPmsg2"])
    else:
        _, state1, _ = _step1(group, {})
        host_sec_key = bytes.fromhex(case.get("hostseckey", group["hostseckey"]))
        _assert_refused(
            lambda: chilldkg.participant_step2(host_sec_key, state1, cmsg1, aux),
            case["expectedError"],
        )


@pytest.mark.parametrize(
    "group, case, valid", _cases("participant_finalize_vectors.json")
)
@both_arms
def test_participant_finalize_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`participant_finalize` answers, or refuses, as the file says."""
    own = valid and _own(group, case)
    host_sec_key, state1, _ = _step1(group, case if own else {})
    aux = bytes.fromhex(group["auxRand"])
    cmsg1 = bytes.fromhex(group["cmsg1"])
    state2, pmsg2 = chilldkg.participant_step2(host_sec_key, state1, cmsg1, aux)
    assert pmsg2 == bytes.fromhex(case["pmsg2"] if own else group["pmsg2"])
    cmsg2 = bytes.fromhex(case["cmsg2"])
    if valid:
        sec_share, info, recovery_data = chilldkg.participant_finalize(state2, cmsg2)
        output = case["expectedOutput"]
        assert sec_share == bytes.fromhex(output["secshare"])
        assert _info_dict(info) == output["thresholdInfo"]
        assert recovery_data == bytes.fromhex(output["recoveryData"])
    else:
        _assert_refused(
            lambda: chilldkg.participant_finalize(state2, cmsg2),
            case["expectedError"],
        )


@pytest.mark.parametrize(
    "group, case, valid", _cases("participant_investigate_vectors.json")
)
@both_arms
def test_participant_investigate_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`participant_investigate` refuses as the file says.

    `participant_step2` refuses the case's `cmsg1` first, naming nobody:
    that is the call the investigation follows.
    """
    assert not valid
    host_sec_key, state1, _ = _step1(group, {})
    aux = bytes.fromhex(group["auxRand"])
    cmsg1 = bytes.fromhex(group["cmsg1Pool"][case["cmsg1Index"]])
    with pytest.raises(UnknownFaultyParticipantOrCoordinatorError) as refused:
        chilldkg.participant_step2(host_sec_key, state1, cmsg1, aux)
    assert type(refused.value) is UnknownFaultyParticipantOrCoordinatorError
    cinv = bytes.fromhex(case["cinvMsg"])
    _assert_refused(
        lambda: chilldkg.participant_investigate(host_sec_key, state1, cmsg1, cinv),
        case["expectedError"],
    )


@pytest.mark.parametrize("group, case, valid", _cases("coordinator_step1_vectors.json"))
@both_arms
def test_coordinator_step1_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`coordinator_step1_var` answers, or refuses, as the file says."""
    pmsgs1 = [bytes.fromhex(group["pmsg1Pool"][i]) for i in case["pmsg1Indices"]]
    params = _params(case["params"])
    if valid:
        _, cmsg1 = chilldkg.coordinator_step1_var(pmsgs1, params)
        assert cmsg1 == bytes.fromhex(case["expectedCmsg1"])
    else:
        _assert_refused(
            lambda: chilldkg.coordinator_step1_var(pmsgs1, params),
            case["expectedError"],
        )


@pytest.mark.parametrize(
    "group, case, valid", _cases("coordinator_finalize_vectors.json")
)
@both_arms
def test_coordinator_finalize_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`coordinator_finalize` answers, or refuses, as the file says."""
    params = _params(group["params"])
    state, cmsg1 = chilldkg.coordinator_step1_var(_hex(group["pmsgs1"]), params)
    assert cmsg1 == bytes.fromhex(group["cmsg1"])
    pmsgs2 = [bytes.fromhex(group["pmsg2Pool"][i]) for i in case["pmsg2Indices"]]
    if valid:
        cmsg2, info, recovery_data = chilldkg.coordinator_finalize(state, pmsgs2)
        output = case["expectedOutput"]
        assert cmsg2 == bytes.fromhex(output["cmsg2"])
        assert _info_dict(info) == output["thresholdInfo"]
        assert recovery_data == bytes.fromhex(output["recoveryData"])
    else:
        _assert_refused(
            lambda: chilldkg.coordinator_finalize(state, pmsgs2),
            case["expectedError"],
        )


@pytest.mark.parametrize(
    "group, case, valid", _cases("coordinator_investigate_vectors.json")
)
@both_arms
def test_coordinator_investigate_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`coordinator_investigate_var` answers as the file says."""
    assert valid
    params = _params(group["params"])
    cinvs = chilldkg.coordinator_investigate_var(_hex(group["pmsgs1"]), params)
    assert cinvs == _hex(case["expectedCinvMsgs"])


@pytest.mark.parametrize("group, case, valid", _cases("recover_vectors.json"))
@both_arms
def test_recover_vectors(
    group: dict[str, Any], case: dict[str, Any], valid: bool
) -> None:
    """`participant_recover`, or `coordinator_recover_var` with no host key."""
    del group
    data = bytes.fromhex(case["recoveryData"])
    host_sec_key = case["hostseckey"]

    def recover() -> tuple[bytes | None, frost.ThresholdInfo, chilldkg.SessionParams]:
        if not host_sec_key:
            return None, *chilldkg.coordinator_recover_var(data)
        return chilldkg.participant_recover(bytes.fromhex(host_sec_key), data)

    if not valid:
        _assert_refused(recover, case["expectedError"])
        return
    sec_share, info, params = recover()
    output = case["expectedOutput"]
    expected_share = output["secshare"]
    assert sec_share == (expected_share and bytes.fromhex(expected_share))
    assert _info_dict(info) == output["thresholdInfo"]
    assert _params_dict(params) == output["params"]


# --------------------------------------------------------------------
# a whole session, with the randomness drawn
# --------------------------------------------------------------------

_HOST_SEC_KEYS = [hashlib.sha256(b"chilldkg host %d" % i).digest() for i in range(3)]
_HOST_PUB_KEYS = [chilldkg.hostpubkey_gen(key) for key in _HOST_SEC_KEYS]
_PARAMS = chilldkg.SessionParams(_HOST_PUB_KEYS, 2)


def _session() -> tuple[
    list[chilldkg.ParticipantState1], list[bytes], bytes, list[Any], bytes
]:
    """Run a 2-of-3 session; return what each step answered."""
    steps1 = [chilldkg.participant_step1(key, _PARAMS) for key in _HOST_SEC_KEYS]
    states1 = [state1 for state1, _ in steps1]
    pmsgs1 = [pmsg1 for _, pmsg1 in steps1]
    cstate, cmsg1 = chilldkg.coordinator_step1_var(pmsgs1, _PARAMS)
    steps2 = [
        chilldkg.participant_step2(key, state1, cmsg1)
        for key, state1 in zip(_HOST_SEC_KEYS, states1, strict=True)
    ]
    cmsg2, info, recovery_data = chilldkg.coordinator_finalize(
        cstate, [pmsg2 for _, pmsg2 in steps2]
    )
    outputs = [chilldkg.participant_finalize(state2, cmsg2) for state2, _ in steps2]
    assert all(output[1:] == (info, recovery_data) for output in outputs)
    return states1, pmsgs1, cmsg1, outputs, recovery_data


def test_participant_step1_draws_its_randomness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`participant_step1` is `participant_step1_` with `token_bytes`."""
    drawn: list[int] = []
    random = bytes(range(1, 33))

    def token_bytes(size: int) -> bytes:
        drawn.append(size)
        return random

    monkeypatch.setattr(secrets, "token_bytes", token_bytes)
    expected = chilldkg.participant_step1_(_HOST_SEC_KEYS[0], _PARAMS, random)
    assert chilldkg.participant_step1(_HOST_SEC_KEYS[0], _PARAMS) == expected
    assert drawn == [32]


@both_arms
def test_a_session_outputs_key_material_frost_signs_with() -> None:
    """Each output validates, and each secret share is its public share's.

    Recovery gives every party the same back, and the threshold info is
    what `ecc.frost.validate_threshold_info` accepts.
    """
    _, _, _, outputs, recovery_data = _session()
    info = outputs[0][1]
    frost.validate_threshold_info(info)
    for i, (sec_share, _, _) in enumerate(outputs):
        assert info.pub_shares[i] == chilldkg.hostpubkey_gen(sec_share)
        recovered = chilldkg.participant_recover(_HOST_SEC_KEYS[i], recovery_data)
        assert recovered == (sec_share, info, _PARAMS)
    assert chilldkg.coordinator_recover_var(recovery_data) == (info, _PARAMS)


@both_arms
def test_an_investigation_of_a_consistent_session_is_refused() -> None:
    """With nothing faulty, there is no one to name."""
    states1, pmsgs1, cmsg1, _, _ = _session()
    cinvs = chilldkg.coordinator_investigate_var(pmsgs1, _PARAMS)
    with pytest.raises(EccValueError, match="all inputs are consistent"):
        chilldkg.participant_investigate(_HOST_SEC_KEYS[0], states1[0], cmsg1, cinvs[0])


@both_arms
def test_a_public_share_at_infinity_accuses_nobody() -> None:
    """A `cmsg1` that puts participant 1's public share at infinity.

    It adds D1 and D2 to the sums of the commitments to the non-constant
    terms of a 3-of-3 session, with D1 = -D2, so that they cancel at
    participant 0's x, and D2 = -(1/2) times participant 1's public share.
    Participant 0's own share checks out, `participant_step2` refuses the
    message as `EccValueError`, and the investigation finds no fault.
    """
    params = chilldkg.SessionParams(_HOST_PUB_KEYS, 3)
    steps1 = [chilldkg.participant_step1(key, params) for key in _HOST_SEC_KEYS]
    state1, pmsgs1 = steps1[0][0], [pmsg1 for _, pmsg1 in steps1]
    cstate, cmsg1 = chilldkg.coordinator_step1_var(pmsgs1, params)
    pub_share_octets = cstate.threshold_info.pub_shares[1]
    assert pub_share_octets is not None
    pub_share = point_from_octets_var(pub_share_octets)
    d2 = secp256k1.negate(mult(pow(2, -1, secp256k1.n), pub_share))
    broken = bytearray(cmsg1)
    for j, shift in enumerate((secp256k1.negate(d2), d2)):
        start = 33 * len(_HOST_PUB_KEYS) + 33 * j
        com = point_from_octets_var(bytes(broken[start : start + 33]))
        broken[start : start + 33] = bytes_from_point(secp256k1.add_var(com, shift))

    with pytest.raises(EccValueError, match="participant 1 is infinity") as refused:
        chilldkg.participant_step2(_HOST_SEC_KEYS[0], state1, bytes(broken))
    assert type(refused.value) is EccValueError
    cinv = chilldkg.coordinator_investigate_var(pmsgs1, params)[0]
    with pytest.raises(EccValueError, match="all inputs are consistent"):
        chilldkg.participant_investigate(_HOST_SEC_KEYS[0], state1, bytes(broken), cinv)


@both_arms
def test_a_certified_share_that_does_not_match_is_refused_at_recovery() -> None:
    """Recovery data whose shares every host key certified is still checked.

    Every participant signs a changed encrypted share of participant 0's:
    the certificate verifies, and the share recovered does not match its
    public share.
    """
    _, _, _, _, recovery_data = _session()
    n = len(_HOST_SEC_KEYS)
    cert_size = 64 * n
    eq_input = bytearray(recovery_data[:-cert_size])
    first_share = len(eq_input) - 32 * n
    eq_input[first_share + 31] ^= 1
    cert = b"".join(
        ssa.sign_(chilldkg._certeq_message(bytes(eq_input), i), key).serialize()
        for i, key in enumerate(_HOST_SEC_KEYS)
    )
    data = bytes(eq_input) + cert
    chilldkg.coordinator_recover_var(data)
    with pytest.raises(RecoveryDataError, match="does not match its public share"):
        chilldkg.participant_recover(_HOST_SEC_KEYS[0], data)


@both_arms
def test_the_recorded_single_participant_session_is_reproduced() -> None:
    """`chilldkg_vectors.json`'s session of one participant, run again here.

    `tests/_data/README.md` gives the program that recorded it, and the
    comment above its loading in `tests/schemes/frost_test.py` why it is
    kept.
    """
    recorded = load("schemes", "_data", "chilldkg_vectors.json")
    seed = recorded["seed"].encode()
    for session in recorded["sessions"]:
        t, n = session["t"], session["n"]

        def rand(x: str, i: int, t: int = t, n: int = n) -> bytes:
            return hashlib.sha256(seed + b"|" + f"{t}|{n}|{x}|{i}".encode()).digest()

        host_sec_keys = [rand("hostseckey", i) for i in range(n)]
        assert [key.hex() for key in host_sec_keys] == session["hostseckeys"]
        params = chilldkg.SessionParams(
            [chilldkg.hostpubkey_gen(key) for key in host_sec_keys], t
        )
        assert [key.hex() for key in params.host_pub_keys] == session["hostpubkeys"]
        steps1 = [
            chilldkg.participant_step1_(key, params, rand("step1", i))
            for i, key in enumerate(host_sec_keys)
        ]
        cstate, cmsg1 = chilldkg.coordinator_step1_var(
            [pmsg1 for _, pmsg1 in steps1], params
        )
        steps2 = [
            chilldkg.participant_step2(key, state1, cmsg1, rand("step2", i))
            for i, (key, (state1, _)) in enumerate(
                zip(host_sec_keys, steps1, strict=True)
            )
        ]
        cmsg2, info, recovery_data = chilldkg.coordinator_finalize(
            cstate, [pmsg2 for _, pmsg2 in steps2]
        )
        assert recovery_data.hex() == session["recovery_data"]
        expected = session["threshold_info"]
        assert info.t == expected["t"]
        assert info.thresh_pk.hex() == expected["thresh_pk"]
        assert [
            None if share is None else share.hex() for share in info.pub_shares
        ] == expected["pubshares"]
        for (state2, _), sec_share in zip(steps2, session["secshares"], strict=True):
            output = chilldkg.participant_finalize(state2, cmsg2)
            assert output == (bytes.fromhex(sec_share), info, recovery_data)


# --------------------------------------------------------------------
# the recovery acknowledgments: upstream's test_recovery_acknowledgment
# --------------------------------------------------------------------


@both_arms
def test_recovery_acknowledgments() -> None:
    """Every participant acknowledges, and a missing or wrong one is refused."""
    _, _, _, _, recovery_data = _session()
    acks = [
        chilldkg.participant_recovery_ack_sign(key, recovery_data, _PARAMS)
        for key in _HOST_SEC_KEYS
    ]
    assert all(len(ack) == 64 for ack in acks)
    chilldkg.validate_recovery_acks(recovery_data, _PARAMS, acks)

    wrong = [acks[0], bytes(64), acks[2]]
    with pytest.raises(InvalidRecoveryAckError) as refused:
        chilldkg.validate_recovery_acks(recovery_data, _PARAMS, wrong)
    assert refused.value.participant_id == 1
    with pytest.raises(EccValueError):
        chilldkg.validate_recovery_acks(
            recovery_data, _PARAMS, [acks[0][:32], *acks[1:]]
        )
    with pytest.raises(EccValueError):
        chilldkg.validate_recovery_acks(recovery_data, _PARAMS, acks[:-1])

    other = chilldkg.SessionParams(_HOST_PUB_KEYS, 3)
    corrupted = bytes(len(recovery_data))
    for call in (
        lambda d, p: chilldkg.participant_recovery_ack_sign(_HOST_SEC_KEYS[0], d, p),
        lambda d, p: chilldkg.validate_recovery_acks(d, p, acks),
    ):
        with pytest.raises(RecoveryDataError, match="does not match"):
            call(recovery_data, other)
        for data in (corrupted, corrupted[:3]):
            with pytest.raises(RecoveryDataError, match="Failed to deserialize"):
                call(data, _PARAMS)
        invalid = chilldkg.SessionParams([_HOST_PUB_KEYS[0], b"\x03" + bytes(32)], 1)
        with pytest.raises(exceptions.InvalidHostPubkeyError):
            call(recovery_data, invalid)

    duplicate = chilldkg.SessionParams([_HOST_PUB_KEYS[0]] * 2, 2)
    with pytest.raises(exceptions.DuplicateHostPubkeyError):
        chilldkg.participant_recovery_ack_sign(
            _HOST_SEC_KEYS[0], recovery_data, duplicate
        )
    above_n = chilldkg.SessionParams(_HOST_PUB_KEYS, len(_HOST_PUB_KEYS) + 1)
    with pytest.raises(exceptions.ThresholdOrCountError):
        chilldkg.participant_recovery_ack_sign(
            _HOST_SEC_KEYS[0], recovery_data, above_n
        )
    with pytest.raises(EccValueError):
        chilldkg.participant_recovery_ack_sign(bytes(16), recovery_data, _PARAMS)
    with pytest.raises(HostSeckeyError, match="does not match any"):
        chilldkg.participant_recovery_ack_sign(
            bytes(31) + b"\x01", recovery_data, _PARAMS
        )
    with pytest.raises(EccValueError):
        chilldkg.participant_recovery_ack_sign(
            _HOST_SEC_KEYS[0], recovery_data, _PARAMS, bytes(16)
        )


# --------------------------------------------------------------------
# what the vectors do not reach
# --------------------------------------------------------------------


def test_a_state_holds_a_participant_of_its_session() -> None:
    """A state is checked when built: its types, and its participant's id."""
    com = _HOST_PUB_KEYS[0]
    chilldkg.ParticipantState1(_PARAMS, 2, com, com)
    with pytest.raises(EccValueError, match="participant_id"):
        chilldkg.ParticipantState1(_PARAMS, 3, com, com)
    with pytest.raises(EccTypeError):
        chilldkg.ParticipantState1(_PARAMS, True, com, com)
    with pytest.raises(EccTypeError):
        chilldkg.CoordinatorState("params", b"", None)  # type: ignore[arg-type]


@both_arms
def test_a_state_of_another_type_is_refused() -> None:
    """`ecc.frost`'s refusal of a foreign session context, here for a state."""
    _, _, cmsg1, _, _ = _session()
    for call in (chilldkg.participant_step2, chilldkg.participant_investigate):
        with pytest.raises(EccTypeError, match="state1"):
            call(_HOST_SEC_KEYS[0], "state1", cmsg1, bytes(32))  # type: ignore[arg-type]
    with pytest.raises(EccTypeError, match="state2"):
        chilldkg.participant_finalize("state2", b"")  # type: ignore[arg-type]
    with pytest.raises(EccTypeError, match="state"):
        chilldkg.coordinator_finalize("state", [])  # type: ignore[arg-type]
    with pytest.raises(EccTypeError, match="pmsgs1"):
        chilldkg.coordinator_step1_var(b"\x00" * 4, _PARAMS)  # type: ignore[arg-type]
    with pytest.raises(EccTypeError, match="host_pub_keys"):
        chilldkg.SessionParams(_HOST_PUB_KEYS[0], 1)  # type: ignore[arg-type]


def test_a_proof_of_possession_out_of_range_does_not_verify() -> None:
    """An r of p or more, or an s of n or more, is no proof at all."""
    P = mult(1)
    pop = chilldkg._pop_prove(1, 0, bytes(32))
    assert chilldkg._pop_verify(pop, P, 0)
    assert not chilldkg._pop_verify(pop, P, 1)
    high_r = secp256k1.p.to_bytes(32, "big") + pop[32:]
    high_s = pop[:32] + secp256k1.n.to_bytes(32, "big")
    assert not chilldkg._pop_verify(high_r, P, 0)
    assert not chilldkg._pop_verify(high_s, P, 0)


@both_arms
def test_participant_state2_repr_holds_no_secret_share() -> None:
    """The secret share is left out of the repr and the str."""
    _, _, _, outputs, _ = _session()
    sec_share, info, _ = outputs[0]
    state2 = chilldkg.ParticipantState2(_PARAMS, b"", sec_share, info)
    as_int = int.from_bytes(sec_share, "big")
    assert_repr_secret_free(
        state2, [sec_share, sec_share.hex(), str(as_int), hex(as_int)]
    )


# --------------------------------------------------------------------
# a refusal carries no secret
# --------------------------------------------------------------------
# Section 7 of the organization's standard: what a secret is refused for
# is said without it. The secret is fed in each spelling of
# `tests.REFUSED_SECRETS` that the call refuses, on both arms.


def _step2_with_aux(aux: Any) -> object:
    state1, _ = chilldkg.participant_step1(_HOST_SEC_KEYS[0], _PARAMS)
    return chilldkg.participant_step2(_HOST_SEC_KEYS[0], state1, b"", aux)


def _step2_with_key(host_sec_key: Any) -> object:
    state1, _ = chilldkg.participant_step1(_HOST_SEC_KEYS[0], _PARAMS)
    return chilldkg.participant_step2(host_sec_key, state1, b"")


def _investigate_with_key(host_sec_key: Any) -> object:
    state1, _ = chilldkg.participant_step1(_HOST_SEC_KEYS[0], _PARAMS)
    return chilldkg.participant_investigate(host_sec_key, state1, b"", b"")


_SECRET_CALLS: dict[str, tuple[Callable[[Any], object], list[str]]] = {
    "hostpubkey_gen": (chilldkg.hostpubkey_gen, REFUSED_OCTETS),
    "participant_step1": (
        lambda s: chilldkg.participant_step1(s, _PARAMS),
        [*REFUSED_OCTETS, "wrong key"],
    ),
    "participant_step1_, random": (
        lambda s: chilldkg.participant_step1_(_HOST_SEC_KEYS[0], _PARAMS, s),
        REFUSED_AUX,
    ),
    "participant_step2": (_step2_with_key, [*REFUSED_OCTETS, "wrong key"]),
    "participant_step2, aux": (_step2_with_aux, REFUSED_AUX),
    "participant_investigate": (
        _investigate_with_key,
        [*REFUSED_OCTETS, "wrong key"],
    ),
    "participant_recover": (
        lambda s: chilldkg.participant_recover(s, _session()[4]),
        [*REFUSED_OCTETS, "wrong key"],
    ),
    "participant_recovery_ack_sign": (
        lambda s: chilldkg.participant_recovery_ack_sign(s, b"", _PARAMS),
        [*REFUSED_OCTETS, "wrong key"],
    ),
    "participant_recovery_ack_sign, aux": (
        lambda s: chilldkg.participant_recovery_ack_sign(
            _HOST_SEC_KEYS[0], b"", _PARAMS, s
        ),
        REFUSED_AUX,
    ),
    # a secret share is exactly 32 octets, as auxiliary randomness is
    "ParticipantState2": (
        lambda s: chilldkg.ParticipantState2(_PARAMS, b"", s, _session()[3][0][1]),
        REFUSED_AUX,
    ),
}

_SECRET_CASES = [
    (name, kind) for name, (_, kinds) in _SECRET_CALLS.items() for kind in kinds
]


@pytest.mark.parametrize("name, kind", _SECRET_CASES)
@both_arms
def test_a_refusal_carries_no_secret(name: str, kind: str) -> None:
    """No piece of the secret is in the exception or in anything it chains."""
    call, _ = _SECRET_CALLS[name]
    secret, spellings = refused_secret(kind)
    with pytest.raises(EccException) as refused:
        call(secret)
    assert_secret_free(refused.value, spellings)


@both_arms
def test_a_peer_refused_for_its_nonce_is_named() -> None:
    """A public nonce no point blames its sender, as the vectors' do.

    The control of the vectors' case: the refusal names the sender, and
    it is `FaultyParticipantOrCoordinatorError` and nothing above it.
    """
    states1, _, cmsg1, _, _ = _session()
    n = len(_HOST_SEC_KEYS)
    nonces = 162 * n + 33 * (_PARAMS.t - 1) - 32 * n - 33 * n
    broken = bytearray(cmsg1)
    broken[nonces + 33] = 0x05
    with pytest.raises(FaultyParticipantOrCoordinatorError) as refused:
        chilldkg.participant_step2(_HOST_SEC_KEYS[0], states1[0], bytes(broken))
    assert refused.value.participant_id == 1
    assert not isinstance(refused.value, FaultyCoordinatorError)
