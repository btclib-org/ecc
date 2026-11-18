# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# The ChillDKG below is a port of BlockstreamResearch/bip-frost-dkg's
# python/chilldkg_ref, at f913f9c7ffc3d67bfbb22dd7d294fb43f71562f3, under
# its notice:
#
# The MIT License (MIT)
#
# Copyright (c) The ChillDKG authors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""ChillDKG, the distributed key generation of BIP-FROST-DKG.

https://github.com/BlockstreamResearch/bip-frost-dkg, `python/chilldkg_ref`
at `f913f9c7ffc3d67bfbb22dd7d294fb43f71562f3`. The BIP is a draft;
`tests/_data/README.md` pins that reference and the vectors this module
is tested on, and the weekly vendored-vectors check reports a change to
either.

ChillDKG gives *n* participants, each known by a long-term host key, a
*t*-of-*n* FROST key: each ends with its secret share and every party
with the same `ecc.frost.ThresholdInfo`, which `ecc.frost` signs with.
Where *t* is above 1, no party learns the threshold secret key; where it
is 1, each secret share is that key. A coordinator relays the messages
and learns no secret either. The rounds:

- `participant_step1` for each participant, then `coordinator_step1_var`
  over what they sent;
- `participant_step2` for each participant, over what the coordinator
  sent, then `coordinator_finalize`;
- `participant_finalize` for each participant, over the coordinator's
  certificate.

Each participant and the coordinator keep the recovery data the last
step returns: `participant_recover` and `coordinator_recover_var`
rebuild the session's output from it and the host key.
`participant_recovery_ack_sign` and `validate_recovery_acks` confirm
that every participant holds it. `participant_investigate` and
`coordinator_investigate_var` name the faulty party where
`participant_step2` could not.

The functions follow the reference's, function for function, and refuse
each error case of its vectors with the exception the case names. They
depart from it where this package's rules ask:

- a `_var` suffix where public values decide the work, and
  `validate_recovery_acks` for `participant_recovery_acks_verify`, a
  name with `verify` in it answering a bool here;
- `participant_step1` draws its randomness and `participant_step1_`
  takes it, as in `ecc.musig2.nonce_gen` and `nonce_gen_`; `aux` is
  drawn where it is None, as in `ecc.ssa.sign_`;
- `participant_investigate` takes the host secret key, the state and the
  message `participant_step2` refused, not that refusal: the reference's
  exception carries the secret share and the decryption pads, and a
  refusal here carries no secret;
- `coordinator_investigate_var` checks the session parameters, and that
  `pmsgs1` holds a message per participant, as `coordinator_step1_var`
  does; the reference's checks neither;
- the reference's exception classes are those of `ecc.exceptions` under
  the same names. Where it refuses a value of the type it declares with
  a bare `ValueError`, with the `RuntimeError` of an investigation that
  finds no fault, or with an `assert`, this module raises
  `ecc.exceptions.EccValueError` or a subclass of it. A public share at
  infinity, for one, is the `EccValueError` `participant_step2`
  describes, and a recovered secret share that does not match its public
  share a `RecoveryDataError`.

secp256k1 and sha256 are fixed, as in `ecc.frost`. SECURITY.md's
limitations say which steps cross into libsecp256k1 and which run in
Python whatever is installed.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from typing import NoReturn, cast

from ecc import ssa
from ecc._utils import _has_type, assert_type, bytes_from_octets, is_integer, is_octets
from ecc.alias import INF, Octets, Point, Public
from ecc.curves import (
    bytes_from_point,
    bytes_from_prv_key_int,
    double_mult_var,
    mult,
    multi_mult_var,
    point_from_octets_var,
    scalar_from_prv_key,
    secp256k1,
    sum_var,
)
from ecc.curves.sec_point import _mult_sec_compressed
from ecc.exceptions import (
    DuplicateHostPubkeyError,
    EccTypeError,
    EccValueError,
    FaultyCoordinatorError,
    FaultyParticipantError,
    FaultyParticipantOrCoordinatorError,
    HostSeckeyError,
    InvalidHostPubkeyError,
    InvalidRecoveryAckError,
    RandomnessError,
    RecoveryDataError,
    SessionParamsError,
    ThresholdOrCountError,
    UnknownFaultyParticipantOrCoordinatorError,
)
from ecc.frost import MAX_PARTICIPANTS, PK_SIZE, ThresholdInfo
from ecc.hashes import tagged_hash

__all__ = [
    "CoordinatorState",
    "ParticipantState1",
    "ParticipantState2",
    "SessionParams",
    "coordinator_finalize",
    "coordinator_investigate_var",
    "coordinator_recover_var",
    "coordinator_step1_var",
    "hostpubkey_gen",
    "params_hash_var",
    "participant_finalize",
    "participant_investigate",
    "participant_recover",
    "participant_recovery_ack_sign",
    "participant_step1",
    "participant_step1_",
    "participant_step2",
    "validate_recovery_acks",
]

_ORDER = secp256k1.n

# a scalar, a BIP340 signature, a participant identifier or a threshold
_SCALAR_SIZE = 32
_SIG_SIZE = 64
_ID_SIZE = 4

# the infinity point as 33 zero bytes, as the reference writes it
_INF_BYTES = bytes(PK_SIZE)

# the reference's tags: every hash of the protocol is tagged under this
# prefix, and the proof of possession signs with its own BIP340 tags
_TAG_PREFIX = b"BIP DKG/"
_POP_TAG = _TAG_PREFIX + b"pop message"
# the certificate's and the acknowledgment's messages open with their tag,
# padded to 33 bytes, BIP340's domain separation for a plain signature
_CERTEQ_PREFIX = (_TAG_PREFIX + b"certeq message").ljust(PK_SIZE, b"\x00")
_ACK_PREFIX = (_TAG_PREFIX + b"recovery acknowledgment").ljust(PK_SIZE, b"\x00")

# the reference's own messages, compared by the vectors that name one
_HOST_KEY_NOT_FOUND_ERR = "Host secret key does not match any host public key"
_FAILED_TO_DESERIALIZE_ERR = "Failed to deserialize recovery data"


class _MsgParseError(EccValueError):
    """A message that does not parse; the caller says whose it is."""


def _hash(tag: bytes, msg: bytes) -> bytes:
    return tagged_hash(_TAG_PREFIX + tag, msg)


def _scalar(octets: bytes) -> int:
    return int.from_bytes(octets, "big") % _ORDER


def _id_bytes(i: int) -> bytes:
    return i.to_bytes(_ID_SIZE, "big")


def _cbytes(P: Point) -> bytes:
    return bytes_from_point(P, secp256k1)


def _cbytes_ext(P: Point) -> bytes:
    """Serialize a point that may be the infinity one."""
    return _INF_BYTES if P[1] == 0 else _cbytes(P)


def _cpoint_ext_var(octets: bytes) -> Point:
    """Deserialize 33 bytes into a point that may be the infinity one."""
    return INF if octets == _INF_BYTES else point_from_octets_var(octets, secp256k1)


def _points_var(octets: bytes, count: int, what: str) -> list[Point]:
    """Deserialize `count` points, refusing the whole as `what`."""
    try:
        return [
            _cpoint_ext_var(octets[i * PK_SIZE : (i + 1) * PK_SIZE])
            for i in range(count)
        ]
    except EccValueError as e:
        raise _MsgParseError(what) from e


def _scalars(octets: bytes, count: int, what: str) -> list[int]:
    """Deserialize `count` scalars, refusing the whole as `what`.

    A value of n or more is refused, never reduced.
    """
    values = [
        int.from_bytes(octets[i * _SCALAR_SIZE : (i + 1) * _SCALAR_SIZE], "big")
        for i in range(count)
    ]
    if any(value >= _ORDER for value in values):
        raise _MsgParseError(what)
    return values


def _scalars_bytes(values: Sequence[int]) -> bytes:
    return b"".join(value.to_bytes(_SCALAR_SIZE, "big") for value in values)


def _chunks(octets: bytes, size: int, count: int) -> list[bytes]:
    return [octets[i * size : (i + 1) * size] for i in range(count)]


def _integer(value: object, what: str) -> int:
    """Return `value` if it is an integer, a bool not being one."""
    if not is_integer(value):
        raise EccTypeError(f"invalid {what} type: {type(value).__name__}")
    return cast("int", value)


def _assert_octets_sequence(value: object, what: str) -> None:
    """Refuse anything but a Sequence of Octets, naming which.

    `ecc.frost._assert_octets_sequence`'s reason: an Octets is itself a
    Sequence, and would be read as a list of its bytes.
    """
    if is_octets(value) or not _has_type(value, Sequence):
        raise EccTypeError(f"invalid {what} type: {type(value).__name__}")


# --------------------------------------------------------------------
# Session parameters and host keys
# --------------------------------------------------------------------


@dataclass(frozen=True, init=False)
class SessionParams:
    """The parameters every party of a session shares.

    The participants' host public keys, in an order every party agrees on,
    and the threshold `t`. The constructor checks types and sizes only:
    every function taking these checks that `1 <= t <= n`, with `n` at
    most `ecc.frost.MAX_PARTICIPANTS`, that each key is a point and that
    no key is repeated, refusing them with the
    `ecc.exceptions.SessionParamsError` that says which.

    Each participant must hold an authentic copy of every other host
    public key before the session starts. `params_hash_var` is a hash of
    these parameters, to compare out of band.
    """

    host_pub_keys: tuple[bytes, ...]
    t: int

    def __init__(self, host_pub_keys: Sequence[Octets], t: int) -> None:
        _assert_octets_sequence(host_pub_keys, "host_pub_keys")
        object.__setattr__(
            self,
            "host_pub_keys",
            tuple(bytes_from_octets(key, PK_SIZE) for key in host_pub_keys),
        )
        object.__setattr__(self, "t", _integer(t, "t"))


def _validate_params_var(params: SessionParams) -> tuple[tuple[bytes, ...], int]:
    """Return the host public keys and the threshold, once checked."""
    host_pub_keys, t = params.host_pub_keys, params.t
    if not 1 <= t <= len(host_pub_keys) <= MAX_PARTICIPANTS:
        raise ThresholdOrCountError(
            f"The threshold must satisfy 1 <= t <= n <= {MAX_PARTICIPANTS}."
        )
    for i, host_pub_key in enumerate(host_pub_keys):
        try:
            point_from_octets_var(host_pub_key, secp256k1)
        except EccValueError as e:
            raise InvalidHostPubkeyError(i) from e
    seen: dict[bytes, int] = {}
    for i, host_pub_key in enumerate(host_pub_keys):
        if host_pub_key in seen:
            raise DuplicateHostPubkeyError(seen[host_pub_key], i)
        seen[host_pub_key] = i
    return host_pub_keys, t


def _host_key(host_sec_key: Octets) -> tuple[bytes, int, bytes]:
    """Return a host secret key's octets, its scalar and its host public key."""
    octets = bytes_from_octets(host_sec_key, _SCALAR_SIZE)
    q = int.from_bytes(octets, "big")
    if not 0 < q < _ORDER:
        raise HostSeckeyError("The host secret key is not in 1..n-1.")
    return octets, q, bytes_from_prv_key_int(q, secp256k1)


def _host_index(host_pub_keys: Sequence[bytes], host_pub_key: bytes, err: str) -> int:
    """Return the position of a host public key, refusing one not there."""
    if host_pub_key not in host_pub_keys:
        raise HostSeckeyError(err)
    return host_pub_keys.index(host_pub_key)


def _aux(aux: Octets | None) -> bytes | None:
    """Return BIP340's auxiliary randomness, None for `ssa.sign_` to draw."""
    return None if aux is None else bytes_from_octets(aux, _SCALAR_SIZE)


def hostpubkey_gen(host_sec_key: Octets) -> bytes:
    """Return the 33-byte compressed host public key of a host secret key.

    The host secret key is 32 bytes of randomness, the participant's
    long-term identity across sessions; a session's every output is
    recovered from it and the session's recovery data.
    """
    return _host_key(host_sec_key)[2]


def params_hash_var(params: SessionParams) -> bytes:
    """Return the 32-byte hash of the session parameters.

    Participants that obtained the same hash, compared out of band, agree
    on every host public key and on the threshold.
    """
    assert_type(params, SessionParams, "params")
    host_pub_keys, t = _validate_params_var(params)
    return _hash(b"params_hash", _id_bytes(t) + b"".join(host_pub_keys))


# --------------------------------------------------------------------
# Verifiable secret sharing
# --------------------------------------------------------------------


def _vss_coeffs(seed: bytes, t: int) -> list[int]:
    """Return the t coefficients of a participant's secret polynomial."""
    return _scalars(
        b"".join(_hash(b"vss coeffs", seed + _id_bytes(i)) for i in range(t)),
        t,
        "invalid polynomial coefficient",
    )


def _poly_eval(coeffs: Sequence[int], x: int) -> int:
    """Evaluate the polynomial at x, by Horner's method."""
    value = 0
    for coeff in reversed(coeffs):
        value = (value * x + coeff) % _ORDER
    return value


def _pubshare_var(com: Sequence[Point], i: Public) -> Point:
    """Return the public share of participant i: the commitment at x = i + 1."""
    if len(com) == 1:
        return com[0]
    return multi_mult_var(
        [Public(pow(i + 1, j, _ORDER)) for j in range(len(com))], com, secp256k1
    )


def _taproot_tweak_var(com: Sequence[Point]) -> tuple[list[Point], int, Point]:
    """Return the commitment tweaked, the tweak and the tweak's point.

    The threshold public key commits to an empty script path, BIP341's
    unspendable one, so that no participant can hide a script path in it;
    every secret share is tweaked by the same scalar.
    """
    x_only = _cbytes(com[0])[1:]
    tweak = _scalars(tagged_hash(b"TapTweak", x_only), 1, "invalid tweak")[0]
    pub_tweak = mult(tweak, ec=secp256k1)
    return [secp256k1.add_var(com[0], pub_tweak), *com[1:]], tweak, pub_tweak


# --------------------------------------------------------------------
# Proof of possession: BIP340 under the tags of its own prefix
# --------------------------------------------------------------------


def _pop_prove(d0: int, participant_id: int, aux: bytes) -> bytes:
    """Sign the participant's identifier with the secret its commitment holds.

    BIP340's signing, with `_POP_TAG` for `BIP0340` in its tags, which
    `ecc.ssa` fixes; the nonce is the tagged hash reduced mod n, as the
    reference reduces it.
    """
    msg = _id_bytes(participant_id)
    P = mult(d0, ec=secp256k1)
    x_P = _cbytes(P)[1:]
    d = (d0, _ORDER - d0)[P[1] & 1]
    mask = int.from_bytes(tagged_hash(_POP_TAG + b"/aux", aux), "big")
    masked = (d ^ mask).to_bytes(_SCALAR_SIZE, "big")
    k0 = _scalar(tagged_hash(_POP_TAG + b"/nonce", masked + x_P + msg))
    R = mult(k0, ec=secp256k1)
    x_R = _cbytes(R)[1:]
    # selected by index, not under an `if`: the parity of R's y is not
    # published, where P's is, P being the first point of the commitment
    k = (k0, _ORDER - k0)[R[1] & 1]
    e = _scalar(tagged_hash(_POP_TAG + b"/challenge", x_R + x_P + msg))
    return x_R + ((k + e * d) % _ORDER).to_bytes(_SCALAR_SIZE, "big")


def _pop_verify(pop: bytes, P: Point, participant_id: int) -> bool:
    """Verify a proof of possession of P, a point that is not infinity.

    BIP340's verification under `_POP_TAG`, against the even-y point of
    P's x, which is what the reference lifts from that x.
    """
    msg = _id_bytes(participant_id)
    r = int.from_bytes(pop[:_SCALAR_SIZE], "big")
    s = int.from_bytes(pop[_SCALAR_SIZE:], "big")
    if r >= secp256k1.p or s >= _ORDER:
        return False
    x_P = _cbytes(P)[1:]
    e = _scalar(tagged_hash(_POP_TAG + b"/challenge", pop[:_SCALAR_SIZE] + x_P + msg))
    P_even = (P, secp256k1.negate(P))[P[1] & 1]
    R = double_mult_var(Public(s), secp256k1.G, Public(_ORDER - e), P_even, secp256k1)
    return R[1] != 0 and R[1] % 2 == 0 and R[0] == r


# --------------------------------------------------------------------
# Encryption of the shares: a pad per recipient, from an ECDH
# --------------------------------------------------------------------


def _enc_context(t: int, host_pub_keys: Sequence[bytes]) -> bytes:
    return _id_bytes(t) + b"".join(host_pub_keys)


def _ecdh_pad(q: int, their_pub: bytes, first: bytes, second: bytes, ctx: bytes) -> int:
    """Return the pad of an ECDH, hashed with both keys, the sender's first.

    The shared point is libsecp256k1's ECDH answer, the sha256 of its
    compressed octets, where the bindings serve.
    """
    shared = sha256(_mult_sec_compressed(their_pub, q, secp256k1)).digest()
    return _scalar(_hash(b"encpedpop ecdh", shared + first + second + ctx))


def _self_pad(host_sec_key: bytes, pub_nonce: bytes, ctx: bytes) -> int:
    """Return the pad of the share a participant encrypts to itself."""
    return _scalar(_hash(b"encaps_multi self_pad", host_sec_key + pub_nonce + ctx))


def _encaps(
    k: int,
    pub_nonce: bytes,
    host_sec_key: bytes,
    host_pub_keys: Sequence[bytes],
    enc_context: bytes,
    participant_id: int,
) -> list[int]:
    """Return the pads a participant encrypts its shares with, one each.

    The recipient's index is hashed into its pad, which is the
    multi-recipient KEM of Pinto, Poettering and Schuldt the reference
    follows.
    """
    pads = []
    for i, host_pub_key in enumerate(host_pub_keys):
        ctx = _id_bytes(i) + enc_context
        if i == participant_id:
            pads.append(_self_pad(host_sec_key, pub_nonce, ctx))
        else:
            pads.append(_ecdh_pad(k, host_pub_key, pub_nonce, host_pub_key, ctx))
    return pads


def _decaps(
    q: int,
    host_sec_key: bytes,
    host_pub_key: bytes,
    pub_nonces: Sequence[bytes],
    enc_context: bytes,
    participant_id: int,
) -> list[int]:
    """Return the pads of the shares a participant received, one per sender."""
    ctx = _id_bytes(participant_id) + enc_context
    pads = []
    for sender_id, pub_nonce in enumerate(pub_nonces):
        if sender_id == participant_id:
            pads.append(_self_pad(host_sec_key, pub_nonce, ctx))
            continue
        try:
            pads.append(_ecdh_pad(q, pub_nonce, pub_nonce, host_pub_key, ctx))
        except EccValueError as e:
            raise FaultyParticipantOrCoordinatorError(
                sender_id, "invalid public nonce"
            ) from e
    return pads


# --------------------------------------------------------------------
# CertEq: every participant signs what it saw, and all must agree
# --------------------------------------------------------------------


def _certeq_message(eq_input: bytes, participant_id: int) -> bytes:
    return _CERTEQ_PREFIX + _id_bytes(participant_id) + eq_input


def _certeq_invalid(
    host_pub_keys: Sequence[bytes], eq_input: bytes, cert: bytes
) -> int | None:
    """Return the first participant whose signature in `cert` is invalid.

    Each verifies under the x-only key of its host public key: the
    message commits to every full host public key, so the parity dropped
    is not lost.
    """
    for i, sig in enumerate(_chunks(cert, _SIG_SIZE, len(host_pub_keys))):
        msg = _certeq_message(eq_input, i)
        if not ssa.verify_(msg, host_pub_keys[i][1:], sig):
            return i
    return None


def _eq_input(
    t: int,
    sum_coms: Sequence[Point],
    host_pub_keys: Sequence[bytes],
    pub_nonces: Sequence[bytes],
    enc_sec_shares: Sequence[int],
) -> bytes:
    """Return what every party signs: the session as it saw it."""
    return (
        _id_bytes(t)
        + b"".join(_cbytes_ext(C) for C in sum_coms)
        + b"".join(host_pub_keys)
        + b"".join(pub_nonces)
        + _scalars_bytes(enc_sec_shares)
    )


def _threshold_info_var(t: int, tweaked: Sequence[Point], n: int) -> ThresholdInfo:
    pub_shares = []
    for i in range(n):
        pub_share = _pubshare_var(tweaked, Public(i))
        if pub_share[1] == 0:
            raise EccValueError(f"The public share of participant {i} is infinity.")
        pub_shares.append(_cbytes(pub_share))
    return ThresholdInfo(t, _cbytes(tweaked[0]), pub_shares)


# --------------------------------------------------------------------
# Participant
# --------------------------------------------------------------------


@dataclass(frozen=True)
class ParticipantState1:
    """A participant's state after `participant_step1`, for `participant_step2`.

    Public values only. It goes to one `participant_step2` call, and to
    `participant_investigate` where that call names nobody.
    """

    params: SessionParams
    participant_id: int
    com_to_secret: bytes
    pub_nonce: bytes

    def __post_init__(self) -> None:
        """Check each field's type and size, and the identifier's range."""
        assert_type(self.params, SessionParams, "params")
        host_pub_keys, _ = _validate_params_var(self.params)
        if (
            not 0
            <= _integer(self.participant_id, "participant_id")
            < len(host_pub_keys)
        ):
            raise EccValueError("The participant_id is not in 0..n-1.")
        for name in ("com_to_secret", "pub_nonce"):
            value = bytes_from_octets(getattr(self, name), PK_SIZE)
            object.__setattr__(self, name, value)


@dataclass(frozen=True)
class ParticipantState2:
    """A participant's state after `participant_step2`, for finalizing.

    `sec_share` is the participant's secret share, left out of the repr.
    """

    params: SessionParams
    eq_input: bytes
    sec_share: bytes = field(repr=False)
    threshold_info: ThresholdInfo

    def __post_init__(self) -> None:
        """Check each field's type and size."""
        assert_type(self.params, SessionParams, "params")
        _validate_params_var(self.params)
        object.__setattr__(self, "eq_input", bytes_from_octets(self.eq_input))
        sec_share = bytes_from_octets(self.sec_share, _SCALAR_SIZE)
        object.__setattr__(self, "sec_share", sec_share)
        assert_type(self.threshold_info, ThresholdInfo, "threshold_info")


@dataclass(frozen=True)
class _Received:
    """What `participant_step2` reads of the coordinator's first message.

    `valid` says whether the participant's secret share matches its
    public share; the rest is what either answer goes on with.
    """

    pub_nonces: list[bytes]
    enc_sec_shares: list[int]
    sum_coms: list[Point]
    tweaked: list[Point]
    pub_tweak: Point
    pub_share_tweaked: Point
    pads: list[int] = field(repr=False)
    sec_share: int = field(repr=False)
    sec_share_tweaked: int = field(repr=False)
    valid: bool


def _cmsg1_size(t: int, n: int) -> int:
    return (2 * PK_SIZE + _SIG_SIZE + _SCALAR_SIZE) * n + PK_SIZE * (t - 1)


def _parse_cmsg1_var(
    cmsg1: bytes, t: int, n: int
) -> tuple[list[Point], list[Point], list[bytes], list[bytes], list[int]]:
    """Return the commitments, the sums, the pops, the nonces, the shares."""
    coms_to_secrets = _points_var(cmsg1, n, "invalid commitment to secret")
    rest = cmsg1[PK_SIZE * n :]
    sum_nonconst = _points_var(
        rest, t - 1, "invalid sum commitment to non-constant term"
    )
    rest = rest[PK_SIZE * (t - 1) :]
    pops = _chunks(rest, _SIG_SIZE, n)
    rest = rest[_SIG_SIZE * n :]
    pub_nonces = _chunks(rest, PK_SIZE, n)
    rest = rest[PK_SIZE * n :]
    enc_sec_shares = _scalars(rest, n, "invalid encrypted secret shares")
    return coms_to_secrets, sum_nonconst, pops, pub_nonces, enc_sec_shares


def _participant_key(
    host_sec_key: Octets, state1: ParticipantState1
) -> tuple[bytes, int, bytes]:
    """Return what `_host_key` returns, `state1`'s type once checked."""
    assert_type(state1, ParticipantState1, "state1")
    return _host_key(host_sec_key)


def _assert_state_key(host_pub_key: bytes, state1: ParticipantState1) -> None:
    if host_pub_key != state1.params.host_pub_keys[state1.participant_id]:
        raise HostSeckeyError(
            "Host secret key does not match the one used in participant_step1"
        )


def _receive(
    host_sec_key: bytes, q: int, state1: ParticipantState1, cmsg1: Octets
) -> _Received:
    """Read the coordinator's first message, up to the check of the share.

    What it refuses, `participant_step2` and `participant_investigate`
    both refuse.
    """
    host_pub_keys, t = state1.params.host_pub_keys, state1.params.t
    n, participant_id = len(host_pub_keys), state1.participant_id
    cmsg1 = bytes_from_octets(cmsg1)
    if len(cmsg1) != _cmsg1_size(t, n):
        raise EccValueError(f"The cmsg1 must be a {_cmsg1_size(t, n)}-byte array.")
    try:
        coms_to_secrets, sum_nonconst, pops, pub_nonces, enc_sec_shares = (
            _parse_cmsg1_var(cmsg1, t, n)
        )
    except _MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e

    if pub_nonces[participant_id] != state1.pub_nonce:
        raise FaultyCoordinatorError("Coordinator replied with wrong pubnonce")
    enc_context = _enc_context(t, host_pub_keys)
    pads = _decaps(
        q,
        host_sec_key,
        host_pub_keys[participant_id],
        pub_nonces,
        enc_context,
        participant_id,
    )
    sec_share = (enc_sec_shares[participant_id] - sum(pads)) % _ORDER

    if _cbytes_ext(coms_to_secrets[participant_id]) != state1.com_to_secret:
        raise FaultyCoordinatorError(
            "Coordinator sent unexpected first group element for local participant id"
        )
    for i in range(n):
        if i == participant_id:
            continue
        if coms_to_secrets[i][1] == 0:
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid commitment"
            )
        if not _pop_verify(pops[i], coms_to_secrets[i], i):
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid proof-of-knowledge"
            )

    sum_coms = [sum_var(coms_to_secrets, secp256k1), *sum_nonconst]
    tweaked, tweak, pub_tweak = _taproot_tweak_var(sum_coms)
    pub_share_tweaked = _pubshare_var(tweaked, Public(participant_id))
    sec_share_tweaked = (sec_share + tweak) % _ORDER
    valid = mult(sec_share_tweaked, ec=secp256k1) == pub_share_tweaked
    return _Received(
        pub_nonces,
        enc_sec_shares,
        sum_coms,
        tweaked,
        pub_tweak,
        pub_share_tweaked,
        pads,
        sec_share,
        sec_share_tweaked,
        valid,
    )


def participant_step1_(
    host_sec_key: Octets, params: SessionParams, random: Octets
) -> tuple[ParticipantState1, bytes]:
    """Return a participant's first state and its first message, given `random`.

    `participant_step1` is the spelling that draws `random`. The message,
    33*t + 32*n + 97 bytes, goes to the coordinator, and the state where
    `ParticipantState1` says.

    `random` is 32 bytes, never all zeros, and must be fresh for each
    session: the host secret key is the other half of the seed of every
    secret the session derives.
    """
    assert_type(params, SessionParams, "params")
    octets, _, host_pub_key = _host_key(host_sec_key)
    host_pub_keys, t = _validate_params_var(params)
    participant_id = _host_index(host_pub_keys, host_pub_key, _HOST_KEY_NOT_FOUND_ERR)
    random = bytes_from_octets(random, _SCALAR_SIZE)
    if random == bytes(_SCALAR_SIZE):
        raise RandomnessError("The randomness must not be all zeros.")

    n = len(host_pub_keys)
    enc_context = _enc_context(t, host_pub_keys)
    seed = _hash(b"encpedpop seed", octets + random + enc_context)
    aux = _hash(b"simplpedpop aux", seed)
    k = scalar_from_prv_key(_hash(b"encpedpop secnonce", seed), secp256k1)
    pub_nonce = bytes_from_prv_key_int(k, secp256k1)

    coeffs = _vss_coeffs(seed, t)
    shares = [_poly_eval(coeffs, i + 1) for i in range(n)]
    pop = _pop_prove(coeffs[0], participant_id, aux)
    com = [mult(coeff, ec=secp256k1) for coeff in coeffs]
    pads = _encaps(k, pub_nonce, octets, host_pub_keys, enc_context, participant_id)
    enc_shares = [
        (share + pad) % _ORDER for share, pad in zip(shares, pads, strict=True)
    ]
    pmsg1 = (
        b"".join(_cbytes_ext(C) for C in com)
        + pop
        + pub_nonce
        + _scalars_bytes(enc_shares)
    )
    state1 = ParticipantState1(params, participant_id, _cbytes_ext(com[0]), pub_nonce)
    return state1, pmsg1


def participant_step1(
    host_sec_key: Octets, params: SessionParams
) -> tuple[ParticipantState1, bytes]:
    """Return a participant's first state and its first message.

    Fresh randomness is drawn here; `participant_step1_` is the spelling
    that takes it, for the test vectors.
    """
    return participant_step1_(host_sec_key, params, secrets.token_bytes(_SCALAR_SIZE))


def participant_step2(
    host_sec_key: Octets,
    state1: ParticipantState1,
    cmsg1: Octets,
    aux: Octets | None = None,
) -> tuple[ParticipantState2, bytes]:
    """Return a participant's second state and its 64-byte second message.

    `cmsg1` is the coordinator's first message, 162*n + 33*(t-1) bytes;
    `aux` is BIP340's auxiliary randomness of the signature the message
    is, drawn where it is None.

    Once the message is sent, the host secret key must be kept, whatever
    follows: another participant may finish the session and use its key,
    and can show this one the recovery data at any later time.

    A `cmsg1` of the right size that does not check out raises the
    `ecc.exceptions` protocol error naming whom it accuses, unless this
    participant's own share checks out and the message puts another
    participant's public share at infinity: that raises `EccValueError`,
    which accuses nobody. `UnknownFaultyParticipantOrCoordinatorError`
    names nobody either: `participant_investigate` does, given the same
    arguments and the coordinator's investigation message.
    """
    octets, q, host_pub_key = _participant_key(host_sec_key, state1)
    aux_ = _aux(aux)
    _assert_state_key(host_pub_key, state1)
    received = _receive(octets, q, state1, cmsg1)
    if not received.valid:
        raise UnknownFaultyParticipantOrCoordinatorError(
            "Received invalid secshare; consider using participant_investigate()"
            " to determine a faulty party"
        )

    params = state1.params
    host_pub_keys, t = params.host_pub_keys, params.t
    eq_input = _eq_input(
        t,
        received.sum_coms,
        host_pub_keys,
        received.pub_nonces,
        received.enc_sec_shares,
    )
    info = _threshold_info_var(t, received.tweaked, len(host_pub_keys))
    sec_share = received.sec_share_tweaked.to_bytes(_SCALAR_SIZE, "big")
    state2 = ParticipantState2(params, eq_input, sec_share, info)
    msg = _certeq_message(eq_input, state1.participant_id)
    return state2, ssa.sign_(msg, q, aux_).serialize()


def participant_finalize(
    state2: ParticipantState2, cmsg2: Octets
) -> tuple[bytes, ThresholdInfo, bytes]:
    """Return the secret share, the threshold info and the recovery data.

    `cmsg2` is the coordinator's certificate, 64*n bytes: a signature by
    every participant of what it saw. Returning, the participant deems
    the session successful; others may not, or may not hold the recovery
    data, which `participant_recovery_ack_sign` confirms before the key
    is used.

    A refusal is no proof the session failed: another participant may
    deem it successful, so the host secret key must still be kept.
    """
    assert_type(state2, ParticipantState2, "state2")
    host_pub_keys = state2.params.host_pub_keys
    cmsg2 = bytes_from_octets(cmsg2, _SIG_SIZE * len(host_pub_keys))
    if _certeq_invalid(host_pub_keys, state2.eq_input, cmsg2) is not None:
        raise FaultyCoordinatorError(
            "Coordinator has provided a certificate with an invalid signature"
        )
    return state2.sec_share, state2.threshold_info, state2.eq_input + cmsg2


def participant_investigate(
    host_sec_key: Octets, state1: ParticipantState1, cmsg1: Octets, cinv: Octets
) -> NoReturn:
    """Name whom a participant's wrong secret share is owed to.

    For `participant_step2`'s `UnknownFaultyParticipantOrCoordinatorError`:
    the host secret key, the state and `cmsg1` are that call's, and `cinv`
    is this participant's message of `coordinator_investigate_var`, 65*n
    bytes. It raises `FaultyParticipantOrCoordinatorError` or
    `FaultyCoordinatorError`, and never returns. What `participant_step2`
    refuses of these arguments before its check of the share, it refuses for
    that reason; where `cmsg1` and `cinv` hold no fault at all, it refuses
    them as `EccValueError`.
    """
    octets, q, host_pub_key = _participant_key(host_sec_key, state1)
    _assert_state_key(host_pub_key, state1)
    received = _receive(octets, q, state1, cmsg1)
    n = len(state1.params.host_pub_keys)
    cinv = bytes_from_octets(cinv, (PK_SIZE + _SCALAR_SIZE) * n)
    try:
        enc_partial = _scalars(cinv, n, "invalid encrypted partial secshare")
        partial_pub_shares = _points_var(
            cinv[_SCALAR_SIZE * n :], n, "invalid partial pubshare"
        )
    except _MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    partial_sec_shares = [
        (enc - pad) % _ORDER
        for enc, pad in zip(enc_partial, received.pads, strict=True)
    ]

    pub_share = secp256k1.add_var(
        received.pub_share_tweaked, secp256k1.negate(received.pub_tweak)
    )
    if sum_var(partial_pub_shares, secp256k1) != pub_share:
        raise FaultyCoordinatorError("Sum of partial pubshares not equal to pubshare")
    if sum(partial_sec_shares) % _ORDER != received.sec_share:
        # the encryption is additively homomorphic, so it is the sum of the
        # encrypted shares, the coordinator's, that is wrong
        raise FaultyCoordinatorError(
            "Sum of encrypted partial secshares not equal to encrypted secshare"
        )
    for i, (sec, pub) in enumerate(
        zip(partial_sec_shares, partial_pub_shares, strict=True)
    ):
        if mult(sec, ec=secp256k1) == pub:
            continue
        if i != state1.participant_id:
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid partial secshare"
            )
        raise FaultyCoordinatorError(
            "Coordinator fiddled with the share from me to myself"
        )
    raise EccValueError(
        "participant_investigate() was called, but all inputs are consistent."
    )


# --------------------------------------------------------------------
# Coordinator
# --------------------------------------------------------------------


@dataclass(frozen=True)
class CoordinatorState:
    """The coordinator's state after `coordinator_step1_var`.

    Public values only, for one `coordinator_finalize` call.
    """

    params: SessionParams
    eq_input: bytes
    threshold_info: ThresholdInfo

    def __post_init__(self) -> None:
        """Check each field's type."""
        assert_type(self.params, SessionParams, "params")
        _validate_params_var(self.params)
        object.__setattr__(self, "eq_input", bytes_from_octets(self.eq_input))
        assert_type(self.threshold_info, ThresholdInfo, "threshold_info")


def _parse_pmsg1_var(
    pmsg1: bytes, t: int, n: int
) -> tuple[list[Point], bytes, bytes, list[int]]:
    """Return a first message's commitment, pop, public nonce and shares."""
    size = PK_SIZE * t + _SIG_SIZE + PK_SIZE + _SCALAR_SIZE * n
    if len(pmsg1) != size:
        raise EccValueError(f"The pmsg1 must be a {size}-byte array.")
    com = _points_var(pmsg1, t, "invalid VSS commitment")
    rest = pmsg1[PK_SIZE * t :]
    pop, pub_nonce = rest[:_SIG_SIZE], rest[_SIG_SIZE : _SIG_SIZE + PK_SIZE]
    enc_shares = _scalars(
        rest[_SIG_SIZE + PK_SIZE :], n, "invalid encrypted secret share"
    )
    return com, pop, pub_nonce, enc_shares


def _parse_pmsgs1_var(
    pmsgs1: Sequence[Octets], params: SessionParams
) -> tuple[tuple[bytes, ...], int, list[tuple[list[Point], bytes, bytes, list[int]]]]:
    """Return the host public keys, the threshold and each first message."""
    assert_type(params, SessionParams, "params")
    host_pub_keys, t = _validate_params_var(params)
    _assert_octets_sequence(pmsgs1, "pmsgs1")
    n = len(host_pub_keys)
    if len(pmsgs1) != n:
        raise EccValueError("The pmsgs1 list must hold one message per participant.")
    parsed = []
    for i, pmsg1 in enumerate(pmsgs1):
        try:
            parsed.append(_parse_pmsg1_var(bytes_from_octets(pmsg1), t, n))
        except _MsgParseError as e:
            raise FaultyParticipantError(i, *e.args) from e
    return host_pub_keys, t, parsed


def coordinator_step1_var(
    pmsgs1: Sequence[Octets], params: SessionParams
) -> tuple[CoordinatorState, bytes]:
    """Return the coordinator's state and its first message to all.

    `pmsgs1` holds every participant's first message, in the order of the
    host public keys. The message is 162*n + 33*(t-1) bytes.
    """
    host_pub_keys, t, parsed = _parse_pmsgs1_var(pmsgs1, params)
    n = len(host_pub_keys)
    coms_to_secrets = [com[0] for com, _, _, _ in parsed]
    sum_nonconst = [
        sum_var([com[j] for com, _, _, _ in parsed], secp256k1) for j in range(1, t)
    ]
    pops = [pop for _, pop, _, _ in parsed]
    pub_nonces = [pub_nonce for _, _, pub_nonce, _ in parsed]
    enc_sec_shares = [
        sum(enc_shares[i] for _, _, _, enc_shares in parsed) % _ORDER for i in range(n)
    ]
    cmsg1 = (
        b"".join(_cbytes_ext(C) for C in coms_to_secrets + sum_nonconst)
        + b"".join(pops)
        + b"".join(pub_nonces)
        + _scalars_bytes(enc_sec_shares)
    )
    sum_coms = [sum_var(coms_to_secrets, secp256k1), *sum_nonconst]
    tweaked, _, _ = _taproot_tweak_var(sum_coms)
    eq_input = _eq_input(t, sum_coms, host_pub_keys, pub_nonces, enc_sec_shares)
    state = CoordinatorState(params, eq_input, _threshold_info_var(t, tweaked, n))
    return state, cmsg1


def coordinator_finalize(
    state: CoordinatorState, pmsgs2: Sequence[Octets]
) -> tuple[bytes, ThresholdInfo, bytes]:
    """Return the certificate, the threshold info and the recovery data.

    `pmsgs2` holds every participant's 64-byte second message, in the
    order of the host public keys. The certificate, 64*n bytes, goes to
    every participant for `participant_finalize`.
    """
    assert_type(state, CoordinatorState, "state")
    _assert_octets_sequence(pmsgs2, "pmsgs2")
    host_pub_keys = state.params.host_pub_keys
    if len(pmsgs2) != len(host_pub_keys):
        raise EccValueError("The pmsgs2 list must hold one message per participant.")
    cert = b"".join(bytes_from_octets(pmsg2, _SIG_SIZE) for pmsg2 in pmsgs2)
    i = _certeq_invalid(host_pub_keys, state.eq_input, cert)
    if i is not None:
        raise FaultyParticipantError(
            i, "Participant has provided an invalid signature for the certificate"
        )
    return cert, state.threshold_info, state.eq_input + cert


def coordinator_investigate_var(
    pmsgs1: Sequence[Octets], params: SessionParams
) -> list[bytes]:
    """Return each participant's investigation message, 65*n bytes.

    `pmsgs1` are the first messages `coordinator_step1_var` was given. A
    message holds no secret and may be broadcast.
    """
    host_pub_keys, _, parsed = _parse_pmsgs1_var(pmsgs1, params)
    return [
        _scalars_bytes([enc_shares[i] for _, _, _, enc_shares in parsed])
        + b"".join(
            _cbytes_ext(_pubshare_var(com, Public(i))) for com, _, _, _ in parsed
        )
        for i in range(len(host_pub_keys))
    ]


# --------------------------------------------------------------------
# Recovery
# --------------------------------------------------------------------


def _parse_recovery_data_var(
    data: bytes,
) -> tuple[int, list[Point], list[bytes], list[bytes], list[int], bytes]:
    """Return t, the summed commitment, keys, nonces, shares and cert."""
    if len(data) < _ID_SIZE:
        raise EccValueError("The recovery data is shorter than its threshold.")
    t = int.from_bytes(data[:_ID_SIZE], "big")
    rest = data[_ID_SIZE:]
    if len(rest) < PK_SIZE * t:
        raise EccValueError("The recovery data is shorter than its commitment.")
    sum_coms = _points_var(rest, t, "invalid commitment")
    rest = rest[PK_SIZE * t :]
    n, remainder = divmod(len(rest), 2 * PK_SIZE + _SCALAR_SIZE + _SIG_SIZE)
    if remainder:
        raise EccValueError("The recovery data is no whole number of participants.")
    host_pub_keys = _chunks(rest, PK_SIZE, n)
    rest = rest[PK_SIZE * n :]
    pub_nonces = _chunks(rest, PK_SIZE, n)
    rest = rest[PK_SIZE * n :]
    enc_sec_shares = _scalars(rest, n, "invalid encrypted secret share")
    cert = rest[_SCALAR_SIZE * n :]
    return t, sum_coms, host_pub_keys, pub_nonces, enc_sec_shares, cert


def _recover_public_var(
    data: bytes,
) -> tuple[ThresholdInfo, SessionParams, list[bytes], list[int], int]:
    """Return what anyone recovers, and what a participant decrypts with."""
    try:
        t, sum_coms, host_pub_keys, pub_nonces, enc_sec_shares, cert = (
            _parse_recovery_data_var(data)
        )
    except EccValueError as e:
        raise RecoveryDataError(_FAILED_TO_DESERIALIZE_ERR) from e
    params = SessionParams(host_pub_keys, t)
    try:
        _validate_params_var(params)
    except SessionParamsError as e:
        raise RecoveryDataError("Invalid session parameters in recovery data") from e
    if _certeq_invalid(host_pub_keys, data[: len(data) - len(cert)], cert) is not None:
        raise RecoveryDataError("Invalid certificate in recovery data")
    tweaked, tweak, _ = _taproot_tweak_var(sum_coms)
    info = _threshold_info_var(t, tweaked, len(host_pub_keys))
    return info, params, pub_nonces, enc_sec_shares, tweak


def participant_recover(
    host_sec_key: Octets, recovery_data: Octets
) -> tuple[bytes, ThresholdInfo, SessionParams]:
    """Return a participant's secret share, the threshold info and the params.

    From the recovery data of a session another party deemed successful,
    or from a backup of it on a new device.
    """
    data = bytes_from_octets(recovery_data)
    info, params, pub_nonces, enc_sec_shares, tweak = _recover_public_var(data)
    octets, q, host_pub_key = _host_key(host_sec_key)
    host_pub_keys = params.host_pub_keys
    participant_id = _host_index(
        host_pub_keys,
        host_pub_key,
        f"{_HOST_KEY_NOT_FOUND_ERR} in the recovery data",
    )
    pads = _decaps(
        q,
        octets,
        host_pub_key,
        pub_nonces,
        _enc_context(params.t, host_pub_keys),
        participant_id,
    )
    sec_share = (enc_sec_shares[participant_id] - sum(pads) + tweak) % _ORDER
    if _cbytes_ext(mult(sec_share, ec=secp256k1)) != info.pub_shares[participant_id]:
        raise RecoveryDataError(
            "The recovered secret share does not match its public share."
        )
    return sec_share.to_bytes(_SCALAR_SIZE, "big"), info, params


def coordinator_recover_var(
    recovery_data: Octets,
) -> tuple[ThresholdInfo, SessionParams]:
    """Return the threshold info and the params of a session's recovery data."""
    info, params, *_ = _recover_public_var(bytes_from_octets(recovery_data))
    return info, params


def _assert_recovery_data_matches_var(data: bytes, params: SessionParams) -> None:
    try:
        t, _, host_pub_keys, *_ = _parse_recovery_data_var(data)
    except EccValueError as e:
        raise RecoveryDataError(_FAILED_TO_DESERIALIZE_ERR) from e
    if t != params.t or tuple(host_pub_keys) != params.host_pub_keys:
        raise RecoveryDataError(
            "Recovery data does not match the provided session parameters"
        )


def _ack_message(data: bytes, participant_id: int) -> bytes:
    return _ACK_PREFIX + _id_bytes(participant_id) + data


def participant_recovery_ack_sign(
    host_sec_key: Octets,
    recovery_data: Octets,
    params: SessionParams,
    aux: Octets | None = None,
) -> bytes:
    """Return the 64-byte acknowledgment that a participant holds the data.

    `validate_recovery_acks` checks every participant's before the
    threshold public key is used. `aux` is BIP340's auxiliary randomness,
    drawn where it is None.

    The recovery data is a successful session's, as the reference asks:
    an acknowledgment says its signer holds these bytes, not that they
    rebuild the session, and neither function here checks the
    certificate. Recovery data received other than from
    `participant_finalize` or `coordinator_finalize` goes through
    `participant_recover` or `coordinator_recover_var` first.
    """
    assert_type(params, SessionParams, "params")
    _, q, host_pub_key = _host_key(host_sec_key)
    host_pub_keys, _ = _validate_params_var(params)
    participant_id = _host_index(host_pub_keys, host_pub_key, _HOST_KEY_NOT_FOUND_ERR)
    aux_ = _aux(aux)
    data = bytes_from_octets(recovery_data)
    _assert_recovery_data_matches_var(data, params)
    return ssa.sign_(_ack_message(data, participant_id), q, aux_).serialize()


def validate_recovery_acks(
    recovery_data: Octets, params: SessionParams, ack_sigs: Sequence[Octets]
) -> None:
    """Refuse unless every participant acknowledged the recovery data.

    `ack_sigs` holds each participant's acknowledgment, in the order of
    the host public keys. `InvalidRecoveryAckError` names the first that
    does not verify, and says what that leaves unconfirmed. The recovery
    data is what `participant_recovery_ack_sign` says it is.
    """
    assert_type(params, SessionParams, "params")
    host_pub_keys, _ = _validate_params_var(params)
    _assert_octets_sequence(ack_sigs, "ack_sigs")
    if len(ack_sigs) != len(host_pub_keys):
        raise EccValueError("The ack_sigs list must hold one per participant.")
    data = bytes_from_octets(recovery_data)
    _assert_recovery_data_matches_var(data, params)
    for i, ack_sig in enumerate(ack_sigs):
        sig = bytes_from_octets(ack_sig, _SIG_SIZE)
        if not ssa.verify_(_ack_message(data, i), host_pub_keys[i][1:], sig):
            raise InvalidRecoveryAckError(
                i, "Participant has provided an invalid recovery acknowledgment"
            )
