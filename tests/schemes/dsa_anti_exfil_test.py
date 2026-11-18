# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the ECDSA anti-exfil protocol of `ecc.dsa`.

BlockstreamResearch/secp256k1-zkp's `secp256k1_ecdsa_s2c.h` specifies the
handshake, and the draft anti-exfil BIP, AvilaLabs/anti-exfil's
`spec/bip-anti-exfil.md`, specifies it again with a base nonce of its
own. `tests/schemes/anti_exfil_vectors_test.py` holds this package to the
draft's vectors; this file runs the handshake against itself.
"""

from hashlib import sha1, sha256
from typing import Any

import pytest

from ecc import dsa
from ecc.commit_nonce import commit_nonce_
from ecc.curves import mult, secp256k1
from ecc.exceptions import EccValueError
from ecc.rfc6979_nonce import challenge_, rfc6979_nonce_
from tests import both_arms

_PRV_KEY = bytes.fromhex("55" * 32)
_PUB_KEY = dsa.gen_keys(_PRV_KEY)[1]

# rho is a constant because a test has to be reproducible; a host draws
# it from a cryptographically secure generator, which is what the
# protocol asks of it and the one thing a test cannot check
_HANDSHAKE_MSG_HASH = sha256(b"to be signed").digest()
_RHO = sha256(b"the host's randomness").digest()
_OTHER_RHO = sha256(b"a second draw").digest()


def test_the_whole_handshake() -> None:
    """The five steps, in order, and then what each of them refuses."""
    # 1. the host draws rho and commits to it
    commitment = dsa.anti_exfil_host_commit(_RHO)
    # 2. the device answers with the point its nonce will have
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    # 3. the host reveals rho
    # 4. the device signs, committing to it
    sig = dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, _RHO)
    # 5. the host checks the signature against that R and its own rho
    assert dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _RHO, R)
    assert dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, sig.serialize(), _RHO, R
    )

    # an ordinary ECDSA signature, which is the whole point: nothing on
    # the chain says the nonce was negotiated
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig)
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig.serialize())

    # not against another message, another rho, or another R
    assert not dsa.anti_exfil_host_verify(
        sha256(b"another message").digest(), _PUB_KEY, sig, _RHO, R
    )
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _OTHER_RHO, R
    )
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH,
        _PUB_KEY,
        sig,
        _RHO,
        secp256k1.add_var(R, secp256k1.G),
    )

    # nor the malleated twin, which shares r and so opens the commitment, and
    # which plain verification accepts: `anti_exfil_host_verify` says why the
    # host refuses it all the same
    malleated = dsa.Sig(sig.r, sig.ec.n - sig.s)
    assert malleated.s > secp256k1.n // 2
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, malleated)
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, malleated, _RHO, R
    )
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, malleated.serialize(), _RHO, R
    )


@both_arms
def test_ordinary_signing_does_not_reach_the_base_nonce() -> None:
    """No ordinary signing nonce has the R of step 2, given the commitment.

    The draft's *Key separation* section asks this. `sign_` takes no
    extra entropy, so the commitment goes to RFC6979 as
    `rfc6979_nonce_`'s extra entropy, and to `sign_` as the value to
    commit to, and rho with it.
    """
    n = secp256k1.n
    for i in range(8):
        rho = sha256(i.to_bytes(1, "big")).digest()
        commitment = dsa.anti_exfil_host_commit(rho)
        R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
        nonce = rfc6979_nonce_(_HANDSHAKE_MSG_HASH, _PRV_KEY, extra_entropy=commitment)
        assert mult(nonce)[0] != R[0]
        assert dsa.sign_(_HANDSHAKE_MSG_HASH, _PRV_KEY).r != R[0] % n
        for value in (commitment, rho):
            _, receipt = dsa.sign_(
                _HANDSHAKE_MSG_HASH, _PRV_KEY, grind=False, commit_hash=value
            )
            assert receipt[0] != R[0]


def test_one_message_reaches_the_challenge_and_the_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A message hash changed during step 4 does not split the signature.

    The challenge and the nonce are derived from one copy of the message
    hash, so a caller's bytearray changed between the two reaches neither.
    """
    commitment = dsa.anti_exfil_host_commit(_RHO)
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    msg_hash = bytearray(_HANDSHAKE_MSG_HASH)

    def changing(*args: Any) -> int:
        c = challenge_(*args)
        # the caller's copy changes once the challenge has read it
        msg_hash[0] ^= 1
        return c

    monkeypatch.setattr("ecc.dsa.challenge_", changing)
    sig = dsa.anti_exfil_sign(msg_hash, _PRV_KEY, _RHO)
    assert dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _RHO, R)


def test_the_largest_low_s_is_accepted_and_the_next_is_refused() -> None:
    """The largest low s, n // 2, passes step 5, and its twin does not.

    Both pass `verify_`, so only the low-s bound tells them apart. The
    draft's `ecdsa-reject-s-half-plus-one` has the next s on a tuple that
    `verify_` refuses already. This builds the twins from a nonce of its
    own, tweaked by rho as step 4 tweaks it, and the message hash that
    makes s the bound.
    """
    n = secp256k1.n
    # the tag `dsa` tweaks its sign-to-contract nonce with
    nonce, R = commit_nonce_(_RHO, 11, b"s2c/ecdsa/point")
    r = mult(nonce)[0] % n
    q = int.from_bytes(_PRV_KEY, "big")
    msg_hash = ((n // 2 * nonce - r * q) % n).to_bytes(32, "big")
    low = dsa.Sig(r, n // 2)
    high = dsa.Sig(r, n // 2 + 1)
    assert high.s == n - low.s
    assert dsa.verify_(msg_hash, _PUB_KEY, low)
    assert dsa.verify_(msg_hash, _PUB_KEY, high)
    assert dsa.anti_exfil_host_verify(msg_hash, _PUB_KEY, low, _RHO, R)
    assert not dsa.anti_exfil_host_verify(msg_hash, _PUB_KEY, high, _RHO, R)


def test_the_signer_keeps_no_state() -> None:
    """A rho that does not match the commitment fails step 5, and only that.

    The device does not remember the commitment it answered step 2 with,
    and does not have to: it re-derives one from whatever rho arrives.
    A host that reveals something else gets a valid signature over an R
    that is not the R it holds, so step 5 says no -- and because that R
    belonged to the commitment it came from, no nonce was reused and the
    key was never what was at stake.
    """
    commitment = dsa.anti_exfil_host_commit(_RHO)
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)

    # step 3 reveals the wrong value; step 4 signs it all the same
    sig = dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, _OTHER_RHO)
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig)
    assert not dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _RHO, R)

    # and what it does open under is the R of the rho it was given, a
    # point the host never saw
    other_R = dsa.anti_exfil_signer_commit(
        _HANDSHAKE_MSG_HASH, _PRV_KEY, dsa.anti_exfil_host_commit(_OTHER_RHO)
    )
    assert other_R != R
    assert dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _OTHER_RHO, other_R
    )


def test_a_restart_takes_the_same_rho() -> None:
    """Step 2 is a function of its arguments, so the host's check bites.

    Restarting with the same rho must reach the same R, or the host has
    nothing to compare and a device could bias the nonces it lets
    through by aborting selectively. Restarting with a fresh rho reaches
    a different R, which is why the protocol asks for the old one.
    """
    commitment = dsa.anti_exfil_host_commit(_RHO)
    assert dsa.anti_exfil_host_commit(_RHO) == commitment
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    assert dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment) == R

    redrawn = dsa.anti_exfil_host_commit(_OTHER_RHO)
    assert redrawn != commitment
    assert dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, redrawn) != R


def test_rho_and_the_commitment_are_hf_len() -> None:
    """The sizes follow hf, and the two signing steps refuse any other.

    Not decoration: rho is what the device cannot predict, and a host
    drawing four bytes of it hands the device a value to guess and grind
    against. Refused where it is drawn and where it is signed with;
    `anti_exfil_host_verify` answers False instead, verify never raising
    over what is merely an input the signature does not match.
    """
    short = b"\x00" * 31
    with pytest.raises(EccValueError, match="invalid size"):
        dsa.anti_exfil_host_commit(short)
    with pytest.raises(EccValueError, match="invalid size"):
        dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, short)
    with pytest.raises(EccValueError, match="invalid size"):
        dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, short)

    commitment = dsa.anti_exfil_host_commit(_RHO)
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    sig = dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, _RHO)
    assert not dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, short, R)

    # hf is the one that says what the sizes are, all the way through:
    # the 20 bytes below reach step 5 and the 32 above would not, each
    # step measuring against the hf it was handed
    msg_hash = sha1(b"to be signed").digest()  # noqa: S324
    rho = sha1(b"the host's randomness").digest()  # noqa: S324
    commitment = dsa.anti_exfil_host_commit(rho, sha1)
    with pytest.raises(EccValueError, match="invalid size"):
        dsa.anti_exfil_signer_commit(msg_hash, _PRV_KEY, _RHO, secp256k1, sha1)
    R = dsa.anti_exfil_signer_commit(msg_hash, _PRV_KEY, commitment, secp256k1, sha1)
    sig = dsa.anti_exfil_sign(msg_hash, _PRV_KEY, rho, True, secp256k1, sha1)
    assert dsa.anti_exfil_host_verify(msg_hash, _PUB_KEY, sig, rho, R, sha1)
