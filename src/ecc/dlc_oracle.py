# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""DLC oracle signatures: BIP340 with a nonce committed in advance.

https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md

A DLC oracle announces the x-only point R = k*G of a nonce k before an
event, and signs the outcome with k once the event happens. The
signature is an ordinary BIP340 one, which `ssa.verify_` accepts.
Before the oracle signs, anyone holding its public key and R computes
the signature point s*G of each possible outcome with `sig_point_var_`, and
a DLC encrypts each outcome's transaction under it.

**A nonce signs one message.** Two signatures with one k reveal the
private key. That is why `sign_` lives here and not in `ssa`, whose
signers derive their nonce: a BIP340 signature that is not an oracle's
is `ssa.sign_`'s.

**The message** is BIP340's, of any size, signed as it is. The
specification's tagged hash of an outcome is the caller's to compute.
The curve, secp256k1, and the hash, sha256, are not arguments, as in
`ecc.ecdsa_adaptor`.

**Timing.** The key and the nonce go through `mult` and integer
products, as in `ssa`'s Python path; what `sig_point_var_` handles is
public and uses the `_var` arithmetic. Python here is not constant-time.
"""

from __future__ import annotations

from hashlib import sha256

from ecc import ssa
from ecc._utils import bytes_from_octets
from ecc.alias import Integer, Octets, Point, Public
from ecc.curves import double_mult_var, scalar_from_prv_key, secp256k1

__all__ = [
    "sig_point_var_",
    "sign_",
]


def sign_(msg: Octets, prv_key: Integer, nonce: Integer) -> ssa.Sig:
    """Return the BIP340 signature of msg with the caller's nonce.

    A nonce whose point has odd y is negated, as BIP340 negates its
    own, so the signature's r is the x-coordinate of nonce*G either way.
    The signature is verified before it is returned.

    Never sign two messages with one nonce: it reveals the private key.
    """
    msg = bytes_from_octets(msg)
    q, x_Q = ssa.gen_keys(scalar_from_prv_key(prv_key))
    k, x_K = ssa.gen_keys(scalar_from_prv_key(nonce))
    c = ssa.challenge_(msg, x_Q, x_K, secp256k1, sha256)
    sig = ssa._sign_(c, q, k, x_K, secp256k1)
    return ssa._checked_sign_(Public(c), sig, Public(x_Q), secp256k1, True)


def sig_point_var_(
    msg: Octets, pub_key: ssa.BIP340PubKey, pub_nonce: ssa.BIP340PubKey
) -> Point:
    """Return s*G for the signature of msg that pub_nonce commits to.

    s*G = R + c*P, with P and R the even-y points of pub_key and
    pub_nonce and c the BIP340 challenge: it needs no secret, and equals
    s*G for the s that `sign_` returns with the nonce of R.
    """
    msg = bytes_from_octets(msg)
    P = ssa.point_from_bip340pub_key_var(pub_key)
    R = ssa.point_from_bip340pub_key_var(pub_nonce)
    c = ssa.challenge_(msg, P[0], R[0], secp256k1, sha256)
    return double_mult_var(Public(c), P, Public(1), R)
