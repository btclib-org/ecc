# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module ecc.ecc.

**The schemes.** ecc.ecc holds what is built *on* an elliptic curve:
dsa, ssa and borromean signatures, the MuSig2 aggregation of many
ssa signers into one, the FROST threshold signing in which a subset of
a group sharing one key signs for all of it, the DahLIAS aggregate
signature of many signers over their own messages, pedersen commitments, the
Confidential Transactions rangeproof built over one and the rewind that
reads a value, a blinding factor and a message back out of it, the
Diffie-Hellman key agreement, the BIE1 ECIES built on top of it, the
ElligatorSwift encoding of a public key, the ECDSA adaptor signatures of
the DLC specification, the
BIP340 signatures of a DLC oracle with a nonce committed in advance, the
single-signer BIP340 adaptor signatures, the BIP458 half-aggregation of
BIP340 signatures, the
BIP374 proof that two points share one discrete logarithm, and the
RFC6979, BIP340 and sign-to-contract nonces. The curve arithmetic underneath is
ecc.curves, and the rule between the two is that direction: ecc.ecc
imports ecc.curves, never the other way round. The key derivation functions
the agreement uses are ecc.kdf: a KDF is a hash construction with no
curve in it, and its own module says why it is not here.

The two names are easy to conflate -- everything here is also about curves -- so
the anchor is worth stating: `from ecc.curves import mult`, `from
ecc.ecc import dsa`.

The schemes are what this package is for, so ``__all__`` names them and
the import below binds each as a package attribute: without it, `import
ecc.ecc` followed by `ecc.ecc.dsa.sign(...)` would raise
AttributeError until something else in the process happened to import the
submodule, and the package would advertise the loose helpers alone
instead of the schemes behind them.

The three nonces are named the same way, as modules. A nonce derivation
is a scheme of its own -- RFC6979 has test vectors, BIP340's auxiliary
randomness is part of the signing standard, and sign-to-contract has its
commitment and its opening -- so `ecc.ecc.rfc6979_nonce` is the
spelling, as `ecc.ecc.dsa` is.

What is *not* here is a module's own functions, plain or prepared:
`dsa.sign` and `dsa.sign_` are both in `dsa.__all__` and neither is in
this one, and nor are `musig2.key_agg_var`, `ecies.encrypt` or
`ellswift.decode_var`. The loose helpers ``__all__`` names above are the whole
of the exception. So the trailing underscore is no part of the
decision, and for some names there is no decision to make: dsa and ssa
both define `sign_`, `verify_` and `assert_as_valid_`, ssa and
rfc6979_nonce both define `challenge_`, and a package-level export of
any of them would collide -- as one of `sign` or of `gen_keys` would,
each defined by more than one of these modules.

**Secrets.** This is the package a private key is handed to, and what
holds around it is conditional. What decides whether an operation here
is one libsecp256k1 call is `curves.curve._libsecp256k1_serves` -- the
process-wide dispatch switch, the curve and the hash function -- with
a caller's choices that the bindings do not take passed to it as keywords,
and a condition on an input's value and-ed on by the call site; whatever
that declines runs the Python arithmetic, which the suite validates against
the bindings but which is not constant-time. Nor is a Python object
holding a secret zeroized, on either path. SECURITY.md's limitations
section states each condition, argument by argument, and README.md
carries the short form.
"""

from ecc.ecc import (
    bip340_nonce,
    borromean,
    commit_nonce,
    dahlias,
    dh,
    dlc_oracle,
    dleq,
    dsa,
    ecdsa_adaptor,
    ecies,
    ellswift,
    frost,
    musig2,
    pedersen,
    rangeproof,
    rfc6979_nonce,
    ssa,
    ssa_adaptor,
    ssa_halfagg,
)
from ecc.ecc.dh import diffie_hellman
from ecc.ecc.pedersen import second_generator

__all__ = [
    "bip340_nonce",
    "borromean",
    "commit_nonce",
    "dahlias",
    "dh",
    "diffie_hellman",
    "dlc_oracle",
    "dleq",
    "dsa",
    "ecdsa_adaptor",
    "ecies",
    "ellswift",
    "frost",
    "musig2",
    "pedersen",
    "rangeproof",
    "rfc6979_nonce",
    "second_generator",
    "ssa",
    "ssa_adaptor",
    "ssa_halfagg",
]
