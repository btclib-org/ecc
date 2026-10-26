# Where the threshold lives

A bitcoin spend can require more than one party in two ways. They are
separate code paths, in separate packages: script multisig is btclib's,
MuSig2 and FROST are this package's, and the psbt transport of all of
them is btclib-wallet's. The numbers *k*, *t* and *n* do not tell the
two ways apart. What tells them apart is where the threshold is
enforced: in consensus, by every node, or in cryptography, settled
off-chain before the transaction exists.

## The discriminant

In script multisig the threshold is script policy, enforced by
consensus. The script holds *n* public keys, the input supplies *k*
signatures, and every node runs `OP_CHECKMULTISIG` — `OP_CHECKSIGADD` in
tapscript — and counts. Those *k* signatures are ordinary independent
signatures, each under its own key: the signers never talk to one
another, each signs alone, in any order, months apart.

In MuSig2 and in FROST the threshold is cryptography, off-chain.
Consensus knows nothing of it: it sees one key and one 64-byte BIP340
signature, exactly what a single-key spend presents. The group structure
is gone before the transaction exists.

## Where MuSig2 and FROST separate

They are two mechanisms, not two settings of one.

**MuSig2 aggregates independent keys.** Each signer holds its own secret
key and never shares it; the *n* public keys combine into one aggregate
key. All *n* have to take part, because there is nothing to interpolate:
the keys are not points of a polynomial, and a missing partial signature
is a sum that does not close.

**FROST shares one key.** There is a single threshold secret key,
Shamir-split into *n* shares, and nobody holds it whole. Any *t* of the
shares reconstruct, by Lagrange interpolation, not the key but the
signature.

So MuSig2 with a *t* smaller than *n* is not a configuration. It is a
different algorithm.

## What changes in practice

| | script multisig | MuSig2 | FROST |
| --- | --- | --- | --- |
| threshold enforced by | consensus | cryptography | cryptography |
| on chain | *n* keys, *k* sigs | one key, one sig | one key, one sig |
| signer interaction | none | two rounds | two rounds |
| secret keys | *n* independent | *n* independent | one, in *n* shares |
| who signed | in the input | not derivable | not derivable |
| membership change | new address | new aggregate key | same public key |
| bound on *n* | consensus | serialization | security |

### Cost and privacy

A 3-of-5 script spend reveals five public keys and three signatures, and
tells anyone watching that the output was a 3-of-5. MuSig2 and FROST
produce a spend indistinguishable from a single-key one, of constant
size, whatever *n* is.

### No consensus ceiling

`OP_CHECKMULTISIG` stops at `MAX_PUBKEYS_PER_MULTISIG` keys, which
btclib's `btclib.script.engine.script` enforces. A `multi_a()` leaf is
bounded by the stack instead, one element per key, which is what
`_MAX_PUBKEYS_PER_MULTI_A` in btclib-wallet's
`btclib_wallet.descriptors.miniscript` states; and a tapscript spend
charges its sigops budget 50 for every non-empty signature, whether or
not that signature verifies.

MuSig2 and FROST have no ceiling the chain imposes, the chain seeing one
key. What bounds them is the specification, and the two bounds are not
the same kind of thing. BIP327's is serialization: the number of
individual public keys is an unsigned 32-bit count. BIP445's is
security: it refuses an *n* past 128, and so does {py:mod}`ecc.ecc.frost`,
whose module docstring gives the reason.

### The price is state and simultaneity

Script multisig is stateless and has no shared nonce: a signer that is
compromised or offline does not touch the others. MuSig2 and FROST need
a nonce round before the partial signatures — so, signers available at
the same time — and above all a secret nonce that is never reused.
Reusing one does not degrade security, it hands out the key.
{py:func}`musig2.sign <ecc.ecc.musig2.sign>` and
{py:func}`frost.sign <ecc.ecc.frost.sign>` zero the two secret scalars
of the nonce they are handed as they read them, so a second call on the
same buffer raises rather than signing; their docstrings say how.

### Attribution

A script multisig input says which *k* of the *n* signed: it is an
audit trail. A MuSig2 or a FROST signature does not — privacy for some
uses, a gap for others, custody and internal delegation among them.

### Membership change

In script multisig, adding or removing a signer means a new script, a
new address, and moving the funds. MuSig2 sits in between: changing the
set changes the aggregate key. In FROST the group public key is a
property of the secret and not of how it is shared, so the same secret
can be shared again over a different set and the funds stay where they
are.

### Who has seen the secret

Script multisig has no phase in which anybody holds everything. FROST
has one wherever a trusted dealer distributes the shares: that dealer
transiently knows the whole key. Avoiding it takes a distributed key
generation, and {py:mod}`ecc.ecc.frost` takes key material already split
rather than splitting any;
btclib's [ISS 2200](https://github.com/btclib-org/btclib/issues/2200)
tracks key generation.

## *t* = *n* FROST is not MuSig2

BIP445's own vectors include a 3-of-3 group. That group is still not
MuSig2: one shared key against *n* independent keys aggregated, with
everything that follows from it about who has seen the secret and about
what a departing member costs.

## MuSig2 with *t* < *n*

Not natively, for the reason above. The two real routes are composition
rather than configuration.

**A taproot tree with one leaf per admitted subset.** Each leaf carries
a MuSig2 key over that subset alone, or a `multi_a()`. The cost is
combinatorial, C(*n*, *t*) leaves: three for a 2-of-3, 126 for a 5-of-9.
Only the leaf used is revealed, and the key path can stay the *n*-of-*n*
"everybody agrees", which is the cheap case. Workable for a small *n*,
senseless past it.

**Nesting with FROST.** A MuSig2 aggregate key can be one participant of
a FROST group, and a FROST group key can be one key inside a MuSig2
aggregation. That is how "either the board's 2-of-3 or the chief
executive" is expressed with one on-chain key.

## A FROST spend's psbt transport is btclib-wallet's own

BIP373 assigns MuSig2 psbt field types of its own — participant public
keys, a public nonce and a partial signature on an input, participant
public keys on an output — which `btclib_wallet.psbt.psbt_in` and
`btclib_wallet.psbt.psbt_out` carry and `btclib_wallet.psbt.musig2`
gives meaning to. They are MuSig2-specific and do not extend to a
threshold: a participants field would have to map a group key to its
*t*, its *n*, the identifiers and the public shares, rather than an
aggregate key to its participants; nonces and partial signatures would
be indexed by identifier rather than by a participant's public key; and
a session needs a field naming the subset that is signing it, for which
BIP373 has no counterpart, MuSig2's subset always being everybody. The
taproot tweaks are the same and carry over.

BIP445 specifies no psbt transport of its own, and no type bytes are
assigned for FROST: choosing bytes in the space BIP174 reserves for
future assignment is how two implementations collide. So
`btclib_wallet.psbt.frost` writes the session into the key space BIP174
reserves for proprietary use instead, under a btclib identifier. No
other wallet reads those records. That module's docstring says what
becomes of them when a psbt BIP assigns FROST type bytes.

## Where each of them lives

The two routes are both implemented, and they do not touch.

The script threshold is btclib's: the op codes `OP_CHECKMULTISIG` and
`OP_CHECKSIGADD` under `btclib.script`. btclib-wallet's
`btclib_wallet.descriptors.descriptors` holds the descriptor grammar
that writes one: `multi()` and `sortedmulti()` (BIP383), `multi_a()` and
`sortedmulti_a()` (BIP386, BIP387).

The cryptographic threshold is this package's:
{py:mod}`ecc.ecc.musig2` (BIP327) and {py:mod}`ecc.ecc.frost` (BIP445).
btclib-wallet's `btclib_wallet.psbt.musig2` (BIP373) and
`btclib_wallet.psbt.frost` carry a session of each through a psbt: the
first in the fields BIP373 assigns, the second in proprietary records of
btclib's own. MuSig2 also has a spelling in the descriptor grammar,
BIP390's `musig()` key expression, inside a `tr()` or a `rawtr()`;
FROST has none.

What they produce is not one object for all three.
{py:func}`musig2.partial_sig_agg <ecc.ecc.musig2.partial_sig_agg>` and
{py:func}`frost.partial_sig_agg <ecc.ecc.frost.partial_sig_agg>` each
answer an {py:class}`ecc.ecc.ssa.Sig`, the BIP340 signature
{py:mod}`ecc.ecc.ssa` verifies and so does every other BIP340 verifier.
A `multi_a()` leaf is checked against BIP340 signatures too, btclib's
tapscript engine calling {py:mod}`ecc.ecc.ssa` for them.
`OP_CHECKMULTISIG` is the one that differs: it verifies ECDSA, through
{py:mod}`ecc.ecc.dsa`.
