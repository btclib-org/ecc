# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/ecc/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to *security at btclib dot org* is
equally welcome.

A report is acknowledged within 7 days, and a fix or a published advisory
follows within 90 days.

A report triaged as easy to rediscover is fixed as soon as possible, since
anyone can find it in the meantime, and its advisory is published with the
fix.

## What belongs here, and what belongs upstream

secp256k1 arithmetic is delegated, where the optional bindings are
installed, to [btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1)
and through it to [libsecp256k1](https://github.com/bitcoin-core/secp256k1),
each with its own security policy. Not every call: one predicate decides,
from a process-wide dispatch switch, the curve, the hash function and the
caller's other choices, and a call site may add a condition on an input's
value. *Limitations, not vulnerabilities* below states each of them. Report a
flaw wherever you found it,
though: routing a report is the maintainers' job, not the reporter's,
and a doubt about which project owns a flaw is not a reason to keep it to
yourself.

What a refusal may print about a value that could be a key is the
organization's rule, [*A refusal carries no
secret*](https://github.com/btclib-org/.github#a-refusal-carries-no-secret).

## Security review

The latest security review is dated 2026-09-30.
[pmazzocchi](https://github.com/pmazzocchi) did it against the
[assurance case](./ASSURANCE_CASE.md), and
[issue 84](https://github.com/btclib-org/ecc/issues/84) records it.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

The same files are attached to the GitHub release, and those copies carry
a build provenance attestation of their own, signed in the run that built
them:

```shell
signer=btclib-org/.github/.github/workflows/reusable-build.yml
id=$(gh api repos/btclib-org/ecc --jq .id)
cert='.[].verificationResult.signature.certificate'
```

```shell
gh attestation verify <file> --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref refs/tags/v<version> --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
```

The exit code is `0` only where a verified attestation names this
repository. The repository is compared by its id, which a rename keeps:
`--repo` compares the current name and refuses every release signed
before a rename.

`<file>` is a distribution file from the release.

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has: the signing runs in
`btclib-org/.github`'s `reusable-build.yml`, which `release.yml` calls,
and `--source-ref` is what keeps a build of a branch from passing as the
release. A release made before that was signed by `reusable-attest.yml`,
named the same way, with the same `--source-ref`.

A CycloneDX bill of materials is attached beside them, generated from the
built wheel and covered by the same attestation. Either distribution file
can also be rebuilt from its tag and compared, the build being
reproducible: RELEASING.md has that command.

## Limitations, not vulnerabilities

These are known and inherent. They are worth stating because this
package is used to teach and to prototype as much as to build:

- secret material handed to this package lives in Python objects, which
    are immutable and not zeroized: it stays in the process memory until
    garbage collection, and may have been copied by the interpreter
    meanwhile. The constant-time properties of libsecp256k1 apply to the
    C side of the boundary, not to what happens before and after it
- **`musig2.nonce_gen` and `sign` stay on this arithmetic by decision,
    not merely by default** (btclib-org/btclib#1050). Delegating them
    would put `musig_nonce_gen`'s secnonce -- an opaque 132-byte struct
    the header calls "implementation defined and not guaranteed to be
    portable between different platforms or versions" -- into
    `ecc.ecc.musig2`'s public API. What it would buy is
    measured rather than assumed: the point-multiplication side is
    regular (btclib-org/btclib#254), and `sign`'s own line,
    `s = (k_1_ + values.b * k_2_ + values.e * a * d) % secp256k1.n`
    (`src/ecc/ecc/musig2.py:858`), spreads 1.016x over
    uniform scalars in `[1, n-1]` -- the magnitude leak that remains
    shows only for scalars with zero high bits, keys already lost for
    other reasons. The gain left is narrower than that figure suggests:
    delegating would only keep `k_1` and `k_2` from becoming Python
    `int`s, and the bullet above already covers why that does not decide
    anything -- `curves.scalar_from_prv_key` produces an unzeroizable
    `int` from the private key on the delegated path too.
    `btclib_secp256k1` itself takes the equivalent opaque handle for
    `musig_keyagg_cache` and `musig_session` without this reasoning
    landing on a different answer there: those have no octets form to
    begin with, where an `int` here already does the job. The same
    reasoning answers two more questions: this package grows no
    private-key class, because zeroization needs exactly the delegation
    declined above -- a class that hands out an `int` the moment anything
    uses it has a session object's ergonomics and none of its guarantee
    -- and curve arithmetic stays on `int` rather than `bytes`, `bytes`
    being immutable exactly like `int` while only `bytearray` zeroizes,
    and bignum arithmetic on a `bytearray` still allocating `int`
    intermediates at every step
- the bindings also let a caller own the buffer a secret is written
    into: a keyword-only `into=`, on the entry points that produce one.
    This package passes none, and that is a decision, not an oversight.
    `commit_nonce.commit_nonce_` reads one straight into a Python `int`
    at `int.from_bytes(tweaked, byteorder="big", signed=False)`
    (`src/ecc/ecc/commit_nonce.py:159`). A caller-owned buffer
    can be wiped once the call that filled it returns; the `int` it is
    read into cannot be, and outlives the call regardless, so taking the
    buffer there would cost a public signature and buy nothing, short of
    this package no longer holding a private key as a Python `int`, which
    is a change to that representation and not to a call site.
    `dsa.Signer.__init__` at `self._q.to_bytes(32, "big")`
    (`src/ecc/ecc/dsa.py:1482`) crosses the same boundary the
    other way, once, at construction: the plain `int`
    `scalar_from_prv_key` already produced becomes a transient `bytes` on
    the way into the owned buffer `wipe` overwrites afterwards. That
    `bytes` is dropped rather than erased, same as the `int` it replaces
    -- one call rather than the buffer's whole lifetime, which is the
    trade this class exists to make
- the boundary is not always there, and an install decides whether it
    is. `pip install "ecc[secp256k1]"` installs the bindings,
    and everything the next bullet says describes that installation.
    `pip install ecc` installs no C at all: signing,
    verification and key agreement all run the Python arithmetic the
    last bullet describes, which is tens of times slower and not
    constant-time. Nothing raises to say so, and
    `curves.is_libsecp256k1_serving()` is how a caller asks which of the
    two it has. The dispatch is a runtime switch besides:
    `curves.set_libsecp256k1_serving(serving=False)` turns it off for the
    whole process, and `ECC_NO_LIBSECP256K1` set in the
    environment makes that the state from the first call -- a test
    framework built on this package wants exactly that, having to check
    libsecp256k1 with something other than libsecp256k1. The variable
    is not a lock: any code in the process can turn the dispatch back on,
    so a framework that must not run on the bindings checks
    `curves.is_libsecp256k1_serving()` itself. With the
    dispatch off, every operation named below is the Python arithmetic,
    whichever way the package was installed
- a call the bindings decline runs the Python arithmetic and says
    nothing, unless the caller asks to be refused instead:
    `curves.set_libsecp256k1_serving(serving=True, required=True)`. A call
    on secp256k1 that the bindings decline for something the caller chose
    -- a hash function that is not `hashlib.sha256` itself, a nonce of
    its own, a commitment, `lower_s=False`, a MuSig2 session with an
    adaptor -- then raises `EccRuntimeError`. What is not a choice
    still runs the Python arithmetic: another curve, the point at
    infinity, a message length the bindings have no call for. `required`
    needs `serving=True`, and each call of the setter sets it afresh, so it
    is False unless passed. A `dsa.Signer` built while the bindings were
    off, or with an `hf` they decline, signs on the Python arithmetic, but
    raises under `required` once they would serve it, or while they
    decline its `hf`
- not every operation crosses that boundary, and one predicate decides
    whether it can: `curve._libsecp256k1_serves` asks for the switch
    above, then for secp256k1 as the curve, then for a hash function
    that is sha256 or absent -- it declines
    `hf is not None and hf is not sha256`
    (`src/ecc/curves/curve.py:697`) -- with whatever further
    options the call site passes it. The hash function is matched
    by identity rather than by what it computes, so
    `functools.partial(sha256)`, or any other wrapper a caller writes to
    fit an interface, is one the predicate declines, and the call it is
    passed to runs the Python arithmetic -- conservative for the
    arithmetic, silent for the caller unless the bindings are required
    (above). The condition each operation below
    states as sha256 is that identity.
    `mult`, `double_mult_var` and `multi_mult_var` reach the bindings for
    secp256k1 and any point of it, the point at infinity excepted --
    libsecp256k1 has no public key for it; a zero scalar, which it has no
    scalar for, is excepted by the two `_var` ones and multiplied as one
    by `mult`, whose answer is then infinity; `dsa.sign` for secp256k1
    with sha256, the lower-s form, no caller-imposed nonce and no
    commitment; `ssa.sign` for secp256k1 with sha256, a message of any
    size and no commitment; `dh.diffie_hellman`,
    `commit_nonce.commit_nonce_`, `curves.prv_key_tweak_add` and
    `ssa.prv_key_tweak_add` for secp256k1, the shared point of a key
    agreement, the tweaking of a sign-to-contract nonce and the tweaking of
    a private key being other places a secret meets the curve.
    Verification crosses it whole, not only in its multiplication:
    `dsa.verify` and `ssa.verify` are one libsecp256k1 call each, where
    the dispatch is on, for secp256k1 with sha256, a high-s signature
    being normalized first where the lower-s form is not being enforced.
    Batch verification is the exception, libsecp256k1 having no call for
    it, so `ssa.batch_verify` is the Python equation over delegated
    multiplications. `musig2.partial_sig_verify_` is a narrower
    delegation again, of one MuSig2 round-two check rather than of every
    operation the module offers (btclib-org/btclib#1049): for secp256k1,
    sha256, a 32-byte message and a session with no adaptor.
    `musig_nonce_process` takes a fixed 32-byte `msg32` with no length
    parameter, so a message of any other size runs the Python equation
    below regardless of the bindings, as does a session carrying the
    adaptor extension `ecc.ecc.musig2` implements and the
    bindings do not. Under `required` such a session raises instead.
    `key_agg_var`, `key_sort` and `nonce_agg_var` stay Python's
    alone either way: measured too close to the delegated arithmetic they
    already call, or run once per session rather than once per signer,
    to earn a second code path. This paragraph is about a secret meeting
    the curve and verification holds none, which is why it is named here
    only to say that the sentence below is not about it.
    A signature the bindings decline is not all Python for that:
    `dsa.gen_keys` and the nonce point of `dsa._sign_` go through `mult`,
    and the verification equation of both `dsa` and `ssa` through
    `double_mult_var`, so those multiplications are delegated whatever
    else the signature asks for. The rest of that signature is not --
    the inversion of the nonce and the arithmetic on the key around it
    are Python integers. That inversion is blinded, as every inversion
    of a secret in the package is: `mod_inv` draws a random factor, so
    that the extended Euclid's iteration count follows
    the factor rather than the nonce. Unblinded it followed the nonce's
    bit-length -- roughly twice the cost for a 256-bit scalar as for a
    128-bit one on secp256k1's order -- which is the correlation the
    Minerva attack turns into the private key.
    Whatever the predicate above and a call's own conditions decline
    runs the Python implementation, whose scalar multiplication is a
    double-and-add in Jacobian coordinates: it is validated against the
    bindings, which are the authority on the answer, but it is not
    constant-time. It tries, which is not the same claim. The Jacobian
    group law neither branches on the point at infinity nor lets it reach
    the arithmetic: a full-size stand-in takes its place and a table
    answers for it, because a Python integer costs what its size costs
    and the zero coordinates of infinity would time the case as well as a
    branch would. That is the case that matters, infinity being the
    identity and so the accumulator every multiplication starts from and
    the multiple a zero digit names: an addition of it costs what any
    other addition costs, and a multiplication takes the same time
    whatever the bits of the scalar. Two points that coincide, or that
    are opposite, do still branch -- that case needs the accumulator to
    land on a table entry, 2^-250 on a curve with a real order, and a
    caller spelling out `P + P` knows it did.
    Nor does the scalar decide how many additions there are, or how many
    windows: `mult` recodes it into signed odd digits, none of them zero
    and always `ceil(nlen / w)` of them, and starts the accumulator at a
    table entry rather than at the identity, so every scalar of the curve
    costs the same additions and the same doublings, and its size is
    hidden as its bits are. The plain fixed window is the contrast: its
    digits are `ceil(m.bit_length() / w)` of them, so a scalar short of a
    full top window costs one window less there and its size is what the
    count shows. On secp256k1, whose endomorphism halves the doublings,
    the regular windows of its decomposition are uniform the same way.
    The interleaved wNAFs of that same decomposition add on a nonzero
    digit and so once per unit of the recoded weight of the coefficient,
    which is why they are not what `mult` reaches for; they are what
    `double_mult_var` and signature verification reach, where the
    coefficients are a signature and a message hash rather than a secret.

    What is left is out of reach from pure Python, and is enough to
    matter: the windowed multiplications index a table of precomputed
    multiples with a secret digit, which is the memory access pattern the
    FLUSH+RELOAD recovery of OpenSSL's nonces read; every reduction and
    multiplication takes the time its operand sizes ask for, and a
    residue is not always the full size; the affine group law spends a
    modular inverse, an extended Euclid whose iteration count follows its
    input, and so does the conversion back from Jacobian coordinates --
    that one on a Z coordinate `_blinded_jac` has randomized, which is
    why it is named here as a cost and not as a channel; and
    `multi_mult_var` is Bos-Coster, whose shape is the scalars
    themselves. The `gmpy2` extra hands the Jacobian group law and its
    inverses to GMP, and changes none of this: gmpy2 calls GMP's `mpz`
    functions, and the GMP manual's [*Low-level functions for
    cryptography*](https://gmplib.org/manual/Low_002dlevel-Functions)
    names only its `mpn_sec_` and `mpn_cnd_` functions as written for
    side-channel resistance. Using the Python arithmetic on key material
    that matters is a choice, and this is the notice of it
- **the delegated multiplication of a point that is not the generator is
    constant time in its scalar where the multiplication is `mult`'s, and
    variable time where it is a `_var` one's.** `mult` reaches
    libsecp256k1 through `secp256k1_ecdh`, whose multiplication is
    `secp256k1_ecmult_const`, constant time in its scalar;
    `ecdh.shared_point` of the bindings is that call answering the point
    rather than a hash of it. The arm `curves.curve.mult` shares with
    `PreparedPoint.mult` asks for the predicate above, with no hash
    function, so the switch and the curve are the whole of what the
    predicate asks; a zero reduced scalar is multiplied as one and the
    product dropped, the substitution `secp256k1_ec_pubkey_create` and
    `secp256k1_ecdh` make for a key they refuse, so a zero is not told
    apart by the arm it takes; the generator is a different call inside
    that arm and infinity is not delegated at all --
    `curve._libsecp256k1_mult` at
    `libsecp256k1_shared_point(_sec_from_point(Q), m, False)`
    (`src/ecc/curves/curve.py:969`). `dh.diffie_hellman` at
    `sec = libsecp256k1_shared_point(`
    (`src/ecc/ecc/dh.py:119`) and `sec_point._mult_sec` at
    `libsecp256k1_shared_point(sec, m, False)`
    (`src/ecc/curves/sec_point.py:434`), under
    `sec_point.mult_pub_key` and `ecies.derive_keys`, make the same call
    on the octets they already hold.
    `double_mult_var` and `multi_mult_var`, and `ssa.batch_verify`, are
    the other call: `keys.pubkey_tweak_mul_sum`, one
    `secp256k1_ec_pubkey_tweak_mul` per term, which runs
    `secp256k1_ecmult`, whose windowed NAF holds at most one more digit
    than the scalar has bits -- so the work follows the scalar rather
    than the order of the curve, which is what their suffix says. A
    verification's scalars are public; a secret handed to them is timed
    by them all the same, so a Pedersen commitment rG+v*gen, whose two
    scalars are secrets, is a `mult` of each and their sum instead --
    `pedersen._commit` at
    `return _add(mult(r, ec.G, ec), mult(v, gen, ec), ec)`
    (`src/ecc/ecc/pedersen.py:382`), under `pedersen.commit`,
    `rangeproof.sign` and `rangeproof.rewind`. The sum is `curve._add` at
    `return _libsecp256k1_sum((P, Q))`
    (`src/ecc/curves/curve.py:1430`):
    `secp256k1_ec_pubkey_combine`, whose group law
    `secp256k1_gej_add_ge` and whose inversion `secp256k1_fe_inv` are
    constant time. A commitment to a zero value has a product at
    infinity, which `_add` does not hand over: it sums the other term
    with itself and drops the answer, so the crossing is made for a zero
    as for any other value.
    `pedersen.generator_from_seed` treats its seed and its blinding
    factor as secrets, as libsecp256k1-zkp does: its blind*G is `mult`
    and its sums are `_add`, and the map its seed goes through is Python
    on either arm, forming the same roots for every seed.
    The other delegations the bullet above names are different calls:
    a multiple of the generator is `secp256k1_ec_pubkey_create`, which
    runs `secp256k1_ecmult_gen`; the tweaking of a sign-to-contract nonce,
    and `curves.prv_key_tweak_add`, are `secp256k1_ec_seckey_tweak_add`,
    which adds scalars; and `ssa.prv_key_tweak_add` is
    `secp256k1_keypair_xonly_tweak_add`, which negates the key where its
    point has an odd y before adding. It does not treat the tweak as a
    secret, and `src/ctime_tests.c` marks it defined before that call.
    These calls and `secp256k1_ecdh` are
    among the entry points libsecp256k1's own `src/ctime_tests.c`
    declassifies a secret for, and
    `secp256k1_ec_pubkey_tweak_mul` is named nowhere in that file
- `rangeproof.rewind` on the Python arm takes time that depends on the value
    it recovers: `rangeproof._value_encoding_var` at
    `return position, int.from_bytes(tmp[24:32], "big")`
    (`src/ecc/ecc/rangeproof.py:1599`) returns early, at a position
    set by a digit of that value, which its `_var` suffix says
- a sign-to-contract commitment is the signer's to open, and opening it
    twice over one message is safe only because the committed value
    reaches the nonce derivation: that is what keeps two such signatures
    from sharing an untweaked nonce and handing out the key. The
    derivation is `ecc.ecc.commit_nonce`, and the property is
    worth knowing about for anyone building on it the anti-exfil
    protocol, which `dsa` and `ssa` carry as `anti_exfil_*`: there, the
    ordering matters as well -- the signer must publish its `R` before
    learning the host's randomness, and `sign` alone cannot enforce that
- randomness comes from the operating system through the `secrets`
    module: the auxiliary randomness of BIP340 signing and the private
    keys of the key generation helpers. Nothing here seeds a generator
    of its own
- `ecc.ecc.ecies` ships no block cipher and takes AES-128-CBC
    as two callables, so the cipher's own resistance to timing and
    side-channel attack is whatever the caller passed in -- this package
    neither provides it nor can check it. That is the point of the
    parameter rather than a gap in it: a pure-Python AES here would be
    table-driven and would leak its key through cache timing, and the
    caveat above about the Python curve arithmetic is exactly the one
    this design refuses to add a second of. The MAC is verified before
    the cipher is called, and compared with `hmac.compare_digest`, so
    what this package does with the envelope does not depend on the
    secret byte by byte; a caller wanting the same of the decryption
    should bring a cipher that gives it
