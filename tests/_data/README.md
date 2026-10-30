# Vendored test vectors

This file is about `tests/**/_data/`, and about the one test module that
carries its vectors inline, `tests/schemes/dsa_anti_exfil_test.py`.

Upstream prose that this package *paraphrases* has no entry here: a
BIP's reasoning, a Core comment, a C library header's rationale are
cited in the docstring or the comment that paraphrases them, and a
paraphrase admits no byte comparison, so there is nothing for the weekly
job to ask. What such a citation carries is decided by what it names. A
file needs no revision -- the repository and the path keep their names,
and a reader who opens it reads the reasoning upstream holds now, which
is what a paraphrase sends them for -- and `ecc.ecc.dsa`'s
anti-exfil docstrings cite `include/secp256k1_ecdsa_s2c.h` of
BlockstreamResearch/secp256k1-zkp that way. A line needs one: a line
number is the one thing that moves under a file that keeps its name, so
without a revision the citation degrades into pointing at whatever now
occupies it.

Where every file under a `tests/**/_data/` directory came from, and
whether our copy still matches it. The test modules already cite their
sources, but against `master`: a citation like
`bips/blob/master/bip-0340/test-vectors.csv` names a file that changes
under us and says nothing about the revision we copied. Here each
citation is pinned to a commit and the two blobs are compared.

Nothing in this file is a mirror of the citations in the test modules.
Those say what a vector *is*; this says which revision of it we hold --
and for the transcribed ones the answer is "no revision of it, byte for
byte", which the verdict then accounts for.

The two halves are kept in agreement in one direction only: a test module
names its upstream and points here for the revision, and this file does
not restate what a vector tests. A citation that names the wrong upstream
is corrected in the module; this file is not where that correction lives.

## Naming

A vendored file carries the name its upstream publishes it under, wherever
upstream publishes a file at all. That is not cosmetic: a name of our own
has no upstream name to be compared against, so the citation in the module
that loads it can drift to a path upstream never had and nobody catches
it -- the byte comparison below is the only check the naming cannot fool.

The files that keep a name of their own do so deliberately, and the reason
is the same in each: there is no upstream file whose name they could take

- `rfc6979.json` is transcribed from prose: no upstream file, so no
  upstream name to take.
- `WYCHEPROOF_COPYING` is upstream's `LICENSE`, renamed because a file
  of that name inside a directory of vendored vectors would read as
  licensing all of them. Its entry says so, and carries the upstream
  name.

## Reading an entry

Where an entry pins to a commit, it gives the upstream repository, the
path in it, and the commit. A `blob` line, where the entry carries one,
gives the git blob SHA-1 of what that entry pins; what it pins, and
whether it was compared byte for byte, is the entry's own to say. An
`ours` line gives the blob of the file kept here where that is not the
`blob`, or where the entry has no upstream blob to name: a file with its
line endings or trailing newline changed, a transcription, a set derived
from a directory. The weekly job holds the file to `ours`, or to `blob`
where there is no `ours`. Most
entries close on a verdict; one with nothing upstream to compare
against says so in prose instead. The verdicts used:

- **identical** -- our file and the upstream blob are the same bytes.
- **reformatted** -- same parsed JSON value, different whitespace.
- **transcribed** -- there is no file compared byte for byte. Over prose
  (a BIP, an RFC) the check is that every value in our copy appears
  verbatim in the pinned text; over a source file the check is the
  entry's own to state.
- **composed locally**, **recorded** -- there is nothing upstream to
  compare, so the entry says what stands in for one. *composed locally*
  is a case written for this suite, naming the third implementation
  that answered it; *recorded* is one reply a program gave, kept
  verbatim, naming the program and the calls that ask it again.

A case of this package's own is written in the test module that reads
the file, never inside the file, so refreshing a pin is a fetch and never
a merge.

`pulled` is the date of the commit that added the file, and `refreshed`
the date of each later commit that changed its bytes. Each is the
committer date of a commit on the default branch, listed by
`git log --follow --raw --format='%h %cd' --date=short origin/main -- <path>`.
A commit whose `--raw` line keeps the blob, a rename, is neither. Where
`--follow` goes on past a copy (`C`) into another file's history, the
copy is the commit that added this one. A file this repository's first
commit carried came over from btclib-org/btclib, whose history this
repository does not carry: its earlier dates are read in that
repository's log, against the file's path under `tests/`. That first
commit is a `refreshed` date only where it changed the bytes.

`behind` counts upstream revisions of that path since the pin. It is a
staleness figure, not a defect: a vector file is a fixed set of cases and
refreshing it is a decision, not a chore.

`ref` names the branch a pin's path lives on, where that is not the
repository's own default branch.
`.github/scripts/check_vendored_vectors.py` reads it as the `sha`
parameter of GitHub's "commits touching a path" API, which otherwise
walks the default branch alone and finds no commit touching a path that
only exists elsewhere, reported as a path the default branch never held
regardless of whether the pin is current. Absent, the call walks the
default branch.

A vector this package fails is vendored anyway and marked `xfail`, never
left out: an absent vector hides the defect it would have shown, and
`xfail_strict` turns the marker red the day the defect is fixed.

## Re-checking a pin

The commit stands in a fence of its own, sitting inside the API path
rather than at the end of the command; the fence below reads it as
`${commit:?}`, the shell's must-be-set form, so a paste of that fence
alone fails naming the variable.

```shell
commit=<the pin the entry gives>
```

```shell
git hash-object tests/schemes/_data/key_agg_vectors.json
gh api "repos/bitcoin/bips/git/trees/${commit:?}:bip-0327/vectors" \
    --jq '.tree[] | select(.path == "key_agg_vectors.json") | .sha'
```

The comparison is on git blob SHA-1, not sha256: it is what a tree entry
already carries, so nothing has to be downloaded, and `git hash-object`
reproduces it locally. Not the contents API, which is the obvious
alternative and caps out on a large file.

The weekly job runs this comparison for every entry whose heading is one
file's path and which carries a `blob` or an `ours` line, and fails,
naming the file, on a mismatch. It compares the file with `ours` (or
`blob`) and the entry's `blob` with upstream's at `commit`, so a file
edited here and a pin whose blob is not the one at its commit both fail.
Add an `ours` line to a new entry whose file is not upstream's bytes,
and a `-text` line for the file to `.gitattributes`.

The two hashes match for every file whose verdict is **identical**. Where
upstream is CRLF they cannot, this repository being LF throughout, and the
entry says so with our own blob alongside. Every csv file vendored from
bitcoin/bips or from a fork's pull request to it is that case, and so far
only those: `bip340_test_vectors.csv`, the BIP324 files, the BIP374 files,
the BIP458 files and the BIP459 files. A csv there is written on Windows
line endings often enough that it is worth expecting rather than
discovering -- `mixed-line-ending` rewrites the file with `--fix=lf` as it
is staged, so the blob to compare is never the one just fetched.

## bitcoin/bips

### `tests/schemes/_data/bip340_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0340/test-vectors.csv
commit  200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb  2023-04-20
blob    672339129a844a060591bb22f444158ff45438ed
ours    aa317a3b3d53aa904def8b5a625b13073898b349
pulled  2020-04-04, refreshed 2020-11-22, 2020-12-08 and 2026-07-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings** — upstream is CRLF and this
repository is LF throughout, which `mixed-line-ending` enforces with
`--fix=lf`, so our blob is `aa317a3b` rather than the one above. All 19
vectors, all eight columns.

Four of the 19 are messages of 0, 1, 17 and 100 bytes: BIP340 accepts a
message of any size, and so do the bindings — `sign_custom` and `verify`
take one, and no 32-byte gate sends these four down the Python path.
All four pass on either arithmetic: `verify_` accepts each, and `sign_`
reproduces each signature byte for byte.

### BIP327 (MuSig2): files under `tests/schemes/_data/`

The vectors of `bip-0327/vectors/`, vendored whole
and under upstream's own names: `key_sort_vectors.json`,
`key_agg_vectors.json`, `nonce_gen_vectors.json`,
`nonce_agg_vectors.json`, `sign_verify_vectors.json`,
`tweak_vectors.json`, `det_sign_vectors.json` and
`sig_agg_vectors.json`. Each is pinned below in its own entry, one real
path per pin, rather than to one placeholder path shared by all of them:
a placeholder is not a path GitHub's own "commits touching a path" API
can be asked about, which is what kept every one of them out of
the weekly check. It also papered over a real difference between
them: six were untouched since the commit that added all eight,
`87394eaeb436d02e0a68b38a1e94bc526d50056e` (2023-03-27, "Add BIP327:
MuSig2 for BIP340-compatible Multi-Signatures"); `sign_verify_vectors.json`
was fixed once since, at `508e3a6a40a6e73c73cbfa8a33aa18a2bc7b9d91`
(2024-05-14, "Fix the four test vectors"); and `sig_agg_vectors.json`
once more again, at `1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439`
(2024-07-19, "bip327: minor fixes") -- the one commit the shared
placeholder cited as the tip of all eight paths, when it is the tip of
only that one.

56 cases between them, and `tests/schemes/musig2_test.py` runs every one:
1 sorting, 4 + 5 aggregations valid and failing, 4 nonce derivations,
2 + 3 nonce aggregations, 6 + 6 + 3 + 2 signatures (valid, refused at
signing, false on verification, refused on verification), 5 + 1
tweaked, 4 + 5 deterministic, 4 + 1 aggregated. An error case carries
what should be raised — which party contributed what, or the text of a
plain value error — and is checked against it, so the failing half of
each file is as load-bearing as the valid half.

What the files are measured against is `bip-0327/reference.py`, pinned
separately at `9297c12729670d09f9149ec6d8bad967d8161bfe` (2025-10-03,
the tip of that path): `src/ecc/ecc/musig2.py` follows it
function for function, and copies four of its error message strings
verbatim because the `error.message` field of a case is compared byte
for byte. That file is not vendored — it is an implementation, not data,
and this package's is the one under test.

### `tests/schemes/_data/key_sort_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/key_sort_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    de088a746e27953614b9f5394553911fb2c86d59
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/key_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/key_agg_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    b2e623de60f302c4004a6d656581bdba1f4e1e05
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/nonce_gen_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/nonce_gen_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    ced946f3efd9f80cb1a3819939f2b39de2061e42
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/nonce_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/nonce_agg_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    1c04b8818f340a5fe2e10eaf73c17a2c9e020f46
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/sign_verify_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/sign_verify_vectors.json
commit  508e3a6a40a6e73c73cbfa8a33aa18a2bc7b9d91  2024-05-14
blob    f71c8dd9d935c8c5f398e6a3888943e1e68b729d
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/tweak_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/tweak_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    d0a7cfe832bfe22375af0d64cd5d0dbb350592e0
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/det_sign_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/det_sign_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    261669ccd01cd4098fa97045f3d32654f64a48af
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### `tests/schemes/_data/sig_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/sig_agg_vectors.json
commit  1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439  2024-07-19
blob    519562c343b6e4bf686ba6e3eda8cee5c8e8b55d
pulled  2026-08-02, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**.

### BIP324 (ElligatorSwift): files under `tests/schemes/_data/`

`ellswift_decode_test_vectors.csv` and `xswiftec_inv_test_vectors.csv`,
under upstream's own names, both genuinely tipped by the same commit --
unlike BIP327 above, there is no exception a shared pin would have
papered over here. Each is pinned below in its own entry, one real path
per pin, rather than to one placeholder path standing in for both: a
placeholder is not a path GitHub's own "commits touching a path" API can
be asked about, which is what kept the pair out of the weekly check.

`packet_encoding_test_vectors.csv` is tipped by a later commit, and is
pinned on its own too.

### `tests/schemes/_data/ellswift_decode_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/ellswift_decode_test_vectors.csv
commit  cc177ab7bc5abcdcdf9c956ee88afd1052053328  2023-01-11
blob    1bab96b721e2f3ab90142c318523551eb520f753
ours    bcc5b31958ca8be59e799226afa1766f99fb5df8
pulled  2026-08-03, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings** — upstream is CRLF and this
repository is LF throughout, which `mixed-line-ending` enforces with
`--fix=lf`, so our blob is `bcc5b319` rather than the one above, the
same exception `bip340_test_vectors.csv` above documents.

### `tests/schemes/_data/xswiftec_inv_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/xswiftec_inv_test_vectors.csv
commit  cc177ab7bc5abcdcdf9c956ee88afd1052053328  2023-01-11
blob    138c4cf85c040785a45c6552c0169c8c12fd3cfc
ours    135958f62813cee4cfbbe68bdba257344f43afc1
pulled  2026-08-03, split into its own pin 2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception, our
blob `135958f6` rather than the one above.

The files test the two halves of the map, and both halves are
this package's own Python: `tests/schemes/ellswift_test.py` runs the decode file
against `_xswiftec` and the inverse file against `_xswiftec_inv`, whose
eight `case` columns are eight assertions per row rather than one — an
empty cell is a case with no preimage, and asserting that it *has* none
is what keeps a permissive inverse from passing. The comment column of
each row names the branch it exercises (`valid_x(x1)`, `non_square(s)`,
`t>=p`, `info[v=0]`), which is what makes the files a branch
inventory and not a sample.

Neither file covers `create` or `encode`: those pick one of up to eight
preimages at random, so there is no vector to hold them to, and what the
suite asserts instead is the round trip against the bindings — the
authority named in the entry that has no file to cite.

### `tests/schemes/_data/packet_encoding_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/packet_encoding_test_vectors.csv
commit  713f000a20421a54b29cd8ab89e711eef1fbccb9  2025-10-23
blob    1588b066b4792d0b03f30d4f7f18e57ccde1f525
ours    c556c47c2a807114411ff478e0bd782a270793da
pulled  2026-10-26
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception, our
blob `c556c47c` rather than the one above.

`tests/schemes/ellswift_test.py` reads its key agreement columns:
`in_priv_ours`, `in_ellswift_ours`, `in_ellswift_theirs` and
`in_initiating` in, `mid_shared_secret` out, against `xdh` on both arms.
The rest of each row is the v2 transport's, which this package does not
implement.

### BIP374 (DLEQ): files under `tests/schemes/_data/`

`test_vectors_generate_proof.csv` and `test_vectors_verify_proof.csv`,
under upstream's own names, which is the whole of `bip-0374/`'s vector
set. They are pinned separately below and their pins differ, which is
the reason a shared one is not offered: upstream last changed the files
in different commits, and one pin would have had to be wrong about one of
them.

The names are unusually bare for a vendored file -- nothing in either
says BIP374 -- and they keep them anyway, the naming rule above being
that upstream's name is the one thing a citation cannot drift away from.

### `tests/schemes/_data/test_vectors_generate_proof.csv`

```text
repo    bitcoin/bips
path    bip-0374/test_vectors_generate_proof.csv
commit  afaa856630058b87188648111da5dab0dd311bf7  2026-10-26
blob    4601ee0cfebba97f5df74c034a55097bf7ae3d6f
ours    f8c6908b25086b840147872931bd63dd1064a9ba
pulled  2026-08-13, refreshed 2026-10-29
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings** — upstream is CRLF and this
repository is LF throughout, which `mixed-line-ending` enforces with
`--fix=lf`, so our blob is `f8c6908b` rather than the one above, the same
exception `bip340_test_vectors.csv` above documents.

Every vector, every column: successes over generators that are not
secp256k1's and over secp256k1's own, the latter including a = 1 and
a = n - 1, and failure cases -- a zero scalar, a scalar equal to n, one
equal to n + 1, which an implementation reducing the scalar mod n would
accept, and a B at infinity. The file spells a failure `INVALID` in the
proof column, and the point at infinity `INFINITY` in the point column.

### `tests/schemes/_data/test_vectors_verify_proof.csv`

```text
repo    bitcoin/bips
path    bip-0374/test_vectors_verify_proof.csv
commit  fc874dd5d34239e070c0fdb8c4ed6a1dd2a94147  2026-08-19
blob    1368013b03521c97984b65ba0586b99dd8818564
ours    2d4acdf1fa0ca3d49c5f853196f934bd91b790a6
pulled  2026-08-13, refreshed 2026-09-21
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception, our blob
`2d4acdf1` rather than the one above.

Every vector: the successes are the proofs of the file above, read back,
all but its a = 1 and a = n - 1 rows, and the failures are permutations
of A, B and C, a bit flipped in the proof, a bit flipped in the message,
an `e` equal to the curve order and an `s` equal to the curve order -- so
the pair covers both directions over one set of keys, and a permutation
the challenge would have accepted is a defect the generation file alone
could not show.

BIP374's failure conditions R1 and R2 landing on infinity have no vector
in either file and are covered by `tests/schemes/dleq_test.py` instead.
Neither is a proof anybody generates -- an infinite R needs s == e over
A == G or B == C -- so upstream's generator produces none and the test
builds each.

`s >= n` is reached by the verification file only at `s == n`; the test
adds the largest value an s field holds.

### `tests/schemes/_data/wallet-test-vectors.json`

```text
repo    bitcoin/bips
path    bip-0341/wallet-test-vectors.json
commit  e35a46ecf3031c21dc7f7fdb694986789a3a8144  2021-11-12
blob    11261b00ba24afb90b62109505d9ca5ddd773b3b
pulled  2026-10-19
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. BIP341's wallet vectors, under upstream's own
name. `tests/schemes/ssa_tweak_test.py` reads the internal key, the tweak, the
output key and the control blocks of every `scriptPubKey` vector, and the
internal and tweaked private keys of every `keyPathSpending` input. The
script trees, addresses and signature hashes are read by nothing here.

### BIP459 (DahLIAS): files under `tests/schemes/_data/bip459/`

The csv files of `bip-0459/vectors/`, vendored whole and under upstream's
own names, in a subdirectory: the names say nothing of BIP459, and
`test_vectors_verify.csv` is a name another BIP's vectors could carry.

The BIP is a draft, on `bitcoin/bips#2210` and on no branch of
`bitcoin/bips` yet. Each pin is the pull request's head ref, which `ref`
names: GitHub keeps that ref in `bitcoin/bips` itself, so it survives the
fork's branch being renamed, rebased or deleted. `commit` is the last
commit on it touching the path, and the pull request's head when this
was pulled, `8678edb4ad56abd98acb56705b1a2861dcc97d8a`, holds the same
blob. The weekly check reports a new revision of the pull request that
touches a file. Once the BIP is merged the ref stops moving, and the
pins move to `master`.

`tests/schemes/dahlias_test.py` runs every case of every file. A
signature of the wrong size, which the verify file reads as False,
raises there instead, as the test module's docstring says.

### `tests/schemes/_data/bip459/test_vectors_partial_sig_verify.csv`

```text
repo    bitcoin/bips
path    bip-0459/vectors/test_vectors_partial_sig_verify.csv
ref     refs/pull/2210/head
commit  b3343f3b848d49f407e2d6e5912bd5c9ce9cdf5f  2026-10-21
blob    995149bc604b861dd17e2da4d524965cb06213d4
ours    a9793e1f321f52351ae4844ff10ba61eb5844d9d
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the exception
`bip340_test_vectors.csv` above documents, our blob `a9793e1f` rather
than the one above.

### `tests/schemes/_data/bip459/test_vectors_sign.csv`

```text
repo    bitcoin/bips
path    bip-0459/vectors/test_vectors_sign.csv
ref     refs/pull/2210/head
commit  b3343f3b848d49f407e2d6e5912bd5c9ce9cdf5f  2026-10-21
blob    6f9c78f77950518d8e46b8f5a031745efa772680
ours    58fa716aac5aba285f0c1402581fbf7e94b5d821
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the exception
`bip340_test_vectors.csv` above documents, our blob `58fa716a` rather
than the one above.

### `tests/schemes/_data/bip459/test_vectors_sign_error.csv`

```text
repo    bitcoin/bips
path    bip-0459/vectors/test_vectors_sign_error.csv
ref     refs/pull/2210/head
commit  b3343f3b848d49f407e2d6e5912bd5c9ce9cdf5f  2026-10-21
blob    859c88e6d3467b452075e5a898f96c7d592590ee
ours    6384a647ad1947010f14669c706a7dcd5270aaca
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the exception
`bip340_test_vectors.csv` above documents, our blob `6384a647` rather
than the one above.

### `tests/schemes/_data/bip459/test_vectors_tweak.csv`

```text
repo    bitcoin/bips
path    bip-0459/vectors/test_vectors_tweak.csv
ref     refs/pull/2210/head
commit  b3343f3b848d49f407e2d6e5912bd5c9ce9cdf5f  2026-10-21
blob    406e8650f610177db40f5562a8bf66ef041eeb72
ours    7380491d292dfb994527f623ebfec70a9928e7ca
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the exception
`bip340_test_vectors.csv` above documents, our blob `7380491d` rather
than the one above.

### `tests/schemes/_data/bip459/test_vectors_verify.csv`

```text
repo    bitcoin/bips
path    bip-0459/vectors/test_vectors_verify.csv
ref     refs/pull/2210/head
commit  b3343f3b848d49f407e2d6e5912bd5c9ce9cdf5f  2026-10-21
blob    68b5564ae6a8544137d0c93904d603a34c9ca8c3
ours    97cfb8151fb789bc97b0b88396456d4ec6992434
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the exception
`bip340_test_vectors.csv` above documents, our blob `97cfb815` rather
than the one above.

## fjahr/bips

### BIP458 (half-aggregation): files under `tests/schemes/_data/`

`test_vectors_aggregate.csv`, `test_vectors_incaggregate.csv` and
`test_vectors_verify.csv`, under upstream's own names, which is the whole
of `bip-0458/vectors/`. The BIP is a draft, bitcoin/bips#2205, and its
files live only on the `halfagg` branch of the fork the pull request
comes from, hence the `ref` line of each entry. Each file is pinned to
the commit on that branch that last touched it;
`2f436b02f60b2ffb4eed8db65aed21e95d1fc4eb`, the revision
[ISS 365](https://github.com/btclib-org/ecc/issues/365) names,
is a later commit that only adds the BIP to the repository's README
index, and holds the same blobs.

`tests/schemes/ssa_halfagg_test.py` runs every vector of each file.
Each one agrees with this package but the empty aggregate of the
verification file, which BIP458 accepts and `ssa_halfagg.verify`
refuses with an `EccValueError`, as `CONTRIBUTING.md`'s "The public
surface" states. Wrong sizes, which the files expect to fail, raise
rather than answer False, by the same rule.

### `tests/schemes/_data/test_vectors_aggregate.csv`

```text
repo    fjahr/bips
path    bip-0458/vectors/test_vectors_aggregate.csv
ref     halfagg
commit  684923c5c9aa05d4124d0a6a4a82f5f9c1c9f959  2026-10-20
blob    dce0fb1bb9df161db1dcb7e24b85f34090a466be
ours    a5657f86ff62fc484697fced7c23df15dfd3a93b
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception
`bip340_test_vectors.csv` documents: our blob is the `ours` line and
not the `blob` one.

### `tests/schemes/_data/test_vectors_incaggregate.csv`

```text
repo    fjahr/bips
path    bip-0458/vectors/test_vectors_incaggregate.csv
ref     halfagg
commit  684923c5c9aa05d4124d0a6a4a82f5f9c1c9f959  2026-10-20
blob    dd9fd28fdb3bc03b069e03852988857d60548ccf
ours    92909886511fc7398498e4788f5a6d336b9af38e
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception
`bip340_test_vectors.csv` documents: our blob is the `ours` line and
not the `blob` one.

### `tests/schemes/_data/test_vectors_verify.csv`

```text
repo    fjahr/bips
path    bip-0458/vectors/test_vectors_verify.csv
ref     halfagg
commit  684923c5c9aa05d4124d0a6a4a82f5f9c1c9f959  2026-10-20
blob    35d50525f6dfa5b7e3203bfab3b5e93b771b061a
ours    b7f0149193dd9f96bfaefde240a30cebf34d753b
pulled  2026-10-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for line endings**, the same exception
`bip340_test_vectors.csv` documents: our blob is the `ours` line and
not the `blob` one.

## siv2r/bip-frost-signing

### BIP445 (FROST signing): files under `tests/schemes/_data/bip445/`

The JSON files of `python/vectors/`, vendored whole and under upstream's
own names, in a subdirectory rather than flat under `tests/schemes/_data/`:
BIP327 above already publishes files of these same names there, and a
vendored file keeps the name upstream gave it rather than losing it to
that collision.

The BIP is a draft, at version 0.12.1 in `siv2r/bip-frost-signing`. Its
pull request to `bitcoin/bips`, `bitcoin/bips#2070`, also reads 0.12.1 at
its head `363f69340b6731368db4a514147c7dec8eb5fd99`, but lacks
`siv2r/bip-frost-signing`'s commits from
`75318bc740428c435ec137842442879980fff1d5` (2026-10-12) to
`ba299badfbe647e670686de75578dd501a627028` (2026-10-15): the rule that an
input of the wrong length fails, the tweak vector file without its
wrong-length tweak, the vectors at the largest number of participants
the BIP allows and for a zero tweak, and `nonce_gen`'s bound on
`signer_id`. The pins below follow
`siv2r/bip-frost-signing` for that reason, and move back to
`bitcoin/bips#2070` once it carries those commits. Each file is pinned to
the commit on that repository's default branch, `master`, that last
touched it, the same distinction the BIP327 entry above draws for
`sign_verify_vectors.json` and `sig_agg_vectors.json`.

`tests/schemes/frost_test.py` runs every case of every file. An error case
carries what should be raised -- which party contributed what, or the
text of a plain value error -- and is checked against it, the same
discipline the BIP327 entry above states.

`src/ecc/ecc/frost.py` follows `python/frost_ref/signing.py`
function for function, checked against it at
`ba299badfbe647e670686de75578dd501a627028` rather than assumed from the
BIP327 ancestry the reference's own header claims: several shapes that
read alike are not the same function, the tweak-range error message
among them. That file is not vendored -- it is an implementation, not
data, and this package's is the one under test.

### `tests/schemes/_data/bip445/nonce_gen_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/nonce_gen_vectors.json
commit  825633bad2f9500d1b4e981f3a11cadd17bbf21d  2026-10-07
blob    83318472f1bbea1e916bbbae8fa20fd80aa3150c
ours    b4dba51b452f8cdb75101a3bc116365e436911a9
pulled  2026-09-17, refreshed 2026-10-09
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/bip445/nonce_agg_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/nonce_agg_vectors.json
commit  a715d1a324b993183e940e5d8f4b7d3b50b3105b  2026-10-06
blob    5bd396bbe00807bde940a183f38b773e927ca34a
ours    e03e38578ecc20b643212e6f28a746cf70475e06
pulled  2026-09-17, refreshed 2026-10-09
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/bip445/sign_verify_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/sign_verify_vectors.json
commit  123f274a9197ca6c98e52b04a88b8c95f4c51dfe  2026-10-13
blob    e6ba168ab31bf8a92b65e55a785f828300c78ed2
ours    ead9f54efff825cdc302516704298d92e287adbf
pulled  2026-09-17, refreshed 2026-10-09, 2026-10-14, 2026-10-19
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/bip445/tweak_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/tweak_vectors.json
commit  d64e6a9887d8903ee840544683eda051a424e57e  2026-10-13
blob    eeaa93d7fec48165b4f4e9c8b2712f536d432ffa
ours    938cd98273fe66074c78955bbc45dda48e653474
pulled  2026-09-17, refreshed 2026-10-09, 2026-10-14, 2026-10-19
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/bip445/det_sign_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/det_sign_vectors.json
commit  762bd48c42eed9a00f6f62fb846f2826013664ac  2026-10-10
blob    b2f0f62065b29c6fd779bdad4184af8cd2e773ea
ours    def3867dbc84c8ee0249b5926e69bb63ef3c81c2
pulled  2026-09-17, refreshed 2026-10-09, 2026-10-14
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/bip445/sig_agg_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/sig_agg_vectors.json
commit  61f589f4f85b862ba7ce0e59b7dadea0f4bd98d3  2026-10-10
blob    4d9c99a06b5c031d6055a0674c3fec3663b9fb53
ours    a6d48f662ae05bd52837cd5274c08411a57b7675
pulled  2026-09-17, refreshed 2026-10-09, 2026-10-14
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/bip445/threshold_info_vectors.json`

```text
repo    siv2r/bip-frost-signing
path    python/vectors/threshold_info_vectors.json
commit  d64e6a9887d8903ee840544683eda051a424e57e  2026-10-13
blob    63c8a92159942132ecc46dffa8e1a8ec6e92c624
ours    70a6dbc84597f48e2c82a6e92495acdaef72dd8a
pulled  2026-10-14, refreshed 2026-10-19
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

## BlockstreamResearch/bip-frost-dkg

### `tests/schemes/_data/chilldkg_vectors.json`

```text
repo      mllwchrry/bip-frost-dkg
path      python/chilldkg_ref/chilldkg.py
ref       remove-dkgoutput
commit    773bc4dfb9c979b699ea7920f1a550f395ee734a  2026-10-12
blob      21c0ac32d009e143a7dfe50a7de53deea8c17f80
ours      29042b15f45de75883e1054ff52cd3f901db1184
program   ChillDKG's reference, python/chilldkg_ref/ at that commit
calls     for each session (t, n), with
          rand(x, i) = sha256(seed + "|" + f"{t}|{n}|{x}|{i}"):
            for each participant i:
              hostseckey[i] = rand("hostseckey", i)
              hostpubkeys[i] = hostpubkey_gen(hostseckey[i])
            params = SessionParams(hostpubkeys, t)
            for each participant i:
              participant_step1(hostseckey[i], params, rand("step1", i))
            coordinator_step1(pmsgs1, params)
            for each participant i:
              participant_step2(hostseckey[i], state1[i], cmsg1,
                                rand("step2", i))
            coordinator_finalize(cstate, pmsgs2)
            for each participant i:
              participant_finalize(state2[i], cmsg2)
recorded  2026-10-26
behind    0 revisions; that commit is the tip of the path
```

Verdict: **recorded**. There is no upstream vector file. Each session is
one run of ChillDKG's reference, the key generation BIP-FROST-DKG
specifies, with every participant honest, for the (t, n) pairs
[ISS 342](https://github.com/btclib-org/ecc/issues/342) lists. `seed` is
the file's own field.

The reference is pinned to the head of
BlockstreamResearch/bip-frost-dkg#165, which is still open. That head is
on the fork's branch `ref` names, and `commit` is the last commit there
touching `chilldkg.py`. So the weekly check reports a revision of that
pull request that changes `chilldkg.py`; one that changes only the rest
of the program goes unreported.

Before writing the file, the program asserted that every participant
finalized with the coordinator's threshold info and recovery data; that
BIP445's own `validate_threshold_info`, in `bip445_threshold_info.py` at
the same commit, accepts that threshold info; that `recover_public` and
`recover_secshare` give back the same threshold info, session parameters
and secret shares from the recovery data; and that each secret share is
below the group order and is the discrete log of its public share.

`tests/schemes/frost_test.py` reads `t`, `n`, `secshares` and
`threshold_info`. The host keys and the recovery data are kept, so that
the file is the program's output unchanged.

## bitcoin-core/secp256k1

### `tests/_data/secp256k1_symbols.txt`

```text
repo    bitcoin-core/secp256k1
path    src
commit  32099110d63a1dec1a7d27067450fd97d20ea30f  2026-10-20
ours    a8f306732166cf782473ecbd2b90030616953689
pulled  2026-09-10, refreshed 2026-09-14, 2026-10-07, 2026-10-26 and 2026-10-28
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically: every `secp256k1_*` name the
pinned tree's own `src` spells, sorted and deduplicated. The pin stands
for a directory rather than for one upstream file, which is why the
block above carries no `blob` line and why what the weekly workflow
reports on it is a commit touching `src` — what a name added there or
taken away from it looks like from outside.

```shell
commit=<the pin this entry gives>
```

```shell
git grep -ohP '(?<![A-Za-z0-9_])secp256k1_[a-z0-9_]+' "${commit:?}" -- src \
    | LC_ALL=C sort -u
```

The names and not the headers holding them, because what reads the file
asks whether upstream has a name and never what its signature is:
`tests/upstream_symbols_test.py` refuses a docstring crediting
libsecp256k1 with a name that library does not have, `secp256k1_ecdsa_sign`
passing and secp256k1-zkp's `secp256k1_ecdsa_s2c_opening` failing. A copy
of the headers would answer that for the published part of the family and
leave C prototypes to be re-pinned for the rest of it.

`src` and not `include` for the same reason. `include` is what the library
publishes, where this tree names what it reads: `curves.curve`'s
`secp256k1_ge_x_on_curve_var` and `number_theory`'s `secp256k1_ctz64_var`
are that library's own and are declared in no header of `include`, only
in one under `src`. Nothing is lost at the other end — every name
`include` declares is spelled in `src` too, the difference being names a
header comment wraps in prose rather than declares.

The revision is one of bitcoin-core/secp256k1's own, and not the one the
bindings vendor. `btclib-secp256k1` compiles the library a caller loads
from a submodule of that repository, so what the suite links is the
submodule of the release `uv.lock` resolves:

```shell
version=<the btclib-secp256k1 version `uv.lock` resolves>
```

```shell
gh api \
    "repos/btclib-org/btclib-secp256k1/contents/secp256k1?ref=v${version:?}" \
    --jq .sha
```

A name upstream has added since that revision is in this set and not in
the library the suite runs against, and a name upstream has renamed away
is in that library and not in this set. The names are what the entry's own
re-derivation prints when it is run again at the submodule's revision
and compared with the vendored set. `comm` walks both sides in its own
collation and takes them as already sorted, so each `sort` and `comm`
itself run under `LC_ALL=C`, and the vendored side is sorted again rather
than trusted to be in that order: a side sorted in another collation
answers a longer difference, and the `comm` macOS ships prints nothing to
say so.

```shell
submodule=<the sha the call above prints>
symbols=<the path to `tests/_data/secp256k1_symbols.txt`>
```

```shell
git grep -ohP '(?<![A-Za-z0-9_])secp256k1_[a-z0-9_]+' "${submodule:?}" \
    -- src | LC_ALL=C sort -u \
    | LC_ALL=C comm -3 - <(LC_ALL=C sort "${symbols:?}")
```

Upstream is what the set is of, because that is the read a credit asks
for: `tests/upstream_symbols_test.py` refuses a credit a reader cannot
follow, and following one is a read of bitcoin-core/secp256k1's source.
Pinning to the submodule would answer for the library the bindings ship
and give that up — a renamed-away name would stay in the set, so a
credit spelling it would pass and land its reader on a function upstream
does not have. What neither pin answers is whether the installed
bindings expose a name, that being a fact about their own surface.

### `tests/schemes/_data/secp256k1_recovery_vectors.json`

```text
repo    bitcoin-core/secp256k1
path    src/modules/recovery/tests_impl.h
commit  9ec3bfe22dc662875e6fca2419713eae105dabee  2025-10-01
blob    09554a242ee9fb2aeb75f4f360f649a460eb5fea
ours    441719cc172fcb20b3aaf8c650b81b6d64414d9a
pulled  2026-10-11
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, off `test_ecdsa_recovery_edge_cases`: the message
`msg32`, the signatures `sig64`, `sigb64` and `sigc64`, and for each the
recovery ids upstream asserts recover a key. In `sigb64` and `sigc64` r
equals s, and both are small. `recovers` maps a recovery id to that
assertion, and an id upstream does not ask about is absent. The rows with
a zero r or s are `sigc64` with the byte upstream's test zeroes. Every other
value is in the pinned blob when its `0x` arrays are read as octets, and
`msg32`, which upstream spells as character literals, is the ASCII of
`This is a very secret message...`:

```shell
blob=<the blob this entry gives>
value=<a hex string the file transcribes, r followed by s>
```

```shell
gh api -H 'Accept: application/vnd.github.raw' \
    "repos/bitcoin-core/secp256k1/git/blobs/${blob:?}" \
    | python3 -c "import re,sys
h = ''.join(re.findall(r'0x([0-9a-fA-F]{2})', sys.stdin.read()))
print(sys.argv[1].lower() in h.lower())" "${value:?}"
```

The outcomes are libsecp256k1's own assertions, so a Python arm held to
them agrees with that library's accept and refuse pattern and not with a
derivation of its own, and for that reason the module reading the file,
`tests/schemes/dsa_secp256k1_recovery_test.py`, is not an authority in
`tests/py_arm_authority_test.py`. Upstream's comment says `sig64` was made
with secret key zero, which is not a valid key. This package refuses a
zero r or s where upstream parses it; the test asks `recover_pub_key_`
for the refusal.

## Other projects

### `tests/schemes/_data/bitcoin_core_compact_vectors.json`

```text
repo    bitcoin/bitcoin
path    src/test/key_tests.cpp
commit  e8691056c0140f8fa850fc6837dde915ebeb22cc  2026-08-03
blob    75173e4b2e0d026b3d406f6830646aec8c1ab2e9
ours    b69061ea0c19ce5ad310816b918f946c3bfebe15
pulled  2026-10-11
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, off `key_test1`: the keys it decodes from
WIF (`strSecret1`, `strSecret1C`, `strSecret2`, `strSecret2C`), the message
`Very deterministic message`, and the compact signature `SignCompact`
must give for each, which the test checks as hex. A compact signature is
a flag byte, which carries the recovery id and whether the key is
compressed, then r and s. The message is hashed with Core's `Hash`, which
is double SHA256, and the test applies that. Core's test also recovers the
key from a compact signature and compares it with the key of the WIF, as
`tests/schemes/dsa_recovery_test.py` does. The expected compact signatures
are libsecp256k1's output inside Core: `CKey::SignCompact` calls
`secp256k1_ecdsa_sign_recoverable` at the pinned commit. What is
independent of it is that the recovered key equals the key of the WIF.
`tests/schemes/dsa_sign_recoverable_test.py` checks signing against the
signatures and is not counted as an authority.
Every string in the file is in the pinned blob:

```shell
blob=<the blob this entry gives>
value=<a string the file transcribes>
```

```shell
gh api -H 'Accept: application/vnd.github.raw' \
    "repos/bitcoin/bitcoin/git/blobs/${blob:?}" \
    | python3 -c "import sys
print(sys.argv[1] in sys.stdin.read())" "${value:?}"
```

### `tests/curves/_data/pubkey.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/pubkey.json
commit  ead56b92a8229e16941318d953c6444268beaa1a  2015-09-18
blob    8aaa0c59d182b126cfedc505473dbdc961aaea1a
ours    9d9546e742a71d322d412176d38b2c46764b6197
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 349 vectors, JSON-equal to the upstream blob;
ours is pretty-printed at four spaces. Re-checked on 2026-07-30: still
JSON-equal, and that blob is still the one on master.

### `tests/schemes/_data/ecdsa_sig.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/ecdsa_sig.json
commit  ead56b92a8229e16941318d953c6444268beaa1a  2015-09-18
blob    af16179725c10c409c7929ac0576161c1f5e72ad
ours    9d3db82654b611b1c3ef5d4ccbd62d63bdf4ccf4
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 199 vectors, JSON-equal.

### `tests/schemes/_data/ecdsa_custom_nonce_sig.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/ecdsa_custom_nonce_sig.json
commit  3caf31d20c668cf54a1621e21b7f1d943f0db048  2016-03-30
blob    e9d61e267f2e8fcd21c660aab17fe5de44cae0f0
ours    b002bb6f0934dcdfe7b37b6c2aeafbd615bf85ca
pulled  2023-01-16
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 199 vectors, JSON-equal.

### C2SP/wycheproof: the ECDSA and ECDH files under `tests/schemes/_data/`

The adversarial vectors, and the one upstream here published under a
licence that is not MIT: Apache-2.0, whose condition on redistribution
is a copy of the licence, so `WYCHEPROOF_COPYING` is vendored beside
them and has its own entry below. There is no `NOTICE` file at the pin
to carry with it.

Each entry below is pinned to its own path's last commit rather than to
one commit shared by all of them, since the files do not all move
together. All live in `testvectors_v1/`. Not `testvectors/`, which
upstream removed on 2025-09-02 and which no refresh can reach again.
They are read by `tests/schemes/wycheproof_test.py`, which is also where
the split between the two ECDSA profiles is explained, and where the
difference the files under a hash other than sha256 make is:
`_libsecp256k1_serves` admits sha256 alone, so those reach the Python
arithmetic without the dispatch being switched off, and are run once
rather than twice.

The SHAKE files need one thing the others do not, and it is a type
rather than a reader: `hashlib.shake_128` is not a `HashF`, an
extendable-output function having no output length of its own, so
`_PinnedXof` in that module pins one and `src/ecc/alias.py`
says why the package does not. The pinned length is `n_size` and any
length above it is the same test, `challenge_` reading the leftmost
`nlen` bits of a digest whose longer forms have these very bytes as
their prefix -- measured, all files verify identically at 32 and at 64.

`ecdsa_secp256k1_sha256_bitcoin_test.json` names its own schema now,
`ecdsa_bitcoin_verify_schema.json`, which upstream added beside it;
upstream's own README still lists the file as missing one, unrenewed in
the same commit. No longer frozen at `generatorVersion 0.9rc5` either:
that top-level field is gone, replaced by a `source: {name, version}`
object per test group, `version` carrying the same string. Vendored
regardless of the schema's presence or absence, which is what
bitcoin-core/secp256k1 and secp256k1lab both do with it.

### `tests/schemes/_data/ecdsa_secp256k1_sha256_bitcoin_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json
commit  12fd3aaf33eb5fa1f52e026912ee00c054f9d984  2026-10-06
blob    d5c273b5d0f54c502616ae0c651696d56d91618c
pulled  2026-08-13, refreshed 2026-08-25, 2026-10-14
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The bitcoin profile, `EcdsaBitcoinVerify`: the
strict DER encoding, and the low-s rule, under which the malleable high-s
twin of a valid signature is `invalid`. This package's parser is the strict one
and its verifier does not apply that rule, so two of these verdicts
are exempted rather than asserted — `wycheproof_test.py` reads which two
out of the file below.

The pin adds tcId 464 to the file at its previous pin (`234d9689d0cb`),
in a test group of its own: an `invalid` signature whose r + n equals
x(kG) modulo p but is not below p. Every other test group and case is
unchanged; `numberOfTests` counts the new one.

### `tests/schemes/_data/ecdsa_secp256k1_sha256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha256_test.json
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    48797ce3b697f47175bdf4dc93976c2dc94438c5
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The same algorithm, curve and hash as the file
above, without the bitcoin profile's two extra rules: what a
general-purpose ECDSA verifier must accept. It is therefore also the
oracle for the exemption named above — a key and a signature `valid` here
and `invalid` there differ by the low-s rule and by nothing else.

### `tests/schemes/_data/ecdsa_secp256k1_sha256_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    3c59b142ede26ecbafecf83341e907dd3bfda40f
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. IEEE P1363 encoding, raw `r` and `s` side by
side, which reaches `Sig` with no DER in front of it.

### `tests/schemes/_data/ecdsa_secp256k1_sha512_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha512_test.json
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    612e1912bfb5e523fbe8183e0d12f468e8309a08
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. A digest wider than the order, so `challenge_`'s
truncation to the leftmost `nlen` bits is under adversarial input here
and nowhere else.

### `tests/schemes/_data/ecdsa_secp256k1_sha3_256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha3_256_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    5c6c5901f4d41af8a992cafc4aa31b6bc7b87163
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. A Keccak digest of the order's own width, which
is the pair to the file above: same width as sha256, different function,
so what it varies is the dispatch and not the arithmetic.

### `tests/schemes/_data/ecdsa_secp256k1_sha3_512_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha3_512_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    2a5770e00be1c4d1218b79e8a805f52a0a1c7f26
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Wide digest and Keccak both, the fourth corner
of the two the files above vary one at a time.

### `tests/schemes/_data/ecdsa_secp256k1_sha512_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_sha512_p1363_test.json
commit  878e5366008753df2064d40c49f8e2f50f9c6af7  2026-05-12
blob    089040205b9d99313d284154cdcdc646079d1d43
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The wide digest without DER around it, which is
what says the P1363 size rule is the encoding's and not the hash's: r
and s stay `n_size` each while the message hash doubles.

### `tests/schemes/_data/ecdsa_secp256k1_shake128_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake128_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    bffa63ed0097e4910a5d99381f88a4b1c12db757
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. An extendable-output function read as a hash of
fixed size, which is the one thing here that needed something built for
it: `_PinnedXof` in the test module, because `HashF` is a constructor of
digests that report their own length and a SHAKE's is 0.

### `tests/schemes/_data/ecdsa_secp256k1_shake256_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake256_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    5bfb394cf971b3c9a68862f23b1251f3d3e7b1c0
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The same stream read at the same `n_size`, over
a sponge of a different rate. Its tcId 425 is upstream's
`Untruncatedhash` case, a signature made over the whole digest instead
of its leftmost `nlen` bits and therefore `invalid` -- which is also the
evidence that upstream generated this file at a length wider than the
order, and that reading the stream at `n_size` reads the leftmost bits
it read.

### `tests/schemes/_data/ecdsa_secp256k1_shake128_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake128_p1363_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    3f63208d4cbeaed6a8c46c430678199bd52d0e50
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The XOF with no DER around it: `Sig` answers for
r and s alone, as under sha256 and sha512, the adapter changing what the
message hashes to and nothing about the encoding.

### `tests/schemes/_data/ecdsa_secp256k1_shake256_p1363_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdsa_secp256k1_shake256_p1363_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    c2b431b5d76016a8da19fdc1aab1ecaa5cfe12f1
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The fourth corner, and it carries the
`Untruncatedhash` case of the pair as tcId 190.

### `tests/schemes/_data/ecdh_secp256k1_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdh_secp256k1_test.json
commit  78898104021ebd2cd98820e4112da89b1531d999  2026-03-11
blob    3ed5207460f29a270e024d0f3c0e1b57d1fa52a9
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Key agreement, with the public key X.509-encoded
rather than a bare point: the invalid-curve, twist and wrong-curve cases
`ecc.ecc.dh` has no other vectors for.

### `tests/schemes/_data/ecdh_secp256k1_webcrypto_test.json`

```text
repo    C2SP/wycheproof
path    testvectors_v1/ecdh_secp256k1_webcrypto_test.json
commit  e0df04e0c033f2d25c5051dd06230336c7822358  2025-10-07
blob    a675c5378e8d10aad7ae241ef5460f4aefa10d0b
pulled  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The same key agreement as `ecdh_secp256k1_test.json`
above with the keys JWK-encoded (RFC 7517) rather than X.509: `WrongCurve`
here attacks the JWK `crv` field where that file's attacks the DER OID,
and its valid cases' shared secrets are exactly that file's own.

### `tests/schemes/_data/WYCHEPROOF_COPYING`

```text
repo    C2SP/wycheproof
path    LICENSE
commit  31387e2cd596587c859c611027b6a44d2e2b65ff  2018-04-04
blob    7a4a3ea2424c09fbe48d455aed1eaa94d9124835
ours    d645695673349e3947e8e5ae42332d0ac3164cd7
pulled  2026-08-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline** -- upstream ends
without one and the `end-of-file-fixer` hook added it, so our blob is
`d6456956`, which is the Apache-2.0 text as most repositories carry it.
The stock text, with no copyright line filled in and no `NOTICE` beside
it, so this file is the whole of what the licence asks a redistributor
to carry.

Renamed, against the naming rule above, and the reason is what the rule
is for. Upstream calls it `LICENSE`, and a file of that name inside
`tests/schemes/_data/` would read as licensing the directory it sits in --
which is false, the BIP and rustyrussell files beside it having their
own terms and this repository's own `LICENSE` being at the root. The upstream
name is in the entry above instead, where the pin already is. It is the
name bitcoin-core/secp256k1 gives its copy for the same reason.

### `tests/schemes/_data/ecdsa_adaptor.json`

```text
repo    discreetlogcontracts/dlcspecs
path    test/ecdsa_adaptor.json
commit  fcc9619f3505afbb5a3d2f7ba3896fc4910ae08e  2021-05-07
blob    a6c9ca1f03a40e9591a416cc5d09d3ff7e530693
pulled  2026-10-10
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. The specification's own file, whose cases
libsecp256k1-zkp carries in `src/modules/ecdsa_adaptor/tests_impl.h` as
`test_ecdsa_adaptor_spec_vectors`.

### `tests/schemes/_data/dlc_schnorr_test.json`

```text
repo    discreetlogcontracts/dlcspecs
path    test/dlc_schnorr_test.json
commit  0b69c3ed784d6a95df12b159ff699b05d150ffc3  2020-10-29
blob    558ea21184490d86d91430d3e9622d6d9f6a0192
ours    eb88600b5360018ef03582b2225d3db58c794d11
pulled  2026-10-10
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical but for a trailing newline**, which the
`end-of-file-fixer` hook added.

### `tests/schemes/_data/rfc6979.json`

Verdict: **transcribed**. Appendix A.2 of RFC 6979 gives 50 vectors, ten each
for NIST P-192, P-224, P-256, P-384 and P-521, as `tests/schemes/rfc6979_test.py`
says. An RFC number is already an immutable reference — there is no commit to
pin, and `rfc-editor.org/rfc/rfc6979` is the document.

Pulled 2020-05-08, refreshed 2020-11-29 and 2023-01-04.

### `tests/schemes/_data/zkp_rangeproof_fixed_vectors.json`

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/rangeproof/tests_impl.h
commit  6a01f71674cd3550e42d725420ddfb9e8571e223  2026-10-17
blob    d594ee382fa7e6df00a1cadcc78030f6feb2ff0c
ours    572c4e396cffc71a03aaab2e3bef968fed4b6d24
pulled  2026-09-09, refreshed 2026-09-10
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per `vector_<n>`
array of `test_rangeproof_fixed_vectors` and
`test_rangeproof_fixed_vectors_reproducible`, which is where
libsecp256k1-zkp publishes fixed rangeproofs: `proof` and `commitment`
are that array and the `commit_<n>` beside it, `blind` is the `blind_<n>`
of the first function and the `vector_blind` the second shares, `nonce`
is the `nonce_3` the first rewinds its `vector_3` under and the
`vector_nonce` the second shares, and
`value` and `verify` are what those functions' own `CHECK`s state about
the octets -- the value a rewind answers, and the range
`secp256k1_rangeproof_verify` answers. `id` is the function and the array
upstream names each by. The pass that produced the file is not committed
-- a one-off read of C source is not a tool -- and what re-derives it is
reading those arrays again.

Not vendored as the file itself because there is no data file upstream
and none anywhere: this format has no published vector file, which is
what the entry below says of it too, so the blob above is that C source
and the weekly re-check reports a proof added to it. The bindings
`uv.lock` resolves vendor a fork of that repository: their
`secp256k1-zkp` submodule is `a8f6b86a804cdfd455dfb943937d254ec6ccc70a`
of `fametrano/secp256k1-zkp`, which exposes
`secp256k1_borromean_verify` as public API, so the blob at this path
there is `02276b1b8745b90c7b6a50a0e3a89b9438e30397` and not the one
above. Both functions this entry transcribes read the same in the fork's
blob, byte for byte, as do the `vector_blind` and `vector_nonce`
declared between them, so the transcription's source is the code the
bindings run.

`vector_1` and `vector_2` of `test_rangeproof_fixed_vectors` carry no
`nonce` field because upstream declares no array for them: it rewinds
those under `pc.data`, and `secp256k1_pedersen_commitment_parse` ends by
copying its input into `commit->data` verbatim, so what a rewind reads
there is the leading octets of the `commitment` above, one scalar wide.
The message a rewind also answers is left out,
`tests/schemes/rangeproof_fixed_vectors_test.py` holding what upstream
signed each entry with instead.

That module asks for the octets back out, the range the header proves,
the rings the value's digits index, `ecc.ecc.rangeproof.verify` against the
commitment published beside each proof, and a rewind of every entry.
The entries of
`tests/schemes/_data/zkp_rangeproof_vectors.json` record a nonce of their
own, and `tests/schemes/rangeproof_test.py` is where those are rewound.

### `tests/schemes/_data/zkp_generator_vectors.json`

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/generator/tests_impl.h
commit  6a01f71674cd3550e42d725420ddfb9e8571e223  2026-10-17
blob    2943ea7b528d5a8f41f01ef1f4a5f68c5897c9fe
ours    455c1177bf612d12fcb0897b5f33fabc4f877af8
pulled  2026-09-11
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per element of
each `secp256k1_ge_storage results[]` array upstream declares in that
file, `x` and `y` being the halves of a `SECP256K1_GE_STORAGE_CONST`.
`shallue van de woestijne` is `test_shallue_van_de_woestijne`'s array
and `t` the field element that function maps -- its loop counter, then
that counter negated, which is the order the array is indexed in;
`generator generate` is `test_generator_generate`'s and `seed` the `v`
that function fills with its own counter. `id` names the argument rather
than the position. The pass that produced the file is not committed -- a
one-off read of C source is not a tool -- and what re-derives it is
reading those arrays again.

Not vendored as the file itself for the reason the entry above gives:
this map has no published vector file anywhere, upstream stating its own
against the sage program it keeps beside the code. The bindings
`uv.lock` resolves vendor a fork of that repository,
`fametrano/secp256k1-zkp` at
`a8f6b86a804cdfd455dfb943937d254ec6ccc70a`; the blob at this path there
is `14ec95dc94780126a796866b05eeafa2093bf22f` and not the one above. Of the
functions this entry transcribes, `test_generator_generate` reads the same
in both, and `test_shallue_van_de_woestijne` differs only where its loop
calls `secp256k1_fe_set_int` in the fork and `secp256k1_fe_set_int_unchecked`
above. The arrays read the same in both, so the transcription's source is
the code the bindings run.

`tests/schemes/pedersen_test.py` is what reads it: the first array against
`ecc.ecc.pedersen._shallue_van_de_woestijne` and the second against
`generator_from_seed`, at no blinding factor and at a zero one, which is
the pair of calls upstream's own loop makes of each entry.

### `tests/schemes/_data/zkp_schnorr_adaptor_vectors.json`

```text
repo    siv2r/secp256k1-zkp
path    src/modules/schnorr_adaptor/tests_impl.h
ref     schnorr-adaptor-module
commit  060dad2ef89f79542d6e3349af04ca0cbeb164c0  2024-10-25
blob    3f9017b5268ee9df69a8166b4488fbaefea37c66
ours    22c32688e4626f19402f3c151c322102a771cf91
pulled  2026-10-10
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, mechanically. One json object per block of
`test_schnorr_adaptor_spec_vectors`, the vectors of the `schnorr_adaptor`
module BlockstreamResearch/secp256k1-zkp#299 proposes. `id` is the
block's comment, each hex field is the `0x` array of that name, and
`checks` names the helpers the block calls, with the flags it passes
them. A block that only asks whether a key or an adaptor point parses
carries the parse function's name, set to false. The pass that produced
the file is not committed, and what re-derives it is reading those arrays
again; the command in the entry of `tests/schemes/dsa_anti_exfil_test.py`
finds each value in the pinned blob.

The pin is the branch of the fork the pull request is opened from, which
`ref` names. `commit` is the last commit on it touching the path, and the
pull request's head, c2f270985d, holds the same blob. The module is on
no branch of secp256k1-zkp itself, so the file is a reference and not an
authority: a revision of the pull request is what the weekly check
reports. `tests/schemes/ssa_adaptor_test.py` runs every block.

### `tests/schemes/dsa_anti_exfil_test.py`

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/ecdsa_s2c/tests_impl.h
commit  6a01f71674cd3550e42d725420ddfb9e8571e223  2026-10-17
blob    701b5ae56795a717b2e6b22f7e2ee349cfd3131d
ours    ddefb3ccb2c582e17352087ea93fb96386abc242
pulled  2026-08-02, refreshed 2026-08-06, 2026-08-07, 2026-08-09,
        2026-08-13, 2026-08-14, 2026-09-10 and 2026-09-26
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**, off `ecdsa_s2c_tests`, the array
`test_ecdsa_s2c_fixed_vectors` and `test_ecdsa_anti_exfil_signer_commit`
both walk: `_ZKP_VECTORS` is its rows, column for column -- `s2c_data`,
`expected_s2c_opening` and `expected_s2c_exfil_opening` -- and
`_PRV_KEY` and `_MSG_HASH` are the key and the message both functions
run those rows against. There is no blob to compare, the values
being `0x` arrays inside C source, so what is checked is that each of
them is in the pinned blob when those arrays are read as octets rather
than as text:

```shell
blob=<the blob this entry gives>
value=<a hex string the module transcribes>
```

```shell
gh api -H 'Accept: application/vnd.github.raw' \
    "repos/BlockstreamResearch/secp256k1-zkp/git/blobs/${blob:?}" \
    | python3 -c "import re,sys
h = ''.join(re.findall(r'0x([0-9a-fA-F]{2})', sys.stdin.read()))
print(sys.argv[1].lower() in h.lower())" "${value:?}"
```

Source rather than a data file, and pinned here for what the columns
settle: a row's openings are one `anti_exfil_host_commit` apart, so the
module holds the R the device promises and the R its signature carries
to libsecp256k1-zkp's own octets rather than to this package run twice. A row
upstream regenerates is one this tree would go on asserting, which is
what the pin is read for. The module points here for the revision
and carries none of its own, which is what puts the pin where the weekly
workflow reads it.

## Not vendored from anywhere

### `tests/schemes/_data/zkp_rangeproof_vectors.json`

```text
program   btclib-secp256k1 0.8.0.5, built from its sdist with
          BTCLIB_LIBSECP256K1_ZKP=true; its secp256k1-zkp submodule is
          037cc6d74cbb4a89e443117459b577d56a582e54
calls     zkp.generator.pedersen_commit(blind, value)
          zkp.rangeproof.sign(commitment, blind, nonce, value, **args)
          zkp.rangeproof.info(proof)
          zkp.rangeproof.verify(commitment, proof)
recorded  2026-09-09
```

Verdict: **recorded**. There is no upstream vector file, which is what
[ISS 1072](https://github.com/btclib-org/btclib/issues/1072) says of
this format too. What libsecp256k1-zkp publishes instead is inside a C
test source, `src/modules/rangeproof/tests_impl.h` -- blob
`19c83ecbd84ae318d8eccf9336638238d3a29826` at the submodule commit
above -- where `test_rangeproof_fixed_vectors` and
`test_rangeproof_fixed_vectors_reproducible` hold proofs as C arrays,
beside the commitments and the ranges they assert. Those are the entry
`zkp_rangeproof_fixed_vectors.json` has above, and are not what this
file holds: each entry below is one proof
libsecp256k1-zkp signed for this tree, kept verbatim, beside the
arguments that produced it and what that library then said about it.

It is here because `tests/schemes/rangeproof_test.py` would otherwise
measure nothing in an unflagged build: the flagged extension those
calls need is what a btclib-secp256k1 installed from its sdist with
`BTCLIB_LIBSECP256K1_ZKP` has, and `ecc.ecc.rangeproof` reads a
format no other vector file in this tree carries.

**Recording another is this file's own arguments.** A rangeproof draws
nothing -- its nonces are the hash chain `rangeproof_genrand` derives
from the caller's -- so `sign` called again with an entry's `blind`,
`nonce`, `value` and `sign arguments` answers that entry's `proof`,
byte for byte. `test_the_vectors_are_what_zkp_signs_today` is that
check, so the procedure is a test rather than a note here, and it runs
wherever the extension does. The same determinism makes the entries an
oracle for what this package writes: `ecc.ecc.rangeproof.sign` builds a proof
from an entry's own `blind`, `value`, `nonce` and `sign arguments`, and
`test_sign_writes_the_octets_zkp_signed` holds it to these octets
wherever the suite runs, extension or not.
`test_sign_public_value_writes_the_octets_zkp_signed` asks the same of
the spelling that fixes the exponent for a value stated in the clear,
and both shapes that proof has are recorded, `public value` carrying a
`min_value` field and `public value, zero` carrying none, so neither is
left to the weekly sentinel.

**The `info` key is why a run without the extension still compares
against something.** Those are `zkp.rangeproof.info`'s own answers for
the same octets, so this package's reading of a header is held
to libsecp256k1-zkp's rather than to its own; what `info` says
nothing about -- the sign bits, the ring commitments and the borromean
signature -- is held by the proof going back out byte for byte.

### `tests/schemes/_data/der_length_vectors.json`

```text
program   cryptography (pyca/cryptography)
calls     encode_dss_signature(r, s)
recorded  2026-09-14
```

Verdict: **recorded**. There is no upstream vector file and no
repository: an outside DER encoder's own bytes, recorded once for a
fixed `(r, s)` on each of `bpp512r1`, `nistp521` and `secp521r1` -- the
catalogued curves whose signature reaches DER's long length form -- and
for a scalar pair on `secp256k1` wide enough that no catalogued curve's
own element does
([ISS 2130](https://github.com/btclib-org/btclib/issues/2130)).

It is here because nothing else in this tree can hold `Sig.serialize`'s
length octets to a parser it did not write: `libsecp256k1_dsa` answers
for `secp256k1` alone, and a decoder or a copy of the encoder written
beside the fix would share its author and the same reading of the
standard, proving nothing about whether that reading is the standard's
own. `tests/schemes/der_test.py`'s `test_der_matches_a_vendored_der_oracle`
compares `serialize()` to each entry's `der` field, byte for byte.

**Recording another** is `dsa.sign`'s own deterministic nonce for each
curve entry, and a synthetic scalar pair for the wide-element one:

```shell
uv run --locked --with cryptography python - <<'EOF'
from ecc.curves.curve import CURVES
from ecc.ecc import dsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature)

for name in ("bpp512r1", "nistp521", "secp521r1"):
    sig = dsa.sign(b"msg", 0x1234567890ABCDEF, ec=CURVES[name])
    print(name, hex(sig.r), hex(sig.s),
          encode_dss_signature(sig.r, sig.s).hex())

r = s = (1 << 1023) + 1
print("secp256k1", hex(r), hex(s), encode_dss_signature(r, s).hex())
EOF
```

Nothing upstream will ever refresh this file: `cryptography`'s encoder
is the fixed point being checked against, not a moving target.

## Outside vectors for the arms and curves other than secp256k1

For each case, which vector of somebody else's making holds it, or that
none was found. Read on 2026-10-11, and each claim has the command that
re-checks it. The Wycheproof commit is
`12fd3aaf33eb5fa1f52e026912ee00c054f9d984`. The commands below read the
file names of its `testvectors_v1/`, not the files. The other sources are
bitcoin/bips at `927b6de9915c9262615a6399de51b200f81e5aa4` and python-ecdsa
(tlsfuzzer/python-ecdsa) at `bff40c6cf2340148d410d5b3def0e949c547caf1`.

- **ECDSA signing and verifying on P-192, P-224, P-256, P-384 and P-521**:
  the appendix of the RFC that `rfc6979.json` transcribes, vendored.
- **ECDSA verifying on the other curves**: Wycheproof has `ecdsa_*` files
  for the curves this prints, vendored only for secp256k1:

  ```shell
  commit=<the Wycheproof commit above>
  ```

  ```shell
  gh api "repos/C2SP/wycheproof/git/trees/${commit:?}:testvectors_v1" \
      --jq '.tree[].path' \
      | sed -nE 's/^ecdsa_(.*)_sha[0-9a-z]+_(p1363_)?test\.json$/\1/p' \
      | sort -u
  ```

  They are secp160k1, secp160r1, secp160r2, secp192k1, secp192r1,
  secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1 and
  brainpoolP224r1 to brainpoolP512r1. Here those brainpool curves are
  `bpp224r1` to `bpp512r1`, and secp192r1 to secp521r1 are also `nistp192`
  to `nistp521`. A curve of `CURVES` it does not print under either name
  has no Wycheproof file: secp112r1, secp112r2, secp128r1, secp128r2,
  `bpp160r1` and `bpp192r1`.
- **ECDSA signing on secp160k1, secp160r1, secp160r2, secp192k1,
  secp224k1 and `bpp224r1` to `bpp512r1`**: none found in the RFC
  or Wycheproof. The RFC's test vectors are for DSA, the NIST prime curves and
  the binary curves, as the headings this prints show:

  ```shell
  curl -s https://www.rfc-editor.org/rfc/rfc6979.txt \
      | grep -E "^A\.2\.[0-9]+\."
  ```

  Every Wycheproof `ecdsa_*` file names a verification schema, none a
  signing one, as this prints (it reads each file of the commit above):

  ```shell
  repo=repos/C2SP/wycheproof
  for f in $(gh api "${repo}/git/trees/${commit:?}:testvectors_v1" \
      --jq '.tree[].path' | grep '^ecdsa_'); do
    gh api -H 'Accept: application/vnd.github.raw' \
        "${repo}/contents/testvectors_v1/${f}?ref=${commit:?}" \
        | grep -m1 '"schema"'
  done | sort | uniq -c
  ```

  The curves without a Wycheproof file are taken by the next bullet.
- **ECDSA on secp112r1, secp112r2, secp128r1, secp128r2, `bpp160r1` and
  `bpp192r1`**: no outside vector was found in Wycheproof, python-ecdsa or
  the RFC. Wycheproof has no file for them, by the call above. The RFC has
  no appendix for them: the first count this prints is zero, and the
  second, a control for the fetch, is above zero:

  ```shell
  curl -s https://www.rfc-editor.org/rfc/rfc6979.txt \
      | grep -ciE "secp112|secp128|brainpool"
  curl -s https://www.rfc-editor.org/rfc/rfc6979.txt | grep -ci "nist"
  ```

  python-ecdsa defines all of them but secp128r2, by the `curves.py` call
  in the last bullet. Its test files name them in the lines this prints,
  which were read: key generation and signing round trips, interoperability
  with OpenSSL where OpenSSL has the curve, arithmetic on the generator
  (Jacobi coordinates, precomputation), a stored public point in an
  inequality test, and the point of the last bullet. None stores a
  signature to verify, so none is an outside vector for ECDSA:

  ```shell
  dir=<a scratch directory>
  ```

  ```shell
  git clone --quiet --filter=blob:none --no-checkout \
      https://github.com/tlsfuzzer/python-ecdsa "${dir:?}/python-ecdsa"
  ```

  ```shell
  git -C "${dir:?}/python-ecdsa" grep -n -iE \
      "112r[12]|128r1|brainpoolP(160|192)r1" \
      bff40c6cf2340148d410d5b3def0e949c547caf1 -- 'src/ecdsa/test_*.py'
  ```

- **ECDH and point decoding**: Wycheproof has `ecdh_*` files for the
  names this prints, vendored only for secp256k1:

  ```shell
  gh api "repos/C2SP/wycheproof/git/trees/${commit:?}:testvectors_v1" \
      --jq '.tree[].path' \
      | sed -nE 's/^ecdh_(.*)_test\.json$/\1/p' | sort -u
  ```

  They are secp224r1, secp256r1, secp384r1, secp521r1 (some with `_pem`,
  `_webcrypto` or `_ecpoint` variants), the brainpool curves above,
  secp256k1 (with a `_webcrypto` variant), and binary curves that `CURVES`
  does not have. The `_ecpoint` files are named for a bare point, and what
  their cases reach was not read.
- **Schnorr and batch verification**: none found. BIP340 is for secp256k1,
  and this prints its sentence on other curves:

  ```shell
  ref=927b6de9915c9262615a6399de51b200f81e5aa4
  ```

  ```shell
  gh api -H 'Accept: application/vnd.github.raw' \
      "repos/bitcoin/bips/contents/bip-0340.mediawiki?ref=${ref:?}" \
      | grep "not straightforward"
  ```

- **The subgroup check on a curve of cofactor above one**, which this
  prints (secp112r2 and secp128r2):

  ```shell
  uv run python -c "from ecc.curves.curve import CURVES; \
  print([n for n, c in CURVES.items() if c.cofactor > 1])"
  ```

  Wycheproof has no file for either, by the call above. python-ecdsa
  defines secp112r2 and not secp128r2, and defines BRAINPOOLP160r1 and
  BRAINPOOLP192r1, which are `bpp160r1` and `bpp192r1` here:

  ```shell
  ref=bff40c6cf2340148d410d5b3def0e949c547caf1
  ```

  ```shell
  gh api -H 'Accept: application/vnd.github.raw' \
      "repos/tlsfuzzer/python-ecdsa/contents/src/ecdsa/curves.py?ref=${ref:?}" \
      | grep -ohE 'SECP1[12][0-9]r[12]|BRAINPOOLP(160|192)r1' | sort -u
  ```

  Its `src/ecdsa/test_ecdsa.py` (blob
  `c1e25829b8558876021f9cdf3401a95a4cd56075` at commit
  `c98364927e406af037d8f9652ff18094f207dcec`) has a point of secp112r2
  that is on the curve, and tests that expect `Public_key` and
  `point_is_valid` to refuse it as outside the subgroup of the generator.
  This prints them:

  ```shell
  blob=c1e25829b8558876021f9cdf3401a95a4cd56075
  ```

  ```shell
  gh api -H 'Accept: application/vnd.github.raw' \
      "repos/tlsfuzzer/python-ecdsa/git/blobs/${blob:?}" \
      | grep -n -A12 "def test_.*not_scalar_multiple_of_base_point"
  ```

  The point is also checked with python-ecdsa's own code at the pinned
  commit; this prints `True False False`, that is on the curve, refused by
  `point_is_valid`, and the group order times it is not the point at
  infinity:

  ```shell
  uv run --no-project \
      --with "ecdsa @ git+https://github.com/tlsfuzzer/python-ecdsa@${ref:?}" \
      python -I -c "
  from ecdsa.ecdsa import generator_112r2 as g, point_is_valid
  from ecdsa.ellipticcurve import PointJacobi, INFINITY
  x, y = 0x02, 0xBE6AA4938EF7CFE6FE29595B6B00
  P = PointJacobi(g.curve(), x, y, 1)
  print(g.curve().contains_point(x, y), point_is_valid(g, x, y),
        (P * g.order()) == INFINITY)"
  ```

  That one case is an outside vector for secp112r2. It is not vendored,
  and what this package answers for it was not measured. For secp128r2
  none was found.

## What is not pinned, and why

- **The transcribed files** are pinned to a prose revision, or, where the
  upstream is a source file rather than a document, to that file's blob;
  neither makes "identical" a claim that can be made about them. What was
  checked is stated in each entry: matching every value verbatim against
  the pinned text, or a check the entry states on its own.
- **The suite checks the local half, offline.**
  `tests/check_vendored_vectors_test.py` holds each file this ledger names
  to its `ours` line, or its `blob` where there is none. No test asks
  upstream for a blob: a network call in the suite would trade a
  documented drift for a flaky one.
  `.github/workflows/vendored-vectors.yml` asks upstream, weekly. A byte
  mismatch fails the run. A stale pin opens an issue rather than being
  refreshed -- which vector to take next is a decision. The staleness
  check skips an entry whose `behind` reads other than 0, a gap somebody
  has decided not to close being one it would report every week.

## Summary

No count here, and no count in front of the lists below. A count is a
line every open branch has to edit, so it is the one conflict a pull
request vendoring a file is guaranteed to have -- and two branches moving
it to the same new number merge with nothing to decide, into a number
that is wrong. The lists *are* the fact the number summarized, and the
tree answers whenever the number is wanted:

```shell
git ls-files 'tests/_data/*' 'tests/*/_data/*' | grep -cv 'README.md'
```

Against a pinned upstream blob:

- identical byte for byte: the BIP327 vector files,
  `wallet-test-vectors.json`, the Wycheproof vector files and
  `ecdsa_adaptor.json`.
- identical but for a trailing newline: `WYCHEPROOF_COPYING`,
  `dlc_schnorr_test.json` and the BIP445 vector files.
- identical but for CRLF against LF: `bip340_test_vectors.csv`, the
  BIP324 vector files, the BIP374 vector files, the BIP458 vector files
  and the BIP459 vector files -- every csv vendored from bitcoin/bips or a
  pull request to it, so far.
- JSON-equal, reformatted: `pubkey.json`, `ecdsa_sig.json`,
  `ecdsa_custom_nonce_sig.json`.

Not checked byte for byte against one:

- transcribed, every value matched either in the pinned text or, for a
  source file, by the check the entry itself states: `rfc6979.json`,
  `zkp_rangeproof_fixed_vectors.json`, `zkp_generator_vectors.json`,
  `zkp_schnorr_adaptor_vectors.json`,
  `dsa_anti_exfil_test.py`, `secp256k1_symbols.txt`,
  `bitcoin_core_compact_vectors.json` and `secp256k1_recovery_vectors.json`.
- recorded from a program pinned upstream: `chilldkg_vectors.json`.
- not vendored: `zkp_rangeproof_vectors.json` and
  `der_length_vectors.json` (this suite's own).
