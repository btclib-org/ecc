# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - every release repeats the same few
    // headings, which is what keeps the page readable scrolling down it;
    // only a duplicate under the same release heading would be the
    // accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

A release's section is written when the release is cut, in the release's
own pull request, from the squash subjects since the previous tag. A
pull request adds no entry; between two releases, the history is
`git log` of `main`. That is sections 9 and 12 of [the organization
standard][std]. [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

Neither file states how many entries it holds: a stated number is one
more line to edit at every release.

## v2026.10.30

### `ssa_halfagg`, BIP458 half-aggregation of BIP340 signatures

`ecc.ecc.ssa_halfagg` aggregates, extends and verifies aggregates, after the
draft of bitcoin/bips#2205, whose vectors run. `verify` refuses an empty
aggregate, which the draft accepts (issue #365).

### `negate` and `negate_jac` raise `EccValueError` for a wrong-length tuple

They raised `EccTypeError` (closes #377).

### frost.py's BIP445 citation is pinned at `ba299ba`

(closes #341)

### BIP374's boundary generation vectors are vendored

`dleq.generate_proof` passes them, `a = n + 1` refused (closes #336).

## v2026.10.28

### `ellswift.xdh`, BIP324's shared secret

It returns the shared secret of two ElligatorSwift encodings, through
`secp256k1_ellswift_xdh` where the bindings serve, and refuses a curve whose
cofactor is not 1 (closes #344).

### musig2 and frost refuse a `session_ctx` that is not a `SessionContext`

As `EccTypeError`, where the first field read raised `AttributeError`
(closes #367).

### The calls of btclib-org/.github name the commit of its tag `v2026.10.26`

`claude-review.yml`'s included, so the release's attestation names
`reusable-build.yml` at that commit (issue btclib-org/.github#1870).

### The publish jobs use `pypa/gh-action-pypi-publish` v1.14.3

(issue btclib-org/.github#1844)

### A release is verified by its repository's id

RELEASING.md and SECURITY.md verify with `--owner btclib-org` and compare the
certificate's repository id, which a rename keeps (closes #349, closes #356).

### uv 0.13.4 or later

`[tool.uv] required-version` is `>=0.13.4`, past GHSA-hq85-5cpj-mr62 (issue
btclib-org/.github#1844).

### `uv.lock` takes setuptools 84.2.1, filelock 4.2.4 and virtualenv 21.14.13

They are past their advisories (issue btclib-org/.github#1849, issue
btclib-org/.github#1844).

### frost is tested on key material from ChillDKG

(closes #342)

### `Sig.parse` is compared with Core and libsecp256k1 on mutated DER

(issue #383, closes #359)

### More edges for `point_from_octets_var`, ellswift and `ssa.sign_`

`point_from_octets_var` at the field's edges (closes #360), the ElligatorSwift
inverse seeded and at its edges (closes #361), and distinct `ssa.sign_` nonces
for messages sharing a prefix, a padding or a digest (closes #372).

### The `xdh` test reads the bindings' calls on PyPy too

It records the names read from the bindings' lib, where PyPy emits no profile
event for a cffi call (closes #398).

### The secp256k1 symbol set moves to upstream's tip

Its re-derivation collates in C (closes #387, closes #321).

### The dev tooling and the pinned hooks move

hypothesis 6.170.5, uv-build 0.13.3, Dependabot's actions bumps and the
pre-commit hook revisions. The check-sdist hook builds with `uv_build<0.14`
(closes #352).

### `dependabot.yml` names the `uv.lock` exception

It says only `uv_build` has a ceiling (issue btclib-org/.github#1818, issue
btclib-org/.github#1848).

### The link check skips the GMP manual page runners cannot reach

(closes #323)

### Docs

The where-the-threshold-lives page is in the docs (closes #364), and `dleq`'s
`G` argument serves another generator, not another curve (closes #332).

### Development is LLM-based

CONTRIBUTING.md and README.md say so, and REVIEWING.md takes the shared part of
btclib-org/.github 72e0222 (issue btclib-org/.github#1846, issue
btclib-org/.github#1904).

## v2026.10.23

### The `secp256k1` extra asks for `btclib-secp256k1>=0.8.0.12`

The extra and the `bindings` group were `>=0.8.0.8`, below 0.8.0.10, which
fixes GHSA-8h6f-34jj-7p6c (closes #343).

### `uv.lock` takes `certifi` 2026.10.19, virtualenv 21.14.12 and GitPython 3.2.1

They are past the advisories `uv audit` refuses (issue
btclib-org/.github#1824, issue btclib-org/.github#1835).

### The dev tooling and the pinned hooks move

hypothesis, pre-commit, ruff and uv-build move, and the `uv_build` ceiling
is below 0.14. astral-sh/setup-uv is 10.3.0, and the pre-commit hook
revisions follow.

### `claude-review.yml` declines zizmor's dangerous-triggers

The `issue_comment` trigger stays, with the ignore on its line and the reason
above it (issue btclib-org/.github#1813).

## v2026.10.20

### The package is `ecc`

The distribution and the import package are `ecc`, with no alias, and so are
the release's files. `BTClibEcc*` is `Ecc*`, and `BTCLIB_ECC_NO_LIBSECP256K1`
is `ECC_NO_LIBSECP256K1` (issue #306).

### The private-key tweak and BIP341's x-only tweaks

`curves.prv_key_tweak_add`, `ssa.prv_key_tweak_add` and
`ssa.pub_key_tweak_add_var` are new; they run on the bindings for secp256k1
and refuse a tweak outside 0..n-1 and a zero sum (issue #304).

### Variable-time public names take `_var`

CONTRIBUTING.md states btclib's `_var` criterion, and public names in
`rangeproof`, `commit_nonce`, `dlc_oracle`, `ssa_adaptor`, `pedersen`, `musig2`
and `frost` take the suffix, with no alias (issue btclib-org/btclib#2687).

### `ellswift.create_var` is `create`

On the Python path the key reaches only `mult`, whose algorithm does not follow
its value, so the plain name holds, with no alias (closes #312).

### The nonce derivations stop at 256 candidates

`rfc6979_nonce`, `bip340_nonce` and `commit_nonce` raise `EccRuntimeError`
where a hash function never yields a valid candidate, so signing no longer
hangs (closes #275).

### `rangeproof` refuses what is no integer

A ring commitment or header field that is no integer is refused as
`EccTypeError` (issue #276, issue #277).

### `rangeproof`'s refusals quote no refused value

They leave out the exponent, minimum value, bit count and mantissa, and a
zero-mantissa proof skips the exponent scaling (closes #301, closes #310).

### gmpy2 is left unused off CPython

On PyPy, `number_theory` keeps to `int`, so an installed gmpy2 no longer makes
`mod_inv_var` raise (closes #290).

### The FROST vectors move to upstream's tips

The vendored files of siv2r/bip-frost-signing are pinned at its tip of
2026-10-19, with a 2-of-128 group and a zero tweak (closes #320).

### `uv.lock` takes aiohttp 3.14.5

It is past the three advisories `uv audit` refuses in 3.14.3 (closes #324).

### CONTRIBUTING.md takes the organization's shared half

The tree's docs drop the maintainer's bypass (issue btclib-org/.github#1740).

### SECURITY.md asks for a fast fix of an easy defect

It takes the organization's paragraph on a defect easy to rediscover (issue
btclib-org/.github#1771).

### The `secret_free` helper refuses a secret printed in groups

It is the organization's, byte for byte (issue btclib-org/.github#1697).

### The pyroma hook builds nothing from source

It takes `--no-build` (issue btclib-org/.github#1763).

### Docs

CONTRIBUTING.md says most wrong values are true, not every one (closes #309),
and ASSURANCE_CASE.md names two more exception tests (closes #311).

## v2026.10.17

### `rangeproof` checks what it serializes

`serialize` checks the header's widths and the counts of sign bits and ring
commitments at `check_validity=False` too, and `assert_valid` refuses a sign
bit that is no bool (closes #279).

### The low-R grind stops at 256 signatures

`dsa`'s grind raises `BTClibEccRuntimeError` after 256 signatures with a high
r, where a hash function that ignores its input kept it looping (closes #278).

### The ellswift inverse test draws enough pairs

It draws 100 pairs where 20 could all miss, as they did once on secp192k1 in
CI (closes #291).

### `verified-signatures.yml` checks the signatures on `main`

After each push to `main` it reports whether every commit pushed is verified
on the forge. It replaces the `required_signatures` rule, which the ruleset no
longer carries (issue btclib-org/.github#1738).

### A merge queues `api-break` instead of cancelling it

The `closed` run of a merged pull request waits for the walk in flight, and a
close without a merge still cancels it (issue btclib-org/.github#1744).

### `uv.lock` takes pydantic 2.14.0

Its pydantic-core has cp315 wheels, so the pyroma hook builds nothing from
source on Python 3.15 (issue btclib-org/btclib#2685).

### Dependabot's bumps

`actions/download-artifact` 8.0.2, `actions/upload-artifact` 7.0.2,
hypothesis 6.168.5, uv-build 0.12.24 and a new digest of the fuzz base image.

## v2026.10.16

### `_var` names follow the algorithm

`sec_point.point_from_octets` and `ssa.point_from_bip340pub_key` are
`point_from_octets_var` and `point_from_bip340pub_key_var`, with no alias,
and so is the re-export `curves.point_from_octets` (closes #232).

### The bare inversions are `mod_inv_var`

The bare `pow(x, -1, n)` over public operands is spelled `mod_inv_var`
(closes #221).

### `rangeproof` refuses an argument that is no integer

It raises `BTClibEccTypeError` for a bool, a float or another type where an
integer is due (closes #270).

### `frost` refuses a `signer_id` out of range

`nonce_gen` refuses one of 128 or more (closes #261), and `deterministic_sign`
one outside `ids` (closes #262).

### `frost` refuses an input of the wrong length

`sign` refuses a `secnonce` that is not 64 bytes, and `deterministic_sign` an
`aux_rand` that is not 32, as BIP445 0.12.1 says (issue #252).

### `ssa.batch_verify` raises for an empty batch

`batch_verify` and `batch_verify_` raise where they answered False
(closes #222).

### Refusals carry no input

`str_from_string` of non-ASCII bytes, `Envelope.b64decode` of a non-ASCII
envelope and `hex_string` of a negative integer refuse without the input
(closes #254, closes #256, closes #246).

### `BTCLIB_ECC_NO_LIBSECP256K1` is an initial state

`set_libsecp256k1_serving(serving=True)` reverses it, and the docstring and
`SECURITY.md` say so (closes #226, closes #238).

### A required binding

`set_libsecp256k1_serving(serving=True, required=True)` makes a call the
bindings decline raise `BTClibEccRuntimeError` (closes #224).

### gmpy2

The Python arithmetic runs on gmpy2's mpz where the optional extra
`btclib-ecc[gmpy2]` is installed (closes #213).

### The gmpy2 extra is off PyPy

The extra and its group carry the marker `implementation_name == 'cpython'`, so
PyPy runs the int arithmetic (closes #288).

### `mod_inv` redraws a zero divisor

On a composite modulus, a blinding factor that is a zero divisor is redrawn
(closes #225).

### The BIP340 signers negate without branching

The nonce and the key are negated without a branch on the y parity
(closes #220).

### The performance page

A page on the performance of the arithmetic reads the census (closes #212).

### Vectors behind upstream

The BIP445 and Wycheproof vectors are refreshed (closes #252), and `frost`
points at the open issue for key generation (closes #244).

### Key recovery is held to outside vectors

Bitcoin Core's and libsecp256k1's vectors hold key recovery (closes #229).

### Fuzzing and concurrency tests

The wire inputs of `musig2`, `frost`, `dleq` and the two adaptors are fuzzed
(closes #228). The tables built on first use are tested under concurrent first
use (closes #214).

### Secret-free refusals and reprs

`assert_secret_free` tests them (closes #263, closes #268).

### `_ProveParams` masks the committed value

Its repr prints `...` for the committed value and for its base-four digits
(closes #271).

### The adaptor proof's `e`

A docstring says that `e` is reduced modulo n (closes #227).

### A local command for the py-arm authority re-derivation

`CONTRIBUTING.md` gives its command and says when to run it (closes #245).

### The actionlint fork, `api-break` and the secret-free helper

They are ported (issue btclib-org/.github#1698, issue
btclib-org/.github#1674, issue btclib-org/.github#1697), and the review call
sets `cache-mode: none` (closes #265).

### `REPOSITORY.md` records the bypass

Strict is off on `main`, a merge through the bypass waits for no required
check, and the maintainer's bypass is everyday practice (issue
btclib-org/.github#1712, issue btclib-org/.github#1695).

### The second tier's algorithm

`CONTRIBUTING.md` says that it closes a channel, not its name (closes #248).

## v2026.10.10

### FROST's deterministic nonce tells a key from its negation

`deterministic_sign` derives its nonce from the share as `sign` uses it, as
BIP445 0.11.0 does, so a threshold key and its negation get different nonces
(closes #168).

### FROST follows BIP445 0.12.0's interface

`my_id` is `signer_id`, and `nonce_gen` takes `signer_id` second. The nonces,
the messages and the checks of `agg_other_nonce` are 0.12.0's, pinned at
siv2r/bip-frost-signing (issue #168).

### ECDSA adaptor signatures

`ecc.ecdsa_adaptor` holds the DLC specification's ECDSA adaptor signatures.
Its nonce is libsecp256k1-zkp's, and the specification's vectors pass
(closes #170).

### The ECDSA adaptor is tested against libsecp256k1-zkp

`zkp-oracle.yml` runs tests that hold `ecdsa_adaptor` to
`btclib_secp256k1.zkp.ecdsa_adaptor`, which the development lock's
btclib-secp256k1 0.8.0.11 carries (closes #172).

### BIP340 adaptor signatures

`ecc.ssa_adaptor` holds single-signer BIP340 adaptor signatures, after
BlockstreamResearch/secp256k1-zkp#299, an open pull request (closes #171).

### `ssa_adaptor.extract_adaptor(sig, pre_sig)`

It takes the name and the argument order of `musig2.extract_adaptor`, not
BlockstreamResearch/secp256k1-zkp#299's `extract_sec(pre_sig, sig)`
(closes #188).

### DLC oracle signatures

`ecc.dlc_oracle`'s `sign_` signs with a nonce the caller gives, and
`sig_point_` computes the point s*G of a signature before it is made
(closes #174).

### `musig2.extract_adaptor` returns an int

It returns the adaptor secret t as an int, the type `ecdsa_adaptor.recover`
returns (closes #189).

### A census of libsecp256k1's speed techniques

`curves/curve_group_2.py`'s docstring maps libsecp256k1 v0.8.0's speed
techniques to the Python arithmetic, taken or not, and why (closes #185).

### Fixed-base multiplication and the square root

Fixed-base multiplication is a signed-digit comb (closes #194). The square
root of secp256k1's field is an addition chain (closes #191).

### ElligatorSwift and the endomorphism

ElligatorSwift tests a square before it inverts (closes #195). The
endomorphism's table is formed by x * beta (closes #193).

### Multi multiplication and the Python arm's `Signer`

The wNAF recoding skips runs of zero bits (closes #192). A multi multiplication
drops a point at infinity (closes #198). The Python arm's `Signer` computes its
key's point once (closes #197).

### The vendored vectors run on the Python arm too

With the bindings installed, the vector tests run on both arms (closes #175).

### `check_vendored_vectors.py` shows why a `gh` call failed

It prints the call's stderr, and retries a server error (closes #183).

### `tests/_data/README.md` defines `refreshed`

`pulled` dates the commit that added a vendored file, `refreshed` each later
commit that changed its bytes, and the entries follow (closes #180).

### The uv export on a Dependabot pull request

`CONTRIBUTING.md` has an owner commit the uv-export hook's output to a
Dependabot uv pull request that needs it (closes #176).
`.clusterfuzzlite/requirements.txt` matches the hook's output (closes #173).

### RELEASING.md runs the dependents' suites and reads the tag back

Before the merge, each dependent's suite runs with the release pull request's
head. After the push, the tag's signature is read back from the API (issue
btclib-org/.github#1647, issue btclib-org/.github#1660).

### What the tag-integrity ruleset does not check

`REPOSITORY.md` says it accepts an unsigned or lightweight `v*` tag on a
commit already on `main` (issue btclib-org/.github#1635).

## v2026.10.8

### The catalogue no longer tests its primes at import

The catalogue builds its curves without testing p and n prime, and the
test suite tests them. A caller's curve is checked as before
(closes #112).

### ECDSA key recovery answers only points of the subgroup

On a curve with a cofactor above 1, key recovery refuses a lifted point outside
the subgroup generated by G, so every key it answers is one `point_from_pub_key`
accepts. secp112r2 and secp128r2 answered keys outside it (closes #125).

### `dependabot.yml` does not say that every workflow passes `--locked`

`.github/dependabot.yml` says the workflows install from `uv.lock` with
`--locked`, bar the exceptions `CONTRIBUTING.md` lists (issue
btclib-org/.github#1538).

### `.gitattributes` marks where the shared copy ends

The `-text` lines for the vendored files sit below a `## This repository in
particular` heading, so they are not compared with the organization's copy
(issue btclib-org/.github#1543).

### `REPOSITORY.md` reads back the web sign-off setting

`REPOSITORY.md` reads `web_commit_signoff_required` back, the organization
setting section 11 of the standard states (issue btclib-org/.github#1540).

### The `Sign-off` check is required

`CONTRIBUTING.md`'s shared half says a pull request whose commits lack the
`Signed-off-by:` trailer cannot merge, and `REPOSITORY.md` lists
`lint / Sign-off` among the required checks (issue btclib-org/.github#1550).

### `CONTRIBUTING.md` says the ack of record is a bot's

*The review* says the maintainer lands their own pull requests through the
bypass, and that the ack of record is a bot's (issue
btclib-org/.github#452).

### The bypass is for emergencies

`CONTRIBUTING.md`, `RELEASING.md`, `REPOSITORY.md` and `REVIEWING.md` say every
pull request lands with an approving review from somebody other than its
author; the bypass is for emergencies (issue btclib-org/.github#1362).

### Earlier entries on how a pull request lands

Entries above that have the maintainer landing without another person's
approval describe the rule before issue btclib-org/.github#1362 (issue
btclib-org/.github#1569).

### The release notes name GHSA-r5pw-9wrg-m3mj, fixed in v2026.10.2

The open section of the release notes names the advisory v2026.10.2 fixed, and
says what a user of `ssa` on secp112r2 and secp128r2 does about it
(closes #135).

### The forms set a type, the history files have no merge driver

Issue forms set `type:`; `.gitattributes` loses `merge=union` and the heading the
entry above added; a release reviews the bestpractices.dev answers (issue
btclib-org/.github#1582).

### The post-release install refreshes the index

RELEASING.md installs the release with `--refresh-package btclib-ecc`,
because uv can answer from a cached index and miss a version just published
(issue btclib-org/.github#1595).

### `--admin` waits for no required check

`CONTRIBUTING.md`'s emergency paragraph says `--admin` skips the
required checks too, and `REVIEWING.md`'s "hold the merge" excepts it
(issue btclib-org/.github#1597).

### Release notes name a change to the release's assets

RELEASING.md asks that RELEASE_NOTES.md name a change to the release's assets
or to how they are verified. RELEASE_NOTES.md names the `.intoto.jsonl` bundle
(issue btclib-org/.github#1596).

### `check-changelog` refuses an entry added to an older release

A `###` heading under a release older than the newest, absent at the merge
base with `origin/main`, is refused (issue btclib-org/.github#1614).

### The symbol set follows upstream's tip

`tests/_data/secp256k1_symbols.txt` is pinned at bitcoin-core/secp256k1's
`186eec1c1b93d71d2131cd228ca16b4b97738f60` and gains `secp256k1_ecmult_const_ge`
and `secp256k1_ecmult_const_gej` (closes #146).

### `rangeproof.sign` warns about its nonce, `_grind_low_r` cites BIP461

`rangeproof.sign`'s docstring says `nonce` must be unique, never reused and
kept secret. `_grind_low_r`'s docstring cites
[BIP461](https://github.com/bitcoin/bips/blob/master/bip-0461.md) (closes #151).

### The bindings are checked against known answers

When the bindings are first selected, they derive one public key and verify one
ECDSA signature, refuse it over another message and verify one BIP340
signature. A wrong answer raises `BTClibEccRuntimeError` (closes #152).

### The README links FROST where the draft is

BIP445 is not on `bitcoin/bips` `master` but in its open pull request
bitcoin/bips#2070, which the README links (closes #143).

### DLEQ proofs follow BIP374 0.3.0

The challenge is reduced modulo n, and a proof with `e` of n or more is
refused, as BIP374 0.3.0 says. Only a challenge hash of n or more, once in
2^128, changes a proof this library makes (closes #149).

### The shared halves and the release's own pull request

A release's section is written in its own pull request (issue
btclib-org/.github#1623). `CONTRIBUTING.md` and `REVIEWING.md` carry .github's
shared text (issue btclib-org/.github#1620, issue btclib-org/.github#1634).

### RELEASING.md tells the release to delete the work-in-progress paragraph

The release that folds the `v2026.11` sections deletes the paragraph that
describes them, in its own pull request (closes #158).

### `Rewound` and `NonceChain` mask their fields in their repr

Their repr names their fields without the values. Unpacking and field access
are unchanged (GHSA-2wgq-4cfh-5gqh).

## v2026.10.2

### The OpenSSF Baseline badge

`README.md`'s badge row ends with the OpenSSF Baseline badge, beside the
Best Practices badge, section 2 of the organization standard admitting it
on the same property (issue btclib-org/.github#1460).

### `pypi-install.yml` retries the install of the version the release published

Each install cell runs `pip install btclib-ecc==<version>` through
btclib-org/.github's `install_published_release.py`, which retries only while
the installer says the pin is not resolvable (issue btclib-org/.github#1458).

### The release's attestation bundle is attached as `*.intoto.jsonl`

`RELEASING.md`'s verification and recovery commands name the bundle
`<tag>.intoto.jsonl`, the name `reusable-github-release.yml` attaches it under
(issue btclib-org/.github#1468).

### `codeql.yml`'s aggregate runs `check_run_jobs.py`

The aggregate's step runs `check_run_jobs.py`, which reads the run's jobs
listing again up to a deadline while a row of `analyze` is unfinished
(issue btclib-org/.github#1463).

### `generate_sbom.py` carries a not-affected list into the bill of materials

`generate_sbom.py` reads `.github/vex.toml`, where the tree lists the
vulnerabilities its release is not affected by, into the document's
`vulnerabilities`; no list, no key (issue btclib-org/.github#1469).

### `SECURITY.md` promises a response time

`SECURITY.md` says a report is acknowledged within 7 days, and a fix or a
published advisory within 90 (issue btclib-org/.github#1460).

### MuSig2 refuses a signer index outside its participant arrays

`partial_sig_verify` raises `BTClibEccValueError` when the signer index is
negative or at least the number of public keys, instead of selecting from the
end or leaking `IndexError` (closes #78).

### `release.yml` audits the lock before it publishes

The `audit` job calls btclib-org/.github's `reusable-audit.yml`, which runs
`uv audit` over what the wheel declares, and both publish jobs wait for its
success (issue btclib-org/.github#1466).

### `CLAUDE.md` carries the shared primary-checkout section

The section *The primary checkout is the maintainer's* is the organization's
shared text, and the *Model* section names only the model to use (issue
btclib-org/.github#1494).

### `generate_sbom.py` is btclib-org/.github's

The `dist` job writes the bill of materials with btclib-org/.github's
`generate_sbom.py`, served from `main`, and the tree keeps no copy of it
(issue btclib-org/.github#1478).

### `CLAUDE.md` names both aggregates a draft pull request fails

`codeql: every job passed` fails a draft as `test: every job passed` does;
only the second is a required check on `main` (issue
btclib-org/.github#1494).

### `Dependency review` is a required check

- **`REPOSITORY.md` reads `lint / Dependency review` back with the other
  required checks** (issue btclib-org/.github#1465).

### `[tool.uv] required-version` is `>=0.12.18`

- **`required-version` reads `>=0.12.18`, not `>=0.12.19`** (issue
  btclib-org/.github#1482): the Dependabot service refused `0.12.19` with
  `tool_version_not_supported`.

### `SECURITY.md` names the latest security review

`SECURITY.md` gives the date of the latest security review and links the issue
that records it (issue btclib-org/.github#1362).

### The curve constructor tests p and n with Baillie-PSW

A base-2 Fermat pseudoprime such as 341 or 561 is refused as p or n
(closes #80).

### A hybrid public key is refused on both arms

`mult_pub_key`, `ecies.derive_keys`, `dsa.assert_as_valid`,
`dsa.assert_as_valid_` and `dsa.sign_` raise `BTClibEccValueError` for a key
with the prefix `0x06` or `0x07`, as `point_from_octets` does (closes #75).

### FROST refuses a signer id outside the session

`partial_sig_verify_` raises `BTClibEccValueError` for an id not in `ids`, and
returns `False` for a public share other than the session's (closes #77).

### FROST coerces no integer

`SessionContext`, `ThresholdInfo`, `sign`, `deterministic_sign` and both
`partial_sig_verify` raise `BTClibEccTypeError` for a `bool`, `float` or `str` as
`n`, `t`, an id or the signer index: `ids=[0, 1.9]` is not `(0, 1)` (closes #79).

### `ASSURANCE_CASE.md` states what the fuzz test, the layering and `--locked` cover

The assurance case no longer claims every decoder is fuzzed, that the package
imports none of the organization's packages, or `--locked` everywhere; four
more module-level decoders are fuzzed (closes #82).

### `BorromeanSig` checks the types of `e0` and of every `s`

`BorromeanSig` raises `BTClibEccTypeError`, from `verify` too, for an `e0` that
is not bytes, an `s` that is not an int or a ring that is not an iterable of
ints. A signature of the right types that does not verify is False (closes #81).

### Pedersen refuses a generator at infinity or outside the subgroup

`commit`, `verify` and `assert_as_valid` raise `BTClibEccValueError` for a
generator off the curve, at infinity or, on a cofactor curve, outside the
subgroup generated by G; `verify` answered instead (closes #76).

### `second_generator` skips a point outside the subgroup

`second_generator` skips a point outside the subgroup generated by G: H changes
where it returned one, as at sha256 on secp112r2 and secp128r2, and never on a
curve of cofactor 1 (issue #76).

### An exception does not repeat a private key passed as a public key

A private key passed as a public key, a committed value and a blinding factor
are not repeated in an exception, its cause or its context. A non-integer
coordinate is named by its type (closes #74).

### A `Signed-off-by:` trailer on every commit of a pull request

*Pull requests* says every commit of a pull request carries a
`Signed-off-by:` trailer, and how to add it (issue
btclib-org/.github#1467).

### The primary-checkout section uses one form for the checkout

- **The section writes the checkout as `"${checkout:?}"` throughout, says
  what `<scratchpad>` is and names the pull** (issue
  btclib-org/.github#1500).

### The `python` inventory has a copy kept in the tree

`docs/source/_inventories/python.inv` is read when `docs.python.org` fails,
so an outage of that site no longer fails the `-n -W` docs build (issue
btclib-org/.github#1508).

### `public-api` is red for a break `RELEASE_NOTES.md` does not name

`release.yml` and `RELEASING.md` say that a red `public-api` means
`RELEASE_NOTES.md` misses a name (closes btclib-org/.github#1517).

### The release's attestation is signed by `reusable-build.yml`, at SLSA Build L3

`release.yml` calls `reusable-build.yml`, which signs the files before the
publish jobs wait for approval (issue btclib-org/.github#1506).

### Exception messages name no scalar operand

`signed_odd_digits`, the functions of `number_theory` and the multiplication
helpers of `curve_group` and `curve_group_2` print no scalar or operand they
refuse, except a modulus, and name a non-integer by its type (closes #100).

### While the bot review is off, `CONTRIBUTING.md` says what stands in for the ack

*The review* says there is no ack of record while `claude-review.yml` is
off, and that a local review of a named sha by a reviewer other than the
author stands in for it (issue btclib-org/.github#1527).

### The release publishes the files the build job built

The publish jobs, `github-release` and `test.yml`'s `dist` job on a release
stop where the `dist` they download differs from the digests
`reusable-build.yml` outputs (issue #83, btclib-org/btclib#2449).

### CONTRIBUTING.md lists the jobs that do not pass `--locked`

CONTRIBUTING.md and `ASSURANCE_CASE.md` no longer say every job passes
`--locked`: they list the exceptions, none of which installs the project's
dependencies unpinned in the build job (btclib-org/btclib#2440, issue #83).

### The verification command pins the tag for every signer

SECURITY.md, RELEASING.md and RELEASE_NOTES.md said a `reusable-attest.yml`
release took no `--source-ref`; it takes the tag, and v2026.9.26 takes
`--repo btclib-org/ellipticcurves` (issue #83, btclib-org/btclib#2447).

### The weekly vendored-vectors check compares bytes

`check_vendored_vectors.py` hashes each vendored file against the blob the
ledger records and compares that blob with upstream's at the pinned commit
(issue #83, btclib-org/btclib#2439).

### `check_vendored_vectors` does not read a removed pin as changed content

A pin whose file upstream deleted or renamed is reported as the commit that
removed it, which the report says may be a deletion or a rename; "no commit"
names a path the branch walked never held (issue #83, btclib-org/btclib#2312).

### A drift line names both commits whole

`check_vendored_vectors.py` prints the pinned commit and upstream's tip as
full shas, so two commits alike in their first twelve characters print as
two (issue #83, btclib-org/.github#1343).

### `ssa` keys and nonce points of a cofactor curve are points of ⟨G⟩

On a curve of cofactor above 1 (secp112r2, secp128r2), `ssa` refuses a key
outside ⟨G⟩, and a batch an `r` whose point is outside it, with `dsa`'s message
(GHSA-r5pw-9wrg-m3mj). secp256k1 is unchanged.

### The BIP340 nonce covers the curve order when the hash is shorter

With a hash shorter than the curve order, such as sha256 on secp521r1, the aux
mask covers the whole key and the nonce the whole order: the `ssa` signatures
of those pairs change, and no other pair's do (GHSA-m38m-987v-j55h).

## v2026.9.30

### Vendored-vector pins follow upstream's tip

Every entry of `tests/_data/README.md` the weekly job reports behind is
pinned at upstream's tip, and no vendored content changes (closes #48).

### `[tool.uv] required-version` follows the `uv` `dependabot-core` bundles to `0.12.19`

`required-version` reads `>=0.12.19`: a floor below the `uv` pin
`dependabot-core` bundles admits a `uv` older than the one Dependabot writes
`uv.lock` with (issue btclib-org/.github#1438).

### `REPOSITORY.md` reads back the imported Read the Docs project

`btclib-ecc.readthedocs.io` serves the documentation, and *Read the Docs*
records the project's settings with the answers their read-backs give
(issue #51).

### `RELEASING.md`'s bundle verification names the signer workflow

The `--bundle` form of *Verify the provenance of an asset* passes
`--signer-workflow "$signer"`, without which `gh attestation verify` refuses
a good release (issue btclib-org/.github#1446).

### A `btclib-secp256k1` too old to import says which version and what to install

An installed release lacking a name `_libsecp256k1` imports still raises, and
the `ImportError` names the installed version, the floor the `secp256k1` extra
declares and how to meet it, instead of the missing symbol alone (closes #56).

### `CONTRIBUTING.md` points a newcomer at `good first issue`

The shared half takes `btclib-org/.github`'s paragraph on the label and its
one search across the organization (issue btclib-org/.github#1362, closes #53).

### `.clusterfuzzlite/.python-version` pins the fuzz image's interpreter

`.clusterfuzzlite/.python-version` names `3.11`, the fuzz image's interpreter,
so that the Dependency Graph's pip job there reads it rather than a root pin
Dependabot does not support yet (issue btclib-org/.github#1436).

### The README carries the OpenSSF Best Practices badge

The row links the tree's bestpractices.dev registration (closes #1).

### An assurance case, and a first use the suite runs

`ASSURANCE_CASE.md` argues the threat model, the trust boundaries and the
design principles, and the README shows a signature made and verified,
which `tests/readme_test.py` runs (issue #52).

### `RELEASING.md`'s griffe step searches `src`

`griffe check` takes `-s . -s src`, the pair `release.yml`'s `public-api`
job passes, where it answered `ModuleNotFoundError` for the previous
release (issue btclib-org/.github#1447).

### `pypi-install.yml` installs the version the release published

The install names `btclib-ecc==<version>` from the tag `release.yml` passes,
where a bare name let a lagging index serve the release before it
(issue btclib-org/.github#1456).

## v2026.9.28

### `REVIEWING.md` lets a filed issue carry its fix

An issue filed from a review may say the fix where one is known: *What is
filed, and what is not* dropped its "no fix", the filing bar standing as it
was (issue btclib-org/.github#1378).

### `codeql.yml`, `REPOSITORY.md` and `dependabot.yml` follow sections 10 and 11

The aggregate accepts `analyze`'s lagging rows (issue btclib-org/.github#1395),
signatures and SHA pinning are read back (issue btclib-org/.github#1409), and
`pre-commit` is an ecosystem left unused (issue btclib-org/.github#1391).

### The fuzz image is pinned by digest, and Dependabot moves it

`.clusterfuzzlite/Dockerfile` builds from `base-builder-python:latest`
pinned to its digest (closes #12), and `dependabot.yml`'s `docker` block is
what proposes the next one (issue btclib-org/.github#1405).

### `codeql.yml` rereads a lagging row and fails on a failed `needs` result

An `analyze` row listed unfinished is read again before it is accepted
(issue btclib-org/.github#1416), and an `analyze` result other than
`success` or `skipped` fails the step (issue btclib-org/.github#1424).

### `REPOSITORY.md` records the `btclib-ecc`/`ellipticcurves` naming exception

Section 3's name-equals-repository rule is declined here, with the
maintainer's decision and its citation, rather than left unexplained
(closes #17).

### The fuzz build installs from `uv.lock`, not the index

`.clusterfuzzlite/build.sh` installs `requirements.txt`, `uv.lock`'s base
dependencies exported with their hashes, with `--require-hashes --no-deps`
before the package itself, instead of resolving off the index (closes #13).

### `_utils.int_from_integer` reads only ASCII hex digits after `0x`

Only ASCII whitespace is stripped, and the refusal no longer quotes the
string, which may be a private key (closes #21).

### `Sig.parse` refuses a long-form or oversized DER length under strict

A DER length octet at 0x80 or above, or an oversized r,s total, is refused
under `strict` instead of CompactSize; errors now name the DER length, not
`var_int` or a psbt caller this tree lacks (closes #8) (closes #14).

### `is_on_curve` and the two cofactor-4 curves get their missing checks

`is_on_curve` refuses an x outside `0..p-1` (closes #7) and a tuple
`(x, 0)` ambiguous with `INF` on a cofactor curve (closes #16); every
public key is confined to the subgroup `G` generates (closes #15).

### The fuzz build's own build backend installs from `uv.lock` too

`requirements.txt`'s `fuzz` group hashes it, and `build.sh` installs the
package `-e --no-build-isolation`, its own backend built from that hash
rather than the index (closes #24).

### `dh.diffie_hellman` validates `dU` before either arithmetic arm sees it

`dU` is read through `curves.scalar_from_prv_key`, and an infinity `QV` is
refused, before the bindings or the Python arithmetic can disagree on
either one (closes #10).

### `Curve()` accepts a cofactor Hasse's bound cannot pin down on its own

The constructor now checks `cofactor*n` against Hasse's bound, in place
of refusing every cofactor but the interval's largest multiple of `n`,
wrong wherever several multiples fit (closes #19).

### `tonelli_var` and `mod_sqrt_var` raise, not hang, on a composite p

The z search is bounded at p, and the inner loop raises
`BTClibEccValueError` when it is exhausted, instead of an outer loop
that ran forever past the "p must be a prime" precondition (closes #9).

### `kdf`, `tagged_hash`, `ecies.encrypt` and `sign` refuse a malformed input

A bare `bytes`, `bytearray` or hash function used to leak a builtin
`TypeError` for a malformed input in `kdf`, `hashes.tagged_hash`,
`ecies.encrypt` and the two `sign`s; each now refuses it by name (issue #11).

### `signed_odd_digits` refuses a non-integer `m`, `w` or `size`

A non-integer used to leak a bare builtin `TypeError` from the comparisons
guarding the recoding; each of the three is now checked and refused as a
`BTClibEccTypeError` ahead of them (closes #34).

### `_libsecp256k1` no longer reads an installed, too-old package as absent

Only `ModuleNotFoundError` naming `btclib_secp256k1` itself means absent; a
name an older, installed package lacks now raises instead of a silent
fallback (closes #25).

### `ec17_13` and `ec19_13`'s test fixtures carry their true cofactor, 1

A genuinely cofactor-2 curve this small has a two-torsion point
`is_on_curve` refuses outright, which an exhaustive sweep reaches;
`secp112r2` carries the cofactor above 1 case now (closes #32).

### `Curve.__init__`'s `order_check` no longer mistakes 2n for n

`_mult_jac_var`, never leaving Jacobian coordinates, replaces the windowed
`_mult`, whose affine table of odd multiples of `G` could hold the curve's
own two-torsion point and read it as infinity (closes #39).

### `_assert_in_subgroup` no longer mistakes 2n for n

The same collision `order_check` was fixed against, at the call site that
confines a parsed public key to ⟨G⟩ on a cofactor > 1 curve: `_mult_jac_var`
replaces the windowed `_mult` there too (closes #42).

### The repository is `btclib-org/btclib-ecc`, not `btclib-org/ellipticcurves`

GitHub's repository was renamed to match the PyPI distribution; every
hardcoded reference in this tree, from `release.yml`'s publish guards to
its own issue citations, now reads `btclib-org/btclib-ecc`.

## v2026.9.26

### The repository opens

The package: elliptic curve arithmetic over any short Weierstrass curve,
the signature, commitment and key-agreement schemes built on it, and the
vectors they answer to (issue btclib-org/btclib#2282).

### `REPOSITORY.md` records what each read-back answers

Each read-back carries what it answered on 2026-09-26; classic
protection's also reads its force-push and deletion switches, and the
environments' their required reviewers (issue btclib-org/btclib#2282).

### The distribution is `btclib-ecc`, imported as `btclib_ecc`

Its exceptions are `BTClibEcc*` and its switch `BTCLIB_ECC_NO_LIBSECP256K1`;
the documentation is `btclib-ecc.readthedocs.io` (issue btclib-org/btclib#2282).
