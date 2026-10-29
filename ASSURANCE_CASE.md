# Assurance case

[SECURITY](./SECURITY.md) states what a user can and cannot expect of
ecc in terms of security. This page argues why those expectations
hold: the threat model, the trust boundaries, how secure design
principles are applied, and how common implementation weaknesses are
countered. Each argument below names the file, the test or the workflow
that supports it; where SECURITY.md already states a fact, this page
points at it instead of repeating it.

## What is claimed

- **The answers are right.** A signature, a verification, a key
  agreement, a commitment and a proof agree with the reference each is
  defined by: libsecp256k1 for secp256k1, and the vectors the BIPs, the
  RFCs, Wycheproof and libsecp256k1-zkp publish.
- **Malformed input is refused the way the package says it is.** A public
  function handed an argument it cannot use raises `EccTypeError`
  or `EccValueError`.
- **Where a secret meets the curve, the protection is the one
  SECURITY.md states**, and no more: SECURITY.md says which operations
  cross into libsecp256k1, whose constant-time properties hold on the C
  side of that call, and that the Python arithmetic is published as not
  constant-time.
- **A published distribution is what this tree built.** SECURITY.md's
  *Supported versions* states how that is verified.

## Threat model

ecc is a library in its caller's process. It has no network
client and no way to start a process, and the only files it opens are
its own package data, so every input it has, but for one environment
variable, is one a caller handed it. The command below lists the
top-level name of every module `src/` imports, at any depth of the code
and in any spelling of the statement. Beside the package's own, what it
lists is the one dependency `pyproject.toml` declares,
`typing_extensions`; `btclib_secp256k1`, which is the `secp256k1` extra;
`gmpy2`, which is the `gmpy2` extra and brings in native code, GMP with
MPFR and MPC in its wheels, for the integers of the Python arithmetic;
and standard-library modules, none of which is a network client or a
process launcher. `os` is there for `os.environ` alone, `json` and
`pathlib` to read the curve catalogue under `src/ecc/curves/_data/`,
and `importlib` to import the package's own submodules and read its
version.

```shell
python3 - <<'EOF'
import ast, pathlib
names = set()
for p in pathlib.Path("src").rglob("*.py"):
    for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            names.update(a.name.split(".")[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.level == 0:
            names.add(n.module.split(".")[0])
print(sorted(names))
EOF
```

**What is defended.**

- Private keys, nonces and shared secrets, against recovery from what the
  package returns or raises, and from the timing of the calls that cross
  into libsecp256k1, the multiplications SECURITY.md lists as variable
  time in their scalar excepted.
- The correctness of every verdict, against an adversary who chooses the
  input: a forged signature, proof or commitment opening accepted, or a
  valid one refused.
- The caller's process, against octets built to make a decoder raise an
  exception the package does not document.

**The adversaries.**

- A remote party supplying octets: a signature, a public key, an ECIES
  envelope or a proof received from anyone.
- A counterparty in a protocol: a co-signer in MuSig2 or FROST, the other
  side of a key agreement, the prover of a discrete logarithm equality.
- An observer of timing on the same machine, for the calls that cross
  into libsecp256k1.
- A party tampering with a distribution between this tree and the user.

**What is not defended**, each stated in SECURITY.md's *Limitations, not
vulnerabilities*:

- side channels on the Python arithmetic, which is not constant-time and
  serves every call the dispatch declines, every call in an install
  without the bindings, and every call with the dispatch turned off
- memory disclosure: a secret in a Python object is not zeroized
- a secret handed to a delegated `_var` multiplication, which is
  variable time in its scalar
- the block cipher `ecc.ecc.ecies` takes from its caller, whose
  resistance to side channels is the caller's
- the operating system's random number generator, which the package uses
  through `secrets` rather than seeding one of its own

Nor is the interpreter or the operating system the package runs on: a
library shares its caller's process and has no defence against it.

## Trust boundaries

**The caller and the public API.** Arguments cross from the caller into
the package at every public function, and each is validated there.
CONTRIBUTING.md's *The public surface* states the rule and names the
tests that drive it, `tests/input_validation_test.py` among them;
`tests/serialization_boundary_test.py` drives the same rule where an
object meets octets, text or json, and `tests/integer_policy_test.py`
holds the one policy on integer fields. The caller is trusted with the
choices the API offers it: a caller-imposed nonce, a hash function, a
curve, or `check_validity=False`. Some of those choices select the
Python arithmetic, and SECURITY.md states which.

**The package and the bindings.** Past this boundary is C code the
package does not own. `ecc.curves.curve._libsecp256k1_serves`
decides whether a call may cross. A caller's choice that the bindings do
not take goes to it as a keyword, and only a condition on an input's value
is and-ed on by the call site, so whether anything crosses is decided by one
predicate and one switch, `ecc.curves.is_libsecp256k1_serving`
being how a caller asks. The bindings are trusted for the answer, and the
suite compares the Python arithmetic against them:
`tests/curves/curve_test.py` states it. The bindings being the authority
would make that comparison circular, so `tests/py_arm_authority_test.py`
inventories, per arm, which vectors somebody other than libsecp256k1
published say the Python arm is right. A flaw on the far side is
reported upstream, as SECURITY.md's *What belongs here, and what belongs
upstream* says. `tests/no_bindings_test.py` imports the package in an
interpreter to which the bindings are refused, and holds that it still
answers.

**Octets from outside.** A signature, a public key, an ECIES envelope, a
proof and a share come from parties the package has no reason to trust.
`src/ecc/_utils.py` states the parse contract: a field is as long
as its encoding says, a complete octet string is one whole object, and a
caller's stream is the caller's. `tests/parse_contract_test.py` walks the
package for every public class carrying a `parse`, and holds each to that
contract or names the reason it is excluded. A range proof header names
an exponent and a mantissa, and `src/ecc/ecc/rangeproof.py`
bounds them by `_MAX_EXP` and `_MAX_MANTISSA`, the mantissa being checked
before any ring size is computed from it. An ECIES envelope's MAC is
verified, by `hmac.compare_digest`, before the caller's cipher is handed
a ciphertext.

**Files.** The package opens no file a caller names. What it reads is
its own catalogue of curve parameters, four json files under
`src/ecc/curves/_data/`, once, at import, in
`src/ecc/curves/curve.py`. It also reads the metadata of the
installed distributions: its own version, in `src/ecc/__init__.py`,
and in `src/ecc/_libsecp256k1.py` its requirements and the
bindings' version.

**The environment.** `ECC_NO_LIBSECP256K1` is read once, at
import, in `src/ecc/_libsecp256k1.py`, and can only turn the
delegation off.

## Secure design principles

Saltzer and Schroeder's principles.

- **Economy of mechanism.** One predicate decides the delegation, as
  above, where a copy per call site could drift. Every error the package
  defines derives from `EccException`
  (`src/ecc/exceptions.py`), and `EccValueError` and
  `EccTypeError` derive from `ValueError` and `TypeError`, so
  `except ValueError` catches a value refused by the package.
- **Fail-safe defaults.** The plain name beside a `_var` one is the one a
  secret may be handed, so a caller who does not choose gets the safer
  call: CONTRIBUTING.md's *A `_var` suffix means the operand decides the
  work* says when a name takes the suffix. A hash function that
  is not sha256 itself, by identity, sends a call down the Python path,
  never to an answer computed for a different function.
- **Complete mediation.** Every public function validates its inputs,
  and where it defers the work to a private twin, the twin trusts its
  inputs because its callers checked them (CONTRIBUTING.md's *The public
  surface*).
- **Open design.** The code, the vectors the suite answers to, and the
  limitations are all published: `tests/_data/README.md` says where every
  vendored vector came from, and for one copied from upstream which
  commit it is pinned to,
  and SECURITY.md states what is not defended.
- **Least privilege.** The package holds no socket and runs no program,
  as the census under *Threat model* shows. The one environment variable
  it reads can only take the bindings away, and `ecies` ships no cipher
  of its own, taking the caller's rather than shipping one that would leak
  its key through cache timing.
- **Psychological acceptability.** The choice that matters is made at
  the call site and read there: `mod_inv` beside `mod_inv_var`, `mult`
  beside `double_mult_var`. A verification answers `False` for a
  signature that does not verify and raises for an input it cannot read,
  so a caller can tell a forgery from a mistake (CONTRIBUTING.md's *The
  public surface*, and `tests/bool_contract_test.py`).
- **Layering.** ARCHITECTURE.md states the layers and
  `tests/imports_test.py` holds them. What the package may import of this
  organization's other packages is in CONTRIBUTING.md's *The public
  surface*, and `test_no_module_imports_outside_the_stdlib_and_the_extras`,
  in the same file, holds it.

**Constant time where it is claimed.** It is claimed only of
libsecp256k1: CONTRIBUTING.md's `_var` section sets out the tiers of
duration and puts nothing written in Python in the first. Which
operations cross into libsecp256k1, and which multiplications there are
not constant time in their scalar, is SECURITY.md's *Limitations, not
vulnerabilities*, whose `path:line` citations
`tests/security_citations_test.py` holds to the code they name.

## Common implementation weaknesses

Weaknesses from MITRE's CWE list that a library of this kind is exposed
to, and what counters each.

- **Improper input validation (CWE-20).** The tests under *Trust
  boundaries*, and `tests/name_contract_test.py`, which holds a public
  name to what its prefix promises about its answer.
- **Uncaught exceptions on hostile input (CWE-248, CWE-755).**
  `tests/fuzz_test.py` asserts that every class decoder, and each
  module-level decoder it lists, fails the way the package says it fails,
  whatever it is handed. The wire inputs of musig2, frost and dleq are
  outside it. The targets under `fuzz/`
  run under ClusterFuzzLite in `.github/workflows/fuzz.yml`, and
  `tests/fuzz_corpus_test.py` checks that every seed of their corpus
  still parses.
- **Observable timing (CWE-208).** The `_var` convention and the
  delegation above; what is left is published in SECURITY.md.
- **Weak randomness (CWE-330, CWE-338).** Randomness comes from `secrets`
  (SECURITY.md), and ruff's flake8-bandit rules, selected with the rest
  of `ALL` in `pyproject.toml`, flag a call into the `random` module
  under `src/`. A `dsa` nonce the caller does not impose is derived by
  RFC 6979 and an `ssa` one by BIP340, each checked against the vectors
  its specification publishes. `musig2`, `frost` and `dleq` draw the
  randomness of BIP327's, BIP445's and BIP374's nonce generation from
  `secrets`, and `tests/schemes/musig2_test.py`, `frost_test.py` and
  `dleq_test.py` check the derivation against those BIPs' vectors.
  `borromean` and `ecies` draw scalars from `secrets` directly.
- **Improper verification of a signature (CWE-347).** A scheme whose
  specification publishes vectors is checked against them, and against
  Wycheproof's adversarial secp256k1 vectors in
  `tests/schemes/wycheproof_test.py`, all pinned in `tests/_data/README.md`.
  `.github/workflows/vendored-vectors.yml` runs weekly: it hashes each
  vendored file against the blob recorded there, compares that blob with
  upstream's at the pinned commit, and reports a pin that is no longer
  upstream's tip. `.github/workflows/zkp-oracle.yml`
  builds the flagged libsecp256k1-zkp extension and runs the tests
  marked `zkp` against it.
- **Exposure of sensitive information (CWE-200).** `dsa.Signer.wipe`
  overwrites, on the delegated arm, the buffer a signer built at
  construction, and drops the key on the Python arm; a wiped signer
  refuses to sign either way; SECURITY.md states what a Python `int` holding
  a key still does not allow.
- **Error message containing sensitive information (CWE-209).** The
  rule is the organization's [*A refusal carries no
  secret*](https://github.com/btclib-org/.github#a-refusal-carries-no-secret),
  section 7 of its standard, which asks each such refusal for a test
  calling `assert_secret_free`. `tests/secret_free/__init__.py` is that
  helper, copied from `btclib-org/.github`, and `tests/secret_free_test.py`
  tests it. `test_a_refusal_carries_no_secret`, in the test file of each
  module that takes a private key, a nonce or a secret share, feeds a
  secret to the refusal of each parameter that holds one: a private key, a
  nonce, a secret share, auxiliary randomness or extra entropy. It passes
  each refusal to `assert_secret_free`. A message and its hash are public and
  have no case, and a `_` spelling whose refusal is its twin's has none of
  its own.
  Here, an exception, its cause and its context do not repeat a key passed as a
  public key, a committed value, a blinding factor or a scalar operand; a
  modulus is printed. `str_from_string`'s refusal of a non-ASCII byte,
  `Envelope.b64decode`'s of a non-ASCII str and `hex_string`'s of a negative
  integer print neither the input nor the number.
  The `repr` and `str` of the classes that hold a key or a nonce are checked
  the same way. `tests/schemes/dsa_test.py` checks `dsa.Signer`,
  `tests/schemes/ssa_test.py` `ssa.Signer`, `tests/schemes/rfc6979_test.py`
  `_HmacDrbg`, and `tests/schemes/rangeproof_test.py` `NonceChain`,
  `Rewound` and `_ProveParams`.
  The other exception tests are in `tests/exception_echo_test.py`,
  `tests/curves/sec_point_test.py`, `tests/schemes/dsa_test.py`,
  `tests/schemes/ecies_test.py`, `tests/schemes/nonce_bound_test.py`,
  `tests/schemes/rangeproof_test.py`, `tests/schemes/ssa_tweak_test.py` and
  `tests/utils_test.py`.
- **Type confusion (CWE-843).** mypy runs with `strict = true`
  (`pyproject.toml`) as a hook of the lint gate in
  `.pre-commit-config.yaml`, and `tests/integer_policy_test.py` refuses a
  `bool` where an integer field is expected.
- **Code that is wrong and still passes.** Line and branch coverage of
  the library and of the suite is held at 100% by `fail_under` in
  `pyproject.toml`, and mutation testing, profiled under
  `.github/mutation/` and run by `.github/workflows/mutation.yml`, asks
  whether the suite notices a line that is wrong.
- **Static analysis.** CodeQL analyses the code and the workflows in
  `.github/workflows/codeql.yml`.
- **Supply chain.** SECURITY.md's *Supported versions* describes the
  attestations and the bill of materials. `uv.lock` pins every
  dependency, and CONTRIBUTING.md's *The environment and the gates*
  states that every job installing from it passes `--locked`, and lists
  the exceptions, none of which installs the project's dependencies
  unpinned in the job that builds the published files. Every third-party
  action is pinned to a commit sha, the organization's own reusable
  workflows being called at `@main` as `.github/zizmor.yml` permits and
  gives the reason for; `actionlint`, `zizmor` and `detect-secrets` run as
  hooks in `.pre-commit-config.yaml`.
