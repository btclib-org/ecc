# ecc

Elliptic curve arithmetic, and the signature, key-agreement and
commitment schemes built on it, in typed Python.

<!-- The badges are what the reader decides with, in three groups: what the
software is and whether it can be used, whether it works, and what the
OpenSSF makes of it.

Inside the second group the gates come first, in the order a commit meets
them, and the sentinels follow in the order section 10 of the organization
standard schedules them -- the badge order *is* the calendar order over
that subset, which is why the two move together or not at all. The day and
hour each sentinel owns live in that section and are not copied here: a
reader wanting the schedule reads it there, where it is still true.

One badge per line keeps a change to one line and every line inside MD013,
whose 80 columns bind only where a space follows them.

A badge that reports no state -- "we use ruff", "we use uv" -- reports a
choice instead, and those are in CONTRIBUTING.md, beside the prose that
says how the choice is enforced.
-->
[![PyPI version](https://img.shields.io/pypi/v/ecc.svg?logo=pypi)](https://pypi.org/project/ecc/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/ecc.svg)](https://github.com/btclib-org/ecc/releases)
[![development status](https://img.shields.io/pypi/status/ecc.svg)](https://pypi.org/project/ecc/)
[![license](https://img.shields.io/github/license/btclib-org/ecc.svg)](https://github.com/btclib-org/ecc/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/ecc)](https://pepy.tech/projects/ecc)
[![supported Python versions](https://img.shields.io/pypi/pyversions/ecc.svg?logo=python)](https://pypi.org/project/ecc/)
[![implementation](https://img.shields.io/pypi/implementation/ecc.svg)](https://pypi.org/project/ecc/)
[![wheel](https://img.shields.io/pypi/wheel/ecc.svg)](https://pypi.org/project/ecc/)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/ecc/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/ecc/main)
[![lint workflow status](https://github.com/btclib-org/ecc/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/lint.yml?query=branch%3Amain)
[![test workflow status](https://github.com/btclib-org/ecc/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/test.yml?query=branch%3Amain)
[![docs workflow status](https://github.com/btclib-org/ecc/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/docs.yml?query=branch%3Amain)
[![documentation build](https://app.readthedocs.org/projects/btclib-ecc/badge/?version=latest)](https://btclib-ecc.readthedocs.io)
[![vendored-vectors workflow status](https://github.com/btclib-org/ecc/actions/workflows/vendored-vectors.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/vendored-vectors.yml?query=branch%3Amain)
[![mutation workflow status](https://github.com/btclib-org/ecc/actions/workflows/mutation.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/mutation.yml?query=branch%3Amain)
[![fuzz workflow status](https://github.com/btclib-org/ecc/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/fuzz.yml?query=branch%3Amain)
[![zkp-oracle workflow status](https://github.com/btclib-org/ecc/actions/workflows/zkp-oracle.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/zkp-oracle.yml?query=branch%3Amain)
[![deps-latest workflow status](https://github.com/btclib-org/ecc/actions/workflows/deps-latest.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/deps-latest.yml?query=branch%3Amain)
[![pypi-install workflow status](https://github.com/btclib-org/ecc/actions/workflows/pypi-install.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/pypi-install.yml?query=branch%3Amain)
[![deps-oldest workflow status](https://github.com/btclib-org/ecc/actions/workflows/deps-oldest.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/deps-oldest.yml?query=branch%3Amain)
[![py-arm-authority workflow status](https://github.com/btclib-org/ecc/actions/workflows/py-arm-authority.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/py-arm-authority.yml?query=branch%3Amain)
[![os-macos workflow status](https://github.com/btclib-org/ecc/actions/workflows/os-macos.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/os-macos.yml?query=branch%3Amain)
[![os-ubuntu workflow status](https://github.com/btclib-org/ecc/actions/workflows/os-ubuntu.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/os-ubuntu.yml?query=branch%3Amain)
[![os-windows workflow status](https://github.com/btclib-org/ecc/actions/workflows/os-windows.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/os-windows.yml?query=branch%3Amain)
[![links workflow status](https://github.com/btclib-org/ecc/actions/workflows/links.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/links.yml?query=branch%3Amain)
[![sdist-rebuild workflow status](https://github.com/btclib-org/ecc/actions/workflows/sdist-rebuild.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/sdist-rebuild.yml?query=branch%3Amain)
[![codeql workflow status](https://github.com/btclib-org/ecc/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/btclib-org/ecc/actions/workflows/codeql.yml?query=branch%3Amain)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/ecc/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/ecc)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15085/badge)](https://www.bestpractices.dev/projects/15085)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/15085/baseline)](https://www.bestpractices.dev/projects/15085)

It is fully annotated and ships `py.typed`.

## What is here

- modular arithmetic: inverse, blinded and variable-time, Legendre
  symbol, square root (`number_theory`)
- the elliptic curve class, over any curve in short Weierstrass form
    - Jacobian coordinates, and the secp256k1 endomorphism
    - double and multi scalar multiplication (Straus's algorithm and
      Bos-Coster's)
    - SEC 1 octet encodings of points and scalars
    - the SEC 2 v1 and v2, NIST and Brainpool curves, and low
      cardinality test curves
- ECDSA, with DER encoding, public key recovery, low-R grinding and
  [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) deterministic
  nonces
- [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
  Schnorr signatures, and their batch verification
- the anti-exfil protocol, and the sign-to-contract commitment it rests
  on, for both signature schemes
- [MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
  multi-signatures and
  [FROST](https://github.com/bitcoin/bips/pull/2070) (draft BIP445)
  threshold signatures, one primitive per round of each protocol
- Diffie-Hellman, and the
  [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
  ElligatorSwift encoding of a public key
- [ECDSA adaptor signatures](https://github.com/discreetlogcontracts/dlcspecs/blob/master/ECDSA-adaptor.md)
  of the DLC specification
- [DLC oracle](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md)
  signatures, BIP340 with a nonce committed in advance, and their
  signature points
- single-signer BIP340 adaptor signatures, after the module
  [BlockstreamResearch/secp256k1-zkp#299](https://github.com/BlockstreamResearch/secp256k1-zkp/pull/299)
  proposes
- [BIP374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
  discrete logarithm equality proofs
- ECIES in the BIE1 layout, the block cipher supplied by the caller
- Pedersen commitments, Borromean ring signatures and the range proofs
  of libsecp256k1-zkp
- the ANSI X9.63 key derivation function and HKDF (`kdf`), and the BIP340
  tagged hash (`hashes`)

For secp256k1 the arithmetic is delegated to
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1),
bindings to Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1), wherever a
call's own guard admits them. They are the `secp256k1` extra below.
Without them, or with the delegation turned off, every call still
answers, on the Python arithmetic, which is slower and not constant-time;
that Python arithmetic serves every other curve anyway, and the suite
validates it against the bindings.
[SECURITY.md](./SECURITY.md)'s "Limitations, not vulnerabilities" states
which calls delegate and what the Python path does and does not hide.

The suite answers to vectors their authors publish -- the BIPs' own,
Wycheproof's and libsecp256k1-zkp's -- and
[tests/_data/README.md](./tests/_data/README.md) pins each vendored file
to the upstream commit it was copied from.

## Installing

```shell
python -m pip install --upgrade "ecc[secp256k1]"
```

The `secp256k1` extra installs the
[libsecp256k1 bindings](https://github.com/btclib-org/btclib-secp256k1).
The quotes are for zsh, which reads the brackets as a glob.

The `gmpy2` extra installs [gmpy2](https://pypi.org/project/gmpy2/), and
the Jacobian group law of the Python arithmetic then runs on GMP's
integers. It changes nothing where the bindings serve. On PyPy the extra
installs nothing, and the package ignores a gmpy2 installed by other means:

```shell
python -m pip install --upgrade "ecc[secp256k1,gmpy2]"
```

## First use

An ECDSA signature, verified from the DER octets a peer would send, and
a BIP340 Schnorr signature:

```python
from ecc.curves import sec_point
from ecc.ecc import dsa, ssa

prv_key = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF

_, pub_key = dsa.gen_keys(prv_key)
assert sec_point.bytes_from_point(pub_key).hex() == (
    "02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
)
sig = dsa.sign(b"hello", prv_key)
assert dsa.verify(b"hello", pub_key, sig.serialize())
assert not dsa.verify(b"HELLO", pub_key, sig.serialize())

msg = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
_, x_pub_key = ssa.gen_keys(prv_key)
assert x_pub_key == int(
    "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", 16
)
assert ssa.verify_(msg, x_pub_key, ssa.sign_(msg, prv_key))
```

The private key and the message are test vector 1 of
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
and `tests/readme_test.py` runs every Python block of this file.

## Security

[SECURITY.md](./SECURITY.md) says how to report a vulnerability, which
versions are supported, and how a published file is traced back to the
run that built it.
[ASSURANCE_CASE.md](./ASSURANCE_CASE.md) argues why the security it states
holds: the threat model, the trust boundaries, the design principles and
the weaknesses countered.

## Contributing

Development is LLM-based: humans are welcome, as long as they are
comfortable with agentic development ;-). A contribution must have been
read and understood by the person who submits it.
[`CONTRIBUTING.md`](./CONTRIBUTING.md#working-with-an-llm) has the rules.

[CONTRIBUTING.md](./CONTRIBUTING.md) has the commands each CI job runs,
verbatim. `uv sync` creates the environment; uv is the only tool that has
to be installed. [REVIEWING.md](./REVIEWING.md) is what a pull request is
answered against.

How the organization decides, and who holds which role, is its
[GOVERNANCE.md](https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md);
what it intends to do, and what it deliberately does not, is its
[ROADMAP.md](https://github.com/btclib-org/.github/blob/main/ROADMAP.md).

## Links

- Documentation: <https://btclib-ecc.readthedocs.io/>
- Source: <https://github.com/btclib-org/ecc>
- Releases: <https://github.com/btclib-org/ecc/releases>
- [CHANGELOG.md](./CHANGELOG.md), and [RELEASE_NOTES.md](./RELEASE_NOTES.md)
  for what a release asks a user to act on

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
