# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.10.28

- **The release's attestation names its signer workflow at a commit**
  (issue btclib-org/.github#1870). `release.yml` calls `reusable-build.yml`
  of `btclib-org/.github` at the commit of its tag `v2026.10.26`, where it
  called it at `refs/heads/main`.

  Act on it if you verify a release with `--signer-workflow` naming
  `reusable-build.yml@refs/heads/main`: name the workflow without a ref, as
  `SECURITY.md` does.
- **musig2 and frost refuse a `session_ctx` that is not a `SessionContext`
  as `EccTypeError`** (closes #367). `session_values`, `sign`,
  `partial_sig_verify_` and `partial_sig_agg` of both modules, and
  `partial_sig_agg_adaptor`, `adapt` and `extract_adaptor` of musig2, raised
  `AttributeError` where they read a field of it.

  Act on it if you catch `AttributeError` there: catch `EccTypeError`.

`CHANGELOG.md`'s own `v2026.10.28` section has the rest.

## v2026.10.23

No breaking changes. The `secp256k1` extra asks for `btclib-secp256k1` at
0.8.0.12 or later, past GHSA-8h6f-34jj-7p6c: upgrade `btclib-secp256k1`, or
install `ecc[secp256k1]`.

## v2026.10.20

- **The package is `ecc`, on PyPI and on import, with no alias**
  (issue #306). The distribution `btclib-ecc` is `ecc`, and the import
  package `btclib_ecc` is `ecc`; the module tree under it is unchanged, so
  `btclib_ecc.ecc.dsa` is `ecc.ecc.dsa`. `import btclib_ecc` fails with
  `ModuleNotFoundError` where only `ecc` is installed.

  Act on it: install `ecc` in place of `btclib-ecc`, and import `ecc`
  wherever you imported `btclib_ecc`.
- **The exception classes drop the `BTClib` prefix, with no alias.**
  `BTClibEccException`, `BTClibEccValueError`, `BTClibEccTypeError` and
  `BTClibEccRuntimeError` are `EccException`, `EccValueError`,
  `EccTypeError` and `EccRuntimeError`, in `ecc.exceptions`. Each derives
  from the same built-in as before.

  Act on it if you catch or raise one by name: use the new name.
- **The switch that refuses the bindings is `ECC_NO_LIBSECP256K1`.**
  `BTCLIB_ECC_NO_LIBSECP256K1` is ignored.

  Act on it if you set it: set `ECC_NO_LIBSECP256K1` instead.
- **`ellswift.create_var` is `ellswift.create`, with no alias**
  (closes #312). The signature is unchanged.

  Act on it if you call it: rename the import and the call.
- **Public names whose work is variable-time take the `_var` suffix, with no
  alias** (issue btclib-org/btclib#2687). In `ecc.ecc`:
  `rangeproof.RangeProof.pubk_rings`, `commit_nonce.commit_point_`,
  `dlc_oracle.sig_point_`, `ssa_adaptor.extract` and `extract_adaptor`,
  `pedersen.commitment_from_octets`, `generator_from_octets`,
  `bytes_from_commitment` and `bytes_from_generator`, `musig2.key_agg`,
  `apply_tweak`, `nonce_agg` and `key_agg_and_tweak`, and
  `frost.tweak_ctx_init`, `apply_tweak`, `nonce_agg` and
  `thresh_pubkey_and_tweak` are the same names with `_var`. A trailing
  underscore stays last: `commit_point_var_`, `sig_point_var_`.

  Act on it if you call one: add the suffix.
- **The release's files are named after `ecc`.** The sdist, the wheel and
  the bill of materials are `ecc-<version>.tar.gz`,
  `ecc-<version>-py3-none-any.whl` and `ecc-<version>.cdx.json`, where
  earlier releases attach `btclib_ecc-<version>…`. `gh attestation verify`
  takes `--repo btclib-org/ecc`, with the same `--signer-workflow` and
  `--source-ref`. Releases v2026.9.28 to v2026.10.17 take
  `--repo btclib-org/btclib-ecc`, the name their certificates carry, and
  v2026.9.26 takes `--repo btclib-org/ellipticcurves`.

  Act on it if a script downloads or verifies a release by name: use the
  new names for this release on.
- **The nonce derivations give up after 256 candidates** (closes #275).
  `rfc6979_nonce`, `bip340_nonce` and `commit_nonce` raise
  `EccRuntimeError` where a hash function never yields a candidate in
  1..n-1, so `dsa.sign_` and `ssa.sign_` raise where they looped for ever.

  Act on it if you sign with such a hash function: pass one that behaves
  as a hash.
- **`RangeProof` refuses a ring commitment or a header field that is no
  integer as `EccTypeError`** (issue #276, issue #277). A bool or float
  ring commitment was accepted, and a header field of the wrong type left
  as a builtin `TypeError` or `AttributeError` under
  `check_validity=False`. `max_value` refuses a `min_value` of 0.0 or "",
  which it read as 0.

  Act on it if you build a `RangeProof` by hand: pass ints.
- **`rangeproof`'s refusals no longer quote the value they refuse**
  (closes #301, closes #310). The exponent, minimum value, bit count and
  mantissa are out of the messages.

  Act on it if you match the old text: match the new one.
- **On PyPy, the Python arithmetic leaves gmpy2 unused** (closes #290). A
  gmpy2 installed there no longer makes `Curve.aff_from_jac_var` raise, and
  the `number_theory` functions refuse an `mpz` operand.

  Act on it if you run PyPy and uninstalled gmpy2 for v2026.10.16: nothing
  needs it uninstalled now. Pass `int`s to `number_theory`.

## v2026.10.17

- **`rangeproof` refuses more malformed proofs** (closes #279).
  `RangeProof.assert_valid`, which the constructor runs by default, refuses a
  sign bit that is no bool as `BTClibEccTypeError`; it took `0` and `1`.
  `serialize(check_validity=False)` refuses as `BTClibEccValueError` an
  exponent outside 0..31 beside a nonzero mantissa, a `min_value` outside
  0..2**64-1, sign bits or ring commitments the mantissa does not ask for, and
  a ring commitment wider than the curve's field. It returned octets for an
  exponent from 32 to 255, too few sign bits or a wrong count of ring
  commitments; it raised `IndexError` for too many sign bits, `ValueError` for
  any other exponent, and `OverflowError` for the rest. A sign bit that is no
  bool is refused there too, as `BTClibEccTypeError`. `assert_valid` and
  `serialize` no longer quote a `min_value` they refuse.

  Act on it if you build a `RangeProof` by hand: pass bools as sign bits, and
  catch `BTClibEccValueError` where you caught `OverflowError` or
  `IndexError`.
- **The low-R grind of `dsa` refuses after 256 signatures** (closes #278).
  With `grind=True`, the default, `dsa.sign`, `dsa.sign_` and `dsa.Signer`'s
  `sign` and `sign_` raise `BTClibEccRuntimeError` where 256 signatures in a
  row have a high r. They looped for ever, as a hash function that ignores its
  input makes them.

  Act on it if you sign with such a hash function: pass `grind=False`.

## v2026.10.16

- **Two functions are renamed, with no alias** (closes #232).
  `sec_point.point_from_octets` is `point_from_octets_var`, and so is its
  re-export `curves.point_from_octets`. `ssa.point_from_bip340pub_key` is
  `point_from_bip340pub_key_var`. The suffix says that the time follows the
  key. Code that uses an old name fails with `ImportError` or
  `AttributeError`.

  Act on it if you call either: rename the import and the call, and hand it a
  public key only. btclib 2026.9.29 to 2026.10.9 and btclib-wallet 2026.9.30
  to 2026.10.9 import the old names, so `import btclib.key` and
  `import btclib_wallet.bip32` fail with this release. Use a release of each
  that names the new ones. Until then, keep btclib-ecc 2026.10.10.
- **`rangeproof` refuses an argument that is no integer as
  `BTClibEccTypeError`** (closes #270). `sign` took a bool `min_value`, `exp`
  or `min_bits`, a float `exp` and a `min_bits` of 0.0.
  `RangeProof.sign_key_idx` and `RangeProof.nonce_chain` took a bool `value`.
  `RangeProof` took a bool `exp` or `mantissa`, and a bool or float
  `min_value`. `verify` of a `RangeProof` built with `check_validity=False`
  raises where it answered False for a bool `exp` or `mantissa` or a `None`
  `mantissa`.

  Act on it if you passed one of these: pass an int.
- **`frost` refuses more inputs** (closes #261, closes #262, closes #252). `nonce_gen`
  refuses a `signer_id` of 128 or more. `deterministic_sign` refuses a
  `signer_id` outside `ids` as `BTClibEccValueError`, where -1 and 2**32 and
  above were a bare `OverflowError`. `sign` refuses a `secnonce` that is not 64
  bytes, and `deterministic_sign` an `aux_rand` that is not 32.

  Act on it if you passed one of these at another length or value: pass one
  BIP445 accepts.
- **`ssa.batch_verify` and `batch_verify_` raise for an empty batch**
  (closes #222). They answered False.

  Act on it if you may pass an empty batch: test for it first.
- **The messages of some refusals change** (closes #254, closes #256,
  closes #246). `str_from_string` of non-ASCII bytes and `Envelope.b64decode`
  of a non-ASCII envelope say `non-ascii character in <what> at position
  <n>`, and `hex_string` of a negative integer says `negative integer`. None of
  them quotes the input, and none chains the codec's error.

  Act on it if you match the old text: match the new one.
- **On PyPy, part of the Python arithmetic raises `TypeError` where gmpy2 is
  installed** (issue #290). The Python arithmetic uses gmpy2 wherever gmpy2
  imports, and PyPy's `pow(a, -1, m)` refuses gmpy2's integers
  (pypy/pypy#5207): `Curve.aff_from_jac_var` raises where v2026.10.10
  returned the point. The `gmpy2` extra does not install gmpy2 on PyPy.

  Act on it if you run PyPy with gmpy2 installed: uninstall gmpy2.

## v2026.10.10

- **In v2026.10.8 and earlier, FROST's `deterministic_sign` could leak a
  signer's secret share** (closes #168). It derived one nonce for a threshold
  key and for its negation, which share an x-only key. A coordinator that sent
  one session under both, with no public shares, got two partial signatures
  over one nonce, and their difference is the share. BIP445 0.11.0 derives the
  nonce from the share as `sign` uses it, and `frost` follows BIP445 0.12.0.

  Act on it if you called `deterministic_sign` without public shares, with a
  coordinator you do not trust: upgrade, and treat that secret share as
  exposed.
- **`frost` follows BIP445 0.12.0's interface** (closes #168). `my_id` is
  `signer_id` in `sign`, `deterministic_sign` and `partial_sig_verify_`.
  `nonce_gen` and `nonce_gen_` take `signer_id` as their second parameter,
  before `pub_share`. The nonces of `nonce_gen_` and `deterministic_sign`
  differ from v2026.10.8's for the same inputs, and so do the error messages.
  `deterministic_sign` refuses an `agg_other_nonce` given for one signer, and
  one missing for more.

  Act on it if you use `frost`: pass `signer_id=` where you passed `my_id=`;
  pass `nonce_gen_` a `signer_id` second, `None` where you have none; pass
  `nonce_gen`'s arguments after `sec_share` by keyword. Re-pin any stored
  nonce, partial signature or error message.
- **`musig2.extract_adaptor` returns the adaptor secret as an int, not as its
  32-byte big-endian encoding** (closes #189).

  Act on it if you use the bytes: call `t.to_bytes(32, "big")` on the result.

## v2026.10.8

- **`Rewound` and `NonceChain` no longer print their fields**
  ([GHSA-2wgq-4cfh-5gqh](https://github.com/btclib-org/btclib-ecc/security/advisories/GHSA-2wgq-4cfh-5gqh),
  low). In v2026.10.2 and earlier, the default repr of `Rewound` (from
  `rangeproof.rewind`) printed the blinding factor, the value and the
  message, and that of `NonceChain` (from `RangeProof.nonce_chain`) printed
  the blinding factors and the draws, which with the proof give the blinding
  factors back.

  Act on it if you log or print those results: upgrade, and treat a blinding
  factor, value or message that such a log holds as exposed.
- **v2026.10.2 fixed GHSA-r5pw-9wrg-m3mj: on a curve of cofactor above 1
  (secp112r2, secp128r2), `ssa` refuses a public key outside the subgroup
  generated by G, and batch verification refuses an `r` whose point is outside
  it.** Before, a forged signature verified under such a key, which nobody
  holds. secp256k1 is unchanged.

  Act on it if you verified `ssa` signatures on one of these curves with an
  earlier release: verify them again. One under a key outside the subgroup now
  fails.
- **The attestation bundle is attached as `v<version>.intoto.jsonl`** from
  v2026.10.2 on, where earlier releases attach `v<version>.attestation.jsonl`.
  A script that downloads it by name, or passes it to
  `gh attestation verify --bundle`, uses the new name.

## v2026.10.2

- **`mult_pub_key`, `ecies.derive_keys`, `dsa.assert_as_valid`,
  `dsa.assert_as_valid_` and `dsa.sign_`'s `pub_key` refuse a hybrid public
  key (prefix `0x06` or `0x07`) as `not a public key`** (closes #75). With
  `btclib-secp256k1` installed they accepted it, and without it they refused
  it.

  Act on it if you pass such a key: convert it first, with
  `point_from_octets(key, hybrid=True)`, and pass the point.

- **`pedersen.verify` raises `BTClibEccValueError` for a generator off the
  curve, at infinity or, on a cofactor curve, outside the subgroup generated
  by G** (closes #76). Before, it answered False for an off-curve generator
  and True for an opening under INF, which opens to every value.
  On a cofactor curve `second_generator` returns a different H where its old
  H was outside the subgroup, as at sha256 on secp112r2 and secp128r2.

  Act on it if you pass a generator of your own: pass one from
  `second_generator` or `generator_from_seed`, or catch `BTClibEccValueError`.
  Commitments made under that old H no longer verify.

- **Verifying a release's attestation names a new signer and the tag.**
  `gh attestation verify` takes
  `--signer-workflow btclib-org/.github/.github/workflows/reusable-build.yml@refs/heads/main`
  and `--source-ref refs/tags/v<version>`; SECURITY.md has the command.
  Earlier releases keep `reusable-attest.yml` and take the same
  `--source-ref`.

- **`ssa` signs with a different nonce on a curve whose order is longer than
  the hash's output, such as sha256 on secp384r1 or secp521r1**
  (GHSA-m38m-987v-j55h). Every other pair, secp256k1 with sha256 included,
  signs as before, and old signatures still verify.

  Act on it if you signed with `ssa` on such a pair: rotate the key, and
  re-pin any deterministic signature you stored.

- **`musig2.partial_sig_verify` raises `BTClibEccValueError` for a signer
  index outside `0..len(pub_keys)-1`** (closes #78). A negative index used to
  select a signer from the end.

  Act on it if you pass one: pass the index counted from the front.

- **FROST takes only an int where it takes an integer** (closes #77, closes
  #79). `n`, `t`, an id and the signer index raise `BTClibEccTypeError` for
  anything else, a bool, a float or a str included, where `int()` converted
  `n`, `t` and the ids. `partial_sig_verify_` raises for an id not in `ids`.

  Act on it if you pass such a value: pass an int.

## v2026.9.30

No breaking changes. An installed `btclib-secp256k1` older than the floor
the `secp256k1` extra names still fails the import, and its `ImportError`
now names the installed version and that floor: upgrade `btclib-secp256k1`,
or install `btclib-ecc[secp256k1]`.

## v2026.9.28

### Breaking changes

- **`_utils.int_from_integer` and `hex_string` refuse a `0x` string whose
  digits are not ASCII hex, as `invalid hex integer: what follows 0x is
  not ASCII hex digits`** (closes #21). Before, `int(i, 16)` alone read
  `0x1_0`, and `0x` followed by fullwidth or Arabic-Indic digits, as 16,
  and quoted the string in its refusal. Only ASCII whitespace is
  stripped now: a `0x` string padded with U+00A0, U+3000 or another
  character `str.isspace` counts, ahead of the prefix or after its
  digits, is refused too — by the message above, or by `bytes.fromhex`'s
  own where the padding leaves neither a `0x` spelling nor valid hex.
  Every `Integer` parameter reads through here, `curve.mult`'s private
  key `m` among them.

  Act on it if you pass such a string, or match this refusal's text: pass
  ASCII hex digits, and match `invalid hex integer` alone rather than the
  string it used to quote.

## v2026.9.26

The first release of `btclib-ecc`: there is no earlier version of it
to upgrade from.
