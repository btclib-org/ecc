# Architecture

The package is layered bottom-up. `exceptions` and `alias` underpin the
other modules and import nothing of the package: `exceptions` holds the
error types, `alias` the type aliases. Private `_utils` validates and
converts inputs, and imports only those two.

Three modules stand on those and do not import one another.
`number_theory` (modular arithmetic) imports `_utils` and `exceptions`.
`hashes` (hash function checks and the BIP340 tagged hash) imports
`_utils`, `alias` and `exceptions`. The private `_libsecp256k1` loads the
optional libsecp256k1 bindings and imports `exceptions` and the root
`ecc`, for the distribution's name. `kdf` (X9.63 and HKDF) builds on
`hashes`.

`curves` is the curve arithmetic and the SEC 1 encodings. It imports
`number_theory` and `_libsecp256k1` and not `hashes` or `kdf`. Inside it
`curve_group` comes first, `curve_group_2` and `curve_group_f` build on it,
`curve` on `curve_group` and `curve_group_2`, and `sec_point` on `curve`.
Only `curves/__init__.py` imports `curve_group_f`.

`ecc` is the top layer: the schemes and the modules they share, one file
each. It may import every lower layer, and none of them imports it. Within
it, `dsa` builds on `commit_nonce` and `rfc6979_nonce`, `ssa` on
`commit_nonce` and `bip340_nonce`, `ecdsa_adaptor` on `dsa`, and
`dlc_oracle`, `frost`, `musig2` and `ssa_adaptor` on `ssa`. `rangeproof`
builds on `borromean`, `pedersen` and `rfc6979_nonce`, and `dh` on `kdf`.

`test_the_layers_import_only_downwards`, in `tests/imports_test.py`,
holds the rule. It reads every import statement of every file, a
function-local one included, and fails on a module that imports above its
layer, on `curves` importing `hashes` or `kdf`, and on a lower layer
importing `ecc`. The root loads the public modules lazily, by name, so a
bare `import ecc` counts as importing any of them. A string passed to
`import_module` is not read.
