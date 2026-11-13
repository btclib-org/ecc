# Performance of the arithmetic

What a scalar multiplication, a point addition and a field inversion
cost on the Python arm, what the literature offers for each, which of
it the tree has, which of it the census in `curves/curve_group_2.py`
has measured and declined, and what that census leaves open. The
figures are below, under their conditions.

The Python arm is not constant-time, and `SECURITY.md` says what that
means. Every Python figure below was taken on secp256k1 with the
bindings off. With the bindings installed, `SECURITY.md`'s *Limitations,
not vulnerabilities* says which calls the Python arm still serves. On a
curve other than secp256k1, `curve._mult_checked` runs the comb for
the generator and for a prepared point, and `_mult`, the regular window
without the endomorphism, for any other point, each on the curve's own
field. Of the figures below, the comb and `_mult` rows are the ones that
carry over. The GLV rows, `mult(m, P)` and the counts of 72 additions
and 125 doublings are secp256k1's own.

## The conditions

The Python figures: one run of one script, `all.py`, in a comment on
issue btclib-org/ecc#212, on CPython 3.15.0rc2, macOS arm64
(Apple silicon), one-minute load average under 2, the bindings off by
`ECC_NO_LIBSECP256K1=1`, secp256k1. A per-call figure is the
best of seven repetitions over the same twenty random 256-bit scalars;
a per-operation figure the best of seven over a fixed set of random
operands, the counts in the script. The same comment holds the script's
output on free-threaded CPython 3.15.0rc2 and on PyPy 3.11.15. The
library's rows are of its `int` arithmetic, which it runs where the
`gmpy2` extra is not installed.

The libsecp256k1 figures: commit 22245ae, built out of tree with
cmake, `Release` (`-O2`), `SECP256K1_ASM=AUTO` on arm64, which builds no
assembly, AppleClang 21, `ECMULT_WINDOW_SIZE=15`, on the same machine,
from its own `bench`, `bench_ecmult` and `bench_internal`. Each figure
is the minimum column of their output, in the first comment on that
issue, unless the page says how it is formed from one.

A ratio is between two figures of the same script.

## add: the point formulas

`mult(m, P)` costs 502 µs. Its regular windows with the endomorphism
make 72 additions and 125 doublings for every scalar
(`_mult_endomorphism_secp256k1_var`'s docstring, counted by
`tests/curves/curve_group_test.py`'s `_CountingGroup`); `add_jac_aff`
costs 2.80 µs and `double_jac` 1.76 µs, not counting their check of a
Jacobian point's form. The multiplication calls `_add_jac_aff` and
`_double_jac`, which check nothing, so the two together are 422 µs, 84%
of the call. Inside them a field multiplication `a * b % p` costs 253
ns, a doubling being seven field operations and a mixed addition eleven.
libsecp256k1 does the doubling in 41 ns and the mixed addition in 79 ns,
with the field multiplication at 7.4 ns.

- **Mixed Jacobian coordinates** (Cohen, Miyaji and Ono 1998): 8M+3S
    for a mixed addition and, with a=0, 3M+4S for a doubling. This is
    what `add_jac_aff` and `_double_jac_helper` do, and what
    libsecp256k1's `gej_add_ge` and `gej_double` do.
- **The 2M+5S doubling** (Explicit-Formulas Database, `dbl-2009-l`)
    trades a multiplication for a squaring. `a * a % p` costs 234 ns
    against 253 ns for `a * b % p`: CPython's `long_mul` takes its
    squaring path when both operands are the same object, which is why
    the census keeps no separate squaring. In libsecp256k1 `field_sqr`
    measures 7.3 ns and `field_mul` 7.4 ns.
- **Unified addition** (Brier and Joye 2002) is for side-channel
    resistance: the census keeps the measurement of its core, without
    the cases, against `add_jac_aff`. libsecp256k1's `gej_add_ge` is
    that formula, with the exceptional cases handled by conditional moves.
- **Complete addition** (Renes, Costello and Batina 2016) retires the
    exceptional cases with more multiplications than the mixed Jacobian
    formulas: `add_jac`'s comment keeps the measurement, for a=0 and for
    a=p-3.
- **Co-Z arithmetic** (Meloni 2007) saves the third coordinate where
    two points share a Z, which is the case in a ladder and in a table.
    The tables here are affine, normalized by Montgomery's trick, so
    the case it helps is already paid for.
- **Delayed reduction**, libsecp256k1's magnitudes on `field_5x52`:
    `add_jac`'s comment keeps the measurement of reducing every
    intermediate as it is formed against the unreduced spelling, because
    the unreduced products reach three thousand bits and Python
    multiplies whatever it is handed. The limbs themselves have no
    routine here: each is an integer operator and a `%`.
- **Solinas reduction** for p = 2^256 - 2^32 - 977: the census
    measures two products by a 33-bit constant and a conditional
    subtraction above `x % p`, which is one call into `long_rem`.
- **Edwards and Montgomery forms** (Bernstein and Lange 2007) need a
    point of order 2 or 4. secp256k1 has prime order.
- **The halving doubling** (`secp256k1_fe_half`): the census keeps its
    cost against `_double_jac_helper`.

The formulas are the right ones. What is left in `add` is the cost
CPython charges for each of the eleven operations, which moves only by
changing who executes them (see *The levers*).

## mult: the scalar multiplication

- **Regular windows with signed odd digits** (Joye and Tunstall 2009)
    for a secret scalar: `_regular_window_loop`, with the table of
    `_signed_odd_multiples_aff`. This is `mult`'s path.
- **GLV** (Gallant, Lambert and Vanstone 2001) with secp256k1's
    endomorphism: `_mult_endomorphism_secp256k1` splits the scalar and
    forms the second table by x * beta. GLS (Galbraith, Lin and Scott
    2009) needs an extension field.
- **wNAF** (Solinas 2000) for a public scalar: `_wNAF_of_m_var`, with
    the table of `_odd_multiples_aff`, in
    `_mult_endomorphism_secp256k1_var`.
- **Hamburg's signed-digit multi-comb** (ePrint 2012/309, section 3.3)
    for the generator: `_mult_fixed_base`, what libsecp256k1's
    `ecmult_gen_gej` runs.
- **Strauss–Shamir with interleaved wNAFs** (Möller 2001) for the
    verification's `s * G - e * P`: `_multi_mult_w_NAF_var`, reached
    through `_double_mult_endomorphism_secp256k1_var`.
- **Bos–Coster** (de Rooij 1994) for the multi-multiplication of a
    batch: `_multi_mult_bos_coster_var`, from `BOS_COSTER_THRESHOLD`
    on. **Pippenger** (1976; Bernstein 2002) is not in the tree:
    `_multi_mult_var`'s docstring keeps the figures of the prototype
    that lost to Bos–Coster at every size tried, its bucket sums being
    additions that cost what any addition costs in Python.
- **The Montgomery ladder** (1987): `_mult_mont_ladder_var`, 1516 µs.

The variants, on the same point and scalars:

| multiplication of a random point                             |   µs |
| ------------------------------------------------------------ | ---: |
| `_mult_endomorphism_secp256k1_var`, wNAFs with GLV           |  449 |
| `_mult_endomorphism_secp256k1`, regular windows with GLV     |  478 |
| `mult(m, P)`, the above with validation, blinding and affine |  502 |
| `_mult`, regular window at w=4 without GLV                   |  696 |
| double-and-add, left-to-right                                |  840 |
| double-and-add, right-to-left                                |  997 |
| double-and-add, recursive (`_mult_recursive_jac_var`)        | 1007 |
| `_mult_jac_var`, the always-add form                         | 1514 |
| `_mult_mont_ladder_var`                                      | 1516 |
| `mult(m, G)`, the comb                                       |  120 |

The wNAFs are 6% under the regular windows, so the regularity `mult`
pays for its scalar costs little; the GLV split is worth 1.46x (696
against 478), since it halves the doublings; and recursion is a loop
with the same primitives, the recursive and the right-to-left
double-and-add being within 1% of each other, while the left-to-right
form wins by adding a fixed point whose Z is one, rather than a general
Jacobian one. The comb is seven to eight and a half times under all
three double-and-adds.

What the census measured and declined, each with where the verdict is
kept: the lambda image in the verification's tables; Hamburg's offset in
place of a parity correction; the x-only multiplication, which saves a
square root that BIP340 verification and `dh.diffie_hellman` have no use
for; the tagged hash from a stored midstate (`hashes.tagged_hash`'s
comment).

What the census leaves open, under *Further improvements*: the joint
sparse form (Hankerson, Menezes and Vanstone, algorithm 3.50) as the
alternative to the interleaved wNAFs of the double multiplication, one
joint recoding of both scalars for fewer additions, and the
state-of-the-art references it lists, none of them measured.

**Batch verification** (Bellare, Garay and Rabin 1998) is
`ssa.batch_verify`: 37.1 ms for 64 signatures against 41.5 ms one by
one, 1.12x, because the Bos–Coster underneath is still interpreted
field arithmetic. `ssa.verify` costs 633 µs a signature.

## inv: the field inversion

- `pow(a, -1, p)` is CPython's `long_invmod`, in C: 8.8 µs. A
    multiplication needs two, one for its table and one for its result,
    3.5% of the call.
- **An addition chain** (Fermat, a^(p-2)): `pow(a, p - 2, p)` costs
    71.8 µs; `number_theory.mod_inv` keeps the measurement, and the
    census its reason, 255 modular squarings in bytecode against one
    C call.
- **safegcd** (Bernstein and Yang 2019) and **the binary GCD** (Pornin
    2020) are what libsecp256k1's `modinv64` does: 1.45 µs
    constant-time, 0.78 µs in its variable-time form. In Python its
    590 division steps would together cost many times the whole `pow`.
- **Montgomery's trick**, one inversion for a table, is what
    normalizes the tables, and the reason a multiplication needs one
    inversion for its table rather than one per entry.
- **GMP**: `gmpy2.invert` takes 571 ns, 15x. It is the one real gain
    on the inversion, and the other side of the first lever below.

## The levers

Each of these changes who executes the operation, not which operation
it is.

1. **gmpy2's `mpz` for the coordinates.** `a * b % p` costs 253 ns on
    `int` and 83 ns on `mpz` (107 ns if `p` stays an `int`, so the
    modulus converts too). The `gmpy2` extra takes this lever: each
    curve converts its modulus to an `mpz` once, and what leaves the
    package is converted back to `int`. A comment on issue
    btclib-org/ecc#213 measures `mult(m, P)` with the extra
    against without, with its script and conditions.
1. **PyPy.** On PyPy 3.11.15 the left-to-right double-and-add runs in
    497 µs, 1.7x, and `mult(m, P)` in 333 µs, 1.5x, with no change to
    the code.
    Threads gain nothing there, PyPy keeping the GIL: sixty-four
    `ssa.verify` calls take 25.8 ms one after another, 32.6 ms on four
    threads and 29.5 ms on eight.
1. **Free-threaded CPython** for independent verifications. Sixty-four
    `ssa.verify` calls: on 3.15 with the GIL, 41.5 ms one after another
    and 41 ms on four or eight threads; on 3.15t, 40.7 ms one after
    another, 12.5 ms on four threads and 9.2 ms on eight, 4.4x. That is
    four times what `batch_verify` gives for the same work. It asks
    nothing of the library's code but that its caches, the comb table
    in particular, build correctly under concurrent first use.

## What transfers to libsecp256k1

Nothing of the above. Mixed Jacobian coordinates, the 3M+4S doubling,
wNAF, GLV, the comb, Strauss–Shamir, safegcd and Montgomery's trick are
all there, in C, constant-time where it matters, on `field_5x52`.
`ssa.verify` at 633 µs against libsecp256k1's `schnorrsig_verify` at
14.6 µs gives the proportion.

What the literature offers that libsecp256k1 does not have on its
verification path is **batch verification by a multi-multiplication**
(Bellare, Garay and Rabin 1998), which BIP 340 was designed to allow.
bitcoin-core/secp256k1#1134 records a batch-verification module,
bitcoin-core/secp256k1#1789 the replacement of `ecmult_multi`'s scratch
space by malloc, with an ABCD cost model to select the algorithm, and
bitcoin/bitcoin#29491 its application to a block.

How much it is worth, from the per-point cost of `ecmult_multi`
measured here (`bench_ecmult`, µs per point, the minimum of its ten
runs):

| points |  1   |  8   | 1023 | 2047 | 4095 | 8191 | 16383 | 32767 |
| ------ | ---- | ---- | ---- | ---- | ---- | ---- | ----- | ----- |
| µs     | 5.17 | 4.44 | 2.81 | 2.52 | 2.33 | 2.19 | 2.03  | 1.88  |

A single verification is one Strauss multiplication of a point and G,
`ecmult_1p_g`, which `bench_ecmult` reports at 5.60 µs a point, so
11.2 µs a call. In a batch each signature contributes two points, R and
P, so its multi-multiplication share is twice the per-point cost: 5.0 µs
at a thousand signatures (the 2047-point row) and 3.8 µs at sixteen
thousand (the 32767-point row). The batch also lifts R, a second
`field_sqrt` at 2.04 µs on top of the one for P that both paths pay,
and no batch amortizes it. bitcoin-core/secp256k1#1134 records 1.20x
with Strauss alone and, with Pippenger, 1.55x at a 256 KB memory limit,
1.78x at 4 MB and 1.95x at 16 MB.

What such a speedup applies to is smaller than a block's validation:

- ECDSA cannot be verified more efficiently in batch without additional
    witness data (BIP 340, *Motivation*), which Bitcoin's signatures do
    not carry, so only Schnorr inputs qualify.
- Bitcoin Core verifies a block's scripts on several threads, and at
    the tip most signatures are hits in the signature cache from the
    mempool. The batch's gain is in initial block download past the
    assumevalid height, on the Schnorr share of the inputs.
- A batch that fails says nothing about which signature failed, so a
    failure falls back to verifying one by one. The randomizers come from a
    CSPRNG seeded by a hash of all of the batch's inputs (BIP 340,
    *Batch Verification*); `ssa.batch_verify` draws them at random
    instead.

Beyond that, a change of curve form is impossible, secp256k1 having
prime order, and the formulas are settled.

## The literature

- Bellare, Garay, Rabin. *Fast batch verification for modular
    exponentiation and digital signatures.* EUROCRYPT 1998.
- Bernstein. *Pippenger's exponentiation algorithm.* 2002.
- Bernstein, Lange. *Explicit-Formulas Database*, `dbl-2009-l`.
- Bernstein, Lange. *Faster addition and doubling on elliptic
    curves.* ASIACRYPT 2007.
- Bernstein, Yang. *Fast constant-time gcd computation and modular
    inversion.* TCHES 2019.
- Brier, Joye. *Weierstrass elliptic curves and side-channel
    attacks.* PKC 2002.
- Cohen, Miyaji, Ono. *Efficient elliptic curve exponentiation using
    mixed coordinates.* ASIACRYPT 1998.
- de Rooij. *Efficient exponentiation using precomputation and vector
    addition chains.* EUROCRYPT 1994.
- Galbraith, Lin, Scott. *Endomorphisms for faster elliptic curve
    cryptography on a large class of curves.* EUROCRYPT 2009.
- Gallant, Lambert, Vanstone. *Faster point multiplication on elliptic
    curves with efficient endomorphisms.* CRYPTO 2001.
- Hamburg. *Fast and compact elliptic-curve cryptography.* ePrint
    2012/309.
- Hankerson, Menezes, Vanstone. *Guide to Elliptic Curve
    Cryptography.* Springer 2004.
- Joye, Tunstall. *Exponent recoding and regular exponentiation
    algorithms.* AFRICACRYPT 2009.
- Meloni. *New point addition formulae for ECC applications.* WAIFI
    2007.
- Möller. *Algorithms for multi-exponentiation.* SAC 2001.
- Montgomery. *Speeding the Pollard and elliptic curve methods of
    factorization.* Mathematics of Computation 48, 1987.
- Pippenger. *On the evaluation of powers and related problems.* FOCS
    1976.
- Pornin. *Optimized binary GCD for modular inversion.* ePrint
    2020/972.
- Renes, Costello, Batina. *Complete addition formulas for prime order
    elliptic curves.* EUROCRYPT 2016.
- Solinas. *Efficient arithmetic on Koblitz curves.* Designs, Codes
    and Cryptography 19, 2000.
