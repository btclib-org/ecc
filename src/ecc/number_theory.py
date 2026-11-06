# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Number theory and modular arithmetic functions.

Implementations originally from
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
and
https://codereview.stackexchange.com/questions/43210/tonelli_var-shanks-algorithm-implementation-of-prime-modular-square-root/43267
with the following modifications:

* type annotated Python3
* minor improvements
* added extensive unit test
"""

from __future__ import annotations

import math
import secrets
import sys
from collections.abc import Sequence
from math import isqrt
from typing import cast

from ecc._utils import hex_string, is_integer
from ecc.alias import Public
from ecc.exceptions import EccTypeError, EccValueError

# the `gmpy2` extra, which a plain install does not have. A gmpy2 that is
# installed and fails to import is not absent, and raises. Off CPython gmpy2
# is not used even where installed, for the reason pyproject.toml gives at the
# extra
if sys.implementation.name == "cpython":
    try:
        from gmpy2 import mpz  # type: ignore[import-untyped]

        _FIELD_TYPES: tuple[type, ...] = (mpz,)
    except (
        ModuleNotFoundError
    ) as exc:  # pragma: no cover -- only an interpreter without gmpy2 reaches this
        if exc.name != "gmpy2":
            raise
        mpz = None
        _FIELD_TYPES = ()
else:  # pragma: no cover -- only PyPy reaches this, and coverage is measured on CPython
    mpz = None
    _FIELD_TYPES = ()

__all__ = [
    "legendre_symbol_var",
    "mod_inv",
    "mod_inv_batch",
    "mod_inv_batch_var",
    "mod_inv_var",
    "mod_sqrt_var",
    "tonelli_var",
    "xgcd_var",
]


def _assert_valid_operand(a: int) -> None:
    """Refuse an operand that is not an integer, a bool not being one.

    A float goes through every function here without complaint --
    `//`, `%` and `*` are all defined for it -- and comes back out of a
    signature that says `int`: `mod_inv_var(3.0, 7)` answers `5.0`, which is
    not a residue and not an error either. `is_integer` is the check, and
    its docstring says why a bool is excluded.

    gmpy2's mpz is an integer too, where the package uses gmpy2 (on CPython,
    where it is installed): it is what `_field_element` makes of a curve's
    modulus, and an operand of that type comes back as one.
    """
    if not (is_integer(a) or isinstance(a, _FIELD_TYPES)):
        raise EccTypeError(f"not an integer: {type(a).__name__}")


def _field_element(i: int) -> int:
    """Return i as gmpy2's mpz where the `gmpy2` extra is installed.

    i itself where it is not. A curve converts its modulus once, and a
    product reduced by an mpz is an mpz, so its group law then runs on GMP.

    The annotation says int: the operators the group law applies, and `pow`,
    answer an mpz as they answer an int. It is not an int subclass, so what
    leaves the package is converted back with `int`.
    """
    return i if mpz is None else cast("int", mpz(i))


def _assert_valid_modulus(m: int) -> None:
    """Refuse a modulus nothing is a residue of.

    Positive, not merely non-zero: zero is the `ZeroDivisionError` of
    `a %= m` and the `ValueError` `pow` raises for a third argument of
    zero, neither of which a caller writing `except EccValueError`
    catches, and a negative modulus would answer with a negative residue
    class that no caller of this module has a use for.
    """
    _assert_valid_operand(m)
    if m < 1:
        raise EccValueError(f"non-positive modulus: {m}")


# every public function here checks its own arguments, rather than five
# private twins doing the work unchecked for the ones that call each
# other: a pair of isinstance calls is a small fraction of the arithmetic
# it stands in front of, an inverse modulo a 256-bit prime being an
# extended Euclid even when C runs it, so the re-checking mod_sqrt_var does
# through tonelli_var and legendre_symbol_var costs less than five more names
# would


def xgcd_var(a: Public, b: Public) -> tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(x, y).

    based on Extended Euclidean Algorithm, see
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    _assert_valid_operand(a)
    _assert_valid_operand(b)
    x0, x1, y0, y1 = 0, 1, 1, 0
    r0: int = b
    r1: int = a
    while r1 != 0:
        q, r0, r1 = r0 // r1, r1, r0 % r1
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return r0, x0, y0


def _no_inverse(m: int) -> EccValueError:
    """Return the error for an operand with no inverse mod m.

    The operand is not named: it may be a secret.
    """
    err_msg = "no inverse mod "
    # int(): m may be gmpy2's mpz, which hex_string refuses
    err_msg += (
        f"{hex_string(int(m))}" if m > 0xFFFFFFFF else f"{m}"
    )  # sourcery skip: remove-unnecessary-cast
    return EccValueError(err_msg)


def _blinding_factor(m: int) -> int:
    """Return a random nonzero factor mod m.

    m == 1 has only the factor 1, every integer being zero modulo it.
    """
    return 1 + secrets.randbelow(m - 1) if m > 1 else 1


def mod_inv_var(a: Public, m: int) -> int:
    """Return the inverse of a (mod m).

    m does not have to be a prime.

    `pow(a, -1, m)` is an Extended Euclidean Algorithm too: on an int,
    CPython's `long_invmod`, which is the loop `xgcd_var` runs with the
    second cofactor dropped; on gmpy2's mpz, GMP's `mpz_invert`. Either way
    it delegates the algorithm to C rather than interpreting it, and that is
    the whole of why it is called. It is not
    a constant-time inverse and neither was the bytecode one; SECURITY.md
    publishes the Python path as variable-time.

    Its duration follows the operand, so a secret one goes to
    `mod_inv` instead: what that duration carries is described
    there, and it is enough to recover a private key from a signature.

    What `pow` does not carry is this module's contract, so the checks
    stay above it and the message below it: a non-invertible operand
    leaves `pow` as a bare `ValueError` naming neither operand, and
    rebuilding the message says more than chaining that one would.
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(m)
    try:
        return pow(a, -1, m)
    except ValueError:
        raise _no_inverse(m) from None


def mod_inv(a: int, m: int) -> int:
    """Return the inverse of a (mod m), timed on a random value instead.

    What `mod_inv_var` is for an operand that is public, this is for one
    that is secret. The extended Euclid under that one takes the
    iterations its input asks for, and for an operand drawn uniformly
    below m what its duration carries is the operand's bit-length: on
    secp256k1's order a 256-bit scalar takes longer than a 128-bit one,
    falling at every step between them. That correlation is
    what the Minerva attack collects -- an ECDSA nonce is
    such a scalar, and a few thousand signing times sorted by it are a
    lattice away from the private key.

    (b*a)^-1 * b is a^-1 for every b invertible mod m, so drawing b at
    random leaves an inverse whose iteration count follows b and tells an
    observer nothing about a. What it adds is two multiplications, two
    reductions and a draw from `secrets`. Fermat's `pow(a, m - 2, m)` is
    the alternative and is flat for a different reason, its ladder
    running on the fixed exponent rather than on a random operand; it is
    not the one chosen.

    The draw is what costs, so a small modulus pays proportionally more:
    on an order of 11 the Euclid is a few iterations and `secrets` is the
    same syscall. Nothing signs with such an order outside the test
    suite.

    Not a constant-time inverse, and no more claiming to be one than
    `curve_group._blinded_jac` does: the duration is still an extended
    Euclid's and still visible, and what the blinding changes is whose it
    is. SECURITY.md publishes the Python path as variable-time, and
    CONTRIBUTING.md has what a name in this library does and does not
    promise about duration.

    m does not have to be a prime, and the blinding holds for any m.
    The factor's gcd with m, a second Euclid timed on the secret factor,
    is taken only when the product has no inverse: a factor that is not
    a unit, which only a composite m draws, is then redrawn, and an
    operand with no inverse raises. The expected number of draws is
    (m - 1) / phi(m). `mod_inv_var` is never handed the operand itself.
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(m)

    while True:
        b = _blinding_factor(m)
        try:
            return mod_inv_var(Public(a * b % m), m) * b % m
        except EccValueError:
            # the product has no inverse: b is a zero divisor, which only
            # a composite m has, or a has none. In the first case redraw;
            # in the second raise about the operand, not the product the
            # caller never formed, without inverting the operand
            if math.gcd(b, m) == 1:
                raise _no_inverse(m) from None


def mod_inv_batch(a: Sequence[int], m: int) -> list[int]:
    """Return every inverse, each timed on a random value instead.

    What `mod_inv` is to `mod_inv_var`, this is to `mod_inv_batch_var`:
    the twin a secret may be handed. Montgomery's trick inverts one
    running product for the whole sequence, so the single extended Euclid
    it spends is timed on a value every element went into -- which is the
    channel, the same one and no smaller for being shared.

    Each element is blinded with a factor of its own rather than the
    sequence with one: `inv(a_i * b_i) * b_i` is `inv(a_i)`, and the
    product the batch forms is then a product of blinded values. One
    factor for all of them would blind that product and leave the ratios
    `a_i / a_j` in the peeled-back inverses, which is what the running
    products are made of.

    So it costs `n` draws from `secrets` and 2n multiplications on top of
    the trick.

    It is still the trick, which is the point of it being a batch at all:
    one extended Euclid for the whole sequence, where `mod_inv` on each
    element spends one each.

    On a composite modulus a factor can be a zero divisor, and an element
    can have no inverse: either fails the batch, which is then answered
    by `mod_inv` on each element in turn, so the cost is at worst n
    independent calls.

    Not constant-time, for the reasons `mod_inv` gives at length. The
    empty sequence is not an error here either.
    """
    _assert_valid_modulus(m)
    for x in a:
        _assert_valid_operand(x)

    if not a:
        return []

    # a factor each, as `mod_inv` draws its one
    factors = [_blinding_factor(m) for _ in a]
    blinded = [Public(x * b % m) for x, b in zip(a, factors, strict=True)]
    try:
        inverses = mod_inv_batch_var(blinded, m)
    except EccValueError:
        # a product has no inverse: a factor is a zero divisor, or an
        # element has none. One at a time, each element draws a factor of
        # its own and redraws its own zero divisors, or raises: n
        # independent calls, where redrawing the whole batch until every
        # factor is a unit would take exponentially many rounds in n. No
        # gcd is taken of the batch factors, and none of them is kept
        return [mod_inv(x, m) for x in a]
    return [i * b % m for i, b in zip(inverses, factors, strict=True)]


def mod_inv_batch_var(a: Sequence[Public], m: int) -> list[int]:
    """Return the inverse of every element of a (mod m), in its order.

    m does not have to be a prime, and every element has to be invertible
    modulo it, as `mod_inv_var` requires of its one operand.

    Montgomery's trick, which libsecp256k1 runs inside
    `secp256k1_ge_set_all_gej_var`: the running products a[0], a[0]*a[1],
    ..., a[0]*...*a[n-1] are formed, the last of them is inverted once,
    and the individual inverses are peeled back off it. So n inverses
    cost one inverse and 3(n-1) products, where n calls to `mod_inv_var`
    are n extended Euclids -- an inverse modulo a 256-bit prime being,
    on an int, some thirty times a product.

    An empty sequence has no inverses and is not an error: it is what a
    caller that filtered its own input is left with.
    """
    _assert_valid_modulus(m)
    for x in a:
        _assert_valid_operand(x)

    if not a:
        return []

    # the running products, the last of which is the one to invert
    acc: list[int] = []
    product = 1
    for x in a:
        product = product * x % m
        acc.append(product)

    try:
        inv = pow(product, -1, m)
    except ValueError:
        # a product is invertible only if every factor is, so at least one
        # element is not: inverting them one at a time reaches it and
        # answers `mod_inv_var`'s own message, naming the operand rather than
        # the product a caller never formed
        return [mod_inv_var(x, m) for x in a]

    # and peeled back off it, from the last element to the first: the
    # inverse of the whole product times the product of everything before
    # element i is the inverse of element i
    inverses = [0] * len(a)
    for i in range(len(a) - 1, 0, -1):
        inverses[i] = inv * acc[i - 1] % m
        inv = inv * a[i] % m
    inverses[0] = inv
    return inverses


def legendre_symbol_var(a: Public, p: int) -> int:
    """Compute the Legendre symbol a|p, as a binary Jacobi symbol.

    p is a prime, a is relatively prime to p (if p divides a, then a|p =
    0). It returns 1 if a has a square root modulo p, -1 otherwise. The
    Jacobi symbol is what is computed, and for a prime modulus the two
    are the same number.

    By the reciprocity recursion rather than by Euler's criterion, which
    is `pow(a, (p - 1) // 2, p)` -- an exponentiation the size of the
    square root the caller is asking about, where this is a gcd. The
    factors of two come out all at once, `a & -a` being the lowest set
    bit, which is libsecp256k1's `secp256k1_ctz64_var`; asking a gcd
    rather than an exponent is what its `secp256k1_fe_is_square_var`
    does, through `secp256k1_jacobi64_maybe_var` and never through a
    power. Its own recursion is the safegcd one, which in bytecode loses
    as every safegcd does -- `curves.curve_group_2` keeps the list.

    The loop's length follows `a`, where an exponentiation's did not.
    SECURITY.md publishes the Python path as variable-time, and nothing
    in the tree asks this about a value that has to stay hidden.
    `curves.curve._is_x_coordinate_var` reaches it for a signature's r,
    the x-coordinate of a serialized xpub, or the -x-u that an
    ElligatorSwift encoding is tested against, and `ecc.ecc.ellswift`
    reaches it directly for the fractions and radicands its map and its
    inverse test, each of them public and on secp256k1 each answered by
    the bindings before this is reached;
    `ecc.ecc.pedersen` and `ecc.ecc.rangeproof` reach it for the residuosity
    octet of a point they are about to write down.
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)

    x = a % p
    result = 1
    while x:
        # every factor of two at once, and the symbol 2|p is -1 for a p
        # of 3 or 5 mod 8, so only an odd count of them turns the sign
        twos = (x & -x).bit_length() - 1
        x >>= twos
        if twos & 1 and p & 7 in {3, 5}:
            result = -result
        # quadratic reciprocity: the operands swap, and the sign turns
        # when both of them are 3 mod 4
        if x & 3 == 3 and p & 3 == 3:
            result = -result
        x, p = p % x, x
    # what is left is the gcd, and a symbol is zero when it is not one:
    # for a prime p that is a multiple of p, which has no square root
    # and is not a non-residue either
    return result if p == 1 else 0


# secp256k1's field prime, spelled here because `curves` imports this module
_SECP256K1_P = 2**256 - 2**32 - 977


def _sqrt_candidate_secp256k1(a: int) -> int:
    """Return a ** ((p + 1) // 4) mod secp256k1's p, for a in 0..p-1.

    The addition chain of `secp256k1_fe_sqrt` in libsecp256k1 (v0.8.0,
    `field_impl.h`): the three blocks of 1s in the exponent, of 2, 22 and
    223 bits, are built as 2^n - 1 powers. It is faster than
    `pow(a, (p + 1) // 4, p)`; btclib-org/ecc#191 holds the script
    that measures it.
    """
    p = _SECP256K1_P

    def sq(x: int, n: int) -> int:
        for _ in range(n):
            x = x * x % p
        return x

    x2 = sq(a, 1) * a % p
    x3 = sq(x2, 1) * a % p
    x6 = sq(x3, 3) * x3 % p
    x9 = sq(x6, 3) * x3 % p
    x11 = sq(x9, 2) * x2 % p
    x22 = sq(x11, 11) * x11 % p
    x44 = sq(x22, 22) * x22 % p
    x88 = sq(x44, 44) * x44 % p
    x176 = sq(x88, 88) * x88 % p
    x220 = sq(x176, 44) * x44 % p
    x223 = sq(x220, 3) * x3 % p
    t = sq(x223, 23) * x22 % p
    t = sq(t, 6) * x2 % p
    return sq(t, 2)


def mod_sqrt_var(a: Public, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    Solve the equation:
        x^2 = a mod p

    and return x; p - x is also a root.

    If a simple solution is not available for p,
    then the Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli_var-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)
    a_p = a % p

    if p == _SECP256K1_P:
        r = _sqrt_candidate_secp256k1(a_p)
    elif p % 4 == 3:
        # inverse candidate is pow(a, (p + 1) // 4, p)
        r = pow(a_p, (p >> 2) + 1, p)
    elif p % 8 == 5:
        # inverse candidate is pow(a, (p + 3) // 8, p)
        r = pow(a_p, (p >> 3) + 1, p)
        if r * r % p == a_p:
            return r
        # another inverse candidate
        r = r * pow(2, p >> 2, p) % p
    else:
        return tonelli_var(Public(a_p), p)

    if r * r % p != a_p:
        err_msg = "no root mod "
        # int(): p may be gmpy2's mpz, which hex_string refuses
        err_msg += (
            f"'{hex_string(int(p))}'" if p > 0xFFFFFFFF else f"{p}"
        )  # sourcery skip: remove-unnecessary-cast
        raise EccValueError(err_msg)
    return r


def tonelli_var(a: Public, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    The Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli_var-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)
    a_p = a % p
    if a_p == 0 or p == 2:
        return a_p

    # Check solution existence for an odd prime p
    if legendre_symbol_var(Public(a_p), p) != 1:
        err_msg = "no root mod "
        # int(): p may be gmpy2's mpz, which hex_string refuses
        err_msg += (
            f"'{hex_string(int(p))}'" if p > 0xFFFFFFFF else f"{p}"
        )  # sourcery skip: remove-unnecessary-cast
        raise EccValueError(err_msg)

    # Factor p-1 on the form q * 2^s (with q odd)
    q, s = p - 1, 0
    while q & 1 == 0:
        s += 1
        q >>= 1
    if s == 1:
        return pow(a_p, (p + 1) // 4, p)

    # Select a z which is a quadratic non residue modulo p, from the
    # first value that can be one: 1 is a square modulo every prime, so
    # its symbol is known before the loop asks for it. A genuine prime
    # always has one below it, half its nonzero residues being
    # non-residues; z reaching p without meeting one is the same
    # violation of "p must be a prime" the t loop below raises on, and it
    # is what a p that is a perfect square does, its Jacobi symbol never
    # being -1.
    z = 2
    while legendre_symbol_var(Public(z), p) != -1:
        z += 1
        if z == p:
            err_msg = "p is not prime: "
            # int(): p may be gmpy2's mpz, which hex_string refuses
            err_msg += (
                f"'{hex_string(int(p))}'" if p > 0xFFFFFFFF else f"{p}"
            )  # sourcery skip: remove-unnecessary-cast
            raise EccValueError(err_msg)
    c = pow(z, q, p)
    r = pow(a_p, (q + 1) // 2, p)
    t = pow(a_p, q, p)
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        t2i = t
        # For a genuine prime p this always finds such an i: the
        # legendre symbol above rules out a == 0, and `a` being a
        # quadratic residue makes `t = a**q` an element of the subgroup
        # of order 2**(s-1), so squaring it reaches 1 at some i < s.
        # Where p is not prime, the legendre symbol above is only a
        # Jacobi symbol and does not rule this out, so the loop's
        # exhaustion -- `for`/`else` running with no `break` -- is the
        # same violation of "p must be a prime" the z search above
        # raises on, rather than a case left for the `while` above to
        # loop on forever.
        for i in range(1, s):
            t2i = t2i * t2i % p
            if t2i == 1:
                # Update next value to iterate
                b = pow(c, 1 << (s - i - 1), p)
                r = (r * b) % p
                c = (b * b) % p
                t = (t * c) % p
                s = i
                break
        else:
            err_msg = "p is not prime: "
            # int(): p may be gmpy2's mpz, which hex_string refuses
            err_msg += (
                f"'{hex_string(int(p))}'" if p > 0xFFFFFFFF else f"{p}"
            )  # sourcery skip: remove-unnecessary-cast
            raise EccValueError(err_msg)

    return r


def _jacobi_var(a: Public, n: int) -> int:
    """Return the Jacobi symbol (a/n), for n odd and positive."""
    x = a % n
    result = 1
    while x:
        while x % 2 == 0:
            x //= 2
            if n % 8 in (3, 5):
                result = -result
        x, n = n, x
        if x % 4 == 3 and n % 4 == 3:
            result = -result
        x %= n
    return result if n == 1 else 0


def _is_strong_probable_prime_base_2_var(n: Public) -> bool:
    """Return True if the odd n > 2 is a strong probable prime to base 2."""
    d = n - 1
    s = (d & -d).bit_length() - 1
    d >>= s
    x = pow(2, d, n)
    if x in (1, n - 1):
        return True
    for _ in range(s - 1):
        x = x * x % n
        if x == n - 1:
            return True
    return False


def _is_strong_lucas_probable_prime_var(n: Public) -> bool:
    """Return True if the odd n > 2 is a strong Lucas probable prime.

    Selfridge's method A picks the parameters: D is the first of 5, -7, 9,
    -11, ... with Jacobi symbol (D/n) = -1, then P = 1 and Q = (1 - D)/4.
    """
    if isqrt(n) ** 2 == n:
        return False
    D = 5
    while (j := _jacobi_var(Public(D), n)) == 1:
        D = -D - 2 if D > 0 else -D + 2
    if j == 0:
        # D has a factor in common with n: n is composite, |D| being < n
        return False
    Q = (1 - D) // 4

    # U_k, V_k and Q^k for k = 1, then for the binary digits of d below
    # the leading one: k -> 2k, and k -> 2k + 1 for a digit 1
    d = n + 1
    s = (d & -d).bit_length() - 1
    d >>= s
    U, V, Qk = 1, 1, Q % n
    for bit in bin(d)[3:]:
        U = U * V % n
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n
        if bit == "1":
            U, V = U + V, D * U + V
            U = (U + n if U % 2 else U) // 2 % n
            V = (V + n if V % 2 else V) // 2 % n
            Qk = Qk * Q % n
    if U == 0 or V == 0:
        return True
    for _ in range(s - 1):
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n
        if V == 0:
            return True
    return False


def _is_prime_var(x: Public) -> bool:
    """Return True if x is an odd prime, by the Baillie-PSW test.

    Trial division by the primes up to 37, then a strong probable prime test
    to base 2, then a strong Lucas test with Selfridge's parameters (Baillie
    and Wagstaff, "Lucas pseudoprimes", Mathematics of Computation 35, 1980).
    No composite below 2^64 passes: Feitsma and Galway listed the base-2
    pseudoprimes below it, and Gilchrist checked that none passes the Lucas
    test. Above 2^64 none is known, which is not a proof.

    Two answers False, being even, and neither caller wants it otherwise:
    the short Weierstrass equation defines no curve in characteristic 2,
    and a subgroup of order 2 holds one point besides infinity.

    Private: it is the test for a curve's p and n, which a caller states
    and does not search for, and the module's public functions take a
    prime on trust.
    """
    if x < 3 or x % 2 == 0:
        return False
    for q in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if x % q == 0:
            return x == q
    return _is_strong_probable_prime_base_2_var(
        x
    ) and _is_strong_lucas_probable_prime_var(x)
