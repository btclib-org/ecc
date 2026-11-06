# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""SEC compressed/uncompressed point representation."""

import contextlib

from ecc._libsecp256k1 import (
    PubkeyTweakChain as Libsecp256k1PubkeyTweakChain,
)
from ecc._libsecp256k1 import keys as libsecp256k1_keys
from ecc._libsecp256k1 import (
    pubkey_from_prvkey as libsecp256k1_pubkey_from_prvkey,
)
from ecc._libsecp256k1 import shared_point as libsecp256k1_shared_point
from ecc._utils import (
    assert_type,
    bytes_from_octets,
    int_from_integer,
)
from ecc.alias import INF, Integer, Octets, Point
from ecc.curves.curve import (
    Curve,
    PreparedPoint,
    _assert_in_subgroup,
    _assert_valid_ec,
    _libsecp256k1_serves,
    _point_from_sec,
    _y_even_var,
    mult,
    secp256k1,
)
from ecc.exceptions import EccTypeError, EccValueError

__all__ = [
    "PubKey",
    "PubKeyTweakChain",
    "bytes_from_point",
    "bytes_from_prv_key_int",
    "mult_pub_key",
    "point_from_octets_var",
    "point_from_pub_key",
    "prv_key_tweak_add",
    "scalar_from_prv_key",
]

# public key inputs: the curve point, as a tuple, as a PreparedPoint, or
# as the SEC octets of one.
#
# Named where `scalar_from_prv_key`'s union is not, and the difference is
# whether mypy has anything to check: a scalar's spellings are `Integer`
# exactly, so a second name for that union would say nothing, where these
# three types are a union no alias holds
PubKey = Octets | Point | PreparedPoint

# the union at run time, with the buffers bytes_from_octets accepts beside
# bytes. No int: in this library an int is a private key and never a
# public one
_PUB_KEY_TYPES = (bytes, bytearray, memoryview, str, tuple, PreparedPoint)


def scalar_from_prv_key(prv_key: Integer, ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer.

    Here rather than in a converter, and beside `bytes_from_prv_key_int`
    for its reason: a scalar in 1..n-1 is a fact about the curve and
    nothing above it knows more about it than this file does.

    `Integer` and not a `PrvKey` of this module's own, which would be
    that same union of types under a second name and so nothing mypy
    could check; the parameter carries the role the way `mult`'s `m_int`
    does. The spellings this takes are narrower than the ones `Integer`
    names -- `int_from_integer` reads "0xc0ffee" and a short hex string,
    where a key is `n_size` octets or nothing. What rules those out is
    reading them with `bytes_from_octets` and the size handed to it,
    rather than with `int_from_integer`; the annotation could not, the
    two unions being one. A WIF and an extended key are not among the
    spellings: turning one into a scalar is a call a caller makes rather
    than a spelling this layer guesses at (issue btclib-org/btclib#1188).

    The range is checked in Python for every curve. `keys.prvkey_verify`
    is libsecp256k1's answer to the same question and is not called for
    want of anything to gain: a comparison on a value that is already a
    Python int, with no constant-time argument to pay for the call with,
    since whether a key is in range is precisely what the caller is being
    told. The comparison also serves every curve, where the binding is
    secp256k1 alone.
    """
    _assert_valid_ec(ec)

    if isinstance(prv_key, int):
        # through `int_from_integer` for an int this already has: it is
        # where the bool rule lives, so a `True` is refused here in the
        # words every other `Integer` parameter refuses it in, and a real
        # int comes back untouched. The hex spellings it also takes never
        # reach it -- the isinstance above is what keeps "0xc0ffee" out
        q = int_from_integer(prv_key)
    else:
        # `n_size` and not a guess: 32 for secp256k1, where a point is 33
        # or 65, so the size alone separates a scalar from one. That is
        # not true of every curve in the catalogue -- secp160k1,
        # secp160r1, secp160r2 and secp224k1 have an `n_size` equal to
        # their compressed point size -- and there a point is refused by
        # the range check below instead, its 02 or 03 prefix putting the
        # integer past n. The refusal is the same; only which line makes
        # it differs
        q = int.from_bytes(bytes_from_octets(prv_key, ec.n_size), "big")

    if not 0 < q < ec.n:
        raise EccValueError("private key not in 1..n-1")

    return q


def _scalar_from_tweak(t: Integer, ec: Curve) -> int:
    """Return a tweak as the integer in 0..n-1 libsecp256k1 takes.

    Refused, not reduced, out of that range: libsecp256k1 refuses such a
    tweak, and BIP32 and BIP341 each refuse it rather than reduce it.
    """
    tweak = int_from_integer(t)
    if not 0 <= tweak < ec.n:
        raise EccValueError("tweak not in 0..n-1")
    return tweak


def prv_key_tweak_add(prv_key: Integer, t: Integer, ec: Curve = secp256k1) -> int:
    """Return the private key plus a tweak, modulo n.

    The private half of `tweak_add_var`: the public key of the answer is
    the public key of prv_key plus t*G. BIP32's private derivation is
    this sum. The two differ on the tweak: `tweak_add_var` reduces it
    modulo n, and this refuses one out of 0..n-1, as libsecp256k1 does. A
    sum of zero is no private key and is refused.

    On secp256k1 the bindings compute the sum,
    `secp256k1_ec_seckey_tweak_add`, in constant time; the Python checks
    and conversions around that call are not, and neither is Python's `%`
    on the other arm. SECURITY.md's limitations name the Python steps.
    `ssa.prv_key_tweak_add` is BIP341's sum, which negates the key first
    where its point has an odd y.
    """
    q = scalar_from_prv_key(prv_key, ec)
    tweak = _scalar_from_tweak(t, ec)

    if _libsecp256k1_serves(ec, None):
        try:
            tweaked = libsecp256k1_keys.prvkey_tweak_add(q, tweak)
        except ValueError as e:
            # key and tweak are in range, so the one sum refused is zero
            raise EccValueError("tweaked private key is zero") from e
        return int.from_bytes(tweaked, byteorder="big", signed=False)

    q = (q + tweak) % ec.n
    if q == 0:
        raise EccValueError("tweaked private key is zero")
    return q


def bytes_from_point(Q: Point, ec: Curve = secp256k1, compressed: bool = True) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """
    _assert_valid_ec(ec)
    assert_type(compressed, bool, "compressed")
    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        raise EccValueError("no bytes representation for infinity point")

    bytes_ = Q[0].to_bytes(ec.p_size, byteorder="big", signed=False)
    if compressed:
        return (b"\x03" if (Q[1] & 1) else b"\x02") + bytes_

    return b"\x04" + bytes_ + Q[1].to_bytes(ec.p_size, byteorder="big", signed=False)


def bytes_from_prv_key_int(
    prv_key_int: Integer, ec: Curve = secp256k1, compressed: bool = True
) -> bytes:
    """Return the public key of a scalar, as SEC octets.

    This is bytes_from_point(mult(prv_key_int, ec.G, ec), ec, compressed)
    and answers what that answers, the edges included: the scalar is
    reduced mod n, and zero -- the infinity point -- has no
    representation and raises.

    That composition is what BIP32 derivation and every private-to-public
    conversion do once per key (issue btclib-org/btclib#127). For secp256k1 this
    never materializes the point: keys.pubkey_from_prvkey is one
    secp256k1_ec_pubkey_create plus one serialize, with the compressed flag
    passed straight through, so the bindings are the ones writing the compressed
    encoding rather than this package slicing it out of the uncompressed one
    (issue btclib-org/btclib#459).
    """
    _assert_valid_ec(ec)
    # before the bindings, which take it as the C bool they serialize with
    assert_type(compressed, bool, "compressed")
    q = int_from_integer(prv_key_int) % ec.n

    # q == 0 is the infinity point, which the bindings reject as a scalar
    if q and _libsecp256k1_serves(ec, None):
        return libsecp256k1_pubkey_from_prvkey(q, compressed)

    return bytes_from_point(mult(q, ec=ec), ec, compressed)


def point_from_octets_var(
    pub_key: Octets, ec: Curve = secp256k1, *, hybrid: bool = False
) -> Point:
    """Return a tuple (x_Q, y_Q) that belongs to the curve.

    Return a tuple (x_Q, y_Q) that belongs to the curve according to SEC
    1 v.2, section 2.3.4.

    The compressed prefixes are the only branch libsecp256k1 serves, and
    the whole cost of the function is there: lifting x to a point is a
    modular square root, nearly all of that cost on either arm, and
    delegated it costs a small fraction of what the Python one does,
    while the 65-byte forms carry the y and cost the same either way
    (issue btclib-org/btclib#284).

    hybrid admits the 0x06 and 0x07 prefixes of that same section, which carry
    both coordinates like 0x04 does and repeat the parity of y in the prefix. It
    is off by default, and not out of squeamishness: the point is a point, and
    libsecp256k1's ec_pubkey_parse takes all three 65-byte prefixes
    (eckey_impl.h). What decides is where the parsed key goes next -- addresses,
    WIF and the descriptor language have no hybrid form to render, and nothing
    in bitcoin produces one. Consensus has to accept what was mined instead:
    Core rejects hybrid keys only under STRICTENC, so the script engine is the
    one caller that asks for them (issue btclib-org/btclib#129). It is refused
    rather than read for its truth: its `True` is the permissive value, and
    most non-bools are true, so `hybrid="no"` would parse the very prefixes
    it was written down to keep out.

    On a curve of cofactor above 1 a point on the curve need not be a
    point of ⟨G⟩: `_assert_in_subgroup` refuses one that is not, after
    the on-curve check every branch already makes and before either
    coordinate leaves this function (issue btclib-org/ecc#15).
    """
    assert_type(hybrid, bool, "hybrid")
    _assert_valid_ec(ec)
    pub_key = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))

    bsize = len(pub_key)  # bytes
    prefix = pub_key[0]
    if prefix in {0x02, 0x03}:  # compressed point
        if bsize != ec.p_size + 1:
            err_msg = "invalid size for compressed point: "
            err_msg += f"{bsize} instead of {ec.p_size + 1}"
            raise EccValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1:], byteorder="big")
        y_Q = _y_even_var(x_Q, ec)  # also check x_Q validity
        Q = x_Q, y_Q if prefix == 0x02 else ec.p - y_Q
        # y_Q == 0 is possible here: x_Q is this curve's real two-torsion
        # x on a curve of cofactor above 1, _y_even_var lifting it to 0
        # without complaint, exactly the ambiguous tuple Curve.is_on_curve
        # exists to refuse. require_on_curve (is_on_curve underneath) is
        # asked before _assert_in_subgroup for that reason --
        # _assert_in_subgroup's own precondition is a point already on the
        # curve, and its Jacobian arithmetic reads y == 0 as infinity
        # exactly as the affine convention does, so it does not catch what
        # is_on_curve is what refuses (issue btclib-org/ecc#16)
        ec.require_on_curve(Q)
        _assert_in_subgroup(Q, ec)
        return Q
    if prefix == 0x04 or (hybrid and prefix in {0x06, 0x07}):  # both coordinates
        if bsize != 2 * ec.p_size + 1:
            err_msg = "invalid size for uncompressed point: "
            err_msg += f"{bsize} instead of {2 * ec.p_size + 1}"
            raise EccValueError(err_msg)
        x_Q = int.from_bytes(pub_key[1 : ec.p_size + 1], byteorder="big", signed=False)
        Q = x_Q, int.from_bytes(pub_key[ec.p_size + 1 :], byteorder="big", signed=False)
        if Q[1] == 0:  # infinity point in affine coordinates
            raise EccValueError("no bytes representation for infinity point")
        # 0x06 says y is even and 0x07 says it is odd, so a hybrid prefix
        # is redundant with the coordinate that follows it -- and a prefix
        # disagreeing with its own coordinate is not a point. libsecp256k1
        # makes this very check, before asking whether the point is on the
        # curve; without it this package would take a key that the bindings, and
        # therefore consensus, refuse
        if prefix != 0x04 and Q[1] % 2 != prefix - 0x06:
            err_msg = f"y is {'odd' if Q[1] % 2 else 'even'}"
            err_msg += f", against the hybrid prefix 0x{prefix:02x}"
            raise EccValueError(err_msg)
        if ec.is_on_curve(Q):
            _assert_in_subgroup(Q, ec)
            return Q
        raise EccValueError("point not on curve")
    # never echo the octets: a 33-byte 0x00-prefixed input
    # is the key field of an xprv, i.e. a private key
    raise EccValueError(f"not a point: prefix 0x{pub_key[:1].hex()}")


def _assert_pub_key_type(pub_key: PubKey) -> None:
    """Refuse a type no spelling of a public key has.

    Asked at the top of the parse, not inferred from whichever spelling failed
    last: a value of no key type at all is an EccTypeError here, kept
    apart from the EccValueError a spelling raises once its type is
    right and its content is not, so "this key is not on the curve" and "this is
    not a key at all" answer as two different classes rather than one.

    The difference is what a boolean verification reads, and issue
    btclib-org/btclib#814 is where it is stated: `dsa.verify` answers False
    about a value of a declared type and refuses a type it does not declare.
    The union is closed, so the question has an answer here;
    `ssa.point_from_bip340pub_key_var` ends in this same refusal for the same
    reason.

    Never echo the input: it may be private material passed by mistake, which is
    the very confusion issue btclib-org/btclib#143 is about -- an int is a
    private key here, so it is refused as a type rather than reported as a
    public key that does not verify.
    """
    if not isinstance(pub_key, _PUB_KEY_TYPES):
        raise EccTypeError("not a public key")


def point_from_pub_key(pub_key: PubKey, ec: Curve = secp256k1) -> Point:
    """Return an elliptic curve point tuple from a public key.

    `point_from_octets_var` is the parse of the one spelling that has to be
    parsed; this is that parse with the two spellings that are already a point
    in front of it, and it lives here for the reason `scalar_from_prv_key`
    does -- what a public key is, at this layer, is a point of the curve, and
    nothing above knows more about one than this file (issue
    btclib-org/btclib#1188). A spelling that carries a network or a
    compression flag is not among them, an extended key being one.

    **A prepared point is read as the point it holds.**
    `curves.PreparedPoint` is a `Point` plus a caller's word that it will
    be multiplied again, and the word is the whole of the difference: a
    point is the point's. What is *not* is the memoized tables, which
    whatever reads them reads off the object and not through here.

    Nothing compares a curve on the way through: a prepared point of
    another curve fails the `is_on_curve` its tuple then faces, exactly
    as a bare `Point` of that curve does and with the same message.

    A tuple is confined to ⟨G⟩ here as `point_from_octets_var` confines the
    octets it parses, on a curve whose cofactor makes the two different
    (issue btclib-org/ecc#15).
    """
    _assert_valid_ec(ec)
    _assert_pub_key_type(pub_key)
    if isinstance(pub_key, PreparedPoint):
        return point_from_pub_key(pub_key.point, ec)

    if isinstance(pub_key, tuple):
        if ec.is_on_curve(pub_key) and pub_key[1] != 0:
            _assert_in_subgroup(pub_key, ec)
            return pub_key[0], pub_key[1]
        raise EccValueError("not a valid public key")
    # it must be octets
    # never echo the input, which may be private material passed by mistake,
    # nor chain the parse failure that may have: raised outside the handler,
    # so that __context__ is empty too
    with contextlib.suppress(TypeError, ValueError):
        return point_from_octets_var(pub_key, ec)
    raise EccValueError("not a public key")


# one byte each, to be compared with `sec[:1]`
_HYBRID_PREFIXES = (b"\x06", b"\x07")


def _sec_from_pub_key(pub_key: PubKey, ec: Curve) -> bytes:
    """Return the SEC octets of a public key, unproven, however spelled.

    `point_from_pub_key` proves the octets a point of the curve -- for a
    compressed key a field square root -- and a caller going on to verify a
    signature under them, to tweak a taproot key with them, or to multiply them
    by a scalar for a shared point, hands them to a call whose own parse is that
    same proof: the two together lift one x twice, which is issue
    btclib-org/btclib#887. `ecc.ecc.dsa.verify_` is one such caller and
    `ecc.ecc.ecies.derive_keys` another, the second through
    `_mult_sec_compressed` below rather than directly.

    So this is that conversion with the proof left out, and it is private
    because the guarantee is the caller's to complete: whatever these
    octets are handed to is what refuses a key that is no point, and it is
    the caller that turns the `ValueError` into this package's own.

    A `Point` comes back uncompressed, which is the cheap form to parse --
    both coordinates are there to read, where a compressed key pays the
    field square root that lifts x. Which encoding a caller below receives
    makes no difference to what it computes: a parse recovers the same point
    from either, and `ecies.derive_keys` hashes its answer compressed
    regardless of what its inputs carried. No network either,
    which is what every caller here asks for: a verification or a
    multiplication takes the key as the key says it is, and the curve it
    is asked about is the caller's own.
    """
    _assert_pub_key_type(pub_key)
    if isinstance(pub_key, PreparedPoint):
        return _sec_from_pub_key(pub_key.point, ec)
    if isinstance(pub_key, tuple):
        # bytes_from_point is this package's own arithmetic and not a parse: it
        # refuses what is not a point of the curve, and infinity
        return bytes_from_point(pub_key, ec, False)
    sec: bytes | None = None
    # as in `point_from_pub_key`: no echo, no chain
    with contextlib.suppress(TypeError, ValueError):
        sec = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))
    # the bindings' parse takes the hybrid prefixes 0x06 and 0x07, which
    # `point_from_pub_key` refuses: refusing them here makes both arms agree
    if sec is None or sec[:1] in _HYBRID_PREFIXES:
        raise EccValueError("not a public key")
    return sec


def _mult_sec(sec: bytes, m: int, ec: Curve) -> Point:
    """Return m*P, for a point given as the SEC octets that name it.

    `mult(m, point_from_octets_var(sec, ec), ec)` is the same answer, and pays
    a round trip this does not: the octets are lifted to a point on the
    way in, and `mult` writes that point back out as octets for
    `ecdh.shared_point`, which is the call libsecp256k1 would have made
    on the bytes it was handed. That call is `secp256k1_ecdh`, constant
    time in m, and the Python arm is `mult`'s own, regular and blinded:
    the name is plain because neither arm's work follows m. Nor do the
    calls made: a zero is multiplied as one and the product dropped, as
    `mult` does, so that it makes the call any other scalar makes. The
    Python tests m for zero on both sides of that call, and SECURITY.md's
    limitations name both steps.

    The octets need not be proved a point first -- `_sec_from_pub_key` hands
    them in unproven, the same trade `ecc.ecc.dsa` makes for its own delegated
    calls (issue btclib-org/btclib#887) -- because the call below is the proof:
    the bindings' own parse refuses what is not a point, and what they decline
    falls through to the lift, whose `point_from_octets_var` is that same
    refusal on the Python arm.

    Hybrid octets are kept from the bindings, whose parse takes them, so that
    the lift refuses them on both arms.
    """
    if sec[:1] not in _HYBRID_PREFIXES and _libsecp256k1_serves(ec, None):
        with contextlib.suppress(ValueError):
            product = _point_from_sec(libsecp256k1_shared_point(sec, m or 1, False))
            return product if m else INF

    return mult(m, point_from_octets_var(sec, ec), ec)


def _mult_sec_compressed(sec: bytes, m: int, ec: Curve) -> bytes:
    """Return m*P as compressed SEC octets, for P given as SEC octets.

    `bytes_from_point(_mult_sec(sec, m, ec), ec, True)` is the same answer.
    Where the bindings serve, they write the 33 octets themselves, so no
    Python of this package reads the product before the caller does:
    neither `_point_from_sec`, nor `bytes_from_point`'s `require_on_curve`
    and its choice of the prefix from y. `ecc.ecc.ecies.derive_keys` hashes
    a shared secret this way.

    m is required to be in 1..n-1, as a private key is: the product of a
    zero is infinity, which has no octets. The octets are taken unproven,
    as `_mult_sec` takes them, for the same reason.
    """
    if sec[:1] not in _HYBRID_PREFIXES and _libsecp256k1_serves(ec, None):
        with contextlib.suppress(ValueError):
            return libsecp256k1_shared_point(sec, m, True)

    return bytes_from_point(mult(m, point_from_octets_var(sec, ec), ec), ec, True)


def mult_pub_key(m: Integer, pub_key: PubKey, ec: Curve = secp256k1) -> Point:
    """Return m*P, for a public key P however it is spelled.

    `mult(m, point_from_pub_key(pub_key, ec), ec)` is the same answer,
    and where the bindings serve it lifts a compressed key's x to a point
    only for them to parse it again: this is `_sec_from_pub_key` and
    `_mult_sec` composed, which leave the proof that the key is a
    point of the curve to the multiplication's own parse. What it is for
    is an ECDH-shaped computation, whose key is the other party's and
    arrives as octets: a shared secret of BIP352 is one, and
    `ecc.ecc.ecies.derive_keys`, through `_mult_sec_compressed`, another.

    The scalar is reduced mod n, and a key that is no point of the curve
    is refused.

    The name is plain, as `mult`'s is, because the scalar is a secret: a
    private key, or BIP352's input_hash*a. The Python arm is `mult`'s own,
    and the arm the bindings serve is `secp256k1_ecdh`, constant time in
    the scalar. The Python around that call is not: SECURITY.md's
    limitations name its steps.
    """
    _assert_valid_ec(ec)
    scalar = int_from_integer(m) % ec.n
    return _mult_sec(_sec_from_pub_key(pub_key, ec), scalar, ec)


class PubKeyTweakChain:
    """A public key and the tweaks added to it one after the other.

    Each step adds t*G to the key the previous step returned, and returns
    the new key as compressed SEC octets. That is BIP32's public
    derivation: each child is the next parent, and the next tweak is
    hashed from the child's compressed key. `TweakChain` answers a
    different question, many tweaks of one fixed point, each measured
    from that point.

    Where the bindings serve, the chain is `keys.PubkeyTweakChain`: the
    key is parsed once, held on the C side, and no Python point is
    built. Elsewhere the key is parsed with `point_from_octets_var`, and
    each step is `ec.add_var(P, mult(t, ec.G, ec))`. The choice is made
    once, when the chain is built.

    A step whose sum is the point at infinity raises, and ends the chain:
    the chain records that it ended, and on either arm every later step
    raises. libsecp256k1 leaves the key it holds invalid after such a
    step, and BIP32 refuses that child as well.

    Args:
        pub_key: the compressed SEC octets of the starting key.
        ec: the curve the key belongs to.

    Raises:
        EccTypeError: if the curve is not a Curve, or the key not octets.
        EccValueError: if the octets are not a compressed key of a point
            of the curve.
    """

    def __init__(self, pub_key: Octets, ec: Curve = secp256k1) -> None:
        _assert_valid_ec(ec)
        sec = bytes_from_octets(pub_key, ec.p_size + 1)
        if sec[0] not in {0x02, 0x03}:
            # never echo the octets: a 0x00 prefix is an xprv's private key
            raise EccValueError(f"not a compressed key: prefix 0x{sec[:1].hex()}")
        self._ec = ec
        self._ended = False
        self._chain: Libsecp256k1PubkeyTweakChain | None = None
        self._point: Point = (0, 0)
        if _libsecp256k1_serves(ec, None):
            # as in `point_from_pub_key`: no echo, no chain of the parse
            # failure, the raise being outside the handler
            with contextlib.suppress(ValueError):
                self._chain = Libsecp256k1PubkeyTweakChain(sec)
            if self._chain is None:
                raise EccValueError("not a public key")
        else:
            self._point = point_from_octets_var(sec, ec)

    @property
    def ec(self) -> Curve:
        """The curve the key belongs to."""
        return self._ec

    def tweak_add_var(self, t: Integer) -> bytes:
        """Return the key plus t*G, compressed, and step the chain to it.

        The tweak is refused outside 0..n-1, as `prv_key_tweak_add`
        refuses it, and a refused tweak leaves the chain where it was.
        """
        tweak = _scalar_from_tweak(t, self.ec)
        if self._ended:
            raise EccValueError("the chain ended at the point at infinity")

        if self._chain is not None:
            sec = None
            with contextlib.suppress(ValueError):
                sec = self._chain.tweak_add(tweak, True)
            if sec is not None:
                return sec
        else:
            point = self.ec.add_var(self._point, mult(tweak, self.ec.G, self.ec))
            # y == 0 is how an affine point spells infinity
            if point[1]:
                self._point = point
                prefix = b"\x03" if point[1] & 1 else b"\x02"
                return prefix + point[0].to_bytes(self.ec.p_size, "big")

        self._ended = True
        raise EccValueError("the sum is the point at infinity")
