# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every class decoder, and the module-level ones listed, on unwritten input.

The rest of the suite is fixed vectors: exactly what conformance needs,
and blind to the malformed octets that never make it into a
specification's test section. This file is the converse. It does not
assert that a decoder accepts the right things -- the vectors do that --
but that it *fails the way the package says it fails*, whatever it is
handed: an IndexError off a short slice, an OverflowError off an
unchecked size or a silent short read reaches a caller who catches
`EccValueError` to reject bad input and has no reason to
expect anything else.

`fuzz/`'s atheris harnesses ask the same question of the signature and
envelope decoders for an hour a week; this asks it of every class
decoder and of the module-level decoders in `BINARY_PARSERS`, on every
run, for as long as hypothesis spends on a test. `WIRE_FUNCTIONS` asks
it of the functions that read what peers send: musig2's, frost's and
dahlias's nonce aggregation, musig2's key aggregation, dleq's proof
verification, dahlias's aggregate verification and the two adaptor
verifications. The other functions of those modules
are not driven here.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ecc.curves import mult, secp256k1
from ecc.curves.sec_point import bytes_from_point, point_from_octets_var
from ecc.ecc import (
    dahlias,
    dleq,
    dsa,
    ecdsa_adaptor,
    ecies,
    ellswift,
    frost,
    musig2,
    pedersen,
    ssa,
    ssa_adaptor,
)
from ecc.ecc.borromean import BorromeanSig
from ecc.ecc.rangeproof import RangeProof
from ecc.exceptions import (
    EccRuntimeError,
    EccTypeError,
    EccValueError,
)
from tests import public_classes_with

# What a decoder of this package is allowed to raise. Anything else
# leaves the contract src/ecc/exceptions.py documents
CONTRACT = (
    EccValueError,
    EccTypeError,
    EccRuntimeError,
)

# Bounded because these are decoders, not benchmarks: what a length field
# does with the octets behind it is decided in the first few of them. The
# mutation tests below are what reaches past the outermost check
MAX_INPUT = 512

BINARY_PARSERS: dict[str, Callable[[bytes], Any]] = {
    "dsa.Sig.parse": dsa.Sig.parse,
    "ssa.Sig.parse": ssa.Sig.parse,
    # `rsizes` left at its default, which is the ring structure a verifier
    # supplies and the wire format does not carry: what the default
    # reaches is the digest read, the trailing-octet refusal, and -- for
    # the input of exactly thirty-two octets that passes both --
    # `assert_valid`'s own "no rings"
    "BorromeanSig.parse": BorromeanSig.parse,
    # the proof that carries one of those signatures, whose own ring
    # structure a mutation *can* reach: the mantissa octet is what says
    # how many rings follow, so a flip there asks for a body the buffer
    # does not hold
    "RangeProof.parse": RangeProof.parse,
    "ecies.Envelope.parse": ecies.Envelope.parse,
    "point_from_octets_var": point_from_octets_var,
    "ssa.point_from_bip340pub_key_var": ssa.point_from_bip340pub_key_var,
    "ellswift.decode_var": ellswift.decode_var,
    "pedersen.commitment_from_octets_var": pedersen.commitment_from_octets_var,
    "pedersen.generator_from_octets_var": pedersen.generator_from_octets_var,
}

# The same contract, for what a user pastes rather than what a peer
# sends. `b64decode` decodes and then hands the octets to `parse`, so
# what it adds is the decoding -- a str that is not ascii, padding that
# is not canonical, a length no multiple of four -- a layer the binary
# entry point never sees
TEXT_PARSERS: dict[str, Callable[[str], Any]] = {
    "ecies.Envelope.b64decode": ecies.Envelope.b64decode,
}

# A class-level decoder is one of these three: `parse` for octets,
# `b64decode` and `b58decode` for the text encodings a class reads on its
# own. `serialization_boundary_test.py`'s `test_every_decoder_is_covered`
# draws the same three names for the same reason, so widening this tuple
# is what a class gaining a fourth would ask for, in both files at once.
# No walk finds a module-level decoder: that file's
# `test_no_codec_is_a_module_function` refuses only one named in its
# family, so each is listed above by hand
_CLASS_DECODER_METHODS = ("parse", "b64decode", "b58decode")


def _classes_driven_here() -> set[str]:
    """Every class the two dicts above drive, through which decoder.

    A bound classmethod carries in `__self__` the class it was read off,
    which is what the entry names. The method name is part of the key,
    since a class offering two of the three would otherwise collide.
    """
    driven = set()
    for entry_point in (*BINARY_PARSERS.values(), *TEXT_PARSERS.values()):
        cls = getattr(entry_point, "__self__", None)
        if isinstance(cls, type) and entry_point.__name__ in _CLASS_DECODER_METHODS:
            driven.add(f"{cls.__module__}.{cls.__qualname__}.{entry_point.__name__}")
    return driven


def test_every_class_that_decodes_is_driven_here() -> None:
    """The inventory is a promise only if omission is what fails.

    A class added to the package and given no line above is held to
    nothing here: the tests keep passing on the entry points they were
    given, and the new decoder answers hostile input however it likes.
    """
    found = {
        f"{name}.{method}"
        for method in _CLASS_DECODER_METHODS
        for name in public_classes_with(method)
    }
    # a walk returning nothing is a defect in the walk and not in the
    # inventory, and the equality alone answers it with a mismatch of
    # every name: this is what says which of the two a red run is
    assert found
    assert found == _classes_driven_here()


def _assert_contract(parse: Callable[[Any], Any], data: Any) -> None:
    """Call parse, and let anything outside the contract propagate.

    Rejecting the input is the expected answer to almost all of what
    these strategies generate, so there is nothing to assert about it.
    What the test is for is the third outcome, neither a value nor a
    refusal: hypothesis reports the exception, and the input it shrank
    to reach it.
    """
    with contextlib.suppress(*CONTRACT):
        parse(data)


@pytest.mark.parametrize(
    "parse", BINARY_PARSERS.values(), ids=list(BINARY_PARSERS.keys())
)
@given(data=st.binary(max_size=MAX_INPUT))
def test_binary_parser_honors_the_exception_contract(
    parse: Callable[[bytes], Any], data: bytes
) -> None:
    """Fuzz every binary decoder: refusals stay within the contract."""
    _assert_contract(parse, data)


@pytest.mark.parametrize("parse", TEXT_PARSERS.values(), ids=list(TEXT_PARSERS.keys()))
@given(data=st.text(max_size=MAX_INPUT))
def test_text_parser_honors_the_exception_contract(
    parse: Callable[[str], Any], data: str
) -> None:
    """Fuzz every text decoder: refusals stay within the contract."""
    _assert_contract(parse, data)


# a DER signature, whose tag, length and integer octets are what a
# mutation lands in: a flipped length asks for octets the buffer does
# not hold, and a flipped integer length moves the boundary between r
# and s
DSA_SIG_BIN = dsa.sign(b"ecc", 1).serialize()
# a BIE1 envelope, whose magic, ephemeral key, ciphertext and MAC sit at
# fixed offsets: a truncation or an extension lands in the ciphertext's
# block alignment, and a flipped octet in the key's prefix or on its
# x-coordinate. The ciphertext is opaque octets to the class, so one
# block of them is an envelope without a cipher; the ephemeral key is the
# generator, compressed
ENVELOPE_BIN = ecies.Envelope.from_ciphertext(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    bytes(16),
    bytes(32),
).serialize()


def _mutations(sample: bytes) -> st.SearchStrategy[bytes]:
    """Return the near-misses of a valid serialization.

    Uniform random octets are rejected by the first field of a decoder
    and so exercise the outermost check and nothing beneath it. What
    reaches the code underneath is a serialization valid right up to the
    point where it is not: the truncation, the flipped length prefix, the
    trailing junk that must not be taken for a second record.
    """
    truncated = st.integers(min_value=0, max_value=len(sample)).map(
        lambda i: sample[:i]
    )
    flipped = st.builds(
        lambda i, byte: sample[:i] + bytes([byte]) + sample[i + 1 :],
        st.integers(min_value=0, max_value=len(sample) - 1),
        st.integers(min_value=0, max_value=0xFF),
    )
    extended = st.binary(max_size=32).map(lambda tail: sample + tail)
    return st.one_of(truncated, flipped, extended)


MUTATED_PARSERS: dict[str, tuple[Callable[[bytes], Any], bytes]] = {
    "dsa.Sig.parse": (dsa.Sig.parse, DSA_SIG_BIN),
    "ecies.Envelope.parse": (ecies.Envelope.parse, ENVELOPE_BIN),
}


@pytest.mark.parametrize(
    "parse, sample",
    MUTATED_PARSERS.values(),
    ids=list(MUTATED_PARSERS.keys()),
)
@given(data=st.data())
def test_mutated_serialization_honors_the_exception_contract(
    parse: Callable[[bytes], Any], sample: bytes, data: st.DataObject
) -> None:
    """Fuzz near-miss serializations: refusals stay within the contract."""
    _assert_contract(parse, data.draw(_mutations(sample)))


def test_the_mutated_samples_parse() -> None:
    """A sample the decoder refuses would make every mutation a refusal."""
    for parse, sample in MUTATED_PARSERS.values():
        assert parse(sample).serialize() == sample


# The functions that read what peers send, each with the type it returns
# on input it does not refuse: the aggregate, or a boolean for a
# verification
_KEY = bytes_from_point(secp256k1.G, secp256k1)
_X_ONLY_KEY = _KEY[1:]
_PUB_NONCE = _KEY + bytes_from_point(mult(2))
_MSG = bytes(range(32))
_DLEQ_A = bytes_from_point(mult(3))
_DLEQ_PROOF = dleq.generate_proof(3, _KEY, bytes(32))
_SSA_PRE_SIG = ssa_adaptor.presign(_MSG, 1, _KEY, bytes(32))
_ECDSA_ADAPTOR_SIG = ecdsa_adaptor.encrypt(_MSG, 1, _KEY, bytes(32))


def _dahlias_sig() -> bytes:
    """Return the aggregate signature of one signer, key 1, over _MSG."""
    sec_nonce, pub_nonce = dahlias.nonce_gen_(bytes(32), 1)
    session = dahlias.SessionContext(
        dahlias.nonce_agg_var([pub_nonce]), [_X_ONLY_KEY], [_MSG], [pub_nonce]
    )
    return dahlias.sig_agg([dahlias.sign(sec_nonce, 1, _MSG, session)], session)


_DAHLIAS_SIG = _dahlias_sig()


# Where each scalar of a sample starts: dleq's e and s, the s of a
# pre-signature after its point, and the s_a, e and s of an ECDSA adaptor
# signature after its two points
_SCALAR_OFFSETS = {
    _DLEQ_PROOF: (0, 32),
    _SSA_PRE_SIG: (33,),
    _ECDSA_ADAPTOR_SIG: (66, 98, 130),
    _DAHLIAS_SIG: (32,),
}


def _wire(sample: bytes) -> st.SearchStrategy[bytes]:
    """Return an argument that is random octets or a near-miss of sample.

    Where sample holds scalars, one of them set to 0xff or 0x00 octets is
    a near-miss too: a scalar that is not below n, or zero.
    """
    strategies = [st.binary(max_size=len(sample) + 8), _mutations(sample)]
    if offsets := _SCALAR_OFFSETS.get(sample):
        strategies.append(
            st.builds(
                lambda i, fill: sample[:i] + bytes([fill]) * 32 + sample[i + 32 :],
                st.sampled_from(offsets),
                st.sampled_from([0x00, 0xFF]),
            )
        )
    return st.one_of(*strategies)


def _wire_args(*samples: bytes) -> st.SearchStrategy[tuple[bytes, ...]]:
    """Return the arguments of a call, all valid but at most a few.

    An argument refused by the first check hides the ones behind it, so
    most calls corrupt one argument and leave the others as they are.
    """
    one_corrupt = [
        st.builds(
            lambda bad, i=i: (*samples[:i], bad, *samples[i + 1 :]), _wire(sample)
        )
        for i, sample in enumerate(samples)
    ]
    return st.one_of(*one_corrupt, st.tuples(*(_wire(sample) for sample in samples)))


def _wire_list(sample: bytes) -> st.SearchStrategy[tuple[list[bytes]]]:
    """Return a list of near-misses and valid samples, as the one argument."""
    item = st.one_of(st.just(sample), _wire(sample))
    return st.tuples(st.lists(item, max_size=4))


WIRE_FUNCTIONS: dict[str, tuple[Callable[..., Any], type, st.SearchStrategy[Any]]] = {
    "musig2.nonce_agg_var": (musig2.nonce_agg_var, bytes, _wire_list(_PUB_NONCE)),
    "musig2.key_agg_var": (musig2.key_agg_var, musig2.KeyAggContext, _wire_list(_KEY)),
    "frost.nonce_agg_var": (frost.nonce_agg_var, bytes, _wire_list(_PUB_NONCE)),
    "dahlias.nonce_agg_var": (dahlias.nonce_agg_var, bytes, _wire_list(_PUB_NONCE)),
    "dahlias.verify": (
        dahlias.verify,
        bool,
        st.one_of(
            st.builds(lambda k: ([k], [_MSG], _DAHLIAS_SIG), _wire(_X_ONLY_KEY)),
            st.builds(lambda m: ([_X_ONLY_KEY], [m], _DAHLIAS_SIG), _wire(_MSG)),
            st.builds(lambda s: ([_X_ONLY_KEY], [_MSG], s), _wire(_DAHLIAS_SIG)),
        ),
    ),
    "dleq.verify_proof": (
        dleq.verify_proof,
        bool,
        _wire_args(_DLEQ_A, _KEY, _DLEQ_A, _DLEQ_PROOF),
    ),
    "ssa_adaptor.verify": (
        ssa_adaptor.verify,
        bool,
        _wire_args(_SSA_PRE_SIG, _MSG, _X_ONLY_KEY, _KEY),
    ),
    "ecdsa_adaptor.verify": (
        ecdsa_adaptor.verify,
        bool,
        _wire_args(_ECDSA_ADAPTOR_SIG, _MSG, _KEY, _KEY),
    ),
}


@pytest.mark.parametrize(
    "function, answer, arguments",
    WIRE_FUNCTIONS.values(),
    ids=list(WIRE_FUNCTIONS.keys()),
)
@given(data=st.data())
def test_wire_function_honors_the_exception_contract(
    function: Callable[..., Any],
    answer: type,
    arguments: st.SearchStrategy[tuple[Any, ...]],
    data: st.DataObject,
) -> None:
    """Fuzz the multi-argument wire functions: a refusal, or the right type."""
    args = data.draw(arguments)
    try:
        result = function(*args)
    except CONTRACT:
        return
    assert isinstance(result, answer)


def test_the_wire_samples_are_accepted() -> None:
    """A sample the function refuses would make every mutation a refusal."""
    assert musig2.nonce_agg_var([_PUB_NONCE])
    assert isinstance(musig2.key_agg_var([_KEY]), musig2.KeyAggContext)
    assert frost.nonce_agg_var([_PUB_NONCE])
    assert dahlias.nonce_agg_var([_PUB_NONCE])
    assert dahlias.verify([_X_ONLY_KEY], [_MSG], _DAHLIAS_SIG)
    assert dleq.verify_proof(_DLEQ_A, _KEY, _DLEQ_A, _DLEQ_PROOF)
    assert ssa_adaptor.verify(_SSA_PRE_SIG, _MSG, _X_ONLY_KEY, _KEY)
    assert ecdsa_adaptor.verify(_ECDSA_ADAPTOR_SIG, _MSG, _KEY, _KEY)
