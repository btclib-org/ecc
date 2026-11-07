# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the two signature decoders.

A signature is the part of a message its verifier did not write, and it
is decoded before anything is verified: `dsa.Sig.parse` walks DER's tag,
length and integer octets, and `ssa.Sig.parse` cuts BIP340's fixed
sixty-four. So both read a stranger's own octets, which is what this
harness is for, and it runs both against the same input: the two
languages are disjoint, DER never being sixty-four octets of two bare
integers.

A crash here on hostile bytes is a defect in the decoder, never in this
harness: `data` is unconstrained bytes handed straight to each entry
point. `EccException` is what both answer malformed input
with, so that family is caught below as the expected outcome; any other
exception propagates to atheris as the finding it is.

The seed corpus is one signature of each kind, as `serialize` writes it.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from ecc.dsa import Sig as DsaSig
from ecc.exceptions import EccException
from ecc.ssa import Sig as SsaSig

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file. The two classes
# are imported under names of their own because that test resolves a
# call one attribute deep, `DsaSig.parse`, against the import that binds
# the name
ENTRY_POINTS = (
    "ecc.dsa:Sig.parse",
    "ecc.ssa:Sig.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a DER ECDSA signature, then as a BIP340 one.

    `EccException` is swallowed as each entry point's own
    refusal of malformed input; any other exception propagates, which is
    how atheris tells a defect in the decoder from the domain of input it
    already rejects.
    """
    with contextlib.suppress(EccException):
        DsaSig.parse(data)
    with contextlib.suppress(EccException):
        SsaSig.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
