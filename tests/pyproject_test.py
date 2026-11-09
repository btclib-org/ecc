# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Each extra and the group beside it name the same requirement.

Section 1 of the organization's standard: where a package is both an extra
and a group, the specifier is written twice, and a test refuses the day
the two disagree. The extra is what an install from the index resolves,
the group what every `uv sync` of this tree does, so a floor raised in one
and not the other leaves the suite running against a release no user is
asked to install.
"""

import tomllib
from pathlib import Path

import pytest

_PYPROJECT = tomllib.loads(
    (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    "extra_name, group_name", [("secp256k1", "bindings"), ("gmpy2", "gmpy2")]
)
def test_the_extra_and_the_group_agree(extra_name: str, group_name: str) -> None:
    """The two lists hold the same requirements, in the same spelling."""
    extra = _PYPROJECT["project"]["optional-dependencies"][extra_name]
    group = _PYPROJECT["dependency-groups"][group_name]
    assert sorted(extra) == sorted(group)
