# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the whole suite shares: hypothesis profiles, a marker, a gate.

Registered once here rather than passed to each `@given`: a settings
profile is process-wide, and a decorator repeating it on every property
test is one more place to forget it.

The gate is `coverage_fail_under` and the guard on it. coverage looks
for its configuration in the directory the process started in, so a run
started from `tests/` finds no `fail_under`, no `source` and no
`branch = true`. Section 8 of the organization's standard leaves a tree
to point such a run at its configuration or to make it say it is
ungated, and this file is the second of the two: such a run is refused
(btclib-org/.github#443).

A guard on the file set sits beside it. Pointed at its configuration
with `--cov-config`, a run from `tests/` still reads the directories
`source` names against `tests/`, and `.github/scripts` is not one there,
so such a run is refused as well.
"""

import os
from pathlib import Path
from typing import Protocol

import pytest
from hypothesis import settings

from ecc._libsecp256k1 import INSTALLED
from tests import ZKP_AVAILABLE, needs_bindings
from tests.curves.curve_test import no_bindings_anywhere

# The deadline is a per-example time limit, measured on a run whose cost
# the interpreter and the runner decide: pypy meets these tests with a
# cold JIT, and the matrix runs them on emulated arm64 as well as on
# native x86. A timing flake in one job of the matrix is a red build
# nobody can reproduce locally, and none of these tests is a benchmark --
# what they assert is the answer, not how long it took to reach it.
#
# Five times the hypothesis default of examples on a run that happens at
# every commit. It is not the number that finds a latent defect, though: a
# defect a search turns up belongs in a vector test rather than in a
# search that may or may not repeat it. Deep exploration is what the
# profile below is for.
settings.register_profile("default", deadline=None, max_examples=500)

# What to run when a parser is being changed, rather than at every
# commit: HYPOTHESIS_PROFILE=thorough uv run pytest
settings.register_profile("thorough", deadline=None, max_examples=2_000)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

# the tree that holds this file, which is where a refused run is sent and
# where a `source` directory is looked for: no pytest or coverage flag
# moves it, where `--rootdir` and `-c` move the rootdir and `--cov-config`
# moves the file coverage reads
TREE = Path(__file__).parents[1]


def asks_for_everything(
    file_or_dir: list[str] | None, testpaths: list[str], rootpath: Path
) -> bool:
    """Whether the paths named on the command line take the suite in.

    No path at all narrows nothing and is the whole run. A path above one
    of them -- `pytest .`, or the rootdir spelled out -- collects it too,
    so what decides is containment and not equality. `tests` alone would
    match either way, and a path above `testpaths` is never equal to it,
    so only containment reads both as the whole run they collect.

    `file_or_dir` is `None` rather than `[]` on the `--help` path, the
    parse having been abandoned rather than left unfinished: `--help` is
    bound to pytest's `HelpAction`, which raises `PrintHelp` to skip the
    rest of argument parsing, so the positional still carries argparse's
    default when `pytest_configure` fires. That is no path either, and
    folding it is what keeps `--help` from ending in a traceback whose
    last frame is this file.

    The two sides are relative to different directories: a path on the
    command line to where pytest was run from, a `testpaths` entry to the
    rootdir, which is what `testpaths` means. What the join onto
    `rootpath` does for the second, `Path.resolve` does for the first: a
    relative path neither equals an absolute one nor is above it, so
    without that call every relative spelling of the suite reads as a
    subset. The second is resolved as well because pytest builds
    `rootpath` with `os.path.abspath`, which leaves a symlink in the path
    alone, while `Path.resolve` follows one, so a tree reached through
    `/tmp` on macOS would compare `/tmp/...` against `/private/tmp/...`
    and find no containment anywhere.
    """
    given = [Path(path).resolve() for path in file_or_dir or []]
    if not given:
        return True
    wanted = [(rootpath / path).resolve() for path in testpaths]
    if not wanted:
        # `all` over nothing is true, which would make every path named
        # here the whole suite. With `testpaths` unset there is nothing
        # to measure containment against, so this errs toward dropping
        # the floor rather than gating a run it cannot call whole
        return False
    return all(
        any(target == path or path in target.parents for path in given)
        for target in wanted
    )


def coverage_fail_under(
    asked: float | None,
    configured: float | None,
    file_or_dir: list[str] | None,
    keyword: str,
    markexpr: str,
    deselect: list[str] | None,
    ignore: list[str] | None,
    ignore_glob: list[str] | None,
    lf: bool,
    testpaths: list[str],
    rootpath: Path,
) -> float | None:
    """Return the coverage threshold this run's selection has to meet.

    `--cov` is in addopts, so the 100% ratchet is what a bare `uv run
    pytest` measures rather than something only the coverage job reaches:
    a gate that CI alone runs is one a change meets after it is pushed.
    What that costs is this function. `fail_under` applies to every
    report coverage writes, a partial one included, so `pytest
    tests/init_test.py` would end in `Required test coverage of
    100.0% not reached` -- true of that run and saying nothing about the
    tree. Running one file and one test are documented commands, and a
    gate that fails them is a gate read as noise.

    So a run that asked for a subset is gated at zero rather than having
    coverage switched off: the report still prints, which is what makes
    it worth measuring while iterating on one module. A whole run is
    handed back `configured`, the threshold pytest-cov has already read
    out of the coverage configuration, so pyproject.toml stays the one
    place the number lives.

    The two thresholds are two arguments because by the time any of this
    runs they no longer agree. pytest-cov fills `cov_fail_under` from the
    coverage configuration in `pytest_load_initial_conftests`, before
    `pytest_configure`, so "the option is set" has stopped meaning
    "somebody asked for it": what still means that is `config.option`,
    which carries only what the command line and addopts put there. An
    explicit `--cov-fail-under` is therefore `asked`, and is handed back
    untouched whichever kind of run it is -- the caller naming the
    threshold is the one thing this must not overrule.

    A subset is what pytest was *asked* for, and section 8 of the
    organization's standard is what names the set: a path that leaves
    part of the suite behind, `-k`, `-m`, `--deselect`, `--ignore`,
    `--ignore-glob`, or `--lf`. A run that leaves tests out measures the
    same source with fewer tests, so what its report is short of is the
    tests it did not run: a shortfall it reports cannot be told apart
    from one the tree has, and a gate whose red cannot be read is what
    teaches whoever runs it to reach for `--no-cov`.

    The narrower reading -- paths, `-k` and `-m` alone -- is rejected: it
    holds the rest to be the flags of an iteration whose next run is the
    whole suite, and reading intent off all of them to make this
    function a second definition of what a real run is. What the wider
    set costs is the occasion where such a run would have cleared 100
    anyway -- a `--lf` that finds nothing to rerun and so is the whole
    suite, a `--deselect` of one arm of a parametrization the others
    cover -- and the next bare run measures the tree again. An early
    `-x` is outside the set either way: what cuts that run short is a
    failure and not what the invocation asked for.

    `lf` arrives as a plain `bool` rather than read off `config.option`
    here, because `-p no:cacheprovider` leaves the attribute unregistered
    rather than false, and a run that cannot pass the flag has not passed
    it -- the caller is where that distinction is made.

    Which paths leave nothing behind is `asks_for_everything` above, and
    it is the reason `testpaths` and the rootdir are arguments here.
    """
    if asked is not None:
        return asked
    if keyword or markexpr or deselect or ignore or ignore_glob or lf:
        return 0
    if not asks_for_everything(file_or_dir, testpaths, rootpath):
        return 0
    return configured


class CoverageConfiguration(Protocol):
    """What this file reads of coverage's own configuration object.

    `config_file` is the file coverage took its settings from, and
    `None` where it took them from none: coverage sets it as it reads
    one, so the attribute is the run's own answer to whether the
    configuration reached it, rather than an inference from a value
    that reached it.

    `source` is the list `[tool.coverage.run]` names, each entry as
    written there, and `None` where nothing names one.
    """

    config_file: str | None
    source: list[str] | None


def coverage_configuration(config: pytest.Config) -> CoverageConfiguration | None:
    """Return the configuration coverage is measuring with, or `None`.

    `None` is the two ways there is nothing to ask about: `--no-cov`,
    where pytest-cov registers its plugin and returns from `__init__`
    with the controller left unbuilt, and a run whose plugin was never
    registered, where `getplugin` hands back `None` -- the same
    `getattr` default answers for both.
    """
    plugin = config.pluginmanager.getplugin("_cov")
    controller = getattr(plugin, "cov_controller", None)
    if controller is None:
        return None
    # annotated because the plugin manager hands back `Any`, and a
    # return of that is what mypy's strict mode refuses here
    measuring: CoverageConfiguration = controller.cov.config
    return measuring


def held_to_a_floor(
    asked: float | None, asked_for_help: bool, collect_only: bool
) -> bool:
    """Return whether a measuring run is one the guards below ask about.

    The arguments are plain values rather than `config.option` itself,
    as `coverage_fail_under` above takes them, and so are those of the
    guards below: reading the run is the hook's, and what is decided
    here is decided from what it read.
    """
    if asked is not None:
        # section 8 of the organization's standard has the hook never
        # overruling an explicit `--cov-fail-under`, and a caller who
        # named the floor has not had one taken away in silence
        return False
    # neither `--help` nor `--collect-only` is held to a floor to begin
    # with: `--help` exits before a session, and pytest-cov never fails a
    # `--collect-only` run on the floor whatever its report prints. The
    # pair is an enumeration rather than every run pytest-cov leaves
    # ungated, and `--markers` and `--fixtures` are refused knowingly.
    # Widening it is the rejected alternative: what would decide the
    # question is whether pytest-cov would have gated this run, which is
    # no property to read here, so a longer list is the same guess under
    # more names
    return not (asked_for_help or collect_only)


def configuration_went_unread(
    cov_config: CoverageConfiguration | None,
    inipath: Path | None,
    asked: float | None,
    asked_for_help: bool,
    collect_only: bool,
) -> bool:
    """Return whether a run held to the floor cannot see one.

    A guard and not a sentence in CONTRIBUTING.md. What it catches is a
    plausible spelling switching the floor off, and a reader told to
    start from the root is not the run that does not: the sentence
    leaves the same failure, with somebody having been told about it.

    What it compares is not the threshold. pyproject.toml is the one
    place the number lives, and a `== 100` here would be the second, so
    what decides is whether coverage read a file at all against whether
    pytest read one -- the asymmetry the defect leaves behind, pytest
    walking up from where it was invoked to find its configuration and
    coverage looking only where the process started.
    """
    if cov_config is None or not held_to_a_floor(asked, asked_for_help, collect_only):
        return False
    # `inipath` is what the message has to name, so a run pytest read no
    # configuration for is one this cannot tell anybody anything about
    return cov_config.config_file is None and inipath is not None


def sources_out_of_reach(
    cov_config: CoverageConfiguration | None,
    tree: Path,
    asked: float | None,
    asked_for_help: bool,
    collect_only: bool,
) -> list[str]:
    """Return each `source` entry this run would leave unmeasured.

    coverage takes an entry for a directory where it is one from the
    directory the run started in, and for a module name otherwise. An
    entry that is a directory under `tree`, is none from here, and
    cannot be a module name is measured by neither reading: from
    `tests/`, `.github/scripts` is that entry, and the floor still
    passes without it. An entry that is a module name, `tests` from
    `tests/` among them, is measured as one. In an sdist, which ships no
    `.github`, `.github/scripts` is no directory under `tree`, so a run
    there is not refused.
    """
    if cov_config is None or not held_to_a_floor(asked, asked_for_help, collect_only):
        return []
    return [
        entry
        for entry in cov_config.source or []
        if (tree / entry).is_dir()
        and not Path(entry).is_dir()
        and not all(part.isidentifier() for part in entry.split("."))
    ]


def pytest_configure(config: pytest.Config) -> None:
    """Gate a whole run at `fail_under`, and a partial one at nothing.

    The threshold is written to `known_args_namespace` and not to
    `config.option`: pytest builds the first by parsing the known
    arguments into a *copy* of the second, and pytest-cov holds on to
    that copy. Writing to `config.option` instead runs without error and
    changes nothing -- the plugin never reads it back, and the run still
    fails on the whole tree's coverage.

    A run coverage's configuration never reached is refused rather than
    gated, and so is a run that would leave a `source` directory
    unmeasured, `pytest.UsageError` being what pytest prints without a
    traceback and exits `4` for -- an exit of its own, so the code says
    the run measured nothing rather than that something in the tree
    failed.
    """
    if configuration_went_unread(
        coverage_configuration(config),
        config.inipath,
        config.option.cov_fail_under,
        config.option.help,
        config.option.collectonly,
    ):
        raise pytest.UsageError(
            "coverage read no configuration, so this run is held to no"
            " floor and measures a different set of files: coverage looks"
            f" only in the directory the run started in, {Path.cwd()}, and"
            f" pytest read {config.inipath}. Run from {TREE}."
        )
    if unmeasured := sources_out_of_reach(
        coverage_configuration(config),
        TREE,
        config.option.cov_fail_under,
        config.option.help,
        config.option.collectonly,
    ):
        raise pytest.UsageError(
            f"coverage would not measure {', '.join(unmeasured)}: it reads"
            " a source directory against the directory the run started in,"
            f" {Path.cwd()}, and no such directory is there. Run from"
            f" {TREE}."
        )
    namespace = config.known_args_namespace
    namespace.cov_fail_under = coverage_fail_under(
        config.option.cov_fail_under,
        namespace.cov_fail_under,
        config.option.file_or_dir,
        config.option.keyword,
        config.option.markexpr,
        config.option.deselect,
        config.option.ignore,
        config.option.ignore_glob,
        getattr(config.option, "lf", False),
        config.getini("testpaths"),
        config.rootpath,
    )


def _skip_what_needs_the_bindings(items: list[pytest.Item]) -> None:
    """Skip every test marked `bindings`, naming why once.

    The hook below calls this only where `btclib_secp256k1` is absent,
    `INSTALLED` being set once at import and not something a test can
    fake in-process. What covers it is `conftest_test.py` calling it
    directly, so the measurement is a fact about the function rather
    than about which build ran it: `test.yml`'s `coverage` job gates at
    100% on a single run with the bindings installed, where the hook
    reaches nothing here. `coverage-union` combines that run with the
    `no-bindings` job's and gates beside the `coverage` job rather than
    instead of it.
    """
    skip = pytest.mark.skip(reason="btclib_secp256k1 is not installed")
    for item in items:
        # `iter_markers` and not `item.keywords`: keywords is what `-k`
        # matches, so it holds the module name, the test name and the
        # parametrize id as well -- and a parametrization with an id
        # spelled `bindings` would then be skipped by the spelling of an
        # id rather than by a mark
        if any(mark.name == "bindings" for mark in item.iter_markers()):
            item.add_marker(skip)


def _skip_what_needs_zkp(items: list[pytest.Item]) -> None:
    """Skip every test marked `zkp`, naming why once.

    The hook below calls this wherever `btclib_secp256k1.zkp.lib` is not
    the flagged extension, `ZKP_AVAILABLE` being set once at import from
    that same attribute access, in `tests/__init__.py`. The reason is
    worded like `bindings`' own rather than naming the extension by
    name: a contributor reading a skip report wants to know what to
    build, not which cffi module answered.

    `conftest_test.py` calls this directly too, so a flagged build
    measures it like any other -- unlike the guard in `tests/__init__.py`
    that sets the name, whose arms run at import and carry a `pragma`
    each, a build being what decides which one a run takes (issue
    btclib-org/btclib#1885).
    """
    skip = pytest.mark.skip(
        reason="btclib_secp256k1.zkp is not built with BTCLIB_LIBSECP256K1_ZKP"
    )
    for item in items:
        # see `iter_markers` and not `item.keywords` above, same reason
        if any(mark.name == "zkp" for mark in item.iter_markers()):
            item.add_marker(skip)


@pytest.fixture(
    params=[pytest.param("bindings", marks=needs_bindings), "python"],
)
def arm(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run the test once on the bindings, then on the Python arithmetic.

    `both_arms` asks for it, so that a run with the bindings installed meets
    the Python arm too. The bindings arm leaves the dispatch as the run found
    it, and is skipped where the bindings are absent, as every test marked
    `bindings` is. The Python arm is `no_bindings_anywhere` of
    `curves/curve_test.py`.
    """
    if request.param == "python":
        no_bindings_anywhere(monkeypatch)
    return str(request.param)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Turn the `bindings` and `zkp` markers into a skip absent their build.

    Each marker is what `tests.needs_bindings` or `tests.needs_zkp`
    applies and what `pytest -m "not bindings"` or `-m "not zkp"` selects
    on; this is what makes it a skip as well, so that one name does the
    selecting and the skipping and cannot drift into doing only one.

    A build takes one way out of each `if` at collection and cannot take
    the other, which is what a `pragma` here would otherwise stand for.
    `conftest_test.py` calls this hook with `INSTALLED` and
    `ZKP_AVAILABLE` monkeypatched instead, and coverage accumulates arcs
    over the whole session, so both ways out of both are taken whatever
    the machine was built with.
    """
    if not INSTALLED:
        _skip_what_needs_the_bindings(items)
    if not ZKP_AVAILABLE:
        _skip_what_needs_zkp(items)


def pytest_report_header() -> str:
    """State which `btclib_secp256k1` build this run measured.

    Beside the interpreter, the rootdir and the plugins pytest already
    announces there: which of the two builds answered is a fact about
    the same run, and the report otherwise carries it only where there
    is a skip. `-ra` names the missing build once per test an unflagged
    run skips, where a flagged run skips none of them and leaves the
    answer to a subtraction over the passed and the skipped totals --
    the exit code, the coverage total and the floor it clears reading
    the same either way (issue btclib-org/btclib#1937).

    Printed under both builds and not under the flagged one alone,
    because a line that appears only one way makes its own absence carry
    the other answer.

    What it names is what `ZKP_AVAILABLE` measured, whether
    `btclib_secp256k1.zkp.lib` resolves, so the second arm covers a
    build made without the flag and an environment without the bindings
    at all alike. A conditional expression rather than an `if`, which
    keeps this one statement. `conftest_test.py` calls the hook under
    each value of that name, so its coverage is a fact about the code
    and not about how the runner was invoked -- unlike the guard in
    `tests/__init__.py`, which runs at import and carries a `pragma` in
    each of its arms (issue btclib-org/btclib#2179).
    """
    return "btclib_secp256k1.zkp: " + (
        "built with BTCLIB_LIBSECP256K1_ZKP, so the tests marked zkp run"
        if ZKP_AVAILABLE
        else "no BTCLIB_LIBSECP256K1_ZKP build, so the tests marked zkp skip"
    )
