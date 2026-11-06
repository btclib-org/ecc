# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the weekly py-arm sentinel: measuring, the diff and the reporting.

`measure()` is what actually runs the suite under coverage, module by
module, which takes minutes. Its tests here stand in for each run:
`measure()`'s replace `_run_coverage`, and `_run_coverage`'s replace
`subprocess.run` with one writing the report a real run would.
`compare()` takes none of that: a `dict[str, frozenset[str]]` in, the
three-way STALE/UNDERSTATED/NEW AUTHORITY diff against `_AUTHORITY` and
`_WITHOUT_AN_AUTHORITY` out, no subprocess or coverage run needed to
exercise it. `_AUTHORITY` and `_WITHOUT_AN_AUTHORITY` are monkeypatched
to small synthetic tables here rather than read from
`tests/py_arm_authority_test.py`, so a change to the real table cannot
make this test pass or fail by accident.

`report()` is the last part, and its only external dependency is `gh`.
`FakeGh` answers each of `gh issue list`, `create`, `edit` and `close`
the way a real one would rather than reaching GitHub, and records every
call, so a test can assert what was asked for as well as what came
back: a real call would need a token and would file an issue against
this repository.

Loaded by path, the same reason and the same shape as
`tests/check_vendored_vectors_test.py`.
"""

from __future__ import annotations

import importlib.util
import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = (
    Path(__file__).parents[1] / ".github" / "scripts" / "check_py_arm_authority.py"
)


@pytest.fixture
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path, registered before it runs."""
    spec = importlib.util.spec_from_file_location("check_py_arm_authority", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "check_py_arm_authority", module)
    spec.loader.exec_module(module)
    return module


class FakeGh:
    """A `subprocess.run` stand-in, answering as the `gh` call it names.

    `open_issue` is the number `_open_issue_number` should report open,
    or None for no issue open at all. Every call is recorded in `calls`,
    argv and all.
    """

    def __init__(self) -> None:
        self.open_issue: int | None = None
        self.calls: list[list[str]] = []

    def __call__(
        self, argv: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        """Record the call, and answer as the `gh` sub-command it names."""
        self.calls.append(list(argv))
        if argv[2] == "list":
            issues = (
                [{"number": self.open_issue}] if self.open_issue is not None else []
            )
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(issues))
        return subprocess.CompletedProcess(argv, 0, stdout="")


@pytest.fixture
def fake_gh(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> FakeGh:
    """Install a `FakeGh` in place of the script's own `subprocess.run`."""
    fake = FakeGh()
    monkeypatch.setattr(checker.subprocess, "run", fake)
    return fake


def test_compare_finds_nothing_when_every_arm_matches(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A measurement equal to `_AUTHORITY` reports no mismatch at all."""
    monkeypatch.setattr(checker, "_AUTHORITY", {"an.arm": ("a.json",)})
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset())

    assert checker.compare({"an.arm": frozenset({"a.json"})}) == []


def test_compare_reports_stale_understated_and_new_authority(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One line per direction `compare()` can report, sorted by arm name."""
    monkeypatch.setattr(
        checker,
        "_AUTHORITY",
        {
            "match.arm": ("b.json",),
            "new.arm": (),
            "stale.arm": ("a.json",),
            "understated.arm": ("c.json",),
        },
    )
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset({"new.arm"}))

    mismatches = checker.compare(
        {
            "match.arm": frozenset({"b.json"}),
            "new.arm": frozenset({"e.json"}),
            "stale.arm": frozenset(),
            "understated.arm": frozenset({"c.json", "d.json"}),
        }
    )

    assert mismatches == [
        "NEW AUTHORITY: new.arm is reached by ['e.json'], not named in its entry",
        "STALE: stale.arm claims ['a.json'], whose run no longer reaches it",
        "UNDERSTATED: understated.arm is reached by ['d.json'], not named in its entry",
    ]


def test_compare_treats_an_arm_missing_from_the_measurement_as_empty(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An arm `_AUTHORITY` claims, and the measurement never mentions: STALE."""
    monkeypatch.setattr(checker, "_AUTHORITY", {"an.arm": ("a.json",)})
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset())

    assert checker.compare({}) == [
        "STALE: an.arm claims ['a.json'], whose run no longer reaches it"
    ]


def test_open_issue_number_reads_the_first_match(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """The number of the first issue `gh issue list` names, as a string."""
    fake_gh.open_issue = 42

    assert checker._open_issue_number("A title") == "42"

    (call,) = fake_gh.calls
    assert '"A title" in:title' in call


def test_open_issue_number_is_none_when_none_is_open(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """An empty `gh issue list` is None, not an empty string."""
    assert checker._open_issue_number("A title") is None


def test_the_issue_body_carries_the_lines_stdout_carries(
    checker: ModuleType,
) -> None:
    """The body is `compare()`'s own lines, as bullets, under the header."""
    body = checker._issue_body(
        ["STALE: an.arm claims ['a.json'], whose run no longer reaches it"]
    )

    assert "`tests/py_arm_authority_test.py`'s `_AUTHORITY`" in body
    assert "- STALE: an.arm claims ['a.json']," in body


def test_report_creates_an_issue_when_none_is_open(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """A disagreement and no issue open: a new one, under the title given.

    The same title is what the search before it asked for, so a run
    finds the issue it filed last week rather than opening a second one.
    """
    checker.report("A census title", ["STALE: an.arm claims ['a.json']"])

    assert [call[2] for call in fake_gh.calls] == ["list", "create"]
    (list_call,) = (call for call in fake_gh.calls if call[2] == "list")
    assert '"A census title" in:title' in list_call
    (create_call,) = (call for call in fake_gh.calls if call[2] == "create")
    assert create_call[create_call.index("--title") + 1] == "A census title"


def test_report_edits_the_open_issue(checker: ModuleType, fake_gh: FakeGh) -> None:
    """A disagreement and an issue already open: it is edited, by number."""
    fake_gh.open_issue = 9

    checker.report("A census title", ["STALE: an.arm claims ['a.json']"])

    assert [call[2] for call in fake_gh.calls] == ["list", "edit"]
    (edit_call,) = (call for call in fake_gh.calls if call[2] == "edit")
    assert edit_call[3] == "9"


def test_report_closes_an_open_issue_when_nothing_disagrees(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """No disagreement and an issue open: it gets closed, with a comment."""
    fake_gh.open_issue = 7

    checker.report("A census title", [])

    assert [call[2] for call in fake_gh.calls] == ["list", "close"]
    (close_call,) = (call for call in fake_gh.calls if call[2] == "close")
    assert "Re-measured" in close_call[close_call.index("--comment") + 1]


def test_report_does_nothing_when_clean_and_no_issue_is_open(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """No disagreement and no issue open: nothing is written."""
    checker.report("A census title", [])

    assert [call[2] for call in fake_gh.calls] == ["list"]


def _never_measures() -> dict[str, frozenset[str]]:
    """Raise instead of measuring, where a path must not reach `measure`."""
    raise AssertionError("measure() ran")


def test_the_measure_stand_in_raises_rather_than_measuring() -> None:
    """The control below is checked before it is relied on.

    A stand-in that quietly returned would leave the usage test passing
    whether or not the check it guards comes first.
    """
    with pytest.raises(AssertionError, match="measure"):
        _never_measures()


@pytest.mark.parametrize(
    "argv",
    [
        ["prog"],
        ["prog", "a title", "another title"],
        ["prog", "--dry-run"],
    ],
)
def test_main_says_how_to_be_called_when_it_is_not(
    checker: ModuleType,
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Anything but one title is the usage, and no measurement at all.

    Only a human running this by hand reaches it -- the workflow passes
    the title every time -- and what an unchecked unpacking of `args`
    gives them is a `ValueError` naming a list they never saw. The
    usage check comes before the measurement, and `_never_measures` is
    what says so: reached, the real `measure` runs every third-party
    vector module under coverage, so the regression would be a test
    taking minutes rather than one failing.
    """
    monkeypatch.setattr(checker, "measure", _never_measures)
    monkeypatch.setattr(sys, "argv", argv)

    assert checker.main() == 2

    captured = capsys.readouterr()
    # argv[0] is what names the program, so the fixture's own "prog" is
    # what comes back here rather than the script's file name
    assert captured.err == "usage: prog <issue title> [--dry-run]\n"
    assert not captured.out


def _measuring(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch, measured: set[str]
) -> None:
    """Stub the coverage runs over a one-arm table `measured` reaches."""
    monkeypatch.setattr(checker, "_AUTHORITY", {"an.arm": ("a.json",)})
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset())
    monkeypatch.setattr(checker, "measure", lambda: {"an.arm": frozenset(measured)})


def test_main_reports_the_disagreement_before_returning_red(
    checker: ModuleType,
    fake_gh: FakeGh,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A disagreement is both the non-zero exit and the issue, not either.

    The exit code is what makes the scheduled run red; the issue is what
    outlives the notification that run sends (issue btclib-org/btclib#1753).
    """
    _measuring(checker, monkeypatch, measured=set())
    monkeypatch.setattr(sys, "argv", ["prog", "A census title"])

    assert checker.main() == 1

    out = capsys.readouterr().out
    assert "STALE: an.arm claims ['a.json']" in out
    assert "1 disagreement(s) with a fresh measurement." in out
    assert [call[2] for call in fake_gh.calls] == ["list", "create"]


def test_main_closes_the_issue_when_the_table_agrees_again(
    checker: ModuleType,
    fake_gh: FakeGh,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A measurement that agrees prints the all-clear and closes the issue."""
    _measuring(checker, monkeypatch, measured={"a.json"})
    fake_gh.open_issue = 3
    monkeypatch.setattr(sys, "argv", ["prog", "A census title"])

    assert checker.main() == 0

    out = capsys.readouterr().out
    assert "Every _AUTHORITY entry matches a fresh no-bindings measurement." in out
    assert [call[2] for call in fake_gh.calls] == ["list", "close"]


def test_main_dry_run_prints_but_never_calls_issue(
    checker: ModuleType,
    fake_gh: FakeGh,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--dry-run keeps the red exit and touches no issue at all.

    What the pull_request trigger passes: a pull request exercising this
    script must not edit or close whatever issue is open at the time.
    """
    _measuring(checker, monkeypatch, measured=set())
    monkeypatch.setattr(sys, "argv", ["prog", "A census title", "--dry-run"])

    assert checker.main() == 1

    assert "1 disagreement(s) with a fresh measurement." in capsys.readouterr().out
    assert fake_gh.calls == []


def test_run_coverage_runs_one_module_and_reads_its_report(
    checker: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One module's pytest run, its JSON report read back as lines by file."""
    report = tmp_path / "0.json"
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        assert kwargs == {"cwd": checker._ROOT, "check": True}
        files = {"src/ecc/a.py": {"executed_lines": [1, 3]}}
        report.write_text(json.dumps({"files": files}), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(checker.subprocess, "run", fake_run)

    assert checker._run_coverage("a_test.py", report) == {"src/ecc/a.py": {1, 3}}
    assert calls == [
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/a_test.py",
            "--cov=ecc",
            f"--cov-report=json:{report}",
            "--cov-fail-under=0",
        ]
    ]


def test_reached_names_the_arms_a_line_of_whose_body_ran(
    checker: ModuleType,
) -> None:
    """A run reaches an arm where it ran a line of its body, and no other."""
    root = checker._ROOT
    locations = {
        "ran": (root / "src" / "ecc" / "a.py", 10, 12),
        "missed": (root / "src" / "ecc" / "a.py", 20, 22),
        "unrun_file": (root / "src" / "ecc" / "b.py", 10, 12),
    }
    executed = {str(Path("src", "ecc", "a.py")): {12, 19, 23}}

    assert checker._reached(executed, locations) == {"ran"}


def test_measuring_is_refused_where_the_bindings_are_installed(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installed bindings stop the run before any module is measured."""
    monkeypatch.setattr(checker, "INSTALLED", True)

    with pytest.raises(SystemExit, match="btclib_secp256k1 is installed"):
        checker._assert_bindings_absent()


def test_measuring_goes_ahead_where_the_bindings_are_absent(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No bindings installed is the environment `_AUTHORITY` is measured in."""
    monkeypatch.setattr(checker, "INSTALLED", False)

    assert checker._assert_bindings_absent() is None


def test_measure_refuses_first_then_runs_each_module_on_its_own_report(
    checker: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One run per module, in name order, each arm collecting who reached it."""
    steps: list[object] = []
    reports: list[Path] = []
    path = checker._ROOT / "src" / "ecc" / "a.py"
    rel = str(Path("src", "ecc", "a.py"))
    executed = {"a_test.py": {rel: {1}}, "b_test.py": {rel: {1, 5}}}

    def run_coverage(module: str, report_path: Path) -> dict[str, set[int]]:
        steps.append(module)
        reports.append(report_path)
        return executed[module]

    monkeypatch.setattr(checker, "_assert_bindings_absent", lambda: steps.append(0))
    monkeypatch.setattr(
        checker, "_arm_locations", lambda: {"one": (path, 1, 2), "two": (path, 5, 6)}
    )
    monkeypatch.setattr(
        checker, "_THIRD_PARTY_VECTORS", {"b_test.py": (), "a_test.py": ()}
    )
    monkeypatch.setattr(checker, "_run_coverage", run_coverage)

    assert checker.measure() == {
        "one": frozenset({"a_test.py", "b_test.py"}),
        "two": frozenset({"b_test.py"}),
    }
    assert steps == [0, "a_test.py", "b_test.py"]
    assert [report.name for report in reports] == ["0.json", "1.json"]
    assert reports[0].parent == reports[1].parent
    assert capsys.readouterr().out == (
        "measuring a_test.py ...\nmeasuring b_test.py ...\n"
    )


def test_the_main_guard_runs_the_script_as___main__(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    This project collects no coverage from a child interpreter, so a real
    subprocess would leave the guard uncovered. `runpy.run_path` executes
    the file fresh with `__name__` set to `"__main__"` in this one. With
    no title, `main` answers with its usage before it measures anything,
    as the usage test above shows.
    """
    # the script puts the repository root on sys.path when it runs
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["prog"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 2
    # runpy sets argv[0] to the file it runs, so its name is what the
    # usage line names
    assert capsys.readouterr().err == (
        f"usage: {_SCRIPT.name} <issue title> [--dry-run]\n"
    )
