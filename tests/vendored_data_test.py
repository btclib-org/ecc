# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `tests/_data/README.md` must not say about itself.

The same claim `release_notes_test.py` forbids CHANGELOG.md, for the same
reason and one more. A stated count is a line every open branch has to
edit, so a pull request vendoring a vector file is guaranteed to conflict
on it -- measured: the summary read 46, 47, 48, 49 and 50 across the
branches open on one afternoon, and each of those numbers was a rebase
conflict for the others. Worse, two branches moving it to the *same* new
number merge with nothing to decide, into a number that is wrong.

The one more is that this file has no `merge=union` driver to fall back
on, and cannot have one: union keeps both sides' added lines, which is
right for a list of bullets and nonsense for the prose around them. So
the number goes, the lists stay -- they are the fact the number
summarized -- and the Summary carries the `git ls-files` command that
derives it on demand.

Section 9 of the organization standard states the rule this module
enforces: never state how many of anything a file holds. Its one
exception is a count of what upstream published, which pins a vendored
file rather than measuring this tree. Everything below is an application
of that rule: a numeral -- a digit run, or a spelled-out numeral as a word -- is
forbidden anywhere in this README unless `_NOT_A_COUNT` accounts for it,
or the line it sits on is named in `_EXEMPT` with the reason beside it.

A shape match is not the guard: "N files." opening a line, and a bullet under
`## Summary` opening with a digit, each have a gap a widened pattern would only
move -- the noun ("response bodies", "vectors", a spelled-out "seven") and the
section (a `###` heading or the Provenance prose are not `## Summary`) -- and
the general form of "a count in prose" is not regular, so a pattern loose enough
to catch every wrong shape also catches sentences that are not wrong
(btclib-org/btclib#1633). What is enumerated instead is what is *permitted*:
every line below was found by running the pattern above against this file as it
stands and reading what it caught, not by predicting the shape a violation would
take.

The carve-outs are mechanical rather than semantic, and none of them scopes
the scan to a section:

- **A fenced block is not scanned, whatever its language.** The
  ` ```text ` ones are the pin metadata -- `repo`, `path`, `commit`,
  `blob`, `pulled`, `behind` -- which this README's own "Reading an
  entry" section already defines as facts of a pin, on every entry;
  scanning them would repeat that one justification once per entry for
  nothing a reader learns twice. The ` ```shell ` ones are commands, and
  a digit in a command is an argument.
- **"one" and "zero" are matched as digits, never as spelled words.** As
  words they are pronouns and articles ("one of them", "not one", "no
  one") far more often than counts in this file's prose, and a pattern
  that treated every "one" as a numeral would flag most of its sentences
  for no reason connected to this guard.
- **A numeral naming something is subtracted before `_NUMERAL` runs.**
  `_NOT_A_COUNT` takes out an ISO date, a `bip-`/`slip-` or NIST `P-` number, an
  `issue #N`, an `ISS N` or an `owner/repo#N`, a Wycheproof `tcId N` and a
  dotted version, each of which names a thing rather than counting one. A hyphen
  is what puts a specification number in front of the pattern at all: a digit
  run is matched between word boundaries, which `bip-0327` offers and a fused
  `BIP0327` does not, so such a number is caught or missed according to how
  upstream spells its own path. Exempting such a line records a decision nobody
  made, where an entry of `_EXEMPT` is meant to record one
  (btclib-org/btclib#1684).

An exemption pins its line verbatim, so editing a line that carries one
means editing its entry too. That cost is one line and not a paragraph:
nothing here rewraps markdown -- `markdownlint`'s MD013 has no fixer and
prettier's own hook does not take markdown -- so a correction is
surgical, and the guards below name the line they are unhappy about.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import re
from pathlib import Path

import pytest

_README = Path(__file__).parents[1] / "tests" / "_data" / "README.md"

# a digit run, or a spelled-out cardinal as a whole word ("one" and "zero"
# excepted -- see the module docstring)
_NUMERAL = re.compile(
    r"(?i)\b(?:\d+|two|three|four|five|six|seven|eight|nine|ten|eleven|"
    r"twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
    r"nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    r"hundred|thousand)\b"
)

# the numerals that name something rather than count it, subtracted before
# _NUMERAL runs: an ISO date at day or month precision, a specification
# identifier as the bips and slips repositories spell one in a path and as NIST
# names a curve, an issue of this tracker in either form the prose uses or
# qualified by its repository, a Wycheproof test-case identifier, and a dotted
# version -- three shapes rather than one, a version appearing here after a
# name, in three components, and with a pre-release suffix. The first takes the
# version and never the name in front of it, which is what keeps subtracting
# able only to leave a numeral visible and never to hide one. A decimal is not
# among them on purpose: a size in megabytes or a percentage is a measurement,
# which is a count and wants a line of its own. No `rfc-`: an RFC is cited here
# with a space rather than a hyphen, and subtracting `RFC \d+` as well empties
# no line that the shapes below do not already empty
_NOT_A_COUNT = re.compile(
    r"\b\d{4}-\d{2}(?:-\d{2})?\b"
    r"|(?i:\b(?:bip|slip)-\d+)|\bP-\d+"
    r"|(?i:\bissues?[ /]#?\d+)|\bISS \d+|\b[\w.-]+/[\w.-]+#\d+"
    r"|\btcId \d+"
    r"|(?<=[a-zA-Z]-)\b\d+(?:\.\d+)+"
    r"|\b\d+\.\d+\.\d+\b"
    r"|\b\d+(?:\.\d+)+(?=(?i:rc|a|b|dev|post)\d)"
)

# the reason an exempted line carries, named once and reused: what reaches
# _EXEMPT is the rule's own exception, a count of what upstream
# published, and a numeral that is not one is a numeral the README drops
_UPSTREAM_FACT = (
    "a fact of the upstream specification or vendored artefact,"
    " not a count of this tree"
)

# built by running _NUMERAL against tests/_data/README.md's prose, past
# _NOT_A_COUNT (every line outside a fenced ```text``` block, see
# _prose_lines) and classifying every hit: each is named here with its
# reason, or the README no longer states it (btclib-org/btclib#1633)
_EXEMPT: dict[str, str] = {
    "citation is pinned to a commit and the two blobs are compared.": _UPSTREAM_FACT,
    "The two halves are kept in agreement in one direction only: a test module": _UPSTREAM_FACT,
    "gives the git blob SHA-1 of what that entry pins; what it pins, and": _UPSTREAM_FACT,
    "The comparison is on git blob SHA-1, not sha256: it is what a tree entry": _UPSTREAM_FACT,
    "The two hashes match for every file whose verdict is **identical**. Where": _UPSTREAM_FACT,
    "`--fix=lf`, so our blob is `aa317a3b` rather than the one above. All 19": _UPSTREAM_FACT,
    "vectors, all eight columns.": _UPSTREAM_FACT,
    "Four of the 19 are messages of 0, 1, 17 and 100 bytes: BIP340 accepts a": _UPSTREAM_FACT,
    "take one, and no 32-byte gate sends these four down the Python path.": _UPSTREAM_FACT,
    "All four pass on either arithmetic: `verify_` accepts each, and `sign_`": _UPSTREAM_FACT,
    "them: six were untouched since the commit that added all eight,": _UPSTREAM_FACT,
    '(2024-05-14, "Fix the four test vectors"); and `sig_agg_vectors.json`': _UPSTREAM_FACT,
    "placeholder cited as the tip of all eight paths, when it is the tip of": _UPSTREAM_FACT,
    "56 cases between them, and `tests/schemes/musig2_test.py` runs every one:": _UPSTREAM_FACT,
    "1 sorting, 4 + 5 aggregations valid and failing, 4 nonce derivations,": _UPSTREAM_FACT,
    "2 + 3 nonce aggregations, 6 + 6 + 3 + 2 signatures (valid, refused at": _UPSTREAM_FACT,
    "signing, false on verification, refused on verification), 5 + 1": _UPSTREAM_FACT,
    "tweaked, 4 + 5 deterministic, 4 + 1 aggregated. An error case carries": _UPSTREAM_FACT,
    "function for function, and copies four of its error message strings": _UPSTREAM_FACT,
    "The files test the two halves of the map, and both halves are": _UPSTREAM_FACT,
    "eight `case` columns are eight assertions per row rather than one — an": _UPSTREAM_FACT,
    "`t>=p`, `info[v=0]`), which is what makes the files a branch": _UPSTREAM_FACT,
    "Neither file covers `create` or `encode`: those pick one of up to eight": _UPSTREAM_FACT,
    "secp256k1's and over secp256k1's own, the latter including a = 1 and": _UPSTREAM_FACT,
    "a = n - 1, and failure cases -- a zero scalar, a scalar equal to n, one": _UPSTREAM_FACT,
    "equal to n + 1, which an implementation reducing the scalar mod n would": _UPSTREAM_FACT,
    "all but its a = 1 and a = n - 1 rows, and the failures are permutations": _UPSTREAM_FACT,
    "Verdict: **reformatted**. 349 vectors, JSON-equal to the upstream blob;": _UPSTREAM_FACT,
    "ours is pretty-printed at four spaces. Re-checked on 2026-07-30: still": _UPSTREAM_FACT,
    "Verdict: **reformatted**. 199 vectors, JSON-equal.": _UPSTREAM_FACT,
    "the split between the two ECDSA profiles is explained, and where the": _UPSTREAM_FACT,
    "their prefix -- measured, all files verify identically at 32 and at 64.": _UPSTREAM_FACT,
    "and its verifier does not apply that rule, so two of these verdicts": _UPSTREAM_FACT,
    "are exempted rather than asserted — `wycheproof_test.py` reads which two": _UPSTREAM_FACT,
    "above, without the bitcoin profile's two extra rules: what a": _UPSTREAM_FACT,
    "of the two the files above vary one at a time.": _UPSTREAM_FACT,
    "digests that report their own length and a SHAKE's is 0.": _UPSTREAM_FACT,
    "Verdict: **identical**. Key agreement, with the public key X.509-encoded": _UPSTREAM_FACT,
    "above with the keys JWK-encoded (RFC 7517) rather than X.509: `WrongCurve`": _UPSTREAM_FACT,
    "Verdict: **transcribed**. Appendix A.2 of RFC 6979 gives 50 vectors, ten each": _UPSTREAM_FACT,
    "  check skips an entry whose `behind` reads other than 0, a gap somebody": _UPSTREAM_FACT,
    "request vendoring a file is guaranteed to have -- and two branches moving": _UPSTREAM_FACT,
}


def _countable(line: str) -> str:
    """`line` with the numerals that name rather than count removed."""
    return _NOT_A_COUNT.sub(" ", line)


def _prose_lines() -> list[str]:
    """Every line of the README outside a fenced ```text``` block."""
    in_fence = False
    lines = []
    for line in _README.read_text(encoding="utf-8").split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return lines


def test_every_numeral_outside_the_allowlist_is_a_count_of_this_tree() -> None:
    """Enforces section 9's "never state how many of anything a file holds".

    A numeral on a line `_EXEMPT` does not name is either a count of what
    this tree holds -- drop it, the way "the eight BIP327 files" became
    "the BIP327 files" -- or it is the rule's own exception, a count of
    what upstream published, and belongs in `_EXEMPT` with the reason
    beside it.
    """
    offenders = sorted(
        {
            line
            for line in _prose_lines()
            if _NUMERAL.search(_countable(line)) and line not in _EXEMPT
        }
    )
    assert not offenders, (
        "tests/_data/README.md states a numeral section 9's"
        ' "never state how many of anything a file holds" forbids,'
        f" on a line _EXEMPT does not name: {offenders!r}"
    )


def test_every_exemption_is_still_a_line_that_needs_one() -> None:
    """An exemption outliving its line is dormant, not gone.

    Each of `_EXEMPT`'s lines must still be in the file, verbatim, and must
    still match `_NUMERAL` once `_NOT_A_COUNT` has run over it -- a line the
    README no longer carries, or whose every numeral is a date or an identifier,
    is an exemption nothing needs and nothing here would otherwise notice.
    """
    lines = set(_prose_lines())
    missing = sorted(line for line in _EXEMPT if line not in lines)
    assert not missing, f"exempted, and no longer in the README: {missing!r}"
    stale = sorted(line for line in _EXEMPT if not _NUMERAL.search(_countable(line)))
    assert not stale, f"exempted, and states no numeral any more: {stale!r}"


def test_the_pattern_still_matches() -> None:
    """The guard above passes for free if `_NUMERAL` matches nothing.

    Which is the failure mode of every assertion written in the negative, and
    the one the file it reads cannot reveal: a pattern reworded past the text it
    forbids leaves a green test guarding an empty set. The first four are the
    strings btclib-org/btclib#1633 measured shape-based patterns missing; the
    other two are a summary line's own shape, spelled in digits and in words.
    """
    for text in (
        "### `tests/fetch/_data/*` — seven response bodies",
        "- the seven under `tests/fetch/_data/` are response bodies",
        "7 files.",
        "- 7 files here",
        "49 files. Against a pinned blob:",
        "Fifty files. Against a pinned blob:",
    ):
        assert _NUMERAL.search(_countable(text)), text


def test_a_numeral_that_names_something_is_subtracted_and_a_count_is_not() -> None:
    """`_NOT_A_COUNT` fails in two directions, and only one of them is loud.

    A shape that stops matching puts its lines back in front of `_NUMERAL`,
    and the guard above says which; a shape that reaches past what it names
    swallows the count beside it and the guard goes quiet. The second group
    is that half: each line states a numeral `_NUMERAL` reads as a count
    *and* carries a date, an identifier or a version, and each is exempted
    for that numeral alone.
    """
    for named in (
        "Pulled 2020-06-08, except `block_200000.bin`, 2020-06-09.",
        "All of them entered upstream in 2026-08, after 3.2.0 shipped, so the",
        "BIP322 files on 2026-08-08, and the Wycheproof files with the licence",
        "The vectors of `bip-0327/vectors/`, vendored whole",
        "P-192, P-224, P-256, P-384 and P-521, as `tests/schemes/rfc6979_test.py`",
        "which engine the vectors feed (issue 168).",
        "is not implemented (issue #187), so there is nothing yet for those to",
        "[ISS 1120](https://github.com/btclib-org/btclib/issues/1120) is where",
        "send (btclib-org/btclib#2160, closed by the same change that added it).",
        "`Untruncatedhash` case of the pair as tcId 190.",
        "licence that is not MIT: Apache-2.0, whose condition on redistribution",
    ):
        assert not _NUMERAL.search(_countable(named)), named
    for counted in (
        '(2024-05-14, "Fix the four test vectors"); and `sig_agg_vectors.json`',
        "The twelve `scriptPubKey`s reported in issue #123, the five transactions",
        "Verdict: **identical**. SLIP-0039's 1024 words, ten bits each, and the",
        "3.2.0, where -4 carries the misspelling this pin's commit corrects — a",
    ):
        assert _NUMERAL.search(_countable(counted)), counted


# a "## " or "### " heading, matched to split the README into sections without
# a sliding window: a window over-counts a "### " heading's own verdict past
# the next entry, which is what first over-counted here
# (btclib-org/btclib#1669)
_SECTION_HEADING = re.compile(r"^#{2,3} .+$", re.MULTILINE)

# a "### " heading that is nothing but one file path in backticks -- a "Not
# vendored as a file: ..." heading has prose of its own and never matches,
# which is the point: such an entry has no name to compare the Summary
# against. The same shape also excludes a heading with trailing prose after
# the path -- "### `tests/tx/_data/*.bin` — segwit transactions" and "###
# `tests/fetch/_data/*` — response bodies" among them -- and neither is
# transcribed today, so nothing is missed; a transcribed entry written with a
# trailing dash would drop out of both sets with nothing red to say so
_VENDORED_FILE_HEADING = re.compile(r"^### `([^`]+)`$")

_TRANSCRIBED_VERDICT = "Verdict: **transcribed**"

_SUMMARY_FILENAME = re.compile(r"`([\w.-]+\.\w+)`")


def _sections(text: str) -> list[tuple[str, str]]:
    """Every heading of `text`, paired with the section text that follows it."""
    heads = [(m.start(), m.group(0)) for m in _SECTION_HEADING.finditer(text)]
    return [
        (
            heading,
            text[pos : heads[i + 1][0] if i + 1 < len(heads) else len(text)],
        )
        for i, (pos, heading) in enumerate(heads)
    ]


def _transcribed_vendored_files(text: str) -> set[str]:
    """Basenames of the vendored files whose own entry is transcribed."""
    return {
        match.group(1).rsplit("/", 1)[-1]
        for heading, body in _sections(text)
        if (match := _VENDORED_FILE_HEADING.match(heading))
        and _TRANSCRIBED_VERDICT in body
    }


def _summary_transcribed_files(text: str) -> set[str]:
    """Basenames the Summary lists in its transcribed bullet."""
    for heading, body in _sections(text):
        if heading.strip() != "## Summary":
            continue
        lines = body.split("\n")
        start = next(
            (i for i, line in enumerate(lines) if line.startswith("- transcribed")),
            None,
        )
        if start is None:
            raise AssertionError(
                'tests/_data/README.md\'s Summary has no "- transcribed" bullet'
            )
        end = start + 1
        while end < len(lines) and not lines[end].startswith("- "):
            end += 1
        return set(_SUMMARY_FILENAME.findall("\n".join(lines[start:end])))
    raise AssertionError("tests/_data/README.md has no ## Summary section")


def test_summary_names_every_transcribed_vendored_file() -> None:
    """The Summary names exactly the vendored files whose entry is transcribed.

    [ISS 1669](https://github.com/btclib-org/btclib/issues/1669) found
    the bullet naming fewer files than the entries carry, and naming one,
    `descriptor_checksums.json`, whose own verdict is **composed
    locally**, not transcribed. Reading the file by its own `###`
    sections is what finds either kind of drift; a sliding window over a
    fixed span of text is not, since it can run past the next entry's own
    verdict and count it as the current one's.
    """
    text = _README.read_text(encoding="utf-8")
    entries = _transcribed_vendored_files(text)
    summary = _summary_transcribed_files(text)
    assert entries == summary, (
        f"in the entries but not the Summary: {sorted(entries - summary)!r}; "
        f"in the Summary but not transcribed in the entries: "
        f"{sorted(summary - entries)!r}"
    )


def test_the_transcribed_comparison_can_actually_fail() -> None:
    """The check above passes for free if it can never disagree with itself.

    Mirrors `test_the_pattern_still_matches`'s idiom: a synthetic pair,
    identical but for one file name, proves the comparison distinguishes
    a matching Summary from a mismatched one rather than only ever
    confirming the real file, which cannot itself demonstrate that.
    """
    heading_and_verdict = (
        "### `tests/_data/kept.json`\n\n"
        "Verdict: **transcribed**, for the purpose of this test.\n\n"
    )
    matching = heading_and_verdict + (
        "## Summary\n\n- transcribed, matched:\n  `kept.json`.\n"
    )
    mismatched = heading_and_verdict + (
        "## Summary\n\n- transcribed, matched:\n  `other.json`.\n"
    )

    assert _transcribed_vendored_files(matching) == _summary_transcribed_files(matching)
    assert _transcribed_vendored_files(mismatched) != _summary_transcribed_files(
        mismatched
    )


def test_a_summary_transcribed_read_needs_a_summary_section() -> None:
    """`_summary_transcribed_files` raises rather than answering an empty set.

    The real README always has a `## Summary`, so nothing in the check
    above trips this path; a text with none is what does, and is what
    keeps a rewrite that drops the heading loud instead of silently
    reading as "the Summary names nothing transcribed".
    """
    with pytest.raises(AssertionError, match="no ## Summary section"):
        _summary_transcribed_files("### `tests/_data/kept.json`\n\nno Summary here.\n")


def test_a_summary_transcribed_read_needs_a_transcribed_bullet() -> None:
    """`_summary_transcribed_files` raises with a message, not `StopIteration`.

    A `## Summary` with no bullet starting "- transcribed" is what trips
    this: the generator `next()` reads has nothing to give it, and the
    message is what keeps such a rewrite loud instead of surfacing as an
    unrelated `RuntimeError` with no README path in it -- the same
    failure class the sibling test above guards, on the other bullet.
    """
    with pytest.raises(AssertionError, match='no "- transcribed" bullet'):
        _summary_transcribed_files(
            "### `tests/_data/kept.json`\n\n## Summary\n\n- identical: `kept.json`.\n"
        )
