"""The Phase 6 frontend, tested from Python -- including the rule it exists for.

WHY A PYTHON TEST FOR A JAVASCRIPT SCREEN
-----------------------------------------
Phase 6 ships with no bundler and no browser, so the frontend is not unit-tested
the way a JavaScript project would test it. It is tested in two layers instead,
and the second one had to be added after an audit showed what the first misses.

**Structure, read as text.** Some of what matters most about this frontend is
not behavioural at all, and a text-level scanner is the right tool for it:

**D8 -- the frontend computes nothing.** Every guarantee this project makes
lives in Python that ~3050 tests and ``--doctest-modules`` cover. A number
computed in JavaScript is outside all of it, and it lands on a screen a judge is
reading, next to numbers that are covered, with nothing to tell them apart. So
:func:`test_no_arithmetic_outside_the_chart_geometry` strips the comments and
string literals out of every shipped script and asserts that no arithmetic
operator survives anywhere except in ``charts.js``, whose whole job is turning
values into pixel coordinates. The rule stops being a promise in a docstring and
becomes something that fails a build.

The other five things this file pins, in the order they would hurt:

* **Nothing is fetched from a network.** Venue wifi fails, and a demo that dies
  on an unreachable CDN dies in public. Every ``src`` and ``href`` is checked to
  be a same-origin path under the mount the service actually uses and to exist
  on disk, and every served file is checked for the ``@import`` or absolute URL
  that would smuggle a remote fetch inside something that looked local -- over
  file CONTENTS rather than over the tags anyone wrote by hand.
* **The page and the service agree on where the frontend is mounted.** The
  service serves the page at ``/`` and mounts the directory at ``/static``, so
  a relative ``css/app.css`` resolves to ``/css/app.css`` and 404s -- every
  stylesheet and every script at once, on the one page anybody looks at, and
  invisibly under a plain static file server. Both ends of that seam are
  asserted here.
* **The screen's vocabulary matches Python's.** ``render.js`` maps
  ``RunOutcome`` and ``Support`` values to visual states. If Python grew a fifth
  outcome, the screen would quietly render "OUTCOME NOT SUPPLIED" for it; the
  maps are read out of the JavaScript and compared against the enums.
* **The recorded runs still exercise the eight things the screen must get
  right.** A no-verdict run, an honest run that fires against the noiseless
  null, an unmonitored run, a degenerate-key-length run, an undetectable-by-
  construction run and an adversary-that-did-not-act run are all asserted to be
  in the set -- because a fixture set that lost one of them would leave the
  corresponding panel unexercised and unseen until the demonstration.
* **The contract and the recordings agree.** The manifest the page validates
  against at runtime is the same file this test reads.

**Behaviour, by running the shipped scripts.** Everything above reads the
frontend as characters, and an audit measured the size of that hole: swapping
one field name in ``boundsPanel`` made the dashboard publish the BUDGET under
the caption "THE NUMBER TO QUOTE", and reversing ``scale()`` in ``charts.js``
mirrored every bar about its axis -- and the whole suite stayed green through
both. So the last section of this file loads ``format.js``, ``charts.js``,
``contract.js`` and ``render.js`` into a Node ``vm`` context under a two-function
DOM shim, feeds them the committed recordings, and asserts on the values that
come out. It needs ``node`` on PATH and skips loudly without it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

import pytest

from sih141.detect.detector import HYPOTHESES, Hypothesis, Support
from sih141.detect.thresholds_structural import RunOutcome

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "sih141" / "web" / "static"
RECORDED = STATIC / "data" / "recorded"
CONTRACT_PATH = STATIC / "data" / "api-contract.json"
CONSTANTS_PATH = STATIC / "data" / "constants.json"

#: The one script allowed to do arithmetic, because plotting is arithmetic and
#: D8 permits plotting. Nothing in it can format a number for display, which is
#: what keeps "turn a value into an x coordinate" from becoming "put a number on
#: the screen that Python never saw".
GEOMETRY_SCRIPT = "charts.js"

#: The one script allowed to format numbers.
FORMAT_SCRIPT = "format.js"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def contract() -> dict[str, Any]:
    """The manifest the page validates responses against."""
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def constants() -> dict[str, Any]:
    """The figures the screen needs that no endpoint returns."""
    return json.loads(CONSTANTS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def recordings() -> dict[str, dict[str, Any]]:
    """Every recorded ``POST /api/run`` response, keyed by scenario."""
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(RECORDED.glob("run_*.json")):
        out[path.stem.replace("run_", "", 1)] = json.loads(
            path.read_text(encoding="utf-8")
        )
    return out


def scripts() -> list[Path]:
    """Return every shipped script, sorted.

    Returns
    -------
    list of pathlib.Path
    """
    return sorted((STATIC / "js").glob("*.js"))


# --------------------------------------------------------------------------- #
# The JavaScript scanner
# --------------------------------------------------------------------------- #


def strip_js(source: str) -> str:
    """Remove comments and replace every string literal with ``§``.

    Written as a character scanner rather than a pile of regular expressions,
    because the thing being looked for afterwards -- an arithmetic operator --
    appears inside comments and string literals constantly, and a scan that
    cannot tell those apart from code either passes everything or fails
    everything. Template literals keep their ``${...}`` holes as code, since
    that is exactly where a calculation would hide.

    Parameters
    ----------
    source : str
        JavaScript source.

    Returns
    -------
    str
        The same source with ``//`` and ``/* */`` comments gone and every
        string, template and template-literal *text* run collapsed to a single
        ``§``. Code inside ``${...}`` survives.

    Examples
    --------
    A comment full of operators contributes nothing:

    >>> strip_js("const a = b; // x * y / z")
    'const a = b; '

    Two string literals joined by ``+`` collapse to the concatenation pattern
    this module allows, while a real multiplication survives to be caught:

    >>> strip_js('t("one " + "two")')
    't(§ + §)'
    >>> strip_js("const w = right - left;")
    'const w = right - left;'

    A template's text is a literal, and its holes are code:

    >>> strip_js("`a ${x * 2} b`")
    '§${x * 2}§'
    """
    out: list[str] = []
    index = 0
    length = len(source)
    # A stack of open template literals, so `${ ... `nested` ... }` works.
    template_depth: list[int] = []
    while index < length:
        char = source[index]
        pair = source[index : index + 2]
        if pair == "//":
            while index < length and source[index] != "\n":
                index += 1
            continue
        if pair == "/*":
            index += 2
            while index < length and source[index : index + 2] != "*/":
                index += 1
            index += 2
            continue
        if char in "'\"":
            quote = char
            index += 1
            while index < length and source[index] != quote:
                index += 2 if source[index] == "\\" else 1
            index += 1
            out.append("§")
            continue
        if char == "`":
            index += 1
            out.append("§")
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == "`":
                    index += 1
                    break
                if source[index : index + 2] == "${":
                    out.append("${")
                    index += 2
                    template_depth.append(1)
                    # Fall back into the outer loop to scan the hole as code.
                    break
                index += 1
            else:  # pragma: no cover - unterminated template
                break
            if template_depth:
                # Scan the hole, then resume the template text after its `}`.
                hole: list[str] = []
                while index < length and template_depth:
                    if source[index] == "{":
                        template_depth[-1] += 1
                    elif source[index] == "}":
                        template_depth[-1] -= 1
                        if template_depth[-1] == 0:
                            template_depth.pop()
                            break
                    hole.append(source[index])
                    index += 1
                out.append(strip_js("".join(hole)))
                out.append("}")
                index += 1
                # Whatever follows is more template text, up to the closing
                # backtick or the next hole. Re-enter by rewinding one char.
                source = f"`{source[index:]}"
                index = 0
                length = len(source)
            continue
        out.append(char)
        index += 1
    return "".join(out)


def strip_comments_only(source: str) -> str:
    """Remove comments and keep every string literal intact.

    The counterpart of :func:`strip_js`. That one hides the strings so the
    scanner can see the arithmetic; this one hides the comments so a scanner
    can see what actually reaches the screen. A prose paragraph explaining that
    a figure must not be hard-coded is not the same thing as hard-coding it.

    Parameters
    ----------
    source : str

    Returns
    -------
    str

    Examples
    --------
    >>> strip_comments_only('const a = "115200"; // not 115200')
    'const a = "115200"; '
    """
    out: list[str] = []
    index = 0
    length = len(source)
    while index < length:
        pair = source[index : index + 2]
        if pair == "//":
            while index < length and source[index] != "\n":
                index += 1
            continue
        if pair == "/*":
            index += 2
            while index < length and source[index : index + 2] != "*/":
                index += 1
            index += 2
            continue
        char = source[index]
        if char in "'\"`":
            quote = char
            out.append(char)
            index += 1
            while index < length and source[index] != quote:
                out.append(source[index])
                if source[index] == "\\":
                    index += 1
                    if index < length:
                        out.append(source[index])
                index += 1
            if index < length:
                out.append(source[index])
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def code_of(path: Path) -> str:
    """Return one script with its comments and string literals removed."""
    return strip_js(path.read_text(encoding="utf-8"))


def drop_negative_literals(code: str) -> str:
    """Remove the unary minus in front of a numeric literal.

    ``{min: -4, max: 4}`` is the CHSH statistic's definitional domain written
    down, not a subtraction. The minus is only unary when what precedes it
    cannot be an operand, which is what the lookbehind checks.

    Parameters
    ----------
    code : str

    Returns
    -------
    str

    Examples
    --------
    >>> drop_negative_literals("domain: { min: -4, max: 4 }")
    'domain: { min: 4, max: 4 }'
    >>> drop_negative_literals("const w = right - 4;")
    'const w = right - 4;'
    """
    return re.sub(r"(?<=[,:\[(=])\s*-(?=\d)", " ", code)


def collapse_string_concatenation(code: str) -> str:
    """Collapse ``§ + § + §`` runs to a single ``§``.

    Joining two string literals with ``+`` is concatenation, not arithmetic: no
    operand is a number and none can become one. Collapsing those runs first
    means the check that follows can simply demand that no ``+`` survives.

    Parameters
    ----------
    code : str
        Output of :func:`strip_js`.

    Returns
    -------
    str

    Examples
    --------
    >>> collapse_string_concatenation("f(§ + § + §);")
    'f(§);'
    >>> collapse_string_concatenation("f(a + b);")
    'f(a + b);'
    """
    return re.sub(r"§(?:\s*\+\s*§)+", "§", code)


# --------------------------------------------------------------------------- #
# D8: no arithmetic, no formatting, no markup injection
# --------------------------------------------------------------------------- #


def test_every_shipped_script_is_scannable() -> None:
    """The scanner must actually see every script, or it proves nothing."""
    names = {path.name for path in scripts()}
    assert names == {
        "app.js",
        "charts.js",
        "contract.js",
        "format.js",
        "render.js",
    }, (
        "a script was added or renamed. Every check in this module is a "
        "whitelist over this set, so an unlisted script would ship unchecked."
    )


@pytest.mark.parametrize(
    "operator", ["*", "/", "%", "-", "+", "**", "+=", "-=", "++", "--"]
)
def test_no_arithmetic_outside_the_chart_geometry(operator: str) -> None:
    """No arithmetic operator survives outside ``charts.js``.

    This is D8 as a build failure. `charts.js` is exempt because turning a
    value into a pixel coordinate is plotting, which D8 permits by name, and
    because that file is separately forbidden from formatting a number for
    display -- so nothing it computes can reach the screen as text.
    """
    for path in scripts():
        if path.name == GEOMETRY_SCRIPT:
            continue
        code = drop_negative_literals(
            collapse_string_concatenation(code_of(path))
        )
        assert operator not in code, (
            f"{path.name} contains {operator!r} outside a comment or a string. "
            f"D8: the frontend formats, lays out, colours and plots; it does "
            f"not derive, average, sum, threshold, round-for-meaning or infer. "
            f"If the screen needs a quantity the API does not return, add it "
            f"to the API with a test."
        )


def test_no_maths_library_calls_outside_the_chart_geometry() -> None:
    """`Math.` is geometry or it is a derivation; only geometry is allowed."""
    for path in scripts():
        if path.name == GEOMETRY_SCRIPT:
            continue
        assert "Math." not in code_of(path), (
            f"{path.name} calls Math. Everything Math offers -- min, max, "
            f"round, log, sqrt -- is a derivation when applied to an API "
            f"value, and every one of them would be a number on the screen "
            f"that no test covers."
        )


def test_the_chart_geometry_cannot_format_a_number() -> None:
    """`charts.js` may compute pixels and may not turn one into text.

    This is half of what makes the arithmetic exemption safe: every string that
    reaches the screen from the chart module arrived as a caller-supplied
    ``label``, formatted in ``format.js`` from a value the API sent. It says
    nothing about whether the GEOMETRY is right -- a mirrored axis puts no wrong
    characters anywhere -- and that half is
    :func:`test_bars_are_drawn_left_to_right_from_the_domain_minimum`, which
    runs the module.
    """
    code = code_of(STATIC / "js" / GEOMETRY_SCRIPT)
    for name in ("toFixed", "toExponential", "toPrecision", "toLocaleString"):
        assert name not in code, (
            f"{GEOMETRY_SCRIPT} calls {name}. The chart module is allowed to "
            f"do arithmetic ONLY because it cannot render a number: if it can "
            f"format one, a computed value reaches the screen."
        )


def test_number_formatting_lives_in_exactly_one_file() -> None:
    """Only ``format.js`` turns a number into a string."""
    for path in scripts():
        if path.name == FORMAT_SCRIPT:
            continue
        code = code_of(path)
        for name in ("toFixed(", "toExponential(", "toPrecision("):
            assert name not in code, (
                f"{path.name} formats a number directly. Route it through "
                f"format.js, which is the one place display rounding is "
                f"pinned to Python's own {{:.4e}}."
            )


def test_no_protocol_figure_is_written_into_the_frontend() -> None:
    """No key length, floor or bound is typed into the JavaScript.

    A figure hard-coded in prose is a figure that goes stale silently: it keeps
    rendering, in the same typeface, next to the API's own numbers, long after
    the parameter set moved. Every one of these must arrive from
    ``/api/defaults`` or from a per-run response.

    ``2`` and ``4`` are exempt by construction -- they are the CHSH
    inequality's own bounds and the statistic's definitional range, which live
    in ``data/constants.json`` and are pinned against ``math.sqrt`` elsewhere
    in this module.
    """
    figures = [
        "115200",
        "115,200",
        "36555",
        "74190",
        "1.4139",
        "1200",
        "0.03125",
        "36,555",
        "74,190",
    ]
    for path in scripts():
        source = strip_comments_only(path.read_text(encoding="utf-8"))
        for figure in figures:
            assert figure not in source, (
                f"{path.name} has {figure!r} written into it. It has to come "
                f"from the API, or it will still be on the screen after the "
                f"parameter set that made it true has changed."
            )


def test_no_percentages_anywhere() -> None:
    """A percentage is a multiplication, so the screen shows rates as rates."""
    for path in scripts():
        assert "percent" not in code_of(path).lower(), (
            f"{path.name} mentions a percentage. Rendering 0.0166 as '1.66%' "
            f"multiplies an API value by 100 in the browser."
        )


def test_no_string_conversion_of_control_values() -> None:
    """Controls are read with the DOM's own ``valueAsNumber``.

    Not a style rule. ``Number(x) * 2`` is one keystroke from
    ``Number(x)``, and every parse in the browser is a place where a value can
    be reshaped before it is sent. The API validates and caps; it has to
    anyway, and it is the only side of the wire that can.
    """
    for path in scripts():
        code = code_of(path)
        for name in ("parseInt(", "parseFloat(", "Number("):
            assert name not in code, f"{path.name} calls {name}"


def test_no_regular_expression_literals_anywhere() -> None:
    """The one construct the D8 scanner cannot tell from a division.

    A regex literal and ``a / b`` are the same three characters to a text
    scanner. Every check in this module rests on that scanner, so the frontend
    simply contains no regex literal: outside ``charts.js`` a stray ``/``
    already fails the arithmetic check, and inside it -- where division is
    allowed -- every slash is required to be a spaced binary operator, which a
    regex literal never is.
    """
    for path in scripts():
        code = code_of(path)
        if path.name != GEOMETRY_SCRIPT:
            assert "/" not in code, f"{path.name} has a slash outside a string"
            continue
        for index, char in enumerate(code):
            if char != "/":
                continue
            before = code[index - 1 : index]
            after = code[index + 1 : index + 2]
            assert before == " " and after == " ", (
                f"{GEOMETRY_SCRIPT} has a slash that is not a spaced division "
                f"at offset {index}: {code[index - 30 : index + 30]!r}. A "
                f"regex literal here would hide arithmetic from the scanner "
                f"every other check in this module depends on."
            )


def test_exponents_are_written_the_way_python_writes_them() -> None:
    """"1.0000e-09", not "1.0000e-9".

    The same bound appears twice on the screen: once in a PROVEN chip that this
    frontend formatted, and once inside ``detection.summary``, which Python
    formatted with ``{:.4e}``. JavaScript's ``toExponential`` does not pad a
    single-digit exponent, so without this the two spellings differ and a
    reader has to work out that they are one number.
    """
    assert f"{1e-9:.4e}" == "1.0000e-09"
    source = (STATIC / "js" / FORMAT_SCRIPT).read_text(encoding="utf-8")
    assert "toExponential(4)" in source
    assert 'digits.length === 1 ? "0" : ""' in source, (
        "format.js no longer pads the exponent, so its chips and the "
        "detector's own summary block spell the same number differently."
    )


def test_no_markup_is_ever_built_from_data() -> None:
    """API strings are set with ``textContent``; data does not write HTML."""
    for path in scripts():
        code = code_of(path)
        for name in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                     "document.write"):
            assert name not in code, (
                f"{path.name} uses {name}. Every string on this screen is API "
                f"data; setting it as markup makes an API response able to "
                f"write the page."
            )


def test_no_reduction_over_api_data() -> None:
    """No summing, no counting-into-a-number, no folding."""
    for path in scripts():
        code = code_of(path)
        for name in (".reduce(", "reduceRight("):
            assert name not in code, (
                f"{path.name} folds a list. A sum taken in the browser is a "
                f"derived number however small it looks."
            )


# --------------------------------------------------------------------------- #
# Nothing is fetched from a network
# --------------------------------------------------------------------------- #


def _assets() -> Iterable[Path]:
    """Every file served to the browser."""
    for path in sorted(STATIC.rglob("*")):
        if path.is_file():
            yield path


def test_every_served_asset_is_a_known_kind() -> None:
    """A binary blob nobody can read is not an artefact anybody can audit."""
    allowed = {".html", ".css", ".js", ".json"}
    unexpected = [
        path.relative_to(STATIC).as_posix()
        for path in _assets()
        if path.suffix not in allowed
    ]
    assert unexpected == [], (
        f"unexpected asset kinds under the static root: {unexpected}. The "
        f"repo is the artefact: no bundles, no minified vendor blobs, nothing "
        f"that needs a toolchain to rebuild."
    )


def uncommented(path: Path) -> str:
    """Return one served asset with its comments removed.

    The prose in these files says, at length, that there is no CDN and no
    ``@import`` anywhere -- and a scan that read the prose would find both
    words and fail. Comments are stripped first so the scan sees only what the
    browser would act on.

    Parameters
    ----------
    path : pathlib.Path

    Returns
    -------
    str
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".js":
        return strip_js(text)
    if path.suffix == ".css":
        return re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    if path.suffix == ".html":
        return re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    return text


def test_no_asset_references_a_remote_origin() -> None:
    """No CDN, no web font, no beacon -- in any served file.

    Checked over the file contents rather than over the tags written by hand,
    because a vendored file with a remote ``@import`` inside it still fails at
    the venue, and it fails in the way that is hardest to notice beforehand.
    """
    pattern = re.compile(r"https?://|//cdn\.|@import|url\(\s*['\"]?//")
    offenders: list[str] = []
    for path in _assets():
        text = uncommented(path)
        for match in pattern.finditer(text):
            snippet = text[max(0, match.start() - 40) : match.end() + 40]
            # The SVG namespace is a URN-shaped constant, never fetched: the
            # DOM requires the literal string and no request is ever made for
            # it. Everything else is a real network reference.
            if "www.w3.org/2000/svg" in snippet:
                continue
            offenders.append(f"{path.relative_to(STATIC).as_posix()}: {snippet}")
    assert offenders == [], (
        "a served asset references a remote origin:\n" + "\n".join(offenders)
    )


def test_every_local_reference_resolves_on_disk() -> None:
    """Every script, stylesheet and data path the page names actually exists."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    referenced = re.findall(r'(?:src|href)="([^"]+)"', html)
    missing = [
        target
        for target in referenced
        if not target.startswith("data:")
        and not (STATIC / target.replace("/static/", "", 1)).exists()
    ]
    assert missing == [], f"index.html names files that do not exist: {missing}"
    assert referenced, "index.html references nothing at all"


def test_every_fetch_target_is_same_origin(
) -> None:
    """No path the page fetches names a host.

    They are root-absolute rather than relative, and deliberately: the service
    serves this page at ``/`` and mounts the frontend at ``/static``, so a
    relative ``css/app.css`` resolves to ``/css/app.css`` and 404s. What
    matters for safety is that none of them can leave the origin, which is what
    this checks.
    """
    code = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    targets = re.findall(r'getJson\(\s*[`"\']([^`"\'$]*)', code)
    assert targets, "app.js fetches nothing, which cannot be right"
    for target in targets:
        assert "://" not in target, f"{target!r} names an origin"
        assert not target.startswith("//"), f"{target!r} is protocol-relative"


def test_the_page_and_the_service_agree_on_where_the_frontend_is_mounted(
) -> None:
    """The seam that 404s the whole demonstration if the two halves disagree.

    ``index.html`` asks for ``/static/...``; the service mounts this directory
    there. Nothing else on the page is as cheap to get wrong or as total when
    it is.
    """
    from sih141.web import api

    html = (STATIC / "index.html").read_text(encoding="utf-8")
    referenced = re.findall(r'(?:src|href)="(/[^"]+)"', html)
    assert referenced, "index.html names no absolute asset paths"
    for target in referenced:
        assert target.startswith("/static/"), (
            f"{target!r} is not under the mount point the service uses"
        )
    source = Path(api.__file__).read_text(encoding="utf-8")
    assert '"/static"' in source, (
        "the service no longer mounts the frontend at /static, so every "
        "stylesheet and script on the page is a 404."
    )


def test_the_recorded_data_the_page_falls_back_to_exists() -> None:
    """The page must survive the API dying mid-demonstration."""
    for name in ("attacks.json", "defaults.json", "index.json"):
        assert (RECORDED / name).is_file(), (
            f"data/recorded/{name} is missing. Without it the page has no "
            f"fallback and a dead API is a blank screen in front of judges."
        )


# --------------------------------------------------------------------------- #
# The screen's vocabulary matches Python's
# --------------------------------------------------------------------------- #


def _js_object_block(source: str, name: str) -> str:
    """Return the body of a top-level ``const NAME = { ... };``.

    Brace-matched rather than pattern-matched, so a nested object inside one of
    the entries does not end the block early and quietly shorten the set of
    keys this module then compares against a Python enum.

    Parameters
    ----------
    source : str
    name : str

    Returns
    -------
    str

    Examples
    --------
    >>> _js_object_block('const M = {a: {b: 1}, c: 2};', 'M')
    'a: {b: 1}, c: 2'
    """
    opening = source.index(f"const {name} = {{")
    start = source.index("{", opening)
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index]
    raise AssertionError(f"{name} is not closed in the source")


def _js_object_keys(source: str, name: str) -> set[str]:
    """Return the quoted-or-bare keys of a top-level ``const NAME = {...}``.

    Parameters
    ----------
    source : str
    name : str

    Returns
    -------
    set of str

    Examples
    --------
    >>> src = 'const M = { a: 1, "b-c": {d: 2}, };'
    >>> sorted(_js_object_keys(src, "M"))
    ['a', 'b-c']
    """
    body = _js_object_block(source, name)
    flattened = re.sub(r"\{[^{}]*\}", "0", body)
    return set(re.findall(r'(?:^|,)\s*"?([A-Za-z][\w-]*)"?\s*:', flattened))


def test_the_outcome_map_covers_every_run_outcome() -> None:
    """A fifth ``RunOutcome`` must not render as "OUTCOME NOT SUPPLIED".

    The four-valued answer is the whole of constraint 1. If Python grows a
    value the screen does not know, the screen falls back to a neutral chip --
    which is a no-verdict shown as something else, silently.
    """
    source = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    keys = _js_object_keys(source, "OUTCOME_STATE")
    assert keys == {member.value for member in RunOutcome}


def test_the_support_map_covers_every_support_value() -> None:
    """Same for ``Support``, whose fourth value is the (AUTH) case."""
    source = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    keys = _js_object_keys(source, "SUPPORT_STATE")
    assert keys == {member.value for member in Support}


def test_the_no_verdict_state_is_visually_distinct_from_both_others() -> None:
    """Constraint 1, as a property of the stylesheet.

    Colour alone will not survive a washed-out projector or a colourblind
    viewer, so each of the four states carries a distinct border STYLE as well
    as a hue, and the two that mean "this was not evaluated" carry a hatch.
    """
    css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    styles = {}
    for name in ("is-clean", "is-detected", "is-noverdict", "is-withheld"):
        block = re.search(rf"\.{name} \{{(.*?)\}}", css, re.S)
        assert block is not None, f"{name} is not defined"
        found = re.search(r"border-style:\s*(\w+)", block.group(1))
        assert found is not None, f"{name} does not set a border style"
        styles[name] = found.group(1)
    assert styles["is-noverdict"] != styles["is-clean"]
    assert styles["is-noverdict"] != styles["is-detected"]
    assert styles["is-withheld"] != styles["is-clean"]
    assert styles["is-withheld"] != styles["is-detected"]
    assert "repeating-linear-gradient" in css, (
        "neither withheld state carries a hatch; on a bad projector the hue "
        "may be all that is left, and hue alone is what constraint 1 forbids."
    )


def test_attribution_statuses_do_not_reuse_the_verdict_colours() -> None:
    """"honest: supported" must not be painted in alarm red.

    The verdict palette says whether a threshold fired and what a verifier did.
    An attribution says which position the evidence is consistent with. Painting
    both with the same two hues blurs the distinction the four states exist to
    keep, and on a clean run it paints the honest row as an alarm.
    """
    source = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    block = re.search(r"const SUPPORT_STATE = \{(.*?)\n  \};", source, re.S)
    assert block is not None
    kinds = set(re.findall(r'kind:\s*"([\w-]+)"', block.group(1)))
    assert "detected" not in kinds and "clean" not in kinds, (
        f"attribution statuses use the verdict palette: {sorted(kinds)}"
    )


# --------------------------------------------------------------------------- #
# The contract and the recordings agree
# --------------------------------------------------------------------------- #


def test_every_recording_satisfies_the_contract(
    contract: dict[str, Any], recordings: dict[str, dict[str, Any]]
) -> None:
    """What the page validates at runtime, checked here at build time."""
    assert recordings, "no recorded runs found"
    top = contract["endpoints"]["run"]["required"]
    for scenario, payload in recordings.items():
        for name in top:
            assert name in payload, f"{scenario}: response has no {name!r}"
        for name in contract["detection"]["required"]:
            assert name in payload["detection"], (
                f"{scenario}: detection has no {name!r}"
            )
        for name in contract["detection"]["budget_required"]:
            assert name in payload["detection"]["budget"]
        for name in contract["run_facts"]["required"]:
            assert name in payload["run"], f"{scenario}: run has no {name!r}"
        for name in contract["run_facts"]["expected"]:
            assert name in payload["run"], f"{scenario}: run has no {name!r}"
        for name in contract["run_facts"]["nulls_expected"]:
            assert name in payload["run"]["nulls"], (
                f"{scenario}: run.nulls has no {name!r}. The null banner picks "
                f"one of three states off this block, and a half-supplied one "
                f"falls back to the rate family's flag alone -- which is the "
                f"state where an honest noisy run reads as an attack."
            )
        for name in contract["ground_truth"]["required"]:
            assert name in payload["ground_truth"]
        for name in contract["timings"]["required"]:
            assert name in payload["timings"]


def test_every_signal_and_attribution_carries_its_whole_shape(
    contract: dict[str, Any], recordings: dict[str, dict[str, Any]]
) -> None:
    """A signal missing its claim is a detection with no stated reason."""
    for scenario, payload in recordings.items():
        for signal in payload["detection"]["signals"]:
            for name in contract["detection"]["signal_required"]:
                assert name in signal, f"{scenario}: signal has no {name!r}"
        for row in payload["detection"]["attributions"]:
            for name in contract["detection"]["attribution_required"]:
                assert name in row, f"{scenario}: attribution has no {name!r}"


def test_the_attack_roster_states_detectability_explicitly(
    contract: dict[str, Any]
) -> None:
    """Constraint 4: the (AUTH) case is a value, never an omission."""
    attacks = json.loads((RECORDED / "attacks.json").read_text("utf-8"))
    allowed = set(contract["endpoints"]["attacks"]["detectable_values"])
    for entry in attacks:
        for name in contract["endpoints"]["attacks"]["item_required"]:
            assert name in entry, f"{entry.get('key')}: no {name!r}"
        assert entry["detectable"] in allowed
    undetectable = [
        entry
        for entry in attacks
        if entry["detectable"] == "undetectable-by-construction"
    ]
    assert len(undetectable) == 1, (
        "exactly one roster entry -- full impersonation -- is out of model by "
        "assumption, and it has to say so rather than be absent."
    )
    assert undetectable[0]["assumption"], (
        "the undetectable entry carries no assumption text. A blank there "
        "reads as 'we tried and failed'; the claim is 'we proved you cannot'."
    )


def test_the_defaults_carry_every_cap_the_ui_shows(
    contract: dict[str, Any]
) -> None:
    """Every bound the UI prints beside a control comes from the API.

    The controls are built from ``limits.fields``: minimum, maximum and the
    API's own sentence about what the field means. Nothing is typed into the
    frontend, so a cap that changes server-side changes on the screen, and a
    cap the API stops sending is printed as "range not supplied by the API"
    rather than silently becoming unbounded.
    """
    defaults = json.loads((RECORDED / "defaults.json").read_text("utf-8"))
    spec = contract["endpoints"]["defaults"]
    for name in spec["required"] + spec["expected"]:
        assert name in defaults, f"defaults has no {name!r}"
    for name in spec["params_expected"]:
        assert name in defaults["params"]
    for name in spec["bounds_expected"]:
        assert name in defaults["bounds"], f"bounds has no {name!r}"
    for name in spec["limits_expected"]:
        assert name in defaults["limits"]
    for name in spec["limit_fields_expected"]:
        field = defaults["limits"]["fields"][name]
        assert "minimum" in field and "maximum" in field, name
        assert field["note"], f"{name} has no note for the operator"
    for row in defaults["limits"]["cost_table"]:
        for name in spec["cost_row_expected"]:
            assert name in row
    # The calibration the panel renders, including the sentence that says the
    # table is one family's and that there are two nulls. Rendering the first
    # line without this one is how the screen came to instruct an operator to
    # state one null and told them it would clear the run.
    for name in spec["calibration_expected"]:
        assert name in defaults["noise_null_calibration"], (
            f"/api/defaults noise_null_calibration has no {name!r}"
        )
    assert defaults["live_key_length_max"] < 115200, (
        "the live cap must be well below DEFAULT_PARAMS: a session there is "
        "about four minutes and cannot come from a button click."
    )


def _pick(objects: list[Any], name: str) -> Any:
    """Python's copy of ``render.js``'s ``pick``: first supplied wins.

    Parameters
    ----------
    objects : list
    name : str

    Returns
    -------
    Any

    Examples
    --------
    >>> _pick([{}, {"a": 1}, {"a": 2}], "a")
    1
    >>> _pick([{}], "a") is None
    True
    """
    for candidate in objects:
        if isinstance(candidate, dict) and name in candidate:
            return candidate[name]
    return None


def test_the_headline_bounds_are_the_ones_the_panels_quote() -> None:
    """The figures the transferability argument rests on.

    The panel's whole argument is a comparison a reader makes by eye: this
    run's enforced repudiation bound, a number close to one, against the
    headline set's 1.4139e-09. Both have to be what the panel says they are, or
    the comparison is theatre.

    Read through the same two-place lookup the screen uses. The ``bounds``
    block moved between a flat layout and a nested ``headline``/``demo`` one
    while the two halves of Phase 6 were written in parallel, and the point of
    the lookup is that neither layout blanks the panel.
    """
    defaults = json.loads((RECORDED / "defaults.json").read_text("utf-8"))
    bounds = defaults["bounds"]
    headline = bounds.get("headline", {})
    params = defaults["params"]
    assert bounds["kind"] == "proven"
    assert _pick(
        [headline, bounds], "enforced_repudiation_bound"
    ) == pytest.approx(1.4139e-09, rel=1e-4, abs=0)
    assert _pick(
        [headline, {"minimum_matched": bounds.get("matched_minimum")}],
        "minimum_matched",
    ) == 36555
    assert _pick(
        [headline, {"minimum_pooled": bounds.get("pooled_minimum")}],
        "minimum_pooled",
    ) == 74190
    assert _pick([headline, params], "key_length") == 115200
    assert bounds["degenerate_below_key_length"] > 0, (
        "the panel prints the length below which the floors collapse; without "
        "it, a run at demo scale has nothing to say about why its own bound "
        "is useless."
    )


def test_the_chsh_reference_lines_come_from_the_api_or_the_shipped_file(
    constants: dict[str, Any]
) -> None:
    """Two sources, never a third, and never arithmetic in the browser."""
    import math

    defaults = json.loads((RECORDED / "defaults.json").read_text("utf-8"))
    bounds = defaults["bounds"]
    classical = _pick(
        [bounds, {"chsh_classical_bound": constants["chsh"]["classical_bound"]}],
        "chsh_classical_bound",
    )
    tsirelson = _pick(
        [bounds, {"chsh_tsirelson_bound": constants["chsh"]["tsirelson_bound"]}],
        "chsh_tsirelson_bound",
    )
    assert classical == 2.0
    assert tsirelson == pytest.approx(2.0 * math.sqrt(2.0))


def test_the_recorded_index_points_at_files_that_exist() -> None:
    """The walk-through must not have a dead button in it."""
    index = json.loads((RECORDED / "index.json").read_text("utf-8"))
    assert index, "the recorded index is empty"
    for entry in index:
        assert (RECORDED / entry["file"]).is_file(), entry["file"]
        assert entry["label"] and entry["why"], (
            f"{entry['file']}: a recorded run nobody can state the point of "
            f"is a recorded run nobody will click."
        )


# --------------------------------------------------------------------------- #
# The recordings still exercise the eight things the screen must get right
# --------------------------------------------------------------------------- #


def test_a_no_verdict_run_is_in_the_set(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Constraint 1 needs a run that actually produces the third state."""
    aborted = {
        scenario: payload
        for scenario, payload in recordings.items()
        if payload["detection"]["not_scored"]
    }
    assert aborted, (
        "no recorded run reaches a no-verdict, so the third visual state is "
        "never exercised and would be seen first at the demonstration."
    )
    for payload in aborted.values():
        for party in payload["detection"]["not_scored"]:
            assert (
                payload["detection"]["outcomes"][party]
                == RunOutcome.REFUSED.value
            )
        rows = {row["party"]: row for row in payload["run"]["verifiers"]}
        for party in payload["detection"]["not_scored"]:
            assert rows[party]["scored"] is False
            assert rows[party]["matched"] is None, (
                "a denied verifier must carry no matched count. A zero there "
                "would plot as a bar and read as a measurement."
            )
            assert rows[party]["rate"] is None


def test_a_failed_run_is_a_fourth_thing_and_the_screen_says_so(
    contract: dict[str, Any], recordings: dict[str, dict[str, Any]]
) -> None:
    """A run that did not happen is not a clean run.

    The service answers a run-level failure with 200, all four contract keys
    present, ``detection`` and ``run`` null and ``error`` filled in -- which is
    the right shape, because a 500 page in the middle of a demonstration tells
    the room nothing. It puts the burden on the screen: a null detection
    rendered as "nothing fired" would be a failed run shown as a clean one.
    """
    assert contract["endpoints"]["run"]["failure"]["field"] == "error"
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    assert "function failurePanel(" in render
    assert "NO RUN" in render
    # It has to run BEFORE the contract check, or a to-contract failure reads
    # as a contract violation.
    assert render.index("const failure = failurePanel(payload);") < render.index(
        "const check = Contract.checkRun(payload);"
    )
    for scenario, payload in recordings.items():
        assert payload.get("error") is None, (
            f"{scenario} was recorded from a failed run; re-record it"
        )


def _js_function_body(source: str, name: str) -> str:
    """Return the balanced body of ``function NAME(...) { ... }``.

    Brace-matched, so a nested function or object literal does not end the
    block early. It is what lets the assertions below be about ONE FUNCTION
    rather than about the file: "``showRecorded`` contains no fetch" is a
    property of the recorded path, while "the file contains a fetch" is a
    property of nothing at all.

    Parameters
    ----------
    source : str
    name : str

    Returns
    -------
    str

    Examples
    --------
    >>> _js_function_body('function f(a) { if (a) { return 1; } }', 'f')
    ' if (a) { return 1; } '
    """
    opening = source.index(f"function {name}(")
    start = source.index("{", opening)
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index]
    raise AssertionError(f"function {name} is not closed in the source")


def _flatten(source: str) -> str:
    """Return JavaScript source with adjacent string concatenations joined.

    ``"a " +\\n  "b"`` is one sentence to a reader and two literals to a
    scanner. Joining them lets a test assert on the sentence.

    Parameters
    ----------
    source : str

    Returns
    -------
    str

    Both quoting styles, because the frontend uses template literals wherever a
    value is interpolated and plain strings everywhere else, and a sentence can
    be built from a run of either.

    Examples
    --------
    >>> _flatten('x = "one " +\\n      "two";')
    'x = "one two";'
    >>> _flatten('x = `one ` +\\n      `two`;')
    'x = `one two`;'
    """
    joined = re.sub(r'"\s*\+\s*"', "", source)
    return re.sub(r"`\s*\+\s*`", "", joined)


def test_a_refused_request_clears_the_previous_run_from_the_screen() -> None:
    """A refusal must not leave another run's verdict standing.

    There are two ways a run fails and they arrive by different doors. A run
    that STARTS and does not finish is answered ``200`` with null bodies and
    reaches ``failurePanel``. A request refused by a cap or by the schema never
    gets that far: it is an HTTP ``400``/``422``, ``fetch`` rejects, and the
    only handler is the ``catch``.

    That catch used to write the status line and nothing else, so the result
    area kept rendering the PREVIOUS run: ``key_length = 5000`` was refused with
    the right sentence and the screen went on showing ``NOTHING FIRED``,
    ``|M| = 265 / 768``, over a control panel reading 5000.
    """
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")

    assert "function refusalPanel(" in render
    assert "refused: refused," in render, "Render.refused is not exported"

    block = _js_function_body(render, "refused")
    assert 'target.textContent = "";' in block, (
        "Render.refused does not clear the stage, so the previous run's "
        "panels stay on screen underneath the refusal"
    )

    body = _flatten(_js_function_body(render, "refusalPanel"))
    assert "STATE.withheld.glyph" in body, (
        "the refusal no longer uses the fourth state's glyph, so it is not "
        "visually distinct from a verdict"
    )
    assert '"NO RUN"' in body
    for phrase in (
        "NOT a clean run",
        "NOT a detection",
        "belongs in no rate",
        "has been cleared",
    ):
        assert phrase in body, f"the refusal panel lost the phrase {phrase!r}"

    # Every path that renders into the stage and can fail must clear it. There
    # is now exactly one function that does that, and it is called by all of
    # them: the live run's catch, the live run's not-reachable guard, and the
    # recorded loader.
    handler = _js_function_body(app, "noteTransportFailure")
    assert "Render.refused(" in handler
    assert app.count("noteTransportFailure(") >= 4, (
        "a failure path stopped routing through the shared handler; a fix "
        "that lives in one branch of one function is a fix for one branch of "
        "one function"
    )


def test_a_dead_service_is_never_reported_as_a_refusal_by_that_service() -> None:
    """`Failed to fetch` is not a cap refusal, and must not be dressed as one.

    The NO RUN panel said "The service refused this request, so no session was
    generated and nothing was scored", followed by the ``key_length`` cap's
    rationale -- for a fetch against a process that was not running and had
    refused nothing. The same copy appeared for a failed recorded-run load,
    which is a static JSON file no cap has an opinion about. The state was
    right (fourth state, stage cleared, raw reason shown); the attribution was
    invented.
    """
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    body = _flatten(_js_function_body(render, "refusalPanel"))

    assert 'kind === "unreachable"' in body, (
        "refusalPanel no longer distinguishes a service that refused from a "
        "service that never answered"
    )
    assert "The request never reached a service" in body
    assert "Nothing refused it and nothing scored it" in body
    # The cap rationale belongs to the refusal branch only. Both sentences must
    # exist, and they must be on opposite sides of the same conditional.
    assert "The service refused this request" in body
    assert "refused rather than quietly run at the nearest" in body
    assert "No cap was hit and no parameter was rejected" in body

    # And the transport path really passes that kind.
    handler = _js_function_body(app, "noteTransportFailure")
    assert '"unreachable"' in handler


def test_the_masthead_never_claims_more_than_it_can_deliver() -> None:
    """Three states, and the chip is CHECKED rather than inferred from a failure.

    Two defects met here. The mode repaint lived only in ``startLiveRun``'s
    catch, so clicking three recorded runs against a dead process gave three
    ``Failed to fetch`` panels under a masthead still reading ``LIVE API`` --
    and the recorded path is the one a presenter falls back to. And
    ``RECORDED ONLY`` is itself a promise: on a cold load against a dead
    service the page rendered from cache with that chip above a rail holding
    ZERO recorded runs.

    So: one shared handler for every discovered failure, a periodic health
    check so the chip is not waiting to be surprised, and a third state for
    "nothing is live and there is nothing recorded either".
    """
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    paint = _js_function_body(app, "paintMode")
    assert '"LIVE API"' in paint
    assert "RECORDED ONLY" in paint
    assert "state.recordedHeld > 0" in paint, (
        "the chip promises a recorded fallback without checking that there is "
        "one; on a cold load against a dead service there is not"
    )
    assert "NOTHING LIVE" in paint, "the third state is gone"

    # The chip is verified, not merely revised on failure. Recorded runs no
    # longer touch the network, so nothing on that path can fail and tell it.
    watch = _js_function_body(app, "watchService")
    assert '"/api/health"' in watch
    assert 'state.mode = "recorded"' in watch
    assert 'state.mode = "live"' in watch, (
        "the health check cannot recover the chip, so restarting the server "
        "leaves the masthead claiming the API is gone"
    )
    assert "watchService();" in app, "the health check is never started"

    # A cap refusal is the service WORKING and must not announce a dead API.
    live = _js_function_body(app, "startLiveRun")
    assert 'error.message.indexOf("HTTP ") === 0' in live, (
        "the failure path no longer distinguishes a server that answered from "
        "a server that is not there, so either a cap refusal claims the API "
        "is dead or a dead API keeps claiming to be live"
    )


def test_a_recorded_run_never_needs_the_service_it_falls_back_from() -> None:
    """The fallback is held in memory, not left to the browser's cache.

    ``showRecorded`` re-fetched ``data/recorded/<file>.json`` on every click
    with no in-memory copy, and the server sent no ``Cache-Control``, so
    survival came down to Chrome's heuristic freshness -- about a tenth of the
    file's age, which on a freshly cloned tree is minutes. Measured on a fresh
    clone: page loaded, process killed, three recorded runs clicked, three
    ``Failed to fetch`` and three ``NO RUN`` panels. The documentation said all
    thirteen keep working.

    A fallback that fetches from the thing it is falling back from is not a
    fallback, so the whole set is loaded once at boot and every click reads
    memory.
    """
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")

    show = _js_function_body(app, "showRecorded")
    assert "getJson(" not in show and "fetch(" not in show, (
        "showRecorded reaches the network; with the service dead that is the "
        "click that fails, in front of the room"
    )
    assert "state.recordedPayloads[entry.file]" in show

    preload = _js_function_body(app, "preloadRecorded")
    assert "state.recordedPayloads[entry.file] = payload" in preload
    assert "state.recordedHeld" in preload
    assert "preloadRecorded" in _js_function_body(app, "boot"), (
        "the preload is never run at boot, so nothing is ever held"
    )

    # How many are held is SHOWN, so a partial preload is visible before the
    # click that needs it rather than after.
    listing = _flatten(_js_function_body(app, "recordedList"))
    assert "held in this page's memory" in listing
    assert "state.recordedHeld" in listing


def test_the_null_banner_has_three_states_and_the_middle_one_warns() -> None:
    """Setting one of two nulls is its own state, and it is not reassuring.

    ``detect()`` takes TWO nulls. ``Detection.null_is_noiseless`` is defined
    over ``channel_error_rate`` alone, so keying the banner off it gave two
    states where there are three -- and the state the screen's own instruction
    led an operator into, one null stated, landed in the calm blue INFO branch
    headed "THE NULL CARRIES THE LINK'S ERROR RATE" while the run read
    DETECTED with ``honest`` RULED OUT and ``channel-manipulation`` NAMED.
    """
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    body = _flatten(_js_function_body(render, "nullBanners"))

    # The three states come off a flag Python computed, not off a comparison
    # made here: `run.nulls` is `sih141.web.payload.nulls_stated`.
    assert "payload.run && payload.run.nulls" in body
    assert "nulls.both_are_default" in body
    assert "nulls.both_are_stated" in body
    assert "const onlyOneStated" in body

    # And the middle state is a WARNING, never the info tone.
    middle = body[
        body.index("if (onlyOneStated)") : body.index("} else if (bothDefault)")
    ]
    assert '"alarm" : "caution"' in middle, (
        "the one-null-stated state is not rendered as a warning; it is the "
        "state in which an honest run is reported as an attack"
    )
    assert "ONE OF THE TWO NULLS IS STILL THE DEFAULT" in middle
    assert "tolerated_depolarising" in body or "field.channel" in body

    # The info banner is reachable only when BOTH are stated, and its heading
    # says only that -- not that the two nulls are the RIGHT ones. An operator
    # can state two nulls that describe a link nobody has, so a heading reading
    # "both nulls carry the link" would assert, on a run with an adversary on
    # the resource seam, that the adversary is not there. Whether they match is
    # the harness's sentence, and only the harness knows it.
    assert "Both nulls were stated by the operator" in body
    assert "Both nulls carry the link" not in body
    assert "Both nulls are noiseless" in body
    assert "whether they are the laws the wire obeyed is a separate" in body

    # And where the response supplies no `run.nulls` at all, the heading claims
    # only the half the rate-family flag actually knows. A heading is read on
    # its own.
    assert "The rate family's null is noiseless" in body


def test_the_screen_tells_an_operator_to_set_both_nulls() -> None:
    """The instruction has to be one that actually clears the run.

    "Set the link's true rate in the controls", singular, is an instruction
    whose result is an honest run reported as detected with an adversary named.
    Measured: 12/12 detected over twelve seeds at L = 192 with only
    ``channel_error_rate`` corrected, 0/12 with both.
    """
    app = _flatten((STATIC / "js" / "app.js").read_text(encoding="utf-8"))
    render = _flatten((STATIC / "js" / "render.js").read_text(encoding="utf-8"))

    assert "TWO NULLS, AND BOTH DEFAULT TO A PERFECT LINK" in app
    assert "NULL 1 of 2" in app and "NULL 2 of 2" in app
    assert '"tolerated_depolarising"' in app, (
        "the channel family's null is not a control, so an operator cannot "
        "carry out the instruction they are given"
    )
    # No surviving sentence tells an operator to set one thing.
    assert "Set the link's true rate in the controls" not in render
    assert "Set BOTH" in render


def test_the_calibration_panel_renders_the_sentence_that_corrects_it() -> None:
    """A sentence the API ships and the screen drops reads as an answer.

    ``noise_null_calibration.second_null_note`` says there are two nulls and
    what happens when only one is stated. ``noiseCalibration`` rendered only
    ``with_true_rate_passed`` and dropped it, so the screen carried "0/30 at
    every level when the link's true rate is passed to detect()" as the whole
    story.
    """
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    body = _js_function_body(render, "noiseCalibration")
    assert "calibration.second_null_note" in body, (
        "the correcting sentence is still dropped"
    )
    assert "with_true_rate_passed" in body
    # It is not rendered in the same grey as the line it corrects.
    assert "warn-note" in body
    css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    assert ".warn-note" in css


def test_no_chip_is_pinned_to_a_single_line() -> None:
    """A chip that cannot wrap pushes the page off a projector.

    At 1024x768 -- the classic projector resolution -- with projector mode on,
    ``white-space: nowrap`` on ``.num`` and ``.state`` put 307 px of the page
    off-screen with no scrolling ancestor: 28 elements past the viewport,
    including the PROVEN and MEASURED chips that carry constraint 2. Measured
    after: ``scrollWidth == clientWidth`` on all thirteen recorded runs, with
    projector mode on and off.
    """
    css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")

    def rule(selector: str) -> str:
        start = css.index(selector + " {")
        return css[start : css.index("}", start)]

    for selector in (".num", ".state"):
        block = rule(selector)
        assert "white-space: nowrap" not in block, (
            f"{selector} cannot wrap, so a long chip leaves the viewport"
        )
        assert "flex-wrap: wrap" in block
        assert "max-width: 100%" in block

    # A NUMBER still never breaks; only the prose around it does.
    value = rule(".num .value")
    assert "overflow-wrap: normal" in value

    # And the two definition-list grids cannot let one long term set a width
    # the viewport does not have.
    for selector in (".kv", ".truth dl"):
        assert "fit-content(" in rule(selector), selector


def test_a_long_unavailable_reason_is_not_drawn_inside_a_chart() -> None:
    """SVG text is not clipped by the panel it sits in.

    The API's reason for an unevaluable CHSH statistic is a whole sentence, and
    ``Charts.bars`` centres ``row.unavailable`` inside the hatched cell: at
    1024x768 in projector mode it ran 66 px past the right edge of the window.
    The chart carries a short marker; the sentence is rendered under it as text
    that wraps.
    """
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    body = _flatten(_js_function_body(render, "channelPanel"))
    assert "chshReasons" in body
    assert 'unavailable: "NOT EVALUATED' in body
    assert "link.chsh_unavailable" in body
    # The reason still reaches the screen -- it is moved, not dropped.
    assert "chshReasons.push(" in body
    assert "chshReasons.length === 0" in body


def test_a_detected_run_can_also_carry_a_no_verdict(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """The two questions are separate, and one run answers both differently.

    Recipient forgery is detected AND denies Bob a verdict. A single three-way
    headline would have to throw one of those away, which is why the screen
    carries the detector and the verifiers side by side.
    """
    both = [
        scenario
        for scenario, payload in recordings.items()
        if payload["detection"]["detected"]
        and payload["detection"]["not_scored"]
    ]
    assert both, (
        "no recorded run is both detected and denied, so the case that "
        "forces the two-panel headline is unexercised."
    )


def test_the_worst_failure_mode_is_in_the_set(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Constraint 3: an honest run that fires against the noiseless null.

    This is the dashboard's worst failure mode -- the baseline lighting up red
    in public -- so it is a recorded run rather than something discovered live.
    """
    offenders = [
        scenario
        for scenario, payload in recordings.items()
        if payload["detection"]["detected"]
        and payload["detection"]["null_is_noiseless"]
        and not payload["ground_truth"]["adversary_present"]
    ]
    assert offenders, (
        "no recorded run is an honest run that fires against the default "
        "noiseless null. That run is the one the null banner exists for."
    )


def test_the_same_run_scored_against_its_true_rate_is_recorded(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """And the conditional-bound banner has something to fire on."""
    conditional = [
        scenario
        for scenario, payload in recordings.items()
        if payload["detection"]["bound_is_unconditional"] is False
    ]
    assert conditional, (
        "no recorded run has a conditional bound, so the banner that says "
        "'the published bound is conditional' is never seen."
    )
    for scenario in conditional:
        assert recordings[scenario]["detection"]["null_is_noiseless"] is False


def test_an_unmonitored_run_is_in_the_set(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Constraint 5: a run whose channel family is unevaluable."""
    unmonitored = [
        scenario
        for scenario, payload in recordings.items()
        if payload["run"]["channel_evaluable"] is False
    ]
    assert unmonitored, "no recorded run has check_fraction = 0"
    for scenario in unmonitored:
        payload = recordings[scenario]
        assert payload["run"]["links"] == [], (
            "an unmonitored run must publish NO links, not four zeroed ones. "
            "Zeros would draw as a flat healthy line."
        )
        assert any(
            str(item).startswith("channel")
            for item in payload["detection"]["withheld"]
        ), "the channel family is unevaluable and nothing says so"


def test_an_unavailable_bell_test_is_never_a_zero(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """"No Bell test here" and "a Bell test that came out at zero" differ.

    A CHSH cell with no rounds behind it has an undefined correlator, and
    treating it as zero would report a two-setting experiment as a Bell test.
    The API sends ``chsh: null`` with ``chsh_unavailable`` saying why, and the
    chart draws a hatched cell carrying that sentence instead of a bar. That
    branch is only tested if a recorded run actually reaches it.
    """
    unavailable = [
        (scenario, link)
        for scenario, payload in recordings.items()
        for link in payload["run"]["links"]
        if link["chsh"] is None
    ]
    assert unavailable, (
        "no recorded run has a link whose CHSH is unavailable, so the branch "
        "that distinguishes an absent Bell test from a failed one is never "
        "exercised."
    )
    for scenario, link in unavailable:
        assert link["chsh_unavailable"], (
            f"{scenario}: a link has no CHSH and no reason given, so the "
            f"screen would have nothing to print but a blank."
        )
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    assert "link.chsh_unavailable" in render, (
        "render.js no longer reads the reason, so an absent Bell test would "
        "render as an unexplained gap."
    )


def test_a_degenerate_run_is_in_the_set(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Constraint 7: a run carrying no security claim, and saying so.

    The trap is that such a run reports ``transferable`` cheerfully. The panel
    has to be shown the case where both are true at once.
    """
    degenerate = [
        scenario
        for scenario, payload in recordings.items()
        if payload["run"]["security_claim"] is False
    ]
    assert degenerate, "no recorded run has degenerate floors"
    trap = [
        scenario
        for scenario in degenerate
        if recordings[scenario]["run"]["transferable"] is True
    ]
    assert trap, (
        "no recorded run is simultaneously transferable and claimless, which "
        "is precisely the run a happy green tick would lie about."
    )
    for scenario in degenerate:
        assert recordings[scenario]["run"]["floors"]["degenerate"] is True


def test_the_enforced_bound_at_demo_scale_is_useless_and_shown(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """The number the transferability panel puts beside the headline one.

    The panel's argument is a comparison the reader makes by eye between two
    figures the API supplies: this run's enforced repudiation bound, which is a
    number close to one, and the headline set's, which is 1.4139e-09. Both have
    to actually be what the panel says they are.
    """
    defaults = json.loads((RECORDED / "defaults.json").read_text("utf-8"))
    headline = defaults["bounds"]["headline"]["enforced_repudiation_bound"]
    assert headline == pytest.approx(1.4139e-09, rel=1e-4, abs=0)
    for scenario, payload in recordings.items():
        enforced = payload["run"]["enforced_repudiation_bound"]
        if enforced is None:
            continue
        assert enforced > 0.9, (
            f"{scenario}: the enforced repudiation bound is {enforced}, which "
            f"is unexpectedly strong for a demo-scale run. The panel's whole "
            f"argument is that this number is close to one here and "
            f"{headline:.4e} at DEFAULT_PARAMS."
        )


def test_the_undetectable_case_is_recorded_and_is_not_a_miss(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Constraint 4: full impersonation, nothing fired, and a stated reason."""
    auth = [
        scenario
        for scenario, payload in recordings.items()
        if payload["ground_truth"]["detectable"]
        == "undetectable-by-construction"
    ]
    assert auth, "the (AUTH) case is not in the recorded set"
    for scenario in auth:
        payload = recordings[scenario]
        assert payload["detection"]["detected"] is False
        assert payload["ground_truth"]["assumption"], (
            "the run carries no assumption text, so the screen would have "
            "nothing but a blank where the proof belongs."
        )


def test_an_adversary_that_did_not_act_is_recorded(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """An untargeted run is byte-identical to an honest one, and is shown so."""
    quiet = [
        scenario
        for scenario, payload in recordings.items()
        if payload["ground_truth"]["adversary_present"]
        and payload["ground_truth"]["acted"] is False
    ]
    assert quiet, "no recorded run has an adversary that declined to act"
    for scenario in quiet:
        payload = recordings[scenario]
        assert payload["ground_truth"]["identical_to_honest"] is True
        assert payload["detection"]["detected"] is False, (
            "an adversary that did nothing left nothing to detect; a fired "
            "signal here would be a false positive, not a catch."
        )


def test_a_targeted_channel_attack_moves_one_link_only(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """The per-link chart has to have something to show, and it must be one-sided.

    Pooling the two links would report the average of two channels and detect
    neither -- which is the exact shape of this attack -- so the recorded set
    keeps a run where exactly one recipient's links moved.
    """
    payload = recordings["channel_manipulation"]
    fired = {
        signal["name"].split(":")[1]
        for signal in payload["detection"]["signals"]
        if signal["family"] == "channel"
    }
    assert fired, "the channel manipulation run fired no channel signal"
    parties = {key.split("/")[0] for key in fired}
    assert parties == {"Bob"}, (
        f"the targeted attack fired on {sorted(parties)}; the recorded run is "
        f"supposed to be one-sided so the per-link panel shows the contrast."
    )
    assert payload["ground_truth"]["targeted_links"], (
        "the harness knows which link it touched and must carry it in "
        "ground_truth, where the detector cannot reach it."
    )


def test_ground_truth_never_leaks_into_the_detection(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """The two objects stay two objects.

    The detector reads a JSON transcript and nothing else. If a ground-truth
    key ever appeared inside ``detection``, the screen would be showing the
    harness's own knowledge as though the detector had worked it out.
    """
    forbidden = {"acted", "seams_held", "targeted_links", "identical_to_honest"}
    for scenario, payload in recordings.items():
        leaked = forbidden & set(payload["detection"])
        assert leaked == set(), f"{scenario}: {leaked} leaked into detection"
        assert "detectable" not in payload["detection"]


def test_every_hypothesis_appears_on_every_run(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """A hypothesis missing from a table reads as one that was ruled out."""
    expected = [str(item) for item in HYPOTHESES]
    for scenario, payload in recordings.items():
        shown = [row["hypothesis"] for row in payload["detection"]["attributions"]]
        assert shown == expected, f"{scenario}: {shown}"


def test_full_impersonation_is_undetectable_on_every_run(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """It is never supported and never excluded, on any run at all."""
    for scenario, payload in recordings.items():
        row = next(
            item
            for item in payload["detection"]["attributions"]
            if item["hypothesis"] == Hypothesis.IMPERSONATION_FULL.value
        )
        assert row["status"] == Support.UNDETECTABLE.value, scenario


def test_outcomes_are_always_one_of_the_four(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Never a boolean, never a fifth value the screen would not know."""
    allowed = {member.value for member in RunOutcome}
    for scenario, payload in recordings.items():
        for party, outcome in payload["detection"]["outcomes"].items():
            assert outcome in allowed, f"{scenario}/{party}: {outcome}"


def test_the_published_bound_is_never_the_budget(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Constraint 8, as a property of the data the screen is fed.

    ``eps`` is asked for; ``false_positive_bound`` is proven. Quoting the first
    in place of the second overstates the detector's own error rate by the
    slack factor, which on these runs is between two and four.
    """
    for scenario, payload in recordings.items():
        detection = payload["detection"]
        assert detection["false_positive_bound"] < detection["eps"], scenario
        assert detection["slack_factor"] > 1.0, scenario
        if detection["evidence_bound"] is not None:
            assert detection["detected"] is True, (
                f"{scenario}: an evidence bound with nothing fired is a "
                f"post-hoc statement about an empty set."
            )


def test_the_recorded_timings_show_detection_is_the_cheap_half(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """The measured fact the two-mode design rests on."""
    for scenario, payload in recordings.items():
        timings = payload["timings"]
        assert timings["detect_ms"] < timings["session_ms"], (
            f"{scenario}: detection cost more than the session, which "
            f"contradicts the reason live runs are capped on key length "
            f"rather than on anything the detector does."
        )


# --------------------------------------------------------------------------- #
# The reference producer and the manifest do not drift
# --------------------------------------------------------------------------- #


def test_every_recording_carries_the_run_shape_the_panels_read(
    contract: dict[str, Any], recordings: dict[str, dict[str, Any]]
) -> None:
    """The seam the two halves of Phase 6 were built across.

    ``Detection.to_dict()`` carries the verdict and the bound and nothing about
    the run that produced it -- no per-link QBER, no matched count, no floor, no
    repudiation guarantee. Those live on ``TranscriptStatistics``, which is why
    the contract has a separate ``run`` key and why its contents had to be
    enumerated rather than left to taste. This holds the API to that
    enumeration, field by field, on every recorded run.
    """
    spec = contract["run_facts"]
    for scenario, payload in recordings.items():
        facts = payload["run"]
        for name in spec["required"] + spec["expected"]:
            assert name in facts, f"{scenario}: run has no {name!r}"
        for name in spec["floors_expected"]:
            assert name in facts["floors"], f"{scenario}: floors {name!r}"
        for name in spec["pooled_expected"]:
            assert name in facts["pooled"], f"{scenario}: pooled {name!r}"
        for row in facts["verifiers"]:
            for name in spec["verifier_expected"]:
                assert name in row, f"{scenario}: verifier {name!r}"
        for row in facts["links"]:
            for name in spec["link_expected"]:
                assert name in row, f"{scenario}: link {name!r}"


def test_ground_truth_carries_the_link_the_detector_cannot_see(
    contract: dict[str, Any], recordings: dict[str, dict[str, Any]]
) -> None:
    """Whether the nulls matched the link is the harness's knowledge.

    It is the single fact that turns "the honest baseline lit up red" from a
    contradiction into an explanation, and it is not derivable from the
    transcript -- at ``check_fraction = 0`` the transcript does not carry the
    link's rate at all. So it lives in ``ground_truth``, beside the detection
    rather than inside it.
    """
    spec = contract["ground_truth"]
    for scenario, payload in recordings.items():
        truth = payload["ground_truth"]
        for name in spec["required"] + spec["expected"]:
            assert name in truth, f"{scenario}: ground_truth has no {name!r}"
        for name in spec["link_expected"]:
            assert name in truth["link"], f"{scenario}: link {name!r}"
    mismatched = [
        scenario
        for scenario, payload in recordings.items()
        if payload["ground_truth"]["link"]["nulls_match_link"] is False
    ]
    assert mismatched, (
        "no recorded run has a null that disagrees with its link, so the "
        "explanation panel for the worst failure mode is never exercised."
    )


def test_run_facts_reports_degeneracy_from_the_package_not_a_local_rule(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """``floors.degenerate`` is exactly ``not security_claim``.

    Not a comparison invented on the way to the wire. A second rule for "is
    this run degenerate", derived somewhere in the serialiser, would be a
    threshold nobody wrote down -- which is the thing D7 forbids, one layer out.
    """
    for scenario, payload in recordings.items():
        assert (
            payload["run"]["floors"]["degenerate"]
            is not payload["run"]["security_claim"]
        ), scenario


# --------------------------------------------------------------------------- #
# The constants the screen ships, pinned to their sources
# --------------------------------------------------------------------------- #


def test_the_shipped_constants_have_the_shape_the_panels_read(
    contract: dict[str, Any], constants: dict[str, Any]
) -> None:
    """`data/constants.json` is data the page reads, not a number it derives."""
    spec = contract["constants"]
    for name in spec["required"]:
        assert name in constants, f"constants has no {name!r}"
    for name in spec["chsh_expected"]:
        assert name in constants["chsh"]
    for name in spec["calibration_expected"]:
        assert name in constants["noise_null_calibration"]


def test_the_chsh_reference_lines_are_the_real_constants(
    constants: dict[str, Any]
) -> None:
    """The two lines on the CHSH chart, checked against arithmetic.

    They are definitions of the CHSH inequality, not thresholds this detector
    applies -- but they are still numbers on a screen, so they are pinned here
    rather than trusted to whoever typed them.
    """
    import math

    chsh = constants["chsh"]
    assert chsh["classical_bound"] == 2.0
    assert chsh["tsirelson_bound"] == pytest.approx(2.0 * math.sqrt(2.0))
    assert chsh["domain"]["minimum"] == -4.0
    assert chsh["domain"]["maximum"] == 4.0
    assert chsh["kind"] == "definition", (
        "the CHSH bounds must be labelled a definition, not a measurement and "
        "not a proven bound: they share no visual treatment with either."
    )


def test_the_noise_calibration_matches_the_docstring_it_cites(
    constants: dict[str, Any]
) -> None:
    """The measured table on screen is the one Phase 4 actually measured.

    The source is the docstring of ``Detection.channel_error_rate``, which the
    suite already runs. Reading the numbers back out of it means the screen and
    the docstring cannot drift: a re-measurement that updated one and not the
    other fails here.
    """
    from sih141.detect.detector import Detection

    # `channel_error_rate` is a dataclass field, so its prose lives in the
    # class's own Attributes section -- which is the docstring the suite
    # already runs as a doctest.
    text = " ".join(Detection.__doc__.split())
    calibration = constants["noise_null_calibration"]
    assert calibration["kind"] == "measured"
    assert f"{calibration['runs_per_level']} runs per level" in text
    saturated = f"``{calibration['runs_per_level']}/"
    saturated = f"{saturated}{calibration['runs_per_level']}``"
    for level in calibration["levels"]:
        fraction = f"{level['detected']}/{calibration['runs_per_level']}"
        stated = f"``{level['noise']}`` fires ``{fraction}``"
        if stated in text:
            continue
        # The docstring states the saturating levels as a range rather than
        # one row each: "from ``0.015`` up -- including the design noise level
        # ``2 s_a = 0.03125`` -- ``30/30``". Both endpoints of that range are
        # checked by name, so a re-measurement that moved either fails here.
        assert level["detected"] == calibration["runs_per_level"], (
            f"{level['noise']} is not stated in the docstring and is not one "
            f"of the saturating levels either"
        )
        assert saturated in text, "the docstring no longer says 30/30"
        if level["noise"] == calibration["design_noise_level"]:
            assert f"2 s_a = {level['noise']}" in text
        else:
            assert f"from ``{level['noise']}`` up" in text


def test_the_timing_is_a_label_and_never_a_thing_summed_over() -> None:
    """Constraint 6, pinned rather than merely implied.

    ``count_exchange_timing`` is a control the operator sets and a label on the
    result: the two orderings answer different questions -- one is a forgery,
    the other a denial of service -- so a mean taken across them is a mean over
    two different experiments and means nothing.

    Half of this was already enforced and the other half was not, which is why
    it is worth its own test. That the browser *cannot* pool is guaranteed by
    the D8 scanner above: no arithmetic operator and no ``Math.`` survives
    outside the chart geometry, and ``.reduce`` appears nowhere, so no total of
    any kind can exist here. What nothing asserted is that the screen SAYS so
    -- that the timing and the detector's own ``grouping_key`` are rendered on
    every run, beside the sentence that forbids averaging over them. A panel
    can be deleted without a scanner noticing.
    """
    code = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    block = re.search(
        r"function groupingPanel\(payload\) \{(.*?)\n  \}", code, re.S
    )
    assert block is not None, (
        "the Grouping key panel is gone. Constraint 6 asks the screen to say "
        "which experiment a run belongs to; nothing else on the page does."
    )
    body = block.group(1)
    assert "detection.grouping_key" in body, (
        "the panel no longer renders the detector's own grouping key"
    )
    assert "run.count_exchange_timing" in body, (
        "the panel no longer renders the ordering the run was taken under"
    )
    # Join adjacent string literals, so a phrase that happens to be wrapped
    # across a `"..." + "..."` is still one phrase to look for.
    joined = re.sub(r'"\s*\+\s*"', "", body)
    for phrase in (
        "never average over it",
        "answer different questions",
        "never a thing summed over, and no total on this page crosses it",
    ):
        assert phrase in joined, (
            f"the grouping panel lost the phrase {phrase!r}"
        )
    # And the panel is rendered on every run, not only on some of them.
    assert "target.appendChild(groupingPanel(payload));" in code


def test_the_two_orderings_are_two_experiments_and_the_recorded_set_says_so(
    recordings: dict[str, dict[str, Any]]
) -> None:
    """Why pooling would be wrong, from the recorded runs themselves.

    Every run carries the ordering it was taken under, inside
    ``detection.grouping_key`` as well as in ``run``. Pooling would require
    those keys to be interchangeable; they are not, and the key exists to say
    which group a run belongs to.
    """
    for name, payload in recordings.items():
        run = payload["run"]
        timing = run["count_exchange_timing"]
        assert timing in ("before-forwarding", "after-forwarding"), name
        key = payload["detection"]["grouping_key"]
        assert timing in [str(part) for part in key], (
            f"{name}: the ordering is not in grouping_key, so a reader "
            f"grouping on that key would pool two different experiments"
        )


def test_nothing_on_the_page_offers_a_false_negative_bound(
    constants: dict[str, Any]
) -> None:
    """There is none, and the screen has to be incapable of implying one."""
    assert constants["false_negative"]["exists"] is False
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "no false-negative bound" in html
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    assert "false-negative bound" in render


# --------------------------------------------------------------------------- #
# Room dynamics
# --------------------------------------------------------------------------- #


def test_the_page_declares_language_viewport_and_a_title() -> None:
    """The cheap accessibility floor, checked so it cannot be lost."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in html
    assert 'name="viewport"' in html
    assert "<title>" in html


def test_charts_are_labelled_for_a_reader_who_cannot_see_them() -> None:
    """Every figure carries a role and a name; SVG text stays real text."""
    code = (STATIC / "js" / GEOMETRY_SCRIPT).read_text(encoding="utf-8")
    assert 'role: "img"' in code
    assert '"aria-label"' in code
    assert 'el("title", {})' in code


def test_projector_mode_scales_type_and_nothing_else() -> None:
    """A demo control that changed a number would be the worst kind of bug."""
    css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    block = re.search(r":root\.projector \{(.*?)\}", css, re.S)
    assert block is not None, "projector mode is not defined"
    declarations = [
        line.strip()
        for line in block.group(1).splitlines()
        if line.strip()
    ]
    assert declarations == ["--scale: 1.28;"], (
        f"projector mode changes more than the type scale: {declarations}"
    )
    code = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    assert "classList.toggle(\"projector\")" in code


def test_projector_mode_sets_the_variable_where_it_is_actually_read() -> None:
    """The toggle must move the page, and the old test could not tell.

    This shipped inert. ``body.projector { --scale: 1.28 }`` set the variable
    on ``<body>``, while the rule that spends it is ``html { font-size:
    calc(16px * var(--scale)) }`` on the PARENT element. A custom property
    inherits downwards only, so ``html`` kept resolving ``--scale`` to the
    ``:root`` value of ``1``; every ``rem`` on the page is the root font-size,
    so nothing whatsoever changed. Measured in a browser before the fix: the
    document was 5563 px tall with projector mode on and 5563 px tall with it
    off.

    The previous test read the declaration and passed, because a rule's text
    says nothing about which element ends up reading it. So this asserts the
    join: the selector that SETS ``--scale`` and the selector that SPENDS it
    both have to match the root element.
    """
    css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    setters = re.findall(r"([^{}]+)\{[^{}]*--scale:\s*1\.28", css)
    assert setters, "nothing sets the projector type scale any more"
    for selector in setters:
        assert re.search(r"(^|\s):root\.projector\s*$", selector), (
            f"projector mode sets --scale on {selector.strip()!r}. It has to "
            f"be the root element: the rule that reads --scale matches "
            f"<html>, and a custom property never reaches a parent."
        )

    spenders = re.findall(r"([^{}]+)\{[^{}]*var\(--scale\)", css)
    assert spenders, "nothing reads --scale, so the toggle cannot do anything"
    for selector in spenders:
        assert re.search(r"(^|\s)(html|:root)\s*$", selector.strip()), (
            f"--scale is spent in a rule matching {selector.strip()!r}. Every "
            f"size on this page is a rem, so it has to be the root font-size "
            f"that moves, or the toggle only scales part of the screen."
        )

    code = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    assert 'document.documentElement.classList.toggle("projector")' in code, (
        "the toggle no longer puts the class on the root element, so the "
        "CSS above sets --scale where the html rule cannot read it"
    )


# --------------------------------------------------------------------------- #
# Executing the shipped JavaScript
# --------------------------------------------------------------------------- #
#
# Everything above this line reads the frontend as TEXT. That was the whole
# coverage this file had, and an audit showed what it buys: swap
# ``detection.false_positive_bound`` for ``detection.eps`` in ``boundsPanel``
# and the dashboard publishes the BUDGET (1e-09) under the label
# ``false_positive_bound`` and the caption "THE NUMBER TO QUOTE", where the
# proven bound (3.8649e-10) belongs -- and 3800 tests pass. Reverse ``scale()``
# in ``charts.js`` so every bar, marker and whisker mirrors about its axis, and
# 3800 tests pass. A scanner proving ``charts.js`` cannot format a number says
# nothing at all about whether its geometry is right.
#
# So the tests below RUN the shipped scripts. There is no bundler and no
# browser: ``node`` loads ``format.js``, ``charts.js``, ``contract.js`` and
# ``render.js`` into one ``vm`` context under a small DOM shim, feeds them a
# committed recording out of ``static/data/recorded/``, and hands back the tree
# they built. The assertions are then about VALUES on the screen rather than
# about substrings in a file.
#
# The shim models exactly the DOM surface those four files touch: building
# elements, ``setAttribute``/``setAttributeNS``, ``textContent``, and -- since
# the presentation views became interactive -- ``addEventListener`` (a no-op:
# no event is ever fired here), ``classList.contains``, a ``querySelector``
# that understands a bare tag name and REFUSES anything else, and a ``window``
# whose ``matchMedia`` and timers are inert. Anything outside that surface
# throws, so a script that starts depending on more of the DOM fails here
# loudly rather than rendering a quietly different tree.
#
# The harness is written to a temp directory rather than committed under
# ``static/``: nothing may live in the served tree that the page does not load.

NODE = shutil.which("node")

requires_node = pytest.mark.skipif(
    NODE is None,
    reason=(
        "node is not on PATH, so the shipped JavaScript goes unexecuted and "
        "only the text-level scanners above are covering it"
    ),
)

#: Loads the shipped scripts under a minimal DOM, runs one job read as JSON on
#: stdin, and writes the resulting element tree to stdout as JSON.
HARNESS_JS = """
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

function El(tag) {
  this.tag = tag;
  this.attrs = {};
  this.children = [];
  this.own = "";
  this.className = "";
}
El.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
El.prototype.setAttributeNS = function (ns, k, v) { this.setAttribute(k, v); };
El.prototype.appendChild = function (c) { this.children.push(c); return c; };
El.prototype.addEventListener = function () {};
Object.defineProperty(El.prototype, "classList", {
  get: function () {
    const names = this.className.split(" ").filter(Boolean);
    return { contains: function (c) { return names.indexOf(c) !== -1; } };
  },
});
El.prototype.querySelector = function (selector) {
  if (!/^[a-z][a-z0-9]*$/.test(selector)) {
    throw new Error("the shim's querySelector takes a bare tag: " + selector);
  }
  const stack = this.children.slice();
  while (stack.length) {
    const node = stack.shift();
    if (node.tag === selector) { return node; }
    Array.prototype.unshift.apply(stack, node.children);
  }
  return null;
};
Object.defineProperty(El.prototype, "textContent", {
  get: function () {
    return this.children.length
      ? this.children.map(function (c) { return c.textContent; }).join("")
      : this.own;
  },
  set: function (v) { this.own = String(v); this.children.length = 0; },
});

function tree(node) {
  return {
    tag: node.tag,
    cls: node.className,
    attrs: node.attrs,
    text: node.own,
    children: node.children.map(tree),
  };
}

const job = JSON.parse(fs.readFileSync(0, "utf-8"));
const dir = path.join(job.root, "sih141", "web", "static", "js");
const sandbox = {
  document: {
    createElement: function (t) { return new El(t); },
    createElementNS: function (ns, t) { return new El(t); },
  },
  window: {
    matchMedia: function () { return { matches: false }; },
    setInterval: function () { return 0; },
    clearInterval: function () {},
  },
};
vm.createContext(sandbox);
["format.js", "charts.js", "contract.js", "render.js"].forEach(function (f) {
  vm.runInContext(fs.readFileSync(path.join(dir, f), "utf-8"), sandbox,
                  { filename: f });
});

// `const Render = ...` at the top level of a vm script lands in that script's
// own lexical scope and not on the context object, so the modules are reached
// by evaluating their names.
const mod = vm.runInContext(
  "({Charts: Charts, Contract: Contract, Render: Render, Fmt: Fmt})", sandbox);

let root;
if (job.op === "run") {
  mod.Contract.install(job.contract);
  root = new El("div");
  mod.Render.run(root, job.payload, job.context);
} else if (job.op === "page") {
  mod.Contract.install(job.contract);
  root = new El("div");
  mod.Render.page(root, job.page, job.payload, job.context, {});
} else if (job.op === "bars") {
  root = mod.Charts.bars(job.options);
} else {
  throw new Error("unknown op: " + job.op);
}
process.stdout.write(JSON.stringify(tree(root)));
"""


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Write the Node harness out once per module."""
    path = tmp_path_factory.mktemp("js") / "harness.js"
    path.write_text(HARNESS_JS, encoding="utf-8")
    return path


def drive(harness: Path, job: dict[str, Any]) -> dict[str, Any]:
    """Run one harness job and return the element tree it produced."""
    job = dict(job, root=str(ROOT))
    done = subprocess.run(
        [str(NODE), str(harness)],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert done.returncode == 0, (
        f"the shipped frontend threw while rendering:\n{done.stderr}"
    )
    return json.loads(done.stdout)


def render_run(harness: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Render one ``POST /api/run`` response with every panel on it."""
    return render_page(harness, payload, None)


def render_page(
    harness: Path, payload: dict[str, Any], page: str | None
) -> dict[str, Any]:
    """Render one response as one of the page's views, or whole if ``None``.

    The views are ``session``, ``evidence`` and ``proof``, the three a room
    sees; ``None`` goes through ``Render.run``, which renders every panel.
    """
    job: dict[str, Any] = (
        {"op": "run"} if page is None else {"op": "page", "page": page}
    )
    return drive(
        harness,
        {
            **job,
            "payload": payload,
            "contract": json.loads(CONTRACT_PATH.read_text(encoding="utf-8")),
            "context": {
                "defaults": json.loads(
                    (RECORDED / "defaults.json").read_text(encoding="utf-8")
                ),
                "attacks": json.loads(
                    (RECORDED / "attacks.json").read_text(encoding="utf-8")
                ),
                "constants": json.loads(
                    CONSTANTS_PATH.read_text(encoding="utf-8")
                ),
            },
        },
    )


def walk(node: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield every element of a rendered tree, in document order."""
    yield node
    for child in node["children"]:
        yield from walk(child)


def text_of(node: dict[str, Any]) -> str:
    """The element's ``textContent``, exactly as the browser computes it."""
    if node["children"]:
        return "".join(text_of(child) for child in node["children"])
    return node["text"]


def rendered_rows(tree: dict[str, Any]) -> dict[str, str]:
    """Every ``<dt>``/``<dd>`` pair on the page, as term to rendered text."""
    rows: dict[str, str] = {}
    for node in walk(tree):
        if node["tag"] != "dl":
            continue
        children = node["children"]
        for term, value in zip(children[0::2], children[1::2]):
            rows[text_of(term)] = text_of(value)
    return rows


def exponential(value: float) -> str:
    """The string ``format.js`` renders for a float, computed independently.

    ``Fmt.exp`` pads the exponent to two digits precisely so that it agrees
    with Python's ``{:.4e}``, which is what makes this an independent check
    rather than the JavaScript grading its own homework.
    """
    return f"{value:.4e}"


def scientific(value: float) -> str:
    """What ``Fmt.sci`` renders for a float, computed independently.

    Three figures and a superscript power, the form the presentation views use
    so a figure reads from the back of a hall.

    >>> scientific(3.8649211592196904e-10)
    '3.86 \u00d7 10\u207b\u00b9\u2070'
    >>> scientific(0.0), scientific(2.5)
    ('0', '2.50')
    """
    if value == 0:
        return "0"
    mantissa, exponent = f"{value:.2e}".split("e")
    power = int(exponent)
    if power == 0:
        return mantissa
    superscript = str.maketrans(
        "0123456789-",
        "\u2070\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079\u207b",
    )
    return f"{mantissa} \u00d7 10{str(power).translate(superscript)}"


@requires_node
def test_the_bounds_panel_publishes_the_proven_bound_not_the_budget(
    harness: Path, recordings: dict[str, dict[str, Any]]
) -> None:
    """The headline number has to be the one that was proven.

    ``false_positive_bound`` is P(any signal | honest run), derived and covered
    in Python. ``eps`` is what the operator ASKED for. They sit within an order
    of magnitude of each other on every recorded run, both render as the same
    shape of string, and the panel captions one of them "THE NUMBER TO QUOTE".
    Reading the wrong field there publishes an input as a result, on the row a
    judge is told to quote, and no amount of reading this file as text can see
    it.
    """
    for name, payload in sorted(recordings.items()):
        detection = payload["detection"]
        if detection is None:
            continue
        rows = rendered_rows(render_run(harness, payload))
        published = rows["false_positive_bound"]
        assert exponential(detection["false_positive_bound"]) in published, (
            f"on {name} the bounds panel published {published!r} as "
            f"false_positive_bound, and the API's own value formats as "
            f"{exponential(detection['false_positive_bound'])!r}"
        )
        assert "THE NUMBER TO QUOTE" in published
        if detection["eps"] != detection["false_positive_bound"]:
            assert exponential(detection["eps"]) not in published, (
                f"on {name} the row captioned THE NUMBER TO QUOTE carries the "
                f"budget eps = {exponential(detection['eps'])}. eps is an "
                f"input; publishing it as the proven bound states a guarantee "
                f"this project never derived."
            )
        budget = rows["eps (the budget asked for)"]
        assert exponential(detection["eps"]) in budget, (
            f"on {name} the budget row reads {budget!r}"
        )


@requires_node
def test_the_verdict_strip_publishes_the_proven_bound_not_the_budget(
    harness: Path, recordings: dict[str, dict[str, Any]]
) -> None:
    """The same field is read a second time, at the top of the page.

    ``verdictStrip`` prints the bound under "P(any signal | honest run)" before
    a reader has scrolled as far as the bounds panel, so it is a second
    unchecked copy of the same expression and gets its own assertion rather
    than trusting the one above.
    """
    for name, payload in sorted(recordings.items()):
        detection = payload["detection"]
        if detection is None:
            continue
        strip = [
            text_of(node)
            for node in walk(render_run(harness, payload))
            if node["cls"] == "num num-proven"
            and "P(any signal | honest run)" in text_of(node)
        ]
        assert strip, f"the verdict strip on {name} publishes no bound at all"
        for shown in strip:
            assert exponential(detection["false_positive_bound"]) in shown, (
                f"on {name} the verdict strip reads {shown!r}, and "
                f"false_positive_bound formats as "
                f"{exponential(detection['false_positive_bound'])!r}"
            )


@requires_node
def test_bars_are_drawn_left_to_right_from_the_domain_minimum(
    harness: Path,
) -> None:
    """``scale()`` is the only arithmetic in the app and nothing ran it.

    Reversing it -- ``(domain.max - value)`` for ``(value - domain.min)`` --
    mirrors every bar, tick, marker and whisker about the middle of the plot
    and leaves the text-level scanners entirely happy, because the geometry
    reaches the screen as pixel coordinates rather than as characters. A QBER
    of 0.02 would draw as one of 0.98, past every threshold marker on the
    chart, and the markers would have moved too.
    """
    tree = drive(
        harness,
        {
            "op": "bars",
            "options": {
                "title": "geometry",
                "domain": {"min": 0.0, "max": 1.0},
                "ticks": [
                    {"value": 0.0, "label": "0"},
                    {"value": 1.0, "label": "1"},
                ],
                "markers": [
                    {"value": 0.5, "label": "half", "className": "marker"}
                ],
                "rows": [
                    {"label": "zero", "valueLabel": "0", "value": 0.0},
                    {"label": "quarter", "valueLabel": "0.25", "value": 0.25},
                    {"label": "full", "valueLabel": "1", "value": 1.0},
                ],
            },
        },
    )
    ticks = [
        float(node["attrs"]["x1"])
        for node in walk(tree)
        if node["attrs"].get("class") == "grid-line"
    ]
    assert len(ticks) == 2
    plot_left, plot_right = ticks
    assert plot_left < plot_right, (
        f"the tick at the domain minimum landed at x={plot_left} and the tick "
        f"at the maximum at x={plot_right}: the axis runs backwards"
    )

    widths = [
        float(node["attrs"]["width"])
        for node in walk(tree)
        if node["attrs"].get("class") == "bar"
    ]
    assert len(widths) == 3
    zero, quarter, full = widths
    assert zero == 0.0, f"a bar at the domain minimum is {zero} px wide"
    assert full == pytest.approx(plot_right - plot_left), (
        f"a bar at the domain maximum is {full} px wide and the plot is "
        f"{plot_right - plot_left} px across"
    )
    assert quarter == pytest.approx(full / 4.0), (
        f"a value one quarter of the way across the domain drew a bar "
        f"{quarter} px wide against a full-scale bar of {full} px"
    )

    marker = [
        float(node["attrs"]["x1"])
        for node in walk(tree)
        if node["attrs"].get("class") == "marker"
    ]
    assert marker == [pytest.approx((plot_left + plot_right) / 2.0)], (
        f"the marker at the middle of the domain landed at {marker}, and the "
        f"plot runs from {plot_left} to {plot_right}"
    )


@requires_node
def test_a_bar_below_the_baseline_is_drawn_below_the_baseline(
    harness: Path,
) -> None:
    """CHSH runs over [-4, 4] and its bars grow from zero, in both directions.

    An SVG ``rect`` is anchored at its LEFT edge. Anchoring every bar at the
    baseline drew a CHSH of -2 as a bar of the right LENGTH on the wrong SIDE
    of the zero line -- indistinguishable from +2, on the one chart whose whole
    job is which side of the classical bound a link sits.
    """
    tree = drive(
        harness,
        {
            "op": "bars",
            "options": {
                "title": "chsh",
                "domain": {"min": -4.0, "max": 4.0},
                "baseline": 0.0,
                "ticks": [{"value": 0.0, "label": "0"}],
                "rows": [
                    {"label": "below", "valueLabel": "-2", "value": -2.0},
                    {"label": "above", "valueLabel": "2", "value": 2.0},
                ],
            },
        },
    )
    zero = [
        float(node["attrs"]["x1"])
        for node in walk(tree)
        if node["attrs"].get("class") == "grid-line"
    ][0]
    bars = [
        (float(node["attrs"]["x"]), float(node["attrs"]["width"]))
        for node in walk(tree)
        if node["attrs"].get("class") == "bar"
    ]
    (below_x, below_width), (above_x, above_width) = bars
    assert below_x + below_width == pytest.approx(zero), (
        f"the bar for CHSH = -2 runs from x={below_x} to "
        f"x={below_x + below_width}, and the zero line is at x={zero}: a "
        f"negative value is drawn on the positive side of the axis"
    )
    assert above_x == pytest.approx(zero)
    assert below_width == pytest.approx(above_width)


@requires_node
def test_the_null_banner_never_speaks_for_a_null_the_response_omitted(
    harness: Path, recordings: dict[str, dict[str, Any]]
) -> None:
    """There are TWO nulls and a response may report neither, one or both.

    ``run.nulls`` carries both; ``detection.null_is_noiseless`` is the RATE
    family's flag and nothing more. With ``run.nulls`` absent the banner stands
    on that one flag, so it may not say what the CHANNEL family's null was --
    and printing ``tolerated_depolarising = n/a`` inside a sentence saying the
    operator supplied it does not withdraw the claim, it decorates it.
    """
    payload = json.loads(json.dumps(recordings["honest"]))
    del payload["run"]["nulls"]
    payload["detection"]["null_is_noiseless"] = False
    page = text_of(render_run(harness, payload))
    assert "Both nulls were stated by the operator" not in page, (
        "with no run.nulls on the response the page still announces that "
        "BOTH nulls were stated. It has been told about one."
    )
    assert "Both were supplied by the operator" not in page
    assert "The API did not supply run.nulls" in page, (
        "the page says nothing about the half of the state it never received"
    )

    # And with `run.nulls` present the sentence is still the full one, so the
    # guard above is a guard rather than a deletion.
    both = recordings["honest_noisy_right_null"]
    assert both["run"]["nulls"]["both_are_stated"] is True
    page = text_of(render_run(harness, both))
    assert "Both nulls were stated by the operator" in page
    assert (
        f"tolerated_depolarising = "
        f"{both['run']['nulls']['tolerated_depolarising']:.6f}"
    ) in page


@requires_node
def test_no_banner_explains_itself_with_a_check_fraction_it_did_not_run_at(
    harness: Path, recordings: dict[str, dict[str, Any]]
) -> None:
    """A true statement given a reason that is false on the run it prints on.

    The noiseless-null banner said the nulls are never inferred from the
    transcript "because at check_fraction = 0 the transcript carries no
    estimate of either". Every recorded run but the unmonitored one is at
    check_fraction = 0.25, where the transcript does carry an estimate. The
    rule holds on every run; the reason was local to one, and a false reason
    for a true rule is what a judge pulls on.
    """
    for name, payload in sorted(recordings.items()):
        fraction = payload["request"]["check_fraction"]
        if fraction == 0:
            continue
        page = text_of(render_run(harness, payload))
        assert "check_fraction = 0 " not in page, (
            f"{name} ran at check_fraction = {fraction} and the page argues "
            f"from what is true at check_fraction = 0"
        )


@requires_node
def test_the_presentation_views_publish_the_proven_bound_not_the_budget(
    harness: Path, recordings: dict[str, dict[str, Any]]
) -> None:
    """Two more copies of the one expression an audit caught being swapped.

    The session view's readout prints the chance of a false alarm beside the
    verdict, and the Proof view leads with the same figure at display size.
    Both read ``detection.false_positive_bound``, both would render ``eps`` in
    exactly the same shape if the field were swapped, and ``eps`` is what the
    operator asked for rather than anything this project proved. Each copy is
    checked on its own, as the verdict strip's is.

    Every recording is rendered through all three views as it goes, so a view
    that throws on one scenario fails here rather than in front of a room.
    """
    for name, payload in sorted(recordings.items()):
        detection = payload["detection"]
        evidence = render_page(harness, payload, "evidence")
        assert text_of(evidence), f"the evidence view rendered nothing on {name}"
        if detection is None:
            continue
        proven = scientific(detection["false_positive_bound"])
        budget = scientific(detection["eps"])
        swapped = detection["eps"] != detection["false_positive_bound"]

        readout = [
            text_of(node)
            for node in walk(render_page(harness, payload, "session"))
            if node["cls"] == "figure is-proven"
        ]
        assert len(readout) == 1, (
            f"the session readout on {name} shows {len(readout)} proven "
            f"figures; it should show exactly the false-alarm bound"
        )
        assert proven in readout[0], (
            f"on {name} the session readout reads {readout[0]!r}, and "
            f"false_positive_bound renders as {proven!r}"
        )
        if swapped:
            assert budget not in readout[0], (
                f"on {name} the session readout publishes the budget {budget}"
            )

        hero = [
            text_of(node)
            for node in walk(render_page(harness, payload, "proof"))
            if node["cls"] == "hero-figure"
        ]
        assert len(hero) == 1, f"the proof view on {name} has no headline"
        assert proven in hero[0], (
            f"on {name} the proof headline reads {hero[0]!r}, and "
            f"false_positive_bound renders as {proven!r}"
        )
        if swapped:
            assert budget not in hero[0], (
                f"on {name} the proof headline publishes the budget {budget}"
            )
