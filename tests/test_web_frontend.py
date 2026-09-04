"""The Phase 6 frontend, tested from Python -- including the rule it exists for.

WHY A PYTHON TEST FOR A JAVASCRIPT SCREEN
-----------------------------------------
Phase 6 ships with no Node, no bundler and no browser in CI, so the frontend
cannot be unit-tested the way a JavaScript project would test it. That is not a
reason to ship it untested, because the property that matters most about this
frontend is not behavioural at all -- it is **structural**, and structure is
exactly what a text-level test can pin:

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
"""

from __future__ import annotations

import json
import re
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

    This is what makes the arithmetic exemption safe. Every string that reaches
    the screen from the chart module arrived as a caller-supplied ``label``,
    formatted in ``format.js`` from a value the API sent.
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
    ) == pytest.approx(1.4139e-09, rel=1e-4)
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


def test_a_refused_request_clears_the_previous_run_from_the_screen() -> None:
    """A refusal must not leave another run's verdict standing.

    There are two ways a run fails and they arrive by different doors. A run
    that STARTS and does not finish is answered ``200`` with null bodies and
    reaches ``failurePanel`` above. A request refused by a cap or by the
    schema never gets that far: it is an HTTP ``400``/``422``, ``fetch``
    rejects, and the only handler is the ``catch``.

    That catch used to write the status line and nothing else, so the result
    area kept rendering the PREVIOUS run. Driving the live service:
    ``key_length = 5000`` was refused with the right sentence, and the screen
    went on showing ``NOTHING FIRED``, ``|M| = 265 / 768``, over a control
    panel reading 5000 -- a verdict from a run at 1024 displayed under the
    parameters of a run that never happened.

    That is precisely what the cap exists to prevent. ``limits.py`` refuses
    rather than clamping because "a screen reporting a clamped run under the
    label of the one that was asked for is the single easiest way for this
    dashboard to lie", and the screen was doing it anyway by another route.
    """
    render = (STATIC / "js" / "render.js").read_text(encoding="utf-8")
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")

    assert "function refusalPanel(" in render, (
        "the refusal panel is gone; a refused request would fall back to "
        "leaving the previous run on screen"
    )
    assert "refused: refused," in render, "Render.refused is not exported"

    block = re.search(r"function refused\(target, message, request\) \{(.*?)\n  \}",
                      render, re.S)
    assert block is not None, "Render.refused is not defined"
    assert 'target.textContent = "";' in block.group(1), (
        "Render.refused does not clear the stage, so the previous run's "
        "panels stay on screen underneath the refusal"
    )

    panel = re.search(r"function refusalPanel\(message, request\) \{(.*?)\n  \}",
                      render, re.S)
    assert panel is not None
    body = panel.group(1)
    assert "STATE.withheld.glyph" in body, (
        "the refusal no longer uses the fourth state's glyph, so it is not "
        "visually distinct from a verdict"
    )
    assert '"NO RUN"' in body
    joined = re.sub(r'"\s*\+\s*"', "", body)
    for phrase in (
        "NOT a clean run",
        "NOT a detection",
        "belongs in no rate",
        "has been cleared",
    ):
        assert phrase in joined, f"the refusal panel lost the phrase {phrase!r}"

    # And EVERY failure path actually calls it. Both of them render into the
    # same stage, so both can leave another run's numbers standing: the live
    # run, and the recorded loader -- which is the one that runs when the
    # service has died, i.e. exactly when nobody can check the screen against
    # anything else.
    catches = re.findall(r"\.catch\(function \(error\) \{(.*?)\n      \}\)",
                         app, re.S)
    assert len(catches) == 2, (
        f"expected the two stage-rendering failure paths, found "
        f"{len(catches)}. A new one that only writes the status line would "
        f"leave the previous run on screen."
    )
    for body_of_catch in catches:
        assert "Render.refused(" in body_of_catch, (
            "a failure path does not clear the stage; a refused request "
            "would leave the previous run's numbers under the new parameters"
        )


def test_the_masthead_stops_claiming_a_live_api_when_the_api_dies() -> None:
    """The mode chip is decided at start-up, and demos fail mid-flight.

    ``RECORDED ONLY — API NOT REACHABLE`` is painted once, when the page loads
    and ``/api/attacks`` cannot be reached. A service that dies DURING a
    demonstration therefore left the masthead reading ``LIVE API`` with the
    process gone -- verified by killing the server with the page open: the run
    failed with ``Failed to fetch``, the stage correctly showed ``NO RUN``, and
    the chip still said ``LIVE API``.

    The two failures have to stay distinguishable, which is the whole reason
    this is a condition and not an unconditional repaint. ``getJson`` raises
    ``HTTP <status> ...`` when the server ANSWERED -- a ``400`` from a cap or a
    ``503`` from the run gate is the service working exactly as designed -- and
    anything else means the fetch itself failed. Repainting on an HTTP error
    would tell the room the API is gone every time somebody typed a key_length
    over the ceiling.
    """
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    assert 'chip.textContent = "RECORDED ONLY' in app, (
        "the mode chip no longer has a not-reachable state"
    )
    assert 'error.message.indexOf("HTTP ") !== 0' in app, (
        "the failure path no longer distinguishes a server that answered "
        "from a server that is not there, so either a cap refusal claims the "
        "API is dead or a dead API keeps claiming to be live"
    )
    # The repaint has to be inside the guard, not beside it.
    guard = re.search(
        r'if \(error\.message\.indexOf\("HTTP "\) !== 0\) \{(.*?)\n        \}',
        app,
        re.S,
    )
    assert guard is not None, "the guard is gone"
    assert 'state.mode = "recorded";' in guard.group(1)
    assert "paintMode();" in guard.group(1)


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
    assert headline == pytest.approx(1.4139e-09, rel=1e-4)
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
