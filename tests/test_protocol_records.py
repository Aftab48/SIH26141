"""The (AUTH) figures in ``records.py`` are the measured ones, or nothing.

``sih141/protocol/records.py`` carries an impersonation table in its module
docstring, directly above a section that promises "the figures this docstring
leans on are tests". They were not: the four retired figures (``60/60``,
``0/60``, ``QBER = 0.4987`` and ``0.4806``) appeared in prose only, and
:mod:`sih141.protocol.analysis` section 0b says the last of them does not
reproduce and could not have. The doctest added beside them pins the table
:func:`sih141.attacks.impersonation.shipped_summary` prints; this module pins
the other half, that the *prose* quotes no count or rate the table does not.
"""

from __future__ import annotations

import re

from sih141.attacks.impersonation import shipped_summary
from sih141.protocol import records

# The retired figures, verbatim. Section 0b of ``analysis`` replaced rather
# than corrected them, because the defect was the missing conditions -- no
# ``L``, no ``n``, no statement of which estimator -- and not the digits.
RETIRED = ("60/60", "0/60", "0.4987", "0.4806")

# Counts written ``a/bb`` and rates written ``0.dddd``, inside double
# backticks. The two-digit denominator is what keeps ``1/2`` -- the null a
# partial impersonator is measured against, not a measurement -- out of the
# set; it is a bound, and it belongs to no row of the table.
FIGURE = re.compile(r"``(\d+/\d{2,}|0\.\d{4})``")


def _auth_section() -> str:
    """The two (AUTH) paragraphs, which are where the table is quoted."""
    text = records.__doc__ or ""
    start = text.index("**(AUTH)")
    end = text.index("The numbers above, as executable claims")
    assert start < end
    return text[start:end]


def test_the_retired_impersonation_figures_are_gone_from_this_module() -> None:
    """The Phase 3 fix corrected ``analysis`` and missed its sibling.

    A figure that survives in one module's prose is as quotable to a judge as
    one that survives in both, so the check is over the whole file and not
    only the docstring.
    """
    source = records.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    for figure in RETIRED:
        assert figure not in text, (
            f"{figure!r} is a retired impersonation figure; the reproducible "
            f"ones come from sih141.attacks.impersonation.shipped_summary()"
        )


def test_every_auth_figure_quoted_is_a_figure_the_attack_measured() -> None:
    """Prose numbers, checked against the seam that produced them."""
    measured = "\n".join(shipped_summary())
    quoted = set(FIGURE.findall(_auth_section()))
    assert quoted, "the (AUTH) section quotes no figures at all"
    unmeasured = sorted(figure for figure in quoted if figure not in measured)
    assert not unmeasured, (
        f"the (AUTH) prose quotes {unmeasured}, which appear in no row of "
        f"shipped_summary():\n{measured}"
    )


def test_the_docstring_quotes_the_figures_that_matter_not_merely_none() -> None:
    """Stops the previous test from being satisfied by deleting the prose.

    The acceptance under full impersonation is the one assumption the scheme
    cannot do without; the acceptance under a single seized seam is what makes
    the first number a statement about (AUTH) rather than about the code.
    """
    quoted = set(FIGURE.findall(_auth_section()))
    assert "200/200" in quoted  # full impersonation is accepted
    assert "0/200" in quoted  # partial impersonation is not
    assert {"0.4988", "0.5038", "0.5031", "0.4997"} <= quoted
