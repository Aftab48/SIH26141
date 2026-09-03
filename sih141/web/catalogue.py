"""The roster of arms the dashboard can run, and what each one may claim.

One entry per adversary plus the honest control. Each carries the seams it
stands on, the words the screen shows, and -- the field this module exists for
-- an explicit :attr:`AttackSpec.detectable` verdict.

.. _keys-are-hypotheses:

The keys are the detector's own hypothesis names
-------------------------------------------------
``outside-forgery``, ``recipient-forgery``, ``impersonation-full``, ``replay``,
``channel-manipulation``, ``count-starvation`` are exactly the names in
:data:`~sih141.detect.detector.HYPOTHESES`. That is not decoration: it means a
reader can put ``ground_truth["attack"]`` beside ``detection["named"]`` and
compare them without a translation table, and it means an arm whose key is not
in the detector's vocabulary is visibly a harness-side variant rather than a
position the detector reasons about.

The frontend's read-side contract
(``sih141/web/static/data/api-contract.json``) fixes these keys and the three
values of ``detectable``; the roster below is the service half of that
agreement. Three arms beyond it -- a distribution-seam impersonator and two
non-parametric channel attacks -- are appended as extra keys, which a menu built
from this endpoint picks up and a fixture-driven screen simply does not offer.

.. _auth-is-not-a-blank:

Why ``detectable`` is a string and never a boolean
--------------------------------------------------
An impersonator holding **both** of Alice's seams is Alice, as far as anything
the protocol can measure is concerned: she distributes with a key of her own and
declares that key, so the recipients' logs and her declaration agree exactly, as
they would on an honest run. Phase 3 measured it accepted ``200/200``. There is
no signal, there is no threshold, and there never can be one from a transcript.

A boolean field would render that as ``false``, and ``false`` on a dashboard
beside a column of ``true``\\ s reads as *we tried and failed*. What is true is
the opposite and stronger: **we proved you cannot, and here is the assumption
that carries the weight** -- (AUTH), that the classical channel is
authenticated. So the field is a string, ``undetectable-by-construction`` is one
of its values, and :attr:`AttackSpec.assumption` is required to be non-empty
exactly there.

The three values
----------------
``not-an-attack``
    The honest control. Not "undetected": there is nothing to detect.
``detectable``
    A derived threshold exists whose stated null this adversary departs from.
    A statement about the *derivation*, not a promise about any one run: there
    is no false-negative bound anywhere in this project and this field is not
    one. Whether a given run fires is on that run's
    :class:`~sih141.detect.detector.Detection`.
``undetectable-by-construction``
    No transcript statistic separates this adversary from an honest signer. The
    assumption that excludes him is named in :attr:`AttackSpec.assumption`.

Examples
--------
>>> from sih141.web.catalogue import ATTACKS, attack_spec, roster_payload
>>> [spec.key for spec in ATTACKS][:4]
['honest', 'outside-forgery', 'recipient-forgery', 'impersonation-partial']
>>> attack_spec("impersonation-full").detectable
'undetectable-by-construction'
>>> "(AUTH)" in attack_spec("impersonation-full").assumption
True
>>> attack_spec("honest").detectable
'not-an-attack'

Every key that names a detector hypothesis is one the detector actually knows:

>>> from sih141.detect.detector import HYPOTHESES
>>> known = {str(item) for item in HYPOTHESES}
>>> sorted(
...     spec.key for spec in ATTACKS
...     if spec.hypothesis is not None and spec.hypothesis not in known
... )
[]
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final


__all__ = [
    "ATTACKS",
    "ATTACK_KEYS",
    "DETECTABLE",
    "DETECTABLE_VALUES",
    "NOT_AN_ATTACK",
    "UNDETECTABLE_BY_CONSTRUCTION",
    "AttackSpec",
    "attack_spec",
    "roster_payload",
]


#: The honest control: there is nothing to detect, which is not the same as a
#: detector that missed something.
NOT_AN_ATTACK: Final[str] = "not-an-attack"

#: A derived threshold exists whose null this adversary departs from.
DETECTABLE: Final[str] = "detectable"

#: Assumption (AUTH) excludes it; no transcript statistic can.
UNDETECTABLE_BY_CONSTRUCTION: Final[str] = "undetectable-by-construction"

#: The whole vocabulary, as the frontend's contract file states it.
DETECTABLE_VALUES: Final[tuple[str, ...]] = (
    NOT_AN_ATTACK,
    DETECTABLE,
    UNDETECTABLE_BY_CONSTRUCTION,
)


@dataclass(frozen=True)
class AttackSpec:
    """One arm of the dashboard: what it mounts, and what it may claim.

    Parameters
    ----------
    key : str
        The wire name, sent as ``attack`` on ``POST /api/run``. Matches a
        :class:`~sih141.detect.detector.Hypothesis` name wherever one exists
        (:ref:`keys-are-hypotheses`).
    label : str
        Short human name for a menu.
    summary : str
        What the screen shows beside the arm. States what the adversary holds
        and what happens to it -- including the outcomes that are *denials*
        rather than detections, since a starved verdict and a refused forward
        are neither an acceptance nor a rejection.
    detectable : str
        One of :data:`DETECTABLE_VALUES`.
    assumption : str or None
        The assumption that excludes the adversary where detection cannot.
        ``None`` where the arm rests on nothing beyond the shipped threat
        model -- and **required** where ``detectable`` is
        ``undetectable-by-construction``, because that is the one case where
        the assumption is the whole claim.
    model_note : str
        The threat-model sentence for this arm: what the adversary holds and
        what he does not. Always present, so no arm is described only by what
        it is called.
    seams : tuple of str
        Which :class:`~sih141.protocol.session.QDSSession` seams the adversary
        occupies. ``()`` for the honest control.
    hypothesis : str or None
        The detector's own name for this position, where it has one.
    owns_resource_line : bool
        ``True`` when the adversary occupies ``resource_factory``, which is the
        same seam the ``noise`` parameter mounts the link on. Exactly one thing
        can stand there, which is why some arms refuse a positive ``noise``.
    noise_is_its_strength : bool
        ``True`` for the one arm whose attack *is* parameterised depolarising
        noise, where ``noise`` sets the attack's strength instead of the
        background link's.
    targets_one_link : bool
        ``True`` where the attack is restricted to Bob's link, which is what
        makes attribution a question at all.

    Raises
    ------
    ValueError
        If ``detectable`` is not one of the three values, or an
        ``undetectable-by-construction`` arm carries no assumption.

    Examples
    --------
    >>> from sih141.web.catalogue import attack_spec
    >>> spec = attack_spec("count-starvation")
    >>> spec.seams, spec.hypothesis
    (('count_exchange',), 'count-starvation')
    """

    key: str
    label: str
    summary: str
    detectable: str
    assumption: str | None
    model_note: str
    seams: tuple[str, ...] = ()
    hypothesis: str | None = None
    owns_resource_line: bool = False
    noise_is_its_strength: bool = False
    targets_one_link: bool = False

    def __post_init__(self) -> None:
        """Reject a spec that could render as an unknown or unexplained verdict.

        Raises
        ------
        ValueError
        """
        if self.detectable not in DETECTABLE_VALUES:
            raise ValueError(
                f"detectable must be one of {list(DETECTABLE_VALUES)}, got "
                f"{self.detectable!r}. It is a string rather than a boolean so "
                f"that the (AUTH) case is carried explicitly instead of by "
                f"omission."
            )
        if self.detectable == UNDETECTABLE_BY_CONSTRUCTION and not (
            self.assumption or ""
        ).strip():
            raise ValueError(
                f"arm {self.key!r} claims to be undetectable by construction "
                f"and names no assumption. That claim IS the assumption: "
                f"without one the field says only that nothing fired, which is "
                f"a missed detection and the opposite of what is meant."
            )
        if not self.model_note.strip():
            raise ValueError(f"arm {self.key!r} has no model note")

    @property
    def accepts_noise(self) -> bool:
        """bool: Whether a positive ``noise`` may be sent with this arm.

        ``False`` only for the two channel arms that occupy the resource line
        with a non-parametric attack. There is one resource line and one thing
        may stand on it; composing two channels would be inventing physics this
        project does not derive.
        """
        return (not self.owns_resource_line) or self.noise_is_its_strength

    def to_dict(self) -> dict[str, Any]:
        """Return the five contract fields, plus what the controls need.

        Returns
        -------
        dict
            ``key``, ``label``, ``summary``, ``detectable`` and ``assumption``
            are the contract. ``model_note``, ``seams``, ``hypothesis``,
            ``owns_resource_line`` and ``accepts_noise`` are additions, so the
            frontend can disable a control rather than discover a refusal.
        """
        return {
            "key": self.key,
            "label": self.label,
            "summary": self.summary,
            "detectable": self.detectable,
            "assumption": self.assumption,
            "model_note": self.model_note,
            "seams": list(self.seams),
            "hypothesis": self.hypothesis,
            "owns_resource_line": self.owns_resource_line,
            "accepts_noise": self.accepts_noise,
        }


_D6: Final[str] = (
    "The adversary owns its randomness and never reads the session's (D6), so "
    "its choices are reproducible from the request seed and independent of the "
    "run."
)

_SEAM: Final[str] = (
    "Mounted through a shipped seam: no protocol edit was needed, so an "
    "attacked run and a clean one are the same program. "
)


ATTACKS: Final[tuple[AttackSpec, ...]] = (
    AttackSpec(
        key="honest",
        label="Honest run",
        summary=(
            "No adversary. Every statistic is drawn from the law the nulls "
            "describe. This is the baseline the false-positive bound is a "
            "statement about -- and note what it is not: it is not a run the "
            "detector is guaranteed to pass. The default null is a NOISELESS "
            "link, so an honest run over a link with noise > 0 departs from it "
            "and fires, correctly, with both verifiers still accepting."
        ),
        detectable=NOT_AN_ATTACK,
        assumption=None,
        model_note=(
            "The honest run is the run every null in this package describes. "
            "Its false-positive bound is PROVEN under that null; it is not a "
            "measurement and not a promise that nothing will fire."
        ),
    ),
    AttackSpec(
        key="outside-forgery",
        label="Outside forgery",
        summary=(
            "Eve substitutes Alice's declaration outright, knowing nothing. "
            "Matched positions disagree with probability 1/2 each, so the "
            "mismatch count leaves the point mass at zero immediately. She "
            "cannot move the matched count -- that depends only on the "
            "declared bases and the recipients' own draws -- which is why the "
            "matched-count floors are an evidence-liveness control here and "
            "not a forgery detector."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            _SEAM + "Eve stands on the classical channel from Alice and holds "
            "no recipient's log and no symmetrisation coin. " + _D6
        ),
        seams=("signer",),
        hypothesis="outside-forgery",
    ),
    AttackSpec(
        key="recipient-forgery",
        label="Recipient forgery",
        summary=(
            "Bob verifies Alice's genuine declaration, accepts it, and forwards "
            "Charlie a declaration built from his own raw log. The 1/12 floor "
            "he runs into -- against the 1/3 he would face without "
            "symmetrisation -- is the clearest single demonstration of what "
            "Phase A' buys. WATCH THE ORDERING: under 'before-forwarding', the "
            "shipped one, Charlie counted against the declaration Alice signed "
            "and is holding another, so he refuses on provenance and reaches "
            "NO VERDICT -- a denial of transfer, not a detection and not a "
            "rejection. Under 'after-forwarding' he scores it, and that is the "
            "arm the closed form predicts. Two questions, never pooled."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            _SEAM + "He holds his own log, the declaration once it reaches "
            "him, and the single integer his counterpart announced -- never "
            "the other recipient's log and never the coins. " + _D6
        ),
        seams=("forwarder",),
        hypothesis="recipient-forgery",
    ),
    AttackSpec(
        key="impersonation-partial",
        label="Impersonation, one seam",
        summary=(
            "Mallory holds Alice's signing seam but not her distribution seam, "
            "so she declares a key the recipients never measured against. "
            "Accepted 0/200 in Phase 3, at a mismatch rate of 1/2. It is the "
            "contrast with the full seizure below that makes assumption (AUTH) "
            "load-bearing rather than decorative."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            "Seizing one of Alice's two seams is inside the threat model. The "
            "transcript cannot separate this from an outside forgery, and the "
            "detector says so rather than picking one. " + _D6
        ),
        seams=("signer",),
        hypothesis="impersonation-signing-seam",
    ),
    AttackSpec(
        key="impersonation-full",
        label="Impersonation, both seams",
        summary=(
            "Mallory holds both of Alice's seams and runs the protocol "
            "correctly with a key pair of her own. Every statistic on the "
            "transcript is drawn from the honest law, because she generated "
            "both halves of it. Phase 3 measured it accepted 200/200. This is "
            "not a gap in the detector and not a threshold anyone forgot to "
            "derive: no transcript statistic separates her from Alice, and "
            "there cannot be one. Expect this run to look exactly like an "
            "honest run, because at the level of the transcript it is one."
        ),
        detectable=UNDETECTABLE_BY_CONSTRUCTION,
        assumption=(
            "(AUTH) -- the classical channel Alice authenticates over is "
            "assumed authentic. Seizing both seams is out of model by "
            "assumption; no transcript statistic separates it from an honest "
            "run, and this project derives no bound that pretends otherwise."
        ),
        model_note=(
            "The assumption is where the weight sits, and it is stated rather "
            "than hidden. " + _D6
        ),
        seams=("distributor", "signer"),
        hypothesis="impersonation-full",
    ),
    AttackSpec(
        key="replay",
        label="Replay",
        summary=(
            "The forwarding hop re-presents a declaration captured from a round "
            "that is over, relabelled with an opening of its own invention. The "
            "capture is minted at THIS run's signing length: a capture of "
            "another shape is declined by the adversary, and the arm would then "
            "forward honestly while looking as though it ran -- a wrong number "
            "this project has already paid for once. The session rebinds "
            "whatever the hop returns to the live round, so Charlie sees two "
            "declarations behind one count and refuses: NO VERDICT again, not a "
            "rejection."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            _SEAM + "Everything replayed was public when it was captured: the "
            "declaration and its opening. " + _D6
        ),
        seams=("forwarder",),
        hypothesis="replay",
    ),
    AttackSpec(
        key="channel-manipulation",
        label="Channel manipulation",
        summary=(
            "Eve twirls the travelling half of each pair on one recipient's "
            "link, at strength `noise`. QBER rises and CHSH falls on that link "
            "only -- pooling the two links would report the average of two "
            "channels and detect neither. She owns the quantum channel and may "
            "degrade the delivery, but what she sees is a locally maximally "
            "mixed half and two uniform classical bits, so she cannot read the "
            "key off the wire. At noise = 0 she is mounted and passes every "
            "pair through untouched: the transcript is then an honest "
            "transcript and is reported as one."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            "The channel adversary owns the quantum links and holds no private "
            "log and no coin, so he degrades but does not learn. Check logs are "
            "built inside distribution and never reach the symmetriser, which "
            "is why this is the one attack a detector can attribute to a named "
            "link -- given enough check rounds. " + _D6
        ),
        seams=("resource_factory",),
        hypothesis="channel-manipulation",
        owns_resource_line=True,
        noise_is_its_strength=True,
        targets_one_link=True,
    ),
    AttackSpec(
        key="count-starvation",
        label="Count starvation",
        summary=(
            "A recipient understates the integer he puts on the wire in "
            "Phase C', denying the other party a verdict. A DENIAL IS NOT A "
            "REJECTION: the denied verifier learned nothing about the "
            "signature, and counting this as a catch would be the single most "
            "likely way for this screen to lie. It is free, deterministic and "
            "selective -- no key material, no quantum resource, no computation "
            "-- and it cannot be done quietly: the quietest denying "
            "declaration sits about -11.5 honest standard deviations below the "
            "mean at every key length."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            _SEAM + "Phase C' is the recipients' own step on their own "
            "authenticated channel, so this seam replaces what THEY do, never "
            "what Alice does. " + _D6
        ),
        seams=("count_exchange",),
        hypothesis="count-starvation",
    ),
    # -- beyond the frontend's fixture set, offered live ---------------------- #
    AttackSpec(
        key="impersonation-distribution",
        label="Impersonation, distribution seam only",
        summary=(
            "The mirror image of the partial seizure above: Mallory runs "
            "Alice's quantum phase with a key of her own while Alice's genuine "
            "declaration still reaches the verifiers. Accepted 0/200, again at "
            "a mismatch rate of 1/2."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            "Seizing one of Alice's two seams is inside the threat model. "
            + _D6
        ),
        seams=("distributor",),
        hypothesis="impersonation-distribution-seam",
    ),
    AttackSpec(
        key="channel-intercept-resend",
        label="Channel: intercept and resend",
        summary=(
            "The textbook attack, and the one that destroys the most "
            "entanglement per unit of effort: Eve measures the travelling half "
            "in an axis of her own and re-sends what she found, leaving Alice "
            "and the recipient sharing a product state. `noise` does not apply "
            "-- this attack occupies the resource line entirely and has no "
            "strength parameter."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            "The channel adversary owns the quantum links and holds no private "
            "log. " + _D6
        ),
        seams=("resource_factory",),
        hypothesis="channel-manipulation",
        owns_resource_line=True,
        targets_one_link=True,
    ),
    AttackSpec(
        key="channel-kept-share",
        label="Channel: Eve keeps a share",
        summary=(
            "Entanglement swapping in the form that matters: Eve copies the "
            "travelling qubit onto an ancilla and keeps it, joining the "
            "entanglement rather than relaying it. The CHSH statistic of what "
            "survives is sqrt(2) = 1.414, well under the classical bound of 2 "
            "-- so a detector thresholding on 'does this link still violate the "
            "classical bound' has 0.59 of margin here, not 0.00."
        ),
        detectable=DETECTABLE,
        assumption=None,
        model_note=(
            "The channel adversary owns the quantum links and holds no private "
            "log. " + _D6
        ),
        seams=("resource_factory",),
        hypothesis="channel-manipulation",
        owns_resource_line=True,
        targets_one_link=True,
    ),
)


#: Every valid ``attack`` value, in menu order.
ATTACK_KEYS: Final[tuple[str, ...]] = tuple(spec.key for spec in ATTACKS)

_BY_KEY: Final[dict[str, AttackSpec]] = {spec.key: spec for spec in ATTACKS}


def attack_spec(key: str) -> AttackSpec:
    """Return the arm named ``key``.

    Parameters
    ----------
    key : str

    Returns
    -------
    AttackSpec

    Raises
    ------
    KeyError
        If no arm has that key. The message lists every valid key, because the
        alternative -- falling back to the honest control -- would run a
        different experiment than the one requested and report it under the
        requested label.

    Examples
    --------
    >>> from sih141.web.catalogue import attack_spec
    >>> attack_spec("honest").label
    'Honest run'
    """
    try:
        return _BY_KEY[key]
    except KeyError:
        raise KeyError(
            f"no such attack {key!r}; valid keys are {list(ATTACK_KEYS)}"
        ) from None


def roster_payload() -> list[dict[str, Any]]:
    """Return the whole roster as ``GET /api/attacks`` serves it.

    Returns
    -------
    list of dict

    Examples
    --------
    >>> from sih141.web.catalogue import DETECTABLE_VALUES, roster_payload
    >>> payload = roster_payload()
    >>> payload[0]["key"], payload[0]["detectable"]
    ('honest', 'not-an-attack')
    >>> {entry["detectable"] for entry in payload} <= set(DETECTABLE_VALUES)
    True

    Exactly one arm is undetectable by construction, and it is the only one
    whose exclusion rests on an assumption rather than on a threshold:

    >>> [
    ...     entry["key"] for entry in payload
    ...     if entry["detectable"] == "undetectable-by-construction"
    ... ]
    ['impersonation-full']
    """
    return [spec.to_dict() for spec in ATTACKS]
