"""Single point of control for randomness in the SIH26141 quantum core.

Every function in this project that consumes randomness accepts a keyword-only
``rng`` argument and resolves it here. Nothing anywhere in the codebase may call
``numpy.random.<function>`` at module level or use the stdlib :mod:`random`
module, because both draw from hidden global state: results would not be
reproducible, and the Phase 5 evaluation (ROC curves, detection rates) would not
be defensible.

The rule is therefore:

.. code-block:: python

    def something(..., *, rng: np.random.Generator | None = None) -> ...:
        generator = resolve_rng(rng)
        ...  # use `generator` exclusively

Callers get reproducibility by constructing one generator and threading it
through a whole experiment::

    rng = np.random.default_rng(20260141)
    outcome_a = projective_measure(state, 0, PauliBasis.Z, rng=rng)
    outcome_b = projective_measure(state, 1, PauliBasis.X, rng=rng)

Note that passing ``rng=None`` is *not* a bug -- it is the documented "give me
fresh entropy" path used in interactive demos. Only the evaluation harness is
required to seed explicitly.

Scalar seeds from the outside world
-----------------------------------
:func:`resolve_rng` deliberately refuses integer seeds, but Phases 5 and 6 read
seeds from a CLI flag, a JSON run description or a config file, where a seed
*is* a bare integer. :func:`seed_to_generator` is the one sanctioned place where
such a scalar is turned into a generator::

    generator = seed_to_generator(args.seed)      # once, at the boundary
    result = run_experiment(..., rng=generator)   # threaded from there on

Doing it anywhere else -- in particular by calling ``numpy.random.default_rng``
inline at each call site -- is what D3 forbids, because it reintroduces exactly
the restarted-stream bug ``resolve_rng`` exists to prevent.

Qubit ordering
--------------
Not applicable in this module (no quantum state is handled here), but the
project-wide convention is Qiskit little-endian: qubit 0 is the rightmost
character of a bitstring label.
"""

from __future__ import annotations

import numpy as np

__all__ = ["resolve_rng", "seed_to_generator"]


def resolve_rng(rng: np.random.Generator | None = None) -> np.random.Generator:
    """Return a usable :class:`numpy.random.Generator`.

    This is the only sanctioned way to obtain randomness in the project.

    Parameters
    ----------
    rng : numpy.random.Generator or None, optional
        An existing generator to use as-is, or ``None`` to create a fresh,
        entropy-seeded generator via :func:`numpy.random.default_rng`.

    Returns
    -------
    numpy.random.Generator
        ``rng`` itself when one was supplied (the *same* object, never a copy,
        so that sequential draws advance a single stream), otherwise a new
        generator.

    Raises
    ------
    TypeError
        If ``rng`` is neither ``None`` nor a :class:`numpy.random.Generator`.
        Integer seeds and the legacy :class:`numpy.random.RandomState` are
        rejected explicitly with instructions, because silently accepting a
        seed would restart the stream on every call and produce correlated
        "random" draws.

    Notes
    -----
    The supplied generator is returned by identity rather than by copy. Advancing
    it in a callee is intentional: one seeded generator threaded through an
    experiment yields one reproducible stream.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.rng import resolve_rng
    >>> generator = resolve_rng(np.random.default_rng(0))
    >>> first = generator.integers(100)
    >>> int(first) == int(np.random.default_rng(0).integers(100))
    True
    >>> isinstance(resolve_rng(None), np.random.Generator)
    True
    """
    if rng is None:
        return np.random.default_rng()
    if isinstance(rng, np.random.Generator):
        return rng
    if isinstance(rng, (int, np.integer)):
        raise TypeError(
            f"rng must be a numpy.random.Generator or None, got the seed "
            f"{rng!r}. Integer seeds are rejected on purpose: build the "
            f"generator once with numpy.random.default_rng({int(rng)}) and pass "
            f"that object, so repeated calls advance one stream instead of "
            f"restarting it."
        )
    if isinstance(rng, np.random.RandomState):
        raise TypeError(
            "rng must be a numpy.random.Generator or None, got the legacy "
            "numpy.random.RandomState. Replace it with "
            "numpy.random.default_rng(seed); the legacy API is not used "
            "anywhere in this project."
        )
    raise TypeError(
        f"rng must be a numpy.random.Generator or None, got "
        f"{type(rng).__name__}. Pass numpy.random.default_rng(seed) for "
        f"reproducible runs, or None for fresh entropy."
    )


def seed_to_generator(seed: int | None) -> np.random.Generator:
    """Convert an untrusted scalar seed into a generator, once, at the boundary.

    This is **the** sanctioned boundary between scalar seeds -- the form a seed
    arrives in from a CLI flag, a JSON run description or a config file -- and
    the generator discipline of D3. Everything downstream of this call takes a
    :class:`numpy.random.Generator` and threads it, so that one seed produces one
    continuous, reproducible stream.

    Use it **once per run**, at the point where the outside world hands over a
    number::

        generator = seed_to_generator(config["seed"])   # boundary
        for trial in range(trials):                     # one stream throughout
            outcome = projective_measure(state, 0, PauliBasis.Z, rng=generator)

    Never call it inside a loop or per call site. That would restart the stream
    on every iteration and produce a run of identical "random" draws -- the
    failure mode :func:`resolve_rng` refuses integer seeds to prevent. If you
    already hold a generator, pass it to :func:`resolve_rng`; this function
    rejects generators on purpose, so that the two entry points cannot be
    confused for each other.

    Parameters
    ----------
    seed : int or None
        A non-negative integer seed, or ``None`` for fresh entropy (the
        interactive-demo path; an unseeded run is not reproducible and must not
        be used for reported numbers).

    Returns
    -------
    numpy.random.Generator
        A freshly constructed generator, deterministic in ``seed``.

    Raises
    ------
    ValueError
        If ``seed`` is a negative integer. NumPy's own seed sequence rejects
        these too; the message here names the fix.
    TypeError
        If ``seed`` is a :class:`bool` (which is an ``int`` in Python but never a
        meaningful seed), a :class:`numpy.random.Generator` (use
        :func:`resolve_rng`), or any other non-integer such as a float or a
        string. Strings from a CLI must be converted with :func:`int` by the
        caller, so that a malformed ``--seed`` value fails at the argument
        parser rather than silently seeding something else.

    See Also
    --------
    resolve_rng : The in-project entry point, which takes a generator or ``None``.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.rng import seed_to_generator
    >>> generator = seed_to_generator(20260141)
    >>> reference = np.random.default_rng(20260141)
    >>> bool(np.array_equal(generator.random(4), reference.random(4)))
    True
    >>> isinstance(seed_to_generator(None), np.random.Generator)
    True
    """
    if seed is None:
        return np.random.default_rng()
    if isinstance(seed, np.random.Generator):
        raise TypeError(
            "seed_to_generator takes a scalar seed, not a "
            "numpy.random.Generator. Pass the generator to resolve_rng (or "
            "straight to the rng= argument) instead; this function exists only "
            "to convert a scalar from outside the project."
        )
    if isinstance(seed, bool):
        raise TypeError(
            f"seed must be a non-negative integer or None, got the boolean "
            f"{seed!r}. Booleans are integers in Python but never a meaningful "
            f"seed; pass an explicit integer such as 20260141."
        )
    if not isinstance(seed, (int, np.integer)):
        raise TypeError(
            f"seed must be a non-negative integer or None, got "
            f"{type(seed).__name__}. Convert command-line and JSON values with "
            f"int(...) at the parser, so a malformed seed fails there rather "
            f"than seeding something unintended here."
        )
    value = int(seed)
    if value < 0:
        raise ValueError(
            f"seed must be non-negative, got {value}. numpy's SeedSequence "
            f"accepts only non-negative integers; use abs({value}) or a "
            f"different seed."
        )
    return np.random.default_rng(value)
