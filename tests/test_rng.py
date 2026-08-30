"""Tests for :mod:`sih141.core.rng`.

``resolve_rng`` is three lines of logic that every stochastic result in the
project depends on, so its contract is pinned tightly: a supplied generator is
returned by identity (so a single seeded stream advances across calls), ``None``
gives fresh entropy, and anything else -- especially a bare integer seed --
fails loudly rather than silently restarting the stream.

``seed_to_generator`` is the one sanctioned crossing in the other direction:
scalar seeds arrive from CLI flags and config files in Phases 5 and 6, and
without a blessed converter callers would reach for ``numpy.random`` directly,
which is exactly what D3 forbids.  Its tests pin that it is deterministic in the
seed, that it is *not* a second ``resolve_rng`` (generators are refused), and
that the two functions compose.
"""

from __future__ import annotations

import numpy as np
import pytest

from sih141.core.rng import resolve_rng, seed_to_generator


def test_none_returns_a_fresh_generator() -> None:
    generator = resolve_rng(None)
    assert isinstance(generator, np.random.Generator)


def test_default_argument_is_none() -> None:
    """``resolve_rng()`` is the documented "fresh entropy" call."""
    assert isinstance(resolve_rng(), np.random.Generator)


def test_two_unseeded_generators_are_independent() -> None:
    """Fresh generators must not share state (a shared singleton would be a bug)."""
    first = resolve_rng(None)
    second = resolve_rng(None)
    assert first is not second
    assert first.integers(0, 2**62, size=8).tolist() != second.integers(
        0, 2**62, size=8
    ).tolist()


def test_supplied_generator_is_returned_by_identity_not_copied() -> None:
    """Identity matters: a copy would rewind the stream on every call."""
    rng = np.random.default_rng(20260141)
    assert resolve_rng(rng) is rng


def test_supplied_generator_keeps_advancing_across_calls() -> None:
    """Threading one generator through calls yields one continuous stream."""
    rng = np.random.default_rng(20260141)
    drawn = [int(resolve_rng(rng).integers(1_000_000)) for _ in range(5)]

    reference = np.random.default_rng(20260141)
    expected = [int(reference.integers(1_000_000)) for _ in range(5)]

    assert drawn == expected
    assert len(set(drawn)) > 1, "the stream was restarted instead of advanced"


def test_same_seed_gives_identical_results() -> None:
    """D3: seeded runs are reproducible."""
    left = resolve_rng(np.random.default_rng(7)).random(16)
    right = resolve_rng(np.random.default_rng(7)).random(16)
    np.testing.assert_array_equal(left, right)


def test_different_seeds_give_different_results() -> None:
    left = resolve_rng(np.random.default_rng(7)).random(16)
    right = resolve_rng(np.random.default_rng(8)).random(16)
    assert not np.array_equal(left, right)


@pytest.mark.parametrize("seed", [0, 7, np.int64(42)])
def test_integer_seeds_are_rejected_with_an_actionable_message(seed: object) -> None:
    """Accepting a seed would silently restart the stream on every call."""
    with pytest.raises(TypeError, match="default_rng"):
        resolve_rng(seed)  # type: ignore[arg-type]


def test_legacy_random_state_is_rejected() -> None:
    with pytest.raises(TypeError, match="RandomState"):
        resolve_rng(np.random.RandomState(0))  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["seed", 3.14, [1, 2, 3], object()])
def test_other_types_are_rejected(bad: object) -> None:
    with pytest.raises(TypeError, match="numpy.random.Generator"):
        resolve_rng(bad)  # type: ignore[arg-type]


def test_alternative_bit_generators_are_accepted() -> None:
    """Any numpy Generator is fine, not just the default PCG64 one."""
    rng = np.random.Generator(np.random.Philox(20260141))
    assert resolve_rng(rng) is rng


# --------------------------------------------------------------------------- #
# seed_to_generator: the sanctioned scalar-seed boundary                       #
# --------------------------------------------------------------------------- #


def test_seed_to_generator_returns_a_generator() -> None:
    assert isinstance(seed_to_generator(20260141), np.random.Generator)


def test_seed_to_generator_is_deterministic_in_the_seed() -> None:
    """The whole point: one scalar in, one reproducible stream out."""
    drawn = seed_to_generator(20260141).random(8)
    expected = np.random.default_rng(20260141).random(8)
    np.testing.assert_array_equal(drawn, expected)


def test_seed_to_generator_different_seeds_differ() -> None:
    assert not np.array_equal(
        seed_to_generator(7).random(8), seed_to_generator(8).random(8)
    )


def test_seed_to_generator_none_gives_fresh_entropy() -> None:
    """``None`` is the documented interactive path, not an error."""
    first = seed_to_generator(None)
    second = seed_to_generator(None)
    assert isinstance(first, np.random.Generator)
    assert first is not second
    assert not np.array_equal(first.random(8), second.random(8))


def test_seed_to_generator_output_is_accepted_by_resolve_rng() -> None:
    """The two entry points compose: convert once, then thread the object."""
    generator = seed_to_generator(20260141)
    assert resolve_rng(generator) is generator


def test_seed_to_generator_result_advances_one_stream() -> None:
    """Convert at the boundary, then loop: the stream must not restart.

    This is the failure mode the whole D3 discipline exists to prevent, so it
    is asserted rather than assumed.
    """
    generator = seed_to_generator(20260141)
    drawn = [float(generator.random()) for _ in range(5)]
    assert len(set(drawn)) == 5, "the stream restarted instead of advancing"

    reference = np.random.default_rng(20260141)
    assert drawn == [float(reference.random()) for _ in range(5)]


def test_seed_to_generator_accepts_numpy_integers() -> None:
    """JSON and argparse both hand over plain ints; numpy ints show up too."""
    np.testing.assert_array_equal(
        seed_to_generator(np.int64(42)).random(4),
        np.random.default_rng(42).random(4),
    )


def test_seed_to_generator_accepts_zero() -> None:
    """Zero is a legal seed and must not be confused with a falsy 'no seed'."""
    np.testing.assert_array_equal(
        seed_to_generator(0).random(4), np.random.default_rng(0).random(4)
    )


def test_seed_to_generator_rejects_a_generator() -> None:
    """It is the scalar boundary, not a second resolve_rng."""
    with pytest.raises(TypeError, match="resolve_rng"):
        seed_to_generator(np.random.default_rng(0))  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [True, False])
def test_seed_to_generator_rejects_booleans(bad: bool) -> None:
    """``bool`` is an ``int`` in Python but never a meaningful seed."""
    with pytest.raises(TypeError, match="boolean"):
        seed_to_generator(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["20260141", 3.14, [1, 2], object()])
def test_seed_to_generator_rejects_non_integers(bad: object) -> None:
    """A CLI string must be int()-ed at the parser, not silently reinterpreted."""
    with pytest.raises(TypeError, match="non-negative integer"):
        seed_to_generator(bad)  # type: ignore[arg-type]


def test_seed_to_generator_rejects_negative_seeds_with_an_actionable_message() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        seed_to_generator(-1)
