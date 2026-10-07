import random
from datetime import timedelta

import pytest

from sieve.worker.queue import BackoffPolicy

POLICY = BackoffPolicy(base_seconds=5, cap_seconds=60)


@pytest.mark.parametrize(
    ("attempt", "ceiling"), [(1, 5), (2, 10), (3, 20), (4, 40), (5, 60), (9, 60)]
)
def test_delay_is_between_half_and_full_exponential_ceiling(attempt: int, ceiling: float) -> None:
    rng = random.Random(1234)
    for _ in range(200):
        delay = POLICY.delay(attempt, rng)
        assert timedelta(seconds=ceiling / 2) <= delay <= timedelta(seconds=ceiling)


def test_jitter_spreads_retries() -> None:
    rng = random.Random(42)
    delays = {POLICY.delay(3, rng) for _ in range(50)}
    assert len(delays) > 40


def test_attempts_start_at_one() -> None:
    with pytest.raises(ValueError, match="start at 1"):
        POLICY.delay(0)
