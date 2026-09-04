"""Unit tests for rate limiting and client token bucket pools."""

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from blazeserve.limiter import IPRateLimiterPool, TokenBucket


@pytest.mark.unit
def test_token_bucket_unlimited():
    tb = TokenBucket(None)
    assert tb.rate == 0.0
    assert tb.consume(1000) == 0.0
    assert tb.take(1000) == 1000

    tb_zero = TokenBucket(0.0)
    assert tb_zero.rate == 0.0
    assert tb_zero.consume(500) == 0.0
    assert tb_zero.take(500) == 500


@pytest.mark.unit
def test_token_bucket_consume():
    tb = TokenBucket(1000.0)
    assert tb.tokens == 2000.0
    wait = tb.consume(500)
    assert wait == 0.0
    assert tb.tokens == 1500.0

    wait2 = tb.consume(2000)
    assert 0.45 <= wait2 <= 0.55
    assert tb.tokens == 0.0


@pytest.mark.unit
def test_token_bucket_take():
    tb = TokenBucket(1000.0)
    taken = tb.take(500)
    assert taken == 500
    assert tb.tokens == 1500.0


@pytest.mark.unit
def test_token_bucket_take_does_not_create_tokens_after_capped_sleep():
    tb = TokenBucket(1.0)
    tb.tokens = 0.0

    with (
        patch("blazeserve.limiter.time.perf_counter", return_value=tb.last),
        patch("blazeserve.limiter.time.sleep") as sleep,
    ):
        assert tb.take(1) == 0

    sleep.assert_called_once_with(0.05)
    assert tb.tokens == 0.0


@pytest.mark.unit
def test_token_bucket_serializes_concurrent_consumers():
    entered_comparison = 0
    comparison_lock = threading.Lock()
    both_comparing = threading.Event()

    class CoordinatedToken(float):
        def __add__(self, other):
            if other == 0:
                return self
            return float(self) + other

        def __ge__(self, other):
            nonlocal entered_comparison
            with comparison_lock:
                entered_comparison += 1
                if entered_comparison == 2:
                    both_comparing.set()
            both_comparing.wait(timeout=0.1)
            return float(self) >= other

    tb = TokenBucket(1.0)
    tb.tokens = CoordinatedToken(1.0)
    with (
        patch("blazeserve.limiter.time.perf_counter", return_value=tb.last),
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        waits = list(executor.map(tb.consume, (1, 1)))

    assert sorted(waits) == [0.0, 1.0]
    assert tb.tokens == 0.0


@pytest.mark.unit
def test_ip_rate_limiter_pool_basic():
    pool = IPRateLimiterPool(max_entries=3)
    lim1 = pool.get_limiter("192.168.1.1", 1000.0)
    lim2 = pool.get_limiter("192.168.1.2", 2000.0)

    assert pool.get_limiter("192.168.1.1", 1000.0) is lim1
    assert pool.get_limiter("192.168.1.2", 2000.0) is lim2


@pytest.mark.unit
def test_ip_rate_limiter_pool_eviction():
    pool = IPRateLimiterPool(max_entries=2)
    lim1 = pool.get_limiter("1.1.1.1", 1000.0)
    pool.get_limiter("2.2.2.2", 2000.0)

    pool.get_limiter("3.3.3.3", 3000.0)
    assert "1.1.1.1" not in pool._limiters
    assert "2.2.2.2" in pool._limiters
    assert "3.3.3.3" in pool._limiters

    lim1_fresh = pool.get_limiter("1.1.1.1", 1000.0)
    assert lim1_fresh is not lim1


@pytest.mark.unit
def test_ip_rate_limiter_pool_evicts_least_recently_used_client():
    pool = IPRateLimiterPool(max_entries=2)
    first = pool.get_limiter("1.1.1.1", 1000.0)
    pool.get_limiter("2.2.2.2", 1000.0)

    assert pool.get_limiter("1.1.1.1", 1000.0) is first
    pool.get_limiter("3.3.3.3", 1000.0)

    assert list(pool._limiters) == ["1.1.1.1", "3.3.3.3"]


@pytest.mark.unit
def test_ip_rate_limiter_pool_updates_existing_bucket_rate():
    pool = IPRateLimiterPool(max_entries=2)
    limiter = pool.get_limiter("1.1.1.1", 100.0)
    limiter.consume(100)

    updated = pool.get_limiter("1.1.1.1", 50.0)

    assert updated is limiter
    assert updated.rate == 50.0
    assert updated.capacity == 100.0
    assert 0.0 <= updated.tokens <= updated.capacity


@pytest.mark.unit
def test_zero_sized_ip_rate_limiter_pool_remains_empty():
    pool = IPRateLimiterPool(max_entries=0)

    first = pool.get_limiter("1.1.1.1", 100.0)
    second = pool.get_limiter("1.1.1.1", 100.0)

    assert first is not second
    assert not pool._limiters
