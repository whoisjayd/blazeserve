"""Unit tests for rate limiting and client token bucket pools."""

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
