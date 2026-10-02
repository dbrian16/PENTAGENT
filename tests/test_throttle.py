"""throttle.py in isolation: RateLimiter sliding window, CircuitBreaker state machine,
and the target-distress heuristic. Pure, offline, no timing flakiness (clock injected)."""
from __future__ import annotations

from agentpentest.throttle import (CircuitBreaker, CircuitOpenError, RateLimitError,
                                   RateLimiter, looks_like_target_failure)


def test_rate_limiter_allows_up_to_the_cap():
    rl = RateLimiter(max_per_second=3)
    rl.check(now=0.0); rl.check(now=0.1); rl.check(now=0.2)   # 3 ok
    try:
        rl.check(now=0.3)
        raise AssertionError("4th action within the same second must be refused")
    except RateLimitError:
        pass


def test_rate_limiter_window_slides():
    rl = RateLimiter(max_per_second=1)
    rl.check(now=0.0)
    try:
        rl.check(now=0.5)
        raise AssertionError("still inside the 1s window")
    except RateLimitError:
        pass
    rl.check(now=1.1)   # outside the window -> allowed again


def test_breaker_trips_after_consecutive_failures():
    cb = CircuitBreaker(max_consecutive_failures=3)
    cb.record(True); cb.record(True)
    assert not cb.tripped
    cb.assert_closed()                 # still closed
    cb.record(True)
    assert cb.tripped
    try:
        cb.assert_closed()
        raise AssertionError("must raise once tripped")
    except CircuitOpenError:
        pass


def test_breaker_resets_streak_on_success():
    cb = CircuitBreaker(max_consecutive_failures=3)
    cb.record(True); cb.record(True); cb.record(False)   # reset
    cb.record(True); cb.record(True)
    assert not cb.tripped, "the reset must have cleared the earlier streak"


def test_breaker_reset_reopens_after_trip():
    cb = CircuitBreaker(max_consecutive_failures=2)
    cb.record(True); cb.record(True)
    assert cb.tripped
    cb.reset()
    assert not cb.tripped
    cb.assert_closed()                 # no longer raises


def test_breaker_ignores_further_records_once_tripped():
    cb = CircuitBreaker(max_consecutive_failures=2)
    cb.record(True); cb.record(True)
    assert cb.streak == 2
    cb.record(False)                   # tripped already; must not "untrip" silently
    assert cb.tripped and cb.streak == 2


def test_looks_like_target_failure_heuristics():
    assert looks_like_target_failure("")
    assert looks_like_target_failure("   ")
    assert looks_like_target_failure("Connection refused by host")
    assert looks_like_target_failure("503 Service Unavailable")
    assert not looks_like_target_failure("80/tcp open http nginx 1.18.0")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
