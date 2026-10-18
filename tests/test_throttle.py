"""throttle.py in isolation: RateLimiter sliding window, CircuitBreaker state machine."""
from __future__ import annotations
import random

from agentpentest.throttle import (CircuitBreaker, CircuitOpenError, Jitter,
                                   PerTargetBreaker, RateLimitError, RateLimiter,
                                   looks_like_env_error, looks_like_target_failure)


def test_env_error_detection_distinct_from_target_failure():
    for s in ("bash: nuclei: command not found",
              "ModuleNotFoundError: No module named 'impacket'",
              "nmap: error while loading shared libraries: libpcap.so",
              "/bin/sh: 1: gobuster: not found",
              "Permission denied"):
        assert looks_like_env_error(s), s
        assert not looks_like_target_failure(s) or "denied" in s.lower()
    # target distress is NOT an env error
    for s in ("Connection refused", "Nmap: 0 hosts up", "503 Service Unavailable"):
        assert not looks_like_env_error(s), s


def test_per_target_breaker_abandons_one_target_not_the_others():
    b = PerTargetBreaker(max_consecutive_failures=3)
    for _ in range(3):
        b.record("a.example.com", failed=True)
    assert b.is_dead("a.example.com")
    assert not b.is_dead("b.example.com")
    # a healthy response on a still-live target clears its streak
    b.record("b.example.com", failed=True)
    b.record("b.example.com", failed=True)
    b.record("b.example.com", failed=False)
    b.record("b.example.com", failed=True)
    assert not b.is_dead("b.example.com")
    assert b.dead_targets() == {"a.example.com"}


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


def test_jitter_zero_is_noop():
    j = Jitter(0.0, 0.0)
    rng = random.Random(42)
    assert j.sleep(rng) == 0.0     # no sleep, returns 0


def test_jitter_returns_value_in_range():
    j = Jitter(1.0, 2.0)
    rng = random.Random(0)
    # Patch time.sleep so test doesn't actually pause
    import agentpentest.throttle as _t
    slept = []
    _orig = _t.time.sleep
    _t.time.sleep = slept.append
    try:
        d = j.sleep(rng)
    finally:
        _t.time.sleep = _orig
    assert 1.0 <= d <= 2.0
    assert len(slept) == 1 and slept[0] == d


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
