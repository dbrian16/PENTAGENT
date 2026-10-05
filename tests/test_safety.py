"""Session stop signal and hard_stop teardown (offline)."""
from __future__ import annotations

import agentpentest.safety as safety


def _reset():
    safety.clear_stop()


# --- signal mechanics -----------------------------------------------------

def test_stop_not_set_initially():
    _reset()
    assert not safety.stop_requested()


def test_request_stop_sets_flag():
    _reset()
    safety.request_stop("test reason")
    assert safety.stop_requested()
    _reset()


def test_clear_stop_resets_flag():
    safety.request_stop("x")
    safety.clear_stop()
    assert not safety.stop_requested()


def test_multiple_request_stop_calls_idempotent():
    _reset()
    safety.request_stop("a")
    safety.request_stop("b")
    assert safety.stop_requested()
    _reset()


# --- SessionStop exception ------------------------------------------------

def test_session_stop_is_base_exception():
    assert issubclass(safety.SessionStop, BaseException)


def test_session_stop_not_caught_by_except_exception():
    """BaseException propagates through bare `except Exception:` guards."""
    raised = False
    try:
        try:
            raise safety.SessionStop("test")
        except Exception:
            pass   # must NOT swallow SessionStop
    except safety.SessionStop:
        raised = True
    assert raised, "SessionStop must not be swallowed by `except Exception:`"


def test_session_stop_carries_reason():
    e = safety.SessionStop("operator kill")
    assert e.reason == "operator kill"
    assert "operator kill" in str(e)


# --- hard_stop: sandbox teardown ------------------------------------------

class _FakeSandbox:
    def __init__(self):
        self.rolled_back = False
        self.closed = False

    def rollback(self):
        self.rolled_back = True

    def close(self, **_kw):
        self.closed = True


def test_hard_stop_signals_stop_event():
    _reset()
    safety.hard_stop("test", rearm_lock=False)
    assert safety.stop_requested()
    _reset()


def test_hard_stop_rolls_back_and_closes_sandbox():
    _reset()
    sb = _FakeSandbox()
    safety.hard_stop("test", sandbox=sb, rearm_lock=False)
    assert sb.rolled_back, "sandbox must be rolled back to last clean snapshot"
    assert sb.closed, "sandbox container must be closed"
    _reset()


def test_hard_stop_tolerates_sandbox_without_rollback():
    _reset()

    class _NoRollback:
        closed = False
        def close(self, **_kw): self.closed = True

    sb = _NoRollback()
    safety.hard_stop("test", sandbox=sb, rearm_lock=False)   # must not raise
    assert sb.closed
    _reset()


def test_hard_stop_tolerates_crashing_sandbox():
    _reset()

    class _CrashSandbox:
        def rollback(self): raise RuntimeError("container gone")
        def close(self, **_kw): raise RuntimeError("already removed")

    safety.hard_stop("test", sandbox=_CrashSandbox(), rearm_lock=False)  # must not raise
    assert safety.stop_requested()
    _reset()


def test_hard_stop_writes_audit_event():
    _reset()
    from agentpentest.runlog import RunLog
    import io, json

    buf = io.StringIO()
    rlog = RunLog.__new__(RunLog)
    events = []
    rlog.event = lambda **kw: events.append(kw)

    safety.hard_stop("unit-test", runlog=rlog, rearm_lock=False)
    assert any(e.get("action") == "session_end" for e in events)
    assert any(e.get("reason") == "unit-test" for e in events)
    _reset()


# --- loop integration: stop_requested() breaks autoloop and EGATS ---------

def test_autoloop_breaks_on_stop_signal():
    from agentpentest.autonomous import autoloop
    from agentpentest.llm import MockReasoner

    _reset()
    safety.request_stop("test")
    steps_executed = []

    def fake_execute(argv, target): steps_executed.append(argv); return ""

    # MockReasoner returns empty => plan.get("done") short-circuits anyway,
    # but with stop_requested the loop breaks BEFORE _plan is called.
    autoloop("probe", {"example.com"}, MockReasoner(), fake_execute, max_steps=10)
    assert steps_executed == [], "no commands must run after stop signal"
    _reset()


def test_egats_breaks_on_stop_signal():
    from agentpentest.brain import EGATS
    from agentpentest.ptt import Evidence, PentestTree

    _reset()
    safety.request_stop("test")

    tree = PentestTree("example.com")
    tree.add("probe http", tree.root_id, Evidence.SPECULATIVE, technique="T1046")
    oracle_calls = []

    def oracle(node):
        oracle_calls.append(node.id)
        return True, "SPECULATIVE"

    eg = EGATS(tree, oracle, max_steps=10)
    eg.run()
    assert oracle_calls == [], "oracle must not be called after stop signal"
    _reset()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
