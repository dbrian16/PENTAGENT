"""Tests for agentpentest.timestomp (T1070.006 - build-only simulation)."""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentpentest.timestomp import (
    DirEntry, StompSpec, StompPlan,
    plan_stomp, apply_stomp, _no_executor,
)


# stub reasoner

class _StubReasoner:
    def __init__(self, response: str):
        self._resp = response

    def ask(self, system: str, user: str) -> str:
        return self._resp


def _make_spec() -> StompSpec:
    return StompSpec(
        target_path="/etc/cron.d/cleanup",
        reference_dir="/etc/cron.d",
        entries=[
            DirEntry("0hourly",    1_700_000_000.0, 1_700_000_100.0, 100),
            DirEntry("sysstat",    1_680_000_000.0, 1_680_000_200.0, 80),
            DirEntry("dailyjobs",  1_690_000_000.0, 1_690_000_300.0, 64),
        ],
    )


# tests

def test_plan_stomp_happy():
    resp = json.dumps({
        "ref_name": "0hourly",
        "mtime_unix": 1_700_000_000.0,
        "atime_unix": 1_700_000_100.0,
        "rationale": "same naming pattern as target",
    })
    plan = plan_stomp(_make_spec(), _StubReasoner(resp))
    assert not plan.error
    assert plan.ref_name == "0hourly"
    assert plan.mtime_unix == 1_700_000_000.0
    assert plan.atime_unix == 1_700_000_100.0


def test_plan_stomp_bad_json():
    plan = plan_stomp(_make_spec(), _StubReasoner("not json at all"))
    assert plan.error


def test_plan_stomp_unknown_ref():
    resp = json.dumps({
        "ref_name": "ghost_file",
        "mtime_unix": 1_600_000_000.0,
        "atime_unix": 1_600_000_000.0,
        "rationale": "does not exist in listing",
    })
    plan = plan_stomp(_make_spec(), _StubReasoner(resp))
    assert plan.error
    assert "ghost_file" in plan.error


def test_apply_stomp_no_executor_raises():
    plan = StompPlan("/etc/cron.d/cleanup", "0hourly",
                     1_700_000_000.0, 1_700_000_100.0, "test")
    try:
        apply_stomp(plan)
        assert False, "should have raised RuntimeError"
    except RuntimeError as e:
        assert "build-only" in str(e)


def test_apply_stomp_error_plan_is_noop():
    plan = StompPlan("/etc/cron.d/cleanup", "", 0.0, 0.0, "", error="parse failed")
    called = []
    apply_stomp(plan, execute=lambda p: called.append(p))
    assert not called


def test_apply_stomp_calls_executor():
    plan = StompPlan("/etc/cron.d/cleanup", "0hourly",
                     1_700_000_000.0, 1_700_000_100.0, "ok")
    called = []
    apply_stomp(plan, execute=lambda p: called.append(p))
    assert called == [plan]


def test_chain_includes_timestomp():
    from agentpentest.chain import FOLLOW_ONS
    techs_from_t1078 = [t for t, _ in FOLLOW_ONS.get("T1078", [])]
    assert "T1070.006" in techs_from_t1078


def test_knowledge_knows_t1070_006():
    from agentpentest.knowledge import technique_name, tactic, severity
    assert "Timestomp" in technique_name("T1070.006")
    assert tactic("T1070.006") == "Defense Evasion"
    assert severity("T1070.006") in ("Low", "Medium", "High", "Critical")


if __name__ == "__main__":
    test_plan_stomp_happy()
    test_plan_stomp_bad_json()
    test_plan_stomp_unknown_ref()
    test_apply_stomp_no_executor_raises()
    test_apply_stomp_error_plan_is_noop()
    test_apply_stomp_calls_executor()
    test_chain_includes_timestomp()
    test_knowledge_knows_t1070_006()
    print("All timestomp tests passed.")
