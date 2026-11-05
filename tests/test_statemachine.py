"""statemachine.py: the Co-RedTeam hypothesis->verification loop (Pillar 2)."""
from __future__ import annotations

from agentpentest.statemachine import (CoRedTeam, ExecResult, Hypothesis, PlanStep,
                                       Status, default_evaluator, shellguard_validator)


def _analyze(ctx):
    return [Hypothesis("h1", "SQLi on /login", "T1190", priority=0.9),
            Hypothesis("h2", "weak ssh creds", "T1110", priority=0.4)]


def _plan(h, feedback):
    if h.id == "h1":
        # first proposal is destructive -> validation refuses -> re-plan with feedback
        return [PlanStep("sqlmap -u http://t/login" if feedback else "rm -rf /")]
    return [PlanStep("hydra ssh://t")]


def _execute(step):
    if step.action.startswith("sqlmap"):
        return ExecResult(stdout="PROOF: dumped users", exit_code=0)
    return ExecResult(stderr="no result", exit_code=1)


def test_full_loop_confirm_and_block():
    team = CoRedTeam(_analyze, _plan, executor=_execute, validator=shellguard_validator())
    result = team.run({})
    h1 = next(h for h in result if h.id == "h1")
    h2 = next(h for h in result if h.id == "h2")
    assert h1.status is Status.CONFIRMED, (h1.status, team.log)
    assert h2.status is Status.BLOCKED, h2.status          # refine cap -> HITL handoff


def test_validation_refuses_destructive_step():
    team = CoRedTeam(_analyze, _plan, executor=_execute, validator=shellguard_validator())
    team.run({})
    assert any("rejected by validation" in m for m in team.log), team.log


def test_build_only_default_executor_refuses():
    # No executor injected -> the default raises, so nothing runs for real.
    team = CoRedTeam(lambda ctx: [Hypothesis("h", "x", "T1190", priority=1.0)],
                     lambda h, fb: [PlanStep("echo hi")])
    raised = {"n": 0}
    try:
        team.run({})
    except RuntimeError:
        raised["n"] += 1
    assert raised["n"] == 1


def test_evaluator_needs_proof_not_just_exit0():
    h = Hypothesis("h", "x", "T1190")
    assert default_evaluator(h, PlanStep("x"), ExecResult(stdout="ok", exit_code=0)) \
        is Status.NEEDS_REFINEMENT
    assert default_evaluator(h, PlanStep("x"), ExecResult(stdout="uid=0", exit_code=0)) \
        is Status.CONFIRMED


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
