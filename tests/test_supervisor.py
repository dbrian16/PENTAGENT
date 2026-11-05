"""Supervision layer: the Adviser kills wasted motion before a step runs, the Reflector
forces a strategy reframe after repeated non-progress. Both are verdict-aware -- that is
the edge over a count-only supervisor -- so these tests pin the verdict-semantics, not
just the counters."""
from agentpentest.statemachine import (CoRedTeam, ExecResult, Hypothesis, PlanStep,
                                       Status, default_evaluator)
from agentpentest.supervisor import Adviser, AttemptRecord, Reflector


def _rec(action, verdict, executed=True):
    return AttemptRecord(action, verdict, executed=executed)


# ---- Adviser ------------------------------------------------------------------
def test_adviser_noop_on_distinct_steps():
    a = Adviser()
    hist = [_rec("nmap -sV t", "needs_refinement")]
    assert not a.advise(hist, PlanStep("gobuster dir -u t")).acted


def test_adviser_warns_on_second_identical_step():
    a = Adviser(repeat_warn=2, repeat_abandon=3)
    hist = [_rec("curl t", "needs_refinement")]
    iv = a.advise(hist, PlanStep("curl t"))
    assert iv.feedback and not iv.abandon
    assert "different tool or technique" in iv.feedback


def test_adviser_inconclusive_repeat_blames_probe_params():
    """A repeat whose prior runs were INCONCLUSIVE means the probe is mis-parameterized,
    not that the hypothesis is wrong -- the hint must say so (count-only cannot)."""
    a = Adviser(repeat_warn=2, repeat_abandon=3)
    hist = [_rec('{"probe":"ssti"}', "inconclusive")]
    iv = a.advise(hist, PlanStep('{"probe":"ssti"}'))
    assert iv.feedback and "injection point" in iv.feedback


def test_adviser_abandons_on_third_identical_step():
    a = Adviser(repeat_warn=2, repeat_abandon=3)
    hist = [_rec("curl t", "needs_refinement"), _rec("curl t", "", executed=False)]
    iv = a.advise(hist, PlanStep("curl t"))
    assert iv.abandon and "stuck" in iv.reason


def test_adviser_abandons_past_total_ceiling():
    a = Adviser(max_total=3)
    hist = [_rec(f"step{i}", "needs_refinement") for i in range(3)]
    iv = a.advise(hist, PlanStep("step-new"))
    assert iv.abandon and "executed attempts" in iv.reason


# ---- Reflector ----------------------------------------------------------------
def test_reflector_noop_below_patience():
    r = Reflector(patience=3)
    hist = [_rec("a", "needs_refinement"), _rec("b", "needs_refinement")]
    assert not r.reflect(hist).acted


def test_reflector_reframes_at_patience():
    r = Reflector(patience=3)
    hist = [_rec(x, "needs_refinement") for x in ("a", "b", "c")]
    iv = r.reflect(hist)
    assert iv.feedback and "change the technique" in iv.feedback and not iv.abandon


def test_reflector_abandons_at_double_patience():
    r = Reflector(patience=3)
    hist = [_rec(str(i), "needs_refinement") for i in range(6)]
    assert r.reflect(hist).abandon


def test_reflector_ignores_inconclusive_noise():
    """INCONCLUSIVE is the resample budget's job; it must neither break nor extend the
    non-progress streak, so pure noise never trips a reframe."""
    r = Reflector(patience=3)
    assert not r.reflect([_rec(str(i), "inconclusive") for i in range(5)]).acted
    # a trailing inconclusive is skipped, the two real failures still count as 2 (< 3)
    hist = [_rec("a", "needs_refinement"), _rec("b", "needs_refinement"),
            _rec("c", "inconclusive")]
    assert not r.reflect(hist).acted


def test_reflector_confirmed_breaks_streak():
    r = Reflector(patience=2)
    hist = [_rec("a", "needs_refinement"), _rec("b", "confirmed"),
            _rec("c", "needs_refinement")]
    assert not r.reflect(hist).acted       # streak is 1 (confirmed broke the run)


# ---- State-machine integration ------------------------------------------------
def test_adviser_cuts_a_stuck_planner_short():
    """A planner stuck re-proposing one step is abandoned by the Adviser well before the
    refine budget would have let it churn."""
    def analyze(_):
        return [Hypothesis("stuck", "x", priority=1.0)]

    def plan(h, fb):
        return [PlanStep("the-only-move")]          # never adapts

    def execute(step):
        return ExecResult(stderr="no", exit_code=1)  # default_evaluator -> NEEDS_REFINEMENT

    team = CoRedTeam(analyze, plan, executor=execute, evaluator=default_evaluator,
                     max_refine=20, adviser=Adviser(repeat_warn=2, repeat_abandon=3))
    h = team.run({})[0]
    assert h.status is Status.BLOCKED
    assert h.attempts == 3                          # not 20: the adviser stopped the churn
    assert any("adviser vetoed" in m for m in team.log)
    assert any("adviser:" in m and "stuck" in m for m in team.log)


def test_reflector_feedback_reaches_the_planner():
    """The Reflector's reframe note must land in the planner's feedback so the next plan
    can change approach."""
    seen: list[list[str]] = []
    counter = {"n": 0}

    def analyze(_):
        return [Hypothesis("reframe", "x", priority=1.0)]

    def plan(h, fb):
        seen.append(list(fb))
        counter["n"] += 1
        return [PlanStep(f"distinct-move-{counter['n']}")]   # distinct -> adviser silent

    def execute(step):
        return ExecResult(stderr="no", exit_code=1)

    team = CoRedTeam(analyze, plan, executor=execute, evaluator=default_evaluator,
                     max_refine=20, reflector=Reflector(patience=3))
    h = team.run({})[0]
    assert h.status is Status.BLOCKED                       # reflector abandons at 2*patience
    assert any(any("REFLECTOR" in f for f in fb) for fb in seen)
    assert any("reflector reframe" in m for m in team.log)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
