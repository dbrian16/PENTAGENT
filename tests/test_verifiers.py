"""Deterministic Verification Engine: every verdict is a math/state check, never a
substring guess. These tests pin the three ways a verdict can go (CONFIRMED /
FALSE_POSITIVE / INCONCLUSIVE) and the state-machine wiring (resample budget)."""
from agentpentest.statemachine import (CoRedTeam, ExecResult, Hypothesis, PlanStep,
                                       Status, deterministic_evaluator)
from agentpentest.verifiers import (AlgebraicCanaryVerifier, IdentityDifferentialVerifier,
                                    LinearRegressionTimingVerifier, OOBInteractionVerifier,
                                    VerdictStatus)


# ---- Algebraic canary (SSTI) --------------------------------------------------
def test_canary_confirms_executed_expression():
    v = AlgebraicCanaryVerifier()
    p = v.verify(baseline_stdout="Hello {{name}}",
                 mutated_stdout="Hello 48552583",      # 6947*6989 computed
                 factor_a=6947, factor_b=6989)
    assert p.status is VerdictStatus.CONFIRMED and p.confidence == 1.0


def test_canary_rejects_reflected_expression():
    v = AlgebraicCanaryVerifier()
    # product present BUT literal expression also echoed -> cannot distinguish -> grey
    p = v.verify(baseline_stdout="x",
                 mutated_stdout="result of 6947*6989 is 48552583",
                 factor_a=6947, factor_b=6989)
    assert p.status is VerdictStatus.INCONCLUSIVE


def test_canary_baseline_collision_is_inconclusive():
    v = AlgebraicCanaryVerifier()
    p = v.verify(baseline_stdout="order 48552583 shipped",
                 mutated_stdout="order 48552583 shipped",
                 factor_a=6947, factor_b=6989)
    assert p.status is VerdictStatus.INCONCLUSIVE


def test_canary_false_positive_when_absent():
    v = AlgebraicCanaryVerifier()
    p = v.verify(baseline_stdout="x", mutated_stdout="syntax error near line 3",
                 factor_a=6947, factor_b=6989)
    assert p.status is VerdictStatus.FALSE_POSITIVE   # an error page is NOT proof


# ---- Identity differential (IDOR / BOLA) -------------------------------------
def _resp(**kw):
    return dict(kw)


def test_idor_confirmed_on_single_high_entropy_leak():
    """A trimmed attacker view that leaks ONLY the victim's email is still a proven
    IDOR -- no leak-ratio gate may hide it."""
    v = IdentityDifferentialVerifier()
    a = _resp(id=1001, email="alice@victim.com", phone="0987654321", plan="pro")
    b_own = _resp(id=1002, email="bob@other.com", phone="0111222333", plan="pro")
    unauth = _resp(error="unauthorized")
    attacker_view = _resp(email="alice@victim.com")   # only the email leaks
    p = v.verify(r_aa_1=a, r_aa_2=a, r_ba=attacker_view, r_bb=b_own, r_unauth=unauth)
    assert p.status is VerdictStatus.CONFIRMED
    assert p.evidence["high_entropy_leak"] is True


def test_idor_false_positive_on_shared_default_page():
    v = IdentityDifferentialVerifier()
    a = _resp(id=1001, email="alice@victim.com", theme="dark", lang="en")
    b_own = _resp(id=1002, email="bob@other.com", theme="dark", lang="en")
    unauth = _resp(theme="dark", lang="en")
    # attacker gets the generic/unauth shell, none of A's private values
    p = v.verify(r_aa_1=a, r_aa_2=a, r_ba=unauth, r_bb=b_own, r_unauth=unauth)
    assert p.status is VerdictStatus.FALSE_POSITIVE


def test_idor_dynamic_fields_are_masked():
    v = IdentityDifferentialVerifier()
    a1 = _resp(email="alice@victim.com", csrf="tok-aaa", ts=111)
    a2 = _resp(email="alice@victim.com", csrf="tok-bbb", ts=222)   # csrf/ts vary
    b_own = _resp(email="bob@other.com", csrf="tok-ccc", ts=333)
    # attacker response carries the volatile csrf but NOT A's email -> not a leak
    attacker = _resp(csrf="tok-aaa", ts=111)
    p = v.verify(r_aa_1=a1, r_aa_2=a2, r_ba=attacker, r_bb=b_own)
    assert p.status is VerdictStatus.FALSE_POSITIVE


# ---- OLS timing (blind time-based) -------------------------------------------
def test_timing_confirmed_linear_k1():
    v = LinearRegressionTimingVerifier()
    samples = [(0, 0.10), (2, 2.11), (4, 4.09), (6, 6.12), (0, 0.13)]
    p = v.verify(samples=samples)
    assert p.status is VerdictStatus.CONFIRMED
    assert 0.9 <= p.evidence["slope_k"] <= 1.1


def test_timing_recovers_loop_multiplier_k3():
    v = LinearRegressionTimingVerifier()
    # each injected second costs ~3s (3-row loop): slope ~= 3
    samples = [(0, 0.1), (1, 3.1), (2, 6.0), (3, 9.2)]
    p = v.verify(samples=samples, min_slope=0.8)
    assert p.status is VerdictStatus.CONFIRMED and p.evidence["slope_k"] > 2.5


def test_timing_false_positive_on_jitter():
    v = LinearRegressionTimingVerifier()
    samples = [(0, 3.0), (2, 0.2), (4, 5.0), (6, 0.1)]   # no correlation
    p = v.verify(samples=samples)
    assert p.status is VerdictStatus.FALSE_POSITIVE


# ---- State-machine wiring -----------------------------------------------------
def test_evaluator_falls_back_without_structured_data():
    h = Hypothesis("h", "x")
    assert deterministic_evaluator(h, PlanStep("c"),
                                   ExecResult(stdout="uid=0", exit_code=0)) is Status.CONFIRMED
    assert deterministic_evaluator(h, PlanStep("c"),
                                   ExecResult(stdout="nope", exit_code=0)) is Status.NEEDS_REFINEMENT


def test_false_positive_maps_to_blocked_immediately():
    def analyze(_):
        return [Hypothesis("fp", "SSTI?", priority=1.0)]

    def plan(h, fb):
        return [PlanStep("inject")]

    def execute(step):
        return ExecResult(stdout="syntax error", exit_code=0, structured_data={
            "verifier": "algebraic_canary",
            "payload": {"baseline_stdout": "x", "mutated_stdout": "syntax error",
                        "factor_a": 6947, "factor_b": 6989}})

    team = CoRedTeam(analyze, plan, executor=execute, evaluator=deterministic_evaluator)
    h = team.run({})[0]
    assert h.status is Status.BLOCKED
    assert h.attempts == 1                       # disproven -> no wasted retries
    assert any("false-positive" in m for m in team.log)


def test_inconclusive_resamples_then_blocks_on_budget():
    def analyze(_):
        return [Hypothesis("inc", "SSTI?", priority=1.0)]

    def plan(h, fb):
        return [PlanStep("inject")]

    def execute(step):
        # product AND raw expression both present -> always INCONCLUSIVE
        return ExecResult(stdout="6947*6989 = 48552583", exit_code=0, structured_data={
            "verifier": "algebraic_canary",
            "payload": {"baseline_stdout": "x", "mutated_stdout": "6947*6989 = 48552583",
                        "factor_a": 6947, "factor_b": 6989}})

    team = CoRedTeam(analyze, plan, executor=execute,
                     evaluator=deterministic_evaluator, max_verify_retries=2)
    h = team.run({})[0]
    assert h.status is Status.BLOCKED
    assert h.verify_attempts == 3                # 2 resamples allowed, 3rd trips the budget
    assert h.attempts == 1                       # refunded: noise never ate the refine budget
    assert sum("resample (inconclusive #" in m for m in team.log) == 2


# ---- OOB interaction verifier -------------------------------------------------
def test_oob_confirmed_on_high_entropy_token():
    v = OOBInteractionVerifier()
    p = v.verify(token="oob-1234567890abcdef1234567890abcdef", received=True,
                 interaction_count=2, first_path="/oob-1234567890abcdef1234567890abcdef")
    assert p.status is VerdictStatus.CONFIRMED
    assert p.confidence == 1.0


def test_oob_false_positive_when_not_received():
    v = OOBInteractionVerifier()
    p = v.verify(token="oob-1234567890abcdef1234567890abcdef", received=False)
    assert p.status is VerdictStatus.FALSE_POSITIVE
    assert p.confidence == 0.0


def test_oob_inconclusive_on_low_entropy_token():
    v = OOBInteractionVerifier()
    p = v.verify(token="short", received=True, interaction_count=1)
    assert p.status is VerdictStatus.INCONCLUSIVE
    assert p.confidence == 0.5


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)

