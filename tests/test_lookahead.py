"""Look-ahead planner: one generator call feeds several attempts, cutting model round-trips,
while a Reflector reframe still forces a fresh, context-aware plan."""
import json

from agentpentest.lookahead import (directive_to_step, lookahead_planner,
                                     multi_candidate_planner)
from agentpentest.statemachine import Hypothesis, PlanStep


def _steps(*names):
    return [PlanStep(n) for n in names]


# ---- directive_to_step --------------------------------------------------------
def test_directive_probe_becomes_probe_step():
    s = directive_to_step({"probe": "ssti", "params": {"factor_a": 11}})
    assert s.kind == "probe"
    assert json.loads(s.action) == {"probe": "ssti", "params": {"factor_a": 11}}


def test_directive_action_and_fallback():
    assert directive_to_step({"action": "nmap -sV t"}).action == "nmap -sV t"
    # an unresolvable tool with a raw action falls back to the action
    s = directive_to_step({"tool": "__nope__", "params": {}, "action": "curl t"})
    assert s.action == "curl t"


def test_directive_non_actionable_is_none():
    assert directive_to_step({}) is None
    assert directive_to_step("not a dict") is None
    assert directive_to_step({"rationale": "no action here"}) is None


# ---- lookahead_planner --------------------------------------------------------
def test_one_generate_call_feeds_many_attempts():
    calls = {"n": 0}

    def generate(h, fb):
        calls["n"] += 1
        return _steps("a", "b", "c")

    plan = lookahead_planner(generate, max_plan=5)
    h = Hypothesis("h1", "x")
    assert plan(h, [])[0].action == "a"
    assert plan(h, [])[0].action == "b"
    assert plan(h, [])[0].action == "c"
    assert calls["n"] == 1                       # three attempts, ONE model call


def test_cache_regenerates_when_exhausted():
    batches = [_steps("a"), _steps("b")]
    calls = {"n": 0}

    def generate(h, fb):
        out = batches[calls["n"]]
        calls["n"] += 1
        return out

    plan = lookahead_planner(generate)
    h = Hypothesis("h1", "x")
    assert plan(h, [])[0].action == "a"
    assert plan(h, [])[0].action == "b"          # cache emptied -> regenerated
    assert calls["n"] == 2


def test_reflector_reframe_invalidates_cache():
    calls = {"n": 0}

    def generate(h, fb):
        calls["n"] += 1
        return _steps("a", "b", "c")

    plan = lookahead_planner(generate)
    h = Hypothesis("h1", "x")
    assert plan(h, [])[0].action == "a"
    # a REFLECTOR note arrives -> drop the stale alternatives, regenerate immediately
    assert plan(h, ["REFLECTOR: change the technique"])[0].action == "a"
    assert calls["n"] == 2


def test_max_plan_caps_candidates():
    plan = lookahead_planner(lambda h, fb: _steps(*"abcdefghij"), max_plan=3)
    h = Hypothesis("h1", "x")
    got = [plan(h, [])[0].action for _ in range(3)]
    assert got == ["a", "b", "c"]
    assert plan(h, [])[0].action == "a"          # 4th attempt regenerated a fresh batch


def test_empty_generate_returns_no_step():
    plan = lookahead_planner(lambda h, fb: [])
    assert plan(Hypothesis("h1", "x"), []) == []


def test_independent_caches_per_hypothesis():
    plan = lookahead_planner(lambda h, fb: _steps(f"{h.id}-a", f"{h.id}-b"))
    h1, h2 = Hypothesis("h1", "x"), Hypothesis("h2", "y")
    assert plan(h1, [])[0].action == "h1-a"
    assert plan(h2, [])[0].action == "h2-a"      # h2 has its own cache
    assert plan(h1, [])[0].action == "h1-b"


# ---- multi_candidate_planner (LLM) --------------------------------------------
class _StubReasoner:
    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    def ask(self, system, user):
        self.calls += 1
        return self.reply


def test_multi_candidate_parses_and_drops_junk():
    reply = json.dumps({"candidates": [
        {"probe": "ssti", "params": {"factor_a": 11, "factor_b": 13}, "rationale": "r1"},
        {"action": "nmap -sV t", "rationale": "r2"},
        {"rationale": "non-actionable, must be dropped"},
    ]})
    gen = multi_candidate_planner(_StubReasoner(reply), {"t"}, n=5)
    h = Hypothesis("h1", "SSTI?", technique="T1190", evidence="reflected")
    steps = gen(h, [])
    assert len(steps) == 2                         # the junk candidate dropped
    assert steps[0].kind == "probe" and steps[1].action == "nmap -sV t"


def test_multi_candidate_composes_with_lookahead():
    reply = json.dumps({"candidates": [{"action": "a"}, {"action": "b"}]})
    stub = _StubReasoner(reply)
    plan = lookahead_planner(multi_candidate_planner(stub, {"t"}))
    h = Hypothesis("h1", "x")
    assert plan(h, [])[0].action == "a"
    assert plan(h, [])[0].action == "b"
    assert stub.calls == 1                         # two attempts, one LLM call


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
