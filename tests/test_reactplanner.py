"""ReAct planner: the reasoner picks among the legal frontier; a bad reply falls back."""
from agentpentest.reactplanner import ReActPlanner
from agentpentest.planner import Planner
from agentpentest.state import ReconState, Service


def _state_with_two_http() -> ReconState:
    # Two http services -> dir_enum + vuln_scan on each = a 4-task frontier to choose from.
    s = ReconState(domain="example.com")
    s.add_service("example.com", Service(80, "tcp", "http", "nginx"))
    s.hosts["example.com"].scanned = True
    return s


class _FixedReasoner:
    def __init__(self, reply): self.reply = reply; self.calls = 0
    def ask(self, system, user, *, json_mode=False):
        self.calls += 1
        assert json_mode is True          # planner must request JSON mode
        return self.reply


def test_reasoner_choice_is_honored():
    s = _state_with_two_http()
    cands = list(Planner().next_tasks(s))
    assert len(cands) > 1
    r = _FixedReasoner('{"choice": 1}')
    first = next(ReActPlanner(r).next_tasks(s))
    assert first == cands[1]              # model's pick, not the rule-order first
    assert r.calls == 1


def test_all_candidates_still_yielded():
    s = _state_with_two_http()
    cands = set(map(str, Planner().next_tasks(s)))
    got = set(map(str, ReActPlanner(_FixedReasoner('{"choice": 1}')).next_tasks(s)))
    assert got == cands                   # selection reorders, never drops work


def test_garbage_reply_falls_back_to_rule_order():
    s = _state_with_two_http()
    cands = list(Planner().next_tasks(s))
    for bad in ("not json", '{"choice": 99}', '{"nope": 1}', ""):
        first = next(ReActPlanner(_FixedReasoner(bad)).next_tasks(s))
        assert first == cands[0]


def test_single_candidate_skips_the_model():
    s = ReconState(domain="example.com")  # only subdomain_enum is ready
    r = _FixedReasoner('{"choice": 0}')
    next(ReActPlanner(r).next_tasks(s))
    assert r.calls == 0                   # no point asking when there is one choice


def test_has_work_matches_base():
    s = _state_with_two_http()
    r = _FixedReasoner('{"choice": 0}')
    assert ReActPlanner(r).has_work(s) == Planner().has_work(s)
