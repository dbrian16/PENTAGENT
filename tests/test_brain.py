"""Checks for Phase 3 (Brain) + Phase 4 (swarm/report). `python test_brain.py`."""
import agentpentest.report as report
from agentpentest.brain import EGATS, assess, MAX_FAIL_STREAK
from agentpentest.campaign import build_tree, simulated_oracle
from agentpentest.ptt import Evidence, PentestTree
from agentpentest.swarm import debate
from agentpentest.orchestrator import run_recon


def test_ptt_math():
    t = PentestTree("x", context_budget=1000)
    a = t.add("service A", t.root_id, Evidence.PLAUSIBLE)
    # Laplace: no attempts -> 0.5, not 1.0
    assert abs(t.success_rate(a) - 0.5) < 1e-9
    t.record(a, False); t.record(a, False)
    assert t.success_rate(a) == (0 + 1) / (2 + 2)     # 0.25
    # path confidence excludes the root's NONE
    assert abs(t.path_confidence(a) - 0.5) < 1e-9
    # abandoning a branch drops it out of the context load
    before = t.context_load()
    t.abandon(a)
    assert t.context_load() < before


def test_backtrack_triggers():
    t = PentestTree("x")
    n = t.nodes[t.add("weak branch", t.root_id, Evidence.SPECULATIVE)]
    for _ in range(MAX_FAIL_STREAK):
        t.record(n.id, False)
    a = assess(n, t, est_steps=5)
    assert a.backtrack and "fail_streak" in a.reason


def test_egats_abandons_failing_branch_no_loop():
    # branch B always fails; branch G always succeeds. The search must reach G and
    # abandon B WITHOUT looping forever on B. This is the whole point of the Brain.
    t = PentestTree("x")
    host = t.add("host", t.root_id, Evidence.CONFIRMED); t.nodes[host].status = "success"
    bad = t.add("bad (ssh brute)", host, Evidence.SPECULATIVE, "T1110")
    good = t.add("good (web)", host, Evidence.PLAUSIBLE, "T1190")

    def oracle(node):
        return (True, Evidence.VERIFIED) if node.technique == "T1190" else (False, Evidence.SPECULATIVE)

    EGATS(t, oracle, max_steps=50).run()
    assert t.nodes[good].status == "success"
    assert t.nodes[bad].status == "abandoned"          # gave up, didn't loop
    assert not t.frontier()                            # search terminated cleanly


def test_swarm_consensus():
    c = debate({"address": "h", "port": 80, "name": "http", "version": "nginx 1.18.0"})
    assert c and c.technique == "T1190" and c.votes >= 2   # multiple roles agree


def test_report_excludes_failures_and_maps_mitre():
    state = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)
    tree = build_tree(state)
    EGATS(tree, simulated_oracle).run()
    md = report.generate(tree)
    assert "MITRE ATT&CK" in md and "T1190" in md
    assert "Remediation" in md
    # failed ssh branches (T1110) were abandoned -> not a reported finding
    assert "## Findings" in md
    assert "brute" not in md.lower()


if __name__ == "__main__":
    test_ptt_math()
    test_backtrack_triggers()
    test_egats_abandons_failing_branch_no_loop()
    test_swarm_consensus()
    test_report_excludes_failures_and_maps_mitre()
    print("ok")
