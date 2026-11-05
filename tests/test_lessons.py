"""Cross-engagement lesson store: durable priors nudge hypothesis priority on the next
engagement, but a prior can only REORDER the analyzer's own hypotheses -- it never adds a
finding and never touches the deterministic verdict."""
from agentpentest.lessons import (LessonStore, boost_priority, laplace_rate,
                                   prior_boosting_analyzer, record_hypotheses)
from agentpentest.statemachine import Hypothesis, Status


def test_laplace_rate_unseen_is_half():
    assert laplace_rate(0, 0) == 0.5
    assert laplace_rate(4, 0) > 0.8
    assert laplace_rate(0, 4) < 0.2


def test_boost_unseen_leaves_base_untouched():
    assert boost_priority(0.5, 0.5, 0) == 0.5          # no samples -> no nudge
    assert boost_priority(0.6, 0.99, 0) == 0.6


def test_boost_scales_with_evidence():
    weak = boost_priority(0.5, 0.9, 1)
    strong = boost_priority(0.5, 0.9, 50)
    assert 0.5 < weak < strong <= 1.0                  # more samples -> bigger nudge
    # a strong disprove history pulls priority DOWN
    assert boost_priority(0.5, 0.05, 50) < 0.5


def test_record_and_confirm_rate():
    s = LessonStore()
    s.record("web-app", "http", "T1190", confirmed=True)
    s.record("web-app", "http", "T1190", confirmed=True)
    s.record("web-app", "http", "T1190", confirmed=False)
    rate, n = s.confirm_rate("web-app", "T1190")
    assert n == 3 and rate == laplace_rate(2, 1)
    s.close()


def test_priors_ranked_by_rate():
    s = LessonStore()
    for _ in range(4):
        s.record("web-app", "*", "T1190", confirmed=True)
    s.record("web-app", "*", "IDOR", confirmed=False)
    pr = s.priors("web-app")
    assert pr[0]["technique"] == "T1190"               # higher confirm rate ranks first
    assert pr[0]["rate"] > pr[1]["rate"]
    s.close()


def test_graph_export():
    s = LessonStore()
    s.record("web-app", "*", "T1190", confirmed=True)
    s.record("ad-enterprise", "*", "T1110", confirmed=True)
    g = s.graph()
    assert set(g["profiles"]) == {"web-app", "ad-enterprise"}
    assert {"T1190", "T1110"} <= set(g["techniques"])
    assert all("rate" in e and "profile" in e for e in g["edges"])
    s.close()


def test_persists_across_reopen(tmp_path):
    p = tmp_path / "lessons.sqlite"
    s1 = LessonStore(p)
    s1.record("web-app", "*", "T1190", confirmed=True)
    s1.close()
    s2 = LessonStore(p)                                # new engagement, same ledger file
    rate, n = s2.confirm_rate("web-app", "T1190")
    assert n == 1 and rate > 0.5
    s2.close()


def test_prior_boosting_analyzer_reorders_but_preserves_set():
    s = LessonStore()
    for _ in range(10):
        s.record("web-app", "*", "T1190", confirmed=True)   # strong SSTI prior

    def base(_ctx):
        return [Hypothesis("h1", "SSTI", technique="T1190", priority=0.5),
                Hypothesis("h2", "weak creds", technique="T1110", priority=0.5)]

    boosted = prior_boosting_analyzer(base, s, "web-app")({})
    by_id = {h.id: h for h in boosted}
    assert len(boosted) == 2                                # nothing added/removed
    assert by_id["h1"].priority > 0.5                       # SSTI boosted by the prior
    assert by_id["h2"].priority == 0.5                      # unseen technique untouched
    s.close()


def test_record_hypotheses_only_terminal_verdicts():
    s = LessonStore()
    confirmed = Hypothesis("h1", "SSTI", technique="T1190"); confirmed.status = Status.CONFIRMED
    blocked = Hypothesis("h2", "XXE", technique="T1190"); blocked.status = Status.BLOCKED
    pending = Hypothesis("h3", "noise", technique="T9999"); pending.status = Status.INCONCLUSIVE
    n = record_hypotheses(s, "web-app", [confirmed, blocked, pending])
    assert n == 2                                           # inconclusive is not a lesson
    rate, cnt = s.confirm_rate("web-app", "T1190")
    assert cnt == 2                                         # one confirm + one disprove
    assert s.confirm_rate("web-app", "T9999")[1] == 0       # nothing learned from noise
    s.close()


def test_cross_engagement_flow(tmp_path):
    """Engagement 1 confirms SSTI on a web-app; engagement 2 starts with SSTI boosted."""
    p = tmp_path / "lessons.sqlite"
    s1 = LessonStore(p)
    h = Hypothesis("h1", "SSTI", technique="T1190"); h.status = Status.CONFIRMED
    record_hypotheses(s1, "web-app", [h])
    s1.close()

    s2 = LessonStore(p)
    def base(_):
        return [Hypothesis("x", "SSTI again", technique="T1190", priority=0.4)]
    out = prior_boosting_analyzer(base, s2, "web-app")({})
    assert out[0].priority > 0.4
    s2.close()


if __name__ == "__main__":
    import tempfile, pathlib
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            if "tmp_path" in fn.__code__.co_varnames:
                with tempfile.TemporaryDirectory() as d:
                    fn(pathlib.Path(d))
            else:
                fn()
            print("ok", name)
