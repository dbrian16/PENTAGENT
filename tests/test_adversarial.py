"""Phase 4 Red-vs-Blue: WAF simulator, multiplicative reward, adversarial loop."""
import os
import tempfile

from agentpentest import blueteam, reward
from agentpentest.adversarial import EpisodicMemory, adversarial_loop, reflect


def test_blue_anomaly_scoring():
    # raw SQLi crosses the threshold -> blocked
    v = blueteam.evaluate({"payload": "' OR 1=1", "user_agent": "Mozilla/5.0"}, paranoia=1)
    assert v.is_blocked and v.anomaly_score >= 5 and any("942100" in r for r in v.triggered_rules)
    # a clean request is allowed
    assert not blueteam.evaluate({"payload": "/search?q=hi", "user_agent": "Mozilla/5.0"}).is_blocked
    # scanner UA + flood: behavioural signals alone block it
    noisy = blueteam.evaluate({"payload": "/admin", "user_agent": "gobuster/3.1",
                               "rate_per_s": 100, "error_404": 500})
    assert noisy.is_blocked and "request_rate" in noisy.noise


def test_blue_paranoia_escalation():
    obf = {"payload": "'/**/OR/**/1=1", "user_agent": "Mozilla/5.0"}
    assert not blueteam.evaluate(obf, paranoia=1).is_blocked   # evades PL1
    assert blueteam.evaluate(obf, paranoia=2).is_blocked       # caught at PL2


def test_multiplicative_reward_kills_hacking():
    assert reward.multiplicative_reward(1, 0, 0) == 0.0        # harmless payload -> 0
    assert reward.multiplicative_reward(0, 1, 0) == 0.0        # blocked -> 0
    assert reward.multiplicative_reward(1, 1, 20) == 0.0       # too loud -> 0
    assert reward.multiplicative_reward(1, 1, 0) == 1.0        # stealthy + effective
    assert reward.intent_intact("' OR 1=1") == 1.0 and reward.intent_intact("hello") == 0.0


def test_best_of_n_group_relative():
    best, r, adv = reward.best_of_n([{"r": 0.1}, {"r": 0.9}, {"r": 0.5}], lambda c: c["r"])
    assert best["r"] == 0.9 and abs(r - 0.9) < 1e-9
    assert abs(adv[1] - 0.4) < 1e-9 and abs(sum(adv)) < 1e-9   # advantages centre on the mean


def test_loop_behavioural_convergence():
    executed = []
    res = adversarial_loop("find admin",
                           {"payload": "/admin", "user_agent": "gobuster/3.1",
                            "rate_per_s": 100, "error_404": 500},
                           paranoia=1, execute=lambda a: executed.append(a))
    assert res.status == "accepted" and "gobuster" not in res.action["user_agent"]
    assert not res.verdict.is_blocked and executed            # stealthy action was executed (sim)


def test_loop_mutation_ladder_pl1_to_pl4_hitl():
    # PL1: inline-comment obfuscation slips the SQLi through -> accepted
    ex1 = []
    r1 = adversarial_loop("dump users",
                          {"payload": "' OR 1=1", "user_agent": "sqlmap/1.5",
                           "rate_per_s": 30, "error_404": 50},
                          paranoia=1, execute=lambda a: ex1.append(a))
    assert r1.status == "accepted" and "/**/" in r1.action["payload"] and ex1
    # PL2: /**/ is caught, so Red escalates to a Unicode/URL-encoding variant -> still accepted,
    # and the evasion keeps the exploit primitive (decoded intent intact).
    r2 = adversarial_loop("dump users",
                          {"payload": "' OR 1=1", "user_agent": "sqlmap/1.5",
                           "rate_per_s": 30, "error_404": 50}, paranoia=2)
    assert r2.status == "accepted" and "/**/" not in r2.action["payload"]
    assert reward.intent_intact(r2.action["payload"]) == 1.0
    # PL4: every encoding is decoded/flagged -> retry cap -> human-in-the-loop, nothing executed
    ex4 = []
    r4 = adversarial_loop("dump users",
                          {"payload": "' OR 1=1", "user_agent": "sqlmap/1.5",
                           "rate_per_s": 30, "error_404": 50},
                          paranoia=4, max_retries=3, execute=lambda a: ex4.append(a))
    assert r4.status == "human_intervention" and not ex4 and r4.memory.lessons


def test_mutation_transforms_escalate_by_pl():
    from agentpentest.adversarial import red_plan, EpisodicMemory
    act = {"payload": "' OR 1=1", "user_agent": "sqlmap/1.5", "rate_per_s": 30}
    # Red picks a variant that bypasses each PL (and keeps intent) until PL4 walls it.
    for pl in (1, 2, 3):
        best = red_plan("x", act, EpisodicMemory(), paranoia=pl)
        assert not blueteam.evaluate(best, pl).is_blocked
        assert reward.intent_intact(best["payload"]) == 1.0
    # PL4: no mutation both bypasses and keeps the primitive -> best offered is still blocked.
    best4 = red_plan("x", act, EpisodicMemory(), paranoia=4)
    assert blueteam.evaluate(best4, 4).is_blocked


def test_reflect_and_memory_checkpoint():
    v = blueteam.evaluate({"payload": "' OR 1=1", "user_agent": "sqlmap/1.5"}, paranoia=1)
    lesson = reflect({"payload": "' OR 1=1"}, v)
    assert "SQLi" in lesson or "User-Agent" in lesson
    mem = EpisodicMemory(); mem.add(lesson); mem.add(lesson)      # dedup
    assert len(mem.lessons) == 1
    fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
    try:
        mem.save(path)
        assert EpisodicMemory.load(path).lessons == mem.lessons
    finally:
        os.remove(path)


def test_campaign_blue_gate_flags_noisy_by_pl():
    from agentpentest.orchestrator import run_recon
    from agentpentest.campaign import build_tree, run
    state = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)

    # PL1: the Red agent can make the web exploit stealthy -> not flagged
    t1 = build_tree(state, paranoia=1)
    web1 = [n for n in t1.nodes.values() if n.technique == "T1190"]
    assert web1 and all(not n.noisy and n.stealth > 0.9 for n in web1)

    # PL4: encoding is exhausted (decoded/flagged) -> Red can't make it stealthy -> noisy
    t4 = build_tree(state, paranoia=4)
    web4 = [n for n in t4.nodes.values() if n.technique == "T1190"]
    assert web4 and any(n.noisy for n in web4) and all(n.stealth < 1.0 for n in web4)

    # end-to-end report surfaces the stealth column + a noisy warning at PL4
    _, md = run("example.com", paranoia=4)
    assert "Stealth" in md and "noisy" in md.lower()


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok")
