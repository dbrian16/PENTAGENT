"""experience_replay.py: cross-campaign memory + gradient-free JitRL (Pillar 4)."""
from __future__ import annotations

from agentpentest.experience_replay import (JitRL, ReplayBuffer, Step, Trajectory,
                                            jitrl_strategist)


def _buf() -> ReplayBuffer:
    b = ReplayBuffer()
    b.add(Trajectory("ad-enterprise", [Step("T1558", 1.0), Step("T1110", -0.5)],
                     outcome="success", strategy_notes=["Kerberos before SMB spray"]))
    b.add(Trajectory("ad-enterprise", [Step("T1558", 0.8), Step("T1110", -0.4)],
                     outcome="partial"))
    return b


def test_discounted_returns_credit_following_rewards():
    t = Trajectory("x", [Step("a", 1.0), Step("b", -0.5)])
    r = t.discounted_returns(gamma=0.9)
    assert abs(r["a"] - (1.0 + 0.9 * -0.5)) < 1e-9
    assert abs(r["b"] - (-0.5)) < 1e-9


def test_advantage_rewards_good_tool_penalizes_blocked():
    adv = JitRL(_buf()).advantage("ad-enterprise")
    assert adv["T1558"] > 0 > adv["T1110"], adv


def test_jitrl_overrides_weak_prior():
    jit = JitRL(_buf())
    ranked = jit.adjust([("T1110", 0.6), ("T1558", 0.5)], "ad-enterprise")
    assert ranked[0][0] == "T1558", ranked        # history beats the 0.1 prior gap


def test_strategy_memory_dedupes():
    b = _buf()
    assert b.strategy_memory("ad-enterprise") == ["Kerberos before SMB spray"]
    assert b.strategy_memory("web-app") == []


def test_buffer_json_roundtrip():
    b2 = ReplayBuffer.from_json(_buf().to_json())
    assert len(b2) == 2 and JitRL(b2).advantage("ad-enterprise")["T1558"] > 0


def test_jitrl_strategist_picks_best_technique():
    class N:
        def __init__(self, nid, tech): self.id, self.technique = nid, tech
    strat = jitrl_strategist(JitRL(_buf()), "ad-enterprise")
    chosen = strat([N("n1", "T1110"), N("n2", "T1558")])
    assert chosen == "n2"


def test_empty_buffer_strategist_returns_none():
    strat = jitrl_strategist(JitRL(ReplayBuffer()), "ad-enterprise")

    class N:
        id, technique = "n1", "T1190"
    assert strat([N()]) is None                    # no history -> defer to TDA


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
