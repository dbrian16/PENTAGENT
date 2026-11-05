"""SimulationOracle: a stateful virtual target with causal preconditions and seeded dice."""
from agentpentest.simworld import SimulationOracle, TECHNIQUES
from agentpentest.ptt import Evidence, PentestTree
from agentpentest import chain, campaign


def _node(tech):
    t = PentestTree("x")
    nid = t.add("goal", t.root_id, Evidence.SPECULATIVE, tech)
    return t.nodes[nid]


def test_preconditions_gate_postexploit():
    o = SimulationOracle(stochastic=False)
    # privesc / lateral must fail before any foothold or creds exist.
    assert o(_node("T1068")) == (False, Evidence.SPECULATIVE)
    assert o(_node("T1210")) == (False, Evidence.SPECULATIVE)
    assert "root" not in o.world and "lateral" not in o.world


def test_causal_chain_opens_in_order():
    o = SimulationOracle(stochastic=False)   # preconditions only, no dice
    assert o(_node("T1190")) == (True, Evidence.VERIFIED)    # initial access
    assert "foothold" in o.world
    assert o(_node("T1068")) == (True, Evidence.VERIFIED)    # now privesc works
    assert "root" in o.world
    assert o(_node("T1078")) == (True, Evidence.VERIFIED)    # creds via foothold
    assert o(_node("T1210")) == (True, Evidence.VERIFIED)    # lateral needs creds
    assert o.domain_admin()                                  # root + lateral reached


def test_unknown_technique_fails():
    assert SimulationOracle()( _node("T9999")) == (False, Evidence.SPECULATIVE)


def test_dice_can_fail_a_met_precondition():
    # T1110 needs no precondition but has prob 0.6: across seeds, both outcomes appear.
    results = [SimulationOracle(seed=s)(_node("T1110"))[0] for s in range(20)]
    assert any(results) and not all(results)


def test_oracle_vocabulary_matches_chain_followons():
    # Every follow-on technique chain.py can emit must be judgeable by the oracle,
    # or that branch would always fail - the bug this oracle fixes.
    emitted = {t for pairs in chain.FOLLOW_ONS.values() for t, _ in pairs}
    emitted |= set(chain.FOLLOW_ONS)           # and every trigger technique too
    assert emitted <= set(TECHNIQUES)


def test_campaign_reaches_multiple_stages():
    # End to end: the stateful oracle should drive the tree past a single T1190 node.
    tree, md = campaign.run("example.com", quiet=True,
                            oracle=SimulationOracle(stochastic=False))
    landed = {n.technique for n in tree.nodes.values() if n.status == "success"}
    assert "T1190" in landed and len(landed) >= 3   # recon foothold + real post-exploit
