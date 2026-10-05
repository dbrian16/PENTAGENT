"""Post-exploit chaining (chain.expand) + EGATS's expander hook + PTT.compact()."""
from __future__ import annotations

from agentpentest import chain
from agentpentest.brain import EGATS
from agentpentest.ptt import Evidence, PentestTree


def test_expand_noop_below_confirmed():
    t = PentestTree("x")
    n = t.nodes[t.add("web", t.root_id, Evidence.PLAUSIBLE, "T1190")]
    assert chain.expand(n, t) == []
    assert n.children == []


def test_expand_adds_known_follow_ons():
    t = PentestTree("x")
    nid = t.add("web", t.root_id, Evidence.VERIFIED, "T1190")
    n = t.nodes[nid]
    added = chain.expand(n, t)
    techs = sorted(t.nodes[c].technique for c in added)
    assert "T1005" in techs and "T1078" in techs
    assert len(added) == len(chain.FOLLOW_ONS["T1190"])
    assert all(t.nodes[c].evidence is Evidence.SPECULATIVE for c in added)


def test_expand_is_idempotent_no_duplicates():
    t = PentestTree("x")
    nid = t.add("web", t.root_id, Evidence.VERIFIED, "T1190")
    n = t.nodes[nid]
    first = chain.expand(n, t)
    second = chain.expand(n, t)      # calling again must not duplicate children
    assert second == []
    assert len(n.children) == len(first)


def test_expand_respects_depth_cap():
    t = PentestTree("x")
    parent = t.root_id
    node = None
    for i in range(chain.MAX_CHAIN_DEPTH + 2):
        nid = t.add(f"n{i}", parent, Evidence.VERIFIED, "T1190")
        node = t.nodes[nid]
        parent = nid
    assert chain.expand(node, t) == [], "must not chain past the depth cap"


def test_expand_unknown_technique_is_quiet_noop():
    t = PentestTree("x")
    n = t.nodes[t.add("odd", t.root_id, Evidence.VERIFIED, "T9999")]
    assert chain.expand(n, t) == []


def test_egats_expander_hook_grows_frontier_on_success():
    t = PentestTree("x")
    nid = t.add("web", t.root_id, Evidence.PLAUSIBLE, "T1190")

    def oracle(node):
        # only the ORIGINAL node succeeds; chained children fail (no loop).
        return (True, Evidence.VERIFIED) if node.id == nid else (False, Evidence.SPECULATIVE)

    EGATS(t, oracle, expander=chain.expand, max_steps=50).run()
    assert t.nodes[nid].status == "success"
    pivots = [n for n in t.nodes.values() if "pivot from" in n.goal]
    assert len(pivots) == len(chain.FOLLOW_ONS["T1190"]), "expander must have added the T1190 follow-ons"
    assert all(n.status == "abandoned" for n in pivots), "they fail the oracle and backtrack"
    assert not t.frontier()                      # search still terminates cleanly


def test_egats_without_expander_tree_stays_flat():
    t = PentestTree("x")
    nid = t.add("web", t.root_id, Evidence.PLAUSIBLE, "T1190")
    EGATS(t, lambda n: (True, Evidence.VERIFIED), max_steps=10).run()   # no expander=
    assert len(t.nodes) == 2, "default behaviour (no expander) must be unchanged"


def test_compact_clears_abandoned_commands_keeps_lineage():
    t = PentestTree("x")
    n = t.nodes[t.add("dead end", t.root_id, Evidence.SPECULATIVE, "T1110")]
    n.commands.append("hydra -l root -P wordlist.txt ssh://target")
    t.abandon(n.id)
    trimmed = t.compact()
    assert trimmed == 1
    assert n.commands == []
    assert n.status == "abandoned" and n.technique == "T1110"   # lineage kept


def test_compact_leaves_open_and_success_nodes_alone():
    t = PentestTree("x")
    n = t.nodes[t.add("open", t.root_id, Evidence.PLAUSIBLE, "T1190")]
    n.commands.append("sqlmap -u target --batch")
    assert t.compact() == 0
    assert n.commands == ["sqlmap -u target --batch"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
