"""Verified kill-chain: the driver advances only on a CONFIRMED verdict, reroutes around a
BLOCKED hop, stops at a dead end, and lets a harvested credential open a route that did not
exist before. State is the KnowledgeGraph; routing is DecisionEngine; the gate is the verdict."""
from agentpentest.attack_graph import DecisionEngine, PathScorer
from agentpentest.killchain import KillChain, deterministic_gate
from agentpentest.knowledge_graph import KnowledgeGraph
from agentpentest.verifiers import VerdictStatus


def _chain(graph, start, objective, actor, max_hops=16):
    engine = DecisionEngine(PathScorer(graph))
    kc = KillChain(graph, engine, actor, objective=objective, start=start, max_hops=max_hops)
    return kc, kc.run()


def _actor(block=(), creds=None):
    """Sim actor: CONFIRMED unless (frm,to) is in `block`; loots `creds[to]` on confirm."""
    creds = creds or {}
    block = set(block)

    def act(frm, to, rel, graph):
        v = "BLOCKED" if (frm, to) in block else "CONFIRMED"
        looted = creds.get(to, ()) if v == "CONFIRMED" else ()
        return v, f"{frm}->{to}", tuple(looted)
    return act


def _g(edges):
    g = KnowledgeGraph("lab")
    for src, dst, rel in edges:
        g.add_edge(src, dst, rel)
    return g


# ---- deterministic gate -------------------------------------------------------
def test_gate_confirms_real_proof_and_shrugs_at_junk():
    sd = {"verifier": "algebraic_canary",
          "payload": {"baseline_stdout": "x", "mutated_stdout": "48552583",
                      "factor_a": 6947, "factor_b": 6989}}
    assert deterministic_gate(sd) == VerdictStatus.CONFIRMED.value
    assert deterministic_gate({}) == VerdictStatus.INCONCLUSIVE.value


# ---- straight chain -----------------------------------------------------------
def test_reaches_objective_on_all_confirmed():
    g = _g([("me", "a", "LEADS_TO"), ("a", "b", "LEADS_TO"), ("b", "DC", "ADMIN_TO")])
    kc, trace = _chain(g, "me", "DC", _actor())
    assert kc.reached
    assert {"me", "a", "b", "DC"} <= kc.compromised
    assert g.nodes["DC"].props.get("compromised") is True
    assert [h.to for h in trace] == ["a", "b", "DC"]


# ---- reroute around a blocked hop --------------------------------------------
def test_reroutes_when_a_hop_is_disproven():
    g = _g([("me", "a", "LEADS_TO"), ("a", "DC", "ADMIN_TO"),
            ("a", "b", "LEADS_TO"), ("b", "DC", "ADMIN_TO")])
    kc, trace = _chain(g, "me", "DC", _actor(block=[("a", "DC")]))
    assert kc.reached                                   # found the b route
    assert any(h.to == "DC" and h.frm == "a" and h.verdict == "BLOCKED" for h in trace)
    assert any(h.to == "DC" and h.verdict == "CONFIRMED" for h in trace)


# ---- dead end -----------------------------------------------------------------
def test_stops_at_a_dead_end():
    g = _g([("me", "a", "LEADS_TO"), ("a", "DC", "ADMIN_TO")])
    kc, trace = _chain(g, "me", "DC", _actor(block=[("a", "DC")]))
    assert not kc.reached
    assert "DC" not in kc.compromised
    assert any(h.verdict == "BLOCKED" for h in trace)


# ---- credential harvest opens a route that did not exist ----------------------
def _cred_graph():
    # me -> jump exists; svc -ADMIN_TO-> DC exists; but jump is NOT linked to svc yet.
    g = _g([("me", "jump", "LEADS_TO"), ("user:svc", "DC", "ADMIN_TO")])
    g.add_node("DC", "host", "DC")
    g.add_node("user:svc", "identity", "svc")
    return g


def test_harvested_cred_unlocks_the_final_hop():
    g = _cred_graph()
    # looting user:svc at jump adds jump -HAS_CRED-> user:svc, opening jump->svc->DC.
    kc, trace = _chain(g, "me", "DC", _actor(creds={"jump": ("user:svc",)}))
    assert kc.reached
    assert any(h.rel == "HAS_CRED" or h.to == "user:svc" for h in trace)


def test_without_the_cred_the_objective_is_unreachable():
    g = _cred_graph()
    kc, trace = _chain(g, "me", "DC", _actor())   # same graph, no loot
    assert not kc.reached
    assert "DC" not in kc.compromised


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
