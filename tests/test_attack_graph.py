"""Tests for agentpentest.attack_graph: PathScorer, DecisionEngine, choke points, and JSON serialization."""
import json
import pytest
from agentpentest.attack_graph import (
    AttackPath,
    DecisionEngine,
    PathScorer,
    build_attack_json,
    load_attack_json,
)
from agentpentest.knowledge_graph import KnowledgeGraph


def _sample_graph() -> KnowledgeGraph:
    g = KnowledgeGraph("lab.internal")
    g.from_bloodhound({
        "users": ["analyst", "operator"],
        "groups": ["secops", "domain_admins"],
        "computers": ["DC01.lab.internal", "FILE01.lab.internal"],
        "edges": [
            {"src": "user:analyst", "dst": "group:secops", "rel": "MEMBER_OF"},
            {"src": "user:operator", "dst": "group:secops", "rel": "MEMBER_OF"},
            {"src": "group:secops", "dst": "group:domain_admins", "rel": "MEMBER_OF"},
            {"src": "group:domain_admins", "dst": "host:DC01.lab.internal", "rel": "ADMIN_TO"},
            {"src": "user:analyst", "dst": "host:FILE01.lab.internal", "rel": "CAN_RDP"},
        ],
    })
    # Add a vulnerable web service
    g.add_node("svc:web:443", "service", "Apache 2.4.49", version="Apache 2.4.49", port=443)
    g.add_node("vuln:CVE-2021-41773", "vulnerability", "CVE-2021-41773", cvss=7.5)
    g.add_edge("host:FILE01.lab.internal", "svc:web:443", "HAS_SERVICE")
    g.add_edge("svc:web:443", "vuln:CVE-2021-41773", "HAS_VULN")
    return g


def test_edge_scoring_with_intel():
    g = _sample_graph()

    def intel_kev(cve_id: str) -> dict:
        return {"epss": 0.90, "kev": True}

    def intel_low(cve_id: str) -> dict:
        return {"epss": 0.001, "kev": False}

    scorer_kev = PathScorer(g, intel=intel_kev)
    scorer_low = PathScorer(g, intel=intel_low)

    vuln_edge = next(e for e in g.edges if e.dst == "vuln:CVE-2021-41773")
    cost_kev = scorer_kev.score_edge(vuln_edge)
    cost_low = scorer_low.score_edge(vuln_edge)

    # Higher CVSS + KEV should have lower cost (easier to attack)
    assert cost_kev < cost_low
    assert scorer_kev._edge_probability(vuln_edge) > scorer_low._edge_probability(vuln_edge)


def test_score_path():
    g = _sample_graph()
    scorer = PathScorer(g)

    path = ["user:analyst", "group:secops", "group:domain_admins", "host:DC01.lab.internal"]
    scored = scorer.score_path(path)

    assert isinstance(scored, AttackPath)
    assert scored.nodes == path
    assert scored.edges == ["MEMBER_OF", "MEMBER_OF", "ADMIN_TO"]
    assert scored.total_cost > 0
    assert 0.0 < scored.success_probability <= 1.0
    assert "DomainAdmin" in scored.required_privileges
    assert "T1078" in scored.techniques


def test_optimal_paths():
    g = _sample_graph()
    scorer = PathScorer(g)

    paths = scorer.optimal_paths("user:analyst", "host:DC01.lab.internal", top_k=2)
    assert len(paths) >= 1
    assert paths[0].nodes == ["user:analyst", "group:secops", "group:domain_admins", "host:DC01.lab.internal"]


def test_choke_points():
    g = _sample_graph()
    scorer = PathScorer(g)

    # Both analyst and operator must go through secops and domain_admins to reach DC01
    chokes = scorer.choke_points(["host:DC01.lab.internal"])
    assert "group:secops" in chokes
    assert "group:domain_admins" in chokes


def test_decision_engine_next_target():
    g = _sample_graph()
    scorer = PathScorer(g)
    engine = DecisionEngine(scorer)

    hop = engine.next_target("user:analyst", "host:DC01.lab.internal")
    assert hop == "group:secops"

    # Same source and destination
    assert engine.next_target("host:DC01.lab.internal", "host:DC01.lab.internal") == "host:DC01.lab.internal"

    # Nonexistent destination
    assert engine.next_target("user:analyst", "host:UNKNOWN") is None


def test_decision_engine_should_exploit():
    g = _sample_graph()

    def intel(cve_id: str) -> dict:
        if "41773" in cve_id:
            return {"epss": 0.88, "kev": True}
        return {"epss": 0.0, "kev": False}

    scorer = PathScorer(g, intel=intel)
    engine = DecisionEngine(scorer)

    res = engine.should_exploit("vuln:CVE-2021-41773")
    assert res["recommend"] is True
    assert res["cvss"] == 7.5
    assert res["epss"] == 0.88
    assert "KEV" in res["reason"]

    # Non-vulnerable host
    res_host = engine.should_exploit("host:DC01.lab.internal")
    assert isinstance(res_host["recommend"], bool)
    assert "reason" in res_host


def test_decision_engine_rank_targets():
    g = _sample_graph()
    scorer = PathScorer(g)
    engine = DecisionEngine(scorer)

    targets = ["host:DC01.lab.internal", "host:FILE01.lab.internal"]
    ranked = engine.rank_targets("user:analyst", targets)
    assert len(ranked) == 2
    # Both targets should have scores
    assert all(score < float("inf") for _, score in ranked)


def test_attack_json_roundtrip():
    g = _sample_graph()
    scorer = PathScorer(g)

    data = build_attack_json(g, scorer)
    assert "target" in data
    assert "nodes" in data
    assert "edges" in data
    assert "choke_points" in data
    assert "paths" in data

    # Verify JSON serialization works cleanly
    dumped = json.dumps(data)
    assert len(dumped) > 0

    reconstructed_g, reconstructed_scorer = load_attack_json(json.loads(dumped))
    assert len(reconstructed_g.nodes) == len(g.nodes)
    assert len(reconstructed_g.edges) == len(g.edges)
    assert reconstructed_scorer.choke_points(["host:DC01.lab.internal"]) == scorer.choke_points(["host:DC01.lab.internal"])
