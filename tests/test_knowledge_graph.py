"""knowledge_graph.py: LPG multi-hop attack-path search, STIX 2.1 export, BloodHound."""
from __future__ import annotations

from agentpentest.knowledge_graph import KnowledgeGraph


def _ad_graph() -> KnowledgeGraph:
    g = KnowledgeGraph("corp.local")
    g.from_bloodhound({
        "users": ["alice", "bob"], "groups": ["helpdesk"], "computers": ["DC01"],
        "edges": [
            {"src": "user:alice", "dst": "group:helpdesk", "rel": "MEMBER_OF"},
            {"src": "group:helpdesk", "dst": "host:DC01", "rel": "ADMIN_TO"},
        ],
    })
    return g


def test_multi_hop_attack_path():
    g = _ad_graph()
    paths = g.attack_paths("user:alice", "host:DC01")
    assert paths == [["user:alice", "group:helpdesk", "host:DC01"]], paths
    assert g.shortest_path("user:alice", "host:DC01") == paths[0]


def test_no_false_path_when_disconnected():
    g = _ad_graph()
    assert g.attack_paths("user:bob", "host:DC01") == []      # bob isn't in helpdesk


def test_describe_path_shows_edges():
    g = _ad_graph()
    desc = g.describe_path(["user:alice", "group:helpdesk", "host:DC01"])
    assert "MEMBER_OF" in desc and "ADMIN_TO" in desc


def test_stix_bundle_is_2_1():
    g = _ad_graph()
    b = g.stix_bundle()
    assert b["type"] == "bundle" and b["spec_version"] == "2.1"
    assert any(o["type"] == "identity" for o in b["objects"])
    assert any(o["type"] == "relationship" for o in b["objects"])


def test_ingest_recon_builds_service_and_vuln_nodes():
    from agentpentest.state import ReconState, Host, Service
    st = ReconState(domain="t")
    st.hosts["1.2.3.4"] = Host(address="1.2.3.4",
                               services=[Service(port=21, proto="tcp", name="ftp",
                                                 version="vsftpd 2.3.4")])
    g = KnowledgeGraph("t")
    g.ingest_recon(st)
    stats = g.stats()
    assert stats["by_type"].get("service", 0) >= 1
    assert stats["by_type"].get("vulnerability", 0) >= 1    # vsftpd 2.3.4 -> CVE hint


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
