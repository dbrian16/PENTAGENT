"""Business-logic layer: role context + IDOR detection, end to end."""
from agentpentest.campaign import build_tree
from agentpentest.perceptor import Perceptor
from agentpentest.planner import Task
from agentpentest.state import ReconState, idor_candidates


def test_record_access_and_json_roundtrip():
    s = ReconState(domain="x")
    s.record_access("alice", "user", "/account/1")
    s.record_access("attacker", "anon", "/account/1")
    back = ReconState.from_json(s.to_json())
    assert back.identities["alice"].sees == {"/account/1"}
    assert back.identities["attacker"].role == "anon"


def test_idor_needs_two_distinct_roles():
    s = ReconState()
    # same resource, two roles -> candidate
    s.record_access("alice", "user", "/account/1")
    s.record_access("anon", "anon", "/account/1")
    # resource seen by one role only -> not a candidate
    s.record_access("alice", "user", "/me")
    cands = idor_candidates(s)
    assert [c["resource"] for c in cands] == ["/account/1"]
    assert cands[0]["roles"] == ["anon", "user"]


def test_perceptor_folds_access():
    s = ReconState()
    Perceptor().perceive(Task("auth_probe", "x"), {"access": [
        {"identity": "alice", "role": "user", "resource": "/account/2", "status": 200},
        {"identity": "bob", "role": "user", "resource": "/account/2", "status": 200},
        {"identity": "bob", "role": "user", "resource": "/secret", "status": 403},  # dropped
    ]}, s)
    assert s.identities["bob"].sees == {"/account/2"}      # 403 not recorded


def test_build_tree_seeds_idor_finding():
    s = ReconState(domain="shop.test")
    s.record_access("alice", "user", "/order/1001")
    s.record_access("mallory", "attacker", "/order/1001")
    tree = build_tree(s)                                   # no reasoner, deterministic
    idor = [n for n in tree.nodes.values() if n.technique == "IDOR"]
    assert len(idor) == 1 and idor[0].status == "success"


if __name__ == "__main__":
    test_record_access_and_json_roundtrip()
    test_idor_needs_two_distinct_roles()
    test_perceptor_folds_access()
    test_build_tree_seeds_idor_finding()
    print("ok")
