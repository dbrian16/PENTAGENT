"""Checks for the completeness pass: knowledge base, LLM in perception/planning."""
import json
import os
import tempfile

from agentpentest import knowledge
from agentpentest.brain import EGATS
from agentpentest.campaign import build_tree, run, simulated_oracle
from agentpentest.executor import Executor
from agentpentest.llm import MockReasoner
from agentpentest.orchestrator import run_recon
from agentpentest.ptt import Evidence, PentestTree
from agentpentest.runlog import RunLog
from agentpentest.sandbox import DockerSandbox
from agentpentest.state import ReconState


def test_knowledge_base():
    assert knowledge.technique_name("T1190") == "Exploit Public-Facing Application"
    tid, ev, note = knowledge.for_service("http")
    assert tid == "T1190" and ev is Evidence.PLAUSIBLE and note
    assert knowledge.for_service("nope") is None
    assert knowledge.cve_hints("nginx 1.18.0") and not knowledge.cve_hints("")
    assert "MFA" in knowledge.remediation("T1110")


class _FakeSandbox:
    """Returns unparseable output so the regex parser yields nothing."""
    def available(self, binary): return True
    def exec(self, argv): return "garbage output the regex cannot parse\n"


def test_executor_llm_perception_fallback():
    class Stub:
        def ask(self, system, user):
            return 'ok {"subdomains":["api.example.com"]}'
    from agentpentest.planner import Task
    ex = Executor({"example.com"}, sandbox=_FakeSandbox(), mock=False,
                  allow_internal=True, reasoner=Stub())        # allow_internal => no DNS
    out = ex.run(Task("subdomain_enum", "example.com"))
    assert out.get("subdomains") == ["api.example.com"]        # LLM recovered the fact
    # without a reasoner, the empty parse stands
    ex2 = Executor({"example.com"}, sandbox=_FakeSandbox(), mock=False, allow_internal=True)
    assert not ex2.run(Task("subdomain_enum", "example.com")).get("subdomains")


def test_egats_llm_strategist_picks_next():
    t = PentestTree("x")
    host = t.add("host", t.root_id, Evidence.CONFIRMED); t.nodes[host].status = "success"
    a = t.add("A", host, Evidence.PLAUSIBLE, "T1190")
    b = t.add("B", host, Evidence.PLAUSIBLE, "T1190")
    order = []

    def oracle(node):
        order.append(node.id)
        return True, Evidence.CONFIRMED

    def strategist(cands):          # always prefer B, whatever TDA says
        return b if any(n.id == b for n in cands) else None

    EGATS(t, oracle, strategist=strategist).run()
    assert order[0] == b            # planner steered the first move


def test_run_budget_stops_early():
    t = PentestTree("x")
    host = t.add("host", t.root_id, Evidence.CONFIRMED); t.nodes[host].status = "success"
    t.add("A", host, Evidence.PLAUSIBLE, "T1190")
    calls = []
    EGATS(t, lambda n: (calls.append(1), (True, Evidence.CONFIRMED))[1],
          max_seconds=-1).run()     # negative budget => stop before any attempt
    assert not calls


def test_failure_type_A_on_oracle_error():
    fd, path = tempfile.mkstemp(suffix=".jsonl"); os.close(fd)
    try:
        t = PentestTree("x")
        host = t.add("host", t.root_id, Evidence.CONFIRMED); t.nodes[host].status = "success"
        t.add("A", host, Evidence.PLAUSIBLE, "T1190")

        def broken(node):
            raise RuntimeError("tool crashed")

        EGATS(t, broken, runlog=RunLog(path), max_steps=10).run()
        events = [json.loads(l) for l in open(path, encoding="utf-8")]
        assert any(e.get("action") == "error" and e.get("failure_type") == "A" for e in events)
        assert any(e.get("failure_type") == "B" for e in events)   # streak -> strategic give-up
    finally:
        os.remove(path)


def test_reconstate_persistence_roundtrip():
    s = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)
    back = ReconState.from_json(s.to_json())
    assert back.domain == s.domain
    assert back.subdomains == s.subdomains
    assert set(back.hosts) == set(s.hosts)
    h = back.hosts["example.com"]
    assert h.scanned and any(sv.name == "http" for sv in h.services)


def test_docker_sandbox_wraps_argv_isolated():
    w = DockerSandbox(image="kali", network="bridge")._wrap(["nmap", "-sV", "x"])
    assert w[:3] == ["docker", "run", "--rm"]
    for flag in ("--cap-drop", "--read-only", "--security-opt"):
        assert flag in w
    assert w[-3:] == ["nmap", "-sV", "x"]        # the tool argv is appended verbatim


def test_llm_path_end_to_end_offline():
    # MockReasoner returns "" everywhere -> every LLM hook degrades to deterministic.
    tree, md = run("example.com", reasoner=MockReasoner())
    assert "T1190" in md and any(n.status == "success" for n in tree.nodes.values())


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok")
