"""Checks for the gap-closing additions: local LLM, persistence, run log."""
import json
import os
import tempfile

from agentpentest.brain import EGATS
from agentpentest.campaign import build_tree, simulated_oracle
from agentpentest.llm import MockReasoner, OllamaReasoner, parse_json_block
from agentpentest.orchestrator import run_recon
from agentpentest.ptt import Evidence, PentestTree
from agentpentest.runlog import RunLog
from agentpentest.swarm import DEFAULT_ROLES, debate, llm_analyst


def test_ollama_self_hosted_ok_cloud_refused():
    # self-hosted: loopback AND another machine on the LAN are fine (local AI).
    OllamaReasoner("m", "http://127.0.0.1:11434")
    OllamaReasoner("m", "http://192.168.1.50:11434")   # the other machine
    OllamaReasoner("m", "http://ollama.lan:11434")
    # cloud LLM APIs are refused, so "local AI not API" holds.
    for bad in ("https://api.openai.com", "https://api.anthropic.com",
                "https://openrouter.ai", "https://generativelanguage.googleapis.com"):
        try:
            OllamaReasoner("m", bad)
            assert False, f"must refuse cloud API {bad}"
        except ValueError:
            pass


def test_mock_reasoner_is_silent():
    assert MockReasoner().ask("s", "u") == ""         # deterministic paths stay in charge


def test_llm_role_parses_hypothesis():
    class Stub:
        def ask(self, system, user):
            return 'sure: {"technique":"T1190","evidence":"CONFIRMED","claim":"x"}'
    role = llm_analyst(Stub())
    h = role({"address": "h", "port": 80, "name": "http", "version": "nginx"})
    assert h and h.technique == "T1190" and h.evidence is Evidence.CONFIRMED
    # a garbage reply yields no hypothesis, never a crash
    class Bad:
        def ask(self, s, u): return "no json here"
    assert llm_analyst(Bad())({"address": "h", "port": 80, "name": "http"}) is None


def test_parse_json_block():
    assert parse_json_block('x {"a":1} y') == {"a": 1}
    assert parse_json_block("nope") is None


def test_ptt_save_resume_roundtrip():
    state = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)
    tree = build_tree(state)
    EGATS(tree, simulated_oracle).run()
    dumped = tree.to_json()
    back = PentestTree.from_json(dumped)
    assert back.target == tree.target
    assert len(back.nodes) == len(tree.nodes)
    # evidence enum survives the round-trip
    for nid, n in tree.nodes.items():
        assert back.nodes[nid].evidence is n.evidence
        assert back.nodes[nid].status == n.status


def test_verification_downgrades_unproven():
    # oracle claims VERIFIED for T1190, but records no proof marker -> the
    # ground-truth gate demotes it to CONFIRMED (anti-hallucination). Without the
    # gate, it stays VERIFIED.
    from agentpentest.brain import EGATS as _E
    from agentpentest.verify import proof_gated, trusting
    state = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)

    t_trust = build_tree(state)
    _E(t_trust, simulated_oracle, verifier=trusting).run()
    assert any(n.evidence is Evidence.VERIFIED for n in t_trust.nodes.values())

    t_gate = build_tree(state)
    _E(t_gate, simulated_oracle, verifier=proof_gated).run()
    assert all(n.evidence is not Evidence.VERIFIED for n in t_gate.nodes.values())
    # findings survive, just at CONFIRMED (not fabricated as ground truth)
    assert any(n.status == "success" and n.evidence is Evidence.CONFIRMED
               for n in t_gate.nodes.values())


def test_runlog_writes_jsonl():
    fd, path = tempfile.mkstemp(suffix=".jsonl"); os.close(fd)
    try:
        state = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)
        tree = build_tree(state)
        EGATS(tree, simulated_oracle, runlog=RunLog(path)).run()
        lines = [json.loads(l) for l in open(path, encoding="utf-8")]
        assert lines and all("action" in e and "ts" in e for e in lines)
        assert any(e["action"] == "backtrack" for e in lines)   # ssh branches abandoned
        assert any(e["action"] == "attempt" and e["success"] for e in lines)
    finally:
        os.remove(path)


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok")
