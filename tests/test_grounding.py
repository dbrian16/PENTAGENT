"""Evidence grounding (ported from PentestGPT 2.0): a claim is evidence only if it is
an exact slice of real output. Plus the live-loop wiring: hallucinated quotes are
stripped, and a repeated command is refused (convergence guard)."""
import json

from agentpentest import grounding
from agentpentest.autonomous import _perceive, autoloop


def test_exact_and_crlf_grounding():
    out = "PORT   STATE SERVICE\r\n22/tcp open  ssh\r\n80/tcp open  http\r\n"
    span, st = grounding.ground(out, "22/tcp open  ssh")
    assert st == "grounded" and span == "22/tcp open  ssh"
    # model quotes with LF where output had CRLF -> still grounds
    _, st = grounding.ground(out, "22/tcp open  ssh\n80/tcp open  http")
    assert st == "grounded"


def test_paraphrase_and_oversize_and_empty():
    out = "22/tcp open ssh OpenSSH 8.2p1"
    assert grounding.ground(out, "ssh running on 22") == (None, "unresolved")
    big = "A" * 5000
    span, st = grounding.ground("x" + big, big)
    assert st == "truncated" and len(span) == grounding.MAX_EVIDENCE
    assert grounding.ground(out, "  ")[1] == "empty"


class _StubLLM:
    def __init__(self, plans): self.plans = list(plans); self.i = 0
    def ask(self, sys, user, **k):
        if "Extract structured facts" in sys:              # perceive call
            return self._perceive_reply
        p = self.plans[self.i] if self.i < len(self.plans) else '{"done":true}'
        self.i += 1
        return p


def test_perceive_strips_hallucinated_evidence():
    llm = _StubLLM([])
    raw = "22/tcp open ssh OpenSSH 8.2p1\n80/tcp open http"
    # grounded quote survives
    llm._perceive_reply = json.dumps({"notes": "ok", "evidence": "22/tcp open ssh OpenSSH 8.2p1"})
    f = _perceive(llm, ["nmap", "t"], raw)
    assert f["evidence_status"] == "grounded" and f["evidence"] == "22/tcp open ssh OpenSSH 8.2p1"
    # paraphrase is dropped and flagged
    llm._perceive_reply = json.dumps({"notes": "ok", "evidence": "ssh is open"})
    f = _perceive(llm, ["nmap", "t"], raw)
    assert f["evidence_status"] == "unresolved" and "evidence" not in f


def test_autoloop_persists_to_memory_and_audits(tmp_path):
    from agentpentest import audit
    from agentpentest.memorydb import MemoryDB
    path = tmp_path / "live.sqlite"
    db = MemoryDB(path)
    db.open_run("live1", "ctf", ["box.lab"])
    llm = _StubLLM(['{"command":["nikto","-h","box.lab"],"target":"box.lab","rationale":"t"}',
                    '{"done":true}'])
    llm._perceive_reply = json.dumps({"notes": "ssh", "evidence": "22/tcp open ssh"})
    autoloop("ctf", {"box.lab"}, llm, lambda a, t: "22/tcp open ssh",
             allow_internal=True, max_steps=4, memory=db, run_id="live1")
    db.close()
    rep = audit.audit_run(path, "live1")
    assert rep["passed"] is True, rep["failures"]
    assert rep["summary"]["tasks"] == 1 and rep["summary"]["grounded_observations"] == 1


def test_tool_perceive_is_deterministic_and_grounded():
    from agentpentest.autonomous import _tool_perceive
    raw = "80/tcp open http nginx 1.18.0\n443/tcp open https nginx"
    f = _tool_perceive("port_scan", {"target": "box.lab"}, raw)
    assert f["evidence_status"] == "grounded" and f["evidence"] in raw
    assert f.get("services")              # the tool's own parse() produced structure


def test_autoloop_typed_tool_persists(tmp_path):
    from agentpentest import audit
    from agentpentest.memorydb import MemoryDB
    db = MemoryDB(tmp_path / "t.sqlite")
    db.open_run("r", "ctf", ["box.lab"])
    llm = _StubLLM(['{"tool":"port_scan","params":{"target":"box.lab"},"rationale":"scan"}',
                    '{"done":true}'])
    llm._perceive_reply = "{}"            # typed tools skip the LLM perceive anyway
    autoloop("ctf", {"box.lab"}, llm, lambda a, t: "22/tcp open ssh OpenSSH 8.2p1",
             allow_internal=True, max_steps=4, memory=db, run_id="r")
    db.close()
    rep = audit.audit_run(tmp_path / "t.sqlite", "r")
    assert rep["passed"] is True, rep["failures"]
    assert rep["summary"]["grounded_observations"] == 1


def test_autoloop_refuses_duplicate_command():
    ran = []
    # propose the same command twice; the second must be refused, not executed again
    plans = ['{"command":["nmap","-sV","box.lab"],"target":"box.lab","rationale":"a"}',
             '{"command":["nmap","-sV","box.lab"],"target":"box.lab","rationale":"b"}',
             '{"done":true}']
    llm = _StubLLM(plans)
    llm._perceive_reply = json.dumps({"notes": "n", "evidence": "open"})
    tr = autoloop("g", {"box.lab"}, llm, lambda a, t: ran.append(1) or "open",
                  allow_internal=True, max_steps=5)
    assert len(ran) == 1 and len(tr) == 1          # ran once, duplicate refused
