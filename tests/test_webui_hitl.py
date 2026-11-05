"""HITL edit flow: operator-edited argv must flow back through confirm()."""
import threading
import time

from agentpentest.webui import App


def _run_confirm(app, argv, done):
    done["ok"] = app.confirm(argv, "example.com", "test")


def test_decide_without_edit_leaves_argv():
    app = App()
    argv = ["whatweb", "http://example.com"]
    done = {}
    t = threading.Thread(target=_run_confirm, args=(app, argv, done))
    t.start()
    while app.pending is None:
        time.sleep(0.01)
    app.decide(True)
    t.join(timeout=2)
    assert done["ok"] is True
    assert argv == ["whatweb", "http://example.com"]


def test_decide_with_edit_mutates_argv():
    app = App()
    argv = ["nmap", "-sV", "example.com"]
    done = {}
    t = threading.Thread(target=_run_confirm, args=(app, argv, done))
    t.start()
    while app.pending is None:
        time.sleep(0.01)
    app.decide(True, ["nmap", "-sC", "-sV", "example.com"])
    t.join(timeout=2)
    assert done["ok"] is True
    assert argv == ["nmap", "-sC", "-sV", "example.com"]


def test_decide_reject_ignores_edit():
    app = App()
    argv = ["dig", "example.com"]
    done = {}
    t = threading.Thread(target=_run_confirm, args=(app, argv, done))
    t.start()
    while app.pending is None:
        time.sleep(0.01)
    app.decide(False, ["dig", "evil.com"])
    t.join(timeout=2)
    assert done["ok"] is False
    assert argv == ["dig", "example.com"]


def test_chat_context_carries_engagement_state():
    """_chat_context must carry the question plainly and the target-derived state fenced."""
    from agentpentest import webui
    webui.APP.plan = {"target": "10.0.0.5",
                      "steps": [{"action": "nmap -sV 10.0.0.5"}]}
    webui.APP.recon = {"services": [{"port": 445, "name": "microsoft-ds"}]}
    webui.APP.summary = {"findings": [{"title": "SMB exposed", "severity": "Medium"}]}
    try:
        out = webui._chat_context("what next?")
    finally:
        webui.APP.plan = webui.APP.recon = webui.APP.summary = None
    assert out.startswith("Operator question: what next?")   # question is NOT fenced as untrusted
    assert "UNTRUSTED TARGET OUTPUT" in out                  # state IS fenced
    for needle in ("10.0.0.5", "nmap -sV 10.0.0.5", "445", "Medium"):
        assert needle in out
