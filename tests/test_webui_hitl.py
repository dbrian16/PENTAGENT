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
