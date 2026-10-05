"""Environment auto-detection: model pick, cloud refusal, offline-safe probing."""
from __future__ import annotations

from unittest.mock import patch

from agentpentest import discover


def test_pick_model_prefers_requested():
    assert discover.pick_model(["llama3", "qwen2.5"], "qwen2.5") == "qwen2.5"


def test_pick_model_matches_by_base_name_and_tag():
    # preferred given without a tag; installed carries a :tag -> match by base name
    assert discover.pick_model(["qwen2.5:7b", "llama3:8b"], "qwen2.5") == "qwen2.5:7b"


def test_pick_model_falls_back_to_priority_then_first():
    assert discover.pick_model(["mistral", "llama3.1"]) == "llama3.1"   # priority order
    assert discover.pick_model(["something-exotic"]) == "something-exotic"
    assert discover.pick_model([]) is None


def test_probe_refuses_cloud_hosts():
    # must never reach out to a paid API, even if asked
    assert discover.probe("https://api.openai.com") is None
    assert discover.probe("https://api.anthropic.com") is None


def test_probe_unreachable_is_none_not_error():
    # an unused high port: connection refused -> None, no exception
    assert discover.probe("http://127.0.0.1:9", timeout=0.5) is None


def test_discover_offline_returns_safe_dict():
    with patch.object(discover, "_DEFAULT_HOSTS", ()):
        d = discover.discover_ollama(hosts=["http://127.0.0.1:9"], timeout=0.5)
    assert d["connected"] is False and d["model"] is None and d["models"] == []


def test_tool_status_shape():
    t = discover.tool_status()
    assert set(t) == {"nmap", "gobuster", "subfinder"}
    assert all(isinstance(v, bool) for v in t.values())


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
