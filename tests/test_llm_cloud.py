"""Opt-in commercial API path: CloudReasoner speaks Anthropic and OpenAI shapes over stdlib
urllib, and make_reasoner dispatches local vs cloud. No network -- urlopen is monkeypatched."""
import json
import urllib.request

import pytest

from agentpentest.llm import CloudReasoner, OllamaReasoner, make_reasoner


class _FakeResp:
    def __init__(self, data):
        self._d = json.dumps(data).encode()

    def read(self):
        return self._d

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture(monkeypatch, data):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        seen["body"] = json.loads(req.data)
        return _FakeResp(data)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return seen


# ---- make_reasoner dispatch ---------------------------------------------------
def test_local_returns_ollama():
    assert isinstance(make_reasoner("local"), OllamaReasoner)
    assert isinstance(make_reasoner("ollama", host="http://192.168.1.5:11434"), OllamaReasoner)


def test_cloud_builds_cloudreasoner():
    r = make_reasoner("anthropic", model="claude-x", api_key="sk-test")
    assert isinstance(r, CloudReasoner) and r.provider == "anthropic"
    assert r.base == "https://api.anthropic.com"


def test_cloud_reads_key_from_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    r = make_reasoner("openai", model="gpt-x")
    assert isinstance(r, CloudReasoner) and r.api_key == "sk-env"


def test_cloud_missing_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AGENTPENTEST_LLM_API_KEY", raising=False)
    with pytest.raises(ValueError, match="API key"):
        make_reasoner("anthropic", model="claude-x")


def test_cloud_missing_model_raises():
    with pytest.raises(ValueError, match="model id is required"):
        make_reasoner("openai", api_key="sk-test")


def test_unknown_provider_raises():
    with pytest.raises(ValueError, match="unknown cloud provider"):
        make_reasoner("gemini", model="m", api_key="k")


# ---- CloudReasoner request/response shapes -----------------------------------
def test_anthropic_shape(monkeypatch):
    seen = _capture(monkeypatch, {"content": [{"type": "text", "text": "hi there"}]})
    r = CloudReasoner("anthropic", "claude-x", "sk-a")
    out = r.ask("be terse", "ping")
    assert out == "hi there"
    assert seen["url"].endswith("/v1/messages")
    assert seen["headers"]["x-api-key"] == "sk-a"
    assert seen["body"]["system"] == "be terse"
    assert seen["body"]["messages"][0]["content"] == "ping"


def test_openai_shape_and_json_mode(monkeypatch):
    seen = _capture(monkeypatch, {"choices": [{"message": {"content": "yo"}}]})
    r = CloudReasoner("openai", "gpt-x", "sk-o")
    out = r.ask("sys", "usr", json_mode=True)
    assert out == "yo"
    assert seen["url"].endswith("/v1/chat/completions")
    assert seen["headers"]["authorization"] == "Bearer sk-o"
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]


def test_cloud_unreachable_raises_runtimeerror(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(RuntimeError, match="unreachable"):
        CloudReasoner("openai", "gpt-x", "sk-o").ask("s", "u")


def test_custom_base_for_openai_compatible_gateway():
    r = make_reasoner("openai", model="m", api_key="k", base="https://gw.local/v1x")
    assert r.base == "https://gw.local/v1x"


def test_ollama_options_num_ctx_and_temperature(monkeypatch):
    seen = _capture(monkeypatch, {"message": {"content": "ok"}})
    r = OllamaReasoner("qwen2.5", "http://127.0.0.1:11434", num_ctx=16384, temperature=0.0)
    out = r.ask("sys", "usr", json_mode=True)
    assert out == "ok"
    assert seen["url"].endswith("/api/chat")
    assert seen["body"]["options"]["num_ctx"] == 16384
    assert seen["body"]["options"]["temperature"] == 0.0
    assert seen["body"]["format"] == "json"


def test_cloud_temperature_payload(monkeypatch):
    seen_anthropic = _capture(monkeypatch, {"content": [{"text": "hi"}]})
    r1 = CloudReasoner("anthropic", "claude-x", "sk-a", temperature=0.0)
    r1.ask("sys", "usr")
    assert seen_anthropic["body"]["temperature"] == 0.0

    seen_openai = _capture(monkeypatch, {"choices": [{"message": {"content": "hi"}}]})
    r2 = CloudReasoner("openai", "gpt-x", "sk-o", temperature=0.0)
    r2.ask("sys", "usr")
    assert seen_openai["body"]["temperature"] == 0.0


if __name__ == "__main__":
    import subprocess, sys
    sys.exit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-q"]))
