"""asset_vault.py: credentials as reference IDs, never plaintext to the LLM (Pillar 1)."""
from __future__ import annotations

from agentpentest.asset_vault import AssetVault


def test_put_returns_ref_without_secret():
    v = AssetVault()
    r = v.put("S3cr3t!", kind="password", principal="alice@corp.local", source="T1110")
    assert r.ref == "cred:0" and r.principal == "alice@corp.local"
    assert all("S3cr3t!" not in str(m) for m in v.refs())     # catalogue carries no secret


def test_dereference_for_task_agent():
    v = AssetVault()
    v.put("pw", kind="password", principal="bob")
    assert v.dereference("cred:0") == "pw"


def test_hallucinated_ref_fails_loud():
    v = AssetVault()
    try:
        v.dereference("cred:99")
        raise AssertionError("expected KeyError on unknown ref")
    except KeyError:
        pass


def test_redact_scrubs_leaked_secret():
    v = AssetVault()
    v.put("S3cr3t!", kind="password", principal="alice")
    assert v.redact("auth ok with S3cr3t! now") == "auth ok with <cred:0> now"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
