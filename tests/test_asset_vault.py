"""asset_vault.py: credentials as reference IDs, never plaintext to the LLM (Pillar 1).
Tests in-memory behavior, encrypted on-disk persistence, tamper-detection, and key handling.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from agentpentest.asset_vault import (
    AssetVault,
    VaultDecryptionError,
    VaultError,
)


def test_put_returns_ref_without_secret():
    v = AssetVault()
    r = v.put("S3cr3t!", kind="password", principal="alice@corp.local", source="T1110")
    assert r.ref == "cred:0" and r.principal == "alice@corp.local"
    assert all("S3cr3t!" not in str(m) for m in v.refs())  # catalogue carries no secret


def test_dereference_for_task_agent():
    v = AssetVault()
    v.put("pw", kind="password", principal="bob")
    assert v.dereference("cred:0") == "pw"


def test_hallucinated_ref_fails_loud():
    v = AssetVault()
    with pytest.raises(KeyError, match="unknown credential ref"):
        v.dereference("cred:99")


def test_redact_scrubs_leaked_secret():
    v = AssetVault()
    v.put("S3cr3t!", kind="password", principal="alice")
    assert v.redact("auth ok with S3cr3t! now") == "auth ok with <cred:0> now"


def test_encrypted_persistence_roundtrip(tmp_path: Path):
    vault_file = tmp_path / "credentials.enc"
    v = AssetVault(storage_path=vault_file, master_key="super-secret-key-42", auto_save=True)
    v.put("API_KEY_123456", kind="token", principal="cloud-admin", source="aws_metadata")
    v.put("shadow_hash_root", kind="hash", principal="root", source="/etc/shadow")

    assert vault_file.exists()

    # Ensure file on disk contains NO plaintext secrets
    file_content = vault_file.read_text(encoding="utf-8")
    assert "API_KEY_123456" not in file_content
    assert "shadow_hash_root" not in file_content

    envelope = json.loads(file_content)
    assert envelope["version"] == 1
    assert "tag" in envelope
    assert "ciphertext" in envelope

    # Reopen and decrypt
    v2 = AssetVault(storage_path=vault_file, master_key="super-secret-key-42")
    assert v2.dereference("cred:0") == "API_KEY_123456"
    assert v2.dereference("cred:1") == "shadow_hash_root"
    assert v2.meta("cred:0").principal == "cloud-admin"
    assert v2.meta("cred:1").source == "/etc/shadow"

    # Redact works with restored secrets
    assert v2.redact("got token API_KEY_123456 here") == "got token <cred:0> here"


def test_encrypted_persistence_wrong_key_fails(tmp_path: Path):
    vault_file = tmp_path / "vault.enc"
    v = AssetVault(storage_path=vault_file, master_key="correct-key", auto_save=True)
    v.put("secret-val", kind="password", principal="user1")

    with pytest.raises(VaultDecryptionError, match="Authentication failed"):
        AssetVault(storage_path=vault_file, master_key="wrong-key")


def test_encrypted_persistence_tamper_detection(tmp_path: Path):
    vault_file = tmp_path / "vault.enc"
    v = AssetVault(storage_path=vault_file, master_key="correct-key", auto_save=True)
    v.put("top-secret", kind="password", principal="user2")

    # Tamper with the ciphertext on disk
    envelope = json.loads(vault_file.read_text(encoding="utf-8"))
    ct = list(envelope["ciphertext"])
    ct[0] = "A" if ct[0] != "A" else "B"
    envelope["ciphertext"] = "".join(ct)
    vault_file.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(VaultDecryptionError, match="Authentication failed|Malformed"):
        AssetVault(storage_path=vault_file, master_key="correct-key")


def test_vault_env_variable_master_key(tmp_path: Path, monkeypatch):
    vault_file = tmp_path / "env_vault.enc"
    monkeypatch.setenv("AGENTPENTEST_VAULT_KEY", "env-provided-passphrase")

    v = AssetVault(storage_path=vault_file, auto_save=True)
    v.put("secret-from-env", kind="token", principal="service_account")

    v2 = AssetVault(storage_path=vault_file)
    assert v2.dereference("cred:0") == "secret-from-env"


def test_vault_missing_key_raises_error(tmp_path: Path, monkeypatch):
    vault_file = tmp_path / "missing_key.enc"
    monkeypatch.delenv("AGENTPENTEST_VAULT_KEY", raising=False)

    v = AssetVault(storage_path=vault_file)
    with pytest.raises(VaultError, match="Master key required"):
        v.save()


def test_from_file_factory(tmp_path: Path):
    vault_file = tmp_path / "factory_vault.enc"
    v = AssetVault.from_file(vault_file, master_key="key123", auto_save=True)
    v.put("pw_factory", kind="password", principal="factory_user")

    v_restored = AssetVault.from_file(vault_file, master_key="key123")
    assert v_restored.dereference("cred:0") == "pw_factory"
