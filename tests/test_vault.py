"""Unit and cryptographic integrity tests for AssetVault."""
from __future__ import annotations

import json
import pytest

from agentpentest.asset_vault import (
    AssetVault,
    CredRef,
    VaultDecryptionError,
    _decrypt_bytes,
    _encrypt_bytes,
)


def test_asset_vault_store_retrieve_and_redact():
    """Store credentials as opaque references and ensure redaction scrubs plaintext from prompts."""
    vault = AssetVault()
    ref = vault.store("db_pass_secret_12345", kind="password", principal="dbadmin", source="mysql_dump")
    assert isinstance(ref, CredRef)
    assert ref.ref.startswith("cred:")
    assert vault.reveal(ref.ref) == "db_pass_secret_12345"

    # Verbatim redaction
    dirty_prompt = "Executing attack with password db_pass_secret_12345 on host"
    cleaned = vault.redact(dirty_prompt)
    assert "db_pass_secret_12345" not in cleaned
    assert f"<{ref.ref}>" in cleaned

    # URL-encoded redaction
    dirty_url = "Login request: pass=db_pass_secret_12345&user=admin"
    cleaned_url = vault.redact(dirty_url)
    assert "db_pass_secret_12345" not in cleaned_url


def test_asset_vault_encryption_envelope_tamper_detection():
    """Tampering with ciphertext or authentication tag must raise VaultDecryptionError."""
    master_key = "secure_vault_passphrase"
    payload = b'{"secret": "root_password"}'
    envelope = _encrypt_bytes(payload, master_key)

    # 1. Successful decrypt
    decrypted = _decrypt_bytes(envelope, master_key)
    assert decrypted == payload

    # 2. Tampered tag
    tampered_tag_env = dict(envelope)
    tampered_tag_env["tag"] = "a" * 64
    with pytest.raises(VaultDecryptionError):
        _decrypt_bytes(tampered_tag_env, master_key)

    # 3. Wrong passphrase
    with pytest.raises(VaultDecryptionError):
        _decrypt_bytes(envelope, "wrong_passphrase")


def test_asset_vault_rejects_unbounded_iterations():
    """Envelope with malicious iteration count must be rejected without hanging CPU."""
    master_key = "secure_vault_passphrase"
    envelope = _encrypt_bytes(b'{"secret":"test"}', master_key)
    envelope["iterations"] = 50_000_000
    with pytest.raises(VaultDecryptionError, match="outside safe bounds"):
        _decrypt_bytes(envelope, master_key)


def test_asset_vault_save_load_disk(tmp_path):
    """Verify persistent encrypted vault save and load on disk."""
    vault_file = tmp_path / "vault.enc"
    v1 = AssetVault(storage_path=vault_file, master_key="disk_key")
    r1 = v1.store("api_token_xyz_987", kind="token", principal="admin")
    v1.save()

    assert vault_file.exists()
    v2 = AssetVault(storage_path=vault_file, master_key="disk_key")
    v2.load()
    assert len(v2.list()) == 1
    assert v2.reveal(r1.ref) == "api_token_xyz_987"
