"""Regression tests verifying all deep bugs and security vulnerabilities found during codebase audit are fixed."""
import pytest
from pathlib import Path

from agentpentest import shellguard
from agentpentest.security import assert_external, is_internal, SsrfError, ScopeError
from agentpentest.tools import _host
from agentpentest.asm import ASMDocumentStore
from agentpentest.web_scanner import map_web_surface, scan_reflected_xss, scan_sqli
from agentpentest.lateral import candidates_for_state
from agentpentest.asset_vault import AssetVault
from agentpentest.oob import OOBListener
from agentpentest.persistence import PersistencePlanner, PersistSpec, PersistMethod


def test_shellguard_host_token_with_path():
    # Out of scope domain with path must be recognized as host token
    assert shellguard._host_token("evil.com/payload") == "evil.com"
    assert shellguard._host_token("target.corp/api/v1") == "target.corp"
    assert shellguard._host_token("203.0.113.5:8080/admin") == "203.0.113.5"
    # Files must still return None
    assert shellguard._host_token("/etc/passwd") is None
    assert shellguard._host_token("./wordlist.txt") is None
    assert shellguard._host_token("wordlist.txt") is None

    # validate must reject out-of-scope host token even when followed by path
    scope = {"authorized.com"}
    with pytest.raises(shellguard.ScopeError):
        shellguard.validate(["curl", "authorized.com", "evil.com/payload"], target="authorized.com", scope=scope)


def test_shellguard_safe_syntax_unwraps_sudo():
    # sudo wrapping data-destroying or host-killing commands must be rejected
    with pytest.raises(shellguard.ShellGuardError) as exc_info:
        shellguard.safe_syntax(["sudo", "rm", "-rf", "/"])
    assert "refusing data-destroying binary" in str(exc_info.value)

    with pytest.raises(shellguard.ShellGuardError) as exc_info:
        shellguard.safe_syntax(["sudo", "-n", "mkfs.ext4", "/dev/sda"])
    assert "refusing host-killer binary" in str(exc_info.value)

    with pytest.raises(shellguard.ShellGuardError) as exc_info:
        shellguard.safe_syntax(["doas", "wipe", "/data"])
    assert "refusing data-destroying binary" in str(exc_info.value)

    # Legitimate wrapped tools must pass allowlist
    shellguard.safe_syntax(["sudo", "-n", "nmap", "-sV", "example.com"], allowlist=["nmap"])


def test_ssrf_guard_detects_urls_and_ports():
    assert is_internal("http://127.0.0.1:8080") is True
    assert is_internal("127.0.0.1:8080") is True
    assert is_internal("http://169.254.169.254/latest/meta-data/") is True
    assert is_internal("169.254.169.254:80") is True
    assert is_internal("[::1]:8080") is True

    with pytest.raises(SsrfError):
        assert_external("http://127.0.0.1:8080")

    with pytest.raises(SsrfError):
        assert_external("127.0.0.1:8080")


def test_tools_rejects_flag_injection_as_target():
    with pytest.raises(ValueError) as exc:
        _host({"target": "-sV"})
    assert "illegal target" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        _host({"target": "--top-ports"})
    assert "illegal target" in str(exc.value)

    # Valid targets pass
    assert _host({"target": "10.0.0.1"}) == "10.0.0.1"
    assert _host({"target": "example.com"}) == "example.com"


def test_web_scanner_blocks_file_scheme(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("TOP_SECRET_CONTENT")

    # file:// scheme must be blocked without reading host file
    surface = map_web_surface(f"file:///{secret_file}")
    assert surface.title == ""
    assert len(surface.forms) == 0


def test_web_scanner_sqli_baseline_differential():
    # If the endpoint is naturally slow (2.6s), it must NOT be falsely flagged as SQLi
    def slow_non_sqli_client(url: str):
        return "<html><body>Slow response</body></html>", 2.6

    findings = scan_sqli(
        "http://example.com/items.php?id=1",
        test_time_based=True,
        http_client=slow_non_sqli_client,
    )
    assert len(findings) == 0


def test_asm_document_store_path_traversal(tmp_path):
    store = ASMDocumentStore(tmp_path)
    with pytest.raises(ValueError) as exc:
        store.get_domain_history("../../etc/passwd")
    assert "illegal domain" in str(exc.value) or "path traversal" in str(exc.value)


def test_lateral_candidates_evaluates_all_ports():
    creds = [{"user": "admin", "password": "Password123!"}]
    # Host has port 80 (HTTP) first, but 445 (SMB) and 22 (SSH) open
    candidates = candidates_for_state(
        creds, ["10.0.0.1"], open_ports={"10.0.0.1": [80, 445, 22]}
    )
    # Must discover lateral candidates for 445 and 22 even though 80 is first
    assert len(candidates) >= 2
    methods = [c["method"] for c in candidates]
    assert "crackmapexec" in methods
    assert "sshpass" in methods


def test_asset_vault_redact_ordering():
    vault = AssetVault()
    # Insert shorter secret first, then longer secret that contains it
    vault.put("admin", kind="password", principal="admin")
    vault.put("administrator", kind="password", principal="administrator")

    redacted = vault.redact("Logging in as administrator and admin")
    assert "<cred:1>" in redacted  # administrator
    assert "<cred:0>" in redacted  # admin
    assert "istrator" not in redacted  # must not leave partial suffix unredacted


def test_persistence_planner_sanitization():
    planner = PersistencePlanner(mock=True)
    with pytest.raises(ValueError):
        planner.plan(PersistSpec(
            method=PersistMethod.SCHEDULED_TASK,
            payload_path=r"C:\payload.exe",
            name='evil"; calc.exe; #',
        ))


def test_snapshot_sandbox_available_signature():
    from agentpentest.sandbox import SnapshotSandbox
    sb = SnapshotSandbox()
    # Must accept binary argument matching Sandbox protocol without TypeError
    assert isinstance(sb.available("nmap"), bool)
    assert isinstance(sb.available(), bool)


def test_shellguard_allows_ct_recon_osint():
    scope = {"example.com"}
    argv = ["curl", "-s", "https://crt.sh/?q=%.example.com&output=json"]
    # Must not raise ScopeError for trusted OSINT service crt.sh
    shellguard.validate(argv, target="example.com", scope=scope)


def test_persistence_planner_sanitization_payload_and_schedule():
    planner = PersistencePlanner(mock=True)
    # Reject payload_path injection
    with pytest.raises(ValueError):
        planner.plan(PersistSpec(
            method=PersistMethod.CRONTAB,
            payload_path='/tmp/payload.sh"; rm -rf / #',
        ))
    # Reject schedule injection
    with pytest.raises(ValueError):
        planner.plan(PersistSpec(
            method=PersistMethod.CRONTAB,
            payload_path="/tmp/payload.sh",
            schedule='* * * * *; calc.exe; #',
        ))

