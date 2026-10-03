"""Runnable checks for the audit fixes. `python tests/test_audit_fixes.py`.

Covers:
  SEC-2  shellguard rejects a second, out-of-scope host in the command.
  BUG-1  a real (non-mock) run refuses to fake recon when the binary is absent.
  SEC-4  assert_external(strict=True) fails closed on an unresolvable host.
"""
from agentpentest import shellguard
from agentpentest.executor import Executor
from agentpentest.planner import Task
from agentpentest.security import assert_external, SsrfError
from agentpentest.shellguard import _host_token


def test_sec2_rejects_extra_out_of_scope_host():
    scope = {"example.com"}
    # the declared target alone is fine
    shellguard.validate(["nmap", "example.com"], "example.com", scope)
    # a smuggled second host must be refused even though the target appears
    try:
        shellguard.validate(["nmap", "example.com", "evil.com"], "example.com", scope)
        assert False, "out-of-scope second host must raise"
    except shellguard.ScopeError:
        pass
    # an in-scope subdomain as the extra host is allowed
    shellguard.validate(["nmap", "example.com", "api.example.com"], "example.com", scope)


def test_sec2_host_token_does_not_flag_files_or_flags():
    assert _host_token("-w") is None
    assert _host_token("/usr/share/wordlists/dirb/common.txt") is None
    assert _host_token("wordlist.txt") is None
    assert _host_token("example.com") == "example.com"
    assert _host_token("https://example.com:8443/path") == "example.com"
    assert _host_token("203.0.113.9") == "203.0.113.9"


class _Unavailable:
    def available(self, binary): return False
    def exec(self, argv): return "SHOULD NOT RUN"


def test_bug1_real_run_refuses_to_fake_recon():
    ex = Executor(scope={"example.com"}, sandbox=_Unavailable(), mock=False)
    try:
        ex.run(Task("subdomain_enum", "example.com"))
        assert False, "missing binary in a real run must raise, not return mock"
    except RuntimeError as e:
        assert "refusing to fake" in str(e)
    # mock=True still uses the simulator deliberately
    assert Executor(scope={"example.com"}, mock=True).run(Task("subdomain_enum", "example.com"))


def test_sec4_strict_fails_closed_on_unresolvable():
    assert_external("example.com", strict=False)           # fail-open default: ok
    try:
        assert_external("nonexistent.invalid", strict=True)
        assert False, "strict mode must refuse an unresolvable host"
    except SsrfError:
        pass


if __name__ == "__main__":
    test_sec2_rejects_extra_out_of_scope_host()
    test_sec2_host_token_does_not_flag_files_or_flags()
    test_bug1_real_run_refuses_to_fake_recon()
    test_sec4_strict_fails_closed_on_unresolvable()
    print("ok")
