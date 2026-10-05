"""Runnable checks for the audit fixes. `python tests/test_audit_fixes.py`.

Covers:
  SEC-2  shellguard rejects a second, out-of-scope host in the command.
  BUG-1  a real (non-mock) run refuses to fake recon when the binary is absent.
  SEC-4  assert_external(strict=True) fails closed on an unresolvable host.
  SEC-5  AGENTPENTEST_STRICT_SSRF=1 makes the default (no strict=) fail closed.
  SEC-6  the web dashboard refuses cross-origin / foreign-Host POSTs (CSRF).
"""
import os

from agentpentest import shellguard
from agentpentest.executor import Executor
from agentpentest.planner import Task
from agentpentest.security import assert_external, SsrfError
from agentpentest.shellguard import _host_token
from agentpentest.webui import Handler


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


def test_sec5_env_flag_flips_default_to_fail_closed():
    assert_external("nonexistent.invalid")                 # no env, no strict=: ok
    os.environ["AGENTPENTEST_STRICT_SSRF"] = "1"
    try:
        assert_external("nonexistent.invalid")             # env on -> fail closed
        assert False, "strict env flag must refuse an unresolvable host by default"
    except SsrfError:
        pass
    finally:
        del os.environ["AGENTPENTEST_STRICT_SSRF"]


class _FakeReq:
    """Enough of a handler to call Handler._same_origin unbound (no real socket)."""
    def __init__(self, host, origin=None):
        self.headers = {"Host": host, **({"Origin": origin} if origin else {})}
        self.server = type("S", (), {"server_port": 8765})()


def test_sec6_dashboard_refuses_cross_origin_post():
    ok = Handler._same_origin(_FakeReq("127.0.0.1:8765"))                     # same-origin
    assert ok
    assert Handler._same_origin(_FakeReq("localhost:8765",
                                         "http://localhost:8765"))            # matching Origin
    assert not Handler._same_origin(_FakeReq("127.0.0.1:8765",
                                             "https://evil.example"))         # CSRF
    assert not Handler._same_origin(_FakeReq("attacker.com"))                 # DNS rebind


if __name__ == "__main__":
    test_sec2_rejects_extra_out_of_scope_host()
    test_sec2_host_token_does_not_flag_files_or_flags()
    test_bug1_real_run_refuses_to_fake_recon()
    test_sec4_strict_fails_closed_on_unresolvable()
    test_sec5_env_flag_flips_default_to_fail_closed()
    test_sec6_dashboard_refuses_cross_origin_post()
    print("ok")
