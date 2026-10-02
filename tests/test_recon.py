"""One runnable check for the PEP loop. `python test_recon.py` — no framework."""
from agentpentest.executor import Executor, ScopeError
from agentpentest.orchestrator import run_recon
from agentpentest.planner import Task
from agentpentest.sandbox import LocalSandbox
from agentpentest.security import is_internal, SsrfError


def test_scope_guard():
    ex = Executor(scope={"example.com"}, mock=True)
    assert ex.run(Task("subdomain_enum", "api.example.com"))       # subdomain ok
    try:
        ex.run(Task("port_scan", "evil.test"))
        assert False, "out-of-scope target must raise"
    except ScopeError:
        pass


def test_no_command_injection():
    # an LLM emitting a shell-metachar target must be rejected at param-validation,
    # not passed to a tool. Scope allows the root so we reach the build() guard.
    ex = Executor(scope={"example.com; rm -rf /"}, mock=True)
    try:
        ex.run(Task("port_scan", "example.com; rm -rf /"))
        assert False, "shell metachars in target must raise ValueError"
    except ValueError:
        pass


def test_ssrf_guard_blocks_internal():
    # literal internal IPs are judged offline (no DNS needed).
    assert is_internal("127.0.0.1") is True
    assert is_internal("10.1.2.3") is True
    assert is_internal("169.254.1.1") is True      # link-local
    assert is_internal("8.8.8.8") is False
    # a real run (mock=False) at an in-scope but internal target must be refused.
    ex = Executor(scope={"10.0.0.5"}, sandbox=LocalSandbox(), mock=False)
    try:
        ex.run(Task("port_scan", "10.0.0.5"))
        assert False, "internal target must raise SsrfError"
    except SsrfError:
        pass
    # ...unless internal testing is explicitly authorized.
    ex2 = Executor(scope={"10.0.0.5"}, mock=True, allow_internal=True)
    assert ex2.run(Task("port_scan", "10.0.0.5"))


def test_full_loop_discovers_and_chains():
    s = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)
    # subdomain_enum found subs -> each became a scan target
    assert "api.example.com" in s.subdomains
    # port_scan parsed services with versions
    root = s.hosts["example.com"]
    assert root.scanned and 80 in root.open_ports()
    assert any("nginx" in svc.version for svc in root.services)
    # dir_enum chained off the http service (precondition satisfied by perceive)
    assert "/admin" in s.paths["example.com:80"]
    # loop reached a fixed point: no task repeated
    assert len(s.log) == len(set(s.log)), "a task ran twice"


if __name__ == "__main__":
    test_scope_guard()
    test_no_command_injection()
    test_ssrf_guard_blocks_internal()
    test_full_loop_discovers_and_chains()
    print("ok")
