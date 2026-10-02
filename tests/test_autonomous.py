"""Autonomous terminal mode: guardrails + the plan/execute/perceive loop.
`PYTHONPATH=. python tests/test_autonomous.py` — offline, no Ollama, nothing runs."""
from agentpentest import shellguard
from agentpentest.autonomous import autoloop
from agentpentest.llm import MockReasoner
from agentpentest.security import ScopeError

SCOPE = {"example.com"}


def test_shellguard_accepts_valid_tool():
    shellguard.validate(["nmap", "-sV", "example.com"], "example.com", SCOPE,
                        allow_internal=True)              # allow_internal => no DNS


def test_shellguard_refuses_destructive():
    try:
        shellguard.validate(["rm", "-rf", "example.com"], "example.com", SCOPE,
                            allow_internal=True)
        assert False
    except shellguard.ShellGuardError:
        pass


def test_shellguard_scope_and_allowlist_and_binding():
    # out of scope
    try:
        shellguard.validate(["nmap", "evil.com"], "evil.com", SCOPE, allow_internal=True)
        assert False
    except ScopeError:
        pass
    # not in allowlist
    try:
        shellguard.validate(["nikto", "-h", "example.com"], "example.com", SCOPE,
                            allow_internal=True, allowlist=["nmap"])
        assert False
    except shellguard.ShellGuardError:
        pass
    # target not present in the command (model can't scan something else)
    try:
        shellguard.validate(["nmap", "other.com"], "example.com", SCOPE, allow_internal=True)
        assert False
    except shellguard.ShellGuardError:
        pass


class _StubLLM:
    """Deterministic stand-in: plan calls return queued JSON, perceive returns facts."""
    def __init__(self, plans, facts='{"services":[{"port":80,"name":"http"}]}'):
        self.plans, self.facts, self.i = list(plans), facts, 0

    def ask(self, system, user):
        if "autonomous penetration tester" in system:
            p = self.plans[self.i] if self.i < len(self.plans) else '{"done":true}'
            self.i += 1
            return p
        return self.facts


def test_autoloop_runs_any_tool_without_wiring():
    executed = []

    def execute(argv, target):                            # injected simulator
        executed.append((argv, target))
        return "80/tcp open http nginx 1.18.0"

    plans = ['{"command":["whatweb","https://example.com"],"target":"example.com","rationale":"fingerprint"}']
    tr = autoloop("fingerprint example.com", SCOPE, _StubLLM(plans), execute,
                  allow_internal=True, max_steps=5)
    # whatweb was never wired as a ToolSpec — the LLM just used it.
    assert len(tr) == 1 and tr[0].command[0] == "whatweb"
    assert tr[0].facts.get("services") and executed


def test_autoloop_refuses_bad_command_without_executing():
    executed = []
    plans = ['{"command":["rm","-rf","example.com"],"target":"example.com","rationale":"nope"}']
    tr = autoloop("x", SCOPE, _StubLLM(plans),
                  lambda a, t: executed.append(1) or "", allow_internal=True, max_steps=3)
    assert tr == [] and not executed                      # destructive never executed


def test_autoloop_noop_offline():
    executed = []
    tr = autoloop("x", SCOPE, MockReasoner(), lambda a, t: executed.append(1) or "")
    assert tr == [] and not executed                      # no model => no commands


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok")
