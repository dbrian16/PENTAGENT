"""Dynamic PoC synthesis: synth -> run -> self-debug -> proof-gated validation (offline)."""
from __future__ import annotations

from agentpentest.poc import PoCSpec, RunResult, execute_and_validate, local_runner, synthesize_poc
from agentpentest.security import ScopeError
from agentpentest.shellguard import ShellGuardError
from agentpentest.throttle import CircuitBreaker

TARGET = "example.com"
SCOPE = {"example.com"}


class ScriptedReasoner:
    """Pops canned LLM replies (fenced scripts); records the system prompts seen."""

    def __init__(self, replies):
        self._it = iter(replies)
        self.systems: list[str] = []

    def ask(self, system: str, user: str) -> str:
        self.systems.append(system)
        try:
            return next(self._it)
        except StopIteration:
            return ""


class ScriptedRunner:
    def __init__(self, results):
        self._it = iter(results)
        self.scripts: list[str] = []

    def __call__(self, script: str, language: str) -> RunResult:
        self.scripts.append(script)
        try:
            return next(self._it)
        except StopIteration:
            return RunResult(-1, "", "no more scripted results")


def _fenced(body: str) -> str:
    return f"```python\n{body}\n```"


def _spec(**kw):
    return PoCSpec(goal="auth bypass", target=TARGET, scope=SCOPE, **kw)


def test_validated_on_first_try():
    r = ScriptedReasoner([_fenced(f"print('POC-OK: hit {TARGET}')")])
    run = ScriptedRunner([RunResult(0, "POC-OK: dumped admin hash", "")])
    res = synthesize_poc(_spec(), r, run)
    assert res.validated and res.attempts == 1
    assert "admin hash" in res.evidence
    assert len(run.scripts) == 1


def test_self_debug_fixes_a_crashing_script():
    bad = _fenced(f"import nope  # {TARGET}")          # will 'crash'
    good = _fenced(f"print('POC-OK: {TARGET} pwned')")
    r = ScriptedReasoner([bad, good])
    run = ScriptedRunner([
        RunResult(1, "POC-FAIL: boom", "Traceback: ModuleNotFoundError: nope"),
        RunResult(0, "POC-OK: leaked /etc/passwd", ""),
    ])
    res = synthesize_poc(_spec(), r, run, max_fix=3)
    assert res.validated and res.attempts == 2
    assert len(run.scripts) == 2, "second (fixed) script must be executed"
    assert "fix" in r.systems[-1].lower(), "the model was asked to FIX after the crash"


def test_gives_up_after_max_fix_unvalidated():
    bad = _fenced(f"print('POC-FAIL: {TARGET}')")
    r = ScriptedReasoner([bad, bad, bad])
    run = ScriptedRunner([RunResult(1, "POC-FAIL: nope", "err") for _ in range(3)])
    res = synthesize_poc(_spec(), r, run, max_fix=3)
    assert not res.validated and res.attempts == 3
    assert res.error and len(run.scripts) == 3


def test_exit0_without_marker_is_not_validated():
    # the model's word ('it worked', exit 0) is NOT proof without the POC-OK marker.
    r = ScriptedReasoner([_fenced(f"print('done {TARGET}')")] * 3)
    run = ScriptedRunner([RunResult(0, "looks exploited to me", "") for _ in range(3)])
    res = synthesize_poc(_spec(), r, run, max_fix=3)
    assert not res.validated, "no POC-OK marker => unvalidated regardless of exit 0"


def test_target_binding_rejects_offtarget_script():
    offtarget = _fenced("print('POC-OK: hit evil.test')")   # no authorized target in it
    r = ScriptedReasoner([offtarget, offtarget, offtarget])
    run = ScriptedRunner([RunResult(0, "POC-OK: x", "")])
    res = synthesize_poc(_spec(), r, run, max_fix=3)
    assert not res.validated
    assert run.scripts == [], "an off-target script must never be executed"


def test_out_of_scope_target_refused():
    r = ScriptedReasoner([_fenced("print('x')")])
    run = ScriptedRunner([RunResult(0, "POC-OK: x", "")])
    try:
        synthesize_poc(PoCSpec(goal="x", target="notmine.com", scope=SCOPE), r, run)
    except ScopeError:
        pass
    else:
        raise AssertionError("out-of-scope target must raise ScopeError")


def test_build_only_default_runner_refuses():
    r = ScriptedReasoner([_fenced(f"print('POC-OK: {TARGET}')")])
    try:
        synthesize_poc(_spec(), r)                 # no runner wired
    except RuntimeError as e:
        assert "build-only" in str(e)
    else:
        raise AssertionError("default runner must refuse to execute a script")


def test_breaker_stops_retries_on_target_distress():
    bad = _fenced(f"print('POC-FAIL: {TARGET}')")
    r = ScriptedReasoner([bad] * 3)
    run = ScriptedRunner([RunResult(1, "Connection refused", "") for _ in range(3)])
    breaker = CircuitBreaker(max_consecutive_failures=1)
    res = synthesize_poc(_spec(), r, run, max_fix=3, breaker=breaker)
    assert not res.validated
    assert len(run.scripts) == 1, "breaker must stop further runs after the first distress sign"
    assert breaker.tripped


def test_breaker_does_not_interfere_on_clean_validation():
    r = ScriptedReasoner([_fenced(f"print('POC-OK: {TARGET}')")])
    run = ScriptedRunner([RunResult(0, "POC-OK: clean hit", "")])
    breaker = CircuitBreaker(max_consecutive_failures=1)
    res = synthesize_poc(_spec(), r, run, breaker=breaker)
    assert res.validated and not breaker.tripped


# --- execute_and_validate: the MCP-exposable single-shot path (no Reasoner) -------

def test_execute_and_validate_happy_path():
    run = ScriptedRunner([RunResult(0, f"POC-OK: hit {TARGET}", "")])
    res, ok, evidence = execute_and_validate(f"print('{TARGET}')", "python", TARGET, run)
    assert ok and f"hit {TARGET}" in evidence


def test_execute_and_validate_rejects_offtarget_script_unrun():
    run = ScriptedRunner([RunResult(0, "POC-OK: x", "")])
    try:
        execute_and_validate("print('evil.test')", "python", TARGET, run)
    except ShellGuardError:
        pass
    else:
        raise AssertionError("off-target script must be refused before running")
    assert run.scripts == []


# --- local_runner: writes a temp file and runs it via sandbox.exec_full ----------

class _FakeLocalSandbox:
    def __init__(self, stdout: str, code: int):
        self.stdout, self.code, self.argv = stdout, code, None

    def exec_full(self, argv):
        self.argv = argv
        return self.stdout, self.code


def test_local_runner_writes_file_and_reports_exit_code():
    sb = _FakeLocalSandbox(f"POC-OK: {TARGET}", 0)
    run = local_runner(sb)
    res = run(f"print('POC-OK: {TARGET}')", "python")
    assert res.exit_code == 0 and f"POC-OK: {TARGET}" in res.stdout
    assert sb.argv[0] == "python3" and sb.argv[1].endswith(".py")
    import os
    assert not os.path.exists(sb.argv[1]), "temp script must be cleaned up"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
