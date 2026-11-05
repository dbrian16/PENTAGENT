"""T1070 Indicator Removal: log analysis + minimal-redaction plan (offline)."""
from __future__ import annotations

from agentpentest.covertrack import (RedactPlan, TrackSpec, _parse_plan,
                                     analyze_log, apply_redaction)

TARGET_IP = "10.10.10.5"
INDICATORS = [TARGET_IP, "nmap", "sqlmap"]

_AUTH_LOG = """\
Oct  4 08:00:01 host sshd[1234]: Accepted password for root from 192.168.1.1 port 22222
Oct  4 08:01:15 host sshd[1235]: Accepted password for admin from {ip} port 45678
Oct  4 08:01:17 host sshd[1235]: pam_unix: session opened for admin from {ip}
Oct  4 08:05:00 host sshd[1236]: Invalid user guest from 203.0.113.9 port 12000
Oct  4 08:06:00 host kernel: SCAN SRC={ip} DST=10.10.10.5 DPT=80""".format(ip=TARGET_IP)


class ScriptedReasoner:
    def __init__(self, reply: str):
        self._reply = reply
        self.prompts: list[tuple[str, str]] = []

    def ask(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        return self._reply


def _spec(**kw):
    return TrackSpec(log_type="auth", log_content=_AUTH_LOG,
                     indicators=INDICATORS, **kw)


# --- _parse_plan ----------------------------------------------------------

def test_parse_plan_extracts_valid_json():
    raw = '{"lines_to_remove": [1, 2, 4], "rationale": "our IP found"}'
    plan = _parse_plan(raw, "auth", 10)
    assert plan.lines_to_remove == [1, 2, 4]
    assert "our IP" in plan.rationale
    assert not plan.error


def test_parse_plan_drops_out_of_bounds():
    raw = '{"lines_to_remove": [0, 4, 99], "rationale": "x"}'
    plan = _parse_plan(raw, "auth", 5)  # valid range 0-4
    assert 99 not in plan.lines_to_remove
    assert 4 in plan.lines_to_remove
    assert 0 in plan.lines_to_remove


def test_parse_plan_deduplicates():
    raw = '{"lines_to_remove": [2, 2, 2], "rationale": "dup"}'
    plan = _parse_plan(raw, "auth", 10)
    assert plan.lines_to_remove == [2]


def test_parse_plan_handles_bad_json():
    plan = _parse_plan("no json here", "auth", 10)
    assert plan.error
    assert plan.lines_to_remove == []


def test_parse_plan_empty_array():
    raw = '{"lines_to_remove": [], "rationale": "nothing matched"}'
    plan = _parse_plan(raw, "auth", 5)
    assert plan.lines_to_remove == []
    assert not plan.error


# --- analyze_log ----------------------------------------------------------

def test_analyze_log_returns_correct_lines():
    reply = '{"lines_to_remove": [1, 2, 4], "rationale": "attacker IP found"}'
    r = ScriptedReasoner(reply)
    plan = analyze_log(_spec(), r)
    assert plan.lines_to_remove == [1, 2, 4]
    assert not plan.error


def test_analyze_log_scrubbed_content_removes_ip_lines():
    reply = '{"lines_to_remove": [1, 2, 4], "rationale": "our IP"}'
    r = ScriptedReasoner(reply)
    plan = analyze_log(_spec(), r)
    # lines 1, 2, 4 contain TARGET_IP - they must be gone
    assert TARGET_IP not in plan.scrubbed_content
    # line 0 and 3 are unrelated - they must survive
    assert "192.168.1.1" in plan.scrubbed_content
    assert "203.0.113.9" in plan.scrubbed_content


def test_analyze_log_sanitizes_log_before_llm():
    reply = '{"lines_to_remove": [], "rationale": "clean"}'
    r = ScriptedReasoner(reply)
    analyze_log(_spec(), r)
    _, user_msg = r.prompts[0]
    # security.sanitize_for_prompt prefixes lines with DATA|
    assert "DATA|" in user_msg, "log content must be sanitized before the LLM sees it"


def test_analyze_log_passes_indicators_to_llm():
    reply = '{"lines_to_remove": [], "rationale": "x"}'
    r = ScriptedReasoner(reply)
    analyze_log(_spec(), r)
    _, user_msg = r.prompts[0]
    assert TARGET_IP in user_msg
    assert "nmap" in user_msg


def test_analyze_log_session_start_included_when_given():
    reply = '{"lines_to_remove": [], "rationale": "x"}'
    r = ScriptedReasoner(reply)
    analyze_log(_spec(session_start="2026-10-04T08:00:00Z"), r)
    _, user_msg = r.prompts[0]
    assert "2026-10-04T08:00:00Z" in user_msg


def test_analyze_log_uses_t1070_prompt():
    reply = '{"lines_to_remove": [], "rationale": "x"}'
    r = ScriptedReasoner(reply)
    analyze_log(_spec(), r)
    sys_prompt, _ = r.prompts[0]
    assert "T1070" in sys_prompt, "system prompt must reference MITRE T1070"
    assert "auth" in sys_prompt, "log_type must be substituted into prompt"


def test_analyze_log_empty_lines_to_remove_preserves_all():
    reply = '{"lines_to_remove": [], "rationale": "nothing matched"}'
    r = ScriptedReasoner(reply)
    plan = analyze_log(_spec(), r)
    assert plan.scrubbed_content == _AUTH_LOG


def test_analyze_log_bad_llm_response_sets_error():
    r = ScriptedReasoner("sorry, I can't do that")
    plan = analyze_log(_spec(), r)
    assert plan.error
    assert plan.scrubbed_content == ""


# --- apply_redaction ------------------------------------------------------

def test_apply_redaction_calls_writer_with_scrubbed_content():
    written = {}

    def fake_writer(path: str, content: str) -> None:
        written["path"] = path
        written["content"] = content

    lines = _AUTH_LOG.splitlines()
    remove = {1, 2, 4}
    scrubbed = "\n".join(l for i, l in enumerate(lines) if i not in remove)
    plan = RedactPlan("auth", len(lines), sorted(remove), "our IP",
                      scrubbed_content=scrubbed)
    apply_redaction(plan, "/var/log/auth.log", fake_writer)
    assert written["path"] == "/var/log/auth.log"
    assert TARGET_IP not in written["content"]
    assert "192.168.1.1" in written["content"]


def test_apply_redaction_noop_on_empty_plan():
    called = []
    plan = RedactPlan("auth", 5, [], "nothing matched")
    apply_redaction(plan, "/var/log/auth.log", lambda p, c: called.append(1))
    assert called == []


def test_apply_redaction_noop_on_error_plan():
    called = []
    plan = RedactPlan("auth", 5, [1], "x", error="parse failed")
    apply_redaction(plan, "/var/log/auth.log", lambda p, c: called.append(1))
    assert called == []


def test_no_writer_refuses_by_default():
    lines = _AUTH_LOG.splitlines()
    plan = RedactPlan("auth", len(lines), [1], "x",
                      scrubbed_content="something")
    try:
        apply_redaction(plan, "/var/log/auth.log")   # no writer wired
    except RuntimeError as e:
        assert "build-only" in str(e)
    else:
        raise AssertionError("default writer must refuse")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
