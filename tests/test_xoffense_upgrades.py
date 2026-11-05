"""Tests for xOffense framework upgrades:
1. Auto-detect local AI & Think tag stripping (llm.py)
2. Success-Preserving MergeTasks (taskgraph.py, Algorithm 3)
3. Shell State Log & Inter-Agent PhaseSummary (state.py, Algorithm 4)
4. MemAgent Chunking & Large Output Filter (perceptor.py)
5. Grey-Box Prompting Contract (prompts.py)
6. Recovery RAG procedures (knowledge.py)
"""
import pytest

from agentpentest.llm import (
    strip_think_tags,
    parse_execute_block,
    parse_structured_json,
    detect_local_model,
)
from agentpentest.taskgraph import (
    Task,
    TaskKind,
    TaskStatus,
    merge_tasks,
    partition_tasks,
)
from agentpentest.state import (
    ShellSession,
    ShellStateLog,
    PhaseSummary,
    ReconState,
)
from agentpentest.perceptor import memagent_filter
from agentpentest.prompts import GREYBOX_CONTRACT, make_greybox_prompt
from agentpentest.knowledge import retrieve_recovery_procedures


def test_strip_think_tags_and_parse_execute():
    raw_llm_reply = (
        "<think>\n"
        "The target has port 80 open. Let's run nikto to find vulnerabilities.\n"
        "Nikto command is: nikto -h http://10.10.10.5\n"
        "</think>\n"
        "<execute>\n"
        "nikto -h http://10.10.10.5\n"
        "</execute>"
    )
    # 1. strip think tags
    stripped = strip_think_tags(raw_llm_reply)
    assert "<think>" not in stripped
    assert "The target has port 80" not in stripped

    # 2. parse execute block
    cmd = parse_execute_block(raw_llm_reply)
    assert cmd == "nikto -h http://10.10.10.5"


def test_parse_structured_json_with_think_and_xml_tags():
    raw_reply = (
        "<think>Formulating task plan for reconnaissance phase</think>\n"
        "<json>\n"
        '[\n'
        '  {"id": "1", "instruction": "nmap scan", "action": "Shell"},\n'
        '  {"id": "2", "instruction": "nikto scan", "action": "Web"}\n'
        ']\n'
        "</json>"
    )
    parsed = parse_structured_json(raw_reply)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["id"] == "1"
    assert parsed[1]["action"] == "Web"


def test_detect_local_model_fallback():
    # If connection fails or offline, detect_local_model returns None safely without crashing
    res = detect_local_model(host="http://127.0.0.1:59999", timeout=0.1)
    assert res is None


def test_merge_tasks_preserves_completed_and_updates_dependencies():
    # Old plan: t1 is DONE, t2 FAILED
    t1 = Task("t1", TaskKind.DISCOVER, "10.10.10.5", "port scan", status=TaskStatus.DONE)
    t2 = Task("t2", TaskKind.TEST, "10.10.10.5", "test sqli", depends_on=("t1",), status=TaskStatus.FAILED)
    old_plan = [t1, t2]

    # Partition test
    succ, fail = partition_tasks(old_plan)
    assert len(succ) == 1 and succ[0].id == "t1"
    assert len(fail) == 1 and fail[0].id == "t2"

    # New plan proposed after reflection: t3 replaces t2 with different objective
    t3 = Task("t3", TaskKind.TEST, "10.10.10.5", "test auth bypass", depends_on=("t1",))
    new_plan = [t3]

    merged = merge_tasks(old_plan, new_plan)
    # t1 should be preserved in DONE state
    m_ids = [t.id for t in merged]
    assert "t1" in m_ids
    assert "t3" in m_ids
    # t1 remains DONE
    t1_merged = next(t for t in merged if t.id == "t1")
    assert t1_merged.status == TaskStatus.DONE
    # t3 has dependency t1 satisfied, so it should be READY
    t3_merged = next(t for t in merged if t.id == "t3")
    assert t3_merged.status == TaskStatus.READY


def test_shell_state_log_and_persistence():
    state_log = ShellStateLog()
    assert state_log.current_privilege == "anonymous"

    # Record low-priv SSH session
    sess1 = ShellSession(
        session_id="s1",
        host="10.10.10.5",
        user="www-data",
        privilege="low_priv",
        os_type="linux",
    )
    state_log.record_session(sess1)
    assert state_log.current_privilege == "low_priv"
    assert state_log.current_user == "www-data"
    assert state_log.target_os == "linux"

    # Record root privilege escalation
    sess2 = ShellSession(
        session_id="s2",
        host="10.10.10.5",
        user="root",
        privilege="root_admin",
        os_type="linux",
    )
    state_log.record_session(sess2)
    assert state_log.current_privilege == "root_admin"
    assert state_log.current_user == "root"

    # Check summary string
    summary = state_log.to_summary()
    assert "root_admin" in summary
    assert "linux" in summary

    # ReconState serialization with ShellStateLog
    recon = ReconState(domain="target.lab")
    recon.shell_state = state_log
    serialized = recon.to_json()
    assert "root_admin" in serialized

    restored = ReconState.from_json(serialized)
    assert restored.shell_state.current_privilege == "root_admin"
    assert restored.shell_state.current_user == "root"


def test_phase_summary_synthesis():
    finished = [
        {"instruction": "Scan ports", "code": "nmap -sV 10.10.10.5", "result": "22, 80 open"},
        {"instruction": "Scan web", "code": "nikto -h 10.10.10.5", "result": "Apache 2.4.41"},
    ]
    summary = PhaseSummary.summarize_tasks("reconnaissance", finished, shell_desc="User: anon")
    assert "Phase Summary: RECONNAISSANCE" in summary.summary_text
    assert "nmap -sV" in summary.summary_text
    assert "Apache 2.4.41" in summary.summary_text


def test_memagent_large_output_filtering():
    # Generate 15,000 characters of repetitive 404 logs with a few hidden signals
    lines = ["Starting gobuster v3.8.2"]
    for i in range(1000):
        lines.append(f"/{i} (Status: 404) [Size: 154]")
    # Inject signal lines
    lines.append("/admin (Status: 200) [Size: 4096]")
    lines.append("/secret_login (Status: 301) [Size: 240]")
    lines.append("Found credentials: admin:SuperSecret123!")
    lines.append("Finished gobuster scan.")
    raw_dump = "\n".join(lines)
    assert len(raw_dump) > 10000

    # Apply MemAgent filter
    filtered = memagent_filter(raw_dump, max_chars=4000)
    assert len(filtered) <= 4000
    assert "MemAgent:" in filtered
    # Signal lines must be preserved!
    assert "/admin (Status: 200)" in filtered
    assert "/secret_login (Status: 301)" in filtered
    assert "admin:SuperSecret123!" in filtered


def test_greybox_prompt_and_recovery_procedures():
    prompt = make_greybox_prompt(
        objective="Get root flag on 10.10.10.5",
        scope=["10.10.10.5"],
        shell_state="OS: Linux | Priv: low_priv (User: www-data)",
        finished_tasks_summary="- Port 80, 22 discovered",
        phase="exploitation"
    )
    assert "STRICT OUTPUT CONTRACT" in prompt
    assert "<json>" in prompt
    assert "<execute>" in prompt
    assert "www-data" in prompt

    # Test recovery procedures retrieval
    rec = retrieve_recovery_procedures("hydra ssh login on 10.10.10.5")
    assert any("SSH" in r or "ssh" in r for r in rec)
