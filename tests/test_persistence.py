"""Tests for agentpentest.persistence: methods, planning, execution, telemetry, and cleanup."""
import pytest
from agentpentest.persistence import (
    PersistMethod,
    PersistPlan,
    PersistSpec,
    PersistencePlanner,
    cleanup,
    detect_telemetry,
)


def test_persist_method_enum():
    assert PersistMethod.SCHEDULED_TASK == "SCHEDULED_TASK"
    assert PersistMethod.STARTUP_FOLDER == "STARTUP_FOLDER"
    assert PersistMethod.REGISTRY_RUN == "REGISTRY_RUN"
    assert PersistMethod.CRONTAB == "CRONTAB"
    assert PersistMethod.SYSTEMD_SERVICE == "SYSTEMD_SERVICE"
    assert PersistMethod.BASHRC == "BASHRC"


def test_scheduled_task_plan():
    planner = PersistencePlanner(mock=True)
    spec = PersistSpec(
        method=PersistMethod.SCHEDULED_TASK,
        payload_path=r"C:\Windows\Temp\updater.exe",
        name="SecurityUpdater",
        schedule="DAILY",
        user="SYSTEM",
        host="win2022.corp.local",
    )
    plan = planner.plan(spec)
    assert plan.mitre_id == "T1053.005"
    assert any("schtasks /create" in cmd and "SecurityUpdater" in cmd for cmd in plan.commands)
    assert any("schtasks /delete" in cmd for cmd in plan.cleanup_commands)
    assert r"C:\Windows\System32\Tasks\SecurityUpdater" in plan.artifacts
    assert "Event ID 4698" in plan.telemetry
    assert "Sysmon 1" in plan.telemetry
    assert "Sysmon 11" in plan.telemetry

    # Mock execution & cleanup
    assert planner.execute(plan) is True
    assert cleanup(plan, mock=True) is True


def test_startup_folder_plan():
    planner = PersistencePlanner(mock=True)
    spec = PersistSpec(
        method=PersistMethod.STARTUP_FOLDER,
        payload_path=r"C:\tools\agent.exe",
        name="AutoSync",
    )
    plan = planner.plan(spec)
    assert plan.mitre_id == "T1547.001"
    assert any("copy" in cmd and "Startup" in cmd for cmd in plan.commands)
    assert any("del" in cmd for cmd in plan.cleanup_commands)
    assert "Sysmon 11" in plan.telemetry
    assert planner.execute(plan) is True


def test_registry_run_plan():
    planner = PersistencePlanner(mock=True)
    spec = PersistSpec(
        method=PersistMethod.REGISTRY_RUN,
        payload_path=r"C:\Users\admin\run.exe",
        name="OneDriveHelper",
    )
    plan = planner.plan(spec)
    assert plan.mitre_id == "T1547.001"
    assert any("reg add" in cmd and "Run" in cmd for cmd in plan.commands)
    assert any("reg delete" in cmd for cmd in plan.cleanup_commands)
    assert "Sysmon 13" in plan.telemetry
    assert planner.execute(plan) is True


def test_crontab_plan():
    planner = PersistencePlanner(mock=True)
    spec = PersistSpec(
        method=PersistMethod.CRONTAB,
        payload_path="/opt/agent/agent.sh",
        schedule="0 * * * *",
        user="www-data",
    )
    plan = planner.plan(spec)
    assert plan.mitre_id == "T1053.003"
    assert any("crontab -" in cmd for cmd in plan.commands)
    assert any("grep -v" in cmd for cmd in plan.cleanup_commands)
    assert "/var/spool/cron/crontabs/www-data" in plan.artifacts
    assert "cron.log" in plan.telemetry
    assert planner.execute(plan) is True


def test_systemd_service_plan():
    planner = PersistencePlanner(mock=True)
    spec = PersistSpec(
        method=PersistMethod.SYSTEMD_SERVICE,
        payload_path="/usr/local/bin/agent_daemon",
        name="systemd-healthcheck",
    )
    plan = planner.plan(spec)
    assert plan.mitre_id == "T1543.002"
    assert any("systemctl enable" in cmd for cmd in plan.commands)
    assert any("systemctl stop" in cmd for cmd in plan.cleanup_commands)
    assert "/etc/systemd/system/systemd-healthcheck.service" in plan.artifacts
    assert "systemd journal" in plan.telemetry
    assert planner.execute(plan) is True


def test_bashrc_plan():
    planner = PersistencePlanner(mock=True)
    spec = PersistSpec(
        method=PersistMethod.BASHRC,
        payload_path="/tmp/backdoor.sh",
    )
    plan = planner.plan(spec)
    assert plan.mitre_id == "T1546.004"
    assert any("~/.bashrc" in cmd for cmd in plan.commands)
    assert "~/.bashrc" in plan.artifacts
    assert "bash_history" in plan.telemetry
    assert planner.execute(plan) is True


def test_auto_select():
    planner = PersistencePlanner(mock=True)
    spec_w = planner.auto_select("win-host", "Windows Server 2019", "C:\\agent.exe")
    assert spec_w.method == PersistMethod.SCHEDULED_TASK
    assert spec_w.host == "win-host"

    spec_l = planner.auto_select("linux-host", "Linux / Debian", "/opt/agent.sh")
    assert spec_l.method == PersistMethod.CRONTAB
    assert spec_l.host == "linux-host"


def test_detect_telemetry_keys():
    for method in PersistMethod:
        telem = detect_telemetry(method)
        assert isinstance(telem, list)
        assert len(telem) > 0
        for item in telem:
            assert "event_source" in item
            assert "event_id" in item
            assert "description" in item
            assert "sysmon_id" in item


def test_detect_telemetry_string_input():
    telem = detect_telemetry("scheduled_task")
    assert len(telem) > 0
    assert any(t["event_id"] == "4698" for t in telem)
