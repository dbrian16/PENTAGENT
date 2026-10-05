"""SnapshotSandbox: checkpoint + rollback, driven by a FAKE docker runner (offline)."""
from __future__ import annotations

from agentpentest.sandbox import SnapshotSandbox


class FakeDocker:
    """Records every `docker <argv>` and returns canned stdout. Starts nothing real."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> str:
        self.calls.append(argv)
        if argv[0] == "exec":
            return "tool-output"
        return ""

    def verbs(self) -> list[str]:
        return [c[0] for c in self.calls]


def test_build_only_default_runner_refuses():
    sb = SnapshotSandbox()                 # no runner wired
    try:
        sb.start()
    except RuntimeError as e:
        assert "build-only" in str(e)
    else:
        raise AssertionError("default runner must refuse to start a container")


def test_start_locks_down_the_host():
    fk = FakeDocker()
    SnapshotSandbox(runner=fk, memory="1g", cpus="1").start()
    run = next(c for c in fk.calls if c[0] == "run")
    for flag in ("--cap-drop", "--security-opt", "--pids-limit", "--memory", "--cpus"):
        assert flag in run, f"host-safety flag missing: {flag}"
    assert "-v" not in run and "--volume" not in run, "no host bind mounts"


def test_exec_runs_inside_the_session_container():
    fk = FakeDocker()
    sb = SnapshotSandbox(runner=fk, name="sess")
    out = sb.exec(["nmap", "-sV", "t"])
    assert out == "tool-output"
    assert ["exec", "sess", "nmap", "-sV", "t"] in fk.calls


def test_snapshot_commits_and_stacks():
    fk = FakeDocker()
    sb = SnapshotSandbox(runner=fk)
    t1 = sb.snapshot("pre-sqli")
    t2 = sb.snapshot()
    assert fk.verbs().count("commit") == 2
    assert t1 != t2 and "pre-sqli" in t1
    assert sb._snaps == [t1, t2]


def test_rollback_recreates_from_last_snapshot():
    fk = FakeDocker()
    sb = SnapshotSandbox(runner=fk, name="sess")
    tag = sb.snapshot("good")
    sb.exec(["rm", "-rf", "/etc"])          # pretend a payload dirties the session
    fk.calls.clear()
    restored = sb.rollback()
    assert restored == tag
    assert fk.calls[0] == ["rm", "-f", "sess"], "dirtied container destroyed first"
    recreate = fk.calls[1]
    assert recreate[0] == "run" and tag in recreate, "recreated from the snapshot image"


def test_rollback_without_snapshot_raises():
    sb = SnapshotSandbox(runner=FakeDocker())
    try:
        sb.rollback()
    except RuntimeError:
        pass
    else:
        raise AssertionError("rollback with no checkpoint must raise")


def test_guarded_rolls_back_on_failure_only():
    fk = FakeDocker()
    sb = SnapshotSandbox(runner=fk, name="sess")

    with sb.guarded("safe"):               # clean exit -> keep state, no rollback
        sb.exec(["id"])
    assert "rm" not in [c[0] for c in fk.calls], "clean block must not roll back"

    fk.calls.clear()
    try:
        with sb.guarded("boom"):
            raise ValueError("payload crashed the session")
    except ValueError:
        pass
    verbs = fk.verbs()
    assert "commit" in verbs and "rm" in verbs and "run" in verbs, "failure must roll back"


def test_close_removes_container_and_snapshots():
    fk = FakeDocker()
    sb = SnapshotSandbox(runner=fk, name="sess")
    sb.snapshot()
    sb.close()
    assert ["rm", "-f", "sess"] in fk.calls
    assert any(c[0] == "rmi" for c in fk.calls), "snapshot images cleaned up"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
