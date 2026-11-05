"""Typed task graph + SQLite canonical memory + audit (ported from PentestGPT 2.0)."""
import pytest

from agentpentest import audit
from agentpentest.memorydb import MemoryDB, MemoryError
from agentpentest.taskgraph import PlanError, Task, TaskKind, TaskStatus, can_finish


# ---- taskgraph rules ----
def test_exploit_requires_done_test_on_same_target():
    g = {"t1": Task("t1", TaskKind.TEST, "box.lab", "probe", status=TaskStatus.DONE)}
    # valid: EXPLOIT cites a DONE TEST on the same target
    ok = Task("x", TaskKind.EXPLOIT, "box.lab", "dump", basis_ids=("t1",), depends_on=("t1",))
    from agentpentest.taskgraph import validate_task
    validate_task(ok, g)                       # no raise
    # target mismatch -> refused
    with pytest.raises(PlanError):
        validate_task(Task("x2", TaskKind.EXPLOIT, "other.lab", "dump",
                           basis_ids=("t1",), depends_on=("t1",)), g)
    # TEST not done -> refused
    g2 = {"t1": Task("t1", TaskKind.TEST, "box.lab", "probe", status=TaskStatus.READY)}
    with pytest.raises(PlanError):
        validate_task(Task("x", TaskKind.EXPLOIT, "box.lab", "dump",
                           basis_ids=("t1",), depends_on=("t1",)), g2)


def _build_good_run(path) -> str:
    db = MemoryDB(path)
    db.open_run("r1", "capture the flag", ["box.lab"])
    db.add_task("r1", Task("t1", TaskKind.DISCOVER, "box.lab", "find web"))
    a1 = db.start_attempt("r1", "t1")
    db.add_observation("r1", "t1", a1, "web found", "PORT 80 open http", "80 open http")
    db.finish_attempt("r1", a1, "done", "ok")
    db.set_status("r1", "t1", TaskStatus.DONE)
    db.add_task("r1", Task("t2", TaskKind.TEST, "box.lab", "probe sqli", depends_on=("t1",)))
    a2 = db.start_attempt("r1", "t2")
    db.add_observation("r1", "t2", a2, "sqli", "PROOF: sqli at id", "PROOF: sqli at id")
    db.set_status("r1", "t2", TaskStatus.DONE)
    db.add_task("r1", Task("x", TaskKind.EXPLOIT, "box.lab", "dump",
                           basis_ids=("t2",), depends_on=("t2",)))
    ax = db.start_attempt("r1", "x")
    db.add_observation("r1", "x", ax, "flag", "FLAG{win}", "FLAG{win}")
    db.set_status("r1", "x", TaskStatus.DONE)
    db.finish_run("r1", ["x"])
    db.close()
    return "r1"


def test_memorydb_grounding_and_revisions(tmp_path):
    db = MemoryDB(tmp_path / "m.sqlite")
    db.open_run("r1", "goal", ["box.lab"])
    db.add_task("r1", Task("t1", TaskKind.DISCOVER, "box.lab", "find"))
    a1 = db.start_attempt("r1", "t1")
    # grounded: excerpt is an exact slice of the output
    _, st = db.add_observation("r1", "t1", a1, "svc", "22/tcp open ssh", "22/tcp open ssh")
    assert st == "grounded"
    # paraphrase: not stored as evidence
    oid, st = db.add_observation("r1", "t1", a1, "guess", "22/tcp open ssh", "ssh is open")
    assert st == "unresolved"
    assert len(db.grounded_observations("r1")) == 1      # only the exact one counts
    assert db.revision("r1") > 0
    # cannot finish while t1 is still open
    with pytest.raises(MemoryError):
        db.finish_run("r1", ["t1"])
    db.close()


def test_audit_passes_good_run_and_checks_oracle(tmp_path):
    path = tmp_path / "run.sqlite"
    _build_good_run(path)
    report = audit.audit_run(path, "r1", expected_flag="FLAG{win}")
    assert report["passed"] is True, report["failures"]
    assert report["checks"]["exploit_provenance"] is True
    assert report["checks"]["oracle_flag"] is True
    # wrong flag -> oracle fails, overall fails
    bad = audit.audit_run(path, "r1", expected_flag="FLAG{nope}")
    assert bad["passed"] is False and bad["checks"]["oracle_flag"] is False


def test_coredteam_on_attempt_persists_and_audits(tmp_path):
    """The Co-RedTeam on_attempt hook persists grounded evidence; the run then audits."""
    from agentpentest import audit
    from agentpentest.statemachine import (CoRedTeam, ExecResult, Hypothesis, PlanStep,
                                           shellguard_validator)
    db = MemoryDB(tmp_path / "ct.sqlite")
    db.open_run("c1", "ctf", ["box.lab"])

    def analyze(ctx):
        return [Hypothesis("h1", "SQLi on /login", "T1190", priority=0.9)]

    def plan(h, feedback):
        return [PlanStep("sqlmap -u http://box.lab/login --batch", "exploit")]

    def execute(step):
        return ExecResult(stdout="PROOF: dumped users table", exit_code=0)

    created: set = set()

    def on_attempt(h, step, res):
        tid = f"h-{h.id}"
        if tid not in created:
            db.add_task("c1", Task(tid, TaskKind.TEST, "box.lab", h.claim)); created.add(tid)
        aid = db.start_attempt("c1", tid)
        db.add_observation("c1", tid, aid, step.action, res.stdout, "PROOF: dumped users table")
        db.finish_attempt("c1", aid, "done" if res.ok else "failed", step.action)

    team = CoRedTeam(analyze, plan, executor=execute, validator=shellguard_validator(),
                     on_attempt=on_attempt)
    results = team.run({})
    for h in results:
        if f"h-{h.id}" in created:
            db.set_status("c1", f"h-{h.id}",
                          TaskStatus.DONE if h.status.value == "confirmed" else TaskStatus.FAILED)
    grounded = {r["task_id"] for r in db.grounded_observations("c1")}
    basis = sorted(grounded & {f"h-{h.id}" for h in results if h.status.value == "confirmed"})
    if basis:
        db.finish_run("c1", basis)
    db.close()
    rep = audit.audit_run(tmp_path / "ct.sqlite", "c1")
    assert rep["passed"] is True, rep["failures"]
    assert rep["summary"]["grounded_observations"] >= 1


def test_audit_flags_incomplete_run(tmp_path):
    db = MemoryDB(tmp_path / "x.sqlite")
    db.open_run("r2", "g", ["box.lab"])
    db.add_task("r2", Task("t1", TaskKind.DISCOVER, "box.lab", "find"))
    db.close()
    report = audit.audit_run(tmp_path / "x.sqlite", "r2")
    assert report["passed"] is False
    assert report["checks"]["structural_completion"] is False
