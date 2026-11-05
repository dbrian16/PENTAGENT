"""Unit tests for the SQLite run audit verification engine."""
from __future__ import annotations

from pathlib import Path
import sqlite3
import pytest

from agentpentest.audit import audit_run


def test_audit_run_validates_provenance_and_revision_continuity(tmp_path):
    """Create a hermetic SQLite run database and audit completion and provenance rules."""
    db_file = tmp_path / "run_audit.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE runs (run_id TEXT, status TEXT, revision INTEGER);")
    cur.execute("CREATE TABLE transitions (run_id TEXT, revision INTEGER);")
    cur.execute("CREATE TABLE tasks (id TEXT, run_id TEXT, kind TEXT, status TEXT, target TEXT, basis TEXT, deps TEXT);")
    cur.execute("CREATE TABLE observations (id TEXT, task_id TEXT, evidence_status TEXT, evidence TEXT);")

    # Seed valid completed run
    cur.execute("INSERT INTO runs VALUES ('run-1', 'completed', 2)")
    cur.execute("INSERT INTO transitions VALUES ('run-1', 1)")
    cur.execute("INSERT INTO transitions VALUES ('run-1', 2)")
    # Valid test and exploit with proper basis
    cur.execute("INSERT INTO tasks VALUES ('t1', 'run-1', 'test', 'done', 'target.corp', '[]', '[]')")
    cur.execute("INSERT INTO tasks VALUES ('t2', 'run-1', 'exploit', 'done', 'target.corp', '[\"t1\"]', '[\"t1\"]')")
    cur.execute("INSERT INTO observations VALUES ('o1', 't1', 'grounded', 'verified_token_present')")
    conn.commit()
    conn.close()

    # Audit the database
    res = audit_run(str(db_file), "run-1")
    assert res["passed"] is True, res.get("failures")
    assert res["failures"] == []


def test_audit_run_flags_uncompleted_run_failure(tmp_path):
    db_file = tmp_path / "uncompleted.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE runs (run_id TEXT, status TEXT, revision INTEGER);")
    cur.execute("CREATE TABLE transitions (run_id TEXT, revision INTEGER);")
    cur.execute("CREATE TABLE tasks (id TEXT, run_id TEXT, kind TEXT, status TEXT, target TEXT, basis TEXT, deps TEXT);")
    cur.execute("CREATE TABLE observations (id TEXT, task_id TEXT, evidence_status TEXT, evidence TEXT);")

    cur.execute("INSERT INTO runs VALUES ('run-2', 'active', 1)")
    cur.execute("INSERT INTO transitions VALUES ('run-2', 1)")
    conn.commit()
    conn.close()

    res = audit_run(str(db_file), "run-2")
    assert res["passed"] is False
    assert any("not marked completed" in f for f in res["failures"])
