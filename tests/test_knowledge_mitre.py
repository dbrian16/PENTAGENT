"""Tests for the compiled MITRE ATT&CK knowledge base and compiler cache invalidation."""
from __future__ import annotations

import os
from pathlib import Path
import time
import pytest

from agentpentest import knowledge
from agentpentest.mitre_compiler import COMPILED_PATH, CSV_PATH, compile_mitre_csv, ensure_compiled
from agentpentest.ptt import Evidence


def test_ensure_compiled_produces_valid_json():
    compiled_file = ensure_compiled()
    assert compiled_file is not None
    assert compiled_file.exists()
    assert compiled_file.stat().st_size > 100 * 1024  # > 100KB


def test_all_techniques_loaded_comprehensively():
    techs = knowledge.all_techniques()
    assert len(techs) >= 1184
    # Legacy custom IDOR preserved
    assert "IDOR" in techs
    # Enterprise ATT&CK techniques present
    assert "T1059.001" in techs
    assert "T1053.005" in techs
    assert "T1190" in techs


def test_technique_details_query():
    ps = knowledge.technique("T1059.001")
    assert ps["name"] == "PowerShell"
    assert "Windows" in ps.get("platforms", [])
    assert len(knowledge.platforms("T1059.001")) > 0
    assert knowledge.remediation("T1059.001") != ""


def test_service_map_expansion():
    # New services mapped cleanly
    ldap = knowledge.for_service("ldap")
    assert ldap is not None
    assert ldap[0] == "T1087.002"
    assert ldap[1] == Evidence.SPECULATIVE

    winrm = knowledge.for_service("winrm")
    assert winrm is not None
    assert winrm[0] == "T1021.006"

    redis = knowledge.for_service("redis")
    assert redis is not None
    assert redis[0] == "T1190"


def test_threat_groups_query():
    # Query by name (case-insensitive)
    apt28 = knowledge.group("apt28")
    assert apt28.get("id") == "G0007"
    assert "T1059.001" in apt28.get("techniques", [])

    # Query by ID
    g7 = knowledge.group("G0007")
    assert g7.get("name") == "APT28"


def test_software_query():
    mimi = knowledge.software("Mimikatz")
    assert mimi.get("id") == "S0002"
    assert mimi.get("type") in ("tool", "malware")


def test_groups_using_technique():
    users = knowledge.groups_using_technique("T1059.001")
    assert len(users) > 0
    assert any(u.get("name") for u in users)


def test_mtime_cache_invalidation(tmp_path: Path):
    # Test compilation logic in isolated tmp directory
    mock_csv = tmp_path / "mock.csv"
    mock_json = tmp_path / "mock.json"

    # Write mini CSV
    header = "domain,type,id,name,external_ids,description,created,modified,revoked,deprecated,platforms,tactics,url,labels,kill_chain_phases,raw_json\n"
    row1 = 'enterprise,attack-pattern,attack-pattern--1,Mock Tech,T9999,"Mock Description",2026-01-01,2026-01-01,,,,Linux,execution,,,,{}\n'
    mock_csv.write_text(header + row1, encoding="utf-8")

    stats = compile_mitre_csv(mock_csv, mock_json)
    assert stats["techniques"] == 1
    assert mock_json.exists()
