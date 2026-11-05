"""Tests for PostRunSynthesizer, CVE matching, threat intel, and report generation."""
from __future__ import annotations

import json
from pathlib import Path

from agentpentest.autonomous import Step
from agentpentest.postrun import DiscoveredService, MatchedCVE, PostRunSynthesizer, post_run_report


def test_postrun_harvests_and_matches_cve(tmp_path: Path) -> None:
    target = "192.168.1.100"
    run_id = "test-run-1"

    transcript = [
        Step(
            command=["nmap", "-sV", target],
            target=target,
            rationale="enumerate ports and versions",
            raw="""Starting Nmap 7.92
Nmap scan report for 192.168.1.100
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache 2.4.49
22/tcp open  ssh     OpenSSH 8.2p1
Nmap done: 1 IP address scanned in 2.10 seconds
""",
            facts={
                "services": [
                    {"port": 80, "name": "http", "version": "Apache 2.4.49"},
                    {"port": 22, "name": "ssh", "version": "OpenSSH 8.2p1"},
                ]
            },
        ),
        Step(
            command=["nuclei", "-u", f"http://{target}", "-t", "cves/2021/CVE-2021-41773.yaml"],
            target=target,
            rationale="verify path traversal",
            raw="""[CVE-2021-41773] [http] [critical] http://192.168.1.100/icons/.%2e/%2e%2e/bin/sh
POC-OK: uid=0(root) gid=0(root) groups=0(root)
""",
            facts={},
        ),
    ]

    facts = [
        {
            "services": [
                {"port": 80, "name": "http", "version": "Apache 2.4.49"},
                {"port": 22, "name": "ssh", "version": "OpenSSH 8.2p1"},
            ]
        }
    ]

    synth, files = post_run_report(
        target=target,
        run_id=run_id,
        transcript=transcript,
        facts=facts,
        output_dir=str(tmp_path),
    )

    # Assert services were discovered
    ports = [s.port for s in synth.services]
    assert 80 in ports
    assert 22 in ports

    # Assert CVE was matched
    cve_ids = [c.id for c in synth.matched_cves]
    assert "CVE-2021-41773" in cve_ids

    cve_41773 = next(c for c in synth.matched_cves if c.id == "CVE-2021-41773")
    assert cve_41773.is_kev is True
    assert cve_41773.cvss >= 7.5
    assert cve_41773.source == "poc_verified"
    assert "POC-OK:" in cve_41773.proof_output

    # Assert report files were written
    assert Path(files["md"]).exists()
    assert Path(files["html"]).exists()
    assert Path(files["json"]).exists()

    md_content = Path(files["md"]).read_text(encoding="utf-8")
    assert "CVE-2021-41773" in md_content
    assert "CISA-KEV" in md_content
    assert "Apache 2.4.49" in md_content

    html_content = Path(files["html"]).read_text(encoding="utf-8")
    assert "CVE-2021-41773" in html_content
    assert "ACTIVE IN WILD" in html_content
    assert "<!doctype html>" in html_content

    with open(files["json"], encoding="utf-8") as f:
        data = json.load(f)
    assert data["metrics"]["total_services"] == 2
    assert data["metrics"]["kev_count"] >= 1


def test_postrun_extracts_credentials(tmp_path: Path) -> None:
    target = "10.0.0.5"
    run_id = "test-run-creds"

    transcript = [
        Step(
            command=["secretsdump.py", f"admin@{target}"],
            target=target,
            rationale="dump hashes",
            raw="Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n",
            facts={
                "credentials": [
                    {"user": "Administrator", "hash_nt": "8846f7eaee8fb117ad06bdd830b7586c", "source": "secretsdump"}
                ]
            },
        )
    ]

    synth, files = post_run_report(
        target=target,
        run_id=run_id,
        transcript=transcript,
        output_dir=str(tmp_path),
    )

    assert len(synth.credentials) == 1
    assert synth.credentials[0]["user"] == "Administrator"

    md_content = Path(files["md"]).read_text(encoding="utf-8")
    assert "Administrator" in md_content
    assert "REDACTED" in md_content
    assert "8846f7eaee8fb117ad06bdd830b7586c" not in md_content  # Redacted secret
