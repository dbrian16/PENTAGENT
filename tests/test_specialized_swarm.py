"""Tests for the 5-Agent Specialized Swarm (Commander, Recon, Web, AD, Ghost)."""
from __future__ import annotations

import pytest

from agentpentest.specialized_swarm import (
    AgentRole,
    CommanderAgent,
    DomainInfiltratorAgent,
    GhostOperatorAgent,
    ReconScoutAgent,
    SpecializedSwarm,
    SwarmDirective,
    WebExploiterAgent,
)
from agentpentest.asset_vault import AssetVault


def test_commander_delegates_to_recon_initially():
    commander = CommanderAgent()
    role = commander.decide_next_phase(
        goal="penetrate target",
        scope=["192.168.1.50"],
        known_services=[],
        compromised_nodes=[],
        unresolved_hypotheses=[],
    )
    assert role == AgentRole.RECON_SCOUT


def test_recon_scout_plans_initial_and_script_scans():
    scout = ReconScoutAgent()

    # Step 1: Initial port scan
    d1 = scout.plan_recon("192.168.1.50", discovered_ports=[])
    assert d1.agent == AgentRole.RECON_SCOUT
    assert "nmap" in d1.command
    assert "192.168.1.50" in d1.command
    assert d1.mitre_technique == "T1046"

    # Step 2: Follow-up script scan
    d2 = scout.plan_recon("192.168.1.50", discovered_ports=[80, 445])
    assert "nmap" in d2.command
    assert "-sC" in d2.command or "-sV" in d2.command


def test_commander_dispatches_web_exploiter_when_http_discovered():
    commander = CommanderAgent()
    role = commander.decide_next_phase(
        goal="find web vulns",
        scope=["192.168.1.50"],
        known_services=[{"name": "http", "port": 80}],
        compromised_nodes=[],
        unresolved_hypotheses=[],
    )
    assert role == AgentRole.WEB_EXPLOITER


def test_web_exploiter_plans_nuclei_scan():
    web = WebExploiterAgent()
    d = web.plan_web_attack("192.168.1.50", port=80, cve_hint="CVE-2021-41773")
    assert d.agent == AgentRole.WEB_EXPLOITER
    assert "nuclei" in d.command
    assert "CVE-2021-41773" in d.command
    assert d.mitre_technique == "T1190"


def test_commander_dispatches_domain_infiltrator_when_smb_discovered():
    commander = CommanderAgent()
    role = commander.decide_next_phase(
        goal="domain compromise",
        scope=["192.168.1.50"],
        known_services=[{"name": "smb", "port": 445}],
        compromised_nodes=["host:192.168.1.50"],
        unresolved_hypotheses=[],
    )
    assert role == AgentRole.DOMAIN_INFILTRATOR


def test_domain_infiltrator_plans_asrep_and_secretsdump():
    vault = AssetVault()
    domain = DomainInfiltratorAgent(vault=vault)

    # Without credentials: AS-REP roasting
    d_asrep = domain.plan_domain_attack("192.168.1.50")
    assert "GetNPUsers" in d_asrep.command
    assert d_asrep.mitre_technique == "T1558.004"

    # With credentials stored in AssetVault
    cred = vault.put("Winter2026!", kind="password", principal="svc_backup")
    d_dump = domain.plan_domain_attack("192.168.1.50", cred_ref=cred.ref)
    assert "secretsdump" in d_dump.command
    assert "svc_backup" in d_dump.command
    assert d_dump.mitre_technique == "T1003.002"


def test_ghost_operator_stealth_evaluation_and_cleanup():
    ghost = GhostOperatorAgent(paranoia_level=1)

    # Moderate command -> evaluated
    directive = SwarmDirective(
        agent=AgentRole.RECON_SCOUT,
        action_type="shell",
        command="nmap -sS -p 80 192.168.1.50",
    )
    approved, score, reason = ghost.evaluate_stealth(directive)
    assert isinstance(approved, bool)
    assert isinstance(score, float)

    # Cleanup commands generated
    cleanup_directives = ghost.plan_cleanup(["192.168.1.50"])
    assert len(cleanup_directives) >= 1
    assert cleanup_directives[0].agent == AgentRole.GHOST_OPERATOR
    assert cleanup_directives[0].action_type == "cleanup"


def test_specialized_swarm_lifecycle():
    swarm = SpecializedSwarm("192.168.1.50")

    # Step 1: Swarm begins with Recon Scout
    step1 = swarm.next_step()
    assert step1.agent == AgentRole.RECON_SCOUT

    # Simulate execution output returning an open HTTP port
    mock_nmap = """
    <nmaprun>
      <host>
        <address addr="192.168.1.50" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4.49"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    res1 = swarm.record_execution(step1, stdout=mock_nmap, stderr="", exit_code=0)
    assert len(swarm.known_services) == 1
    assert swarm.known_services[0]["name"] == "http"

    # Step 2: Now that HTTP is known, Commander activates Web Exploiter
    step2 = swarm.next_step()
    assert step2.agent == AgentRole.WEB_EXPLOITER
    assert step2.approved is True
