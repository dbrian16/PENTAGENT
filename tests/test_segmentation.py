"""Unit tests for the PCI DSS Segmentation & Internal Network Verification Engine."""
import pytest

from agentpentest.asm import AssetDrift, AssetRecord
from agentpentest.ptt import Evidence, PentestTree
from agentpentest.report import generate, to_dict
from agentpentest.segmentation import (
    ACLRule,
    NetworkZone,
    SegmentedHost,
    SegmentationEngine,
    SegmentationViolation,
    ZoneType,
    format_pci_report,
)


def test_network_zone_contains_ip():
    z = NetworkZone("cde", ZoneType.CDE, ["10.200.1.0/24", "192.168.100.0/28"])
    assert z.contains_ip("10.200.1.50") is True
    assert z.contains_ip("10.200.2.1") is False
    assert z.contains_ip("192.168.100.5") is True
    assert z.contains_ip("invalid-ip") is False


def test_segmentation_direct_breach():
    engine = SegmentationEngine()
    z_cde = NetworkZone("CDE", ZoneType.CDE, ["10.200.1.0/24"])
    z_non = NetworkZone("Corp", ZoneType.NON_CDE, ["10.10.1.0/24"])
    engine.add_zone(z_cde)
    engine.add_zone(z_non)

    engine.add_host(SegmentedHost("10.10.1.5", "Corp"))
    engine.add_host(SegmentedHost("10.200.1.10", "CDE", {443: "payment-api", 3306: "mysql"}))

    # Erroneous firewall rule: allows Corp -> CDE 443
    engine.add_rule(ACLRule("R1", "Corp", "CDE", "ALLOW", [443], "tcp", "Erroneous portal rule"))

    violations = engine.check_direct_breaches()
    assert len(violations) == 1
    v = violations[0]
    assert v.violation_type == "DIRECT_BREACH"
    assert v.severity == "CRITICAL"
    assert v.source_host == "10.10.1.5"
    assert v.target_host == "10.200.1.10"
    assert v.target_port == 443


def test_segmentation_lateral_pivot_pathway():
    engine = SegmentationEngine()
    z_corp = NetworkZone("Corp", ZoneType.NON_CDE, ["10.10.1.0/24"])
    z_mgmt = NetworkZone("Shared_Mgmt", ZoneType.CONNECTED_TO, ["10.100.1.0/24"])
    z_cde = NetworkZone("CDE", ZoneType.CDE, ["10.200.1.0/24"])

    engine.add_zone(z_corp)
    engine.add_zone(z_mgmt)
    engine.add_zone(z_cde)

    # Hosts: Workstation in Corp, Jump host in Mgmt, Database in CDE
    engine.add_host(SegmentedHost("10.10.1.20", "Corp"))
    engine.add_host(SegmentedHost("10.100.1.10", "Shared_Mgmt", {22: "ssh"}, is_jump_host=True))
    engine.add_host(SegmentedHost("10.200.1.50", "CDE", {3306: "mysql"}))

    # Rule 1: Corp -> Mgmt SSH (Allowed)
    engine.add_rule(ACLRule("R-SSH", "Corp", "Shared_Mgmt", "ALLOW", [22], "tcp"))
    # Rule 2: Mgmt -> CDE MySQL (Allowed)
    engine.add_rule(ACLRule("R-DB", "Shared_Mgmt", "CDE", "ALLOW", [3306], "tcp"))

    # Direct breach should be 0 because Corp -> CDE is blocked by default
    assert len(engine.check_direct_breaches()) == 0

    # But lateral pivot should detect the realistic 2-hop pathway!
    pivots = engine.check_lateral_pivot_pathways()
    assert len(pivots) == 1
    p = pivots[0]
    assert p.violation_type == "LATERAL_PIVOT_PATH"
    assert p.severity == "HIGH"
    assert len(p.pivot_chain) == 3
    assert "10.10.1.20" in p.pivot_chain[0]
    assert "10.100.1.10:22" in p.pivot_chain[1]
    assert "10.200.1.50:3306" in p.pivot_chain[2]


def test_segmentation_dual_homed_bypass():
    engine = SegmentationEngine()
    z_corp = NetworkZone("Corp", ZoneType.NON_CDE, ["10.10.1.0/24"])
    z_cde = NetworkZone("CDE", ZoneType.CDE, ["10.200.1.0/24"])
    engine.add_zone(z_corp)
    engine.add_zone(z_cde)

    # Dual-homed server with interfaces in both subnets
    engine.add_host(SegmentedHost("10.200.1.99", "CDE", {8080: "pos"}, interfaces=["10.200.1.99", "10.10.1.99"]))

    violations = engine.check_dual_homed_bypasses()
    assert len(violations) == 1
    v = violations[0]
    assert v.violation_type == "DUAL_HOMED_BYPASS"
    assert v.severity == "CRITICAL"


def test_segmentation_clean_environment():
    engine = SegmentationEngine()
    z_corp = NetworkZone("Corp", ZoneType.NON_CDE, ["10.10.1.0/24"])
    z_cde = NetworkZone("CDE", ZoneType.CDE, ["10.200.1.0/24"])
    engine.add_zone(z_corp)
    engine.add_zone(z_cde)

    engine.add_host(SegmentedHost("10.10.1.5", "Corp"))
    engine.add_host(SegmentedHost("10.200.1.10", "CDE", {443: "payment-api"}))
    # No allow rules -> Strict implicit deny

    violations = engine.run_full_assessment()
    assert len(violations) == 0

    report = format_pci_report(violations, [z_corp, z_cde])
    assert "COMPLIANT (Segmentation Verified)" in report
    assert "Total Violations Found**: 0" in report


def test_report_generation_with_asm_and_pci():
    tree = PentestTree("example.com")
    nid = tree.add("host example.com", tree.root_id, Evidence.CONFIRMED, "T1046")
    tree.nodes[nid].status = "success"

    # Mock ASM Drift
    drift = AssetDrift(
        domain="example.com",
        previous_timestamp=100.0,
        current_timestamp=200.0,
        new_assets=[AssetRecord("dev.example.com", tags=["staging"])],
        triage_queue=[{"identifier": "dev.example.com", "priority": "CRITICAL", "reason": "NEW_EXPOSURE", "action": "scan"}],
    )

    # Mock PCI Violation
    vio = SegmentationViolation(
        violation_id="PCI-VIO-01",
        severity="CRITICAL",
        violation_type="DIRECT_BREACH",
        source_host="10.10.1.5",
        source_zone="Corp",
        target_host="10.200.1.5",
        target_zone="CDE",
        target_port=443,
        service="https",
        description="Direct exposure test",
        remediation="Revoke rule",
    )

    md = generate(tree, asm_drift=drift, pci_violations=[vio])
    assert "## Attack surface management (ASM) & drift analysis" in md
    assert "Drift detected: **YES ⚠**" in md
    assert "## PCI DSS v4.0 Network segmentation verification (Req 11.4.5)" in md
    assert "NON-COMPLIANT ❌" in md
    assert "PCI-VIO-01" in md

    # Check to_dict structured JSON export
    d = to_dict(tree, asm_drift=drift, pci_violations=[vio])
    assert d["asm_drift"] is not None
    assert d["asm_drift"]["summary"]["new"] == 1
    assert d["pci_violations"] is not None
    assert len(d["pci_violations"]) == 1
    assert d["pci_violations"][0]["violation_id"] == "PCI-VIO-01"
