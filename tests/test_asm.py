"""Unit tests for the Attack Surface Management (ASM) & Drift Engine."""
import json
import pytest

from agentpentest.asm import (
    AssetRecord,
    AssetSnapshot,
    ASMAnalyzer,
    calculate_asset_drift,
    detect_cdn_presence,
    detect_wildcard_dns,
    format_asm_report,
    parse_ct_json,
    query_ct_logs,
)


def test_parse_ct_json_basic():
    sample_json = json.dumps([
        {"name_value": "api.example.com"},
        {"name_value": "auth.example.com\nadmin.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "unrelated.other.org"},
    ])
    subs = parse_ct_json(sample_json, "example.com")
    assert "api.example.com" in subs
    assert "auth.example.com" in subs
    assert "admin.example.com" in subs
    assert "dev.example.com" in subs   # stripped *.
    assert "unrelated.other.org" not in subs


def test_parse_ct_json_empty_and_malformed():
    assert parse_ct_json("", "example.com") == []
    assert parse_ct_json("not valid json", "example.com") == []
    assert parse_ct_json("{}", "example.com") == []


def test_query_ct_logs_with_mock_fetcher():
    mock_data = json.dumps([
        {"name_value": "portal.example.com"},
        {"name_value": "payments.example.com"},
    ])
    subs = query_ct_logs("example.com", fetcher=lambda url: mock_data)
    assert subs == ["payments.example.com", "portal.example.com"]


def test_detect_wildcard_dns_active():
    # Resolver that resolves everything to 203.0.113.1
    mock_resolver = lambda host: ["203.0.113.1"]
    res = detect_wildcard_dns("example.com", resolver=mock_resolver)
    assert res["is_wildcard"] is True
    assert "203.0.113.1" in res["wildcard_ips"]
    assert "avoid brute-force" in res["guidance"].lower() or "wildcard dns detected" in res["guidance"].lower()


def test_detect_wildcard_dns_inactive():
    # Resolver that returns empty (NXDOMAIN)
    mock_resolver = lambda host: []
    res = detect_wildcard_dns("example.com", resolver=mock_resolver)
    assert res["is_wildcard"] is False
    assert len(res["wildcard_ips"]) == 0


def test_detect_cdn_presence():
    cf_headers = {"Server": "cloudflare", "CF-RAY": "12345abcde"}
    res_cf = detect_cdn_presence(headers=cf_headers)
    assert res_cf["is_cdn"] is True
    assert "Cloudflare" in res_cf["providers"]

    clean_headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html"}
    res_clean = detect_cdn_presence(headers=clean_headers)
    assert res_clean["is_cdn"] is False


def test_asset_snapshot_save_load(tmp_path):
    snap = AssetSnapshot(domain="target.com")
    snap.add_asset(AssetRecord(
        identifier="api.target.com",
        ip_addresses=["192.168.1.10"],
        ports=[443, 80],
        tags=["staging", "api"],
    ))
    save_file = tmp_path / "snap.json"
    snap.save_json(save_file)

    loaded = AssetSnapshot.load_json(save_file)
    assert loaded.domain == "target.com"
    assert "api.target.com" in loaded.assets
    assert loaded.assets["api.target.com"].ports == [443, 80]


def test_calculate_asset_drift():
    # Snapshot t0
    t0 = AssetSnapshot(domain="corp.com", timestamp=1000.0)
    t0.add_asset(AssetRecord("stable.corp.com", ports=[80, 443]))
    t0.add_asset(AssetRecord("legacy.corp.com", ports=[80]))

    # Snapshot t1 (stable unchanged, legacy decommissioned, staging newly added, stable ports modified)
    t1 = AssetSnapshot(domain="corp.com", timestamp=2000.0)
    t1.add_asset(AssetRecord("stable.corp.com", ports=[80, 443, 8080]))   # new port 8080
    t1.add_asset(AssetRecord("staging-dev.corp.com", ports=[443], tags=["staging"]))

    drift = calculate_asset_drift(t0, t1)
    assert drift.has_drift is True
    assert len(drift.new_assets) == 1
    assert drift.new_assets[0].identifier == "staging-dev.corp.com"
    assert "legacy.corp.com" in drift.decommissioned_assets
    assert len(drift.modified_assets) == 1
    assert drift.modified_assets[0]["identifier"] == "stable.corp.com"
    assert drift.modified_assets[0]["changes"]["new_ports"] == [8080]

    # Verify high-priority triage queue
    priorities = {q["identifier"]: q["priority"] for q in drift.triage_queue}
    assert priorities["staging-dev.corp.com"] == "CRITICAL"   # "staging" tag triggers CRITICAL
    assert priorities["stable.corp.com"] == "HIGH"            # new port triggers HIGH


def test_asm_analyzer_full_cycle(tmp_path):
    analyzer = ASMAnalyzer("lab.com", storage_dir=tmp_path)
    mock_ct = json.dumps([{"name_value": "vpn.lab.com"}, {"name_value": "portal.lab.com"}])
    snap, drift = analyzer.run_sweep(
        seed_subdomains=["main.lab.com"],
        ct_fetcher=lambda url: mock_ct,
        dns_resolver=lambda host: [],
    )
    assert "vpn.lab.com" in snap.assets
    assert "portal.lab.com" in snap.assets
    assert "main.lab.com" in snap.assets
    assert len(drift.new_assets) == 3

    report_md = format_asm_report(drift)
    assert "Attack Surface Management (ASM) Drift Report: lab.com" in report_md
    assert "vpn.lab.com" in report_md


# ============================================================================
# Chapter 4 Native Document Store & Autonomous Pipeline Tests
# ============================================================================

from agentpentest.asm import (
    ASMDocumentStore,
    ASMAgentPipeline,
    SubdomainRecord,
    profile_http_endpoint,
    resolve_subdomain_dns,
)


def test_subdomain_record_schema():
    rec = SubdomainRecord(subdomain="api.example.com", domain="example.com")
    rec.dns["a"] = ["203.0.113.5"]
    rec.http["status_code"] = 200
    rec.http["webserver"] = "nginx/1.18.0"
    rec.http["hash"] = {"body_md5": "d41d8cd98f00b204e9800998ecf8427e", "header_md5": "abc"}
    rec.nuclei.append({"id": "cve-2023-1234", "severity": "high", "name": "Test Vuln"})

    d = rec.to_dict()
    assert d["subdomain"] == "api.example.com"
    assert d["http"]["status_code"] == 200
    assert d["dns"]["a"] == ["203.0.113.5"]
    assert len(d["nuclei"]) == 1

    loaded = SubdomainRecord.from_dict(d)
    assert loaded.subdomain == "api.example.com"
    assert loaded.nuclei[0]["id"] == "cve-2023-1234"


def test_asm_document_store(tmp_path):
    store = ASMDocumentStore(storage_dir=tmp_path)
    # Check non-existent domain history
    assert store.get_domain_history("newtarget.com") is None

    # Upsert record 1
    rec = SubdomainRecord(subdomain="auth.newtarget.com", domain="newtarget.com")
    rec.dns["a"] = ["192.168.1.10"]
    store.upsert_subdomain(rec)

    # Verify history now exists
    hist = store.get_domain_history("newtarget.com")
    assert hist is not None
    assert hist["total_subdomains"] == 1
    assert hist["live_subdomains"] == 1

    # Upsert same record with updated ports - createdAt should be preserved!
    first_created = store.get_subdomain("newtarget.com", "auth.newtarget.com").createdAt
    rec.port_scanning["ports"] = [80, 443]
    store.upsert_subdomain(rec)

    reloaded = store.get_subdomain("newtarget.com", "auth.newtarget.com")
    assert reloaded.createdAt == first_created
    assert reloaded.port_scanning["ports"] == [80, 443]


def test_profile_http_endpoint_with_mock():
    mock_fetcher = lambda **kwargs: {
        "url": f"https://{kwargs['subdomain']}:{kwargs['port']}",
        "scheme": "https",
        "port": 443,
        "status_code": 200,
        "webserver": "Apache/2.4.41",
        "tech": ["Apache", "PHP"],
        "content_length": 1024,
        "time": "0.15s",
        "failed": False,
        "title": "Login Portal",
        "hash": {"body_md5": "098f6bcd4621d373cade4e832627b4f6", "header_md5": "deadbeef"},
        "cdn_name": "",
        "cdn_type": "",
    }
    res = profile_http_endpoint("login.target.com", fetcher=mock_fetcher)
    assert res["status_code"] == 200
    assert "PHP" in res["tech"]
    assert res["hash"]["body_md5"] == "098f6bcd4621d373cade4e832627b4f6"


def test_asm_agent_pipeline_full_workflow(tmp_path):
    pipeline = ASMAgentPipeline("corp.com", storage_dir=tmp_path)

    # Stage 1: History check before scan
    h1 = pipeline.stage1_check_history()
    assert h1["has_history"] is False

    # Stage 2-4 mocks
    mock_ct = json.dumps([{"name_value": "api.corp.com"}, {"name_value": "admin.corp.com"}])
    mock_dns = lambda host: ["10.0.0.1"] if host.startswith("api") else []
    mock_prober = lambda **kw: {
        "url": f"https://{kw['subdomain']}:443",
        "status_code": 200,
        "webserver": "Nginx",
        "tech": ["Nginx"],
        "failed": False,
        "hash": {"body_md5": "aabbcc", "header_md5": "ddeeff"},
    }
    mock_vulns = lambda url: [{"id": "CVE-2024-9999", "severity": "critical", "name": "RCE in API"}]

    records, drift = pipeline.execute_full_pipeline(
        seed_subdomains=["www.corp.com"],
        ct_fetcher=lambda url: mock_ct,
        dns_resolver=mock_dns,
        http_prober=mock_prober,
        vuln_scanner=mock_vulns,
    )

    # Assertions on pipeline outcomes
    assert len(records) >= 3
    api_rec = next(r for r in records if r.subdomain == "api.corp.com")
    assert api_rec.dns["a"] == ["10.0.0.1"]
    assert api_rec.http["status_code"] == 200
    assert len(api_rec.nuclei) == 1
    assert api_rec.nuclei[0]["id"] == "CVE-2024-9999"

    # Stage 1: History check after scan
    h2 = pipeline.stage1_check_history()
    assert h2["has_history"] is True
    assert h2["data"]["total_subdomains"] >= 3
