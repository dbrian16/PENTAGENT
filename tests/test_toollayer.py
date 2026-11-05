"""Typed Tool Layer (PentestGPT-2.0 style): resolve() builds exact argv from params,
rejects bad input as a Type-A failure, and the catalog/RAG feed the live planner."""
import pytest

from agentpentest import knowledge, tools


def test_resolve_builds_expected_argv():
    assert tools.resolve("port_scan", {"target": "scanme.local"}) == [
        "nmap", "-sV", "--top-ports", "100", "-oX", "-", "scanme.local"]
    # default port (80) applied -> http scheme
    argv = tools.resolve("dir_enum", {"target": "scanme.local"})
    assert argv[0] == "gobuster" and "http://scanme.local:80" in argv


def test_resolve_applies_and_validates_port():
    argv = tools.resolve("web_fingerprint", {"target": "x.local", "port": 443})
    assert "https://x.local:443" in argv              # 443 -> https scheme
    with pytest.raises(tools.ParamError):
        tools.resolve("web_fingerprint", {"target": "x.local", "port": 99999})


def test_resolve_rejects_injection_and_missing():
    with pytest.raises(tools.ParamError):
        tools.resolve("port_scan", {"target": "a.local; rm -rf /"})   # not a clean host
    with pytest.raises(tools.ParamError):
        tools.resolve("port_scan", {})                                 # missing target
    with pytest.raises(tools.ParamError):
        tools.resolve("no_such_tool", {"target": "a.local"})


def test_new_tools_resolve():
    assert tools.resolve("smb_enum", {"target": "dc.lab"}) == ["enum4linux-ng", "-A", "dc.lab"]
    assert tools.resolve("whois", {"target": "ex.lab"}) == ["whois", "ex.lab"]
    # snmp community defaults to "public" when omitted
    assert tools.resolve("snmp_enum", {"target": "ex.lab"}) == [
        "snmpwalk", "-v2c", "-c", "public", "ex.lab"]
    assert tools.resolve("snmp_enum", {"target": "ex.lab", "community": "private"})[3] == "private"
    assert "wafw00f" in tools.resolve("waf_detect", {"target": "ex.lab", "port": 443})[0]


def test_catalog_lists_tools_with_params():
    cat = tools.catalog()
    for name in ("port_scan", "web_fingerprint", "dns_recon", "web_vuln_scan",
                 "smb_enum", "snmp_enum", "wp_scan", "waf_detect", "whois"):
        assert name in cat
    assert "params:" in cat and "target:host" in cat
    assert "[SMB]" in cat and tools.catalog(phase="SMB").count("\n") >= 1


def test_hazard_tools_resolve_with_safe_flags():
    # httpx / ffuf build the URL deterministically
    assert tools.resolve("http_probe", {"target": "box.lab", "port": 443}) == [
        "httpx", "-json", "-silent", "-u", "https://box.lab:443"]
    assert "http://box.lab:80/FUZZ" in tools.resolve("fuzz_dirs", {"target": "box.lab"})
    # sqlmap is ALWAYS non-interactive + bounded (the anti-hang guarantee)
    argv = tools.resolve("sqli_scan", {"target": "box.lab", "url": "http://box.lab/i?id=1"})
    assert "--batch" in argv and "--timeout" in argv and "http://box.lab/i?id=1" in argv
    # netexec proto defaults to smb; a bad proto is rejected
    assert tools.resolve("netexec", {"target": "dc.lab"}) == ["netexec", "smb", "dc.lab"]
    assert tools.resolve("netexec", {"target": "dc.lab", "user": "a", "password": "b"})[-4:] == \
        ["-u", "a", "-p", "b"]
    with pytest.raises(tools.ParamError):
        tools.resolve("netexec", {"target": "dc.lab", "proto": "telnet"})
    # hydra stops on first hit and bounds each attempt
    h = tools.resolve("brute_login", {"target": "box.lab", "service": "ssh", "user": "root"})
    assert "hydra" in h and "-f" in h and "root" in h and "ssh" in h


def test_filter_peass_keeps_only_high_confidence():
    raw = tools.REGISTRY["linpeas"].mock
    out = tools.filter_peass(raw)
    names = [f["name"] for f in out["findings"]]
    assert any("sudo misconfig" in n for n in names)        # red line kept
    assert any("Writable /etc/passwd" in n for n in names)  # yellow line kept
    assert not any("uninteresting" in n for n in names)     # plain line dropped


def test_catalog_has_cred_and_privesc_phases():
    cat = tools.catalog()
    for name in ("http_probe", "fuzz_dirs", "sqli_scan", "netexec", "brute_login", "linpeas",
                 "secrets_dump", "kerberoast", "asrep_roast"):
        assert name in cat
    assert "[Cred]" in cat and "[PrivEsc]" in cat and "[AD]" in cat


def test_nmap_xml_parse_with_text_fallback():
    xml = ('<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5"/><ports>'
           '<port protocol="tcp" portid="22"><state state="open"/>'
           '<service name="ssh" product="OpenSSH" version="8.2p1"/></port>'
           '<port protocol="tcp" portid="81"><state state="closed"/></port>'
           '</ports></host></nmaprun>')
    svcs = tools.REGISTRY["port_scan"].parse(xml, {"target": "10.0.0.5"})["services"]
    assert len(svcs) == 1 and svcs[0]["port"] == 22 and svcs[0]["name"] == "ssh"
    assert svcs[0]["version"] == "OpenSSH 8.2p1"              # closed port dropped
    txt = tools.REGISTRY["port_scan"].parse("80/tcp open http nginx", {"target": "10.0.0.5"})
    assert txt["services"][0]["port"] == 80                   # text still parses (regex)


def test_impacket_resolve_and_parse():
    assert tools.resolve("secrets_dump", {"target": "10.0.0.5", "domain": "lab.local",
                         "user": "a", "password": "b"}) == [
        "impacket-secretsdump", "lab.local/a:b@10.0.0.5"]
    k = tools.resolve("kerberoast", {"target": "10.0.0.5", "domain": "lab.local",
                      "user": "a", "password": "b"})
    assert "-request" in k and "lab.local/a:b" in k
    a = tools.resolve("asrep_roast", {"target": "10.0.0.5", "domain": "lab.local"})
    assert "-usersfile" in a and "-dc-ip" in a
    with pytest.raises(tools.ParamError):
        tools.resolve("secrets_dump", {"target": "10.0.0.5", "user": "a", "password": "b"})
    # parse keeps only the hash, drops banners
    out = tools.REGISTRY["secrets_dump"].parse(tools.REGISTRY["secrets_dump"].mock, {})
    assert out["findings"][0]["name"].startswith("Administrator:500:")
    assert not any("Dumping" in f["name"] for f in out["findings"])
    kerb = tools.REGISTRY["kerberoast"].parse(tools.REGISTRY["kerberoast"].mock, {})
    assert kerb["findings"][0]["name"].startswith("$krb5tgs$")


def test_installed_tools_reach_the_live_planner(monkeypatch):
    from agentpentest import autonomous
    monkeypatch.setattr(autonomous.discover, "installed_tools", lambda: ["nmap", "nikto"])
    captured = {}

    class Rec:
        def ask(self, sys, user, **k):
            captured["user"] = user
            return '{"done":true}'

    autonomous.autoloop("g", {"box.lab"}, Rec(), lambda a, t: "", max_steps=1)
    assert "installed_kali_tools" in captured["user"] and "nikto" in captured["user"]


def test_knowledge_augment_is_text():
    out = knowledge.augment([{"services": [{"name": "http", "version": "nginx 1.18.0"}]}])
    assert isinstance(out, str)        # never raises on unknown services
    assert len(out) <= 2000
