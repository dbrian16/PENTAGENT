"""Unit tests for the Web Application Attack Surface & Vulnerability Scanner (Chapter 5)."""
import pytest

from agentpentest.web_scanner import (
    FormInput,
    WebAttackSurface,
    WebForm,
    XSSFinding,
    SQLiFinding,
    format_web_report,
    map_web_surface,
    run_web_assessment,
    scan_dom_xss,
    scan_reflected_xss,
    scan_sqli,
)


SAMPLE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Acme Test Portal</title>
</head>
<body>
    <h1>Welcome</h1>
    <a href="/products.php?cat=1">Products</a>
    <a href="https://external.com/faq">External FAQ</a>
    
    <form action="/login.php" method="POST">
        <input type="text" name="uname" id="user_id" value="admin">
        <input type="password" name="pass">
        <input type="hidden" name="csrf_token" value="abc123xyz">
    </form>

    <script>
        // DOM XSS vulnerable pattern
        function loadContent() {
            var term = location.hash.substring(1);
            document.getElementById('output').innerHTML = "Search: " + term;
        }
    </script>
</body>
</html>
"""


def test_map_web_surface_parsing():
    surface = map_web_surface("http://test.corp.com/index.php?page=home&debug=1", html_content=SAMPLE_HTML)
    assert surface.title == "Acme Test Portal"
    assert surface.url_params == {"page": "home", "debug": "1"}
    assert len(surface.forms) == 1

    form = surface.forms[0]
    assert form.action == "/login.php"
    assert form.method == "POST"
    assert len(form.inputs) == 3

    input_names = [i.name for i in form.inputs]
    assert "uname" in input_names
    assert "pass" in input_names
    assert "csrf_token" in input_names

    # Check same-domain vs external links
    assert "http://test.corp.com/products.php?cat=1" in surface.same_domain_links
    assert not any("external.com" in link for link in surface.same_domain_links)

    # Check inline script extraction
    assert len(surface.inline_scripts) == 1
    assert "location.hash" in surface.inline_scripts[0]


def test_scan_reflected_xss_vulnerable():
    import urllib.parse
    # Mock client that reflects the parameter value unencoded
    def mock_reflected_client(url: str) -> str:
        unquoted = urllib.parse.unquote_plus(url)
        if '<script>alert("XSS")</script>' in unquoted:
            return "<html><body>Search results for: <script>alert(\"XSS\")</script></body></html>"
        return "<html><body>Normal page</body></html>"

    findings = scan_reflected_xss(
        "http://test.corp.com/search.php?q=apple",
        http_client=mock_reflected_client
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "REFLECTED_XSS"
    assert f.parameter == "q"
    assert '<script>alert("XSS")</script>' in f.payload
    assert f.severity == "HIGH"


def test_scan_reflected_xss_safe():
    # Mock client that HTML-encodes output
    def mock_safe_client(url: str) -> str:
        return "<html><body>Search results for: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;</body></html>"

    findings = scan_reflected_xss(
        "http://test.corp.com/search.php?q=apple",
        http_client=mock_safe_client
    )
    assert len(findings) == 0


def test_scan_dom_xss_static_and_dynamic():
    script_source = """
    function renderQuery() {
        var query = decodeURIComponent(location.hash.substring(1));
        document.getElementById('results').innerHTML = '<p>' + query + '</p>';
    }
    """
    # 1. Static detection
    findings_static = scan_dom_xss(
        "http://localhost/dom.html",
        inline_scripts=[script_source],
    )
    assert len(findings_static) >= 1
    f = findings_static[0]
    assert f.vuln_type == "DOM_XSS_STATIC"
    assert "location.hash" in f.payload
    assert "innerHTML" in f.payload

    # 2. Dynamic detection mock
    mock_hash_client = lambda u: "<html><body><img src=x onerror=alert(1)></body></html>" if "#<img src=x onerror=alert(1)>" in u else "<html><body></body></html>"
    findings_dynamic = scan_dom_xss(
        "http://localhost/dom.html",
        inline_scripts=[],
        http_client=mock_hash_client,
    )
    assert any(d.vuln_type == "DOM_XSS_DYNAMIC" for d in findings_dynamic)


def test_scan_sqli_error_based():
    # Mock client returning MySQL syntax error on single quote
    def mock_sqli_client(url: str) -> tuple[str, float]:
        if "id=10%27" in url or "id=10'" in url:
            return "Warning: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", 0.05
        return "Item description: Book #10", 0.05

    findings = scan_sqli(
        "http://test.corp.com/items.php?id=10",
        http_client=mock_sqli_client,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.technique == "ERROR_BASED"
    assert f.parameter == "id"
    assert "MySQL" in f.dbms
    assert f.severity == "CRITICAL"


def test_scan_sqli_boolean_and_time_based():
    # Mock client with boolean differential and time delay
    def mock_advanced_client(url: str) -> tuple[str, float]:
        if "cat=1%27+OR+%271%27%3D%271" in url or "cat=1' OR '1'='1" in url:
            # Huge content length difference (all products returned)
            return "<html><body>" + ("Product Card<br>" * 80) + "</body></html>", 0.05
        if "SLEEP" in url:
            return "<html><body>Delayed page</body></html>", 3.1
        return "<html><body>One Product Card</body></html>", 0.05

    # 1. Boolean test
    findings_bool = scan_sqli(
        "http://test.corp.com/products.php?cat=1",
        test_time_based=False,
        http_client=mock_advanced_client,
    )
    assert any(f.technique == "BOOLEAN_BASED" for f in findings_bool)

    # 2. Time-based test
    findings_time = scan_sqli(
        "http://test.corp.com/products.php?cat=1",
        test_time_based=True,
        http_client=mock_advanced_client,
    )
    assert any(f.technique == "TIME_BASED" for f in findings_time)


def test_findings_carry_confidence_and_recommendation():
    # Chapter-7 iterative loop: every finding tells the agent its next escalation step.
    err = SQLiFinding(technique="ERROR_BASED", parameter="id", payload="'", dbms="MySQL")
    assert err.confidence == "HIGH"
    assert "UNION SELECT" in err.recommendation

    boolean = SQLiFinding(technique="BOOLEAN_BASED", parameter="id", payload="x", dbms="?")
    assert boolean.confidence == "MEDIUM"          # length-delta only -> less certain
    assert "time-based" in boolean.recommendation.lower()

    xss = XSSFinding(vuln_type="REFLECTED_XSS", parameter="q", payload="<script>")
    assert xss.confidence == "HIGH" and xss.recommendation

    # Explicit values are never overwritten by the post-init defaults.
    pinned = SQLiFinding(technique="ERROR_BASED", parameter="id", payload="'", dbms="MySQL",
                         confidence="LOW", recommendation="stop")
    assert pinned.confidence == "LOW" and pinned.recommendation == "stop"

    # Reaches to_dict() so MCP/report consumers see it.
    assert err.to_dict()["recommendation"] == err.recommendation


def test_run_web_assessment_end_to_end():
    mock_text = lambda u: "<html><body><form action='/post.php' method='POST'><input name='search'></form>Result: <script>alert(\"XSS\")</script> syntax error near MySQL</body></html>"
    results = run_web_assessment(
        "http://test.corp.com/page.php?test=1",
        http_text_client=mock_text,
    )
    assert results["forms_count"] == 1
    assert len(results["xss_findings"]) >= 1
    assert len(results["sqli_findings"]) >= 1

    report_md = format_web_report(results)
    assert "Web Application Security Assessment" in report_md
    assert "SQL Injection Vulnerabilities (CRITICAL)" in report_md
    assert "Cross-Site Scripting (XSS) Findings" in report_md
