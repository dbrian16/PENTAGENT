"""One runnable check for the vuln_scan capability + findings fact type."""
from agentpentest.executor import Executor
from agentpentest.orchestrator import run_recon
from agentpentest.perceptor import Perceptor
from agentpentest.planner import Planner, Task
from agentpentest.state import ReconState, Host, Service


def test_vuln_scan_parses_and_folds():
    ex = Executor(scope={"example.com"}, mock=True)
    result = ex.run(Task("vuln_scan", "example.com", {"port": 80}))
    sev = {f["severity"] for f in result["findings"]}
    assert {"info", "medium", "high"} <= sev, result

    s = ReconState()
    facts = Perceptor().perceive(Task("vuln_scan", "example.com", {"port": 80}), result, s)
    assert len(s.findings) == 3
    assert any("CVE-2021-41773" in f for f in facts)
    # dedupe on (key, id): re-folding the same result adds nothing new.
    Perceptor().perceive(Task("vuln_scan", "example.com", {"port": 80}), result, s)
    assert len(s.findings) == 3


def test_planner_chains_vuln_scan_off_http():
    s = ReconState()
    h = s.add_host("example.com")
    h.services.append(Service(80, "tcp", "http", "nginx"))
    kinds = {t.kind for t in Planner().next_tasks(s)}
    assert "vuln_scan" in kinds and "dir_enum" in kinds


def test_full_loop_finds_vulns():
    s = run_recon("example.com", scope={"example.com"}, mock=True, verbose=False)
    assert any(f["id"] == "CVE-2021-41773" for f in s.findings), s.findings
    # survives a save/load round-trip
    assert ReconState.from_json(s.to_json()).findings == s.findings
    assert len(s.log) == len(set(s.log)), "a task ran twice"


if __name__ == "__main__":
    test_vuln_scan_parses_and_folds()
    test_planner_chains_vuln_scan_off_http()
    test_full_loop_finds_vulns()
    print("ok")
