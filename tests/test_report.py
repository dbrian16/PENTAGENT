"""report.py: severity column/sort, and the JSON export counterpart to the markdown."""
from __future__ import annotations

import json

from agentpentest import report
from agentpentest.ptt import Evidence, PentestTree


def _tree_with_mixed_severity() -> PentestTree:
    t = PentestTree("x")
    # T1046 (Low) added first, T1190 (Critical) second -- sort must put Critical first.
    low = t.add("discover", t.root_id, Evidence.NONE, "T1046")
    t.nodes[low].status, t.nodes[low].evidence = "success", Evidence.CONFIRMED
    crit = t.add("exploit web", t.root_id, Evidence.NONE, "T1190")
    t.nodes[crit].status, t.nodes[crit].evidence = "success", Evidence.VERIFIED
    t.nodes[crit].commands.append("sqlmap -u http://x --batch")
    return t, low, crit


def test_findings_sorted_by_severity_desc():
    t, low, crit = _tree_with_mixed_severity()
    md = report.generate(t)
    assert md.index(f"| {crit} |") < md.index(f"| {low} |"), \
        "Critical (T1190) must be listed before Low (T1046)"


def test_markdown_has_severity_column():
    t, _, crit = _tree_with_mixed_severity()
    md = report.generate(t)
    assert "Severity" in md
    assert "Critical" in md


def test_to_dict_matches_markdown_findings():
    t, low, crit = _tree_with_mixed_severity()
    d = report.to_dict(t)
    assert d["target"] == "x" and d["simulated"] is True
    assert d["summary"]["findings"] == 2
    ids = [f["id"] for f in d["findings"]]
    assert ids[0] == crit, "JSON export must share the same severity ordering"
    crit_entry = d["findings"][0]
    assert crit_entry["severity"] == "Critical"
    assert crit_entry["technique"] == "T1190"
    assert "sqlmap" in crit_entry["poc"][0]


def test_generate_json_is_valid_json_round_trip():
    t, _, _ = _tree_with_mixed_severity()
    s = report.generate_json(t)
    d = json.loads(s)                       # must not raise
    assert d == report.to_dict(t)


def test_empty_tree_json_has_no_findings():
    t = PentestTree("empty")
    d = report.to_dict(t)
    assert d["findings"] == [] and d["summary"]["findings"] == 0


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
