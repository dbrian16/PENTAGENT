"""evidence.py: the Evidence Ladder (G1->E1) and CVSS 4.0 scoring (Pillar 5)."""
from __future__ import annotations

from agentpentest.evidence import (EvidenceLadder, Grade, cvss40, exploit_maturity,
                                   severity_of)


def test_ladder_must_be_climbed_in_order():
    el = EvidenceLadder()
    el.candidate("f1")
    assert el.confirm("f1") is False                 # can't jump to E1
    assert el.adjudicate("f1", reproductions=3)
    assert el.matched_control("f1", signal_without_payload=False)
    assert el.patched_counterfactual("f1", signal_on_patched=False)
    assert el.confirm("f1")
    assert el.state("f1").confirmed and el.grade("f1") is Grade.E1


def test_single_reproduction_is_not_adjudicated():
    el = EvidenceLadder()
    el.candidate("f")
    assert el.adjudicate("f", reproductions=1) is False   # network noise not ruled out


def test_control_signal_blocks_advance():
    el = EvidenceLadder()
    el.candidate("f")
    el.adjudicate("f", reproductions=2)
    # signal present WITHOUT payload => it's app instability, not the vuln
    assert el.matched_control("f", signal_without_payload=True) is False
    assert not el.state("f").confirmed


def test_patched_counterfactual_blocks_confirmation():
    el = EvidenceLadder()
    el.candidate("f")
    el.adjudicate("f", reproductions=2)
    el.matched_control("f", signal_without_payload=False)
    assert el.patched_counterfactual("f", signal_on_patched=True) is False
    assert el.confirm("f") is False


def test_cvss40_anchor_critical():
    r = cvss40({"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"})
    assert r.severity == "Critical" and r.score >= 9.0, r
    assert r.vector.startswith("CVSS:4.0/AV:N")


def test_cvss40_threat_and_env_downgrade():
    base = cvss40({"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"})
    down = cvss40({"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                   "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N",
                   "MAV": "A", "MAC": "H", "E": "U"})
    assert down.score < base.score and down.severity in ("Medium", "Low"), down


def test_exploit_maturity_from_threat_intel():
    assert exploit_maturity("CVE-x", lambda c: {"kev": True}) == "A"
    assert exploit_maturity("CVE-x", lambda c: {"epss": 0.5}) == "P"
    assert exploit_maturity("CVE-x", lambda c: {"epss": 0.0, "kev": False}) == "U"


def test_severity_bands():
    assert severity_of(9.5) == "Critical" and severity_of(7.1) == "High"
    assert severity_of(5.0) == "Medium" and severity_of(1.0) == "Low"
    assert severity_of(0.0) == "None"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
