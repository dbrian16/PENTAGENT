"""Execution contract + forced decision schema (prompts.py)."""
from agentpentest import prompts
from agentpentest.prompts import contract, parse_decision, normalize_phase


def test_contract_carries_all_pillars():
    for needle in ("Evidence outranks eloquence", "RULES OF ENGAGEMENT",
                   "PTES", "MITRE ATT&CK", "UNTRUSTED DATA"):
        assert needle in prompts.CONTRACT


def test_contract_composes_task_and_opt_in_schema():
    sys = contract("Do the thing.")
    assert prompts.CONTRACT in sys and "Do the thing." in sys
    assert "thought_process" not in sys                   # schema off by default
    assert "thought_process" in contract("Decide.", decision=True)


def test_parse_decision_normalizes_and_clamps():
    dec = parse_decision('{"thought_process":"old nginx","current_phase":"recon",'
                         '"tactic_id":"t1190","confidence_score":1.7,'
                         '"next_action_justification":"probe"}')
    assert dec is not None
    assert dec.current_phase == "reconnaissance"          # alias -> canonical
    assert dec.tactic_id == "T1190"                       # upper-cased
    assert dec.confidence_score == 1.0                    # clamped into [0,1]


def test_parse_decision_accepts_dict_and_subtechnique():
    dec = parse_decision({"thought_process": "x", "current_phase": "exploitation",
                          "tactic_id": "T1059.001", "confidence_score": 0.5,
                          "next_action_justification": "y"})
    assert dec and dec.tactic_id == "T1059.001"


def test_parse_decision_rejects_malformed():
    assert parse_decision("not json") is None
    assert parse_decision('{"thought_process":"x"}') is None          # missing fields
    assert parse_decision('{"thought_process":"a","current_phase":"recon",'
                          '"tactic_id":"nope","confidence_score":0.5,'
                          '"next_action_justification":"b"}') is None  # bad tactic id
    assert parse_decision('{"thought_process":"a","current_phase":"brunch",'
                          '"tactic_id":"T1190","confidence_score":0.5,'
                          '"next_action_justification":"b"}') is None  # unknown phase
    assert parse_decision('{"thought_process":"a","current_phase":"recon",'
                          '"tactic_id":"T1190","confidence_score":"high",'
                          '"next_action_justification":"b"}') is None  # non-numeric conf


def test_normalize_phase():
    assert normalize_phase("Intelligence-Gathering") == "reconnaissance"
    assert normalize_phase("post exploitation") == "post-exploitation"
    assert normalize_phase("nonsense") is None


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print("ok")
