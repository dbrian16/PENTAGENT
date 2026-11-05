"""Zero-trust PoC path: a synthesized exploit proves itself by handing a comparison-set to
the deterministic engine (POC-STRUCT), not by printing its own POC-OK. The math -- not the
script's self-claim -- decides, so a script that lies ('POC-OK') but whose data disproves
the bug is correctly NOT validated. Legacy POC-OK still works when no comparison-set exists."""
import json

from agentpentest.poc import POC_STRUCT, PoCSpec, RunResult, synthesize_poc, validate_result
from agentpentest.verifiers import VerdictStatus, verify_structured

TARGET = "example.com"
SCOPE = {"example.com"}
# 6947 * 6989 = 48552583
_CANARY_OK = {"verifier": "algebraic_canary",
              "payload": {"baseline_stdout": "Hello {{name}}", "mutated_stdout": "Hello 48552583",
                          "factor_a": 6947, "factor_b": 6989}}
_CANARY_FP = {"verifier": "algebraic_canary",
              "payload": {"baseline_stdout": "x", "mutated_stdout": "syntax error near line 3",
                          "factor_a": 6947, "factor_b": 6989}}


def _struct(sd):
    return POC_STRUCT + " " + json.dumps(sd)


# ---- verify_structured dispatch ----------------------------------------------
def test_verify_structured_dispatch():
    assert verify_structured(_CANARY_OK).status is VerdictStatus.CONFIRMED
    assert verify_structured({"verifier": "unknown", "payload": {}}) is None
    assert verify_structured(None) is None
    assert verify_structured({"no": "verifier"}) is None


# ---- validate_result: struct beats marker ------------------------------------
def test_struct_confirmed_validates():
    res = RunResult(0, "scanning...\n" + _struct(_CANARY_OK))
    ok, ev, proof = validate_result(res)
    assert ok and proof.status is VerdictStatus.CONFIRMED


def test_struct_false_positive_overrides_a_lying_marker():
    """Script prints POC-OK AND a comparison-set that disproves the bug: math wins."""
    res = RunResult(0, "POC-OK: trust me it worked\n" + _struct(_CANARY_FP))
    ok, ev, proof = validate_result(res)
    assert not ok and proof.status is VerdictStatus.FALSE_POSITIVE


def test_malformed_struct_is_inconclusive_not_marker_fallback():
    res = RunResult(0, "POC-OK: trust me\n" + POC_STRUCT + " {not valid json")
    ok, ev, proof = validate_result(res)
    assert not ok and proof.status is VerdictStatus.INCONCLUSIVE


def test_unknown_verifier_struct_is_inconclusive():
    res = RunResult(0, _struct({"verifier": "nope", "payload": {}}))
    ok, ev, proof = validate_result(res)
    assert not ok and proof.status is VerdictStatus.INCONCLUSIVE


def test_last_struct_line_wins():
    res = RunResult(0, _struct(_CANARY_FP) + "\nretrying\n" + _struct(_CANARY_OK))
    ok, ev, proof = validate_result(res)
    assert ok and proof.status is VerdictStatus.CONFIRMED


# ---- legacy POC-OK path still works ------------------------------------------
def test_legacy_marker_validates_on_clean_exit():
    ok, ev, proof = validate_result(RunResult(0, "POC-OK: dumped users table"))
    assert ok and proof is None and ev == "dumped users table"


def test_legacy_marker_requires_clean_exit():
    ok, ev, proof = validate_result(RunResult(1, "POC-OK: but I crashed"))
    assert not ok and proof is None


# ---- end-to-end through synthesize_poc ---------------------------------------
class _Reasoner:
    def __init__(self, script):
        self.script = script

    def ask(self, system, user):
        return f"```python\n{self.script}\n```"


def test_synthesize_poc_confirmed_by_struct():
    script = f"# probe {TARGET}\nprint('done')"
    r = _Reasoner(script)
    run = lambda s, lang: RunResult(0, _struct(_CANARY_OK))
    res = synthesize_poc(PoCSpec(goal="SSTI", target=TARGET, scope=SCOPE), r, run)
    assert res.validated and res.proof.status is VerdictStatus.CONFIRMED


def test_synthesize_poc_disproven_by_struct_carries_verdict():
    script = f"# probe {TARGET}\nprint('done')"
    r = _Reasoner(script)
    run = lambda s, lang: RunResult(0, _struct(_CANARY_FP))
    res = synthesize_poc(PoCSpec(goal="SSTI", target=TARGET, scope=SCOPE), r, run, max_fix=1)
    assert not res.validated
    assert res.proof is not None and res.proof.status is VerdictStatus.FALSE_POSITIVE
    assert "absent" in res.error.lower() or res.error      # the verifier's reason, not a traceback


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
