"""Self-contained HTML evidence report: a confirmed finding must carry its deterministic
proof (verifier/verdict/metrics), and all dynamic content must be HTML-escaped so a
hostile claim or reason cannot break the document."""
from agentpentest.report import format_co_redteam_html
from agentpentest.statemachine import Hypothesis, Status
from agentpentest.verifiers import VerdictStatus, VerificationProof


def _confirmed_hyp(hid="h1", claim="SSTI on /render"):
    h = Hypothesis(hid, claim, technique="T1190")
    h.status = Status.CONFIRMED
    h.attempts = 2
    return h


def _proof_sd(status=VerdictStatus.CONFIRMED):
    proof = VerificationProof(status, "AlgebraicCanaryVerifier", 1.0,
                              {"expected_canary": "48552583", "present_in_mutated": True},
                              "Arithmetic executed server-side.")
    return {"verifier": "algebraic_canary", "payload": {}, "proof": proof}


def test_html_is_a_standalone_document():
    out = format_co_redteam_html([_confirmed_hyp()], proof_map={"h1": _proof_sd()},
                                 target="lab.local")
    assert out.startswith("<!doctype html>")
    assert out.rstrip().endswith("</html>")
    assert "<style>" in out                      # CSS inlined -> no external resources


def test_html_renders_the_proof_chain():
    out = format_co_redteam_html([_confirmed_hyp()], proof_map={"h1": _proof_sd()},
                                 target="lab.local")
    assert "AlgebraicCanaryVerifier" in out
    assert "expected_canary" in out and "48552583" in out
    assert "Arithmetic executed server-side." in out
    assert "badge ok" in out                      # CONFIRMED -> green verdict badge
    assert "confidence 1.00" in out


def test_html_escapes_hostile_content():
    h = _confirmed_hyp(claim="<script>alert(1)</script>")
    proof = VerificationProof(VerdictStatus.CONFIRMED, "V", 0.9,
                              {"k": "<img src=x onerror=1>"}, "<b>reason</b>")
    out = format_co_redteam_html([h], proof_map={"h1": {"proof": proof}})
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "<img src=x" not in out
    assert "<b>reason</b>" not in out and "&lt;b&gt;reason" in out


def test_html_confirmed_without_proof_is_honest():
    """A shell-confirmed finding with no comparison-set must say so, not fake a proof."""
    out = format_co_redteam_html([_confirmed_hyp()], proof_map={})
    assert "no structured comparison-set" in out.lower()


def test_html_summary_counts_and_empty_run():
    blocked = Hypothesis("h2", "disproven")
    blocked.status = Status.BLOCKED
    out = format_co_redteam_html([_confirmed_hyp(), blocked],
                                 proof_map={"h1": _proof_sd()})
    assert "Confirmed (math-proven)" in out
    empty = format_co_redteam_html([], proof_map={})
    assert "No hypotheses were tested" in empty
    assert empty.startswith("<!doctype html>")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
