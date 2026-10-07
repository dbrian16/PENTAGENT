"""Steer-at-approve: typing an instruction instead of y/N declines the command and
feeds the words back to the planner, which re-plans the next proposal."""
import json
from agentpentest.autonomous import autoloop


class _Reasoner:
    """Fake local model: records every plan prompt so we can see what the planner saw."""
    def __init__(self): self.plan_prompts = []
    def ask(self, system, user, *, json_mode=False):
        if "autonomous penetration tester" in system:      # a _plan call
            self.plan_prompts.append(user)
            return json.dumps({"command": ["nmap", "127.0.0.1"], "target": "127.0.0.1",
                               "rationale": "scan"})
        return "{}"                                         # a _perceive call


class _Confirm:
    """Decline the first proposal with a typed instruction, accept the second."""
    def __init__(self): self.n = 0; self.last_note = ""
    def __call__(self, argv, target, rationale):
        self.n += 1
        if self.n == 1:
            self.last_note = "scan the web paths instead"
            return False
        self.last_note = ""
        return True


def test_typed_instruction_reaches_planner_and_runs_next():
    r, c = _Reasoner(), _Confirm()
    transcript = autoloop("enumerate", {"127.0.0.1"}, r, lambda argv, t: "22/tcp open ssh",
                          allow_internal=True, max_steps=2, confirm=c)
    # the command declined with a note did not run; the accepted one did.
    assert len(transcript) == 1
    # the operator's typed words were handed to the planner on the re-plan.
    assert any("scan the web paths instead" in p for p in r.plan_prompts)


def test_plain_no_carries_no_instruction():
    class _No:
        last_note = ""
        def __call__(self, *a): return False
    r = _Reasoner()
    transcript = autoloop("enumerate", {"127.0.0.1"}, r, lambda argv, t: "x",
                          allow_internal=True, max_steps=2, confirm=_No())
    assert transcript == []                                 # nothing approved, nothing ran
    assert all("operator instruction" not in p for p in r.plan_prompts)
