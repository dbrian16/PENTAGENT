"""Co-RedTeam planner now speaks the typed Tool Layer: a {"tool","params"} reply
resolves to a deterministic command; a bad/unknown tool falls back to a raw action."""
import importlib.util
import os

from agentpentest.statemachine import Hypothesis

_PATH = os.path.join(os.path.dirname(__file__), "..", "deploy", "live_autonomous.py")
# Importing the live script runs `os.environ.setdefault("AGENTPENTEST_STRICT_SSRF","1")`
# at module top level; snapshot + restore so we don't pollute other tests' env.
_prev_ssrf = os.environ.get("AGENTPENTEST_STRICT_SSRF")
_spec = importlib.util.spec_from_file_location("live_autonomous", _PATH)
live = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(live)
if _prev_ssrf is None:
    os.environ.pop("AGENTPENTEST_STRICT_SSRF", None)
else:
    os.environ["AGENTPENTEST_STRICT_SSRF"] = _prev_ssrf


class _Stub:
    def __init__(self, reply): self.reply = reply
    def ask(self, sys, user, **k): return self.reply


def _plan_once(reply):
    planner = live._llm_planner(_Stub(reply), {"box.lab"})
    return planner(Hypothesis("h1", "SMB open on box.lab", "T1021"), [])


def test_typed_tool_resolves_to_command():
    steps = _plan_once('{"tool":"smb_enum","params":{"target":"box.lab"},"rationale":"enum"}')
    assert len(steps) == 1
    assert steps[0].action == "enum4linux-ng -A box.lab"


def test_bad_tool_params_fall_back_to_action():
    # illegal host in params -> ParamError -> use the raw action instead
    steps = _plan_once('{"tool":"port_scan","params":{"target":"box.lab; rm -rf /"},'
                       '"action":"nmap -sV box.lab","rationale":"x"}')
    assert steps and steps[0].action == "nmap -sV box.lab"


def test_no_step_when_nothing_usable():
    assert _plan_once('{"rationale":"thinking"}') == []
