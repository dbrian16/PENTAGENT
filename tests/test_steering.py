"""Interactive steering (next/todo) over EGATS — offline, scripted operator."""
from __future__ import annotations

from agentpentest.brain import EGATS
from agentpentest.ptt import Evidence, PentestTree
from agentpentest.steering import steerer


def _tree() -> PentestTree:
    t = PentestTree("target")
    t.add("exploit A", t.root_id, Evidence.PLAUSIBLE, "T1190")
    t.add("exploit B", t.root_id, Evidence.PLAUSIBLE, "T1190")
    return t


def _scripted(answers):
    """An `ask` that pops scripted replies, then raises EOF (non-interactive end)."""
    it = iter(answers)

    def ask(_prompt):
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    return ask


def test_quit_stops_before_any_action():
    t = _tree()
    EGATS(t, lambda n: (True, Evidence.VERIFIED),
          steer=steerer(_scripted(["quit"]))).run()
    assert all(n.attempts == 0 for n in t.nodes.values()), "quit must act on nothing"


def test_skip_abandons_the_pick():
    t = _tree()
    # skip the first pick, then quit -> one node abandoned, none attempted.
    EGATS(t, lambda n: (True, Evidence.VERIFIED),
          steer=steerer(_scripted(["skip", "quit"]))).run()
    abandoned = [n for n in t.nodes.values() if n.status == "abandoned"]
    assert len(abandoned) == 1
    assert all(n.attempts == 0 for n in t.nodes.values())


def test_pick_override_runs_the_named_node():
    t = _tree()
    EGATS(t, lambda n: (True, Evidence.VERIFIED),
          steer=steerer(_scripted(["pick n2", "quit"]))).run()
    assert t.nodes["n2"].status == "success"
    assert t.nodes["n1"].attempts == 0, "override must not touch the other node"


def test_auto_hands_control_back():
    t = _tree()
    # one 'auto' disables steering; the rest runs unattended to the fixed point.
    EGATS(t, lambda n: (True, Evidence.VERIFIED),
          steer=steerer(_scripted(["auto"]))).run()
    assert all(n.status in ("success", "root") for n in t.nodes.values())


def test_eof_is_quit_not_crash():
    t = _tree()
    EGATS(t, lambda n: (True, Evidence.VERIFIED),
          steer=steerer(_scripted([]))).run()      # empty script -> immediate EOF
    assert all(n.attempts == 0 for n in t.nodes.values())


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("ok")
