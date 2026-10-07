"""Live autonomous run: LLM-driven Kali terminal against a real target.

Needs: RUN_DISABLED deleted, Kali/Linux, Docker running, Ollama running.
Run only against hosts you are authorized to test.

    python deploy/live_autonomous.py 192.168.56.101 --scope 192.168.56.101 --poc --allow-high-impact
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

os.environ.setdefault("AGENTPENTEST_STRICT_SSRF", "1")

from agentpentest import autonomous, covertrack, poc, timestomp
from agentpentest.config import Config
from agentpentest.ebpf_monitor import EbpfMonitor, LsmPolicy, lsm_guard
from agentpentest.llm import OllamaReasoner, parse_json_block
from agentpentest.prompts import contract
from agentpentest.runlog import RunLog
from agentpentest.safety import guard
from agentpentest.sandbox import DockerSandbox, LocalSandbox, SnapshotSandbox, docker_cli
from agentpentest.statemachine import (CoRedTeam, Hypothesis, PlanStep,
                                       default_evaluator, shellguard_executor,
                                       shellguard_validator)
from agentpentest.throttle import CircuitBreaker, RateLimiter

# high-impact tools need --allow-high-impact to run (still HITL)
_HIGH_IMPACT = ("msfconsole", "msfvenom", "meterpreter", "mimikatz", "impacket",
                "secretsdump", "crackmapexec", "nxc", "evil-winrm", "dd", "shred")

# hard-blocked even inside Docker — these can corrupt the host disk
_FORBID_SPAWN = ("mkfs", "wipefs", "blkdiscard", "fdisk", "parted")


def make_confirm(allow_high_impact: bool):
    """Build the human-in-the-loop gate: print the proposed action, require."""
    def operator_confirm(argv, target, rationale):
        operator_confirm.last_note = ""
        binary = (argv[0] if argv else "").lower()
        cmd = " ".join(argv)
        print(f"\n  proposed : {cmd}")
        print(f"  target   : {target}")
        print(f"  why      : {rationale}")
        if any(h in binary for h in _HIGH_IMPACT) and not allow_high_impact:
            print("  WARNING  : high-impact tool. Refused (pass --allow-high-impact to permit).")
            return False
        try:
            ans = input("  run this? [y/N, or type what to do instead] ").strip()
        except EOFError:
            return False
        low = ans.lower()
        if low in ("y", "yes"):
            return True
        if low in ("", "n", "no"):
            return False
        # anything else is a steering note; planner sees it next round
        operator_confirm.last_note = ans
        print("  noted    : re-planning with your instruction")
        return False
    operator_confirm.last_note = ""
    return operator_confirm


def build_executor(args):
    """Pick the execution backend. Returns (execute, sandbox)."""
    if args.unsafe_local_exec:
        print("=" * 70)
        print("WARNING: --unsafe-local-exec runs tools DIRECTLY on THIS host — NO isolation.")
        print("Use ONLY on a dedicated, disposable VM you own and can destroy.")
        print("=" * 70)
        try:
            if input("Type 'I UNDERSTAND' to proceed: ").strip() != "I UNDERSTAND":
                raise SystemExit("aborted.")
        except EOFError:
            raise SystemExit("aborted (no confirmation).")
        return autonomous.sandbox_execute(LocalSandbox()), None

    if not shutil.which("docker"):
        print("[warn] Docker not found — falling back to LocalSandbox (no container isolation).")
        return autonomous.sandbox_execute(LocalSandbox()), None
    sandbox = SnapshotSandbox(image=args.image, runner=docker_cli())
    return autonomous.sandbox_execute(sandbox), sandbox


_ANALYZE_SYS = contract(
    "You are a senior red-team analyst. Given recon facts about a target, propose up to 5 "
    "concrete exploitation hypotheses ranked by likelihood. "
    'Reply with strict JSON: {"hypotheses":[{"id":"h1","claim":"...","technique":"T1190",'
    '"priority":0.9,"evidence":"why exploitable"}]}'
)

_PLAN_SYS = contract(
    "You are a penetration tester. Given a hypothesis and feedback from prior attempts, "
    "propose ONE concrete next Kali command to test it. The target must appear in the command. "
    'Reply with strict JSON: {"action":"<full command>","rationale":"why"}'
)


def _llm_analyzer(reasoner, ctx: dict) -> list[Hypothesis]:
    d = parse_json_block(reasoner.ask(_ANALYZE_SYS, json.dumps(ctx)) or "{}") or {}
    return [
        Hypothesis(h["id"], h["claim"], h.get("technique", ""),
                   float(h.get("priority", 0.5)), h.get("evidence", ""))
        for h in d.get("hypotheses", [])
        if "id" in h and "claim" in h
    ]


def _llm_planner(reasoner, scope: set):
    def plan(hyp: Hypothesis, feedback: list[str]) -> list[PlanStep]:
        user = json.dumps({"hypothesis": hyp.claim, "technique": hyp.technique,
                           "evidence": hyp.evidence, "feedback": feedback[-3:],
                           "scope": sorted(scope)})
        d = parse_json_block(reasoner.ask(_PLAN_SYS, user) or "{}") or {}
        if "action" not in d:
            return []
        return [PlanStep(d["action"], d.get("rationale", ""))]
    return plan


def _run_co_redteam(args, reasoner, sandbox, scope: set, rlog: RunLog) -> None:
    """Run the multi-agent Co-RedTeam state machine instead of the flat autoloop."""
    _sbox = sandbox if sandbox is not None else LocalSandbox()
    ctx = {"target": args.target, "scope": sorted(scope), "goal": args.goal}
    print(f"Co-RedTeam mode: LLM analyzer + planner, shellguard executor, proof-gated evaluator.")
    team = CoRedTeam(
        analyzer=lambda c: _llm_analyzer(reasoner, c),
        planner=_llm_planner(reasoner, scope),
        executor=shellguard_executor(_sbox, scope=scope),
        validator=shellguard_validator(),
        evaluator=default_evaluator,
        max_refine=args.max_steps,
    )
    results = team.run(ctx)
    confirmed = [h for h in results if h.status.value == "confirmed"]
    blocked = [h for h in results if h.status.value == "blocked"]
    print(f"\nCo-RedTeam done. confirmed={len(confirmed)} blocked={len(blocked)}")
    for h in confirmed:
        rlog.event(action="co_redteam_confirmed", id=h.id, claim=h.claim,
                   technique=h.technique, attempts=h.attempts)
    for h in blocked:
        rlog.event(action="co_redteam_blocked", id=h.id, claim=h.claim,
                   technique=h.technique, attempts=h.attempts)
    for msg in team.log:
        print(f"  {msg}")


def main() -> None:
    guard("live autonomous run")          # exits while RUN_DISABLED exists
    cfg = Config.from_env()
    ap = argparse.ArgumentParser(description="Live autonomous run (authorized lab only)")
    ap.add_argument("target", help="the authorized host/domain to test")
    ap.add_argument("--scope", nargs="+", default=[], help="authorized roots (omit = open scope)")
    ap.add_argument("--goal", default="enumerate services and web content safely")
    ap.add_argument("--allow-internal", action="store_true",
                    help="permit private/LAN targets (your own lab)")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--rate", type=float, default=5.0, help="max actions/second at the target")
    ap.add_argument("--log", default="live_run.jsonl")
    ap.add_argument("--image", default="kalilinux/kali-rolling",
                    help="container image for the isolated sandbox (must carry your tools)")
    ap.add_argument("--unsafe-local-exec", action="store_true",
                    help="run tools directly on this host with NO isolation (disposable VM only)")
    ap.add_argument("--poc", action="store_true",
                    help="UNLOCK real exploitation: let the model synthesize and RUN "
                         "proof-gated PoC scripts (Mode 3). Validated only on a real "
                         "'POC-OK:' line + exit 0. Each PoC still needs your approval.")
    ap.add_argument("--poc-fix", type=int, default=3,
                    help="max self-debug iterations per PoC script")
    ap.add_argument("--allow-high-impact", action="store_true",
                    help="permit msfconsole/sqlmap-class tools (still per-command HITL). "
                         "Your own isolated lab only.")
    ap.add_argument("--mode", choices=["auto", "co-redteam"], default="auto",
                    help="auto: flat autonomous terminal loop (default); "
                         "co-redteam: multi-agent hypothesis->plan->validate->execute->evaluate loop")
    args = ap.parse_args()

    from agentpentest import discover
    info = discover.discover_ollama(cfg.llm_model, hosts=[cfg.llm_host])
    if not info["connected"]:
        raise SystemExit("No local Ollama found. Start it (ollama serve) and pull a model.")
    print(f"Using local model {info['model']} at {info['host']}")
    reasoner = OllamaReasoner(info["model"], info["host"])   # local AI; refuses cloud hosts

    raw_execute, sandbox = build_executor(args)
    monitor = EbpfMonitor(policy=LsmPolicy(forbidden_spawns=_FORBID_SPAWN))
    scope = set(args.scope)
    egress_scope = (scope | {args.target}) if scope else None  # None = open egress
    execute = lsm_guard(raw_execute, monitor, egress_scope=egress_scope)
    poc_run = None
    if args.poc:
        poc_run = poc.local_runner(sandbox if sandbox is not None else LocalSandbox())

    where = "isolated DockerSandbox" if sandbox is not None else "LOCAL host (unsafe)"
    print(f"LIVE RUN via {where}. Authorized targets only. Ctrl-C to stop.")
    print("BPF-LSM gate ON: forbidden writes/spawns/off-scope egress are vetoed pre-exec.")
    if args.poc:
        print("PoC mode ON: the model may synthesize and run proof-gated exploits.")
    print()

    rlog = RunLog(args.log)

    if args.mode == "co-redteam":
        _run_co_redteam(args, reasoner, sandbox, scope, rlog)
        if sandbox is not None and hasattr(sandbox, "close"):
            sandbox.close()
        return

    # --- default: flat autonomous terminal loop ---
    transcript = autonomous.autoloop(
        args.goal, scope, reasoner, execute,
        allow_internal=args.allow_internal, max_steps=args.max_steps,
        runlog=rlog,
        poc_run=poc_run, max_poc_fix=args.poc_fix,
        rate_limiter=RateLimiter(max_per_second=args.rate),
        breaker=CircuitBreaker(max_consecutive_failures=3),
        confirm=make_confirm(args.allow_high_impact),
    )
    print(f"\nDone. {len(transcript)} step(s) ran. Audit log: {args.log}")

    if sandbox is not None and transcript:
        _live_cleanup(transcript, sandbox, reasoner, rlog)

    if sandbox is not None and hasattr(sandbox, "close"):
        sandbox.close()


def _live_cleanup(transcript, sandbox, reasoner, rlog: RunLog) -> None:
    """Post-loop T1070 cleanup: redact session log lines, stomp dropped file timestamps."""
    cmds = [step.command for step in transcript]
    indicators = list({c[0] for c in cmds if c} | {step.target for step in transcript})
    log_lines = [f"audit: execve({' '.join(c)!r})" for c in cmds]

    ct_spec = covertrack.TrackSpec(
        log_type="syslog",
        log_content="\n".join(log_lines),
        indicators=indicators,
    )
    ct_plan = covertrack.analyze_log(ct_spec, reasoner, runlog=rlog)
    covertrack.apply_redaction(ct_plan, "/var/log/syslog",
                               write=covertrack.sandbox_writer(sandbox), runlog=rlog)

    ref_entries = timestomp.local_dir_listing("/etc") or [
        timestomp.DirEntry("passwd", 1_700_000_000.0, 1_700_000_000.0, 2048),
    ]
    for step in transcript:
        ts_spec = timestomp.StompSpec(
            target_path=f"/tmp/.payload_{step.target}",
            reference_dir="/etc",
            entries=ref_entries,
        )
        ts_plan = timestomp.plan_stomp(ts_spec, reasoner, runlog=rlog)
        timestomp.apply_stomp(ts_plan,
                              execute=timestomp.sandbox_executor(sandbox), runlog=rlog)
        break  # ponytail: one step demo; remove break for full transcript coverage


if __name__ == "__main__":
    main()
