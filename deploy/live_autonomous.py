"""Live autonomous run: LLM-driven Kali terminal against a real target.

Needs: RUN_DISABLED deleted, Kali/Linux, Docker running, Ollama running.
Run only against hosts you are authorized to test.

    python deploy/live_autonomous.py 192.168.56.101 --scope 192.168.56.101 --poc --allow-high-impact
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
import threading
import time

os.environ.setdefault("AGENTPENTEST_STRICT_SSRF", "1")

from agentpentest import (autonomous, covertrack, knowledge, memorydb, poc,
                          probe, report, taskgraph, timestomp, tools)
from agentpentest.config import Config
from agentpentest.ebpf_monitor import EbpfMonitor, LsmPolicy, lsm_guard
from agentpentest.llm import OllamaReasoner, parse_json_block
from agentpentest.prompts import contract
from agentpentest.runlog import RunLog
from agentpentest.safety import guard
from agentpentest.sandbox import DockerSandbox, LocalSandbox, SnapshotSandbox, docker_cli
from agentpentest.statemachine import (CoRedTeam, Hypothesis, PlanStep,
                                       ValidationResult, default_evaluator,
                                       deterministic_evaluator, shellguard_executor,
                                       shellguard_validator)
from agentpentest.throttle import CircuitBreaker, PerTargetBreaker, RateLimiter

# high-impact tools need --allow-high-impact to run (still HITL)
_HIGH_IMPACT = ("msfconsole", "msfvenom", "meterpreter", "mimikatz", "impacket",
                "secretsdump", "crackmapexec", "nxc", "netexec", "evil-winrm",
                "hydra", "medusa", "dd", "shred")

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
        print("=" * 70)
        print("WARNING: Docker not found — no container isolation available.")
        print("All pentest tools will run DIRECTLY on THIS host with no sandboxing.")
        print("Use ONLY on a dedicated, disposable VM you own and can destroy.")
        print("=" * 70)
        try:
            if input("Type 'I UNDERSTAND' to proceed without Docker: ").strip() != "I UNDERSTAND":
                raise SystemExit("aborted.")
        except EOFError:
            raise SystemExit("aborted (no confirmation).")
        return autonomous.sandbox_execute(LocalSandbox()), None
    sandbox = SnapshotSandbox(image=args.image, runner=docker_cli())
    return autonomous.sandbox_execute(sandbox), sandbox


_ANALYZE_SYS = contract(
    "You are a senior red-team analyst. Given recon facts about a target (and INTEL: "
    "relevant MITRE techniques / CVE hints from the offline KB), propose up to 5 "
    "concrete exploitation hypotheses ranked by likelihood. "
    'Reply with strict JSON: {"hypotheses":[{"id":"h1","claim":"...","technique":"T1190",'
    '"priority":0.9,"evidence":"why exploitable"}]}'
)

_PLAN_SYS = contract(
    "You are a penetration tester. Given a hypothesis, prior-attempt feedback, and the "
    "TOOLS catalog, propose ONE concrete next action to test it. "
    'PREFER a typed tool: {"tool":"<name from TOOLS>","params":{...},"rationale":"why"} '
    "- the system builds the exact command so you cannot mistype a flag. "
    'Use {"action":"<full Kali command>","rationale":"why"} ONLY for a tool not in TOOLS. '
    'For a math-verifiable web bug, emit a PROBE instead of a shell tool: '
    '{"probe":"ssti|idor|timing|oob","params":{...},"rationale":"why"} - the system runs '
    "a controlled comparison-set and a DETERMINISTIC verifier (no LLM, no substring) "
    "returns the verdict. probe params carry an 'inject' descriptor, e.g. "
    '{"mode":"query","url":"http://host/page","param":"q"}; ssti also needs factor_a/'
    "factor_b, timing needs delays, idor needs victim_request/attacker_own_request/owner/"
    "attacker, oob injects a callback URL for blind SSRF/RCE/XXE. "
    "The target must appear in the command or params."
)


def _llm_analyzer(reasoner, ctx: dict) -> list[Hypothesis]:
    enriched = {**ctx, "intel": knowledge.augment([ctx])}   # RAG: KB hints into the prompt
    d = parse_json_block(reasoner.ask(_ANALYZE_SYS, json.dumps(enriched)) or "{}") or {}
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
                           "scope": sorted(scope), "tools": tools.catalog()})
        d = parse_json_block(reasoner.ask(_PLAN_SYS, user) or "{}") or {}
        if d.get("probe"):                       # Tier-2 math-verified web probe
            directive = json.dumps({"probe": d["probe"], "params": d.get("params") or {}})
            return [PlanStep(directive, d.get("rationale", ""), kind="probe")]
        if d.get("tool"):                        # typed tool -> deterministic argv
            try:
                argv = tools.resolve(d["tool"], d.get("params") or {})
                return [PlanStep(shlex.join(argv), d.get("rationale", ""))]
            except (tools.ParamError, ValueError):
                pass                             # fall through to a raw action if given
        if "action" in d:
            return [PlanStep(d["action"], d.get("rationale", ""))]
        return []
    return plan


def _proof_or_first_line(out: str) -> str:
    """Pick a grounded evidence line: a proof marker if present, else the first line."""
    for ln in out.splitlines():
        if any(m in ln for m in ("PROOF:", "POC-OK:", "uid=", "root@")):
            return ln
    return next((ln for ln in out.splitlines() if ln.strip()), "")


def _run_co_redteam(args, reasoner, sandbox, scope: set, rlog: RunLog) -> None:
    """Run the multi-agent Co-RedTeam state machine, persisting each attempt + grounded
    evidence into canonical SQLite memory so the run is auditable like the flat loop."""
    _sbox = sandbox if sandbox is not None else LocalSandbox()
    ctx = {"target": args.target, "scope": sorted(scope), "goal": args.goal}
    print("Co-RedTeam mode: LLM analyzer + planner, shellguard executor, proof-gated evaluator.")

    run_id = args.run_id or f"live-{int(time.time())}"
    os.makedirs(args.mem_dir, exist_ok=True)
    mem_path = os.path.join(args.mem_dir, f"{run_id}.sqlite")
    mem = memorydb.MemoryDB(mem_path)
    scope_list = sorted(scope) if scope else [args.target]
    try:
        mem.open_run(run_id, args.goal, scope_list)
    except memorydb.MemoryError:
        run_id = f"{run_id}-{int(time.time())}"
        mem.open_run(run_id, args.goal, scope_list)

    created: set = set()
    _created_lock = threading.Lock()
    proof_map: dict = {}        # hypothesis id -> structured_data (with stashed proof)

    def _persist_attempt(h, step, res) -> None:
        tid = f"h-{h.id}"
        # deterministic_evaluator stashes the math proof on res.structured_data before
        # on_attempt runs, so capture it here for the quantitative report section.
        if res.structured_data and "proof" in res.structured_data:
            proof_map[h.id] = res.structured_data
        # Guard the check-then-add with a lock so concurrent on_attempt callbacks
        # from different threads cannot both pass the 'tid not in created' check and
        # both call add_task (which would raise PlanError on the duplicate id).
        with _created_lock:
            if tid not in created:
                try:
                    mem.add_task(run_id, taskgraph.Task(tid, taskgraph.TaskKind.TEST,
                                 args.target, h.claim[:200]))
                    created.add(tid)
                except (taskgraph.PlanError, memorydb.MemoryError):
                    return
        aid = mem.start_attempt(run_id, tid)
        out = (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
        mem.add_observation(run_id, tid, aid, step.action[:200], out,
                            _proof_or_first_line(out))
        mem.finish_attempt(run_id, aid, "done" if res.ok else "failed", step.action[:200])

    # Composite executor/validator: a "probe" PlanStep is a math-verified web probe
    # (scope-gated inside the HttpSampler), everything else is a shell command gated by
    # shellguard. This is what lets deterministic_evaluator actually reach the verifiers.
    _shell_exec = shellguard_executor(_sbox, scope=scope)
    _probe_exec = probe.probe_executor(scope, allow_internal=args.allow_internal)
    _shell_val = shellguard_validator()

    def _exec(step):
        return _probe_exec(step) if step.kind == "probe" else _shell_exec(step)

    def _val(step):
        if step.kind == "probe":
            return ValidationResult(True, "probe: scope-gated inside the sampler")
        return _shell_val(step)

    team = CoRedTeam(
        analyzer=lambda c: _llm_analyzer(reasoner, c),
        planner=_llm_planner(reasoner, scope),
        executor=_exec,
        validator=_val,
        evaluator=deterministic_evaluator,
        max_refine=args.max_steps,
        on_attempt=_persist_attempt,
    )
    results = team.run(ctx)
    confirmed = [h for h in results if h.status.value == "confirmed"]
    blocked = [h for h in results if h.status.value == "blocked"]

    # settle task statuses, then finish the run on grounded + confirmed evidence
    for h in results:
        tid = f"h-{h.id}"
        if tid in created:
            mem.set_status(run_id, tid, taskgraph.TaskStatus.DONE
                           if h.status.value == "confirmed" else taskgraph.TaskStatus.FAILED)
    grounded = {r["task_id"] for r in mem.grounded_observations(run_id)}
    basis = sorted(grounded & {f"h-{h.id}" for h in confirmed})
    if basis:
        try:
            mem.finish_run(run_id, basis)
        except memorydb.MemoryError as e:
            rlog.event(action="finish_skipped", reason=str(e)[:160])
    mem.close()

    # quantitative Markdown report: the hypothesis table + the math-proof block for each
    # confirmed finding (empty proof block for shell-confirmed ones with no comparison-set).
    report_md = report.format_co_redteam_results(results, proof_map=proof_map)
    report_path = os.path.join(args.mem_dir, f"{run_id}.co-redteam.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"\nCo-RedTeam done. confirmed={len(confirmed)} blocked={len(blocked)}")
    for h in confirmed:
        rlog.event(action="co_redteam_confirmed", id=h.id, claim=h.claim,
                   technique=h.technique, attempts=h.attempts)
    for h in blocked:
        rlog.event(action="co_redteam_blocked", id=h.id, claim=h.claim,
                   technique=h.technique, attempts=h.attempts)
    for msg in team.log:
        print(f"  {msg}")
    print(f"Run memory: {mem_path}")
    print(f"Co-RedTeam report: {report_path}")
    print(f"Audit it:   agentpentest-audit --db {mem_path} --run-id {run_id} "
          "[--expected-flag 'FLAG{...}']")


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
    ap.add_argument("--run-id", default=None,
                    help="id for the persisted SQLite run memory (default: live-<ts>)")
    ap.add_argument("--mem-dir", default="runs",
                    help="directory for the run's .sqlite canonical memory")
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
    run_id = args.run_id or f"live-{int(time.time())}"
    os.makedirs(args.mem_dir, exist_ok=True)
    mem_path = os.path.join(args.mem_dir, f"{run_id}.sqlite")
    mem = memorydb.MemoryDB(mem_path)
    scope_list = sorted(scope) if scope else [args.target]
    try:
        mem.open_run(run_id, args.goal, scope_list)
    except memorydb.MemoryError:
        run_id = f"{run_id}-{int(time.time())}"
        mem.open_run(run_id, args.goal, scope_list)

    transcript = autonomous.autoloop(
        args.goal, scope, reasoner, execute,
        allow_internal=args.allow_internal, max_steps=args.max_steps,
        runlog=rlog,
        poc_run=poc_run, max_poc_fix=args.poc_fix,
        rate_limiter=RateLimiter(max_per_second=args.rate),
        # per-target breaker abandons a single dead host early (3 strikes); the global
        # breaker is a higher backstop that stops a run where everything is failing.
        breaker=CircuitBreaker(max_consecutive_failures=8),
        target_breaker=PerTargetBreaker(max_consecutive_failures=3),
        confirm=make_confirm(args.allow_high_impact),
        memory=mem, run_id=run_id,
    )
    mem.close()
    print(f"\nDone. {len(transcript)} step(s) ran. Audit log: {args.log}")
    print(f"Run memory: {mem_path}")
    print(f"Audit it:   agentpentest-audit --db {mem_path} --run-id {run_id} "
          "[--expected-flag 'FLAG{...}']")

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
