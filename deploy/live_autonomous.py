"""Live deploy wiring: hands the autonomous loop a real, host-isolated executor.

The operational engine (a real Kali terminal driven by a local LLM), not the simulated
campaign. Built to stay safe on the operator's own host:

  * Runs nothing while agentpentest/RUN_DISABLED exists (safety.guard).
  * Refuses real execution on Windows (no container isolation here); real runs go on a Linux/Kali lab.
  * Default executor is an isolated DockerSandbox (cap-drop ALL, no-new-privileges, read-only
    root, no host bind mounts). --unsafe-local-exec opts out (disposable VM only).
  * An eBPF/BPF-LSM gate vetoes forbidden writes/spawns and off-scope egress before a command runs.
  * Scope + strict SSRF, per-command HITL approval, rate limit + circuit breaker.

Run only against hosts you are authorized to test.

Usage (Kali/Linux, after deleting agentpentest/RUN_DISABLED):
    export AGENTPENTEST_OLLAMA_HOST=http://127.0.0.1:11434
    export AGENTPENTEST_OLLAMA_MODEL=qwen2.5
    python deploy/live_autonomous.py 192.168.56.101 \\
        --scope 192.168.56.101 --allow-internal --goal "enumerate services and web paths"
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

# Live run: fail CLOSED on a host that won't resolve (DNS-rebind / typo'd scope).
# security.assert_external reads this at call time; override by exporting =0.
os.environ.setdefault("AGENTPENTEST_STRICT_SSRF", "1")

from agentpentest import autonomous, poc
from agentpentest.config import Config
from agentpentest.ebpf_monitor import EbpfMonitor, LsmPolicy, lsm_guard
from agentpentest.llm import OllamaReasoner
from agentpentest.runlog import RunLog
from agentpentest.safety import guard
from agentpentest.sandbox import DockerSandbox, LocalSandbox
from agentpentest.throttle import CircuitBreaker, RateLimiter

# Tool-name prefixes that must never run unattended even with a human present:
# impact / exfiltration / C2 / persistence territory. The operator is warned and
# the command is refused by this launcher. `--allow-high-impact` lifts this (still
# per-command HITL), for your own lab, when you understand the blast radius.
_HIGH_IMPACT = ("msfconsole", "msfvenom", "meterpreter", "mimikatz", "impacket",
                "secretsdump", "crackmapexec", "nxc", "evil-winrm", "dd", "shred")

# Binaries the BPF-LSM gate blocks on the OPERATOR'S box regardless of the HITL gate:
# classic reverse-shell / wipe tooling the agent has no business spawning locally.
_FORBID_SPAWN = ("nc", "ncat", "netcat", "dd", "shred", "mkfs")


def make_confirm(allow_high_impact: bool):
    """Build the human-in-the-loop gate: print the proposed action, require."""
    def operator_confirm(argv, target, rationale):
        binary = (argv[0] if argv else "").lower()
        cmd = " ".join(argv)
        print(f"\n  proposed : {cmd}")
        print(f"  target   : {target}")
        print(f"  why      : {rationale}")
        if any(h in binary for h in _HIGH_IMPACT) and not allow_high_impact:
            print("  WARNING  : high-impact tool. Refused (pass --allow-high-impact to permit).")
            return False
        try:
            ans = input("  run this? [y/N] ").strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes")
    return operator_confirm


def build_executor(args):
    """Pick the execution backend, enforcing host safety. Returns (execute, sandbox)."""
    if sys.platform.startswith("win"):
        raise SystemExit(
            "Real execution is REFUSED on Windows: this host has no container isolation.\n"
            "Run live engagements on your Linux/Kali lab, where tools run inside an\n"
            "isolated DockerSandbox. (The staged simulation, `agentpentest <domain>`,\n"
            "is what runs on this box — and only after you remove RUN_DISABLED.)")

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
        raise SystemExit(
            "Docker not found. Isolated execution needs Docker (the host-safety boundary).\n"
            "Install Docker, or — on a disposable VM only — pass --unsafe-local-exec.")
    sandbox = DockerSandbox(image=args.image)
    return autonomous.sandbox_execute(sandbox), sandbox


def main() -> None:
    guard("live autonomous run")          # exits while RUN_DISABLED exists
    cfg = Config.from_env()
    ap = argparse.ArgumentParser(description="Live autonomous run (authorized lab only)")
    ap.add_argument("target", help="the authorized host/domain to test")
    ap.add_argument("--scope", nargs="+", required=True, help="authorized roots")
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
    args = ap.parse_args()

    from agentpentest import discover
    info = discover.discover_ollama(cfg.llm_model, hosts=[cfg.llm_host])
    if not info["connected"]:
        raise SystemExit("No local Ollama found. Start it (ollama serve) and pull a model.")
    print(f"Using local model {info['model']} at {info['host']}")
    reasoner = OllamaReasoner(info["model"], info["host"])   # local AI; refuses cloud hosts

    raw_execute, sandbox = build_executor(args)
    # Active BPF-LSM blast-radius gate in front of the real executor: a hallucinated or
    # injected command that writes a forbidden path, spawns reverse-shell tooling, or
    # egresses off-scope is vetoed BEFORE it runs (raises LsmDenied -> loop logs + skips).
    monitor = EbpfMonitor(policy=LsmPolicy(forbidden_spawns=_FORBID_SPAWN))
    scope = set(args.scope)
    execute = lsm_guard(raw_execute, monitor, egress_scope=scope | {args.target})
    # Real exploitation path: proof-gated PoC synthesis+run. Off unless --poc. When a
    # sandbox is wired, run PoCs inside it; else (local-exec VM) on the host sandbox.
    poc_run = None
    if args.poc:
        poc_run = poc.local_runner(sandbox if sandbox is not None else LocalSandbox())

    where = "isolated DockerSandbox" if sandbox is not None else "LOCAL host (unsafe)"
    print(f"LIVE RUN via {where}. Authorized targets only. Approve each step; Ctrl-C to stop.")
    print("BPF-LSM gate ON: forbidden writes/spawns/off-scope egress are vetoed pre-exec.")
    if args.poc:
        print("PoC mode ON: the model may synthesize and run proof-gated exploits.")
    print()
    transcript = autonomous.autoloop(
        args.goal, scope, reasoner, execute,
        allow_internal=args.allow_internal, max_steps=args.max_steps,
        runlog=RunLog(args.log),
        poc_run=poc_run, max_poc_fix=args.poc_fix,
        rate_limiter=RateLimiter(max_per_second=args.rate),
        breaker=CircuitBreaker(max_consecutive_failures=3),
        confirm=make_confirm(args.allow_high_impact),
    )
    print(f"\nDone. {len(transcript)} step(s) ran. Audit log: {args.log}")


if __name__ == "__main__":
    main()
