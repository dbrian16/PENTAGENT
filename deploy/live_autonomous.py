"""Live deploy wiring: hands the autonomous loop a real executor via Ollama.

Requires agentpentest/RUN_DISABLED to be deleted first.
Run only against hosts you are authorized to test.

Usage (Kali/Linux):
    export AGENTPENTEST_OLLAMA_HOST=http://127.0.0.1:11434
    export AGENTPENTEST_OLLAMA_MODEL=qwen2.5
    python deploy/live_autonomous.py 192.168.56.101 \\
        --scope 192.168.56.101 --allow-internal --goal "enumerate services and web paths"
"""
from __future__ import annotations

import argparse
import os

# Live run: fail CLOSED on a host that won't resolve (DNS-rebind / typo'd scope).
# security.assert_external reads this at call time; override by exporting =0.
os.environ.setdefault("AGENTPENTEST_STRICT_SSRF", "1")

from agentpentest import autonomous, poc
from agentpentest.config import Config
from agentpentest.llm import OllamaReasoner
from agentpentest.runlog import RunLog
from agentpentest.safety import guard
from agentpentest.sandbox import LocalSandbox
from agentpentest.throttle import CircuitBreaker, RateLimiter

# Tool-name prefixes that must never run unattended even with a human present:
# impact / exfiltration / C2 / persistence territory. The operator is warned and
# the command is refused by this launcher. `--allow-high-impact` lifts this (still
# per-command HITL), for your own lab, when you understand the blast radius.
_HIGH_IMPACT = ("msfconsole", "msfvenom", "meterpreter", "mimikatz", "impacket",
                "secretsdump", "crackmapexec", "nxc", "evil-winrm", "dd", "shred")


def make_confirm(allow_high_impact: bool):
    """Build the human-in-the-loop gate: print the proposed action, require an
    explicit yes. High-impact tools are refused unless `allow_high_impact`."""
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
    sandbox = LocalSandbox()
    execute = autonomous.sandbox_execute(sandbox)           # REAL execution on this box
    # Real exploitation path: proof-gated PoC synthesis+run on the host sandbox. Off
    # unless --poc. local_runner runs the script via LocalSandbox.exec_full (no Docker);
    # for stronger isolation swap in poc.sandbox_runner(SnapshotSandbox(...)).
    poc_run = poc.local_runner(sandbox) if args.poc else None

    print("LIVE RUN. Authorized targets only. Approve each step; Ctrl-C to stop.")
    if args.poc:
        print("PoC mode ON: the model may synthesize and run proof-gated exploits.")
    print()
    transcript = autonomous.autoloop(
        args.goal, set(args.scope), reasoner, execute,
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
