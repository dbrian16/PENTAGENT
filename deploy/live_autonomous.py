"""LIVE autonomous run, for an AUTHORIZED lab only.

This is the deploy wiring the library deliberately leaves out: it hands the
autonomous loop a REAL executor so the local model can pick and run any Kali tool
by itself. It is an example you read and adapt, not a turnkey weapon.

Run it ONLY against a host you own or are explicitly authorized to test. It still
honors every guard in the framework:

  * the run lock: it exits while agentpentest/RUN_DISABLED exists,
  * scope allowlist + SSRF guard (internal IPs need --allow-internal),
  * shellguard: destructive host binaries (rm, dd, mkfs, shutdown, ...) are refused,
  * rate limiter + circuit breaker so a struggling target is left alone,
  * a per-command human gate: you approve EVERY real action before it runs.

It needs a self-hosted Ollama model (local AI only). Without one the loop does
nothing, by design.

Usage (on the Kali/Linux box, after removing agentpentest/RUN_DISABLED):

    export AGENTPENTEST_OLLAMA_HOST=http://127.0.0.1:11434
    export AGENTPENTEST_OLLAMA_MODEL=qwen2.5
    python deploy/live_autonomous.py 192.168.56.101 \
        --scope 192.168.56.101 --allow-internal --goal "enumerate services and web paths"
"""
from __future__ import annotations

import argparse
import os

# Live run: fail CLOSED on a host that won't resolve (DNS-rebind / typo'd scope).
# security.assert_external reads this at call time; override by exporting =0.
os.environ.setdefault("AGENTPENTEST_STRICT_SSRF", "1")

from agentpentest import autonomous
from agentpentest.config import Config
from agentpentest.llm import OllamaReasoner
from agentpentest.runlog import RunLog
from agentpentest.safety import guard
from agentpentest.sandbox import LocalSandbox
from agentpentest.throttle import CircuitBreaker, RateLimiter

# Tool-name prefixes that must never run unattended even with a human present:
# impact / exfiltration / C2 / persistence territory. The operator is warned and
# the command is refused by this launcher. Loosen this ONLY if you truly mean to,
# on your own lab, and understand the blast radius.
_HIGH_IMPACT = ("msfconsole", "msfvenom", "meterpreter", "mimikatz", "impacket",
                "secretsdump", "crackmapexec", "nxc", "evil-winrm", "dd", "shred")


def operator_confirm(argv, target, rationale):
    """Human-in-the-loop gate: print the proposed action, require an explicit yes."""
    binary = (argv[0] if argv else "").lower()
    cmd = " ".join(argv)
    print(f"\n  proposed : {cmd}")
    print(f"  target   : {target}")
    print(f"  why      : {rationale}")
    if any(h in binary for h in _HIGH_IMPACT):
        print("  WARNING  : high-impact tool. This launcher refuses it by default.")
        return False
    try:
        ans = input("  run this? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


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
    args = ap.parse_args()

    from agentpentest import discover
    info = discover.discover_ollama(cfg.llm_model, hosts=[cfg.llm_host])
    if not info["connected"]:
        raise SystemExit("No local Ollama found. Start it (ollama serve) and pull a model.")
    print(f"Using local model {info['model']} at {info['host']}")
    reasoner = OllamaReasoner(info["model"], info["host"])   # local AI; refuses cloud hosts
    execute = autonomous.sandbox_execute(LocalSandbox())    # REAL execution on this box

    print("LIVE RUN. Authorized targets only. Approve each step; Ctrl-C to stop.\n")
    transcript = autonomous.autoloop(
        args.goal, set(args.scope), reasoner, execute,
        allow_internal=args.allow_internal, max_steps=args.max_steps,
        runlog=RunLog(args.log),
        rate_limiter=RateLimiter(max_per_second=args.rate),
        breaker=CircuitBreaker(max_consecutive_failures=3),
        confirm=operator_confirm,
    )
    print(f"\nDone. {len(transcript)} step(s) ran. Audit log: {args.log}")


if __name__ == "__main__":
    main()
