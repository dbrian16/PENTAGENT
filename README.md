# AI Agent Pentest

A research prototype of a multi agent LLM architecture for penetration testing. It studies how an agent can plan, remember, debate findings and backtrack through an engagement, using a simulated environment throughout.

> **Academic use only.** This project is not an attack tool and has never been run against a real target. It is shipped build only: nothing reaches a real system by default, and the CLI is locked by `agentpentest/RUN_DISABLED`. Read [SECURITY.md](SECURITY.md) before using or modifying the code, and only ever test systems you are explicitly authorized to test.

## Architecture

| Component | Module | Purpose |
|---|---|---|
| Recon loop | `orchestrator.py`, `planner.py`, `executor.py`, `perceptor.py` | Planner, Executor, Perceptor loop. Raw tool output never reaches the planner. |
| Attack tree memory | `ptt.py`, `brain.py` | Penetration Testing Tree with evidence levels. The EGATS search abandons failing branches. |
| Debate | `swarm.py` | Several roles propose hypotheses, and agreement raises confidence. |
| Stealth gate | `blueteam.py`, `reward.py`, `adversarial.py` | Simulated WAF scores how noisy each action would be. |
| Post exploit | `chain.py` | Confirmed findings suggest follow on steps. |
| Safety | `security.py`, `shellguard.py`, `throttle.py`, `sandbox.py` | Scope and SSRF guards, command validation, rate limiting, circuit breaker, snapshot and rollback. |
| Reporting | `report.py` | MITRE mapped Markdown or JSON report with remediation notes. |

## Usage

```bash
pip install -e .
agentpentest example.com               # simulated run, writes report.md
agentpentest example.com --interactive # approve each step
agentpentest example.com -o report.json
```

The CLI refuses to start while `agentpentest/RUN_DISABLED` exists. Remove that file only when you deliberately want to run the simulation on your own machine.

Tests run without a framework:

```bash
PYTHONPATH=. python tests/test_brain.py
```

## Design notes

- Every path that could touch a real target takes an injected function. This repository only wires in simulators and mocks.
- The reasoning model is optional and must be self hosted. Known cloud LLM API hosts are refused in code.
- The core uses only the standard library. The MCP server needs `fastmcp`.

## License

All rights reserved. See [LICENSE](LICENSE).
