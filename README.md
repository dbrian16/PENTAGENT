# AI Agent Pentest

What happens when you give a language model the mindset of a penetration tester, not just its vocabulary? Most LLM security tools stall the moment a step fails: the model forgets what it already tried, repeats a dead end, and loses the thread of a long engagement. This project is a research prototype that tackles that head on. It models a single pentest as a team of cooperating agents that plan the next move, remember every branch they have explored, argue findings out before trusting them, and walk back from dead ends the way a human operator would.

The design borrows from recent agentic AI research and assembles it into one coherent pipeline: a Planner, Executor, Perceptor reconnaissance loop that keeps raw tool noise away from the model's reasoning; an external attack tree that gives the agent a real memory and a real sense of when to give up; a small council of specialist roles that debate each hypothesis; a simulated blue team that scores how loud every action would be; and a reporting layer that turns the surviving path into a MITRE mapped write up. Everything runs in simulation, so the architecture can be studied, tested, and extended without ever touching a live system.

It is built to be read as much as run. Each module is small, documented, and wired to the next through a clean seam, so the whole flow from recon to report can be followed end to end.

## Architecture

| Component | Module | Purpose |
|---|---|---|
| Recon loop | `orchestrator.py`, `planner.py`, `executor.py`, `perceptor.py` | Planner, Executor, Perceptor loop. Raw tool output never reaches the planner. |
| Attack tree memory | `ptt.py`, `brain.py` | Penetration Testing Tree with evidence levels. The EGATS search abandons failing branches. |
| Execution contract | `prompts.py` | The one system prompt every reasoner call inherits: epistemic discipline, scope ROE, PTES + ATT&CK, untrusted-tool-output, and a forced decision schema. |
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

- The execution contract (`prompts.py`) aligns the model; the code binds it. Scope, shellguard, SSRF, and proof-gating enforce the same rules in code and do not depend on the prompt being obeyed.
- Every path that could touch a real target takes an injected function. This repository only wires in simulators and mocks.
- The reasoning model is optional and must be self hosted. Known cloud LLM API hosts are refused in code.
- The core uses only the standard library. The MCP server needs `fastmcp`.

## License

All rights reserved. See [LICENSE](LICENSE).
