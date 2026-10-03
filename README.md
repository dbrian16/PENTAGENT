# AI Agent Pentest

This is a personal research project about agentic AI architecture for penetration testing. It is not a hacking tool and it was never used against a real target. The goal was to study how a multi agent LLM system could plan, remember, debate and backtrack through an engagement, and to build that architecture end to end.

## Academic project, not an attack tool

Everything here runs in simulation. No path to a real target is wired in by default, and the repository ships with a run lock (`agentpentest/RUN_DISABLED`) that keeps the CLI from executing anything until someone deliberately removes it. Please read `SECURITY.md` before touching any of this code, and only ever point a real build at systems you are authorized to test.

## What it is

A small Python package that models five phases of an agentic pentest:

* Recon runs as a Planner, Executor and Perceptor loop so the model never has to read raw tool dumps.
* A Penetration Testing Tree acts as external memory. It tracks evidence and attempt history per node so a failed branch actually gets abandoned instead of retried forever.
* An EGATS search scores every open branch and backtracks the weak ones.
* A small council of roles debates each finding before it is trusted (static analysis, protocol knowledge, a deterministic fuzzing stand in, optionally a local LLM).
* A blue team agent scores how noisy an action would be against a simulated WAF, so the report can flag what would likely get caught.
* A reporting pass turns the surviving branches into a MITRE mapped write up with remediation notes.

Later passes added a few more pieces: a sandbox with snapshot and rollback, an interactive "approve every step" mode, a PoC synthesis mode for cases no wrapped tool covers, a rate limiter and circuit breaker so the agent cannot hammer a struggling service, and post exploit chaining so a confirmed finding can suggest a follow on step.

All of it is offline by default. If a reasoning model is wired in at all, it has to be self hosted (Ollama). The code refuses known cloud LLM API hosts outright.

## Quick start

```bash
pip install -e .
agentpentest example.com
```

That command will refuse to run while `agentpentest/RUN_DISABLED` exists, which is the point. Delete that file only if you actually want to run the simulation locally.

```bash
PYTHONPATH=. python tests/test_recon.py
```

runs one of the test files directly if you do not want to install the package.

## Layout

```
agentpentest/      the package: planner, executor, perceptor, brain, swarm, sandbox, poc synthesis, reporting
agentpentest/data/  the MITRE technique table and the WAF rule set
tests/              one test file per area, plain asserts, no test framework
```

## License

All rights reserved. See `LICENSE`.
