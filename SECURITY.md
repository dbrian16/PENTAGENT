# Security & Responsible Use

## What this project is

This repository is an **academic / research project**: a software-architecture
study of multi-agent LLM designs applied to penetration testing concepts — a
Planner–Executor–Perceptor reconnaissance loop, an external attack-tree memory
with evidence-guided backtracking, multi-agent hypothesis debate, and a
red-vs-blue stealth-scoring gate. It exists to document and test that
*architecture*.

**It is not an attack tool, and it has not been used to attack, scan, or access
any real system.** Nothing in this repository is, or is derived from, a real
penetration test, intrusion, or engagement against any organization.

## Build-only, by design

- **Execution is deliberately disconnected everywhere.** Every path that could
  touch a real target — tool execution, the EGATS outcome oracle, PoC script
  execution, Docker snapshot/rollback — takes an *injected* function
  (`execute=...`, `oracle=...`, `run=...`, `runner=...`). This repository only
  ever wires those to offline simulators, mocks, or a function that refuses by
  default. See the "Build-only boundary" notes throughout `README.md` and the
  module docstrings for the exact seam in each case.
- **A run lock ships enabled.** `agentpentest/RUN_DISABLED` is committed to
  this repository on purpose. While it exists, `safety.guard()` makes the
  `agentpentest` / `agentpentest-recon` CLI entry points exit immediately
  without doing anything. Cloning or installing this repository does **not**
  give you a working offensive tool — you would have to deliberately delete
  that file *and* wire a real executor behind one of the injected seams above,
  against a system you are explicitly authorized to test.
- **Local AI only.** If a reasoning model is wired in at all (off by default),
  it must be a self-hosted model you run yourself (`llm.OllamaReasoner`).
  Known cloud LLM API hosts are refused in code, not just in a policy
  document — see `llm.py`'s `_CLOUD_DENY` list.
- **Simulated findings only.** The default pipeline (`campaign.py`) runs a
  scripted, offline outcome oracle. Any "finding" it produces is a
  demonstration of the search/backtracking mechanism, not evidence of a real
  vulnerability in any real system.

## Authorized use only

If you remove the run lock and wire a real executor, every guard in this
codebase (scope allowlist, SSRF guard, shell-command target-binding, PoC
script target-binding, rate limiting, the circuit breaker) exists to make
*unauthorized* use harder by construction — not to make it acceptable to skip
authorization. **Only ever point this at systems you have explicit, written
permission to test.** Scanning, exploiting, or otherwise accessing a system
without authorization is illegal in most jurisdictions regardless of what
tooling is used.

## Reporting a concern

This is a personal academic project, not a maintained commercial product.
If you believe something in this repository could be misused in a way the
build-only design above doesn't already prevent, please open a GitHub issue
on this repository describing the concern.
