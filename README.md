# Autonomous Offensive Agent

A research prototype that models an autonomous penetration test as a team of
cooperating agents: they plan the next move, keep an external memory of every
branch they have tried, debate findings before trusting them, and back out of
dead ends instead of looping on them. Everything runs as an offline simulation,
so the whole flow from recon to report can be read, tested, and extended without
touching a live system.

## What it does

- **Recon loop** — a Planner / Executor / Perceptor cycle. Raw tool output is
  distilled into structured state before the model ever sees it, so the reasoning
  context never drowns in Nmap or Subfinder dumps.
- **External memory** — a Penetration Testing Tree (PTT) holds the campaign
  trajectory outside the model. The EGATS search expands the most promising node,
  records outcomes, and abandons failing branches so they are not re-proposed.
- **Debate** — a small council of roles proposes competing hypotheses; agreement
  raises confidence before a node enters the tree.
- **Stealth gate** — a deterministic blue-team scorer (an OWASP-CRS WAF model plus
  light SOC signals) rates how noisy each proposed action would be. Nothing runs;
  it only scores.
- **Reporting** — the surviving path becomes a MITRE ATT&CK-mapped report with
  CVSS 4.0 scores, a rebuilt proof-of-concept, and remediation notes, as Markdown
  or JSON.

## Architecture

| Area | Modules | Role |
|---|---|---|
| Recon loop | `orchestrator.py`, `planner.py`, `executor.py`, `perceptor.py` | Planner / Executor / Perceptor cycle; raw tool output never reaches the planner. |
| Attack-tree memory | `ptt.py`, `brain.py` | PTT with evidence levels; EGATS expands, records, and abandons failing branches. |
| Execution contract | `prompts.py` | The single system prompt every reasoner call inherits: epistemic discipline, scope ROE, PTES + ATT&CK, untrusted tool output, forced decision schema. |
| Debate | `swarm.py` | Competing hypotheses from several roles; agreement raises confidence. |
| Stealth gate | `blueteam.py`, `reward.py`, `adversarial.py` | Simulated WAF/SOC scores how loud each action would be. |
| Post-exploit | `chain.py` | Confirmed findings seed follow-on frontier nodes. |
| Safety | `security.py`, `shellguard.py`, `throttle.py`, `sandbox.py` | Scope and SSRF guards, command validation, rate limiter, circuit breaker, snapshot/rollback. |
| Reporting | `report.py` | MITRE-mapped Markdown or JSON with CVSS 4.0 and remediation. |

Five further modules push the design from "an LLM that free-generates" toward a
workflow of specialized agents around deterministic state. All are offline; every
path that could act takes an injected seam that defaults to a no-op.

| Area | Module | Role |
|---|---|---|
| Graph state | `knowledge_graph.py`, `asset_vault.py` | Campaign state is a labeled property graph (STIX 2.1), not linear context; `attack_paths` finds multi-hop AD escalation chains. Credentials live in the vault as reference IDs, never plaintext in a prompt. |
| Agent state machine | `statemachine.py` | A hypothesis-to-verification loop (Analysis, Planner, Validation, Execution, Evaluation): planning is separated from execution, a validator refuses destructive steps, a deterministic evaluator decides confirm / refine / block. |
| Kernel observability | `ebpf_monitor.py` | A simulated eBPF/Falco telemetry and BPF-LSM policy engine: tells the agent when an EDR is blocking it, and hard-denies forbidden writes, stray spawns, and off-gateway egress. No real kernel probes are attached. |
| Cross-campaign memory | `experience_replay.py` | A replay buffer abstracts past campaigns into strategy and technical-action memory; Just-In-Time RL re-ranks candidate actions by past advantage, gradient-free. |
| Evidence and risk | `evidence.py` | An Evidence Ladder a finding must climb in order (candidate to strict confirmation), plus deterministic CVSS 4.0 scoring. |

## Safety

This repository is build-only. It ships wired to simulators and mocks, and is
designed so that reading or running it cannot touch a real target.

- A run lock: the CLIs refuse to start while `agentpentest/RUN_DISABLED` exists.
- Every path that could reach a real target takes an injected function; the
  defaults are simulators and no-ops.
- The reasoning model is optional and must be self-hosted (Ollama). Known cloud
  LLM API hosts are refused in code.
- Scope and SSRF checks, a destructive-binary denylist, shell-free argv (no shell
  string for a model to inject into), a rate limiter, and a circuit breaker apply
  in code, not just in the prompt.

## Usage

```bash
pip install -e .

agentpentest example.com                # simulated run, writes report.md
agentpentest example.com --interactive  # approve each step
agentpentest example.com -o report.json # structured findings instead of Markdown
agentpentest example.com --save run.json # save the attack tree for later inspection

agentpentest-view tree run.json         # inspect a saved attack tree
agentpentest-ui                         # local dashboard at http://127.0.0.1:8765
```

The simulated campaign runs even while the lock is on; only real recon and the
live loop are gated. Delete `agentpentest/RUN_DISABLED` only when you deliberately
want to enable those on your own machine.

## Requirements

- Python 3.11+. The core depends on the standard library only.
- Optional: a self-hosted Ollama instance for the reasoning roles; `fastmcp` for
  the MCP server.

## Tests

```bash
python -m pytest -q
```

## License

All rights reserved. See [LICENSE](LICENSE).
