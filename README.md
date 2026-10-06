<div align="center">

# 🛡️ PENTAGENT

### The Autonomous Offensive Agent

**A team of cooperating AI agents that plan, attack, debate, and report — like a real red team, entirely in simulation.**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Stdlib Core](https://img.shields.io/badge/core-stdlib_only-success.svg)](#requirements)
[![Mode](https://img.shields.io/badge/mode-offline_simulation-orange.svg)](#-safety-first-by-design)
[![MITRE ATT&CK](https://img.shields.io/badge/maps_to-MITRE_ATT%26CK-red.svg)](#-from-recon-to-report)

</div>

---

## Why PENTAGENT

Most "AI hacking" projects are a single large language model free-generating shell
commands and hoping for the best. They forget what they tried, loop on dead ends,
trust their own hallucinations, and drown in raw Nmap output.

**PENTAGENT is the opposite.** It models a penetration test the way a real red team
runs one: a crew of specialized agents that **plan the next move, remember every
branch they've explored, argue findings out before trusting them, and walk away from
dead ends** instead of spinning on them. Deterministic state and hard safety rails
sit underneath the reasoning — not inside a hopeful prompt.

And it does all of this **offline**. Every path that could touch a live target is
wired to a simulator by default, so the entire flow — recon to final report — can be
read, tested, and extended on your laptop without a single packet leaving it.

> 🧪 **Research prototype. Build-only.** PENTAGENT is for studying how autonomous
> offensive reasoning *could* be structured safely. It ships disarmed. See
> [Safety](#-safety-first-by-design).

---

## ✨ What makes it different

| | |
|---|---|
| 🧠 **It thinks in a tree, not a transcript** | A Penetration Testing Tree (PTT) holds the whole campaign *outside* the model. EGATS search expands the most promising node, records what happened, and abandons failing branches so they're never re-proposed. No more goldfish memory. |
| 🗣️ **It argues with itself** | A council of agent roles proposes competing hypotheses. Agreement raises confidence *before* a finding is trusted. One model's hallucination doesn't become the plan. |
| 🤫 **It knows when it's being loud** | A deterministic blue-team scorer (an OWASP-CRS WAF model + SOC signals) rates how noisy every proposed action would be — so stealth is measured, not guessed. |
| 🧹 **It never sees the mess** | Raw tool output is distilled into structured state *before* the reasoning model ever reads it. The planner reasons over facts, not Nmap dumps. |
| 🔒 **It's dangerous to no one** | Run lock, injected no-op seams, self-hosted-only models, scope/SSRF guards, destructive-command denylist, rate limiter, circuit breaker — enforced in code, not in a prompt. |
| 📄 **It writes the report for you** | The surviving attack path becomes a MITRE ATT&CK–mapped report with CVSS 4.0 scores, a rebuilt proof-of-concept, and remediation notes. Markdown or JSON. |

---

## 🎯 From recon to report

```
         ┌──────────── Recon loop ────────────┐
Target → │ Planner → Executor → Perceptor ──┐  │
         └──────────────────────────────────┘  │
                     ▲                          ▼
         ┌───────────┴──── structured state ────────────┐
         │   Attack Tree (PTT) + Knowledge Graph (STIX)  │
         └───────────────────────────────────────────────┘
                     ▲                          ▼
            Debate (swarm)            Stealth gate (WAF/SOC)
                     │                          │
                     └──────────┬───────────────┘
                                ▼
                   MITRE ATT&CK report · CVSS 4.0 · PoC
```

- **Recon loop** — a Planner / Executor / Perceptor cycle. Raw tool output is
  distilled into structured state before the model ever sees it, so the reasoning
  context never drowns in Nmap or Subfinder dumps.
- **External memory** — the PTT holds the campaign trajectory outside the model.
  EGATS expands the most promising node, records outcomes, and abandons failing
  branches so they are not re-proposed.
- **Debate** — a small council of roles proposes competing hypotheses; agreement
  raises confidence before a node enters the tree.
- **Stealth gate** — a deterministic blue-team scorer rates how noisy each proposed
  action would be. Nothing runs; it only scores.
- **Reporting** — the surviving path becomes a MITRE ATT&CK–mapped report with
  CVSS 4.0 scores, a rebuilt proof-of-concept, and remediation notes.

---

## 🏗️ Architecture

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

---

## 🔒 Safety first, by design

This repository is **build-only**. It ships wired to simulators and mocks, and is
designed so that reading or running it cannot touch a real target.

- 🔐 **Run lock** — the CLIs refuse to start while `agentpentest/RUN_DISABLED` exists.
- 🧩 **No-op by default** — every path that could reach a real target takes an injected
  function; the defaults are simulators and no-ops.
- 🏠 **Self-hosted only** — the reasoning model is optional and must be self-hosted
  (Ollama). Known cloud LLM API hosts are refused in code.
- 🚧 **Guards in code, not prompts** — scope and SSRF checks, a destructive-binary
  denylist, shell-free argv (no shell string for a model to inject into), a rate
  limiter, and a circuit breaker apply in code.

---

## 🚀 Quickstart

```bash
pip install -e .

agentpentest example.com                # simulated run, writes report.md
agentpentest example.com --interactive  # approve each step
agentpentest example.com -o report.json # structured findings instead of Markdown
agentpentest example.com --save run.json # save the attack tree for later inspection

agentpentest-view tree run.json         # inspect a saved attack tree
agentpentest-ui                         # local dashboard at http://127.0.0.1:8765
```

The simulated campaign runs even while the lock is on; only real recon and the live
loop are gated. Delete `agentpentest/RUN_DISABLED` only when you deliberately want to
enable those on your own machine.

---

## 📦 Requirements

- **Python 3.11+** — the core depends on the standard library only.
- *Optional:* a self-hosted Ollama instance for the reasoning roles; `fastmcp` for the
  MCP server.

## ✅ Tests

```bash
python -m pytest -q
```

## 📄 License

All rights reserved. See [LICENSE](LICENSE).

<div align="center">
<sub>Built for research into safe, structured, autonomous offensive reasoning. Use responsibly.</sub>
</div>
