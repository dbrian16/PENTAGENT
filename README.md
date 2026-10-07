<div align="center">

# PENTAGENT

**Autonomous AI red-team agent — simulation and live modes.**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Core](https://img.shields.io/badge/core-stdlib_only-success.svg)](#requirements)
[![MITRE ATT&CK](https://img.shields.io/badge/maps_to-MITRE_ATT%26CK-red.svg)](#architecture)

</div>

---

PENTAGENT is an AI-driven penetration testing framework that runs a full red-team campaign — recon, planning, exploitation, evasion, and reporting — using a team of cooperating agents backed by a local LLM (Ollama). It ships in simulation mode by default and can be unlocked for live runs against authorized targets.

## What it does

- **Recon** — Planner/Executor/Perceptor loop. Raw tool output is distilled into structured state before the LLM ever reads it.
- **Attack tree (PTT + EGATS)** — External memory holds the campaign outside the model. The search engine expands the best node, records outcomes, abandons dead ends, and seeds follow-on techniques after each confirmed finding.
- **Swarm debate** — Multiple agent roles propose competing hypotheses. Agreement is required before a finding enters the tree.
- **Red vs Blue** — A deterministic WAF/SOC scorer (OWASP-CRS, four paranoia levels) rates how noisy each action would be. The Red agent learns from failures via Reflexion and re-plans stealthier variants.
- **PoC synthesis** — When no existing Kali tool fits, the LLM writes a single-use script, runs it in a sandbox, and self-debugs on failure. Only accepted on a `POC-OK:` proof line + exit 0.
- **Report** — Surviving attack path becomes a MITRE ATT&CK-mapped report with CVSS 4.0 scores, EPSS/KEV threat intel, stealth ratings, PoC, and remediation. Markdown or JSON.

## Architecture

| Module(s) | Role |
|---|---|
| `orchestrator`, `planner`, `executor`, `perceptor` | Recon loop |
| `ptt`, `brain` | Penetration Testing Tree + EGATS search |
| `swarm` | Multi-role debate and consensus |
| `adversarial`, `blueteam`, `reward` | Red vs Blue stealth loop |
| `poc` | LLM-synthesized proof-of-concept scripts |
| `statemachine` | Co-RedTeam: Analysis → Planner → Validation → Execution → Evaluation |
| `knowledge_graph`, `asset_vault` | STIX 2.1 campaign graph; credentials as vault refs (never plaintext to LLM) |
| `experience_replay` | Cross-campaign replay buffer + JitRL re-ranking |
| `evidence` | Evidence Ladder (G1→E1) anti-hallucination gates + CVSS 4.0 |
| `ebpf_monitor` | Simulated eBPF/Falco policy engine; tells the agent when EDR is blocking it |
| `shellguard`, `throttle`, `sandbox` | Command validation, rate limiter, circuit breaker, snapshot/rollback |
| `prompts` | Single system prompt contract every LLM call inherits |
| `report` | MITRE-mapped output with CVSS 4.0, EPSS, remediation |
| `simworld` | SimulationOracle (causal dice model) and LiveOracle (real autoloop) |

## Quickstart

```bash
pip install -e .

# Simulation — no lock required, no real traffic
agentpentest example.com
agentpentest example.com --interactive   # approve each EGATS step
agentpentest example.com -o report.json  # structured JSON instead of Markdown

# Inspect results
agentpentest-view tree run.json
agentpentest-ui                          # dashboard at http://127.0.0.1:8765
```

## Live mode (authorized targets only)

```bash
# Toggle the run lock
agentpentest-lock status
agentpentest-lock off    # unlock — delete RUN_DISABLED
agentpentest-lock on     # re-lock

# Autonomous terminal loop (LLM drives a Kali sandbox step by step)
python deploy/live_autonomous.py 192.168.1.10 \
    --scope 192.168.1.10 \
    --goal "enumerate services and find vulnerabilities" \
    --poc \
    --allow-high-impact

# Multi-agent Co-RedTeam (hypothesis → plan → validate → execute → evaluate)
python deploy/live_autonomous.py 192.168.1.10 \
    --scope 192.168.1.10 \
    --mode co-redteam

# MCP server (exposes tools to an external LLM client)
python deploy/mcp_server.py --scope 192.168.1.10
```

Needs: Kali/Linux, Docker running, Ollama running (`ollama serve`).

## Safety

- **Run lock** — all CLIs exit immediately while `agentpentest/RUN_DISABLED` exists. Use `agentpentest-lock off` to remove it.
- **Injected executors** — every path that touches a real target takes an injected function; simulation mode wires in no-ops and dice oracles.
- **Self-hosted LLM only** — Ollama only. Cloud API hosts are refused in code.
- **Guards in code** — scope/SSRF checks, destructive-binary denylist, argv-only (no shell string), rate limiter, circuit breaker, snapshot/rollback sandbox, BPF-LSM policy gate.
- **Prompt injection quarantine** — raw tool output is sanitized before it reaches the LLM. Steering phrases are flagged and logged.

## Requirements

- Python 3.11+ (core is stdlib-only)
- Ollama (optional, for LLM-driven roles)
- Docker (for live sandbox isolation)
- `fastmcp` for the MCP server (`pip install -e ".[mcp]"`)

## Tests

```bash
python -m pytest -q
```

## License

All rights reserved. See [LICENSE](LICENSE).
