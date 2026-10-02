# AI Agent Pentest

**A research framework for studying multi-agent LLM architectures applied to penetration testing.** It is a software-architecture study, not an attack tool: it ships **build-only**, runs nothing against any real target by default, and exists to document and test a design — Planner–Executor–Perceptor recon, an external attack-tree memory with evidence-guided backtracking, multi-agent hypothesis debate, red-vs-blue stealth scoring, and a self-hosted-LLM reasoning layer.

> 🎓 **Academic / educational project — not an attack toolkit.** This is a personal research build exploring agentic-AI architecture patterns for security tooling. It is **not affiliated with, used in, or a record of, any real penetration test, intrusion, or attack against any system.** Every path that could touch a real target is deliberately disconnected (see "Build-only boundary" throughout this document), and the repository ships with a run lock enabled (`agentpentest/RUN_DISABLED`) so the CLI refuses to execute anything until that lock is removed. Read **[SECURITY.md](SECURITY.md)** before using any part of this code, and only ever point it at systems you are explicitly authorized to test.

## Contents

- [Phase 1 — Reconnaissance (PEP loop)](#phase-1--reconnaissance-pep-loop)
- [Install & layout](#install--layout)
- [Phase 3 — Brain: PTT + TDA + EGATS backtracking](#phase-3--brain-ptt--tda--egats-backtracking)
- [Phase 4 — Swarm reasoning + reporting](#phase-4--swarm-reasoning--reporting)
- [Phase 4+ — Adversarial Red-vs-Blue (WAF-in-the-loop)](#phase-4-adversarial-red-vs-blue-waf-in-the-loop)
- [Snapshot & rollback sandbox](#snapshot--rollback-sandbox--sandboxsnapshotsandbox)
- [Interactive steering (human-in-the-loop)](#interactive-steering-human-in-the-loop--steeringpy)
- [Mode 3 — Dynamic PoC synthesis](#mode-3--dynamic-poc-synthesis-self-debugging-exploit-scripts--pocpy)
- [Hardening pass — closing the gaps found on review](#hardening-pass--closing-the-gaps-found-on-review)
- [Gap analysis vs PentestGPT & hackingBuddyGPT](#gap-analysis-vs-pentestgpt--hackingbuddygpt)
- [Configuration](#configuration-pre-configured-off-on-this-machine)
- [Where we can be stronger — and what we cannot do](#where-we-can-be-stronger--and-what-we-cannot-do)

## Phase 1 — Reconnaissance (PEP loop)

Implements the **Planner–Executor–Perceptor** decomposition from the PEP paradigm
for the recon phase only. The point of the split is context isolation: raw
Nmap/Subfinder/Gobuster output is distilled by the Perceptor and never reaches
the Planner's memory, so the loop doesn't drown in tool dumps.

```
Planner.next_tasks(state) -> Executor.run(task) -> Perceptor.perceive() -> state -> (loop)
```

| Component | File | Role |
|-----------|------|------|
| Planner   | `planner.py`   | STRIPS-style precondition scan over state; yields ready tasks (enum → scan → dir-bust) |
| Executor  | `executor.py`  | Looks up capability, runs it in a Sandbox; **scope guard**. Tool-agnostic |
| Perceptor | `perceptor.py` | Folds the uniform structured result into state. **Zero per-tool code** |
| State     | `state.py`     | The bounded shared memory (the "state set") |
| Loop      | `orchestrator.py` | Re-plans after every perceive; stops at fixed point or step budget |

### Tool integration & isolation (PentestMCP + sandbox)
| Layer | File | Role |
|-------|------|------|
| Capability registry | `tools.py` | Each tool is a `ToolSpec`: `build(params)->argv` + `parse(raw,params)->structured`. The MCP contract, in-process. Add a tool = add a spec; nothing else changes |
| MCP server | `mcp_server.py` | FastMCP wrappers (`@mcp.tool`) exposing the same capabilities over JSON-RPC. Schema inferred from type hints + docstrings. Runs inside the container |
| Container | `Dockerfile` | Kali image with nmap/gobuster/subfinder + the server; non-root, read-only, cap-dropped |
| Sandbox | `sandbox.py` | `LocalSandbox` (dev) / `DockerSandbox` (throwaway, read-only, caps dropped) / `SnapshotSandbox` (stateful session, **snapshot + rollback**) |
| Security controls | `security.py` | OWASP MCP Top-10 guards, stdlib-only (run without the MCP stack) |

**Why an MCP server on top of the in-process registry?** The registry is the same
contract; wrapping it in FastMCP puts a real client↔server boundary between the
agent and the tools, which is what lets the toolbox live inside the Kali container
(server) while the agent runs outside (client), talking over stdio-via-SSH or SSE.

### OWASP MCP Top-10 — risk → control
| Risk | Control (where) |
|------|-----------------|
| Over-privileged context | Server exposes **only** the 3 recon capabilities — no `run_command`/shell/file tool exists to reach host config (`mcp_server.py`, `tools.py`) |
| Instruction confusion (prompt injection via tool output) | Tool output is parsed to typed fields, never replayed to the model as a prompt; free-text remnants tagged by `security.quarantine()` |
| Confused deputy / SSRF | `security.assert_external()` refuses targets resolving to private/loopback/link-local/reserved space unless `allow_internal` is set (`test_ssrf_guard_blocks_internal`) |
| Token passthrough | Server reads scope from its **own** `RECON_SCOPE` env, never a client-forwarded scope/authorization — the client cannot widen scope |

**Two challenges, two answers:**
- *No rigid per-tool parsing* — every capability emits one schema (`subdomains` /
  `services` / `paths`), so Executor and Perceptor are tool-agnostic. Uniform in,
  uniform out = the MCP pattern; liftable onto a real MCP transport unchanged.
- *LLM must not run arbitrary commands* — the LLM emits `{capability, params}`
  only. `build()` validates params and returns an argv **list**; the Sandbox runs
  it `shell=False` inside a capability-dropped, read-only container. No shell
  string exists to inject into. (See `test_no_command_injection`.) The sandbox
  isolates the **host**, not the target network — recon still needs outbound.

## Install & layout

A proper Python package (`agentpentest/`), stdlib-only core, installable on Kali:

```bash
pip install -e .            # console commands: agentpentest, agentpentest-recon, agentpentest-view
pip install -e ".[mcp]"     # + the FastMCP server dependency
```

Run without installing (from this dir): `PYTHONPATH=. python -m agentpentest.campaign …`.

```bash
agentpentest example.com                 # full pipeline (simulation) -> report.md
agentpentest-recon example.com --scope example.com --mock   # Phase-1 recon only
agentpentest-view tree run.json          # inspect a saved trajectory
PYTHONPATH=. python tests/test_recon.py  # self-check (tests bypass the run lock)
```

**Build-only run lock:** while `agentpentest/RUN_DISABLED` exists, the `agentpentest`
and `agentpentest-recon` commands refuse to run (`safety.py`). Delete it to enable.
The lock is machine-local — it is **not** packaged into the wheel or the Kali image.

`--scope` is an allowlist. Any target not equal to, or a subdomain of, a listed
root is **refused** — only run against systems you are authorized to test.

## Deliberate simplifications (see `Design note:` comments in the source)
- Planner is a precondition scan, not a PDDL/DAG solver — recon is linear, so
  greedy ordering is correct. Swap behind `Planner.next_tasks()` if chains branch.
- Parsers are regex over `-sV` / `-silent` / `-q` output. Move to `nmap -oX` XML
  if you need bulletproof parsing.
- No LLM *required* — the whole pipeline runs deterministically offline. When a
  local reasoner is wired it augments three points (all off by default): the
  Executor's perception fallback (parse messy output), the EGATS strategist (pick
  the next move), and the swarm council (propose hypotheses).

## Phase 3 — Brain: PTT + TDA + EGATS backtracking

An LLM has no innate "give up": a failed branch still in the context window gets
re-proposed forever. The fix is an **external** trajectory memory the Planner reads
instead of the raw chat history.

| Piece | File | Role |
|-------|------|------|
| Penetration Testing Tree | `ptt.py` | Nodes = states/goals (root→host→service→hypothesis), edges = actions. Each node carries an `Evidence` level + attempt tally |
| Task Difficulty Assessment | `brain.py` `assess()` | Scores a node on the guide's four spaces: **horizon** (steps to goal), **success rate** (Laplace `(s+1)/(n+2)`), **evidence confidence** (mean root→node), **context load** (>60% degrades reasoning) → one `feasibility` |
| EGATS search | `brain.py` `EGATS` | Expand the most feasible open node; on `fail_streak ≥ 3` or `feasibility < 0.35`, **abandon** the branch and pivot. Proven not to loop (`test_egats_abandons_failing_branch_no_loop`) |

Evidence ladder (guide): verified shell `1.0` · confirmed vuln `0.8` · plausible
(version↔CVE) `0.5` · speculative `0.3`.

## Phase 4 — Swarm reasoning + reporting

| Piece | File | Role |
|-------|------|------|
| Multi-agent debate | `swarm.py` | RSA roles (static-analyst / protocol-expert / fuzzing-agent) propose competing hypotheses; agreement between ≥2 roles bumps the consensus evidence one notch. Seeds PTT nodes with a MITRE technique |
| Summarizer | `report.py` | Walks the PTT's **successful** path → Markdown: MITRE ATT&CK map, PoC rebuilt from winning actions (failed attempts dropped), remediation per technique |

## Phase 4+ — Adversarial Red-vs-Blue (WAF-in-the-loop)

The swarm alone imagines success and stays noisy. Adding a **Blue Team Agent** as a
Defender Simulator turns imagination into evolutionary pressure toward stealth.

```
Red_Planner ─action→ Blue_Evaluator ─blocked?─yes→ Red_Reflector ─lesson→ (episodic memory) → re-plan
    ▲ best-of-N          (WAF anomaly score)   │no                                                   │
    └─ consult lessons ──────────────────────  └→ Environment_Executor (INJECTED, simulated) ────────┘
                                          retry cap → Human-in-the-loop
```

| Piece | File | Role |
|-------|------|------|
| Blue Team Agent | `blueteam.py` + `data/crs_rules.json` | Deterministic **OWASP-CRS WAF simulator**: anomaly scoring (Critical 5 / Error 4 / Warning 3 / Notice 2, threshold 5), Paranoia Levels PL1–4, SOC noise (rate, 404 floods, scanner UA). Returns a structured `BlueVerdict` — no free-text to sweet-talk |
| Reward | `reward.py` | **Multiplicative** reward `S_bypass · I_intent · stealth` (kills reward-hacking) + **best-of-N** group-relative pick — the GRPO idea at inference |
| Adversarial loop | `adversarial.py` | Red↔Blue state machine: **Reflexion** turns each block into a lesson in **episodic memory** (checkpointable), best-of-N re-plans, retry-cap routes to HITL. LangGraph's design on our own loop, no new dependency |

It works: at **PL1** the Red agent obfuscates a raw `' OR 1=1` and spoofs the UA →
anomaly 0 → accepted; at **PL2** the WAF catches the obfuscation → blocked every round
→ human-in-the-loop with lessons recorded (`tests/test_adversarial.py`).

**Build-only.** Blue is a pure scorer; the `Environment_Executor` is **injected**
(`adversarial_loop(execute=…)`, default None) so accepting an action runs nothing. The
loop is an offline simulation that yields stealthier *strategies* and defensive
training data.

**Deploy/research-only (NOT built, by design):** real **GRPO fine-tuning** (needs a
trainable policy + reward rollouts + compute — we ship the reward + best-of-N, not the
trainer); a **real ModSecurity/CRS** binding behind `blueteam.evaluate`; **LangGraph**
orchestration if you prefer it over our loop; wiring a real (sandboxed) executor to the
accept path.

## Full pipeline (simulation only)

```bash
agentpentest example.com                 # recon -> swarm+Blue gate -> PTT -> EGATS -> report.md
agentpentest example.com --paranoia 2    # stricter WAF: more hypotheses flagged noisy
PYTHONPATH=. python tests/test_brain.py  # self-check
```

The pipeline is: recon → each swarm hypothesis passes the **Red-vs-Blue stealth gate**
(`build_tree` runs `adversarial_loop`, tagging each PTT node with a `stealth` rating
and a `noisy` flag) → EGATS deprioritises noisy branches and backtracks dead ones →
the report shows a **Stealth** column and flags noisy findings. At `--paranoia 1` the
Red agent makes everything stealthy (0 noisy); at `--paranoia 2` the WAF catches the
obfuscation and findings are flagged noisy.

`campaign.py` runs **no live pentest**: recon is mock, the Blue agent only scores, and
the EGATS outcome oracle is a scripted, offline function (`simulated_oracle`).

**Build-only boundary (deliberate).** No real exploit capability is wired in.
`brain.EGATS` calls an *injected* oracle; this repo only ever passes it a simulator.
To go live you would add exploit `ToolSpec`s and an oracle that runs them in the
Docker sandbox — that step is intentionally left out.

### Snapshot & rollback sandbox — `sandbox.SnapshotSandbox`

`DockerSandbox` runs one throwaway `--rm` container per command — perfect isolation but
**zero session state**, so a payload can't dirty anything and there's nothing to restore.
Real engagements need a container that persists across commands (foothold, loot, installed
tools) — which is precisely what a bad payload pollutes (crashed service, locked account,
overwritten config). `SnapshotSandbox` adds the checkpoint/rollback that was missing:

```python
from agentpentest import sandbox
sb = sandbox.SnapshotSandbox(runner=sandbox.docker_cli())   # deploy wires the real runner
sb.start()
with sb.guarded("pre-sqli"):          # docker commit BEFORE the dangerous payload
    sb.exec(["sqlmap", "-u", target]) # if it crashes/dirties the session -> auto rollback
sb.close()                            # tear down container + snapshot images
```

- `snapshot(label)` = `docker commit` (native, no flaky CRIU) → pushes an image tag.
- `rollback()` destroys the dirtied container and recreates it from the last good commit — session back to the pre-payload state instantly.
- `guarded(label)` wraps a block: snapshot first, auto-rollback on any exception.

**Host safety (the priority).** The session container is writable (snapshot/rollback needs
a dirty-able layer), so defence targets the host: caps dropped, `no-new-privileges`,
pid/memory/cpu limits, **no host bind mounts**. Only the container's own layer changes —
the host FS and kernel are never exposed.

**Build-only.** The docker runner is **injected** (`SnapshotSandbox(runner=…)`) and
defaults to a refusal, so nothing starts a container here. Deploy passes
`sandbox.docker_cli()`; tests inject a fake (`tests/test_sandbox_snapshot.py`). Same
injected-boundary pattern as `brain.EGATS`'s oracle — the live-execution seam stays
deliberately un-wired.

### Interactive steering (human-in-the-loop) — `steering.py`

The one capability PentestGPT had and we lacked. Pass `--interactive` (or `-i`) and
EGATS pauses before each step so the operator drives:

```bash
agentpentest example.com --interactive
  todo - open frontier by feasibility:
      n3  feas=0.62  ev=CONFIRMED   exploit http on 93.184.216.34:80
      n5  feas=0.46  ev=PLAUSIBLE   exploit ssh on 93.184.216.34:22
[steer] next -> n3 (exploit http ...) ?        # enter/next run it · todo relist ·
                                               # pick <id> override · skip abandon ·
                                               # auto hand back · quit stop
```

It only *gates* the same offline simulation — no new capability, the safest posture:
nothing proceeds without a keystroke, and the loop still contacts no target. The gate
is a `brain.Steer` hook (`EGATS(..., steer=...)`), so it reuses the TDA ranking rather
than duplicating it; `input` is injectable for testing (`tests/test_steering.py`).

## Gap analysis vs PentestGPT & hackingBuddyGPT

Compared against [PentestGPT](https://github.com/GreyDGL/PentestGPT) and
[hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT), and the gaps closed:

| Capability | PentestGPT | hackingBuddyGPT | Ours | Status |
|---|---|---|---|---|
| PTT / external memory | ✓ | JSONL | ✓ `ptt.py` | had it |
| Tool/capability abstraction | ✓ | ✓ | ✓ `tools.py` | had it |
| MCP + Docker isolation | partial | Docker VMs | ✓ | ahead |
| **Local LLM reasoning (no API)** | `ollama:` | `api_base` | ✓ `llm.py` | **added** |
| **Session save/resume** | ✓ | ✓ | ✓ `ptt.save/load` | **added** |
| **Structured run log (audit)** | ✓ | OTel JSONL | ✓ `runlog.py` | **added** |
| **Ground-truth verification** | — | ✓ (checks real UID) | ✓ `verify.py` | **added** |
| Interactive steering (`next/todo`) | ✓ | auto | ✓ `steering.py` | **added** |

**Local AI, self-hosted — never a cloud API.** `llm.OllamaReasoner` refuses known
cloud LLM API hosts (`_CLOUD_DENY`) but **allows self-hosted Ollama on loopback or
another machine on your LAN** (`test_gaps.py`). Opt-in; default `MockReasoner` keeps
the pipeline deterministic/offline. The model only *proposes* — build-only means it
executes nothing.

**Ground-truth verification (anti-hallucination).** `verify.proof_gated` gates the
EGATS oracle: a claimed `VERIFIED` with no corroborating proof recorded on the node
is demoted to `CONFIRMED` (hackingBuddyGPT's "check the real UID" idea). Off by
default (`trusting`); enable with `--verify`.

## Configuration (pre-configured, OFF on this machine)

Everything is env-driven (`config.py`). Defaults run nothing here; point the LLM at
your **other machine** and flip it on when ready:

```bash
export AGENTPENTEST_LLM=1
export AGENTPENTEST_OLLAMA_HOST=http://192.168.1.50:11434   # the other machine
export AGENTPENTEST_OLLAMA_MODEL=qwen2.5
export AGENTPENTEST_VERIFY=1
python campaign.py example.com --log run.jsonl --save run.json
python campaign.py --resume run.json          # reload trajectory, re-render report
```

| Env var | Default | Effect |
|---|---|---|
| `AGENTPENTEST_LLM` | off | add the local model as a swarm role |
| `AGENTPENTEST_OLLAMA_HOST` | `127.0.0.1:11434` | self-hosted Ollama (loopback or LAN) |
| `AGENTPENTEST_OLLAMA_MODEL` | `qwen2.5` | model name |
| `AGENTPENTEST_VERIFY` | off | ground-truth gate on |

## Where we can be stronger — and what we cannot do

**Adapt / improve to beat them (realistic):**
1. **Quantified auto-pivot (TDA+EGATS) > manual `next/todo`.** PentestGPT leans on a
   human typing `next`; our `brain.assess()` scores four spaces and backtracks on its
   own. Push it further: tune the weights against a benchmark, add Horizon estimation
   from the model.
2. **MCP tool layer > hand-wired Python capabilities.** Any tool with a JSON schema
   drops in (`tools.py` → `mcp_server.py`), hot-swappable and shareable across agents.
   Neither reference tool has the full MCP + Docker isolation we do.
3. **Proof-gated evidence ladder > "trust the model".** `verify.proof_gated` makes a
   finding only as strong as its corroboration — fewer hallucinated "got root" than a
   single-agent tool.
4. **Multi-agent debate/consensus for the unknown.** `swarm.py` cross-checks role
   hypotheses; extend it toward the guide's zero-day RSA council. Single-agent
   PentestGPT can't cross-examine itself.
5. **Enterprise-grade output.** MITRE ATT&CK + PoC + remediation + severity, both as
   markdown and as `report.generate_json` for a ticketing pipeline, is closer to a
   deliverable than either tool's raw text.
6. **Chains, doesn't stop at one hop.** `chain.py` pivots a verified foothold into
   follow-on goals (credential reuse, lateral movement, privesc) automatically —
   neither reference tool models post-exploitation.
7. **Protects the target, not just the host.** `throttle.py`'s rate cap + circuit
   breaker stop the agent from hammering a service that is already struggling —
   neither reference tool guards against the agent knocking over what it's testing.

**What we cannot do (honest limits):**
1. **No real findings while build-only.** With no live execution, "findings" are the
   simulator's — we cannot prove a real vuln or measure real success rate. This is the
   hard ceiling of the strict no-pentest rule, by design.
2. **Ground-truth verification is only as real as the observation.** `verify.py` gates
   claims, but in simulation the "proof" is a marker; true verification needs to read
   real target state (a live-execution step we don't build).
3. **Local-model reasoning caps our ceiling.** A self-hosted 7–14B model reasons well
   below frontier cloud models on exploit logic. Trading cloud for local is a
   deliberate privacy/cost choice, not a capability win — we win on *architecture*,
   not raw model IQ.
4. **No real zero-day discovery.** The debate can *propose* novel ideas; proving them
   needs real fuzzing/PoC execution + compute, which build-only excludes.
5. **No real benchmark.** hackingBuddyGPT regression-tests against live VMs; we can't
   reproduce that without running against targets.

## Two execution modes: typed capabilities vs autonomous terminal

The app now supports both, and you choose per engagement:

**1. Typed capabilities (safe default).** Each tool is a `ToolSpec` (nmap/gobuster/
subfinder) with a validated argv builder and a structured parser. No shell, tiny
attack surface — but you add code per tool.

**2. Autonomous terminal (any Kali tool, zero per-tool wiring).** The LLM reasons
from its OWN knowledge of Kali and proposes commands; you wire the loop ONCE.

```
LLM-Planner ─propose→ shellguard.validate ─ok→ execute(argv) ─raw→ LLM-Perceptor ─facts→ (loop)
   ▲                    (refuse → tell model)      (sandbox)                          │
   └──────────────────────────── compact facts only ───────────────────────────────┘
```

- `autonomous.py` — the plan→guard→execute→perceive loop. Add a tool to Kali and it
  is instantly usable; the knowledge lives in the model, not in app code.
- `shellguard.py` — destructive-binary denylist, optional tool allowlist, scope +
  SSRF, and **target-binding** (the declared target must appear in the command, so
  the model can't say "example.com" and scan something else).
- `mcp_server.run_command` — the same, exposed over MCP; **disabled unless
  `RECON_ALLOW_SHELL=1`**.

**The trade-off (stated honestly).** Mode 2 re-opens the OWASP *over-privileged
context* risk that mode 1 avoids. It is defensible because: the **ephemeral,
read-only, cap-dropped container is the security boundary** (not argv parsing), and
`shellguard` is defence in depth. PEP still bounds context — only distilled facts,
never raw dumps, return to the planner.

**Build-only.** Execution is **injected** (`autoloop(..., execute=...)`); this repo
always passes a simulator, so the loop runs nothing. Deploy wiring is one line:
`execute = autonomous.sandbox_execute(DockerSandbox(...))`. Offline default reasoner
proposes nothing → the loop is a no-op. (`tests/test_autonomous.py`.)

### Mode 3 — Dynamic PoC synthesis (self-debugging exploit scripts) — `poc.py`

Modes 1–2 still assume a *tool* (wrapped or named) exists for the job. The edge case
nobody wrapped — a custom packet structure, a one-off auth bypass — needs the agent to
**write its own script**, not reach for a wrapper. `poc.synthesize_poc` does that:

```
synthesize -> run -> validated(POC-OK marker)? -> done
                └ crash / POC-FAIL ─ feed traceback back ─ LLM fixes it ─ retry (<= max_fix)
```

- The LLM writes ONE self-contained python/go script tailored to the target.
- It runs in the sandbox; a crash's traceback is fed back so the model **debugs its own
  script** (self-correct loop), not just retries blindly.
- **Proof-gated validation:** success is not the model's word — the script must print
  `POC-OK: <proof>` and exit 0, which is extracted as the validated PoC. No marker =>
  unvalidated, however confident the model (the `verify.py` evidence idea, for code).

**Safety.** Target-binding at the script level: the authorized target must appear
literally in the generated source, or it is refused un-run (mirrors `shellguard`);
scope + SSRF checked up front. **Build-only:** the script runner is injected and defaults
to a refusal — nothing executes here. Deploy wires `poc.sandbox_runner(SnapshotSandbox(…))`
so generated code runs in a host-locked, snapshot/rollback container, never on the host.
(`tests/test_poc.py`.)

**Exposed over MCP, read-only-synth:** `mcp_server.run_poc(target, script, language)` —
the server never writes the script itself (no reasoner wired there); the client's own
LLM composes it, this tool only executes+proof-gates it inside the already-isolated Kali
container (`poc.execute_and_validate` + `poc.local_runner`). Same `RECON_ALLOW_SHELL=1`
gate and target-binding as `run_command`.

## Hardening pass — closing the gaps found on review

A follow-up review of the finished framework found seven more build-time gaps (no
deploy needed to close them). All seven are closed, offline, build-only, each with its
own test file:

| # | Gap | Fix | File(s) |
|---|-----|-----|---------|
| 1 | **Prompt injection** — raw target/script output went straight into LLM prompts (`executor._llm_extract`, `autonomous._perceive`, `poc`'s self-debug loop); `security.quarantine()` existed but nothing called it | `security.sanitize_for_prompt()` tags every line as `DATA\|` and flags known steering phrases (`flag_injection`); wired into all three call sites + a `runlog` event on a flagged hit | `security.py`, `executor.py`, `autonomous.py`, `poc.py` — `tests/test_injection_guard.py` |
| 2 | **PoC synth + snapshot sandbox were ocean apart from the agent** — neither `poc.synthesize_poc` nor `SnapshotSandbox` was reachable from `autoloop` | `autoloop` gained a `synthesize_poc` plan action (Mode 3 from inside Mode 2's loop) and an optional `session` (SnapshotSandbox) that snapshots before every risky step and auto-rolls-back on a crash (`_run_guarded`) | `autonomous.py` — `tests/test_autonomous_advanced.py` |
| 3 | **No DoS guard protecting the TARGET** — `shellguard` protects the host, `blueteam` only scores Red's stealth; nothing stopped the loop from hammering a fragile service | `throttle.py`: `RateLimiter` (sliding window) + `CircuitBreaker` (opens after consecutive connection-refused/timeout/5xx signs), wired into `autoloop` and `poc.synthesize_poc` | `throttle.py`, `autonomous.py`, `poc.py` — `tests/test_throttle.py` |
| 4 | **PoC/snapshot not reachable over MCP** | `mcp_server.run_poc` (see above); `poc.execute_and_validate`/`poc.local_runner` extracted so the server needs no reasoner of its own | `mcp_server.py`, `poc.py` |
| 5 | **No post-exploit chaining** — the tree stopped at host→service→hypothesis | `chain.py`: `expand()` turns a CONFIRMED/VERIFIED node into new frontier nodes (credential reuse, lateral movement, privesc) from the knowledge base; `EGATS` gained an `expander` hook called on every success — zero change to its own search loop, chaining is just more frontier | `chain.py`, `brain.py`, `campaign.py` — `tests/test_chain.py` |
| 6 | **Context budget was a char-count with no relief valve** | `PentestTree.compact()` drops abandoned branches' heavy command transcripts (keeps lineage for the report); `EGATS` calls it when `context_load() > CONTEXT_HIGH` after a backtrack | `ptt.py`, `brain.py` — `tests/test_chain.py` |
| 7 | **Report had no severity and no machine-readable export** | `knowledge.severity()`/`severity_rank()` (from `data/attack.json`); findings sorted worst-first with a Severity column; `report.to_dict`/`generate_json` — `campaign --out report.json` picks it automatically | `data/attack.json`, `knowledge.py`, `report.py`, `campaign.py` — `tests/test_report.py` |

All seven keep the same injected-seam pattern as everything else in this repo
(`brain.EGATS`'s oracle, `SnapshotSandbox`'s docker runner, `poc`'s script runner):
nothing new executes by default, build-only holds.

## Completeness pass (built, offline, build-only)

| Area | What was added |
|------|----------------|
| Packaging | Real `agentpentest/` package + `pyproject.toml` + console entry points — installs & runs anywhere on Kali |
| Knowledge base | `knowledge.py` + `data/attack.json`: MITRE techniques, service→technique map, CVE hints. One editable source; replaces scattered hardcode |
| LLM in perception | `Executor` optional reasoner: LLM parse-fallback when regex finds nothing |
| LLM in planning | `EGATS` optional `strategist`: local model picks the next move among TDA's top candidates |
| Failure Type A/B | Oracle errors → Type A (tool/skill), TDA give-up → Type B (strategic); both in the run log |
| Run budget | `EGATS(max_seconds=…)` wall-clock cap, plus `max_steps` |
| Persistence | `ReconState` and `PentestTree` both `save`/`load` JSON |
| Audit log | `runlog` now covers recon **and** the brain; `agentpentest-view` inspects tree/log |

## Deploy on Kali — done here vs deploy-only

**Done here (nothing to build at deploy):** the whole framework, all four test
suites, the package, the knowledge base, the local-AI wiring, the OWASP MCP
controls, the report generator. `pip install -e .` and it runs (simulation).

**Deploy-only (needs the Kali box / your call — I did NOT do these, per build-only):**
1. **Install the real tools** on Kali: `nmap`, `gobuster`, `subfinder` (the Dockerfile does this for the MCP server image).
2. **Build the MCP image:** `docker build -t kali-recon-mcp .` then run it `--read-only --cap-drop ALL` (command in the Dockerfile footer). Docker isn't installed in this dev env.
3. **Point the LLM at your other machine:** `export AGENTPENTEST_OLLAMA_HOST=http://<that-box>:11434` and `AGENTPENTEST_LLM=1`. Ollama must be reachable from Kali.
4. **Enable live execution** (turn the simulated EGATS oracle into a real one that runs tools via MCP) — this is the line you asked me *not* to cross. The seam is `brain.EGATS`'s injected `oracle`; wiring a real one + a real `verify.py` observation check is a deliberate, separate decision.
5. **Remove `RUN_DISABLED`** on the deploy box when you actually want it to run.

## Phase map → guide
| Guide phase | Built |
|-------------|-------|
| 0 — LLM vs RL (hybrid: LLM core + external graph) | rationale; realized as PEP loop + PTT |
| 1 — Recon + PEP | `planner/executor/perceptor/state/orchestrator` |
| 2 — Toolbox: MCP + Docker | `tools.py`, `mcp_server.py`, `Dockerfile`, `sandbox.py`, `security.py` |
| 3 — Brain: state + backtracking | `ptt.py`, `brain.py` |
| 4 — Swarm + zero-day + reporting | `swarm.py`, `report.py`, `campaign.py` |
