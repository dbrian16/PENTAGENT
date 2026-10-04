# Deploying for a live run (authorized lab)

This guide takes the framework from simulation to a real run on Linux. Read
[SECURITY.md](SECURITY.md) first. Only ever point this at a host you own or are
explicitly authorized to test. The examples below assume a lab VM you control
(for example DVWA or Metasploitable on an internal network).

## What actually runs, and what does not

- **Reconnaissance runs for real.** `agentpentest-recon` drives nmap, subfinder and
  gobuster against the target through the sandbox.
- **The autonomous terminal can run any Kali tool** when you hand it a real executor
  (`deploy/live_autonomous.py`). The local model proposes each command; you approve it.
- **The staged campaign (`agentpentest ...`) stays simulated.** Its exploit oracle is a
  scripted offline function. It is a demo of the search and reporting, not a live attack.
- **Real exploitation is not wired in.** The EGATS oracle seam is left unconnected on
  purpose; this repo does not turn it into a real one.

## 1. Prepare the box

Kali already has the tools. On plain Ubuntu/Debian:

```bash
sudo apt update && sudo apt install -y nmap gobuster python3-pip
# subfinder: install from the ProjectDiscovery release or your package manager
python3 --version        # need 3.11+
```

Install the package:

```bash
cd AI-Agent-Pentest
pip install -e .
```

## 2. (Optional) local model

The autonomous loop needs a self-hosted model to reason. Cloud API hosts are refused
in code. Point it at Ollama on this box or another machine on the LAN:

```bash
export AGENTPENTEST_OLLAMA_HOST=http://127.0.0.1:11434
export AGENTPENTEST_OLLAMA_MODEL=qwen2.5
ollama serve &  ollama pull qwen2.5
```

Reconnaissance does not need a model; the autonomous loop does.

## 3. Unlock

The CLI refuses to run while the lock file exists. Remove it deliberately:

```bash
rm agentpentest/RUN_DISABLED
```

Put it back (`touch agentpentest/RUN_DISABLED`) when you are done.

## 4. Run real recon

```bash
agentpentest-recon 192.168.56.101 --scope 192.168.56.101 --allow-internal
```

`--scope` is an allowlist; anything outside it is refused. `--allow-internal` permits
private/LAN addresses for your lab while keeping the SSRF guard on for everything else.

## 5. Run the autonomous loop (approve each step)

```bash
python deploy/live_autonomous.py 192.168.56.101 \
    --scope 192.168.56.101 --allow-internal \
    --goal "enumerate services and web paths"
```

The model proposes one command at a time. You approve or decline each one. Guards stay
on throughout: scope and SSRF, the destructive-binary denylist, a rate limiter and a
circuit breaker (it stops if the target starts failing), and a JSONL audit log.

High-impact tooling (Metasploit, credential dumpers, C2) is refused by that launcher by
default. Enabling it is a deliberate edit you make, understanding the blast radius, on
your own lab.

### Kali + Metasploitable, host-only network

This is the recommended first lab. Two VMs on a host-only adapter (no Internet route):
Kali as the attacker, Metasploitable as the deliberately vulnerable target. Find the
target's address with `ip a` on the Metasploitable VM (often `192.168.56.x`), then use
it as both the positional target and the `--scope` entry, with `--allow-internal`.

Because it is an isolated box you own, exploiting it is fine. If you want the agent to
drive Metasploit itself, remove `"msfconsole"` from `_HIGH_IMPACT` in
`deploy/live_autonomous.py`. Note the autonomous loop proposes one argv command at a
time, so it works best with non-interactive invocations such as
`msfconsole -x "<resource commands>; exit"`, or with sqlmap/hydra/nmap NSE scripts.
Keep the per-command approval gate on for the first runs.

## Safety checklist before you start

- [ ] The target is yours or you have written authorization.
- [ ] `--scope` lists only authorized hosts.
- [ ] You are on an isolated lab network, not a production path.
- [ ] You will watch the run and approve each action.
- [ ] You will restore `RUN_DISABLED` afterwards.
