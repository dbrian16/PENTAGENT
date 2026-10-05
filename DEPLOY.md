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

The run lock can be removed from the command line **or via the UI** (click the
🔓 button that appears in the sidebar when the lock is active).

```bash
rm agentpentest/RUN_DISABLED
```

Put it back (`touch agentpentest/RUN_DISABLED`) when you are done.

## 3b. Sudo for privileged tools

Many nmap scan types (SYN scan `-sS`, OS detection `-O`, etc.) require root
privileges. Three options, pick one:

**Option A — run the dashboard as root (simplest for a lab VM):**
```bash
sudo PYTHONPATH=. python -m agentpentest.webui --sudo
```

**Option B — NOPASSWD in sudoers (per-tool, more controlled):**
```bash
sudo visudo -f /etc/sudoers.d/agentpentest
# add: kali ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/sbin/masscan
```
Then start with `--sudo`:
```bash
PYTHONPATH=. python -m agentpentest.webui --sudo
```

**Option C — Linux capabilities (no sudo at all):**
```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/nmap
```
nmap can then run raw-socket scans as a regular user.

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
default. Pass `--allow-high-impact` to permit it (still one approval per command), on
your own isolated lab.

## 5b. Unlock real exploitation (proof-gated PoC)

Recon and the terminal only *enumerate*. To let the agent actually *exploit*, add `--poc`:

```bash
python deploy/live_autonomous.py 192.168.56.101 \
    --scope 192.168.56.101 --allow-internal \
    --goal "prove the SQL injection on the login form" --poc
```

With `--poc` the model can, when no stock tool fits, write a single-use script, run it in
the sandbox, read the traceback, and self-debug (up to `--poc-fix` times). It counts as a
real finding **only** if the script prints `POC-OK: <proof>` and exits 0 — the model's word
is never enough. You still approve each PoC before it runs. This is the line between an
enumeration toy and a real agent: creative exploration by the model, strict verification by
code.

### A legal target to point at

On the Kali box, stand up a deliberately-vulnerable app you own, then target it:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop   # or DVWA, or a Metasploitable VM
python deploy/live_autonomous.py 127.0.0.1:3000 --scope 127.0.0.1 --allow-internal \
    --goal "find and prove an injection or broken-auth flaw" --poc
```

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
