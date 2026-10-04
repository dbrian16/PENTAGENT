# Security and responsible use

## What this project is

This is a research project about multi agent LLM architecture for penetration testing. It studies a design (a planner/executor/perceptor loop, an external attack tree memory, multi agent debate, a red versus blue stealth gate). It is not an attack tool, and it has not been used to scan, access or attack any real system.

## It is build only

Every path that could touch a real target takes an injected function (`execute=`, `oracle=`, `run=`, `runner=`). This repository only ever wires those to an offline simulator, a mock, or a function that refuses by default.

The file `agentpentest/RUN_DISABLED` ships committed and enabled. While it exists, the CLI entry points refuse to run at all (`safety.guard()`). Cloning or installing this repository does not give you a working offensive tool. Someone would have to delete that file and then wire a real executor behind one of the injected seams above, against a system they are actually authorized to test.

If a reasoning model is wired in at all (it is off by default), it has to be self hosted. `llm.py` refuses known cloud LLM API hosts in code.

The default pipeline runs a scripted offline oracle. Anything it reports is a demonstration of the search and backtracking logic, not evidence of a real vulnerability anywhere.

## Authorized use only

Every guard in this codebase (scope allowlist, SSRF guard, target binding on commands and PoC scripts, rate limiting, the circuit breaker) exists to make unauthorized use harder by construction. None of it makes unauthorized use acceptable. Only ever point a real build of this at a system you have explicit written permission to test.

## Known limits of the guards

The guards are defence in depth, not perfect boundaries. Two are worth stating plainly, because the real boundary sits elsewhere (the sandbox container and the human approval gate):

- **Target binding is a substring check.** `shellguard` and `poc` require the declared target to appear literally in the command/script, and reject a second out-of-scope host token. A crafted argument that embeds the target string while still reaching elsewhere, or a schemeless host-with-path, can slip the heuristic. The container's network policy, not this string match, is what actually keeps traffic in scope.
- **A generated PoC runs arbitrary code in the container.** `poc` only binds the target by substring; the script body itself is unconstrained, and the recon container runs with a normal outbound bridge network (recon needs it). A hallucinated or injected PoC could therefore reach a host outside scope. The only hard boundary here is the container's network. If you run live against a sensitive network, restrict the container's egress to the engagement scope (e.g. a scoped `--network`/firewall), which this repo does not do for you.

The SSRF guard (`assert_external`) is fail-open on an unresolvable host by default so offline tests pass. Set `AGENTPENTEST_STRICT_SSRF=1` to fail closed instead; the live launcher (`deploy/live_autonomous.py`) and the Kali container both turn it on, since they have DNS and a non-resolving target there means a typo or a rebind, not an offline test.

The web dashboard (`webui.py`) binds loopback only and refuses cross-origin POSTs (CSRF) and foreign `Host` headers (DNS rebinding), so a malicious page the operator has open cannot drive it. It still has no user auth, so treat access to the machine as access to the console.

## Reporting a concern

This is a personal project, not a maintained product. If you think something here could be misused in a way the build only design above does not already prevent, please open a GitHub issue.
