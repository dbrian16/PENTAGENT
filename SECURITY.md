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

## Reporting a concern

This is a personal project, not a maintained product. If you think something here could be misused in a way the build only design above does not already prevent, please open a GitHub issue.
