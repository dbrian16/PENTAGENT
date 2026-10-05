# Security notes

## Guards and their limits

**Target binding is a substring check.** `shellguard` and `poc` require the declared
target to appear literally in the command/script. A crafted argument that embeds the
target string while still reaching elsewhere can slip it. The container's network
policy is the hard boundary, not this string match.

**Generated PoC runs arbitrary code in the container.** `poc` binds the target by
substring; the script body is otherwise unconstrained. If running live against a
sensitive network, restrict the container's egress to the engagement scope with a
scoped `--network` or firewall rule — this repo does not do that for you.

**SSRF guard is fail-open on unresolvable hosts by default** so offline tests pass.
Set `AGENTPENTEST_STRICT_SSRF=1` to fail closed; `deploy/live_autonomous.py` turns
this on automatically.

**Web dashboard has no auth.** `webui.py` binds loopback only and blocks CSRF and
DNS-rebinding, but anyone with access to the machine has access to the console.

## Reporting

Open a GitHub issue if you believe something here can be misused in a way the
injected-seam / run-lock design does not already prevent.
