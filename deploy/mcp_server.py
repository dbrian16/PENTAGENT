"""MCP server launcher with run_command and run_poc enabled (RECON_ALLOW_SHELL=1).

    python deploy/mcp_server.py --scope 192.168.1.10
"""
from __future__ import annotations

import argparse
import os
import sys

from agentpentest.safety import guard

guard("MCP server")        # exits while RUN_DISABLED exists


def main() -> None:
    ap = argparse.ArgumentParser(description="Live MCP server (authorized lab only)")
    ap.add_argument("--scope", nargs="+", default=[], metavar="ROOT",
                    help="authorized target roots; sets RECON_SCOPE")
    ap.add_argument("--allow-internal", action="store_true",
                    help="permit private/LAN targets (your own lab)")
    ap.add_argument("--tool-allowlist", nargs="+", default=[], metavar="TOOL",
                    help="restrict run_command to these tool names only")
    args = ap.parse_args()

    os.environ["RECON_ALLOW_SHELL"] = "1"
    if args.scope:
        os.environ["RECON_SCOPE"] = ",".join(args.scope)
    if args.allow_internal:
        os.environ["RECON_ALLOW_INTERNAL"] = "1"
    if args.tool_allowlist:
        os.environ["RECON_TOOL_ALLOWLIST"] = ",".join(args.tool_allowlist)

    scope_str = ", ".join(args.scope) if args.scope else "(open)"
    print(f"[mcp] RECON_ALLOW_SHELL=1  scope={scope_str}")
    print("[mcp] run_command and run_poc are ACTIVE. Authorized targets only.")
    print()

    from agentpentest import mcp_server as _srv
    transport = os.environ.get("RECON_MCP_TRANSPORT", "stdio")
    _srv.mcp.run(transport=transport)


if __name__ == "__main__":
    main()
