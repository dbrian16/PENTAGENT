# Kali MCP server: the recon toolbox, isolated from the host.
# The agent (MCP client) talks to this over stdio (via SSH) or SSE, never a shell.
FROM kalilinux/kali-rolling

# Only the recon tools this phase exposes. No shells-as-a-service, nothing extra.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap gobuster python3 python3-pip python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# subfinder is Go tooling; grab the static release rather than the whole Go stack.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -sSL -o /tmp/sf.zip \
        https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip \
    && (cd /usr/local/bin && python3 -c "import zipfile,sys; zipfile.ZipFile('/tmp/sf.zip').extractall()") \
    && chmod +x /usr/local/bin/subfinder && rm /tmp/sf.zip \
    && apt-get purge -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY agentpentest ./agentpentest
RUN pip3 install --no-cache-dir --break-system-packages ".[mcp]"

# Drop privileges: the server never needs root.
RUN useradd -m recon
USER recon

# Scope is injected at runtime, e.g. -e RECON_SCOPE=example.com. Empty = deny all.
ENV RECON_SCOPE="" RECON_MCP_TRANSPORT="stdio"
ENTRYPOINT ["python3", "-m", "agentpentest.mcp_server"]

# Run isolated (host FS protected; outbound kept for recon):
#   docker build -t kali-recon-mcp .
#   docker run --rm -i --cap-drop ALL --security-opt no-new-privileges \
#              --read-only --pids-limit 256 -e RECON_SCOPE=example.com kali-recon-mcp
