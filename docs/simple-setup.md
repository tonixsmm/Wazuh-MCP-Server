# Wazuh MCP — Simple Local Setup (Claude Desktop, no Docker)

A lightweight setup that connects Claude Desktop directly to your Wazuh manager via stdio. No Docker, no auth server, no JWT tokens — just Python and a config file.

---

## Prerequisites

- Python 3.10+ (system Python, conda, or pyenv)
- A running Wazuh manager with API access on port 55000
- Claude Desktop installed on macOS or Windows

---

## Install

```bash
git clone https://github.com/tonixsmm/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
pip install -r requirements.txt
```

Note your Python binary path after install — you'll need it for the Claude Desktop config:

```bash
# conda environment
conda activate your-env && which python

# system Python
which python3
```

---

## If Wazuh is on a remote VM (SSH tunnel)

If your Wazuh manager isn't reachable directly, forward the port over SSH:

```bash
ssh -N -L 55000:localhost:55000 user@your-vm-ip

# examples: applicable to Gonzaga SEAS wazuh
ssh -L 8443:localhost:443 -L 55000:localhost:55000 ai-wazuh #IP to wazuh - hosted on SEAS GPU subnet instance.
ssh -L 8443:localhost:443 ai-wazuh #tunnel the dashboard 
ssh -L 15500:localhost:15500 -L 9200:localhost:9200 ai-wazuh # wazuh indexer
```

Then use `localhost` as `WAZUH_HOST` in the config below. Keep this tunnel open while using Claude.

---

## Configure Claude Desktop

Edit the Claude Desktop config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/python3",
      "args": ["/path/to/Wazuh-MCP-Server/simple_server.py"],
      "env": {
        "WAZUH_HOST": "your-wazuh-ip-or-hostname",
        "WAZUH_USER": "wazuh-wui",
        "WAZUH_PASS": "your-password",
        "WAZUH_PORT": "55000",
        "VERIFY_SSL": "false"
      }
    }
  }
}
```

> **Key gotcha**: `WAZUH_HOST` must be a bare hostname or IP — no `https://` prefix. The client adds the protocol automatically.
>

### Optional: Vulnerability tools (Wazuh 4.8.0+)

Since Wazuh 4.8.0 the vulnerability API was moved to the Wazuh Indexer. Add these vars to unlock the three vulnerability tools:

```json
"WAZUH_INDEXER_HOST": "your-indexer-ip",
"WAZUH_INDEXER_USER": "admin",
"WAZUH_INDEXER_PASS": "admin-password"
```

---

## Restart Claude Desktop & verify

Fully quit Claude Desktop (Cmd+Q on Mac, or right-click the tray icon on Windows) and reopen it.

Look for the hammer icon in the chat bar — it should show **30 tools**. Then ask:

> "validate my Wazuh connection"

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Tools icon missing | Config JSON syntax error | Validate JSON at [jsonlint.com](https://jsonlint.com) |
| "Wazuh client not initialised" | Wrong `WAZUH_HOST` or unreachable server | Check host format; verify tunnel/network |
| `https://https://...` in logs | `WAZUH_HOST` set to `https://...` | Remove the `https://` from `WAZUH_HOST` |
| 401 Unauthorized | Wrong credentials | Verify with the curl command below |
| Vulnerability tools return errors | Indexer not configured | Add `WAZUH_INDEXER_*` env vars |

### Verify credentials manually

```bash
curl -k -u 'wazuh-wui:your-password' \
  https://your-wazuh-host:55000/security/user/authenticate -X POST
```

A successful response contains a `token` field. A 401 means wrong credentials.

### Check MCP server logs (macOS)

```bash
tail -f ~/Library/Logs/Claude/mcp-server-wazuh.log
```

---

## HTTP mode (optional, multi-user)

To share the server with a team instead of running it locally per-user:

```bash
MCP_TRANSPORT=streamable-http MCP_HOST=0.0.0.0 MCP_PORT=8000 \
  WAZUH_HOST=your-host WAZUH_USER=your-user WAZUH_PASS=your-password \
  python simple_server.py
```

Each user then adds `http://your-server:8000/mcp` to Claude Desktop → **Settings** → **Connectors**.

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WAZUH_HOST` | Yes | — | Wazuh manager hostname or IP (no `https://`) |
| `WAZUH_USER` | Yes | — | Wazuh API username |
| `WAZUH_PASS` | Yes | — | Wazuh API password |
| `WAZUH_PORT` | No | `55000` | Wazuh API port |
| `VERIFY_SSL` | No | `true` | Set `false` for self-signed certificates |
| `WAZUH_INDEXER_HOST` | No | — | Indexer hostname or IP (vulnerability tools) |
| `WAZUH_INDEXER_USER` | No | — | Indexer username |
| `WAZUH_INDEXER_PASS` | No | — | Indexer password |
| `WAZUH_INDEXER_PORT` | No | `9200` | Indexer port |
| `MCP_TRANSPORT` | No | `stdio` | `stdio` or `streamable-http` |
| `MCP_HOST` | No | `127.0.0.1` | HTTP bind host (HTTP mode only) |
| `MCP_PORT` | No | `8000` | HTTP bind port (HTTP mode only) |
