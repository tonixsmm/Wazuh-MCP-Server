"""
Wazuh MCP Simple Server — stdio & streamable-http transport.

A lightweight alternative to the full FastAPI remote server. No auth, no Docker,
no complexity. Designed for direct use with Claude Desktop (stdio) or simple HTTP
deployment for multi-user access.

Transport selection via MCP_TRANSPORT env var:
  stdio (default)  — Claude Desktop / local use
  streamable-http  — HTTP server at MCP_HOST:MCP_PORT/mcp

SSL note: Wazuh SSL verification is controlled by the VERIFY_SSL env var
(not WAZUH_VERIFY_SSL). Set VERIFY_SSL=false for self-signed certs.

Quick start (Claude Desktop):
  Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
  {
    "mcpServers": {
      "wazuh": {
        "command": "/path/to/venv/bin/python3",
        "args": ["/Users/tony/Documents/Python/Wazuh-MCP-Server/simple_server.py"],
        "env": {
          "WAZUH_HOST": "your-wazuh-ip",
          "WAZUH_USER": "wazuh-api-user",
          "WAZUH_PASS": "wazuh-api-password",
          "WAZUH_PORT": "55000",
          "VERIFY_SSL": "false",
          "WAZUH_INDEXER_HOST": "your-indexer-host",  (optional)
          "WAZUH_INDEXER_USER": "admin",              (optional)
          "WAZUH_INDEXER_PASS": "admin"               (optional)
        }
      }
    }
  }

HTTP deployment:
  MCP_TRANSPORT=streamable-http MCP_HOST=0.0.0.0 MCP_PORT=8000 \\
    WAZUH_HOST=... WAZUH_USER=... WAZUH_PASS=... \\
    python simple_server.py
  # → binds at http://0.0.0.0:8000/mcp
"""

import json
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

# Allow running from project root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from fastmcp import FastMCP
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError

# ---------------------------------------------------------------------------
# Global client — initialised in lifespan, used by all tool functions
# ---------------------------------------------------------------------------

_wazuh_client: Optional[WazuhClient] = None


@asynccontextmanager
async def wazuh_lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Initialize and teardown the Wazuh API client."""
    global _wazuh_client
    try:
        config = WazuhConfig.from_env()
        _wazuh_client = WazuhClient(config)
        await _wazuh_client.initialize()
        print("Wazuh MCP Server ready.", file=sys.stderr)
    except Exception as exc:
        # Don't crash the process — tools will return a helpful error instead
        print(f"WARNING: Wazuh client init failed: {exc}", file=sys.stderr)
        _wazuh_client = None
    yield {}
    if _wazuh_client is not None:
        await _wazuh_client.close()
        _wazuh_client = None


mcp = FastMCP("Wazuh Security MCP Server", lifespan=wazuh_lifespan)


def _client() -> WazuhClient:
    """Return the global WazuhClient, raising if not initialised."""
    if _wazuh_client is None:
        raise RuntimeError(
            "Wazuh client is not initialised. "
            "Check WAZUH_HOST, WAZUH_USER, WAZUH_PASS env vars and server logs."
        )
    return _wazuh_client


# ---------------------------------------------------------------------------
# Alerts (4 tools)
# ---------------------------------------------------------------------------

@mcp.tool
async def get_wazuh_alerts(
    limit: int = 100,
    rule_id: Optional[str] = None,
    level: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> str:
    """Retrieve Wazuh security alerts.

    Args:
        limit: Maximum number of alerts to return (default 100, max 1000).
        rule_id: Filter alerts by Wazuh rule ID.
        level: Filter alerts by severity level (e.g. "10" or "10-15" for a range).
        agent_id: Filter alerts by agent ID.
    """
    params: dict = {"limit": limit}
    if rule_id is not None:
        params["rule.id"] = rule_id
    if level is not None:
        params["level"] = level
    if agent_id is not None:
        params["agent.id"] = agent_id
    result = await _client().get_alerts(**params)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_alert_summary(
    time_range: str = "24h",
    group_by: str = "rule.description",
) -> str:
    """Get a summary of Wazuh alerts grouped by a field.

    Args:
        time_range: Time window to summarise (e.g. "1h", "24h", "7d").
        group_by: Field to group results by (default "rule.description").
    """
    result = await _client().get_alert_summary(time_range=time_range, group_by=group_by)
    return json.dumps(result, indent=2)


@mcp.tool
async def analyze_alert_patterns(
    time_range: str = "24h",
    min_frequency: int = 5,
) -> str:
    """Analyze recurring alert patterns to surface high-signal security events.

    Args:
        time_range: Time window to analyze (e.g. "1h", "24h", "7d").
        min_frequency: Minimum number of occurrences for a pattern to be included.
    """
    result = await _client().analyze_alert_patterns(
        time_range=time_range,
        min_frequency=min_frequency,
    )
    return json.dumps(result, indent=2)


@mcp.tool
async def search_security_events(
    query: str,
    time_range: str = "24h",
    limit: int = 100,
) -> str:
    """Full-text search across Wazuh security events.

    Args:
        query: Search query string (supports Wazuh query syntax).
        time_range: Time window to search within (e.g. "1h", "24h", "7d").
        limit: Maximum number of results to return.
    """
    result = await _client().search_security_events(
        query=query,
        time_range=time_range,
        limit=limit,
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Agents (6 tools)
# ---------------------------------------------------------------------------

@mcp.tool
async def get_wazuh_agents(
    status: Optional[str] = None,
    limit: int = 100,
    agent_id: Optional[str] = None,
) -> str:
    """List Wazuh agents.

    Args:
        status: Filter by agent status ("active", "disconnected", "never_connected", "pending").
        limit: Maximum number of agents to return.
        agent_id: Retrieve a specific agent by ID.
    """
    params: dict = {"limit": limit}
    if status is not None:
        params["status"] = status
    if agent_id is not None:
        params["agents_list"] = agent_id
    result = await _client().get_agents(**params)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_running_agents() -> str:
    """List all currently active (running) Wazuh agents."""
    result = await _client().get_running_agents()
    return json.dumps(result, indent=2)


@mcp.tool
async def check_agent_health(agent_id: str) -> str:
    """Check the health status of a specific Wazuh agent.

    Args:
        agent_id: The Wazuh agent ID to check (e.g. "001").
    """
    result = await _client().check_agent_health(agent_id=agent_id)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_agent_processes(
    agent_id: str,
    limit: int = 100,
) -> str:
    """Get the running processes on a Wazuh agent via syscollector.

    Args:
        agent_id: The Wazuh agent ID.
        limit: Maximum number of processes to return.
    """
    result = await _client().get_agent_processes(agent_id=agent_id, limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_agent_ports(
    agent_id: str,
    limit: int = 100,
) -> str:
    """Get the open network ports on a Wazuh agent via syscollector.

    Args:
        agent_id: The Wazuh agent ID.
        limit: Maximum number of port entries to return.
    """
    result = await _client().get_agent_ports(agent_id=agent_id, limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_agent_configuration(agent_id: str) -> str:
    """Retrieve the effective configuration of a Wazuh agent.

    Args:
        agent_id: The Wazuh agent ID.
    """
    result = await _client().get_agent_configuration(agent_id=agent_id)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Vulnerabilities (3 tools — require Wazuh Indexer)
# ---------------------------------------------------------------------------

@mcp.tool
async def get_wazuh_vulnerabilities(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> str:
    """Retrieve vulnerability data from the Wazuh Indexer (Wazuh 4.8.0+).

    Requires WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS
    environment variables to be set.

    Args:
        agent_id: Filter vulnerabilities for a specific agent.
        severity: Filter by severity level ("critical", "high", "medium", "low").
        limit: Maximum number of vulnerabilities to return.
    """
    try:
        result = await _client().get_vulnerabilities(
            agent_id=agent_id,
            severity=severity,
            limit=limit,
        )
        return json.dumps(result, indent=2)
    except IndexerNotConfiguredError:
        return json.dumps({
            "error": "Wazuh Indexer not configured. "
                     "Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."
        }, indent=2)


@mcp.tool
async def get_wazuh_critical_vulnerabilities(limit: int = 100) -> str:
    """Retrieve critical-severity vulnerabilities from the Wazuh Indexer.

    Requires WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS.

    Args:
        limit: Maximum number of critical vulnerabilities to return.
    """
    try:
        result = await _client().get_critical_vulnerabilities(limit=limit)
        return json.dumps(result, indent=2)
    except IndexerNotConfiguredError:
        return json.dumps({
            "error": "Wazuh Indexer not configured. "
                     "Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."
        }, indent=2)


@mcp.tool
async def get_wazuh_vulnerability_summary(time_range: str = "24h") -> str:
    """Get a summary of vulnerability counts by severity from the Wazuh Indexer.

    Requires WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS.

    Args:
        time_range: Time range for the summary (e.g. "24h", "7d").
    """
    try:
        result = await _client().get_vulnerability_summary(time_range=time_range)
        return json.dumps(result, indent=2)
    except IndexerNotConfiguredError:
        return json.dumps({
            "error": "Wazuh Indexer not configured. "
                     "Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."
        }, indent=2)


# ---------------------------------------------------------------------------
# Security Analysis (6 tools)
# ---------------------------------------------------------------------------

@mcp.tool
async def analyze_security_threat(
    indicator: str,
    indicator_type: str = "ip",
) -> str:
    """Analyze a security threat indicator using Wazuh threat intelligence.

    Args:
        indicator: The threat indicator value (IP, domain, hash, etc.).
        indicator_type: Type of indicator ("ip", "domain", "hash", "url").
    """
    result = await _client().analyze_security_threat(
        indicator=indicator,
        indicator_type=indicator_type,
    )
    return json.dumps(result, indent=2)


@mcp.tool
async def check_ioc_reputation(
    indicator: str,
    indicator_type: str = "ip",
) -> str:
    """Check the reputation of an Indicator of Compromise (IoC).

    Args:
        indicator: The IoC value to check (IP, domain, file hash, etc.).
        indicator_type: Type of indicator ("ip", "domain", "hash", "url").
    """
    result = await _client().check_ioc_reputation(
        indicator=indicator,
        indicator_type=indicator_type,
    )
    return json.dumps(result, indent=2)


@mcp.tool
async def perform_risk_assessment(agent_id: Optional[str] = None) -> str:
    """Perform a risk assessment for an agent or the entire environment.

    Args:
        agent_id: Agent ID to assess. If omitted, assesses the full environment.
    """
    result = await _client().perform_risk_assessment(agent_id=agent_id)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_top_security_threats(
    limit: int = 10,
    time_range: str = "24h",
) -> str:
    """Get the top security threats detected by Wazuh.

    Args:
        limit: Number of top threats to return.
        time_range: Time window to search (e.g. "1h", "24h", "7d").
    """
    result = await _client().get_top_security_threats(
        limit=limit,
        time_range=time_range,
    )
    return json.dumps(result, indent=2)


@mcp.tool
async def generate_security_report(
    report_type: str = "executive",
    include_recommendations: bool = True,
) -> str:
    """Generate a security report from Wazuh data.

    Args:
        report_type: Report format ("executive", "technical", "compliance").
        include_recommendations: Whether to include remediation recommendations.
    """
    result = await _client().generate_security_report(
        report_type=report_type,
        include_recommendations=include_recommendations,
    )
    return json.dumps(result, indent=2)


@mcp.tool
async def run_compliance_check(
    framework: str,
    agent_id: Optional[str] = None,
) -> str:
    """Run a compliance check against a security framework.

    Args:
        framework: Compliance framework to check ("pci_dss", "hipaa", "gdpr", "nist", "cis").
        agent_id: Agent ID to check. If omitted, checks the full environment.
    """
    result = await _client().run_compliance_check(
        framework=framework,
        agent_id=agent_id,
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# System Monitoring (10 tools)
# ---------------------------------------------------------------------------

@mcp.tool
async def get_wazuh_statistics() -> str:
    """Get overall Wazuh manager statistics (events processed, queue usage, etc.)."""
    result = await _client().get_wazuh_statistics()
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_weekly_stats() -> str:
    """Get weekly statistical summary from the Wazuh manager."""
    result = await _client().get_weekly_stats()
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_cluster_health() -> str:
    """Get the health status of the Wazuh cluster."""
    result = await _client().get_cluster_health()
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_cluster_nodes() -> str:
    """List all nodes in the Wazuh cluster with their status."""
    result = await _client().get_cluster_nodes()
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_rules_summary() -> str:
    """Get a summary of loaded Wazuh detection rules grouped by category."""
    result = await _client().get_rules_summary()
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_remoted_stats() -> str:
    """Get statistics from the Wazuh remoted daemon (agent communication)."""
    result = await _client().get_remoted_stats()
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_log_collector_stats() -> str:
    """Get statistics from the Wazuh log collector daemon."""
    result = await _client().get_log_collector_stats()
    return json.dumps(result, indent=2)


@mcp.tool
async def search_wazuh_manager_logs(
    query: str,
    limit: int = 100,
) -> str:
    """Search Wazuh manager internal logs.

    Args:
        query: Search string to filter log entries.
        limit: Maximum number of log entries to return.
    """
    result = await _client().search_manager_logs(query=query, limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
async def get_wazuh_manager_error_logs(limit: int = 50) -> str:
    """Retrieve error-level log entries from the Wazuh manager.

    Args:
        limit: Maximum number of error log entries to return.
    """
    result = await _client().get_manager_error_logs(limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
async def validate_wazuh_connection() -> str:
    """Validate the connection to the Wazuh manager and return version/status info."""
    result = await _client().validate_connection()
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Incident Response (1 tool)
# ---------------------------------------------------------------------------

@mcp.tool
async def build_incident_timeline(
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    query: Optional[str] = None,
    level: Optional[str] = None,
    time_range: str = "24h",
    limit: int = 200,
) -> str:
    """Build a unified incident timeline correlating alerts and manager logs.

    Concurrently fetches alerts and manager logs, normalises them into a
    common format, and returns them sorted by timestamp (newest first).
    If one source fails the other's results are still returned.

    Args:
        agent_id: Filter timeline events for a specific agent.
        rule_id: Filter by Wazuh rule ID.
        query: Full-text search query applied to manager logs.
        level: Filter by severity level (applied to both alerts and logs).
        time_range: Time window to cover ("1h", "6h", "24h", "7d").
        limit: Maximum total events in the returned timeline.
    """
    result = await _client().build_incident_timeline(
        agent_id=agent_id,
        rule_id=rule_id,
        query=query,
        level=level,
        time_range=time_range,
        limit=limit,
    )
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()

    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="streamable-http",
            host=os.getenv("MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_PORT", "8000")),
        )
