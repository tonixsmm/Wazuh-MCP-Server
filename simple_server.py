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

import functools
import json
import os
import sys
from collections import Counter
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

# Allow running from project root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from fastmcp import FastMCP
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError
from usage_tracker import UsageTracker

# Default usage log to repo root if not set by the caller
if not os.environ.get("USAGE_LOG_PATH"):
    os.environ["USAGE_LOG_PATH"] = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "wazuh_mcp_usage.json"
    )
_tracker = UsageTracker()

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


def with_usage_tracking(fn):
    """Append a token-usage footer to every tool response."""
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs) -> str:
        result: str = await fn(*args, **kwargs)
        try:
            input_text = json.dumps(kwargs)
            info = _tracker.record(fn.__name__, input_text, result)
            call_tok = info.get("call_tokens", 0)
            sess_tok  = info.get("session_tokens", 0)
            limit     = _tracker.soft_limit
            sess_pct  = (sess_tok / limit * 100) if limit else 0.0
            footer = (
                f"\n\n---\n"
                f"📊 Usage: {call_tok} tokens this call | "
                f"Session: {sess_tok:,} / {limit:,} ({sess_pct:.1f}%)"
            )
            warning = info.get("warning")
            if warning:
                footer += f"\n{warning}"
            return result + footer
        except Exception:
            return result  # never let tracking break a tool
    return wrapper


# ---------------------------------------------------------------------------
# Guardrail constants & helpers
# ---------------------------------------------------------------------------

MAX_RAW_RESULTS = 500
_ALERT_SUMMARY_THRESHOLD = 50


def _truncation_notice(returned: int, total: int) -> str:
    """Append-friendly notice when results are capped."""
    return (
        f"\n\n[TRUNCATED] Showing {returned} of {total:,} total results. "
        "Narrow your query with filters (agent_name, rule_level, rule_id, "
        "time range) to see more specific data."
    )


def _build_alert_summary(alerts: list, total: int) -> dict:
    """Build a compact summary dict from a list of raw alert dicts."""
    rule_ids: Counter = Counter()
    agents: Counter = Counter()
    mitre_techniques: Counter = Counter()
    severity_buckets = {
        "Critical(12+)": 0,
        "High(8-11)": 0,
        "Medium(4-7)": 0,
        "Low(1-3)": 0,
    }
    timestamps: list = []

    for alert in alerts:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        rid = rule.get("id")
        if rid:
            rule_ids[rid] += 1

        aname = agent.get("name") or agent.get("id")
        if aname:
            agents[aname] += 1

        lvl = rule.get("level")
        if isinstance(lvl, (int, float)):
            if lvl >= 12:
                severity_buckets["Critical(12+)"] += 1
            elif lvl >= 8:
                severity_buckets["High(8-11)"] += 1
            elif lvl >= 4:
                severity_buckets["Medium(4-7)"] += 1
            else:
                severity_buckets["Low(1-3)"] += 1

        mitre = rule.get("mitre", {})
        for tid in mitre.get("id") or []:
            mitre_techniques[tid] += 1

        ts = alert.get("@timestamp") or alert.get("timestamp")
        if ts:
            timestamps.append(ts)

    return {
        "total_alerts": total,
        "time_range": (
            f"{min(timestamps)} to {max(timestamps)}" if timestamps else "N/A"
        ),
        "top_rule_ids": {
            rid: cnt for rid, cnt in rule_ids.most_common(10)
        },
        "top_agents": {
            name: cnt for name, cnt in agents.most_common(10)
        },
        "severity_breakdown": {
            k: v for k, v in severity_buckets.items() if v > 0
        },
        "top_mitre_techniques": {
            tid: cnt for tid, cnt in mitre_techniques.most_common(10)
        },
    }


def _compact_alert(alert: dict) -> dict:
    """Extract only essential fields from a raw alert document."""
    out: dict = {}
    ts = alert.get("@timestamp") or alert.get("timestamp")
    if ts:
        out["timestamp"] = ts

    rule = alert.get("rule", {})
    if rule.get("id"):
        out["rule.id"] = rule["id"]
    if rule.get("level") is not None:
        out["rule.level"] = rule["level"]
    if rule.get("description"):
        out["rule.description"] = rule["description"]

    agent = alert.get("agent", {})
    if agent.get("name"):
        out["agent.name"] = agent["name"]
    if agent.get("id"):
        out["agent.id"] = agent["id"]

    mitre = rule.get("mitre", {})
    if mitre.get("id"):
        out["rule.mitre.id"] = mitre["id"]
    if mitre.get("tactic"):
        out["rule.mitre.tactic"] = mitre["tactic"]

    data = alert.get("data", {})
    for key in ("srcip", "dstip", "srcuser", "dstuser"):
        if data.get(key):
            out[f"data.{key}"] = data[key]

    return out


def _compact_alerts(alerts: list) -> list:
    """Apply _compact_alert to a list of alert dicts."""
    return [_compact_alert(a) for a in alerts]


# ---------------------------------------------------------------------------
# Alerts (4 tools)
# ---------------------------------------------------------------------------

@mcp.tool
@with_usage_tracking
async def get_wazuh_alerts(
    limit: int = 500,
    rule_id: Optional[str] = None,
    level: Optional[str] = None,
    agent_id: Optional[str] = None,
    time_range: str = "4h",
    compact: bool = False,
    include_imports: bool = False,
) -> str:
    """Retrieve raw Wazuh security alert documents.

    [Context cost: HIGH -- returns up to 500 raw alert documents]

    When to use: You need raw alert details (full_log, source IPs, rule info)
    for a specific, filtered investigation. Always specify filters to keep
    results focused. Use compact=True for initial investigation to save context.
    Use compact=False only when you need full alert details for a small number
    of specific alerts.

    When NOT to use: For initial triage or high-level overview, use
    get_wazuh_alert_summary (LOW cost, aggregated counts) or
    analyze_alert_patterns (MEDIUM cost, recurring patterns) instead.

    Args:
        limit: Maximum alerts to return (default 500, capped at 500).
        rule_id: Filter alerts by Wazuh rule ID.
        level: Filter by severity level (e.g. "10" or "10-15" for a range).
        agent_id: Filter alerts by agent ID.
        time_range: Time window (e.g. "1h", "4h", "24h", "7d"). Default "4h".
        compact: If True, return only key fields per alert (~80% smaller).
        include_imports: Also search wazuh-import-* indices.
    """
    effective_limit = min(limit, MAX_RAW_RESULTS)
    index = "wazuh-alerts-*,wazuh-import-*" if include_imports else "wazuh-alerts-*"
    params: dict = {"limit": effective_limit, "index": index, "time_range": time_range}
    if rule_id is not None:
        params["rule.id"] = rule_id
    if level is not None:
        params["level"] = level
    if agent_id is not None:
        params["agent.id"] = agent_id
    result = await _client().get_alerts(**params)

    alerts = result.get("data", {}).get("affected_items", [])
    total = result.get("data", {}).get("total_affected_items", len(alerts))

    # Task 4: summarization when >50 alerts
    if len(alerts) > _ALERT_SUMMARY_THRESHOLD:
        summary = _build_alert_summary(alerts, total)
        result["data"]["summary"] = summary
        result["data"]["affected_items"] = alerts[:_ALERT_SUMMARY_THRESHOLD]
        result["data"]["showing"] = _ALERT_SUMMARY_THRESHOLD

    # Task 5: compact mode
    if compact:
        result["data"]["affected_items"] = _compact_alerts(
            result["data"]["affected_items"]
        )
        result["data"]["response_mode"] = "compact"

    output = json.dumps(result, indent=2)

    # Truncation notice
    shown = result["data"].get("showing", len(result["data"]["affected_items"]))
    if total > shown:
        output += (
            f"\n\n[Showing {shown} of {total:,} alerts. "
            "Use filters to narrow: agent_id, rule_id, level, or a tighter time_range.]"
        )

    return output


@mcp.tool
@with_usage_tracking
async def get_wazuh_alert_summary(
    time_range: str = "24h",
    group_by: str = "rule.description",
    include_imports: bool = False,
) -> str:
    """Get a summary of Wazuh alerts grouped by a field.

    [Context cost: LOW -- returns aggregated counts, not raw alerts]

    When to use: Use this FIRST for initial triage. Returns grouped counts
    by rule, severity level, and agent. Cheapest way to understand the alert
    landscape before drilling into specifics.

    When NOT to use: If you need raw alert details, use get_wazuh_alerts
    after reviewing this summary.

    Args:
        time_range: Time window to summarise (e.g. "1h", "24h", "7d").
        group_by: Field to group results by (default "rule.description").
        include_imports: Also search wazuh-import-* indices.
    """
    index = "wazuh-alerts-*,wazuh-import-*" if include_imports else "wazuh-alerts-*"
    result = await _client().get_alert_summary(time_range=time_range, group_by=group_by, index=index)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def analyze_alert_patterns(
    time_range: str = "24h",
    min_frequency: int = 5,
    include_imports: bool = False,
) -> str:
    """Analyze recurring alert patterns to surface high-signal security events.

    [Context cost: MEDIUM -- returns pattern analysis, not raw alerts]

    When to use: For identifying recurring patterns and noisy rules before
    drilling into specifics. Good second step after get_wazuh_alert_summary.

    When NOT to use: If you need raw alerts, use get_wazuh_alerts. If you
    just need counts, use get_wazuh_alert_summary.

    Args:
        time_range: Time window to analyze (e.g. "1h", "24h", "7d").
        min_frequency: Minimum occurrences for a pattern to be included.
        include_imports: Also search wazuh-import-* indices.
    """
    index = "wazuh-alerts-*,wazuh-import-*" if include_imports else "wazuh-alerts-*"
    result = await _client().analyze_alert_patterns(
        time_range=time_range,
        min_frequency=min_frequency,
        index=index,
    )
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def search_security_events(
    query: str,
    time_range: str = "24h",
    limit: int = 500,
    compact: bool = False,
    include_imports: bool = False,
) -> str:
    """Full-text search across Wazuh security events.

    [Context cost: HIGH -- returns up to 500 matching event documents]

    When to use: You need to search alerts by keyword or phrase (e.g. "ssh AND
    failed", "mimikatz", a specific IP). Always include a specific search term.
    Use compact=True for initial investigation to save context.

    When NOT to use: For broad overview without a search term, use
    get_wazuh_alert_summary or analyze_alert_patterns instead. Never use
    broad/empty queries -- they return massive payloads.

    Args:
        query: Search query string (supports Lucene syntax, e.g. "ssh AND failed").
        time_range: Time window to search within (e.g. "1h", "24h", "7d").
        limit: Maximum results to return (default 500, capped at 500).
        compact: If True, return only key fields per event (~80% smaller).
        include_imports: Also search wazuh-import-* indices.
    """
    effective_limit = min(limit, MAX_RAW_RESULTS)
    index = "wazuh-alerts-*,wazuh-import-*" if include_imports else "wazuh-alerts-*"
    result = await _client().search_security_events(
        query=query,
        time_range=time_range,
        limit=effective_limit,
        index=index,
    )

    total = result.get("total", 0)
    results_list = result.get("results", [])

    if compact:
        compacted = []
        for r in results_list:
            compacted.append({
                "timestamp": r.get("timestamp"),
                "rule_id": r.get("rule_id"),
                "level": r.get("rule_level"),
                "description": r.get("rule_description"),
                "agent": r.get("agent_name"),
                "agent_id": r.get("agent_id"),
                "src_ip": r.get("src_ip"),
            })
        result["results"] = compacted
        result["response_mode"] = "compact"

    output = json.dumps(result, indent=2)

    if total > len(results_list):
        output += _truncation_notice(len(results_list), total)

    return output


# ---------------------------------------------------------------------------
# Agents (6 tools)
# ---------------------------------------------------------------------------

@mcp.tool
@with_usage_tracking
async def get_wazuh_agents(
    status: Optional[str] = None,
    limit: int = 100,
    agent_id: Optional[str] = None,
) -> str:
    """List Wazuh agents with optional status filter.

    [Context cost: LOW -- returns agent metadata, not alert data]

    When to use: To discover agent IDs/names, check which agents are
    registered, or filter by connection status.

    Args:
        status: Filter by status ("active", "disconnected", "never_connected", "pending").
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
@with_usage_tracking
async def get_wazuh_running_agents() -> str:
    """List all currently active (running) Wazuh agents.

    [Context cost: LOW -- returns only active agent metadata]

    When to use: Quick check of which agents are currently online."""
    result = await _client().get_running_agents()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def check_agent_health(agent_id: str) -> str:
    """Check the health status of a specific Wazuh agent.

    [Context cost: LOW -- returns single agent status]

    When to use: Verify a specific agent is connected and healthy.

    Args:
        agent_id: The Wazuh agent ID to check (e.g. "001").
    """
    result = await _client().check_agent_health(agent_id=agent_id)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_agent_processes(
    agent_id: str,
    limit: int = 100,
) -> str:
    """Get the running processes on a Wazuh agent via syscollector.

    [Context cost: HIGH -- can return up to 100 process entries]

    When to use: During host investigation to identify suspicious processes.

    Args:
        agent_id: The Wazuh agent ID.
        limit: Maximum number of processes to return.
    """
    result = await _client().get_agent_processes(agent_id=agent_id, limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_agent_ports(
    agent_id: str,
    limit: int = 100,
) -> str:
    """Get the open network ports on a Wazuh agent via syscollector.

    [Context cost: MEDIUM -- returns port/protocol list for one agent]

    When to use: During host investigation to check for unexpected open ports.

    Args:
        agent_id: The Wazuh agent ID.
        limit: Maximum number of port entries to return.
    """
    result = await _client().get_agent_ports(agent_id=agent_id, limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_agent_configuration(agent_id: str) -> str:
    """Retrieve the effective configuration of a Wazuh agent.

    [Context cost: MEDIUM -- returns config sections for one agent]

    When to use: To audit an agent's configuration (log collection, syscheck,
    active response). Useful when verifying detection coverage.

    Args:
        agent_id: The Wazuh agent ID.
    """
    result = await _client().get_agent_configuration(agent_id=agent_id)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Vulnerabilities (3 tools — require Wazuh Indexer)
# ---------------------------------------------------------------------------

@mcp.tool
@with_usage_tracking
async def get_wazuh_vulnerabilities(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 500,
) -> str:
    """Retrieve raw vulnerability records from the Wazuh Indexer (Wazuh 4.8.0+).

    [Context cost: HIGH -- returns up to 500 vulnerability documents]

    When to use: You need detailed vulnerability records for a specific agent
    or severity. Always filter by agent_id and/or severity.

    When NOT to use: For an overview of vulnerability counts by severity, use
    get_wazuh_vulnerability_summary first (LOW cost). Only drill into raw
    records after reviewing the summary.

    Requires WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS.

    Args:
        agent_id: Filter vulnerabilities for a specific agent.
        severity: Filter by severity ("critical", "high", "medium", "low").
        limit: Maximum vulnerabilities to return (default 500, capped at 500).
    """
    effective_limit = min(limit, MAX_RAW_RESULTS)
    try:
        result = await _client().get_vulnerabilities(
            agent_id=agent_id,
            severity=severity,
            limit=effective_limit,
        )
        total = result.get("data", {}).get("total_affected_items", 0)
        returned = len(result.get("data", {}).get("affected_items", []))
        output = json.dumps(result, indent=2)
        if total > returned:
            output += _truncation_notice(returned, total)
        return output
    except IndexerNotConfiguredError:
        return json.dumps({
            "error": "Wazuh Indexer not configured. "
                     "Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."
        }, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_critical_vulnerabilities(limit: int = 500) -> str:
    """Retrieve critical-severity vulnerabilities from the Wazuh Indexer.

    [Context cost: HIGH -- returns up to 500 critical vulnerability records]

    When to use: You need the list of critical vulnerabilities after reviewing
    get_wazuh_vulnerability_summary and confirming critical vulns exist.

    When NOT to use: For an overview first, use get_wazuh_vulnerability_summary
    (LOW cost).

    Requires WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS.

    Args:
        limit: Maximum critical vulnerabilities to return (default 500, capped at 500).
    """
    effective_limit = min(limit, MAX_RAW_RESULTS)
    try:
        result = await _client().get_critical_vulnerabilities(limit=effective_limit)
        total = result.get("data", {}).get("total_affected_items", 0)
        returned = len(result.get("data", {}).get("affected_items", []))
        output = json.dumps(result, indent=2)
        if total > returned:
            output += _truncation_notice(returned, total)
        return output
    except IndexerNotConfiguredError:
        return json.dumps({
            "error": "Wazuh Indexer not configured. "
                     "Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."
        }, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_vulnerability_summary(time_range: str = "24h") -> str:
    """Get a summary of vulnerability counts by severity from the Wazuh Indexer.

    [Context cost: LOW -- returns aggregated counts, not raw records]

    When to use: Use this FIRST before get_wazuh_vulnerabilities or
    get_wazuh_critical_vulnerabilities. Returns counts by severity level
    and affected agent count. Cheapest way to assess vulnerability posture.

    When NOT to use: If you need detailed vulnerability records, use
    get_wazuh_vulnerabilities after reviewing this summary.

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
@with_usage_tracking
async def analyze_security_threat(
    indicator: str,
    indicator_type: str = "ip",
) -> str:
    """Analyze a security threat indicator using Wazuh threat intelligence.

    [Context cost: MEDIUM -- searches alerts for a single indicator]

    When to use: When you have a specific IP, domain, hash, or URL to
    investigate. Returns matching alerts and vulnerability context.

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
@with_usage_tracking
async def check_ioc_reputation(
    indicator: str,
    indicator_type: str = "ip",
) -> str:
    """Check the reputation of an Indicator of Compromise (IoC).

    [Context cost: MEDIUM -- searches 30d of alerts for one indicator]

    When to use: When you have a specific IoC and want to know how often
    it appears in alerts and its reputation classification.

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
@with_usage_tracking
async def perform_risk_assessment(agent_id: Optional[str] = None) -> str:
    """Perform a risk assessment for an agent or the entire environment.

    [Context cost: MEDIUM -- aggregates alert and vulnerability data into risk score]

    When to use: To get a risk score and posture summary for an agent or
    the overall environment. Good for executive-level status checks.

    Args:
        agent_id: Agent ID to assess. If omitted, assesses the full environment.
    """
    result = await _client().perform_risk_assessment(agent_id=agent_id)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_top_security_threats(
    limit: int = 10,
    time_range: str = "24h",
) -> str:
    """Get the top security threats detected by Wazuh, ranked by frequency.

    [Context cost: LOW -- returns a ranked list of top threat types]

    When to use: Quick overview of the most common threat categories.
    Good starting point alongside get_wazuh_alert_summary.

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
@with_usage_tracking
async def generate_security_report(
    report_type: str = "executive",
    include_recommendations: bool = True,
) -> str:
    """Generate a security report from Wazuh data.

    [Context cost: MEDIUM -- aggregates multiple data sources into a report]

    When to use: To produce a structured security report for stakeholders.
    Choose "executive" for high-level summary, "technical" for detailed
    findings, "compliance" for framework-aligned output.

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
@with_usage_tracking
async def run_compliance_check(
    framework: str,
    agent_id: Optional[str] = None,
) -> str:
    """Run a compliance check against a security framework.

    [Context cost: MEDIUM -- returns compliance status and relevant events]

    When to use: To assess compliance posture against a specific framework.
    Returns compliance events from the last 30 days.

    Args:
        framework: Framework to check ("pci_dss", "hipaa", "gdpr", "nist", "cis").
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
@with_usage_tracking
async def get_wazuh_statistics() -> str:
    """Get overall Wazuh manager statistics (events processed, queue usage, etc.).

    [Context cost: LOW -- returns manager performance metrics]"""
    result = await _client().get_wazuh_statistics()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_weekly_stats() -> str:
    """Get weekly statistical summary from the Wazuh manager.

    [Context cost: LOW -- returns weekly event counts by day/hour]"""
    result = await _client().get_weekly_stats()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_cluster_health() -> str:
    """Get the health status of the Wazuh cluster.

    [Context cost: LOW -- returns cluster enabled/disabled status and node info]"""
    result = await _client().get_cluster_health()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_cluster_nodes() -> str:
    """List all nodes in the Wazuh cluster with their status.

    [Context cost: LOW -- returns cluster node metadata]"""
    result = await _client().get_cluster_nodes()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_rules_summary() -> str:
    """Get a summary of loaded Wazuh detection rules grouped by category.

    [Context cost: MEDIUM -- returns rule file breakdown and total counts]"""
    result = await _client().get_rules_summary()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_remoted_stats() -> str:
    """Get statistics from the Wazuh remoted daemon (agent communication).

    [Context cost: LOW -- returns daemon performance counters]"""
    result = await _client().get_remoted_stats()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_log_collector_stats() -> str:
    """Get statistics from the Wazuh log collector daemon.

    [Context cost: LOW -- returns log collector performance counters]"""
    result = await _client().get_log_collector_stats()
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def search_wazuh_manager_logs(
    query: str,
    limit: int = 100,
) -> str:
    """Search Wazuh manager internal logs.

    [Context cost: HIGH -- can return up to 100 log entries]

    When to use: To search manager logs for specific errors, warnings,
    or events. Always provide a focused query string.

    Args:
        query: Search string to filter log entries.
        limit: Maximum number of log entries to return.
    """
    result = await _client().search_manager_logs(query=query, limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def get_wazuh_manager_error_logs(limit: int = 50) -> str:
    """Retrieve error-level log entries from the Wazuh manager.

    [Context cost: MEDIUM -- returns up to 50 error log entries]

    When to use: To check for manager-level errors and operational issues.

    Args:
        limit: Maximum number of error log entries to return.
    """
    result = await _client().get_manager_error_logs(limit=limit)
    return json.dumps(result, indent=2)


@mcp.tool
@with_usage_tracking
async def validate_wazuh_connection() -> str:
    """Validate the connection to the Wazuh manager and return version/status info.

    [Context cost: LOW -- returns connection status and version string]"""
    result = await _client().validate_connection()
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Incident Response (1 tool)
# ---------------------------------------------------------------------------

@mcp.tool
@with_usage_tracking
async def build_incident_timeline(
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    query: Optional[str] = None,
    level: Optional[str] = None,
    time_range: str = "24h",
    limit: int = 200,
    include_imports: bool = False,
) -> str:
    """Build a unified incident timeline correlating alerts and manager logs.

    [Context cost: HIGH -- returns up to 500 timeline events]

    Concurrently fetches alerts and manager logs, normalises them into a
    common format, and returns them sorted by timestamp (newest first).
    If one source fails the other's results are still returned.

    When to use: After identifying specific alerts/agents to investigate, build
    a timeline to understand the sequence of events. Always filter by agent_id,
    rule_id, or level.

    When NOT to use: For broad exploration, use get_wazuh_alert_summary or
    analyze_alert_patterns first. This tool is for focused incident investigation.

    Args:
        agent_id: Filter timeline events for a specific agent.
        rule_id: Filter by Wazuh rule ID.
        query: Full-text search query applied to manager logs.
        level: Filter by severity level (applied to both alerts and logs).
        time_range: Time window to cover ("1h", "6h", "24h", "7d").
        limit: Maximum total events in the returned timeline (capped at 500).
        include_imports: Also search wazuh-import-* indices.
    """
    effective_limit = min(limit, MAX_RAW_RESULTS)
    index = "wazuh-alerts-*,wazuh-import-*" if include_imports else "wazuh-alerts-*"
    result = await _client().build_incident_timeline(
        agent_id=agent_id,
        rule_id=rule_id,
        query=query,
        level=level,
        time_range=time_range,
        limit=effective_limit,
        index=index,
    )

    output = json.dumps(result, indent=2)
    total = result.get("data", {}).get("summary", {}).get("total_events", 0)
    timeline_len = len(result.get("data", {}).get("timeline", []))
    if total > timeline_len:
        output += _truncation_notice(timeline_len, total)

    return output


# ---------------------------------------------------------------------------
# Host Investigation & Raw Query (2 tools)
# ---------------------------------------------------------------------------

@mcp.tool
@with_usage_tracking
async def investigate_host(
    agent_name: str,
    time_range: str = "7d",
    compact: bool = False,
) -> str:
    """Deep host investigation across 5 parallel OpenSearch queries.

    [Context cost: VERY HIGH -- runs 5 concurrent queries, returns large composite result]

    Builds a comprehensive picture of activity on a given agent/host covering:
    severity distribution, high-severity events (level 7+), executables seen
    via BAM/syscheck registry, registry changes, login activity (successes and
    failures), top triggered rules, and a 6-hour activity timeline.

    When to use: Only for deep-dive on a specific host AFTER initial triage
    with get_wazuh_alert_summary or analyze_alert_patterns has identified it
    as suspicious. Use compact=True to reduce payload.

    When NOT to use: For broad exploration across all hosts. Use
    get_wazuh_alert_summary first, then investigate only flagged hosts.

    Args:
        agent_name: Agent/host name to investigate (e.g. 'ai-wazuh').
        time_range: How far back to search (e.g. '24h', '7d', '30d').
        compact: If True, return only key fields in high_severity_events.
    """
    c = _client()
    if c._indexer_client is None:
        return json.dumps({"error": "Wazuh Indexer not configured. Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."})
    result = await c._indexer_client.investigate_host(
        agent_name=agent_name,
        time_range=time_range,
    )

    if compact and "high_severity_events" in result:
        compacted = []
        for e in result["high_severity_events"]:
            compacted.append({
                "timestamp": e.get("timestamp"),
                "rule_id": e.get("rule_id"),
                "level": e.get("rule_level"),
                "description": e.get("rule_description"),
                "src_ip": e.get("src_ip"),
            })
        result["high_severity_events"] = compacted
        result["response_mode"] = "compact"

    output = json.dumps(result, indent=2)

    total_events = result.get("total_events", 0)
    if total_events > 1000:
        output += (
            f"\n\n[Note: {total_events:,} total events for this host. "
            "Consider narrowing time_range for a more focused investigation.]"
        )

    return output


@mcp.tool
@with_usage_tracking
async def run_opensearch_query(
    body: str,
    index: str = "wazuh-alerts-*",
    path_suffix: str = "_search",
    max_response_chars: int = 30000,
    compact: bool = False,
) -> str:
    """Execute a raw OpenSearch DSL query against any Wazuh index.

    [Context cost: VERY HIGH -- returns raw OpenSearch responses, capped at 30K chars]

    Use this for custom threat hunting, forensic queries, or any search not
    covered by the other tools. Supports aggregations, filters, and any
    OpenSearch query DSL construct. Always include a "size" limit in your
    DSL query body.

    When to use: As a last resort when other tools cannot express the query
    you need. Prefer aggregation queries (size: 0) over document fetches.
    Use compact=True if fetching documents.

    When NOT to use: If get_wazuh_alerts, search_security_events,
    get_wazuh_alert_summary, or analyze_alert_patterns can answer your
    question, use those instead -- they have built-in guardrails.

    Args:
        body: OpenSearch query DSL as a JSON string.
        index: Index pattern (default: wazuh-alerts-*). Others:
               wazuh-import-*, wazuh-states-vulnerabilities-*, wazuh-monitoring-*.
        path_suffix: API path suffix -- '_search', '_count', '_mapping'.
        max_response_chars: Truncate response at this character limit (default 30000).
        compact: If True, strip hit documents to key fields only.
    """
    c = _client()
    if c._indexer_client is None:
        return json.dumps({"error": "Wazuh Indexer not configured. Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASS."})
    try:
        parsed_body = json.loads(body)
    except Exception:
        return json.dumps({"error": f"Invalid JSON in body: {body[:200]}"})
    result = await c._indexer_client.run_query(
        body=parsed_body,
        index=index,
        path_suffix=path_suffix,
    )

    # Compact mode: strip hit _source to key fields
    if compact and isinstance(result, dict) and "hits" in result:
        hits = result["hits"].get("hits", [])
        result["hits"]["hits"] = [
            {"_source": _compact_alert(h.get("_source", {}))}
            for h in hits
        ]
        result["response_mode"] = "compact"

    output = json.dumps(result, indent=2)

    # Character-level truncation
    if len(output) > max_response_chars:
        hit_count = "unknown"
        if isinstance(result, dict):
            total = result.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                hit_count = total.get("value", "unknown")
            elif isinstance(total, int):
                hit_count = total
        full_len = len(output)
        output = output[:max_response_chars] + (
            f"\n\n[RESPONSE TRUNCATED at {max_response_chars:,} chars] "
            f"Full response was {full_len:,} chars with {hit_count} total hits. "
            "Use more specific filters or reduce max_results to get complete "
            "data within context limits."
        )

    return output


# ---------------------------------------------------------------------------
# Usage meta-tools (not tracked — no @with_usage_tracking)
# ---------------------------------------------------------------------------

@mcp.tool
async def get_usage_summary() -> str:
    """Get token usage summary for this session -- tokens consumed, top tools, budget status.

    [Context cost: LOW -- returns session usage metadata]"""
    return json.dumps(_tracker.get_summary(), indent=2)


@mcp.tool
async def reset_usage_session() -> str:
    """Reset the session token counter. All-time total is preserved.

    [Context cost: LOW -- returns reset confirmation]"""
    return json.dumps(_tracker.reset_session(), indent=2)


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