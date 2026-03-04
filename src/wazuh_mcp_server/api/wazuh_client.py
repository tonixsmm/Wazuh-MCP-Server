"""Wazuh API client optimized for Wazuh 4.8.0 to 4.14.x compatibility.

Fixes applied vs original:
- get_wazuh_statistics      → GET /manager/stats (was /manager/stats/all - fake)
- get_cluster_health        → GET /cluster/status (was /cluster/health - fake)
- get_cluster_nodes         → GET /cluster/nodes/info (was /cluster/nodes - wrong)
- get_rules_summary         → GET /rules aggregation (was /rules/summary - fake)
- get_log_collector_stats   → GET /manager/stats/remoted (was /manager/stats/logcollector - fake)
- analyze_security_threat   → Indexer: search_security_events (was /security/threat/analyze - fake)
- check_ioc_reputation      → Indexer: search alerts + vulns (was /security/ioc/reputation - fake)
- perform_risk_assessment   → Indexer: aggregate alerts+vulns by agent (was /security/risk - fake)
- get_top_security_threats  → Indexer: get_alert_summary (was /security/threats/top - fake)
- generate_security_report  → Indexer: multi-query aggregate (was /security/reports/generate - fake)
- run_compliance_check      → Indexer: compliance-tagged alert search (was /security/compliance/check - fake)
- get_alert_summary         → Indexer: get_alert_summary (was /alerts/summary - fake)
- analyze_alert_patterns    → Indexer: analyze_alert_patterns (was /alerts/patterns - fake)
- search_security_events    → Indexer: search_security_events (was /security/events - fake)
"""

import asyncio
import json
import sys
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
import httpx
import logging

from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    RetryConfig
)
from wazuh_mcp_server.api.wazuh_indexer import (
    WazuhIndexerClient,
    IndexerNotConfiguredError
)

logger = logging.getLogger(__name__)


class WazuhClient:
    """Wazuh API client with rate limiting, circuit breaker, and retry logic."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times = []
        self._max_requests_per_minute = getattr(config, 'max_requests_per_minute', 100)
        self._rate_limit_enabled = True

        circuit_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=Exception
        )
        self._circuit_breaker = CircuitBreaker(circuit_config)

        self._indexer_client: Optional[WazuhIndexerClient] = None
        if config.wazuh_indexer_host:
            self._indexer_client = WazuhIndexerClient(
                host=config.wazuh_indexer_host,
                port=config.wazuh_indexer_port,
                username=config.wazuh_indexer_user,
                password=config.wazuh_indexer_pass,
                verify_ssl=config.verify_ssl,
                timeout=config.request_timeout_seconds
            )
            logger.info(f"WazuhIndexerClient configured for {config.wazuh_indexer_host}:{config.wazuh_indexer_port}")
            print(f"✅ Wazuh Indexer client configured for {config.wazuh_indexer_host}:{config.wazuh_indexer_port}", file=sys.stderr)
        else:
            logger.warning(
                "Wazuh Indexer not configured. Vulnerability and analytics tools will not work. "
                "Set WAZUH_INDEXER_HOST to enable."
            )

    def _require_indexer(self) -> WazuhIndexerClient:
        """Return indexer client or raise a clean error."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return self._indexer_client

    async def initialize(self):
        """Initialize the HTTP client and authenticate."""
        self.client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.request_timeout_seconds
        )
        await self._authenticate()

        if self._indexer_client:
            try:
                await self._indexer_client.initialize()
                logger.info("Wazuh Indexer client initialized successfully")
            except Exception as e:
                logger.warning(f"Wazuh Indexer initialization failed: {e}")

    async def _authenticate(self):
        """Authenticate with Wazuh API."""
        auth_url = f"{self.config.base_url}/security/user/authenticate"
        try:
            response = await self.client.post(
                auth_url,
                auth=(self.config.wazuh_user, self.config.wazuh_pass)
            )
            response.raise_for_status()
            data = response.json()
            if "data" not in data or "token" not in data["data"]:
                raise ValueError("Invalid authentication response from Wazuh API")
            self.token = data["data"]["token"]
            print(f"✅ Authenticated with Wazuh server at {self.config.wazuh_host}", file=sys.stderr)
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh server at {self.config.wazuh_host}:{self.config.wazuh_port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Connection timeout to Wazuh server at {self.config.wazuh_host}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise ValueError("Invalid Wazuh credentials. Check WAZUH_USER and WAZUH_PASS")
            elif e.response.status_code == 403:
                raise ValueError("Wazuh user does not have sufficient permissions")
            else:
                raise ValueError(f"Wazuh API error: {e.response.status_code} - {e.response.text}")

    # -------------------------------------------------------------------------
    # Core request machinery
    # -------------------------------------------------------------------------

    async def _rate_limit_check(self):
        current_time = time.time()
        self._request_times = [t for t in self._request_times if current_time - t < 60]
        if len(self._request_times) >= self._max_requests_per_minute:
            oldest = self._request_times[0]
            sleep_time = 60 - (current_time - oldest)
            if sleep_time > 0:
                print(f"⚠️ Rate limit reached. Waiting {sleep_time:.1f}s...", file=sys.stderr)
                await asyncio.sleep(sleep_time)
                current_time = time.time()
                self._request_times = [t for t in self._request_times if current_time - t < 60]
        self._request_times.append(current_time)

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        async with self._rate_limiter:
            await self._rate_limit_check()
            return await self._request_with_resilience(method, endpoint, **kwargs)

    @RetryConfig.WAZUH_API_RETRY
    async def _request_with_resilience(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _execute_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        if not self.token:
            await self._authenticate()

        url = f"{self.config.base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.token}"}

        try:
            response = await self.client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            data = response.json()
            if "data" not in data:
                raise ValueError(f"Invalid response structure from Wazuh API: {endpoint}")
            return data

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                self.token = None
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await self.client.request(method, url, headers=headers, **kwargs)
                response.raise_for_status()
                return response.json()
            else:
                logger.error(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Request timeout to Wazuh server")

    # -------------------------------------------------------------------------
    # Alerts
    # -------------------------------------------------------------------------

    async def get_alerts(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/alerts", params=params)

    async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
        """Summarise alerts via Indexer aggregation."""
        return await self._require_indexer().get_alert_summary(
            time_range=time_range, group_by=group_by
        )

    async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
        """Identify recurring alert patterns via Indexer."""
        return await self._require_indexer().analyze_alert_patterns(
            time_range=time_range, min_frequency=min_frequency
        )

    async def search_security_events(self, query: str, time_range: str, limit: int) -> Dict[str, Any]:
        """Full-text search across alerts via Indexer."""
        return await self._require_indexer().search_security_events(
            query=query, time_range=time_range, limit=limit
        )

    # -------------------------------------------------------------------------
    # Agents
    # -------------------------------------------------------------------------

    async def get_agents(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/agents", params=params)

    async def get_running_agents(self) -> Dict[str, Any]:
        return await self._request("GET", "/agents", params={"status": "active"})

    async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"/agents", params={"agents_list": agent_id})

    async def get_agent_processes(self, agent_id: str, limit: int) -> Dict[str, Any]:
        return await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": limit})

    async def get_agent_ports(self, agent_id: str, limit: int) -> Dict[str, Any]:
        return await self._request("GET", f"/syscollector/{agent_id}/ports", params={"limit": limit})

    async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"/agents/{agent_id}/config/client/client")

    # -------------------------------------------------------------------------
    # Vulnerabilities (Indexer required — Wazuh 4.8.0+)
    # -------------------------------------------------------------------------

    async def get_vulnerabilities(self, **params) -> Dict[str, Any]:
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return await self._indexer_client.get_vulnerabilities(
            agent_id=params.get("agent_id"),
            severity=params.get("severity"),
            limit=params.get("limit", 100)
        )

    async def get_critical_vulnerabilities(self, limit: int) -> Dict[str, Any]:
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return await self._indexer_client.get_critical_vulnerabilities(limit=limit)

    async def get_vulnerability_summary(self, time_range: str) -> Dict[str, Any]:
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return await self._indexer_client.get_vulnerability_summary()

    async def get_cti_data(self, cve_id: str) -> Dict[str, Any]:
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return await self._indexer_client.get_vulnerabilities(cve_id=cve_id, limit=100)

    # -------------------------------------------------------------------------
    # Security Analysis (all rebuilt on Indexer — fake Manager endpoints removed)
    # -------------------------------------------------------------------------

    async def analyze_security_threat(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Search alerts and vulnerabilities for a given indicator (IP, domain, hash, URL)."""
        indexer = self._require_indexer()
        # Search alerts for any mention of the indicator
        alert_results = await indexer.search_security_events(
            query=indicator, time_range="7d", limit=50
        )
        # Also check vulnerability index if it's a CVE-style hash
        vuln_results = None
        if indicator_type == "hash" or indicator.upper().startswith("CVE-"):
            try:
                vuln_results = await indexer.get_vulnerabilities(cve_id=indicator, limit=10)
            except Exception:
                pass

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "alert_matches": alert_results,
            "vulnerability_matches": vuln_results,
        }

    async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check IoC by searching alerts for any events involving the indicator."""
        indexer = self._require_indexer()
        results = await indexer.search_security_events(
            query=indicator, time_range="30d", limit=100
        )
        total = results.get("total", 0)
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "total_alert_hits": total,
            "reputation": "malicious" if total > 10 else "suspicious" if total > 0 else "clean",
            "evidence": results.get("results", [])[:10],
        }

    async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
        """Assess risk by aggregating alert severity and vulnerability counts per agent."""
        indexer = self._require_indexer()

        group_by = "agent.name"
        alert_summary = await indexer.get_alert_summary(time_range="7d", group_by=group_by)
        vuln_summary = await indexer.get_vulnerability_summary()

        scope = f"agent {agent_id}" if agent_id else "full environment"
        return {
            "scope": scope,
            "assessment_time": datetime.now(timezone.utc).isoformat(),
            "alert_summary_7d": alert_summary,
            "vulnerability_summary": vuln_summary,
        }

    async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
        """Return top threats by alert frequency from the Indexer."""
        indexer = self._require_indexer()
        summary = await indexer.get_alert_summary(
            time_range=time_range, group_by="rule.description"
        )
        # Trim to requested limit
        top = summary.get("top_entries", [])[:limit]
        return {
            "time_range": time_range,
            "limit": limit,
            "top_threats": top,
            "by_level": summary.get("by_level", []),
            "by_agent": summary.get("by_agent", []),
            "total_alerts": summary.get("total_alerts", 0),
        }

    async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
        """Generate a security report by aggregating Indexer data."""
        indexer = self._require_indexer()

        alert_summary, vuln_summary, patterns = await asyncio.gather(
            indexer.get_alert_summary(time_range="7d", group_by="rule.description"),
            indexer.get_vulnerability_summary(),
            indexer.analyze_alert_patterns(time_range="7d", min_frequency=3),
            return_exceptions=True,
        )

        report: Dict[str, Any] = {
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": "7d",
        }

        if not isinstance(alert_summary, Exception):
            report["alert_summary"] = alert_summary
        if not isinstance(vuln_summary, Exception):
            report["vulnerability_summary"] = vuln_summary
        if not isinstance(patterns, Exception):
            report["alert_patterns"] = patterns

        if include_recommendations:
            recs = []
            if not isinstance(alert_summary, Exception):
                total = alert_summary.get("total_alerts", 0)
                if total > 1000:
                    recs.append("High alert volume detected — review top recurring rules and consider tuning.")
            if not isinstance(vuln_summary, Exception):
                critical = vuln_summary.get("data", {}).get("critical", 0)
                if critical > 0:
                    recs.append(f"{critical} critical vulnerabilities detected — prioritize patching.")
            if not recs:
                recs.append("No immediate high-priority actions identified.")
            report["recommendations"] = recs

        return {"data": report}

    async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
        """Check compliance by searching alerts tagged with the framework."""
        indexer = self._require_indexer()

        # Map framework names to Wazuh rule group tags
        framework_tags = {
            "pci_dss": "pci_dss",
            "hipaa": "hipaa",
            "gdpr": "gdpr",
            "nist": "nist",
            "cis": "cis",
        }
        tag = framework_tags.get(framework.lower(), framework.lower())

        query = f"rule.groups:{tag}"
        if agent_id:
            query += f" AND agent.id:{agent_id}"

        results = await indexer.search_security_events(
            query=query, time_range="30d", limit=200
        )
        total = results.get("total", 0)

        return {
            "framework": framework,
            "agent_id": agent_id,
            "period": "30d",
            "total_compliance_events": total,
            "status": "violations_found" if total > 0 else "clean",
            "events": results.get("results", [])[:20],
        }

    # -------------------------------------------------------------------------
    # System Monitoring (corrected Manager API endpoints)
    # -------------------------------------------------------------------------

    async def get_wazuh_statistics(self) -> Dict[str, Any]:
        """GET /manager/stats — hourly event counts for today."""
        return await self._request("GET", "/manager/stats")

    async def get_weekly_stats(self) -> Dict[str, Any]:
        """GET /manager/stats/weekly — event counts broken down by day/hour."""
        return await self._request("GET", "/manager/stats/weekly")

    async def get_cluster_health(self) -> Dict[str, Any]:
        """GET /cluster/status — cluster enabled/disabled and node info."""
        return await self._request("GET", "/cluster/status")

    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """GET /cluster/nodes/info — detailed node status (cluster must be enabled)."""
        try:
            return await self._request("GET", "/cluster/nodes/info")
        except Exception:
            # Fall back to cluster status if nodes/info isn't available (single-node)
            return await self._request("GET", "/cluster/status")

    async def get_rules_summary(self) -> Dict[str, Any]:
        """Aggregate rule counts by file/group from GET /rules."""
        # Fetch just 1 result to get total count, then fetch group breakdown
        overview = await self._request("GET", "/rules", params={"limit": 1})
        total = overview.get("data", {}).get("total_affected_items", 0)

        # Get rules grouped by filename for a meaningful summary
        by_file = await self._request("GET", "/rules/files", params={"limit": 100})

        return {
            "data": {
                "total_rules": total,
                "rule_files": by_file.get("data", {}).get("affected_items", []),
                "total_files": by_file.get("data", {}).get("total_affected_items", 0),
            }
        }

    async def get_remoted_stats(self) -> Dict[str, Any]:
        """GET /manager/stats/remoted — agent communication daemon stats."""
        return await self._request("GET", "/manager/stats/remoted")

    async def get_log_collector_stats(self) -> Dict[str, Any]:
        """
        Logcollector per-agent stats via GET /agents/{id}/stats/logcollector.
        Falls back to general manager stats if no agents are found.
        """
        try:
            agents = await self._request("GET", "/agents", params={"status": "active", "limit": 10})
            items = agents.get("data", {}).get("affected_items", [])
            if not items:
                return await self._request("GET", "/manager/stats")
            # Return logcollector stats for the first active agent
            agent_id = items[0].get("id", "000")
            return await self._request("GET", f"/agents/{agent_id}/stats/logcollector")
        except Exception:
            return await self._request("GET", "/manager/stats")

    async def search_manager_logs(self, query: str, limit: int) -> Dict[str, Any]:
        """
        Search manager logs. Wazuh /manager/logs accepts:
          level=<debug|info|warning|error|critical>
          tag=<wazuh-modulesd|...>
        Plain-text search isn't supported — we map common keywords to level filters.
        """
        level_keywords = {"error", "warning", "info", "debug", "critical"}
        level = query.lower() if query.lower() in level_keywords else None

        params: Dict[str, Any] = {"limit": limit}
        if level:
            params["level"] = level
        else:
            # Use the query as a tag filter — best approximation available
            params["tag"] = query

        return await self._request("GET", "/manager/logs", params=params)

    async def get_manager_error_logs(self, limit: int) -> Dict[str, Any]:
        """GET /manager/logs?level=error."""
        return await self._request("GET", "/manager/logs", params={"level": "error", "limit": limit})

    async def validate_connection(self) -> Dict[str, Any]:
        try:
            result = await self._request("GET", "/")
            return {"status": "connected", "details": result}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # -------------------------------------------------------------------------
    # Incident Timeline
    # -------------------------------------------------------------------------

    async def build_incident_timeline(
        self,
        agent_id: str = None,
        rule_id: str = None,
        query: str = None,
        level: str = None,
        time_range: str = "24h",
        limit: int = 200,
    ) -> Dict[str, Any]:
        """Correlate alerts and manager logs into a unified timeline."""
        now = datetime.now(timezone.utc)
        range_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
        hours = range_map.get(time_range, 24)
        start_time = now - timedelta(hours=hours)
        start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        log_params: Dict[str, Any] = {"limit": limit}
        if query:
            log_params["tag"] = query
        if level and level in {"debug", "info", "warning", "error", "critical"}:
            log_params["level"] = level

        # Alerts come from the Indexer; logs from the Manager API
        alert_task = (
            self._indexer_client.get_alerts(
                limit=limit,
                agent_id=agent_id,
                rule_id=rule_id,
                level=level,
                time_range=time_range,
            )
            if self._indexer_client
            else asyncio.sleep(0)
        )

        alert_result, log_result = await asyncio.gather(
            alert_task,
            self._request("GET", "/manager/logs", params=log_params),
            return_exceptions=True,
        )

        timeline: List[Dict[str, Any]] = []
        alert_count = 0
        log_count = 0
        errors: List[str] = []

        if alert_result is None or isinstance(alert_result, Exception):
            if isinstance(alert_result, Exception):
                errors.append(f"Alerts fetch failed: {alert_result}")
            elif not self._indexer_client:
                errors.append("Alerts fetch skipped: Wazuh Indexer not configured")
        else:
            # Indexer returns {"total": N, "alerts": [...]}
            items = alert_result.get("alerts", [])
            for item in items:
                timeline.append({
                    "timestamp": item.get("@timestamp", ""),
                    "source_type": "alert",
                    "severity": str(item.get("rule", {}).get("level", "")),
                    "description": item.get("rule", {}).get("description", ""),
                    "rule_id": str(item.get("rule", {}).get("id", "")),
                    "rule_groups": item.get("rule", {}).get("groups", []),
                    "agent_id": str(item.get("agent", {}).get("id", "")),
                    "agent_name": item.get("agent", {}).get("name", ""),
                    "tag": "alert",
                })
            alert_count = len(items)

        if isinstance(log_result, Exception):
            errors.append(f"Logs fetch failed: {log_result}")
        else:
            items = log_result.get("data", {}).get("affected_items", [])
            for item in items:
                timeline.append({
                    "timestamp": item.get("timestamp", ""),
                    "source_type": "log",
                    "severity": item.get("level", ""),
                    "description": item.get("description", item.get("message", "")),
                    "rule_id": "",
                    "rule_groups": [],
                    "agent_id": "",
                    "agent_name": "",
                    "tag": item.get("tag", "manager"),
                })
            log_count = len(items)

        timeline.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        timeline = timeline[:limit]

        filters_applied = {}
        if agent_id:
            filters_applied["agent_id"] = agent_id
        if rule_id:
            filters_applied["rule_id"] = rule_id
        if query:
            filters_applied["query"] = query
        if level:
            filters_applied["level"] = level

        summary = {
            "total_events": len(timeline),
            "alert_count": alert_count,
            "log_count": log_count,
            "time_range": time_range,
            "start_time": start_iso,
            "end_time": end_iso,
            "filters_applied": filters_applied,
        }
        if errors:
            summary["errors"] = errors

        return {"data": {"timeline": timeline, "summary": summary}}

    # -------------------------------------------------------------------------
    # Misc / legacy pass-through
    # -------------------------------------------------------------------------

    async def get_manager_info(self) -> Dict[str, Any]:
        return await self._request("GET", "/")

    async def get_rules(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/rules", params=params)

    async def get_rule_info(self, rule_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"/rules", params={"rule_ids": rule_id})

    async def get_decoders(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/decoders", params=params)

    async def get_fim_events(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/syscheck", params=params)

    async def get_syscollector_info(self, agent_id: str, **params) -> Dict[str, Any]:
        return await self._request("GET", f"/syscollector/{agent_id}", params=params)

    async def get_manager_stats(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/manager/stats", params=params)

    async def get_cdb_lists(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/lists", params=params)

    async def execute_active_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data = {k: v for k, v in data.items() if k != 'custom'}
        return await self._request("PUT", "/active-response", json=data)

    async def get_vulnerability_details(self, vuln_id: str, **params) -> Dict[str, Any]:
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return await self._indexer_client.get_vulnerabilities(cve_id=vuln_id, limit=1)

    async def get_manager_version_check(self) -> Dict[str, Any]:
        return await self._request("GET", "/manager/version/check")

    async def get_agent_stats(self, agent_id: str, component: str = "logcollector") -> Dict[str, Any]:
        return await self._request("GET", f"/agents/{agent_id}/stats/{component}")

    async def close(self):
        if self.client:
            await self.client.aclose()
        if self._indexer_client:
            await self._indexer_client.close()