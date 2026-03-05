"""
Wazuh Indexer client for vulnerability queries (Wazuh 4.8.0+).

Since Wazuh 4.8.0, vulnerability data is stored in the Wazuh Indexer
(Elasticsearch/OpenSearch) instead of being available via the Wazuh Manager API.

The vulnerability API endpoint (/vulnerability/*) was deprecated in 4.7.0
and removed in 4.8.0. This client queries the wazuh-states-vulnerabilities-*
index directly.
"""

import logging
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger(__name__)

# Vulnerability index pattern for Wazuh 4.8+
VULNERABILITY_INDEX = "wazuh-states-vulnerabilities-*"


class WazuhIndexerClient:
    """
    Client for querying the Wazuh Indexer (Elasticsearch/OpenSearch).

    Required for vulnerability queries in Wazuh 4.8.0 and later.
    """

    def __init__(
        self,
        host: str,
        port: int = 9200,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None
        self._initialized = False

    def _time_range_to_ms(self, time_range: str) -> str:
        """Convert a time range string like '24h', '7d' to OpenSearch 'now-Xh' format."""
        return f"now-{time_range}"

    @property
    def base_url(self) -> str:
        """Get the base URL for the Wazuh Indexer."""
        return f"https://{self.host}:{self.port}"

    async def initialize(self):
        """Initialize the HTTP client."""
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)

        self.client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            auth=auth
        )
        self._initialized = True
        logger.info(f"WazuhIndexerClient initialized for {self.host}:{self.port}")

    async def close(self):
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()
            self._initialized = False

    async def _ensure_initialized(self):
        """Ensure client is initialized."""
        if not self._initialized:
            await self.initialize()

    async def _search(self, index: str, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """
        Execute a search query against the Wazuh Indexer.

        Args:
            index: Index pattern to search
            query: Elasticsearch query DSL
            size: Maximum number of results

        Returns:
            Search results from the indexer
        """
        await self._ensure_initialized()

        url = f"{self.base_url}/{index}/_search"
        body = {
            "query": query,
            "size": size
        }

        try:
            response = await self.client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"Indexer search failed: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Indexer query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Timeout connecting to Wazuh Indexer at {self.host}:{self.port}")

    async def get_vulnerabilities(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Get vulnerabilities from the Wazuh Indexer.

        Args:
            agent_id: Filter by agent ID
            severity: Filter by severity (Critical, High, Medium, Low)
            cve_id: Filter by specific CVE ID
            limit: Maximum number of results

        Returns:
            Vulnerability data matching the criteria
        """
        # Build query
        must_clauses = []

        if agent_id:
            must_clauses.append({"match": {"agent.id": agent_id}})

        if severity:
            # Normalize severity to match indexer format
            severity_normalized = severity.capitalize()
            must_clauses.append({"match": {"vulnerability.severity": severity_normalized}})

        if cve_id:
            must_clauses.append({"match": {"vulnerability.id": cve_id}})

        # Build the query
        if must_clauses:
            query = {"bool": {"must": must_clauses}}
        else:
            query = {"match_all": {}}

        result = await self._search(VULNERABILITY_INDEX, query, size=limit)

        # Transform to standard format
        hits = result.get("hits", {})
        vulnerabilities = []

        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            vulnerabilities.append({
                "id": source.get("vulnerability", {}).get("id"),
                "severity": source.get("vulnerability", {}).get("severity"),
                "description": source.get("vulnerability", {}).get("description"),
                "reference": source.get("vulnerability", {}).get("reference"),
                "status": source.get("vulnerability", {}).get("status"),
                "detected_at": source.get("vulnerability", {}).get("detected_at"),
                "published_at": source.get("vulnerability", {}).get("published_at"),
                "agent": {
                    "id": source.get("agent", {}).get("id"),
                    "name": source.get("agent", {}).get("name"),
                },
                "package": {
                    "name": source.get("package", {}).get("name"),
                    "version": source.get("package", {}).get("version"),
                    "architecture": source.get("package", {}).get("architecture"),
                }
            })

        return {
            "data": {
                "affected_items": vulnerabilities,
                "total_affected_items": hits.get("total", {}).get("value", len(vulnerabilities)),
                "total_failed_items": 0,
                "failed_items": []
            }
        }

    async def get_critical_vulnerabilities(self, limit: int = 50) -> Dict[str, Any]:
        """
        Get critical severity vulnerabilities.

        Args:
            limit: Maximum number of results

        Returns:
            Critical vulnerability data
        """
        return await self.get_vulnerabilities(severity="Critical", limit=limit)

    async def get_vulnerability_summary(self) -> Dict[str, Any]:
        """
        Get vulnerability summary statistics.

        Returns:
            Summary with counts by severity
        """
        await self._ensure_initialized()

        # Aggregation query for severity counts
        url = f"{self.base_url}/{VULNERABILITY_INDEX}/_search"
        body = {
            "size": 0,
            "aggs": {
                "by_severity": {
                    "terms": {
                        "field": "vulnerability.severity",
                        "size": 10
                    }
                },
                "by_agent": {
                    "cardinality": {
                        "field": "agent.id"
                    }
                },
                "total_vulnerabilities": {
                    "value_count": {
                        "field": "vulnerability.id"
                    }
                }
            }
        }

        try:
            response = await self.client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            result = response.json()

            # Parse aggregations
            aggs = result.get("aggregations", {})
            severity_buckets = aggs.get("by_severity", {}).get("buckets", [])

            severity_counts = {}
            for bucket in severity_buckets:
                severity_counts[bucket.get("key", "unknown")] = bucket.get("doc_count", 0)

            return {
                "data": {
                    "total_vulnerabilities": aggs.get("total_vulnerabilities", {}).get("value", 0),
                    "affected_agents": aggs.get("by_agent", {}).get("value", 0),
                    "by_severity": severity_counts,
                    "critical": severity_counts.get("Critical", 0),
                    "high": severity_counts.get("High", 0),
                    "medium": severity_counts.get("Medium", 0),
                    "low": severity_counts.get("Low", 0)
                }
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"Vulnerability summary query failed: {e.response.status_code}")
            raise ValueError(f"Vulnerability summary query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

    async def get_alerts(
        self,
        limit: int = 100,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        level: Optional[str] = None,
        time_range: str = "24h",
    ) -> Dict[str, Any]:
        """
        Retrieve alerts from the Wazuh Indexer with optional filters.

        Args:
            limit: Maximum number of alerts to return.
            agent_id: Filter by agent ID.
            rule_id: Filter by rule ID.
            level: Filter by severity level or range (e.g. "10" or "7-15").
            time_range: Time window (e.g. "1h", "24h", "7d").

        Returns:
            Dict with total count and list of alert dicts.
        """
        await self._ensure_initialized()

        filter_clauses = [
            {"range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}}
        ]

        if agent_id:
            filter_clauses.append({"match": {"agent.id": agent_id}})
        if rule_id:
            filter_clauses.append({"match": {"rule.id": rule_id}})
        if level:
            if "-" in level:
                lo, hi = level.split("-", 1)
                filter_clauses.append(
                    {"range": {"rule.level": {"gte": int(lo), "lte": int(hi)}}}
                )
            else:
                filter_clauses.append({"term": {"rule.level": int(level)}})

        body = {
            "query": {"bool": {"filter": filter_clauses}},
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(
                url, json=body, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Alerts query failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

        hits = result.get("hits", {})
        alerts = [h["_source"] for h in hits.get("hits", [])]
        total = hits.get("total", {})
        total = total.get("value", 0) if isinstance(total, dict) else total

        return {"total": total, "alerts": alerts}

    async def get_alert_summary(
        self,
        time_range: str = "24h",
        group_by: str = "rule.description",
    ) -> Dict[str, Any]:
        """
        Summarise alerts via OpenSearch aggregations.

        Args:
            time_range: Time window (e.g. "1h", "24h", "7d").
            group_by: Field to group results by (default "rule.description").

        Returns:
            Dict with top_entries list, by_level list, by_agent list, and total_alerts.
        """
        await self._ensure_initialized()

        body = {
            "size": 0,
            "query": {
                "range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}
            },
            "aggs": {
                "top_entries": {
                    "terms": {"field": group_by, "size": 20}
                },
                "by_level": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low (0-6)",      "from": 0,  "to": 7},
                            {"key": "medium (7-10)",  "from": 7,  "to": 11},
                            {"key": "high (11-14)",   "from": 11, "to": 15},
                            {"key": "critical (15+)", "from": 15},
                        ],
                    }
                },
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 20}
                },
            },
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(
                url, json=body, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Alert summary query failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

        total = result.get("hits", {}).get("total", {})
        total = total.get("value", 0) if isinstance(total, dict) else total
        aggs = result.get("aggregations", {})

        return {
            "time_range": time_range,
            "group_by": group_by,
            "total_alerts": total,
            "top_entries": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_entries", {}).get("buckets", [])
            ],
            "by_level": [
                {"level": b["key"], "count": b["doc_count"]}
                for b in aggs.get("by_level", {}).get("buckets", [])
            ],
            "by_agent": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in aggs.get("by_agent", {}).get("buckets", [])
            ],
        }

    async def analyze_alert_patterns(
        self,
        time_range: str = "24h",
        min_frequency: int = 5,
    ) -> Dict[str, Any]:
        """
        Surface recurring alert patterns above a minimum frequency threshold.

        Args:
            time_range: Time window (e.g. "1h", "24h", "7d").
            min_frequency: Minimum hit count for a pattern to be included.

        Returns:
            Dict with patterns list (rule, count, level, sample_agents) and metadata.
        """
        await self._ensure_initialized()

        body = {
            "size": 0,
            "query": {
                "range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}
            },
            "aggs": {
                "by_rule": {
                    "terms": {"field": "rule.description", "size": 100, "min_doc_count": min_frequency},
                    "aggs": {
                        "rule_id":    {"terms": {"field": "rule.id",    "size": 1}},
                        "rule_level": {"terms": {"field": "rule.level", "size": 1}},
                        "agents":     {"terms": {"field": "agent.name", "size": 5}},
                    },
                }
            },
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(
                url, json=body, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Alert pattern query failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

        aggs = result.get("aggregations", {})
        patterns = []
        for b in aggs.get("by_rule", {}).get("buckets", []):
            rule_id_buckets = b.get("rule_id", {}).get("buckets", [])
            level_buckets   = b.get("rule_level", {}).get("buckets", [])
            agent_buckets   = b.get("agents", {}).get("buckets", [])
            patterns.append({
                "rule":          b["key"],
                "count":         b["doc_count"],
                "rule_id":       rule_id_buckets[0]["key"] if rule_id_buckets else None,
                "rule_level":    level_buckets[0]["key"]   if level_buckets   else None,
                "sample_agents": [a["key"] for a in agent_buckets],
            })

        # Sort by count descending so highest-signal patterns come first
        patterns.sort(key=lambda x: x["count"], reverse=True)

        return {
            "time_range":     time_range,
            "min_frequency":  min_frequency,
            "pattern_count":  len(patterns),
            "patterns":       patterns,
        }

    async def search_security_events(
        self,
        query: str,
        time_range: str = "24h",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Full-text search across Wazuh alerts using a query string.

        Args:
            query: Query string (supports Lucene syntax, e.g. "ssh AND failed").
            time_range: Time window (e.g. "1h", "24h", "7d").
            limit: Maximum number of results to return.

        Returns:
            Dict with total count and results list.
        """
        await self._ensure_initialized()

        body = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query, "default_field": "*"}}],
                    "filter": [
                        {"range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}}
                    ],
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "rule.id", "rule.description", "rule.level",
                "rule.groups", "agent.id", "agent.name", "data.srcip",
                "full_log",
            ],
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(
                url, json=body, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Security event search failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

        hits = result.get("hits", {})
        total = hits.get("total", {})
        total = total.get("value", 0) if isinstance(total, dict) else total

        results = []
        for h in hits.get("hits", []):
            src = h["_source"]
            results.append({
                "timestamp":        src.get("@timestamp"),
                "rule_id":          src.get("rule", {}).get("id"),
                "rule_description": src.get("rule", {}).get("description"),
                "rule_level":       src.get("rule", {}).get("level"),
                "rule_groups":      src.get("rule", {}).get("groups", []),
                "agent_id":         src.get("agent", {}).get("id"),
                "agent_name":       src.get("agent", {}).get("name"),
                "src_ip":           src.get("data", {}).get("srcip"),
                "full_log":         (src.get("full_log") or "")[:500],
            })

        return {"total": total, "results": results}

    async def investigate_host(
        self,
        agent_name: str,
        time_range: str = "7d",
    ) -> Dict[str, Any]:
        """
        Deep host investigation: runs 5 parallel OpenSearch queries to build
        a comprehensive picture of activity on a given agent/host.

        Covers: severity distribution, high-severity events, executables (BAM
        registry via syscheck), registry changes, login activity, top rules,
        and a 6-hour activity timeline.

        Args:
            agent_name: Agent/host name to investigate (e.g. 'ai-wazuh').
            time_range: How far back to search (e.g. '24h', '7d', '30d').
        """
        import asyncio
        await self._ensure_initialized()

        gte = self._time_range_to_ms(time_range)
        base_filter = [
            {"match_phrase": {"agent.name": agent_name}},
            {"range": {"@timestamp": {"gte": gte}}},
        ]

        async def _search(body: Dict[str, Any]) -> Dict[str, Any]:
            url = f"{self.base_url}/wazuh-alerts-*/_search"
            try:
                response = await self.client.post(
                    url, json=body, headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"investigate_host query failed: {e.response.status_code}")
                return {}
            except Exception as e:
                logger.error(f"investigate_host query error: {e}")
                return {}

        # Fire all 5 queries concurrently
        overview_q = {
            "query": {"bool": {"filter": base_filter}},
            "size": 0,
            "aggs": {
                "agent_id": {"terms": {"field": "agent.id", "size": 1}},
                "agent_ip": {"terms": {"field": "agent.ip", "size": 1}},
                "severity": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low (0-6)", "from": 0, "to": 7},
                            {"key": "medium (7-10)", "from": 7, "to": 11},
                            {"key": "high (11-14)", "from": 11, "to": 15},
                            {"key": "critical (15+)", "from": 15},
                        ],
                    }
                },
                "top_rules": {"terms": {"field": "rule.description", "size": 15}},
                "rule_groups": {"terms": {"field": "rule.groups", "size": 20}},
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "6h",
                    }
                },
            },
        }

        executables_q = {
            "query": {
                "bool": {
                    "filter": base_filter + [
                        {"wildcard": {"syscheck.value_name": "*\\*.exe"}}
                    ]
                }
            },
            "size": 50,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "_source": [
                "@timestamp", "syscheck.value_name", "syscheck.event",
                "syscheck.sha256_after", "rule.id", "rule.description",
            ],
        }

        registry_q = {
            "query": {
                "bool": {
                    "filter": base_filter + [
                        {"terms": {"rule.id": ["750", "751", "752", "753"]}}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "by_event": {"terms": {"field": "syscheck.event", "size": 10}},
                "by_path": {"terms": {"field": "syscheck.path", "size": 10}},
            },
        }

        high_sev_q = {
            "query": {
                "bool": {
                    "filter": base_filter + [
                        {"range": {"rule.level": {"gte": 7}}}
                    ]
                }
            },
            "size": 20,
            "sort": [
                {"rule.level": {"order": "desc"}},
                {"@timestamp": {"order": "desc"}},
            ],
            "_source": [
                "@timestamp", "rule.id", "rule.description", "rule.level",
                "rule.groups", "rule.mitre", "data.srcip", "data.dstip",
                "syscheck.path", "syscheck.value_name", "full_log",
            ],
        }

        login_q = {
            "query": {
                "bool": {
                    "filter": base_filter + [
                        {"terms": {"rule.groups": [
                            "authentication_success", "authentication_failed"
                        ]}}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "by_user": {"terms": {"field": "data.dstuser", "size": 10}},
                "by_src_ip": {"terms": {"field": "data.srcip", "size": 10}},
                "by_logon_type": {"terms": {"field": "data.logonType", "size": 10}},
            },
        }

        overview, executables, registry, high_sev, logins = await asyncio.gather(
            _search(overview_q),
            _search(executables_q),
            _search(registry_q),
            _search(high_sev_q),
            _search(login_q),
        )

        # --- Build structured result ---
        total = (overview.get("hits", {}).get("total") or {})
        total = total.get("value", 0) if isinstance(total, dict) else total

        aggs = overview.get("aggregations", {})

        def buckets(agg_key: str) -> list:
            return aggs.get(agg_key, {}).get("buckets", [])

        result: Dict[str, Any] = {
            "host": agent_name,
            "time_range": time_range,
            "total_events": total,
            "agent_id": (buckets("agent_id") or [{}])[0].get("key"),
            "agent_ip": (buckets("agent_ip") or [{}])[0].get("key"),
        }

        # Severity distribution
        result["severity_distribution"] = {
            b["key"]: b["doc_count"] for b in buckets("severity")
        }

        # High severity events
        high_hits = high_sev.get("hits", {}).get("hits", [])
        result["high_severity_events"] = [
            {
                "timestamp": h["_source"].get("@timestamp"),
                "rule_id": h["_source"].get("rule", {}).get("id"),
                "rule_level": h["_source"].get("rule", {}).get("level"),
                "rule_description": h["_source"].get("rule", {}).get("description"),
                "rule_groups": h["_source"].get("rule", {}).get("groups"),
                "full_log": (h["_source"].get("full_log") or "")[:300],
                "src_ip": h["_source"].get("data", {}).get("srcip"),
            }
            for h in high_hits
        ]

        # Executables from syscheck BAM registry
        exe_hits = executables.get("hits", {}).get("hits", [])
        seen_exe: set = set()
        exe_list = []
        for h in exe_hits:
            sc = h["_source"].get("syscheck", {})
            val = sc.get("value_name", "")
            exe_name = val.split("\\")[-1] if "\\" in val else val
            key = f"{exe_name}|{sc.get('event', '')}"
            if key not in seen_exe:
                seen_exe.add(key)
                exe_list.append({
                    "timestamp": h["_source"].get("@timestamp"),
                    "exe_name": exe_name,
                    "full_path": val,
                    "event": sc.get("event"),
                    "sha256": sc.get("sha256_after"),
                })
        result["executables"] = exe_list

        # Registry changes
        reg_aggs = registry.get("aggregations", {})
        result["registry_changes"] = {
            "by_event": {b["key"]: b["doc_count"] for b in reg_aggs.get("by_event", {}).get("buckets", [])},
            "by_path": {b["key"]: b["doc_count"] for b in reg_aggs.get("by_path", {}).get("buckets", [])},
        }

        # Login activity
        login_aggs = logins.get("aggregations", {})
        result["login_activity"] = {
            "by_user": {b["key"]: b["doc_count"] for b in login_aggs.get("by_user", {}).get("buckets", [])},
            "by_src_ip": {b["key"]: b["doc_count"] for b in login_aggs.get("by_src_ip", {}).get("buckets", [])},
        }

        # Top rules
        result["top_rules"] = [
            {"rule": b["key"], "count": b["doc_count"]} for b in buckets("top_rules")
        ]

        # Activity timeline (non-zero buckets only)
        result["activity_timeline"] = [
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in buckets("timeline")
            if b["doc_count"] > 0
        ]

        return result

    async def run_query(
        self,
        body: Dict[str, Any],
        index: str = "wazuh-alerts-*",
        path_suffix: str = "_search",
    ) -> Dict[str, Any]:
        """
        Execute a raw OpenSearch DSL query against any index.

        Args:
            body: OpenSearch query DSL as a dict.
            index: Index pattern to query (default: wazuh-alerts-*).
            path_suffix: API path suffix, e.g. '_search', '_count', '_mapping'.
        """
        await self._ensure_initialized()

        url = f"{self.base_url}/{index}/{path_suffix}"
        try:
            if body:
                response = await self.client.post(
                    url, json=body, headers={"Content-Type": "application/json"}
                )
            else:
                response = await self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"OpenSearch query failed: {e.response.status_code} - {e.response.text}"
            )
        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}"
            )

    async def health_check(self) -> Dict[str, Any]:
        """
        Check Wazuh Indexer health status.

        Returns:
            Health status information
        """
        await self._ensure_initialized()

        try:
            response = await self.client.get(f"{self.base_url}/_cluster/health")
            response.raise_for_status()
            health = response.json()

            return {
                "status": health.get("status"),
                "cluster_name": health.get("cluster_name"),
                "number_of_nodes": health.get("number_of_nodes"),
                "active_shards": health.get("active_shards")
            }

        except Exception as e:
            return {
                "status": "unavailable",
                "error": str(e)
            }


class IndexerNotConfiguredError(Exception):
    """Raised when Wazuh Indexer is not configured but required."""

    def __init__(self, message: str = None):
        default_message = (
            "Wazuh Indexer not configured. "
            "Vulnerability tools require the Wazuh Indexer for Wazuh 4.8.0+.\n\n"
            "Please set the following environment variables:\n"
            "  WAZUH_INDEXER_HOST=<indexer_hostname>\n"
            "  WAZUH_INDEXER_USER=<indexer_username>\n"
            "  WAZUH_INDEXER_PASS=<indexer_password>\n"
            "  WAZUH_INDEXER_PORT=9200 (optional, default: 9200)\n\n"
            "Note: The /vulnerability API was removed in Wazuh 4.8.0. "
            "Vulnerability data must be queried from the Wazuh Indexer."
        )
        super().__init__(message or default_message)