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

    def _time_range_to_ms(self, time_range: str) -> str:
        """Convert a time range string like '24h', '7d' to OpenSearch 'now-Xh' format."""
        return f"now-{time_range}"

    async def get_alerts(
        self,
        limit: int = 100,
        rule_id: Optional[str] = None,
        level: Optional[str] = None,
        agent_id: Optional[str] = None,
        time_range: str = "24h",
    ) -> Dict[str, Any]:
        """
        Retrieve Wazuh alerts from the Indexer.

        Args:
            limit: Max alerts to return.
            rule_id: Filter by rule ID.
            level: Filter by severity level or range (e.g. "10" or "10-15").
            agent_id: Filter by agent ID.
            time_range: Time window (e.g. "1h", "24h", "7d").
        """
        await self._ensure_initialized()

        must = [{"range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}}]

        if rule_id:
            must.append({"term": {"rule.id": rule_id}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if level:
            if "-" in level:
                lo, hi = level.split("-", 1)
                must.append({"range": {"rule.level": {"gte": int(lo), "lte": int(hi)}}})
            else:
                must.append({"term": {"rule.level": int(level)}})

        query = {"bool": {"must": must}}

        body = {
            "query": query,
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "agent.id", "agent.name", "rule.id",
                        "rule.level", "rule.description", "rule.groups",
                        "data", "location", "full_log"],
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(url, json=body,
                                              headers={"Content-Type": "application/json"})
            response.raise_for_status()
            raw = response.json()
            hits = raw.get("hits", {}).get("hits", [])
            return {
                "total": raw.get("hits", {}).get("total", {}).get("value", len(hits)),
                "alerts": [h["_source"] for h in hits],
            }
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Alert query failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

    async def get_alert_summary(
        self,
        time_range: str = "24h",
        group_by: str = "rule.description",
    ) -> Dict[str, Any]:
        """
        Summarise alerts grouped by a field using aggregations.

        Args:
            time_range: Time window (e.g. "1h", "24h", "7d").
            group_by: Field to aggregate on.
        """
        await self._ensure_initialized()

        body = {
            "query": {"range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}},
            "size": 0,
            "aggs": {
                "by_field": {
                    "terms": {"field": group_by, "size": 50, "order": {"_count": "desc"}}
                },
                "by_level": {
                    "terms": {"field": "rule.level", "size": 20}
                },
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 20}
                },
            },
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(url, json=body,
                                              headers={"Content-Type": "application/json"})
            response.raise_for_status()
            raw = response.json()
            aggs = raw.get("aggregations", {})
            total = raw.get("hits", {}).get("total", {}).get("value", 0)

            def buckets(key):
                return [
                    {"key": b["key"], "count": b["doc_count"]}
                    for b in aggs.get(key, {}).get("buckets", [])
                ]

            return {
                "total_alerts": total,
                "time_range": time_range,
                "grouped_by": group_by,
                "top_entries": buckets("by_field"),
                "by_level": buckets("by_level"),
                "by_agent": buckets("by_agent"),
            }
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Alert summary query failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

    async def analyze_alert_patterns(
        self,
        time_range: str = "24h",
        min_frequency: int = 5,
    ) -> Dict[str, Any]:
        """
        Identify recurring alert patterns (high-frequency rule/agent combos).

        Args:
            time_range: Time window to analyze.
            min_frequency: Minimum occurrences to include a pattern.
        """
        await self._ensure_initialized()

        body = {
            "query": {"range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}},
            "size": 0,
            "aggs": {
                "patterns": {
                    "composite": {
                        "size": 100,
                        "sources": [
                            {"rule_id": {"terms": {"field": "rule.id"}}},
                            {"agent": {"terms": {"field": "agent.name"}}},
                        ],
                    },
                    "aggs": {
                        "rule_desc": {"terms": {"field": "rule.description", "size": 1}},
                        "max_level": {"max": {"field": "rule.level"}},
                    },
                }
            },
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(url, json=body,
                                              headers={"Content-Type": "application/json"})
            response.raise_for_status()
            raw = response.json()
            buckets = raw.get("aggregations", {}).get("patterns", {}).get("buckets", [])

            patterns = []
            for b in buckets:
                if b["doc_count"] >= min_frequency:
                    desc_buckets = b.get("rule_desc", {}).get("buckets", [])
                    description = desc_buckets[0]["key"] if desc_buckets else "Unknown"
                    patterns.append({
                        "rule_id": b["key"]["rule_id"],
                        "agent": b["key"]["agent"],
                        "count": b["doc_count"],
                        "description": description,
                        "max_level": b.get("max_level", {}).get("value"),
                    })

            patterns.sort(key=lambda x: x["count"], reverse=True)
            return {
                "time_range": time_range,
                "min_frequency": min_frequency,
                "pattern_count": len(patterns),
                "patterns": patterns,
            }
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Alert pattern query failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

    async def search_security_events(
        self,
        query: str,
        time_range: str = "24h",
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Full-text search across Wazuh alerts in the Indexer.

        Args:
            query: Search string (Lucene syntax supported).
            time_range: Time window to search within.
            limit: Max results to return.
        """
        await self._ensure_initialized()

        body = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query, "default_field": "*"}},
                        {"range": {"@timestamp": {"gte": self._time_range_to_ms(time_range)}}},
                    ]
                }
            },
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "agent.id", "agent.name", "rule.id",
                        "rule.level", "rule.description", "data", "full_log"],
        }

        url = f"{self.base_url}/wazuh-alerts-*/_search"
        try:
            response = await self.client.post(url, json=body,
                                              headers={"Content-Type": "application/json"})
            response.raise_for_status()
            raw = response.json()
            hits = raw.get("hits", {}).get("hits", [])
            return {
                "total": raw.get("hits", {}).get("total", {}).get("value", len(hits)),
                "query": query,
                "time_range": time_range,
                "results": [h["_source"] for h in hits],
            }
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Security event search failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

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