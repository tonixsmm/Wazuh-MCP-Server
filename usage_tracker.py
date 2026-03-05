"""
Usage tracker for Wazuh MCP Server.

Tracks token consumption per tool call and per session, persisted to a local
JSON file. Designed for soft-awareness nudging — shows students how much they
are consuming and warns when approaching a configurable budget.

Configuration (env vars):
    USAGE_LOG_PATH       Path to usage log file (default: ~/.wazuh_mcp_usage.json)
    USAGE_SOFT_LIMIT     Token budget before warnings fire (default: 50000)
    USAGE_WARN_THRESHOLD Fraction of budget that triggers a warning (default: 0.90)
    STUDENT_ID           Optional label shown in usage summaries (default: "user")
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Token estimation (no external deps)
# ~4 chars per token is a reasonable approximation for English/code text
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Estimate token count from character length (~4 chars per token)."""  
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# UsageTracker
# ---------------------------------------------------------------------------

class UsageTracker:
    """
    Tracks MCP tool token usage per session, persisted to a JSON log file.
    """

    def __init__(self) -> None:
        self.student_id: str = os.getenv("STUDENT_ID", "user")
        self.soft_limit: int = int(os.getenv("USAGE_SOFT_LIMIT", "50000"))
        self.warn_threshold: float = float(os.getenv("USAGE_WARN_THRESHOLD", "0.90"))

        default_path = Path.home() / ".wazuh_mcp_usage.json"
        self.log_path = Path(os.getenv("USAGE_LOG_PATH", str(default_path)))

        self._session_start: str = datetime.now(timezone.utc).isoformat()
        self._session_tokens: int = 0
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.log_path.exists():
            try:
                with open(self.log_path) as f:
                    data = json.load(f)
                data["session_start"] = self._session_start
                data["session_tokens"] = 0
                return data
            except (json.JSONDecodeError, KeyError):
                pass
        return {
            "student_id": self.student_id,
            "session_start": self._session_start,
            "last_updated": self._session_start,
            "session_tokens": 0,
            "total_tokens": 0,
            "soft_limit": self.soft_limit,
            "warn_threshold": self.warn_threshold,
            "calls": [],
        }

    def _save(self) -> None:
        self._data["last_updated"] = datetime.now(timezone.utc).isoformat()
        self._data["session_tokens"] = self._session_tokens
        self._data["soft_limit"] = self.soft_limit
        self._data["warn_threshold"] = self.warn_threshold
        try:
            with open(self.log_path, "w") as f:
                json.dump(self._data, f, indent=2)
        except OSError as e:
            import sys
            print(f"WARNING: Could not save usage log: {e}", file=sys.stderr)

    def record(self, tool_name: str, input_text: str, output_text: str) -> Dict[str, Any]:
        input_tokens = _estimate_tokens(input_text)
        output_tokens = _estimate_tokens(output_text)
        call_tokens = input_tokens + output_tokens

        self._session_tokens += call_tokens
        self._data["total_tokens"] = self._data.get("total_tokens", 0) + call_tokens

        self._data.setdefault("calls", []).append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "call_tokens": call_tokens,
            "session_running_total": self._session_tokens,
        })
        self._save()

        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "call_tokens": call_tokens,
            "session_tokens": self._session_tokens,
            "total_tokens": self._data["total_tokens"],
            "warning": self._check_warning(),
        }

    def _check_warning(self) -> Optional[str]:
        warn_at = int(self.soft_limit * self.warn_threshold)
        pct = (self._session_tokens / self.soft_limit) * 100
        if self._session_tokens >= self.soft_limit:
            return (
                f"⛔ You've used {self._session_tokens:,} tokens this session "
                f"({pct:.0f}% of your {self.soft_limit:,} token budget). "
                f"Consider wrapping up or being more concise with your queries."
            )
        elif self._session_tokens >= warn_at:
            remaining = self.soft_limit - self._session_tokens
            return (
                f"⚠️  You've used {self._session_tokens:,} tokens this session "
                f"({pct:.0f}% of your {self.soft_limit:,} token budget). "
                f"{remaining:,} tokens remaining — be intentional with your queries."
            )
        return None

    def get_summary(self) -> Dict[str, Any]:
        calls = self._data.get("calls", [])
        total = self._data.get("total_tokens", 0)
        session = self._session_tokens
        limit = self.soft_limit
        pct = (session / limit) * 100 if limit else 0

        session_start = self._data.get("session_start", "")
        tool_breakdown: Dict[str, Dict[str, int]] = {}
        for c in calls:
            if c.get("ts", "") >= session_start:
                t = c["tool"]
                tool_breakdown.setdefault(t, {"calls": 0, "tokens": 0})
                tool_breakdown[t]["calls"] += 1
                tool_breakdown[t]["tokens"] += c.get("call_tokens", 0)

        top_tools = sorted(
            [{"tool": k, **v} for k, v in tool_breakdown.items()],
            key=lambda x: x["tokens"], reverse=True,
        )

        return {
            "student_id": self.student_id,
            "session_start": session_start,
            "session_tokens": session,
            "session_pct_of_budget": round(pct, 1),
            "soft_limit": limit,
            "warn_threshold_pct": int(self.warn_threshold * 100),
            "total_tokens_all_time": total,
            "total_calls_this_session": len([c for c in calls if c.get("ts", "") >= session_start]),
            "top_tools_this_session": top_tools,
            "status": (
                "over_budget" if session >= limit
                else "warning" if session >= int(limit * self.warn_threshold)
                else "ok"
            ),
        }

    def reset_session(self) -> Dict[str, Any]:
        self._session_tokens = 0
        self._session_start = datetime.now(timezone.utc).isoformat()
        self._data["session_start"] = self._session_start
        self._data["session_tokens"] = 0
        self._save()
        return {"reset": True, "message": "Session usage reset. All-time total preserved."}