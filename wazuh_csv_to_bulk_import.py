#!/usr/bin/env python3
"""
Convert a flattened Wazuh CSV export into OpenSearch/Wazuh Indexer bulk NDJSON,
with an optional direct upload step.

Designed for CSVs with columns like:
  _index, _id, _score, _version, _source.rule.id, _source.agent.name, _source.@timestamp, ...

Examples
--------
# 1) Convert only (preserve the original source index names from the CSV)
python wazuh_csv_to_bulk_import.py \
  --input-csv logs_wazuh_head200.csv \
  --output-ndjson wazuh_import.ndjson \
  --index-mode source

# 2) Convert into one custom index and parse the human-readable Wazuh timestamps
python wazuh_csv_to_bulk_import.py \
  --input-csv logs_wazuh_head200.csv \
  --output-ndjson wazuh_import.ndjson \
  --index-mode custom \
  --dest-index wazuh-import-4.x-2025.10.03 \
  --parse-human-timestamps \
  --timezone UTC

# 3) Convert and upload directly
python wazuh_csv_to_bulk_import.py \
  --input-csv logs_wazuh_head200.csv \
  --output-ndjson wazuh_import.ndjson \
  --index-mode custom \
  --dest-index wazuh-import-4.x-2025.10.03 \
  --parse-human-timestamps \
  --timezone UTC \
  --bulk-url https://YOUR_INDEXER:9200/_bulk \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --insecure
"""
from __future__ import annotations

import argparse
import csv
import json
import ssl
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPSHandler
import base64


HUMAN_TS_FORMAT = "%b %d, %Y @ %H:%M:%S.%f"
SKIP_COLS = {"_score", "_version"}
SPECIAL_BLANKS = {"", " ", "  ", "-", "null", "None", "nan", "NaN"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Convert Wazuh CSV exports to bulk NDJSON.")
    p.add_argument("--input-csv", required=True, help="Path to the source CSV export.")
    p.add_argument("--output-ndjson", required=True, help="Path to write NDJSON for _bulk import.")
    p.add_argument(
        "--index-mode",
        choices=("source", "custom"),
        default="custom",
        help="Use the CSV row _index values ('source') or force a single custom destination index ('custom').",
    )
    p.add_argument(
        "--dest-index",
        default="wazuh-import-4.x-manual",
        help="Destination index name when --index-mode=custom.",
    )
    p.add_argument(
        "--preserve-id",
        action="store_true",
        help="Preserve each row's original _id when present.",
    )
    p.add_argument(
        "--parse-human-timestamps",
        action="store_true",
        help="Convert Wazuh Dashboard-style timestamps like 'Oct 3, 2025 @ 19:59:58.144' into ISO-8601.",
    )
    p.add_argument(
        "--timezone",
        default="UTC",
        help=(
            "Timezone label to append when converting human-readable timestamps. "
            "Used as metadata only in the output (_import.timezone_assumed). "
            "The actual ISO value is written as a naive UTC-like string ending in Z."
        ),
    )
    p.add_argument(
        "--bulk-url",
        help="Optional full _bulk endpoint URL, e.g. https://HOST:9200/_bulk",
    )
    p.add_argument("--username", help="Basic auth username for --bulk-url")
    p.add_argument("--password", help="Basic auth password for --bulk-url")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for HTTPS upload.",
    )
    p.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Optional safety limit for testing. 0 means no limit.",
    )
    return p.parse_args()


def set_nested(d: Dict[str, Any], keys: list[str], value: Any) -> None:
    cur = d
    for key in keys[:-1]:
        if key not in cur or not isinstance(cur[key], dict):
            cur[key] = {}
        cur = cur[key]
    cur[keys[-1]] = value


def maybe_parse_json(value: str) -> Any:
    if not value:
        return value
    stripped = value.strip()
    if not stripped:
        return stripped
    if (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    ):
        try:
            return json.loads(stripped)
        except Exception:
            return value
    return value


def maybe_parse_scalar(value: str) -> Any:
    """
    Conservative scalar coercion:
    - booleans
    - ints
    - floats
    - JSON-looking arrays/objects
    Otherwise keep as string.
    """
    parsed_json = maybe_parse_json(value)
    if parsed_json is not value:
        return parsed_json

    s = value.strip()

    if s == "true":
        return True
    if s == "false":
        return False

    # keep hex-ish values, ids with leading zeros, and similar as strings
    if s.lower().startswith("0x"):
        return value
    if len(s) > 1 and s.startswith("0") and s.isdigit():
        return value

    if s.isdigit():
        try:
            return int(s)
        except Exception:
            return value

    # try float, but avoid accidental conversion of version-like values with many dots
    if s.count(".") == 1:
        left, right = s.split(".", 1)
        if left.lstrip("-").isdigit() and right.isdigit():
            try:
                return float(s)
            except Exception:
                return value

    return value


def convert_human_timestamp(value: str) -> Optional[str]:
    """
    Converts 'Oct 3, 2025 @ 19:59:58.144' -> '2025-10-03T19:59:58.144000Z'
    Assumes the provided time is already the desired wall-clock time.
    """
    try:
        dt = datetime.strptime(value.strip(), HUMAN_TS_FORMAT)
        return dt.isoformat(timespec="microseconds") + "Z"
    except Exception:
        return None


def normalize_value(col: str, raw: Any, parse_human_timestamps: bool) -> Any:
    if raw is None:
        return None

    # csv module returns strings; keep defensive support for non-strings
    if not isinstance(raw, str):
        return raw

    if raw in SPECIAL_BLANKS or raw.strip() in SPECIAL_BLANKS:
        return None

    value = raw

    if parse_human_timestamps and col in {"_source.@timestamp", "_source.timestamp"}:
        converted = convert_human_timestamp(value)
        if converted:
            return converted

    return maybe_parse_scalar(value)


def clean_column_name(name: str) -> str:
    return name.lstrip("\ufeff")


def row_to_bulk_lines(
    row: Dict[str, str],
    *,
    index_mode: str,
    dest_index: str,
    preserve_id: bool,
    parse_human_timestamps: bool,
    timezone_label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized_row = {clean_column_name(k): v for k, v in row.items()}
    source_index = (normalized_row.get("_index") or "").strip()
    target_index = source_index if index_mode == "source" and source_index else dest_index

    action: dict[str, Any] = {"index": {"_index": target_index}}
    if preserve_id and normalized_row.get("_id"):
        action["index"]["_id"] = normalized_row["_id"]

    doc: dict[str, Any] = {}

    for col, raw in normalized_row.items():
        if col in SKIP_COLS:
            continue
        if col in {"_index", "_id"}:
            continue

        value = normalize_value(col, raw, parse_human_timestamps)
        if value is None:
            continue

        if col.startswith("_source."):
            path = col[len("_source.") :].split(".")
            set_nested(doc, path, value)
        else:
            # keep non-_source columns except skipped metadata
            doc[col] = value

    # small import trail so you can tell these docs were replayed from CSV
    doc.setdefault("_import", {})
    if isinstance(doc["_import"], dict):
        doc["_import"]["source"] = "csv_replay"
        doc["_import"]["timezone_assumed"] = timezone_label
        if source_index:
            doc["_import"]["original_index"] = source_index

    return action, doc


def upload_bulk(ndjson_path: Path, bulk_url: str, username: Optional[str], password: Optional[str], insecure: bool) -> None:
    data = ndjson_path.read_bytes()

    headers = {
        "Content-Type": "application/x-ndjson",
        "Content-Length": str(len(data)),
    }

    if username is not None and password is not None:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"

    req = Request(bulk_url, data=data, headers=headers, method="POST")

    if bulk_url.lower().startswith("https"):
        if insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
        opener = build_opener(HTTPSHandler(context=context))
    else:
        opener = build_opener()

    try:
        with opener.open(req) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print(f"[upload] HTTP {resp.status}")
            try:
                payload = json.loads(body)
            except Exception:
                print(body[:2000])
                return

            if payload.get("errors") is True:
                print("[upload] Bulk API returned errors=true. Inspect the first few failed items below:")
                failures = []
                for item in payload.get("items", []):
                    op = item.get("index", {})
                    if op.get("error"):
                        failures.append({
                            "_index": op.get("_index"),
                            "_id": op.get("_id"),
                            "status": op.get("status"),
                            "error": op.get("error"),
                        })
                    if len(failures) >= 5:
                        break
                print(json.dumps(failures, indent=2))
            else:
                print("[upload] Bulk import completed without item-level errors.")
                print(json.dumps({
                    "took": payload.get("took"),
                    "errors": payload.get("errors"),
                    "items": len(payload.get("items", [])),
                }, indent=2))
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        print(f"[upload] HTTP error {e.code}: {e.reason}", file=sys.stderr)
        print(detail[:4000], file=sys.stderr)
        raise
    except URLError as e:
        print(f"[upload] Connection error: {e}", file=sys.stderr)
        raise


def main() -> int:
    args = parse_args()

    input_csv = Path(args.input_csv)
    output_ndjson = Path(args.output_ndjson)

    if not input_csv.exists():
        print(f"Input CSV not found: {input_csv}", file=sys.stderr)
        return 2

    rows_written = 0

    with input_csv.open("r", encoding="utf-8", newline="") as f_in, output_ndjson.open("w", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)

        for row in reader:
            if args.max_rows and rows_written >= args.max_rows:
                break

            action, doc = row_to_bulk_lines(
                row,
                index_mode=args.index_mode,
                dest_index=args.dest_index,
                preserve_id=args.preserve_id,
                parse_human_timestamps=args.parse_human_timestamps,
                timezone_label=args.timezone,
            )
            f_out.write(json.dumps(action, separators=(",", ":")) + "\n")
            f_out.write(json.dumps(doc, separators=(",", ":"), ensure_ascii=False) + "\n")
            rows_written += 1

    print(f"[convert] Wrote {rows_written} documents to {output_ndjson}")

    if args.bulk_url:
        upload_bulk(
            output_ndjson,
            args.bulk_url,
            args.username,
            args.password,
            args.insecure,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
