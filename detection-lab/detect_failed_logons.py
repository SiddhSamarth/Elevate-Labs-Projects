#!/usr/bin/env python3
"""Detect repeated Windows failed logons in synthetic or exported JSONL events.

Expected input keys: TimeGenerated (ISO-8601), EventID, Computer, Account, IpAddress.
This is a lab reference implementation, not a production SIEM replacement.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def parse_timestamp(value: str, line_number: int) -> datetime:
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"line {line_number}: invalid TimeGenerated {value!r}") from exc
    if stamp.tzinfo is None:
        raise ValueError(f"line {line_number}: TimeGenerated must include a timezone")
    return stamp.astimezone(timezone.utc)


def bucket_start(stamp: datetime, window_minutes: int) -> datetime:
    seconds = int(stamp.timestamp())
    width = window_minutes * 60
    return datetime.fromtimestamp(seconds - seconds % width, tz=timezone.utc)


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
                if not isinstance(item, dict):
                    raise ValueError(f"line {line_number}: each JSONL row must be an object")
                if "TimeGenerated" not in item or "EventID" not in item:
                    raise ValueError(f"line {line_number}: TimeGenerated and EventID are required")
                item["_timestamp"] = parse_timestamp(item["TimeGenerated"], line_number)
                try:
                    item["EventID"] = int(item["EventID"])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"line {line_number}: EventID must be an integer") from exc
                events.append(item)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    return events


def detect(events: list[dict[str, Any]], threshold: int, window_minutes: int) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, datetime], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["EventID"] != 4625:
            continue
        ip = str(event.get("IpAddress") or "").strip()
        computer = str(event.get("Computer") or "UNKNOWN").strip() or "UNKNOWN"
        if not ip or ip in {"-", "::1", "127.0.0.1"}:
            continue
        stamp: datetime = event["_timestamp"]
        groups[(ip, computer, bucket_start(stamp, window_minutes))].append(event)

    alerts: list[dict[str, Any]] = []
    for (ip, computer, start), group in groups.items():
        if len(group) < threshold:
            continue
        accounts = sorted({str(row.get("Account") or "UNKNOWN") for row in group})
        timestamps = [row["_timestamp"] for row in group]
        alerts.append({
            "Accounts": accounts,
            "Computer": computer,
            "DetectionName": "Repeated Windows authentication failures",
            "DistinctAccounts": len(accounts),
            "FailureCount": len(group),
            "FirstSeen": min(timestamps).isoformat().replace("+00:00", "Z"),
            "IpAddress": ip,
            "LastSeen": max(timestamps).isoformat().replace("+00:00", "Z"),
            "TimeWindow": start.isoformat().replace("+00:00", "Z"),
            "TriageNote": "Potential password guessing, password spray, or misconfigured client; not proof of compromise",
            "WindowEnd": (start + timedelta(minutes=window_minutes)).isoformat().replace("+00:00", "Z"),
        })
    alerts.sort(key=lambda row: (-row["FailureCount"], row["FirstSeen"], row["IpAddress"], row["Computer"]))
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="UTF-8 JSONL input file")
    parser.add_argument("--threshold", type=int, default=5, help="minimum failures per time bucket (default: 5)")
    parser.add_argument("--window-minutes", type=int, default=10, help="fixed UTC bucket size in minutes (default: 10)")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window_minutes < 1:
        parser.error("--window-minutes must be at least 1")
    try:
        events = read_events(args.input)
        alerts = detect(events, threshold=args.threshold, window_minutes=args.window_minutes)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    json.dump(alerts, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
