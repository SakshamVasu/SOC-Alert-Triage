"""
In-memory alert store: ingestion, severity sorting, filtering and aggregates.

Alerts live only for the lifetime of the Flask process - this is a triage
workbench for uploaded exports, not a SIEM. Restarting the server clears it.
"""

from __future__ import annotations

import threading
from collections import Counter
from datetime import datetime

from .mitre import MitreMapper
from .normalize import SEVERITY_ORDER, SEVERITY_RANK


def _time_key(ts: str | None) -> str:
    """Sortable form of a normalized timestamp. isoformat() omits the fraction
    when microseconds are 0 ("...:33Z" vs "...:33.500000Z"), and "." < "Z" would
    order those wrongly, so pad to a fixed width."""
    if not ts:
        return ""
    return ts if "." in ts else ts[:-1] + ".000000Z"


def sort_alerts(alerts: list[dict]) -> list[dict]:
    """Most severe first; within a severity, newest first; missing timestamps last.

    Two stable sorts: first by timestamp (newest first), then by severity.
    Normalized timestamps are ISO-8601 UTC strings, so once padded to a fixed
    width they sort chronologically.
    """
    by_time = sorted(alerts, key=lambda a: _time_key(a.get("timestamp")), reverse=True)
    return sorted(by_time, key=lambda a: -SEVERITY_RANK.get(a["severity"], 0))


def _csv_param(value) -> set[str]:
    """'high,critical' -> {'high', 'critical'}; also accepts a list."""
    if not value:
        return set()
    items = value if isinstance(value, (list, tuple, set)) else str(value).split(",")
    return {v.strip().lower() for v in items if v and v.strip()}


def filter_alerts(alerts, severity=None, host=None, tactic=None, technique=None, q=None):
    severities, hosts = _csv_param(severity), _csv_param(host)
    tactics, techniques = _csv_param(tactic), _csv_param(technique)
    q = (q or "").strip().lower()

    out = []
    for a in alerts:
        if severities and a["severity"] not in severities:
            continue
        if hosts and a["host"].lower() not in hosts:
            continue
        if tactics and not tactics & {m["tactic"].lower() for m in a["mitre"]}:
            continue
        if techniques and not techniques & {m["technique_id"].lower() for m in a["mitre"]}:
            continue
        if q and q not in f"{a['rule_name']} {a['description']} {a['source_ip']} {a['host']}".lower():
            continue
        out.append(a)
    return out


def time_buckets(alerts: list[dict]) -> dict:
    """Count alerts per hour (span <= 2 days) or per day, split by severity."""
    stamps = [datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00")) for a in alerts if a["timestamp"]]
    if not stamps:
        return {"interval": "day", "series": []}
    hourly = (max(stamps) - min(stamps)).total_seconds() <= 2 * 86400
    fmt = "%Y-%m-%dT%H:00Z" if hourly else "%Y-%m-%d"

    buckets: dict[str, Counter] = {}
    for a in alerts:
        if not a["timestamp"]:
            continue
        dt = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
        buckets.setdefault(dt.strftime(fmt), Counter())[a["severity"]] += 1

    series = []
    for bucket in sorted(buckets):
        row = {"bucket": bucket, "total": sum(buckets[bucket].values())}
        row.update({s: buckets[bucket].get(s, 0) for s in SEVERITY_ORDER})
        series.append(row)
    return {"interval": "hour" if hourly else "day", "series": series}


def aggregate(alerts: list[dict]) -> dict:
    by_severity = Counter(a["severity"] for a in alerts)
    by_tactic, by_technique, technique_names = Counter(), Counter(), {}
    for a in alerts:
        # An alert mapped to two techniques of the same tactic counts once for that tactic.
        for tactic in {m["tactic"] for m in a["mitre"]}:
            by_tactic[tactic] += 1
        for m in a["mitre"]:
            by_technique[m["technique_id"]] += 1
            technique_names[m["technique_id"]] = m["technique_name"]

    return {
        "total": len(alerts),
        "by_severity": [{"severity": s, "count": by_severity.get(s, 0)} for s in SEVERITY_ORDER],
        "by_tactic": [{"tactic": t, "count": c} for t, c in by_tactic.most_common()],
        "by_technique": [
            {"technique_id": t, "technique_name": technique_names[t], "count": c}
            for t, c in by_technique.most_common()
        ],
        "over_time": time_buckets(alerts),
        "hosts": sorted({a["host"] for a in alerts}),
    }


class AlertStore:
    def __init__(self, mapper: MitreMapper):
        self.mapper = mapper
        self._alerts: list[dict] = []
        self._next_id = 1
        self._lock = threading.Lock()

    def add(self, alerts: list[dict], filename: str) -> int:
        with self._lock:
            for alert in alerts:
                alert["id"] = self._next_id
                alert["file"] = filename
                alert["mitre"] = self.mapper.map_alert(alert)
                alert["summary"] = None
                self._next_id += 1
                self._alerts.append(alert)
            self._alerts = sort_alerts(self._alerts)
        return len(alerts)

    def remap(self, mapper: MitreMapper) -> None:
        """Re-apply a (re)loaded rules file to every stored alert."""
        with self._lock:
            self.mapper = mapper
            for alert in self._alerts:
                alert["mitre"] = mapper.map_alert(alert)

    def clear(self) -> None:
        with self._lock:
            self._alerts = []

    def all(self) -> list[dict]:
        return list(self._alerts)

    def get(self, alert_id: int) -> dict | None:
        return next((a for a in self._alerts if a["id"] == alert_id), None)
