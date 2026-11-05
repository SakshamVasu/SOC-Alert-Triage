from triage.store import aggregate, filter_alerts, sort_alerts


def alert(id, severity, ts, host="h1", tactic="Execution", tid="T1059"):
    return {"id": id, "severity": severity, "timestamp": ts, "host": host, "rule_name": f"r{id}",
            "description": "", "source_ip": "",
            "mitre": [{"technique_id": tid, "technique_name": "n", "tactic": tactic}]}


def test_severity_order_then_newest_first():
    alerts = [
        alert(1, "low", "2026-11-04T10:00:00Z"),
        alert(2, "critical", "2026-11-04T08:00:00Z"),
        alert(3, "informational", "2026-11-04T12:00:00Z"),
        alert(4, "high", "2026-11-04T09:00:00Z"),
        alert(5, "critical", "2026-11-04T09:30:00Z"),
        alert(6, "medium", "2026-11-04T07:00:00Z"),
    ]
    assert [a["id"] for a in sort_alerts(alerts)] == [5, 2, 4, 6, 1, 3]


def test_missing_timestamp_sorts_last_within_severity():
    alerts = [alert(1, "high", None), alert(2, "high", "2026-11-04T09:00:00Z")]
    assert [a["id"] for a in sort_alerts(alerts)] == [2, 1]


def test_fractional_seconds_sort_correctly_within_the_same_second():
    # isoformat() drops ".000000", and "." < "Z" in ASCII; the sort must not be fooled.
    alerts = [alert(1, "high", "2026-11-04T12:01:33Z"), alert(2, "high", "2026-11-04T12:01:33.500000Z")]
    assert [a["id"] for a in sort_alerts(alerts)] == [2, 1]


def test_filter_by_severity_host_and_tactic():
    alerts = [
        alert(1, "high", None, host="web-01"),
        alert(2, "low", None, host="web-01"),
        alert(3, "high", None, host="DB-01", tactic="Impact"),
    ]
    assert [a["id"] for a in filter_alerts(alerts, severity="high,critical")] == [1, 3]
    assert [a["id"] for a in filter_alerts(alerts, host="db-01")] == [3]   # case-insensitive
    assert [a["id"] for a in filter_alerts(alerts, severity="high", tactic="impact")] == [3]


def test_aggregate_counts_and_hourly_buckets():
    alerts = [
        alert(1, "high", "2026-11-04T10:05:00Z"),
        alert(2, "high", "2026-11-04T10:45:00Z", tactic="Impact", tid="T1486"),
        alert(3, "low", "2026-11-04T11:10:00Z"),
    ]
    stats = aggregate(alerts)
    assert {r["severity"]: r["count"] for r in stats["by_severity"]}["high"] == 2
    assert stats["by_tactic"][0] == {"tactic": "Execution", "count": 2}
    assert stats["over_time"]["interval"] == "hour"
    assert stats["over_time"]["series"][0]["bucket"] == "2026-11-04T10:00Z"
    assert stats["over_time"]["series"][0]["high"] == 2
