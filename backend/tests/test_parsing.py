import json
from pathlib import Path

import pytest

from triage.normalize import ParseError, normalize_record, normalize_severity, normalize_timestamp, parse_file

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def load(name):
    return parse_file(name, (SAMPLES / name).read_bytes())


def test_wazuh_json_sample_is_normalized():
    alerts, info = load("wazuh_alerts.json")
    assert info["file_format"] == "json"
    assert info["source_formats"] == ["wazuh"]
    first = alerts[0]
    assert first["timestamp"] == "2026-11-04T08:12:03.512000Z"
    assert first["severity"] == "high"                 # rule.level 10
    assert first["rule_id"] == "5712"
    assert first["host"] == "web-01"                   # agent.name
    assert first["source_ip"] == "203.0.113.45"        # data.srcip
    assert "authentication_failures" in first["category"]
    assert first["raw"]["rule"]["level"] == 10         # original record kept


def test_wazuh_csv_with_dotted_headers_matches_json():
    csv_alerts, info = load("wazuh_alerts.csv")
    json_alerts, _ = load("wazuh_alerts.json")
    assert info["file_format"] == "csv"
    for c, j in zip(csv_alerts, json_alerts):
        for field in ("timestamp", "severity", "rule_name", "rule_id", "host", "source_ip"):
            assert c[field] == j[field], field


def test_splunk_csv_sample():
    alerts, info = load("splunk_alerts.csv")
    assert info["source_formats"] == ["splunk"]
    assert alerts[0]["rule_name"].startswith("Endpoint - Ransomware")
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["host"] == "WIN-HR07"
    assert alerts[0]["source_ip"] == "10.0.4.47"


def test_splunk_ndjson_export_with_epoch_time():
    alerts, _ = load("splunk_alerts.json")
    assert len(alerts) == 5
    assert alerts[0]["timestamp"] == "2026-11-04T12:01:33Z"
    assert alerts[0]["severity"] == "critical"         # urgency
    assert alerts[0]["host"] == "WIN-HR07"             # dest
    assert alerts[0]["rule_id"] == "ES-0042"           # signature_id


def test_opensearch_envelope_is_unwrapped():
    doc = {"hits": {"hits": [{"_source": {"rule": {"level": 3, "description": "x"}, "agent": {"name": "h"}}}]}}
    alerts, _ = parse_file("export.json", json.dumps(doc).encode())
    assert alerts[0]["host"] == "h"
    assert alerts[0]["severity"] == "informational"


@pytest.mark.parametrize("value,source,expected", [
    (15, "wazuh", "critical"), (12, "wazuh", "critical"), (10, "wazuh", "high"),
    (7, "wazuh", "medium"), (4, "wazuh", "low"), (2, "wazuh", "informational"),
    ("HIGH", "splunk", "high"), ("warning", "generic", "medium"), ("info", "splunk", "informational"),
    ("5", "splunk", "critical"), (85, "splunk", "critical"), (None, "wazuh", "informational"),
    ("P1", "generic", "critical"), ("p3", "splunk", "medium"), ("Sev 2", "generic", "high"),
    ("SEV-4", "generic", "low"), ("sev_5", "generic", "informational"),
])
def test_severity_normalization(value, source, expected):
    assert normalize_severity(value, source) == expected


def test_timestamp_formats():
    assert normalize_timestamp("2026-11-04T08:12:03+0000") == "2026-11-04T08:12:03Z"
    assert normalize_timestamp("2026-11-04 10:00:00+02:00") == "2026-11-04T08:00:00Z"
    assert normalize_timestamp(1793865600) == "2026-11-05T08:00:00Z"
    assert normalize_timestamp("1793865600000") == "2026-11-05T08:00:00Z"      # epoch milliseconds
    assert normalize_timestamp(1793865600500) == "2026-11-05T08:00:00.500000Z"
    assert normalize_timestamp("not a date") is None


def test_unrecognized_severity_is_kept_but_warned():
    data = json.dumps([{"rule": {"description": "x"}, "timestamp": "2026-11-04T08:00:00Z",
                        "severity": "Urgent-ish"}]).encode()
    alerts, info = parse_file("x.json", data)
    assert alerts[0]["severity"] == "informational"
    assert any("unrecognized severity 'Urgent-ish'" in w for w in info["warnings"])


def test_large_csv_cell_is_accepted():
    # Larger than the csv module's default 131,072-character field limit.
    big = "A" * 200_000
    alerts, _ = parse_file("big.csv", f"rule_name,description\nX,{big}\n".encode())
    assert len(alerts[0]["description"]) == 200_000


def deep(levels):
    return '{"a":' * levels + "1" + "}" * levels


def test_deeply_nested_record_is_skipped_with_warning():
    data = f'[{{"rule": {{"description": "ok"}}}}, {{"rule": {{"description": "deep"}}, "x": {deep(100)}}}]'
    alerts, info = parse_file("x.json", data.encode())
    assert [a["rule_name"] for a in alerts] == ["ok"]
    assert info["skipped"] == 1
    assert "Record 2 skipped: nested deeper than 64 levels." in info["warnings"]


def test_pathologically_nested_json_is_a_parse_error():
    with pytest.raises(ParseError, match="nested too deeply|No alerts recognized"):
        parse_file("x.json", deep(200_000).encode())


def test_unknown_layout_falls_back_to_generic():
    alert = normalize_record({"title": "Something odd", "message": "details"})
    assert alert["source"] == "generic"
    assert alert["host"] == "unknown"
    assert alert["severity"] == "informational"


@pytest.mark.parametrize("name,data,fragment", [
    ("malformed.json", (SAMPLES / "malformed.json").read_bytes(), "Invalid JSON"),
    ("empty.json", b"   ", "empty"),
    ("x.csv", b"foo,bar\n1,2\n", "No alerts recognized"),
    ("x.csv", b"rule_name,host\nA,h1,extra\n", "more columns"),
    ("x.json", b'"just a string"', "object or an array"),
])
def test_malformed_files_raise_clear_errors(name, data, fragment):
    with pytest.raises(ParseError, match=fragment):
        parse_file(name, data)
