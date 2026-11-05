"""
Parsing and normalization of Wazuh / Splunk alert exports.

Every alert, whatever its origin, is turned into ONE internal schema:

    {
        "timestamp":   ISO-8601 UTC string or None,
        "severity":    "critical" | "high" | "medium" | "low" | "informational",
        "rule_name":   str,
        "rule_id":     str,
        "category":    str   (comma-joined Wazuh groups / Splunk category),
        "host":        str,
        "source_ip":   str,
        "description": str,
        "source":      "wazuh" | "splunk" | "generic",
        "raw":         the original record, untouched,
    }

SOC ANALYSTS: if your export uses field names that are not picked up, add
them to FIELD_CANDIDATES below. Nested JSON is flattened to dotted keys first
(e.g. {"rule": {"level": 10}} -> "rule.level"), so a Wazuh CSV exported from
the dashboard (columns like "rule.level") and a Wazuh JSON alert look the same
to the mapper.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from dateutil import parser as date_parser


class ParseError(ValueError):
    """Raised for files that cannot be parsed. The message is shown to the user."""


# --------------------------------------------------------------------------- #
# Field mappings  (EDIT HERE to support new export layouts)
# --------------------------------------------------------------------------- #
# For each internal field, candidate source keys are tried IN ORDER and the
# first non-empty value wins. Keys are matched case-insensitively against the
# flattened record.
FIELD_CANDIDATES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "@timestamp", "_time", "time", "event_time", "date"],
    "severity": [
        "rule.level",        # Wazuh: 0-15
        "severity",          # Splunk ES / generic: label or number
        "urgency",           # Splunk ES notable events
        "priority",
        "level",
        "risk_score",        # Splunk RBA: 0-100
    ],
    "rule_name": [
        "rule.description",  # Wazuh: the rule's human-readable title
        "rule_name",
        "search_name",       # Splunk saved search / correlation search
        "signature",         # Splunk CIM (IDS, malware, ...)
        "alert",
        "alert_name",
        "name",
        "title",
    ],
    "rule_id": ["rule.id", "rule_id", "signature_id", "alert_id", "event_id", "eventcode"],
    "category": ["rule.groups", "category", "eventtype", "tag", "type"],
    "host": [
        "agent.name",        # Wazuh agent that raised the alert
        "host",
        "dest",              # Splunk CIM destination
        "dvc",
        "hostname",
        "computer",
        "manager.name",      # Wazuh fallback: the manager itself
    ],
    "source_ip": [
        "data.srcip",        # Wazuh decoders
        "data.src_ip",
        "data.win.eventdata.ipAddress",
        "src_ip",
        "src",               # Splunk CIM
        "srcip",
        "source_ip",
        "client_ip",
        "agent.ip",
    ],
    "description": [
        "full_log",          # Wazuh: the raw log line that fired the rule
        "description",
        "message",
        "_raw",              # Splunk raw event
        "rule.description",
    ],
}

# Keys whose presence identifies the export's origin (checked on flattened keys).
WAZUH_MARKERS = {"rule.level", "rule.id", "agent.name", "agent.id", "full_log", "decoder.name"}
SPLUNK_MARKERS = {"_time", "_raw", "search_name", "urgency", "sourcetype", "_cd", "splunk_server"}

# Real SIEM alerts nest a handful of levels; anything deeper is junk or hostile.
MAX_NESTING_DEPTH = 64
# Splunk _raw cells can be large; the csv module's default cap is 131,072 chars.
CSV_FIELD_LIMIT = 32 * 1024 * 1024

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
# Rank used for sorting: higher = more urgent.
SEVERITY_RANK = {name: len(SEVERITY_ORDER) - i for i, name in enumerate(SEVERITY_ORDER)}

# Text labels seen in the wild -> internal severity.
SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "fatal": "critical",
    "emergency": "critical", "emerg": "critical", "alert": "critical",
    "high": "high", "severe": "high", "error": "high", "err": "high", "major": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "warning": "medium", "warn": "medium",
    "low": "low", "minor": "low",
    "informational": "informational", "information": "informational",
    "info": "informational", "notice": "informational", "debug": "informational",
    "none": "informational", "unknown": "informational",
    # Priority / incident-style scales (P1 = most urgent). Spaces, dashes and
    # underscores are ignored when matching, so "Sev 2" and "sev-2" hit "sev2".
    "p1": "critical", "p2": "high", "p3": "medium", "p4": "low", "p5": "informational",
    "sev1": "critical", "sev2": "high", "sev3": "medium", "sev4": "low", "sev5": "informational",
}


def wazuh_level_to_severity(level: float) -> str:
    """Wazuh rule levels run 0-15. Thresholds below are a common SOC convention;
    tune them to your own escalation policy."""
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def score_to_severity(score: float) -> str:
    """0-100 risk scores (e.g. Splunk RBA risk_score)."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


def splunk_number_to_severity(n: float) -> str:
    """Splunk numeric severity 1-5 (5 = most severe), larger values are scores."""
    if n > 5:
        return score_to_severity(n)
    return {5: "critical", 4: "high", 3: "medium", 2: "low"}.get(int(n), "informational")


def classify_severity(value, source: str) -> tuple[str, bool]:
    """Return (severity, recognized). Unrecognized values fall back to
    "informational" and recognized=False, so the upload can warn about them."""
    if value is None or value == "":
        return "informational", True
    text = str(value).strip().lower()
    key = text.replace(" ", "").replace("-", "").replace("_", "")
    if key in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[key], True
    try:
        number = float(text)
    except ValueError:
        return "informational", False
    if source == "wazuh":
        return wazuh_level_to_severity(number), True
    if source == "splunk":
        return splunk_number_to_severity(number), True
    # Unknown origin: small numbers look like Wazuh levels, big ones like scores.
    return (wazuh_level_to_severity(number) if number <= 15 else score_to_severity(number)), True


def normalize_severity(value, source: str) -> str:
    return classify_severity(value, source)[0]


def normalize_timestamp(value) -> str | None:
    """Accepts ISO strings (incl. Wazuh's '+0000' offsets), Splunk epoch seconds,
    or anything dateutil understands. Returns ISO-8601 UTC or None."""
    if value is None or value == "":
        return None
    try:
        text = str(value).strip()
        # Splunk often exports _time as epoch seconds ("1714558530.123"); some
        # tools use epoch milliseconds ("1714558530123"). Short digit strings
        # like "20240501" are left for dateutil.
        if text.replace(".", "", 1).isdigit() and float(text) > 1e9:
            epoch = float(text)
            if epoch > 1e11:  # seconds would be past the year 5000: milliseconds
                epoch /= 1000
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        else:
            dt = date_parser.parse(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)  # assume UTC when unspecified
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


# --------------------------------------------------------------------------- #
# Record helpers
# --------------------------------------------------------------------------- #
def flatten(record: dict, prefix: str = "") -> dict:
    """{"a": {"b": 1}} -> {"a.b": 1}. Lists of scalars are kept as lists."""
    flat = {}
    for key, value in record.items():
        full_key = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{full_key}."))
        else:
            flat[full_key] = value
    return flat


def nesting_depth_exceeds(obj, limit: int) -> bool:
    """True if dicts/lists nest deeper than `limit`. Iterative, so pathological
    input cannot hit Python's recursion limit here (or later in flatten/jsonify)."""
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        children = node.values() if isinstance(node, dict) else node
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return False


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    return str(value).strip()


def _pick(flat_lower: dict, field: str):
    for key in FIELD_CANDIDATES[field]:
        value = flat_lower.get(key.lower())
        if value not in (None, "", []):
            return value
    return None


def detect_source(flat_keys) -> str:
    keys = {k.lower() for k in flat_keys}
    if keys & {m.lower() for m in WAZUH_MARKERS}:
        return "wazuh"
    if keys & {m.lower() for m in SPLUNK_MARKERS}:
        return "splunk"
    return "generic"


def normalize_record(record: dict) -> dict:
    """Map one raw alert (any supported layout) to the internal schema."""
    return _normalize(record)[0]


def _normalize(record: dict) -> tuple[dict, str | None]:
    """normalize_record() plus the raw severity value when it was not recognized
    (None otherwise), so parse_file() can warn instead of silently downgrading."""
    flat = flatten(record)
    flat_lower = {k.lower(): v for k, v in flat.items()}
    source = detect_source(flat.keys())

    rule_name = _as_text(_pick(flat_lower, "rule_name"))
    description = _as_text(_pick(flat_lower, "description"))
    raw_severity = _pick(flat_lower, "severity")
    severity, recognized = classify_severity(raw_severity, source)

    alert = {
        "timestamp": normalize_timestamp(_pick(flat_lower, "timestamp")),
        "severity": severity,
        "rule_name": rule_name or "(unnamed rule)",
        "rule_id": _as_text(_pick(flat_lower, "rule_id")),
        "category": _as_text(_pick(flat_lower, "category")),
        "host": _as_text(_pick(flat_lower, "host")) or "unknown",
        "source_ip": _as_text(_pick(flat_lower, "source_ip")),
        "description": description,
        "source": source,
        "raw": record,
    }
    return alert, None if recognized else str(raw_severity)


# --------------------------------------------------------------------------- #
# File parsing
# --------------------------------------------------------------------------- #
def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ParseError("File is not valid text (could not decode as UTF-8 or Latin-1).")


def _unwrap_json(doc) -> list:
    """Find the list of alert records inside the common export envelopes."""
    if isinstance(doc, list):
        records = doc
    elif isinstance(doc, dict):
        if isinstance(doc.get("hits"), dict) and isinstance(doc["hits"].get("hits"), list):
            records = doc["hits"]["hits"]                      # Wazuh indexer / OpenSearch
        elif isinstance(doc.get("results"), list):
            records = doc["results"]                           # Splunk REST export
        elif isinstance(doc.get("alerts"), list):
            records = doc["alerts"]
        elif isinstance(doc.get("data"), dict) and isinstance(doc["data"].get("affected_items"), list):
            records = doc["data"]["affected_items"]            # Wazuh API
        else:
            records = [doc]                                    # a single alert object
    else:
        raise ParseError("JSON must be an object or an array of alert objects.")

    unwrapped = []
    for rec in records:
        if isinstance(rec, dict) and isinstance(rec.get("_source"), dict):
            rec = rec["_source"]                               # OpenSearch hit
        if isinstance(rec, dict) and isinstance(rec.get("result"), dict):
            rec = rec["result"]                                # Splunk {"preview":..,"result":{}}
        unwrapped.append(rec)
    return unwrapped


def parse_json(text: str) -> list:
    stripped = text.strip()
    if not stripped:
        raise ParseError("File is empty.")
    try:
        return _unwrap_json(json.loads(stripped))
    except RecursionError:
        raise ParseError("JSON is nested too deeply to be an alert export.") from None
    except json.JSONDecodeError as first_error:
        # Not a single JSON document: try newline-delimited JSON (Wazuh alerts.json,
        # Splunk 'export' endpoint).
        records = []
        for line_no, line in enumerate(stripped.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.extend(_unwrap_json(json.loads(line)))
            except RecursionError:
                raise ParseError(f"JSON on line {line_no} is nested too deeply to be an alert.") from None
            except json.JSONDecodeError as e:
                if line_no == 1:
                    raise ParseError(
                        f"Invalid JSON at line {first_error.lineno}, column {first_error.colno}: "
                        f"{first_error.msg}"
                    ) from None
                raise ParseError(f"Invalid JSON on line {line_no}: {e.msg}") from None
        return records


def parse_csv(text: str) -> list:
    if not text.strip():
        raise ParseError("File is empty.")
    if csv.field_size_limit() < CSV_FIELD_LIMIT:
        csv.field_size_limit(CSV_FIELD_LIMIT)
    reader = csv.DictReader(io.StringIO(text))
    records = []
    try:
        if not reader.fieldnames or all(not (f or "").strip() for f in reader.fieldnames):
            raise ParseError("CSV has no header row.")
        for row_no, row in enumerate(reader, start=2):
            if None in row:
                raise ParseError(f"CSV row {row_no} has more columns than the header.")
            # Dotted headers such as "rule.level" (Wazuh dashboard CSV export) already
            # match the flattened-key names in FIELD_CANDIDATES. Blank cells are dropped.
            records.append({k.strip(): v for k, v in row.items() if k and v not in (None, "")})
    except csv.Error as e:
        # line_num is the physical line the reader stopped on (quoted cells can span lines).
        raise ParseError(f"Malformed CSV near line {reader.line_num}: {e}") from None
    return records


def detect_file_format(filename: str, text: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return "csv"
    if name.endswith((".json", ".ndjson", ".jsonl")):
        return "json"
    return "json" if text.lstrip()[:1] in ("{", "[") else "csv"


def parse_file(filename: str, data: bytes) -> tuple[list[dict], dict]:
    """Parse an uploaded export and return (normalized_alerts, info).

    info = {"file_format", "source_formats", "skipped", "warnings"}.
    Raises ParseError with a user-facing message on malformed input.
    """
    text = _decode(data)
    file_format = detect_file_format(filename, text)
    records = parse_json(text) if file_format == "json" else parse_csv(text)

    alerts, warnings, skipped = [], [], 0
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            skipped += 1
            warnings.append(f"Record {index} skipped: not an object.")
            continue
        if nesting_depth_exceeds(record, MAX_NESTING_DEPTH):
            skipped += 1
            warnings.append(f"Record {index} skipped: nested deeper than {MAX_NESTING_DEPTH} levels.")
            continue
        alert, unknown_severity = _normalize(record)
        # A record with neither a rule name nor a description carries no
        # triage value - most likely the wrong file or a junk row.
        if alert["rule_name"] == "(unnamed rule)" and not alert["description"]:
            skipped += 1
            warnings.append(f"Record {index} skipped: no recognizable rule name or description.")
            continue
        if alert["timestamp"] is None:
            warnings.append(f"Record {index}: timestamp missing or unparseable.")
        if unknown_severity is not None:
            warnings.append(
                f"Record {index}: unrecognized severity {unknown_severity!r} treated as informational "
                "(add it to SEVERITY_ALIASES in normalize.py)."
            )
        alerts.append(alert)

    if not alerts:
        # Surface the first skip reason (e.g. "nested deeper than 64 levels"), if any.
        reason = f" First problem: {warnings[0]}" if warnings else ""
        raise ParseError(
            "No alerts recognized. Expected Wazuh fields (rule.description, rule.level, "
            "agent.name) or Splunk fields (_time, search_name/signature, severity/urgency, host)."
            + reason
        )

    info = {
        "file_format": file_format,
        "source_formats": sorted({a["source"] for a in alerts}),
        "skipped": skipped,
        # Cap the list so a 10k-row file with no timestamps doesn't flood the UI.
        "warnings": warnings[:20] + ([f"... and {len(warnings) - 20} more"] if len(warnings) > 20 else []),
    }
    return alerts, info
