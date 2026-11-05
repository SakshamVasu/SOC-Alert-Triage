import io
from pathlib import Path

import pytest

from app import DEFAULT_RULES, create_app
from triage.mitre import MitreMapper, RulesError

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture(scope="module")
def mapper():
    return MitreMapper.from_file(DEFAULT_RULES)


def alert(rule_name="", description="", rule_id="", category=""):
    return {"rule_name": rule_name, "description": description, "rule_id": rule_id, "category": category}


def test_match_by_rule_id(mapper):
    assert mapper.map_alert(alert(rule_id="5712"))[0]["technique_id"] == "T1110"


def test_match_by_keyword_in_description(mapper):
    m = mapper.map_alert(alert("Process access", "Process accessed lsass.exe"))[0]
    assert (m["technique_id"], m["tactic"]) == ("T1003.001", "Credential Access")


def test_match_by_category_token(mapper):
    assert mapper.map_alert(alert(category="web, accesslog, sql_injection"))[0]["technique_id"] == "T1190"


def test_rule_order_gives_primary_technique(mapper):
    # Matches both "password spray" (T1110.003) and "brute force" (T1110); the
    # more specific rule is listed first in the YAML.
    ids = [m["technique_id"] for m in mapper.map_alert(alert("Password spray / brute force"))]
    assert ids[:2] == ["T1110.003", "T1110"]


def test_regex_word_boundary(mapper):
    assert mapper.map_alert(alert("Inbound RDP from internet"))[0]["technique_id"] == "T1021.001"
    assert mapper.map_alert(alert("WordPress login page"))[0]["technique_id"] == "Unmapped"


def test_unmatched_alert_is_labeled_unmapped(mapper):
    result = mapper.map_alert(alert("Disk usage above 90%"))
    assert result == [{"technique_id": "Unmapped", "technique_name": "Unmapped", "tactic": "Unmapped", "rule": None}]


def test_invalid_rules_are_rejected(tmp_path):
    bad = tmp_path / "rules.yaml"
    bad.write_text("rules:\n  - name: x\n    technique_id: T1\n    tactic: Y\n    match: {keywords: [a]}\n")
    with pytest.raises(RulesError, match="technique_name"):
        MitreMapper.from_file(bad)
    bad.write_text("rules:\n  - {name: x, technique_id: T1, technique_name: n, tactic: Y, match: {foo: [a]}}\n")
    with pytest.raises(RulesError, match="needs a 'match:'"):
        MitreMapper.from_file(bad)


# --- API-level: upload -> mapped, sorted queue ------------------------------ #
@pytest.fixture()
def client():
    return create_app().test_client()


def upload(client, name):
    data = {"file": (io.BytesIO((SAMPLES / name).read_bytes()), name)}
    return client.post("/api/upload", data=data, content_type="multipart/form-data")


def test_upload_maps_and_sorts_samples(client):
    assert upload(client, "wazuh_alerts.json").status_code == 201
    assert upload(client, "splunk_alerts.csv").status_code == 201

    alerts = client.get("/api/alerts").get_json()["alerts"]
    assert len(alerts) == 22
    severities = [a["severity"] for a in alerts]
    order = ["critical", "high", "medium", "low", "informational"]
    assert severities == sorted(severities, key=order.index)
    # Every alert carries a mapping; unmatched ones say "Unmapped" rather than vanishing.
    assert all(a["mitre"] for a in alerts)
    assert any(a["mitre"][0]["technique_id"] == "Unmapped" for a in alerts)

    stats = client.get("/api/stats?host=WIN-FS01").get_json()
    assert stats["total"] == 4


def test_upload_rejects_bad_files(client):
    r = upload(client, "malformed.json")
    assert r.status_code == 422 and "Invalid JSON" in r.get_json()["error"]
    r = client.post("/api/upload", data={"file": (io.BytesIO(b"x"), "alerts.txt")},
                    content_type="multipart/form-data")
    assert r.status_code == 400 and "Unsupported file type" in r.get_json()["error"]
    assert client.post("/api/upload").status_code == 400


def test_summarize_disabled_by_default(client):
    upload(client, "splunk_alerts.csv")
    r = client.post("/api/alerts/1/summarize")
    assert r.status_code == 400 and "disabled" in r.get_json()["error"]
