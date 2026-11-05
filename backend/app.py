"""
SOC Alert Triage Dashboard - Flask API.

Run:  python app.py            (serves http://127.0.0.1:5000)

Endpoints (all JSON):
    GET    /api/health                  status + whether AI summaries are enabled
    POST   /api/upload                  multipart "file": Wazuh/Splunk JSON or CSV export
    GET    /api/alerts                  prioritized queue; filters: severity, host, tactic, technique, q
    GET    /api/alerts/<id>             one alert incl. raw record
    DELETE /api/alerts                  clear all alerts
    GET    /api/stats                   aggregates for charts (same filters as /api/alerts)
    GET    /api/rules                   loaded MITRE rules
    POST   /api/rules/reload            re-read the rules file and re-map stored alerts
    POST   /api/alerts/<id>/summarize   optional AI summary (ENABLE_AI_SUMMARY=true)
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from triage.mitre import MitreMapper, RulesError
from triage.normalize import ParseError, parse_file
from triage.store import AlertStore, aggregate, filter_alerts
from triage.summarizer import Summarizer, ai_enabled

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_RULES = BASE_DIR / "rules" / "mitre_rules.yaml"
ALLOWED_EXTENSIONS = {".json", ".ndjson", ".jsonl", ".csv"}
MAX_UPLOAD_MB = 20


def create_app(rules_path: str | Path | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

    rules_path = Path(rules_path or os.environ.get("MITRE_RULES_FILE", DEFAULT_RULES))
    store = AlertStore(MitreMapper.from_file(rules_path))  # fail fast on a broken rules file
    summarizer = Summarizer() if ai_enabled() else None
    app.extensions["alert_store"] = store

    def error(message: str, status: int = 400):
        return jsonify({"error": message}), status

    def list_view(alert: dict) -> dict:
        """Queue rows omit the raw record to keep responses small."""
        return {k: v for k, v in alert.items() if k != "raw"}

    def current_filters() -> dict:
        args = request.args
        return {k: args.get(k) for k in ("severity", "host", "tactic", "technique", "q")}

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_):
        return error(f"File too large (limit {MAX_UPLOAD_MB} MB).", 413)

    @app.errorhandler(HTTPException)
    def http_error(e):
        return error(e.description, e.code)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "ai_enabled": summarizer is not None,
                        "alerts": len(store.all()), "rules": len(store.mapper.rules)})

    @app.post("/api/upload")
    def upload():
        file = request.files.get("file")
        if file is None or not file.filename:
            return error("No file uploaded. Send a multipart form with a 'file' field.")
        ext = Path(file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return error(f"Unsupported file type '{ext or 'none'}'. Upload a .json, .ndjson, .jsonl or .csv export.")
        data = file.read()
        if not data.strip():
            return error("Uploaded file is empty.")
        try:
            alerts, info = parse_file(file.filename, data)
        except ParseError as e:
            return error(f"Could not parse {file.filename}: {e}", 422)

        ingested = store.add(alerts, file.filename)
        return jsonify({"filename": file.filename, "ingested": ingested,
                        "total": len(store.all()), **info}), 201

    @app.get("/api/alerts")
    def list_alerts():
        alerts = filter_alerts(store.all(), **current_filters())
        return jsonify({"count": len(alerts), "alerts": [list_view(a) for a in alerts]})

    @app.delete("/api/alerts")
    def clear_alerts():
        store.clear()
        return jsonify({"status": "cleared"})

    @app.get("/api/alerts/<int:alert_id>")
    def get_alert(alert_id: int):
        alert = store.get(alert_id)
        return jsonify(alert) if alert else error(f"Alert {alert_id} not found.", 404)

    @app.get("/api/stats")
    def stats():
        return jsonify(aggregate(filter_alerts(store.all(), **current_filters())))

    @app.get("/api/rules")
    def rules():
        return jsonify({"path": str(rules_path), "rules": store.mapper.summary()})

    @app.post("/api/rules/reload")
    def reload_rules():
        # Lets an analyst edit mitre_rules.yaml and apply it without a restart.
        try:
            store.remap(MitreMapper.from_file(rules_path))
        except RulesError as e:
            return error(str(e), 422)
        return jsonify({"status": "reloaded", "rules": len(store.mapper.rules)})

    @app.post("/api/alerts/<int:alert_id>/summarize")
    def summarize(alert_id: int):
        if summarizer is None:
            return error("AI summarization is disabled. Set ENABLE_AI_SUMMARY=true and restart.", 400)
        alert = store.get(alert_id)
        if alert is None:
            return error(f"Alert {alert_id} not found.", 404)
        try:
            alert["summary"] = summarizer.summarize(alert)
        except Exception as e:  # model download / API failures are reported, not fatal
            return error(f"Summarization failed: {e}", 502)
        return jsonify({"id": alert_id, "summary": alert["summary"]})

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=True)
