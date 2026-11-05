# SOC Alert Triage Dashboard

Upload Wazuh or Splunk alert exports (JSON / NDJSON / CSV). The Flask backend
normalizes them into one schema, sorts by severity, and maps each alert to
MITRE ATT&CK using an editable YAML rules file. The React dashboard shows the
prioritized queue, per-alert details with the mapped technique, and summary charts.

Scope: file upload only (no live pipeline). No model training. The optional AI
summary uses a pretrained Hugging Face model and is **off by default**.

## Project structure

```
soc-alert-triage/
├── backend/
│   ├── app.py                  Flask API (endpoints listed at top of file)
│   ├── rules/mitre_rules.yaml  MITRE ATT&CK mapping rules  <- edit me
│   ├── triage/
│   │   ├── normalize.py        JSON/CSV parsing, field mappings, severity scale  <- edit FIELD_CANDIDATES
│   │   ├── mitre.py            rules loader + matcher
│   │   ├── store.py            in-memory store, sorting, filters, chart aggregates
│   │   └── summarizer.py       optional Hugging Face summarization
│   ├── tests/                  pytest: parsing, sorting, mapping, API
│   ├── requirements.txt
│   └── requirements-ai.txt     extra deps for the AI feature
├── frontend/                   React (Vite) + Recharts
│   └── src/
│       ├── App.jsx
│       ├── api.js
│       └── components/         UploadPanel, Filters, AlertTable, AlertDetail, Charts
└── samples/                    test inputs (Wazuh JSON/CSV, Splunk CSV/NDJSON, a malformed file)
```

## Setup

Requires Python 3.10+ and Node 18+.

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
python app.py                   # http://127.0.0.1:5000
```

### Frontend (second terminal)

```bash
cd frontend
npm install
npm run dev                     # http://localhost:5173 (proxies /api to :5000)
```

Open http://localhost:5173 and upload the files in `samples/`.

### Tests

```bash
cd backend
python -m pytest -q
```

## Using it

- **Upload**: drag files onto the upload box or use *Choose files*. Several files can be loaded; alerts accumulate until you press *Clear alerts* or restart the backend (storage is in memory).
- **Queue**: sorted critical → high → medium → low → informational, newest first within a severity. Filter by severity chips, host, or free-text search.
- **Charts**: by severity, over time (hourly or daily, depending on the time span), by tactic, and top techniques. Click a bar to filter the queue.
- **Detail**: click a row to see normalized fields, every matched technique (linked to attack.mitre.org), the description, and the raw event.
- **Errors**: malformed files return a specific message, such as `Invalid JSON at line 2, column 12`, `CSV row 4 has more columns than the header`, or `No alerts recognized`.

## Editing the MITRE rules

`backend/rules/mitre_rules.yaml` holds the rules. Each rule names one technique, and it fires when **any** of its conditions match:

```yaml
- name: Brute force / repeated authentication failures
  technique_id: T1110
  technique_name: Brute Force
  tactic: Credential Access
  match:
    rule_ids: ["5712", "5720"]          # exact Wazuh rule.id / Splunk signature_id
    rule_names: ["sshd: brute force"]   # substring of rule name
    keywords: ["brute force"]           # substring of rule name + description
    categories: ["authentication_failures"]  # Wazuh group / Splunk category token
    regex: ["failed password for .* from"]   # Python regex
```

- **Order matters.** An alert keeps every technique it matches, but the first match is its primary technique. Put specific rules above generic ones.
- An alert that matches nothing is labeled **Unmapped**. It is never dropped.
- After editing, click **Reload rules** in the UI (or `POST /api/rules/reload`). Stored alerts are re-mapped without re-uploading. A broken rules file returns a clear error and the old rules stay active.
- To use a different file, set `MITRE_RULES_FILE=/path/to/rules.yaml`.

## Field mappings and severity

`backend/triage/normalize.py` controls normalization:

- `FIELD_CANDIDATES` lists the source keys tried for each internal field (`timestamp`, `severity`, `rule_name`, `rule_id`, `category`, `host`, `source_ip`, `description`). The first non-empty key wins. Nested JSON is flattened to dotted keys, so the Wazuh JSON `rule.level` and the Wazuh dashboard CSV column `rule.level` are handled the same way.
- Supported envelopes: a plain array, NDJSON (Wazuh `alerts.json`), Splunk `{"result": {...}}` lines and `{"results": [...]}`, OpenSearch / Wazuh indexer `hits.hits[]._source`, and Wazuh API `data.affected_items`.
- Severity scales (tune them to your escalation policy):
  - Wazuh `rule.level`: 12–15 critical, 10–11 high, 7–9 medium, 4–6 low, 0–3 informational
  - Splunk numeric 1–5 (5 = critical); values above 5 are treated as a 0–100 risk score
  - Text labels (`critical`, `high`, `warning`, `info`, …) via `SEVERITY_ALIASES`

## Optional: AI summaries

Uses a **pretrained** Hugging Face summarization model. Nothing is trained.

```bash
pip install -r requirements-ai.txt
```

| Variable | Default | Meaning |
|---|---|---|
| `ENABLE_AI_SUMMARY` | `false` | set to `true` to enable the *Summarize* button |
| `AI_SUMMARY_BACKEND` | `local` | `local` = `transformers.pipeline` on this machine; `api` = HF Inference API |
| `HF_SUMMARY_MODEL` | `sshleifer/distilbart-cnn-12-6` | any summarization model id |
| `HF_API_TOKEN` | — | required for `api` backend |

```bash
# Windows PowerShell
$env:ENABLE_AI_SUMMARY="true"; python app.py
```

The first summary downloads the model (about 1 GB for the local backend). Summaries appear in the alert detail panel under a clearly labeled **AI summary** heading.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | status, alert/rule counts, `ai_enabled` |
| POST | `/api/upload` | multipart field `file`; returns ingested count and warnings |
| GET | `/api/alerts` | query: `severity=high,critical`, `host`, `tactic`, `technique`, `q` |
| GET | `/api/alerts/<id>` | includes `raw` |
| DELETE | `/api/alerts` | clear all |
| GET | `/api/stats` | `by_severity`, `by_tactic`, `by_technique`, `over_time`, `hosts` (same filters) |
| GET | `/api/rules` | loaded rules |
| POST | `/api/rules/reload` | re-read the YAML and re-map alerts |
| POST | `/api/alerts/<id>/summarize` | 400 when AI is disabled |
