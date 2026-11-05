import { useEffect, useState } from "react";
import { api } from "../api.js";
import { SeverityBadge, formatTime } from "./AlertTable.jsx";

// T1059.001 -> https://attack.mitre.org/techniques/T1059/001/
const attackUrl = (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

export default function AlertDetail({ alertId, aiEnabled, onClose, version }) {
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState("");
  const [summarizing, setSummarizing] = useState(false);

  useEffect(() => {
    setAlert(null);
    setError("");
    if (alertId == null) return;
    api.alert(alertId).then(setAlert).catch((e) => setError(e.message));
  }, [alertId, version]);

  async function summarize() {
    setSummarizing(true);
    setError("");
    try {
      const r = await api.summarize(alertId);
      setAlert((a) => ({ ...a, summary: r.summary }));
    } catch (e) {
      setError(e.message);
    } finally {
      setSummarizing(false);
    }
  }

  if (alertId == null) {
    return <aside className="card detail empty">Select an alert to see its details.</aside>;
  }
  if (!alert) {
    return <aside className="card detail">{error ? <div className="banner error">{error}</div> : "Loading…"}</aside>;
  }

  const fields = [
    ["Time", formatTime(alert.timestamp)],
    ["Host", alert.host],
    ["Source IP", alert.source_ip || "—"],
    ["Rule ID", alert.rule_id || "—"],
    ["Category", alert.category || "—"],
    ["Source", `${alert.source} · ${alert.file}`],
  ];

  return (
    <aside className="card detail">
      <div className="detail-head">
        <SeverityBadge severity={alert.severity} />
        <button className="link" onClick={onClose} aria-label="Close details">✕</button>
      </div>
      <h2>{alert.rule_name}</h2>

      <dl className="fields">
        {fields.map(([k, v]) => (
          <div key={k}><dt>{k}</dt><dd>{v}</dd></div>
        ))}
      </dl>

      <h3>MITRE ATT&amp;CK</h3>
      <table className="mitre">
        <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th></tr></thead>
        <tbody>
          {alert.mitre.map((m) => (
            <tr key={m.technique_id}>
              <td className="mono">
                {m.technique_id === "Unmapped" ? "Unmapped" : (
                  <a href={attackUrl(m.technique_id)} target="_blank" rel="noreferrer">{m.technique_id}</a>
                )}
              </td>
              <td>{m.technique_name}</td>
              <td>{m.tactic}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {alert.mitre[0].rule && <p className="muted small">Matched rule: “{alert.mitre[0].rule}” in mitre_rules.yaml</p>}

      {aiEnabled && (
        <div className="ai">
          <div className="ai-head">
            <h3>AI summary <span className="pill">pretrained model · verify before acting</span></h3>
            <button onClick={summarize} disabled={summarizing}>
              {summarizing ? "Summarizing…" : alert.summary ? "Regenerate" : "Summarize"}
            </button>
          </div>
          <p className="summary">{alert.summary || <span className="muted">No summary yet.</span>}</p>
        </div>
      )}

      {error && <div className="banner error">{error}</div>}

      <h3>Description</h3>
      <pre className="description">{alert.description || "—"}</pre>

      <details>
        <summary>Raw event</summary>
        <pre className="raw">{JSON.stringify(alert.raw, null, 2)}</pre>
      </details>
    </aside>
  );
}
