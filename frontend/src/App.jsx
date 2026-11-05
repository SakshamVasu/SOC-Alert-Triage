import { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";
import UploadPanel from "./components/UploadPanel.jsx";
import Charts from "./components/Charts.jsx";
import Filters from "./components/Filters.jsx";
import AlertTable from "./components/AlertTable.jsx";
import AlertDetail from "./components/AlertDetail.jsx";

const EMPTY_FILTERS = { severity: [], host: "", tactic: "", technique: "", q: "" };

export default function App() {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);       // whole dataset: drives charts + host list
  const [alerts, setAlerts] = useState([]);       // filtered queue
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [selectedId, setSelectedId] = useState(null);
  const [error, setError] = useState("");
  const [version, setVersion] = useState(0);      // bump to refetch after upload/clear/reload

  const refresh = useCallback(() => setVersion((v) => v + 1), []);

  useEffect(() => {
    api.health().then(setHealth).catch((e) => setError(e.message));
  }, [version]);

  useEffect(() => {
    api.stats({}).then(setStats).catch((e) => setError(e.message));
  }, [version]);

  useEffect(() => {
    api.alerts(filters).then((r) => setAlerts(r.alerts)).catch((e) => setError(e.message));
  }, [filters, version]);

  // Clicking a chart bar narrows the queue to that severity / tactic / technique.
  const applyChartFilter = (key, value) =>
    setFilters((f) => ({ ...f, [key]: key === "severity" ? [value] : value }));

  const run = (fn) => async () => {
    setError("");
    try {
      await fn();
      setSelectedId(null);
      refresh();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>SOC Alert Triage</h1>
          <span className="muted">
            {health ? `${health.alerts} alerts · ${health.rules} MITRE rules` : "connecting…"}
            {health && (
              <span className={`pill ${health.ai_enabled ? "pill-on" : ""}`}>
                AI summaries {health.ai_enabled ? "on" : "off"}
              </span>
            )}
          </span>
        </div>
        <div className="actions">
          <button className="secondary" onClick={run(api.reloadRules)} title="Re-read mitre_rules.yaml and re-map all alerts">
            Reload rules
          </button>
          <button className="danger" onClick={run(api.clear)} disabled={!stats?.total}>
            Clear alerts
          </button>
        </div>
      </header>

      <main>
        <UploadPanel onUploaded={refresh} />
        {error && <div className="banner error">{error}</div>}

        {stats?.total ? (
          <>
            <Charts stats={stats} onSelect={applyChartFilter} />
            <section className="queue-layout">
              <div className="card queue">
                <Filters
                  filters={filters}
                  hosts={stats.hosts}
                  count={alerts.length}
                  onChange={setFilters}
                  onReset={() => setFilters(EMPTY_FILTERS)}
                />
                <AlertTable alerts={alerts} selectedId={selectedId} onSelect={setSelectedId} />
              </div>
              <AlertDetail
                alertId={selectedId}
                aiEnabled={health?.ai_enabled}
                onClose={() => setSelectedId(null)}
                version={version}
              />
            </section>
          </>
        ) : (
          <div className="card empty">
            No alerts loaded. Upload a Wazuh or Splunk export (JSON or CSV) — try the files in <code>samples/</code>.
          </div>
        )}
      </main>
    </div>
  );
}
