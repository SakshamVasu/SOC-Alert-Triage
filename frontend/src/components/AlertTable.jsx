export function SeverityBadge({ severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function formatTime(ts) {
  if (!ts) return "—";
  return ts.replace("T", " ").replace(/\.\d+/, "").replace("Z", " UTC");
}

export default function AlertTable({ alerts, selectedId, onSelect }) {
  if (!alerts.length) return <div className="empty">No alerts match the current filters.</div>;

  return (
    <div className="table-wrap">
      <table className="alerts">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Time</th>
            <th>Rule</th>
            <th>Host</th>
            <th>Source IP</th>
            <th>MITRE technique</th>
            <th>Tactic</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => {
            const primary = a.mitre[0];
            const unmapped = primary.technique_id === "Unmapped";
            return (
              <tr
                key={a.id}
                className={a.id === selectedId ? "selected" : ""}
                onClick={() => onSelect(a.id)}
                onKeyDown={(e) => e.key === "Enter" && onSelect(a.id)}
                tabIndex={0}
              >
                <td><SeverityBadge severity={a.severity} /></td>
                <td className="nowrap mono">{formatTime(a.timestamp)}</td>
                <td className="rule">
                  {a.rule_name}
                  <span className="muted small"> · {a.source}{a.rule_id ? ` #${a.rule_id}` : ""}</span>
                </td>
                <td className="nowrap">{a.host}</td>
                <td className="mono">{a.source_ip || "—"}</td>
                <td className={`technique ${unmapped ? "muted" : ""}`}>
                  {unmapped ? "Unmapped" : (
                    <>
                      <span className="mono">{primary.technique_id}</span> {primary.technique_name}
                      {a.mitre.length > 1 && <span className="muted small"> +{a.mitre.length - 1}</span>}
                    </>
                  )}
                </td>
                <td className={`nowrap ${unmapped ? "muted" : ""}`}>{primary.tactic}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
