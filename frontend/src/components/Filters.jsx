import { SEVERITIES } from "../api.js";

export default function Filters({ filters, hosts, count, onChange, onReset }) {
  const set = (key, value) => onChange({ ...filters, [key]: value });
  const toggleSeverity = (s) =>
    set("severity", filters.severity.includes(s) ? filters.severity.filter((x) => x !== s) : [...filters.severity, s]);
  const active = filters.severity.length || filters.host || filters.tactic || filters.technique || filters.q;

  return (
    <div className="filters">
      <div className="filter-row">
        <span className="label">Severity</span>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            className={`chip sev-${s} ${filters.severity.includes(s) ? "chip-on" : ""}`}
            onClick={() => toggleSeverity(s)}
            aria-pressed={filters.severity.includes(s)}
          >
            {s}
          </button>
        ))}
      </div>
      <div className="filter-row">
        <label className="label" htmlFor="host-filter">Host</label>
        <select id="host-filter" value={filters.host} onChange={(e) => set("host", e.target.value)}>
          <option value="">All hosts</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <input
          type="search"
          placeholder="Search rule, description, IP…"
          value={filters.q}
          onChange={(e) => set("q", e.target.value)}
        />
        {filters.tactic && <button className="chip chip-on" onClick={() => set("tactic", "")}>tactic: {filters.tactic} ✕</button>}
        {filters.technique && <button className="chip chip-on" onClick={() => set("technique", "")}>technique: {filters.technique} ✕</button>}
        <span className="spacer" />
        <span className="muted">{count} shown</span>
        {active ? <button className="link" onClick={onReset}>Reset filters</button> : null}
      </div>
    </div>
  );
}
