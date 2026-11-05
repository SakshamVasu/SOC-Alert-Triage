import {
  Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { SEVERITIES } from "../api.js";

// Keep in sync with the --sev-* variables in styles.css.
export const SEVERITY_COLORS = {
  critical: "#b42318",
  high: "#e8590c",
  medium: "#d4a20b",
  low: "#2f6fdb",
  informational: "#8a8f98",
};
const ACCENT = "#5b5bd6";
const UNMAPPED = "#c4c7cc";

function ChartCard({ title, children, hint }) {
  return (
    <div className="card chart">
      <div className="chart-head">
        <h3>{title}</h3>
        {hint && <span className="muted small">{hint}</span>}
      </div>
      <div className="chart-body">{children}</div>
    </div>
  );
}

const axis = { fontSize: 12, fill: "var(--muted)" };

export default function Charts({ stats, onSelect }) {
  const topTechniques = stats.by_technique.slice(0, 10).map((t) => ({
    ...t,
    label: t.technique_id === "Unmapped" ? "Unmapped" : `${t.technique_id} ${t.technique_name}`,
  }));
  const timeLabel = (b) => (stats.over_time.interval === "hour" ? b.slice(5, 16).replace("T", " ") : b.slice(5));

  return (
    <section className="charts">
      <ChartCard title="Alerts by severity" hint="click a bar to filter">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={stats.by_severity} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="severity" tick={axis} tickLine={false} />
            <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
            <Tooltip cursor={{ fill: "var(--hover)" }} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]} onClick={(d) => onSelect("severity", d.severity)} cursor="pointer">
              {stats.by_severity.map((d) => <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title={`Alerts over time (per ${stats.over_time.interval})`}>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={stats.over_time.series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="bucket" tickFormatter={timeLabel} tick={axis} tickLine={false} minTickGap={12} />
            <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
            <Tooltip cursor={{ fill: "var(--hover)" }} labelFormatter={timeLabel} />
            <Legend iconSize={10} wrapperStyle={{ fontSize: 12 }} />
            {SEVERITIES.map((s) => (
              <Bar key={s} dataKey={s} stackId="sev" fill={SEVERITY_COLORS[s]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Alerts by MITRE tactic" hint="click to filter">
        <ResponsiveContainer width="100%" height={Math.max(220, stats.by_tactic.length * 28)}>
          <BarChart data={stats.by_tactic} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
            <CartesianGrid horizontal={false} stroke="var(--grid)" />
            <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} />
            <YAxis type="category" dataKey="tactic" width={130} tick={axis} tickLine={false} />
            <Tooltip cursor={{ fill: "var(--hover)" }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} onClick={(d) => onSelect("tactic", d.tactic)} cursor="pointer">
              {stats.by_tactic.map((d) => <Cell key={d.tactic} fill={d.tactic === "Unmapped" ? UNMAPPED : ACCENT} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Top MITRE techniques" hint="click to filter">
        <ResponsiveContainer width="100%" height={Math.max(220, topTechniques.length * 28)}>
          <BarChart data={topTechniques} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
            <CartesianGrid horizontal={false} stroke="var(--grid)" />
            <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} />
            <YAxis type="category" dataKey="technique_id" width={80} tick={axis} tickLine={false} />
            <Tooltip cursor={{ fill: "var(--hover)" }} labelFormatter={(id) => topTechniques.find((t) => t.technique_id === id)?.label} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} onClick={(d) => onSelect("technique", d.technique_id)} cursor="pointer">
              {topTechniques.map((d) => <Cell key={d.technique_id} fill={d.technique_id === "Unmapped" ? UNMAPPED : ACCENT} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>
    </section>
  );
}
