import { useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from "recharts";
import { apiGet } from "../lib/api";
import { useLiveData, useRealtimeStream } from "../lib/useRealtime";
import LiveBadge from "../components/LiveBadge";

interface ShapFeature {
  name: string; meanAbsShap: number; positiveShap: number; negativeShap: number; category: string;
}
interface ShapData {
  features: ShapFeature[];
  sampleCount: number;
  lastUpdated?: string;
}

const catColors: Record<string, string> = {
  network: "#22d3ee", memory: "#a78bfa", file: "#fb923c",
  registry: "#f87171", process: "#34d399", dll: "#4ade80",
  behavioral: "#c084fc", system: "#94a3b8", thread: "#818cf8",
  evasion: "#fca5a5", static: "#67e8f9", other: "#64748b",
};

export default function Shap() {
  const fetchFn = useCallback(() => apiGet<ShapData>("/models/shap"), []);
  const { data, loading, lastUpdated, refresh } = useLiveData(fetchFn, 8000);

  useRealtimeStream((e) => {
    if (e.type === "session_added") refresh();
  });

  if (loading) return <Spinner />;
  if (!data) return null;

  const chartData = data.features.map((f) => ({
    ...f,
    name: f.name.length > 30 ? f.name.slice(0, 27) + "..." : f.name,
    fullName: f.name,
    positiveShapPct: parseFloat((f.positiveShap * 100).toFixed(3)),
    negativeShapPct: parseFloat((Math.abs(f.negativeShap) * 100).toFixed(3)),
    meanAbsPct: parseFloat((f.meanAbsShap * 100).toFixed(3)),
  }));

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">SHAP Explainability Analysis</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Feature-confidence correlations from {data.sampleCount} real sessions — positive SHAP = correlation with malware classification
          </p>
        </div>
        <LiveBadge lastUpdated={lastUpdated} sampleCount={data.sampleCount} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <div className="text-2xl font-bold text-foreground tabular-nums">{data.sampleCount.toLocaleString()}</div>
          <div className="text-xs text-muted-foreground mt-1">Real Sessions Analyzed</div>
        </div>
        <div className="rounded-xl border border-green-500/30 bg-green-500/5 p-4 text-center">
          <div className="text-2xl font-bold text-green-400 tabular-nums">
            {(data.features[0]?.meanAbsShap * 100).toFixed(1)}%
          </div>
          <div className="text-xs text-muted-foreground mt-1">Top Feature Contribution</div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <div className="text-2xl font-bold text-foreground tabular-nums">{data.features.length}</div>
          <div className="text-xs text-muted-foreground mt-1">Features Explained</div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-bold text-foreground">SHAP Summary — Mean |SHAP| Values</div>
          <div className="text-xs text-muted-foreground mt-0.5">
            Correlation magnitude between each feature and the model's confidence score across {data.sampleCount} sessions
          </div>
        </div>
        <div className="p-4">
          <ResponsiveContainer width="100%" height={Math.max(360, chartData.length * 28)}>
            <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 80, left: 10, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} tickFormatter={(v) => `${v.toFixed(2)}%`} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 9.5, fill: "hsl(215 20% 65%)", fontFamily: "JetBrains Mono, monospace" }} width={185} />
              <Tooltip
                contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 12 }}
                formatter={(v: number, _n: string, props: { payload: typeof chartData[0] }) => [
                  `${v.toFixed(3)}%`, `${props.payload.fullName} [${props.payload.category}]`,
                ]}
              />
              <Bar dataKey="meanAbsPct" radius={[0, 3, 3, 0]} maxBarSize={20} name="Mean |SHAP|">
                {chartData.map((entry) => (
                  <Cell key={entry.fullName} fill={catColors[entry.category] ?? "#888"} opacity={0.9} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-bold text-foreground">Directional SHAP Contributions</div>
          <div className="text-xs text-muted-foreground mt-0.5">
            Positive = pushes toward malware. Negative = pushes toward benign.
          </div>
        </div>
        <div className="p-4">
          <ResponsiveContainer width="100%" height={Math.max(360, chartData.length * 28)}>
            <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 80, left: 10, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} tickFormatter={(v) => `${v.toFixed(2)}%`} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 9.5, fill: "hsl(215 20% 65%)", fontFamily: "JetBrains Mono, monospace" }} width={185} />
              <Tooltip contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 12 }} formatter={(v: number) => `${v.toFixed(3)}%`} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="positiveShapPct" name="Positive (→ Malware)" fill="hsl(0 72% 51%)" maxBarSize={20} opacity={0.85} />
              <Bar dataKey="negativeShapPct" name="Negative (→ Benign)" fill="hsl(160 84% 39%)" maxBarSize={20} opacity={0.85} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-bold text-foreground">SHAP Value Table</div>
          <div className="text-xs text-muted-foreground mt-0.5">Live-computed from real session data — updates on each new submission</div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Feature</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Category</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Mean |SHAP|</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Positive</th>
                <th className="text-right px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Negative</th>
              </tr>
            </thead>
            <tbody>
              {data.features.map((f, i) => (
                <tr key={f.name} className={`border-b border-border/40 hover:bg-muted/10 ${i % 2 === 0 ? "" : "bg-muted/5"}`}>
                  <td className="px-5 py-2.5 font-mono text-xs text-foreground">{f.name}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded capitalize border"
                      style={{ color: catColors[f.category] ?? "#888", borderColor: (catColors[f.category] ?? "#888") + "40", backgroundColor: (catColors[f.category] ?? "#888") + "15" }}>
                      {f.category}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-right text-xs font-semibold tabular-nums text-foreground">{(f.meanAbsShap * 100).toFixed(3)}%</td>
                  <td className="px-4 py-2.5 text-right text-xs tabular-nums text-red-400">+{(f.positiveShap * 100).toFixed(3)}%</td>
                  <td className="px-5 py-2.5 text-right text-xs tabular-nums text-green-400">{(f.negativeShap * 100).toFixed(3)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center h-96">
      <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );
}
