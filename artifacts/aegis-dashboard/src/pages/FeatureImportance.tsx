import { useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { apiGet } from "../lib/api";
import { useLiveData, useRealtimeStream } from "../lib/useRealtime";
import LiveBadge from "../components/LiveBadge";
import { useState } from "react";

interface FeatureImportanceItem { name: string; importance: number; category: string; }
interface FeatureImportanceData {
  features: FeatureImportanceItem[];
  modelType: string;
  sampleCount?: number;
  lastUpdated?: string;
}

const catColors: Record<string, string> = {
  network: "hsl(200 95% 55%)", memory: "hsl(280 87% 65%)", file: "hsl(38 92% 50%)",
  registry: "hsl(0 72% 51%)", process: "hsl(160 84% 39%)", dll: "hsl(160 60% 55%)",
  behavioral: "hsl(300 70% 60%)", system: "hsl(215 20% 65%)", thread: "hsl(250 80% 65%)",
  evasion: "hsl(0 60% 70%)", static: "hsl(180 60% 50%)", other: "hsl(215 20% 55%)",
};

export default function FeatureImportance() {
  const [highlighted, setHighlighted] = useState<string | null>(null);
  const fetchFn = useCallback(() => apiGet<FeatureImportanceData>("/models/feature-importance"), []);
  const { data, loading, lastUpdated, refresh } = useLiveData(fetchFn, 8000);

  useRealtimeStream((e) => {
    if (e.type === "session_added") refresh();
  });

  if (loading) return <Spinner />;
  if (!data) return null;

  const top30 = data.features.slice(0, 30).map((f) => ({
    ...f,
    importancePct: parseFloat((f.importance * 100).toFixed(3)),
    shortName: f.name.length > 28 ? f.name.slice(0, 25) + "..." : f.name,
  }));

  const categories = [...new Set(data.features.map((f) => f.category))];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Feature Importance</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Computed from real session features — importance = separation between malware and benign feature distributions
          </p>
        </div>
        <LiveBadge lastUpdated={lastUpdated} sampleCount={data.sampleCount} />
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setHighlighted(null)}
          className={`text-xs px-3 py-1.5 rounded-full border transition-all ${
            !highlighted ? "border-primary bg-primary/20 text-primary" : "border-border text-muted-foreground hover:border-border/60"
          }`}
        >
          All
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setHighlighted(highlighted === cat ? null : cat)}
            className="text-xs px-3 py-1.5 rounded-full border transition-all flex items-center gap-1.5"
            style={highlighted === cat
              ? { borderColor: catColors[cat], color: catColors[cat], backgroundColor: catColors[cat] + "20" }
              : { borderColor: "hsl(217 33% 17%)", color: "hsl(215 20% 55%)" }
            }
          >
            <span className="w-2 h-2 rounded-full" style={{ background: catColors[cat] ?? "#888" }} />
            {cat}
          </button>
        ))}
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-bold text-foreground">Feature Importance Scores</div>
          <div className="text-xs text-muted-foreground mt-0.5">
            Derived from {data.sampleCount ?? 0} real sessions — separation between malware/benign feature distributions
          </div>
        </div>
        <div className="p-4">
          <ResponsiveContainer width="100%" height={Math.max(400, top30.length * 20)}>
            <BarChart data={top30} layout="vertical" margin={{ top: 5, right: 80, left: 10, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} tickFormatter={(v) => `${v.toFixed(2)}%`} />
              <YAxis type="category" dataKey="shortName" tick={{ fontSize: 9.5, fill: "hsl(215 20% 65%)", fontFamily: "JetBrains Mono, monospace" }} width={180} />
              <Tooltip
                contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 12 }}
                formatter={(v: number, _n: string, props: { payload: FeatureImportanceItem }) => [
                  `${v.toFixed(3)}%`, `${props.payload.name} [${props.payload.category}]`,
                ]}
              />
              <Bar dataKey="importancePct" radius={[0, 3, 3, 0]} maxBarSize={18}>
                {top30.map((entry) => (
                  <Cell key={entry.name} fill={catColors[entry.category] ?? "hsl(160 84% 39%)"} opacity={highlighted && highlighted !== entry.category ? 0.15 : 1} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-bold text-foreground">Feature Detail Table</div>
          <div className="text-xs text-muted-foreground mt-0.5">
            Live-computed from {data.sampleCount ?? 0} sessions — refreshes every 8s and on new submissions
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Rank</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Feature Name</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Category</th>
                <th className="text-right px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Importance</th>
              </tr>
            </thead>
            <tbody>
              {top30.map((f, i) => (
                <tr key={f.name} className={`border-b border-border/40 hover:bg-muted/10 transition-colors ${highlighted && highlighted !== f.category ? "opacity-25" : ""}`}>
                  <td className="px-5 py-2.5 text-xs text-muted-foreground tabular-nums font-mono">#{i + 1}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-foreground">{f.name}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded capitalize border"
                      style={{ color: catColors[f.category] ?? "#888", borderColor: (catColors[f.category] ?? "#888") + "40", backgroundColor: (catColors[f.category] ?? "#888") + "15" }}>
                      {f.category}
                    </span>
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-20 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div className="h-full rounded-full"
                          style={{ width: `${(f.importance / (top30[0]?.importance || 1)) * 100}%`, background: catColors[f.category] ?? "hsl(160 84% 39%)" }} />
                      </div>
                      <span className="text-xs font-semibold tabular-nums text-foreground w-14 text-right">
                        {(f.importance * 100).toFixed(3)}%
                      </span>
                    </div>
                  </td>
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
