import { useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis } from "recharts";
import { apiGet } from "../lib/api";
import { useLiveData, useRealtimeStream } from "../lib/useRealtime";
import LiveBadge from "../components/LiveBadge";
import { Trophy, TrendingUp, Zap } from "lucide-react";

interface ModelPerformance {
  name: string; accuracy: number; balancedAccuracy: number;
  sensitivity: number; specificity: number; f1Score: number; auc: number;
  note?: string; liveAccuracy?: number; sampleCount?: number;
}
interface PerformanceData {
  models: ModelPerformance[];
  lastUpdated?: string;
  liveSampleCount?: number;
}

const modelColors: Record<string, string> = {
  "SVM": "hsl(215 20% 55%)",
  "Random Forest": "hsl(200 95% 55%)",
  "LightGBM (Ours)": "hsl(160 84% 39%)",
};

export default function Performance() {
  const fetchFn = useCallback(() => apiGet<PerformanceData>("/models/performance-comparison"), []);
  const { data, loading, lastUpdated, refresh } = useLiveData(fetchFn, 8000);

  useRealtimeStream((e) => {
    if (e.type === "session_added") refresh();
  });

  if (loading) return <Spinner />;
  if (!data) return null;

  const metrics: (keyof ModelPerformance)[] = ["accuracy", "balancedAccuracy", "sensitivity", "specificity", "f1Score", "auc"];
  const metricLabels: Record<string, string> = {
    accuracy: "Accuracy", balancedAccuracy: "Balanced Accuracy",
    sensitivity: "Sensitivity", specificity: "Specificity", f1Score: "F1 Score", auc: "AUC-ROC",
  };

  const barData = metrics.map((m) => ({
    metric: metricLabels[m] ?? m,
    ...Object.fromEntries(data.models.map((mod) => [mod.name, parseFloat(((mod[m] as number) * 100).toFixed(2))])),
  }));

  const radarData = metrics.map((m) => ({
    metric: metricLabels[m].replace(" ", "\n"),
    ...Object.fromEntries(data.models.map((mod) => [mod.name, parseFloat(((mod[m] as number) * 100).toFixed(2))])),
  }));

  const bestModel = data.models.reduce((a, b) => a.accuracy > b.accuracy ? a : b);
  const liveModel = data.models.find((m) => m.note === "live");

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Model Performance Comparison</h1>
          <p className="text-sm text-muted-foreground mt-1">
            LightGBM metrics update live from {data.liveSampleCount ?? 0} real sessions — SVM/RF are reference baselines
          </p>
        </div>
        <LiveBadge lastUpdated={lastUpdated} sampleCount={data.liveSampleCount} />
      </div>

      {liveModel && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 p-4 flex items-center gap-4">
          <Zap className="w-5 h-5 text-primary shrink-0" />
          <div className="flex-1">
            <div className="text-sm font-bold text-primary">Live Model Accuracy</div>
            <div className="text-xs text-muted-foreground mt-0.5">
              LightGBM ensemble accuracy computed from {liveModel.sampleCount} real sessions. Recomputes on every new submission.
            </div>
          </div>
          <div className="text-2xl font-bold tabular-nums text-primary">
            {((liveModel.liveAccuracy ?? liveModel.accuracy) * 100).toFixed(1)}%
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {data.models.map((model) => {
          const isBest = model.name === bestModel.name;
          const isLive = model.note === "live";
          return (
            <div key={model.name} className={`rounded-xl border p-5 transition-all ${isBest ? "border-primary/40 bg-primary/5 ring-1 ring-primary/20" : "border-border bg-card"}`}>
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="text-sm font-bold text-foreground">{model.name}</div>
                  <div className="flex items-center gap-2 mt-1">
                    {isBest && (
                      <div className="flex items-center gap-1">
                        <Trophy className="w-3 h-3 text-yellow-400" />
                        <span className="text-[10px] text-yellow-400 font-bold">BEST</span>
                      </div>
                    )}
                    {isLive ? (
                      <div className="flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                        <span className="text-[10px] text-primary font-bold">LIVE DATA</span>
                      </div>
                    ) : (
                      <span className="text-[10px] text-muted-foreground">Baseline</span>
                    )}
                  </div>
                </div>
                <div className="text-2xl font-bold tabular-nums" style={{ color: modelColors[model.name] ?? "inherit" }}>
                  {(model.accuracy * 100).toFixed(1)}%
                </div>
              </div>
              <div className="space-y-2">
                {metrics.slice(1).map((m) => (
                  <div key={m} className="flex justify-between items-center">
                    <span className="text-xs text-muted-foreground">{metricLabels[m]}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${(model[m] as number) * 100}%`, background: modelColors[model.name] ?? "hsl(160 84% 39%)" }} />
                      </div>
                      <span className="text-xs font-semibold tabular-nums text-foreground w-10 text-right">
                        {((model[m] as number) * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-primary" />
            <div className="text-sm font-bold text-foreground">Side-by-Side Metric Comparison</div>
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">LightGBM values reflect live session data. Higher is better for all metrics.</div>
        </div>
        <div className="p-5">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={barData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
              <XAxis dataKey="metric" tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} />
              <YAxis domain={[80, 100]} tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} tickFormatter={(v) => `${v}%`} />
              <Tooltip contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 12 }} formatter={(v: number) => `${v.toFixed(2)}%`} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {data.models.map((model) => (
                <Bar key={model.name} dataKey={model.name} fill={modelColors[model.name] ?? "#888"} radius={[3, 3, 0, 0]} maxBarSize={50} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-sm font-bold text-foreground">Radar Performance Chart</div>
          </div>
          <div className="p-5">
            <ResponsiveContainer width="100%" height={300}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="hsl(217 33% 20%)" />
                <PolarAngleAxis dataKey="metric" tick={{ fontSize: 9, fill: "hsl(215 20% 55%)" }} />
                <PolarRadiusAxis angle={30} domain={[80, 100]} tick={{ fontSize: 8, fill: "hsl(215 20% 45%)" }} />
                <Tooltip contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => `${v.toFixed(2)}%`} />
                {data.models.map((model) => (
                  <Radar key={model.name} name={model.name} dataKey={model.name} stroke={modelColors[model.name] ?? "#888"} fill={modelColors[model.name] ?? "#888"} fillOpacity={0.15} strokeWidth={2} />
                ))}
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-sm font-bold text-foreground">Performance Summary Table</div>
            <div className="text-xs text-muted-foreground mt-0.5">★ = best score per metric</div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/20">
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Metric</th>
                  {data.models.map((m) => (
                    <th key={m.name} className="text-right px-3 py-2.5 text-xs font-semibold text-muted-foreground uppercase">
                      {m.name.replace(" (Ours)", "")}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {metrics.map((metric) => {
                  const vals = data.models.map((m) => (m[metric] as number) * 100);
                  const maxVal = Math.max(...vals);
                  return (
                    <tr key={metric} className="border-b border-border/40 hover:bg-muted/10">
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{metricLabels[metric]}</td>
                      {data.models.map((model) => {
                        const val = (model[metric] as number) * 100;
                        const isBest = Math.abs(val - maxVal) < 0.001;
                        return (
                          <td key={model.name} className={`px-3 py-2.5 text-right text-xs font-semibold tabular-nums ${isBest ? "text-primary" : "text-muted-foreground"}`}>
                            {val.toFixed(2)}%{isBest && " ★"}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
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
