import { useCallback } from "react";
import { apiGet } from "../lib/api";
import { useLiveData, useRealtimeStream } from "../lib/useRealtime";
import LiveBadge from "../components/LiveBadge";

interface ConfusionData {
  labels: string[];
  matrix: number[][];
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  sampleCount?: number;
  lastUpdated?: string;
}

export default function ConfusionMatrix() {
  const fetchFn = useCallback(() => apiGet<ConfusionData>("/models/confusion-matrix"), []);
  const { data, loading, lastUpdated, refresh } = useLiveData(fetchFn, 8000);

  useRealtimeStream((e) => {
    if (e.type === "session_added") refresh();
  });

  if (loading) return <Spinner />;
  if (!data) return null;

  const maxVal = Math.max(...data.matrix.flat().filter((v) => v > 0), 1);
  const total = data.matrix.flat().reduce((a, b) => a + b, 0);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Confusion Matrix</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Classification results derived from real analysis sessions — updates automatically as new data arrives
          </p>
        </div>
        <LiveBadge lastUpdated={lastUpdated} sampleCount={data.sampleCount} />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Accuracy", value: `${(data.accuracy * 100).toFixed(2)}%` },
          { label: "Precision", value: `${(data.precision * 100).toFixed(2)}%` },
          { label: "Recall", value: `${(data.recall * 100).toFixed(2)}%` },
          { label: "F1 Score", value: `${(data.f1Score * 100).toFixed(2)}%` },
        ].map((m) => (
          <div key={m.label} className="rounded-xl border border-border bg-card p-4 text-center">
            <div className="text-xs text-muted-foreground uppercase tracking-widest mb-1">{m.label}</div>
            <div className="text-2xl font-bold tabular-nums text-foreground">{m.value}</div>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between">
          <div>
            <div className="text-sm font-bold text-foreground">Classification Matrix</div>
            <div className="text-xs text-muted-foreground mt-0.5">
              {total} classifications from {data.sampleCount ?? 0} real sessions — rows: Actual, Cols: Predicted
            </div>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
            <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-green-500 opacity-70" /><span>Correct</span></div>
            <div className="flex items-center gap-1"><div className="w-3 h-3 rounded bg-red-500 opacity-50" /><span>Error</span></div>
          </div>
        </div>
        <div className="p-4 overflow-x-auto">
          <div className="flex">
            <div className="shrink-0 w-6 flex items-center justify-center mr-2">
              <span className="text-[10px] text-muted-foreground -rotate-90 whitespace-nowrap tracking-widest uppercase">Actual</span>
            </div>
            <div className="flex-1">
              <div className="flex mb-1 ml-[120px]">
                <div className="flex-1 text-center text-[10px] text-muted-foreground font-semibold uppercase tracking-widest mb-1">Predicted</div>
              </div>
              <div className="flex mb-1 ml-[120px]">
                {data.labels.map((label) => (
                  <div key={label} className="flex-1 text-center text-[9px] text-muted-foreground font-semibold px-0.5" style={{ minWidth: 56 }}>
                    {label.length > 8 ? label.slice(0, 7) + "…" : label}
                  </div>
                ))}
              </div>
              {data.matrix.map((row, i) => (
                <div key={data.labels[i]} className="flex items-center mb-1">
                  <div className="w-[120px] shrink-0 text-right pr-3 text-xs font-semibold text-muted-foreground truncate">
                    {data.labels[i]}
                  </div>
                  {row.map((val, j) => {
                    const isDiag = i === j;
                    const intensity = val / maxVal;
                    const bgColor = isDiag
                      ? `rgba(52, 211, 153, ${0.1 + intensity * 0.6})`
                      : val > 0
                        ? `rgba(239, 68, 68, ${0.05 + intensity * 0.55})`
                        : "rgba(255,255,255,0.02)";
                    return (
                      <div
                        key={j}
                        className="flex-1 flex items-center justify-center rounded-sm mx-0.5 text-xs font-bold tabular-nums transition-all"
                        style={{
                          minWidth: 56, height: 44,
                          background: bgColor,
                          color: val > 0 ? (isDiag ? "hsl(160 84% 70%)" : "hsl(0 72% 70%)") : "hsl(215 20% 30%)",
                          border: isDiag ? "1px solid rgba(52,211,153,0.2)" : "1px solid rgba(255,255,255,0.04)",
                        }}
                        title={`Actual: ${data.labels[i]} → Predicted: ${data.labels[j]} = ${val}`}
                      >
                        {val}
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-bold text-foreground">Per-Class Performance</div>
          <div className="text-xs text-muted-foreground mt-0.5">Precision, Recall, and F1 computed from real session classifications</div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Class</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">TP</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">FP</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">FN</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Precision</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Recall</th>
                <th className="text-right px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">F1</th>
              </tr>
            </thead>
            <tbody>
              {data.labels.map((label, i) => {
                const tp = data.matrix[i][i];
                const fp = data.matrix.reduce((sum, row, ri) => ri !== i ? sum + row[i] : sum, 0);
                const fn = data.matrix[i].reduce((sum, v, ci) => ci !== i ? sum + v : sum, 0);
                const prec = tp / (tp + fp || 1);
                const rec = tp / (tp + fn || 1);
                const f1 = 2 * prec * rec / (prec + rec || 1);
                return (
                  <tr key={label} className="border-b border-border/40 hover:bg-muted/10">
                    <td className="px-5 py-2.5 text-xs font-semibold text-foreground">{label}</td>
                    <td className="px-4 py-2.5 text-right text-xs text-green-400 tabular-nums font-bold">{tp}</td>
                    <td className="px-4 py-2.5 text-right text-xs text-red-400 tabular-nums">{fp}</td>
                    <td className="px-4 py-2.5 text-right text-xs text-orange-400 tabular-nums">{fn}</td>
                    <td className="px-4 py-2.5 text-right text-xs tabular-nums">{tp + fp > 0 ? `${(prec * 100).toFixed(1)}%` : "—"}</td>
                    <td className="px-4 py-2.5 text-right text-xs tabular-nums">{tp + fn > 0 ? `${(rec * 100).toFixed(1)}%` : "—"}</td>
                    <td className="px-5 py-2.5 text-right text-xs font-bold tabular-nums text-primary">
                      {tp + fp + fn > 0 ? `${(f1 * 100).toFixed(1)}%` : "—"}
                    </td>
                  </tr>
                );
              })}
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
