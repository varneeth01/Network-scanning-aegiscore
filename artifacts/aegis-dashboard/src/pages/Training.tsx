import { useCallback } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceLine } from "recharts";
import { apiGet } from "../lib/api";
import { useLiveData, useRealtimeStream } from "../lib/useRealtime";
import LiveBadge from "../components/LiveBadge";

interface LightgbmData {
  rounds: number[]; trainLoss: number[]; validLoss: number[];
  earlyStopRound: number; bestScore: number; finalAccuracy: number;
  sampleCount?: number; lastUpdated?: string;
}
interface LstmData {
  epochs: number[]; trainAccuracy: number[]; validAccuracy: number[];
  trainLoss: number[]; validLoss: number[];
  earlyStopEpoch: number; bestValidAccuracy: number;
  sampleCount?: number; lastUpdated?: string;
}

export default function Training() {
  const lgbmFetch = useCallback(() => apiGet<LightgbmData>("/models/lightgbm/training"), []);
  const lstmFetch = useCallback(() => apiGet<LstmData>("/models/lstm/training"), []);

  const { data: lgbm, loading: lgbmLoading, lastUpdated: lgbmUpdated, refresh: refreshLgbm } = useLiveData(lgbmFetch, 8000);
  const { data: lstm, loading: lstmLoading, lastUpdated: lstmUpdated, refresh: refreshLstm } = useLiveData(lstmFetch, 8000);

  useRealtimeStream((e) => {
    if (e.type === "session_added") {
      refreshLgbm();
      refreshLstm();
    }
  });

  const loading = lgbmLoading && lstmLoading;
  if (loading) return <Spinner />;

  const lgbmChart = lgbm ? lgbm.rounds.filter((_, i) => i % Math.max(1, Math.floor(lgbm.rounds.length / 60)) === 0).map((r, idx) => {
    const realIdx = idx * Math.max(1, Math.floor(lgbm.rounds.length / 60));
    return { round: r, trainLoss: lgbm.trainLoss[realIdx], validLoss: lgbm.validLoss[realIdx] };
  }) : [];

  const lstmAccChart = lstm ? lstm.epochs.filter((_, i) => i % Math.max(1, Math.floor(lstm.epochs.length / 60)) === 0).map((e, idx) => {
    const realIdx = idx * Math.max(1, Math.floor(lstm.epochs.length / 60));
    return {
      epoch: e,
      trainAcc: parseFloat((lstm.trainAccuracy[realIdx] * 100).toFixed(2)),
      validAcc: parseFloat((lstm.validAccuracy[realIdx] * 100).toFixed(2)),
    };
  }) : [];

  const lstmLossChart = lstm ? lstm.epochs.filter((_, i) => i % Math.max(1, Math.floor(lstm.epochs.length / 60)) === 0).map((e, idx) => {
    const realIdx = idx * Math.max(1, Math.floor(lstm.epochs.length / 60));
    return { epoch: e, trainLoss: lstm.trainLoss[realIdx], validLoss: lstm.validLoss[realIdx] };
  }) : [];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Model Training Analysis</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Training curves update dynamically as new analysis sessions are submitted
          </p>
        </div>
        <LiveBadge lastUpdated={lgbmUpdated} sampleCount={lgbm?.sampleCount} />
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-sm font-bold text-foreground">LightGBM Training Progress</div>
              <div className="text-xs text-muted-foreground mt-0.5">
                Gradient boosting loss over {lgbm?.earlyStopRound ?? "—"} rounds — recomputed from {lgbm?.sampleCount ?? 0} real sessions
              </div>
            </div>
            <div className="flex gap-3">
              <MetricPill label="Rounds" value={`${lgbm?.earlyStopRound ?? "—"}`} color="yellow" />
              <MetricPill label="Best Valid Loss" value={lgbm?.bestScore.toFixed(4) ?? "--"} color="green" />
              <MetricPill label="Accuracy" value={`${((lgbm?.finalAccuracy ?? 0) * 100).toFixed(1)}%`} color="primary" />
            </div>
          </div>
        </div>
        <div className="p-5">
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={lgbmChart} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
              <XAxis dataKey="round" tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }} label={{ value: "Boosting Round", position: "insideBottom", offset: -2, style: { fill: "hsl(215 20% 55%)", fontSize: 11 } }} />
              <YAxis tick={{ fontSize: 11, fill: "hsl(215 20% 55%)" }} label={{ value: "Loss", angle: -90, position: "insideLeft", style: { fill: "hsl(215 20% 55%)", fontSize: 11 } }} />
              <Tooltip contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <ReferenceLine x={lgbm?.earlyStopRound} stroke="hsl(38 92% 50%)" strokeDasharray="4 4" label={{ value: "Early Stop", fill: "hsl(38 92% 50%)", fontSize: 10 }} />
              <Line type="monotone" dataKey="trainLoss" stroke="hsl(160 84% 39%)" dot={false} strokeWidth={2} name="Train Loss" />
              <Line type="monotone" dataKey="validLoss" stroke="hsl(200 95% 55%)" dot={false} strokeWidth={2} name="Valid Loss" strokeDasharray="5 3" />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="px-5 pb-5">
          <div className="terminal">
            <div className="text-green-300 text-[11px] space-y-0.5">
              <div>[INFO] LightGBM v3.3.5 — Trained on {lgbm?.sampleCount ?? 0} real sessions</div>
              <div>[INFO] num_class=8, num_leaves=127, learning_rate=0.05</div>
              {lgbm && lgbmChart.filter((_, i) => [2, 5, 8, 11].includes(i)).map((d, i) => (
                <div key={i}>[INFO] Round {d.round}: train_loss={d.trainLoss?.toFixed(4)}, valid_loss={d.validLoss?.toFixed(4)}</div>
              ))}
              <div className="text-yellow-400">[WARN] Early stopping at round {lgbm?.earlyStopRound} — no improvement for 50 rounds</div>
              <div className="text-green-400">[DONE] best_valid_loss={lgbm?.bestScore.toFixed(4)}, accuracy={((lgbm?.finalAccuracy ?? 0) * 100).toFixed(2)}%</div>
              <div className="text-cyan-400">[LIVE] Last updated: {lgbmUpdated?.toLocaleTimeString() ?? "—"} | Data: {lgbm?.lastUpdated ? new Date(lgbm.lastUpdated).toLocaleTimeString() : "—"}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-sm font-bold text-foreground">Bidirectional LSTM Training Curves</div>
              <div className="text-xs text-muted-foreground mt-0.5">
                Deep sequence model over {lstm?.earlyStopEpoch ?? "—"} epochs — recomputed from {lstm?.sampleCount ?? 0} real sessions
              </div>
            </div>
            <div className="flex gap-3">
              <MetricPill label="Epochs" value={`${lstm?.earlyStopEpoch ?? "—"}`} color="yellow" />
              <MetricPill label="Best Val Acc" value={`${((lstm?.bestValidAccuracy ?? 0) * 100).toFixed(2)}%`} color="primary" />
              <LiveBadge lastUpdated={lstmUpdated} compact />
            </div>
          </div>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 divide-y lg:divide-y-0 lg:divide-x divide-border">
          <div className="p-5">
            <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3">Accuracy Curves</div>
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={lstmAccChart} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
                <XAxis dataKey="epoch" tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} label={{ value: "Epoch", position: "insideBottom", offset: -2, style: { fill: "hsl(215 20% 55%)", fontSize: 10 } }} />
                <YAxis domain={[40, 100]} tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} />
                <Tooltip contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => [`${v.toFixed(2)}%`]} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <ReferenceLine x={lstm?.earlyStopEpoch} stroke="hsl(38 92% 50%)" strokeDasharray="4 4" />
                <Line type="monotone" dataKey="trainAcc" stroke="hsl(160 84% 39%)" dot={false} strokeWidth={2} name="Train Acc" />
                <Line type="monotone" dataKey="validAcc" stroke="hsl(280 87% 65%)" dot={false} strokeWidth={2} name="Valid Acc" strokeDasharray="5 3" />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="p-5">
            <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3">Loss Curves</div>
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={lstmLossChart} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
                <XAxis dataKey="epoch" tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} />
                <YAxis tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }} />
                <Tooltip contentStyle={{ background: "hsl(222 47% 10%)", border: "1px solid hsl(217 33% 17%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => [v.toFixed(4)]} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="trainLoss" stroke="hsl(200 95% 55%)" dot={false} strokeWidth={2} name="Train Loss" />
                <Line type="monotone" dataKey="validLoss" stroke="hsl(0 72% 51%)" dot={false} strokeWidth={2} name="Valid Loss" strokeDasharray="5 3" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="px-5 pb-5">
          <div className="terminal">
            <div className="text-green-300 text-[11px] space-y-0.5">
              <div>[INFO] BiLSTM — 3 layers, 256 hidden units, dropout=0.3, trained on {lstm?.sampleCount ?? 0} sessions</div>
              {lstmAccChart.filter((_, i) => [5, 15, 30, 50].includes(i)).map((d, i) => (
                <div key={i}>[INFO] Epoch {d.epoch}/{lstm?.earlyStopEpoch}: train_acc={d.trainAcc?.toFixed(2)}%, val_acc={d.validAcc?.toFixed(2)}%</div>
              ))}
              <div className="text-yellow-400">[WARN] Early stopping at epoch {lstm?.earlyStopEpoch} — val_acc plateau</div>
              <div className="text-green-400">[DONE] Best val_accuracy={((lstm?.bestValidAccuracy ?? 0) * 100).toFixed(2)}% — checkpoint saved</div>
              <div className="text-cyan-400">[LIVE] Curves recomputed from actual session data — refreshes on new submissions</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricPill({ label, value, color }: { label: string; value: string; color: string }) {
  const colors: Record<string, string> = {
    primary: "border-primary/30 text-primary bg-primary/10",
    green: "border-green-500/30 text-green-400 bg-green-500/10",
    yellow: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return (
    <div className={`px-3 py-1.5 rounded-lg border text-center ${colors[color] ?? colors.primary}`}>
      <div className="text-[10px] opacity-70">{label}</div>
      <div className="text-sm font-bold tabular-nums">{value}</div>
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
