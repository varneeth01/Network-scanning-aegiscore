import { useEffect, useState } from "react";
import { Link } from "wouter";
import { Shield, AlertTriangle, CheckCircle, Activity, TrendingUp, Zap } from "lucide-react";
import { apiGet } from "../lib/api";
import ThreatBadge from "../components/ThreatBadge";
import { useRealtimeStream } from "../lib/useRealtime";

interface DashboardStats {
  totalAnalyzed: number;
  malwareDetected: number;
  benignFiles: number;
  activeSessionsCount: number;
  avgConfidence: number;
  detectionRate: number;
  recentSessions: Session[];
}

interface Session {
  id: string;
  inputType: string;
  classification: string;
  confidence: number;
  threatLevel: string;
  timestamp: string;
  status: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    apiGet<DashboardStats>("/dashboard/stats")
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  useRealtimeStream((e) => {
    if (e.type === "session_added" || e.type === "stats_update") load();
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center space-y-3">
          <div className="w-10 h-10 rounded-full border-2 border-primary border-t-transparent animate-spin mx-auto" />
          <div className="text-sm text-muted-foreground">Loading dashboard...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">AegisCore Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Hybrid LightGBM + BiLSTM Ensemble — Real-time malware detection &amp; zero-day analysis
          </p>
        </div>
        <Link href="/analyze">
          <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors">
            <Zap className="w-4 h-4" />
            New Analysis
          </button>
        </Link>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<Shield className="w-5 h-5 text-primary" />}
          label="Total Analyzed"
          value={stats?.totalAnalyzed ?? 0}
          sub="All-time submissions"
          color="primary"
        />
        <StatCard
          icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
          label="Threats Detected"
          value={stats?.malwareDetected ?? 0}
          sub={`${((stats?.detectionRate ?? 0) * 100).toFixed(1)}% detection rate`}
          color="red"
        />
        <StatCard
          icon={<CheckCircle className="w-5 h-5 text-green-400" />}
          label="Benign"
          value={stats?.benignFiles ?? 0}
          sub="Clean samples confirmed"
          color="green"
        />
        <StatCard
          icon={<Activity className="w-5 h-5 text-blue-400" />}
          label="Avg Confidence"
          value={`${((stats?.avgConfidence ?? 0) * 100).toFixed(1)}%`}
          sub="Ensemble model accuracy"
          color="blue"
        />
      </div>

      {/* Quick nav panels */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <QuickPanel
          href="/sandbox"
          icon={<Activity className="w-5 h-5 text-primary" />}
          title="Sandbox Execution"
          desc="Live system call and network monitoring of executing samples"
          badge="LIVE"
        />
        <QuickPanel
          href="/training"
          icon={<TrendingUp className="w-5 h-5 text-purple-400" />}
          title="Model Training"
          desc="LightGBM (423 rounds) + BiLSTM (847 epochs) training curves"
          badge="97.3%"
        />
        <QuickPanel
          href="/performance"
          icon={<Shield className="w-5 h-5 text-blue-400" />}
          title="Performance Comparison"
          desc="SVM vs Random Forest vs LightGBM hybrid ensemble"
          badge="BEST"
        />
      </div>

      {/* Recent sessions */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-foreground">Recent Analysis Sessions</div>
            <div className="text-xs text-muted-foreground mt-0.5">Latest malware analysis submissions</div>
          </div>
          <Link href="/analyze">
            <button className="text-xs text-primary hover:text-primary/80 transition-colors">
              New analysis →
            </button>
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-5 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Session ID</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Source</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Classification</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Threat</th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Confidence</th>
                <th className="text-right px-5 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Time</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.recentSessions ?? []).map((s, i) => (
                <tr key={s.id} className={`border-b border-border/50 hover:bg-muted/20 transition-colors ${i % 2 === 0 ? "" : "bg-muted/5"}`}>
                  <td className="px-5 py-3">
                    <code className="text-xs text-muted-foreground font-mono">{s.id}</code>
                  </td>
                  <td className="px-4 py-3">
                    <SourceBadge type={s.inputType} />
                  </td>
                  <td className="px-4 py-3 font-medium text-foreground">{s.classification}</td>
                  <td className="px-4 py-3">
                    <ThreatBadge level={s.threatLevel} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <ConfBar value={s.confidence} />
                  </td>
                  <td className="px-5 py-3 text-right text-xs text-muted-foreground">
                    {formatTime(s.timestamp)}
                  </td>
                </tr>
              ))}
              {(!stats?.recentSessions?.length) && (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-muted-foreground text-sm">
                    No analysis sessions yet. Submit your first sample.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, sub, color }: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub: string;
  color: string;
}) {
  const borders: Record<string, string> = {
    primary: "border-primary/30 hover:border-primary/50",
    red: "border-red-500/30 hover:border-red-500/50",
    green: "border-green-500/30 hover:border-green-500/50",
    blue: "border-blue-500/30 hover:border-blue-500/50",
  };
  return (
    <div className={`rounded-xl border bg-card p-5 transition-all ${borders[color] ?? borders.primary}`}>
      <div className="flex items-start justify-between">
        <div className="p-2 rounded-lg bg-muted/30">{icon}</div>
      </div>
      <div className="mt-3 text-2xl font-bold text-foreground tabular-nums">{value}</div>
      <div className="text-xs font-medium text-muted-foreground mt-0.5">{label}</div>
      <div className="text-[10px] text-muted-foreground/70 mt-1">{sub}</div>
    </div>
  );
}

function QuickPanel({ href, icon, title, desc, badge }: {
  href: string; icon: React.ReactNode; title: string; desc: string; badge: string;
}) {
  return (
    <Link href={href}>
      <div className="rounded-xl border border-border bg-card p-5 hover:border-primary/40 hover:bg-primary/5 transition-all cursor-pointer group">
        <div className="flex items-start justify-between mb-3">
          <div className="p-2 rounded-lg bg-muted/30">{icon}</div>
          <span className="text-[10px] font-bold text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded tracking-widest">
            {badge}
          </span>
        </div>
        <div className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">{title}</div>
        <div className="text-xs text-muted-foreground mt-1 leading-relaxed">{desc}</div>
      </div>
    </Link>
  );
}

function SourceBadge({ type }: { type: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    wireshark: { label: "Wireshark", cls: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20" },
    browser: { label: "Browser", cls: "text-purple-400 bg-purple-400/10 border-purple-400/20" },
    file: { label: "File", cls: "text-orange-400 bg-orange-400/10 border-orange-400/20" },
    manual: { label: "Manual", cls: "text-gray-400 bg-gray-400/10 border-gray-400/20" },
  };
  const cfg = map[type] ?? map.manual;
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${cfg.cls}`}>
      {cfg.label}
    </span>
  );
}

function ConfBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct > 85 ? "bg-red-400" : pct > 65 ? "bg-orange-400" : pct > 40 ? "bg-yellow-400" : "bg-green-400";
  return (
    <div className="flex items-center gap-2 justify-end">
      <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-muted-foreground tabular-nums w-8 text-right">{pct}%</span>
    </div>
  );
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    if (diff < 60000) return "just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return d.toLocaleDateString();
  } catch {
    return iso;
  }
}
