import { useEffect, useState, useCallback } from "react";
import { Activity, RefreshCw, AlertTriangle, Shield } from "lucide-react";
import { apiGet } from "../lib/api";

interface SyscallEvent { id: number; name: string; category: string; count: number; timestamp: number; }
interface NetworkEvent { id: number; protocol: string; srcIp: string; dstIp: string; dstPort: number; bytes: number; timestamp: number; malicious: boolean; }
interface ProcessEvent { pid: number; name: string; parentPid: number; cmdLine: string; suspicious: boolean; }
interface SandboxData {
  sampleId: string; status: string;
  systemCalls: SyscallEvent[]; networkActivity: NetworkEvent[]; processTree: ProcessEvent[];
  totalSyscalls: number; totalNetworkConnections: number; runningTime: number;
}

const catColors: Record<string, string> = {
  file: "text-orange-400", network: "text-cyan-400", memory: "text-purple-400",
  process: "text-red-400", registry: "text-yellow-400", thread: "text-blue-400",
  dll: "text-green-400", system: "text-gray-400", sync: "text-pink-400", other: "text-muted-foreground",
};

export default function Sandbox() {
  const [data, setData] = useState<SandboxData | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"syscalls" | "network" | "process">("syscalls");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const load = useCallback(() => {
    apiGet<SandboxData>("/sandbox/events").then(setData).catch(console.error).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [autoRefresh, load]);

  if (loading) return <Spinner />;

  const maliciousNet = data?.networkActivity.filter((n) => n.malicious) ?? [];
  const suspProc = data?.processTree.filter((p) => p.suspicious) ?? [];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Sandbox Execution Monitor</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time system call and network activity during malware execution
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border transition-all ${
              autoRefresh
                ? "border-primary/40 bg-primary/10 text-primary"
                : "border-border bg-muted/20 text-muted-foreground"
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? "bg-primary animate-pulse" : "bg-muted-foreground"}`} />
            {autoRefresh ? "LIVE" : "Paused"}
          </button>
          <button onClick={load} className="p-2 rounded-lg border border-border hover:bg-muted/20 transition-colors text-muted-foreground hover:text-foreground">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Sample info + stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Sample ID</div>
          <code className="text-sm text-primary font-mono font-bold">{data?.sampleId}</code>
          <div className="flex items-center gap-1.5 mt-2">
            <span className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse" />
            <span className="text-xs text-yellow-400 font-semibold">EXECUTING</span>
          </div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Total Syscalls</div>
          <div className="text-2xl font-bold tabular-nums">{data?.totalSyscalls.toLocaleString()}</div>
          <div className="text-xs text-muted-foreground mt-1">{data?.systemCalls.length} unique calls</div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Network Connections</div>
          <div className="text-2xl font-bold tabular-nums text-red-400">{maliciousNet.length}
            <span className="text-base text-muted-foreground">/{data?.totalNetworkConnections}</span>
          </div>
          <div className="text-xs text-red-400 mt-1">malicious detected</div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Run Time</div>
          <div className="text-2xl font-bold tabular-nums">{data?.runningTime.toFixed(0)}s</div>
          <div className="text-xs text-muted-foreground mt-1">{suspProc.length} suspicious processes</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="flex border-b border-border">
          {[
            { key: "syscalls", label: "System Calls", count: data?.systemCalls.length },
            { key: "network", label: "Network Activity", count: data?.networkActivity.length },
            { key: "process", label: "Process Tree", count: data?.processTree.length },
          ].map(({ key, label, count }) => (
            <button
              key={key}
              onClick={() => setTab(key as typeof tab)}
              className={`px-5 py-3 text-sm font-medium border-b-2 transition-all ${
                tab === key
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
              <span className="ml-2 text-[10px] bg-muted/40 px-1.5 py-0.5 rounded">{count}</span>
            </button>
          ))}
        </div>

        {tab === "syscalls" && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/20">
                  <th className="text-left px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Syscall</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Category</th>
                  <th className="text-right px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Count</th>
                </tr>
              </thead>
              <tbody>
                {data?.systemCalls.sort((a, b) => b.count - a.count).map((s) => (
                  <tr key={s.id} className="border-b border-border/40 hover:bg-muted/10">
                    <td className="px-5 py-2.5">
                      <code className="text-xs font-mono text-foreground">{s.name}</code>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs font-semibold capitalize ${catColors[s.category] ?? "text-muted-foreground"}`}>
                        {s.category}
                      </span>
                    </td>
                    <td className="px-5 py-2.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-20 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${catColors[s.category]?.replace("text-", "bg-") ?? "bg-primary"}`}
                            style={{ width: `${Math.min(100, (s.count / 500) * 100)}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums text-muted-foreground w-10 text-right">{s.count}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "network" && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/20">
                  <th className="text-left px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Protocol</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Source</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Destination</th>
                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Port</th>
                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Bytes</th>
                  <th className="text-center px-5 py-2.5 text-xs font-semibold text-muted-foreground uppercase">Status</th>
                </tr>
              </thead>
              <tbody>
                {data?.networkActivity.sort((a, b) => (b.malicious ? 1 : 0) - (a.malicious ? 1 : 0)).map((n) => (
                  <tr key={n.id} className={`border-b border-border/40 hover:bg-muted/10 ${n.malicious ? "bg-red-500/3" : ""}`}>
                    <td className="px-5 py-2.5">
                      <span className="text-xs font-mono font-bold text-cyan-400">{n.protocol}</span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">{n.srcIp}</td>
                    <td className="px-4 py-2.5 font-mono text-xs">
                      <span className={n.malicious ? "text-red-400" : "text-foreground"}>{n.dstIp}</span>
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-xs text-muted-foreground">{n.dstPort}</td>
                    <td className="px-4 py-2.5 text-right text-xs text-muted-foreground">{n.bytes.toLocaleString()}</td>
                    <td className="px-5 py-2.5 text-center">
                      {n.malicious ? (
                        <span className="text-[10px] text-red-400 bg-red-400/10 border border-red-400/30 px-2 py-0.5 rounded font-bold">
                          MALICIOUS
                        </span>
                      ) : (
                        <span className="text-[10px] text-green-400 bg-green-400/10 border border-green-400/30 px-2 py-0.5 rounded">
                          OK
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "process" && (
          <div className="p-4 space-y-2">
            {data?.processTree.map((p) => (
              <div key={p.pid} className={`flex items-start gap-3 p-3 rounded-lg border ${
                p.suspicious ? "border-red-500/30 bg-red-500/5" : "border-border bg-muted/10"
              }`}>
                <div className={`mt-0.5 p-1.5 rounded-md ${p.suspicious ? "bg-red-500/20" : "bg-muted/30"}`}>
                  {p.suspicious
                    ? <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                    : <Shield className="w-3.5 h-3.5 text-muted-foreground" />
                  }
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-semibold ${p.suspicious ? "text-red-400" : "text-foreground"}`}>
                      {p.name}
                    </span>
                    <span className="text-[10px] text-muted-foreground font-mono">PID:{p.pid}</span>
                    <span className="text-[10px] text-muted-foreground font-mono">PPID:{p.parentPid}</span>
                    {p.suspicious && (
                      <span className="text-[10px] text-red-400 bg-red-400/10 border border-red-400/30 px-1.5 py-0.5 rounded font-bold">SUSPICIOUS</span>
                    )}
                  </div>
                  <div className="text-xs text-muted-foreground font-mono mt-0.5 truncate">{p.cmdLine}</div>
                </div>
              </div>
            ))}
          </div>
        )}
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
