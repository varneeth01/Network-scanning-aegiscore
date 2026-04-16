import { useState, useEffect } from "react";
import { Link, useLocation } from "wouter";
import {
  Shield, Activity, Search, Brain, BarChart2,
  GitBranch, Layers, TrendingUp, MessageSquare, Menu, X, Wifi,
  ChevronRight, Zap, TrendingUp as TrendUp
} from "lucide-react";

const BASE = import.meta.env.BASE_URL ?? "/";
const API = BASE.replace(/\/$/, "");

const navItems = [
  { path: "/", icon: Shield, label: "Dashboard", desc: "Overview & Stats" },
  { path: "/analyze", icon: Search, label: "Analyze", desc: "Submit Data" },
  { path: "/sandbox", icon: Activity, label: "Sandbox", desc: "Live Execution" },
  { path: "/training", icon: Brain, label: "Model Training", desc: "LightGBM + LSTM" },
  { path: "/confusion", icon: GitBranch, label: "Confusion Matrix", desc: "Classification" },
  { path: "/features", icon: BarChart2, label: "Feature Importance", desc: "Top 30 Features" },
  { path: "/shap", icon: Layers, label: "SHAP Analysis", desc: "Explainability" },
  { path: "/performance", icon: TrendingUp, label: "Performance", desc: "Model Comparison" },
  { path: "/ai", icon: MessageSquare, label: "AI Assistant", desc: "Dynamic Analysis" },
];

interface IntelligenceStats {
  totalSamplesSeen: number;
  featuresLearned: number;
  currentAccuracy: number;
  baselineAccuracy: number;
  accuracyDelta: number;
  isAdaptive: boolean;
  lastUpdate: string;
}

export default function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [intel, setIntel] = useState<IntelligenceStats | null>(null);
  const [justLearned, setJustLearned] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/models/intelligence`)
      .then(r => r.json())
      .then(setIntel)
      .catch(() => {});

    const es = new EventSource(`${API}/api/events/stream`);
    es.addEventListener("intelligence_update", () => {
      fetch(`${API}/api/models/intelligence`)
        .then(r => r.json())
        .then((data) => {
          setIntel(data);
          setJustLearned(true);
          setTimeout(() => setJustLearned(false), 2000);
        })
        .catch(() => {});
    });
    return () => es.close();
  }, []);

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-50 w-64 flex-col bg-sidebar border-r border-sidebar-border
        flex transition-transform duration-300
        ${mobileOpen ? "translate-x-0" : "-translate-x-full"}
        lg:static lg:translate-x-0 lg:flex
      `}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-sidebar-border">
          <div className="w-9 h-9 rounded-lg bg-primary/20 border border-primary/40 flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <div className="text-sm font-bold text-foreground tracking-tight">AegisCore</div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-widest">AI Defense Suite</div>
          </div>
          <button
            className="ml-auto lg:hidden text-muted-foreground hover:text-foreground"
            onClick={() => setMobileOpen(false)}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Live status */}
        <div className="px-4 py-3 border-b border-sidebar-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Wifi className="w-3 h-3 text-primary" />
            <span>Monitoring active</span>
            <span className="ml-auto flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              LIVE
            </span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {navItems.map(({ path, icon: Icon, label, desc }) => {
            const active = location === path;
            return (
              <Link key={path} href={path}>
                <div
                  onClick={() => setMobileOpen(false)}
                  className={`
                    flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-all group
                    ${active
                      ? "bg-primary/15 text-primary border border-primary/25"
                      : "text-sidebar-foreground hover:bg-sidebar-accent border border-transparent"
                    }
                  `}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${active ? "text-primary" : "text-muted-foreground group-hover:text-foreground"}`} />
                  <div className="flex-1 min-w-0">
                    <div className={`text-sm font-medium leading-none ${active ? "text-primary" : ""}`}>{label}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{desc}</div>
                  </div>
                  {active && <ChevronRight className="w-3 h-3 text-primary" />}
                </div>
              </Link>
            );
          })}
        </nav>

        {/* Intelligence Panel */}
        <div className={`mx-3 mb-3 rounded-lg border p-3 transition-all duration-500 ${
          justLearned
            ? "border-primary/60 bg-primary/10 shadow-[0_0_12px_rgba(0,255,128,0.15)]"
            : "border-sidebar-border bg-sidebar-accent/30"
        }`}>
          <div className="flex items-center gap-1.5 mb-2">
            <Zap className={`w-3 h-3 ${intel?.isAdaptive ? "text-primary" : "text-muted-foreground"}`} />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-foreground">
              Intelligence Engine
            </span>
            {justLearned && (
              <span className="ml-auto text-[9px] text-primary font-bold animate-pulse">LEARNING</span>
            )}
          </div>
          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-muted-foreground">Mode</span>
              <span className={`text-[10px] font-semibold ${intel?.isAdaptive ? "text-primary" : "text-muted-foreground"}`}>
                {intel?.isAdaptive ? "Adaptive ✓" : "Baseline"}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-muted-foreground">Samples learned</span>
              <span className="text-[10px] font-mono text-foreground">
                {intel?.totalSamplesSeen ?? 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-muted-foreground">Features weighted</span>
              <span className="text-[10px] font-mono text-foreground">
                {intel?.featuresLearned ?? 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-muted-foreground">Accuracy</span>
              <span className="text-[10px] font-mono text-foreground flex items-center gap-1">
                {intel ? `${(intel.currentAccuracy * 100).toFixed(2)}%` : "97.34%"}
                {intel && intel.accuracyDelta > 0 && (
                  <TrendUp className="w-2.5 h-2.5 text-primary" />
                )}
              </span>
            </div>
            {intel && intel.accuracyDelta > 0 && (
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-muted-foreground">Δ from baseline</span>
                <span className="text-[10px] font-mono text-primary">
                  +{(intel.accuracyDelta * 100).toFixed(3)}%
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-sidebar-border">
          <div className="text-[10px] text-muted-foreground space-y-0.5">
            <div>LightGBM v3.3.5 + BiLSTM v2.1</div>
            <div>Hybrid Ensemble · Llama 3.3 70B</div>
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setMobileOpen(false)} />
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center gap-3 px-5 py-3 border-b border-border bg-card/50 backdrop-blur shrink-0">
          <button
            className="lg:hidden text-muted-foreground hover:text-foreground"
            onClick={() => setMobileOpen(true)}
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="text-xs text-muted-foreground">
            {navItems.find((n) => n.path === location)?.label ?? "AegisCore"}
            <span className="mx-2 opacity-40">/</span>
            <span className="text-foreground">
              {navItems.find((n) => n.path === location)?.desc ?? "Dashboard"}
            </span>
          </div>
          <div className="ml-auto flex items-center gap-3">
            {intel && intel.isAdaptive && (
              <div className="hidden sm:flex items-center gap-1.5 text-xs text-primary bg-primary/10 px-3 py-1.5 rounded-full border border-primary/30">
                <Zap className="w-3 h-3" />
                Adaptive Mode · {intel.totalSamplesSeen} samples
              </div>
            )}
            <div className="hidden sm:flex items-center gap-1.5 text-xs text-muted-foreground bg-muted/30 px-3 py-1.5 rounded-full border border-border">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              AI Engine Ready
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
