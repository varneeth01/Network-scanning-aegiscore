const configs: Record<string, { label: string; classes: string }> = {
  critical: { label: "CRITICAL", classes: "bg-red-500/15 text-red-400 border-red-500/30" },
  high: { label: "HIGH", classes: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium: { label: "MEDIUM", classes: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  low: { label: "LOW", classes: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
  benign: { label: "BENIGN", classes: "bg-green-500/15 text-green-400 border-green-500/30" },
};

export default function ThreatBadge({ level }: { level: string }) {
  const cfg = configs[level] ?? configs.low;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold tracking-widest border ${cfg.classes}`}>
      {cfg.label}
    </span>
  );
}
