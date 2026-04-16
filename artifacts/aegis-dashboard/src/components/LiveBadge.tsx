interface LiveBadgeProps {
  lastUpdated: Date | null;
  sampleCount?: number;
  compact?: boolean;
}

export default function LiveBadge({ lastUpdated, sampleCount, compact = false }: LiveBadgeProps) {
  if (compact) {
    return (
      <div className="flex items-center gap-1 px-2 py-1 rounded-lg border border-primary/20 bg-primary/5">
        <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
        <span className="text-[10px] text-primary font-bold">LIVE</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3">
      {sampleCount !== undefined && (
        <div className="text-right">
          <div className="text-lg font-bold tabular-nums text-foreground">{sampleCount}</div>
          <div className="text-[10px] text-muted-foreground">sessions</div>
        </div>
      )}
      <div className="flex flex-col items-end gap-1">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-primary/30 bg-primary/10">
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          <span className="text-xs text-primary font-bold tracking-widest">LIVE</span>
        </div>
        {lastUpdated && (
          <div className="text-[10px] text-muted-foreground">
            {lastUpdated.toLocaleTimeString()}
          </div>
        )}
      </div>
    </div>
  );
}
