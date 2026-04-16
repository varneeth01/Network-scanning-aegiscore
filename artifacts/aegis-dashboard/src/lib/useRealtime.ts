import { useEffect, useRef, useCallback, useState } from "react";
import { getBaseUrl } from "./api";

export interface RealtimeEvent {
  type: "init" | "session_added" | "stats_update";
  data: {
    sessionCount?: number;
    malwareCount?: number;
    lastUpdated?: string;
    id?: string;
    classification?: string;
    threatLevel?: string;
    confidence?: number;
    inputType?: string;
    timestamp?: string;
  };
}

export function useRealtimeStream(onEvent: (e: RealtimeEvent) => void) {
  const esRef = useRef<EventSource | null>(null);
  const stableOnEvent = useRef(onEvent);
  stableOnEvent.current = onEvent;

  useEffect(() => {
    const url = `${getBaseUrl()}/events/stream`;
    const es = new EventSource(url);
    esRef.current = es;

    const handleEvent = (type: RealtimeEvent["type"]) => (raw: MessageEvent) => {
      try {
        stableOnEvent.current({ type, data: JSON.parse(raw.data) });
      } catch {}
    };

    es.addEventListener("init", handleEvent("init"));
    es.addEventListener("session_added", handleEvent("session_added"));
    es.addEventListener("stats_update", handleEvent("stats_update"));

    return () => {
      es.close();
      esRef.current = null;
    };
  }, []);
}

export function useLiveData<T>(
  fetchFn: () => Promise<T>,
  intervalMs = 10000
): { data: T | null; loading: boolean; lastUpdated: Date | null; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetch = useCallback(() => {
    fetchFn()
      .then((d) => {
        setData(d);
        setLastUpdated(new Date());
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [fetchFn]);

  useEffect(() => {
    fetch();
    const t = setInterval(fetch, intervalMs);
    return () => clearInterval(t);
  }, [fetch, intervalMs]);

  return { data, loading, lastUpdated, refresh: fetch };
}
