const BASE = import.meta.env.BASE_URL.replace(/\/$/, "") + "/api";

export function getBaseUrl(): string { return BASE; }

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res.json();
}

export async function apiDelete(path: string): Promise<void> {
  const res = await fetch(`${BASE}${path}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`API error ${res.status}`);
}

export function streamPost(path: string, body: unknown, onChunk: (text: string) => void, onDone: () => void, onError: (e: Error) => void) {
  const controller = new AbortController();
  fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: controller.signal,
  }).then(async (res) => {
    if (!res.ok) throw new Error(`API error ${res.status}`);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop()!;
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.done) { onDone(); return; }
            if (data.content) onChunk(data.content);
          } catch { }
        }
      }
    }
    onDone();
  }).catch((e) => {
    if (e.name !== "AbortError") onError(e);
  });
  return () => controller.abort();
}
