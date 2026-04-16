import { useEffect, useState, useRef, useCallback } from "react";
import { Send, Plus, Trash2, Wifi, Globe, Upload, FileText, Bot, User, Copy, Zap } from "lucide-react";
import { apiGet, apiPost, apiDelete, streamPost } from "../lib/api";

interface Conversation { id: number; title: string; createdAt: string; }
interface Message { id: number; conversationId: number; role: string; content: string; createdAt: string; }

const QUICK_PROMPTS = [
  { label: "Analyze Wireshark", text: "Analyze this Wireshark capture for malware, C2 communication, and potential zero-day exploits:\n\n[PASTE YOUR WIRESHARK/TSHARK OUTPUT HERE]" },
  { label: "Detect Zero-Days", text: "Scan for zero-day exploit indicators in this traffic. Look for novel attack patterns, unusual protocol behaviors, heap spray patterns, ROP chains, or exploitation signatures not in CVE databases:\n\n" },
  { label: "Browser Analysis", text: "Analyze this browser log for malicious JavaScript, drive-by downloads, cryptojacking, or web-based exploits:\n\n[PASTE BROWSER CONSOLE/NETWORK LOG]" },
  { label: "IOC Extraction", text: "Extract all indicators of compromise (IOCs) from this data. List IPs, domains, file hashes, registry keys, mutexes, and behavioral signatures:\n\n" },
  { label: "Ransomware Analysis", text: "Identify ransomware behavior in this sample. Look for: file encryption patterns, shadow copy deletion, C2 check-in, ransom note drops, and lateral movement:\n\n" },
  { label: "Threat Hunt", text: "Perform a threat hunt analysis on this network traffic. Identify APT TTPs, living-off-the-land techniques, and covert C2 channels:\n\n" },
];

export default function AIChat() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [streamBuf, setStreamBuf] = useState("");
  const [inputMode, setInputMode] = useState<"manual" | "wireshark" | "browser" | "file">("manual");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const stopRef = useRef<(() => void) | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const loadConversations = useCallback(() => {
    apiGet<Conversation[]>("/anthropic/conversations").then(setConversations).catch(console.error);
  }, []);

  useEffect(() => { loadConversations(); }, [loadConversations]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamBuf]);

  const selectConversation = async (id: number) => {
    setActiveId(id);
    setStreamBuf("");
    try {
      const data = await apiGet<{ messages: Message[] }>(`/anthropic/conversations/${id}`);
      setMessages(data.messages ?? []);
    } catch (e) {
      console.error(e);
    }
  };

  const newConversation = async () => {
    const modeLabels = { manual: "Manual", wireshark: "Wireshark", browser: "Browser", file: "File" };
    const conv = await apiPost<Conversation>("/anthropic/conversations", {
      title: `${modeLabels[inputMode]} Analysis — ${new Date().toLocaleTimeString()}`,
    });
    setConversations((prev) => [conv, ...prev]);
    setActiveId(conv.id);
    setMessages([]);
    setStreamBuf("");
  };

  const deleteConversation = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    await apiDelete(`/anthropic/conversations/${id}`).catch(console.error);
    loadConversations();
    if (activeId === id) { setActiveId(null); setMessages([]); }
  };

  const sendMessage = async () => {
    if (!input.trim() || streaming) return;
    let convId = activeId;
    if (!convId) {
      const conv = await apiPost<Conversation>("/anthropic/conversations", {
        title: input.slice(0, 50) + (input.length > 50 ? "..." : ""),
      });
      setConversations((prev) => [conv, ...prev]);
      setActiveId(conv.id);
      convId = conv.id;
      setMessages([]);
    }

    const userMsg: Message = {
      id: Date.now(), conversationId: convId, role: "user", content: input, createdAt: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    const msgContent = input;
    setInput("");
    setStreaming(true);
    setStreamBuf("");

    const stop = streamPost(
      `/anthropic/conversations/${convId}/messages`,
      { content: msgContent, inputSource: inputMode },
      (chunk) => setStreamBuf((prev) => prev + chunk),
      () => {
        setStreaming(false);
        setStreamBuf((buf) => {
          if (buf) {
            setMessages((prev) => [
              ...prev,
              { id: Date.now() + 1, conversationId: convId!, role: "assistant", content: buf, createdAt: new Date().toISOString() },
            ]);
          }
          return "";
        });
        loadConversations();
      },
      (e) => { console.error(e); setStreaming(false); setStreamBuf(""); },
    );
    stopRef.current = stop;
  };

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result as string;
      setInput(`Analyze this file: ${file.name}\n\n${content.slice(0, 5000)}`);
    };
    reader.readAsText(file);
    setInputMode("file");
  };

  const inputModes = [
    { mode: "manual" as const, icon: <FileText className="w-3.5 h-3.5" />, label: "Manual" },
    { mode: "wireshark" as const, icon: <Wifi className="w-3.5 h-3.5" />, label: "Wireshark" },
    { mode: "browser" as const, icon: <Globe className="w-3.5 h-3.5" />, label: "Browser" },
    { mode: "file" as const, icon: <Upload className="w-3.5 h-3.5" />, label: "File" },
  ];

  return (
    <div className="flex h-full overflow-hidden">
      {/* Sidebar - conversations list */}
      <div className="w-64 shrink-0 border-r border-border bg-card flex flex-col">
        <div className="p-3 border-b border-border">
          <button
            onClick={newConversation}
            className="w-full flex items-center justify-center gap-2 py-2 bg-primary/10 hover:bg-primary/20 border border-primary/30 text-primary rounded-lg text-sm font-medium transition-all"
          >
            <Plus className="w-4 h-4" />
            New Analysis
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {conversations.length === 0 && (
            <div className="text-center text-xs text-muted-foreground py-8">No conversations yet</div>
          )}
          {conversations.map((conv) => (
            <div
              key={conv.id}
              onClick={() => selectConversation(conv.id)}
              className={`flex items-center gap-2 px-3 py-2.5 rounded-lg cursor-pointer group transition-all ${
                activeId === conv.id
                  ? "bg-primary/15 border border-primary/25 text-primary"
                  : "text-muted-foreground hover:bg-muted/20 border border-transparent"
              }`}
            >
              <Bot className="w-3.5 h-3.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium truncate">{conv.title}</div>
                <div className="text-[10px] opacity-60 mt-0.5">{formatTime(conv.createdAt)}</div>
              </div>
              <button
                onClick={(e) => deleteConversation(conv.id, e)}
                className="opacity-0 group-hover:opacity-100 p-0.5 hover:text-red-400 transition-all"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Chat area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {!activeId && messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center space-y-6">
              <div className="w-16 h-16 rounded-2xl bg-primary/20 border border-primary/30 flex items-center justify-center">
                <Zap className="w-8 h-8 text-primary" />
              </div>
              <div>
                <div className="text-lg font-bold text-foreground">AegisCore AI</div>
                <div className="text-sm text-muted-foreground mt-1 max-w-md">
                  Expert cybersecurity AI for malware analysis, zero-day detection, network forensics, and threat intelligence
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 max-w-lg w-full">
                {QUICK_PROMPTS.map((p) => (
                  <button
                    key={p.label}
                    onClick={() => { setInput(p.text); }}
                    className="text-left p-3 rounded-lg border border-border bg-card hover:border-primary/40 hover:bg-primary/5 transition-all group"
                  >
                    <div className="text-xs font-semibold text-foreground group-hover:text-primary">{p.label}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2">{p.text.slice(0, 60)}...</div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((msg) => (
            <div key={msg.id} className={`flex gap-3 ${msg.role === "user" ? "flex-row-reverse" : "flex-row"}`}>
              <div className={`w-7 h-7 rounded-lg shrink-0 flex items-center justify-center ${
                msg.role === "user" ? "bg-primary/20 border border-primary/30" : "bg-muted/40 border border-border"
              }`}>
                {msg.role === "user" ? <User className="w-3.5 h-3.5 text-primary" /> : <Bot className="w-3.5 h-3.5 text-muted-foreground" />}
              </div>
              <div className={`flex-1 max-w-3xl ${msg.role === "user" ? "text-right" : ""}`}>
                <div className={`inline-block rounded-xl px-4 py-3 text-sm text-left ${
                  msg.role === "user"
                    ? "bg-primary/15 border border-primary/25 text-foreground"
                    : "bg-card border border-border text-foreground"
                }`}>
                  <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">{msg.content}</pre>
                </div>
                <div className="flex items-center gap-2 mt-1 justify-end">
                  <div className="text-[10px] text-muted-foreground">{formatTime(msg.createdAt)}</div>
                  <button
                    onClick={() => navigator.clipboard.writeText(msg.content)}
                    className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5"
                  >
                    <Copy className="w-2.5 h-2.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}

          {/* Streaming indicator */}
          {streaming && streamBuf && (
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg shrink-0 bg-muted/40 border border-border flex items-center justify-center">
                <Bot className="w-3.5 h-3.5 text-primary animate-pulse" />
              </div>
              <div className="flex-1 max-w-3xl">
                <div className="inline-block rounded-xl px-4 py-3 bg-card border border-primary/20 text-sm text-foreground">
                  <pre className="whitespace-pre-wrap font-sans leading-relaxed">{streamBuf}</pre>
                  <span className="inline-block w-1.5 h-4 bg-primary animate-pulse rounded-sm ml-0.5 align-middle" />
                </div>
              </div>
            </div>
          )}

          {streaming && !streamBuf && (
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg shrink-0 bg-muted/40 border border-border flex items-center justify-center">
                <Bot className="w-3.5 h-3.5 text-primary animate-pulse" />
              </div>
              <div className="bg-card border border-border rounded-xl px-4 py-3 flex items-center gap-2">
                <div className="flex gap-1">
                  {[0, 1, 2].map((i) => (
                    <div key={i} className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
                  ))}
                </div>
                <span className="text-xs text-muted-foreground">AegisCore analyzing...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input area */}
        <div className="border-t border-border bg-card/50 p-4 space-y-3">
          {/* Input mode selector */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Input:</span>
            {inputModes.map(({ mode, icon, label }) => (
              <button
                key={mode}
                onClick={() => {
                  setInputMode(mode);
                  if (mode === "file") fileRef.current?.click();
                }}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-all ${
                  inputMode === mode
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground hover:border-border/60"
                }`}
              >
                {icon} {label}
              </button>
            ))}
            <input ref={fileRef} type="file" className="hidden" onChange={handleFile}
              accept=".pcap,.pcapng,.log,.txt,.json,.xml,.csv" />
            <div className="ml-auto text-[10px] text-muted-foreground">
              {inputMode === "wireshark" ? "Paste Wireshark/tshark capture output" :
               inputMode === "browser" ? "Paste browser console or network logs" :
               inputMode === "file" ? "Click 'File' to select file for analysis" :
               "Direct query or analysis request"}
            </div>
          </div>

          <div className="flex gap-3">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
              placeholder={
                inputMode === "wireshark" ? "Paste Wireshark PCAP text output, tshark data, or packet logs for zero-day analysis..." :
                inputMode === "browser" ? "Paste browser console logs, network requests, or JavaScript for malware analysis..." :
                "Ask AegisCore to analyze threats, extract IOCs, detect zero-days..."
              }
              rows={3}
              className="flex-1 bg-background border border-border rounded-xl px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/50 resize-none font-mono"
            />
            <div className="flex flex-col gap-2">
              <button
                onClick={sendMessage}
                disabled={!input.trim() || streaming}
                className="flex items-center justify-center w-10 h-10 bg-primary text-primary-foreground rounded-xl hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                <Send className="w-4 h-4" />
              </button>
              {streaming && (
                <button
                  onClick={() => { stopRef.current?.(); setStreaming(false); setStreamBuf(""); }}
                  className="flex items-center justify-center w-10 h-10 bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl hover:bg-red-500/30 transition-all text-[10px] font-bold"
                >
                  ■
                </button>
              )}
            </div>
          </div>
          <div className="text-[10px] text-muted-foreground">
            Shift+Enter for new line · Enter to send · Supports Wireshark PCAP, browser logs, binary analysis, zero-day detection
          </div>
        </div>
      </div>
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
  } catch { return iso; }
}
