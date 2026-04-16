import { EventEmitter } from "events";

export interface FeatureValue {
  name: string;
  value: number;
  category: string;
}

export interface AnalysisSession {
  id: string;
  inputType: string;
  classification: string;
  confidence: number;
  threatLevel: string;
  timestamp: string;
  status: string;
  features?: FeatureValue[];
  aiAnalysis?: string;
  modelPredictions?: { lightgbm: number; lstm: number; ensemble: number; transformer?: number };
  rawData?: string;
}

export const sessions = new Map<string, AnalysisSession>();
export const storeEvents = new EventEmitter();
storeEvents.setMaxListeners(200);

export function addSession(session: AnalysisSession) {
  sessions.set(session.id, session);
  storeEvents.emit("session", session);
}

export function getAllSessions(): AnalysisSession[] {
  return Array.from(sessions.values());
}

export function seedDemoSessions() {
  const demos: AnalysisSession[] = [
    {
      id: "demo-001",
      inputType: "wireshark",
      classification: "Ransomware",
      confidence: 0.97,
      threatLevel: "critical",
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      status: "completed",
      modelPredictions: { lightgbm: 0.96, lstm: 0.98, ensemble: 0.97 },
      aiAnalysis: "WannaCry variant detected via SMB exploitation pattern.",
      features: [
        { name: "smb_traffic", value: 47, category: "network" },
        { name: "tcp_syn_count", value: 312, category: "network" },
        { name: "suspicious_ports", value: 3, category: "network" },
        { name: "unique_dst_ips", value: 28, category: "network" },
        { name: "irc_traffic", value: 0, category: "network" },
        { name: "dns_query_count", value: 89, category: "network" },
        { name: "tcp_rst_count", value: 78, category: "network" },
        { name: "udp_packet_count", value: 45, category: "network" },
        { name: "total_bytes", value: 1048576, category: "network" },
        { name: "avg_packet_size", value: 512, category: "network" },
      ],
    },
    {
      id: "demo-002",
      inputType: "file",
      classification: "Trojan.Downloader",
      confidence: 0.89,
      threatLevel: "high",
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      status: "completed",
      modelPredictions: { lightgbm: 0.91, lstm: 0.87, ensemble: 0.89 },
      aiAnalysis: "Malicious downloader detected. Attempts to contact external C2 server.",
      features: [
        { name: "smb_traffic", value: 2, category: "network" },
        { name: "tcp_syn_count", value: 45, category: "network" },
        { name: "suspicious_ports", value: 2, category: "network" },
        { name: "unique_dst_ips", value: 8, category: "network" },
        { name: "dns_query_count", value: 23, category: "network" },
        { name: "tcp_rst_count", value: 12, category: "network" },
        { name: "udp_packet_count", value: 8, category: "network" },
        { name: "total_bytes", value: 204800, category: "network" },
        { name: "avg_packet_size", value: 256, category: "network" },
        { name: "http_request_count", value: 18, category: "network" },
      ],
    },
    {
      id: "demo-003",
      inputType: "browser",
      classification: "Benign",
      confidence: 0.06,
      threatLevel: "benign",
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      status: "completed",
      modelPredictions: { lightgbm: 0.07, lstm: 0.05, ensemble: 0.06 },
      aiAnalysis: "No malicious indicators detected. Normal browser traffic patterns.",
      features: [
        { name: "js_eval_count", value: 1, category: "behavioral" },
        { name: "iframe_count", value: 0, category: "behavioral" },
        { name: "obfuscated_code", value: 0, category: "behavioral" },
        { name: "crypto_mining_calls", value: 0, category: "behavioral" },
        { name: "cookie_access_count", value: 2, category: "behavioral" },
        { name: "redirect_count", value: 1, category: "behavioral" },
        { name: "dom_manipulation", value: 3, category: "behavioral" },
        { name: "xhr_request_count", value: 12, category: "behavioral" },
        { name: "local_storage_access", value: 4, category: "behavioral" },
        { name: "canvas_fingerprint", value: 1, category: "behavioral" },
      ],
    },
    {
      id: "demo-004",
      inputType: "wireshark",
      classification: "Botnet C2",
      confidence: 0.92,
      threatLevel: "high",
      timestamp: new Date(Date.now() - 900000).toISOString(),
      status: "completed",
      modelPredictions: { lightgbm: 0.90, lstm: 0.94, ensemble: 0.92 },
      aiAnalysis: "Mirai botnet variant detected. DDoS coordination traffic on UDP with SYN flood patterns.",
      features: [
        { name: "smb_traffic", value: 0, category: "network" },
        { name: "tcp_syn_count", value: 892, category: "network" },
        { name: "suspicious_ports", value: 5, category: "network" },
        { name: "unique_dst_ips", value: 64, category: "network" },
        { name: "irc_traffic", value: 8, category: "network" },
        { name: "dns_query_count", value: 134, category: "network" },
        { name: "tcp_rst_count", value: 203, category: "network" },
        { name: "udp_packet_count", value: 1240, category: "network" },
        { name: "total_bytes", value: 5242880, category: "network" },
        { name: "icmp_count", value: 156, category: "network" },
      ],
    },
    {
      id: "demo-005",
      inputType: "file",
      classification: "Spyware",
      confidence: 0.85,
      threatLevel: "medium",
      timestamp: new Date(Date.now() - 300000).toISOString(),
      status: "completed",
      modelPredictions: { lightgbm: 0.87, lstm: 0.83, ensemble: 0.85 },
      aiAnalysis: "Keylogger/spyware detected. Suspicious registry operations and clipboard access.",
      features: [
        { name: "js_eval_count", value: 12, category: "behavioral" },
        { name: "iframe_count", value: 2, category: "behavioral" },
        { name: "obfuscated_code", value: 18, category: "behavioral" },
        { name: "crypto_mining_calls", value: 0, category: "behavioral" },
        { name: "clipboard_access", value: 7, category: "behavioral" },
        { name: "cookie_access_count", value: 23, category: "behavioral" },
        { name: "redirect_count", value: 4, category: "behavioral" },
        { name: "dom_manipulation", value: 31, category: "behavioral" },
        { name: "local_storage_access", value: 18, category: "behavioral" },
        { name: "canvas_fingerprint", value: 6, category: "behavioral" },
      ],
    },
  ];

  for (const s of demos) {
    sessions.set(s.id, s);
  }
}
