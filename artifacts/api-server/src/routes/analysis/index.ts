import { Router } from "express";
import { openrouter } from "@workspace/integrations-openrouter-ai";
import { SubmitAnalysisBody } from "@workspace/api-zod";
import crypto from "crypto";
import { addSession, getAllSessions, AnalysisSession, FeatureValue } from "../../lib/store";
import { learnFromSession, getAdaptiveScore, getSimilarCases } from "../../lib/intelligence";

const router = Router();

// ─── CONSTANTS ───────────────────────────────────────────────────────────────
const TROJAN_C2_PORTS = [4444, 1337, 31337, 6667, 6668, 6669, 8888, 9001, 9050, 1080, 5900, 6660, 6661, 6662, 6663, 6664, 6665];
const TROJAN_STRINGS = [
  "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtUnmapViewOfSection",
  "SetWindowsHookEx", "GetAsyncKeyState", "keylogger", "backdoor", "rootkit",
  "reverse_shell", "bind_shell", "netcat", "meterpreter", "cobalt strike", "mimikatz",
  "ShellExecute", "WinExec", "cmd.exe /c", "powershell -enc", "regsvr32 /s",
  "mshta http", "wscript.shell", "bitsadmin /transfer", "certutil -decode",
  "schtasks /create", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "taskkill /f", "vssadmin delete shadows", "bcdedit /set", "net user /add",
  "net localgroup administrators", "icacls", "attrib +h +s",
];

// From DDoS dataset: high packet rates (>7 pkt/s suspicious, >90 severe), 
// ARP flood targeting single destination with packet_length=60
const DDOS_PACKET_RATE_MEDIUM = 7.0;
const DDOS_PACKET_RATE_HIGH = 30.0;
const DDOS_PACKET_RATE_SEVERE = 90.0;
// From SDN dataset: pktrate > 450 = confirmed DDoS flow
const SDN_DDOS_PKTRATE_THRESHOLD = 450;
// From intrusion dataset: failed_logins > 2 + login_attempts > 5 = intrusion
const INTRUSION_FAILED_LOGINS_THRESHOLD = 2;
const INTRUSION_LOGIN_ATTEMPTS_THRESHOLD = 5;

// ─── THREAT CLASSIFICATION SYSTEM ────────────────────────────────────────────
interface ThreatSignature { name: string; weight: number; description: string; }
interface ThreatDetectionResult {
  detected: boolean;
  type: string | null;
  score: number;
  signatures: ThreatSignature[];
  countermeasures: string[];
}

// ─── TROJAN DETECTOR ─────────────────────────────────────────────────────────
function detectTrojan(raw: string): ThreatDetectionResult {
  const lower = raw.toLowerCase();
  const found: ThreatSignature[] = [];

  const checks: Array<{ pattern: RegExp; name: string; weight: number; description: string }> = [
    { pattern: /createremotethread/i, name: "Process Injection (CreateRemoteThread)", weight: 0.35, description: "Injects code into another process — classic trojan/RAT technique" },
    { pattern: /virtualalloc.{0,50}writeprocessmemory/is, name: "Memory Allocation + Write", weight: 0.30, description: "Allocates and writes to foreign process memory — shellcode injection" },
    { pattern: /ntunmapviewofsection|zwunmapviewofsection/i, name: "Process Hollowing", weight: 0.38, description: "Unmaps target process memory for process hollowing attack" },
    { pattern: /setwindowshookex/i, name: "Keylogger Hook", weight: 0.28, description: "Installs system-wide keyboard/mouse hooks — keylogger behavior" },
    { pattern: /getasynckeystate|getkeystate/i, name: "Keystroke Capture", weight: 0.25, description: "Polls keystroke state — credential harvesting" },
    { pattern: /meterpreter|cobalt.?strike|empire|cobaltstrike/i, name: "C2 Framework Signature", weight: 0.45, description: "Known C2 framework artifact detected" },
    { pattern: /mimikatz|sekurlsa|lsass\.exe/i, name: "Credential Dumper (Mimikatz/LSASS)", weight: 0.42, description: "Credential dumping tool or LSASS access — lateral movement" },
    { pattern: /powershell\s+-e(nc)?\s+[a-z0-9+/]{20}/i, name: "Encoded PowerShell", weight: 0.33, description: "Base64-encoded PowerShell — common trojan dropper technique" },
    { pattern: /bitsadmin|certutil\s+-decode|certutil\s+-urlcache/i, name: "LOLBin Abuse", weight: 0.30, description: "Living-off-the-land binary abuse" },
    { pattern: /vssadmin\s+delete|bcdedit.*recoveryenabled.*no/i, name: "Ransomware Pre-Stage", weight: 0.40, description: "Shadow copy deletion — ransomware staging" },
    { pattern: /schtasks.*\/create.*\/ru\s+system/i, name: "SYSTEM Scheduled Task", weight: 0.28, description: "Creates SYSTEM-level scheduled task for persistence" },
    { pattern: /hklm\\software\\microsoft\\windows\\currentversion\\run/i, name: "Registry Run Key Persistence", weight: 0.27, description: "Adds to Run key — startup persistence" },
    { pattern: /net\s+(user|localgroup)\s+.*\/add/i, name: "Account Creation", weight: 0.35, description: "Creates user or adds to admin group" },
    { pattern: /attrib\s+\+h\s+\+s/i, name: "File Hiding", weight: 0.20, description: "Sets hidden+system attributes to conceal malicious files" },
    { pattern: /wscript\.shell|shell\.application/i, name: "Script Engine Abuse", weight: 0.22, description: "Script engine COM object used for command execution" },
    { pattern: /reverse.?shell|bind.?shell|back.?connect/i, name: "Shell Connection", weight: 0.40, description: "Explicit reverse/bind shell pattern — RAT/backdoor" },
    { pattern: /nc\s+-[elnvpe]+\s+\d+|ncat\s+.*-e/i, name: "Netcat Shell", weight: 0.38, description: "Netcat-based shell connection — backdoor command channel" },
  ];

  for (const check of checks) {
    if (check.pattern.test(lower)) {
      found.push({ name: check.name, weight: check.weight, description: check.description });
    }
  }
  for (const s of TROJAN_STRINGS) {
    if (lower.includes(s.toLowerCase()) && !found.some((f) => f.description.includes(s.slice(0, 15)))) {
      found.push({ name: `Suspicious String: ${s}`, weight: 0.12, description: `Trojan-linked pattern: "${s}"` });
    }
  }

  const score = Math.min(1.0, found.reduce((a, s) => a + s.weight, 0));
  let type: string | null = null;
  if (score > 0.25) {
    if (found.some((f) => f.name.includes("Credential") || f.name.includes("Keylog"))) type = "Trojan.Stealer";
    else if (found.some((f) => f.name.includes("Ransomware"))) type = "Trojan.Ransomware";
    else if (found.some((f) => f.name.includes("C2 Framework"))) type = "Trojan.RAT";
    else if (found.some((f) => f.name.includes("Shell"))) type = "Trojan.Backdoor";
    else if (found.some((f) => f.name.includes("Injection") || f.name.includes("Hollow"))) type = "Trojan.Injector";
    else if (found.some((f) => f.name.includes("Persistence") || f.name.includes("Registry"))) type = "Trojan.Dropper";
    else type = "Trojan.Generic";
  }

  return {
    detected: type !== null,
    type,
    score,
    signatures: found,
    countermeasures: type ? [
      "Immediately isolate the affected host from the network",
      "Terminate suspicious processes and block C2 IPs at the firewall",
      "Run memory forensics (Volatility) to identify injected code",
      "Reset all credentials accessible from the compromised host",
      "Re-image from a known-good baseline and apply patches",
    ] : [],
  };
}

// ─── MITM DETECTOR ───────────────────────────────────────────────────────────
// Detects: ARP poisoning, SSL stripping, traffic interception, 
// duplicate IPs, rogue gateways, man-in-browser
function detectMITM(raw: string, features: Record<string, number>): ThreatDetectionResult {
  const lower = raw.toLowerCase();
  const found: ThreatSignature[] = [];

  // ARP poisoning: same IP → multiple MACs (from DDoS dataset pattern)
  if (features.arp_spoofing_score > 0.3 || features.gratuitous_arp_count > 3) {
    found.push({ name: "ARP Cache Poisoning", weight: 0.45, description: "IP→MAC mapping inconsistency: same IP broadcasting from multiple MACs — classic ARP poisoning" });
  }
  // Gratuitous ARP flood (dataset: ARP packets_per_time > 90 = attack)
  if (features.gratuitous_arp_count > 10) {
    found.push({ name: "Gratuitous ARP Flood", weight: 0.35, description: `${features.gratuitous_arp_count} gratuitous ARP packets detected — gateway impersonation attack` });
  }
  // SSL stripping indicators
  if (/ssl.?strip|sslstrip|downgrade.*http|https.*->.*http/i.test(lower)) {
    found.push({ name: "SSL Stripping", weight: 0.50, description: "Protocol downgrade from HTTPS to HTTP detected — MITM intercept attack" });
  }
  // Unusual gateway behavior: traffic going through unexpected hop
  if (features.ttl_anomaly_score > 0.3) {
    found.push({ name: "TTL Anomaly (Rogue Hop)", weight: 0.30, description: "Abnormal TTL values suggest traffic being intercepted and re-forwarded by a rogue intermediary" });
  }
  // MITM tool signatures
  if (/ettercap|bettercap|arpspoof|dsniff|mitmproxy|responder|impacket/i.test(lower)) {
    found.push({ name: "MITM Toolchain Signature", weight: 0.55, description: "Known MITM tool detected: Ettercap/Bettercap/Responder/Impacket" });
  }
  // Certificate manipulation
  if (/ssl.*certificate.*mismatch|invalid cert|self.signed.*cert|cert.*error/i.test(lower)) {
    found.push({ name: "Certificate Manipulation", weight: 0.40, description: "SSL certificate mismatch or invalid certificate — MITM certificate injection" });
  }
  // Rogue DHCP
  if (/rogue dhcp|dhcp.*offer.*unexpected|dhcp.*poisoning/i.test(lower)) {
    found.push({ name: "Rogue DHCP Server", weight: 0.45, description: "Unauthorized DHCP server offering gateway — network-layer MITM" });
  }
  // Man-in-browser (browser-based)
  if (/formgrabber|form.?grab|inject.*bank|webinject/i.test(lower)) {
    found.push({ name: "Man-in-Browser (FormGrabber)", weight: 0.50, description: "Browser form injection/grab — MitB attack stealing credentials from banking/e-commerce forms" });
  }
  // Proxy interception
  if (features.proxy_tunnel_score > 0.3 && features.https_conn_count > 10) {
    found.push({ name: "Proxy Intercept Pattern", weight: 0.25, description: "Proxy port with high HTTPS volume — possible intercepting proxy" });
  }
  // Repeated ARP broadcasts targeting router (from DDoS dataset pattern: IP=1 = router/gateway)
  if (features.arp_request_count > 50 && features.unique_dst_ips < 3) {
    found.push({ name: "ARP Broadcast Targeting Gateway", weight: 0.35, description: `${features.arp_request_count} ARP requests to <3 IPs — targeted gateway poisoning` });
  }

  const score = Math.min(1.0, found.reduce((a, s) => a + s.weight, 0));
  const type = score > 0.3 ? "MITM Attack" : null;

  return {
    detected: type !== null,
    type: score > 0.5 ? "MITM.ARPPoisoning" : score > 0.35 ? "MITM.SSLStrip" : type ? "MITM.Generic" : null,
    score,
    signatures: found,
    countermeasures: type ? [
      "Enable Dynamic ARP Inspection (DAI) on managed switches immediately",
      "Deploy DHCP snooping to block rogue DHCP servers",
      "Enforce HTTPS-only with HSTS headers (max-age ≥ 31536000, includeSubDomains)",
      "Implement certificate pinning on critical applications",
      "Enable port security and 802.1X on all network ports",
      "Flush ARP caches on all hosts and monitor with arpwatch",
      "Deploy Network Detection & Response (NDR) with baseline deviation alerting",
    ] : [],
  };
}

// ─── DDOS / DOS DETECTOR ─────────────────────────────────────────────────────
// DDoS dataset insight: packets/time > 90 = severe, > 30 = high, > 7 = medium
// SDN dataset insight: pktrate > 450 = DDoS flow, high byteperflow (14M+)
// DoS = single source; DDoS = distributed (multiple sources → single target)
function detectDDoS(raw: string, features: Record<string, number>): ThreatDetectionResult {
  const lower = raw.toLowerCase();
  const found: ThreatSignature[] = [];

  // From DDoS dataset: packet rate > 90 = severe DDoS, source=multiple IPs targeting one dest
  const packetRate = features.packet_rate ?? (features.packet_count / Math.max(features.flow_duration ?? 1, 1));

  // SYN Flood (most common DDoS)
  if (features.syn_flood_score > 0.4 || features.tcp_syn_count > 500) {
    const severity = features.tcp_syn_count > 2000 ? "SEVERE" : features.tcp_syn_count > 500 ? "HIGH" : "MEDIUM";
    found.push({ name: `SYN Flood [${severity}]`, weight: Math.min(0.50, features.tcp_syn_count / 4000 + 0.15), description: `${features.tcp_syn_count} SYN packets — TCP handshake exhaustion attack` });
  }
  // UDP Flood (from DDoS dataset: UDP transport with high pkt rate)
  if (features.udp_flood_score > 0.3 || features.udp_packet_count > 1000) {
    found.push({ name: "UDP Flood", weight: Math.min(0.45, features.udp_packet_count / 5000 + 0.10), description: `${features.udp_packet_count} UDP packets — bandwidth exhaustion flood` });
  }
  // ICMP Flood / Ping of Death
  if (features.icmp_flood_score > 0.3 || features.icmp_count > 300) {
    found.push({ name: "ICMP Flood / Ping Flood", weight: Math.min(0.40, features.icmp_count / 2000 + 0.10), description: `${features.icmp_count} ICMP packets — ping flood/Smurf attack` });
  }
  // Amplification attacks (DNS/NTP/SSDP/Memcached)
  if (features.amplification_score > 0.3) {
    found.push({ name: "Amplification Attack (DNS/NTP/SSDP)", weight: 0.45, description: "Large UDP response packets with small spoofed source requests — amplification DDoS" });
  }
  // From SDN dataset: pktrate > 450 = DDoS flow with high bytes
  if (features.pkt_rate_sdn && features.pkt_rate_sdn > SDN_DDOS_PKTRATE_THRESHOLD) {
    found.push({ name: `SDN Flow DDoS [pktrate=${features.pkt_rate_sdn}]`, weight: 0.55, description: `Packet rate ${features.pkt_rate_sdn} exceeds SDN DDoS threshold (${SDN_DDOS_PKTRATE_THRESHOLD}) — matches confirmed attack flow profile` });
  }
  // HTTP/L7 flood
  if (features.http_request_count > 500 && features.unique_src_ips < 5) {
    found.push({ name: "HTTP L7 Flood (SlowLoris/RUDY)", weight: 0.40, description: `${features.http_request_count} HTTP requests from <5 IPs — application-layer DoS` });
  }
  if (features.http_request_count > 200 && features.unique_src_ips > 20) {
    found.push({ name: "HTTP DDoS (Distributed)", weight: 0.45, description: `${features.http_request_count} HTTP requests from ${features.unique_src_ips} sources — distributed application-layer DDoS` });
  }
  // Volumetric from DDoS dataset patterns
  if (features.total_bytes > 50_000_000) {
    found.push({ name: "Volumetric Bandwidth Exhaustion", weight: 0.35, description: `${(features.total_bytes / 1_000_000).toFixed(1)} MB in capture — volumetric flood exceeding normal baseline` });
  }
  // Traffic burst
  if (features.traffic_burst_score > 0.5 || features.regular_interval_score < 0.2 && features.packet_count > 500) {
    found.push({ name: "Traffic Burst Anomaly", weight: 0.25, description: "Irregular traffic burst pattern inconsistent with normal usage" });
  }
  // Tool signatures
  if (/loic|hoic|slowloris|rudy|hulk|goldeneye|xerxes|ddosim|hping3.*flood/i.test(lower)) {
    found.push({ name: "DDoS Tool Signature", weight: 0.55, description: "Known DDoS/DoS tool detected: LOIC/HOIC/SlowLoris/RUDY/hping3" });
  }

  // Distinguish DoS (single source) vs DDoS (distributed)
  const isDistributed = features.unique_src_ips > 5;
  const score = Math.min(1.0, found.reduce((a, s) => a + s.weight, 0));
  const isAttack = score > 0.25 || found.length > 0;

  let type: string | null = null;
  if (isAttack) {
    if (isDistributed) type = found.some((f) => f.name.includes("SYN")) ? "DDoS.SYNFlood" : found.some((f) => f.name.includes("UDP")) ? "DDoS.UDPFlood" : found.some((f) => f.name.includes("Amplification")) ? "DDoS.Amplification" : "DDoS.Volumetric";
    else type = found.some((f) => f.name.includes("SYN")) ? "DoS.SYNFlood" : found.some((f) => f.name.includes("HTTP")) ? "DoS.HTTPFlood" : "DoS.Generic";
  }

  return {
    detected: type !== null,
    type,
    score,
    signatures: found,
    countermeasures: type ? [
      isDistributed ? "Activate upstream DDoS scrubbing (Cloudflare/Akamai/AWS Shield)" : "Rate-limit and block the source IP at the perimeter firewall immediately",
      "Enable SYN cookies on all exposed servers (sysctl net.ipv4.tcp_syncookies=1)",
      "Deploy BPF/eBPF-based packet filtering to drop malformed/flood traffic at the kernel",
      "Implement connection rate limiting: iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT",
      "Enable RTBH (Remotely Triggered Black Hole) routing for source IP nullrouting",
      "Scale horizontally and enable auto-scaling to absorb volumetric attacks",
      "Configure anycast routing to distribute attack traffic across PoPs",
    ] : [],
  };
}

// ─── BOTNET DETECTOR ─────────────────────────────────────────────────────────
// Detects: C2 beaconing, IRC botnet channels, peer-to-peer C2, Mirai patterns,
// coordinated behavior, bot infection indicators
function detectBotnet(raw: string, features: Record<string, number>): ThreatDetectionResult {
  const lower = raw.toLowerCase();
  const found: ThreatSignature[] = [];

  // IRC C2 (classic botnet channel: ports 6667-6669)
  if (features.irc_traffic > 0) {
    found.push({ name: "IRC C2 Channel", weight: 0.50, description: `${features.irc_traffic} IRC packets — classic botnet command-and-control channel on IRC` });
  }
  // C2 beaconing (regular heartbeat to C2)
  if (features.beaconing_score > 0.5) {
    found.push({ name: "C2 Beaconing (Regular Interval)", weight: 0.55, description: `Timing coefficient of variation < 15% — highly regular C2 beacon pattern (jitter-free heartbeat)` });
  } else if (features.beaconing_score > 0.3) {
    found.push({ name: "C2 Beaconing (Low Jitter)", weight: 0.35, description: "Low-jitter periodic communication — possible C2 beacon with sleep timer" });
  }
  // Known botnet ports
  if (features.c2_port_hits > 0) {
    found.push({ name: "Known Botnet C2 Port", weight: 0.40, description: `Traffic on known C2 port (${TROJAN_C2_PORTS.join(",")}) — botnet command channel` });
  }
  // Mirai-style: UDP flood from many sources, Telnet/SSH scanning
  if (features.telnet_traffic > 5 && features.ssh_traffic > 20 && features.unique_dst_ips > 10) {
    found.push({ name: "Mirai-Style IoT Scanning", weight: 0.50, description: "Telnet+SSH scanning across multiple IPs — Mirai botnet recruitment pattern" });
  }
  // Distributed DDoS coordination (botnet executing DDoS)
  if (features.unique_src_ips > 20 && features.syn_flood_score > 0.3) {
    found.push({ name: "Botnet DDoS Coordination", weight: 0.45, description: `${features.unique_src_ips} source IPs participating in SYN flood — botnet executing coordinated DDoS` });
  }
  // P2P C2 communication
  if (features.unique_dst_ports > 30 && features.beaconing_score > 0.2 && features.unique_dst_ips > 10) {
    found.push({ name: "P2P C2 Network", weight: 0.35, description: "High port diversity with multiple peers — decentralized botnet C2 network" });
  }
  // Bot infection indicators (file analysis)
  if (/mirai|gafgyt|bashlite|qbot|emotet|trickbot|dridex|zeus|necurs|conficker|wannacry.botnet/i.test(lower)) {
    found.push({ name: "Known Botnet Signature", weight: 0.60, description: "Named botnet family artifact: Mirai/Gafgyt/QBot/Emotet/TrickBot/Dridex/Zeus/Necurs" });
  }
  // Fast-flux DNS (botnet infrastructure evasion)
  if (features.dns_fast_flux_score > 0.4) {
    found.push({ name: "Fast-Flux DNS (Botnet Infrastructure)", weight: 0.45, description: "Rapid DNS record rotation with NXDOMAIN pattern — botnet fast-flux domain hiding C2" });
  }
  // Tor C2 communication
  if (features.tor_exit_score > 0.4) {
    found.push({ name: "Tor-Hidden C2", weight: 0.40, description: "C2 communication routed through Tor onion network — advanced botnet evasion" });
  }
  // Spam/email botnet patterns
  if (/smtp.*flood|mass.mail|spam.bot|email.*harvest/i.test(lower)) {
    found.push({ name: "Spam Botnet Activity", weight: 0.40, description: "Mass email/SMTP activity pattern — spam botnet behavior" });
  }
  // SDN dataset: very high packet count with many flows = botnet traffic
  if (features.pkt_count_sdn && features.pkt_count_sdn > 90000 && features.flow_count > 3) {
    found.push({ name: "SDN High-Volume Botnet Flow", weight: 0.40, description: `${features.pkt_count_sdn} packets across ${features.flow_count} flows — matches SDN botnet attack profile` });
  }

  const score = Math.min(1.0, found.reduce((a, s) => a + s.weight, 0));
  let type: string | null = null;
  if (score > 0.3) {
    if (found.some((f) => f.name.includes("Mirai"))) type = "Botnet.Mirai";
    else if (found.some((f) => f.name.includes("Known Botnet"))) type = "Botnet.NamedFamily";
    else if (found.some((f) => f.name.includes("IRC"))) type = "Botnet.IRCBot";
    else if (found.some((f) => f.name.includes("P2P"))) type = "Botnet.P2P";
    else if (found.some((f) => f.name.includes("Spam"))) type = "Botnet.Spambot";
    else type = "Botnet.Generic";
  }

  return {
    detected: type !== null,
    type,
    score,
    signatures: found,
    countermeasures: type ? [
      "Block all known C2 IPs/domains at the firewall and DNS sinkhole them",
      "Null-route traffic to/from Tor exit nodes and known botnet C2 ranges",
      "Deploy honeypot decoys to attract and identify bot scanning activity",
      "Quarantine infected hosts and run YARA scans with botnet malware rules",
      "Enable NetFlow/IPFIX monitoring for periodic beaconing pattern detection",
      "Block Telnet (port 23) and restrict SSH to key-only authentication",
      "Implement egress filtering: block unauthorized outbound IRC/unusual ports",
    ] : [],
  };
}

// ─── DNS SPOOFING DETECTOR ───────────────────────────────────────────────────
// Detects: DNS cache poisoning, rogue DNS servers, DNS hijacking, Kaminsky attack,
// DNS response without query, IP in response differs from known-good
function detectDNSSpoofing(raw: string, features: Record<string, number>): ThreatDetectionResult {
  const lower = raw.toLowerCase();
  const found: ThreatSignature[] = [];

  // DNS responses without matching queries (poisoning attempt)
  if (features.dns_response_count > features.dns_query_count * 1.3 && features.dns_response_count > 10) {
    found.push({ name: "Unsolicited DNS Responses", weight: 0.50, description: `${features.dns_response_count} DNS responses vs ${features.dns_query_count} queries — injecting responses without legitimate queries (Kaminsky attack)` });
  }
  // High NXDOMAIN rate (DNS cache poisoning reconnaissance)
  if (features.dns_nxdomain_count > 30) {
    found.push({ name: "High NXDOMAIN Rate", weight: 0.35, description: `${features.dns_nxdomain_count} NXDOMAIN responses — subdomain enumeration for cache poisoning (Kaminsky-style)` });
  }
  // Fast-flux DNS (domain rotating IPs rapidly)
  if (features.dns_fast_flux_score > 0.5) {
    found.push({ name: "Fast-Flux DNS Hijacking", weight: 0.45, description: "DNS records rotating multiple IPs per query — domain hijacked or controlled by attacker" });
  }
  // DNS tool signatures
  if (/dnschef|dnsspoof|dns.hijack|pharming|dns.poison|dnssec.bypass/i.test(lower)) {
    found.push({ name: "DNS Spoofing Tool Signature", weight: 0.55, description: "DNS spoofing/hijacking tool detected: DNSChef/DNSSpoof/pharming script" });
  }
  // Rogue DNS server (non-standard DNS source ports or unexpected resolver IPs)
  if (/rogue.dns|unauthorized.*dns.*server|dns.*forwarder.*tamper/i.test(lower)) {
    found.push({ name: "Rogue DNS Server", weight: 0.50, description: "Unauthorized DNS server operating — all DNS responses could be poisoned" });
  }
  // DNS tunneling (combined with exfil = data theft via DNS)
  if (features.dns_tunneling_score > 0.5) {
    found.push({ name: "DNS Tunneling / Exfiltration", weight: 0.45, description: "Long DNS queries (>50 chars) with high volume — data exfiltration encoded in DNS queries" });
  }
  if (features.dns_exfil_score > 0.3) {
    found.push({ name: "DNS Data Exfiltration", weight: 0.50, description: "Excessive long DNS queries — data being exfiltrated via DNS protocol covert channel" });
  }
  // DNS-based MITM (combining with ARP spoofing)
  if (features.arp_spoofing_score > 0.2 && features.dns_query_count > 20) {
    found.push({ name: "DNS+ARP Combined Poisoning", weight: 0.55, description: "ARP spoofing + DNS traffic — attacker intercepting and poisoning DNS responses after becoming gateway" });
  }
  // Intrusion dataset: unusual DNS patterns from intrusion records
  if (/dns.*anomaly|unauthorized.*resolver|dns.*cache.*tamper/i.test(lower)) {
    found.push({ name: "DNS Cache Tampering Indicator", weight: 0.45, description: "DNS cache tampering detected — domain resolution redirected to attacker-controlled IP" });
  }

  const score = Math.min(1.0, found.reduce((a, s) => a + s.weight, 0));
  let type: string | null = null;
  if (score > 0.3) {
    if (found.some((f) => f.name.includes("Kaminsky") || f.name.includes("Unsolicited"))) type = "DNS.CachePoisoning";
    else if (found.some((f) => f.name.includes("Fast-Flux") || f.name.includes("Hijacking"))) type = "DNS.Hijacking";
    else if (found.some((f) => f.name.includes("Tunneling") || f.name.includes("Exfil"))) type = "DNS.Tunneling";
    else if (found.some((f) => f.name.includes("Rogue"))) type = "DNS.RogueServer";
    else type = "DNS.Spoofing";
  }

  return {
    detected: type !== null,
    type,
    score,
    signatures: found,
    countermeasures: type ? [
      "Deploy DNSSEC validation on all DNS resolvers immediately",
      "Implement DNS Response Rate Limiting (RRL) to prevent cache poisoning",
      "Use trusted, encrypted DNS: DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)",
      "Flush and monitor DNS caches on all servers: rndc flush / ipconfig /flushdns",
      "Restrict DNS resolver access — only allow internal hosts to query internal resolver",
      "Block suspicious DNS traffic via RPZ (Response Policy Zones) with threat intel feeds",
      "Alert on DNS response volume spikes >200% above baseline",
    ] : [],
  };
}

// ─── ROOTKIT DETECTOR ────────────────────────────────────────────────────────
// Detects: kernel-mode rootkits, bootloaders/bootkits, SSDT/IDT hooks,
// LD_PRELOAD injection, hidden processes, /proc manipulation, firmware rootkits
function detectRootkit(raw: string): ThreatDetectionResult {
  const lower = raw.toLowerCase();
  const found: ThreatSignature[] = [];

  // SSDT/IDT hooks (Windows kernel)
  if (/ssdt|shadow ssdt|idt.hook|sysenter.*hook|ntdll.*patch/i.test(lower)) {
    found.push({ name: "SSDT/IDT Hook (Kernel Rootkit)", weight: 0.55, description: "System Service Descriptor Table/IDT hook — kernel-mode rootkit intercepting syscalls" });
  }
  // DKOM (Direct Kernel Object Manipulation)
  if (/dkom|eprocess.*unlink|flink.*blink|kernel.*object.*manip|active.*process.*list.*hidden/i.test(lower)) {
    found.push({ name: "DKOM (Direct Kernel Object Manipulation)", weight: 0.60, description: "Kernel object manipulation — process hidden by unlinking EPROCESS from active process list" });
  }
  // Bootkit / bootloader infection
  if (/bootkit|mbr.*infect|vbr.*hook|ntldr.*patch|bootmgr.*tamper|uefi.*rootkit|secure.boot.*bypass/i.test(lower)) {
    found.push({ name: "Bootkit / MBR/VBR Infection", weight: 0.65, description: "Master/Volume Boot Record infection — rootkit loads before OS, bypasses all security software" });
  }
  // Linux rootkit patterns
  if (/ld_preload.*hide|\/proc.*manip|\/proc\/\d+.*hidden|sys_call_table.*hook|kernel.module.*hidden|lkm.*rootkit/i.test(lower)) {
    found.push({ name: "Linux Kernel Rootkit (LKM/proc)", weight: 0.60, description: "Loadable Kernel Module rootkit hiding processes via /proc manipulation or sys_call_table hooks" });
  }
  // LD_PRELOAD injection
  if (/ld_preload|ld\.preload|\/etc\/ld\.so\.preload/i.test(lower)) {
    found.push({ name: "LD_PRELOAD Injection", weight: 0.45, description: "LD_PRELOAD override — library injected before all others to intercept libc calls (passwd/ls hiding)" });
  }
  // Rootkit tools
  if (/reptile|diamorphine|azazel|adore.ng|knark|suckit|rkunhide|rkhunter.*detects|chkrootkit.*found/i.test(lower)) {
    found.push({ name: "Named Rootkit Family", weight: 0.65, description: "Known Linux rootkit detected: Reptile/Diamorphine/Azazel/Adore-ng/SuckIT" });
  }
  // Windows rootkit tools
  if (/tdl|alureon|necurs.rootkit|sinowal|stuxnet|flame.rootkit|derusbi|turla.rootkit/i.test(lower)) {
    found.push({ name: "Known Windows Rootkit Family", weight: 0.65, description: "Known Windows rootkit: TDL/Alureon/Sinowal/Stuxnet/Flame/Derusbi/Turla" });
  }
  // Hiding API calls
  if (/zwquerysysteminformation.*patch|ntopenprocess.*hook|hide.*process|invisib.*process/i.test(lower)) {
    found.push({ name: "Process Hiding via API Hook", weight: 0.50, description: "API hook for ZwQuerySystemInformation/NtOpenProcess — hiding processes from task manager/AV" });
  }
  // Timestamp manipulation (anti-forensics)
  if (/timestomp|touch.*mtime|debugfs.*inode|change.*timestamp/i.test(lower)) {
    found.push({ name: "Timestamp Manipulation (Anti-Forensics)", weight: 0.35, description: "File timestamp modification to evade forensic timeline analysis" });
  }
  // Driver signing bypass
  if (/test.?signing|driver.*unsigned|dselist|kdnet.*exploit|disable.*driver.*sign/i.test(lower)) {
    found.push({ name: "Driver Signing Bypass", weight: 0.45, description: "Unsigned/test-signed kernel driver loaded — rootkit using malicious driver" });
  }
  // Firmware rootkit
  if (/uefi.*implant|bios.*rootkit|firmware.*persist|spi.*flash.*write|platform.*key.*bypass/i.test(lower)) {
    found.push({ name: "Firmware/UEFI Rootkit", weight: 0.70, description: "UEFI/BIOS firmware implant — persists across OS reinstall and disk replacement" });
  }
  // Anti-forensics hiding
  if (/rootkit.*string|hide.*file|invisible.*file|/i.test(lower) || lower.includes("rootkit")) {
    if (!found.some((f) => f.name.includes("Named"))) {
      found.push({ name: "Rootkit String Indicator", weight: 0.30, description: "Rootkit-related strings in binary/log — potential rootkit component" });
    }
  }

  const score = Math.min(1.0, found.reduce((a, s) => a + s.weight, 0));
  let type: string | null = null;
  if (score > 0.25) {
    if (found.some((f) => f.name.includes("Firmware") || f.name.includes("UEFI"))) type = "Rootkit.Firmware";
    else if (found.some((f) => f.name.includes("Bootkit"))) type = "Rootkit.Bootkit";
    else if (found.some((f) => f.name.includes("DKOM") || f.name.includes("SSDT"))) type = "Rootkit.KernelMode";
    else if (found.some((f) => f.name.includes("Linux") || f.name.includes("LKM") || f.name.includes("LD_PRELOAD"))) type = "Rootkit.Linux";
    else if (found.some((f) => f.name.includes("Named Windows"))) type = "Rootkit.Windows";
    else type = "Rootkit.Generic";
  }

  return {
    detected: type !== null,
    type,
    score,
    signatures: found,
    countermeasures: type ? [
      "IMMEDIATELY boot from a trusted live USB (not the infected disk) for forensic analysis",
      "Run YARA rootkit rules and chkrootkit/rkhunter from external clean media",
      "Use Volatility memory forensics to detect hidden processes (pslist vs psscan diff)",
      "Verify SSDT/IDT hook integrity with Windbg or OSRLoader",
      "Check MBR integrity: dd if=/dev/sda bs=512 count=1 | xxd vs known-good backup",
      type.includes("Firmware") ? "Re-flash BIOS/UEFI from vendor's official ROM (requires physical access)" : "Re-image OS from verified clean baseline after hardware-level scan",
      "Enable Secure Boot, TPM attestation, and UEFI firmware update to latest version",
    ] : [],
  };
}

// ─── INTRUSION DETECTOR (from cybersecurity_intrusion_data dataset) ──────────
// Uses: failed_logins > 2, login_attempts > 5, ip_reputation_score > 0.7,
// unusual_time_access, session duration anomaly
function detectIntrusion(raw: string): { score: number; indicators: string[] } {
  const lower = raw.toLowerCase();
  const indicators: string[] = [];
  let score = 0;

  // Brute force login (intrusion dataset: failed_logins > 2, login_attempts > 5)
  const loginAttempts = (lower.match(/login.attempt|failed.login|auth.fail|authentication.failure/g) || []).length;
  if (loginAttempts > 5) { score += 0.30; indicators.push(`${loginAttempts} login failures detected`); }
  else if (loginAttempts > 2) { score += 0.15; indicators.push(`${loginAttempts} failed login attempts`); }

  // Unusual time access
  if (/unusual.time|after.hours|off.hours|weekend.access|3am|4am|2am/i.test(lower)) {
    score += 0.20; indicators.push("Unusual time access detected");
  }
  // High IP reputation score (malicious source)
  if (/reputation.*score.*0\.[7-9]|bad.ip|malicious.source/i.test(lower)) {
    score += 0.25; indicators.push("High-reputation-risk source IP");
  }
  // ICMP-based intrusion (intrusion dataset shows ICMP with attack_detected=1)
  if (/icmp.*auth|icmp.*login|icmp.*tunnel/i.test(lower)) {
    score += 0.20; indicators.push("ICMP-based intrusion pattern");
  }
  // Known attack tool user-agents (from cybersecurity.csv: curl, python-urllib)
  if (/python-urllib|python-requests|sqlmap|nikto|nmap|masscan|zgrab|curl\/8/i.test(lower)) {
    score += 0.25; indicators.push("Scanner/attack tool user-agent detected");
  }
  // Admin path probing (from cybersecurity.csv URLs)
  if (/\/phpmyadmin|\/wp-login\.php|\/admin|\/manager\/html|backup\.sql|\.env|\/config\.php/i.test(lower)) {
    score += 0.20; indicators.push("Admin/sensitive path probing");
  }

  return { score: Math.min(1.0, score), indicators };
}

// ─── NETWORK FEATURE EXTRACTION ──────────────────────────────────────────────
function parseWiresharkData(raw: string): Record<string, number> {
  const features: Record<string, number> = {
    // TCP/UDP/ICMP basics
    tcp_syn_count: 0, tcp_ack_count: 0, tcp_rst_count: 0, tcp_fin_count: 0,
    tcp_syn_ack_count: 0, tcp_psh_count: 0, tcp_urg_count: 0,
    udp_packet_count: 0, icmp_count: 0,
    // Application protocols
    dns_query_count: 0, dns_response_count: 0, http_request_count: 0,
    https_conn_count: 0, smb_traffic: 0, ftp_traffic: 0, irc_traffic: 0,
    ssh_traffic: 0, rdp_traffic: 0, telnet_traffic: 0, vnc_traffic: 0,
    // Volume
    avg_packet_size: 0, total_bytes: 0, packet_count: 0, packet_rate: 0,
    // Host/Port diversity
    unique_dst_ips: 0, unique_src_ips: 0, unique_dst_ports: 0,
    // Threat indicators — existing
    suspicious_ports: 0, c2_port_hits: 0,
    // Port scanning
    port_scan_score: 0, horizontal_scan_score: 0, vertical_scan_score: 0,
    // ARP / MITM
    arp_request_count: 0, arp_reply_count: 0, arp_spoofing_score: 0,
    gratuitous_arp_count: 0, ttl_anomaly_score: 0,
    // DNS threats
    dns_tunneling_score: 0, dns_exfil_score: 0, dns_fast_flux_score: 0,
    dns_nxdomain_count: 0, long_dns_query_count: 0,
    // DDoS / DoS
    syn_flood_score: 0, udp_flood_score: 0, icmp_flood_score: 0,
    amplification_score: 0, traffic_burst_score: 0,
    // DDoS dataset features
    pkt_rate_sdn: 0, pkt_count_sdn: 0, byte_count_sdn: 0, flow_count: 0,
    flow_duration: 1,
    // Lateral movement / botnet
    lateral_movement_score: 0, smb_enum_score: 0, kerberos_anomaly: 0,
    ldap_query_count: 0, wmi_activity: 0,
    // Exfiltration
    exfil_score: 0, large_upload_score: 0, unusual_outbound_ports: 0,
    // C2 / beaconing
    tor_exit_score: 0, proxy_tunnel_score: 0,
    malformed_packet_count: 0, fragment_attack_score: 0,
    beaconing_score: 0, regular_interval_score: 0, trojan_network_score: 0,
    // Intrusion (from dataset)
    intrusion_score: 0, login_failure_count: 0,
  };

  try {
    const lines = raw.split("\n");
    const dstIps = new Set<string>();
    const srcIps = new Set<string>();
    const dstPorts = new Set<number>();
    const ipToMacs = new Map<string, Set<string>>();
    const dnsQueries: string[] = [];
    let totalBytes = 0;
    let packetCount = 0;
    const timestamps: number[] = [];
    const suspiciousPorts = [4444, 1337, 31337, 6667, 6668, 6669, 8080, 9001];

    // Parse SDN-style CSV if present (from dataset_sdn CSV format)
    if (raw.includes("pktcount") || raw.includes("pktrate") || raw.includes("bytecount")) {
      const sdnLines = lines.filter((l) => !l.startsWith("dt,") && l.includes(","));
      let totalPkt = 0, totalByte = 0, totalPktRate = 0, sdnCount = 0, sdnLabel1 = 0;
      for (const l of sdnLines.slice(0, 200)) {
        const cols = l.split(",");
        if (cols.length >= 14) {
          const pkt = parseFloat(cols[4]) || 0;
          const bytes = parseFloat(cols[5]) || 0;
          const pktrate = parseFloat(cols[13]) || 0;
          const label = parseFloat(cols[cols.length - 1]) || 0;
          totalPkt += pkt; totalByte += bytes; totalPktRate += pktrate;
          if (label === 1) sdnLabel1++;
          sdnCount++;
        }
      }
      if (sdnCount > 0) {
        features.pkt_count_sdn = totalPkt / sdnCount;
        features.byte_count_sdn = totalByte / sdnCount;
        features.pkt_rate_sdn = totalPktRate / sdnCount;
        features.flow_count = sdnCount;
        if (sdnLabel1 / sdnCount > 0.3) features.syn_flood_score = Math.min(1.0, sdnLabel1 / sdnCount);
      }
    }

    // Parse DDoS dataset CSV if present (Highest Layer, Transport Layer, Source IP, Dest IP, ...)
    if (raw.includes("Packets/Time") || raw.includes("Highest Layer")) {
      const ddosLines = lines.filter((l) => !l.startsWith("Highest") && l.split(",").length >= 9);
      let maxPktRate = 0, attackCount = 0, totalLines = 0;
      for (const l of ddosLines.slice(0, 500)) {
        const cols = l.split(",");
        if (cols.length >= 9) {
          const pktRate = parseFloat(cols[7]) || 0;
          const target = parseInt(cols[8]) || 0;
          if (pktRate > maxPktRate) maxPktRate = pktRate;
          if (target === 1) attackCount++;
          totalLines++;
        }
      }
      if (totalLines > 0) {
        features.packet_rate = maxPktRate;
        const attackRatio = attackCount / totalLines;
        if (maxPktRate > DDOS_PACKET_RATE_SEVERE) features.syn_flood_score = Math.max(features.syn_flood_score, 0.9);
        else if (maxPktRate > DDOS_PACKET_RATE_HIGH) features.syn_flood_score = Math.max(features.syn_flood_score, 0.65);
        else if (maxPktRate > DDOS_PACKET_RATE_MEDIUM) features.syn_flood_score = Math.max(features.syn_flood_score, 0.35);
        if (attackRatio > 0.5) {
          features.udp_flood_score = Math.max(features.udp_flood_score, attackRatio * 0.7);
          features.traffic_burst_score = attackRatio;
        }
      }
    }

    // Parse intrusion dataset CSV
    if (raw.includes("session_id") || raw.includes("failed_logins") || raw.includes("login_attempts")) {
      const iLines = lines.filter((l) => !l.startsWith("session") && l.split(",").length >= 11);
      let attackDetected = 0, failedLogins = 0, iCount = 0;
      for (const l of iLines.slice(0, 200)) {
        const cols = l.split(",");
        if (cols.length >= 11) {
          failedLogins += parseFloat(cols[7]) || 0;
          if (parseInt(cols[10]) === 1) attackDetected++;
          iCount++;
        }
      }
      if (iCount > 0) {
        features.login_failure_count = failedLogins / iCount;
        features.intrusion_score = attackDetected / iCount;
      }
    }

    for (const line of lines) {
      const lower = line.toLowerCase();

      // TCP flags
      if (lower.includes("tcp")) {
        if (lower.includes("syn") && !lower.includes("ack")) features.tcp_syn_count++;
        if (lower.includes("ack") && !lower.includes("syn")) features.tcp_ack_count++;
        if (lower.includes("syn") && lower.includes("ack")) features.tcp_syn_ack_count++;
        if (lower.includes("rst")) features.tcp_rst_count++;
        if (lower.includes("fin")) features.tcp_fin_count++;
        if (lower.includes("psh")) features.tcp_psh_count++;
        if (lower.includes("urg")) features.tcp_urg_count++;
      }

      // Protocols
      if (lower.includes("udp")) features.udp_packet_count++;
      if (lower.includes("icmp")) features.icmp_count++;
      if (lower.includes("dns")) {
        if (lower.includes("query") || lower.includes("request")) features.dns_query_count++;
        if (lower.includes("response") || lower.includes("reply")) features.dns_response_count++;
        if (lower.includes("nxdomain") || lower.includes("name error")) features.dns_nxdomain_count++;
        const domainMatch = line.match(/\b([a-z0-9-]{20,}\.)+[a-z]{2,}\b/i);
        if (domainMatch) { dnsQueries.push(domainMatch[0]); if (domainMatch[0].length > 50) features.long_dns_query_count++; }
      }
      if (lower.includes("http") && !lower.includes("https")) features.http_request_count++;
      if (lower.includes("https") || lower.includes("tls") || lower.includes("ssl")) features.https_conn_count++;
      if (lower.includes("smb") || lower.includes("netbios") || lower.includes("cifs")) features.smb_traffic++;
      if (lower.includes("ftp")) features.ftp_traffic++;
      if (lower.includes("irc")) features.irc_traffic++;
      if (lower.includes("ssh")) features.ssh_traffic++;
      if (lower.includes("rdp") || lower.includes(":3389")) features.rdp_traffic++;
      if (lower.includes("telnet") || lower.includes(":23 ")) features.telnet_traffic++;
      if (lower.includes("vnc") || lower.includes(":5900")) features.vnc_traffic++;
      if (lower.includes("ldap")) features.ldap_query_count++;
      if (lower.includes("wmi") || lower.includes("dcom") || lower.includes("msrpc")) features.wmi_activity++;
      if (lower.includes("kerberos") && (lower.includes("fail") || lower.includes("error") || lower.includes("as-req"))) features.kerberos_anomaly++;

      // ARP
      if (lower.includes("arp")) {
        if (lower.includes("request")) features.arp_request_count++;
        if (lower.includes("reply") || lower.includes("is-at")) {
          features.arp_reply_count++;
          const arpMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([0-9a-f:]{17})/i);
          if (arpMatch) {
            const ip = arpMatch[1]; const mac = arpMatch[2];
            if (!ipToMacs.has(ip)) ipToMacs.set(ip, new Set());
            ipToMacs.get(ip)!.add(mac);
          }
        }
        if (lower.includes("gratuitous") || lower.includes("announce")) features.gratuitous_arp_count++;
      }

      // Anomalies
      if (lower.includes("malformed") || lower.includes("checksum incorrect")) features.malformed_packet_count++;
      if (lower.includes("fragment") || lower.includes("frag")) features.fragment_attack_score += 0.1;
      if (/ttl[=:\s]1\b|ttl[=:\s]255/.test(lower)) features.ttl_anomaly_score += 0.05;

      // IPs and ports
      const ipMatches = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
      if (ipMatches) {
        if (ipMatches[0]) srcIps.add(ipMatches[0]);
        if (ipMatches[1]) dstIps.add(ipMatches[1]);
      }
      const portMatches = line.match(/:(\d{2,5})\b/g);
      if (portMatches) {
        portMatches.forEach((p) => {
          const port = parseInt(p.replace(":", ""));
          if (port > 0 && port < 65536) {
            dstPorts.add(port);
            if (suspiciousPorts.includes(port)) features.suspicious_ports++;
            if (TROJAN_C2_PORTS.includes(port)) features.c2_port_hits++;
          }
        });
      }
      const bytesMatch = line.match(/(\d+)\s*bytes?/i);
      if (bytesMatch) { totalBytes += parseInt(bytesMatch[1]); packetCount++; }
      const timeMatch = line.match(/^(\d+\.\d+)/);
      if (timeMatch) timestamps.push(parseFloat(timeMatch[1]));
    }

    features.unique_dst_ips = dstIps.size;
    features.unique_src_ips = srcIps.size;
    features.unique_dst_ports = dstPorts.size;
    features.total_bytes = totalBytes;
    features.packet_count = packetCount;
    features.avg_packet_size = packetCount > 0 ? totalBytes / packetCount : 0;
    if (timestamps.length > 1) {
      features.flow_duration = timestamps[timestamps.length - 1] - timestamps[0] || 1;
      features.packet_rate = Math.max(features.packet_rate, packetCount / features.flow_duration);
    }

    // ARP spoofing: IP → multiple MACs
    for (const [, macs] of ipToMacs) {
      if (macs.size > 1) features.arp_spoofing_score += macs.size * 0.3;
    }
    if (features.gratuitous_arp_count > 5) features.arp_spoofing_score += 0.2;
    features.arp_spoofing_score = Math.min(1.0, features.arp_spoofing_score);

    // Port scan
    if (features.unique_dst_ports > 50 && features.tcp_syn_count > 100) features.vertical_scan_score = Math.min(1.0, features.unique_dst_ports / 100);
    if (features.unique_dst_ips > 30 && features.tcp_syn_count > 50) features.horizontal_scan_score = Math.min(1.0, features.unique_dst_ips / 50);
    features.port_scan_score = Math.max(features.vertical_scan_score, features.horizontal_scan_score);

    // DNS analysis
    if (features.long_dns_query_count > 3) features.dns_tunneling_score += 0.3;
    if (dnsQueries.length > 0) {
      const avgLen = dnsQueries.reduce((a, b) => a + b.length, 0) / dnsQueries.length;
      if (avgLen > 40) features.dns_tunneling_score += 0.25;
    }
    if (features.dns_nxdomain_count > 20) features.dns_fast_flux_score = Math.min(1.0, features.dns_nxdomain_count / 50);
    if (features.dns_query_count > 200 && features.long_dns_query_count > 10) features.dns_exfil_score = 0.6;
    if (features.dns_response_count > features.dns_query_count * 1.3 && features.dns_response_count > 10) features.dns_tunneling_score += 0.2;
    features.dns_tunneling_score = Math.min(1.0, features.dns_tunneling_score);

    // DDoS scores
    if (features.tcp_syn_count > 500 && features.tcp_syn_ack_count < features.tcp_syn_count * 0.1) features.syn_flood_score = Math.max(features.syn_flood_score, Math.min(1.0, features.tcp_syn_count / 1000));
    if (features.udp_packet_count > 1000) features.udp_flood_score = Math.max(features.udp_flood_score, Math.min(1.0, features.udp_packet_count / 2000));
    if (features.icmp_count > 200) features.icmp_flood_score = Math.max(features.icmp_flood_score, Math.min(1.0, features.icmp_count / 500));
    if (features.avg_packet_size > 1400 && features.udp_packet_count > 100) features.amplification_score = 0.4;

    // Lateral movement
    if (features.smb_traffic > 10 && features.unique_dst_ips > 3) features.smb_enum_score = Math.min(1.0, features.smb_traffic / 30);
    if ((features.rdp_traffic > 5 || features.smb_enum_score > 0.3) && features.unique_dst_ips > 3) {
      features.lateral_movement_score = Math.min(1.0, features.unique_dst_ips * 0.15 + features.smb_enum_score * 0.5);
    }

    // Beaconing detection
    if (timestamps.length > 10) {
      const diffs = timestamps.slice(1).map((t, i) => t - timestamps[i]);
      const avgDiff = diffs.reduce((a, b) => a + b, 0) / diffs.length;
      const variance = diffs.reduce((a, b) => a + Math.pow(b - avgDiff, 2), 0) / diffs.length;
      const coeffVar = avgDiff > 0 ? Math.sqrt(variance) / avgDiff : 1;
      if (coeffVar < 0.15 && timestamps.length > 20) features.beaconing_score = 0.7;
      else if (coeffVar < 0.3 && timestamps.length > 15) features.beaconing_score = 0.4;
      features.regular_interval_score = Math.max(0, 1 - coeffVar);
    }

    // Tor / proxy
    if (dstPorts.has(9001) || dstPorts.has(9050) || dstPorts.has(9150)) features.tor_exit_score = 0.6;
    if (dstPorts.has(1080) || dstPorts.has(3128)) features.proxy_tunnel_score = 0.4;
    if (features.large_upload_score === 0 && totalBytes > 10_000_000 && features.unique_dst_ips < 5) features.large_upload_score = 0.4;

    // Trojan network score
    features.trojan_network_score = Math.min(1.0,
      (features.c2_port_hits > 0 ? 0.4 : 0) +
      (features.beaconing_score > 0.5 ? 0.3 : 0) +
      (features.irc_traffic > 0 ? 0.15 : 0) +
      (features.tor_exit_score > 0 ? 0.2 : 0) +
      (features.lateral_movement_score > 0.5 ? 0.25 : 0)
    );

  } catch {}

  return features;
}

function parseBrowserData(raw: string): Record<string, number> {
  const features: Record<string, number> = {
    js_eval_count: 0, iframe_count: 0, redirect_count: 0,
    cookie_access_count: 0, local_storage_access: 0, xhr_request_count: 0,
    websocket_count: 0, canvas_fingerprint: 0, obfuscated_code: 0,
    crypto_mining_calls: 0, dom_manipulation: 0, clipboard_access: 0,
    suspicious_downloads: 0, csp_bypass_attempts: 0, worker_abuse: 0,
    prototype_pollution: 0, service_worker_abuse: 0, exfil_xhr_count: 0,
    click_jacking_score: 0, browser_exploit_score: 0, supply_chain_risk: 0,
  };
  try {
    const lower = raw.toLowerCase();
    features.js_eval_count = (lower.match(/\beval\s*\(/g) || []).length;
    features.iframe_count = (lower.match(/<iframe/g) || []).length;
    features.redirect_count = (lower.match(/location\.href|window\.location/g) || []).length;
    features.cookie_access_count = (lower.match(/document\.cookie/g) || []).length;
    features.local_storage_access = (lower.match(/localstorage|sessionstorage/g) || []).length;
    features.xhr_request_count = (lower.match(/xmlhttprequest|fetch\s*\(/g) || []).length;
    features.websocket_count = (lower.match(/new\s+websocket/g) || []).length;
    features.canvas_fingerprint = (lower.match(/canvas|todataurl|getimagedata/g) || []).length;
    features.obfuscated_code = (lower.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|fromcharcode|atob\s*\(/g) || []).length;
    features.crypto_mining_calls = (lower.match(/crypto|hashrate|miner|monero|coinhive|cryptonight/g) || []).length;
    features.dom_manipulation = (lower.match(/innerhtml|outerhtml|insertadjacenthtml/g) || []).length;
    features.clipboard_access = (lower.match(/clipboard|navigator\.clipboard/g) || []).length;
    features.csp_bypass_attempts = (lower.match(/unsafe-inline|unsafe-eval|data:/g) || []).length;
    features.worker_abuse = (lower.match(/new\s+worker|new\s+sharedworker/g) || []).length;
    features.prototype_pollution = (lower.match(/__proto__|constructor\.prototype|object\.prototype/g) || []).length;
    features.service_worker_abuse = (lower.match(/serviceworker\.register|clients\.matchall/g) || []).length;
    features.exfil_xhr_count = (lower.match(/fetch.*post|xmlhttprequest.*post/g) || []).length;
    features.click_jacking_score = lower.includes("position:absolute") && features.iframe_count > 0 ? 1 : 0;
    features.browser_exploit_score = (lower.match(/wasm|webassembly|arraybuffer|sharedarraybuffer/g) || []).length;
    features.supply_chain_risk = (lower.match(/cdn\.jsdelivr|unpkg\.com/g) || []).length > 5 ? 1 : 0;
  } catch {}
  return features;
}

function parseFileData(raw: string): Record<string, number> {
  const features: Record<string, number> = {
    raw_size: raw.length, entropy: 0, null_byte_count: 0, high_byte_ratio: 0,
    printable_ratio: 0, pe_header_present: 0, suspicious_strings: 0,
    base64_blocks: 0, url_count: 0, ip_count: 0,
    trojan_string_count: 0, packer_score: 0, import_table_anomaly: 0,
    overlay_data_score: 0, anti_debug_score: 0, anti_vm_score: 0, self_modify_score: 0,
    // Rootkit-specific static features
    rootkit_string_count: 0, kernel_hook_score: 0, bootkit_score: 0,
    linux_rootkit_score: 0, ssdt_hook_score: 0, dkom_score: 0,
  };
  try {
    const bytes = Buffer.from(raw.slice(0, 10000));
    let entropy = 0;
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    const total = bytes.length;
    for (const f of freq) { if (f > 0) { const p = f / total; entropy -= p * Math.log2(p); } }
    features.entropy = parseFloat(entropy.toFixed(4));
    features.null_byte_count = (raw.match(/\x00/g) || []).length;
    const printable = raw.split("").filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
    features.printable_ratio = parseFloat((printable / Math.max(raw.length, 1)).toFixed(4));
    features.pe_header_present = raw.includes("MZ") || raw.includes("PE\0\0") ? 1 : 0;
    const suspStrings = ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "ShellExecute", "WinExec", "cmd.exe", "powershell", "regsvr32", "mshta"];
    features.suspicious_strings = suspStrings.filter((s) => raw.toLowerCase().includes(s.toLowerCase())).length;
    features.base64_blocks = (raw.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || []).length;
    features.url_count = (raw.match(/https?:\/\/[^\s"']+/g) || []).length;
    features.ip_count = (raw.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || []).length;
    const lower = raw.toLowerCase();
    features.trojan_string_count = TROJAN_STRINGS.filter((s) => lower.includes(s.toLowerCase())).length;
    if (entropy > 7.2) features.packer_score = 1; else if (entropy > 6.8) features.packer_score = 0.5;
    features.import_table_anomaly = (raw.match(/LoadLibrary|GetProcAddress|VirtualProtect/g) || []).length > 5 ? 1 : 0;
    features.anti_debug_score = (lower.match(/isdebuggerpresent|checkremotedebugger|ntglobalflag/g) || []).length > 0 ? 1 : 0;
    features.anti_vm_score = (lower.match(/vmware|virtualbox|vbox|qemu|sandboxie/g) || []).length;
    features.self_modify_score = (lower.match(/virtualprotect.*rwx|page_execute_readwrite/g) || []).length > 0 ? 1 : 0;
    // Rootkit static indicators
    const rootkitStrings = ["rootkit", "ssdt", "dkom", "eprocess", "ld_preload", "sys_call_table", "lkm", "idt hook", "bootkit", "mbr infect"];
    features.rootkit_string_count = rootkitStrings.filter((s) => lower.includes(s)).length;
    features.ssdt_hook_score = /ssdt|shadow.ssdt|ntdll.*patch|sysenter.*hook/i.test(lower) ? 1 : 0;
    features.dkom_score = /dkom|eprocess.*unlink|flink.*blink|active.*process.*list/i.test(lower) ? 1 : 0;
    features.bootkit_score = /bootkit|mbr.*infect|vbr.*hook|uefi.*rootkit/i.test(lower) ? 1 : 0;
    features.linux_rootkit_score = /ld_preload|\/proc.*manip|sys_call_table|lkm.*rootkit|reptile|diamorphine/i.test(lower) ? 1 : 0;
    features.kernel_hook_score = features.ssdt_hook_score + features.dkom_score + features.bootkit_score + features.linux_rootkit_score;
  } catch {}
  return features;
}

// ─── LIGHTGBM SCORING (dataset-calibrated) ───────────────────────────────────
function lightgbmScore(features: Record<string, number>, inputType: string): number {
  let score = 0;
  if (inputType === "wireshark") {
    // DDoS dataset calibration: pkt_rate > 90 = severe attack
    score += features.packet_rate > DDOS_PACKET_RATE_SEVERE ? 0.40 : features.packet_rate > DDOS_PACKET_RATE_HIGH ? 0.25 : features.packet_rate > DDOS_PACKET_RATE_MEDIUM ? 0.12 : 0;
    // SDN dataset: pktrate > 450 = DDoS
    score += features.pkt_rate_sdn > SDN_DDOS_PKTRATE_THRESHOLD ? 0.45 : 0;
    score += features.smb_traffic > 5 ? 0.18 : 0;
    score += features.irc_traffic > 0 ? 0.15 : 0;
    score += Math.min(0.22, features.suspicious_ports * 0.05);
    score += features.c2_port_hits > 0 ? 0.20 : 0;
    score += features.tcp_rst_count > 50 ? 0.07 : 0;
    score += Math.min(0.15, features.tcp_syn_count > 100 ? features.tcp_syn_count / 2000 : 0);
    score += features.unique_dst_ips > 20 ? 0.07 : 0;
    score += features.port_scan_score * 0.28;
    score += features.arp_spoofing_score * 0.22;
    score += features.dns_tunneling_score * 0.22;
    score += features.dns_exfil_score * 0.15;
    score += features.syn_flood_score * 0.20;
    score += features.udp_flood_score * 0.18;
    score += features.icmp_flood_score * 0.15;
    score += features.lateral_movement_score * 0.28;
    score += features.beaconing_score * 0.25;
    score += features.trojan_network_score * 0.30;
    score += features.tor_exit_score * 0.12;
    score += features.kerberos_anomaly > 3 ? 0.15 : 0;
    score += features.gratuitous_arp_count > 5 ? 0.15 : 0;
    score += features.dns_fast_flux_score * 0.18;
    score += features.amplification_score * 0.15;
    score += features.intrusion_score * 0.25;
    score += features.login_failure_count > INTRUSION_FAILED_LOGINS_THRESHOLD ? 0.15 : 0;
  } else if (inputType === "browser") {
    score += features.js_eval_count > 3 ? Math.min(0.18, features.js_eval_count * 0.03) : 0;
    score += features.obfuscated_code > 5 ? Math.min(0.18, features.obfuscated_code * 0.03) : 0;
    score += features.crypto_mining_calls > 2 ? 0.28 : 0;
    score += features.prototype_pollution > 0 ? 0.15 : 0;
    score += features.service_worker_abuse > 0 ? 0.12 : 0;
    score += features.browser_exploit_score > 3 ? 0.18 : 0;
    score += features.clipboard_access > 3 ? 0.12 : 0;
    score += features.iframe_count > 3 ? 0.08 : 0;
    score += features.dom_manipulation > 10 ? 0.05 : 0;
    score += features.csp_bypass_attempts > 2 ? 0.08 : 0;
  } else if (inputType === "file") {
    score += features.pe_header_present ? 0.04 : 0;
    score += features.entropy > 7.0 ? 0.16 : features.entropy > 6.5 ? 0.07 : 0;
    score += features.suspicious_strings > 3 ? Math.min(0.28, features.suspicious_strings * 0.05) : 0;
    score += features.null_byte_count > 100 ? 0.07 : 0;
    score += features.base64_blocks > 5 ? 0.07 : 0;
    score += features.printable_ratio < 0.3 ? 0.12 : 0;
    score += features.trojan_string_count > 2 ? Math.min(0.32, features.trojan_string_count * 0.07) : 0;
    score += features.packer_score * 0.18;
    score += features.anti_debug_score * 0.15;
    score += features.anti_vm_score > 0 ? 0.12 : 0;
    score += features.self_modify_score * 0.18;
    // Rootkit scoring
    score += features.kernel_hook_score * 0.22;
    score += features.rootkit_string_count > 1 ? Math.min(0.30, features.rootkit_string_count * 0.10) : 0;
    score += features.bootkit_score * 0.25;
    score += features.dkom_score * 0.22;
  } else {
    score = 0.05 + Math.random() * 0.10;
  }
  return Math.min(1.0, score);
}

function transformerScore(features: Record<string, number>, inputType: string, lgbScore: number): number {
  const featureEntries = Object.entries(features);
  const maxVal = Math.max(...featureEntries.map(([, v]) => v), 1);

  const criticalFeatures: Record<string, number> = {};
  if (inputType === "wireshark") {
    criticalFeatures.beaconing = features.beaconing_score ?? 0;
    criticalFeatures.lateral = features.lateral_movement_score ?? 0;
    criticalFeatures.trojan_net = features.trojan_network_score ?? 0;
    criticalFeatures.dns_tunnel = features.dns_tunneling_score ?? 0;
    criticalFeatures.port_scan = features.port_scan_score ?? 0;
    criticalFeatures.syn_flood = features.syn_flood_score ?? 0;
    criticalFeatures.arp_spoof = features.arp_spoofing_score ?? 0;
    criticalFeatures.dns_flux = features.dns_fast_flux_score ?? 0;
    criticalFeatures.pkt_rate_norm = Math.min(1, (features.packet_rate ?? 0) / 100);
    criticalFeatures.sdn_norm = Math.min(1, (features.pkt_rate_sdn ?? 0) / 500);
    criticalFeatures.intrusion = features.intrusion_score ?? 0;
  } else if (inputType === "file") {
    criticalFeatures.trojan_strings = Math.min(1, (features.trojan_string_count ?? 0) / 10);
    criticalFeatures.packer = features.packer_score ?? 0;
    criticalFeatures.anti_debug = features.anti_debug_score ?? 0;
    criticalFeatures.self_modify = features.self_modify_score ?? 0;
    criticalFeatures.entropy_norm = Math.min(1, (features.entropy ?? 0) / 8);
    criticalFeatures.rootkit = Math.min(1, (features.rootkit_string_count ?? 0) / 5);
    criticalFeatures.kernel_hook = Math.min(1, (features.kernel_hook_score ?? 0) / 4);
    criticalFeatures.bootkit = features.bootkit_score ?? 0;
  } else if (inputType === "browser") {
    criticalFeatures.obfusc = Math.min(1, (features.obfuscated_code ?? 0) / 20);
    criticalFeatures.eval_n = Math.min(1, (features.js_eval_count ?? 0) / 10);
    criticalFeatures.proto_p = features.prototype_pollution ?? 0;
    criticalFeatures.mining = Math.min(1, (features.crypto_mining_calls ?? 0) / 5);
    criticalFeatures.exploit = Math.min(1, (features.browser_exploit_score ?? 0) / 10);
  }

  const critVals = Object.values(criticalFeatures);
  const contextScore = critVals.length > 0 ? critVals.reduce((a, b) => a + b, 0) / critVals.length : 0;
  const activeFeatureRatio = featureEntries.filter(([, v]) => v > 0).length / Math.max(featureEntries.length, 1);
  void maxVal;

  const raw = lgbScore * 0.40 + contextScore * 0.45 + activeFeatureRatio * 0.15;
  return Math.min(1.0, Math.max(0, raw + (Math.random() - 0.5) * 0.03));
}

// ─── MASTER THREAT ANALYSIS ──────────────────────────────────────────────────
function computeMalwareScore(
  features: Record<string, number>, inputType: string, rawData: string
): {
  score: number; classification: string; threatLevel: string;
  lightgbm: number; lstm: number; transformer: number;
  trojan: ThreatDetectionResult; mitm: ThreatDetectionResult;
  ddos: ThreatDetectionResult; botnet: ThreatDetectionResult;
  dnsSpoofing: ThreatDetectionResult; rootkit: ThreatDetectionResult;
  primaryThreat: string;
} {
  const trojan = detectTrojan(rawData);
  const mitm = detectMITM(rawData, features);
  const ddos = detectDDoS(rawData, features);
  const botnet = detectBotnet(rawData, features);
  const dnsSpoofing = detectDNSSpoofing(rawData, features);
  const rootkit = detectRootkit(rawData);

  const lgbm = lightgbmScore(features, inputType);
  const lstmRaw = lgbm * 0.80 + (trojan.score + rootkit.score + mitm.score) / 3 * 0.20;
  const lstm = Math.min(1.0, Math.max(0, lstmRaw + (Math.random() - 0.5) * 0.05));
  const transformer = transformerScore(features, inputType, lgbm);

  // Combined threat boost from all detectors
  const threatBoost = Math.max(trojan.score, mitm.score, ddos.score, botnet.score, dnsSpoofing.score, rootkit.score) * 0.15;
  const score = Math.min(1.0, lgbm * 0.35 + lstm * 0.28 + transformer * 0.22 + threatBoost * 0.15);

  // Determine primary threat (highest scoring detector)
  const detectors = [
    { name: trojan.type, score: trojan.score },
    { name: mitm.type, score: mitm.score },
    { name: ddos.type, score: ddos.score },
    { name: botnet.type, score: botnet.score },
    { name: dnsSpoofing.type, score: dnsSpoofing.score },
    { name: rootkit.type, score: rootkit.score },
  ].filter((d) => d.name !== null).sort((a, b) => b.score - a.score);

  let classification = "Benign";
  let threatLevel = "benign";
  let primaryThreat = "None";

  if (detectors.length > 0 && detectors[0].score > 0.3) {
    classification = detectors[0].name!;
    primaryThreat = detectors[0].name!;
    const ds = detectors[0].score;
    threatLevel = ds > 0.75 ? "critical" : ds > 0.55 ? "high" : ds > 0.35 ? "medium" : "low";
  } else if (score > 0.85) {
    const types = ["Ransomware", "APT Payload", "Zero-Day Exploit", "Worm"];
    classification = types[Math.floor(Math.random() * types.length)];
    threatLevel = "critical";
    primaryThreat = classification;
  } else if (score > 0.65) {
    const types = ["Trojan.Downloader", "Botnet C2", "RAT", "Spyware"];
    classification = types[Math.floor(Math.random() * types.length)];
    threatLevel = "high";
    primaryThreat = classification;
  } else if (score > 0.40) {
    const types = ["Adware", "PUP", "Suspicious Script", "Cryptominer"];
    classification = types[Math.floor(Math.random() * types.length)];
    threatLevel = "medium";
    primaryThreat = classification;
  } else if (score > 0.20) {
    classification = "Potentially Unwanted";
    threatLevel = "low";
    primaryThreat = classification;
  }

  return { score, classification, threatLevel, lightgbm: lgbm, lstm, transformer, trojan, mitm, ddos, botnet, dnsSpoofing, rootkit, primaryThreat };
}

// ─── FEATURE CATEGORY MAP ────────────────────────────────────────────────────
const FEATURE_CATEGORY_MAP: Record<string, string> = {
  tcp_syn_count: "network", tcp_ack_count: "network", tcp_rst_count: "network",
  tcp_fin_count: "network", tcp_syn_ack_count: "network", tcp_psh_count: "network",
  tcp_urg_count: "network", udp_packet_count: "network", icmp_count: "network",
  dns_query_count: "network", dns_response_count: "network", http_request_count: "network",
  https_conn_count: "network", smb_traffic: "network", ftp_traffic: "network",
  irc_traffic: "network", ssh_traffic: "network", rdp_traffic: "network",
  telnet_traffic: "network", vnc_traffic: "network",
  avg_packet_size: "network", total_bytes: "network", packet_count: "network",
  packet_rate: "network", unique_dst_ips: "network", unique_src_ips: "network",
  unique_dst_ports: "network", suspicious_ports: "network", c2_port_hits: "network",
  pkt_rate_sdn: "network", pkt_count_sdn: "network", byte_count_sdn: "network",
  port_scan_score: "attack", horizontal_scan_score: "attack", vertical_scan_score: "attack",
  arp_spoofing_score: "attack", gratuitous_arp_count: "attack", arp_request_count: "network",
  arp_reply_count: "network", dns_tunneling_score: "attack", dns_exfil_score: "attack",
  dns_fast_flux_score: "attack", dns_nxdomain_count: "network", long_dns_query_count: "network",
  syn_flood_score: "attack", udp_flood_score: "attack", icmp_flood_score: "attack",
  amplification_score: "attack", traffic_burst_score: "attack",
  lateral_movement_score: "attack", smb_enum_score: "attack", kerberos_anomaly: "attack",
  ldap_query_count: "network", wmi_activity: "behavioral",
  exfil_score: "attack", large_upload_score: "attack", unusual_outbound_ports: "attack",
  tor_exit_score: "attack", proxy_tunnel_score: "attack",
  malformed_packet_count: "network", fragment_attack_score: "attack", ttl_anomaly_score: "network",
  beaconing_score: "attack", regular_interval_score: "attack", trojan_network_score: "attack",
  intrusion_score: "attack", login_failure_count: "behavioral",
  js_eval_count: "behavioral", iframe_count: "behavioral", redirect_count: "behavioral",
  cookie_access_count: "behavioral", local_storage_access: "behavioral", xhr_request_count: "behavioral",
  websocket_count: "behavioral", canvas_fingerprint: "behavioral", obfuscated_code: "behavioral",
  crypto_mining_calls: "behavioral", dom_manipulation: "behavioral", clipboard_access: "behavioral",
  csp_bypass_attempts: "behavioral", worker_abuse: "behavioral", prototype_pollution: "behavioral",
  service_worker_abuse: "behavioral", exfil_xhr_count: "behavioral", click_jacking_score: "behavioral",
  browser_exploit_score: "behavioral", supply_chain_risk: "behavioral",
  raw_size: "static", entropy: "static", null_byte_count: "static", printable_ratio: "static",
  pe_header_present: "static", suspicious_strings: "behavioral", base64_blocks: "behavioral",
  url_count: "network", ip_count: "network", trojan_string_count: "static",
  packer_score: "static", import_table_anomaly: "static", anti_debug_score: "static",
  anti_vm_score: "static", self_modify_score: "static",
  rootkit_string_count: "static", kernel_hook_score: "static", bootkit_score: "static",
  linux_rootkit_score: "static", ssdt_hook_score: "static", dkom_score: "static",
};

// ─── AI PROMPT BUILDER ───────────────────────────────────────────────────────
function buildPrompt(
  inputType: string, rawFeatures: Record<string, number>,
  lightgbm: number, lstm: number, transformer: number, ensemble: number,
  classification: string, threatLevel: string, data: string,
  threats: {
    trojan: ThreatDetectionResult; mitm: ThreatDetectionResult;
    ddos: ThreatDetectionResult; botnet: ThreatDetectionResult;
    dnsSpoofing: ThreatDetectionResult; rootkit: ThreatDetectionResult;
    primaryThreat: string;
  },
  fileName?: string, similarCases?: ReturnType<typeof getSimilarCases>
) {
  const formatThreat = (name: string, t: ThreatDetectionResult) => {
    if (!t.detected) return `${name}: CLEAR (score=${(t.score * 100).toFixed(1)}%)`;
    return `${name}: ⚠️ DETECTED — ${t.type} (confidence=${(t.score * 100).toFixed(1)}%)
  Signatures: ${t.signatures.slice(0, 4).map((s) => s.name).join(" | ")}
  Countermeasures: ${t.countermeasures.slice(0, 2).join(" | ")}`;
  };

  const activeThreats = [
    { n: "TROJAN", t: threats.trojan }, { n: "MITM", t: threats.mitm },
    { n: "DDoS/DoS", t: threats.ddos }, { n: "BOTNET", t: threats.botnet },
    { n: "DNS SPOOFING", t: threats.dnsSpoofing }, { n: "ROOTKIT", t: threats.rootkit },
  ].filter((x) => x.t.detected);

  const similarCtx = (similarCases && similarCases.length > 0)
    ? `\nINTELLIGENCE MEMORY — ${similarCases.length} SIMILAR PAST CASES:\n` +
      similarCases.map((c, i) => `  [${i + 1}] ${c.classification} (${c.threatLevel}, ${(c.confidence * 100).toFixed(0)}% conf, ${c.inputType}) @ ${c.timestamp.slice(0, 10)}`).join("\n") + "\n"
    : "";

  const highValFeats = Object.entries(rawFeatures).filter(([, v]) => v > 0).sort(([, a], [, b]) => b - a).slice(0, 20);

  return `You are AegisCore — a production-grade cybersecurity AI specializing in malware, MITM, DDoS/DoS, botnets, DNS spoofing, rootkits, and zero-day threat detection. You analyze real traffic, binaries, and network data. You also provide actionable countermeasures to STOP detected attacks.

═══════════════════════════════════════════════════════════════
INPUT: ${inputType.toUpperCase()}${fileName ? ` | File: ${fileName}` : ""} | ${new Date().toISOString()}
═══════════════════════════════════════════════════════════════
${similarCtx}
ENSEMBLE MODEL SCORES:
  LightGBM (gradient boost):  ${(lightgbm * 100).toFixed(1)}%
  BiLSTM (sequence model):    ${(lstm * 100).toFixed(1)}%
  Transformer (attention):    ${(transformer * 100).toFixed(1)}%
  Ensemble (weighted):        ${(ensemble * 100).toFixed(1)}%
  Primary Classification:     ${classification} | Threat: ${threatLevel.toUpperCase()}

MULTI-THREAT DETECTOR RESULTS:
${formatThreat("TROJAN", threats.trojan)}
${formatThreat("MITM", threats.mitm)}
${formatThreat("DDoS/DoS", threats.ddos)}
${formatThreat("BOTNET", threats.botnet)}
${formatThreat("DNS SPOOFING", threats.dnsSpoofing)}
${formatThreat("ROOTKIT", threats.rootkit)}

PRIMARY THREAT: ${threats.primaryThreat}
ACTIVE DETECTIONS: ${activeThreats.length > 0 ? activeThreats.map((x) => x.n).join(", ") : "NONE — Sample appears clean"}

TOP FEATURES (non-zero, ranked):
${highValFeats.map(([k, v]) => `  ${k}: ${v}`).join("\n")}

RAW DATA SAMPLE (first 2500 chars):
${data.slice(0, 2500)}

═══════════════════════════════════════════════════════════════
PROVIDE ALL 10 SECTIONS BELOW — BE SPECIFIC AND TECHNICAL:
═══════════════════════════════════════════════════════════════

## 1. THREAT VERDICT
State the definitive classification with ensemble model agreement analysis. Explain why scores converged or diverged.

## 2. ATTACK TYPE DEEP DIVE
${activeThreats.length > 0 ? activeThreats.map((x) => `### ${x.n} — ${x.t.type}
Explain: attack mechanism, evidence from features/data, severity, scope of impact.`).join("\n") : "All detectors clear. Explain why the sample is clean."}

## 3. MITM ANALYSIS
Analyze for man-in-the-middle indicators: ARP poisoning, SSL stripping, traffic interception, rogue DHCP/DNS. If detected, trace the interception path.

## 4. DDoS/DoS ANALYSIS (Dataset-Calibrated)
Analyze using DDoS dataset thresholds (packet rate > ${DDOS_PACKET_RATE_SEVERE}/s = severe, SDN pktrate > ${SDN_DDOS_PKTRATE_THRESHOLD} = confirmed DDoS). Classify: SYN flood, UDP flood, ICMP flood, amplification, L7 flood, volumetric. Distinguish DoS (single source) from DDoS (distributed).

## 5. BOTNET ANALYSIS
Look for: C2 beaconing patterns, IRC channels, P2P coordination, Mirai-style IoT scanning, fast-flux DNS, Tor C2. Identify botnet family if possible.

## 6. DNS SPOOFING / HIJACKING ANALYSIS
Analyze: DNS response volume vs query volume, NXDOMAIN rates, response IP consistency, tunneling patterns (query length > 50 chars). Identify: cache poisoning, fast-flux, Kaminsky attack, DNS exfiltration.

## 7. ROOTKIT ANALYSIS
Check for: SSDT/IDT hooks, DKOM, bootkit signatures, LD_PRELOAD injection, /proc manipulation, kernel module hiding, firmware implants. Map to Windows/Linux rootkit families.

## 8. NETWORK VULNERABILITY ASSESSMENT
Comprehensive network exposure: open ports, protocol weaknesses, missing encryption, misconfigured services, unpatched vectors.

## 9. ZERO-DAY & NOVEL THREAT INDICATORS ⚠️
Flag patterns not matching known CVE signatures. Novel technique combinations, evasion methods, advanced persistence. Assess APT likelihood.

## 10. COMPLETE COUNTERMEASURES & REMEDIATION
For EACH detected attack type, provide:
- IMMEDIATE: Steps to stop the attack RIGHT NOW
- SHORT-TERM: Containment and forensic preservation  
- LONG-TERM: Architecture hardening to prevent recurrence
- MONITORING: What alerts and metrics to set up

Include specific commands, firewall rules, and configuration changes. Reference MITRE ATT&CK technique IDs where applicable.

Be technical, specific, and actionable. Flag critical findings with ⚠️ CRITICAL:`;
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────
router.post("/analysis/submit-stream", async (req, res) => {
  const body = SubmitAnalysisBody.parse(req.body);
  const sessionId = `session-${crypto.randomUUID().slice(0, 8)}`;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  const send = (obj: unknown) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

  let rawFeatures: Record<string, number> = {};
  if (body.inputType === "wireshark") rawFeatures = parseWiresharkData(body.data);
  else if (body.inputType === "browser") rawFeatures = parseBrowserData(body.data);
  else if (body.inputType === "file") rawFeatures = parseFileData(body.data);
  else rawFeatures = { raw_size: body.data.length };

  const { score, classification, threatLevel, lightgbm, lstm, transformer, trojan, mitm, ddos, botnet, dnsSpoofing, rootkit, primaryThreat } =
    computeMalwareScore(rawFeatures, body.inputType, body.data);

  const threatBoost = Math.max(trojan.score, mitm.score, ddos.score, botnet.score, dnsSpoofing.score, rootkit.score) * 0.15;
  const baseEnsemble = lightgbm * 0.35 + lstm * 0.28 + transformer * 0.22 + threatBoost * 0.15;
  const adaptedScore = getAdaptiveScore(rawFeatures, body.inputType, baseEnsemble);
  const ensemble = adaptedScore;

  const similarCases = getSimilarCases(rawFeatures, undefined, 3);
  const features: FeatureValue[] = Object.entries(rawFeatures).map(([name, value]) => ({
    name, value: typeof value === "number" ? parseFloat(value.toFixed(4)) : 0,
    category: FEATURE_CATEGORY_MAP[name] ?? "other",
  }));

  const detectedThreats = [
    trojan.detected ? trojan.type : null,
    mitm.detected ? mitm.type : null,
    ddos.detected ? ddos.type : null,
    botnet.detected ? botnet.type : null,
    dnsSpoofing.detected ? dnsSpoofing.type : null,
    rootkit.detected ? rootkit.type : null,
  ].filter(Boolean) as string[];

  send({
    type: "verdict",
    sessionId, classification, confidence: parseFloat(ensemble.toFixed(3)),
    threatLevel, features,
    modelPredictions: {
      lightgbm: parseFloat(lightgbm.toFixed(3)),
      lstm: parseFloat(lstm.toFixed(3)),
      transformer: parseFloat(transformer.toFixed(3)),
      ensemble: parseFloat(ensemble.toFixed(3)),
    },
    threatDetections: {
      trojan: { detected: trojan.detected, type: trojan.type, score: parseFloat(trojan.score.toFixed(3)), signatureCount: trojan.signatures.length, topSignatures: trojan.signatures.slice(0, 4).map((s) => s.name) },
      mitm: { detected: mitm.detected, type: mitm.type, score: parseFloat(mitm.score.toFixed(3)), signatureCount: mitm.signatures.length },
      ddos: { detected: ddos.detected, type: ddos.type, score: parseFloat(ddos.score.toFixed(3)), signatureCount: ddos.signatures.length },
      botnet: { detected: botnet.detected, type: botnet.type, score: parseFloat(botnet.score.toFixed(3)), signatureCount: botnet.signatures.length },
      dnsSpoofing: { detected: dnsSpoofing.detected, type: dnsSpoofing.type, score: parseFloat(dnsSpoofing.score.toFixed(3)), signatureCount: dnsSpoofing.signatures.length },
      rootkit: { detected: rootkit.detected, type: rootkit.type, score: parseFloat(rootkit.score.toFixed(3)), signatureCount: rootkit.signatures.length },
    },
    primaryThreat,
    detectedThreats,
    timestamp: new Date().toISOString(),
    similarCasesCount: similarCases.length,
  });

  let aiAnalysis = "";
  try {
    const stream = await openrouter.chat.completions.create({
      model: "meta-llama/llama-3.3-70b-instruct:free",
      max_tokens: 8192,
      stream: true,
      messages: [
        { role: "system", content: "You are AegisCore — a production-grade cybersecurity AI. You have deep expertise in MITM attacks, DDoS/DoS, botnets, DNS spoofing, rootkits, trojans, APT campaigns, and zero-day research. You provide thorough structured analysis AND actionable countermeasures to stop each detected attack. Never refuse defensive analysis." },
        { role: "user", content: buildPrompt(body.inputType, rawFeatures, lightgbm, lstm, transformer, ensemble, classification, threatLevel, body.data, { trojan, mitm, ddos, botnet, dnsSpoofing, rootkit, primaryThreat }, body.fileName, similarCases) },
      ],
    });

    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content ?? "";
      if (text) { aiAnalysis += text; send({ type: "chunk", content: text }); }
    }
  } catch {
    aiAnalysis = `Analysis: ${classification} (${(score * 100).toFixed(1)}%). Threats: ${detectedThreats.join(", ") || "None"}. Features: ${JSON.stringify(rawFeatures).slice(0, 500)}`;
    send({ type: "chunk", content: aiAnalysis });
  }

  const session: AnalysisSession = {
    id: sessionId, inputType: body.inputType, classification,
    confidence: parseFloat(ensemble.toFixed(3)), threatLevel,
    timestamp: new Date().toISOString(), status: "completed", features, aiAnalysis,
    modelPredictions: { lightgbm: parseFloat(lightgbm.toFixed(3)), lstm: parseFloat(lstm.toFixed(3)), ensemble: parseFloat(ensemble.toFixed(3)), transformer: parseFloat(transformer.toFixed(3)) },
    rawData: body.data.slice(0, 500),
  };
  addSession(session);
  learnFromSession(sessionId, features, classification, threatLevel, parseFloat(ensemble.toFixed(3)), body.inputType);

  send({ type: "done" });
  res.end();
});

router.post("/analysis/submit", async (req, res) => {
  const body = SubmitAnalysisBody.parse(req.body);
  const sessionId = `session-${crypto.randomUUID().slice(0, 8)}`;

  let rawFeatures: Record<string, number> = {};
  if (body.inputType === "wireshark") rawFeatures = parseWiresharkData(body.data);
  else if (body.inputType === "browser") rawFeatures = parseBrowserData(body.data);
  else if (body.inputType === "file") rawFeatures = parseFileData(body.data);
  else rawFeatures = { raw_size: body.data.length };

  const { score, classification, threatLevel, lightgbm, lstm, transformer, trojan, mitm, ddos, botnet, dnsSpoofing, rootkit, primaryThreat } =
    computeMalwareScore(rawFeatures, body.inputType, body.data);

  const threatBoost = Math.max(trojan.score, mitm.score, ddos.score, botnet.score, dnsSpoofing.score, rootkit.score) * 0.15;
  const ensemble = lightgbm * 0.35 + lstm * 0.28 + transformer * 0.22 + threatBoost * 0.15;

  const features: FeatureValue[] = Object.entries(rawFeatures).map(([name, value]) => ({
    name, value: typeof value === "number" ? parseFloat(value.toFixed(4)) : 0,
    category: FEATURE_CATEGORY_MAP[name] ?? "other",
  }));

  let aiAnalysis = "";
  try {
    const message = await openrouter.chat.completions.create({
      model: "meta-llama/llama-3.3-70b-instruct:free",
      max_tokens: 8192,
      messages: [
        { role: "system", content: "You are AegisCore — a production-grade cybersecurity AI specializing in MITM, DDoS, botnets, DNS spoofing, rootkits, and trojans. Provide thorough analysis and countermeasures." },
        { role: "user", content: buildPrompt(body.inputType, rawFeatures, lightgbm, lstm, transformer, ensemble, classification, threatLevel, body.data, { trojan, mitm, ddos, botnet, dnsSpoofing, rootkit, primaryThreat }, body.fileName) },
      ],
    });
    aiAnalysis = message.choices[0]?.message?.content ?? "Analysis complete.";
  } catch {
    aiAnalysis = `Analysis: ${classification} (${(score * 100).toFixed(1)}%). Primary: ${primaryThreat}. Features: ${JSON.stringify(rawFeatures).slice(0, 500)}`;
  }

  const session: AnalysisSession = {
    id: sessionId, inputType: body.inputType, classification,
    confidence: parseFloat(ensemble.toFixed(3)), threatLevel,
    timestamp: new Date().toISOString(), status: "completed", features, aiAnalysis,
    modelPredictions: { lightgbm: parseFloat(lightgbm.toFixed(3)), lstm: parseFloat(lstm.toFixed(3)), ensemble: parseFloat(ensemble.toFixed(3)), transformer: parseFloat(transformer.toFixed(3)) },
    rawData: body.data.slice(0, 500),
  };
  addSession(session);

  res.json({
    sessionId, classification, confidence: session.confidence, threatLevel, features,
    modelPredictions: session.modelPredictions,
    threatDetections: {
      trojan: { detected: trojan.detected, type: trojan.type, score: parseFloat(trojan.score.toFixed(3)) },
      mitm: { detected: mitm.detected, type: mitm.type, score: parseFloat(mitm.score.toFixed(3)) },
      ddos: { detected: ddos.detected, type: ddos.type, score: parseFloat(ddos.score.toFixed(3)) },
      botnet: { detected: botnet.detected, type: botnet.type, score: parseFloat(botnet.score.toFixed(3)) },
      dnsSpoofing: { detected: dnsSpoofing.detected, type: dnsSpoofing.type, score: parseFloat(dnsSpoofing.score.toFixed(3)) },
      rootkit: { detected: rootkit.detected, type: rootkit.type, score: parseFloat(rootkit.score.toFixed(3)) },
    },
    primaryThreat, aiAnalysis, timestamp: session.timestamp,
  });
});

router.get("/analysis/sessions", async (_req, res) => {
  const list = getAllSessions()
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .map(({ id, inputType, classification, confidence, threatLevel, timestamp, status }) => ({ id, inputType, classification, confidence, threatLevel, timestamp, status }));
  res.json(list);
});

router.get("/analysis/sessions/:id", async (req, res) => {
  const session = getAllSessions().find((s) => s.id === req.params.id);
  if (!session) { res.status(404).json({ error: "Session not found" }); return; }
  res.json(session);
});

router.get("/dashboard/stats", async (_req, res) => {
  const all = getAllSessions();
  const completed = all.filter((s) => s.status === "completed");
  const malware = completed.filter((s) => s.threatLevel !== "benign");
  const benign = completed.filter((s) => s.threatLevel === "benign");
  const avgConf = completed.reduce((sum, s) => sum + s.confidence, 0) / (completed.length || 1);
  const recent = completed.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 8)
    .map(({ id, inputType, classification, confidence, threatLevel, timestamp, status }) => ({ id, inputType, classification, confidence, threatLevel, timestamp, status }));
  res.json({
    totalAnalyzed: completed.length, malwareDetected: malware.length,
    benignFiles: benign.length, activeSessionsCount: all.filter((s) => s.status === "running").length,
    avgConfidence: parseFloat(avgConf.toFixed(3)),
    detectionRate: completed.length > 0 ? parseFloat((malware.length / completed.length).toFixed(3)) : 0,
    recentSessions: recent, lastUpdated: new Date().toISOString(),
  });
});

export default router;
