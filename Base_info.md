# AegisCore — Cybersecurity AI Suite

A production-grade cybersecurity platform combining real-time threat detection, ensemble machine learning, and AI-powered analysis. It detects Trojans, MITM attacks, DDoS/DoS, Botnets, DNS Spoofing, and Rootkits — then provides specific countermeasures to stop each one.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  React Dashboard  (port 3000)                   │
│  Vite + TypeScript + Tailwind CSS               │
│  Live browser capture · Wireshark feed          │
└─────────────────┬───────────────────────────────┘
                  │ /api  (Vite proxy)
┌─────────────────▼───────────────────────────────┐
│  Express API Server  (port 3001)                │
│  Threat detection · ML scoring · AI analysis   │
│  OpenRouter LLaMA 3.3 70B via SSE streaming    │
└─────────────────────────────────────────────────┘
```

**Monorepo:** pnpm workspaces · Node 24 · TypeScript 5.9 · Express 5

---

## Running the Project

Both services start automatically via the **Project** run button.

| Service | Command | Port |
|---|---|---|
| Dashboard | `PORT=3000 BASE_PATH=/ pnpm --filter @workspace/aegis-dashboard run dev` | 3000 |
| API Server | `PORT=3001 pnpm --filter @workspace/api-server run dev` | 3001 |

---

## Threat Detection Suite

Six independent detectors run in parallel on every submission. Each produces a confidence score, matched signatures, and tailored countermeasures.

### Trojan Detector
Rule engine with 17 signatures covering:
- **Process injection** — CreateRemoteThread, VirtualAllocEx, WriteProcessMemory
- **Process hollowing** — NtUnmapViewOfSection, ZwUnmapViewOfSection
- **Keyloggers** — SetWindowsHookEx, GetAsyncKeyState
- **C2 frameworks** — Cobalt Strike, Meterpreter, Empire
- **Credential dumpers** — Mimikatz, LSASS access
- **LOLBin abuse** — encoded PowerShell, certutil, bitsadmin, mshta
- **Ransomware staging** — vssadmin delete shadows, bcdedit recovery disable
- **Persistence** — scheduled tasks, registry Run keys, rogue account creation

Classifies into: `Trojan.Stealer` · `Trojan.RAT` · `Trojan.Backdoor` · `Trojan.Injector` · `Trojan.Dropper` · `Trojan.Ransomware`

---

### MITM Detector
Detects man-in-the-middle attacks via:
- **ARP poisoning** — same IP broadcasting from multiple MACs
- **Gratuitous ARP floods** — gateway impersonation
- **SSL stripping** — HTTPS→HTTP protocol downgrade
- **Rogue DHCP/DNS** — unauthorized servers offering gateway
- **Certificate manipulation** — self-signed or mismatched certs
- **Man-in-Browser** — FormGrabber / webinject patterns
- **Tool signatures** — Ettercap, Bettercap, Responder, Impacket, mitmproxy

Countermeasures: Dynamic ARP Inspection, DHCP snooping, HSTS, certificate pinning, 802.1X, arpwatch.

---

### DDoS / DoS Detector
Dataset-calibrated thresholds:

| Source | Threshold | Classification |
|---|---|---|
| DDoS dataset | pktrate > 7/s | Suspicious |
| DDoS dataset | pktrate > 30/s | High severity |
| DDoS dataset | pktrate > 90/s | Severe DDoS |
| SDN dataset | pktrate > 450 | Confirmed DDoS flow |

Attack types: SYN flood · UDP flood · ICMP flood · DNS/NTP/SSDP amplification · SlowLoris · RUDY · HTTP L7 flood · volumetric

Automatically distinguishes **DoS** (single source) from **DDoS** (distributed).

Countermeasures: SYN cookies, eBPF packet filtering, RTBH nullrouting, upstream scrubbing (Cloudflare/AWS Shield), anycast routing.

---

### Botnet Detector
Identifies bot infection and C2 infrastructure:
- **C2 beaconing** — timing jitter analysis (coefficient of variation < 15% = confirmed beacon)
- **IRC C2** — traffic on ports 6667–6669, JOIN #botnet patterns
- **P2P C2** — high port diversity with multiple peers
- **Mirai-style scanning** — Telnet + SSH spread to many IPs
- **Fast-flux DNS** — rapid record rotation hiding C2
- **Tor-hidden C2** — outbound on ports 9001/9050
- **Named families** — Mirai, Gafgyt, QBot, Emotet, TrickBot, Dridex, Zeus, Necurs

Countermeasures: DNS sinkholing, Tor nullrouting, honeypot decoys, YARA botnet scans, egress filtering on IRC/unusual ports.

---

### DNS Spoofing Detector
Catches DNS-based attacks:
- **Kaminsky attack** — DNS responses exceeding query count by >30%
- **NXDOMAIN flooding** — subdomain enumeration for cache poisoning
- **Fast-flux hijacking** — domains resolving to rotating IPs
- **DNS tunneling** — queries longer than 50 characters
- **DNS exfiltration** — high-volume long query covert channel
- **Rogue DNS servers** — unauthorized resolvers
- **Combined ARP+DNS** — ARP poisoning combined with DNS interception

Countermeasures: DNSSEC validation, DNS-over-HTTPS/TLS, Response Rate Limiting (RRL), RPZ threat intelligence zones, cache flush procedures.

---

### Rootkit Detector
Detects kernel-level and persistent threats:
- **SSDT/IDT hooks** — Windows syscall table manipulation
- **DKOM** — Direct Kernel Object Manipulation (EPROCESS unlinking)
- **Bootkits** — MBR/VBR/UEFI firmware infection
- **Linux LKM rootkits** — /proc manipulation, sys_call_table hooks
- **LD_PRELOAD injection** — library override hiding processes
- **Named Windows families** — TDL/Alureon, Sinowal, Stuxnet, Flame, Derusbi, Turla
- **Named Linux families** — Reptile, Diamorphine, Azazel, Adore-ng, SuckIT
- **Firmware/UEFI implants** — persists across OS reinstall
- **Anti-forensics** — timestomping, driver signing bypass

Countermeasures: Volatility memory forensics, chkrootkit/rkhunter from live USB, MBR integrity verification, Secure Boot enforcement, UEFI firmware update.

---

## ML Ensemble Models

Four models score every submission independently, then combine:

| Model | Weight | Specialization |
|---|---|---|
| LightGBM (gradient boost) | 35% | Network feature classification |
| BiLSTM (sequence model) | 28% | Temporal packet pattern analysis |
| Transformer (attention) | 22% | Context-weighted feature correlation |
| Threat detector boost | 15% | Highest rule-based score |

**Threat level:** `benign` → `low` → `medium` → `high` → `critical`

---

## AI Analysis Report

Each analysis produces a 10-section structured report via LLaMA 3.3 70B (streamed):

1. **Threat Verdict** — ensemble model agreement analysis
2. **Attack Type Deep Dive** — mechanism, evidence, severity, impact scope
3. **MITM Analysis** — interception path tracing
4. **DDoS/DoS Analysis** — dataset-calibrated flood classification
5. **Botnet Analysis** — family identification, C2 infrastructure mapping
6. **DNS Spoofing Analysis** — cache poisoning, tunneling, exfil covert channels
7. **Rootkit Analysis** — kernel hook mapping, persistence mechanism
8. **Network Vulnerability Assessment** — exposed ports, protocol weaknesses
9. **Zero-Day & Novel Threat Indicators** — APT likelihood, evasion techniques
10. **Complete Countermeasures** — immediate/short-term/long-term steps with commands

---

## Input Sources

| Source | Description |
|---|---|
| Live Browser | Auto-captures network requests via Performance API, no permissions needed |
| Live tshark | WebSocket stream from real tshark output piped via netcat |
| Wireshark | Paste PCAP text export or tshark output |
| Browser Logs | Console logs, JS source, network requests |
| File Upload | Binary files, .exe, .dll, .log, .pcap, .csv |
| Manual | Raw text, hex dumps, log snippets |

---

## Datasets Used for Calibration

| Dataset | Records | Used For |
|---|---|---|
| `DDoS_dataset.csv` | 852K rows | Packet rate thresholds (>90/s = severe DDoS) |
| `dataset_sdn.csv` | 104K rows | SDN flow DDoS detection (pktrate > 450) |
| `cybersecurity_intrusion_data.csv` | 9.5K rows | Brute-force/intrusion scoring |
| `cybersecurity.csv` | 10K rows | Port-scan, attack type labeling |

---

## Project Structure

```
/
├── artifacts/
│   ├── aegis-dashboard/        # React + Vite frontend
│   │   └── src/
│   │       ├── pages/Analyze.tsx   # Main analysis UI
│   │       ├── pages/Dashboard.tsx # Overview stats
│   │       └── components/         # ThreatBadge, charts
│   └── api-server/             # Express API backend
│       └── src/
│           ├── routes/analysis/index.ts  # All 6 detectors + ML
│           ├── lib/store.ts              # Session storage
│           └── lib/intelligence.ts       # Adaptive scoring
├── lib/
│   ├── api-zod/                # Zod request/response schemas
│   ├── api-client-react/       # Generated React Query hooks
│   └── db/                     # Drizzle ORM + PostgreSQL
├── aegiscore/                  # Python ML reference models
│   └── src/                    # XGBoost, IsolationForest, RandomForest
├── attached_assets/            # Uploaded training datasets (.csv)
└── replit.md                   # This file
```

---

## Key Files

| File | Purpose |
|---|---|
| `artifacts/api-server/src/routes/analysis/index.ts` | All 6 threat detectors, ML scoring, AI prompt |
| `artifacts/aegis-dashboard/src/pages/Analyze.tsx` | Analysis UI with 6-panel threat display |
| `artifacts/api-server/src/lib/store.ts` | In-memory session store |
| `artifacts/api-server/src/lib/intelligence.ts` | Adaptive scoring & session learning |
| `artifacts/aegis-dashboard/vite.config.ts` | Vite proxy config (`/api` → port 3001) |
