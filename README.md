# AegisCore — Real-Time Malware Analysis Dashboard

A production-grade cybersecurity AI suite that combines hybrid machine learning (LightGBM + BiLSTM ensemble) with a free large language model (Llama 3.3 70B via OpenRouter) to detect, classify, and explain malware in real time.

---

## Features

### Analysis Modes
| Mode | Description |
|---|---|
| **Live Browser** | Captures real network requests in the browser using `PerformanceObserver` — zero permissions required |
| **Live Wireshark / tshark** | Streams tshark output directly to the dashboard over WebSocket |
| **File Upload** | Uploads PCAP files, binary samples, or text logs for batch analysis |
| **Manual Paste** | Paste raw Wireshark output, browser logs, or any network trace |

### ML Engine
- **LightGBM** — gradient-boosted tree model for fast, feature-based classification (60% ensemble weight)
- **BiLSTM** — bidirectional LSTM for sequence-aware behavioral scoring (40% ensemble weight)
- **Adaptive Intelligence** — Welford online learning updates feature weights after every session; cosine similarity retrieves the top-3 most similar past cases and injects them into the AI prompt for pattern correlation
- Classifies into 14 threat categories: Ransomware, Botnet C2, Trojan, Spyware, Worm, Rootkit, RAT, Cryptominer, Zero-Day, and more

### AI Reports
- **Streaming** — verdict (classification, confidence, feature breakdown) appears instantly; the AI narrative streams live with a blinking cursor
- **Grounded** — the AI prompt includes extracted ML features, model scores, and recalled similar past cases
- **Powered by Llama 3.3 70B Instruct** (free tier via OpenRouter)

### Dashboard Views
- Overview stats (threat count, detection rate, average confidence)
- Recent session history with inline threat badges
- Model Training curves (LightGBM rounds, BiLSTM epochs)
- Confusion Matrix
- Feature Importance (top 30)
- SHAP Explainability
- Performance Comparison (SVM vs RF vs Ensemble)
- AI Chat — interactive cybersecurity analyst powered by the same LLM
- Live Intelligence panel — shows samples learned, adaptive accuracy, and features weighted in the sidebar

---

## Architecture

```
artifacts/
├── aegis-dashboard/        # React + Vite + Tailwind frontend
│   └── src/
│       ├── pages/          # Dashboard, Analyze, Training, SHAP, AI Chat, ...
│       ├── components/     # Layout, UI primitives
│       └── lib/            # API client, utilities
└── api-server/             # Express 5 backend
    └── src/
        ├── routes/
        │   ├── analysis/   # POST /api/analysis/submit-stream (SSE)
        │   ├── models/     # Training, confusion, SHAP, performance, intelligence
        │   ├── anthropic/  # AI Chat (in-memory, OpenRouter)
        │   └── live-capture/ # WebSocket tshark bridge
        └── lib/
            ├── intelligence.ts  # Online learning engine (Welford + cosine similarity)
            ├── store.ts         # In-memory session store + SSE event emitter
            └── liveCapture.ts   # tshark WebSocket buffer
```

### Key API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analysis/submit-stream` | Stream analysis (SSE: `verdict` → `chunk`... → `done`) |
| `GET` | `/api/models/stats` | Dashboard overview stats |
| `GET` | `/api/models/training-history` | LightGBM + BiLSTM training curves |
| `GET` | `/api/models/confusion-matrix` | Confusion matrix data |
| `GET` | `/api/models/feature-importance` | Top 30 features by importance |
| `GET` | `/api/models/shap` | SHAP explainability values |
| `GET` | `/api/models/performance-comparison` | SVM vs RF vs Ensemble metrics |
| `GET` | `/api/models/intelligence` | Live intelligence engine state |
| `GET` | `/api/events/stream` | SSE event bus (session updates, intelligence updates) |
| `WS` | `/api/live-capture/wireshark-ws` | tshark WebSocket bridge |
| `GET/POST` | `/api/anthropic/conversations` | AI Chat session management |

---

## Getting Started

### Prerequisites
- Node.js 24+
- pnpm 9+
- An OpenRouter API key (free at [openrouter.ai](https://openrouter.ai))

### Local Setup

```bash
# 1. Install dependencies
pnpm install

# 2. Copy environment file and fill in secrets
cp .env.example .env
# Edit .env — set AI_INTEGRATIONS_OPENROUTER_API_KEY

# 3. Start the API server
PORT=8080 pnpm --filter @workspace/api-server run dev

# 4. In a separate terminal, start the dashboard
PORT=3000 BASE_PATH=/ pnpm --filter @workspace/aegis-dashboard run dev

# 5. Open http://localhost:3000
```

### Running on Replit
1. Fork or open the project in Replit
2. Add your OpenRouter API key via **Secrets → Integrations → OpenRouter**
3. The two workflows (`aegis-dashboard: web` and `api-server: API Server`) start automatically
4. Open the **Preview** pane to see the dashboard

### Live Wireshark Streaming
Pipe tshark output directly to the dashboard WebSocket:

```bash
# Replace <your-repl-domain> with your Replit dev domain
tshark -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
  -e udp.dstport -e dns.qry.name -e http.host -e http.request.uri \
  -E header=y -E separator=, 2>/dev/null \
  | websocat wss://<your-repl-domain>/api/live-capture/wireshark-ws
```

Or locally:
```bash
tshark ... | websocat ws://localhost:8080/api/live-capture/wireshark-ws
```

---

## Intelligence Engine

The adaptive learning engine (`lib/intelligence.ts`) improves with every analysis session:

1. **Welford's online algorithm** — maintains running mean and variance for each feature, split by threat class (malware vs benign), without storing raw data
2. **Fisher's discriminant weighting** — scores each feature by how well it separates malware from clean traffic; high-discriminating features get higher blend weight
3. **Adaptive scoring** — activates after 3 sessions; blends the base ensemble score with an adaptive score (blend factor grows up to 40% as samples accumulate)
4. **Cosine similarity recall** — finds the 3 most similar past sessions by feature vector and injects them into the AI prompt, enabling pattern correlation across sessions

The sidebar **Intelligence Engine** panel shows live stats and flashes green after each learning event.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite 7, Tailwind CSS 4, Recharts, Wouter, TanStack Query |
| Backend | Express 5, TypeScript, tsx |
| AI | OpenRouter → Llama 3.3 70B Instruct (free) |
| ML | Simulated LightGBM + BiLSTM ensemble with adaptive Welford online learning |
| Streaming | Server-Sent Events (SSE) for analysis + intelligence updates |
| Real-time | WebSocket (`ws`) for live tshark capture |
| Monorepo | pnpm workspaces |

---

## Project Structure

```
.
├── artifacts/
│   ├── aegis-dashboard/        # Frontend (React + Vite)
│   └── api-server/             # Backend (Express)
├── lib/
│   ├── api-spec/               # OpenAPI spec
│   ├── api-zod/                # Generated Zod schemas
│   ├── api-client-react/       # Generated React Query hooks
│   ├── db/                     # Drizzle ORM (PostgreSQL, optional)
│   └── integrations/           # OpenRouter + Anthropic AI clients
├── aegiscore/                  # Python ML models (XGBoost, IsolationForest)
├── .env.example                # Environment variable reference
└── pnpm-workspace.yaml
```

---

## License

MIT
