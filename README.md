<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.9-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-4.2-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

<h1 align="center">🔍 TrustLens AI</h1>
<p align="center"><strong>Explainable AI-Powered URL Trust Intelligence Engine</strong></p>
<p align="center">
  <em>Drop any URL → get an instant, transparent trust score backed by 15+ analysis engines, AI deception classification, and full evidence breakdown.</em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/70df1827-afa7-4b10-b9ec-eab7f49918fa" alt="TrustLens Scan Page" width="720" />
</p>

---

## Table of Contents

- [What is TrustLens?](#what-is-trustlens)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Setup Wizard — LLM Provider](#setup-wizard--llm-provider)
- [Manual Setup](#manual-setup)
- [Docker](#docker)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Analysis Engines](#analysis-engines)
- [Scoring Methodology](#scoring-methodology)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [License](#license)

---

## What is TrustLens?

TrustLens is an open-source security tool that analyses any URL through **15+ independent analysis engines** running in parallel, combines rule-based heuristics (70%) with AI advisory signals (30%), and produces a transparent, explainable trust score from 0–100.

Unlike opaque "safe/unsafe" verdicts, TrustLens shows you **exactly why** a URL is risky — every signal, every rule, every AI finding is visible in the full-transparency Deep Dive panel.

**Key Principles:**

- 🔍 **Full Transparency** — Every signal is shown with evidence and source
- 🧠 **AI is Advisory** — AI never directly determines the verdict; rules lead
- 🛡️ **Anti-Hallucination** — AI prompts include injection fences and calibration anchors
- ⚡ **Real-time** — 15+ engines run in parallel via async pipeline
- 🔒 **Security-first** — SSRF protection, input sanitisation, sandboxed browser

---

## Features

### Core Analysis

- **Sandboxed Browser Crawl** — Headless Chromium with intelligent page-load waiting (handles SPAs, loading screens, JS frameworks)
- **AI Deception Classifier** — Multi-provider LLM analysis with anti-hallucination prompts, confidence calibration, and injection detection
- **Brand Impersonation Detection** — 50+ brand registry with Levenshtein typosquatting, homograph detection, and content similarity
- **Domain Intelligence** — RDAP lookup, domain age scoring (14-tier), structural analysis, suspicious registrar detection
- **Security Header Audit** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options analysis
- **SSL Certificate Extraction** — Real TLS connection to extract protocol version, issuer, validity, SAN, serial number

### Advanced Detection

- **Behavioral Analysis** — JS redirect chains, anti-analysis detection, urgency language, popup abuse, clipboard manipulation, WebSocket/ServiceWorker detection
- **Tracker & Malware Detection** — 24 analytics + 17 ad + 15 fingerprinting + 12 malware/cryptominer pattern databases
- **Download Threat Scanner** — Detects dangerous file extensions (.exe, .ps1, .bat, etc.) and auto-download scripts
- **Screenshot Visual Clone Detection** — Perceptual hash comparison against known brand screenshots
- **Zero-Day Suspicion Scoring** — Structural anomaly detection across 4 sub-scorers
- **Heuristic Rules** — URL structure, form analysis, cross-origin submission, content patterns, redirect behavior, external resource loading

### Platform Features

- **Live Page Screenshot** — Captured after intelligent page-load wait, stored in-memory only
- **Community Reporting** — Crowdsourced URL reports with consensus scoring
- **Threat Intel Feeds** — Auto-ingesting external threat intelligence feeds
- **Enterprise Mode** — Brand monitoring, API key management, audit logging
- **Interactive Setup Wizard** — Choose your LLM provider interactively on first start

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (Vite)                     │
│  ScanPage → ResultsPage → ScoreGauge + SignalCards + DeepDive│
└────────────────────────┬────────────────────────────────────┘
                         │ REST API
┌────────────────────────▼────────────────────────────────────┐
│                   FastAPI Backend                            │
│                                                             │
│  ┌──────────┐   ┌──────────────────────────────────────┐   │
│  │  Queue    │──▶│           Orchestrator                │   │
│  └──────────┘   │                                      │   │
│                 │  1. Crawl (Playwright)                │   │
│                 │  2. ┌─────────────────────────────┐   │   │
│                 │     │ Parallel Analysis Engines    │   │   │
│                 │     │ ┌─────┐ ┌─────┐ ┌────────┐ │   │   │
│                 │     │ │Rules│ │ AI  │ │ Brand  │ │   │   │
│                 │     │ ├─────┤ ├─────┤ ├────────┤ │   │   │
│                 │     │ │Behav│ │Domn │ │Headers │ │   │   │
│                 │     │ ├─────┤ ├─────┤ ├────────┤ │   │   │
│                 │     │ │Track│ │Down │ │Screen  │ │   │   │
│                 │     │ ├─────┤ ├─────┤ ├────────┤ │   │   │
│                 │     │ │Logo │ │Pay  │ │Threat  │ │   │   │
│                 │     │ ├─────┤ ├─────┤ ├────────┤ │   │   │
│                 │     │ │Comm │ │Zero │ │Content │ │   │   │
│                 │     │ └─────┘ └─────┘ └────────┘ │   │   │
│                 │     └─────────────────────────────┘   │   │
│                 │  3. Scoring (70/30 hybrid)            │   │
│                 │  4. AI Explanation                    │   │
│                 │  5. Store Results                     │   │
│                 └──────────────────────────────────────┘   │
│                                                             │
│  SQLite DB │ Rate Limiter │ SSRF Guard │ Audit Logger       │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

| Tool        | Version                                 | Required |
| ----------- | --------------------------------------- | -------- |
| Python      | 3.9+                                    | ✅       |
| Node.js     | 18+                                     | ✅       |
| npm         | 9+                                      | ✅       |
| LLM API Key | Any of: Gemini, OpenAI, Anthropic, Grok | ✅       |

### One-Command Start

```bash
git clone https://github.com/abhishekayu/TrustLens.git
cd TrustLens
chmod +x start.sh
./start.sh
```

That's it. The `start.sh` script will:

1. 🧙 **Run the Setup Wizard** — Interactively pick your LLM provider and enter your API key
2. 📦 **Install all dependencies** — Both Python (`pip install -r requirements.txt`) and Node.js (`npm install`)
3. 🎭 **Install Playwright Chromium** — For sandboxed browser crawling
4. 🚀 **Start the backend** — FastAPI on `http://localhost:3010`
5. ⚛️ **Start the frontend** — Vite dev server on `http://localhost:5173`

```
╔══════════════════════════════════════════════════╗
║            🚀  TrustLens AI Running               ║
╠══════════════════════════════════════════════════╣
║  Frontend  → http://localhost:5173               ║
║  Backend   → http://localhost:3010               ║
║  API Docs  → http://localhost:3010/docs          ║
╠══════════════════════════════════════════════════╣
║  Press Ctrl+C to stop                            ║
╚══════════════════════════════════════════════════╝
```

> **Stop everything:** Press `Ctrl+C` — the script gracefully shuts down both servers.

---

## Setup Wizard — LLM Provider

On first run, the interactive CLI wizard prompts you to choose an AI provider:

```
╔══════════════════════════════════════════════════════════════╗
║   ████████╗██████╗ ██╗   ██╗███████╗████████╗                ║
║      ██║   ██████╔╝██║   ██║███████╗   ██║                   ║
║      ██║   ██║  ██║╚██████╔╝███████║   ██║                   ║
║          L E N S   A I   Setup Wizard                        ║
╚══════════════════════════════════════════════════════════════╝

  Choose your LLM provider:

   1. 🤖  Grok (xAI)
   2. 💎  Gemini (Google)
   3. 🧠  Anthropic (Claude)
   4. ⚡  OpenAI (GPT)

➤ Select provider (1-4):
```

### Provider Details

| #   | Provider               | Default Model              | API Key URL                                                          |
| --- | ---------------------- | -------------------------- | -------------------------------------------------------------------- |
| 1   | **Grok (xAI)**         | `grok-3`                   | [console.x.ai](https://console.x.ai)                                 |
| 2   | **Gemini (Google)**    | `gemini-2.5-flash`         | [aistudio.google.com/apikey](https://aistudio.google.com/apikey)     |
| 3   | **Anthropic (Claude)** | `claude-sonnet-4-20250514` | [console.anthropic.com](https://console.anthropic.com/settings/keys) |
| 4   | **OpenAI (GPT)**       | `gpt-4o`                   | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |

After entering your API key, the wizard saves the config to `.env`. On subsequent starts, it offers:

- **C** — Continue with saved config
- **N** — Pick a new LLM provider
- **Q** — Quit

You can also specify a custom model name when prompted (e.g., `gpt-4o-mini`, `claude-haiku-4-20250514`).

---

## Manual Setup

If you prefer manual setup over `./start.sh`:

### 1. Clone & Install

```bash
git clone https://github.com/abhishekayu/TrustLens.git
cd TrustLens

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browser
python3 -m playwright install chromium

# Install frontend dependencies
cd frontend && npm install && cd ..
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set your AI provider + API key:

```env
TRUSTLENS_AI_PROVIDER=gemini
TRUSTLENS_GEMINI_API_KEY=your-api-key-here
TRUSTLENS_GEMINI_MODEL=gemini-2.5-flash
```

### 3. Start Backend

```bash
PYTHONPATH=src python3 -m uvicorn trustlens.main:app --host 0.0.0.0 --port 8000
```

### 4. Start Frontend

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## Docker

### Build & Run

```bash
docker build -t trustlens-ai .
docker run -p 8000:8000 --env-file .env trustlens-ai
```

### Docker Compose

```bash
docker-compose up
```

This starts both backend (`:8000`) and frontend (`:5173`) containers.

---

## Configuration

All configuration is via environment variables with the `TRUSTLENS_` prefix. See [.env.example](.env.example) for the full list.

### Key Settings

| Variable                              | Default  | Description                                           |
| ------------------------------------- | -------- | ----------------------------------------------------- |
| `TRUSTLENS_AI_PROVIDER`               | `gemini` | LLM provider: `gemini`, `openai`, `anthropic`, `grok` |
| `TRUSTLENS_CRAWLER_TIMEOUT`           | `30`     | Max seconds for page crawl                            |
| `TRUSTLENS_SSRF_BLOCK_PRIVATE`        | `true`   | Block private/internal IPs                            |
| `TRUSTLENS_SCORE_WEIGHT_RULES`        | `0.70`   | Rule-based signal weight                              |
| `TRUSTLENS_SCORE_WEIGHT_AI`           | `0.30`   | AI advisory signal weight                             |
| `TRUSTLENS_RATE_LIMIT_REQUESTS`       | `30`     | Requests per window                                   |
| `TRUSTLENS_RATE_LIMIT_WINDOW_SECONDS` | `60`     | Rate limit window                                     |
| `TRUSTLENS_SCREENSHOT_ENABLED`        | `true`   | Capture page screenshots                              |
| `TRUSTLENS_COMMUNITY_REPORTS_ENABLED` | `true`   | Enable community reports                              |
| `TRUSTLENS_ENTERPRISE_MODE`           | `false`  | Enterprise brand monitoring                           |
| `TRUSTLENS_API_KEY_REQUIRED`          | `false`  | Require API keys                                      |
| `TRUSTLENS_AUDIT_LOG_ENABLED`         | `true`   | Audit logging                                         |

---

## API Endpoints

| Method | Endpoint                            | Description                    |
| ------ | ----------------------------------- | ------------------------------ |
| `POST` | `/api/analyze`                      | Submit a URL for analysis      |
| `GET`  | `/api/analyze/{id}`                 | Get analysis results (poll)    |
| `GET`  | `/api/report/{id}`                  | Get formatted report           |
| `GET`  | `/health`                           | Health check + provider status |
| `POST` | `/api/community/report`             | Submit community report        |
| `GET`  | `/api/community/consensus/{domain}` | Get community consensus        |
| `POST` | `/api/threat-intel/feeds`           | Add threat intel feed          |
| `GET`  | `/api/threat-intel/check/{domain}`  | Check domain against feeds     |
| `POST` | `/api/keys`                         | Create API key (enterprise)    |
| `GET`  | `/api/enterprise/brand-monitor`     | Brand monitor status           |

Full interactive docs at `http://localhost:3010/docs` (Swagger UI).

---

## Analysis Engines

TrustLens runs **15+ engines in parallel** for each URL scan:

| Engine                      | What It Does                             | Key Signals                                                  |
| --------------------------- | ---------------------------------------- | ------------------------------------------------------------ |
| **Heuristic Rules**         | URL structure, forms, content, redirects | SSL, suspicious URLs, cross-origin forms, hidden iframes     |
| **AI Deception Classifier** | LLM-powered phishing/scam detection      | Deception confidence, indicators, classifier scores          |
| **Brand Impersonation**     | Typosquatting & brand clone detection    | Domain similarity, content match, impersonation probability  |
| **Domain Intelligence**     | RDAP, age, TLD risk, DNS, structure      | Domain age, suspicious TLD, registrar, hyphen/digit analysis |
| **Behavioral Analysis**     | Runtime behavior & evasion detection     | JS redirects, obfuscation, anti-analysis, popup abuse        |
| **Security Headers**        | HTTP security headers audit              | CSP, HSTS, X-Frame-Options presence                          |
| **SSL Certificate**         | Real TLS cert extraction & validation    | Protocol version, issuer, validity, SAN                      |
| **Tracker & Malware**       | Analytics/ad/fingerprint/malware scan    | 68+ tracker patterns, crypto miners, spyware                 |
| **Download Threats**        | Dangerous file extension detection       | .exe, .ps1, .bat, auto-download scripts                      |
| **Screenshot Clone**        | Visual similarity via perceptual hashing | pHash/dHash comparison against brand screenshots             |
| **Zero-Day Suspicion**      | Structural anomaly scoring               | Novel attack pattern indicators                              |
| **Payment Detection**       | Payment form & crypto address scan       | Card fields, crypto wallets, payment processors              |
| **Content Extraction**      | Deep HTML/JS content analysis            | Text extraction, script analysis, metadata                   |
| **Community Reports**       | Crowdsourced URL safety data             | Community consensus, report counts                           |
| **Threat Intel Feeds**      | External threat intelligence checks      | Known malicious domains, blocklist matches                   |

---

## Scoring Methodology

```
Final Score = (Rule Score × 0.70) + (AI Score × 0.30)
```

### Rule Score Components

| Component           | Weight | Description                               |
| ------------------- | ------ | ----------------------------------------- |
| Heuristic Rules     | 30%    | URL patterns, forms, content, redirects   |
| Brand Impersonation | 25%    | Domain/content similarity to known brands |
| Behavioral Analysis | 20%    | Runtime behavior & evasion techniques     |
| Domain Intelligence | 15%    | Age, TLD, registrar, structure            |
| Security Headers    | 10%    | HTTP security header presence             |

### Risk Categories

| Score  | Category          | Description                           |
| ------ | ----------------- | ------------------------------------- |
| 75–100 | ✅ **Safe**       | No significant risk indicators        |
| 50–74  | 🟡 **Low Risk**   | Minor concerns, likely legitimate     |
| 25–49  | 🟠 **Suspicious** | Multiple concerning signals           |
| 0–24   | 🔴 **High Risk**  | Strong indicators of malicious intent |

### AI Confidence Calibration

The AI confidence is calibrated against reference anchors to prevent overclassification:

| Range     | Meaning                                    |
| --------- | ------------------------------------------ |
| 0.00–0.15 | No evidence / normal page                  |
| 0.15–0.35 | Minor suspicious element, likely benign    |
| 0.35–0.55 | Moderate concern, multiple soft indicators |
| 0.55–0.75 | Clear deceptive intent with evidence       |
| 0.75–0.90 | Strong multi-signal deception pattern      |
| 0.90–1.00 | Reserved for overwhelming evidence only    |

---

## Project Structure

```
TrustLens/
├── start.sh                    # One-command start script
├── setup_wizard.py             # Interactive LLM provider wizard
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Project metadata & build config
├── Dockerfile                  # Container build (python:3.12-slim)
├── docker-compose.yml          # Multi-container setup
├── .env.example                # Configuration template (30+ settings)
│
├── src/trustlens/
│   ├── main.py                 # FastAPI app entry point
│   ├── api/
│   │   ├── routes/
│   │   │   ├── analyze.py      # URL analysis endpoints
│   │   │   ├── community.py    # Community reporting
│   │   │   ├── enterprise.py   # Brand monitoring
│   │   │   ├── health.py       # Health check
│   │   │   ├── keys.py         # API key management
│   │   │   ├── report.py       # Report generation
│   │   │   └── threat_intel.py # Threat intel feeds
│   │   ├── middleware/
│   │   │   ├── api_auth.py     # API key authentication
│   │   │   ├── rate_limit.py   # Rate limiting
│   │   │   └── domain_filter.py# Domain allowlist/denylist
│   │   └── deps.py             # Dependency injection
│   │
│   ├── services/
│   │   ├── ai/                 # AI provider system
│   │   │   └── __init__.py     # Prompts, calibration, multi-provider
│   │   ├── analysis/
│   │   │   ├── behavioral.py   # Behavioral redirect/evasion analysis
│   │   │   ├── brand_similarity.py  # Brand impersonation (50+ brands)
│   │   │   ├── content_extractor.py # Content parsing engine
│   │   │   ├── domain_intel.py      # RDAP, DNS, domain scoring
│   │   │   ├── download_threat_detector.py  # Dangerous download detection
│   │   │   ├── logo_detection.py    # Logo similarity analysis
│   │   │   ├── payment_detector.py  # Payment form/crypto detection
│   │   │   ├── rules.py            # Heuristic rule engine (7 rules)
│   │   │   ├── screenshot_similarity.py  # Visual clone detection
│   │   │   ├── security_headers.py  # Security header audit
│   │   │   ├── tracker_detector.py  # Tracker/malware scanner (68+ patterns)
│   │   │   └── zeroday.py          # Zero-day suspicion scoring
│   │   ├── crawler/            # Playwright browser + intelligent page-load
│   │   ├── scoring/            # Hybrid 70/30 scoring engine
│   │   ├── orchestrator.py     # Analysis pipeline orchestrator
│   │   ├── queue/              # Async task queue
│   │   ├── community/          # Community reporting service
│   │   ├── enterprise/         # Brand monitoring service
│   │   └── threat_intel/       # Threat feed ingestion
│   │
│   ├── models/                 # Pydantic data models
│   ├── schemas/                # API request/response schemas
│   ├── security/               # SSRF protection, URL validation
│   ├── core/                   # Settings, logging config
│   ├── db/                     # SQLite database layer (aiosqlite)
│   ├── observability/          # Audit logging
│   └── utils/                  # Utility functions
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── ScanPage.tsx    # URL input + feature cards
│   │   │   ├── ResultsPage.tsx # Score gauge + signals + AI assessment
│   │   │   ├── AboutPage.tsx   # About & license
│   │   │   └── CommunityPage.tsx  # Community reports
│   │   ├── components/
│   │   │   ├── DeepDive.tsx    # Full transparency panel (15 sections)
│   │   │   ├── ScoreGauge.tsx  # Animated circular score gauge
│   │   │   ├── SignalCard.tsx  # Individual signal cards
│   │   │   ├── PipelineSteps.tsx  # Real-time pipeline progress
│   │   │   ├── Layout.tsx      # App shell + navigation
│   │   │   └── EvidenceTimeline.tsx  # Evidence timeline
│   │   ├── services/api.ts     # API client + TypeScript types
│   │   └── hooks/              # React hooks
│   ├── package.json
│   └── vite.config.ts
│
├── docs/
│   ├── ai-trust-explanation.md # AI trust scoring explained
│   ├── anti-hallucination.md   # Anti-hallucination strategy
│   ├── scoring-methodology.md  # Scoring algorithm details
│   └── security-model.md       # Security architecture
│
├── tests/                      # Test suite
└── LICENSE                     # MIT License
```

---

## Tech Stack

### Backend

| Technology               | Purpose                              |
| ------------------------ | ------------------------------------ |
| **Python 3.9+**          | Core language                        |
| **FastAPI**              | Async REST API framework             |
| **Pydantic v2**          | Data validation & serialisation      |
| **Playwright**           | Headless browser crawling (Chromium) |
| **SQLite + aiosqlite**   | Async embedded database              |
| **httpx**                | Async HTTP client                    |
| **structlog**            | Structured logging                   |
| **tldextract**           | Domain parsing & TLD extraction      |
| **python-Levenshtein**   | String similarity for typosquatting  |
| **Pillow + imagehash**   | Screenshot perceptual hashing        |
| **cryptography**         | SSL/TLS cert operations              |
| **BeautifulSoup + lxml** | HTML parsing & content extraction    |
| **dnspython**            | DNS resolution                       |

### Frontend

| Technology          | Purpose                                |
| ------------------- | -------------------------------------- |
| **React 19**        | UI framework                           |
| **TypeScript 5.9**  | Type safety                            |
| **Vite 7**          | Build tool & dev server                |
| **Tailwind CSS v4** | Utility-first styling (terminal theme) |
| **Lucide React**    | Icon library                           |
| **React Router v7** | Client-side routing                    |

### AI Providers (choose one)

| Provider          | SDK                   | Default Model              |
| ----------------- | --------------------- | -------------------------- |
| **Google Gemini** | `google-generativeai` | `gemini-2.5-flash`         |
| **OpenAI**        | `openai`              | `gpt-4o`                   |
| **Anthropic**     | `anthropic`           | `claude-sonnet-4-20250514` |
| **Grok (xAI)**    | `openai` (compatible) | `grok-3`                   |

---

## Contributing

Contributions are welcome! Here's how to get started:

```bash
# Fork & clone
git clone https://github.com/your-username/TrustLens.git
cd TrustLens

# Create a branch
git checkout -b feature/your-feature

# Start development
./start.sh

# Make changes, test, then submit a pull request
```

### Areas for Contribution

- New analysis engines
- Additional AI provider integrations
- Browser extension
- Improved documentation
- Bug reports & fixes

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/be4e31e1-ef1e-430f-b9da-500692100e64" alt="Designed & Developed by Abhishek Verma" width="520" />
</p>

<p align="center">
  <sub>Built by <a href="https://github.com/abhishekayu">Abhishek Verma</a></sub>
</p>
