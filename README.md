<p align="center">
  <img src="docs/assets/trustlens-banner.png" alt="TrustLens AI" width="720" />
</p>

<h1 align="center">TrustLens AI</h1>

<p align="center">
  <strong>Explainable AI-Powered URL Trust Intelligence Engine</strong><br/>
  <em>Every risk score comes with evidence you can verify.</em>
</p>

<p align="center">
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://fastapi.tiangolo.com"><img src="https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white" alt="FastAPI"></a>
  <a href="https://react.dev"><img src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black" alt="React"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/status-active%20development-brightgreen" alt="Status">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-vision">Vision</a> &bull;
  <a href="#-architecture">Architecture</a> &bull;
  <a href="#-api-reference">API Docs</a> &bull;
  <a href="#-react-dashboard">Dashboard</a> &bull;
  <a href="#-roadmap">Roadmap</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Vision

The internet trust problem is getting worse. Phishing attacks increased 150% year-over-year. Existing URL checkers give you a binary **safe/unsafe** with zero explanation &mdash; a black box you're supposed to blindly trust.

**TrustLens AI exists to fix this.**

We believe security verdicts must be **transparent, explainable, and verifiable**. Every score TrustLens produces comes with a complete evidence trail &mdash; the signals that contributed, the weights applied, and the reasoning behind each decision. You don't have to trust our AI. You can verify every conclusion yourself.

### Core Principles

| Principle                        | Implementation                                                                      |
| -------------------------------- | ----------------------------------------------------------------------------------- |
| **AI advises, rules decide**     | AI is capped at 30% influence. Deterministic rules control 70%.                     |
| **Evidence over authority**      | Every signal includes raw evidence a human can independently verify.                |
| **Privacy by default**           | Self-hostable. Supports multiple AI providers. Your URLs stay under your control.   |
| **Zero hallucination tolerance** | Multi-layer anti-hallucination pipeline prevents AI from fabricating evidence.      |
| **Open by design**               | MIT licensed. Every algorithm, every weight, every threshold &mdash; all auditable. |

---

## Why TrustLens Is Different

<table>
<tr><th>Capability</th><th>Google Safe Browsing</th><th>VirusTotal</th><th>URLScan.io</th><th><strong>TrustLens AI</strong></th></tr>
<tr><td>Explainable evidence trail</td><td>No</td><td>Partial</td><td>Partial</td><td><strong>Full transparency</strong></td></tr>
<tr><td>Hybrid AI + Rule scoring</td><td>No</td><td>No</td><td>No</td><td><strong>70/30 model</strong></td></tr>
<tr><td>Visual clone detection</td><td>No</td><td>No</td><td>No</td><td><strong>Perceptual hashing</strong></td></tr>
<tr><td>Zero-day anomaly heuristics</td><td>No</td><td>No</td><td>No</td><td><strong>4-axis scoring</strong></td></tr>
<tr><td>Community crowd reports</td><td>No</td><td>Yes</td><td>No</td><td><strong>Weighted consensus</strong></td></tr>
<tr><td>Threat intel aggregation</td><td>N/A</td><td>Partial</td><td>Partial</td><td><strong>Multi-feed pipeline</strong></td></tr>
<tr><td>Multi-provider AI</td><td>No</td><td>No</td><td>No</td><td><strong>Gemini, Grok, OpenAI, Anthropic</strong></td></tr>
<tr><td>Enterprise brand monitoring</td><td>No</td><td>No</td><td>Partial</td><td><strong>Webhook alerts</strong></td></tr>
<tr><td>Anti-hallucination pipeline</td><td>N/A</td><td>N/A</td><td>N/A</td><td><strong>Multi-layer defense</strong></td></tr>
<tr><td>Full audit logging</td><td>No</td><td>Partial</td><td>No</td><td><strong>Structured events</strong></td></tr>
</table>

---

## Architecture

```
+------------------------------------------------------------------------------+
|                      React Dashboard (Port 5173)                             |
|  +-----------+  +-----------+  +-----------+  +-----------+  +----------+   |
|  | URL Input |  | Score     |  | Evidence  |  | Threat    |  | Community|   |
|  | Scanner   |  | Gauge     |  | Timeline  |  | Map       |  | Reports  |   |
|  +-----------+  +-----------+  +-----------+  +-----------+  +----------+   |
+--------------------------------------+---------------------------------------+
                                       | HTTP/JSON
+--------------------------------------v---------------------------------------+
|                      FastAPI Backend (Port 8000)                             |
|  +----------+  +----------+  +----------+  +----------+  +--------------+   |
|  | CORS     |  | Rate     |  | Domain   |  | API Key  |  | Observability|   |
|  |          |  | Limiter  |  | Filter   |  | Auth     |  | and Audit    |   |
|  +----------+  +----------+  +----------+  +----------+  +--------------+   |
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |                     API Routes (/api/v1/*)                             |  |
|  |  POST /analyze            GET /analysis/{id}  GET /analysis/{id}/report|  |
|  |  POST /analyze/batch      GET /health                                  |  |
|  |  POST /community/report   GET /community/consensus                     |  |
|  |  POST /keys/register      GET /threat-intel/lookup                     |  |
|  |  POST /threat-intel/ingest  GET /threat-intel/stats                    |  |
|  |  POST /enterprise/monitors  GET /enterprise/alerts                     |  |
|  +------------------------------------+-----------------------------------+  |
|                                       |                                      |
|                              +--------v--------+                             |
|                              |  Orchestrator   |                             |
|                              +--------+--------+                             |
|                                       |                                      |
|    +----------+----------+----+-------+--------+----------+----------+       |
|    v          v          v    v                 v          v          v       |
| +--------++--------++------++--------++----------++--------++----------+     |
| |Playwrt ||Analysis||  AI  ||Screen- ||Zero-Day  ||Threat  ||Community |     |
| |Crawler ||Pipeline||Provdr||shot    ||Suspicion ||Intel   ||Consensus |     |
| |(sandbox||        ||      ||Similar.||Scorer    ||Feeds   ||          |     |
| |)       ||  Rules ||Gemini|+--------++----------++--------++----------+     |
| +--------+|  Brand ||OpenAI|                                                 |
|           |  Behav.||Anthr.|    +--------------------------+                 |
|           |  Domain|+------+    |  Enterprise Monitoring   |                 |
|           |  Header|            |  Brand Scanning          |                 |
|           |  Contnt|            |  Webhook Alerts           |                |
|           +--------+            +--------------------------+                 |
|                                       |                                      |
|                              +--------v--------+                             |
|                              | Scoring Engine  |                             |
|                              | 70% Rules + 30% |                            |
|                              | AI + Supplements|                             |
|                              +--------+--------+                             |
|                                       |                                      |
|                              +--------v--------+                             |
|                              |  SQLite / DB    |  9 tables                   |
|                              |  (repo pattern) |  repository pattern         |
|                              +-----------------+                             |
+------------------------------------------------------------------------------+
```

---

## Hybrid AI + Rule Scoring Model

TrustLens uses a **70/30 hybrid model** that combines deterministic rule-based analysis with AI advisory signals.

### Why Not 100% AI?

AI models hallucinate. They produce confident-sounding verdicts with fabricated evidence. In security, a false negative can lead to credential theft. A false positive erodes user trust.

Our solution: **AI advises, rules decide.**

### Rule Component Weights

| Sub-Component       | Weight | What It Measures                          |
| ------------------- | ------ | ----------------------------------------- |
| Heuristic Rules     | 30%    | SSL, forms, URL patterns, content signals |
| Brand Impersonation | 25%    | Levenshtein similarity, typosquatting     |
| Behavioral Analysis | 20%    | Redirects, hidden elements, evasion       |
| Domain Intelligence | 15%    | Domain age, RDAP, DNS, suspicious TLDs    |
| Security Headers    | 10%    | HSTS, CSP, X-Frame-Options                |

### Supplementary Signal Adjustments

After the core 70/30 calculation, hard-evidence signals apply additional adjustments:

| Signal                      | Max Adjustment | Trigger Condition                    |
| --------------------------- | -------------- | ------------------------------------ |
| **Screenshot Visual Clone** | -15 pts        | Perceptual hash similarity >= 85%    |
| **Zero-Day Suspicion**      | -10 pts        | Anomaly score >= 50 (sigmoid scaled) |
| **Threat Intel Match**      | -30 pts        | Known threat in feed databases       |
| **Community Consensus**     | +/-5 pts       | Weighted crowd reports               |

### Risk Categories

| Score  | Category       | Meaning                             |
| ------ | -------------- | ----------------------------------- |
| 75-100 | **Safe**       | No significant risk indicators      |
| 50-74  | **Low Risk**   | Minor concerns, likely legitimate   |
| 25-49  | **Suspicious** | Multiple risk indicators present    |
| 0-24   | **High Risk**  | Strong evidence of malicious intent |

> **Deep dive:** See [docs/scoring-methodology.md](docs/scoring-methodology.md) for the full whitepaper.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for React dashboard)
- An AI provider API key (Gemini, OpenAI, Anthropic, or Grok)

### 1. Clone and Install Backend

```bash
git clone https://github.com/abhishekayu/TrustLens.git
cd TrustLens

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install Playwright browser
playwright install chromium
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env - configure your AI provider
```

### 3. Start Backend

```bash
uvicorn trustlens.main:app --reload --port 8000
```

### 4. Start React Dashboard

```bash
cd frontend
npm install
npm run dev
```

**Backend API docs:** http://localhost:8000/docs
**React Dashboard:** http://localhost:5173

---

## AI Provider Setup

TrustLens supports multiple AI providers. Run the interactive setup wizard or configure manually.

### Interactive Setup

```bash
python setup_wizard.py
# Or simply start the backend — the wizard runs automatically on first launch
uvicorn trustlens.main:app --reload --port 8000
```

### Manual Configuration

```env
# Gemini (default)
TRUSTLENS_AI_PROVIDER=gemini
TRUSTLENS_GEMINI_API_KEY=your-key
TRUSTLENS_GEMINI_MODEL=gemini-2.5-flash

# OpenAI
TRUSTLENS_AI_PROVIDER=openai
TRUSTLENS_OPENAI_API_KEY=your-key
TRUSTLENS_OPENAI_MODEL=gpt-4o

# Anthropic
TRUSTLENS_AI_PROVIDER=anthropic
TRUSTLENS_ANTHROPIC_API_KEY=your-key
TRUSTLENS_ANTHROPIC_MODEL=claude-sonnet-4-20250514

# Grok (xAI)
TRUSTLENS_AI_PROVIDER=grok
TRUSTLENS_GROK_API_KEY=your-key
TRUSTLENS_GROK_MODEL=grok-3-mini
```

### Supported Providers

| Provider      | Model Example              | Best For                        |
| ------------- | -------------------------- | ------------------------------- |
| **Gemini**    | `gemini-2.5-flash`         | Default &mdash; fast & accurate |
| **OpenAI**    | `gpt-4o`                   | Highest accuracy                |
| **Anthropic** | `claude-sonnet-4-20250514` | Strong reasoning                |
| **Grok**      | `grok-3-mini`              | xAI ecosystem                   |

---

## Deployment

### Docker

```bash
docker build -t trustlens-ai .
docker run -p 8000:8000 --env-file .env trustlens-ai
```

### Docker Compose (Full Stack)

```yaml
version: "3.9"
services:
  backend:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    volumes:
      - ./data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    build: ./frontend
    ports:
      - "5173:80"
    depends_on:
      - backend
    environment:
      - VITE_API_URL=http://backend:8000
```

### Production Checklist

- [ ] Set `TRUSTLENS_DEBUG=false`
- [ ] Enable `TRUSTLENS_API_KEY_REQUIRED=true`
- [ ] Configure threat feed URLs
- [ ] Set up reverse proxy (nginx/Caddy) with TLS
- [ ] Enable audit logging
- [ ] Configure rate limits for production traffic
- [ ] Swap SQLite for PostgreSQL (change `TRUSTLENS_DB_URL`)

---

## API Reference

### Core Analysis

| Method | Endpoint                       | Description                |
| ------ | ------------------------------ | -------------------------- |
| `POST` | `/api/v1/analyze`              | Submit URL for analysis    |
| `POST` | `/api/v1/analyze/batch`        | Submit multiple URLs       |
| `GET`  | `/api/v1/analysis/{id}`        | Get analysis status/result |
| `GET`  | `/api/v1/analysis/{id}/report` | Full transparency report   |

### Community

| Method | Endpoint                      | Description                 |
| ------ | ----------------------------- | --------------------------- |
| `POST` | `/api/v1/community/report`    | Submit a community report   |
| `GET`  | `/api/v1/community/consensus` | Get crowd consensus for URL |
| `GET`  | `/api/v1/community/reports`   | List reports for URL/domain |

### Threat Intelligence

| Method | Endpoint                      | Description                |
| ------ | ----------------------------- | -------------------------- |
| `GET`  | `/api/v1/threat-intel/lookup` | Check domain against feeds |
| `GET`  | `/api/v1/threat-intel/stats`  | Feed ingestion statistics  |
| `POST` | `/api/v1/threat-intel/ingest` | Trigger feed re-ingestion  |

### API Keys

| Method | Endpoint                | Description             |
| ------ | ----------------------- | ----------------------- |
| `POST` | `/api/v1/keys/register` | Register for an API key |

### Enterprise

| Method | Endpoint                      | Description          |
| ------ | ----------------------------- | -------------------- |
| `POST` | `/api/v1/enterprise/monitors` | Create brand monitor |
| `GET`  | `/api/v1/enterprise/monitors` | List active monitors |
| `GET`  | `/api/v1/enterprise/alerts`   | Get brand alerts     |

### System

| Method | Endpoint  | Description            |
| ------ | --------- | ---------------------- |
| `GET`  | `/health` | Health check + metrics |

<details>
<summary><strong>Example: Analyze a URL</strong></summary>

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.example.com/login",
    "options": {
      "enable_ai": true,
      "enable_domain_intel": true,
      "enable_brand_check": true,
      "enable_behavioral": true,
      "enable_threat_intel": true,
      "enable_community": true,
      "enable_zeroday": true
    }
  }'
```

**Response (202 Accepted):**

```json
{
  "analysis_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "pending",
  "url": "https://suspicious-site.example.com/login",
  "submitted_at": "2026-03-04T10:30:00Z"
}
```

</details>

---

## React Dashboard

The React frontend provides a modern, real-time interface for TrustLens.

### Screenshots

<p align="center">
  <img src="docs/assets/screenshot-scan.png" alt="URL Scanner" width="700" /><br/>
  <em>URL Scanner &mdash; paste a URL and get instant trust analysis</em>
</p>

<p align="center">
  <img src="docs/assets/screenshot-results.png" alt="Analysis Results" width="700" /><br/>
  <em>Analysis Results &mdash; score gauge, risk signals, evidence timeline</em>
</p>

<p align="center">
  <img src="docs/assets/screenshot-report.png" alt="Transparency Report" width="700" /><br/>
  <em>Transparency Report &mdash; full explainability for every decision</em>
</p>

<p align="center">
  <img src="docs/assets/screenshot-community.png" alt="Community Reports" width="700" /><br/>
  <em>Community Reports &mdash; crowd-sourced trust signals</em>
</p>

---

## Roadmap

### v0.2 - Current Release

- [x] 70/30 hybrid AI + rule scoring engine
- [x] 15+ analysis modules (brand, behavioral, domain, headers, content)
- [x] Screenshot similarity via perceptual hashing
- [x] Zero-day suspicion anomaly scoring
- [x] Community reporting with weighted consensus
- [x] Threat intelligence feed aggregation
- [x] Tiered API key authentication
- [x] Enterprise brand monitoring stubs
- [x] Observability, audit logging, metrics
- [x] React dashboard with real-time scanning
- [x] Multi-provider AI support (Gemini, OpenAI, Anthropic, Grok)
- [x] Docker deployment

### v0.3 - Intelligence Expansion

- [ ] Browser extension (Chrome/Firefox) for real-time protection
- [ ] Logo detection via CLIP/YOLOv8 vision models
- [ ] Certificate Transparency log monitoring
- [ ] Email header analysis module
- [ ] Historical trend analysis per domain
- [ ] Bulk CSV import/export

### v0.4 - Enterprise Hardening

- [ ] PostgreSQL primary database
- [ ] Redis-backed task queue
- [ ] Multi-tenant workspace isolation
- [ ] SSO/SAML authentication
- [ ] Custom scoring rule builder (no-code)
- [ ] Webhook integrations (Slack, Teams, PagerDuty)

### v0.5 - Intelligence Network

- [ ] Federated threat sharing between TrustLens instances
- [ ] ML-based reporter reputation scoring
- [ ] Automated phishing takedown integration
- [ ] API marketplace for third-party analyzers
- [ ] Mobile app (React Native)

### v1.0 - Production GA

- [ ] SOC 2 Type II compliance documentation
- [ ] 99.9% uptime SLA architecture
- [ ] Horizontally scalable worker pool
- [ ] Full internationalization (i18n)
- [ ] Public threat intelligence dashboard

---

## Project Structure

```
TrustLens/
  frontend/                        React 19 + Vite dashboard
    src/
      components/                  Reusable UI components
      pages/                       Route pages
      hooks/                       Custom React hooks
      services/                    API client
      App.tsx
    package.json
  src/trustlens/                   Python backend
    main.py                        FastAPI entry-point
    core/                          Settings, logging
    models/                        Domain models (Pydantic v2)
    schemas/                       API request/response schemas
    db/                            Database + 8 repositories
    security/                      SSRF protection
    observability/                 Audit logger, metrics
    api/
      middleware/                  Rate limit, domain filter, API auth
      routes/                      All API endpoints
    services/
      orchestrator.py              Analysis pipeline coordinator
      scoring/                     70/30 hybrid scoring engine
      ai/providers/                Gemini, OpenAI, Anthropic, Grok
      analysis/                    9 analysis modules
      community/                   Community reporting
      threat_intel/                Feed parsers + ingestion
      enterprise/                  Brand monitoring
  docs/                            Documentation
    scoring-methodology.md         Scoring whitepaper
    ai-trust-explanation.md        AI trust model
    security-model.md              Security architecture
    anti-hallucination.md          Anti-hallucination strategy
  Dockerfile
  docker-compose.yml
  requirements.txt
  pyproject.toml
  CONTRIBUTING.md
  LICENSE (MIT)
  README.md
```

---

## Configuration

All settings via environment variables (prefix `TRUSTLENS_`):

<details>
<summary><strong>Full Configuration Table</strong></summary>

| Variable                                    | Default                              | Description                                |
| ------------------------------------------- | ------------------------------------ | ------------------------------------------ |
| `TRUSTLENS_HOST`                            | `0.0.0.0`                            | Server bind address                        |
| `TRUSTLENS_PORT`                            | `8000`                               | Server port                                |
| `TRUSTLENS_DEBUG`                           | `false`                              | Debug mode                                 |
| `TRUSTLENS_LOG_LEVEL`                       | `info`                               | Logging level                              |
| `TRUSTLENS_DB_URL`                          | `sqlite+aiosqlite:///./trustlens.db` | Database URL                               |
| `TRUSTLENS_AI_PROVIDER`                     | `gemini`                             | AI provider (gemini/openai/anthropic/grok) |
| `TRUSTLENS_GEMINI_API_KEY`                  | -                                    | Gemini API key                             |
| `TRUSTLENS_GEMINI_MODEL`                    | `gemini-2.5-flash`                   | Gemini model                               |
| `TRUSTLENS_OPENAI_API_KEY`                  | -                                    | OpenAI API key                             |
| `TRUSTLENS_OPENAI_MODEL`                    | `gpt-4o`                             | OpenAI model                               |
| `TRUSTLENS_ANTHROPIC_API_KEY`               | -                                    | Anthropic API key                          |
| `TRUSTLENS_ANTHROPIC_MODEL`                 | `claude-sonnet-4-20250514`           | Anthropic model                            |
| `TRUSTLENS_GROK_API_KEY`                    | -                                    | Grok (xAI) API key                         |
| `TRUSTLENS_GROK_MODEL`                      | `grok-3-mini`                        | Grok model                                 |
| `TRUSTLENS_RATE_LIMIT_REQUESTS`             | `30`                                 | Max requests per window                    |
| `TRUSTLENS_RATE_LIMIT_WINDOW_SECONDS`       | `60`                                 | Rate limit window                          |
| `TRUSTLENS_SCORE_WEIGHT_RULES`              | `0.70`                               | Rule-based score weight                    |
| `TRUSTLENS_SCORE_WEIGHT_AI`                 | `0.30`                               | AI advisory score weight                   |
| `TRUSTLENS_API_KEY_REQUIRED`                | `false`                              | Require API keys                           |
| `TRUSTLENS_THREAT_FEED_URLS`                | -                                    | Comma-separated feed URLs                  |
| `TRUSTLENS_THREAT_FEED_REFRESH_HOURS`       | `6`                                  | Feed refresh interval                      |
| `TRUSTLENS_SCREENSHOT_SIMILARITY_THRESHOLD` | `0.85`                               | Visual clone threshold                     |
| `TRUSTLENS_COMMUNITY_REPORTS_ENABLED`       | `true`                               | Enable community reports                   |
| `TRUSTLENS_ENTERPRISE_MODE`                 | `false`                              | Enable enterprise features                 |
| `TRUSTLENS_AUDIT_LOG_ENABLED`               | `true`                               | Enable audit logging                       |

</details>

---

## Documentation

| Document                                                  | Description                                           |
| --------------------------------------------------------- | ----------------------------------------------------- |
| [Scoring Methodology](docs/scoring-methodology.md)        | Complete whitepaper on the 70/30 hybrid scoring model |
| [AI Trust Explanation](docs/ai-trust-explanation.md)      | How AI is constrained and why                         |
| [Security Model](docs/security-model.md)                  | SSRF protection, sandboxing, threat model             |
| [Anti-Hallucination Strategy](docs/anti-hallucination.md) | Multi-layer defense against AI fabrication            |

| [Contributing](CONTRIBUTING.md) | How to contribute to TrustLens |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork, Clone, Branch, Implement, Test, PR
git checkout -b feature/my-feature
# Make your changes
pytest
ruff check src/
git push origin feature/my-feature
```

---

## License

MIT License &mdash; see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with security-first principles.</strong><br/>
  AI advises. Rules decide. Evidence explains.
</p>
