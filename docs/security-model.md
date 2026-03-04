# TrustLens AI — Security Model

> Threat model, attack surface analysis, and security architecture.

---

## 1. Threat Model

### 1.1 System Context

TrustLens is a URL analysis engine that:

- Accepts URLs from untrusted users
- Crawls those URLs using a headless browser
- Sends page content to AI models for analysis
- Stores results in a database
- Serves results via API

Each of these operations presents an attack surface.

### 1.2 Threat Actors

| Actor              | Motivation                              | Capabilities                                       |
| ------------------ | --------------------------------------- | -------------------------------------------------- |
| **Phisher**        | Evade detection of their phishing page  | Controls target page content, HTML, JavaScript     |
| **Scanner abuser** | Use TrustLens as an attack proxy (SSRF) | Submits crafted URLs pointing to internal services |
| **API abuser**     | Exhaust resources or extract data       | High-volume automated requests                     |
| **AI manipulator** | Inject instructions via page content    | Embeds prompt injection payloads in crawled pages  |
| **Insider threat** | Access or modify analysis data          | Authenticated API access                           |

### 1.3 Trust Boundaries

```
                    UNTRUSTED                    TRUSTED
                  ┌───────────┐             ┌───────────────┐
  User Request ──▶│ API Layer │──validated──▶│ Orchestrator  │
                  │ (FastAPI) │              └───────┬───────┘
                  └───────────┘                      │
                                                     ▼
                  ┌───────────┐             ┌───────────────┐
  Target Page ───▶│ Crawler   │──sanitized─▶│ Analysis      │
  (UNTRUSTED)     │ (sandbox) │              │ Pipeline      │
                  └───────────┘              └───────┬───────┘
                                                     │
                  ┌───────────┐                      ▼
  AI Model ──────▶│ AI Layer  │──calibrated─▶ Scoring Engine
  (SEMI-TRUSTED)  │ (bounded) │
                  └───────────┘
```

---

## 2. SSRF Protection

### 2.1 The Risk

Server-Side Request Forgery (SSRF) is the most critical threat. An attacker submits a URL like:

- `http://169.254.169.254/latest/meta-data/` (AWS metadata)
- `http://localhost:8000/admin` (internal services)
- `http://192.168.1.1/` (internal network)

If TrustLens crawls these URLs, the attacker gains access to internal resources via the server.

### 2.2 Defense: Multi-Layer SSRF Protection

```python
# Layer 1: URL validation
- Reject non-HTTP(S) schemes (file://, ftp://, gopher://, etc.)
- Reject URLs without valid hostnames
- Reject URLs with authentication credentials in the URL

# Layer 2: DNS resolution check (pre-crawl)
- Resolve hostname to IP BEFORE connecting
- Block private/reserved IP ranges:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 127.0.0.0/8
  - 169.254.0.0/16 (link-local)
  - ::1 (IPv6 loopback)
  - fc00::/7 (IPv6 private)

# Layer 3: Post-redirect validation
- After EVERY redirect, re-validate the new URL
- Prevents DNS rebinding (initial resolve → public IP, redirect → private IP)

# Layer 4: Network-level isolation (Docker)
- Crawler container on isolated network
- No access to host network or Docker socket
```

### 2.3 Configuration

```env
TRUSTLENS_SSRF_BLOCK_PRIVATE=true    # Block private IP ranges (default: true)
TRUSTLENS_DOMAIN_ALLOWLIST=          # Only allow specific domains
TRUSTLENS_DOMAIN_DENYLIST=           # Block specific domains
```

---

## 3. Browser Sandbox Security

### 3.1 Playwright Isolation

The Playwright Chromium browser is configured for maximum isolation:

| Setting           | Value                           | Purpose                               |
| ----------------- | ------------------------------- | ------------------------------------- |
| `--no-sandbox`    | Disabled in production          | OS-level sandboxing                   |
| JavaScript        | Enabled (required for analysis) | Page behavior detection               |
| Network isolation | Playwright proxy                | All traffic routed through validation |
| Timeout           | 30 seconds                      | Prevent infinite hangs                |
| Max redirects     | 10                              | Prevent redirect loops                |
| File downloads    | Disabled                        | Prevent filesystem access             |
| Geolocation       | Disabled                        | Privacy                               |
| Cookies           | Ephemeral per-session           | No persistence                        |

### 3.2 Screenshot Security

Screenshots are:

- Stored as PNG files in a configurable directory
- Named with analysis IDs (no user-controlled filenames)
- Cleaned up after configurable retention period
- Never served directly (accessed via API with authentication)

### 3.3 Content Extraction

Raw HTML from crawled pages is:

- Truncated to maximum configurable length
- Stripped of script tags for AI analysis (behavior analyzed separately)
- Never stored in raw form in the database
- Never reflected back to users without sanitization

---

## 4. API Security

### 4.1 Authentication

TrustLens supports tiered API key authentication:

| Tier           | Rate Limit   | Scopes                           | Use Case      |
| -------------- | ------------ | -------------------------------- | ------------- |
| **Free**       | 30 req/min   | analyze, community               | Public access |
| **Pro**        | 200 req/min  | analyze, community, threat_intel | Power users   |
| **Enterprise** | 1000 req/min | All scopes                       | Organizations |

API keys are:

- Prefixed with `tl_` for easy identification
- Stored as SHA-256 hashes (never plaintext)
- Shown to the user only once at creation
- Revocable at any time

### 4.2 Rate Limiting

Two layers of rate limiting:

1. **Per-IP rate limiting** — Middleware-level, configurable window/count
2. **Per-key rate limiting** — Sliding window per API key, tier-based limits

### 4.3 Input Validation

All API inputs are validated via Pydantic v2 schemas:

- URL format validation
- Maximum request body size
- String length limits
- Enum validation for options

### 4.4 CORS

```python
CORSMiddleware(
    allow_origins=["*"],      # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Production recommendation:** Restrict `allow_origins` to your frontend domain.

---

## 5. AI Security

### 5.1 Prompt Injection Defense

See [Anti-Hallucination Strategy](anti-hallucination.md) for the complete defense.

**Summary:**

- System prompt with explicit anti-injection instructions
- Content placed inside a clearly marked fence
- Output validation against strict JSON schema
- Confidence calibration reduces impact of manipulated outputs
- 70/30 scoring cap limits AI influence regardless of injection success

### 5.2 AI Provider Security

| Provider       | Data Transmission          | Privacy                          |
| -------------- | -------------------------- | -------------------------------- |
| **Gemini**     | HTTPS to Google servers    | Subject to Google AI data policy |
| **OpenAI**     | HTTPS to OpenAI servers    | Subject to OpenAI data policy    |
| **Anthropic**  | HTTPS to Anthropic servers | Subject to Anthropic data policy |
| **Grok (xAI)** | HTTPS to xAI servers       | Subject to xAI data policy       |

**Recommendation:** Review each provider's data retention policy before deploying with sensitive URLs.

### 5.3 Model Selection

The AI model is configurable. Security considerations:

- All supported providers transmit data over HTTPS
- Review each provider's data retention policy
- Model accuracy varies — use recommended models for best results

---

## 6. Database Security

### 6.1 SQLite (Default)

- File-based, no network exposure
- WAL mode for concurrent read access
- Located at configurable path (default: `./trustlens.db`)

### 6.2 Data Stored

| Table               | Sensitive Data        | Protection                         |
| ------------------- | --------------------- | ---------------------------------- |
| `analyses`          | URLs analyzed, scores | None (URLs are inherently public)  |
| `brands`            | Brand definitions     | Public data                        |
| `community_reports` | Reporter IDs (hashed) | SHA-256 reporter anonymization     |
| `api_keys`          | Key hashes, emails    | SHA-256 key hashing                |
| `threat_entries`    | Threat indicators     | Public threat intel data           |
| `screenshot_hashes` | Perceptual hashes     | Non-reversible to original image   |
| `audit_log`         | Request metadata      | IP addresses, usernames            |
| `brand_monitors`    | Webhook URLs          | Enterprise-only, access-controlled |
| `brand_alerts`      | Alert details         | Enterprise-only                    |

### 6.3 PostgreSQL Migration

For production, swap to PostgreSQL:

- Change `TRUSTLENS_DB_URL` to a PostgreSQL connection string
- The repository pattern abstracts all queries
- Enable connection pooling via `asyncpg`

---

## 7. Observability Security

### 7.1 Audit Logging

All security-relevant events are logged:

| Event Type                | What's Logged          | Why                      |
| ------------------------- | ---------------------- | ------------------------ |
| `analysis.started`        | URL, analysis ID       | Forensics                |
| `api.rate_limited`        | IP, path               | Abuse detection          |
| `api.unauthorized`        | IP, attempted key      | Brute force detection    |
| `ssrf.blocked`            | URL, resolved IP       | Attack monitoring        |
| `injection.detected`      | Sanitized content hash | AI manipulation tracking |
| `system.startup/shutdown` | Configuration summary  | Operations               |

### 7.2 Suspicious Activity Detection

The `ActivityMonitor` uses sliding-window analysis:

- Detects high-frequency requests from single IPs
- Identifies authentication brute-force attempts
- Flags active attack patterns (repeated SSRF attempts)

### 7.3 Metrics

In-memory metrics collector tracks:

- Request counts by endpoint
- Error rates
- Analysis completion times
- AI provider response times

---

## 8. Deployment Security Checklist

### Development

- [ ] Use `.env` file (not committed to git)
- [ ] Configure AI provider API key
- [ ] SQLite is fine

### Staging

- [ ] Enable API key authentication
- [ ] Configure rate limits
- [ ] Enable audit logging
- [ ] Test with realistic threat feeds

### Production

- [ ] `TRUSTLENS_DEBUG=false`
- [ ] `TRUSTLENS_API_KEY_REQUIRED=true`
- [ ] Reverse proxy with TLS (nginx/Caddy)
- [ ] Restrict CORS origins
- [ ] PostgreSQL database
- [ ] Docker with network isolation
- [ ] Log aggregation (ELK/Loki)
- [ ] Monitoring and alerting
- [ ] Regular security updates
- [ ] Backup strategy for database

---

## 9. Known Limitations

1. **SQLite concurrency** — Single-writer limitation for high-throughput deployments (use PostgreSQL)
2. **Screenshot storage** — File-based storage; consider object storage (S3) for scale
3. **In-memory rate limits** — Lost on restart; consider Redis for persistence
4. **Community report trust** — Initial implementation uses fixed trust weights; ML-based reputation is planned

---

## 10. Responsible Disclosure

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainers with a detailed description
3. Include reproduction steps
4. Allow reasonable time for a fix (typically 90 days)

We will credit responsible reporters in our security advisories.
