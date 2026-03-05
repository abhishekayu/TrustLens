# GitHub SEO Checklist for TrustLens AI

Your repo currently shows **"No description, website, or topics provided"** — fixing this alone will massively boost discoverability.

---

## 1. Repository Description (CRITICAL)

Go to: **Repo page → ⚙️ gear icon** (next to "About" on right sidebar)

**Set Description to:**

```
🔍 Explainable AI-Powered URL Trust Intelligence Engine — 15+ parallel analysis engines, hybrid 70/30 rule+AI scoring, brand impersonation detection, behavioral analysis, and full-transparency evidence breakdown. Self-hosted, open-source.
```

> GitHub indexes this for search. Keep it keyword-rich and under 350 characters.

---

## 2. Topics / Tags (CRITICAL)

In the same ⚙️ About settings, add these **topics** (GitHub allows up to 20):

```
phishing-detection
url-scanner
cybersecurity
ai-security
threat-intelligence
fastapi
react
typescript
python
brand-impersonation
domain-analysis
security-headers
explainable-ai
url-analysis
trust-scoring
anti-phishing
malware-detection
open-source-security
self-hosted
web-security
```

> Topics appear as clickable tags on your repo and feed into GitHub's Explore/Topics pages.
> People browsing `github.com/topics/phishing-detection` will find you.

---

## 3. Website URL

In the same ⚙️ About settings, set the **Website** field to:

```
https://github.com/abhishekayu/TrustLens#-trustlens-ai
```

Or if you deploy a GitHub Pages site later, use that URL instead.

---

## 4. Social Preview Image (Open Graph)

Go to: **Settings → General → Social Preview**

Upload a custom 1280×640 image that shows:

- TrustLens AI logo/banner
- The terminal-theme UI screenshot
- Tagline: "Explainable AI-Powered URL Trust Intelligence Engine"

This image appears when your repo link is shared on Twitter/LinkedIn/Discord/Slack.

> Without it, GitHub auto-generates a plain card. A custom one gets **2-3x more clicks**.

---

## 5. Create a Release (IMPORTANT)

Go to: **Releases → Draft a new release**

```
Tag:        v0.1.0
Title:      v0.1.0 — Initial Release
```

**Release notes (copy this):**

````markdown
## 🚀 TrustLens AI v0.1.0 — Initial Release

### Highlights

- **15+ Parallel Analysis Engines** — Rule-based heuristics, AI deception classifier, brand impersonation, behavioral analysis, domain intel, and more
- **Hybrid 70/30 Scoring** — Rule score (70%) + AI advisory score (30%) for transparent, explainable verdicts
- **Multi-LLM Support** — Gemini, OpenAI, Anthropic, and Grok via interactive setup wizard
- **Terminal-Theme UI** — Dark hacker aesthetic with full-transparency Deep Dive panel
- **One-Command Start** — `./start.sh` handles everything: wizard, deps, backend, frontend

### Analysis Engines

- Heuristic Rules (7 rules) · Brand Impersonation (50+ brands) · Domain Intelligence (RDAP, 14-tier age scoring)
- Behavioral Analysis (redirects, popups, clipboard, WebSocket) · Security Headers · SSL Certificate Extraction
- Tracker & Malware Detection (68+ patterns) · Download Threat Scanner · Screenshot Clone Detection
- Zero-Day Suspicion Scoring · Payment Form Detection · Community Reports · Threat Intel Feeds

### Tech Stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2, Playwright, SQLite
- **Frontend:** React 19, TypeScript 5.9, Vite 7, Tailwind CSS v4
- **AI:** Gemini · OpenAI · Anthropic · Grok

### Getting Started

```bash
git clone https://github.com/abhishekayu/TrustLens.git
cd TrustLens && chmod +x start.sh && ./start.sh
```
````

```

> Releases show up in GitHub search results, RSS feeds, and the repo sidebar.

---

## 6. Pin the Repository

Go to: **Your GitHub profile → Customize your pins**

Pin TrustLens to your profile so it appears on your profile page prominently.

---

## 7. Commit Message SEO

Your recent commits use generic messages like `"s"` and `"feat: Implement..."`.

**Going forward, use descriptive messages with keywords:**
```

feat: add zero-day anomaly detection with 4 sub-scorers
fix: correct SSL certificate extraction using real TLS connections
feat: implement 50+ brand registry for typosquatting detection

````

These are indexed by GitHub search.

---

## 8. GitHub Discussions (Optional)

Go to: **Settings → Features → ✅ Discussions**

Enable Discussions to create a community hub. Categories to create:
- **Q&A** — How to use TrustLens
- **Ideas** — Feature requests
- **Show & Tell** — Share your scans/use cases

> Discussions are indexed by Google and increase your repo's organic traffic.

---

## 9. Issue Templates

Create `.github/ISSUE_TEMPLATE/` with templates:

**Already referenced in CONTRIBUTING.md** — now create the actual templates so the "New Issue" button shows structured forms.

---

## 10. GitHub Actions Badge (README boost)

If you add CI later, add a build status badge to README:
```markdown
![Build](https://github.com/abhishekayu/TrustLens/actions/workflows/ci.yml/badge.svg)
````

---

## Quick Action Summary

| Priority  | Action                      | Where                    | Time   |
| --------- | --------------------------- | ------------------------ | ------ |
| 🔴 **#1** | Set repo description        | About ⚙️                 | 1 min  |
| 🔴 **#2** | Add 20 topics               | About ⚙️                 | 2 min  |
| 🔴 **#3** | Create v0.1.0 release       | Releases tab             | 5 min  |
| 🟡 **#4** | Upload social preview image | Settings → General       | 3 min  |
| 🟡 **#5** | Set website URL             | About ⚙️                 | 1 min  |
| 🟡 **#6** | Pin to profile              | Profile → Customize pins | 1 min  |
| 🟢 **#7** | Enable Discussions          | Settings → Features      | 1 min  |
| 🟢 **#8** | Create issue templates      | .github/ folder          | 10 min |

**Total time: ~25 minutes for massive SEO improvement.**
