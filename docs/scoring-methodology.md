# TrustLens AI — Scoring Methodology Whitepaper

> **Version 0.2** | Last updated: March 2026

---

## Abstract

This document describes the scoring methodology used by TrustLens AI to produce URL trust scores. The system uses a **70/30 hybrid model** combining deterministic rule-based analysis (70%) with AI advisory signals (30%), augmented by supplementary evidence signals. Every score produced includes a complete evidence trail enabling independent human verification.

---

## 1. Design Philosophy

### 1.1 Why Hybrid Scoring?

Pure AI-based scoring systems suffer from three critical problems:

1. **Hallucination** — LLMs generate confident assertions without factual basis
2. **Opacity** — Neural network decisions cannot be traced to specific evidence
3. **Adversarial fragility** — Prompt injection can manipulate AI verdicts

Pure rule-based systems have different weaknesses:

1. **Rigidity** — Cannot detect novel attack patterns
2. **Blind spots** — Cannot understand semantic deception (e.g., urgency manipulation)
3. **Maintenance burden** — Rules must be manually updated for new attack vectors

The 70/30 hybrid combines the reliability of rules with the pattern recognition of AI, while ensuring AI can never unilaterally determine a trust score.

### 1.2 Core Invariant

```
AI influence ≤ 30% of final score. Always. No exceptions.
```

This invariant is enforced at the code level, not by convention. The scoring engine mathematically caps AI contribution regardless of the AI's confidence output.

---

## 2. Scoring Pipeline

### 2.1 Overview

```
URL Input
    │
    ├──▶ Phase 1: Crawl & Data Collection
    │       Playwright sandbox → HTML, headers, redirects, screenshot
    │
    ├──▶ Phase 2: Parallel Analysis (5 sub-analyzers)
    │       ├── Heuristic Rules Engine
    │       ├── Brand Impersonation Checker
    │       ├── Behavioral Redirect Analyzer
    │       ├── Domain Intelligence (RDAP/DNS)
    │       └── Security Header Auditor
    │
    ├──▶ Phase 3: AI Classification
    │       Anti-injection prompt fence → LLM → Confidence calibration
    │
    ├──▶ Phase 4: Supplementary Signals
    │       ├── Screenshot Similarity (perceptual hashing)
    │       ├── Zero-Day Suspicion Scoring
    │       ├── Threat Intelligence Feed Lookup
    │       └── Community Consensus
    │
    └──▶ Phase 5: Score Computation
            70/30 merge → supplementary adjustments → final score + evidence
```

### 2.2 Phase Timing

All Phase 2 analyzers execute **in parallel** using Python asyncio. Phase 3 (AI) runs concurrently with Phase 2. Phase 4 signals are computed after Phase 2 completes (they depend on analysis results). Phase 5 aggregates all signals synchronously.

---

## 3. Rule-Based Scoring (70%)

### 3.1 Sub-Component Weights

The rule-based score is itself a weighted combination of five sub-analyzers:

| Sub-Analyzer        | Weight | Score Range | Normalization        |
| ------------------- | ------ | ----------- | -------------------- |
| Heuristic Rules     | 0.30   | 0–100       | Direct               |
| Brand Impersonation | 0.25   | 0–100       | Inverted probability |
| Behavioral Analysis | 0.20   | 0–100       | Direct               |
| Domain Intelligence | 0.15   | 0–100       | Direct               |
| Security Headers    | 0.10   | 0–100       | Direct               |

```
rule_score = (heuristic × 0.30) + (brand × 0.25) + (behavioral × 0.20)
           + (domain × 0.15) + (headers × 0.10)
```

### 3.2 Heuristic Rules Engine (30%)

The rule engine evaluates 6 signal categories:

| Signal            | What It Checks                                           | Penalty Range |
| ----------------- | -------------------------------------------------------- | ------------- |
| SSL/TLS           | Valid certificate, issuer, expiration                    | 0–25 pts      |
| Suspicious Forms  | Login forms on non-HTTPS, action mismatches              | 0–20 pts      |
| URL Patterns      | Excessive subdomains, IP URLs, suspicious keywords       | 0–20 pts      |
| Page Content      | Urgency language, brand mentions without matching domain | 0–15 pts      |
| Redirect Behavior | Chain length, cross-domain ratio                         | 0–10 pts      |
| Security Headers  | Presence of HSTS, CSP, etc.                              | 0–10 pts      |

Each signal produces a deduction from a base score of 100. The engine returns a named list of triggered rules with evidence strings.

### 3.3 Brand Impersonation (25%)

Brand impersonation scoring uses three techniques:

1. **Levenshtein Distance** — Character-level edit distance between the scanned domain and 20+ known brand domains
2. **Normalized Similarity** — `1 - (edit_distance / max_length)`, threshold at 0.80
3. **Typosquatting Detection** — Strips non-alphanumeric characters and compares; catches `g00gle.com` → `google.com`

The impersonation score is: `max(levenshtein_similarity, typosquat_similarity)`

A similarity ≥ 0.80 without the domain being an actual brand domain triggers a **high confidence** impersonation signal.

### 3.4 Behavioral Analysis (20%)

Evaluates runtime page behavior:

| Signal                  | Evidence                                         | Severity |
| ----------------------- | ------------------------------------------------ | -------- |
| Redirect chain > 3 hops | Full redirect path                               | Medium   |
| Cross-domain redirects  | Source → destination domains                     | High     |
| Hidden iframes          | iframe src, dimensions                           | High     |
| JavaScript evasion      | Obfuscation patterns detected                    | Medium   |
| Timing anomalies        | Page load > 10s (stalling for detection evasion) | Low      |

### 3.5 Domain Intelligence (15%)

| Signal                  | Threshold                                | Scoring Impact      |
| ----------------------- | ---------------------------------------- | ------------------- |
| Domain age < 7 days     | Registration date from RDAP              | -20 pts             |
| Domain age < 30 days    | Registration date from RDAP              | -10 pts             |
| Suspicious TLD          | `.tk`, `.ml`, `.ga`, `.cf`, `.xyz`, etc. | -15 pts             |
| No MX records           | DNS lookup                               | -5 pts              |
| Privacy-protected WHOIS | RDAP registrant masked                   | -5 pts (low signal) |

### 3.6 Security Headers (10%)

Six headers are checked with individual weights:

| Header                    | Weight | Full Score If                     |
| ------------------------- | ------ | --------------------------------- |
| Strict-Transport-Security | 25%    | Present with `max-age` ≥ 31536000 |
| Content-Security-Policy   | 25%    | Present with meaningful policy    |
| X-Frame-Options           | 15%    | `DENY` or `SAMEORIGIN`            |
| X-Content-Type-Options    | 15%    | `nosniff`                         |
| Referrer-Policy           | 10%    | Any restrictive value             |
| Permissions-Policy        | 10%    | Present                           |

---

## 4. AI Advisory Score (30%)

### 4.1 Prompt Architecture

The AI receives a structured prompt containing:

1. **System prompt** with anti-injection fence (see [Anti-Hallucination Strategy](anti-hallucination.md))
2. **User prompt** with sanitized page content, URL structure, and metadata
3. **Output schema** requiring specific JSON fields

The AI produces:

```json
{
  "impersonation": 0.0-1.0,
  "credential_harvesting": 0.0-1.0,
  "urgency_manipulation": 0.0-1.0,
  "fear_tactics": 0.0-1.0,
  "payment_demand": 0.0-1.0,
  "deception_confidence": 0.0-1.0,
  "reasoning": "Free-text explanation"
}
```

### 4.2 Confidence Calibration

Raw AI confidence is **never used directly**. It passes through a calibration pipeline:

1. **Hard ceiling at 0.95** — No AI output can claim 100% confidence
2. **Sigmoid squashing** — Compresses mid-range values toward center, reducing variance
3. **Evidence anchoring** — AI confidence is weighted by the number of rule signals that corroborate it
4. **Agreement penalty** — If AI confidence direction contradicts rule-based signals, AI weight is reduced further

```python
calibrated = min(raw_confidence, 0.95)                    # Step 1
calibrated = sigmoid_squash(calibrated, center=0.5)       # Step 2
calibrated = calibrated * evidence_anchor_factor           # Step 3
if contradicts_rules:
    calibrated *= 0.5                                      # Step 4
```

### 4.3 AI Score Integration

```
ai_score = (1.0 - calibrated_deception_confidence) × 100
final_ai_contribution = ai_score × 0.30
```

High deception confidence maps to a low AI score. The AI contribution is always ≤ 30 points of the final 100-point scale.

---

## 5. Supplementary Signal Adjustments

After the core 70/30 calculation, supplementary signals apply bounded adjustments:

### 5.1 Screenshot Visual Clone (max -15 pts)

Uses perceptual hashing (pHash/dHash) to compare the page screenshot against a database of known brand login pages.

```
if similarity_score ≥ 0.85:
    penalty = similarity_score × 15
    final_score -= penalty
```

This is a **hard evidence** signal — visual similarity at the pixel level is extremely difficult to fake accidentally.

### 5.2 Zero-Day Suspicion (max -10 pts)

A 4-axis anomaly detector checks for threat patterns not yet in any database:

- **Language anomalies** (invisible Unicode, homoglyphs, mixed scripts)
- **Structural anomalies** (eval chains, base64 inline, hex encoding)
- **Behavioral anomalies** (redirect chains, timing, cross-domain)
- **Domain novelty** (new domain + brand similarity + rule violations)

```
if suspicion_score ≥ 50:
    penalty = (suspicion_score / 100) × 10
    final_score -= penalty
```

### 5.3 Threat Intelligence Match (max -30 pts)

Queries local cache of URLhaus, PhishTank, OpenPhish, and custom feeds.

```
if is_known_threat:
    penalty = highest_confidence × 30
    final_score -= penalty
```

This is the strongest supplementary signal because it represents **confirmed threats** from established intelligence sources.

### 5.4 Community Consensus (max ±5 pts)

Aggregates community reports with trust-weighted voting.

```
if consensus_confidence ≥ 0.5:
    # crowd_risk_score: 0 = universally safe, 100 = universally dangerous
    adjustment = ((crowd_risk_score - 50) / 50) × 5 × consensus_confidence
    final_score -= adjustment
```

Community signals are intentionally low-weight to prevent gaming.

---

## 6. Final Score Computation

```
core_score = (rule_score × 0.70) + (ai_score × 0.30)

supplementary = screenshot_penalty + zeroday_penalty
              + threat_intel_penalty + community_adjustment

final_score = clamp(core_score + supplementary, 0, 100)

risk_category = categorize(final_score)
```

### 6.1 Score Clamping

The final score is always clamped to [0, 100]. Supplementary signals can push it below 0 (clamped to 0) but never above 100.

### 6.2 Risk Category Mapping

| Score Range | Category   | Color  | Action             |
| ----------- | ---------- | ------ | ------------------ |
| 75–100      | Safe       | Green  | No action needed   |
| 50–74       | Low Risk   | Yellow | Review recommended |
| 25–49       | Suspicious | Orange | Exercise caution   |
| 0–24        | High Risk  | Red    | Do not proceed     |

---

## 7. Evidence Trail

Every analysis produces a transparency report containing:

1. **Individual signal scores** with evidence strings
2. **Rule-by-rule breakdown** showing which rules triggered and why
3. **AI reasoning** (the raw text output from the model)
4. **Supplementary signal details** (which feeds matched, screenshot similarity %, etc.)
5. **Weight breakdown** showing exactly how the final score was computed
6. **Methodology citation** (links back to this document)

This ensures **complete auditability** — any security researcher can independently verify why a particular score was assigned.

---

## 8. Limitations and Known Biases

### 8.1 New Domain Bias

Newly registered domains receive a penalty even if legitimate. This is a deliberate design choice — the vast majority of domains used in phishing are less than 30 days old. False positives on new legitimate domains are acceptable because the evidence trail clearly explains the reason.

### 8.2 AI Provider Variance

Different AI providers (Gemini/OpenAI/Anthropic/Grok) may produce slightly different confidence values. The calibration pipeline reduces this variance, but scores may differ by ±3% between providers.

### 8.3 Screenshot Database Coverage

Visual clone detection is limited by the number of brand screenshots in the database. New brands must be manually added.

### 8.4 Community Signal Cold Start

Community consensus requires a minimum number of reports to produce meaningful signals. For URLs with zero reports, this signal is effectively neutral.

---

## 9. Future Improvements

1. **Adaptive weights** — Machine learning to optimize sub-component weights based on confirmed phishing datasets
2. **Temporal decay** — Reduce the impact of old community reports
3. **Cross-instance learning** — Federated scoring intelligence across TrustLens deployments
4. **F1 score optimization** — Tune thresholds against labeled datasets to minimize false positives/negatives

---

## References

- Hamming, R.W. (1950). "Error Detecting and Error Correcting Codes." Bell System Technical Journal.
- Levenshtein, V.I. (1966). "Binary codes capable of correcting deletions, insertions, and reversals."
- APWG (2025). "Phishing Activity Trends Report." Anti-Phishing Working Group.
- Zauner, C. (2010). "Implementation and Benchmarking of Perceptual Image Hash Functions." University of Applied Sciences, Hagenberg.
