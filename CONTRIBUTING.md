# Contributing to TrustLens AI

Thank you for your interest in contributing to TrustLens AI! This document provides guidelines and information to make the contribution process smooth and effective.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How to Contribute](#how-to-contribute)
3. [Development Setup](#development-setup)
4. [Project Architecture](#project-architecture)
5. [Coding Standards](#coding-standards)
6. [Testing](#testing)
7. [Pull Request Process](#pull-request-process)
8. [Issue Guidelines](#issue-guidelines)
9. [Security Vulnerabilities](#security-vulnerabilities)
10. [Recognition](#recognition)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code. Report unacceptable behavior to the maintainers.

**Core values:**

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Prioritize the community's best interests

---

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. Use the **Bug Report** template
3. Include:
   - Python version and OS
   - Steps to reproduce
   - Expected vs. actual behavior
   - Error logs (redact sensitive URLs)

### Suggesting Features

1. Open an issue with the **Feature Request** template
2. Explain the use case and why it benefits the project
3. If possible, outline a proposed implementation approach

### Contributing Code

1. **Fork** the repository
2. **Clone** your fork locally
3. Create a **feature branch** from `main`
4. **Implement** your changes
5. **Test** thoroughly
6. Submit a **Pull Request**

### Contributing Documentation

Documentation improvements are always welcome! This includes:

- Fixing typos or unclear explanations
- Adding examples
- Improving the docs/ folder content
- Translating documentation

---

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm 9+
- Git
- An LLM API key (Gemini, OpenAI, Anthropic, or Grok)

### Quickest Way (Recommended)

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/TrustLens.git
cd TrustLens

# One command — installs everything, runs setup wizard, starts both servers
chmod +x start.sh
./start.sh
```

The `start.sh` script handles virtual env detection, dependency installation, LLM provider setup wizard, and launches both backend (port 3010) and frontend (port 5173).

### Manual Setup

#### Backend

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/TrustLens.git
cd TrustLens

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
python3 -m playwright install chromium

# Copy environment config & configure your LLM provider
cp .env.example .env
# Edit .env → set TRUSTLENS_AI_PROVIDER and your API key
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

#### Running the Full Stack (Manual)

```bash
# Terminal 1: Backend (PYTHONPATH=src is required)
PYTHONPATH=src python3 -m uvicorn trustlens.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Frontend
cd frontend && npm run dev
```

> **Note:** When using `./start.sh`, the backend runs on port **3010**. When starting manually, you can choose any port (default example uses **8000**).

---

## Project Architecture

Understanding the architecture helps you contribute effectively:

```
src/trustlens/
├── core/           # Settings, logging (pydantic-settings, structlog)
├── models/         # Domain models (Pydantic v2 BaseModel)
├── schemas/        # API request/response schemas
├── db/             # Database layer (aiosqlite, repository pattern)
├── security/       # SSRF protection, URL validation
├── observability/  # Audit logging, metrics, activity monitoring
├── api/
│   ├── middleware/  # Rate limiting, auth, domain filtering
│   ├── routes/      # FastAPI route handlers
│   └── deps.py      # Dependency injection
└── services/
    ├── orchestrator.py   # Main pipeline coordinator
    ├── scoring/          # 70/30 hybrid scoring engine
    ├── ai/               # AI provider abstraction
    ├── analysis/         # Analysis modules (rules, brand, etc.)
    ├── community/        # Community reporting
    ├── threat_intel/     # Threat feed ingestion
    └── enterprise/       # Brand monitoring
```

### Key Design Principles

- **Repository pattern** for database access (easy to swap backends)
- **Dependency injection** via FastAPI deps and module-level singletons
- **Plugin architecture** for AI providers (`@register_provider`)
- **Async throughout** — all I/O operations are async
- **Pydantic v2** for all data validation

---

## Coding Standards

### Python

- **Style:** Follow [PEP 8](https://pep8.org/)
- **Type hints:** Required for all function signatures
- **Docstrings:** Google style for public functions and classes
- **Async:** Use `async def` for all I/O-bound functions
- **Line length:** 100 characters max
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes
- **Pydantic v2:** Use `BaseModel` for all data structures

```bash
# Verify imports work
PYTHONPATH=src python3 -c "from trustlens.main import app; print('OK')"

# Run the backend to check for errors
PYTHONPATH=src python3 -m uvicorn trustlens.main:app --host 0.0.0.0 --port 8000
```

### TypeScript/React (Frontend)

- **Framework:** React 19 with TypeScript 5.9
- **Styling:** Tailwind CSS v4 (terminal/hacker theme — green `#00ff41`, cyan `#00ffff`)
- **Icons:** Lucide React
- **Components:** Functional components with hooks
- **State:** React hooks (`useState`, `useEffect`, `useCallback`)
- **Routing:** React Router v7

```bash
cd frontend
npm run build    # Type-check + build
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add certificate transparency monitoring
fix: correct scoring weight normalization
docs: update API reference for community endpoints
refactor: extract brand matching logic into separate module
test: add unit tests for zero-day scorer
chore: update dependencies
```

---

## Testing

### Running Tests

```bash
# All tests
PYTHONPATH=src pytest

# With coverage
PYTHONPATH=src pytest --cov=trustlens --cov-report=html

# Specific module
PYTHONPATH=src pytest tests/test_scoring.py

# Verbose
PYTHONPATH=src pytest -v
```

### Writing Tests

- Place tests in `tests/` mirroring the source structure
- Use `pytest` fixtures for common setup
- Mock external services (AI providers, HTTP calls)
- Test edge cases, especially for security-critical code

```python
# Example test structure
import pytest
from trustlens.services.scoring import ScoringEngine

@pytest.fixture
def scoring_engine():
    return ScoringEngine()

def test_safe_score_range(scoring_engine):
    """Scores above 75 should be categorized as Safe."""
    result = scoring_engine.score(...)
    assert result.risk_category == "Safe"
    assert result.trust_score >= 75
```

### Test Categories

| Category          | Description                          | Required for PR?           |
| ----------------- | ------------------------------------ | -------------------------- |
| Unit tests        | Individual function/method tests     | Yes                        |
| Integration tests | Cross-module interaction tests       | Recommended                |
| Security tests    | SSRF, injection, auth bypass         | Required for security code |
| API tests         | Endpoint request/response validation | Required for route changes |

---

## Pull Request Process

### Before Submitting

1. **Rebase** on the latest `main` branch
2. **Run all tests** and ensure they pass
3. **Run linters** with zero warnings
4. **Update documentation** if behavior changes
5. **Add tests** for new functionality

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

Describe tests added or modified.

## Checklist

- [ ] Tests pass locally
- [ ] Linters pass with no warnings
- [ ] Documentation updated
- [ ] No security regressions
```

### Review Process

1. All PRs require at least **one approving review**
2. CI must pass (tests, linting, type checking)
3. Security-sensitive changes require **two reviews**
4. Maintainers may request changes before merging

### What Makes a Good PR

- **Small and focused** — one logical change per PR
- **Well-tested** — new code has corresponding tests
- **Documented** — public APIs have docstrings
- **Clean history** — squash fixup commits before merging

---

## Issue Guidelines

### Good Issue Title Examples

- `fix: ScoringEngine crashes when AI provider returns empty response`
- `feat: Add support for custom threat feed CSV formats`
- `docs: Missing API authentication examples`

### Bug Report Template

```markdown
**Describe the bug**
A clear description of the issue.

**To Reproduce**

1. Start TrustLens with config: ...
2. Send request: ...
3. Observe error: ...

**Expected behavior**
What should happen instead.

**Environment**

- OS: [e.g. macOS 15, Ubuntu 24.04]
- Python: [e.g. 3.11, 3.12]
- Node.js: [e.g. 20, 22]
- AI Provider: [e.g. Gemini (gemini-2.5-flash)]

**Logs**
```

Paste relevant log output here

```

```

---

## Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Instead, please report security issues privately:

1. Contact the maintainer via GitHub ([@abhishekayu](https://github.com/abhishekayu))
2. Include a detailed description and reproduction steps
3. Allow reasonable time for a fix before public disclosure

We follow responsible disclosure practices and will credit reporters in our security advisories.

---

## Recognition

All contributors are recognized in our releases. Significant contributions may be highlighted in the README.

### Contribution Areas

| Area                | Skills Needed                         | Impact |
| ------------------- | ------------------------------------- | ------ |
| Area                | Skills Needed                         | Impact |
| ------------------- | ------------------------------------- | ------ |
| Analysis engines    | Python, async, security               | High   |
| AI providers        | LLM APIs, prompt engineering          | High   |
| Frontend            | React 19, TypeScript, Tailwind CSS v4 | Medium |
| Documentation       | Technical writing                     | Medium |
| Testing             | Python, pytest                        | Medium |
| DevOps              | Docker, CI/CD, shell scripting        | Medium |
| Security research   | Phishing, malware, threat intel       | High   |
| Browser extension   | WebExtension APIs, JS                 | High   |

---

## Questions?

- Open a [Discussion](https://github.com/abhishekayu/TrustLens/discussions) for general questions
- Check existing issues and PRs for context
- Read the [documentation](docs/) for technical details

Thank you for helping make the internet safer!
