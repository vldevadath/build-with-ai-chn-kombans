# 🛡️ AI-Powered Bug Bounty Scanner

> **Team Kombans** — Build with AI CHN Hackathon 2026

An automated, AI-driven web application vulnerability scanner that **thinks like a hacker**. Give it a URL — it crawls, classifies, attacks, and reports vulnerabilities in real-time with zero manual effort.

---

## 🎯 Problem Statement

**Cybersecurity — AI-Powered Threat Detection & Prevention**

Security testing is manual, slow, and expensive. Traditional automated scanners are pattern-matching tools that throw massive wordlists at websites without understanding context. They produce overwhelming false positives and miss nuanced vulnerabilities that require contextual reasoning.

**Our solution:** A scanner that uses **LLM intelligence** to understand each endpoint — what parameters exist, what they do, what vulnerability is most likely — then generates **targeted payloads**, sends them, and uses AI again to **confirm** if the vulnerability is real. Not a guess. Actual proof.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🕷️ **Smart Crawling** | Automatically discovers endpoints, forms, query parameters, and hidden paths via robots.txt & sitemap.xml |
| 🎯 **DVWA Auto-Detection** | Detects DVWA targets, auto-logins with CSRF token handling, sets security level, and disables PHPIDS |
| 🧠 **AI Classification** | Uses Gemini Flash / Groq LLaMA to classify vulnerability types per endpoint based on context |
| ⚔️ **Automated Attack** | AI-generated targeted payloads for SQLi, XSS, CMDi, LFI, SSRF, IDOR, CSRF, File Upload, Open Redirect |
| 🔍 **Pattern + AI Analysis** | Local pattern matching for fast detection with AI fallback for edge cases — minimizes false positives |
| 📡 **Real-Time Dashboard** | Live log streaming, findings panel, and report viewer via WebSocket |
| 📄 **Auto Reports** | Generates professional Markdown bug bounty reports with curl reproduction steps |
| 🛡️ **WAF Detection** | Fingerprints target tech stack and detects WAFs (Cloudflare, Akamai, ModSecurity, etc.) |
| 🔄 **Encoding Bypass** | URL double-encoding, SQL comment bypass, case variation, and whitespace bypass for WAF evasion |
| 🤖 **Multi-AI Fallback** | Automatic provider fallback: Gemini → Groq → OpenRouter with rate-limit retry |

---

## 🔎 Vulnerability Types Detected

| Type | Severity | Detection Method |
|------|----------|-----------------|
| SQL Injection (SQLi) | 🔴 Critical | AI payload generation + response analysis |
| Blind SQL Injection | 🔴 Critical | Time-based delay detection |
| Command Injection (CMDi) | 🔴 Critical | OS command output pattern matching |
| Local File Inclusion (LFI) | 🟠 High | Path traversal + file content detection |
| Server-Side Request Forgery (SSRF) | 🟠 High | Internal IP/metadata response analysis |
| Insecure Direct Object Reference (IDOR) | 🟠 High | Response differential analysis |
| File Upload | 🟠 High | Extension/content-type bypass testing |
| Cross-Site Scripting (XSS) | 🟡 Medium | Reflected payload detection in response |
| Header Injection | 🟡 Medium | CRLF injection testing |
| Cross-Site Request Forgery (CSRF) | 🟡 Medium | Token absence detection |
| Open Redirect | 🔵 Low | Redirect location analysis |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Browser Dashboard                         │
│              (Vanilla HTML/CSS/JS + WebSocket)               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│    ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐│
│    │ STAGE 0  │──▶│ STAGE 1  │──▶│ STAGE 2  │──▶│STAGE 3 ││
│    │Fingerprint│  │  Crawl   │   │ Classify │   │ Attack  ││
│    │& WAF Det │   │Endpoints │   │  (AI)    │   │& Verify ││
│    └──────────┘   └──────────┘   └──────────┘   └────┬────┘│
│                                                      │      │
│                                              ┌───────▼─────┐│
│                                              │  STAGE 4    ││
│                                              │  Report     ││
│                                              │ Generation  ││
│                                              └─────────────┘│
│                                                             │
│              Flask + Flask-SocketIO (Python)                 │
│              AI: Gemini Flash / Groq / OpenRouter            │
└─────────────────────────────────────────────────────────────┘
```

### How Each Stage Works

1. **Fingerprint** — Detects server technology, language, framework, and WAF presence
2. **Crawl** — Visits pages, follows links, parses forms with BeautifulSoup, discovers robots.txt & sitemap.xml paths
3. **Classify** — Sends endpoint metadata to the LLM to predict vulnerability types based on parameter names, HTTP methods, and URL context
4. **Attack** — AI generates smart payloads (e.g., `' OR '1'='1` for `id` param), sends baseline + attack requests, AI analyzes response differential to confirm exploitation
5. **Report** — Generates professional Markdown reports with severity, evidence, reproduction steps, and remediation advice

---

## 🛠️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| **Python 3** | Core backend language |
| **Flask** | Lightweight web server and REST API |
| **Flask-SocketIO** | Real-time WebSocket communication for live log streaming |
| **Requests** | HTTP client for sending baseline and attack payloads |
| **BeautifulSoup4** | HTML parsing for crawling forms, links, and input fields |
| **Google GenAI (Gemini 2.0 Flash)** | Primary AI brain — classifies, generates payloads, analyzes responses |
| **Groq (LLaMA 3.3 70B)** | Fallback AI provider with high rate limits |
| **OpenRouter** | Secondary fallback with free model rotation |
| **Vanilla HTML/CSS/JS** | Frontend dashboard — dark-mode glassmorphism design, no build step |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- A Gemini or Groq API key (free tier works)

### Setup

```bash
# Clone the repo
git clone https://github.com/vldevadath/build-with-ai-chn-kombans.git
cd build-with-ai-chn-kombans

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your API key(s)
```

### Run

```bash
python app.py
```

Open **http://127.0.0.1:7331** in your browser.

### Testing with DVWA (Recommended Demo Target)

```bash
# Start DVWA in Docker
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# In the scanner, enter: http://127.0.0.1/
# The scanner auto-detects DVWA, logs in, and begins scanning
```

---

## 📸 Dashboard

The real-time dashboard features:
- **Live Log Panel** — Watch the scanner crawl, classify, and attack in real-time
- **Findings Panel** — Severity-tagged vulnerability cards appear as they're discovered
- **Report Viewer** — Click any finding to view the full professional bug bounty report
- **Stage Pipeline** — Visual indicator showing current scan progress
- **Stats Bar** — Live counters for Critical/High/Medium/Low findings

---

## 🔧 Configuration

### Environment Variables (`.env`)

```env
GEMINI_API_KEY=your_gemini_api_key_here    # Primary AI (1500 req/day free)
GROQ_API_KEY=your_groq_api_key_here        # Fallback AI (14400 req/day free)
FLASK_PORT=7331                             # Server port
```

### Scanner Options (via Dashboard)

| Option | Description |
|--------|-------------|
| **Target URL** | The web application URL to scan |
| **Cookies** | Optional session cookies for authenticated scanning |
| **Username / Password** | Auto-login credentials for generic sites |
| **AI-Assisted Mode** | Toggle AI classification and analysis |
| **Aggressive Mode** | Enable encoding bypass and extended payloads |

---

## 📁 Project Structure

```
├── app.py              # Single-file backend (Flask + all scan logic)
├── static/
│   └── index.html      # Full frontend (HTML + CSS + JS in one file)
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
├── .gitignore          # Git ignore rules
├── findings.json       # Runtime: discovered vulnerabilities
└── reports/            # Runtime: generated Markdown reports
```

---

## 🛡️ Safety & Ethics

This tool is designed for **authorized security testing only**.

- **Scope-locked** — Only scans the URL entered by the user
- **Local-only** — Flask binds to `127.0.0.1`, not exposed to the network
- **Rate-limited** — Sequential exploit execution, no parallel attacks
- **Non-destructive** — Read-only payloads; no data modification or persistent access
- **Educational** — Built for hackathon demonstration against intentionally vulnerable apps (DVWA)

> ⚠️ **Disclaimer:** Only use this tool on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

## 👥 Team

**Team Kombans** — Codeerum Hackathon 2026

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.
