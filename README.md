# 🎯 AI-Powered Bug Bounty Scanner

An automated, AI-driven web application vulnerability scanner with a real-time dashboard. Built for the Codeerum Hackathon.

## Features

- **Smart Crawling** — Automatically discovers endpoints, forms, and query parameters on any website
- **DVWA Auto-Detection** — Detects DVWA targets and auto-logins with CSRF token handling
- **AI Classification** — Uses Groq (LLaMA 3.3) or Gemini to classify vulnerability types per endpoint
- **Automated Attack** — Tests for SQLi, XSS, CMDi, LFI, SSRF, IDOR, CSRF, File Upload, and Open Redirect
- **Pattern + AI Analysis** — Local pattern matching for fast detection, with AI fallback for edge cases
- **Real-Time Dashboard** — Live log streaming, findings panel, and report viewer via WebSocket
- **Auto Reports** — Generates professional Markdown bug bounty reports with curl reproduce steps

## Vulnerability Types Detected

| Type | Severity |
|------|----------|
| SQL Injection (SQLi) | Critical |
| Command Injection (CMDi) | Critical |
| Local File Inclusion (LFI) | High |
| Server-Side Request Forgery (SSRF) | High |
| Insecure Direct Object Reference (IDOR) | High |
| File Upload | High |
| Cross-Site Scripting (XSS) | Medium |
| Cross-Site Request Forgery (CSRF) | Medium |
| Open Redirect | Low |

## Quick Start

### Prerequisites
- Python 3.8+
- A Groq or Gemini API key

### Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/bug-bounty-scanner.git
cd bug-bounty-scanner

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your API keys

# Run
python app.py
```

Open `http://127.0.0.1:7331` in your browser.

### Testing with DVWA

```bash
# Start DVWA in Docker
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# Enter http://127.0.0.1/ in the scanner — it auto-detects DVWA and logs in
```

## Architecture

```
Browser (index.html)
    │  WebSocket (live logs + findings)
    │  REST (start scan, get findings, get reports)
    ▼
app.py (Flask + Flask-SocketIO)
    │
    ├── Stage 1: Crawl — discover endpoints, forms, query params
    ├── Stage 2: Classify — AI + heuristics to assign vuln types
    ├── Stage 3: Attack — generate payloads, test, analyze responses
    └── Stage 4: Report — generate Markdown bug bounty reports
```

## Tech Stack

- **Backend**: Python, Flask, Flask-SocketIO
- **AI**: Groq (LLaMA 3.3 70B) / Google Gemini 2.0 Flash
- **Frontend**: Vanilla HTML/CSS/JS, WebSocket
- **Parsing**: BeautifulSoup4

## Team

**Codeerum Kombans** — Built at Codeerum Hackathon 2026

## License

MIT
