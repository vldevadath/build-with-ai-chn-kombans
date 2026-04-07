"""
AI-Powered Bug Bounty Scanner — Production Edition v2
Supports: DVWA + Real-world web applications
Features: Smart crawling, AI classification, automated attack, real-time dashboard,
          triage verification, safe AI payloads, tech fingerprinting, WAF detection,
          time-based blind detection, encoding bypass, header injection, multi-param testing
"""

import os
import json
import time
import hashlib
import threading
import random
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO
import requests as http_req
from bs4 import BeautifulSoup
import urllib3

# Try importing genai for Gemini
try:
    from google import genai
except ImportError:
    genai = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── App ─────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'bugbounty-scanner-2026')
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

Path('reports').mkdir(exist_ok=True)
if not Path('findings.json').exists():
    Path('findings.json').write_text('[]')

# ─── AI Provider Setup ──────────────────────────────────────────────────────

OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', '')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

gemini_client = None
if GEMINI_API_KEY and genai:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception:
        pass

# Priority: Gemini > Groq > OpenRouter (Gemini has most generous free tier: 1500 req/day)
if gemini_client:
    AI_PROVIDER = 'gemini'
elif GROQ_API_KEY:
    AI_PROVIDER = 'groq'
elif OPENROUTER_API_KEY:
    AI_PROVIDER = 'openrouter'
else:
    AI_PROVIDER = 'none'
print(f"  🤖 AI Provider (primary): {AI_PROVIDER.upper()}")

# ─── Global State ────────────────────────────────────────────────────────────

scan_active = False
scan_cancel = threading.Event()   # Signal to cancel scan
findings_lock = threading.Lock()
ai_call_lock = threading.Lock()

# ─── User-Agent Pool ─────────────────────────────────────────────────────────

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def log(level, text):
    socketio.emit('log', {'level': level, 'text': str(text), 'ts': time.time()})
    print(f"[{level.upper():6s}] {text}")

def emit_progress(current, total, stage=''):
    pct = round((current / max(total, 1)) * 100)
    socketio.emit('progress', {'current': current, 'total': total, 'pct': pct, 'stage': stage})

def fp(method, url, param, vuln):
    return hashlib.sha256(f"{method}:{url}:{param}:{vuln}".lower().encode()).hexdigest()[:8]

def read_findings():
    with findings_lock:
        try:
            return json.loads(Path('findings.json').read_text())
        except Exception:
            return []

def write_finding(finding):
    with findings_lock:
        try:
            findings = json.loads(Path('findings.json').read_text())
        except Exception:
            findings = []
        if any(f['id'] == finding['id'] for f in findings):
            return False
        findings.append(finding)
        Path('findings.json').write_text(json.dumps(findings, indent=2))
        return True

def is_cancelled():
    return scan_cancel.is_set()

def ai_call(prompt, temp=0.3):
    """Call AI — one request at a time, with automatic provider fallback and retry."""
    with ai_call_lock:
        result = _do_ai_call(prompt, temp)
        time.sleep(0.8)
        return result

def _do_ai_call(prompt, temp=0.3):
    """Try providers in order with automatic fallback on failure/rate-limit."""
    providers = []
    # Order: Gemini first (1500/day free), then Groq (14400/day), then OpenRouter (50/day per model)
    if gemini_client:
        providers.append(('gemini', _gemini_call))
    if GROQ_API_KEY:
        providers.append(('groq', _groq_call))
    if OPENROUTER_API_KEY:
        providers.append(('openrouter', _openrouter_call))

    if not providers:
        raise Exception("No AI provider configured (set OPENROUTER_API_KEY, GROQ_API_KEY, or GEMINI_API_KEY)")

    last_error = None
    for name, call_fn in providers:
        # Try up to 2 attempts per provider (with backoff for temporary rate limits)
        for attempt in range(2):
            try:
                return call_fn(prompt, temp)
            except Exception as e:
                last_error = e
                error_str = str(e).lower()
                is_rate_limit = '429' in error_str or 'rate limit' in error_str or 'quota' in error_str or 'resource_exhausted' in error_str
                if is_rate_limit and attempt == 0:
                    # Brief wait and retry once
                    wait_time = 3
                    log('warn', f'  ⚡ {name.upper()} rate-limited — retrying in {wait_time}s...')
                    time.sleep(wait_time)
                    continue
                elif is_rate_limit:
                    log('warn', f'  ⚡ {name.upper()} rate-limited — falling back to next provider')
                else:
                    log('warn', f'  ⚡ {name.upper()} error: {str(e)[:100]} — trying next provider')
                break  # Move to next provider
    raise last_error

# ─── OpenRouter Model Rotation ─────────────────────────────────────────────
# Each free model has its own 50/day quota — rotating multiplies total capacity

OPENROUTER_FREE_MODELS = [
    'meta-llama/llama-3.3-70b-instruct:free',
    'arcee-ai/trinity-large-preview:free',
    'arcee-ai/trinity-mini:free',
    'google/gemma-3-27b-it:free',
    'openrouter/free',  # Auto-routes to any available free model
]
_openrouter_model_index = 0
_openrouter_model_lock = threading.Lock()

def _get_next_openrouter_model():
    global _openrouter_model_index
    with _openrouter_model_lock:
        model = OPENROUTER_FREE_MODELS[_openrouter_model_index % len(OPENROUTER_FREE_MODELS)]
        _openrouter_model_index += 1
        return model

def _openrouter_call(prompt, temp=0.3):
    model = _get_next_openrouter_model()
    resp = http_req.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {OPENROUTER_API_KEY}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'http://localhost:7331',
            'X-Title': 'Bug Bounty Scanner'
        },
        json={
            'model': model,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': temp,
            'max_tokens': 1024
        },
        timeout=60
    )
    if resp.status_code == 429:
        # Try a different model immediately
        model2 = _get_next_openrouter_model()
        resp = http_req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {OPENROUTER_API_KEY}',
                'Content-Type': 'application/json',
                'HTTP-Referer': 'http://localhost:7331',
                'X-Title': 'Bug Bounty Scanner'
            },
            json={
                'model': model2,
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': temp,
                'max_tokens': 1024
            },
            timeout=60
        )
    if resp.status_code != 200:
        raise Exception(f"OpenRouter API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()['choices'][0]['message']['content'].strip()

def _groq_call(prompt, temp=0.3):
    resp = http_req.post(
        'https://api.groq.com/openai/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {GROQ_API_KEY}',
            'Content-Type': 'application/json'
        },
        json={
            'model': 'llama-3.3-70b-versatile',
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': temp,
            'max_tokens': 1024
        },
        timeout=30
    )
    if resp.status_code != 200:
        raise Exception(f"Groq API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()['choices'][0]['message']['content'].strip()

def _gemini_call(prompt, temp=0.3):
    resp = gemini_client.models.generate_content(
        model='gemini-2.0-flash',
        contents=prompt,
        config={'temperature': temp}
    )
    return resp.text.strip()

def parse_json(text):
    text = text.strip()
    if '```' in text:
        lines = text.split('\n')
        lines = [l for l in lines if not l.strip().startswith('```')]
        text = '\n'.join(lines)
    s1, s2 = text.find('['), text.find('{')
    if s1 == -1 and s2 == -1:
        raise ValueError("No JSON found in response")
    if s1 != -1 and (s2 == -1 or s1 < s2):
        return json.loads(text[s1:text.rfind(']') + 1])
    return json.loads(text[s2:text.rfind('}') + 1])

def normalize_url(url):
    """Normalize a URL for deduplication."""
    parsed = urlparse(url)
    # Remove fragment, normalize path
    path = parsed.path.rstrip('/') or '/'
    return urlunparse((parsed.scheme, parsed.netloc, path, '', parsed.query, ''))

def create_session(cookies_str=''):
    """Create a requests.Session with realistic headers."""
    session = http_req.Session()
    session.verify = False
    session.headers.update({
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    if cookies_str:
        for cookie in cookies_str.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                session.cookies.set(name.strip(), value.strip())
    return session

SEVERITY = {
    'sqli': 'Critical', 'cmdi': 'Critical', 'lfi': 'High',
    'ssrf': 'High', 'xss': 'Medium', 'idor': 'High',
    'csrf': 'Medium', 'open_redirect': 'Low', 'file_upload': 'High',
    'security_headers': 'Info', 'clickjacking': 'Medium',
    'html_injection': 'Low', 'header_injection': 'Medium',
    'blind_sqli': 'Critical', 'blind_cmdi': 'High',
}

FALLBACK_PAYLOADS = {
    'sqli': ["' OR '1'='1", "' OR '1'='1' --", "1 OR 1=1", "1 UNION SELECT NULL,NULL--", "' AND '1'='2", "' AND SLEEP(3)--"],
    'xss': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', "'-alert(1)-'", '<img src=x onerror=alert(document.domain)>'],
    'cmdi': ['; ls', '| id', '& whoami', '127.0.0.1; cat /etc/passwd', '`id`', '; uname -a'],
    'lfi': ['../../../../etc/passwd', '....//....//....//etc/passwd', '/etc/passwd%00', '..\\..\\..\\..\\windows\\win.ini'],
    'ssrf': ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://0x7f000001/'],
    'idor': ['1', '2', '0', '999', '-1'],
    'open_redirect': ['https://evil.com', '//evil.com', '/\\evil.com', 'https://evil.com%2F%2F'],
}

# ─── Target Fingerprinting & WAF Detection ───────────────────────────────────

def step_fingerprint(target_url, session):
    """Fingerprint target technology stack and detect WAFs."""
    log('info', '═══ STAGE 0: FINGERPRINT & RECON ═══')
    fingerprint = {
        'server': 'unknown', 'language': 'unknown', 'framework': 'unknown',
        'waf_detected': False, 'waf_name': 'none', 'technologies': [],
        'interesting_headers': {}
    }

    try:
        r = session.get(target_url, timeout=10)
        headers = {k.lower(): v for k, v in r.headers.items()}

        # Server detection
        server = headers.get('server', '')
        fingerprint['server'] = server or 'hidden'
        if server:
            log('info', f'  🖥️ Server: {server}')

        # Language detection from headers
        powered_by = headers.get('x-powered-by', '')
        if powered_by:
            fingerprint['technologies'].append(powered_by)
            log('info', f'  ⚙️ X-Powered-By: {powered_by}')
            if 'php' in powered_by.lower():
                fingerprint['language'] = 'php'
            elif 'asp' in powered_by.lower():
                fingerprint['language'] = 'asp'
            elif 'express' in powered_by.lower() or 'node' in powered_by.lower():
                fingerprint['language'] = 'node'

        # Language detection from URL/content
        body_lower = r.text.lower()
        url_lower = target_url.lower()
        if '.php' in url_lower or 'phpsessid' in str(r.cookies) or 'php' in body_lower[:500]:
            fingerprint['language'] = 'php'
        elif '.asp' in url_lower or 'asp.net' in str(headers):
            fingerprint['language'] = 'asp'
        elif '.jsp' in url_lower or 'jsessionid' in str(r.cookies):
            fingerprint['language'] = 'java'

        # Framework detection
        if 'wp-content' in r.text or 'wordpress' in body_lower:
            fingerprint['framework'] = 'wordpress'
        elif 'drupal' in body_lower:
            fingerprint['framework'] = 'drupal'
        elif 'joomla' in body_lower:
            fingerprint['framework'] = 'joomla'
        elif 'django' in body_lower or 'csrfmiddlewaretoken' in r.text:
            fingerprint['framework'] = 'django'
        elif 'laravel' in str(r.cookies) or 'laravel' in body_lower:
            fingerprint['framework'] = 'laravel'
        elif 'rails' in body_lower or 'csrf-token' in r.text:
            fingerprint['framework'] = 'rails'

        log('info', f'  💻 Language: {fingerprint["language"]}')
        log('info', f'  📦 Framework: {fingerprint["framework"]}')

        # WAF Detection — send a deliberate trigger
        waf_test_payloads = [
            ("'", 'Single quote'),
            ('<script>', 'Script tag'),
            ('../../../etc/passwd', 'Path traversal'),
        ]

        waf_signatures = {
            'cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status'],
            'akamai': ['akamai', 'akamaighhost', 'x-akamai'],
            'aws_waf': ['awselb', 'x-amzn', 'x-amz-cf'],
            'modsecurity': ['mod_security', 'modsecurity', 'nyob'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'imperva': ['incapsula', 'imperva', 'x-iinfo'],
            'barracuda': ['barracuda', 'barra_counter_session'],
            'f5_big_ip': ['bigip', 'f5', 'ts=', 'bigipserver'],
            'wordfence': ['wordfence', 'wfwaf'],
        }

        # Check response headers for WAF signatures
        all_headers_str = json.dumps(dict(r.headers)).lower()
        cookie_str = str(r.cookies).lower()
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in all_headers_str or sig in cookie_str:
                    fingerprint['waf_detected'] = True
                    fingerprint['waf_name'] = waf_name
                    log('warn', f'  🛡️ WAF DETECTED: {waf_name.upper()}')
                    break
            if fingerprint['waf_detected']:
                break

        # Active WAF test with suspicious payloads
        if not fingerprint['waf_detected']:
            parsed = urlparse(target_url)
            for payload, desc in waf_test_payloads:
                try:
                    test_url = f"{target_url}{'&' if '?' in target_url else '?'}waftest={payload}"
                    r_waf = session.get(test_url, timeout=5, allow_redirects=False)
                    if r_waf.status_code in (403, 406, 429, 503):
                        fingerprint['waf_detected'] = True
                        fingerprint['waf_name'] = 'generic'
                        log('warn', f'  🛡️ WAF DETECTED: Got {r_waf.status_code} on {desc}')
                        break
                    # Check for WAF block pages
                    if any(kw in r_waf.text.lower() for kw in ['blocked', 'forbidden', 'access denied', 'security', 'waf']):
                        if r_waf.status_code != 200 or len(r_waf.text) < 2000:
                            fingerprint['waf_detected'] = True
                            fingerprint['waf_name'] = 'generic'
                            log('warn', f'  🛡️ WAF DETECTED: Block page on {desc}')
                            break
                except Exception:
                    pass

        if not fingerprint['waf_detected']:
            log('ok', '  ✅ No WAF detected')

        # Store interesting headers
        for h in ['x-powered-by', 'server', 'x-aspnet-version', 'x-runtime',
                   'x-generator', 'x-drupal-cache', 'x-wordpress']:
            if h in headers:
                fingerprint['interesting_headers'][h] = headers[h]

    except Exception as e:
        log('error', f'  Fingerprint error: {e}')

    socketio.emit('fingerprint', fingerprint)
    return fingerprint


# ─── Encoding Bypass Engine ──────────────────────────────────────────────────

def _encode_payloads(payloads, vtype, waf_detected=False):
    """Apply encoding variations to bypass WAFs and filters."""
    if not waf_detected:
        return payloads  # No encoding needed without WAF

    encoded = list(payloads)  # Keep originals

    for payload in payloads[:3]:  # Only encode top 3 payloads
        # URL double-encoding
        from urllib.parse import quote
        encoded.append(quote(payload))
        encoded.append(quote(quote(payload)))

        if vtype in ('sqli',):
            # SQL comment bypass: SE/**/LECT
            for kw in ['SELECT', 'UNION', 'OR', 'AND', 'FROM', 'WHERE']:
                if kw.lower() in payload.lower():
                    bypassed = payload
                    for k in [kw, kw.lower(), kw.upper()]:
                        bypassed = bypassed.replace(k, f'{k[0]}/**/{k[1:]}')
                    encoded.append(bypassed)
            # Case variation
            encoded.append(payload.replace('SELECT', 'SeLeCt').replace('UNION', 'UnIoN')
                          .replace('select', 'SeLeCt').replace('union', 'UnIoN'))

        elif vtype in ('xss',):
            # HTML entity encoding
            encoded.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            # Case mixing
            encoded.append(payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'))
            # Event handler variations
            if 'onerror' in payload.lower():
                encoded.append(payload.replace('onerror', 'ONERROR'))
                encoded.append(payload.replace('onerror=', 'onerror\x0d='))

        elif vtype in ('cmdi',):
            # Whitespace bypass
            encoded.append(payload.replace(' ', '${IFS}'))
            encoded.append(payload.replace(' ', '\t'))

    # Deduplicate
    seen = set()
    unique = []
    for p in encoded:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique[:10]  # Max 10 encoded variants

# ─── DVWA Auto-Login ─────────────────────────────────────────────────────────

def dvwa_auto_login(base_url, username='admin', password='password'):
    """
    Auto-login to DVWA. Handles DB setup, CSRF tokens, security level.
    Returns a requests.Session with valid cookies, or None.
    """
    log('info', f'Auto-logging into DVWA at {base_url}...')

    try:
        # Step 0: Ensure DB is set up
        log('info', '  Ensuring database is initialized...')
        setup_session = create_session()
        setup_url = urljoin(base_url, 'setup.php')
        try:
            r_setup = setup_session.get(setup_url, timeout=10)
            soup_setup = BeautifulSoup(r_setup.text, 'html.parser')
            setup_token = soup_setup.find('input', {'name': 'user_token'})
            if setup_token:
                setup_session.post(setup_url, data={
                    'create_db': 'Create / Reset Database',
                    'user_token': setup_token['value']
                }, timeout=15, allow_redirects=True)
                log('ok', '  Database created/reset')
                time.sleep(2)  # Wait for DB to be ready
            else:
                log('info', '  Database already initialized')
        except Exception as e:
            log('warn', f'  DB setup note: {e}')

        # Step 1: Fresh session for login
        session = create_session()

        login_url = urljoin(base_url, 'login.php')
        r = session.get(login_url, timeout=10)
        log('info', f'  Login page: {r.status_code} ({len(r.text)} bytes)')

        soup = BeautifulSoup(r.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        user_token = token_input['value'] if token_input else ''

        # Step 2: POST login
        r2 = session.post(login_url, data={
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }, allow_redirects=False, timeout=10)

        location = r2.headers.get('Location', '')
        if 'login' in location.lower():
            log('error', '  Login FAILED — wrong credentials')
            return None

        # Follow redirect
        session.get(urljoin(base_url, location), timeout=10)
        log('ok', f'  Logged in! → {location}')

        # Step 3: Set security level to low (most vulns detectable)
        session.cookies.set('security', 'low')
        sec_url = urljoin(base_url, 'security.php')
        r3 = session.get(sec_url, timeout=10)
        soup3 = BeautifulSoup(r3.text, 'html.parser')
        sec_token = soup3.find('input', {'name': 'user_token'})
        if sec_token:
            session.post(sec_url, data={
                'security': 'low',
                'seclev_submit': 'Submit',
                'user_token': sec_token['value']
            }, timeout=10)
        session.cookies.set('security', 'low')
        log('ok', '  Security set to LOW')

        # Step 4: Disable PHPIDS
        try:
            phpids_url = urljoin(base_url, 'security.php')
            r_ids = session.get(phpids_url, timeout=10)
            if 'phpids' in r_ids.text.lower() or 'Enable IDS' in r_ids.text:
                log('ok', '  PHPIDS already disabled')
            elif 'Disable IDS' in r_ids.text:
                # Find the disable link
                soup_ids = BeautifulSoup(r_ids.text, 'html.parser')
                disable_link = soup_ids.find('a', string=re.compile(r'Disable', re.I))
                if disable_link:
                    session.get(urljoin(base_url, disable_link['href']), timeout=10)
                    log('ok', '  PHPIDS disabled')
        except Exception:
            pass

        # Step 5: Verify access
        test_url = urljoin(base_url, 'vulnerabilities/sqli/?id=1&Submit=Submit')
        r_test = session.get(test_url, timeout=10, allow_redirects=False)
        if r_test.status_code in (301, 302, 303, 307):
            redir = r_test.headers.get('Location', '')
            if 'login' in redir.lower():
                log('error', '  Session invalid — still redirecting to login')
                return None

        log('ok', f'  Session verified! SQLi page: {r_test.status_code} ({len(r_test.text)} bytes)')
        return session

    except Exception as e:
        log('error', f'  Login error: {e}')
        return None


# ─── Generic Auto-Login ──────────────────────────────────────────────────────

def generic_auto_login(base_url, username, password):
    """
    Attempt to find and submit a login form on a generic website.
    Returns session if successful, None otherwise.
    """
    log('info', f'Attempting generic auto-login at {base_url}...')
    session = create_session()

    try:
        # Common login paths to try
        login_paths = ['login', 'login.php', 'signin', 'auth/login', 'user/login',
                       'account/login', 'admin/login', 'wp-login.php', '']

        for path in login_paths:
            login_url = urljoin(base_url, path)
            try:
                r = session.get(login_url, timeout=8, allow_redirects=True)
                if r.status_code != 200:
                    continue

                soup = BeautifulSoup(r.text, 'html.parser')
                forms = soup.find_all('form')

                for form in forms:
                    inputs = form.find_all('input')
                    input_names = {inp.get('name', '').lower(): inp for inp in inputs if inp.get('name')}

                    # Look for username/password fields
                    user_field = None
                    pass_field = None
                    for name, inp in input_names.items():
                        inp_type = (inp.get('type') or 'text').lower()
                        if inp_type == 'password' or name in ('password', 'pass', 'passwd', 'pwd'):
                            pass_field = inp.get('name')
                        elif name in ('username', 'user', 'login', 'email', 'uname', 'user_login') or inp_type == 'email':
                            user_field = inp.get('name')

                    if not user_field or not pass_field:
                        continue

                    log('info', f'  Found login form at {login_url} (fields: {user_field}, {pass_field})')

                    # Build form data
                    form_data = {}
                    for inp in inputs:
                        name = inp.get('name')
                        if not name:
                            continue
                        if name == user_field:
                            form_data[name] = username
                        elif name == pass_field:
                            form_data[name] = password
                        else:
                            form_data[name] = inp.get('value', '')

                    action = form.get('action', '')
                    method = (form.get('method', 'POST')).upper()
                    submit_url = urljoin(login_url, action) if action else login_url

                    if method == 'POST':
                        r2 = session.post(submit_url, data=form_data, timeout=10, allow_redirects=True)
                    else:
                        r2 = session.get(submit_url, params=form_data, timeout=10, allow_redirects=True)

                    # Check if login succeeded (no longer on login page, or dashboard keywords)
                    final_url = r2.url.lower()
                    body_lower = r2.text.lower()
                    if ('login' not in final_url and 'signin' not in final_url) or \
                       any(kw in body_lower for kw in ['dashboard', 'welcome', 'logout', 'sign out', 'my account']):
                        log('ok', f'  Login appears successful → {r2.url}')
                        return session
                    else:
                        log('warn', f'  Login attempt failed at {submit_url}')

            except Exception:
                continue

    except Exception as e:
        log('error', f'  Generic login error: {e}')

    return None


# ─── Session Health Check ────────────────────────────────────────────────────

def check_session_health(session, base_url, is_dvwa=False):
    """Verify the session is still valid."""
    try:
        r = session.get(base_url, timeout=8, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307):
            location = r.headers.get('Location', '').lower()
            if 'login' in location:
                return False
        return True
    except Exception:
        return False


# ─── Stage 1: Crawl ─────────────────────────────────────────────────────────

DVWA_VULN_PATHS = [
    'vulnerabilities/xss_r/', 'vulnerabilities/xss_s/', 'vulnerabilities/xss_d/',
    'vulnerabilities/sqli/', 'vulnerabilities/sqli_blind/',
    'vulnerabilities/exec/', 'vulnerabilities/fi/',
    'vulnerabilities/csrf/', 'vulnerabilities/upload/',
    'vulnerabilities/brute/', 'vulnerabilities/weak_id/',
]

def _is_directory_listing(response_text):
    """Detect Apache/Nginx directory listing pages."""
    soup = BeautifulSoup(response_text, 'html.parser')
    title = soup.find('title')
    if title and 'index of' in title.text.lower():
        return True
    if '<h1>Index of' in response_text or 'Directory listing for' in response_text:
        return True
    return False

def _parse_robots(base_url, session):
    """Parse robots.txt for interesting paths."""
    paths = []
    try:
        r = session.get(urljoin(base_url, 'robots.txt'), timeout=5)
        if r.status_code == 200 and 'text' in r.headers.get('Content-Type', ''):
            for line in r.text.splitlines():
                line = line.strip()
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/' and '*' not in path:
                        paths.append(path)
                elif line.startswith('Sitemap:'):
                    paths.append(line.split(':', 1)[1].strip())
    except Exception:
        pass
    return paths

def _parse_sitemap(base_url, session):
    """Parse sitemap.xml for additional URLs."""
    urls = []
    try:
        r = session.get(urljoin(base_url, 'sitemap.xml'), timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'xml')
            for loc in soup.find_all('loc'):
                urls.append(loc.text.strip())
    except Exception:
        pass
    return urls[:50]  # Limit

def step_crawl(target_url, session, max_pages=100):
    log('info', '═══ STAGE 1: CRAWL ═══')
    log('info', f'Target: {target_url}')

    base = target_url.rstrip('/')
    parsed_base = urlparse(base)
    base_domain = parsed_base.netloc
    base_path = parsed_base.path.rstrip('/')

    # Detect if target is DVWA
    is_dvwa = False
    try:
        r_check = session.get(target_url, timeout=8)
        page_text = r_check.text.lower()
        if 'damn vulnerable web application' in page_text or 'dvwa' in page_text:
            is_dvwa = True
            log('info', '  🎯 Detected DVWA — seeding known vulnerability paths')
        else:
            log('info', '  🌐 Generic target — crawling organically')
    except Exception:
        pass

    # Build initial URL list
    start_url = f"{parsed_base.scheme}://{base_domain}{base_path}/index.php"
    to_visit = [target_url, start_url]

    # DVWA seeded paths
    if is_dvwa:
        seeded = [f"{parsed_base.scheme}://{base_domain}{base_path}/{p}" for p in DVWA_VULN_PATHS]
        to_visit += seeded

    # Robots.txt discovery
    robot_paths = _parse_robots(target_url, session)
    if robot_paths:
        log('info', f'  📄 robots.txt: found {len(robot_paths)} paths')
        for rp in robot_paths:
            if rp.startswith('http'):
                to_visit.append(rp)
            else:
                to_visit.append(urljoin(target_url, rp))

    # Sitemap discovery
    sitemap_urls = _parse_sitemap(target_url, session)
    if sitemap_urls:
        log('info', f'  🗺 sitemap.xml: found {len(sitemap_urls)} URLs')
        to_visit += sitemap_urls

    visited = set()
    endpoints = []
    skip_ext = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.pdf', '.zip',
                '.mp3', '.avi', '.mov', '.webp', '.webm', '.map'}
    skip_pages = {'logout.php', 'setup.php', 'login.php', 'security.php', 'phpinfo.php'}

    while to_visit and len(visited) < max_pages:
        if is_cancelled():
            log('warn', '  Scan cancelled during crawl')
            break

        url = to_visit.pop(0).split('#')[0]

        # Normalize for dedup
        norm = normalize_url(url)
        if norm in visited:
            continue

        parsed = urlparse(url)
        if parsed.netloc != base_domain:
            continue
        if any(url.lower().endswith(e) for e in skip_ext):
            continue
        if any(skip in url.lower().split('/')[-1].lower() for skip in skip_pages):
            continue

        visited.add(norm)

        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                continue

            log('info', f'  → GET {url}  [{resp.status_code}] {len(resp.text)} bytes')
        except Exception as e:
            log('warn', f'  ✗ GET {url} FAILED: {e}')
            continue

        # Detect login redirect
        if 'login.php' in resp.url and 'login' not in url.lower():
            log('warn', f'  ⚠ Redirected to login — skipping')
            continue

        if _is_directory_listing(resp.text):
            log('info', f'  ⏭ Directory listing — skipping')
            continue

        soup = BeautifulSoup(resp.text, 'html.parser')

        # Extract forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = (form.get('method', 'GET')).upper()
            form_url = urljoin(url, action) if action else url
            params = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    params.append({
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'default_value': inp.get('value', '')
                    })
            if params:
                pnames = {p['name'].lower() for p in params}
                # Skip login forms
                if 'username' in pnames and 'password' in pnames:
                    continue
                if 'user_login' in pnames and 'user_pass' in pnames:
                    continue
                endpoints.append({
                    'url': form_url, 'method': method,
                    'source': url, 'params': params, 'type': 'form'
                })
                log('ok', f'    📋 Form: {method} {form_url} → params={[p["name"] for p in params]}')

        # Extract links
        for a in soup.find_all('a', href=True):
            link = urljoin(url, a['href'])
            link_parsed = urlparse(link)
            if link_parsed.netloc != base_domain:
                continue
            if link_parsed.query:
                qs = parse_qs(link_parsed.query)
                params = [{'name': k, 'type': 'query', 'default_value': v[0]} for k, v in qs.items()]
                endpoints.append({
                    'url': link.split('?')[0], 'method': 'GET',
                    'source': url, 'params': params, 'type': 'query'
                })
            clean = link.split('?')[0].split('#')[0]
            norm_clean = normalize_url(clean)
            if norm_clean not in visited:
                to_visit.append(link)

        # Small delay to be respectful
        time.sleep(0.2)

    # Deduplicate endpoints
    seen = set()
    unique = []
    for ep in endpoints:
        key = f"{ep['method']}:{ep['url']}:{','.join(sorted(p['name'] for p in ep['params']))}"
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    log('ok', f'Crawl done: {len(visited)} pages visited, {len(unique)} unique endpoints found')
    return unique, is_dvwa


# ─── Stage 2: Classify ──────────────────────────────────────────────────────

def step_classify(endpoints):
    log('info', '═══ STAGE 2: CLASSIFY ═══')

    ep_summary = [{'i': i, 'url': e['url'], 'method': e['method'],
                    'params': [p['name'] for p in e['params']], 'type': e['type']}
                   for i, e in enumerate(endpoints)]

    prompt = f"""You are a web security expert. Classify vulnerability types for these endpoints.

ENDPOINTS:
{json.dumps(ep_summary, indent=2)}

Rules:
- id/uid/user_id → sqli, idor
- name/search/comment/text/message/txtName/mtxMessage → xss
- ip/host/cmd/command/ping → cmdi
- page/file/path/include → lfi
- url/redirect/next → open_redirect, ssrf
- upload paths → file_upload
- Any form without CSRF token → csrf

Types: sqli, xss, cmdi, lfi, ssrf, idor, csrf, open_redirect, file_upload

Respond ONLY JSON array:
[{{"i": 0, "vuln_types": ["sqli"], "priority": "high"}}]"""

    try:
        raw = ai_call(prompt, temp=0.2)
        cls_list = parse_json(raw)
        for c in cls_list:
            idx = c.get('i', -1)
            if 0 <= idx < len(endpoints):
                endpoints[idx]['vuln_types'] = c.get('vuln_types', [])
                endpoints[idx]['priority'] = c.get('priority', 'medium')
                log('ai', f'  {endpoints[idx]["url"]} → {c.get("vuln_types", [])}')
    except Exception as e:
        log('warn', f'AI classify failed ({e}), using heuristics')
        for ep in endpoints:
            ep['vuln_types'] = _guess(ep)
            ep['priority'] = 'medium'

    # Ensure all endpoints have vuln_types
    for ep in endpoints:
        if not ep.get('vuln_types'):
            ep['vuln_types'] = _guess(ep)
            ep['priority'] = 'medium'

    order = {'high': 0, 'medium': 1, 'low': 2}
    endpoints.sort(key=lambda e: order.get(e.get('priority', 'medium'), 1))
    return endpoints

def _guess(ep):
    types = set()
    url_lower = ep['url'].lower()
    for p in ep['params']:
        n = p['name'].lower()
        if n in ('id', 'uid', 'user_id', 'item', 'no', 'userid', 'article', 'product_id', 'order_id'):
            types.update(['sqli', 'idor'])
        if n in ('search', 'q', 'name', 'comment', 'text', 'msg', 'message',
                 'txtname', 'mtxmessage', 'txtmessage', 'input', 'query',
                 'keyword', 'term', 'feedback', 'data', 'content', 'value',
                 'title', 'body', 'description', 'default'):
            types.add('xss')
        if n in ('ip', 'host', 'cmd', 'command', 'ping', 'target', 'exec',
                 'run', 'system', 'shell'):
            types.add('cmdi')
        if n in ('page', 'file', 'path', 'include', 'doc', 'document',
                 'filename', 'load', 'template', 'view', 'lang'):
            types.add('lfi')
        if n in ('url', 'redirect', 'next', 'return', 'goto', 'link',
                 'dest', 'destination', 'continue', 'return_url', 'redirect_to'):
            types.update(['open_redirect', 'ssrf'])
    if 'upload' in url_lower:
        types.add('file_upload')
    if 'xss' in url_lower:
        types.add('xss')
    if 'sqli' in url_lower or 'sql' in url_lower:
        types.add('sqli')
    if 'cmdi' in url_lower or 'exec' in url_lower or 'cmd' in url_lower:
        types.add('cmdi')
    if '/fi/' in url_lower or 'file' in url_lower:
        types.add('lfi')
    if 'csrf' in url_lower:
        types.add('csrf')
    if 'redirect' in url_lower:
        types.add('open_redirect')
    return list(types) if types else ['xss', 'sqli']


# ─── Stage 3: Attack ────────────────────────────────────────────────────────

def step_attack(endpoints, session, is_dvwa=False, fingerprint=None):
    log('info', '═══ STAGE 3: ATTACK ═══')
    fp_info = fingerprint or {}
    waf = fp_info.get('waf_detected', False)

    testable = [e for e in endpoints if e.get('vuln_types')]

    # ── Build full test matrix: all params × all vuln types ──
    test_matrix = []
    skip = {'submit', 'login', 'btnsign', 'btnclear', 'btnsubmit',
            'user_token', 'csrf_token', 'change', 'upload', 'max_file_size',
            'step', 'send', 'seclev_submit', '_token', 'csrf',
            'captcha', 'submit_btn', 'action'}

    for ep in testable:
        injectable_params = [p for p in ep['params']
                             if p['name'].lower() not in skip
                             and p.get('type', '') not in ('submit', 'hidden', 'file')]
        if not injectable_params:
            injectable_params = [p for p in ep['params'] if p['name'].lower() not in skip]
        if not injectable_params:
            continue

        for param in injectable_params:
            for vtype in ep['vuln_types']:
                test_matrix.append((ep, param, vtype))

    total = len(test_matrix)
    log('info', f'Testing {total} param/vuln combinations across {len(testable)} endpoints')
    if waf:
        log('warn', f'  🛡️ WAF detected ({fp_info.get("waf_name", "unknown")}) — applying encoding bypass')

    found_combos = set()  # Track (url, vtype) to avoid duplicate findings

    for count, (ep, target_p, vtype) in enumerate(test_matrix, 1):
        if is_cancelled():
            log('warn', 'Scan cancelled during attack phase')
            break

        # Skip if we already found this vuln type on this URL
        combo_key = f"{ep['url']}:{vtype}"
        if combo_key in found_combos:
            continue

        log('attack', f'━━━ [{count}/{total}] {vtype.upper()} → {ep["method"]} {ep["url"]} ({target_p["name"]}) ━━━')
        emit_progress(count, total, 'attack')

        try:
            payloads = _generate_safe_payloads(vtype, ep, target_p)

            # Apply encoding bypass if WAF detected
            if waf:
                payloads = _encode_payloads(payloads, vtype, waf_detected=True)

            # Multiple baselines for stability
            bl = _send_timed(session, ep, target_p['name'], target_p.get('default_value', 'test'))
            bl2 = _send_timed(session, ep, target_p['name'], target_p.get('default_value', 'test'))
            if bl and bl2:
                bl['baseline_time_avg'] = (bl['response_time'] + bl2['response_time']) / 2
                log('info', f'  📤 Baseline: {ep["method"]} → [{bl["status_code"]}] {bl["length"]} bytes ({bl["baseline_time_avg"]:.2f}s avg)')
            elif bl:
                bl['baseline_time_avg'] = bl['response_time']
                log('info', f'  📤 Baseline: {ep["method"]} → [{bl["status_code"]}] {bl["length"]} bytes ({bl["response_time"]:.2f}s)')

            for payload in payloads:
                if is_cancelled():
                    break

                log('attack', f'  🔫 Payload: {payload}')

                resp = _send_timed(session, ep, target_p['name'], payload)
                if not resp:
                    log('warn', f'  ✗ No response')
                    continue

                log('info', f'  📥 Response: [{resp["status_code"]}] {resp["length"]} bytes ({resp["response_time"]:.2f}s)')

                # Check for session death
                if resp['status_code'] == 302 or 'login.php' in resp.get('url', ''):
                    log('warn', f'  ⚠ Session expired — skipping')
                    continue

                vuln, evidence = _analyze(vtype, ep['url'], target_p['name'], payload, bl, resp)

                if vuln:
                    log('ok', f'  🔍 Initial detection: {vtype.upper()} — sending to Triage Agent...')
                    socketio.emit('log', {'level': 'triage', 'text': f'🛡️ Triage Agent verifying {vtype.upper()} on {ep["url"]}...', 'ts': time.time()})

                    # ── TRIAGE AGENT: Double-check the vulnerability ──
                    triage_result = _triage_verify(
                        session, ep, target_p, vtype, payload,
                        evidence, bl, resp
                    )

                    if triage_result['confirmed']:
                        log('ok', f'  ✅ TRIAGE CONFIRMED! {vtype.upper()} is real!')
                        log('ok', f'  📋 Initial evidence: {evidence}')
                        log('ok', f'  🛡️ Triage evidence: {triage_result["triage_evidence"]}')
                        socketio.emit('log', {'level': 'triage', 'text': f'✅ Triage Agent CONFIRMED {vtype.upper()} — vulnerability is real', 'ts': time.time()})

                        fid = fp(ep['method'], ep['url'], target_p['name'], vtype)
                        finding = {
                            'id': fid, 'url': ep['url'], 'method': ep['method'],
                            'param': target_p['name'], 'vuln_type': vtype,
                            'payload': payload, 'evidence': evidence,
                            'severity': SEVERITY.get(vtype, 'Low'),
                            'confirmed': True,
                            'triage_verified': True,
                            'triage_evidence': triage_result['triage_evidence'],
                            'triage_payload': triage_result.get('triage_payload', ''),
                            'response_code': resp['status_code'],
                            'response_snippet': resp['body'][:500],
                            'timestamp': time.time()
                        }
                        if write_finding(finding):
                            socketio.emit('finding', finding)
                        found_combos.add(combo_key)
                        break
                    else:
                        log('warn', f'  ❌ TRIAGE REJECTED — false positive discarded')
                        log('warn', f'  Reason: {triage_result.get("reason", "Triage could not confirm")}')
                        socketio.emit('log', {'level': 'triage', 'text': f'❌ Triage Agent REJECTED {vtype.upper()} — false positive', 'ts': time.time()})
                else:
                    log('info', f'  ✗ Not vulnerable with this payload')

            time.sleep(0.3)
        except Exception as e:
            log('error', f'  Error testing {ep["url"]}: {e}')

    # ── Header Injection Testing ──
    if testable and not is_cancelled():
        _test_header_injection(testable[0]['url'], session, waf)

def _send(session, ep, param_name, value):
    """Send a request (backward compatible wrapper)."""
    return _send_timed(session, ep, param_name, value)

def _send_timed(session, ep, param_name, value):
    """Send a request and measure response time for blind detection."""
    try:
        params = {}
        for p in ep['params']:
            if p['name'] == param_name:
                params[p['name']] = value
            else:
                params[p['name']] = p.get('default_value', '') or 'test'

        start_time = time.time()

        if ep['method'] == 'GET':
            url = f"{ep['url']}?{urlencode(params)}"
            resp = session.get(url, timeout=15, allow_redirects=False)
        else:
            resp = session.post(ep['url'], data=params, timeout=15, allow_redirects=False)

        response_time = time.time() - start_time

        # Handle redirects
        if resp.status_code in (301, 302, 303, 307):
            location = resp.headers.get('Location', '')
            if 'login' in location.lower():
                return {
                    'status_code': 302,
                    'body': 'REDIRECTED TO LOGIN - SESSION EXPIRED',
                    'url': location,
                    'length': 0,
                    'headers': dict(resp.headers),
                    'response_time': response_time
                }
            # Follow non-login redirects
            try:
                resp = session.get(urljoin(ep['url'], location), timeout=12, allow_redirects=False)
                response_time = time.time() - start_time
            except Exception:
                pass

        return {
            'status_code': resp.status_code,
            'body': resp.text[:5000],
            'url': resp.url if hasattr(resp, 'url') else ep['url'],
            'length': len(resp.text),
            'headers': dict(resp.headers),
            'response_time': response_time
        }
    except Exception as e:
        log('warn', f'  Request error: {e}')
        return None


# ─── Header Injection Testing ────────────────────────────────────────────────

def _test_header_injection(target_url, session, waf_detected=False):
    """Test for vulnerabilities via HTTP headers (User-Agent, Referer, etc.)."""
    log('info', '═══ STAGE 3b: HEADER INJECTION ═══')

    injectable_headers = {
        'User-Agent': [
            "' OR '1'='1' --",
            '<script>alert(1)</script>',
            '$(id)',
        ],
        'Referer': [
            "' OR '1'='1' --",
            '<script>alert(1)</script>',
            'http://evil.com',
        ],
        'X-Forwarded-For': [
            '127.0.0.1',
            "' OR '1'='1' --",
            '0.0.0.0',
        ],
        'X-Forwarded-Host': [
            'evil.com',
            '<script>alert(1)</script>',
        ],
    }

    # Get baseline
    try:
        bl = session.get(target_url, timeout=10)
        bl_body = bl.text[:5000]
        bl_len = len(bl.text)
    except Exception:
        log('warn', '  Could not get baseline for header injection testing')
        return

    for header_name, payloads in injectable_headers.items():
        if is_cancelled():
            break

        for payload in payloads:
            try:
                custom_headers = {header_name: payload}
                r = session.get(target_url, headers=custom_headers, timeout=10, allow_redirects=True)

                # Check if payload is reflected
                if payload in r.text and payload not in bl_body:
                    vuln_type = 'xss' if '<script' in payload.lower() else 'header_injection'
                    log('ok', f'  ✅ {header_name} injection: payload reflected!')

                    fid = fp('GET', target_url, header_name, vuln_type)
                    finding = {
                        'id': fid, 'url': target_url, 'method': 'GET',
                        'param': f'Header: {header_name}', 'vuln_type': vuln_type,
                        'payload': f'{header_name}: {payload}',
                        'evidence': f'Payload injected via {header_name} header was reflected in response body',
                        'severity': SEVERITY.get(vuln_type, 'Medium'),
                        'confirmed': True, 'triage_verified': False,
                        'response_code': r.status_code,
                        'response_snippet': r.text[:500],
                        'timestamp': time.time()
                    }
                    if write_finding(finding):
                        socketio.emit('finding', finding)
                    break

                # Check for SQL errors via header
                sql_errors = ['mysql_', 'sql syntax', 'sqlstate[', 'pg_query', 'ora-']
                for err in sql_errors:
                    if err.lower() in r.text.lower() and err.lower() not in bl_body.lower():
                        log('ok', f'  ✅ SQL injection via {header_name} header!')
                        fid = fp('GET', target_url, header_name, 'sqli')
                        finding = {
                            'id': fid, 'url': target_url, 'method': 'GET',
                            'param': f'Header: {header_name}', 'vuln_type': 'sqli',
                            'payload': f'{header_name}: {payload}',
                            'evidence': f'SQL error triggered via {header_name} header: {err}',
                            'severity': 'Critical',
                            'confirmed': True, 'triage_verified': False,
                            'response_code': r.status_code,
                            'response_snippet': r.text[:500],
                            'timestamp': time.time()
                        }
                        if write_finding(finding):
                            socketio.emit('finding', finding)
                        break

            except Exception:
                continue

    log('ok', '  Header injection testing complete')

# ─── AI Safe Payload Agent ───────────────────────────────────────────────────

SAFE_PAYLOAD_RULES = {
    'sqli': {
        'safe': [
            "Read-only detection: OR tautology, UNION SELECT NULL, time-based SLEEP",
            "Error-based: single quote, double quote to trigger syntax errors",
        ],
        'forbidden': [
            "NO DROP, DELETE, UPDATE, INSERT, ALTER, TRUNCATE, CREATE",
            "NO INTO OUTFILE, INTO DUMPFILE, LOAD_FILE for writing",
            "NO shell commands via xp_cmdshell, sys_exec",
            "NO modification of any data whatsoever",
        ]
    },
    'xss': {
        'safe': [
            "alert(1), alert(document.domain), console.log() — harmless JS",
            "img/svg/body event handlers with alert() only",
        ],
        'forbidden': [
            "NO document.cookie theft, NO fetch/XMLHttpRequest to external",
            "NO keyloggers, NO credential harvesting, NO DOM manipulation",
            "NO persistent payloads that modify stored data",
        ]
    },
    'cmdi': {
        'safe': [
            "Read-only: id, whoami, uname -a, cat /etc/passwd (world-readable)",
            "Time-based: sleep 3, ping -c 3 127.0.0.1",
        ],
        'forbidden': [
            "NO rm, NO mkfs, NO dd, NO file deletion or modification",
            "NO reverse shells, NO bind shells, NO wget/curl to download",
            "NO user creation, NO permission changes, NO service manipulation",
        ]
    },
    'lfi': {
        'safe': [
            "Read world-readable files: /etc/passwd, /etc/hostname",
            "Path traversal with encoding variations",
        ],
        'forbidden': [
            "NO /etc/shadow, NO private keys, NO writing files",
            "NO PHP wrappers that execute code (except php://filter for read)",
            "NO log poisoning, NO file upload chaining",
        ]
    },
    'ssrf': {
        'safe': [
            "Localhost probing: 127.0.0.1, [::1], 0x7f000001",
            "Metadata endpoints: 169.254.169.254 (read-only detection)",
        ],
        'forbidden': [
            "NO port scanning of internal networks",
            "NO requests to external attacker-controlled servers",
            "NO file:// protocol for reading sensitive files",
        ]
    },
    'open_redirect': {
        'safe': [
            "Redirect to well-known domains: https://example.com, //example.com",
            "Protocol-relative URLs, path-based bypasses",
        ],
        'forbidden': [
            "NO javascript: URIs with harmful code",
            "NO data: URIs with executable content",
        ]
    },
}

def _generate_safe_payloads(vtype, ep, target_param):
    """AI Safe Payload Agent — generates context-aware, 100% safe payloads."""
    pnames = [p['name'] for p in ep['params']]
    rules = SAFE_PAYLOAD_RULES.get(vtype, {})
    safe_rules = '\n'.join(f'  ✅ {r}' for r in rules.get('safe', []))
    forbidden_rules = '\n'.join(f'  🚫 {r}' for r in rules.get('forbidden', []))

    prompt = f"""You are a SAFE Payload Generation Agent for ethical penetration testing.
Your job is to create payloads that PROVE a vulnerability exists WITHOUT causing any damage.

TARGET CONTEXT:
- Vulnerability type: {vtype}
- URL: {ep['url']}
- HTTP Method: {ep['method']}
- Parameter to inject: {target_param['name']} (type: {target_param.get('type', 'text')})
- Default value: {target_param.get('default_value', 'N/A')}
- All parameters: {json.dumps(pnames)}
- Endpoint type: {ep.get('type', 'unknown')}

SAFETY RULES (MUST FOLLOW):
{safe_rules}

FORBIDDEN (NEVER GENERATE):
{forbidden_rules}

GENERAL SAFETY MANDATE:
- Every payload MUST be read-only and non-destructive
- Payloads should DETECT the vulnerability, not EXPLOIT it
- Use harmless proof-of-concept techniques only (alert boxes, reading public files, timing)
- Consider the specific parameter name and context to craft targeted payloads
- Generate 4-6 payloads, ordered from most likely to succeed to least likely
- Each payload should test a DIFFERENT technique (don't repeat the same approach)

Respond with ONLY a JSON array of payload strings:
["payload1", "payload2", "payload3", "payload4"]"""

    try:
        raw = ai_call(prompt, temp=0.3)
        result = parse_json(raw)
        if isinstance(result, list):
            payloads = [p if isinstance(p, str) else p.get('payload', str(p)) for p in result]
            # Safety filter: reject any payload with destructive keywords
            safe_payloads = [p for p in payloads if _is_payload_safe(p, vtype)]
            if safe_payloads:
                log('ai', f'  🛡️ Safe Payload Agent generated {len(safe_payloads)} payloads')
                return safe_payloads[:6]
            else:
                log('warn', f'  ⚠ All AI payloads failed safety check — using safe fallbacks')
    except Exception as e:
        log('warn', f'  Safe Payload Agent error ({e}) — using safe fallbacks')

    return SAFE_FALLBACK_PAYLOADS.get(vtype, ['test'])


def _is_payload_safe(payload, vtype):
    """Hard safety filter — rejects any payload with destructive intent."""
    payload_lower = payload.lower()

    # Universal dangerous patterns
    dangerous = [
        'drop ', 'delete ', 'update ', 'insert ', 'alter ', 'truncate ',
        'create ', 'into outfile', 'into dumpfile', 'xp_cmdshell',
        'sys_exec', 'load_file', 'rm -', 'rm /', 'mkfs', 'dd if=',
        'chmod ', 'chown ', 'useradd', 'passwd ', '/etc/shadow',
        'reverse', 'bind shell', 'nc -', 'ncat ', 'bash -i',
        'python -c', 'perl -e', 'ruby -e', 'wget ', 'curl ',
        'fetch(', 'xmlhttprequest', 'document.cookie',
        'new image', 'navigator.sendbeacon',
    ]
    for d in dangerous:
        if d in payload_lower:
            log('warn', f'  🚫 Safety filter blocked payload containing: {d}')
            return False
    return True


# Safe fallback payloads (guaranteed non-destructive)
SAFE_FALLBACK_PAYLOADS = {
    'sqli': [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1 UNION SELECT NULL,NULL--",
        "' AND '1'='2",
        "' AND SLEEP(3)--",
        "1' ORDER BY 1--",
    ],
    'xss': [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(document.domain)>',
    ],
    'cmdi': [
        '; id', '| whoami', '& uname -a',
        '127.0.0.1; cat /etc/passwd',
        '`id`', '$(whoami)',
    ],
    'lfi': [
        '../../../../etc/passwd',
        '....//....//....//etc/passwd',
        '/etc/passwd%00',
        '..\\..\\..\\..\\etc/hostname',
    ],
    'ssrf': [
        'http://127.0.0.1',
        'http://169.254.169.254/latest/meta-data/',
        'http://[::1]/',
        'http://0x7f000001/',
    ],
    'idor': ['1', '2', '0', '999', '-1'],
    'open_redirect': [
        'https://example.com',
        '//example.com',
        '/\\example.com',
        'https://example.com%2F%2F',
    ],
}


# ─── Triage Verification Agent ───────────────────────────────────────────────

def _triage_verify(session, ep, target_param, vtype, original_payload, original_evidence, baseline, original_resp):
    """
    Triage Agent: independently verifies a suspected vulnerability.
    1. AI analyzes whether the original evidence is convincing
    2. Generates a DIFFERENT safe verification payload
    3. Re-tests with the new payload
    4. Both must agree for confirmation
    """
    log('info', f'  🛡️ TRIAGE AGENT: Verifying {vtype.upper()} on {ep["url"]}...')

    # ── Step 1: AI skeptical review of original evidence ──
    bl_text = _extract_relevant(baseline['body'])[:1500] if baseline else 'N/A'
    atk_text = _extract_relevant(original_resp['body'])[:2000]

    review_prompt = f"""You are a SKEPTICAL Triage Security Agent. Your job is to prevent false positives.
A scanner claims it found a vulnerability. Analyze the evidence CRITICALLY.

CLAIMED VULNERABILITY: {vtype}
URL: {ep['url']}
PARAMETER: {target_param['name']}
PAYLOAD USED: {original_payload}
CLAIMED EVIDENCE: {original_evidence}

BASELINE RESPONSE: status={baseline['status_code'] if baseline else 'N/A'} length={baseline['length'] if baseline else 'N/A'}
{bl_text}

ATTACK RESPONSE: status={original_resp['status_code']} length={original_resp['length']}
{atk_text}

CRITICAL QUESTIONS TO ASK:
1. Is the evidence ACTUALLY proving the vulnerability, or could it be a normal application behavior?
2. Could the response difference be caused by input validation, WAF, or error handling (not the actual vuln)?
3. For XSS: Is the payload ACTUALLY reflected with JS execution capability, or is it just HTML/text?
4. For SQLi: Are there REAL SQL errors or data leaks, or just different page content?
5. For CMDi: Is there ACTUAL command output, or just application error messages?
6. Could this be a honeypot or intentionally deceptive response?

Be VERY skeptical. Only confirm if the evidence is UNDENIABLE.

Respond ONLY JSON:
{{"initial_review": "pass"/"fail", "confidence": 0-100, "concerns": "any doubts"}}"""

    try:
        raw = ai_call(review_prompt, temp=0.1)
        review = parse_json(raw)
    except Exception:
        review = {'initial_review': 'pass', 'confidence': 50, 'concerns': 'AI review unavailable'}

    log('info', f'  🛡️ Triage review: {review.get("initial_review", "unknown")} (confidence: {review.get("confidence", "?")}%)')
    if review.get('concerns'):
        log('info', f'  🛡️ Concerns: {review.get("concerns", "")[:200]}')

    # If AI is very confident it's a false positive, reject immediately
    if review.get('initial_review') == 'fail' and review.get('confidence', 0) >= 80:
        return {
            'confirmed': False,
            'reason': f'Triage AI review rejected with {review.get("confidence")}% confidence: {review.get("concerns", "")}'
        }

    # ── Step 2: Generate a DIFFERENT verification payload ──
    verify_prompt = f"""Generate exactly ONE safe verification payload for a suspected {vtype} vulnerability.
This MUST be DIFFERENT from the original payload but test the SAME vulnerability type.

Original payload was: {original_payload}
Parameter: {target_param['name']}
URL: {ep['url']}
Method: {ep['method']}

SAFETY: The payload must be 100% non-destructive and read-only.
It should use a DIFFERENT technique than the original to independently verify the vulnerability.

For SQLi: if original was OR-based, try UNION or error-based or time-based
For XSS: if original was script tag, try img onerror or svg onload
For CMDi: if original was semicolon, try pipe or backticks
For LFI: if original was ../../../, try encoding or null byte

Respond with ONLY a JSON string (the single payload):
"verification_payload_here"""

    try:
        raw = ai_call(verify_prompt, temp=0.4)
        # Try to extract just the string
        raw = raw.strip().strip('"').strip("'")
        if raw.startswith('['):
            parsed = parse_json(raw)
            verify_payload = parsed[0] if parsed else None
        elif raw.startswith('{'):
            parsed = parse_json(raw)
            verify_payload = parsed.get('payload', None)
        else:
            verify_payload = raw
    except Exception:
        verify_payload = None

    if not verify_payload or not _is_payload_safe(verify_payload, vtype):
        # Use a different fallback payload than the original
        fallbacks = SAFE_FALLBACK_PAYLOADS.get(vtype, ['test'])
        verify_payload = None
        for fb in fallbacks:
            if fb != original_payload:
                verify_payload = fb
                break
        if not verify_payload:
            verify_payload = fallbacks[0] if fallbacks else 'test'

    log('info', f'  🛡️ Triage re-test with: {verify_payload}')

    # ── Step 3: Re-test with verification payload ──
    verify_resp = _send(session, ep, target_param['name'], verify_payload)
    if not verify_resp:
        return {
            'confirmed': False,
            'reason': 'Triage verification request failed (no response)'
        }

    log('info', f'  🛡️ Triage response: [{verify_resp["status_code"]}] {verify_resp["length"]} bytes')

    # ── Step 4: Analyze verification result ──
    verify_vuln, verify_evidence = _analyze(vtype, ep['url'], target_param['name'], verify_payload, baseline, verify_resp)

    if verify_vuln:
        log('ok', f'  🛡️ Triage re-test CONFIRMED with different payload!')
        return {
            'confirmed': True,
            'triage_evidence': f'Independently verified with payload: {verify_payload}. Evidence: {verify_evidence}',
            'triage_payload': verify_payload
        }

    # If re-test didn't confirm but AI initial review was positive with high confidence
    if review.get('initial_review') == 'pass' and review.get('confidence', 0) >= 85:
        log('info', f'  🛡️ Re-test inconclusive but AI review highly confident ({review.get("confidence")}%) — accepting')
        return {
            'confirmed': True,
            'triage_evidence': f'AI triage review confirmed with {review.get("confidence")}% confidence. Re-test inconclusive but original evidence compelling: {original_evidence}',
            'triage_payload': verify_payload
        }

    return {
        'confirmed': False,
        'reason': f'Triage re-test did not confirm. AI confidence: {review.get("confidence", "?")}%. Verification payload: {verify_payload}'
    }

def _extract_relevant(html):
    """Strip HTML boilerplate, return just the text content."""
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup(['script', 'style', 'head', 'nav', 'footer']):
        tag.decompose()
    text = soup.get_text(separator='\n', strip=True)
    pres = [p.get_text() for p in BeautifulSoup(html, 'html.parser').find_all('pre')]
    if pres:
        text = '\n'.join(pres) + '\n---FULL TEXT---\n' + text
    return text[:3000]

def _analyze(vtype, url, param, payload, baseline, resp):
    if not resp:
        return False, ""

    body = resp['body']
    bl_body = baseline['body'] if baseline else ''
    bl_len = baseline['length'] if baseline else 0
    atk_len = resp['length']

    # ── LOCAL PATTERN MATCHING ──────────────────────────────────────────

    if vtype == 'sqli':
        sql_errors = ['mysql_', 'You have an error in your SQL syntax',
                      'Warning: mysql', 'Unclosed quotation mark',
                      'SQLSTATE[', 'pg_query', 'ORA-', 'SQL syntax',
                      'sqlite3.OperationalError', 'psycopg2', 'MySQLdb',
                      'sqlalchemy.exc', 'unterminated quoted string',
                      'Microsoft OLE DB Provider', 'ODBC SQL Server Driver',
                      'JET Database Engine', 'Syntax error in query',
                      'MariaDB server version', 'valid MySQL result',
                      'Warning: pg_', 'supplied argument is not a valid']
        for err in sql_errors:
            if err.lower() in body.lower() and err.lower() not in bl_body.lower():
                return True, f"SQL error message found: {err}"

        # Multiple data rows returned (DVWA pattern)
        atk_pres = len(BeautifulSoup(body, 'html.parser').find_all('pre'))
        bl_pres = len(BeautifulSoup(bl_body, 'html.parser').find_all('pre'))
        if atk_pres > bl_pres and atk_pres >= 2:
            return True, f"Data leaked: {atk_pres} data rows vs {bl_pres} baseline"

        # Significantly larger response with data
        if atk_len > bl_len * 1.3 and atk_len - bl_len > 100:
            soup = BeautifulSoup(body, 'html.parser')
            pres = soup.find_all('pre')
            tds = soup.find_all('td')
            if pres or len(tds) > 4:
                return True, f"Response significantly larger ({atk_len} vs {bl_len} bytes) with data output"

        # Time-based blind SQLi detection
        bl_time = baseline.get('baseline_time_avg', baseline.get('response_time', 0)) if baseline else 0
        atk_time = resp.get('response_time', 0)
        payload_lower = payload.lower()
        if any(kw in payload_lower for kw in ['sleep', 'waitfor', 'pg_sleep', 'benchmark']):
            if atk_time > bl_time + 2.5 and atk_time > 3.0:
                return True, f"Time-based blind SQLi: response took {atk_time:.1f}s vs baseline {bl_time:.1f}s (delay payload: {payload[:50]})"

    elif vtype == 'xss':
        # ── STRICT XSS detection ──
        # Only confirm XSS if a JavaScript-executing payload is reflected.
        # HTML injection (<u>, <b>, <i>, etc.) is NOT XSS — it cannot execute JS.
        
        # These are the ONLY markers that prove JS execution is possible
        js_exec_markers = [
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg/onload=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe onload=alert(1)>',
            'javascript:alert(1)',
        ]
        
        # Check if a JS-executing payload is reflected unescaped
        for marker in js_exec_markers:
            if marker.lower() in body.lower() and marker.lower() not in bl_body.lower():
                return True, f"XSS confirmed — JS-executing payload reflected: {marker}"
        
        # Check if the full payload is reflected AND it contains JS execution capability
        if payload in body and payload not in bl_body:
            payload_lower = payload.lower()
            has_js = any(trigger in payload_lower for trigger in [
                '<script', 'onerror=', 'onload=', 'onfocus=', 'onmouseover=',
                'onclick=', 'onmouseenter=', 'javascript:', 'eval(',
                'expression(', 'onanimationend=', 'ontransitionend='
            ])
            if has_js:
                return True, f"XSS payload reflected unescaped with JS execution: {payload[:60]}"
            else:
                # It's HTML injection, not XSS — log but don't confirm as XSS
                log('info', f'  ℹ HTML injection detected (not XSS): {payload[:50]}')
                # Record as html_injection instead
                fid = fp('GET', url, param, 'html_injection')
                finding = {
                    'id': fid, 'url': url, 'method': 'GET',
                    'param': param, 'vuln_type': 'html_injection',
                    'payload': payload, 'evidence': f'HTML tags rendered but no JS execution possible: {payload[:60]}',
                    'severity': 'Low',
                    'confirmed': True,
                    'response_code': resp['status_code'],
                    'response_snippet': body[:500],
                    'timestamp': time.time()
                }
                if write_finding(finding):
                    socketio.emit('finding', finding)
                return False, ""

    elif vtype == 'cmdi':
        cmd_evidence = [
            ('uid=', 'Unix uid output found'),
            ('root:x:0:0:', '/etc/passwd content leaked'),
            ('root:x:0:0', 'System file contents revealed'),
            ('daemon:', 'System user list exposed'),
            ('www-data', 'Web server user info exposed'),
            ('bin/bash', 'Shell path revealed'),
            ('Linux ', 'OS info leaked via uname'),
            ('total ', 'Directory listing output (ls command)'),
            ('drwx', 'Directory permission listing leaked'),
            ('PING ', 'Ping command output detected'),
            ('TTL=', 'Ping TTL output detected'),
            ('bytes from', 'Ping response detected'),
        ]
        for marker, desc in cmd_evidence:
            if marker in body and marker not in bl_body:
                return True, desc

        if atk_len > bl_len + 50:
            extra = body[len(bl_body):] if len(body) > len(bl_body) else body
            if any(m in extra for m, _ in cmd_evidence):
                return True, "Command execution output detected"

        # Time-based blind CMDi detection
        bl_time = baseline.get('baseline_time_avg', baseline.get('response_time', 0)) if baseline else 0
        atk_time = resp.get('response_time', 0)
        payload_lower = payload.lower()
        if any(kw in payload_lower for kw in ['sleep', 'ping -c', 'timeout']):
            if atk_time > bl_time + 2.5 and atk_time > 3.0:
                return True, f"Time-based blind CMDi: response took {atk_time:.1f}s vs baseline {bl_time:.1f}s (delay payload: {payload[:50]})"

    elif vtype == 'lfi':
        lfi_markers = [
            ('root:x:0:0:', '/etc/passwd file contents exposed'),
            ('[boot loader]', 'Windows boot.ini exposed'),
            ('root:*:0:0:', '/etc/passwd (BSD) exposed'),
            ('[extensions]', 'PHP ini file exposed'),
            ('[PHP]', 'PHP configuration exposed'),
            ('<?php', 'PHP source code exposed'),
        ]
        for marker, desc in lfi_markers:
            if marker in body and marker not in bl_body:
                return True, desc

    elif vtype == 'idor':
        # Stricter IDOR check — require meaningful data difference
        if atk_len != bl_len and abs(atk_len - bl_len) > 50:
            bl_text = _extract_relevant(bl_body)
            atk_text = _extract_relevant(body)
            # Both must have real content and be substantially different
            if len(bl_text) > 20 and len(atk_text) > 20:
                # Check similarity — if texts share less than 70% content, it might be different user data
                common = set(bl_text.split()) & set(atk_text.split())
                total_words = max(len(set(bl_text.split())), len(set(atk_text.split())), 1)
                similarity = len(common) / total_words
                if similarity < 0.7:
                    return True, f"Different data returned for different ID (similarity: {similarity:.0%})"

    elif vtype == 'open_redirect':
        if resp['status_code'] in (301, 302, 303, 307):
            location = resp.get('headers', {}).get('Location', '')
            if location and ('evil.com' in location or payload in location):
                return True, f"Open redirect confirmed: Location header points to {location[:100]}"

    # ── AI Analysis as fallback ──────────────────────────────────────────
    try:
        bl_text = _extract_relevant(bl_body)[:1500]
        atk_text = _extract_relevant(body)[:2000]

        prompt = f"""Determine if this web vulnerability was ACTUALLY exploited. Be VERY strict.

VULN: {vtype} | URL: {url} | PARAM: {param} | PAYLOAD: {payload}

BASELINE: status={baseline['status_code'] if baseline else 'N/A'} len={bl_len}
{bl_text}

ATTACK: status={resp['status_code']} len={atk_len}
{atk_text}

STRICT RULES:
- SQLi: ONLY confirm if you see SQL error messages, extra database rows, or data from other users. Response size differences alone are NOT proof.
- XSS: ONLY confirm if a JavaScript-executing payload (<script>, onerror=, onload=) appears UNESCAPED in the response. If only benign HTML tags like <u>, <b>, <i> are reflected, that is HTML injection NOT XSS. HTML injection is NOT XSS.
- CMDi: ONLY confirm if you see actual OS command output (uid=, /etc/passwd contents, directory listings) that was NOT in the baseline.
- LFI: ONLY confirm if system file contents appear.
- IDOR: ONLY confirm if you see DIFFERENT user's private data.
- Open Redirect: ONLY confirm if Location header redirects to attacker-controlled domain.

When in doubt, say NOT vulnerable. False positives are worse than false negatives.

ONLY JSON: {{"vulnerable": true/false, "evidence": "proof"}}"""

        raw = ai_call(prompt, temp=0.1)
        result = parse_json(raw)
        if isinstance(result, dict):
            return result.get('vulnerable', False), result.get('evidence', '')
    except Exception:
        pass

    return False, ""


# ─── Stage 3.5: Security Header + Clickjacking Check ────────────────────────

def step_header_check(target_url, session):
    """Check for missing security headers and clickjacking."""
    log('info', '═══ STAGE 3.5: SECURITY HEADERS & CLICKJACKING ═══')

    try:
        r = session.get(target_url, timeout=10)
        headers = {k.lower(): v for k, v in r.headers.items()}

        # ── Clickjacking check (separate, higher severity) ──
        has_xfo = 'x-frame-options' in headers
        has_csp_frame = False
        csp_value = headers.get('content-security-policy', '')
        if csp_value:
            has_csp_frame = 'frame-ancestors' in csp_value.lower()

        if not has_xfo and not has_csp_frame:
            log('warn', '  🖼️ CLICKJACKING VULNERABLE — No X-Frame-Options or frame-ancestors CSP!')
            log('warn', '  ⚠ This site can be embedded in an iframe by any attacker')

            fid = fp('GET', target_url, 'X-Frame-Options', 'clickjacking')
            finding = {
                'id': fid, 'url': target_url, 'method': 'GET',
                'param': 'X-Frame-Options / CSP frame-ancestors',
                'vuln_type': 'clickjacking',
                'payload': f'<iframe src="{target_url}" width="800" height="600"></iframe>',
                'evidence': 'Missing X-Frame-Options header AND no frame-ancestors in CSP. '
                            'The page can be embedded in a malicious iframe for UI redressing attacks.',
                'severity': 'Medium',
                'confirmed': True,
                'response_code': r.status_code,
                'response_snippet': f'Response headers:\n'
                    f'X-Frame-Options: MISSING\n'
                    f'Content-Security-Policy: {csp_value[:200] if csp_value else "MISSING"}\n\n'
                    f'PoC: Create an HTML file with:\n'
                    f'<iframe src="{target_url}" width="100%" height="600"></iframe>',
                'timestamp': time.time()
            }
            if write_finding(finding):
                socketio.emit('finding', finding)
        else:
            protection = []
            if has_xfo:
                protection.append(f'X-Frame-Options: {headers["x-frame-options"]}')
            if has_csp_frame:
                protection.append(f'CSP frame-ancestors present')
            log('ok', f'  ✅ Clickjacking protected: {", ".join(protection)}')

        # ── Other security headers ──
        other_headers = {
            'x-content-type-options': 'MIME sniffing protection (X-Content-Type-Options)',
            'x-xss-protection': 'Browser XSS filter (X-XSS-Protection)',
            'strict-transport-security': 'HSTS (Strict-Transport-Security)',
            'referrer-policy': 'Referrer policy',
        }

        missing = []
        present = []
        for header, description in other_headers.items():
            if header in headers:
                present.append(f'  ✅ {description}: {headers[header][:80]}')
            else:
                missing.append(description)

        for p in present:
            log('ok', p)

        if missing:
            log('warn', f'  ⚠ Other missing headers:')
            for m in missing:
                log('warn', f'    ✗ {m}')

            fid = fp('GET', target_url, 'headers', 'security_headers')
            finding = {
                'id': fid, 'url': target_url, 'method': 'GET',
                'param': 'HTTP Headers', 'vuln_type': 'security_headers',
                'payload': 'N/A', 'evidence': f'Missing: {", ".join(missing)}',
                'severity': 'Info',
                'confirmed': True,
                'response_code': r.status_code,
                'response_snippet': json.dumps(dict(r.headers), indent=2)[:500],
                'timestamp': time.time()
            }
            if write_finding(finding):
                socketio.emit('finding', finding)

    except Exception as e:
        log('error', f'Header check error: {e}')


# ─── Stage 3.6: Static Frontend Analysis ────────────────────────────────────

# Known vulnerable JS library versions (library name → [(version_regex, CVE/issue, severity)])
VULNERABLE_LIBRARIES = {
    'jquery': [
        (r'[12]\.\d+\.\d+', '< 3.5.0', 'XSS via jQuery.htmlPrefilter — CVE-2020-11022/11023', 'Medium'),
        (r'1\.\d+\.\d+', '< 2.0.0', 'Multiple XSS and DoS vulnerabilities', 'High'),
    ],
    'bootstrap': [
        (r'[23]\.\d+\.\d+', '< 4.3.1', 'XSS via data-template — CVE-2019-8331', 'Medium'),
        (r'3\.3\.[0-6]', '3.3.0-3.3.6', 'XSS in tooltip/popover — CVE-2018-14041', 'Medium'),
    ],
    'angular': [
        (r'1\.\d+\.\d+', '1.x (EOL)', 'AngularJS 1.x is end-of-life, multiple known XSS vectors', 'High'),
    ],
    'angularjs': [
        (r'1\.\d+\.\d+', '1.x (EOL)', 'AngularJS 1.x is end-of-life — sandbox escape CVEs', 'High'),
    ],
    'lodash': [
        (r'4\.[01][0-6]?\.\d+', '< 4.17.21', 'Prototype pollution — CVE-2021-23337', 'High'),
    ],
    'moment': [
        (r'\d+\.\d+\.\d+', 'any', 'Moment.js is deprecated — ReDoS in date parsing — CVE-2022-31129', 'Low'),
    ],
    'vue': [
        (r'2\.[0-5]\.\d+', '< 2.6.0', 'XSS via template injection — CVE-2018-6341', 'Medium'),
    ],
    'react-dom': [
        (r'16\.[0-7]\.\d+', '< 16.8.0', 'XSS via dangerouslySetInnerHTML edge cases', 'Low'),
    ],
    'dompurify': [
        (r'2\.[0-2]\.\d+', '< 2.3.0', 'Mutation XSS bypass — CVE-2021-23648', 'High'),
    ],
    'handlebars': [
        (r'[0-3]\.\d+\.\d+', '< 4.7.7', 'Prototype pollution — CVE-2021-23369', 'High'),
    ],
    'axios': [
        (r'0\.\d+\.\d+', '< 1.0.0', 'SSRF via follow redirects — CVE-2023-45857', 'Medium'),
    ],
}

# Secret/API key patterns
SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key exposed'),
    (r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', 'Secret/Password exposed'),
    (r'(?:aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Z0-9]{16,})["\']', 'AWS Key exposed'),
    (r'(?:AKIA[0-9A-Z]{16})', 'AWS Access Key ID'),
    (r'(?:sk-[a-zA-Z0-9]{20,})', 'OpenAI/Stripe Secret Key'),
    (r'(?:ghp_[a-zA-Z0-9]{36})', 'GitHub Personal Access Token'),
    (r'(?:glpat-[a-zA-Z0-9\-]{20,})', 'GitLab Access Token'),
    (r'(?:Bearer\s+[a-zA-Z0-9_\-\.]{20,})', 'Bearer Token exposed'),
    (r'(?:mongodb(?:\+srv)?://[^"\'\s]+)', 'MongoDB Connection String'),
    (r'(?:postgres(?:ql)?://[^"\'\s]+)', 'PostgreSQL Connection String'),
    (r'(?:mysql://[^"\'\s]+)', 'MySQL Connection String'),
    (r'(?:firebase[a-zA-Z]*\.com/[^"\'\s]+)', 'Firebase URL exposed'),
    (r'(?:sk-or-v1-[a-f0-9]{64})', 'OpenRouter API Key'),
]

# Insecure JS patterns
INSECURE_JS_PATTERNS = [
    (r'\beval\s*\(', 'eval() usage — code injection risk', 'Medium'),
    (r'\.innerHTML\s*=', 'innerHTML assignment — DOM XSS risk', 'Low'),
    (r'document\.write\s*\(', 'document.write() — DOM XSS risk', 'Low'),
    (r'window\.location\s*=\s*[^;]*(?:get|query|param|hash|search)', 'DOM-based open redirect risk', 'Medium'),
    (r'\.setAttribute\s*\(\s*["\'](?:on\w+|href|src|action)', 'Dynamic attribute setting — potential XSS sink', 'Low'),
    (r'new\s+Function\s*\(', 'new Function() — code injection risk', 'Medium'),
    (r'setTimeout\s*\(\s*["\']', 'setTimeout with string — eval equivalent', 'Medium'),
    (r'setInterval\s*\(\s*["\']', 'setInterval with string — eval equivalent', 'Medium'),
    (r'location\s*\.\s*(?:href|replace|assign)\s*=\s*(?:.*(?:location|document|window)\s*\.)', 'DOM-based redirect from user input', 'Medium'),
    (r'(?:localStorage|sessionStorage)\.setItem\s*\([^)]*(?:password|token|secret|key)', 'Sensitive data in browser storage', 'Medium'),
    (r'document\.cookie\s*=', 'Cookie manipulation via JS — potential session issues', 'Low'),
]


def step_static_analysis(target_url, session, max_resources=30):
    """Static analyzer: scan frontend HTML, JS, CSS for security issues."""
    log('info', '═══ STAGE 3.6: STATIC FRONTEND ANALYSIS ═══')

    parsed_base = urlparse(target_url)
    base_domain = parsed_base.netloc

    issues_found = 0

    try:
        # ── Step 1: Fetch main page and discover resources ──
        r = session.get(target_url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')

        # Collect all script, link, and resource URLs
        resources = []

        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                resources.append({
                    'url': urljoin(target_url, src),
                    'type': 'js',
                    'has_sri': bool(script.get('integrity')),
                    'crossorigin': script.get('crossorigin'),
                    'tag': str(script)[:200]
                })
            # Inline scripts
            if script.string and len(script.string.strip()) > 10:
                resources.append({
                    'url': target_url,
                    'type': 'inline_js',
                    'content': script.string,
                    'tag': 'inline'
                })

        for link in soup.find_all('link', rel=True):
            href = link.get('href')
            if href and 'stylesheet' in ' '.join(link.get('rel', [])):
                resources.append({
                    'url': urljoin(target_url, href),
                    'type': 'css',
                    'has_sri': bool(link.get('integrity')),
                    'tag': str(link)[:200]
                })

        log('info', f'  Found {len(resources)} frontend resources')

        # ── Step 2: Analyze the main HTML page ──
        log('info', '  📄 Analyzing main HTML page...')
        issues_found += _analyze_html(target_url, r.text, base_domain)

        # ── Step 3: Check each external resource ──
        js_count = 0
        for res in resources[:max_resources]:
            if is_cancelled():
                break

            if res['type'] == 'inline_js':
                log('info', f'  📜 Analyzing inline script...')
                issues_found += _analyze_js(target_url, res['content'], 'inline script')
                continue

            if res['type'] == 'js':
                # Check SRI on CDN scripts
                res_parsed = urlparse(res['url'])
                is_cdn = res_parsed.netloc != base_domain
                if is_cdn and not res.get('has_sri'):
                    log('warn', f'  ⚠ Missing SRI on CDN script: {res["url"][:80]}')
                    fid = fp('GET', res['url'], 'integrity', 'missing_sri')
                    finding = {
                        'id': fid, 'url': res['url'], 'method': 'GET',
                        'param': 'integrity attribute',
                        'vuln_type': 'security_headers',
                        'payload': 'N/A',
                        'evidence': f'CDN-hosted script loaded without Subresource Integrity (SRI). '
                                    f'If the CDN is compromised, malicious code could be injected. '
                                    f'Script: {res["url"][:100]}',
                        'severity': 'Medium',
                        'confirmed': True,
                        'response_code': 200,
                        'response_snippet': res['tag'][:500],
                        'timestamp': time.time()
                    }
                    if write_finding(finding):
                        socketio.emit('finding', finding)
                        issues_found += 1

                # Fetch and analyze JS content
                try:
                    r_js = session.get(res['url'], timeout=8)
                    if r_js.status_code == 200 and len(r_js.text) > 0:
                        js_count += 1
                        short_name = res['url'].split('/')[-1].split('?')[0] or 'script.js'
                        log('info', f'  📜 Analyzing JS: {short_name} ({len(r_js.text)} bytes)')
                        issues_found += _analyze_js(res['url'], r_js.text, short_name)
                except Exception:
                    pass

            elif res['type'] == 'css':
                try:
                    r_css = session.get(res['url'], timeout=8)
                    if r_css.status_code == 200:
                        issues_found += _analyze_css(res['url'], r_css.text)
                except Exception:
                    pass

            time.sleep(0.1)

        log('ok', f'  Static analysis complete: {issues_found} issues found across {len(resources)} resources')

    except Exception as e:
        log('error', f'  Static analysis error: {e}')

    return issues_found


def _analyze_html(url, html, base_domain):
    """Analyze HTML for security issues."""
    issues = 0
    soup = BeautifulSoup(html, 'html.parser')

    # ── Mixed content check ──
    if url.startswith('https://'):
        http_resources = []
        for tag in soup.find_all(['script', 'link', 'img', 'iframe', 'object', 'embed']):
            src = tag.get('src') or tag.get('href') or ''
            if src.startswith('http://'):
                http_resources.append(src[:80])
        if http_resources:
            log('warn', f'  ⚠ Mixed content: {len(http_resources)} HTTP resources on HTTPS page')
            fid = fp('GET', url, 'mixed_content', 'security_headers')
            finding = {
                'id': fid, 'url': url, 'method': 'GET',
                'param': 'Mixed Content',
                'vuln_type': 'security_headers',
                'payload': 'N/A',
                'evidence': f'HTTPS page loads {len(http_resources)} resources over HTTP. '
                            f'Examples: {", ".join(http_resources[:3])}',
                'severity': 'Medium',
                'confirmed': True,
                'response_code': 200,
                'response_snippet': '\n'.join(http_resources[:5]),
                'timestamp': time.time()
            }
            if write_finding(finding):
                socketio.emit('finding', finding)
                issues += 1

    # ── Forms posting to HTTP ──
    for form in soup.find_all('form'):
        action = form.get('action', '')
        if action.startswith('http://') and url.startswith('https://'):
            log('warn', f'  ⚠ Form submits to HTTP: {action[:80]}')
            issues += 1

    # ── Sensitive HTML comments ──
    comments = soup.find_all(string=lambda text: isinstance(text, type(soup.new_string(''))) and '<!--' in str(text) or (hasattr(text, 'element') if False else False))
    import re as _re
    comment_texts = _re.findall(r'<!--(.*?)-->', html, _re.DOTALL)
    sensitive_keywords = ['password', 'secret', 'api_key', 'apikey', 'token', 'admin',
                          'debug', 'todo', 'fixme', 'hack', 'temp', 'username',
                          'database', 'db_', 'mysql', 'postgres', 'internal',
                          'private', 'credentials', 'config']
    for comment in comment_texts:
        comment_lower = comment.lower().strip()
        if len(comment_lower) > 5:  # Skip tiny comments
            for kw in sensitive_keywords:
                if kw in comment_lower:
                    log('warn', f'  ⚠ Sensitive HTML comment contains "{kw}": {comment_lower[:60]}...')
                    fid = fp('GET', url, f'comment_{kw}', 'info_disclosure')
                    finding = {
                        'id': fid, 'url': url, 'method': 'GET',
                        'param': f'HTML Comment ({kw})',
                        'vuln_type': 'security_headers',
                        'payload': 'N/A',
                        'evidence': f'HTML comment contains sensitive keyword "{kw}": {comment_lower[:120]}',
                        'severity': 'Low',
                        'confirmed': True,
                        'response_code': 200,
                        'response_snippet': f'<!-- {comment_lower[:300]} -->',
                        'timestamp': time.time()
                    }
                    if write_finding(finding):
                        socketio.emit('finding', finding)
                        issues += 1
                    break  # One finding per comment

    # ── Autocomplete on password fields ──
    for inp in soup.find_all('input', {'type': 'password'}):
        if inp.get('autocomplete', '').lower() not in ('off', 'new-password', 'current-password'):
            log('warn', '  ⚠ Password field without autocomplete="off"')
            issues += 1

    # ── Source map references ──
    if '//# sourceMappingURL=' in html:
        log('warn', '  ⚠ Source map reference found — may expose original source code')
        issues += 1

    return issues


def _analyze_js(url, content, name):
    """Analyze JavaScript content for vulnerabilities."""
    issues = 0

    # ── Library version detection ──
    for lib_name, vulns in VULNERABLE_LIBRARIES.items():
        # Common version patterns in JS files
        version_patterns = [
            rf'(?:{lib_name})\s*[vV]?(\d+\.\d+\.\d+)',
            rf'["\']?version["\']?\s*[:=]\s*["\'](\d+\.\d+\.\d+)',
            rf'{lib_name}[.-](\d+\.\d+\.\d+)',
            rf'/\*[^*]*{lib_name}\s+v?(\d+\.\d+\.\d+)',
        ]
        for vp in version_patterns:
            matches = re.findall(vp, content[:5000], re.IGNORECASE)
            if matches:
                version = matches[0]
                for vuln_pattern, version_range, description, severity in vulns:
                    if re.match(vuln_pattern, version):
                        log('warn', f'  🔴 OUTDATED: {lib_name} v{version} ({version_range}) — {description}')
                        fid = fp('GET', url, f'{lib_name}_{version}', 'outdated_library')
                        finding = {
                            'id': fid, 'url': url, 'method': 'GET',
                            'param': f'{lib_name} v{version}',
                            'vuln_type': 'security_headers',
                            'payload': 'N/A',
                            'evidence': f'Outdated library: {lib_name} v{version} ({version_range}). {description}',
                            'severity': severity,
                            'confirmed': True,
                            'response_code': 200,
                            'response_snippet': f'Detected in: {name}\nVersion: {version}\nVulnerability: {description}',
                            'timestamp': time.time()
                        }
                        if write_finding(finding):
                            socketio.emit('finding', finding)
                            issues += 1
                        break
                break  # Stop checking patterns once version found

    # ── Secret/API key detection ──
    for pattern, desc in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            for match in matches[:2]:  # Max 2 per pattern
                masked = match[:6] + '...' + match[-4:] if len(match) > 10 else '***'
                log('warn', f'  🔑 {desc}: {masked} in {name}')
                fid = fp('GET', url, f'secret_{desc[:20]}', 'info_disclosure')
                finding = {
                    'id': fid, 'url': url, 'method': 'GET',
                    'param': desc,
                    'vuln_type': 'security_headers',
                    'payload': 'N/A',
                    'evidence': f'{desc} found in {name}: {masked}',
                    'severity': 'High',
                    'confirmed': True,
                    'response_code': 200,
                    'response_snippet': f'Pattern: {desc}\nFile: {name}\nValue: {masked}',
                    'timestamp': time.time()
                }
                if write_finding(finding):
                    socketio.emit('finding', finding)
                    issues += 1

    # ── Insecure JS patterns ──
    for pattern, desc, severity in INSECURE_JS_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            count = min(len(matches), 3)
            log('warn', f'  ⚠ {desc} ({count}x in {name})')
            fid = fp('GET', url, f'jspattern_{desc[:20]}', 'insecure_code')
            finding = {
                'id': fid, 'url': url, 'method': 'GET',
                'param': f'JS Pattern: {desc[:50]}',
                'vuln_type': 'security_headers',
                'payload': 'N/A',
                'evidence': f'{desc} — found {count} occurrence(s) in {name}',
                'severity': severity,
                'confirmed': True,
                'response_code': 200,
                'response_snippet': f'Pattern: {pattern}\nFile: {name}\nOccurrences: {count}',
                'timestamp': time.time()
            }
            if write_finding(finding):
                socketio.emit('finding', finding)
                issues += 1

    # ── Exposed internal URLs/endpoints ──
    endpoint_patterns = [
        r'(?:https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:\d]*/[^\s"\']+)',
        r'(?:/api/[a-zA-Z0-9_/\-]+)',
        r'(?:/admin[/a-zA-Z0-9_\-]*)',
        r'(?:/internal[/a-zA-Z0-9_\-]*)',
        r'(?:/debug[/a-zA-Z0-9_\-]*)',
    ]
    for ep in endpoint_patterns:
        matches = re.findall(ep, content)
        if matches:
            unique = list(set(matches))[:5]
            for endpoint in unique:
                if 'localhost' in endpoint or '127.0.0.1' in endpoint or '/api/' in endpoint:
                    log('info', f'  📡 Internal endpoint in {name}: {endpoint[:80]}')

    # ── Source map check ──
    if '//# sourceMappingURL=' in content or '//@ sourceMappingURL=' in content:
        map_match = re.search(r'//[#@] sourceMappingURL=(\S+)', content)
        if map_match:
            log('warn', f'  ⚠ Source map reference in {name}: {map_match.group(1)[:60]}')
            issues += 1

    # ── Debug artifacts ──
    debug_patterns = [
        (r'\bconsole\.(log|debug|info|warn|error)\s*\(', 'console.log() in production'),
        (r'\bdebugger\b', 'debugger statement in production'),
    ]
    for dp, desc in debug_patterns:
        if re.search(dp, content):
            debug_count = len(re.findall(dp, content))
            if debug_count > 3:  # Only flag if excessive
                log('info', f'  ℹ {desc}: {debug_count}x in {name}')

    return issues


def _analyze_css(url, content):
    """Analyze CSS for security issues."""
    issues = 0

    # External resource loading via CSS
    imports = re.findall(r'@import\s+(?:url\s*\()?["\']?(https?://[^"\')\s]+)', content)
    if imports:
        for imp in imports[:3]:
            if 'http://' in imp:
                log('warn', f'  ⚠ CSS imports over HTTP: {imp[:80]}')
                issues += 1

    # CSS expressions (IE-specific XSS vector)
    if 'expression(' in content.lower():
        log('warn', '  ⚠ CSS expression() found — potential XSS (IE)')
        issues += 1

    # CSS behavior/binding (security risk)
    if 'behavior:' in content.lower() or '-moz-binding:' in content.lower():
        log('warn', '  ⚠ CSS behavior/binding found — potential code execution')
        issues += 1

    return issues


# ─── Stage 4: Reports ───────────────────────────────────────────────────────

def step_reports():
    log('info', '═══ STAGE 4: REPORTS ═══')
    findings = [f for f in read_findings() if f.get('confirmed')]

    for i, f in enumerate(findings):
        if is_cancelled():
            break

        rpath = Path('reports') / f"{f['id']}.md"
        if rpath.exists():
            log('info', f'  Report {rpath.name} already exists')
            continue

        emit_progress(i + 1, len(findings), 'report')

        prompt = f"""Write a professional bug bounty report.

VULN: {f['vuln_type']} | SEVERITY: {f['severity']}
URL: {f['url']} | METHOD: {f['method']} | PARAM: {f['param']}
PAYLOAD: {f['payload']}
EVIDENCE: {f['evidence']}
RESPONSE CODE: {f.get('response_code', '')}
RESPONSE: {f.get('response_snippet', '')[:800]}

Format:
# {f['severity']} — [Title]
## Summary
## Affected Endpoint
## Steps to Reproduce (with curl command)
## Impact
## Remediation"""

        try:
            report = ai_call(prompt, temp=0.3)
            rpath.write_text(report)
            log('ok', f'  Report generated: {rpath.name}')
        except Exception as e:
            rpath.write_text(
                f"# {f['severity']} — {f['vuln_type'].upper()} in {f['param']}\n\n"
                f"**URL:** {f['url']}\n**Method:** {f['method']}\n"
                f"**Payload:** `{f['payload']}`\n**Evidence:** {f['evidence']}\n"
            )
            log('warn', f'  Template report saved ({e})')


# ─── Pipeline ────────────────────────────────────────────────────────────────

def run_pipeline(target_url, cookies_str='', auto_login=True, username='', password='', static_analysis=True, triage_agent=True):
    global scan_active
    start = time.time()
    scan_cancel.clear()

    try:
        log('info', '═══ SCAN STARTED ═══')
        log('info', f'Target: {target_url}')
        log('info', f'Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        log('info', f'AI: {AI_PROVIDER.upper()}')

        is_dvwa = False

        # ── Detect target type & setup session ──
        if auto_login:
            try:
                test_session = create_session()
                r_check = test_session.get(target_url, timeout=8, allow_redirects=True)
                page_lower = r_check.text.lower()
                is_dvwa = 'damn vulnerable web application' in page_lower or 'dvwa' in page_lower
            except Exception:
                is_dvwa = False

            if is_dvwa:
                log('info', '🎯 DVWA detected — attempting auto-login')
                session = dvwa_auto_login(target_url, username or 'admin', password or 'password')
                if not session:
                    log('error', 'DVWA auto-login failed. Try providing cookies manually.')
                    return
            elif username and password:
                log('info', '🔑 Credentials provided — attempting generic auto-login')
                session = generic_auto_login(target_url, username, password)
                if not session:
                    log('warn', 'Generic login failed — continuing without auth')
                    session = create_session()
            else:
                log('info', '🌐 Generic target — scanning without authentication')
                session = create_session()
        else:
            session = create_session(cookies_str)
            # Verify session
            try:
                r = session.get(target_url, timeout=10)
                if 'login.php' in r.url and 'login' not in target_url.lower():
                    log('error', 'Cookie session invalid — redirected to login.')
                    return
                log('ok', 'Cookie session verified')
            except Exception as e:
                log('error', f'Session verification failed: {e}')
                return

        if is_cancelled():
            log('warn', 'Scan cancelled')
            return

        # ── Stage 0: Fingerprint & Recon ──
        socketio.emit('stage', {'stage': 'fingerprint', 'status': 'active'})
        fingerprint = step_fingerprint(target_url, session)
        socketio.emit('stage', {'stage': 'fingerprint', 'status': 'done'})

        # ── Stage 1: Crawl ──
        socketio.emit('stage', {'stage': 'crawl', 'status': 'active'})
        endpoints, detected_dvwa = step_crawl(target_url, session)
        is_dvwa = is_dvwa or detected_dvwa
        socketio.emit('stage', {'stage': 'crawl', 'status': 'done'})

        if is_cancelled():
            log('warn', 'Scan cancelled after crawl')
            return

        if not endpoints:
            log('warn', 'No endpoints found. The target may require authentication or has no forms/queries.')
            socketio.emit('stage', {'stage': 'complete', 'status': 'done'})
            return

        # ── Stage 2: Classify ──
        socketio.emit('stage', {'stage': 'classify', 'status': 'active'})
        classified = step_classify(endpoints)
        socketio.emit('stage', {'stage': 'classify', 'status': 'done'})

        if is_cancelled():
            log('warn', 'Scan cancelled after classify')
            return

        # ── Stage 3: Attack ──
        socketio.emit('stage', {'stage': 'attack', 'status': 'active'})
        step_attack(classified, session, is_dvwa, fingerprint=fingerprint)
        socketio.emit('stage', {'stage': 'attack', 'status': 'done'})

        if is_cancelled():
            log('warn', 'Scan cancelled after attack')
            return

        # ── Stage 3.5: Security Headers ──
        step_header_check(target_url, session)

        # ── Stage 3.6: Static Frontend Analysis ──
        if static_analysis and not is_cancelled():
            socketio.emit('stage', {'stage': 'static_analysis', 'status': 'active'})
            step_static_analysis(target_url, session)
            socketio.emit('stage', {'stage': 'static_analysis', 'status': 'done'})
        elif not static_analysis:
            log('info', '  ⏭ Static analysis skipped (disabled)')

        # ── Stage 4: Reports ──
        socketio.emit('stage', {'stage': 'report', 'status': 'active'})
        step_reports()
        socketio.emit('stage', {'stage': 'report', 'status': 'done'})

        # ── Done ──
        dur = round(time.time() - start, 1)
        confirmed = [f for f in read_findings() if f.get('confirmed')]
        severity_breakdown = {}
        for f in confirmed:
            sev = f.get('severity', 'Unknown')
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        socketio.emit('scan_complete', {
            'duration': dur,
            'total': len(read_findings()),
            'confirmed': len(confirmed),
            'severity': severity_breakdown,
            'cancelled': is_cancelled()
        })
        log('ok', f'═══ SCAN COMPLETE: {len(confirmed)} vulns in {dur}s ═══')

    except Exception as e:
        log('error', f'Pipeline error: {e}')
        import traceback
        log('error', traceback.format_exc())
    finally:
        scan_active = False
        socketio.emit('stage', {'stage': 'complete', 'status': 'done'})


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_file('static/index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_active
    if scan_active:
        return jsonify({'error': 'Scan already running'}), 409

    data = request.get_json()
    url = data.get('target_url', '').strip()
    cookies = data.get('cookies', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    static_analysis = data.get('static_analysis', True)
    triage_agent = data.get('triage_agent', True)

    if not url:
        return jsonify({'error': 'URL required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Clear previous findings
    Path('findings.json').write_text('[]')

    auto = not bool(cookies)

    scan_active = True
    scan_cancel.clear()
    threading.Thread(
        target=run_pipeline,
        args=(url, cookies, auto, username, password, static_analysis, triage_agent),
        daemon=True
    ).start()
    return jsonify({'status': 'started'})

@app.route('/scan/cancel', methods=['POST'])
def cancel_scan():
    global scan_active
    if not scan_active:
        return jsonify({'error': 'No scan running'}), 409
    scan_cancel.set()
    log('warn', '⚠ Scan cancellation requested...')
    return jsonify({'status': 'cancelling'})

@app.route('/findings')
def get_findings():
    return jsonify(read_findings())

@app.route('/reports/<path:filename>')
def get_report(filename):
    p = Path('reports') / Path(filename).name
    if not p.exists():
        return 'Report not found', 404
    return p.read_text(), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/status')
def status():
    return jsonify({
        'active': scan_active,
        'ai_provider': AI_PROVIDER,
        'findings_count': len(read_findings())
    })

@app.route('/export')
def export_findings():
    """Export all findings as JSON."""
    findings = read_findings()
    return jsonify(findings), 200, {
        'Content-Disposition': 'attachment; filename=findings.json'
    }

@socketio.on('connect')
def on_connect():
    log('info', '🔌 Dashboard connected')

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', '7331'))
    print(f"\n  🎯 AI-Powered Bug Bounty Scanner")
    print(f"  🌐 http://127.0.0.1:{port}")
    print(f"  🤖 AI Provider: {AI_PROVIDER.upper()}")
    print(f"  📁 Reports: ./reports/")
    print()
    socketio.run(app, host='127.0.0.1', port=port, debug=False, allow_unsafe_werkzeug=True)
