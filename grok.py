import os, json, random, string, time, re, struct, argparse, socket
import threading
import concurrent.futures
import sys
from urllib.parse import urljoin, urlparse
from curl_cffi import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

load_dotenv()

from email_service import EmailService
from YesCaptcha_service import TurnstileService, CaptchaAuthError, captcha_solver_mode

# Base config
site_url = "https://accounts.x.ai"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
_proxy = str(os.getenv("GROK_PROXY") or "").strip()
PROXIES = {"http": _proxy, "https": _proxy} if _proxy else None
adb_rotate_enabled = False
adb_serial = None
adb_every = 3

TOR_BROWSER_SOCKS = ("127.0.0.1", 9150)  # Tor Browser
TOR_DAEMON_SOCKS = ("127.0.0.1", 9050)   # system tor


def _port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def configure_proxy(use_tor: bool = False) -> None:
    """Set module-level _proxy / PROXIES. --tor uses Tor Browser SOCKS (9150, else 9050)."""
    global _proxy, PROXIES
    if use_tor:
        explicit = str(os.getenv("TOR_PROXY") or "").strip()
        if explicit:
            _proxy = explicit
        elif _port_open(*TOR_BROWSER_SOCKS):
            _proxy = f"socks5h://{TOR_BROWSER_SOCKS[0]}:{TOR_BROWSER_SOCKS[1]}"
        elif _port_open(*TOR_DAEMON_SOCKS):
            _proxy = f"socks5h://{TOR_DAEMON_SOCKS[0]}:{TOR_DAEMON_SOCKS[1]}"
        else:
            print("[-] Tor SOCKS not found. Start Tor Browser (proxy 127.0.0.1:9150), then retry --tor")
            sys.exit(1)
        os.environ["GROK_PROXY"] = _proxy
    else:
        _proxy = str(os.getenv("GROK_PROXY") or "").strip()
    PROXIES = {"http": _proxy, "https": _proxy} if _proxy else None

# Runtime config filled during init
config = {
    "site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
    "action_id": None,
    "ts_action": "",
    "ts_cdata": "",
    "state_tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
}

def extract_turnstile_widget_params(text: str) -> dict:
    """Pull Turnstile sitekey / action / cdata from HTML or a JS chunk."""
    out = {}
    if not text:
        return out
    key_m = re.search(r'sitekey["\']?\s*[:=]\s*["\'](0x4[a-zA-Z0-9_-]+)', text)
    if key_m:
        out["site_key"] = key_m.group(1)
        window = text[max(0, key_m.start() - 500): key_m.end() + 500]
        act = re.search(r'\baction["\']?\s*[:=]\s*["\']([^"\']{1,80})', window)
        if act and not re.fullmatch(r"[a-fA-F0-9]{20,}", act.group(1)):
            out["ts_action"] = act.group(1)
        cdata = re.search(r'\bcdata["\']?\s*[:=]\s*["\']([^"\']{1,80})', window)
        if cdata:
            out["ts_cdata"] = cdata.group(1)
    data_act = re.search(r'data-action=["\']([^"\']+)', text)
    if data_act and "ts_action" not in out:
        out["ts_action"] = data_act.group(1)
    data_cd = re.search(r'data-cdata=["\']([^"\']+)', text)
    if data_cd and "ts_cdata" not in out:
        out["ts_cdata"] = data_cd.group(1)
    return out

post_lock = threading.Lock()
file_lock = threading.Lock()
count_lock = threading.Lock()
stop_event = threading.Event()
success_count = 0
completed_count = 0
target_count = 0  # 0 = unlimited
start_time = time.time()
EMAIL_PROVIDER = str(os.getenv("EMAIL_PROVIDER") or "gptmail").strip().lower()

def generate_random_name() -> str:
    length = random.randint(4, 6)
    return random.choice(string.ascii_uppercase) + ''.join(random.choice(string.ascii_lowercase) for _ in range(length - 1))

def generate_random_string(length: int = 15) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

def encode_grpc_message(field_id, string_value):
    key = (field_id << 3) | 2
    value_bytes = string_value.encode('utf-8')
    length = len(value_bytes)
    payload = struct.pack('B', key) + struct.pack('B', length) + value_bytes
    return b'\x00' + struct.pack('>I', len(payload)) + payload

def encode_grpc_message_verify(email, code):
    p1 = struct.pack('B', (1 << 3) | 2) + struct.pack('B', len(email)) + email.encode('utf-8')
    p2 = struct.pack('B', (2 << 3) | 2) + struct.pack('B', len(code)) + code.encode('utf-8')
    payload = p1 + p2
    return b'\x00' + struct.pack('>I', len(payload)) + payload

def send_email_code_grpc(session, email):
    url = f"{site_url}/auth_mgmt.AuthManagement/CreateEmailValidationCode"
    data = encode_grpc_message(1, email)
    headers = {"content-type": "application/grpc-web+proto", "x-grpc-web": "1", "x-user-agent": "connect-es/2.1.1", "origin": site_url, "referer": f"{site_url}/sign-up?redirect=grok-com"}
    try:
        # print(f"[debug] {email} sending verification code request...")
        res = session.post(url, data=data, headers=headers, timeout=15)
        # print(f"[debug] {email} request finished, status: {res.status_code}")
        return res.status_code == 200
    except Exception as e:
        print(f"[-] {email} send verification code error: {e}")
        return False

def verify_email_code_grpc(session, email, code):
    url = f"{site_url}/auth_mgmt.AuthManagement/VerifyEmailValidationCode"
    data = encode_grpc_message_verify(email, code)
    headers = {"content-type": "application/grpc-web+proto", "x-grpc-web": "1", "x-user-agent": "connect-es/2.1.1", "origin": site_url, "referer": f"{site_url}/sign-up?redirect=grok-com"}
    try:
        print(f"[debug] {email} code: {code}, checking status...")
        res = session.post(url, data=data, headers=headers, timeout=15)
        # print(f"[debug] {email} verify response status: {res.status_code}, body length: {len(res.content)}")
        return res.status_code == 200
    except Exception as e:
        print(f"[-] {email} verify code error: {e}")
        return False

def register_single_thread(email_provider: str = "gptmail", one_shot: bool = False, stagger: float = 0):
    global success_count, completed_count
    if stagger:
        time.sleep(stagger)
    elif not adb_rotate_enabled:
        time.sleep(random.uniform(0, 5))

    try:
        email_service = EmailService(proxies=PROXIES, provider=email_provider)
        turnstile_service = TurnstileService(solver=os.getenv("CAPTCHA_SOLVER"))
    except Exception as e:
        print(f"[-] Service init failed: {e}")
        return

    # Manual browser flow does not need Next.js Action ID from curl.
    if captcha_solver_mode() != "manual":
        if not config.get("action_id"):
            print("[-] Thread exiting: missing Action ID")
            return
    final_action_id = config.get("action_id")

    turnstile_reject_count = 0
    first_account = True
    finished_one = False

    while not stop_event.is_set():
        if one_shot and finished_one:
            return
        finished_one = True
        try:
            if adb_rotate_enabled and not one_shot and not first_account:
                from adb_rotate import rotate_ip
                print("[*] Rotating phone IP via ADB...")
                rotate_ip(serial=adb_serial)
            first_account = False

            with requests.Session(impersonate="chrome120", proxies=PROXIES) as session:
                # Warm up the connection
                try: session.get(site_url, timeout=10)
                except: pass

                password = generate_random_string()
                
                # print(f"[debug] thread-{threading.get_ident()} requesting inbox...")
                try:
                    jwt, email = email_service.create_email()
                except CaptchaAuthError as e:
                    print(f"[-] {e}")
                    stop_event.set()
                    return
                except Exception as e:
                    print(f"[-] Email service error: {e}")
                    jwt, email = None, None

                if not email:
                    print(f"[-] thread-{threading.get_ident()} email create returned empty (API down or timeout), waiting 5s...")
                    time.sleep(5); continue
                
                print(f"[*] Starting registration: {email}")

                if turnstile_service.mode == "manual":
                    given = generate_random_name()
                    family = generate_random_name()

                    def fetch_code():
                        for _ in range(12):
                            time.sleep(5)
                            content = email_service.fetch_first_email(jwt)
                            if content:
                                match = re.search(r"([A-Z0-9]{3}-[A-Z0-9]{3})", content)
                                if match:
                                    return match.group(1).replace("-", "")
                        return None

                    from manual_signup import run_manual_signup
                    print("[*] Edge will open the REAL signup page. Click the captcha when you see it.")
                    br = run_manual_signup(email, password, given, family, fetch_code)
                    if br.get("error"):
                        print(f"[-] {email} manual signup: {br['error']}")
                        continue
                    sso = br.get("sso")
                    if sso:
                        with file_lock:
                            os.makedirs("keys", exist_ok=True)
                            with open("keys/grok.txt", "a") as f:
                                f.write(sso + "\n")
                            with open("keys/accounts.txt", "a") as f:
                                f.write(f"{email}:{password}:{sso}\n")
                            success_count += 1
                            completed_count += 1
                            avg = (time.time() - start_time) / success_count
                        if target_count > 0 and completed_count >= target_count:
                            stop_event.set()
                        print(f"[OK] Registered: {email} | SSO: {sso[:15]}... | avg: {avg:.1f}s | progress: {completed_count}/{target_count if target_count else 'unlimited'}")
                    else:
                        print(f"[-] {email} manual signup produced no SSO")
                    continue

                # Step 1: send verification code
                if not send_email_code_grpc(session, email):
                    print(f"[-] {email} failed to send verification code")
                    time.sleep(5); continue
                
                # Step 2: poll inbox for verification code
                verify_code = None
                for _ in range(12):
                    time.sleep(5)
                    content = email_service.fetch_first_email(jwt)
                    if content:
                        # Also match formats like "SZ0-0SW xAI confirmation code" and HTML "SZ0-0SW"
                        match = re.search(r"([A-Z0-9]{3}-[A-Z0-9]{3})", content)
                        if match:
                            verify_code = match.group(1).replace("-", "")
                            break
                if not verify_code:
                    print(f"[-] {email} did not receive a verification code")
                    continue

                given = generate_random_name()
                family = generate_random_name()

                if turnstile_service.mode == "local":
                    from turnstile_solver_local import solve_and_submit_signup

                    payload = [{
                        "emailValidationCode": verify_code,
                        "createUserAndSessionRequest": {
                            "email": email, "givenName": given, "familyName": family,
                            "clearTextPassword": password, "tosAcceptedVersion": "$undefined"
                        },
                        "turnstileToken": "", "promptOnDuplicateEmail": True
                    }]
                    br = solve_and_submit_signup(
                        site_url,
                        config["site_key"],
                        payload,
                        final_action_id,
                        config["state_tree"],
                        ts_action=config.get("ts_action") or "",
                        ts_cdata=config.get("ts_cdata") or "",
                    )
                    if br.get("error"):
                        print(f"[-] {email} local browser signup failed: {br['error']}")
                        continue
                    body = br.get("text") or ""
                    sso = br.get("sso")
                    print(f"  [local-captcha] POST status={br.get('status')} len={len(body)}")
                    if sso:
                        with file_lock:
                            os.makedirs("keys", exist_ok=True)
                            with open("keys/grok.txt", "a") as f: f.write(sso + "\n")
                            with open("keys/accounts.txt", "a") as f: f.write(f"{email}:{password}:{sso}\n")
                            success_count += 1
                            completed_count += 1
                            avg = (time.time() - start_time) / success_count
                        if target_count > 0 and completed_count >= target_count:
                            stop_event.set()
                        print(f"[OK] Registered: {email} | SSO: {sso[:15]}... | avg: {avg:.1f}s | progress: {completed_count}/{target_count if target_count else 'unlimited'}")
                        continue
                    print(f"[-] {email} no SSO (browser POST): {body[:200]}")
                    if "turnstile" in body.lower():
                        print("[-] Same-browser submit still failed Turnstile verify. Use --captcha yescaptcha.")
                        stop_event.set()
                        return
                    continue

                # Step 3: YesCaptcha (or other token APIs) then curl_cffi POST
                ts_retries = 3
                ts_token = None
                for ts_attempt in range(ts_retries):
                    task_id = turnstile_service.create_task(
                        f"{site_url}/sign-up",
                        config["site_key"],
                        action=config.get("ts_action") or "",
                        cdata=config.get("ts_cdata") or "",
                    )
                    ts_token = turnstile_service.get_response(task_id)
                    if ts_token and ts_token != "CAPTCHA_FAIL":
                        break
                    if ts_attempt + 1 < ts_retries:
                        print(f"[-] {email} CAPTCHA failed, retrying...")
                        time.sleep(2)
                if not ts_token or ts_token == "CAPTCHA_FAIL":
                    print(f"[-] {email} CAPTCHA failed after all retries")
                    continue

                # Step 4: submit registration (skip pre-verify so the code is not consumed twice)
                for attempt in range(1):  # one try; on failure, switch email
                    headers = {
                        "user-agent": user_agent, "accept": "text/x-component", "content-type": "text/plain;charset=UTF-8",
                        "origin": site_url, "referer": f"{site_url}/sign-up", "cookie": f"__cf_bm={session.cookies.get('__cf_bm','')}",
                        "next-router-state-tree": config["state_tree"],
                    }
                    if final_action_id:
                        headers["next-action"] = final_action_id
                    payload = [{
                        "emailValidationCode": verify_code,
                        "createUserAndSessionRequest": {
                            "email": email, "givenName": generate_random_name(), "familyName": generate_random_name(),
                            "clearTextPassword": password, "tosAcceptedVersion": "$undefined"
                        },
                        "turnstileToken": ts_token, "promptOnDuplicateEmail": True
                    }]
                    
                    with post_lock:
                        res = session.post(f"{site_url}/sign-up", json=payload, headers=headers)
                    
                    if res.status_code == 200:
                        # Try several SSO extraction methods
                        sso = None
                        # Method 1: set-cookie?q= URL (legacy)
                        for pat in [
                            r'(https://[^"\s]+set-cookie\?q=[^:"\s]+)',
                            r'(https://[^"\s]+set-cookie[^"\s]+)',
                        ]:
                            m = re.search(pat, res.text)
                            if m:
                                sso_url = m.group(0).rstrip("1:").rstrip("2:").rstrip("3:")
                                try:
                                    session.get(sso_url, allow_redirects=True, timeout=15)
                                except:
                                    pass
                                sso = session.cookies.get("sso")
                                if sso:
                                    break
                        # Method 2: cookie jar
                        if not sso:
                            sso = session.cookies.get("sso")
                        # Method 3: Set-Cookie header
                        if not sso:
                            set_cookie = res.headers.get("set-cookie", "")
                            for c in set_cookie.split(","):
                                if "sso=" in c:
                                    sso_val = c.split("sso=")[1].split(";")[0]
                                    if sso_val:
                                        sso = sso_val
                                        break
                        # Treat as a real failure only when the body has an explicit invalid-code error
                        if '"error"' in res.text and 'invalid' in res.text.lower():
                            if not sso:
                                print(f"[-] {email} invalid verification code: {res.text[:150]}")
                            # Still count as success if an SSO cookie is present (messy response formats)

                        if sso:
                            with file_lock:
                                os.makedirs("keys", exist_ok=True)
                                with open("keys/grok.txt", "a") as f: f.write(sso + "\n")
                                with open("keys/accounts.txt", "a") as f: f.write(f"{email}:{password}:{sso}\n")
                                success_count += 1
                                completed_count += 1
                                avg = (time.time() - start_time) / success_count

                            if target_count > 0 and completed_count >= target_count:
                                stop_event.set()

                            print(f"[OK] Registered: {email} | SSO: {sso[:15]}... | avg: {avg:.1f}s | progress: {completed_count}/{target_count if target_count else 'unlimited'}")
                            break
                        elif '"error"' not in res.text or 'invalid' not in res.text.lower():
                            print(f"[-] {email} no SSO (200 OK, len={len(res.text)}): {res.text[:150]}")
                        if "turnstile" in res.text.lower():
                            turnstile_reject_count += 1
                            if turnstile_service.mode == "local":
                                print(
                                    "[-] x.ai rejected the local Turnstile token. "
                                    "Stopping so the solver does not keep opening browsers. "
                                    "Use --captcha yescaptcha if Theyka tokens are also rejected."
                                )
                                stop_event.set()
                                return
                            if turnstile_reject_count >= 3:
                                print("[-] Turnstile verification failed 3 times, stopping")
                                stop_event.set()
                                return
                    else:
                        print(f"[-] {email} submit failed ({res.status_code}): {res.text[:200]}")
                    time.sleep(2)
                else:
                    print(f"[-] {email} giving up, switching email")
                    time.sleep(5)

        except Exception as e:
            # Keep the worker alive on unexpected errors
            print(f"[-] Error: {str(e)[:50]}")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--email-provider", choices=["gptmail", "luckmail", "mailtm", "gmail"], default=os.getenv("EMAIL_PROVIDER", "gptmail"), help="Email provider: gptmail/luckmail/mailtm/gmail")
    parser.add_argument("--threads", type=int, default=None, help="Number of worker threads")
    parser.add_argument("--count", type=int, default=0, help="Total accounts to register (0 = unlimited)")
    parser.add_argument(
        "--captcha",
        choices=["auto", "local", "yescaptcha", "manual"],
        default=os.getenv("CAPTCHA_SOLVER", "auto"),
        help="yescaptcha | local (inject widget) | manual (real signup page, you click captcha)",
    )
    parser.add_argument(
        "--tor",
        action="store_true",
        help="Route traffic through Tor Browser SOCKS (127.0.0.1:9150, or 9050). Start Tor Browser first.",
    )
    parser.add_argument(
        "--adb-rotate",
        action="store_true",
        help="USB tether + ADB: after each batch of --adb-every accounts, cycle the phone IP. Opens that many browsers/threads in parallel.",
    )
    parser.add_argument(
        "--adb-every",
        type=int,
        default=3,
        help="Accounts to register in parallel per phone IP before ADB rotate (default 3)",
    )
    parser.add_argument("--adb-serial", default=os.getenv("ADB_SERIAL") or "", help="adb device serial if several phones are plugged in")
    args = parser.parse_args()
    if args.captcha != "auto":
        os.environ["CAPTCHA_SOLVER"] = args.captcha
    elif "CAPTCHA_SOLVER" not in os.environ:
        os.environ["CAPTCHA_SOLVER"] = ""
    configure_proxy(use_tor=args.tor)

    global target_count, adb_rotate_enabled, adb_serial, adb_every
    target_count = args.count
    adb_rotate_enabled = bool(args.adb_rotate)
    adb_serial = (args.adb_serial or "").strip() or None
    adb_every = max(1, int(args.adb_every or 3))
    if adb_rotate_enabled and args.tor:
        print("[-] Do not combine --tor and --adb-rotate")
        return
    if adb_rotate_enabled:
        from adb_rotate import find_adb, require_device, public_ip
        try:
            find_adb()
            require_device(adb_serial)
        except Exception as e:
            print(f"[-] ADB rotate: {e}")
            return
        ip = public_ip()
        print(f"[*] ADB rotate: on  (tether the phone so this PC uses cellular; IP now {ip or 'unknown'})")
        print(f"[*] ADB batch: {adb_every} parallel account(s) per IP")

    print("=" * 60 + "\nGrok registrar\n" + "=" * 60)
    print(f"[*] Email provider: {args.email_provider}")
    print(f"[*] Target count: {args.count if args.count else 'unlimited'}")
    print(f"[*] Proxy: {_proxy or 'none (direct)'}")
    print(f"[*] Captcha: {captcha_solver_mode()}")
    if adb_rotate_enabled:
        print(f"[*] ADB rotate: {adb_every} parallel per IP, then cycle")

    # 1. Discover signup parameters
    print("[*] Initializing...")
    start_url = f"{site_url}/sign-up"
    with requests.Session(impersonate="chrome120", proxies=PROXIES) as s:
        try:
            html = s.get(start_url).text
            widget = extract_turnstile_widget_params(html)
            if widget.get("site_key"):
                config["site_key"] = widget["site_key"]
            else:
                key_match = re.search(r'sitekey":"(0x4[a-zA-Z0-9_-]+)"', html)
                if key_match:
                    config["site_key"] = key_match.group(1)
            if widget.get("ts_action"):
                config["ts_action"] = widget["ts_action"]
            if widget.get("ts_cdata"):
                config["ts_cdata"] = widget["ts_cdata"]
            # Tree
            tree_match = re.search(r'next-router-state-tree":"([^"]+)"', html)
            if tree_match: config["state_tree"] = tree_match.group(1)
            # Action ID — fetch JS chunks in parallel (stdlib requests: thread-safe and fast)
            js_urls = list(set(urljoin(start_url, m.group(0)) for m in re.finditer(r"/_next/static/chunks/[^\"'\s>]+\.js", html)))
            if not js_urls:
                print(f"[Warn] HTML length {len(html)}, no JS URLs parsed. First 500 chars: {html[:500].replace('\n',' ')}")
            action_found = None
            print(f"[*] Searching {len(js_urls)} JS files for Action ID...")

            def _fetch_and_search(url):
                """Fetch a JS chunk; look for Next action ID and Turnstile widget params."""
                import requests as _req
                found_action = None
                widget = {}
                try:
                    js = _req.get(url, proxies=PROXIES, timeout=10).text
                    m = re.search(r'7f[a-fA-F0-9]{40}', js)
                    if m:
                        found_action = m.group(0)
                    widget = extract_turnstile_widget_params(js)
                except Exception:
                    pass
                return found_action, widget

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                for found_action, widget in pool.map(_fetch_and_search, js_urls):
                    if widget.get("site_key"):
                        config["site_key"] = widget["site_key"]
                    if widget.get("ts_action") and not config.get("ts_action"):
                        config["ts_action"] = widget["ts_action"]
                    if widget.get("ts_cdata") and not config.get("ts_cdata"):
                        config["ts_cdata"] = widget["ts_cdata"]
                    if found_action and not action_found:
                        action_found = found_action
                        # keep scanning remaining JS for widget params
            if config.get("ts_action") or config.get("ts_cdata"):
                print(f"[+] Turnstile widget action={config.get('ts_action')!r} cdata={config.get('ts_cdata')!r}")

            if action_found:
                config["action_id"] = action_found
                print(f"[+] Action ID: {action_found}")
                try:
                    open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".action_id.cache"), "w").write(action_found)
                except Exception:
                    pass
            else:
                # Fall back to cache if the live scan misses (intermittent fetch failures)
                try:
                    cached = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".action_id.cache")).read().strip()
                    if re.match(r"^7f[a-fA-F0-9]{40}$", cached):
                        config["action_id"] = cached
                        print(f"[+] Using cached Action ID: {cached}")
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] Init scan failed: {e}")
            if captcha_solver_mode() != "manual":
                return

    if not config["action_id"] and captcha_solver_mode() != "manual":
        print("[-] Error: Action ID not found")
        return

    # 2. Start workers
    if adb_rotate_enabled:
        print(f"[*] Batch mode: {adb_every} parallel signup(s), then ADB IP change")
        first_batch = True
        try:
            while not stop_event.is_set():
                if target_count > 0 and completed_count >= target_count:
                    break
                if not first_batch:
                    from adb_rotate import rotate_ip
                    print("[*] Batch done — rotating phone IP via ADB...")
                    rotate_ip(serial=adb_serial)
                first_batch = False
                batch = adb_every
                if target_count > 0:
                    batch = min(batch, target_count - completed_count)
                if batch <= 0:
                    break
                print(f"[*] Starting parallel batch of {batch}...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=batch) as executor:
                    futs = [
                        executor.submit(
                            register_single_thread,
                            args.email_provider,
                            True,
                            i * 1.5,
                        )
                        for i in range(batch)
                    ]
                    concurrent.futures.wait(futs)
        except KeyboardInterrupt:
            print("\n[!] Interrupt received, shutting down...")
            stop_event.set()
        return

    if captcha_solver_mode() == "manual":
        t = 1
    elif args.threads is not None:
        t = args.threads
    else:
        try:
            t = int(input("\nThreads (default 1): ").strip() or 1)
        except:
            t = 1
    
    print(f"[*] Starting {t} thread(s)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=t) as executor:
        futures = [executor.submit(register_single_thread, args.email_provider) for _ in range(t)]
        try:
            concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            print("\n[!] Interrupt received, shutting down...")

if __name__ == "__main__":
    main()
