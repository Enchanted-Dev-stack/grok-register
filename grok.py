import os, json, random, string, time, re, struct, argparse
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
from YesCaptcha_service import TurnstileService, CaptchaAuthError

# Base config
site_url = "https://accounts.x.ai"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
_proxy = str(os.getenv("GROK_PROXY") or "").strip()
PROXIES = {"http": _proxy, "https": _proxy} if _proxy else None

# Runtime config filled during init
config = {
    "site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
    "action_id": None,
    "state_tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
}

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

def register_single_thread(email_provider: str = "gptmail"):
    # Stagger thread start to avoid a burst of concurrent requests
    time.sleep(random.uniform(0, 5))

    try:
        email_service = EmailService(proxies=PROXIES, provider=email_provider)
        turnstile_service = TurnstileService()
    except Exception as e:
        print(f"[-] Service init failed: {e}")
        return

    # Exit if action_id was not discovered during init
    final_action_id = config.get("action_id")
    if not final_action_id:
        print("[-] Thread exiting: missing Action ID")
        return

    while not stop_event.is_set():
        try:
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

                # Step 3: solve Turnstile first (slowest step) so the code does not expire
                ts_token = None
                for ts_attempt in range(3):
                    task_id = turnstile_service.create_task(site_url, config["site_key"])
                    ts_token = turnstile_service.get_response(task_id)
                    if ts_token and ts_token != "CAPTCHA_FAIL":
                        break
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
                                global success_count, completed_count
                                success_count += 1
                                completed_count += 1
                                avg = (time.time() - start_time) / success_count

                            if target_count > 0 and completed_count >= target_count:
                                stop_event.set()

                            print(f"[OK] Registered: {email} | SSO: {sso[:15]}... | avg: {avg:.1f}s | progress: {completed_count}/{target_count if target_count else 'unlimited'}")
                            break
                        elif '"error"' not in res.text or 'invalid' not in res.text.lower():
                            # No clear error, but also no SSO — extra debug
                            print(f"[-] {email} no SSO (200 OK, len={len(res.text)}): {res.text[:150]}")
                        # else: invalid error and no SSO — already printed above
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
    args = parser.parse_args()

    global target_count
    target_count = args.count

    print("=" * 60 + "\nGrok registrar\n" + "=" * 60)
    print(f"[*] Email provider: {args.email_provider}")
    print(f"[*] Target count: {args.count if args.count else 'unlimited'}")
    print(f"[*] Proxy: {_proxy or 'none (direct)'}")

    # 1. Discover signup parameters
    print("[*] Initializing...")
    start_url = f"{site_url}/sign-up"
    with requests.Session(impersonate="chrome120", proxies=PROXIES) as s:
        try:
            html = s.get(start_url).text
            # Key
            key_match = re.search(r'sitekey":"(0x4[a-zA-Z0-9_-]+)"', html)
            if key_match: config["site_key"] = key_match.group(1)
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
                """Fetch a JS chunk with stdlib requests and look for Action ID."""
                import requests as _req
                try:
                    js = _req.get(url, proxies=PROXIES, timeout=10).text
                    m = re.search(r'7f[a-fA-F0-9]{40}', js)
                    if m:
                        return m.group(0)
                except Exception:
                    pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                for result in pool.map(_fetch_and_search, js_urls):
                    if result:
                        action_found = result
                        pool.shutdown(wait=False, cancel_futures=True)
                        break

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
            return

    if not config["action_id"]:
        print("[-] Error: Action ID not found")
        return

    # 2. Start workers
    if args.threads is not None:
        t = args.threads
    else:
        try:
            t = int(input("\nThreads (default 1): ").strip() or 1)
        except:
            t = 1
    
    print(f"[*] Starting {t} thread(s)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=t) as executor:
        # One long-running worker per thread
        futures = [executor.submit(register_single_thread, args.email_provider) for _ in range(t)]
        try:
            concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            print("\n[!] Interrupt received, shutting down...")

if __name__ == "__main__":
    main()
