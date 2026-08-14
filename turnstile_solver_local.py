"""
Client + launcher for Theyka/Turnstile-Solver (open-source local API).

https://github.com/Theyka/Turnstile-Solver

`--captcha local` talks to this API instead of the old in-repo widget.
"""
from __future__ import annotations

import os
import sys
import time
import subprocess
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parent
VENDOR_DIR = REPO_ROOT / "vendor" / "Turnstile-Solver"
THEYKA_GIT = "https://github.com/Theyka/Turnstile-Solver.git"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = int(os.getenv("TURNSTILE_PORT") or "5000")
BASE_URL = os.getenv("TURNSTILE_API") or f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"

_solver_proc: subprocess.Popen | None = None


def _browser_type() -> str:
    explicit = str(os.getenv("TURNSTILE_BROWSER") or "").strip().lower()
    if explicit in ("msedge", "chrome", "chromium", "camoufox"):
        return explicit
    edge = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
    edge2 = Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")
    if edge.is_file() or edge2.is_file():
        return "msedge"
    return "chromium"


def _api_up(timeout: float = 1.5) -> bool:
    try:
        r = requests.get(BASE_URL + "/", timeout=timeout)
        return r.status_code < 500
    except Exception:
        return False


def _clone_theyka() -> None:
    if (VENDOR_DIR / "api_solver.py").is_file():
        return
    VENDOR_DIR.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Cloning Theyka/Turnstile-Solver into {VENDOR_DIR} ...")
    subprocess.run(
        ["git", "clone", "--depth", "1", THEYKA_GIT, str(VENDOR_DIR)],
        check=True,
    )


def ensure_solver_running() -> str:
    """Return the Theyka API base URL, starting the process if needed."""
    global _solver_proc
    if _api_up():
        print(f"[+] Theyka Turnstile API already running at {BASE_URL}")
        return BASE_URL

    _clone_theyka()
    solver = VENDOR_DIR / "api_solver.py"
    if not solver.is_file():
        raise RuntimeError(f"Theyka solver missing: {solver}")

    browser = _browser_type()
    cmd = [
        sys.executable,
        str(solver),
        "--browser_type",
        browser,
        "--thread",
        "1",
        "--host",
        DEFAULT_HOST,
        "--port",
        str(DEFAULT_PORT),
    ]
    log_path = VENDOR_DIR / "solver.log"
    print(f"[*] Starting Theyka Turnstile-Solver ({browser}) on {BASE_URL} ...")
    log_f = open(log_path, "a", encoding="utf-8", errors="replace")
    _solver_proc = subprocess.Popen(
        cmd,
        cwd=str(VENDOR_DIR),
        stdout=log_f,
        stderr=log_f,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        if _solver_proc.poll() is not None:
            raise RuntimeError(
                f"Theyka solver exited early (code {_solver_proc.returncode}). "
                "Install deps with: uv add quart camoufox, then "
                f"uv run python {solver} --browser_type {browser}"
            )
        if _api_up():
            print(f"[+] Theyka Turnstile API ready at {BASE_URL}")
            return BASE_URL
        time.sleep(0.4)
    raise RuntimeError(f"Theyka solver did not become ready at {BASE_URL} within 60s")


def create_theyka_task(siteurl: str, sitekey: str, action: str = "", cdata: str = "") -> str:
    ensure_solver_running()
    params = {"url": siteurl, "sitekey": sitekey}
    if action:
        params["action"] = action
    if cdata:
        params["cdata"] = cdata
    print(f"  [theyka] create task url={siteurl}")
    r = requests.get(f"{BASE_URL}/turnstile", params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    task_id = data.get("task_id")
    if not task_id:
        raise RuntimeError(f"Theyka create failed: {data}")
    return str(task_id)


def poll_theyka_result(task_id: str, max_retries: int = 40, retry_delay: float = 1.5) -> str | None:
    for _ in range(max_retries):
        try:
            r = requests.get(f"{BASE_URL}/result", params={"id": task_id}, timeout=15)
            if r.status_code == 400:
                time.sleep(retry_delay)
                continue
            try:
                data = r.json()
            except Exception:
                text = (r.text or "").strip().strip('"')
                if text == "CAPTCHA_NOT_READY":
                    time.sleep(retry_delay)
                    continue
                if "CAPTCHA_FAIL" in text:
                    print("  [theyka] CAPTCHA_FAIL")
                    return None
                time.sleep(retry_delay)
                continue

            if isinstance(data, str):
                if data == "CAPTCHA_NOT_READY":
                    time.sleep(retry_delay)
                    continue
                if "CAPTCHA_FAIL" in data:
                    print("  [theyka] CAPTCHA_FAIL")
                    return None
                time.sleep(retry_delay)
                continue

            value = (data or {}).get("value")
            if value == "CAPTCHA_NOT_READY" or value is None:
                time.sleep(retry_delay)
                continue
            if value == "CAPTCHA_FAIL" or "CAPTCHA_FAIL" in str(value):
                print("  [theyka] CAPTCHA_FAIL")
                return None
            if isinstance(value, str) and len(value) > 50:
                elapsed = (data or {}).get("elapsed_time")
                print(f"  [theyka] token ok ({elapsed}s)")
                return value
        except Exception as e:
            print(f"  [theyka] poll error: {e}")
        time.sleep(retry_delay)
    print("  [theyka] timed out waiting for token")
    return None


# ── Same-browser signup (local captcha experiment) ──────────────────────────
import asyncio
import json
import re
import threading
from urllib.parse import urlparse

_BROWSER_LOCK = threading.Lock()

_WIDGET_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Turnstile Solver</title>
  <script>
    window.onloadTurnstileCallback = function () {{
      turnstile.render("#cf-widget", Object.assign({opts}, {{
        callback: function (token) {{
          var h = document.querySelector("[name=cf-turnstile-response]");
          if (!h) {{
            h = document.createElement("input");
            h.type = "hidden";
            h.name = "cf-turnstile-response";
            document.body.appendChild(h);
          }}
          h.value = token;
        }}
      }}));
    }};
  </script>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
</head>
<body>
  <div id="cf-widget"></div>
</body>
</html>
"""


async def _click_checkbox(page) -> None:
    try:
        box = await page.locator("iframe").first.bounding_box()
        if box:
            await page.mouse.click(box["x"] + 26, box["y"] + 32)
            return
    except Exception:
        pass
    try:
        await page.frame_locator("iframe").first.locator("body").click(timeout=1500)
    except Exception:
        pass


async def _solve_and_submit_async(
    site_url: str,
    site_key: str,
    payload: list,
    action_id: str,
    state_tree: str,
    ts_action: str = "",
    ts_cdata: str = "",
    timeout: int = 60,
) -> dict:
    from patchright.async_api import async_playwright

    opts = {"sitekey": site_key, "theme": "light"}
    if ts_action:
        opts["action"] = ts_action
    if ts_cdata:
        opts["cdata"] = ts_cdata
    html = _WIDGET_HTML.format(opts=json.dumps(opts))
    host = urlparse(site_url).hostname or "accounts.x.ai"
    origin = site_url.rstrip("/")
    signup = f"{origin}/sign-up"
    channel = _browser_type()
    if channel not in ("msedge", "chrome"):
        channel = "msedge"
    proxy = str(os.getenv("GROK_PROXY") or "").strip()
    launch_kwargs = {
        "headless": False,
        "channel": channel,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--disable-features=msEdgeTrackingPrevention,TrackingPrevention,InterestFeedContentSuggestions",
        ],
    }
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}

    t0 = time.time()
    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        page = await context.new_page()

        async def _serve_get_only(route):
            req = route.request
            req_host = urlparse(req.url).hostname or ""
            if (
                req.method == "GET"
                and req.resource_type == "document"
                and req_host == host
            ):
                await route.fulfill(
                    status=200,
                    content_type="text/html; charset=utf-8",
                    body=html,
                )
            else:
                await route.continue_()

        try:
            await page.route("**/*", _serve_get_only)
            print(f"  [local-captcha] same-browser widget on {signup} via {channel}")
            await page.goto(signup, wait_until="domcontentloaded", timeout=30_000)
            await page.wait_for_selector("iframe", timeout=15_000)
            await page.eval_on_selector(
                "#cf-widget",
                "el => { el.style.width = '70px'; el.style.height = '70px'; }",
            )
            token = ""
            deadline = time.time() + timeout
            clicked = False
            while time.time() < deadline:
                try:
                    token = await page.input_value("[name=cf-turnstile-response]", timeout=1500)
                except Exception:
                    token = ""
                if token and len(token) > 50:
                    break
                if not clicked:
                    await _click_checkbox(page)
                    clicked = True
                await asyncio.sleep(0.4)
            if not token or len(token) < 50:
                return {"error": "no turnstile token", "elapsed": time.time() - t0}

            print(f"  [local-captcha] token ok ({time.time() - t0:.1f}s), submitting from this page")
            await page.unroute("**/*")
            payload[0]["turnstileToken"] = token
            result = await page.evaluate(
                """async ({url, actionId, stateTree, body}) => {
                    const res = await fetch(url, {
                        method: "POST",
                        headers: {
                            "accept": "text/x-component",
                            "content-type": "text/plain;charset=UTF-8",
                            "next-action": actionId,
                            "next-router-state-tree": stateTree,
                        },
                        body: JSON.stringify(body),
                        credentials: "include",
                    });
                    const headerBag = {};
                    res.headers.forEach((v, k) => { headerBag[k] = v; });
                    return { status: res.status, text: await res.text(), headers: headerBag };
                }""",
                {
                    "url": signup,
                    "actionId": action_id,
                    "stateTree": state_tree,
                    "body": payload,
                },
            )
            cookies = await context.cookies()
            sso = next((c["value"] for c in cookies if c.get("name") == "sso"), None)
            text = result.get("text") or ""
            if not sso:
                m = re.search(r'(https://[^"\s]+set-cookie[^"\s]+)', text)
                if m:
                    sso_url = m.group(0).rstrip("123:")
                    try:
                        await page.goto(sso_url, wait_until="domcontentloaded", timeout=15_000)
                        cookies = await context.cookies()
                        sso = next((c["value"] for c in cookies if c.get("name") == "sso"), None)
                    except Exception:
                        pass
            return {
                "status": result.get("status"),
                "text": text,
                "sso": sso,
                "elapsed": time.time() - t0,
            }
        except Exception as e:
            return {"error": str(e)[:240]}
        finally:
            await context.close()
            await browser.close()


def solve_and_submit_signup(
    site_url: str,
    site_key: str,
    payload: list,
    action_id: str,
    state_tree: str,
    ts_action: str = "",
    ts_cdata: str = "",
) -> dict:
    with _BROWSER_LOCK:
        return asyncio.run(
            _solve_and_submit_async(
                site_url,
                site_key,
                payload,
                action_id,
                state_tree,
                ts_action=ts_action,
                ts_cdata=ts_cdata,
            )
        )
