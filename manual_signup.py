"""
Real x.ai /sign-up in headed Edge. Automates email/code/password.
You click the Cloudflare checkbox yourself.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SIGNUP = "https://accounts.x.ai/sign-up?redirect=grok-com"
BLOCK_HINTS = (
    "you have been blocked",
    "not available in your region",
    "unable to access",
    "sorry, you have been blocked",
)


def _edge_channel() -> str:
    for path, ch in (
        (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge"),
        (r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", "msedge"),
        (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome"),
    ):
        if Path(path).is_file():
            return ch
    return "msedge"


async def _click_visible(page, locator, what: str, timeout: int = 12_000) -> bool:
    try:
        el = locator.first
        await el.wait_for(state="visible", timeout=timeout)
        await el.scroll_into_view_if_needed()
        await el.click(timeout=timeout)
        print(f"[manual] clicked {what}")
        return True
    except Exception as e:
        print(f"[manual] could not click {what}: {str(e)[:120]}")
        return False


async def _click_signup_email(page) -> bool:
    await page.wait_for_timeout(1500)
    locators = [
        page.get_by_role("button", name=re.compile(r"sign up with email", re.I)),
        page.locator("button", has_text=re.compile(r"sign up with email", re.I)),
        page.get_by_text("Sign up with email", exact=True),
        page.locator("text=Sign up with email"),
    ]
    for loc in locators:
        if await loc.count() > 0:
            if await _click_visible(page, loc, "Sign up with email"):
                return True
    return False


async def _click_primary(page, *names: str) -> bool:
    for name in names:
        loc = page.get_by_role("button", name=re.compile(rf"^{re.escape(name)}$", re.I))
        if await loc.count() > 0 and await loc.first.is_visible():
            if await _click_visible(page, loc, name):
                return True
    for name in names:
        loc = page.locator("button", has_text=re.compile(name, re.I))
        if await loc.count() > 0 and await loc.first.is_visible():
            if await _click_visible(page, loc, name):
                return True
    return False


async def _dismiss_cookies(page) -> None:
    for name in ("Accept All Cookies", "Accept all", "Reject All", "Reject all"):
        loc = page.get_by_role("button", name=re.compile(rf"^{re.escape(name)}$", re.I))
        try:
            if await loc.count() and await loc.first.is_visible():
                await loc.first.click(timeout=2000)
                print(f"[manual] dismissed cookies ({name})")
                await page.wait_for_timeout(400)
                return
        except Exception:
            pass


async def _fill_otp(page, code: str) -> bool:
    """x.ai uses 6 one-character boxes (XXX-XXX), not a single input."""
    code = re.sub(r"[^A-Za-z0-9]", "", code).upper()
    if len(code) < 6:
        print(f"[manual] code too short: {code!r}")
        return False
    loc = page.locator('input[maxlength="1"]')
    n = await loc.count()
    if n < 6:
        loc = page.locator("input:visible")
        n = await loc.count()
    if n >= 6:
        print(f"[manual] typing OTP into {n} boxes: {code[:3]}-{code[3:6]}")
        for i in range(6):
            box = loc.nth(i)
            await box.click()
            await box.fill("")
            await box.press_sequentially(code[i], delay=50)
        return True
    print("[manual] no OTP boxes found; typing as a sequence")
    first = page.locator("input:visible").first
    await first.click()
    await page.keyboard.type(code[:6], delay=80)
    return True


async def _heading_text(page) -> str:
    try:
        return (await page.locator("h1,h2").first.inner_text()).strip()
    except Exception:
        return ""


async def _fill_visible_input(page, value: str, *, password: bool = False) -> bool:
    if password:
        loc = page.locator('input[type="password"]').first
    else:
        loc = page.locator('input[type="email"], input[type="text"], input:not([type])').first
    try:
        await loc.wait_for(state="visible", timeout=12_000)
        await loc.click()
        await loc.fill("")
        await loc.fill(value)
        print(f"[manual] filled input ({'password' if password else 'text'})")
        return True
    except Exception as e:
        print(f"[manual] fill failed: {str(e)[:120]}")
        return False


async def _page_blocked(page) -> str | None:
    try:
        text = (await page.inner_text("body")).lower()
    except Exception:
        return None
    for h in BLOCK_HINTS:
        if h in text:
            return h
    return None


async def _sso_from_context(context) -> str | None:
    cookies = await context.cookies()
    for c in cookies:
        if c.get("name") == "sso" and c.get("value"):
            return c["value"]
    return None


async def run_manual_signup_async(
    email: str,
    password: str,
    given: str,
    family: str,
    fetch_code,
    captcha_wait: int = 180,
) -> dict:
    from patchright.async_api import async_playwright

    channel = _edge_channel()
    proxy = str(os.getenv("GROK_PROXY") or "").strip()
    launch_kwargs = {
        "headless": False,
        "channel": channel,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--disable-features=msEdgeTrackingPrevention,TrackingPrevention",
        ],
    }
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}

    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        context = await browser.new_context(viewport={"width": 1280, "height": 900})
        page = await context.new_page()
        try:
            print(f"[manual] opening {SIGNUP} in {channel}")
            await page.goto(SIGNUP, wait_until="load", timeout=45_000)
            await page.wait_for_timeout(2500)
            blocked = await _page_blocked(page)
            if blocked:
                return {
                    "error": f"real signup page blocked ({blocked}). Use phone USB tethering / --adb-rotate, then retry."
                }

            if not await _click_signup_email(page):
                print("[manual] click the 'Sign up with email' button yourself")
            await page.wait_for_timeout(2000)
            await _dismiss_cookies(page)

            print(f"[manual] filling email {email}")
            if not await _fill_visible_input(page, email):
                print("[manual] type the email yourself in Edge")
            await page.wait_for_timeout(400)
            if not await _click_primary(page, "Continue", "Next", "Send code", "Verify"):
                await page.keyboard.press("Enter")
            await page.wait_for_timeout(1500)

            print("[manual] waiting for verification email...")
            code = await asyncio.to_thread(fetch_code)
            if not code:
                print("[manual] no code from inbox — paste all 6 characters yourself")
            else:
                print(f"[manual] code {code[:3]}-{code[3:6]}")
                await _fill_otp(page, code)
                await page.wait_for_timeout(400)
                if not await _click_primary(page, "Confirm email", "Confirm", "Continue", "Verify"):
                    await page.keyboard.press("Enter")
                await page.wait_for_timeout(2000)

            # Stay on verify-email until the next step actually appears.
            for _ in range(20):
                heading = (await _heading_text(page)).lower()
                has_pw = await page.locator('input[type="password"]').count() > 0
                has_cf = await page.locator("iframe[src*='challenges.cloudflare'], iframe[src*='turnstile']").count() > 0
                if has_pw or has_cf or (heading and "verify" not in heading):
                    break
                await page.wait_for_timeout(500)

            print("[manual] filling name/password if those fields are on screen")
            try:
                boxes = page.locator("input:visible")
                n = await boxes.count()
                texts = []
                for i in range(n):
                    inp = boxes.nth(i)
                    typ = (await inp.get_attribute("type") or "text").lower()
                    if typ == "password":
                        await inp.fill(password)
                    elif typ in ("text", "email", ""):
                        texts.append(inp)
                if len(texts) >= 2:
                    await texts[0].fill(given)
                    await texts[1].fill(family)
                elif len(texts) == 1:
                    val = await texts[0].input_value()
                    if email not in val:
                        await texts[0].fill(given)
            except Exception as e:
                print(f"[manual] name/password fill skipped: {e}")

            print("=" * 60)
            print("[manual] CLICK THE CAPTCHA in the Edge window (Verify you are human).")
            print(f"[manual] Waiting up to {captcha_wait}s...")
            print("=" * 60)

            deadline = time.time() + captcha_wait
            while time.time() < deadline:
                sso = await _sso_from_context(context)
                if sso:
                    print("[manual] SSO cookie appeared")
                    return {"sso": sso}
                blocked = await _page_blocked(page)
                if blocked:
                    return {"error": f"page blocked while waiting: {blocked}"}
                try:
                    token = await page.evaluate(
                        'document.querySelector("[name=cf-turnstile-response]")?.value || ""'
                    )
                except Exception:
                    token = ""
                if token and len(token) > 50:
                    print("[manual] captcha token present — clicking Continue / Create")
                    await _click_primary(
                        page, "Create account", "Create", "Sign up", "Continue", "Next", "Submit", "Agree"
                    )
                    await page.wait_for_timeout(3000)
                    sso = await _sso_from_context(context)
                    if sso:
                        return {"sso": sso}
                    html = await page.content()
                    m = re.search(r'(https://[^"\s]+set-cookie[^"\s]+)', html)
                    if m:
                        try:
                            await page.goto(m.group(0).rstrip("123:"), wait_until="domcontentloaded")
                            await page.wait_for_timeout(2000)
                            sso = await _sso_from_context(context)
                            if sso:
                                return {"sso": sso}
                        except Exception:
                            pass
                await asyncio.sleep(1)

            sso = await _sso_from_context(context)
            if sso:
                return {"sso": sso}
            return {"error": "timed out waiting for captcha/SSO"}
        except Exception as e:
            return {"error": str(e)[:300]}
        finally:
            await context.close()
            await browser.close()


def run_manual_signup(email, password, given, family, fetch_code, captcha_wait=180) -> dict:
    return asyncio.run(
        run_manual_signup_async(email, password, given, family, fetch_code, captcha_wait)
    )
