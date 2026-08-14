import os
import re
import time
import requests

from dotenv import load_dotenv

load_dotenv()

YESCAPTCHA_SOFT_ID = 102154


class CaptchaAuthError(Exception):
    """YesCaptcha rejected the account key; retrying will not help."""
    pass


def captcha_solver_mode() -> str:
    explicit = str(os.getenv("CAPTCHA_SOLVER") or "").strip().lower()
    if explicit in ("local", "yescaptcha", "manual"):
        return explicit
    if str(os.getenv("YESCAPTCHA_KEY") or "").strip():
        return "yescaptcha"
    return "local"


class TurnstileService:
    def __init__(self, solver: str | None = None):
        self.mode = (solver or captcha_solver_mode()).strip().lower()
        if self.mode not in ("local", "yescaptcha", "manual"):
            self.mode = captcha_solver_mode()
        self.yescaptcha_key = os.getenv("YESCAPTCHA_KEY", "").strip()
        self.yescaptcha_api = "https://api.yescaptcha.com"
        self._local_token = None

        if self.mode == "yescaptcha" and not self.yescaptcha_key:
            raise CaptchaAuthError(
                "CAPTCHA_SOLVER=yescaptcha but YESCAPTCHA_KEY is empty. "
                "Set the key, or use --captcha local"
            )

    def create_task(self, siteurl, sitekey, action: str = "", cdata: str = ""):
        if self.mode == "local":
            from turnstile_solver_local import create_theyka_task

            return create_theyka_task(siteurl, sitekey, action=action or "", cdata=cdata or "")

        url = f"{self.yescaptcha_api}/createTask"
        task = {
            "type": "TurnstileTaskProxyless",
            "websiteURL": siteurl,
            "websiteKey": sitekey,
        }
        if action:
            task["action"] = action
        payload = {
            "clientKey": self.yescaptcha_key,
            "task": task,
            "softID": YESCAPTCHA_SOFT_ID,
        }
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        if data.get("errorId") != 0:
            code = str(data.get("errorCode") or "")
            desc = str(data.get("errorDescription") or "unknown error")
            desc = re.sub(r"[a-fA-F0-9]{16,}", "[redacted]", desc)
            if code == "ERROR_KEY_DOES_NOT_EXIST":
                raise CaptchaAuthError(
                    "YESCAPTCHA_KEY was loaded from .env but YesCaptcha rejected it "
                    "(ERROR_KEY_DOES_NOT_EXIST). Copy a fresh ClientKey from "
                    "https://yescaptcha.com, or run with --captcha local"
                )
            raise Exception(f"YesCaptcha create task failed: {desc}")
        return data["taskId"]

    def get_response(self, task_id, max_retries=30, initial_delay=5, retry_delay=2):
        if self.mode == "local":
            from turnstile_solver_local import poll_theyka_result

            return poll_theyka_result(str(task_id))

        if not self.yescaptcha_key:
            raise Exception("Missing YESCAPTCHA_KEY, cannot get result")

        time.sleep(initial_delay)

        for _ in range(max_retries):
            try:
                url = f"{self.yescaptcha_api}/getTaskResult"
                payload = {
                    "clientKey": self.yescaptcha_key,
                    "taskId": task_id,
                }
                response = requests.post(url, json=payload)
                response.raise_for_status()
                data = response.json()

                if data.get("errorId") != 0:
                    print(f"YesCaptcha get result failed: {data.get('errorDescription')}")
                    return None

                status = data.get("status")
                if status == "ready":
                    token = data.get("solution", {}).get("token")
                    if token:
                        return token
                    print("YesCaptcha result has no token")
                    return None
                elif status == "processing":
                    time.sleep(retry_delay)
                else:
                    print(f"YesCaptcha unknown status: {status}")
                    time.sleep(retry_delay)
            except Exception as e:
                print(f"Turnstile response error: {e}")
                time.sleep(retry_delay)

        return None
