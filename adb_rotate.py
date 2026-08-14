"""
Cycle Android mobile data / airplane mode over ADB so USB-tethered
PC traffic picks up a new cellular IP.

Requires: platform-tools (`adb` on PATH), USB debugging, USB tethering.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

IPIFY = "https://api.ipify.org"


def find_adb() -> str:
    env = str(os.getenv("ADB") or "").strip()
    if env and os.path.isfile(env):
        return env
    which = shutil.which("adb")
    if which:
        return which
    extras = [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        r"C:\platform-tools\adb.exe",
        os.path.expandvars(r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
    ]
    for p in extras:
        if p and os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "adb not found. Install Android platform-tools and add them to PATH, "
        "or set ADB=C:\\path\\to\\adb.exe"
    )


def adb(args: list[str], serial: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
    cmd = [find_adb()]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def require_device(serial: str | None = None) -> str:
    r = adb(["devices"], timeout=15)
    lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip() and not ln.startswith("List")]
    ready = []
    for ln in lines:
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            ready.append(parts[0])
    if not ready:
        unauthorized = any("unauthorized" in ln for ln in lines)
        hint = " Unlock the phone and allow USB debugging." if unauthorized else ""
        raise RuntimeError("No ADB device in 'device' state." + hint + " Plug in USB and enable USB debugging.")
    if serial:
        if serial not in ready:
            raise RuntimeError(f"ADB serial {serial!r} not among {ready}")
        return serial
    if len(ready) > 1:
        raise RuntimeError(f"Multiple devices {ready}; pass --adb-serial")
    return ready[0]


def public_ip(timeout: float = 8.0) -> str | None:
    try:
        with urllib.request.urlopen(IPIFY, timeout=timeout) as resp:
            ip = resp.read().decode("ascii", errors="replace").strip()
            return ip or None
    except Exception:
        return None


def wait_for_ip(timeout: float = 60.0) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ip = public_ip()
        if ip:
            return ip
        time.sleep(2)
    return None


def _shell(serial: str, command: str, timeout: int = 20) -> str:
    r = adb(["shell", command], serial=serial, timeout=timeout)
    return (r.stdout or "") + (r.stderr or "")


def enable_usb_tether(serial: str) -> None:
    # Best-effort; OEM skins differ. Harmless if already tethered.
    for cmd in (
        "svc usb setFunctions rndis",
        "cmd connectivity tether usb start",
        "svc usb setFunction rndis",
    ):
        try:
            _shell(serial, cmd)
        except Exception:
            pass


def cycle_mobile_data(serial: str) -> None:
    _shell(serial, "svc data disable")
    time.sleep(3)
    _shell(serial, "svc data enable")


def cycle_airplane(serial: str) -> None:
    out = _shell(serial, "cmd connectivity airplane-mode enable")
    if "Unknown" in out or "not found" in out.lower():
        _shell(serial, "settings put global airplane_mode_on 1")
        _shell(serial, "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true")
        time.sleep(4)
        _shell(serial, "settings put global airplane_mode_on 0")
        _shell(serial, "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false")
    else:
        time.sleep(4)
        _shell(serial, "cmd connectivity airplane-mode disable")
    time.sleep(2)
    enable_usb_tether(serial)


def rotate_ip(serial: str | None = None, wait: float = 60.0) -> str | None:
    """
    Cycle cellular radio, wait for internet, return new public IP (or None).
    Prefers mobile-data toggle; falls back to airplane if IP did not change.
    """
    serial = require_device(serial)
    old_ip = public_ip()
    print(f"[adb] device={serial} current IP={old_ip or 'unknown'}")
    print("[adb] cycling mobile data...")
    cycle_mobile_data(serial)
    time.sleep(5)
    new_ip = wait_for_ip(timeout=wait)
    if new_ip and new_ip != old_ip:
        print(f"[adb] new IP={new_ip}")
        return new_ip
    print("[adb] IP unchanged after data cycle, trying airplane mode...")
    cycle_airplane(serial)
    time.sleep(8)
    enable_usb_tether(serial)
    new_ip = wait_for_ip(timeout=wait)
    if not new_ip:
        print("[adb] no public IP after wait — check USB tethering is on")
        return None
    if old_ip and new_ip == old_ip:
        print(f"[adb] IP still {new_ip} (carrier reused it)")
    else:
        print(f"[adb] new IP={new_ip}")
    return new_ip


def main() -> None:
    p = argparse.ArgumentParser(description="ADB-cycle phone IP (USB tether + debugging required)")
    p.add_argument("--once", action="store_true", help="Cycle once and print the public IP")
    p.add_argument("--serial", default=os.getenv("ADB_SERIAL") or "", help="adb device serial")
    p.add_argument("--wait", type=float, default=60.0, help="Seconds to wait for internet after cycle")
    args = p.parse_args()
    serial = args.serial.strip() or None
    if not args.once:
        p.print_help()
        print("\nTest with: uv run python adb_rotate.py --once")
        return
    try:
        find_adb()
        require_device(serial)
    except Exception as e:
        print(f"[-] {e}")
        sys.exit(1)
    ip = rotate_ip(serial=serial, wait=args.wait)
    sys.exit(0 if ip else 1)


if __name__ == "__main__":
    main()
