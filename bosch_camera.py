#!/usr/bin/env python3
"""
Bosch Smart Home Camera — All-in-one Standalone Tool
Version: 2.0.0
=====================================================
No hardcoded camera IDs or credentials.
All configuration is stored in bosch_config.json (created on first run).

First run:
  1. Creates bosch_config.json with empty credentials
  2. Prompts for Bearer token (via mitmproxy — see README)
  3. Auto-discovers all cameras from the API
  4. Saves cameras + token to config file

Subsequent runs:
  • Reads cameras from config (no repeated discovery needed)
  • If token is expired → prompts for a fresh one → saves to config

Snapshot methods (newest → fastest, tried in order):
  1. Cloud proxy live snap  — proxy-NN.live.cbs.boschsecurity.com snap.jpg
                               (only if a live connection has been opened)
  2. Local camera snap      — https://<local_ip>/snap.jpg  (Digest auth)
                               (only if local_ip + credentials are set in config)
  3. Latest event snapshot  — most recent motion-triggered JPEG from cloud events API
                               (always available, but only updates on motion)

Usage (interactive menu):
  python3 bosch_camera.py

Usage (CLI):
  python3 bosch_camera.py status
  python3 bosch_camera.py snapshot [<cam-name>] [--live]   # --live: prefer live methods
  python3 bosch_camera.py liveshot [<cam-name>]            # alias: forces live methods
  python3 bosch_camera.py live     [<cam-name>]            # open RTSP stream in VLC
  python3 bosch_camera.py download [<cam-name>] [--limit N] [--snaps-only] [--clips-only]
  python3 bosch_camera.py events   [<cam-name>] [--limit N]
  python3 bosch_camera.py config                           # show current config
  python3 bosch_camera.py rescan                           # re-discover cameras
"""

import os
import sys
import json
import time
import shutil
import datetime
import argparse
import subprocess
import urllib3

import requests

urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "bosch_config.json")
CLOUD_API   = "https://residential.cbs.boschsecurity.com"
VERSION     = "3.0.0"

DELAY = 0.5   # seconds between download requests (rate-limit protection)

# ConnectionType enum — confirmed working values (discovered 2026-03-19)
# REMOTE = cloud proxy snap.jpg (fast ~1.5s, no credentials needed)
# LOCAL  = direct LAN snap.jpg (slow ~15s Digest auth, same quality)
# Use REMOTE first for all operations — it is faster than LOCAL despite going via cloud.
LIVE_TYPE_CANDIDATES = [
    "REMOTE",   # ✅ cloud proxy — faster (1.5s vs 15s for LOCAL)
    "LOCAL",    # ✅ LAN direct — fallback if cloud unavailable
]

DEFAULT_CONFIG = {
    "account": {
        "username":      "",
        "password":      "",
        "bearer_token":  "",
        "refresh_token": "",
        "_note": (
            "Set username (your Bosch SingleKey ID email). "
            "Run 'python3 get_token.py' to get tokens automatically via browser login. "
            "After first login the refresh_token enables silent renewal forever."
        ),
    },
    "cameras": {
        # Auto-populated on first run. Example entry:
        # "MyCam": {
        #   "id":              "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        #   "name":            "MyCam",
        #   "model":           "CAMERA_EYES",
        #   "firmware":        "...",
        #   "mac":             "xx:xx:xx:xx:xx:xx",
        #   "download_folder": "MyCam",
        #   "local_ip":        "",   ← optional: set for local snap.jpg access
        #   "local_username":  "",   ← local camera Digest auth username
        #   "local_password":  "",   ← local camera Digest auth password
        #   "last_live": { "rtsp_url": "", "proxy_url": "", "cookie": "" }
        # }
    },
    "settings": {
        "download_base_path":    "",
        "scan_interval_seconds": 30,
        "request_delay_seconds": 0.5,
        "_note": (
            "download_base_path: folder for downloaded events. "
            "Empty = use this script's directory. "
            "local_ip / local_username / local_password per camera: "
            "enables direct local snap.jpg (HTTP Digest auth). "
            "local_ip and credentials are optional — cloud API works without them."
        ),
    },
}
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════ CONFIG MANAGEMENT ═════════════════════════════════

def load_config() -> dict:
    """Load config from file. Creates default config if it doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        _create_default_config()
    with open(CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    # Merge in any missing keys from DEFAULT_CONFIG (forward-compat)
    _merge_defaults(cfg, DEFAULT_CONFIG)
    return cfg


def save_config(cfg: dict) -> None:
    """Save config to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _create_default_config() -> None:
    """Create a new config file with defaults and print instructions."""
    save_config(DEFAULT_CONFIG)
    print(f"\n✅  Created config file: {CONFIG_FILE}")
    print("    Edit it to add your credentials, or continue — the script will prompt you.\n")


def _merge_defaults(cfg: dict, defaults: dict) -> None:
    """Recursively add missing keys from defaults into cfg (in-place)."""
    for key, val in defaults.items():
        if key not in cfg:
            cfg[key] = val
        elif isinstance(val, dict) and isinstance(cfg[key], dict):
            _merge_defaults(cfg[key], val)


# ══════════════════════════ TOKEN MANAGEMENT ══════════════════════════════════

def _is_token_expired(token: str) -> bool:
    """Return True if the JWT bearer token is expired or expiring within 60s."""
    import base64 as _b64, json as _json
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            pad  = len(parts[1]) % 4
            body = _b64.urlsafe_b64decode(parts[1] + "=" * pad)
            exp  = _json.loads(body).get("exp", 0)
            return exp > 0 and (exp - time.time()) < 60
    except Exception:
        pass
    return False


def get_token(cfg: dict) -> str:
    """
    Return a valid Bearer token. Tries in order:
      1. Saved bearer_token in config (if not expired)
      2. Silent renewal via refresh_token (auto, no user interaction)
      3. Browser login via get_token.py (auto-opens browser)
      4. Manual paste as last resort
    """
    token = cfg["account"].get("bearer_token", "").strip()
    if token and not _is_token_expired(token):
        return token

    # Token expired or missing — try silent renewal first
    refresh = cfg["account"].get("refresh_token", "").strip()
    if refresh:
        try:
            from get_token import _do_refresh
            if token:  # only print if we had a token (i.e. it expired)
                print("  🔄  Token expired — renewing automatically via refresh_token...")
            tokens = _do_refresh(refresh)
            if tokens:
                new_token   = tokens.get("access_token", "")
                new_refresh = tokens.get("refresh_token", refresh)
                cfg["account"]["bearer_token"]  = new_token
                cfg["account"]["refresh_token"] = new_refresh
                save_config(cfg)
                print("  ✅  Token renewed silently.")
                return new_token
        except ImportError:
            pass
        except Exception as e:
            print(f"  ⚠️   Silent renewal failed: {e}")

    if token:
        return token  # Expired but renewal failed — return as-is and let the API reject it

    # Try get_token.py auto-flow (refresh + browser login)
    try:
        from get_token import get_token_auto
        print("  🔑  No token in config — trying automatic token retrieval...")
        new_token = get_token_auto(cfg)
        if new_token:
            return new_token
    except ImportError:
        # get_token.py not in path — fall through to manual
        pass
    except Exception as e:
        print(f"  ⚠️   Auto-token failed: {e}")

    # Manual fallback
    print("\n  ⚠️   Could not obtain token automatically.")
    print("  Options:")
    print("    • Run: python3 get_token.py  (browser login, saves token automatically)")
    print("    • Or paste a Bearer token captured from the Bosch Smart Home Camera app")
    print("      (See README.md for mitmproxy instructions)\n")
    token = input("  Paste Bearer token (or press Enter to exit): ").strip()
    if not token:
        print("  ❌  No token. Exiting.")
        sys.exit(1)
    cfg["account"]["bearer_token"] = token
    save_config(cfg)
    print(f"  💾  Token saved.")
    return token


def check_token_age(cfg: dict) -> str:
    """Return human-readable token expiry decoded from JWT claims."""
    import base64 as _b64, json as _json
    token = cfg["account"].get("bearer_token", "").strip()
    if not token:
        return "no token"
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            pad  = len(parts[1]) % 4
            body = _b64.urlsafe_b64decode(parts[1] + "=" * pad)
            info = _json.loads(body)
            exp  = info.get("exp", 0)
            if exp:
                exp_dt = datetime.datetime.fromtimestamp(exp)
                diff   = exp_dt - datetime.datetime.now()
                mins   = int(diff.total_seconds() / 60)
                if mins > 5:
                    return f"valid, expires in ~{mins}m ✅"
                elif mins > 0:
                    return f"expires in ~{mins}m ⚠️"
                else:
                    return f"EXPIRED {abs(mins)}m ago ❌  — run: python3 bosch_camera.py token fix"
    except Exception:
        pass
    # Fallback to file mtime
    mtime = os.path.getmtime(CONFIG_FILE)
    age   = datetime.datetime.now() - datetime.datetime.fromtimestamp(mtime)
    mins  = int(age.total_seconds() / 60)
    if mins < 60:
        return f"~{mins} min old ✅"
    elif mins < 120:
        return f"~{mins} min old ⚠️  (may be expired)"
    else:
        return f"~{mins} min old ❌  — run: python3 bosch_camera.py token fix"


def handle_401(cfg: dict) -> str:
    """Called when API returns 401. Clears token, prompts for a new one."""
    print("\n  ❌  Bearer token expired (HTTP 401).")
    cfg["account"]["bearer_token"] = ""
    return get_token(cfg)


# ══════════════════════════ SESSION ═══════════════════════════════════════════

def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
    s.verify = False
    return s


# ══════════════════════════ CAMERA DISCOVERY ══════════════════════════════════

def discover_cameras(cfg: dict, session: requests.Session) -> dict:
    """
    GET /v11/video_inputs → discover all cameras.
    Returns dict keyed by camera name (title):
      {
        "MyCam": { "id": "...", "name": "MyCam", "model": "...",
                    "firmware": "...", "mac": "...", "download_folder": "MyCam" },
        ...
      }
    Saves discovered cameras to config.
    """
    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        return {}
    r.raise_for_status()

    cam_list = r.json()
    cameras  = {}
    for cam in cam_list:
        name = cam.get("title", cam.get("id", "unknown"))
        # Keep existing local config if camera already known
        existing = cfg.get("cameras", {}).get(name, {})
        feat = cam.get("featureSupport", {})
        cameras[name] = {
            "id":              cam.get("id", ""),
            "name":            name,
            "model":           cam.get("hardwareVersion", "CAMERA"),
            "firmware":        cam.get("firmwareVersion", ""),
            "mac":             cam.get("macAddress", ""),
            "download_folder": name,
            "local_ip":        existing.get("local_ip", ""),
            "local_username":  existing.get("local_username", ""),
            "local_password":  existing.get("local_password", ""),
            "has_light":       feat.get("light", False),
            "pan_limit":       feat.get("panLimit", 0),
        }
        # Ask for local IP if not already set
        if not cameras[name]["local_ip"]:
            print(f"\n  📷  Camera: {name}")
            ip = input(f"     Local IP address (e.g. 192.168.1.100) — press Enter to skip: ").strip()
            if ip:
                cameras[name]["local_ip"] = ip
    cfg["cameras"] = cameras
    save_config(cfg)
    print(f"  💾  Discovered {len(cameras)} camera(s) → saved to {CONFIG_FILE}")
    return cameras


def get_cameras(cfg: dict, session: requests.Session) -> dict:
    """Return cameras from config; auto-discover if none are saved yet."""
    if not cfg.get("cameras"):
        print("  🔍  No cameras in config — auto-discovering...")
        return discover_cameras(cfg, session)
    return cfg["cameras"]


def resolve_cam(cfg: dict, key: str | None) -> dict:
    """
    Resolve a partial camera name to the full cameras dict entry.
    If key is None → return all cameras.
    If key matches exactly or case-insensitively → return that single camera dict.
    """
    cameras = cfg.get("cameras", {})
    if not key:
        return cameras
    # Exact match
    if key in cameras:
        return {key: cameras[key]}
    # Case-insensitive partial match
    key_lower = key.lower()
    matches = {k: v for k, v in cameras.items() if key_lower in k.lower()}
    if len(matches) == 1:
        return matches
    if len(matches) > 1:
        names = ", ".join(matches.keys())
        print(f"  ⚠️   Ambiguous camera name '{key}' — matches: {names}")
        sys.exit(1)
    print(f"  ❌  Camera '{key}' not found in config. Known: {', '.join(cameras.keys())}")
    print(f"      Run 'python3 bosch_camera.py rescan' to re-discover cameras.")
    sys.exit(1)


# ══════════════════════════ API HELPERS ═══════════════════════════════════════

def api_ping(session: requests.Session, cam_id: str) -> str:
    try:
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/ping", timeout=10)
        if r.status_code == 200:
            return r.text.strip().strip('"')
        return f"HTTP {r.status_code}"
    except Exception as e:
        return f"ERROR: {e}"


def api_get_events(session: requests.Session, cam_id: str, limit: int = 400) -> list:
    r = session.get(
        f"{CLOUD_API}/v11/events?videoInputId={cam_id}&limit={limit}", timeout=30
    )
    if r.status_code == 401:
        return []
    r.raise_for_status()
    return r.json()


def api_get_camera(session: requests.Session, cam_id: str) -> dict | None:
    """
    GET /v11/video_inputs/{cam_id} — fetch a single camera object by ID.
    Returns the camera dict or None on error.
    """
    try:
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def build_filename(event: dict, ext: str) -> str:
    ts    = event.get("timestamp", "")[:19].replace(":", "-").replace("T", "_")
    etype = event.get("eventType", "EVENT")
    ev_id = event.get("id", "")[:8]
    return f"{ts}_{etype}_{ev_id}.{ext}"


def get_download_folder(cfg: dict, cam_info: dict) -> str:
    """Resolve the absolute download folder for a camera."""
    base = cfg["settings"].get("download_base_path", "") or BASE_DIR
    return os.path.join(base, cam_info.get("download_folder", cam_info["name"]))


# ══════════════════════════ OPEN FILE / VLC ═══════════════════════════════════

def open_file(path: str) -> None:
    if sys.platform == "darwin":
        subprocess.Popen(["open", path])
    elif sys.platform.startswith("linux"):
        subprocess.Popen(["xdg-open", path])
    else:
        os.startfile(path)


def open_vlc(url: str, user: str = "", password: str = "", token: str = "") -> None:
    # Prefer ffplay/mpv for RTSP — they support custom headers for Bearer auth.
    # VLC does not support Authorization headers for RTSP.
    if url.startswith("rtsp://"):
        players = [
            shutil.which("ffplay"),
            shutil.which("mpv"),
            shutil.which("vlc"),
            "/Applications/VLC.app/Contents/MacOS/VLC",
        ]
    else:
        players = [
            shutil.which("vlc"),
            "/Applications/VLC.app/Contents/MacOS/VLC",
            shutil.which("mpv"),
            shutil.which("ffplay"),
        ]
    player = next((p for p in players if p and os.path.exists(p)), None)
    if not player:
        print(f"\n  ❌  No media player found (VLC / mpv / ffplay).")
        print(f"      Install:  brew install ffmpeg   # or brew install --cask vlc")
        print(f"      Stream URL:   {url}")
        return

    print(f"\n  ▶️   Opening in {os.path.basename(player)}: {url}")

    name = os.path.basename(player).lower()
    if "ffplay" in name:
        cmd = [player, "-rtsp_transport", "tcp"]
        if token:
            cmd += ["-headers", f"Authorization: Bearer {token}\r\n"]
        cmd += [url]
    elif "mpv" in name:
        cmd = [player]
        if token:
            cmd += [f"--http-header-fields=Authorization: Bearer {token}"]
        cmd += [url]
    else:
        # VLC — embed creds in URL if provided, otherwise try as-is
        open_url = url
        if user and password and url.startswith("rtsp://"):
            from urllib.parse import quote
            host_part = url[len("rtsp://"):]
            open_url = f"rtsp://{quote(user, safe='')}:{quote(password, safe='')}@{host_part}"
        cmd = [player, open_url]
        if token and "vlc" in name:
            cmd += ["--http-cookie", f"HcsoB={token[:20]}"]

    if user:
        print(f"  🔑  Using credentials: {user}")
    subprocess.Popen(cmd)


# ══════════════════════════ COMMANDS ══════════════════════════════════════════

def cmd_status(cfg: dict, args) -> None:
    """Show all cameras with ONLINE/OFFLINE status."""
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)

    print(f"\n── Bosch Smart Home Cameras ────────────────────────────────")
    print(f"   Token age: {check_token_age(cfg)}\n")

    for name, cam_info in cameras.items():
        status = api_ping(session, cam_info["id"])
        icon   = "🟢" if status == "ONLINE" else "🔴"
        print(f"  {icon}  {name}")
        print(f"      ID:      {cam_info['id']}")
        print(f"      Model:   {cam_info['model']}   FW: {cam_info['firmware']}")
        print(f"      MAC:     {cam_info['mac']}")
        print(f"      Status:  {status}")
        print()


def cmd_events(cfg: dict, args) -> None:
    """Show latest events for a camera."""
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    limit   = getattr(args, "limit", None) or 10
    cams    = resolve_cam(cfg, getattr(args, "cam", None))

    for name, cam_info in cams.items():
        print(f"\n── Events: {name} (last {limit}) ────────────────────────────")
        events = api_get_events(session, cam_info["id"], limit=limit)
        if not events:
            print("  (no events or token expired)")
            continue
        for ev in events:
            ts    = ev.get("timestamp", "")[:19]
            etype = ev.get("eventType", "")
            has_img  = "📸" if ev.get("imageUrl")     else "  "
            has_clip = "🎬" if ev.get("videoClipUrl") else "  "
            clip_st  = ev.get("videoClipUploadStatus", "")
            print(f"  {has_img}{has_clip}  {ts}  {etype:20s}  {clip_st}")


# ══════════════════════════ LIVE SNAPSHOT METHODS ═══════════════════════════

def snap_from_proxy(cam_info: dict, token: str, hq: bool = False) -> bytes | None:
    """
    Live snapshot via PUT /connection.
    Tries LOCAL first (faster on home network), then REMOTE (cloud proxy).
    If snap.jpg returns 404 (proxy session expired), automatically re-requests
    a fresh connection and retries once.
    hq=True requests highQualityVideo in the connection payload.
    Returns JPEG bytes or None.
    """
    cam_id  = cam_info.get("id", "")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _fetch_snap(conn_type: str) -> bytes | None:
        label = "local" if conn_type == "LOCAL" else "cloud proxy"
        print(f"  🌐  Opening {label} connection...")
        r = requests.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
            headers=headers, json={"type": conn_type, "highQualityVideo": hq}, verify=False, timeout=15,
        )
        if r.status_code != 200:
            return None
        data     = r.json()
        urls     = data.get("urls", [])
        scheme   = data.get("imageUrlScheme", "https://{url}/snap.jpg")
        api_user = data.get("user") or ""
        api_pass = data.get("password") or ""
        if not urls:
            return None
        snap_url = scheme.replace("{url}", urls[0])
        snap_timeout = 5 if conn_type == "LOCAL" else 15
        if api_user and api_pass:
            from requests.auth import HTTPDigestAuth
            snap_r = requests.get(snap_url, auth=HTTPDigestAuth(api_user, api_pass),
                                  verify=False, timeout=snap_timeout)
        else:
            snap_r = requests.get(snap_url, verify=False, timeout=snap_timeout)
        if snap_r.status_code == 200 and snap_r.headers.get("Content-Type", "").startswith("image"):
            print(f"  ✅  Live snapshot ({label}): {len(snap_r.content):,} bytes")
            return snap_r.content
        elif snap_r.status_code == 404:
            print(f"  ⚠️   Proxy session expired (404) — re-requesting connection...")
            # Retry once with a fresh connection
            r2 = requests.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
                headers=headers, json={"type": conn_type, "highQualityVideo": hq}, verify=False, timeout=15,
            )
            if r2.status_code == 200:
                data2     = r2.json()
                urls2     = data2.get("urls", [])
                scheme2   = data2.get("imageUrlScheme", "https://{url}/snap.jpg")
                api_user2 = data2.get("user") or ""
                api_pass2 = data2.get("password") or ""
                if urls2:
                    snap_url2 = scheme2.replace("{url}", urls2[0])
                    if api_user2 and api_pass2:
                        from requests.auth import HTTPDigestAuth
                        snap_r2 = requests.get(snap_url2, auth=HTTPDigestAuth(api_user2, api_pass2),
                                               verify=False, timeout=snap_timeout)
                    else:
                        snap_r2 = requests.get(snap_url2, verify=False, timeout=snap_timeout)
                    if snap_r2.status_code == 200 and snap_r2.headers.get("Content-Type", "").startswith("image"):
                        print(f"  ✅  Live snapshot ({label}, retry): {len(snap_r2.content):,} bytes")
                        return snap_r2.content
            print(f"  ⚠️   {label} snap retry also failed")
            return None
        else:
            print(f"  ⚠️   {label} snap returned HTTP {snap_r.status_code}")
            return None

    for conn_type in LIVE_TYPE_CANDIDATES:
        try:
            result = _fetch_snap(conn_type)
            if result:
                return result
        except Exception as e:
            label = "local" if conn_type == "LOCAL" else "cloud proxy"
            print(f"  ⚠️   {label} error: {e}")
    return None


def snap_from_local(cam_info: dict) -> bytes | None:
    """
    Method 2 — Local camera snap.jpg via HTTP Digest authentication.
    Direct access to the camera at https://<local_ip>/snap.jpg
    Returns 1920×1080 JPEG bytes or None.

    Credentials are randomly generated by the SHC at pairing time.
    Capture via mitmproxy and store in config under local_ip / local_username / local_password.

    WARNING: Excessive requests to the local camera IP can break the connection,
    causing the SHC to regenerate random credentials. Use sparingly.
    """
    local_ip   = cam_info.get("local_ip", "")
    username   = cam_info.get("local_username", "")
    password   = cam_info.get("local_password", "")

    if not local_ip or not username or not password:
        return None

    url = f"https://{local_ip}/snap.jpg"
    print(f"  🏠  Trying local camera snapshot: {url}")
    try:
        from requests.auth import HTTPDigestAuth
        r = requests.get(
            url,
            auth=HTTPDigestAuth(username, password),
            timeout=10,
            verify=False,
        )
        if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image"):
            print(f"  ✅  Local snapshot: {len(r.content):,} bytes  (1920×1080)")
            return r.content
        else:
            print(f"  ⚠️   Local camera returned {r.status_code}")
    except Exception as e:
        print(f"  ⚠️   Local camera error: {e}")
    return None


def snap_from_events(session, cam_info: dict) -> tuple[bytes | None, str]:
    """
    Method 3 — Latest event snapshot (cloud API, motion-triggered).
    Returns (jpeg_bytes, timestamp_str) or (None, "").
    Only updates when the camera detects motion — not a live view.
    """
    events = api_get_events(session, cam_info["id"], limit=10)
    for ev in events:
        img_url = ev.get("imageUrl")
        if not img_url:
            continue
        try:
            r = session.get(img_url, timeout=20)
            if r.status_code == 200:
                ts = ev.get("timestamp", "")[:19]
                return r.content, ts
        except Exception:
            pass
    return None, ""


def _save_and_open(data: bytes, name: str, ts: str, method: str) -> str:
    """Save image bytes to file and open in Preview. Returns file path."""
    safe_name = name.replace(" ", "_")
    ts_safe   = ts.replace(":", "-").replace("T", "_") if ts else \
                datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fn   = f"snapshot_{safe_name}_{ts_safe}_{method}.jpg"
    path = os.path.join(BASE_DIR, fn)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  💾  {path}  ({len(data):,} bytes)")
    open_file(path)
    return path


# ─────────────────────────────────────────────────────────────────────────────
def cmd_snapshot(cfg: dict, args) -> None:
    """
    Fetch and open the best available snapshot for a camera.

    Without --live: shows latest event snapshot (cloud events API).
    With --live:    tries methods in order:
                      1. Cloud proxy live snap (if live connection previously opened)
                      2. Local camera snap.jpg (if local_ip + credentials in config)
                      3. Latest event snapshot (fallback)
    --hq: request highQualityVideo=true in PUT /connection (higher resolution).
    """
    token   = get_token(cfg)
    session = make_session(token)
    session.headers["Accept"] = "*/*"
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))
    live    = getattr(args, "live", False)
    quality = getattr(args, "quality", None)
    if quality == "high":
        hq = True
    elif quality is not None:
        hq = False
    else:
        hq = getattr(args, "hq", False)

    for name, cam_info in cams.items():
        mode_str = "Live Snapshot" if live else "Latest Event Snapshot"
        print(f"\n── {mode_str}: {name} ──────────────────────────────────────")

        if live:
            # ── Method 1: Cloud proxy live snap ───────────────────────────────
            data = snap_from_proxy(cam_info, token, hq=hq)
            if data:
                _save_and_open(data, name, "", "proxy_live")
                continue

            # ── Method 2: Local camera snap.jpg ───────────────────────────────
            data = snap_from_local(cam_info)
            if data:
                _save_and_open(data, name, "", "local_live")
                continue

            print("  ℹ️   Live methods unavailable:")
            if not cam_info.get("last_live", {}).get("proxy_url"):
                print("       • Cloud proxy: no live connection opened yet")
                print("         → Press 'Open Live Stream' button in HA, or run: live " + name)
            if not cam_info.get("local_ip"):
                print("       • Local: no local_ip set in config")
                print(f"         → Edit {CONFIG_FILE} and set local_ip, local_username, local_password")
            print("  ↩️   Falling back to latest event snapshot...\n")

        # ── Method 3 (or default): Latest event snapshot ──────────────────────
        data, ts = snap_from_events(session, cam_info)
        if data:
            _save_and_open(data, name, ts, "event")
            if not live:
                print(f"  ℹ️   This is a motion-triggered snapshot from {ts[:10]},")
                print(f"       not a live view. Use '--live' for live snapshot methods.")
        else:
            print("  ⚠️   No snapshot available (token expired or no events).")


def cmd_download(cfg: dict, args) -> None:
    """Bulk-download all events (snaps + clips) for a camera."""
    token    = get_token(cfg)
    session  = make_session(token)
    session.headers["Accept"] = "*/*"
    cameras  = get_cameras(cfg, session)
    cams     = resolve_cam(cfg, getattr(args, "cam", None))

    limit       = getattr(args, "limit",      None)
    snaps_only  = getattr(args, "snaps_only",  False)
    clips_only  = getattr(args, "clips_only",  False)
    re_download = getattr(args, "re_download", False)

    start = datetime.datetime.now()

    for name, cam_info in cams.items():
        folder = get_download_folder(cfg, cam_info)
        os.makedirs(folder, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"📷  {name}  ({cam_info['id']})")
        print(f"📂  {folder}")
        print(f"{'='*60}")

        url = f"{CLOUD_API}/v11/events?videoInputId={cam_info['id']}"
        if limit:
            url += f"&limit={limit}"

        r = session.get(url, timeout=30)
        if r.status_code == 401:
            print("  ❌  Token expired — recapture needed.")
            cfg["account"]["bearer_token"] = ""
            save_config(cfg)
            sys.exit(1)
        r.raise_for_status()
        events = r.json()
        print(f"  Found {len(events)} events\n")

        snaps_dl = clips_dl = snaps_skip = clips_skip = snaps_miss = clips_miss = 0

        for i, ev in enumerate(events):
            img_url  = ev.get("imageUrl")
            clip_url = ev.get("videoClipUrl")
            ts       = ev.get("timestamp", "")[:19]
            etype    = ev.get("eventType", "")
            print(f"  [{i+1}/{len(events)}]  {ts}  {etype}")

            # ── Snapshot ──────────────────────────────────────────────────────
            if not clips_only:
                if img_url:
                    fn   = build_filename(ev, "jpg")
                    dest = os.path.join(folder, fn)
                    if os.path.exists(dest) and not re_download:
                        print(f"    ⏭️   Skip: {fn}")
                        snaps_skip += 1
                    else:
                        time.sleep(DELAY)
                        rr = session.get(img_url, timeout=60, stream=True)
                        if rr.status_code == 200:
                            with open(dest, "wb") as f:
                                for chunk in rr.iter_content(65536):
                                    f.write(chunk)
                            print(f"    💾  {fn}  ({os.path.getsize(dest):,} bytes)")
                            snaps_dl += 1
                        else:
                            print(f"    ❌  snap HTTP {rr.status_code}")
                else:
                    snaps_miss += 1

            # ── Video clip ────────────────────────────────────────────────────
            if not snaps_only:
                if clip_url and ev.get("videoClipUploadStatus") == "Done":
                    fn   = build_filename(ev, "mp4")
                    dest = os.path.join(folder, fn)
                    if os.path.exists(dest) and not re_download:
                        print(f"    ⏭️   Skip: {fn}")
                        clips_skip += 1
                    else:
                        time.sleep(DELAY)
                        rr = session.get(clip_url, timeout=120, stream=True)
                        if rr.status_code == 200:
                            with open(dest, "wb") as f:
                                for chunk in rr.iter_content(65536):
                                    f.write(chunk)
                            sz = os.path.getsize(dest)
                            szm = f"{sz/1_000_000:.1f} MB" if sz > 1_000_000 else f"{sz:,} bytes"
                            print(f"    🎬  {fn}  ({szm})")
                            clips_dl += 1
                        else:
                            print(f"    ❌  clip HTTP {rr.status_code}")
                elif not clip_url:
                    clips_miss += 1
                else:
                    print(f"    ⏳  Clip not ready: {ev.get('videoClipUploadStatus')}")

        print(f"\n  ✅  Summary — {name}:")
        if not clips_only:
            print(f"      Snapshots: {snaps_dl} downloaded, {snaps_skip} skipped, {snaps_miss} no image")
        if not snaps_only:
            print(f"      Clips:     {clips_dl} downloaded, {clips_skip} skipped, {clips_miss} no clip")

    elapsed = datetime.datetime.now() - start
    print(f"\n🏁  Done in {elapsed.seconds}s")
    for name, cam_info in cams.items():
        folder = get_download_folder(cfg, cam_info)
        if os.path.exists(folder):
            files = [f for f in os.listdir(folder) if not f.startswith(".")]
            total = sum(os.path.getsize(os.path.join(folder, f)) for f in files)
            szm   = f"{total/1_000_000:.1f} MB" if total > 1_000_000 else f"{total:,} bytes"
            print(f"   📂  {folder}  →  {len(files)} files, {szm}")


def _live_snap_loop(snap_url: str, cam_name: str, interval: float = 1.0) -> None:
    """
    Live view: serves snap.jpg frames as a local MJPEG stream, then opens ffplay on it.
    ffplay connects to http://localhost:PORT and receives a continuous MJPEG feed.
    Press Q in the ffplay window or Ctrl+C in the terminal to stop.
    """
    import threading
    import http.server
    import socket

    ffplay = shutil.which("ffplay") or "/opt/homebrew/bin/ffplay"
    if not os.path.exists(ffplay):
        ffplay = None

    if not ffplay:
        print(f"\n  ❌  ffplay not found. Install with: brew install ffmpeg\n")
        return

    # Find a free port
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    stop_event = threading.Event()
    frame_lock  = threading.Lock()
    current_frame: list = [None]  # [bytes | None]

    # ── Fetcher thread: polls snap.jpg ────────────────────────────────────────
    def fetcher():
        count = 0
        while not stop_event.is_set():
            t0 = time.time()
            try:
                r = requests.get(snap_url, verify=False, timeout=10)
                if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image"):
                    with frame_lock:
                        current_frame[0] = r.content
                    count += 1
                    print(f"\r  🖼️   Frame {count}  {len(r.content):,} bytes", end="", flush=True)
                elif r.status_code == 404:
                    print(f"\n  ⏰  Proxy session expired after {count} frames.")
                    stop_event.set()
                    break
            except Exception:
                pass
            elapsed = time.time() - t0
            remaining = interval - elapsed
            if remaining > 0:
                stop_event.wait(remaining)

    # ── MJPEG HTTP server ─────────────────────────────────────────────────────
    class MJPEGHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass  # silence request logs

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=--frame")
            self.end_headers()
            try:
                while not stop_event.is_set():
                    with frame_lock:
                        frame = current_frame[0]
                    if frame:
                        header = (
                            f"--frame\r\n"
                            f"Content-Type: image/jpeg\r\n"
                            f"Content-Length: {len(frame)}\r\n\r\n"
                        ).encode()
                        self.wfile.write(header)
                        self.wfile.write(frame)
                        self.wfile.write(b"\r\n")
                        self.wfile.flush()
                    time.sleep(interval)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), MJPEGHandler)
    server.daemon_threads = True

    threading.Thread(target=fetcher, daemon=True).start()

    # Wait for first frame
    print(f"\n  📺  Starting live view (press Q in player window or Ctrl+C to stop)...")
    for _ in range(30):
        if current_frame[0]:
            break
        time.sleep(0.2)
    else:
        print("  ❌  No frames received.")
        stop_event.set()
        return

    def _serve():
        server.serve_forever()

    server_thread = threading.Thread(target=_serve, daemon=True)
    server_thread.start()

    mjpeg_url = f"http://127.0.0.1:{port}/"

    # On macOS, ffplay launched as a subprocess doesn't get a window session.
    # Use 'open -a' to properly bring the player to the foreground.
    if sys.platform == "darwin":
        # Try mpv first (works as CLI subprocess), then VLC via open -a
        mpv = shutil.which("mpv")
        vlc = "/Applications/VLC.app/Contents/MacOS/VLC"
        if mpv:
            cmd = [mpv, "--no-terminal", "--title", f"Live: {cam_name}", mjpeg_url]
            print(f"  ▶️   Launching mpv: {mjpeg_url}")
            proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
        elif os.path.exists(vlc):
            cmd = ["open", "-a", "VLC", mjpeg_url]
            print(f"  ▶️   Launching VLC: {mjpeg_url}")
            proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
        else:
            # ffplay via open — write a tiny shell script and open it
            script = os.path.join(BASE_DIR, "_live_ffplay.sh")
            with open(script, "w") as f:
                f.write(f"#!/bin/sh\n{ffplay} -loglevel warning -f mjpeg -window_title 'Live: {cam_name}' '{mjpeg_url}'\n")
            os.chmod(script, 0o755)
            cmd = ["open", "-W", "-a", "Terminal", script]
            print(f"  ▶️   Launching ffplay via Terminal: {mjpeg_url}")
            proc = subprocess.Popen(cmd)
    else:
        cmd = [ffplay, "-loglevel", "warning", "-f", "mjpeg", "-window_title", f"Live: {cam_name}", mjpeg_url]
        print(f"  ▶️   Launching: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.kill()
    finally:
        stop_event.set()
        server.shutdown()
        print(f"\n  ⏹️   Live view stopped.")


def _open_rtsps_stream(rtsps_url: str, cam_name: str, fallback_snap_url: str = "", use_vlc: bool = False) -> None:
    """
    Open live audio+video stream via rtsps:// (RTSP over TLS on port 443).
    use_vlc=True opens in VLC (macOS only, uses osascript to bring window to front).
    Default uses ffplay. Falls back to snap.jpg MJPEG loop if no player available.
    """
    ffplay = shutil.which("ffplay") or "/opt/homebrew/bin/ffplay"
    mpv    = shutil.which("mpv")
    vlc    = "/Applications/VLC.app/Contents/MacOS/VLC"

    if use_vlc and os.path.exists(vlc):
        # VLC can't skip TLS verification for rtsps://, so proxy via ffmpeg:
        # ffmpeg pulls rtsps:// and re-muxes to MPEG-TS over HTTP on localhost
        ffmpeg = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
        if not ffmpeg or not os.path.exists(ffmpeg):
            print("  ⚠️   ffmpeg not found — needed to proxy stream for VLC. Install: brew install ffmpeg")
            return
        import socket as _socket
        with _socket.socket() as _s:
            _s.bind(("127.0.0.1", 0))
            http_port = _s.getsockname()[1]
        local_url = f"http://127.0.0.1:{http_port}/live"
        ffmpeg_cmd = [
            ffmpeg, "-loglevel", "warning",
            "-rtsp_transport", "tcp", "-tls_verify", "0",
            "-i", rtsps_url,
            "-c", "copy", "-f", "mpegts",
            f"http://127.0.0.1:{http_port}/live",
        ]
        # ffmpeg can't serve HTTP — use pipe to VLC's stdin instead
        # Pipe: ffmpeg → stdout (mpegts) → VLC stdin
        ffmpeg_pipe = [
            ffmpeg, "-loglevel", "warning",
            "-rtsp_transport", "tcp", "-tls_verify", "0",
            "-i", rtsps_url,
            "-c", "copy", "-f", "mpegts", "pipe:1",
        ]
        print(f"  ▶️   Launching VLC via ffmpeg pipe (audio+video)...")
        proxy = subprocess.Popen(ffmpeg_pipe, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        proc  = subprocess.Popen([vlc, "-"], stdin=proxy.stdout, stderr=subprocess.DEVNULL)
        proxy.stdout.close()
        time.sleep(1.5)
        subprocess.Popen(["osascript", "-e", 'tell application "VLC" to activate'],
                         stderr=subprocess.DEVNULL)
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.kill()
        finally:
            proxy.kill()
            print(f"\n  ⏹️   Live view stopped.")
        return
    elif ffplay and os.path.exists(ffplay):
        cmd = [ffplay,
               "-rtsp_transport", "tcp",
               "-tls_verify", "0",
               "-loglevel", "warning",
               "-window_title", f"Live: {cam_name}",
               rtsps_url]
        print(f"  ▶️   Launching ffplay (audio+video): {rtsps_url}")
        proc = subprocess.Popen(cmd)
    elif mpv:
        cmd = [mpv, "--no-terminal", "--title", f"Live: {cam_name}",
               "--rtsp-tls-verification=no", rtsps_url]
        print(f"  ▶️   Launching mpv (audio+video): {rtsps_url}")
        proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
    else:
        print("  ⚠️   No player found (ffplay/mpv) — falling back to snap.jpg MJPEG (video only).")
        print("      Install with: brew install ffmpeg")
        if fallback_snap_url:
            _live_snap_loop(fallback_snap_url, cam_name)
        return

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.kill()
    finally:
        print(f"\n  ⏹️   Live view stopped.")


def cmd_live(cfg: dict, args) -> None:
    """Open live stream — tries PUT /connection → open VLC on success.

    --hq: request highQualityVideo=true in PUT /connection (higher bitrate stream).
    --inst N: select stream instance (default 2; use 1 for alternative stream).
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))

    # Quality preset overrides --hq/--inst
    quality = getattr(args, "quality", None)
    if quality == "high":
        hq   = True
        inst = getattr(args, "inst", 2) if getattr(args, "inst", 2) != 2 else 1
    elif quality == "low":
        hq   = False
        inst = getattr(args, "inst", 2) if getattr(args, "inst", 2) != 2 else 4
    else:
        hq   = getattr(args, "hq", False)
        inst = getattr(args, "inst", 2)

    for name, cam_info in cams.items():
        print(f"\n── Live Stream: {name} ──────────────────────────────────────")
        status = api_ping(session, cam_info["id"])
        icon   = "🟢" if status == "ONLINE" else "🔴"
        print(f"  {icon}  Status: {status}")

        if status != "ONLINE":
            print("  ⚠️   Camera is OFFLINE — live stream not available.")
            continue

        print("  🔄  Opening live connection...")
        url         = f"{CLOUD_API}/v11/video_inputs/{cam_info['id']}/connection"
        result      = None
        result_type = ""

        # Always use REMOTE for RTSP (LOCAL gives LAN IP which doesn't support RTSP tunnel)
        for type_val in ["REMOTE", "LOCAL"]:
            r = session.put(
                url,
                json={"type": type_val, "highQualityVideo": hq},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if r.status_code in (200, 201):
                result      = r.json()
                result_type = type_val
                print(f"  ✅  ConnectionType '{type_val}' worked!")
                break
            elif r.status_code == 401:
                print("  ❌  Token expired.")
                break

        if result:
            urls       = result.get("urls", [])
            img_scheme = result.get("imageUrlScheme", "https://{url}/snap.jpg")
            user       = result.get("user") or ""
            password   = result.get("password") or ""

            proxy_url = img_scheme.replace("{url}", urls[0]) if urls else ""
            print(f"  🌐  Snap URL:  {proxy_url or '(none)'}")
            if user:
                print(f"  🔑  Creds: {user} / {password}")

            cfg["cameras"][name]["last_live"] = {
                "type":      result_type,
                "proxy_url": proxy_url,
                "user":      user,
                "password":  password,
                "timestamp": datetime.datetime.now().isoformat()[:19],
            }
            save_config(cfg)

            if urls:
                # Build rtsps:// URL on port 443 — the proxy serves real RTSP/1.0 over
                # TLS on port 443 (port 42090 silently drops all RTSP connections).
                # No auth needed — the hash in the path is the credential.
                u = urls[0]  # e.g. proxy-20.live.cbs.boschsecurity.com:42090/{hash}
                host_port, hash_path = u.split("/", 1)
                proxy_host = host_port.split(":")[0]
                rtsps_url = (
                    f"rtsps://{proxy_host}:443/{hash_path}"
                    f"/rtsp_tunnel?inst={inst}&enableaudio=1&fmtp=1&maxSessionDuration=3600"
                )
                print(f"  📡  RTSPS URL: {rtsps_url}")
                _open_rtsps_stream(rtsps_url, name, proxy_url, use_vlc=getattr(args, "vlc", False))
            else:
                print("  ⚠️   No URLs in response.")
        else:
            print("\n  ❌  Could not open live connection.")

            # Fallback: latest snapshot
            print("\n  📸  Showing latest event snapshot instead...")
            session.headers["Accept"] = "*/*"
            events = api_get_events(session, cam_info["id"], limit=5)
            for ev in events:
                img_url = ev.get("imageUrl")
                if img_url:
                    r = session.get(img_url, timeout=20)
                    if r.status_code == 200:
                        ts   = ev.get("timestamp", "")[:19].replace(":", "-").replace("T", "_")
                        fn   = f"snapshot_{name}_{ts}.jpg"
                        path = os.path.join(BASE_DIR, fn)
                        with open(path, "wb") as f:
                            f.write(r.content)
                        print(f"  💾  {path}  ({len(r.content):,} bytes)")
                        open_file(path)
                        break


def cmd_config(cfg: dict, args) -> None:
    """Show current config (mask the token for security)."""
    display = json.loads(json.dumps(cfg))  # deep copy
    token = display["account"].get("bearer_token", "")
    if token:
        display["account"]["bearer_token"] = f"{token[:20]}...({len(token)} chars)"
    refresh = display["account"].get("refresh_token", "")
    if refresh:
        display["account"]["refresh_token"] = f"{refresh[:20]}...({len(refresh)} chars)"
    print(f"\n── Config: {CONFIG_FILE} ──────────────────────────────────")
    print(json.dumps(display, indent=2))
    print(f"\n  Token age: {check_token_age(cfg)}")


def cmd_info(cfg: dict, args) -> None:
    """Show full camera information from the API.

    Usage:
      python3 bosch_camera.py info           → standard info + stream URLs
      python3 bosch_camera.py info --full    → also fetch 8 extra endpoints
                                               (firmware, motion, audio, light, WiFi, etc.)
    """
    token   = get_token(cfg)
    session = make_session(token)
    full    = getattr(args, "full", False)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cameras = r.json()

    print(f"\n── Camera Info ──────────────────────────────────────────────")
    print(f"   Token age: {check_token_age(cfg)}\n")

    for cam in cameras:
        name   = cam.get("title", cam.get("id"))
        cam_id = cam.get("id", "")
        status = cam.get("connectionStatus", "?")
        icon   = "🟢" if status == "ONLINE" else "🔴"
        model  = cam.get("hardwareVersion", "?")
        fw     = cam.get("firmwareVersion", "?")
        mac    = cam.get("macAddress", "?")
        priv   = cam.get("privacyMode", "?")
        rec    = "✅ ON" if cam.get("recordingOn") else "❌ OFF"
        unread = cam.get("numberOfUnreadEvents", 0)
        tz     = cam.get("timeZone", "?")
        alarm  = cam.get("alarmType") or "NONE"
        notif  = cam.get("notificationsEnabledStatus", "?")

        print(f"  {icon}  {name}")
        print(f"      ID:            {cam_id}")
        print(f"      Model:         {model}   FW: {fw}")
        print(f"      MAC:           {mac}")
        print(f"      Status:        {status}")
        print(f"      Privacy mode:  {priv}")
        print(f"      Recording:     {rec}")
        print(f"      Unread events: {unread}")
        print(f"      Timezone:      {tz}")
        print(f"      Alarm:         {alarm}")
        print(f"      Notifications: {notif}")

        notifs = cam.get("notifications", {})
        notif_parts = [k for k, v in notifs.items() if v]
        if notif_parts:
            print(f"      Notif. types:  {', '.join(notif_parts)}")

        fs = cam.get("featureSupport", {})
        print(f"      Features:      light={fs.get('light')}, sound={fs.get('sound')}, "
              f"viewAngle={fs.get('viewingAngle')}°, panLimit={fs.get('panLimit')}°")

        fst = cam.get("featureStatus", {})
        print(f"      Light sched.:  {fst.get('scheduleStatus')}  "
              f"on={fst.get('generalLightOnTime')} off={fst.get('generalLightOffTime')}")
        print(f"      Light on motion: {fst.get('lightOnMotion')}  "
              f"follow-up={fst.get('lightOnMotionFollowUpTimeSeconds')}s")
        print(f"      Sound recording: {cam.get('soundIsOnForRecording')}")

        # ── WiFi info (always shown if available) ─────────────────────────
        try:
            wr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/wifiinfo", timeout=10)
            if wr.status_code == 200:
                wd = wr.json()
                ssid   = wd.get("ssid", "?")
                signal = wd.get("signalStrength", wd.get("signal", "?"))
                ip     = wd.get("ipAddress", wd.get("ip", "?"))
                mac_w  = wd.get("macAddress", wd.get("mac", "?"))
                signal_str = f"{signal}%" if isinstance(signal, int) else str(signal)
                print(f"      WiFi:          {ssid}  signal={signal_str}  IP={ip}  MAC={mac_w}")
        except Exception:
            pass

        # ── Streaming URLs (live connection) ──────────────────────────────
        cam_id_local = cam_id
        print(f"      Fetching stream URLs...")
        try:
            sr = session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id_local}/connection",
                json={"type": "REMOTE", "highQualityVideo": False},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if sr.status_code == 200:
                sd = sr.json()
                urls = sd.get("urls", [])
                if urls:
                    u = urls[0]
                    proxy_host = u.split(":")[0]
                    hash_path  = u.split("/", 1)[1]
                    snap_url   = sd.get("imageUrlScheme", "https://{url}/snap.jpg").replace("{url}", u)
                    rtsps_url  = (f"rtsps://{proxy_host}:443/{hash_path}"
                                  f"/rtsp_tunnel?inst=2&enableaudio=1&fmtp=1&maxSessionDuration=3600")
                    print(f"      Snap URL:      {snap_url}")
                    print(f"      RTSPS URL:     {rtsps_url}")
                    print(f"      Stream:        H.264 1920×1080 30fps + AAC 16kHz (session ~60s)")
            else:
                print(f"      Stream URLs:   unavailable (HTTP {sr.status_code})")
        except Exception as e:
            print(f"      Stream URLs:   error — {e}")

        # ── Extra endpoints (--full only) ─────────────────────────────────
        if full:
            print(f"\n      ── Full details (--full) ───────────────────────────────")

            # /commissioned
            try:
                cr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/commissioned", timeout=10)
                if cr.status_code == 200:
                    cd = cr.json()
                    print(f"      Commissioned:  {json.dumps(cd)}")
            except Exception:
                pass

            # /firmware
            try:
                fwr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/firmware", timeout=10)
                if fwr.status_code == 200:
                    fwd = fwr.json()
                    ver     = fwd.get("version", fwd.get("firmwareVersion", "?"))
                    up2date = fwd.get("upToDate", fwd.get("isUpToDate", "?"))
                    print(f"      Firmware:      version={ver}  upToDate={up2date}")
            except Exception:
                pass

            # /lighting_override
            try:
                lor = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_override", timeout=10)
                if lor.status_code == 200:
                    lod = lor.json()
                    front = lod.get("frontLightOn", "?")
                    wall  = lod.get("wallwasherOn", "?")
                    print(f"      Light override: frontLightOn={front}  wallwasherOn={wall}")
            except Exception:
                pass

            # /motion
            try:
                mr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion", timeout=10)
                if mr.status_code == 200:
                    md = mr.json()
                    enabled  = md.get("enabled", md.get("motionEnabled", "?"))
                    sens     = md.get("sensitivity", "?")
                    print(f"      Motion:        enabled={enabled}  sensitivity={sens}")
            except Exception:
                pass

            # /audioAlarm
            try:
                ar = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/audioAlarm", timeout=10)
                if ar.status_code == 200:
                    ad = ar.json()
                    enabled   = ad.get("enabled", ad.get("audioAlarmEnabled", "?"))
                    threshold = ad.get("threshold", ad.get("sensitivity", "?"))
                    print(f"      Audio alarm:   enabled={enabled}  threshold={threshold}")
            except Exception:
                pass

            # /recording_options
            try:
                ror = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/recording_options", timeout=10)
                if ror.status_code == 200:
                    rod = ror.json()
                    rec_sound = rod.get("recordSound", rod.get("soundIsOnForRecording", "?"))
                    print(f"      Recording opts: recordSound={rec_sound}")
            except Exception:
                pass

            # /ambient_light_sensor_level
            try:
                alr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/ambient_light_sensor_level", timeout=10)
                if alr.status_code == 200:
                    ald = alr.json()
                    level = ald.get("level", ald.get("ambientLightLevel", json.dumps(ald)))
                    print(f"      Ambient light: level={level}")
            except Exception:
                pass

            # ── RCP (via proxy) ───────────────────────────────────────────
            print(f"\n      ── RCP (via proxy) ──────────────────────────────────────")
            try:
                # We already opened a REMOTE connection above for stream URLs.
                # Re-use it by opening a new RCP session on the same proxy hash.
                _rcp_proxy_base, _ = rcp_open_connection(cam_id, token)
                _rcp_sessionid     = rcp_session(_rcp_proxy_base)
                _rcp_url           = f"{_rcp_proxy_base}/rcp.xml"

                # Product name (0x0aea)
                d = rcp_read(_rcp_url, "0x0aea", _rcp_sessionid)
                if d:
                    print(f"      Product:       {rcp_parse_string(d)}")

                # Cloud FQDN (0x0aee)
                d = rcp_read(_rcp_url, "0x0aee", _rcp_sessionid)
                if d:
                    print(f"      Cloud FQDN:    {rcp_parse_string(d)}")

                # Camera clock (0x0a0f)
                d = rcp_read(_rcp_url, "0x0a0f", _rcp_sessionid)
                if d:
                    print(f"      Clock:         {rcp_parse_clock(d)}")

                # LAN IP (0x0a36)
                d = rcp_read(_rcp_url, "0x0a36", _rcp_sessionid)
                if d:
                    ip_str = rcp_parse_ip(d) if len(d) == 4 else rcp_parse_string(d)
                    print(f"      LAN IP:        {ip_str}  (via RCP)")

            except RuntimeError as _rcp_err:
                print(f"      RCP:           unavailable ({_rcp_err})")
            except Exception as _rcp_ex:
                print(f"      RCP:           error — {_rcp_ex}")

        print()


def cmd_privacy(cfg: dict, args) -> None:
    """Get or set privacy mode for a camera via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py privacy [cam-name]        → show current state
      python3 bosch_camera.py privacy [cam-name] on     → turn privacy ON
      python3 bosch_camera.py privacy [cam-name] off    → turn privacy OFF

    API: PUT /v11/video_inputs/{id}/privacy
         Body: {"privacyMode": "ON"/"OFF", "durationInSeconds": null}
         Response: HTTP 204 on success.
    No SHC local API needed — uses cloud API directly.
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    action  = getattr(args, "action", None)  # "on" / "off" / None

    # If action was parsed as cam and cam_arg looks like an action, swap them
    # (e.g. "privacy on" → cam=None, action="on")
    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action  = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    # Fetch current state from /v11/video_inputs
    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id  = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        current = cam_raw.get("privacyMode", "UNKNOWN")
        icon    = "🔒" if current.upper() == "ON" else "👁️"

        print(f"\n── Privacy Mode: {name} ─────────────────────────────────────")
        print(f"  {icon}  Current state:  {current}")

        if action is None:
            # Status only
            priv_url = f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy"
            pr = session.get(priv_url, timeout=10)
            if pr.status_code == 200:
                pd = pr.json()
                dur = pd.get("durationInSeconds")
                end = pd.get("privacyTimeEnd")
                print(f"       Duration:       {dur if dur else 'indefinite'}")
                if end:
                    print(f"       End time:       {end}")
            print(f"\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py privacy {name.lower()} on")
            continue

        # Set privacy mode
        new_state = "ON" if action == "on" else "OFF"
        if current.upper() == new_state:
            print(f"  ✅  Already {new_state} — no change needed.")
            continue

        minutes = getattr(args, "minutes", None)
        if new_state == "ON" and minutes:
            body = {"privacyMode": "ON", "privacyTimeSeconds": int(minutes) * 60}
            print(f"  🔄  Setting privacy mode → ON for {minutes} minute(s)...")
        else:
            body = {"privacyMode": new_state, "durationInSeconds": None}
            print(f"  🔄  Setting privacy mode → {new_state}...")

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            icon_new = "🔒" if new_state == "ON" else "👁️"
            print(f"  {icon_new}  Privacy mode set to {new_state}.")
            if new_state == "ON":
                if minutes:
                    print(f"     Camera is now blocked for {minutes} minute(s).")
                else:
                    print("     Camera is now blocked — no live images available.")
            else:
                print("     Camera is now active — live images available.")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_light(cfg: dict, args) -> None:
    """Get or set the camera light (manual override) via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py light [cam-name]        → show current state
      python3 bosch_camera.py light [cam-name] on     → turn light ON
      python3 bosch_camera.py light [cam-name] off    → turn light OFF

    API: PUT /v11/video_inputs/{id}/lighting_override
         ON:  {"frontLightOn": true, "wallwasherOn": true, "frontLightIntensity": 1.0}
         OFF: {"frontLightOn": false, "wallwasherOn": false}
         Response: HTTP 204 on success.
    Only available for cameras with featureSupport.light = true (outdoor camera).

    featureStatus fields (shown in status view):
      scheduleStatus         — ALWAYS_OFF / ALWAYS_ON / SCHEDULE
      frontIlluminatorInGeneralLightOn  — general light mode enabled
      lightOnMotion          — activate light on motion detection
      lightOnMotionFollowUpTimeSeconds  — how long after motion
      generalLightOnTime / generalLightOffTime  — schedule window
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    action  = getattr(args, "action", None)

    # Allow "light on" / "light off" without camera name
    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action  = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id  = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        feat_support = cam_raw.get("featureSupport", {})
        has_light    = feat_support.get("light", False)
        feat_status  = cam_raw.get("featureStatus", {})

        print(f"\n── Camera Light: {name} ─────────────────────────────────────")
        if not has_light:
            print(f"  ℹ️   This camera does not support a built-in light.")
            continue

        sched     = feat_status.get("scheduleStatus", "UNKNOWN")
        front_on  = feat_status.get("frontIlluminatorInGeneralLightOn", False)
        intensity = feat_status.get("frontIlluminatorGeneralLightIntensity", 0)
        wall_on   = feat_status.get("wallwasherInGeneralLightOn", False)
        on_time   = feat_status.get("generalLightOnTime", "?")
        off_time  = feat_status.get("generalLightOffTime", "?")
        on_motion = feat_status.get("lightOnMotion", False)
        follow_up = feat_status.get("lightOnMotionFollowUpTimeSeconds", 0)

        mode_icon = {"ALWAYS_ON": "💡", "ALWAYS_OFF": "🌑", "SCHEDULE": "📅"}.get(sched, "❓")
        print(f"  {mode_icon}  Schedule mode:       {sched}")
        print(f"  {'💡' if front_on else '🌑'}  General light mode:  {'ON' if front_on else 'OFF'}  "
              f"(intensity: {intensity:.0%})")
        if wall_on:
            print(f"  💡  Wallwasher:          ON")
        print(f"  🕐  Schedule window:     {on_time} → {off_time}")
        print(f"  🏃  Light on motion:     {'YES' if on_motion else 'NO'}  "
              f"(follow-up: {follow_up}s)")

        if action is None:
            print()
            print(f"  Run with 'on' or 'off' to toggle the manual override. E.g.:")
            print(f"    python3 bosch_camera.py light {name.lower()} on")
            continue

        # Set manual light override via cloud API
        new_state = action.upper()
        print(f"\n  🔄  Setting light override → {new_state}...")
        if action == "on":
            body = {"frontLightOn": True, "wallwasherOn": True, "frontLightIntensity": 1.0}
        else:
            body = {"frontLightOn": False, "wallwasherOn": False}

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_override",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            icon_new = "💡" if action == "on" else "🌑"
            print(f"  {icon_new}  Light override set to {new_state}.")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_pan(cfg: dict, args) -> None:
    """Get or set the pan position of the 360 camera via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py pan [cam-name]           → show current position
      python3 bosch_camera.py pan [cam-name] left      → pan to -120° (full left)
      python3 bosch_camera.py pan [cam-name] center    → pan to 0° (center)
      python3 bosch_camera.py pan [cam-name] right     → pan to +120° (full right)
      python3 bosch_camera.py pan [cam-name] <-120..120>  → pan to absolute position

    API: GET /v11/video_inputs/{id}/pan
           → {"currentAbsolutePosition": 15, "panLimit": 120}
         PUT /v11/video_inputs/{id}/pan
           Body: {"absolutePosition": -120}   (range: -panLimit to +panLimit)
           Response: {"currentAbsolutePosition": -120, "cameraStoppedAtLimit": false,
                      "estimatedTimeToCompletion": 970}
    Only available for cameras with featureSupport.panLimit > 0 (indoor 360 camera).
    Discovered 2026-03-21 via mitmproxy capture.
    """
    token   = get_token(cfg)
    session = make_session(token)
    cam_arg = getattr(args, "cam", None)
    action  = getattr(args, "action", None)

    # Allow "pan left" / "pan center" / "pan right" / "pan 45" without camera name
    PRESETS = ("left", "center", "right")
    if cam_arg and action is None:
        try:
            int(cam_arg)
            action, cam_arg = cam_arg, None   # "pan 45" → action=45, cam=None
        except ValueError:
            if cam_arg.lower() in PRESETS:
                action, cam_arg = cam_arg.lower(), None

    cams = resolve_cam(cfg, cam_arg)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id      = cam_info["id"]
        cam_raw     = cam_list.get(cam_id, {})
        pan_limit   = cam_raw.get("featureSupport", {}).get("panLimit", 0)

        print(f"\n── Pan Control: {name} ──────────────────────────────────────")
        if not pan_limit:
            print(f"  ℹ️   This camera does not support pan (panLimit=0).")
            continue

        # Fetch current position
        pr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/pan", timeout=10)
        if pr.status_code != 200:
            print(f"  ❌  Could not fetch pan state: HTTP {pr.status_code}")
            continue
        pan_data = pr.json()
        current  = pan_data.get("currentAbsolutePosition", 0)
        limit    = pan_data.get("panLimit", pan_limit)

        # Visual position bar
        pct   = (current + limit) / (2 * limit)  # 0.0 = full left, 1.0 = full right
        width = 30
        pos   = int(pct * width)
        bar   = "─" * pos + "●" + "─" * (width - pos)
        direction = "CENTER" if abs(current) < 5 else ("RIGHT ▶" if current > 0 else "◀ LEFT")
        print(f"  📍  Position:  {current:+4d}°  {direction}")
        print(f"      Range:    -{limit}° ◀ [{bar}] ▶ +{limit}°")

        if action is None:
            print(f"\n  Run with 'left', 'center', 'right', or a number (-{limit}..+{limit}). E.g.:")
            print(f"    python3 bosch_camera.py pan {name.lower()} center")
            print(f"    python3 bosch_camera.py pan {name.lower()} 45")
            continue

        # Resolve target position
        PRESET_MAP = {"left": -limit, "center": 0, "right": limit}
        if action.lower() in PRESET_MAP:
            target = PRESET_MAP[action.lower()]
        else:
            try:
                target = int(action)
            except ValueError:
                print(f"  ❌  Unknown action '{action}'. Use left/center/right or a number.")
                continue
            if not (-limit <= target <= limit):
                print(f"  ❌  Position {target} out of range (-{limit} to +{limit}).")
                continue

        if target == current:
            print(f"  ✅  Already at {target:+d}° — no change needed.")
            continue

        direction_str = "▶ right" if target > current else "◀ left"
        print(f"\n  🔄  Panning {direction_str} → {target:+d}°...")
        resp = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/pan",
            json={"absolutePosition": target},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            new_pos = data.get("currentAbsolutePosition", target)
            eta_ms  = data.get("estimatedTimeToCompletion", 0)
            at_limit = data.get("cameraStoppedAtLimit", False)
            print(f"  ✅  Moving to {new_pos:+d}°  (ETA: {eta_ms}ms)")
            if at_limit:
                print(f"  ⚠️   Camera stopped at mechanical limit.")
        else:
            print(f"  ❌  Failed: HTTP {resp.status_code}  {resp.text[:200]}")


def cmd_notifications(cfg: dict, args) -> None:
    """Get or set notification settings for a camera via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py notifications [cam-name]        → show current state
      python3 bosch_camera.py notifications [cam-name] on     → enable (FOLLOW_CAMERA_SCHEDULE)
      python3 bosch_camera.py notifications [cam-name] off    → disable (ALWAYS_OFF)

    API: PUT /v11/video_inputs/{id}/enable_notifications
         Body: {"enabledNotificationsStatus": "FOLLOW_CAMERA_SCHEDULE"/"ALWAYS_OFF"}
         Response: HTTP 204 on success.
    State is visible in GET /v11/video_inputs as notificationsEnabledStatus.
    """
    token   = get_token(cfg)
    session = make_session(token)
    cam_arg = getattr(args, "cam", None)
    action  = getattr(args, "action", None)

    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action  = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id  = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        current = cam_raw.get("notificationsEnabledStatus", "UNKNOWN")
        notif_on = current != "ALWAYS_OFF"
        icon     = "🔔" if notif_on else "🔕"

        # Friendly display for all known states
        STATE_LABELS = {
            "ALWAYS_OFF":             "OFF",
            "FOLLOW_CAMERA_SCHEDULE": "ON (follows schedule)",
            "ON_CAMERA_SCHEDULE":     "ON (explicit schedule)",
        }
        state_label = STATE_LABELS.get(current, current)

        print(f"\n── Notifications: {name} ─────────────────────────────────────")
        print(f"  {icon}  Current state:  {current}  →  {state_label}")

        if action is None:
            print(f"\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py notifications {name.lower()} on")
            continue

        new_status = "FOLLOW_CAMERA_SCHEDULE" if action == "on" else "ALWAYS_OFF"
        # ON_CAMERA_SCHEDULE also counts as "on" — don't overwrite with FOLLOW_CAMERA_SCHEDULE
        already_on  = action == "on"  and current in ("FOLLOW_CAMERA_SCHEDULE", "ON_CAMERA_SCHEDULE")
        already_off = action == "off" and current == "ALWAYS_OFF"
        if already_on or already_off:
            print(f"  ✅  Already {current} — no change needed.")
            continue

        print(f"  🔄  Setting notifications → {new_status}...")
        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/enable_notifications",
            json={"enabledNotificationsStatus": new_status},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            icon_new = "🔔" if action == "on" else "🔕"
            print(f"  {icon_new}  Notifications set to {new_status}.")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


# ── FCM Push constants (from APK analysis) ───────────────────────────────────
FCM_PROJECT_ID    = "bosch-smart-cameras"
FCM_APP_ID        = "1:404630424405:android:9e5b6b58e4c70075"
FCM_API_KEY       = "REDACTED"
FCM_SENDER_ID     = "404630424405"
FCM_CRED_KEY      = "_fcm_credentials"  # key in bosch_config.json settings


def _send_signal_alert(
    signal_url: str, sender: str, recipients: list[str],
    cam_name: str, event_type: str, ts: str,
    image_url: str = "", token: str = "",
) -> None:
    """Send an alert message (with optional snapshot) via signal-cli-rest-api.

    API: POST {signal_url}/v2/send
    Body: {"message": "...", "number": sender, "recipients": [...], "base64_attachments": [...]}
    """
    import base64 as _b64

    msg = f"{cam_name}: {event_type} um {ts}"
    body: dict = {
        "message": msg,
        "number": sender,
        "recipients": recipients,
    }

    # Download and attach the event snapshot if available
    if image_url and token:
        try:
            headers = {"Authorization": f"Bearer {token}", "Accept": "*/*"}
            r = requests.get(image_url, headers=headers, verify=False, timeout=15)
            if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                b64 = _b64.b64encode(r.content).decode()
                body["base64_attachments"] = [b64]
        except Exception as e:
            print(f"             ⚠️  Signal image download failed: {e}")

    try:
        r = requests.post(
            f"{signal_url.rstrip('/')}/v2/send",
            json=body, timeout=15,
        )
        if r.status_code in (200, 201):
            print(f"             📨 Signal alert sent to {', '.join(recipients)}")
        else:
            print(f"             ⚠️  Signal send failed: HTTP {r.status_code} {r.text[:100]}")
    except Exception as e:
        print(f"             ⚠️  Signal send error: {e}")


def _watch_fcm_push(cfg: dict, token: str, cams: dict, duration: int, auto_snap: bool,
                    signal_url: str = "", signal_sender: str = "", signal_recipients: list[str] | None = None) -> None:
    """Watch for events using FCM push notifications instead of polling.

    Near-instant event detection (~2-3s) via Firebase Cloud Messaging.
    Requires: pip install firebase-messaging
    """
    try:
        import asyncio
        from firebase_messaging import FcmPushClient, FcmRegisterConfig
    except ImportError:
        print("  ❌  firebase-messaging not installed. Install with:")
        print("      pip3 install firebase-messaging")
        return

    session_req = make_session(token)
    cam_ids = {name: info["id"] for name, info in cams.items()}

    # Build baseline
    last_seen: dict[str, str] = {}
    print(f"\n  Fetching baseline events...")
    for name, cam_info in cams.items():
        events = api_get_events(session_req, cam_info["id"], limit=1)
        if events:
            last_seen[name] = events[0].get("id", "")
        print(f"  {name}: baseline = {last_seen.get(name, '(none)')[:8]}")

    total_new = [0]
    start_time = [time.time()]

    def on_notification(notification, persistent_id, obj=None):
        """Called on each FCM push — fetch events for all cameras."""
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        # Re-get token in case it was refreshed
        tok = cfg["account"].get("bearer_token", token)
        sess = make_session(tok)

        for name, cam_id in cam_ids.items():
            try:
                events = api_get_events(sess, cam_id, limit=5)
            except Exception:
                events = []
            if not events:
                continue

            baseline = last_seen.get(name, "")
            new_events = []
            for ev in events:
                if ev.get("id", "") == baseline:
                    break
                new_events.append(ev)

            for ev in reversed(new_events):
                etype   = ev.get("eventType", "EVENT")
                ts      = ev.get("timestamp", "")[:19]
                img_url = ev.get("imageUrl", "")
                clip_url = ev.get("videoClipUrl", "")
                icon    = "🔊" if "AUDIO" in etype else "🚨"
                print(f"\n  [{now_str}] {icon} {etype:<15s}  cam={name:<12s}  {ts}  (via FCM push)")
                if img_url:
                    print(f"             📸 {img_url}")
                if clip_url:
                    print(f"             🎬 {clip_url}")
                total_new[0] += 1

                # Signal alert
                if signal_url and signal_sender and signal_recipients:
                    _send_signal_alert(
                        signal_url, signal_sender, signal_recipients,
                        name, etype, ts, img_url, tok,
                    )

                if auto_snap and img_url:
                    try:
                        r = sess.get(img_url, verify=False, timeout=15)
                        if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                            fname = f"event_{name}_{ts.replace(':', '-')}.jpg"
                            fpath = os.path.join(BASE_DIR, fname)
                            with open(fpath, "wb") as f:
                                f.write(r.content)
                            print(f"             💾 Saved: {fpath}")
                            open_file(fpath)
                    except Exception as e:
                        print(f"             ⚠️  Snapshot error: {e}")

            if new_events:
                last_seen[name] = new_events[0].get("id", baseline)

    def on_creds_updated(creds):
        cfg["settings"][FCM_CRED_KEY] = creds
        save_config(cfg)

    async def _run():
        fcm_config = FcmRegisterConfig(
            project_id=FCM_PROJECT_ID,
            app_id=FCM_APP_ID,
            api_key=FCM_API_KEY,
            messaging_sender_id=FCM_SENDER_ID,
        )

        saved_creds = cfg.get("settings", {}).get(FCM_CRED_KEY)

        client = FcmPushClient(
            callback=on_notification,
            fcm_config=fcm_config,
            credentials=saved_creds,
            credentials_updated_callback=on_creds_updated,
        )

        print(f"\n  🔑  Registering with FCM...")
        fcm_token = await client.checkin_or_register()
        print(f"  ✅  FCM Token: {fcm_token[:50]}...")

        # Register with Bosch CBS
        print(f"  🔗  Registering with Bosch CBS...")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        r = requests.post(
            f"{CLOUD_API}/v11/devices",
            headers=headers,
            json={"deviceType": "ANDROID", "deviceToken": fcm_token},
            verify=False, timeout=10,
        )
        if r.status_code in (200, 201, 204):
            print(f"  ✅  Registered with Bosch CBS!")
        else:
            print(f"  ⚠️   CBS registration: HTTP {r.status_code} — pushes may not arrive")

        n_cams = len(cams)
        print(f"\n  📡  Listening for FCM pushes ({n_cams} camera(s))...")
        print(f"      Near-instant event detection (~2-3s latency)")
        if duration:
            print(f"      Will stop after {duration}s.")
        print(f"      Press Ctrl+C to stop.\n")

        start_time[0] = time.time()

        await client.start()

        try:
            while True:
                await asyncio.sleep(1)
                if duration and (time.time() - start_time[0]) >= duration:
                    print(f"\n  Duration of {duration}s reached — stopping.")
                    break
        except asyncio.CancelledError:
            pass
        finally:
            await client.stop()

    try:
        import asyncio
        asyncio.run(_run())
    except KeyboardInterrupt:
        elapsed = int(time.time() - start_time[0])
        print(f"\n\n  Stopped after {elapsed}s. Total new events: {total_new[0]}")


def cmd_watch(cfg: dict, args) -> None:
    """
    Watch for new camera events by polling GET /v11/events every N seconds.

    Usage:
      python3 bosch_camera.py watch [<cam-name>] [--interval N] [--duration N]

    Polls every --interval seconds (default 30). Runs until Ctrl+C or --duration
    seconds elapsed. Prints each new event with type, timestamp, image URL and
    clip URL.
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))
    interval  = getattr(args, "interval", 30) or 30
    duration  = getattr(args, "duration", 0) or 0
    auto_snap = getattr(args, "snapshot", False)
    use_push  = getattr(args, "push", False)
    signal_url = getattr(args, "signal", "") or ""
    signal_sender = getattr(args, "signal_sender", "") or ""
    signal_recipients_str = getattr(args, "signal_recipients", "") or ""
    signal_recipients = [r.strip() for r in signal_recipients_str.split(",") if r.strip()] if signal_recipients_str else []

    if signal_url:
        print(f"  📨  Signal alerts → {signal_url} (sender={signal_sender}, recipients={signal_recipients})")

    if use_push:
        _watch_fcm_push(cfg, token, cams, duration, auto_snap,
                        signal_url, signal_sender, signal_recipients)
        return

    # Build initial baseline of seen event IDs per camera
    last_seen: dict[str, str] = {}
    print(f"\n  Fetching baseline events...")
    for name, cam_info in cams.items():
        events = api_get_events(session, cam_info["id"], limit=1)
        if events:
            last_seen[name] = events[0].get("id", "")
        else:
            last_seen[name] = ""
        print(f"  {name}: baseline event id = {last_seen[name] or '(none)'}")

    n_cams = len(cams)
    print(f"\nWatching {n_cams} camera(s)... (Ctrl+C to stop)")
    if duration:
        print(f"  Will stop after {duration}s.")
    print(f"  Polling every {interval}s.")
    if auto_snap:
        print(f"  --snapshot: will auto-download and open event JPEG on new events.")
    print()

    start_time = time.time()
    total_new  = 0

    def _renew_session() -> tuple[str, requests.Session]:
        t = get_token(cfg)
        s = make_session(t)
        return t, s

    try:
        while True:
            if duration and (time.time() - start_time) >= duration:
                print(f"\n  Duration of {duration}s reached — stopping.")
                break

            time.sleep(interval)

            now_str = datetime.datetime.now().strftime("%H:%M:%S")

            for name, cam_info in cams.items():
                cam_id  = cam_info["id"]

                # Fetch latest events; retry once on 401
                try:
                    events = api_get_events(session, cam_id, limit=20)
                except Exception:
                    events = []

                if not events and session.headers.get("Authorization", ""):
                    # Possibly 401 — try renewing
                    try:
                        token, session = _renew_session()
                        events = api_get_events(session, cam_id, limit=20)
                    except Exception:
                        events = []

                baseline = last_seen.get(name, "")
                new_events = []
                for ev in events:
                    ev_id = ev.get("id", "")
                    if ev_id == baseline:
                        break
                    new_events.append(ev)

                # Print new events (oldest first — events list is newest-first)
                for ev in reversed(new_events):
                    etype     = ev.get("eventType", "EVENT")
                    ts        = ev.get("timestamp", "")[:19]
                    img_url   = ev.get("imageUrl", "")
                    clip_url  = ev.get("videoClipUrl", "")
                    type_icon = "🔊" if "AUDIO" in etype else "🚨"
                    print(f"  [{now_str}] {type_icon} {etype:<15s}  cam={name:<12s}  {ts}")
                    if img_url:
                        print(f"             📸 {img_url}")
                    if clip_url:
                        print(f"             🎬 {clip_url}")
                    total_new += 1
                    # Signal alert
                    if signal_url and signal_sender and signal_recipients:
                        _send_signal_alert(
                            signal_url, signal_sender, signal_recipients,
                            name, etype, ts, img_url, token,
                        )
                    # Auto-download and open the event snapshot if requested
                    if auto_snap and img_url:
                        try:
                            r = session.get(img_url, verify=False, timeout=15)
                            if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                                fname = f"event_{name}_{ts.replace(':', '-').replace(' ', '_')}.jpg"
                                fpath = os.path.join(BASE_DIR, fname)
                                with open(fpath, "wb") as f:
                                    f.write(r.content)
                                print(f"             💾 Saved: {fpath}")
                                open_file(fpath)
                            else:
                                print(f"             ⚠️  Could not download snapshot (HTTP {r.status_code})")
                        except Exception as snap_err:
                            print(f"             ⚠️  Snapshot download error: {snap_err}")

                if new_events:
                    last_seen[name] = new_events[0].get("id", baseline)

    except KeyboardInterrupt:
        elapsed = int(time.time() - start_time)
        print(f"\n\n  Stopped after {elapsed}s. Total new events seen: {total_new}")


def cmd_motion(cfg: dict, args) -> None:
    """
    Get or set motion detection settings.

    Usage:
      python3 bosch_camera.py motion [<cam>]                    # show current
      python3 bosch_camera.py motion [<cam>] --enable           # enable motion
      python3 bosch_camera.py motion [<cam>] --disable          # disable motion
      python3 bosch_camera.py motion [<cam>] --sensitivity S    # set sensitivity
        Sensitivity values: OFF | LOW | MEDIUM_LOW | MEDIUM_HIGH | HIGH | SUPER_HIGH

    API: GET/PUT /v11/video_inputs/{id}/motion
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))
    enable  = getattr(args, "enable", False)
    disable = getattr(args, "disable", False)
    sensitivity = getattr(args, "sensitivity", None)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Motion Detection: {name} ──────────────────────────────────")

        # GET current settings
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code != 200:
            print(f"  ❌  Could not fetch motion settings: HTTP {r.status_code}")
            continue
        data    = r.json()
        current_enabled  = data.get("enabled", False)
        current_sens     = data.get("motionAlarmConfiguration", data.get("sensitivity", "UNKNOWN"))

        enabled_str = "ENABLED" if current_enabled else "DISABLED"
        icon        = "✅" if current_enabled else "❌"
        print(f"  {icon}  Motion: {enabled_str}  Sensitivity: {current_sens}")

        if not enable and not disable and not sensitivity:
            print(f"\n  Run with --enable / --disable / --sensitivity to change.")
            print(f"  E.g.: python3 bosch_camera.py motion {name.lower()} --enable --sensitivity SUPER_HIGH")
            continue

        # Build PUT body
        new_enabled = current_enabled
        new_sens    = current_sens
        if enable:
            new_enabled = True
        if disable:
            new_enabled = False
        if sensitivity:
            new_sens    = sensitivity
            new_enabled = True  # enabling implicitly when setting sensitivity

        body = {"enabled": new_enabled, "motionAlarmConfiguration": new_sens}
        print(f"  🔄  Setting motion → enabled={new_enabled}  sensitivity={new_sens}...")

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            state_str = "ENABLED" if new_enabled else "DISABLED"
            icon_new  = "✅" if new_enabled else "❌"
            print(f"  {icon_new}  Motion {state_str}  Sensitivity: {new_sens}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_audio_alarm(cfg: dict, args) -> None:
    """
    Get or set audio alarm detection settings.

    Usage:
      python3 bosch_camera.py audio-alarm [<cam>]               # show current
      python3 bosch_camera.py audio-alarm [<cam>] --enable      # enable
      python3 bosch_camera.py audio-alarm [<cam>] --disable     # disable
      python3 bosch_camera.py audio-alarm [<cam>] --threshold N # set threshold 0-100

    API: GET/PUT /v11/video_inputs/{id}/audioAlarm
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))
    enable    = getattr(args, "enable", False)
    disable   = getattr(args, "disable", False)
    threshold = getattr(args, "threshold", None)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Audio Alarm: {name} ──────────────────────────────────────")

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/audioAlarm", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code != 200:
            print(f"  ❌  Could not fetch audio alarm settings: HTTP {r.status_code}")
            continue
        data              = r.json()
        current_enabled   = data.get("enabled", False)
        current_threshold = data.get("threshold", 80)

        enabled_str = "ENABLED" if current_enabled else "DISABLED"
        icon        = "🔊" if current_enabled else "🔕"
        print(f"  {icon}  Audio Alarm: {enabled_str}  Threshold: {current_threshold}")

        if not enable and not disable and threshold is None:
            print(f"\n  Run with --enable / --disable / --threshold to change.")
            print(f"  E.g.: python3 bosch_camera.py audio-alarm {name.lower()} --enable --threshold 60")
            continue

        new_enabled   = current_enabled
        new_threshold = current_threshold
        if enable:
            new_enabled = True
        if disable:
            new_enabled = False
        if threshold is not None:
            new_threshold = threshold

        body = {"enabled": new_enabled, "threshold": new_threshold}
        print(f"  🔄  Setting audio alarm → enabled={new_enabled}  threshold={new_threshold}...")

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/audioAlarm",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            state_str = "ENABLED" if new_enabled else "DISABLED"
            icon_new  = "🔊" if new_enabled else "🔕"
            print(f"  {icon_new}  Audio Alarm {state_str}  Threshold: {new_threshold}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_recording(cfg: dict, args) -> None:
    """
    Get or set cloud recording options.

    Usage:
      python3 bosch_camera.py recording [<cam>]                 # show current
      python3 bosch_camera.py recording [<cam>] --sound-on      # include audio
      python3 bosch_camera.py recording [<cam>] --sound-off     # exclude audio

    API: GET/PUT /v11/video_inputs/{id}/recording_options
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))
    sound_on  = getattr(args, "sound_on",  False)
    sound_off = getattr(args, "sound_off", False)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Recording Options: {name} ──────────────────────────────────")

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/recording_options", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code != 200:
            print(f"  ❌  Could not fetch recording options: HTTP {r.status_code}")
            continue
        data          = r.json()
        current_sound = data.get("recordSound", False)

        sound_str = "ON" if current_sound else "OFF"
        icon      = "🔊" if current_sound else "🔇"
        print(f"  {icon}  Record Sound: {sound_str}")

        if not sound_on and not sound_off:
            print(f"\n  Run with --sound-on or --sound-off to change.")
            print(f"  E.g.: python3 bosch_camera.py recording {name.lower()} --sound-on")
            continue

        new_sound = current_sound
        if sound_on:
            new_sound = True
        if sound_off:
            new_sound = False

        body = {"recordSound": new_sound}
        print(f"  🔄  Setting recordSound → {new_sound}...")

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/recording_options",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            state_str = "ON" if new_sound else "OFF"
            icon_new  = "🔊" if new_sound else "🔇"
            print(f"  {icon_new}  Record Sound: {state_str}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


# ══════════════════════════ RCP PROTOCOL ══════════════════════════════════════
#
# RCP (Remote Configuration Protocol) is Bosch's proprietary binary protocol
# used internally for low-level camera configuration. It is tunnelled through
# the cloud proxy at:
#   https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/rcp.xml
#
# Auth level via cloud proxy hash = 3 (read-only / viewer). Writes require
# a service account (auth level 5) which is not accessible via the cloud proxy.
#
# Session flow:
#   1. WRITE 0xff0c (HELLO) with a fixed payload → response contains sessionid
#   2. WRITE 0xff0d (SESSION_INIT) with the sessionid to activate the session
#   3. READ any command using the sessionid as a query parameter
#
# All payloads are hex-encoded in the URL query string.
# Responses are XML: <rcp_cmd> ... <str>HEX</str> ... </rcp_cmd>

RCP_BASE_PORT = 42090

# Fixed HELLO payload for auth level 3 (viewer) — matches Bosch app behaviour
_RCP_HELLO_PAYLOAD = "0102004000000000040000000000000000010000000000000001000000000000"

# RCP session ID cache: proxy_base → (sessionid, expires_timestamp)
# Avoids re-running the 2-step RCP handshake on every command call.
_RCP_SESSION_CACHE: dict[str, tuple[str, float]] = {}


def rcp_open_connection(cam_id: str, token: str) -> tuple[str, str]:
    """
    Open a REMOTE proxy connection for the given camera.
    Returns (proxy_base_url, proxy_hash_path) where:
      proxy_base_url = 'https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}'
    Raises RuntimeError on failure.
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.put(
        f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
        headers=headers,
        json={"type": "REMOTE", "highQualityVideo": False},
        verify=False, timeout=15,
    )
    if r.status_code != 200:
        raise RuntimeError(f"PUT /connection returned HTTP {r.status_code}")
    data = r.json()
    urls = data.get("urls", [])
    if not urls:
        raise RuntimeError("No URLs in /connection response")
    # urls[0] = "proxy-NN.live.cbs.boschsecurity.com:42090/{hash}"
    raw = urls[0]
    proxy_base = f"https://{raw}"
    return proxy_base, raw


def rcp_session(proxy_base: str) -> str:
    """
    Perform the RCP session handshake via the proxy.
    Step 1: WRITE 0xff0c (HELLO) — get a sessionid back
    Step 2: WRITE 0xff0d (SESSION_INIT) with that sessionid
    Returns sessionid string (e.g. '0x1a2b3c4d').
    Raises RuntimeError on failure.
    """
    import re as _re

    rcp_url = f"{proxy_base}/rcp.xml"

    # Step 1: HELLO (0xff0c WRITE P_OCTET)
    params_hello = {
        "command": "0xff0c",
        "direction": "WRITE",
        "type": "P_OCTET",
        "payload": _RCP_HELLO_PAYLOAD,
    }
    r1 = requests.get(rcp_url, params=params_hello,
                      auth=("", ""), verify=False, timeout=10)
    if r1.status_code != 200:
        raise RuntimeError(f"RCP HELLO returned HTTP {r1.status_code}")

    m = _re.search(r"<sessionid>(0x[0-9a-fA-F]+)</sessionid>", r1.text)
    if not m:
        # Try to extract from <str> field (hex-encoded XML)
        ms = _re.search(r"<str>([0-9a-fA-F]+)</str>", r1.text)
        if ms:
            raw = bytes.fromhex(ms.group(1))
            m2  = _re.search(rb"(0x[0-9a-fA-F]+)", raw)
            if m2:
                sessionid = m2.group(1).decode()
            else:
                raise RuntimeError(f"Cannot parse sessionid from HELLO response: {r1.text[:400]}")
        else:
            raise RuntimeError(f"No sessionid in HELLO response: {r1.text[:400]}")
    else:
        sessionid = m.group(1)

    # Step 2: SESSION_INIT (0xff0d WRITE P_OCTET sessionid=...)
    params_init = {
        "command": "0xff0d",
        "direction": "WRITE",
        "type": "P_OCTET",
        "sessionid": sessionid,
        "payload": _RCP_HELLO_PAYLOAD,
    }
    r2 = requests.get(rcp_url, params=params_init,
                      auth=("", ""), verify=False, timeout=10)
    if r2.status_code != 200:
        raise RuntimeError(f"RCP SESSION_INIT returned HTTP {r2.status_code}")

    return sessionid


def rcp_session_cached(proxy_base: str) -> str:
    """Return a cached RCP session ID, calling rcp_session() if missing or expired (5 min TTL).

    Avoids the 2-step handshake overhead (0xff0c + 0xff0d) when multiple RCP
    commands are called in sequence for the same camera within a session.
    """
    now = time.time()
    cached = _RCP_SESSION_CACHE.get(proxy_base)
    if cached:
        session_id, expires_at = cached
        if now < expires_at:
            return session_id
        del _RCP_SESSION_CACHE[proxy_base]
    session_id = rcp_session(proxy_base)
    _RCP_SESSION_CACHE[proxy_base] = (session_id, now + 300.0)
    return session_id


def rcp_read(rcp_url: str, command: str, sessionid: str,
             type_: str = "P_OCTET", num: int = 0) -> bytes | None:
    """
    Send an RCP READ request and return the raw result bytes.
    Returns None if the response is empty (len=0) or an error occurs.

    Args:
        rcp_url:   full URL to rcp.xml, e.g. https://proxy-NN:42090/{hash}/rcp.xml
        command:   hex command code, e.g. '0x0a0f'
        sessionid: session ID from rcp_session()
        type_:     RCP type string, default 'P_OCTET'
        num:       instance number (0 = default)
    """
    import re as _re

    params = {
        "command":   command,
        "direction": "READ",
        "type":      type_,
        "num":       num,
        "sessionid": sessionid,
    }
    try:
        r = requests.get(rcp_url, params=params,
                         auth=("", ""), verify=False, timeout=10)
    except Exception as e:
        return None

    if r.status_code != 200:
        return None

    # Parse XML — result is in <str>HEX</str>
    m = _re.search(r"<str>([0-9a-fA-F]*)</str>", r.text)
    if not m:
        return None
    hex_str = m.group(1)
    if not hex_str:
        return None   # empty result
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def rcp_parse_utf16be_strings(data: bytes) -> list[str]:
    """
    Parse a UTF-16-BE encoded string list (as used in RCP 0x0c38 alarm catalog).
    Splits on null words (\\x00\\x00) and decodes each non-empty segment.
    Returns list of strings.
    """
    results = []
    # Split on null word boundaries
    i = 0
    current = bytearray()
    while i < len(data) - 1:
        word = data[i:i+2]
        if word == b"\x00\x00":
            if current:
                try:
                    s = current.decode("utf-16-be").strip("\x00").strip()
                    if s:
                        results.append(s)
                except Exception:
                    pass
                current = bytearray()
        else:
            current += word
        i += 2
    if current:
        try:
            s = current.decode("utf-16-be").strip("\x00").strip()
            if s:
                results.append(s)
        except Exception:
            pass
    return results


def rcp_parse_clock(data: bytes) -> str:
    """
    Parse the 8-byte RCP clock from command 0x0a0f.
    Format: YYYY(2B big-endian) MM(1B) DD(1B) HH(1B) MM(1B) SS(1B) DOW(1B)
    Returns a formatted datetime string, e.g. '2026-03-22 05:54:25'.
    """
    if len(data) < 7:
        return f"(invalid clock data: {data.hex()})"
    try:
        year  = (data[0] << 8) | data[1]
        month = data[2]
        day   = data[3]
        hour  = data[4]
        minute = data[5]
        second = data[6]
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    except Exception as e:
        return f"(parse error: {e})"


def rcp_parse_string(data: bytes) -> str:
    """Decode a null-terminated ASCII/UTF-8 string from RCP data bytes."""
    try:
        return data.rstrip(b"\x00").decode("utf-8", errors="replace")
    except Exception:
        return data.hex()


def rcp_parse_ip(data: bytes) -> str:
    """Parse a 4-byte big-endian IPv4 address from RCP data."""
    if len(data) >= 4:
        return f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"
    return data.hex()


def rcp_parse_word(data: bytes) -> int | None:
    """Parse a 2-byte big-endian unsigned integer (T_WORD) from RCP data."""
    if len(data) >= 2:
        return (data[0] << 8) | data[1]
    return None


def _rcp_setup(cam_info: dict, token: str) -> tuple[str, str]:
    """
    Open a REMOTE connection and perform RCP session handshake.
    Returns (rcp_url, sessionid).
    Prints status messages. Raises RuntimeError on failure.
    """
    cam_id = cam_info["id"]
    print(f"  🌐  Opening REMOTE proxy connection...")
    proxy_base, _ = rcp_open_connection(cam_id, token)
    print(f"  🔗  Proxy: {proxy_base}")
    print(f"  🤝  RCP session handshake (cached)...")
    sessionid = rcp_session_cached(proxy_base)
    print(f"  ✅  Session: {sessionid}")
    rcp_url = f"{proxy_base}/rcp.xml"
    return rcp_url, sessionid


def cmd_rcp(cfg: dict, args) -> None:
    """
    RCP — Remote Configuration Protocol reads via cloud proxy.

    Subcommands:
      info      — camera identity: MAC, product name, FQDN, LAN IP
      clock     — real-time camera clock (0x0a0f)
      snapshot  — RCP JPEG thumbnail 320×180 (0x099e, resolution from 0x0a88) — save + open
      alarms    — alarm catalog from 0x0c38 (UTF-16-BE)
      privacy   — privacy mask state read (0x0d00)
      dimmer    — LED dimmer value 0-100 (0x0c22 T_WORD)
      motion    — motion zone count from 0x0c0a
      services  — network services list from 0x0c62
      frame     — raw video frame 320x180 YUV422 (0x0c98) → JPEG
      script    — IVA automation script gzip (0x09f3) → text
      iva       — IVA rule types + resiMotion config (0x0ba9 + 0x0a1b)
      bitrate   — bitrate ladder tiers in kbps (0x0c81)
      all       — run all of the above

    The cloud proxy hash acts as the credential — no username/password needed.
    Auth level via cloud proxy = 3 (read-only). Writes require auth level 5.
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub     = (getattr(args, "sub", None) or "").lower()

    # Allow "rcp info" without a camera name (sub parsed as cam_arg)
    RCP_SUBS = ("info", "clock", "snapshot", "alarms", "privacy",
                "dimmer", "motion", "services", "frame", "script", "iva", "bitrate", "all")
    if cam_arg and cam_arg.lower() in RCP_SUBS and not sub:
        sub, cam_arg = cam_arg.lower(), None

    if not sub:
        print("\n  ℹ️   Usage: python3 bosch_camera.py rcp [camera] <subcommand>")
        print("  Subcommands: info | clock | snapshot | alarms | privacy | dimmer | motion | services | frame | script | iva | bitrate | all")
        return

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        print(f"\n── RCP: {name} ({sub}) ─────────────────────────────────────────")

        try:
            rcp_url, sessionid = _rcp_setup(cam_info, token)
        except RuntimeError as e:
            print(f"  ❌  RCP setup failed: {e}")
            continue

        run_all = (sub == "all")

        # ── info ──────────────────────────────────────────────────────────────
        if sub in ("info", "all"):
            print(f"\n  ── Identity ──────────────────────────────────────────────")
            # 0x0aea — product name (null-terminated ASCII)
            d = rcp_read(rcp_url, "0x0aea", sessionid)
            if d:
                print(f"  Product:    {rcp_parse_string(d)}")
            else:
                print(f"  Product:    (not available)")
            # 0x0aee — cloud FQDN
            d = rcp_read(rcp_url, "0x0aee", sessionid)
            if d:
                print(f"  Cloud FQDN: {rcp_parse_string(d)}")
            else:
                print(f"  Cloud FQDN: (not available)")
            # 0x0a36 — LAN IP (4-byte or string)
            d = rcp_read(rcp_url, "0x0a36", sessionid)
            if d:
                ip_str = rcp_parse_ip(d) if len(d) == 4 else rcp_parse_string(d)
                print(f"  LAN IP:     {ip_str}  (via RCP)")
            else:
                print(f"  LAN IP:     (not available)")
            # 0x0a30 — MAC address (6 bytes)
            d = rcp_read(rcp_url, "0x0a30", sessionid)
            if d and len(d) >= 6:
                mac_str = ":".join(f"{b:02x}" for b in d[:6])
                print(f"  MAC:        {mac_str}  (via RCP)")
            elif d:
                print(f"  MAC:        {rcp_parse_string(d)}")
            else:
                print(f"  MAC:        (not available)")

        # ── clock ─────────────────────────────────────────────────────────────
        if sub in ("clock", "all"):
            print(f"\n  ── Camera Clock ──────────────────────────────────────────")
            d = rcp_read(rcp_url, "0x0a0f", sessionid)
            if d:
                print(f"  Clock:      {rcp_parse_clock(d)}  (camera local time)")
                print(f"  Raw:        {d.hex()}")
            else:
                print(f"  Clock:      (not available)")

        # ── snapshot ──────────────────────────────────────────────────────────
        if sub in ("snapshot", "all"):
            print(f"\n  ── RCP Thumbnail Snapshot ────────────────────────────────")
            # Confirm resolution via 0x0a88 (returns 8B: width 4B BE + height 4B BE)
            import struct as _struct
            res_d = rcp_read(rcp_url, "0x0a88", sessionid)
            if res_d and len(res_d) >= 8:
                w, h = _struct.unpack(">II", res_d[:8])
                print(f"  Resolution: {w}×{h}  (from 0x0a88)")
            else:
                w, h = 320, 180
                print(f"  Resolution: {w}×{h}  (assumed — 0x0a88 not available)")
            d = rcp_read(rcp_url, "0x099e", sessionid)
            if d and d[:2] == b"\xff\xd8":  # JPEG magic
                suffix = f"_rcp_thumb_{name.replace(' ', '_')}.jpg"
                tmp = os.path.join(BASE_DIR, f"rcp_snapshot{suffix}")
                with open(tmp, "wb") as f:
                    f.write(d)
                print(f"  Thumbnail:  {w}×{h} JPEG  ({len(d):,} bytes)")
                print(f"  Saved:      {tmp}")
                open_file(tmp)
            elif d:
                # Not JPEG — save raw for inspection
                tmp = os.path.join(BASE_DIR, f"rcp_snapshot_{name.replace(' ', '_')}.bin")
                with open(tmp, "wb") as f:
                    f.write(d)
                print(f"  Data:       {len(d)} bytes (not JPEG — saved as .bin: {tmp})")
                print(f"  Header:     {d[:16].hex()}")
            else:
                print(f"  Snapshot:   (not available)")

        # ── alarms ────────────────────────────────────────────────────────────
        if sub in ("alarms", "all"):
            print(f"\n  ── Alarm Catalog (0x0c38) ────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c38", sessionid)
            if d:
                strings = rcp_parse_utf16be_strings(d)
                if strings:
                    for i, s in enumerate(strings):
                        print(f"  [{i:02d}] {s}")
                else:
                    print(f"  (no strings decoded — raw {len(d)} bytes: {d[:32].hex()}...)")
            else:
                print(f"  Alarms:     (not available)")

        # ── privacy ───────────────────────────────────────────────────────────
        if sub in ("privacy", "all"):
            print(f"\n  ── Privacy Mask State (0x0d00) ───────────────────────────")
            d = rcp_read(rcp_url, "0x0d00", sessionid)
            if d and len(d) >= 1:
                state_byte = d[1] if len(d) > 1 else d[0]
                state_str  = "ON (masked)" if state_byte else "OFF (visible)"
                icon       = "🔒" if state_byte else "👁️"
                print(f"  {icon}  Privacy mask: {state_str}  (byte[1]={state_byte:#04x})")
                print(f"  Raw:          {d.hex()}")
            else:
                print(f"  Privacy:    (not available)")

        # ── dimmer ────────────────────────────────────────────────────────────
        if sub in ("dimmer", "all"):
            print(f"\n  ── LED Dimmer (0x0c22) ───────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c22", sessionid, type_="T_WORD")
            if d is None:
                # Try P_OCTET fallback
                d = rcp_read(rcp_url, "0x0c22", sessionid)
            if d:
                val = rcp_parse_word(d)
                if val is not None:
                    print(f"  Dimmer:     {val}  (0=off, 100=max)")
                else:
                    print(f"  Dimmer raw: {d.hex()}")
            else:
                print(f"  Dimmer:     (not available)")

        # ── motion ────────────────────────────────────────────────────────────
        if sub in ("motion", "all"):
            print(f"\n  ── Motion Zones (0x0c0a) ─────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c0a", sessionid)
            if d:
                # Each zone is typically 8 bytes: x1(2B) y1(2B) x2(2B) y2(2B) in 0-10000 units
                zone_size = 8
                n_zones   = len(d) // zone_size
                print(f"  Zones:      {n_zones} zone(s)  ({len(d)} bytes raw)")
                for z in range(n_zones):
                    chunk = d[z*zone_size:(z+1)*zone_size]
                    if len(chunk) == 8:
                        x1 = (chunk[0] << 8) | chunk[1]
                        y1 = (chunk[2] << 8) | chunk[3]
                        x2 = (chunk[4] << 8) | chunk[5]
                        y2 = (chunk[6] << 8) | chunk[7]
                        print(f"  Zone {z}:     ({x1},{y1}) → ({x2},{y2})  [0-10000 coords]")
                    else:
                        print(f"  Zone {z}:     {chunk.hex()}")
            else:
                print(f"  Motion:     (not available)")

        # ── services ──────────────────────────────────────────────────────────
        if sub in ("services", "all"):
            print(f"\n  ── Network Services (0x0c62) ─────────────────────────────")
            d = rcp_read(rcp_url, "0x0c62", sessionid)
            if d:
                # Services list is typically null-terminated ASCII strings
                services = [s for s in d.decode("ascii", errors="replace").split("\x00") if s.strip()]
                if services:
                    for svc in services:
                        print(f"  Service:    {svc}")
                else:
                    print(f"  Services raw: {len(d)} bytes  {d[:48].hex()}")
            else:
                print(f"  Services:   (not available)")

        # ── frame ─────────────────────────────────────────────────────────────
        if sub in ("frame", "all"):
            print(f"\n  ── Raw Frame (0x0c98) ────────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c98", sessionid)
            if d and len(d) == 115200:
                safe_name = name.replace(' ', '_')
                try:
                    import numpy as np
                    from PIL import Image
                    # YUV422 interleaved (YUYV): each 4 bytes = 2 pixels: Y0 U Y1 V
                    raw = np.frombuffer(d, dtype=np.uint8).reshape(180, 320, 2)
                    # Expand to YUV444
                    y = raw[:, :, 0].astype(np.float32)
                    uv = raw[:, :, 1].astype(np.float32)
                    u = np.repeat(uv[:, 0::2][:, :, np.newaxis], 2, axis=1).reshape(180, 320) - 128
                    v = np.repeat(uv[:, 1::2][:, :, np.newaxis], 2, axis=1).reshape(180, 320) - 128
                    r = np.clip(y + 1.402 * v, 0, 255).astype(np.uint8)
                    g = np.clip(y - 0.344136 * u - 0.714136 * v, 0, 255).astype(np.uint8)
                    b = np.clip(y + 1.772 * u, 0, 255).astype(np.uint8)
                    rgb = np.stack([r, g, b], axis=2)
                    img = Image.fromarray(rgb)
                    path = os.path.join(BASE_DIR, f"rcp_frame_{safe_name}.jpg")
                    img.save(path, "JPEG")
                    print(f"  Frame:      320x180 YUV422 ({len(d):,} bytes) -> saved as JPEG: {path}")
                    open_file(path)
                except Exception:
                    path = os.path.join(BASE_DIR, f"rcp_frame_{safe_name}.yuv")
                    with open(path, "wb") as f:
                        f.write(d)
                    print(f"  Frame:      320x180 YUV422 ({len(d):,} bytes) -> saved as raw YUV: {path}")
                    print(f"  Note:       Install numpy + Pillow for JPEG conversion")
            elif d:
                safe_name = name.replace(' ', '_')
                path = os.path.join(BASE_DIR, f"rcp_frame_{safe_name}.bin")
                with open(path, "wb") as f:
                    f.write(d)
                print(f"  Frame:      {len(d):,} bytes (unexpected size — saved as .bin: {path})")
            else:
                print(f"  Frame:      (not available)")

        # ── script ────────────────────────────────────────────────────────────
        if sub in ("script", "all"):
            print(f"\n  ── IVA Automation Script (0x09f3) ────────────────────────")
            d = rcp_read(rcp_url, "0x09f3", sessionid)
            if d and d[:2] == b'\x1f\x8b':  # gzip magic
                import gzip
                try:
                    text = gzip.decompress(d).decode('utf-8', errors='replace')
                    print(f"  Script:     {len(d):,} bytes compressed -> {len(text):,} chars decompressed")
                    for line in text.splitlines():
                        print(f"  {line}")
                except Exception as exc:
                    print(f"  Decompress error: {exc}")
                    print(f"  Raw header: {d[:16].hex()}")
            elif d:
                print(f"  Data:       {len(d):,} bytes (not gzip)")
                print(f"  Raw header: {d[:16].hex()}")
            else:
                print(f"  Script:     (not available)")

        # ── iva ───────────────────────────────────────────────────────────────
        if sub in ("iva", "all"):
            print(f"\n  ── IVA Rules & resiMotion Config ─────────────────────────")
            # 0x0ba9 — IVA rule type names (null-terminated ASCII list)
            d = rcp_read(rcp_url, "0x0ba9", sessionid)
            if d:
                rule_names = [s for s in d.decode("ascii", errors="replace").split("\x00") if s.strip()]
                if rule_names:
                    print(f"  IVA rule types ({len(rule_names)}):")
                    for rn in rule_names:
                        print(f"    • {rn}")
                else:
                    print(f"  IVA rule types: raw {len(d)} bytes  {d[:32].hex()}")
            else:
                print(f"  IVA rule types: (not available)")
            # 0x0a1b — resiMotion config (motion detection polygon + sensitivity params)
            d = rcp_read(rcp_url, "0x0a1b", sessionid)
            if d:
                try:
                    text = d.decode("utf-8", errors="replace").rstrip("\x00")
                    print(f"  resiMotion config ({len(d):,} bytes):")
                    for line in text.splitlines():
                        print(f"    {line}")
                except Exception:
                    print(f"  resiMotion raw: {len(d):,} bytes  {d[:32].hex()}")
            else:
                print(f"  resiMotion config: (not available)")

        # ── bitrate ───────────────────────────────────────────────────────────────
        if sub in ("bitrate", "all"):
            print(f"\n  ── Bitrate Ladder (0x0c81) ───────────────────────────────")
            d = rcp_read(rcp_url, "0x0c81", sessionid)
            if d and len(d) >= 4:
                import struct as _s
                # Ladder is a series of big-endian uint32 values (kbps)
                n = len(d) // 4
                tiers = [_s.unpack(">I", d[i*4:(i+1)*4])[0] for i in range(n)]
                labels = ["low", "medium-low", "medium", "medium-high", "high"]
                for i, kbps in enumerate(tiers):
                    label = labels[i] if i < len(labels) else f"tier{i}"
                    marker = " ←" if i == len(tiers)-1 else ""
                    print(f"  [{label}]  {kbps:,} kbps  ({kbps//1000:.1f} Mbps){marker}")
                print(f"\n  Note: highQualityVideo=true selects the highest tier")
            else:
                print(f"  Bitrate: (not available)")

        print()


def cmd_token(cfg: dict, args) -> None:
    """Show token status and optionally renew it.

    Usage:
      python3 bosch_camera.py token          → show current status
      python3 bosch_camera.py token fix      → renew via refresh_token (or browser)
      python3 bosch_camera.py token browser  → force new browser login
    """
    import base64 as _b64

    action = getattr(args, "cam", None) or getattr(args, "action", None)
    if action:
        action = action.lower()

    acct    = cfg.get("account", {})
    token   = acct.get("bearer_token", "").strip()
    refresh = acct.get("refresh_token", "").strip()

    print("\n── Token Status ─────────────────────────────────────────────")
    if token:
        print(f"  Access token:  {token[:24]}...  ({len(token)} chars)")
        try:
            parts = token.split(".")
            pad   = len(parts[1]) % 4
            info  = json.loads(_b64.urlsafe_b64decode(parts[1] + "=" * pad))
            exp   = info.get("exp", 0)
            exp_dt = datetime.datetime.fromtimestamp(exp)
            diff   = exp_dt - datetime.datetime.now()
            mins   = int(diff.total_seconds() / 60)
            if mins > 0:
                status = f"valid ~{mins}m ✅"
            else:
                status = f"EXPIRED {abs(mins)}m ago ❌"
            print(f"  Email:         {info.get('email', info.get('preferred_username', ''))}")
            print(f"  Expires:       {exp_dt.strftime('%Y-%m-%d %H:%M')}  ({status})")
            expired = mins <= 0
        except Exception:
            print(f"  Status:        {check_token_age(cfg)}")
            expired = False
    else:
        print("  Access token:  (none)")
        expired = True

    if refresh:
        print(f"  Refresh token: {refresh[:20]}...  ({len(refresh)} chars) — auto-renewal ✅")
    else:
        print("  Refresh token: (none) — browser login needed")

    if action in ("fix", "refresh", "renew", "browser"):
        print()
        force_browser = (action == "browser")
        try:
            from get_token import get_token_auto
            new_token = get_token_auto(cfg, force_browser=force_browser)
            if new_token:
                print(f"\n  ✅  Token renewed successfully.")
            else:
                print(f"\n  ❌  Token renewal failed.")
        except ImportError:
            print("  ❌  get_token.py not found in the same folder.")
    elif expired:
        print()
        print("  ➡️   To fix: python3 bosch_camera.py token fix")
    print()


def cmd_rescan(cfg: dict, args) -> None:
    """Re-discover cameras from API and update config."""
    token   = get_token(cfg)
    session = make_session(token)
    print("\n  🔍  Re-scanning cameras...")
    cameras = discover_cameras(cfg, session)
    print(f"\n  Found {len(cameras)} camera(s):")
    for name, cam in cameras.items():
        print(f"    • {name}  ({cam['model']})  ID: {cam['id']}")


# ══════════════════════════ INTERACTIVE MENU ══════════════════════════════════

def cmd_menu(cfg: dict) -> None:
    """Interactive numbered menu."""
    cameras = cfg.get("cameras", {})
    cam_names = list(cameras.keys())

    # Auto-renew token silently if expired before displaying status
    token = cfg["account"].get("bearer_token", "").strip()
    if not token or _is_token_expired(token):
        get_token(cfg)

    print("""
╔══════════════════════════════════════════════════════════╗
║        Bosch Smart Home Camera — Control Panel           ║
╚══════════════════════════════════════════════════════════╝
""")
    print(f"  Version: {VERSION}")
    print(f"  Config: {CONFIG_FILE}")
    print(f"  Token:  {check_token_age(cfg)}")
    if cam_names:
        print(f"  Cameras in config: {', '.join(cam_names)}")
    else:
        print("  ⚠️   No cameras in config — choose option 12 to scan")
    print()

    print("  1)  Camera status (ONLINE / OFFLINE)")
    print("  2)  Camera info (full details + stream URLs)")
    for i, name in enumerate(cam_names, start=3):
        print(f"  {i})  Latest event snapshot — {name}")
    offset = 3 + len(cam_names)

    print(f"  {offset})  Latest event snapshot — ALL cameras")
    offset += 1

    liveshot_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Live snapshot — {name}  (remote/local)")
        offset += 1

    live_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Live stream — {name} (ffplay, audio+video)")
        offset += 1

    live_vlc_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Live stream — {name} (VLC, audio+video)")
        offset += 1

    dl_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Download ALL events — {name}")
        offset += 1
    print(f"  {offset})  Download ALL events — ALL cameras")
    offset += 1

    print(f"  {offset})  Show recent events — ALL cameras (last 20)")
    events_item = offset
    offset += 1

    # ── Camera controls ───────────────────────────────────────────────────────
    print()
    print("  ── Privacy ──────────────────────────────────────────────────")
    privacy_start = offset
    for name in cam_names:
        print(f"  {offset})  Privacy ON  — {name}")
        offset += 1
        print(f"  {offset})  Privacy OFF — {name}")
        offset += 1

    # Light — only cameras with has_light=True
    light_cams = [n for n in cam_names if cameras.get(n, {}).get("has_light", False)]
    light_start = offset
    if light_cams:
        print()
        print("  ── Camera Light ─────────────────────────────────────────────")
        for name in light_cams:
            print(f"  {offset})  Light ON  — {name}")
            offset += 1
            print(f"  {offset})  Light OFF — {name}")
            offset += 1

    print()
    print("  ── Notifications ────────────────────────────────────────────")
    notif_start = offset
    for name in cam_names:
        print(f"  {offset})  Notifications ON  — {name}")
        offset += 1
        print(f"  {offset})  Notifications OFF — {name}")
        offset += 1

    # Pan — only cameras with pan_limit > 0
    pan_cams = [n for n in cam_names if cameras.get(n, {}).get("pan_limit", 0) > 0]
    pan_start = offset
    pan_actions = [("left", "◀◀ Full left"), ("center", "■  Center (0°)"), ("right", "▶▶ Full right")]
    if pan_cams:
        print()
        print("  ── Pan ──────────────────────────────────────────────────────")
        for name in pan_cams:
            for action_key, label in pan_actions:
                lim = cameras[name].get("pan_limit", 120)
                lim_str = f"-{lim}°" if action_key == "left" else (f"+{lim}°" if action_key == "right" else "0°")
                print(f"  {offset})  Pan {label} ({lim_str}) — {name}")
                offset += 1

    print()
    print("  ── Token ────────────────────────────────────────────────────")
    token_item = offset
    print(f"  {offset})  Show token status / renew")
    offset += 1

    print()
    print(f"  {offset})  Show config file")
    config_item = offset
    offset += 1
    print(f"  {offset})  Re-scan cameras")
    rescan_item = offset
    offset += 1
    print("  0)  Exit")
    print()

    choice = input("  Enter choice: ").strip()

    class A:
        cam     = None
        action  = None
        sub     = None
        limit   = None
        snaps_only  = False
        clips_only  = False
        re_download = False
        live    = False
        vlc     = False
        full    = False
        minutes = None

    a = A()
    try:
        c = int(choice)
    except ValueError:
        return  # empty Enter or invalid → just redraw menu

    if c == 0:
        sys.exit(0)
    elif c == 1:        cmd_status(cfg, a)
    elif c == 2:        cmd_info(cfg, a)
    elif 3 <= c < 3 + len(cam_names):
        a.cam = cam_names[c - 3]
        a.live = False
        cmd_snapshot(cfg, a)
    elif c == 3 + len(cam_names):
        a.live = False
        cmd_snapshot(cfg, a)
    elif liveshot_start <= c < liveshot_start + len(cam_names):
        a.cam  = cam_names[c - liveshot_start]
        a.live = True
        cmd_snapshot(cfg, a)
    elif live_start <= c < live_start + len(cam_names):
        a.cam = cam_names[c - live_start]
        a.vlc = False
        cmd_live(cfg, a)
    elif live_vlc_start <= c < live_vlc_start + len(cam_names):
        a.cam = cam_names[c - live_vlc_start]
        a.vlc = True
        cmd_live(cfg, a)
    elif dl_start <= c < dl_start + len(cam_names):
        a.cam = cam_names[c - dl_start]
        cmd_download(cfg, a)
    elif c == dl_start + len(cam_names):
        cmd_download(cfg, a)
    elif c == events_item:
        a.limit = 20
        cmd_events(cfg, a)
    # Privacy
    elif privacy_start <= c < privacy_start + len(cam_names) * 2:
        idx = c - privacy_start
        a.cam    = cam_names[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_privacy(cfg, a)
    # Light (only light_cams)
    elif light_cams and light_start <= c < light_start + len(light_cams) * 2:
        idx = c - light_start
        a.cam    = light_cams[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_light(cfg, a)
    # Notifications
    elif notif_start <= c < notif_start + len(cam_names) * 2:
        idx = c - notif_start
        a.cam    = cam_names[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_notifications(cfg, a)
    # Pan (only pan_cams)
    elif pan_cams and pan_start <= c < pan_start + len(pan_cams) * len(pan_actions):
        idx = c - pan_start
        a.cam    = pan_cams[idx // len(pan_actions)]
        a.action = pan_actions[idx % len(pan_actions)][0]
        cmd_pan(cfg, a)
    elif c == token_item:
        a.action = "fix"
        cmd_token(cfg, a)
    elif c == config_item:
        cmd_config(cfg, a)
    elif c == rescan_item:
        cmd_rescan(cfg, a)
    else:
        print(f"  Unknown choice: {c}")

    input("\n  Press Enter to return to menu...")


def cmd_autofollow(cfg: dict, args) -> None:
    """Get or set auto-follow for a 360 camera via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py autofollow [cam-name]        → show current state
      python3 bosch_camera.py autofollow [cam-name] on     → enable auto-follow
      python3 bosch_camera.py autofollow [cam-name] off    → disable auto-follow

    API: GET/PUT /v11/video_inputs/{id}/autofollow
         Body: {"result": true/false}
         Response: HTTP 204 on success.
    Only available for cameras with featureSupport.panLimit > 0 (CAMERA_360).
    """
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    action  = getattr(args, "action", None)

    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action  = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id    = cam_info["id"]
        pan_limit = cam_info.get("pan_limit", 0)

        print(f"\n── Auto-Follow: {name} ─────────────────────────────────────")
        if not pan_limit:
            print(f"  ℹ️   This camera does not support auto-follow (panLimit=0).")
            continue

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/autofollow", timeout=10)
        if r.status_code != 200:
            print(f"  ❌  Could not fetch auto-follow state: HTTP {r.status_code}")
            continue
        current = r.json().get("result", False)
        icon = "🎯" if current else "⏸️"
        print(f"  {icon}  Auto-follow:  {'ENABLED' if current else 'DISABLED'}")

        if action is None:
            print(f"\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py autofollow {name.lower()} on")
            continue

        new_state = action == "on"
        if new_state == current:
            print(f"  ✅  Already {'ENABLED' if current else 'DISABLED'} — no change needed.")
            continue

        print(f"  🔄  Setting auto-follow → {'ENABLED' if new_state else 'DISABLED'}...")
        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/autofollow",
            json={"result": new_state},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            icon_new = "🎯" if new_state else "⏸️"
            print(f"  {icon_new}  Auto-follow {'ENABLED' if new_state else 'DISABLED'}.")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def main():
    # ── Top-level parser ───────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog="bosch_camera.py",
        description=(
            "📷  Bosch Smart Home Camera — standalone control tool  v" + VERSION + "\n"
            "    Full cloud API access: snapshots, live stream, events, camera controls."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "────────────────────────────────────────────────────────────────\n"
            "  Run WITHOUT arguments to open the interactive menu.\n"
            "  Use '<command> --help' for per-command details.\n"
            "\n"
            "  Examples:\n"
            "    python3 bosch_camera.py                          # interactive menu\n"
            "    python3 bosch_camera.py status\n"
            "    python3 bosch_camera.py snapshot Garten\n"
            "    python3 bosch_camera.py snapshot Garten --live\n"
            "    python3 bosch_camera.py live Kamera --vlc\n"
            "    python3 bosch_camera.py download Garten --clips-only --limit 20\n"
            "    python3 bosch_camera.py privacy Garten on --minutes 30\n"
            "    python3 bosch_camera.py pan Kamera right\n"
            "    python3 bosch_camera.py pan Kamera 45\n"
            "    python3 bosch_camera.py token fix\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # ── status ─────────────────────────────────────────────────────────────────
    subparsers.add_parser(
        "status",
        help="Show all cameras with ONLINE/OFFLINE status",
        description=(
            "📶  status — Camera list with ONLINE/OFFLINE status\n"
            "\n"
            "  Pings every known camera via the cloud API and prints\n"
            "  name, model, firmware version, MAC address and status."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  Example:\n    python3 bosch_camera.py status",
    )

    # ── info ───────────────────────────────────────────────────────────────────
    p_info = subparsers.add_parser(
        "info",
        help="Full camera details + live stream URLs",
        description=(
            "ℹ️   info — Full camera details + live stream URLs\n"
            "\n"
            "  Fetches the complete camera object from the cloud API:\n"
            "  privacy mode, recording state, notifications, features,\n"
            "  WiFi signal, and the live RTSPS/snap URLs.\n"
            "\n"
            "  With --full: also queries 6 extra endpoints\n"
            "  (firmware, motion, audio alarm, lighting override,\n"
            "   recording options, ambient light sensor)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py info\n"
            "    python3 bosch_camera.py info --full"
        ),
    )
    p_info.add_argument(
        "--full",
        action="store_true",
        help="Also fetch extra endpoints: firmware, motion, audio alarm, ambient light, WiFi",
    )

    # ── snapshot ───────────────────────────────────────────────────────────────
    p_snap = subparsers.add_parser(
        "snapshot",
        help="Save + open a camera snapshot",
        description=(
            "📸  snapshot — Save and open a camera snapshot\n"
            "\n"
            "  Default (no --live): fetches the latest motion-triggered\n"
            "  event snapshot from the cloud events API.\n"
            "\n"
            "  With --live: tries real-time methods in order:\n"
            "    1. Cloud proxy live snap  (~1.5 s, no credentials needed)\n"
            "    2. Local camera snap.jpg  (LAN, requires local_ip + creds in config)\n"
            "    3. Latest event snapshot  (fallback)\n"
            "\n"
            "  Aliases: liveshot / livesnap / live-snapshot  (imply --live)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py snapshot\n"
            "    python3 bosch_camera.py snapshot Garten\n"
            "    python3 bosch_camera.py snapshot Garten --live\n"
            "    python3 bosch_camera.py liveshot Kamera"
        ),
    )
    p_snap.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_snap.add_argument(
        "--live",
        action="store_true",
        help="Prefer live snapshot methods (cloud proxy or local LAN) over event snapshot",
    )
    p_snap.add_argument(
        "--hq",
        action="store_true",
        help="Request highQualityVideo=true in PUT /connection (higher resolution)",
    )
    p_snap.add_argument(
        "--quality",
        choices=["auto", "high", "low"],
        metavar="Q",
        help="Quality preset: auto (default) | high (highQualityVideo=true) | low",
    )

    # ── liveshot aliases ───────────────────────────────────────────────────────
    for _alias in ("liveshot", "livesnap", "live-snapshot"):
        p_alias = subparsers.add_parser(
            _alias,
            help=f"Alias for 'snapshot --live'",
            description=f"📸  {_alias} — Alias for: snapshot --live\n\nSee 'snapshot --help' for full details.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        p_alias.add_argument("cam", nargs="?", metavar="<camera>",
                             help="Camera name or partial match")
        p_alias.add_argument("--live", action="store_true", help=argparse.SUPPRESS)

    # ── live ───────────────────────────────────────────────────────────────────
    p_live = subparsers.add_parser(
        "live",
        help="Open live audio+video stream (ffplay / VLC)",
        description=(
            "📺  live — Open live audio+video stream\n"
            "\n"
            "  Opens an RTSPS stream (H.264 1920×1080 30fps + AAC audio)\n"
            "  via the Bosch cloud proxy (port 443, TLS).\n"
            "\n"
            "  Default player: ffplay (recommended — supports TLS cert skip).\n"
            "  --vlc: pipes the stream through ffmpeg → VLC stdin (macOS only).\n"
            "\n"
            "  Alias: stream\n"
            "\n"
            "  Requirements:\n"
            "    brew install ffmpeg      # for ffplay (default)\n"
            "    brew install --cask vlc  # for --vlc mode"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py live\n"
            "    python3 bosch_camera.py live Kamera\n"
            "    python3 bosch_camera.py live Garten --vlc"
        ),
    )
    p_live.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = first camera)",
    )
    p_live.add_argument(
        "--vlc",
        action="store_true",
        help="Open in VLC via ffmpeg pipe instead of ffplay (macOS only)",
    )
    p_live.add_argument(
        "--hq",
        action="store_true",
        help="Request highQualityVideo=true in PUT /connection (higher bitrate stream)",
    )
    p_live.add_argument(
        "--inst",
        type=int,
        default=2,
        metavar="N",
        help="Stream instance number in RTSPS URL (default: 2)",
    )
    p_live.add_argument(
        "--quality",
        choices=["auto", "high", "low"],
        metavar="Q",
        help="Quality preset: auto (inst=2, default) | high (inst=1, 30Mbps) | low (inst=4, 1.9Mbps)",
    )

    # stream alias
    p_stream = subparsers.add_parser(
        "stream",
        help="Alias for 'live'",
        description="📺  stream — Alias for: live\n\nSee 'live --help' for full details.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_stream.add_argument("cam", nargs="?", metavar="<camera>",
                          help="Camera name or partial match")
    p_stream.add_argument("--vlc", action="store_true",
                          help="Open in VLC via ffmpeg pipe instead of ffplay")
    p_stream.add_argument("--hq", action="store_true",
                          help="Request highQualityVideo=true in PUT /connection")
    p_stream.add_argument("--inst", type=int, default=2, metavar="N",
                          help="Stream instance number in RTSPS URL (default: 2)")
    p_stream.add_argument("--quality", choices=["auto", "high", "low"], metavar="Q",
                          help="Quality preset: auto | high (30Mbps) | low (1.9Mbps)")

    # ── download ───────────────────────────────────────────────────────────────
    p_dl = subparsers.add_parser(
        "download",
        help="Bulk-download all events (JPEG snapshots + MP4 clips)",
        description=(
            "💾  download — Bulk-download all events\n"
            "\n"
            "  Downloads every event's JPEG snapshot and MP4 video clip\n"
            "  from the cloud events API into a per-camera subfolder.\n"
            "\n"
            "  Already-downloaded files are skipped by default.\n"
            "  Only clips with videoClipUploadStatus=Done are downloaded."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py download\n"
            "    python3 bosch_camera.py download Garten\n"
            "    python3 bosch_camera.py download Garten --limit 50\n"
            "    python3 bosch_camera.py download Garten --clips-only\n"
            "    python3 bosch_camera.py download --snaps-only --re-download"
        ),
    )
    p_dl.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_dl.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Maximum number of events to process (default: all)",
    )
    p_dl.add_argument(
        "--snaps-only",
        action="store_true",
        help="Download only JPEG snapshots, skip MP4 clips",
    )
    p_dl.add_argument(
        "--clips-only",
        action="store_true",
        help="Download only MP4 video clips, skip JPEG snapshots",
    )
    p_dl.add_argument(
        "--re-download",
        action="store_true",
        help="Re-download files that already exist locally",
    )

    # ── events ─────────────────────────────────────────────────────────────────
    p_ev = subparsers.add_parser(
        "events",
        help="Show recent event list (timestamps, types, status)",
        description=(
            "📋  events — Show recent event list\n"
            "\n"
            "  Lists the most recent motion/alarm events for a camera.\n"
            "  Each row shows: timestamp, event type, and whether\n"
            "  a snapshot (📸) or video clip (🎬) is available."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py events\n"
            "    python3 bosch_camera.py events Garten\n"
            "    python3 bosch_camera.py events Garten --limit 50"
        ),
    )
    p_ev.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_ev.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Number of events to show (default: 10)",
    )

    # ── privacy ────────────────────────────────────────────────────────────────
    p_priv = subparsers.add_parser(
        "privacy",
        help="Show or toggle privacy mode (cloud API, no SHC needed)",
        description=(
            "🔒  privacy — Show or toggle privacy mode\n"
            "\n"
            "  Uses the Bosch cloud API directly — no SHC local API needed.\n"
            "  API: PUT /v11/video_inputs/{id}/privacy\n"
            "\n"
            "  States:\n"
            "    ON  — camera is blocked, no live images available\n"
            "    OFF — camera is active, live images available\n"
            "\n"
            "  With --minutes: sets a timed privacy period (auto-expires)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py privacy                    # show all\n"
            "    python3 bosch_camera.py privacy Garten             # show one\n"
            "    python3 bosch_camera.py privacy on                 # ON (all cameras)\n"
            "    python3 bosch_camera.py privacy Garten on\n"
            "    python3 bosch_camera.py privacy Garten off\n"
            "    python3 bosch_camera.py privacy Garten on --minutes 30"
        ),
    )
    p_priv.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_priv.add_argument(
        "action",
        nargs="?",
        metavar="on|off",
        choices=["on", "off"],
        help="Set privacy mode: on or off",
    )
    p_priv.add_argument(
        "--minutes",
        type=int,
        default=None,
        metavar="N",
        help="(with 'on') Enable privacy for N minutes, then auto-disable",
    )

    # ── light ──────────────────────────────────────────────────────────────────
    p_light = subparsers.add_parser(
        "light",
        help="Show or toggle camera light manual override (outdoor camera only)",
        description=(
            "💡  light — Show or toggle camera light manual override\n"
            "\n"
            "  Controls the built-in LED/wallwasher light of outdoor cameras.\n"
            "  Only available for cameras with featureSupport.light = true.\n"
            "  Uses the Bosch cloud API — no SHC local API needed.\n"
            "  API: PUT /v11/video_inputs/{id}/lighting_override\n"
            "\n"
            "  Shows current schedule mode, intensity, and motion-triggered\n"
            "  light settings when called without on/off."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py light                  # show all\n"
            "    python3 bosch_camera.py light Garten           # show one\n"
            "    python3 bosch_camera.py light on               # ON (all cameras)\n"
            "    python3 bosch_camera.py light Garten on\n"
            "    python3 bosch_camera.py light Garten off"
        ),
    )
    p_light.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_light.add_argument(
        "action",
        nargs="?",
        metavar="on|off",
        choices=["on", "off"],
        help="Turn light override on or off",
    )

    # ── notifications ──────────────────────────────────────────────────────────
    p_notif = subparsers.add_parser(
        "notifications",
        help="Show or toggle push notifications (cloud API)",
        description=(
            "🔔  notifications — Show or toggle push notifications\n"
            "\n"
            "  Uses the Bosch cloud API.\n"
            "  API: PUT /v11/video_inputs/{id}/enable_notifications\n"
            "\n"
            "  States:\n"
            "    on  → FOLLOW_CAMERA_SCHEDULE (follows app schedule)\n"
            "    off → ALWAYS_OFF"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py notifications\n"
            "    python3 bosch_camera.py notifications Garten\n"
            "    python3 bosch_camera.py notifications on\n"
            "    python3 bosch_camera.py notifications Garten off"
        ),
    )
    p_notif.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_notif.add_argument(
        "action",
        nargs="?",
        metavar="on|off",
        choices=["on", "off"],
        help="Enable or disable push notifications",
    )

    # ── pan ────────────────────────────────────────────────────────────────────
    p_pan = subparsers.add_parser(
        "pan",
        help="Pan the 360 indoor camera (±120°)",
        description=(
            "↔️   pan — Pan the 360 indoor camera\n"
            "\n"
            "  Controls the pan position of the indoor 360 camera.\n"
            "  Only available for cameras with featureSupport.panLimit > 0.\n"
            "  API: PUT /v11/video_inputs/{id}/pan\n"
            "       Body: {\"absolutePosition\": <degrees>}\n"
            "\n"
            "  Presets:\n"
            "    left   →  -120° (full left)\n"
            "    center →    0°  (center)\n"
            "    right  → +120°  (full right)\n"
            "\n"
            "  Or pass any integer in range -panLimit to +panLimit."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py pan                    # show position\n"
            "    python3 bosch_camera.py pan Kamera             # show position\n"
            "    python3 bosch_camera.py pan left               # full left\n"
            "    python3 bosch_camera.py pan Kamera center\n"
            "    python3 bosch_camera.py pan Kamera right\n"
            "    python3 bosch_camera.py pan Kamera 45\n"
            "    python3 bosch_camera.py pan Kamera -90"
        ),
    )
    p_pan.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all 360 cameras)",
    )
    p_pan.add_argument(
        "action",
        nargs="?",
        metavar="left|center|right|<degrees>",
        help="Target position: preset (left/center/right) or angle in degrees",
    )

    # ── token ──────────────────────────────────────────────────────────────────
    p_tok = subparsers.add_parser(
        "token",
        help="Show token status and optionally renew",
        description=(
            "🔑  token — Show OAuth2 token status and optionally renew\n"
            "\n"
            "  Decodes the JWT access token and shows expiry time,\n"
            "  account email, and refresh token status.\n"
            "\n"
            "  Actions:\n"
            "    fix      → renew silently via refresh_token (or browser if needed)\n"
            "    refresh  → same as fix\n"
            "    browser  → force a new browser login (ignores saved refresh_token)\n"
            "\n"
            "  The refresh_token enables silent renewal indefinitely\n"
            "  (set up once via: python3 get_token.py)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py token\n"
            "    python3 bosch_camera.py token fix\n"
            "    python3 bosch_camera.py token browser"
        ),
    )
    p_tok.add_argument(
        "cam",
        nargs="?",
        metavar="fix|refresh|browser",
        help="Action: 'fix' or 'refresh' = silent renewal; 'browser' = force login",
    )

    # ── config ─────────────────────────────────────────────────────────────────
    subparsers.add_parser(
        "config",
        help="Show current config file (tokens masked)",
        description=(
            "⚙️   config — Show current config file\n"
            "\n"
            "  Prints bosch_config.json with tokens truncated for security.\n"
            "  Also shows the current token expiry."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  Example:\n    python3 bosch_camera.py config",
    )

    # ── rcp ────────────────────────────────────────────────────────────────────
    p_rcp = subparsers.add_parser(
        "rcp",
        help="RCP protocol reads via cloud proxy (info, clock, snapshot, alarms, bitrate, ...)",
        description=(
            "🔌  rcp — Remote Configuration Protocol reads via cloud proxy\n"
            "\n"
            "  Opens a REMOTE proxy connection automatically, performs the RCP\n"
            "  session handshake, then reads the requested data.\n"
            "\n"
            "  The proxy hash acts as the credential — no extra auth needed.\n"
            "  Auth level = 3 (read-only). Writes require level 5 (not accessible\n"
            "  via cloud proxy).\n"
            "\n"
            "  Subcommands:\n"
            "    info      — identity: MAC, product name, FQDN, LAN IP\n"
            "    clock     — real-time camera clock (0x0a0f)\n"
            "    snapshot  — RCP JPEG thumbnail 160x90 (0x099e) — save + open\n"
            "    alarms    — alarm catalog from 0x0c38 (UTF-16-BE parsed)\n"
            "    privacy   — privacy mask state read (0x0d00 byte[1])\n"
            "    dimmer    — LED dimmer value 0-100 (0x0c22 T_WORD)\n"
            "    motion    — motion zones from 0x0c0a (count + coords)\n"
            "    services  — network services list from 0x0c62\n"
            "    frame     — raw video frame (0x0c98, 320x180 YUV422 -> JPEG)\n"
            "    script    — IVA automation script (0x09f3, gzip -> text)\n"
            "    iva       — IVA rule types + resiMotion config (0x0ba9 + 0x0a1b)\n"
            "    bitrate   — bitrate ladder tiers in kbps (0x0c81)\n"
            "    all       — run all of the above"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py rcp info\n"
            "    python3 bosch_camera.py rcp Garten info\n"
            "    python3 bosch_camera.py rcp Kamera clock\n"
            "    python3 bosch_camera.py rcp Garten snapshot\n"
            "    python3 bosch_camera.py rcp Garten bitrate\n"
            "    python3 bosch_camera.py rcp all\n"
            "    python3 bosch_camera.py rcp Garten all"
        ),
    )
    p_rcp.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_rcp.add_argument(
        "sub",
        nargs="?",
        metavar="info|clock|snapshot|alarms|privacy|dimmer|motion|services|frame|script|iva|bitrate|all",
        help="RCP subcommand to run",
    )

    # ── rescan ─────────────────────────────────────────────────────────────────
    subparsers.add_parser(
        "rescan",
        help="Re-discover cameras from API and update config",
        description=(
            "🔍  rescan — Re-discover cameras\n"
            "\n"
            "  Calls GET /v11/video_inputs, updates the cameras section\n"
            "  in bosch_config.json, and optionally prompts for local IPs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  Example:\n    python3 bosch_camera.py rescan",
    )

    # ── watch ──────────────────────────────────────────────────────────────────
    p_watch = subparsers.add_parser(
        "watch",
        help="Poll for new events in real-time",
        description=(
            "👁️   watch — Poll for new camera events in real-time\n"
            "\n"
            "  Polls GET /v11/events every N seconds (default 30) and prints\n"
            "  any new events as they arrive. Runs until Ctrl+C or --duration\n"
            "  seconds elapsed.\n"
            "\n"
            "  Each new event shows: time, type (MOVEMENT / AUDIO_ALARM),\n"
            "  camera name, timestamp, snapshot URL, and clip URL."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py watch\n"
            "    python3 bosch_camera.py watch Garten\n"
            "    python3 bosch_camera.py watch Garten --interval 15\n"
            "    python3 bosch_camera.py watch --duration 600\n"
            "    python3 bosch_camera.py watch Garten --snapshot   # auto-open JPEG on new event"
        ),
    )
    p_watch.add_argument("cam", nargs="?", help="Camera name (optional, all cameras if omitted)")
    p_watch.add_argument("--interval", type=int, default=30, metavar="N",
                         help="Poll interval in seconds (default: 30)")
    p_watch.add_argument("--duration", type=int, default=0, metavar="N",
                         help="Stop after N seconds (default: 0 = infinite)")
    p_watch.add_argument("--snapshot", action="store_true",
                         help="Auto-download and open the event JPEG when a new event arrives")
    p_watch.add_argument("--push", action="store_true",
                         help="Use FCM push notifications instead of polling (~2s latency, requires firebase-messaging)")
    p_watch.add_argument("--signal", metavar="URL",
                         help="Send alerts to Signal via signal-cli-rest-api (e.g. http://localhost:8080)")
    p_watch.add_argument("--signal-recipients", metavar="NUMS",
                         help="Comma-separated Signal recipients (phone numbers, e.g. +491234567890)")
    p_watch.add_argument("--signal-sender", metavar="NUM",
                         help="Signal sender number (your registered signal-cli number)")

    # ── motion ─────────────────────────────────────────────────────────────────
    p_motion = subparsers.add_parser(
        "motion",
        help="Get/set motion detection settings",
        description=(
            "🏃  motion — Get or set motion detection settings\n"
            "\n"
            "  Reads or writes the motion detection configuration.\n"
            "  API: GET/PUT /v11/video_inputs/{id}/motion\n"
            "\n"
            "  Sensitivity values: OFF | LOW | MEDIUM_LOW | MEDIUM_HIGH | HIGH | SUPER_HIGH"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py motion Garten\n"
            "    python3 bosch_camera.py motion Garten --enable\n"
            "    python3 bosch_camera.py motion Garten --disable\n"
            "    python3 bosch_camera.py motion Garten --enable --sensitivity SUPER_HIGH\n"
            "    python3 bosch_camera.py motion Garten --sensitivity MEDIUM"
        ),
    )
    p_motion.add_argument("cam", nargs="?", help="Camera name (optional, all cameras if omitted)")
    p_motion.add_argument("--enable",  action="store_true", help="Enable motion detection")
    p_motion.add_argument("--disable", action="store_true", help="Disable motion detection")
    p_motion.add_argument("--sensitivity",
                          choices=["OFF", "LOW", "MEDIUM_LOW", "MEDIUM_HIGH", "HIGH", "SUPER_HIGH"],
                          metavar="S",
                          help="Sensitivity: OFF | LOW | MEDIUM | HIGH | SUPER_HIGH")

    # ── audio-alarm ────────────────────────────────────────────────────────────
    p_audio = subparsers.add_parser(
        "audio-alarm",
        help="Get/set audio alarm detection settings",
        description=(
            "🔊  audio-alarm — Get or set audio alarm detection settings\n"
            "\n"
            "  Reads or writes the audio alarm configuration.\n"
            "  API: GET/PUT /v11/video_inputs/{id}/audioAlarm\n"
            "\n"
            "  Threshold is 0-100 (higher = less sensitive)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py audio-alarm Garten\n"
            "    python3 bosch_camera.py audio-alarm Garten --enable\n"
            "    python3 bosch_camera.py audio-alarm Garten --disable\n"
            "    python3 bosch_camera.py audio-alarm Garten --enable --threshold 60"
        ),
    )
    p_audio.add_argument("cam", nargs="?", help="Camera name (optional, all cameras if omitted)")
    p_audio.add_argument("--enable",    action="store_true", help="Enable audio alarm")
    p_audio.add_argument("--disable",   action="store_true", help="Disable audio alarm")
    p_audio.add_argument("--threshold", type=int, metavar="N",
                         help="Detection threshold 0-100 (higher = less sensitive)")

    # ── recording ──────────────────────────────────────────────────────────────
    p_rec = subparsers.add_parser(
        "recording",
        help="Get/set cloud recording options (sound on/off)",
        description=(
            "🎬  recording — Get or set cloud recording options\n"
            "\n"
            "  Reads or writes the recording configuration.\n"
            "  API: GET/PUT /v11/video_inputs/{id}/recording_options\n"
            "\n"
            "  Controls whether audio is included in cloud-stored recordings."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py recording Garten\n"
            "    python3 bosch_camera.py recording Garten --sound-on\n"
            "    python3 bosch_camera.py recording Garten --sound-off"
        ),
    )
    p_rec.add_argument("cam", nargs="?", help="Camera name (optional, all cameras if omitted)")
    p_rec.add_argument("--sound-on",  action="store_true", dest="sound_on",
                       help="Enable sound recording")
    p_rec.add_argument("--sound-off", action="store_true", dest="sound_off",
                       help="Disable sound recording")

    # ── autofollow ─────────────────────────────────────────────────────────────
    p_af = subparsers.add_parser(
        "autofollow",
        help="Get or set auto-follow (360 camera auto-tracks motion)",
        description=(
            "Auto-follow makes the indoor 360 camera automatically pan to track\n"
            "detected motion. Only available for cameras with panLimit > 0."
        ),
    )
    p_af.add_argument("cam", nargs="?", help="Camera name (optional)")
    p_af.add_argument("action", nargs="?", choices=["on", "off"],
                      help="on = enable auto-follow, off = disable")

    # ── parse ──────────────────────────────────────────────────────────────────
    args = parser.parse_args()

    # Provide sensible defaults for attributes that some subparsers don't define,
    # so all cmd_* functions can safely use getattr(args, "...", default).
    _defaults = dict(
        cam=None, action=None, sub=None, limit=None,
        snaps_only=False, clips_only=False, re_download=False,
        live=False, vlc=False, full=False, minutes=None,
        interval=30, duration=0,
        enable=False, disable=False, sensitivity=None,
        threshold=None, sound_on=False, sound_off=False, push=False,
        signal=None, signal_sender=None, signal_recipients=None,
    )
    for _k, _v in _defaults.items():
        if not hasattr(args, _k):
            setattr(args, _k, _v)

    # Load (or create) config
    cfg = load_config()

    if not args.command:
        # If no cameras yet, do initial discovery
        if not cfg.get("cameras"):
            print("\n  🆕  First run — let's set up your cameras.\n")
            token   = get_token(cfg)
            session = make_session(token)
            cameras = discover_cameras(cfg, session)
            if cameras:
                print(f"\n  Found {len(cameras)} camera(s): {', '.join(cameras.keys())}")
        while True:
            cmd_menu(cfg)
        return

    cmd = args.command.lower()
    # liveshot / livesnap / live-snapshot are aliases for snapshot --live
    if cmd in ("liveshot", "livesnap", "live-snapshot"):
        args.live = True
        cmd = "snapshot"
    # stream is an alias for live
    if cmd == "stream":
        cmd = "live"

    dispatch = {
        "status":        cmd_status,
        "info":          cmd_info,
        "snapshot":      cmd_snapshot,
        "live":          cmd_live,
        "download":      cmd_download,
        "events":        cmd_events,
        "privacy":       cmd_privacy,
        "light":         cmd_light,
        "pan":           cmd_pan,
        "notifications": cmd_notifications,
        "watch":         cmd_watch,
        "motion":        cmd_motion,
        "audio-alarm":   cmd_audio_alarm,
        "recording":     cmd_recording,
        "autofollow":    cmd_autofollow,
        "rcp":           cmd_rcp,
        "token":         cmd_token,
        "config":        cmd_config,
        "rescan":        cmd_rescan,
    }
    if cmd not in dispatch:
        print(f"❌  Unknown command '{cmd}'. Run without arguments for the menu.")
        sys.exit(1)
    dispatch[cmd](cfg, args)


if __name__ == "__main__":
    main()
