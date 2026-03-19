#!/usr/bin/env python3
"""
Bosch Smart Home Camera — All-in-one Standalone Tool
Version: 1.0.0
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
VERSION     = "1.0.0"

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

def get_token(cfg: dict) -> str:
    """
    Return a valid Bearer token. Tries in order:
      1. Saved bearer_token in config
      2. Silent renewal via refresh_token (Keycloak)
      3. Browser login via get_token.py (auto-opens browser)
      4. Manual paste as last resort
    """
    token = cfg["account"].get("bearer_token", "").strip()
    if token:
        return token

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
    """Return human-readable age of bearer_token.txt or config file mtime."""
    # Use config file mtime as proxy for token age
    if not cfg["account"].get("bearer_token"):
        return "no token"
    mtime = os.path.getmtime(CONFIG_FILE)
    age   = datetime.datetime.now() - datetime.datetime.fromtimestamp(mtime)
    mins  = int(age.total_seconds() / 60)
    if mins < 60:
        return f"~{mins} min old ✅"
    elif mins < 120:
        return f"~{mins} min old ⚠️  (may be expired)"
    else:
        return f"~{mins} min old ❌  (likely expired — recapture needed)"


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

def snap_from_proxy(cam_info: dict, token: str) -> bytes | None:
    """
    Live snapshot via PUT /connection.
    Tries LOCAL first (faster on home network), then REMOTE (cloud proxy).
    Returns JPEG bytes or None.
    """
    cam_id  = cam_info.get("id", "")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for conn_type in LIVE_TYPE_CANDIDATES:
        label = "local" if conn_type == "LOCAL" else "cloud proxy"
        print(f"  🌐  Opening {label} connection...")
        try:
            r = requests.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
                headers=headers, json={"type": conn_type}, verify=False, timeout=15,
            )
            if r.status_code != 200:
                continue
            data     = r.json()
            urls     = data.get("urls", [])
            scheme   = data.get("imageUrlScheme", "https://{url}/snap.jpg")
            api_user = data.get("user") or ""
            api_pass = data.get("password") or ""
            if not urls:
                continue
            snap_url = scheme.replace("{url}", urls[0])
            # LOCAL returns Digest credentials; REMOTE needs no auth (hash in URL)
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
            else:
                print(f"  ⚠️   {label} snap returned HTTP {snap_r.status_code}")
        except Exception as e:
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
    """
    token   = get_token(cfg)
    session = make_session(token)
    session.headers["Accept"] = "*/*"
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))
    live    = getattr(args, "live", False)

    for name, cam_info in cams.items():
        mode_str = "Live Snapshot" if live else "Latest Event Snapshot"
        print(f"\n── {mode_str}: {name} ──────────────────────────────────────")

        if live:
            # ── Method 1: Cloud proxy live snap ───────────────────────────────
            data = snap_from_proxy(cam_info, token)
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


def _open_rtsps_stream(rtsps_url: str, cam_name: str, fallback_snap_url: str = "") -> None:
    """
    Open live audio+video stream via rtsps:// (RTSP over TLS on port 443).
    Uses VLC on macOS. Falls back to snap.jpg MJPEG loop if VLC is unavailable.

    Discovery: the cloud proxy speaks real RTSP/1.0 over TLS on port 443.
    Port 42090 (from the API response) only serves HTTP snap.jpg and silently
    drops all RTSP connections. Replace port 42090 → 443 and use rtsps://.
    """
    ffplay = shutil.which("ffplay") or "/opt/homebrew/bin/ffplay"
    mpv    = shutil.which("mpv")
    vlc    = "/Applications/VLC.app/Contents/MacOS/VLC"

    if ffplay and os.path.exists(ffplay):
        # ffplay handles rtsps:// fine from subprocess (unlike MJPEG which needs a window session)
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
    elif os.path.exists(vlc):
        # VLC via open -a — TLS verification may block self-signed certs
        cmd = ["open", "-a", "VLC", "--args", rtsps_url]
        print(f"  ▶️   Launching VLC (audio+video): {rtsps_url}")
        proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
    else:
        print("  ⚠️   No VLC or mpv found — falling back to snap.jpg MJPEG (video only).")
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
    """Open live stream — tries PUT /connection → open VLC on success."""
    token   = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)
    cams    = resolve_cam(cfg, getattr(args, "cam", None))

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
                json={"type": type_val},
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
                    f"/rtsp_tunnel?inst=1&enableaudio=1&fmtp=1&maxSessionDuration=60"
                )
                print(f"  📡  RTSPS URL: {rtsps_url}")
                _open_rtsps_stream(rtsps_url, name, proxy_url)
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
    for i, name in enumerate(cam_names, start=2):
        print(f"  {i})  Latest event snapshot — {name}")
    offset = 2 + len(cam_names)

    print(f"  {offset})  Latest event snapshot — ALL cameras")
    offset += 1

    liveshot_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Live snapshot — {name}  (remote/local)")
        offset += 1

    live_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Live stream — {name} (RTSP → VLC / mpv)")
        offset += 1

    dl_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Download ALL events — {name}")
        offset += 1
    print(f"  {offset})  Download ALL events — ALL cameras")
    offset += 1

    print(f"  {offset})  Show recent events — ALL cameras (last 20)")
    offset += 1
    print(f"  {offset})  Show config file")
    offset += 1
    print(f"  {offset})  Re-scan cameras")
    offset += 1
    print("  0)  Exit")
    print()

    choice = input("  Enter choice: ").strip()

    class A:
        cam = None
        limit = None
        snaps_only = False
        clips_only = False
        re_download = False

    a = A()
    try:
        c = int(choice)
    except ValueError:
        return  # empty Enter or invalid → just redraw menu

    if c == 0:
        sys.exit(0)
    elif c == 1:        cmd_status(cfg, a)
    elif 2 <= c < 2 + len(cam_names):
        a.cam = cam_names[c - 2]
        a.live = False
        cmd_snapshot(cfg, a)
    elif c == 2 + len(cam_names):
        a.live = False
        cmd_snapshot(cfg, a)
    elif liveshot_start <= c < liveshot_start + len(cam_names):
        a.cam  = cam_names[c - liveshot_start]
        a.live = True
        cmd_snapshot(cfg, a)
    elif live_start <= c < live_start + len(cam_names):
        a.cam = cam_names[c - live_start]
        cmd_live(cfg, a)
    elif dl_start <= c < dl_start + len(cam_names):
        a.cam = cam_names[c - dl_start]
        cmd_download(cfg, a)
    elif c == dl_start + len(cam_names):
        cmd_download(cfg, a)
    elif c == dl_start + len(cam_names) + 1:
        a.limit = 20
        cmd_events(cfg, a)
    elif c == dl_start + len(cam_names) + 2:
        cmd_config(cfg, a)
    elif c == dl_start + len(cam_names) + 3:
        cmd_rescan(cfg, a)
    else:
        print(f"  Unknown choice: {c}")

    input("\n  Press Enter to return to menu...")

def main():
    parser = argparse.ArgumentParser(
        description="Bosch Smart Home Camera — standalone tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  status               Camera list with ONLINE/OFFLINE status
  snapshot [name]      Save + open latest snapshot (name: partial camera name)
  live     [name]      Open live stream in VLC/mpv
  download [name]      Bulk download all events (JPEG + MP4)
  events   [name]      Show recent event list
  config               Show current config file contents
  rescan               Re-discover cameras and update config

Run without arguments for the interactive menu.
        """,
    )
    parser.add_argument("command",        nargs="?",              help="Command")
    parser.add_argument("cam",            nargs="?",              help="Camera name (partial match)")
    parser.add_argument("--limit",        type=int, default=None, help="Max events")
    parser.add_argument("--snaps-only",   action="store_true",    help="Only JPEG snapshots")
    parser.add_argument("--clips-only",   action="store_true",    help="Only MP4 clips")
    parser.add_argument("--re-download",  action="store_true",    help="Re-download existing files")
    parser.add_argument("--live",         action="store_true",    help="Use live snapshot methods (proxy/local)")

    args = parser.parse_args()

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
    # liveshot is an alias for snapshot --live
    if cmd in ("liveshot", "livesnap", "live-snapshot"):
        args.live = True
        cmd = "snapshot"

    dispatch = {
        "status":   cmd_status,
        "snapshot": cmd_snapshot,
        "live":     cmd_live,
        "stream":   cmd_live,
        "download": cmd_download,
        "events":   cmd_events,
        "config":   cmd_config,
        "rescan":   cmd_rescan,
    }
    if cmd not in dispatch:
        print(f"❌  Unknown command '{cmd}'. Run without arguments for the menu.")
        sys.exit(1)
    dispatch[cmd](cfg, args)


if __name__ == "__main__":
    main()
