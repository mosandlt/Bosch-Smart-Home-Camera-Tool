#!/usr/bin/env python3
"""
Bosch Smart Home Camera — All-in-one Standalone Tool
Version: 10.7.7
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
  python3 bosch_camera.py events   [<cam-name>] [--limit N] [--clip EVENT_ID]
  python3 bosch_camera.py ping      [<cam-name>] [--json]
  python3 bosch_camera.py lan-ips   [set <cam-name> <ip>|unset <cam-name>|sync]
  python3 bosch_camera.py privacy   [<cam-name>] [on|off] [--local]
  python3 bosch_camera.py light     [<cam-name>] [on|off|intensity N] [--local]
  python3 bosch_camera.py privacy-sound [<cam-name>] [on|off]
  python3 bosch_camera.py audio     [<cam-name>] [--mic N] [--speaker N] [--json]
  python3 bosch_camera.py intrusion [<cam-name>] [--mode indoor|outdoor] [--sensitivity 0-7] [--distance 1-8] [--json]
  python3 bosch_camera.py audio-detection [<cam-name>] [--glass-break on|off] [--fire-alarm on|off] [--json]
  python3 bosch_camera.py wifi      [<cam-name>] [--json]
  python3 bosch_camera.py rules    [<cam-name>] [add|edit|delete]
  python3 bosch_camera.py friends  [invite|share|unshare|resend|remove]
  python3 bosch_camera.py rename   <cam-name> "New Name"
  python3 bosch_camera.py profile  [edit --display-name NAME --marketing on|off]
  python3 bosch_camera.py account                          # feature flags, contracts, purchases
  python3 bosch_camera.py config                           # show current config
  python3 bosch_camera.py rescan                           # re-discover cameras
  python3 bosch_camera.py nvr status [<cam-name>]          # NVR status (BETA)
  python3 bosch_camera.py nvr list   [<cam-name>] [--limit N]
  python3 bosch_camera.py nvr prune  [<cam-name>] [--keep N]
  python3 bosch_camera.py nvr upload [<cam-name>] [--clip PATH]
  python3 bosch_camera.py watch      [<cam-name>] --auto-record  # motion → MP4 (BETA)

Diagnostic & Performance Commands (new in v10.9.0):
  python3 bosch_camera.py snapshot-mjpeg [<cam-name>] [-o out.jpg]  # FFmpeg snap (Gen2, ~150-300ms)
  python3 bosch_camera.py onvif-scopes   [<cam-name>] [--json]      # ONVIF scope strings via LAN RCP
  python3 bosch_camera.py rcp-version    [<cam-name>]               # RCP protocol version (0xff00/0xff04)
  python3 bosch_camera.py feature-flags  [--json]                   # cloud feature flags for account
"""

import os
import sys
import json
import time
import shutil
import signal
import datetime
import argparse
import threading
import subprocess
import urllib3

import requests
from requests.adapters import HTTPAdapter
from typing import Any, Optional, cast
from urllib.parse import urlparse, urlsplit, urlunsplit

import bosch_rcp_client  # RCP session/read/LOCAL-write via bosch-shc-camera-client
from bosch_i18n import t, set_lang, detect_lang
from bosch_maintenance import MaintenanceWindow, fetch_maintenance
from bosch_tls import bosch_get  # TOFU fingerprint pinning for LAN cameras
from bosch_cloud_ssl import (  # CWE-295: verified TLS for Bosch cloud/proxy hosts
    _BoschCloudAdapter,
    get_bosch_cloud_ssl_context,
    make_bosch_cloud_session,
    requests_get_bosch_cloud,
    requests_put_bosch_cloud,
    requests_post_bosch_cloud,
)

# Suppress InsecureRequestWarning — bosch_tls handles LAN camera TLS security via
# TOFU fingerprint pinning (verify=False + SHA-256 pin comparison).
# Cloud endpoints now use proper certificate verification via bosch_cloud_ssl.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "bosch_config.json")
CLOUD_API = "https://residential.cbs.boschsecurity.com"
VERSION = "10.10.5"

# SSRF guard: event snapshot/clip URLs come from the cloud API response, so they
# must be validated against a Bosch-domain allowlist before we fetch them with
# the bearer-carrying session (mirrors the HA integration's _is_safe_bosch_url).
_SAFE_BOSCH_DOMAINS = (".boschsecurity.com", ".bosch.com")


def _is_safe_bosch_url(url: str) -> bool:
    """Return True only for https:// URLs on a known Bosch domain."""
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.hostname.endswith(_SAFE_BOSCH_DOMAINS)
    )


def redact_rtsp_creds(url: str) -> str:
    """Replace userinfo credentials in an RTSP(S) URL with ``***:***``.

    Applied to log/status output only — never to the explicit stream-URL
    command result that the user requests as machine-readable output.

    Mirrors HA's ``_redact_rtsp_creds()`` (switch.py, CWE-312).

    Examples::

        redact_rtsp_creds("rtsps://user:pass@cam.example:443/rtsp_tunnel?inst=2")
        # → "rtsps://***:***@cam.example:443/rtsp_tunnel?inst=2"

        redact_rtsp_creds("rtsps://cam.example/live")   # no userinfo → unchanged
        # → "rtsps://cam.example/live"
    """
    if not url:
        return url
    parsed = urlsplit(url)
    if "@" not in parsed.netloc:
        return url
    host_part = parsed.netloc.rsplit("@", 1)[1]
    redacted = urlunsplit(
        (parsed.scheme, f"***:***@{host_part}", parsed.path, parsed.query, parsed.fragment)
    )
    return redacted


DELAY = 0.5  # seconds between download requests (rate-limit protection)

# Human-readable display names for camera hardware versions
HW_DISPLAY_NAMES = {
    "INDOOR": "360 Innenkamera",
    "OUTDOOR": "Eyes Außenkamera",
    "CAMERA_360": "360 Innenkamera",
    "CAMERA_EYES": "Eyes Außenkamera",
    "HOME_Eyes_Outdoor": "Eyes Außenkamera II",
    "HOME_Eyes_Indoor": "Eyes Innenkamera II",
    "CAMERA_OUTDOOR_GEN2": "Eyes Außenkamera II",
    "CAMERA_INDOOR_GEN2": "Eyes Innenkamera II",
}

# ConnectionType enum — confirmed working values (discovered 2026-03-19)
# REMOTE = cloud proxy snap.jpg (fast ~1.5s, no credentials needed)
# LOCAL  = direct LAN snap.jpg (slow ~15s Digest auth, same quality)
# Use REMOTE first for all operations — it is faster than LOCAL despite going via cloud.
LIVE_TYPE_CANDIDATES = [
    "REMOTE",  # ✅ cloud proxy — faster (1.5s vs 15s for LOCAL)
    "LOCAL",  # ✅ LAN direct — fallback if cloud unavailable
]

DEFAULT_CONFIG = {
    "account": {
        "username": "",
        "password": "",
        "bearer_token": "",
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
        "download_base_path": "",
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
    "lan_ips": {
        # cam_id (UUID) → LAN IP.  Used by --local flag for RCP writes.
        # Populated automatically by "bosch lan-ips set <cam> <ip>".
        # Also auto-populated from cameras[*].local_ip on load.
        # Example:
        #   "AABBCCDD-0000-1111-2222-333344445555": "192.168.1.100"
    },
    "nvr": {
        "max_clips": 50,
        "max_duration": 60,
        "smb": {
            "host": "",
            "share": "",
            "username": "",
            "password": "",
            "path": "",
            "delete_after_upload": False,
        },
        "_note": (
            "nvr.max_clips: keep only the N most recent clips per camera (FIFO). "
            "nvr.max_duration: length of each recorded segment while motion stays "
            "active — a single motion session longer than this produces multiple "
            "consecutive clips instead of one file. "
            "nvr.segment_seconds: optional newer alias for max_duration, takes "
            "priority if both are set — NOT part of this default config on purpose "
            "(deliberately not auto-injected into existing configs on load, so it "
            "never silently shadows a max_duration value you've customized; add it "
            "yourself if you want the new name). --nvr-segment-seconds on `watch` "
            "overrides both, per run. "
            "nvr.smb.*: optional SMB/NAS upload — requires 'pip install smbprotocol'. "
            "Leave nvr.smb.host empty to disable upload."
        ),
    },
}
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════ CONFIG MANAGEMENT ═════════════════════════════════


def load_config() -> dict[str, Any]:
    """Load config from file. Creates default config if it doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        _create_default_config()
    with open(CONFIG_FILE, encoding="utf-8") as f:
        cfg: dict[str, Any] = json.load(f)
    # Merge in any missing keys from DEFAULT_CONFIG (forward-compat)
    _merge_defaults(cfg, DEFAULT_CONFIG)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    """Save config to file.

    Serialized via _CONFIG_LOCK so concurrent writes (main thread saving a fresh
    bearer token + FCM credentials-update callback firing from a background
    thread) cannot interleave. Written via tmpfile + os.replace so readers
    never see a half-written JSON — process crash mid-write leaves the
    previous file intact instead of a truncated one.
    """
    with _CONFIG_LOCK:
        tmp_path = f"{CONFIG_FILE}.tmp.{os.getpid()}"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, CONFIG_FILE)
        except Exception:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise


def _create_default_config() -> None:
    """Create a new config file with defaults and print instructions."""
    save_config(DEFAULT_CONFIG)
    print(t("cli.config.created", path=CONFIG_FILE))
    print(t("cli.config.created.hint"))


def _merge_defaults(cfg: dict[str, Any], defaults: dict[str, Any]) -> None:
    """Recursively add missing keys from defaults into cfg (in-place)."""
    for key, val in defaults.items():
        if key not in cfg:
            cfg[key] = val
        elif isinstance(val, dict) and isinstance(cfg[key], dict):
            _merge_defaults(cfg[key], val)


# ══════════════════════════ TOKEN MANAGEMENT ══════════════════════════════════


def _is_token_expired(token: str) -> bool:
    """Return True if the JWT bearer token is expired or expiring within 60s.

    Fail-safe: returns True (treat as expired) if the token cannot be decoded.
    Matches _is_token_near_expiry semantics so an undecodable token never
    bypasses a refresh and gets sent to the cloud API.
    """
    import base64 as _b64
    import json as _json

    try:
        parts = token.split(".")
        if len(parts) >= 2:
            pad = len(parts[1]) % 4
            body = _b64.urlsafe_b64decode(parts[1] + "=" * pad)
            exp: int = int(_json.loads(body).get("exp", 0))
            return exp == 0 or (exp - time.time()) < 60
    except Exception:
        pass
    return True


def _is_token_near_expiry(token_str: str, buffer_secs: int = 60) -> bool:
    """Return True if the JWT bearer token expires within buffer_secs seconds.

    Fail-safe: returns True (treat as near-expiry) if decoding fails.
    Uses only stdlib: base64, json, time.
    """
    import base64 as _b64
    import json as _json

    try:
        parts = token_str.split(".")
        if len(parts) >= 2:
            pad = len(parts[1]) % 4
            body = _b64.urlsafe_b64decode(parts[1] + "=" * pad)
            exp: int = int(_json.loads(body).get("exp", 0))
            return exp == 0 or (exp - time.time()) < buffer_secs
    except Exception:
        pass
    return True


def get_token(cfg: dict[str, Any]) -> str:
    """
    Return a valid Bearer token. Tries in order:
      1. Saved bearer_token in config (if not expired)
      2. Silent renewal via refresh_token (auto, no user interaction)
      3. Browser login via get_token.py (auto-opens browser)
      4. Manual paste as last resort
    """
    token: str = cfg["account"].get("bearer_token", "").strip()
    if token and not _is_token_expired(token):
        return token

    # Token expired or missing — try silent renewal first
    refresh: str = cfg["account"].get("refresh_token", "").strip()
    if refresh:
        try:
            from get_token import _do_refresh

            if token:  # only print if we had a token (i.e. it expired)
                print(t("cli.token.renewing"))
            tokens = _do_refresh(refresh)
            if tokens:
                new_token: str = tokens.get("access_token", "")
                new_refresh: str = tokens.get("refresh_token", refresh)
                cfg["account"]["bearer_token"] = new_token
                cfg["account"]["refresh_token"] = new_refresh
                save_config(cfg)
                print(t("cli.token.renewed"))
                return new_token
        except ImportError:
            pass
        except Exception as e:
            print(t("cli.token.renew_failed", error=e))

    if token:
        return token  # Expired but renewal failed — return as-is and let the API reject it

    # Try get_token.py auto-flow (refresh + browser login)
    try:
        from get_token import get_token_auto

        print(t("cli.token.no_token"))
        auto_token: Optional[str] = get_token_auto(cfg)
        if auto_token:
            return auto_token
    except ImportError:
        # get_token.py not in path — fall through to manual
        pass
    except Exception as e:
        print(t("cli.token.auto_failed", error=e))

    # Manual fallback
    print(t("cli.token.obtain_failed"))
    print(t("cli.token.options"))
    print(t("cli.token.option_get_token"))
    print(t("cli.token.option_paste"))
    print(t("cli.token.option_paste2"))
    token = input(t("input.paste_token")).strip()
    if not token:
        print(t("cli.token.no_token_exit"))
        sys.exit(1)
    cfg["account"]["bearer_token"] = token
    save_config(cfg)
    print(t("cli.token.saved"))
    return token


def check_token_age(cfg: dict[str, Any]) -> str:
    """Return human-readable token expiry decoded from JWT claims."""
    import base64 as _b64
    import json as _json

    token = cfg["account"].get("bearer_token", "").strip()
    if not token:
        return "no token"
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            pad = len(parts[1]) % 4
            body = _b64.urlsafe_b64decode(parts[1] + "=" * pad)
            info = _json.loads(body)
            exp = info.get("exp", 0)
            if exp:
                exp_dt = datetime.datetime.fromtimestamp(exp)
                diff = exp_dt - datetime.datetime.now()
                mins = int(diff.total_seconds() / 60)
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
    age = datetime.datetime.now() - datetime.datetime.fromtimestamp(mtime)
    mins = int(age.total_seconds() / 60)
    if mins < 60:
        return f"~{mins} min old ✅"
    elif mins < 120:
        return f"~{mins} min old ⚠️  (may be expired)"
    else:
        return f"~{mins} min old ❌  — run: python3 bosch_camera.py token fix"


def handle_401(cfg: dict[str, Any]) -> str:
    """Called when API returns 401. Clears token, prompts for a new one."""
    print(t("cli.token.expired_401"))
    cfg["account"]["bearer_token"] = ""
    return get_token(cfg)


# ══════════════════════════ SESSION ═══════════════════════════════════════════

# Cached global session — reuses a single TCP/TLS connection pool across all API
# calls (avoids handshake-per-request). Token updates only touch the Authorization
# header, so the underlying pool stays warm.
_HTTP_SESSION: Optional[requests.Session] = None


def make_session(token: str) -> requests.Session:
    """Return the cached module-level session, updating the Bearer token header.

    On first call, creates a requests.Session with a connection-pooled HTTPAdapter
    (pool_connections=10, pool_maxsize=20, max_retries=0 — retries are handled
    explicitly by _request_with_retry). Subsequent calls just swap the token on
    the existing session so connections are reused.
    """
    global _HTTP_SESSION
    if _HTTP_SESSION is None:
        s = requests.Session()
        # Mount the Bosch cloud SSL adapter on https:// — trusts system roots
        # AND the Bosch private CA (Video CA 2A), replacing verify=False (CWE-295).
        cloud_adapter = _BoschCloudAdapter(
            ssl_context=get_bosch_cloud_ssl_context(),
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0,
        )
        s.mount("https://", cloud_adapter)
        s.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=0))
        # Do NOT set s.verify = False — the adapter handles TLS for cloud hosts.
        _HTTP_SESSION = s
    # Accept must stay binary-safe (*/*): Bosch nginx returns
    # HTTP 500 sh:internal.error on /v11/events/{id}/snap.jpg and /clip.mp4
    # when Accept is application/json. JSON endpoints accept */* fine.
    _HTTP_SESSION.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "*/*",
        }
    )
    return _HTTP_SESSION


# Lock serializing bosch_config.json writes (FCM creds-update callback may fire
# from a background thread while the main thread is also saving tokens).
_CONFIG_LOCK = threading.Lock()


# Set by SIGTERM/SIGINT handlers so long-running loops (watch, FCM) can exit
# cleanly instead of relying solely on KeyboardInterrupt propagation.
_STOP_REQUESTED = threading.Event()

# Maintenance hint: shown at most once per process run to avoid log spam.
_maintenance_hint_shown = False


def _maybe_print_maintenance_hint() -> None:
    """Print a one-line maintenance hint when a 5xx response was received.

    Fetches the community RSS feeds lazily and prints a hint only when state is
    'active' or 'scheduled'.  Shown at most once per process run.
    """
    global _maintenance_hint_shown
    if _maintenance_hint_shown:
        return
    _maintenance_hint_shown = True
    try:
        mw: MaintenanceWindow | None = fetch_maintenance(timeout_s=5.0)
        if mw is not None and mw.state() in {"active", "scheduled"}:
            print(t("cmd.maintenance.hint_5xx"))
    except Exception:
        pass  # never let hint logic crash the caller


def _install_stop_handlers() -> None:
    """Install SIGINT/SIGTERM handlers that flip _STOP_REQUESTED.

    Safe to call multiple times — later calls just re-install the same handler.
    Only installs in the main thread (signal.signal() raises otherwise).
    """
    if threading.current_thread() is not threading.main_thread():
        return

    def _handler(signum: int, frame: Any) -> None:
        _STOP_REQUESTED.set()

    try:
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):
        # signal.signal() can fail in odd embedding contexts — ignore.
        pass


def _request_with_retry(
    session: requests.Session, method: str, url: str, max_attempts: int = 3, **kwargs: Any
) -> requests.Response:
    """Issue an HTTP request with exponential backoff on transient failures.

    Retries only on HTTP 5xx responses and on requests.exceptions.Timeout /
    ConnectionError. Auth/client errors (401/403/404, etc.) pass through on the
    first attempt — the caller decides how to react.

    Backoff: 1s, 2s, 4s between attempts (max_attempts=3 → up to 2 retries).
    """
    last_exc: Optional[BaseException] = None
    for attempt in range(max_attempts):
        try:
            r = session.request(method, url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_exc = e
            if attempt == max_attempts - 1:
                raise
            time.sleep(2**attempt)
            continue
        # Retry only on server-side errors.
        if 500 <= r.status_code < 600 and attempt < max_attempts - 1:
            time.sleep(2**attempt)
            continue
        # All retries exhausted with a persistent 5xx — show maintenance hint.
        if 500 <= r.status_code < 600:
            _maybe_print_maintenance_hint()
        return r
    # Unreachable — loop either returns a response or re-raises. Keep for safety.
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("unreachable: _request_with_retry loop exited without result")


# ══════════════════════════ CAMERA DISCOVERY ══════════════════════════════════


def discover_cameras(cfg: dict[str, Any], session: requests.Session) -> dict[str, Any]:
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
    cameras = {}
    for cam in cam_list:
        name = cam.get("title", cam.get("id", "unknown"))
        # Keep existing local config if camera already known
        existing = cfg.get("cameras", {}).get(name, {})
        feat = cam.get("featureSupport", {})
        cameras[name] = {
            "id": cam.get("id", ""),
            "name": name,
            "model": cam.get("hardwareVersion", "CAMERA"),
            "firmware": cam.get("firmwareVersion", ""),
            "mac": cam.get("macAddress", ""),
            "download_folder": name,
            "local_ip": existing.get("local_ip", ""),
            "local_username": existing.get("local_username", ""),
            "local_password": existing.get("local_password", ""),
            "has_light": feat.get("light", False),
            "pan_limit": feat.get("panLimit", 0),
        }
        # Ask for local IP if not already set (skip prompt in non-interactive mode)
        if not cameras[name]["local_ip"]:
            print(t("cli.cam.discovered", name=name))
            try:
                ip = input(t("input.local_ip")).strip()
            except EOFError:
                # Non-interactive (CI, cron, piped) — leave blank, user can edit
                # bosch_config.json later. Without this guard `rescan` crashes.
                print(
                    "    (non-interactive — skipping local_ip prompt; edit bosch_config.json later)"
                )
                ip = ""
            if ip:
                cameras[name]["local_ip"] = ip
    cfg["cameras"] = cameras
    save_config(cfg)
    print(t("cli.cam.discovered_count", count=len(cameras), path=CONFIG_FILE))
    return cameras


def get_cameras(cfg: dict[str, Any], session: requests.Session) -> dict[str, Any]:
    """Return cameras from config; auto-discover if none are saved yet."""
    if not cfg.get("cameras"):
        print(t("cli.cam.no_cameras_discovering"))
        return discover_cameras(cfg, session)
    return cast(dict[str, Any], cfg["cameras"])


def resolve_cam(cfg: dict[str, Any], key: str | None) -> dict[str, Any]:
    """
    Resolve a partial camera name to the full cameras dict entry.
    If key is None → return all cameras.
    If key matches exactly or case-insensitively → return that single camera dict.
    """
    cameras: dict[str, Any] = cfg.get("cameras", {})
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
        print(t("cli.cam.ambiguous", key=key, names=names))
        sys.exit(1)
    print(t("cli.cam.not_found", key=key, known=", ".join(cameras.keys())))
    print(t("cli.cam.not_found_hint"))
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


def api_get_events(session: requests.Session, cam_id: str, limit: int = 400) -> list[Any]:
    r = _request_with_retry(
        session,
        "GET",
        f"{CLOUD_API}/v11/events?videoInputId={cam_id}&limit={limit}",
        timeout=30,
    )
    if r.status_code == 401:
        return []
    r.raise_for_status()
    return cast(list[Any], r.json())


def api_mark_events_read(session: requests.Session, event_ids: list[str]) -> bool:
    """Mark events as read on the Bosch cloud via PUT /v11/events.

    The /v11/events/bulk endpoint only supports `{ids, action: "DELETE"}` —
    there is no bulk mark-as-read. Returns True if at least one PUT succeeded.
    """
    if not event_ids:
        return True

    success = False
    for eid in event_ids:
        try:
            r = session.put(
                f"{CLOUD_API}/v11/events",
                json={"id": eid, "isRead": True},
                timeout=5,
            )
            if r.status_code in (200, 204):
                success = True
        except Exception:
            pass
    return success


def api_get_camera(session: requests.Session, cam_id: str) -> dict[str, Any] | None:
    """
    GET /v11/video_inputs/{cam_id} — fetch a single camera object by ID.
    Returns the camera dict or None on error.
    """
    try:
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}", timeout=15)
        if r.status_code == 200:
            return cast(dict[str, Any], r.json())
    except Exception:
        pass
    return None


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
        print(t("cli.player.not_found"))
        print(t("cli.player.not_found_hint"))
        print(f"      Stream URL:   {url}")
        return

    print(t("cli.player.opening", player=os.path.basename(player), url=url))

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

            host_part = url[len("rtsp://") :]
            open_url = f"rtsp://{quote(user, safe='')}:{quote(password, safe='')}@{host_part}"
        cmd = [player, open_url]
        if token and "vlc" in name:
            cmd += ["--http-cookie", f"HcsoB={token[:20]}"]

    if user:
        print(t("cli.player.creds", user=user))
    subprocess.Popen(cmd)


# ══════════════════════════ COMMANDS ══════════════════════════════════════════


def cmd_status(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show all cameras with ONLINE/OFFLINE status."""
    token = get_token(cfg)
    session = make_session(token)
    cameras = get_cameras(cfg, session)

    # Check live list for cameras added in the Bosch app since last rescan.
    try:
        live_r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
        if live_r.status_code == 200:
            live_titles = {c.get("title", c.get("id", "")) for c in live_r.json()}
            new_cams = sorted(live_titles - set(cameras.keys()))
            if new_cams:
                print(
                    f"  ℹ️  {len(new_cams)} new camera(s) detected — run `rescan` to add them to config: {', '.join(new_cams)}"
                )
    except Exception:
        pass

    print(t("cmd.status.header"))
    print(t("cmd.status.token_age", age=check_token_age(cfg)))

    for name, cam_info in cameras.items():
        status = api_ping(session, cam_info["id"])
        if status == "ONLINE":
            icon = "🟢"
        elif status.startswith("UPDATING"):
            icon = "🔄"
            status = "UPDATING (firmware)"
        else:
            icon = "🔴"
        print(t("cmd.status.cam_name", icon=icon, name=name))
        print(t("cmd.status.cam_id", id=cam_info["id"]))
        print(t("cmd.status.cam_model", model=cam_info["model"], fw=cam_info["firmware"]))
        print(t("cmd.status.cam_mac", mac=cam_info["mac"]))
        print(t("cmd.status.cam_status", status=status))
        print()


def cmd_events(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show latest events — removed (cloud event listing no longer available)."""
    print(t("cmd.status.events_removed"))
    return


# ══════════════════════════ LIVE SNAPSHOT METHODS ═══════════════════════════


def snap_from_proxy(
    cam_info: dict[str, Any],
    token: str,
    hq: bool = False,
    cfg: Optional[dict[str, Any]] = None,
    session: Optional[requests.Session] = None,
) -> bytes | None:
    """
    Live snapshot via PUT /connection.
    Tries LOCAL first (faster on home network), then REMOTE (cloud proxy).
    If snap.jpg returns 404 (proxy session expired), automatically re-requests
    a fresh connection and retries once.
    hq=True requests highQualityVideo in the connection payload.
    If cfg is provided and we receive a 401 on PUT /connection, refresh the
    token once and retry. On second 401 we fail hard with a clear message.

    ``session``: pooled ``requests.Session`` (see ``make_session()``) reused for
    both the cloud PUT /connection call and the REMOTE snap.jpg GET — avoids a
    fresh TCP/TLS handshake on every poll tick in hot callers like the live-view
    loop. Defaults to the cached module-level session via ``make_session(token)``
    when omitted (e.g. one-shot CLI callers) — same session ``cmd_live``/``cmd_watch``
    already use for their own cloud calls, so this is not a new shared resource.
    LOCAL (LAN camera) requests are unaffected — they keep using a one-shot
    ``requests.get`` since each LOCAL host is a different self-signed camera IP.

    Returns JPEG bytes or None.
    """
    cam_id = cam_info.get("id", "")
    _session = session if session is not None else make_session(token)
    # Mutable list so the inner closure can update the header after a token refresh.
    headers_box = [{"Authorization": f"Bearer {token}", "Content-Type": "application/json"}]

    def _put_connection(conn_type: str) -> requests.Response:
        """PUT /connection with one-shot token refresh on 401."""
        r = _session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
            headers=headers_box[0],
            json={"type": conn_type, "highQualityVideo": hq},
            timeout=15,
        )
        if r.status_code == 401 and cfg is not None:
            print(t("cmd.token.refresh_401"))
            try:
                new_token = get_token(cfg)
            except Exception as e:
                print(t("cmd.token.refresh_failed", error=e))
                print(t("cmd.token.refresh_failed_hint"))
                return r
            headers_box[0] = {
                "Authorization": f"Bearer {new_token}",
                "Content-Type": "application/json",
            }
            # Also update the cached session so subsequent calls use the new token.
            make_session(new_token)
            r = _session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
                headers=headers_box[0],
                json={"type": conn_type, "highQualityVideo": hq},
                timeout=15,
            )
            if r.status_code == 401:
                print(t("cmd.token.still_401") + "Run `bosch-camera login`.")
        return r

    def _fetch_snap(conn_type: str) -> bytes | None:
        label = "local" if conn_type == "LOCAL" else "cloud proxy"
        print(t("cmd.live.opening_conn", label=label))
        r = _put_connection(conn_type)
        if r.status_code != 200:
            return None
        data = r.json()
        urls = data.get("urls", [])
        scheme = data.get("imageUrlScheme", "https://{url}/snap.jpg")
        api_user = data.get("user") or ""
        api_pass = data.get("password") or ""
        if not urls:
            return None
        snap_url = scheme.replace("{url}", urls[0])
        snap_timeout = 5 if conn_type == "LOCAL" else 15
        # LOCAL: camera self-signed cert → verify=False (TOFU-pinned by bosch_tls),
        # one-shot since each LOCAL host is a different self-signed camera IP.
        # REMOTE: Bosch cloud proxy → same pooled cloud session as the PUT above
        # (CWE-295 fix via the session's mounted _BoschCloudAdapter; avoids a
        # fresh TCP/TLS handshake on every poll tick — see docstring).
        _snap_get = requests.get if conn_type == "LOCAL" else _session.get
        if api_user and api_pass:
            from requests.auth import HTTPDigestAuth

            _snap_kwargs: dict[str, Any] = {
                "auth": HTTPDigestAuth(api_user, api_pass),
                "timeout": snap_timeout,
            }
            if conn_type == "LOCAL":
                _snap_kwargs["verify"] = False
            snap_r = _snap_get(snap_url, **_snap_kwargs)
        else:
            _snap_kwargs2: dict[str, Any] = {"timeout": snap_timeout}
            if conn_type == "LOCAL":
                _snap_kwargs2["verify"] = False
            snap_r = _snap_get(snap_url, **_snap_kwargs2)
        if snap_r.status_code == 200 and snap_r.headers.get("Content-Type", "").startswith("image"):
            print(t("cmd.live.snap_ok", label=label, bytes=f"{len(snap_r.content):,}"))
            return snap_r.content
        elif snap_r.status_code == 404:
            print(t("cmd.live.proxy_expired"))
            # Retry once with a fresh connection (reuses the refreshed token if
            # the first PUT already triggered a token renewal).
            r2 = _put_connection(conn_type)
            if r2.status_code == 200:
                data2 = r2.json()
                urls2 = data2.get("urls", [])
                scheme2 = data2.get("imageUrlScheme", "https://{url}/snap.jpg")
                api_user2 = data2.get("user") or ""
                api_pass2 = data2.get("password") or ""
                if urls2:
                    snap_url2 = scheme2.replace("{url}", urls2[0])
                    if api_user2 and api_pass2:
                        from requests.auth import HTTPDigestAuth

                        _retry_kwargs: dict[str, Any] = {
                            "auth": HTTPDigestAuth(api_user2, api_pass2),
                            "timeout": snap_timeout,
                        }
                        if conn_type == "LOCAL":
                            _retry_kwargs["verify"] = False
                        snap_r2 = _snap_get(snap_url2, **_retry_kwargs)
                    else:
                        _retry_kwargs2: dict[str, Any] = {"timeout": snap_timeout}
                        if conn_type == "LOCAL":
                            _retry_kwargs2["verify"] = False
                        snap_r2 = _snap_get(snap_url2, **_retry_kwargs2)
                    if snap_r2.status_code == 200 and snap_r2.headers.get(
                        "Content-Type", ""
                    ).startswith("image"):
                        print(
                            t(
                                "cmd.live.snap_retry_ok",
                                label=label,
                                bytes=f"{len(snap_r2.content):,}",
                            )
                        )
                        return snap_r2.content
            print(t("cmd.live.snap_retry_fail", label=label))
            return None
        else:
            print(t("cmd.live.snap_http_fail", label=label, status=snap_r.status_code))
            return None

    for conn_type in LIVE_TYPE_CANDIDATES:
        try:
            result = _fetch_snap(conn_type)
            if result:
                return result
        except Exception as e:
            label = "local" if conn_type == "LOCAL" else "cloud proxy"
            print(t("cmd.live.snap_error", label=label, error=e))
    return None


def get_stream_url(
    cam_info: dict[str, Any],
    token: str,
    hq: bool = False,
    cfg: Optional[dict[str, Any]] = None,
    conn_type: Optional[str] = None,
) -> dict[str, Any] | None:
    """Resolve a live RTSP(S) stream URL for a camera via PUT /connection.

    This is the shared accessor behind the CLI ``live`` command and the NiceGUI
    frontend's WebRTC player (a go2rtc source — see the frontend's
    ``docs/live-webrtc-plan.md``). Browsers cannot play rtsp(s):// directly; the
    consumer feeds this URL to go2rtc which transcodes to WebRTC/HLS.

    Tries LOCAL first then REMOTE (LOCAL_OVER_REMOTE) unless ``conn_type`` pins one.
    One-shot token refresh on 401 when ``cfg`` is given.

    Returns ``{"url", "type", "user", "password"}`` (url = ``rtsp://user:pass@host``
    for LOCAL, ``rtsps://proxy:443/<hash>`` for REMOTE) or ``None`` if no
    connection could be opened. NOTE: Gen2 cameras ROTATE the Digest credentials on
    each PUT /connection, so callers must treat the URL as short-lived and
    re-resolve on stream failure (the frontend plan covers the refresh loop).
    """
    cam_id = cam_info.get("id", "")
    if not cam_id:
        return None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    # inst=1 → main (HQ) stream, inst=2 → sub-stream (lighter). Mirror the `hq`
    # flag into the stream selector so callers actually get the quality they ask
    # for (matches _build_stream_urls' inst=1-for-main convention).
    inst = 1 if hq else 2
    params = f"inst={inst}&enableaudio=1&fmtp=1&maxSessionDuration=3600"
    candidates = [conn_type] if conn_type else list(LIVE_TYPE_CANDIDATES)

    def _put(ctype: str) -> requests.Response:
        r = requests.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
            headers=headers,
            json={"type": ctype, "highQualityVideo": hq},
            timeout=15,
        )
        if r.status_code == 401 and cfg is not None:
            try:
                new_token = get_token(cfg)
            except Exception:
                return r
            headers["Authorization"] = f"Bearer {new_token}"
            make_session(new_token)
            r = requests.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
                headers=headers,
                json={"type": ctype, "highQualityVideo": hq},
                timeout=15,
            )
        return r

    for ctype in candidates:
        try:
            r = _put(ctype)
            if r.status_code not in (200, 201):
                continue
            data = r.json()
            urls = data.get("urls", [])
            user = data.get("user", "") or ""
            password = data.get("password", "") or ""
            if not urls:
                continue
            u = urls[0]
            if "/" in u:
                # REMOTE: "proxy-NN…:42090/{hash}" → rtsps over TLS on 443
                host_port, hash_path = u.split("/", 1)
                proxy_host = host_port.split(":")[0]
                url = f"rtsps://{proxy_host}:443/{hash_path}/rtsp_tunnel?{params}"
            else:
                # LOCAL: "192.168.x.x:443" → rtsp:// with URL-encoded Digest creds
                from urllib.parse import quote as _q

                auth = f"{_q(user, safe='')}:{_q(password, safe='')}@" if user and password else ""
                url = f"rtsp://{auth}{u}/rtsp_tunnel?{params}"
            return {"url": url, "type": ctype, "user": user, "password": password}
        except Exception:
            continue
    return None


def snap_from_local(cam_info: dict[str, Any], cfg: Optional[dict[str, Any]] = None) -> bytes | None:
    """
    Method 2 — Local camera snap.jpg via HTTP Digest authentication.
    Direct access to the camera at https://<local_ip>/snap.jpg
    Returns 1920×1080 JPEG bytes or None.

    Credentials are randomly generated by the SHC at pairing time.
    Capture via mitmproxy and store in config under local_ip / local_username / local_password.

    Pass ``cfg`` (the loaded bosch_config.json dict) to enable TOFU fingerprint
    pinning — on first contact the certificate fingerprint is stored; subsequent
    calls verify it matches.  Without ``cfg`` the call degrades to verify=False.

    WARNING: Excessive requests to the local camera IP can break the connection,
    causing the SHC to regenerate random credentials. Use sparingly.
    """
    local_ip = cam_info.get("local_ip", "")
    username = cam_info.get("local_username", "")
    password = cam_info.get("local_password", "")

    if not local_ip or not username or not password:
        return None

    # Append ?JpegSize=1206 — without it the camera triggers a slow on-demand
    # full-sensor capture (~6–10 s when idle). With it, the cached path serves
    # in ~1.4 s. Verified empirically; matches HA integration v10.4.5 fix.
    url = f"https://{local_ip}/snap.jpg?JpegSize=1206"
    print(t("cmd.local_snap.trying", url=url))
    try:
        from requests.auth import HTTPDigestAuth

        r = bosch_get(
            url,
            cfg=cfg,
            auth=HTTPDigestAuth(username, password),
            timeout=10,
        )
        if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image"):
            print(t("cmd.local_snap.ok", bytes=f"{len(r.content):,}"))
            return r.content
        else:
            print(t("cmd.local_snap.http_fail", status=r.status_code))
    except Exception as e:
        print(t("cmd.local_snap.error", error=e))
    return None


def snap_from_events(
    session: requests.Session, cam_info: dict[str, Any]
) -> tuple[bytes | None, str]:
    """
    Method 3 — Latest event snapshot (cloud API, motion-triggered).
    Returns (jpeg_bytes, timestamp_str) or (None, "").
    Only updates when the camera detects motion — not a live view.
    """
    events = api_get_events(session, cam_info["id"], limit=10)
    for ev in events:
        img_url = ev.get("imageUrl")
        if not img_url or not _is_safe_bosch_url(img_url):
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
    ts_safe = (
        ts.replace(":", "-").replace("T", "_")
        if ts
        else datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    )
    fn = f"snapshot_{safe_name}_{ts_safe}_{method}.jpg"
    path = os.path.join(BASE_DIR, fn)
    with open(path, "wb") as f:
        f.write(data)
    print(t("cmd.snapshot.saved", path=path, bytes=f"{len(data):,}"))
    open_file(path)
    return path


# ─────────────────────────────────────────────────────────────────────────────
def cmd_snapshot(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """
    Fetch and open the best available snapshot for a camera.

    Without --live: shows latest event snapshot (cloud events API).
    With --live:    tries methods in order:
                      1. Cloud proxy live snap (if live connection previously opened)
                      2. Local camera snap.jpg (if local_ip + credentials in config)
                      3. Latest event snapshot (fallback)
    --hq: request highQualityVideo=true in PUT /connection (higher resolution).
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))
    live = getattr(args, "live", False)
    quality = getattr(args, "quality", None)
    if quality == "high":
        hq = True
    elif quality is not None:
        hq = False
    else:
        hq = getattr(args, "hq", False)

    for name, cam_info in cams.items():
        mode_str = "Live Snapshot" if live else "Latest Event Snapshot"
        print(t("cmd.snapshot.header", mode=mode_str, name=name))

        if live:
            # ── Method 1: Cloud proxy live snap ───────────────────────────────
            data = snap_from_proxy(cam_info, token, hq=hq, cfg=cfg, session=session)
            if data:
                _save_and_open(data, name, "", "proxy_live")
                continue

            # ── Method 2: Local camera snap.jpg ───────────────────────────────
            data = snap_from_local(cam_info, cfg=cfg)
            if data:
                _save_and_open(data, name, "", "local_live")
                continue

            print(t("cmd.snapshot.live_unavail"))
            if not cam_info.get("last_live", {}).get("proxy_url"):
                print(t("cmd.snapshot.live_no_proxy"))
                print(t("cmd.snapshot.live_no_proxy_hint", name=name))
            if not cam_info.get("local_ip"):
                print(t("cmd.snapshot.live_no_local"))
                print(t("cmd.snapshot.live_no_local_hint", path=CONFIG_FILE))
        # ── Method 3 (non-live mode only): Latest event snapshot ──────────────
        # Do NOT fall through to a (possibly days-old) event image when the user
        # explicitly requested --live — mirrors the HA stale-event fix: a transient
        # live failure must not silently save/serve a stale event snapshot. In live
        # mode the messages above already explain that live is unavailable.
        if not live:
            data, ts = snap_from_events(session, cam_info)
            if data:
                _save_and_open(data, name, ts, "event")
                print(t("cmd.snapshot.event_hint", date=ts[:10]))
                print(t("cmd.snapshot.event_hint2"))
            else:
                print(t("cmd.snapshot.none_available"))


def _live_snap_loop(snap_url: str, cam_name: str, interval: float = 1.0) -> None:
    """
    Live view: serves snap.jpg frames as a local MJPEG stream, then opens ffplay on it.
    ffplay connects to http://localhost:PORT and receives a continuous MJPEG feed.
    Press Q in the ffplay window or Ctrl+C in the terminal to stop.
    """
    import threading
    import http.server
    import socket

    _ffplay_path: str = shutil.which("ffplay") or "/opt/homebrew/bin/ffplay"
    ffplay: Optional[str] = _ffplay_path if os.path.exists(_ffplay_path) else None

    if not ffplay:
        print("\n  ❌  ffplay not found. Install with: brew install ffmpeg\n")
        return

    # Find a free port
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    stop_event = threading.Event()
    frame_lock = threading.Lock()
    current_frame: list[bytes | None] = [None]  # [bytes | None]

    # Pooled session for the fetcher loop below — created once, reused for every
    # poll tick instead of the one-shot requests_get_bosch_cloud()-per-frame the
    # loop used to open (fresh TCP/TLS handshake every `interval` seconds at the
    # default 1s poll rate). Thread-confined: only the single `fetcher` daemon
    # thread spawned below ever touches this session, so no cross-thread
    # requests.Session sharing/locking is needed (unlike the shared module-level
    # _HTTP_SESSION, which is only ever used from a single thread at a time too,
    # but by design, not by construction — keeping this one local and dedicated
    # avoids relying on that invariant here).
    _snap_loop_session = make_bosch_cloud_session(pool_connections=1, pool_maxsize=1)

    # ── Fetcher thread: polls snap.jpg ────────────────────────────────────────
    # snap_url here is always the cloud proxy URL (proxy-*.live.cbs.boschsecurity.com)
    # → use Bosch cloud SSL context instead of verify=False (CWE-295 fix).
    def fetcher() -> None:
        count = 0
        try:
            while not stop_event.is_set():
                t0 = time.time()
                try:
                    r = _snap_loop_session.get(snap_url, timeout=10)
                    if r.status_code == 200 and r.headers.get("Content-Type", "").startswith(
                        "image"
                    ):
                        with frame_lock:
                            current_frame[0] = r.content
                        count += 1
                        print(
                            f"\r  🖼️   Frame {count}  {len(r.content):,} bytes", end="", flush=True
                        )
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
        finally:
            # Close from inside this thread, once the loop has genuinely exited —
            # _snap_loop_session is thread-confined to `fetcher` by design (see
            # comment above), so closing it must happen here too, not from the
            # main thread via stop_event.set() + close() with no join(). That
            # older pattern raced a live in-flight .get() against .close() on
            # the same requests.Session (not fully thread-safe) whenever the
            # main thread returned early (no-frames timeout) or hit the
            # finally-block on player exit, without ever waiting for this
            # thread to actually stop.
            try:
                _snap_loop_session.close()
            except Exception:
                pass

    # ── MJPEG HTTP server ─────────────────────────────────────────────────────
    class MJPEGHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass  # silence request logs

        def do_GET(self) -> None:
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
    print("\n  📺  Starting live view (press Q in player window or Ctrl+C to stop)...")
    for _ in range(30):
        if current_frame[0]:
            break
        time.sleep(0.2)
    else:
        print("  ❌  No frames received.")
        stop_event.set()
        return

    def _serve() -> None:
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
            with open(script, "w", encoding="utf-8") as f:
                f.write(
                    f"#!/bin/sh\n{ffplay} -loglevel warning -f mjpeg -window_title 'Live: {cam_name}' '{mjpeg_url}'\n"
                )
            os.chmod(script, 0o755)
            cmd = ["open", "-W", "-a", "Terminal", script]
            print(f"  ▶️   Launching ffplay via Terminal: {mjpeg_url}")
            proc = subprocess.Popen(cmd)
    else:
        cmd = [
            ffplay,
            "-loglevel",
            "warning",
            "-f",
            "mjpeg",
            "-window_title",
            f"Live: {cam_name}",
            mjpeg_url,
        ]
        print(f"  ▶️   Launching: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.kill()
    finally:
        stop_event.set()
        server.shutdown()
        print("\n  ⏹️   Live view stopped.")


def _start_tls_proxy_sync(cam_host: str, cam_port: int) -> int:
    """Start a local TCP→TLS proxy in a background thread. Returns the local port.

    Bosch cameras use RTSPS (RTSP over TLS) with a self-signed certificate.
    FFmpeg cannot skip TLS verification for RTSP Digest auth properly.
    This proxy accepts plain TCP from FFmpeg and forwards to the camera over TLS.
    FFmpeg handles Digest auth itself — the proxy only unwraps TLS.
    """
    import ssl
    import socket
    import threading
    import select as _select

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port: int = srv.getsockname()[1]
    srv.listen(2)

    def _proxy_thread() -> None:
        _reconnect_attempts = [0]
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                break
            conn_start = time.time()
            try:
                raw = socket.create_connection((cam_host, cam_port), timeout=10)
                # TCP keep-alive to prevent OS from dropping idle connections
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                try:
                    _tcp_keepidle = getattr(socket, "TCP_KEEPIDLE", None)
                    if _tcp_keepidle is not None:
                        raw.setsockopt(socket.IPPROTO_TCP, _tcp_keepidle, 30)
                    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except (AttributeError, OSError):
                    pass
                tls = ctx.wrap_socket(raw, server_hostname=cam_host)
            except Exception as _proxy_exc:
                client.close()
                _reconnect_attempts[0] += 1
                if _reconnect_attempts[0] > 3:
                    print(
                        f"  [TLS proxy] {cam_host}:{cam_port} — "
                        f"3 consecutive connection failures, giving up.",
                        file=sys.stderr,
                    )
                    break
                time.sleep(2 ** (_reconnect_attempts[0] - 1))  # 1s, 2s, 4s
                continue
            client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            def _pipe(src: Any, dst: Any, is_cam_to_client: bool = False) -> None:
                try:
                    while True:
                        # CAM→Client: no timeout (dark scenes have sparse RTP)
                        # Client→CAM: 120s timeout (FFmpeg sends periodic keepalive)
                        timeout = None if is_cam_to_client else 120
                        r, _, _ = _select.select([src], [], [], timeout)
                        if not r:
                            break
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        src.close()
                    except Exception:
                        pass
                    try:
                        dst.close()
                    except Exception:
                        pass

            t1 = threading.Thread(target=_pipe, args=(client, tls, False), daemon=True)
            t2 = threading.Thread(target=_pipe, args=(tls, client, True), daemon=True)
            t1.start()
            t2.start()

            # Reset failure counter after the connection stays up 30s+.
            def _reset_on_stable(start: float, counter: list[int]) -> None:
                t1.join(timeout=30)
                if time.time() - start >= 30:
                    counter[0] = 0

            threading.Thread(
                target=_reset_on_stable,
                args=(conn_start, _reconnect_attempts),
                daemon=True,
            ).start()

    t = threading.Thread(target=_proxy_thread, daemon=True)
    t.start()
    return port


def _open_rtsps_stream(
    rtsps_url: str, cam_name: str, fallback_snap_url: str = "", use_vlc: bool = False
) -> None:
    """
    Open live audio+video stream via rtsps:// (RTSP over TLS on port 443).
    use_vlc=True opens in VLC (macOS only, uses osascript to bring window to front).
    Default uses ffplay. Falls back to snap.jpg MJPEG loop if no player available.
    """
    ffplay = shutil.which("ffplay") or "/opt/homebrew/bin/ffplay"
    mpv = shutil.which("mpv")
    vlc = "/Applications/VLC.app/Contents/MacOS/VLC"

    if use_vlc and os.path.exists(vlc):
        # VLC can't skip TLS verification for rtsps://, so proxy via ffmpeg:
        # ffmpeg pulls rtsps:// and re-muxes to MPEG-TS piped into VLC's stdin
        ffmpeg = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
        if not ffmpeg or not os.path.exists(ffmpeg):
            print(
                "  ⚠️   ffmpeg not found — needed to proxy stream for VLC. Install: brew install ffmpeg"
            )
            return
        # ffmpeg can't serve HTTP — use pipe to VLC's stdin instead
        # Pipe: ffmpeg → stdout (mpegts) → VLC stdin
        ffmpeg_pipe = [
            ffmpeg,
            "-loglevel",
            "warning",
            "-rtsp_transport",
            "tcp",
            "-tls_verify",
            "0",
            "-i",
            rtsps_url,
            "-c",
            "copy",
            "-f",
            "mpegts",
            "pipe:1",
        ]
        print("  ▶️   Launching VLC via ffmpeg pipe (audio+video)...")
        proxy = subprocess.Popen(ffmpeg_pipe, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        proc = subprocess.Popen([vlc, "-"], stdin=proxy.stdout, stderr=subprocess.DEVNULL)
        if proxy.stdout is not None:
            proxy.stdout.close()
        time.sleep(1.5)
        subprocess.Popen(
            ["osascript", "-e", 'tell application "VLC" to activate'], stderr=subprocess.DEVNULL
        )
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.kill()
        finally:
            proxy.kill()
            print("\n  ⏹️   Live view stopped.")
        return
    elif ffplay and os.path.exists(ffplay):
        cmd = [
            ffplay,
            "-rtsp_transport",
            "tcp",
            "-tls_verify",
            "0",
            "-loglevel",
            "warning",
            "-window_title",
            f"Live: {cam_name}",
            rtsps_url,
        ]
        print(f"  ▶️   Launching ffplay (audio+video): {redact_rtsp_creds(rtsps_url)}")
        proc = subprocess.Popen(cmd)
    elif mpv:
        cmd = [
            mpv,
            "--no-terminal",
            "--title",
            f"Live: {cam_name}",
            "--rtsp-tls-verification=no",
            rtsps_url,
        ]
        print(f"  ▶️   Launching mpv (audio+video): {redact_rtsp_creds(rtsps_url)}")
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
        print("\n  ⏹️   Live view stopped.")


def cmd_test_local(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Test LOCAL vs REMOTE connection — dumps full API response, snap timing, RTSP URL.

    Calls PUT /connection with both types and prints:
      • Full raw JSON response (user, password, urls, imageUrlScheme, ...)
      • snap.jpg timing and result
      • Local RTSP URL to try in VLC/ffplay

    Use this to verify LOCAL streaming works and measure the 15-second startup issue.
    """
    token = get_token(cfg)
    session = make_session(token)
    cams = resolve_cam(cfg, getattr(args, "cam", None))

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n{'─' * 60}")
        print(f"  TEST LOCAL CONNECTION: {name}")
        print(f"  Camera ID: {cam_id}")
        print(f"{'─' * 60}")
        url = f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection"

        for conn_type in ["LOCAL", "REMOTE"]:
            print(f"\n  ─── type={conn_type} ───────────────────────────")
            t0 = time.time()
            r = session.put(
                url,
                json={"type": conn_type, "highQualityVideo": False},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            elapsed = time.time() - t0
            print(f"  PUT /connection → HTTP {r.status_code}  ({elapsed:.2f}s)")

            if r.status_code not in (200, 201):
                print(f"  Response body: {r.text[:400]}")
                continue

            data = r.json()
            print(f"  Full response:\n{json.dumps(data, indent=4)}")

            urls_list = data.get("urls", [])
            user = data.get("user", "")
            password = data.get("password", "")
            scheme = data.get("imageUrlScheme", "https://{url}/snap.jpg")

            if not urls_list:
                print("  ⚠️   No URLs in response.")
                continue

            snap_url = scheme.replace("{url}", urls_list[0])
            print(f"\n  snap.jpg: {snap_url}")
            t1 = time.time()
            # LOCAL: self-signed cert → verify=False; REMOTE: Bosch proxy → Bosch CA (CWE-295)
            _tl_snap_get = requests.get if conn_type == "LOCAL" else requests_get_bosch_cloud
            try:
                if user and password:
                    from requests.auth import HTTPDigestAuth

                    _tl_kw: dict[str, Any] = {"auth": HTTPDigestAuth(user, password), "timeout": 15}
                    if conn_type == "LOCAL":
                        _tl_kw["verify"] = False
                    sr = _tl_snap_get(snap_url, **_tl_kw)
                else:
                    _tl_kw2: dict[str, Any] = {"timeout": 15}
                    if conn_type == "LOCAL":
                        _tl_kw2["verify"] = False
                    sr = _tl_snap_get(snap_url, **_tl_kw2)
                snap_elapsed = time.time() - t1
                ct = sr.headers.get("Content-Type", "")
                print(f"  snap.jpg → HTTP {sr.status_code}  ({snap_elapsed:.2f}s)  {ct}")
                if sr.status_code == 200 and "image" in ct:
                    fn = f"test_{conn_type.lower()}_{name}.jpg"
                    path = os.path.join(BASE_DIR, fn)
                    with open(path, "wb") as f:
                        f.write(sr.content)
                    print(f"  ✅  Saved: {path}  ({len(sr.content):,} bytes)")
                    open_file(path)
            except Exception as e:
                print(f"  ⚠️   snap.jpg error: {e}")

            # Build RTSP URL — use videoUrlScheme from API response
            u = urls_list[0]
            video_scheme = data.get("videoUrlScheme", "")
            if "/" in u:
                # REMOTE: "proxy-NN.live.cbs.boschsecurity.com:42090/{hash}"
                host_port, hash_path = u.split("/", 1)
                proxy_host = host_port.split(":")[0]
                rtsp_url = (
                    f"rtsps://{proxy_host}:443/{hash_path}"
                    f"/rtsp_tunnel?inst=2&enableaudio=1&fmtp=1&maxSessionDuration=3600"
                )
            else:
                # LOCAL: "192.168.x.x:443" — plain rtsp://, credentials URL-encoded
                from urllib.parse import quote as _q

                auth_prefix = (
                    f"{_q(user, safe='')}:{_q(password, safe='')}@" if user and password else ""
                )
                rtsp_url = (
                    f"rtsp://{auth_prefix}{u}"
                    f"/rtsp_tunnel?inst=2&enableaudio=1&fmtp=1&maxSessionDuration=3600"
                )
            # NOTE: `test-local` is a diagnostic command whose deliverable IS the
            # copyable RTSP URL (for VLC/ffplay) — kept UNREDACTED on purpose.
            print(f"\n  RTSP URL:  {rtsp_url}")
            if video_scheme:
                full_url = video_scheme.replace("{url}", u)
                if user and password and "://" in full_url:
                    scheme_part, rest = full_url.split("://", 1)
                    full_url = f"{scheme_part}://{user}:{password}@{rest}"
                print(f"  API scheme: {full_url}")

            if getattr(args, "play", False):
                print("  ▶️   Opening stream...")
                _open_rtsps_stream(rtsp_url, name, snap_url)

        print()


# ── Dual-stream URL helper ────────────────────────────────────────────────────
# Bosch RTSP URLs encode stream quality as an `inst=N` query parameter:
#   inst=1 → main stream   (~30 Mbps LOCAL full-HD, balanced on REMOTE)
#   inst=2 → sub-stream    (~7.5 Mbps — lower bandwidth, same Bosch session)
# Both live on the same TLS proxy session; the camera only sends a stream when
# an external client actually connects (pull-based RTSP), so sub costs nothing
# extra unless consumed. Gen1 cameras (INDOOR/OUTDOOR) may silently ignore
# inst=2 and fall back to their default stream — same URL, same data.
def _build_stream_urls(
    cam: dict[str, Any],
    conn_result: dict[str, Any],
    inst: int = 2,
    *,
    use_tls_proxy: bool = False,
    proxy_port: int = 0,
) -> tuple[str, str]:
    """Return ``(main_url, sub_url)`` RTSPS URLs for a live connection result.

    Both URLs are derived from the same ``PUT /connection`` response.
    ``main_url`` uses ``inst`` as-is (or inst=1 for REMOTE main quality).
    ``sub_url`` substitutes ``inst=2`` regardless of the caller's quality setting.

    Args:
        cam:          Camera dict from config (used for ``id`` only; reserved for
                      future per-model logic such as Gen1 sub-stream detection).
        conn_result:  Parsed JSON body of a successful ``PUT /connection`` 200 response.
        inst:         Instance number for the *main* URL (default 2; 1 = max-quality).
        use_tls_proxy: When True the URL prefix is ``rtsp://127.0.0.1:{proxy_port}``
                       (LOCAL mode with TLS proxy) instead of ``rtsps://``.
        proxy_port:   Local TCP port of the already-started TLS proxy (LOCAL mode only).

    Returns:
        Tuple ``(main_url, sub_url)``.  If ``urls`` is empty both strings are ``""``.
    """
    urls: list[str] = conn_result.get("urls", [])
    if not urls:
        return ("", "")

    u = urls[0]
    user: str = conn_result.get("user") or ""
    password: str = conn_result.get("password") or ""

    def _make_url(chosen_inst: int) -> str:
        if use_tls_proxy:
            from urllib.parse import quote as _q

            auth_prefix = (
                f"{_q(user, safe='')}:{_q(password, safe='')}@" if user and password else ""
            )
            return (
                f"rtsp://{auth_prefix}127.0.0.1:{proxy_port}"
                f"/rtsp_tunnel?inst={chosen_inst}&enableaudio=1&fmtp=1&maxSessionDuration=3600"
            )
        else:
            # REMOTE: "proxy-NN.live.cbs.boschsecurity.com:42090/{hash}"
            host_port, hash_path = u.split("/", 1)
            proxy_host = host_port.split(":")[0]
            return (
                f"rtsps://{proxy_host}:443/{hash_path}"
                f"/rtsp_tunnel?inst={chosen_inst}&enableaudio=1&fmtp=1&maxSessionDuration=3600"
            )

    main_url: str = _make_url(inst)
    sub_url: str = _make_url(2)
    return (main_url, sub_url)


# ── WebRTC / go2rtc helper ────────────────────────────────────────────────────
#
# go2rtc config format (YAML), minimal for single-camera use:
#
#   api:
#     listen: ":1984"   # HTTP API + WebRTC signaling
#   webrtc:
#     listen: ":8555"   # ICE/RTP (TCP+UDP)
#   streams:
#     bosch_cam: rtsps://user:pass@host:443/rtsp_tunnel?inst=2&...
#
# Browser URL: http://localhost:<port>/stream.html?src=bosch_cam
# WHEP URL:    http://localhost:<port>/api/webrtc?src=bosch_cam
#
# Bosch RTSPS caveat: go2rtc connects to the RTSPS URL via its built-in RTSP
# client with InsecureSkipVerify (rtsps:// scheme accepted without cert check).
# No need for the Python TLS proxy for this path.
#
# TODO: ICE/TURN server config for remote-network (NAT traversal) not supported
#       in this implementation. go2rtc defaults to Google STUN servers. Add
#       --webrtc-ice-server flag if needed in a future iteration.


def _build_go2rtc_config(rtsps_url: str, stream_name: str = "bosch_cam", port: int = 1984) -> str:
    """Build a minimal go2rtc YAML config string for a single RTSPS source.

    Args:
        rtsps_url:   Full rtsps:// URL (from _build_stream_urls, REMOTE mode).
        stream_name: Key used in go2rtc streams map; also appears in browser URL.
        port:        go2rtc HTTP/WebRTC-signaling port (default 1984).

    Returns:
        YAML string ready to write to a temp file.
    """
    return (
        f"api:\n"
        f'  listen: ":{port}"\n'
        f"webrtc:\n"
        f'  listen: ":8555"\n'
        f"streams:\n"
        f'  {stream_name}: "{rtsps_url}"\n'
    )


class Go2rtcError(RuntimeError):
    """Raised when go2rtc cannot be started."""


def _start_go2rtc_with_camera(
    rtsps_url: str,
    *,
    port: int = 1984,
    go2rtc_bin: str = "go2rtc",
    stream_name: str = "bosch_cam",
    start_timeout: float = 10.0,
) -> tuple[subprocess.Popen[bytes], str]:
    """Start go2rtc as a subprocess and wait until its HTTP port is reachable.

    Args:
        rtsps_url:     Full rtsps:// URL for the camera stream.
        port:          HTTP port for go2rtc API + WebRTC signaling (default 1984).
        go2rtc_bin:    Name or path of the go2rtc binary (searched in PATH if bare name).
        stream_name:   Key for the stream entry in go2rtc config.
        start_timeout: Seconds to wait for go2rtc's HTTP port to become available.

    Returns:
        Tuple ``(Popen handle, browser URL)``.

    Raises:
        Go2rtcError: binary not found, port already in use, or startup timeout.
    """
    import socket
    import tempfile

    # 1. Resolve binary
    resolved_bin: Optional[str] = shutil.which(go2rtc_bin)
    if resolved_bin is None:
        # If the caller passed an absolute path, shutil.which still returns None
        # for non-PATH paths, so check existence directly.
        if os.path.isfile(go2rtc_bin) and os.access(go2rtc_bin, os.X_OK):
            resolved_bin = go2rtc_bin
        else:
            raise Go2rtcError(t("err.webrtc.binary_not_found", path=go2rtc_bin))

    # 2. Check port availability (fail fast before spawning)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _s:
        _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            _s.bind(("127.0.0.1", port))
        except OSError as exc:
            raise Go2rtcError(t("err.webrtc.port_in_use", port=port)) from exc

    # 3. Write temp config
    config_yaml = _build_go2rtc_config(rtsps_url, stream_name=stream_name, port=port)
    tmp_cfg = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", prefix="bosch_go2rtc_", delete=False
    )
    tmp_cfg.write(config_yaml)
    tmp_cfg.flush()
    tmp_cfg.close()
    cfg_path = tmp_cfg.name

    # 4. Spawn go2rtc
    proc = subprocess.Popen(
        [resolved_bin, "-config", cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # 5. Wait for HTTP port to accept connections (poll with 0.2s sleep)
    deadline = time.time() + start_timeout
    port_ready = False
    while time.time() < deadline:
        # Check if process exited prematurely
        if proc.poll() is not None:
            os.unlink(cfg_path)
            raise Go2rtcError(t("cmd.live.webrtc.timeout", timeout=int(start_timeout)))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                port_ready = True
                break
        except OSError:
            time.sleep(0.2)

    if not port_ready:
        proc.terminate()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass
        raise Go2rtcError(t("cmd.live.webrtc.timeout", timeout=int(start_timeout)))

    # 6. Register cleanup: terminate + unlink config on SIGTERM
    _orig_sigterm = signal.getsignal(signal.SIGTERM)

    def _cleanup_go2rtc(signum: int, frame: Any) -> None:
        proc.terminate()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass
        if callable(_orig_sigterm):
            _orig_sigterm(signum, frame)

    signal.signal(signal.SIGTERM, _cleanup_go2rtc)

    # Store cfg_path on the proc object so callers can unlink on KeyboardInterrupt
    proc._go2rtc_cfg_path = cfg_path  # type: ignore[attr-defined]

    browser_url = f"http://localhost:{port}/stream.html?src={stream_name}"
    return proc, browser_url


def _open_webrtc_stream(
    rtsps_url: str,
    cam_name: str,
    *,
    port: int = 1984,
    go2rtc_bin: str = "go2rtc",
) -> None:
    """Start go2rtc and open the WebRTC viewer page in the default browser.

    Blocks until the user presses Ctrl+C, then terminates go2rtc and cleans up.
    """
    import webbrowser

    print(t("cmd.live.webrtc.starting", port=port))
    try:
        proc, browser_url = _start_go2rtc_with_camera(
            rtsps_url,
            port=port,
            go2rtc_bin=go2rtc_bin,
        )
    except Go2rtcError as exc:
        print(str(exc))
        return

    print(t("cmd.live.webrtc.ready", url=browser_url))
    webbrowser.open(browser_url)

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        cfg_path: Optional[str] = getattr(proc, "_go2rtc_cfg_path", None)
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
        print("\n  ⏹️   WebRTC stopped.")


def cmd_live(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Open live stream — tries PUT /connection → open VLC on success.

    --hq:    request highQualityVideo=true in PUT /connection (higher bitrate stream).
    --inst N: select stream instance (default 2; use 1 for alternative stream).
    --sub:   use the sub-stream (inst=2, ~7.5 Mbps) instead of the main stream.
    --webrtc: start go2rtc + open WebRTC viewer in browser instead of ffplay/VLC.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))

    use_sub: bool = getattr(args, "sub", False)

    # Quality preset overrides --hq/--inst.  --sub maps to the inst=2 sub-stream.
    quality = getattr(args, "quality", None)
    if use_sub:
        hq = False
        inst = 2  # sub-stream is always inst=2
    elif quality == "high":
        hq = True
        inst = getattr(args, "inst", 2) if getattr(args, "inst", 2) != 2 else 1
    elif quality == "low":
        hq = False
        inst = getattr(args, "inst", 2) if getattr(args, "inst", 2) != 2 else 4
    else:
        hq = getattr(args, "hq", False)
        inst = getattr(args, "inst", 2)

    for name, cam_info in cams.items():
        print(f"\n── Live Stream: {name} ──────────────────────────────────────")
        if use_sub:
            print(f"  ℹ️   {t('cmd.live.using_sub_stream')}")
        status = api_ping(session, cam_info["id"])
        if status == "ONLINE":
            icon = "🟢"
        elif status.startswith("UPDATING"):
            icon = "🔄"
        else:
            icon = "🔴"
        print(f"  {icon}  Status: {status}")

        if status != "ONLINE":
            print("  ⚠️   Camera is OFFLINE — live stream not available.")
            continue

        print("  🔄  Opening live connection...")
        conn_url = f"{CLOUD_API}/v11/video_inputs/{cam_info['id']}/connection"
        result: Optional[dict[str, Any]] = None
        result_type = ""

        # --local flag forces LOCAL (direct LAN); default is REMOTE (cloud proxy).
        # LOCAL response gives user/password + LAN IP — credentials embedded in RTSP URL.
        force_local = getattr(args, "local", False)
        type_candidates = ["LOCAL"] if force_local else ["REMOTE", "LOCAL"]
        token_refreshed = False  # refresh the bearer at most once per camera
        for type_val in type_candidates:
            r = session.put(
                conn_url,
                json={"type": type_val, "highQualityVideo": hq},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if r.status_code == 401 and not token_refreshed:
                # One-shot refresh: update the cached session's Authorization
                # header and retry this single connection type immediately.
                print("  🔄  Token expired (401) — refreshing once...")
                try:
                    new_token = get_token(cfg)
                except Exception as e:
                    print(f"  ❌  Token refresh failed: {e}")
                    print("      Run `bosch-camera login` (or `python3 get_token.py`).")
                    break
                token = new_token
                session = make_session(token)
                token_refreshed = True
                r = session.put(
                    conn_url,
                    json={"type": type_val, "highQualityVideo": hq},
                    headers={"Content-Type": "application/json"},
                    timeout=15,
                )
            if r.status_code in (200, 201):
                result = r.json()
                result_type = type_val
                print(f"  ✅  ConnectionType '{type_val}' worked!")
                break
            elif r.status_code == 401:
                print("  ❌  Token could not be refreshed — run `bosch-camera login`.")
                break

        if result:
            urls: list[str] = result.get("urls", [])
            img_scheme: str = result.get("imageUrlScheme", "https://{url}/snap.jpg")
            user: str = result.get("user") or ""
            password: str = result.get("password") or ""

            proxy_url = img_scheme.replace("{url}", urls[0]) if urls else ""
            print(f"  🌐  Snap URL:  {proxy_url or '(none)'}")
            if user:
                print(f"  🔑  Creds: {user} / {password}")

            cfg["cameras"][name]["last_live"] = {
                "type": result_type,
                "proxy_url": proxy_url,
                "user": user,
                "password": password,
                "timestamp": datetime.datetime.now().isoformat()[:19],
            }
            save_config(cfg)

            use_webrtc: bool = getattr(args, "webrtc", False)
            webrtc_port: int = getattr(args, "webrtc_port", 1984)
            go2rtc_binary: str = getattr(args, "go2rtc_binary", "go2rtc")

            if urls:
                u = urls[0]
                if "/" in u:
                    # REMOTE: "proxy-NN.live.cbs.boschsecurity.com:42090/{hash}"
                    # Port 42090 drops RTSP; use port 443 instead.
                    main_url, sub_url = _build_stream_urls(cam_info, result, inst=inst)
                    rtsps_url = sub_url if use_sub else main_url
                else:
                    # LOCAL: "192.168.x.x:443" — camera uses TLS with self-signed cert
                    # + Digest auth. FFmpeg can't do RTSPS+Digest with self-signed certs,
                    # so we start a local TCP→TLS proxy and point FFmpeg at plain rtsp://.
                    cam_host, cam_port_str = u.split(":")
                    tls_port = _start_tls_proxy_sync(cam_host, int(cam_port_str))
                    main_url, sub_url = _build_stream_urls(
                        cam_info,
                        result,
                        inst=inst,
                        use_tls_proxy=True,
                        proxy_port=tls_port,
                    )
                    rtsps_url = sub_url if use_sub else main_url
                    print(f"  🏠  Local stream ({u}) via TLS proxy :{tls_port}")
                print(f"  📡  RTSPS URL: {redact_rtsp_creds(rtsps_url)}")
                if use_webrtc:
                    _open_webrtc_stream(
                        rtsps_url,
                        name,
                        port=webrtc_port,
                        go2rtc_bin=go2rtc_binary,
                    )
                else:
                    _open_rtsps_stream(
                        rtsps_url, name, proxy_url, use_vlc=getattr(args, "vlc", False)
                    )
            else:
                print("  ⚠️   No URLs in response.")
        else:
            print("\n  ❌  Could not open live connection.")

            # Fallback: latest snapshot
            print("\n  📸  Showing latest event snapshot instead...")
            events = api_get_events(session, cam_info["id"], limit=5)
            for ev in events:
                img_url = ev.get("imageUrl")
                if img_url and _is_safe_bosch_url(img_url):
                    r = session.get(img_url, timeout=20)
                    if r.status_code == 200:
                        ts = ev.get("timestamp", "")[:19].replace(":", "-").replace("T", "_")
                        fn = f"snapshot_{name}_{ts}.jpg"
                        path = os.path.join(BASE_DIR, fn)
                        with open(path, "wb") as f:
                            f.write(r.content)
                        print(f"  💾  {path}  ({len(r.content):,} bytes)")
                        open_file(path)
                        break


def cmd_config(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show current config (mask all credentials for security)."""
    display = json.loads(json.dumps(cfg))  # deep copy
    # Mask every secret-shaped field, not just bearer/refresh — access_token,
    # firebase keys, FCM tokens, local camera passwords are all credentials.
    SECRET_KEYS = (
        "bearer_token",
        "refresh_token",
        "access_token",
        "local_password",
        "password",
        "private",
        "secret",
        "token",
        "security_token",
    )

    def _mask(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: (
                    f"{str(v)[:20]}...({len(str(v))} chars)"
                    if isinstance(v, str) and v and any(s in k.lower() for s in SECRET_KEYS)
                    else _mask(v)
                )
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [_mask(x) for x in obj]
        return obj

    display = _mask(display)
    print(f"\n── Config: {CONFIG_FILE} ──────────────────────────────────")
    print(json.dumps(display, indent=2))
    print(f"\n  Token age: {check_token_age(cfg)}")


def cmd_info(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show full camera information from the API.

    Usage:
      python3 bosch_camera.py info           → standard info + stream URLs
      python3 bosch_camera.py info --full    → also fetch 8 extra endpoints
                                               (firmware, motion, audio, light, WiFi, etc.)
    """
    token = get_token(cfg)
    session = make_session(token)
    full = getattr(args, "full", False)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cameras = r.json()

    print("\n── Camera Info ──────────────────────────────────────────────")
    print(f"   Token age: {check_token_age(cfg)}")

    # Protocol version check
    try:
        pr = session.get(
            f"{CLOUD_API}/protocol_support",
            params={"protocol": "11", "client": f"pythonV{VERSION}"},
            timeout=10,
        )
        if pr.status_code == 200:
            pd = pr.json()
            proto_state = pd.get("state", pd.get("status", "UNKNOWN"))
            if proto_state != "SUPPORTED":
                print(f"   ⚠️  Protocol v11 state: {proto_state} — API changes may affect this tool")
            else:
                print(f"   Protocol: v11 ({proto_state})")
        else:
            print(f"   Protocol check: HTTP {pr.status_code}")
    except Exception:
        pass

    print()

    for cam in cameras:
        name = cam.get("title", cam.get("id"))
        cam_id = cam.get("id", "")
        status = cam.get("connectionStatus", "?")
        if status == "ONLINE":
            icon = "🟢"
        elif status.startswith("UPDATING"):
            icon = "🔄"
        else:
            icon = "🔴"
        model = cam.get("hardwareVersion", "?")
        fw = cam.get("firmwareVersion", "?")
        mac = cam.get("macAddress", "?")
        priv = cam.get("privacyMode", "?")
        rec = "✅ ON" if cam.get("recordingOn") else "❌ OFF"
        unread = cam.get("numberOfUnreadEvents", 0)
        tz = cam.get("timeZone", "?")
        alarm = cam.get("alarmType") or "NONE"
        notif = cam.get("notificationsEnabledStatus", "?")

        print(f"  {icon}  {name}")
        print(f"      ID:            {cam_id}")
        model_name = HW_DISPLAY_NAMES.get(model, model)
        print(f"      Model:         {model_name} ({model})   FW: {fw}")
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
        print(
            f"      Features:      light={fs.get('light')}, sound={fs.get('sound')}, "
            f"viewAngle={fs.get('viewingAngle')}°, panLimit={fs.get('panLimit')}°"
        )

        fst = cam.get("featureStatus", {})
        print(
            f"      Light sched.:  {fst.get('scheduleStatus')}  "
            f"on={fst.get('generalLightOnTime')} off={fst.get('generalLightOffTime')}"
        )
        print(
            f"      Light on motion: {fst.get('lightOnMotion')}  "
            f"follow-up={fst.get('lightOnMotionFollowUpTimeSeconds')}s"
        )
        print(f"      Sound recording: {cam.get('soundIsOnForRecording')}")

        # ── WiFi info (always shown if available) ─────────────────────────
        try:
            wr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/wifiinfo", timeout=10)
            if wr.status_code == 200:
                wd = wr.json()
                ssid = wd.get("ssid", "?")
                signal = wd.get("signalStrength", wd.get("signal", "?"))
                ip = wd.get("ipAddress", wd.get("ip", "?"))
                mac_w = wd.get("macAddress", wd.get("mac", "?"))
                signal_str = f"{signal}%" if isinstance(signal, int) else str(signal)
                print(f"      WiFi:          {ssid}  signal={signal_str}  IP={ip}  MAC={mac_w}")
        except Exception:
            pass

        # ── Streaming URLs (live connection) ──────────────────────────────
        # Uses inst=1 for main (max quality) and inst=2 for sub-stream.
        # Both share the same Bosch REMOTE session — sub costs nothing extra.
        print("      Fetching stream URLs...")
        try:
            sr = session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
                json={"type": "REMOTE", "highQualityVideo": False},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if sr.status_code == 200:
                sd: dict[str, Any] = sr.json()
                conn_urls: list[str] = sd.get("urls", [])
                if conn_urls:
                    u = conn_urls[0]
                    snap_url = sd.get("imageUrlScheme", "https://{url}/snap.jpg").replace(
                        "{url}", u
                    )
                    main_url, sub_url = _build_stream_urls(cam, sd, inst=1)
                    print(f"      Snap URL:      {snap_url}")
                    # `info` deliberately surfaces the copyable stream URLs — it is
                    # the only CLI path that outputs them, so keep creds UNREDACTED.
                    print(t("cmd.info.stream_url_main", url=main_url))
                    print(t("cmd.info.stream_url_sub", url=sub_url))
                    print("      Stream:        H.264 1920×1080 30fps + AAC 16kHz (session ~60s)")
            else:
                print(f"      Stream URLs:   unavailable (HTTP {sr.status_code})")
        except Exception as e:
            print(f"      Stream URLs:   error — {e}")

        # ── Extra endpoints (--full only) ─────────────────────────────────
        if full:
            print("\n      ── Full details (--full) ───────────────────────────────")

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
                    ver = fwd.get("version", fwd.get("firmwareVersion", "?"))
                    up2date = fwd.get("upToDate", fwd.get("isUpToDate", "?"))
                    print(f"      Firmware:      version={ver}  upToDate={up2date}")
            except Exception:
                pass

            # /lighting_override
            try:
                lor = session.get(
                    f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_override", timeout=10
                )
                if lor.status_code == 200:
                    lod = lor.json()
                    front = lod.get("frontLightOn", "?")
                    wall = lod.get("wallwasherOn", "?")
                    print(f"      Light override: frontLightOn={front}  wallwasherOn={wall}")
            except Exception:
                pass

            # /motion
            try:
                mr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion", timeout=10)
                if mr.status_code == 200:
                    md = mr.json()
                    enabled = md.get("enabled", md.get("motionEnabled", "?"))
                    sens = md.get("sensitivity", "?")
                    print(f"      Motion:        enabled={enabled}  sensitivity={sens}")
            except Exception:
                pass

            # /recording_options
            try:
                ror = session.get(
                    f"{CLOUD_API}/v11/video_inputs/{cam_id}/recording_options", timeout=10
                )
                if ror.status_code == 200:
                    rod = ror.json()
                    rec_sound = rod.get("recordSound", rod.get("soundIsOnForRecording", "?"))
                    print(f"      Recording opts: recordSound={rec_sound}")
            except Exception:
                pass

            # /ambient_light_sensor_level
            try:
                alr = session.get(
                    f"{CLOUD_API}/v11/video_inputs/{cam_id}/ambient_light_sensor_level", timeout=10
                )
                if alr.status_code == 200:
                    ald = alr.json()
                    level = ald.get("ambientLightSensorLevel", ald.get("level", json.dumps(ald)))
                    pct = (
                        f" ({round(float(level) * 100)}%)"
                        if isinstance(level, (int, float))
                        else ""
                    )
                    print(f"      Ambient light: {level}{pct}")
            except Exception:
                pass

            # /intrusionDetectionConfig (Gen2 only)
            try:
                idr = session.get(
                    f"{CLOUD_API}/v11/video_inputs/{cam_id}/intrusionDetectionConfig", timeout=10
                )
                if idr.status_code == 200:
                    idd = idr.json()
                    print(
                        f"      Intrusion:     enabled={idd.get('enabled')}, mode={idd.get('detectionMode')}, sensitivity={idd.get('sensitivity')}, distance={idd.get('distance')}m"
                    )
            except Exception:
                pass

            # /credentials (local camera userToken)
            try:
                cr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/credentials", timeout=10)
                if cr.status_code == 200:
                    crd = cr.json()
                    print(f"      Credentials:   userToken={crd.get('userToken', '?')}")
            except Exception:
                pass

            # /rules (camera automation rules)
            try:
                rr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/rules", timeout=10)
                if rr.status_code == 200:
                    rules = rr.json()
                    print(f"      Rules:         {len(rules)} rule(s) — {json.dumps(rules)[:200]}")
            except Exception:
                pass

            # /timestamp (time/date overlay)
            try:
                tr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/timestamp", timeout=10)
                if tr.status_code == 200:
                    td = tr.json()
                    print(f"      Timestamp:     overlay={td.get('result', '?')}")
            except Exception:
                pass

            # /privacy_sound_override
            try:
                psr = session.get(
                    f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy_sound_override", timeout=10
                )
                if psr.status_code == 200:
                    psd = psr.json()
                    print(f"      Privacy sound: {psd.get('result', '?')}")
                elif psr.status_code == 442:
                    print("      Privacy sound: not supported (HTTP 442)")
            except Exception:
                pass

            # ── RCP (via proxy) ───────────────────────────────────────────
            print("\n      ── RCP (via proxy) ──────────────────────────────────────")
            try:
                # We already opened a REMOTE connection above for stream URLs.
                # Re-use it by opening a new RCP session on the same proxy hash.
                _rcp_proxy_base, _ = rcp_open_connection(cam_id, token)
                _rcp_sessionid = rcp_session_cached(_rcp_proxy_base)
                _rcp_url = f"{_rcp_proxy_base}/rcp.xml"

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

                # NOTE: privacy cross-check via 0x0d00 was added in v10.2.0
                # and removed in v10.2.1. A/B testing proved 0x0d00 byte[1]
                # stays 1 even with privacy-mode OFF — it's not the mode flag,
                # so the cross-check produced a permanent false-positive.
                # Cloud /v11/video_inputs.privacyMode is the correct source.

            except RuntimeError as _rcp_err:
                print(f"      RCP:           unavailable ({_rcp_err})")
            except Exception as _rcp_ex:
                print(f"      RCP:           error — {_rcp_ex}")

        print()

    # ── Feature flags (account-level, shown with --full) ──────────────
    if full:
        print("── Feature Flags ─────────────────────────────────────────────")
        try:
            ffr = session.get(f"{CLOUD_API}/v11/feature_flags", timeout=10)
            if ffr.status_code == 200:
                flags = ffr.json()
                if isinstance(flags, dict):
                    parts = [f"{k}={v}" for k, v in flags.items()]
                    print(f"   {', '.join(parts)}")
                elif isinstance(flags, list):
                    parts = []
                    for flag in flags:
                        if isinstance(flag, dict):
                            fname = flag.get("name", flag.get("key", "?"))
                            fval = flag.get("value", flag.get("enabled", "?"))
                            parts.append(f"{fname}={fval}")
                        else:
                            parts.append(str(flag))
                    print(f"   {', '.join(parts)}")
                else:
                    print(f"   {json.dumps(flags)}")
            else:
                print(f"   ⚠️  Feature flags: HTTP {ffr.status_code}")
        except Exception:
            pass
        print()


# ══════════════════════ LAN-FALLBACK HELPERS ═════════════════════════════════
#
# Direct RCP writes over HTTP to the camera's LAN IP (port 80, no auth).
# Gen2 cameras accept unauthenticated RCP on http://<cam_ip>/rcp.xml.
# Gen1 cameras return 401 — these functions return False gracefully.
# Uses synchronous `requests` (same as the rest of the CLI).


def _lan_rcp_write_privacy(
    cam_ip: str, enabled: bool, *, user: str = "", password: str = ""
) -> bool:
    """Write privacy-mode via direct LOCAL RCP (Gen2, HTTPS, Digest-authed).

    Uses command 0x0d00.  payload byte[1] = 1 (ON) or 0 (OFF).
    Delegates to bosch_rcp_client (bosch-shc-camera-client library) -- HTTPS
    on port 443, matching what modern Gen2 firmware actually answers (the
    previous plain-HTTP-port-80 implementation is confirmed dead on real
    hardware, see bosch_rcp_client.lan_write_privacy's docstring). Pass the
    cycling LOCAL Digest credentials from _get_local_connection_creds() --
    without them the write goes out unauthenticated and modern firmware
    rejects it with 401 (matches the HA integration's shc.py, which sources
    the same cycling creds from its coordinator's local_creds_cache).
    """
    return bosch_rcp_client.lan_write_privacy(cam_ip, enabled, user=user, password=password)


def _lan_rcp_write_front_light(
    cam_ip: str, brightness: int, *, user: str = "", password: str = ""
) -> bool:
    """Write front-light brightness (0–100) via direct LOCAL RCP (Gen2, HTTPS, Digest-authed).

    Maps to RCP 0x0c22 (T_WORD, num=1).  0 = off; 1-100 = dimmer level.
    Wallwasher is cloud-only (write payload too complex for unauthenticated RCP).
    Delegates to bosch_rcp_client -- see _lan_rcp_write_privacy docstring.
    """
    val = max(0, min(100, int(brightness)))
    return bosch_rcp_client.lan_write_front_light(cam_ip, val, user=user, password=password)


def _lan_tcp_ping(host: str, port: int = 443, timeout: float = 3.0) -> tuple[bool, float]:
    """TCP-connect probe to (host, port).  Returns (reachable, rtt_ms)."""
    import socket as _socket

    t0 = time.monotonic()
    try:
        with _socket.create_connection((host, port), timeout=timeout):
            rtt = (time.monotonic() - t0) * 1000
            return True, rtt
    except OSError:
        return False, 0.0


def _resolve_lan_ip(cfg: dict[str, Any], cam_id: str, cam_info: dict[str, Any]) -> str | None:
    """Return the LAN IP for a camera.

    Priority:
      1. cfg["lan_ips"][cam_id]  — explicit lan_ips map
      2. cam_info["local_ip"]    — per-camera legacy field
    Returns None if no IP is configured.
    """
    lan_ips: dict[str, str] = cfg.get("lan_ips", {})
    if cam_id in lan_ips and lan_ips[cam_id].strip():
        return lan_ips[cam_id].strip()
    legacy = cam_info.get("local_ip", "").strip()
    return legacy or None


def _hint_local_on_5xx(status_code: int, command_hint: str = "") -> None:
    """Print a one-line hint when a cloud call returns 5xx.

    `command_hint` should be the suggested --local invocation, e.g.
    "bosch privacy Garten on --local".
    """
    if 500 <= status_code <= 599:
        msg = f"  ⚠️   Cloud returned HTTP {status_code}."
        if command_hint:
            msg += f"  Try the LAN fallback:  {command_hint}"
        else:
            msg += "  If the camera is reachable on LAN, retry with --local."
        print(msg)


# ══════════════════════ LAN-FALLBACK COMMANDS ════════════════════════════════


def cmd_ping(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """TCP-connect probe to every configured camera's LAN IP on port 443.

    Usage:
      python3 bosch_camera.py ping                  # all cameras
      python3 bosch_camera.py ping <cam-name>       # one camera
      python3 bosch_camera.py ping --json           # machine-readable output
    """
    import json as _json_mod

    cam_arg = getattr(args, "cam", None)
    as_json = getattr(args, "json", False)
    cams = resolve_cam(cfg, cam_arg)
    results: list[dict[str, Any]] = []

    for name, cam_info in cams.items():
        cam_id = cam_info.get("id", "")
        ip = _resolve_lan_ip(cfg, cam_id, cam_info)
        if not ip:
            entry = {
                "cam": name,
                "cam_id": cam_id,
                "ip": None,
                "reachable": False,
                "rtt_ms": None,
                "error": "no LAN IP configured — set local_ip in config or run 'bosch lan-ips set'",
            }
            results.append(entry)
            if not as_json:
                print(f"  {name}: no LAN IP configured")
            continue

        ok, rtt = _lan_tcp_ping(ip, port=443)
        entry = {
            "cam": name,
            "cam_id": cam_id,
            "ip": ip,
            "reachable": ok,
            "rtt_ms": round(rtt, 1) if ok else None,
        }
        results.append(entry)
        if not as_json:
            icon = "✅" if ok else "❌"
            rtt_str = f"  {rtt:.1f} ms" if ok else ""
            print(f"  {icon}  {name}  ({ip}){rtt_str}")

    if as_json:
        print(_json_mod.dumps(results, indent=2))


def cmd_lan_ips(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """List or edit the LAN IP map used by --local flag commands.

    Usage:
      python3 bosch_camera.py lan-ips                              # list
      python3 bosch_camera.py lan-ips set <cam-name> <ip>         # set IP
      python3 bosch_camera.py lan-ips unset <cam-name>            # remove IP
      python3 bosch_camera.py lan-ips sync                        # copy local_ip fields → lan_ips
    """
    sub = getattr(args, "lan_sub", None) or ""
    cam_arg = getattr(args, "lan_cam", None)
    ip_arg = getattr(args, "lan_ip", None)

    lan_ips: dict[str, str] = cfg.setdefault("lan_ips", {})
    cameras: dict[str, dict[str, Any]] = cfg.get("cameras", {})

    if sub == "set":
        if not cam_arg or not ip_arg:
            print("  Usage: bosch lan-ips set <cam-name> <ip>")
            return
        cams = resolve_cam(cfg, cam_arg)
        for name, cam_info in cams.items():
            cam_id = cam_info.get("id", "")
            lan_ips[cam_id] = ip_arg
            print(f"  Set {name} ({cam_id[:8]}…) → {ip_arg}")
        save_config(cfg)
        return

    if sub == "unset":
        if not cam_arg:
            print("  Usage: bosch lan-ips unset <cam-name>")
            return
        cams = resolve_cam(cfg, cam_arg)
        for name, cam_info in cams.items():
            cam_id = cam_info.get("id", "")
            if cam_id in lan_ips:
                del lan_ips[cam_id]
                print(f"  Removed {name}")
            else:
                print(f"  {name}: no entry to remove")
        save_config(cfg)
        return

    if sub == "sync":
        count = 0
        for name, cam_info in cameras.items():
            ip = cam_info.get("local_ip", "").strip()
            cam_id = cam_info.get("id", "")
            if ip and cam_id:
                lan_ips[cam_id] = ip
                count += 1
        save_config(cfg)
        print(f"  Synced {count} camera(s) from local_ip fields.")
        return

    # List
    print("\n  LAN IP map (used by --local flag)\n")
    if not cameras:
        print("  (no cameras configured)")
        return
    for name, cam_info in cameras.items():
        cam_id = cam_info.get("id", "")
        ip = _resolve_lan_ip(cfg, cam_id, cam_info)
        ok_str = ""
        if ip:
            ok, rtt = _lan_tcp_ping(ip, port=443, timeout=2.0)
            ok_str = f"  {'OK' if ok else 'UNREACHABLE'}  ({rtt:.0f} ms)" if ok else "  UNREACHABLE"
        ip_display = ip or "(not set)"
        print(f"  {name:<20} {ip_display:<18}{ok_str}")
    print()


def cmd_privacy(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)  # "on" / "off" / None
    use_local = getattr(args, "local", False)

    # If action was parsed as cam and cam_arg looks like an action, swap them
    # (e.g. "privacy on" → cam=None, action="on")
    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    # ── --local path: RCP write directly to camera, skip cloud ────────────────
    if use_local:
        if action is None:
            print("  ℹ️   --local requires an action: on or off")
            return
        new_state = action.upper()
        enabled = new_state == "ON"
        cred_session: requests.Session | None = None
        for name, cam_info in cams.items():
            cam_id = cam_info.get("id", "")
            ip = _resolve_lan_ip(cfg, cam_id, cam_info)
            print(f"\n── Privacy Mode (LOCAL RCP): {name} ──────────────────────")
            if not ip:
                print(f"  ❌  No LAN IP for {name}. Run: bosch lan-ips set {name.lower()} <ip>")
                continue
            # Gen2 rcp.xml requires Digest auth -- fetch cycling LOCAL creds
            # via a brief PUT /connection LOCAL handshake (matches the HA
            # integration's coordinator.local_creds_cache pattern). The
            # RCP write itself still goes straight to the camera's LAN IP.
            # Session built lazily -- only once we know at least one camera
            # actually needs it, so a config with no LAN IPs set never
            # touches get_token()/make_session() at all.
            if cred_session is None:
                cred_session = make_session(get_token(cfg))
            creds = _get_local_connection_creds(cred_session, cam_id)
            if not creds:
                print(f"  ❌  Could not obtain LOCAL Digest credentials for {name}.")
                print("     Camera offline, LAN unreachable, or not Gen2?")
                continue
            cred_host, cred_user, cred_pass = creds
            write_ip = cred_host or ip
            print(f"  🔄  Writing privacy → {new_state} via RCP to {write_ip}...")
            ok = _lan_rcp_write_privacy(write_ip, enabled, user=cred_user, password=cred_pass)
            if ok:
                icon_new = "🔒" if enabled else "👁️"
                print(f"  {icon_new}  Privacy mode set to {new_state} (LAN RCP).")
            else:
                print(f"  ❌  LOCAL RCP write failed for {name} ({ip}).")
                print("     Is it a Gen2 camera reachable on LAN?")
        return

    # ── cloud path (default) ───────────────────────────────────────────────────
    token = get_token(cfg)
    session = make_session(token)
    _ = get_cameras(cfg, session)  # ensure discovery if needed

    # Fetch current state from /v11/video_inputs
    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    if 500 <= r.status_code <= 599:
        _hint_local_on_5xx(
            r.status_code,
            f"bosch privacy{' ' + cam_arg if cam_arg else ''}"
            f"{' ' + action if action else ''} --local",
        )
        r.raise_for_status()
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        current = cam_raw.get("privacyMode", "UNKNOWN")
        icon = "🔒" if current.upper() == "ON" else "👁️"

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
            print("\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py privacy {name.lower()} on")
            continue

        # Set privacy mode
        new_state = "ON" if action == "on" else "OFF"
        if current.upper() == new_state:
            print(f"  ✅  Already {new_state} — no change needed.")
            continue

        minutes = getattr(args, "minutes", None)
        body: dict[str, Any]
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
            _hint_local_on_5xx(pr.status_code, f"bosch privacy {name.lower()} {action} --local")
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_light(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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

    Extended syntax:
      light [cam] front on/off      → toggle front light only
      light [cam] wall on/off       → toggle wallwasher only
      light [cam] intensity <0-100> → set front light brightness

    featureStatus fields (shown in status view):
      scheduleStatus         — ALWAYS_OFF / ALWAYS_ON / SCHEDULE
      frontIlluminatorInGeneralLightOn  — general light mode enabled
      lightOnMotion          — activate light on motion detection
      lightOnMotionFollowUpTimeSeconds  — how long after motion
      generalLightOnTime / generalLightOffTime  — schedule window
    """
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)
    use_local = getattr(args, "local", False)

    # Allow "light on" / "light off" without camera name
    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action = cam_arg.lower()
        cam_arg = None
    # Allow "light front on" / "light wall off" / "light intensity 50"
    if cam_arg and cam_arg.lower() in ("front", "wall", "intensity"):
        component = cam_arg.lower()
        cam_arg = None
        action = f"{component} {action}" if action else component
    elif action and action.lower() in ("front", "wall", "intensity"):
        extra = getattr(args, "extra_args", [])
        action = f"{action.lower()} {extra[0]}" if extra else action.lower()

    cams = resolve_cam(cfg, cam_arg)

    # ── --local path: front-light RCP write directly to camera ────────────────
    if use_local:
        if action is None:
            print("  ℹ️   --local requires an action: on / off / intensity <0-100>")
            return
        # Parse brightness from action
        parts = action.split()
        if parts[0] == "off":
            brightness = 0
            desc = "OFF (brightness=0)"
        elif parts[0] == "intensity" and len(parts) >= 2:
            brightness = max(0, min(100, int(parts[1])))
            desc = f"intensity {brightness}%"
        elif parts[0] in ("on", "front") and len(parts) >= 2 and parts[1].lower() == "on":
            brightness = 100
            desc = "ON (brightness=100%)"
        elif parts[0] in ("on", "front") and len(parts) >= 2 and parts[1].lower() == "off":
            brightness = 0
            desc = "OFF (brightness=0)"
        elif parts[0] in ("on",):
            brightness = 100
            desc = "ON (brightness=100%)"
        else:
            # wall / wallwasher — local RCP not supported
            print(
                "  ℹ️   --local only supports front light and intensity. Wallwasher is cloud-only."
            )
            return
        cred_session: requests.Session | None = None
        for name, cam_info in cams.items():
            cam_id = cam_info.get("id", "")
            ip = _resolve_lan_ip(cfg, cam_id, cam_info)
            print(f"\n── Camera Light (LOCAL RCP): {name} ─────────────────────")
            if not ip:
                print(f"  ❌  No LAN IP for {name}. Run: bosch lan-ips set {name.lower()} <ip>")
                continue
            # Gen2 rcp.xml requires Digest auth -- fetch cycling LOCAL creds
            # via a brief PUT /connection LOCAL handshake (matches the HA
            # integration's coordinator.local_creds_cache pattern). The
            # RCP write itself still goes straight to the camera's LAN IP.
            # Session built lazily -- only once we know at least one camera
            # actually needs it, so a config with no LAN IPs set never
            # touches get_token()/make_session() at all.
            if cred_session is None:
                cred_session = make_session(get_token(cfg))
            creds = _get_local_connection_creds(cred_session, cam_id)
            if not creds:
                print(f"  ❌  Could not obtain LOCAL Digest credentials for {name}.")
                print("     Camera offline, LAN unreachable, or not Gen2?")
                continue
            cred_host, cred_user, cred_pass = creds
            write_ip = cred_host or ip
            print(f"  🔄  Writing front light → {desc} via RCP to {write_ip}...")
            ok = _lan_rcp_write_front_light(
                write_ip, brightness, user=cred_user, password=cred_pass
            )
            if ok:
                icon = "💡" if brightness > 0 else "🌑"
                print(f"  {icon}  Front light set to {desc} (LAN RCP).")
                print("     Note: wallwasher control is cloud-only and was not changed.")
            else:
                print(f"  ❌  LOCAL RCP write failed for {name} ({write_ip}).")
                print("     Is it a Gen2 camera reachable on LAN?")
        return

    # ── cloud path (default) ───────────────────────────────────────────────────
    token = get_token(cfg)
    session = make_session(token)
    _ = get_cameras(cfg, session)  # ensure discovery if needed

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    if 500 <= r.status_code <= 599:
        _hint_local_on_5xx(
            r.status_code,
            f"bosch light{' ' + cam_arg if cam_arg else ''}"
            f"{' ' + action if action else ''} --local",
        )
        r.raise_for_status()
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        feat_support = cam_raw.get("featureSupport", {})
        has_light = feat_support.get("light", False)
        feat_status = cam_raw.get("featureStatus", {})

        print(f"\n── Camera Light: {name} ─────────────────────────────────────")
        if not has_light:
            print("  ℹ️   This camera does not support a built-in light.")
            continue

        sched = feat_status.get("scheduleStatus", "UNKNOWN")
        front_on = feat_status.get("frontIlluminatorInGeneralLightOn", False)
        intensity = feat_status.get("frontIlluminatorGeneralLightIntensity", 0)
        wall_on = feat_status.get("wallwasherInGeneralLightOn", False)
        on_time = feat_status.get("generalLightOnTime", "?")
        off_time = feat_status.get("generalLightOffTime", "?")
        on_motion = feat_status.get("lightOnMotion", False)
        follow_up = feat_status.get("lightOnMotionFollowUpTimeSeconds", 0)

        mode_icon = {"ALWAYS_ON": "💡", "ALWAYS_OFF": "🌑", "SCHEDULE": "📅"}.get(sched, "❓")
        print(f"  {mode_icon}  Schedule mode:       {sched}")
        print(
            f"  {'💡' if front_on else '🌑'}  General light mode:  {'ON' if front_on else 'OFF'}  "
            f"(intensity: {intensity:.0%})"
        )
        if wall_on:
            print("  💡  Wallwasher:          ON")
        print(f"  🕐  Schedule window:     {on_time} → {off_time}")
        print(
            f"  🏃  Light on motion:     {'YES' if on_motion else 'NO'}  (follow-up: {follow_up}s)"
        )

        # Also show current override state
        try:
            ovr = session.get(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_override",
                timeout=10,
            ).json()
            ovr_front = ovr.get("frontLightOn", False)
            ovr_wall = ovr.get("wallwasherOn", False)
            ovr_int = ovr.get("frontLightIntensity")
            print("  ── Override (instant) ──")
            print(
                f"  {'💡' if ovr_front else '🌑'}  Front light:         {'ON' if ovr_front else 'OFF'}"
                + (f"  (intensity: {ovr_int:.0%})" if ovr_int is not None else "")
            )
            print(
                f"  {'💡' if ovr_wall else '🌑'}  Wallwasher:          {'ON' if ovr_wall else 'OFF'}"
            )
        except Exception:
            pass

        if action is None:
            print()
            print("  Commands:")
            print(f"    light {name.lower()} on              # both lights ON 100%")
            print(f"    light {name.lower()} off             # both lights OFF")
            print(f"    light {name.lower()} front on/off    # front light only")
            print(f"    light {name.lower()} wall on/off     # wallwasher only")
            print(f"    light {name.lower()} intensity 50    # front light 50%")
            continue

        # Read current override state to preserve components
        try:
            cur = session.get(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_override",
                timeout=10,
            ).json()
        except Exception:
            cur = {}
        cur_front = cur.get("frontLightOn", False)
        cur_wall = cur.get("wallwasherOn", False)
        cur_int = cur.get("frontLightIntensity") or 1.0

        # Parse action: "on", "off", "front on", "wall off", "intensity 50"
        parts = action.split()
        if parts[0] in ("front", "wall", "intensity") and len(parts) >= 2:
            component = parts[0]
            val = parts[1]
            if component == "front":
                cur_front = val.lower() == "on"
                desc = f"front light → {'ON' if cur_front else 'OFF'}"
            elif component == "wall":
                cur_wall = val.lower() == "on"
                desc = f"wallwasher → {'ON' if cur_wall else 'OFF'}"
            elif component == "intensity":
                cur_int = max(0.0, min(1.0, int(val) / 100))
                cur_front = True  # intensity implies front on
                desc = f"front light intensity → {int(cur_int * 100)}%"
        elif action == "on":
            cur_front = True
            cur_wall = True
            cur_int = 1.0
            desc = "all lights → ON"
        else:
            cur_front = False
            cur_wall = False
            desc = "all lights → OFF"

        body = {
            "frontLightOn": cur_front,
            "wallwasherOn": cur_wall,
            "frontLightIntensity": cur_int,
        }

        print(f"\n  🔄  Setting light override: {desc}...")
        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_override",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            print(
                f"  💡  Done. Front={'ON' if cur_front else 'OFF'}  "
                f"Wall={'ON' if cur_wall else 'OFF'}  "
                f"Intensity={int(cur_int * 100)}%"
            )
        else:
            _hint_local_on_5xx(pr.status_code, f"bosch light {name.lower()} {action} --local")
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


# Pan preset angles — canonical mapping used by CLI, MCP, and ioBroker.
# home=0° / left=-60° / right=+60° / back-left=-120° / back-right=+120°
# (legacy presets: "left"→full-left=-limit, "center"→0, "right"→full-right=+limit)
PAN_PRESET_MAP: dict[str, int] = {
    "home": 0,
    "left": -60,
    "right": 60,
    "back-left": -120,
    "back-right": 120,
}


def cmd_pan(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Get or set the pan position of the 360 camera via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py pan [cam-name]                       → show current position
      python3 bosch_camera.py pan [cam-name] --preset home         → pan to 0°
      python3 bosch_camera.py pan [cam-name] --preset left         → pan to -60°
      python3 bosch_camera.py pan [cam-name] --preset right        → pan to +60°
      python3 bosch_camera.py pan [cam-name] --preset back-left    → pan to -120°
      python3 bosch_camera.py pan [cam-name] --preset back-right   → pan to +120°
      python3 bosch_camera.py pan [cam-name] center                → pan to 0° (legacy alias)
      python3 bosch_camera.py pan [cam-name] <-120..120>           → pan to absolute position

    API: GET /v11/video_inputs/{id}/pan
           → {"currentAbsolutePosition": 15, "panLimit": 120}
         PUT /v11/video_inputs/{id}/pan
           Body: {"absolutePosition": -120}   (range: -panLimit to +panLimit)
           Response: {"currentAbsolutePosition": -120, "cameraStoppedAtLimit": false,
                      "estimatedTimeToCompletion": 970}
    Only available for cameras with featureSupport.panLimit > 0 (indoor 360 camera).
    Discovered 2026-03-21 via mitmproxy capture.
    """
    token = get_token(cfg)
    session = make_session(token)
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)

    # --preset flag takes priority and sets action
    preset_flag = getattr(args, "preset", None)
    if preset_flag:
        action = preset_flag

    # Allow "pan left" / "pan center" / "pan right" / "pan 45" without camera name
    PRESETS = ("left", "center", "right")
    if cam_arg and action is None:
        try:
            int(cam_arg)
            action, cam_arg = cam_arg, None  # "pan 45" → action=45, cam=None
        except ValueError:
            cam_arg_str: str = str(cam_arg)
            if cam_arg_str.lower() in PRESETS:
                action, cam_arg = cam_arg_str.lower(), None

    cams = resolve_cam(cfg, cam_arg)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        pan_limit = cam_raw.get("featureSupport", {}).get("panLimit", 0)

        print(f"\n── Pan Control: {name} ──────────────────────────────────────")
        if not pan_limit:
            print("  ℹ️   This camera does not support pan (panLimit=0).")
            continue

        # Fetch current position
        pr = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/pan", timeout=10)
        if pr.status_code != 200:
            hint = (
                "  💡  Camera is in privacy mode — disable privacy first (`bosch_camera.py privacy <cam> --off`)."
                if pr.status_code == 443
                else ""
            )
            print(f"  ❌  Could not fetch pan state: HTTP {pr.status_code}")
            if hint:
                print(hint)
            continue
        pan_data = pr.json()
        current = pan_data.get("currentAbsolutePosition", 0)
        limit = pan_data.get("panLimit", pan_limit)

        # Visual position bar
        pct = (current + limit) / (2 * limit)  # 0.0 = full left, 1.0 = full right
        width = 30
        pos = int(pct * width)
        bar_str = "─" * pos + "●" + "─" * (width - pos)
        direction = "CENTER" if abs(current) < 5 else ("RIGHT ▶" if current > 0 else "◀ LEFT")
        print(f"  📍  Position:  {current:+4d}°  {direction}")
        print(f"      Range:    -{limit}° ◀ [{bar_str}] ▶ +{limit}°")

        if action is None:
            print(f"\n  Run with --preset or a number (-{limit}..+{limit}). E.g.:")
            print(f"    python3 bosch_camera.py pan {name.lower()} --preset home")
            print(f"    python3 bosch_camera.py pan {name.lower()} --preset left")
            print(f"    python3 bosch_camera.py pan {name.lower()} 45")
            continue

        # Resolve target position — check PAN_PRESET_MAP first, then legacy aliases,
        # then numeric value
        LEGACY_MAP: dict[str, int] = {"center": 0, "left": -limit, "right": limit}
        action_lower = action.lower()
        if action_lower in PAN_PRESET_MAP:
            target = PAN_PRESET_MAP[action_lower]
        elif action_lower in LEGACY_MAP:
            target = LEGACY_MAP[action_lower]
        else:
            try:
                target = int(action)
            except ValueError:
                print(
                    f"  ❌  Unknown action '{action}'. "
                    f"Use --preset home/left/right/back-left/back-right or a number."
                )
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
            eta_ms = data.get("estimatedTimeToCompletion", 0)
            at_limit = data.get("cameraStoppedAtLimit", False)
            print(f"  ✅  Moving to {new_pos:+d}°  (ETA: {eta_ms}ms)")
            if at_limit:
                print("  ⚠️   Camera stopped at mechanical limit.")
        else:
            print(f"  ❌  Failed: HTTP {resp.status_code}  {resp.text[:200]}")


def cmd_notifications(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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
    token = get_token(cfg)
    session = make_session(token)
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)

    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    r = session.get(f"{CLOUD_API}/v11/video_inputs", timeout=15)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    r.raise_for_status()
    cam_list = {cam.get("id"): cam for cam in r.json()}

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        cam_raw = cam_list.get(cam_id, {})
        current = cam_raw.get("notificationsEnabledStatus", "UNKNOWN")
        notif_on = current != "ALWAYS_OFF"
        icon = "🔔" if notif_on else "🔕"

        # Friendly display for all known states
        STATE_LABELS = {
            "ALWAYS_OFF": "OFF",
            "FOLLOW_CAMERA_SCHEDULE": "ON (follows schedule)",
            "ON_CAMERA_SCHEDULE": "ON (explicit schedule)",
        }
        state_label = STATE_LABELS.get(current, current)

        print(f"\n── Notifications: {name} ─────────────────────────────────────")
        print(f"  {icon}  Current state:  {current}  →  {state_label}")

        if action is None:
            print("\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py notifications {name.lower()} on")
            continue

        new_status = "FOLLOW_CAMERA_SCHEDULE" if action == "on" else "ALWAYS_OFF"
        # ON_CAMERA_SCHEDULE also counts as "on" — don't overwrite with FOLLOW_CAMERA_SCHEDULE
        already_on = action == "on" and current in ("FOLLOW_CAMERA_SCHEDULE", "ON_CAMERA_SCHEDULE")
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
FCM_PROJECT_ID = "bosch-smart-cameras"
FCM_APP_ID = "1:404630424405:android:9e5b6b58e4c70075"
FCM_SENDER_ID = "404630424405"


def _get_fcm_api_key() -> str:
    """Return the Google API key for FCM registration.

    Switched 2026-04-20 to the vendor-sanctioned OSS key.
    Firebase Installations + FCM registration permissions confirmed working.
    """
    import base64

    return base64.b64decode("QUl6YVN5Q0toaGZ4ZlRzMUc3V3Z6VERBaU8wQWlzN0VIMjVEYk9z").decode()


FCM_CRED_KEY = "_fcm_credentials"  # key in bosch_config.json settings


# ── firebase-messaging upstream bug fixes ────────────────────────────────────
# The `firebase-messaging` PyPI library has three open, unmerged upstream bugs
# that this tool hits in production against Bosch's cloud. Rather than vendor
# the library we subclass it and replace exactly the three broken methods:
#
#   sdb9696/firebase-messaging#33 — `_listen()` logs a full traceback for the
#       very first connectivity error of every reset, because `run_state` only
#       becomes RESETTING *inside* `_reset()`, which runs *after* the log
#       decision. On a WAN outage that is one traceback per ~63 s forever.
#   sdb9696/firebase-messaging#37 — `_decrypt_raw_data()` decodes the webpush
#       crypto-key/salt headers and our own stored keys with plain
#       `urlsafe_b64decode`, which raises `binascii.Error` on the RFC 8291-legal
#       *unpadded* base64 they are actually transmitted in — every push then
#       fails to decrypt.
#   sdb9696/firebase-messaging#42 + #44 — `_handle_data_message()` extracts the
#       header values with a blind `header[3:]` / `header[5:]` slice, assuming
#       they always start with exactly `"dh="` / `"salt="`. Real headers are
#       multi-segment (`dh=<key>; p256ecdsa=<vapid>`) and case-insensitive, so
#       the slice silently yields corrupted key bytes that still base64-decode
#       but fail EC-point validation — raising a bare `ValueError("Invalid EC
#       key.")` that escapes `_listen()`'s narrow handlers, hits its broad
#       `except Exception`, and **terminates the whole push client**, silently
#       ending the watch session.
#
# Each override is guarded independently against the upstream signature it
# replicates: if a future library release changes one of them, only that fix
# degrades back to the vanilla behaviour — the other two keep working.


def _fcm_patch_note(msg: str) -> None:
    """Report that one of the firebase-messaging fixes could not be applied.

    Only ever fires when the installed library diverges from what the override
    replicates (i.e. after a library upgrade), so it is worth surfacing rather
    than swallowing — but it is never fatal, the vanilla behaviour still runs.
    """
    print(f"  [warn] FCM patch: {msg}", file=sys.stderr)


def _urlsafe_b64decode_padded(data: str) -> bytes:
    """Decode urlsafe base64 that may be missing its ``=`` padding.

    Webpush keys and the crypto-key/salt headers (RFC 8291) are transmitted
    without padding; Python's ``urlsafe_b64decode`` requires it and raises
    ``binascii.Error`` on unpadded input (upstream #37).
    """
    import base64

    return base64.urlsafe_b64decode(data.encode("ascii") + b"=" * (-len(data) % 4))


def _decode_message_header(data: str) -> bytes:
    """Decode a per-message crypto-key/salt header.

    ``crypto-key``/``encryption`` are proto3 ``string`` fields, so their content
    can legitimately contain non-ASCII bytes — but ``.encode("ascii")`` above
    raises ``UnicodeEncodeError`` (a ``ValueError``, not a ``binascii.Error``)
    for those, which would escape the skip-one-message handler and terminate the
    whole client over a single bad message. Normalise to ``binascii.Error`` so
    every header-decode failure is uniformly a single-message fault.
    """
    import binascii

    try:
        return _urlsafe_b64decode_padded(data)
    except UnicodeEncodeError as ex:
        raise binascii.Error(str(ex)) from ex


def _decode_credential_material(data: str) -> bytes:
    """Decode OUR OWN stored credential material (private/secret keys).

    Same padding math as :func:`_decode_message_header`, but a failure here
    means the stored credentials are corrupt — a client-wide fault that must
    propagate rather than be silently skipped per message forever. Re-raised as
    a plain ``ValueError`` to match what ``load_der_private_key`` already raises
    for other forms of credential corruption.
    """
    import binascii

    try:
        return _urlsafe_b64decode_padded(data)
    except (binascii.Error, UnicodeEncodeError) as ex:
        raise ValueError(f"corrupt stored credential material: {ex}") from ex


def _extract_crypto_header(raw: str, prefix: str) -> str:
    """Extract a crypto-key/salt header value, tolerating real-world shapes.

    Upstream (#42 + #44) does ``header[3:]``/``header[5:]``, assuming the wanted
    parameter is the first ``;``-separated segment and matches case-exactly.
    Neither holds: ``Crypto-Key``/``Encryption`` are ``;``-separated parameter
    lists *and* (RFC 8188) ``,``-separated element lists, so a VAPID
    ``p256ecdsa=`` or an ``rs=``/``keyid=`` parameter may legally precede
    ``dh=``/``salt=``; and HTTP parameter names are case-insensitive.

    Scans every segment across both separators for a case-insensitive prefix
    match and strips surrounding whitespace (leftover whitespace would throw off
    the padding math in :func:`_decode_message_header`). Falls back to the whole
    stripped string unmodified if nothing matches — passing an unexpected shape
    through rather than guessing.
    """
    for element in raw.split(","):
        for segment in element.split(";"):
            stripped = segment.strip()
            if stripped.lower().startswith(prefix.lower()):
                return stripped[len(prefix) :].strip()
    return raw.strip()


def _build_fcm_decrypt_override(
    fcm_push_client_cls: type,
) -> tuple[Optional[Any], tuple[type[Exception], ...]]:
    """Build the upstream-#37 padded-decrypt override for ``_decrypt_raw_data``.

    Returns ``(override_or_None, skip_exceptions)`` — the latter being the
    exception types ``_listen()`` should treat as "skip just this one message".
    ``skip_exceptions`` is built independently of whether the override itself
    could be created: even vanilla ``_decrypt_raw_data`` reaches
    ``http_ece.decrypt()`` and can raise ``ECEException`` whenever a message's
    headers happen to already be a multiple of 4 in length.
    """
    import binascii
    import inspect

    skip_exceptions: tuple[type[Exception], ...] = (binascii.Error,)
    try:
        from http_ece import ECEException
    except ImportError:
        _fcm_patch_note("http_ece unavailable — unpadded-base64 decrypt fix not applied")
        return None, skip_exceptions
    skip_exceptions = (binascii.Error, ECEException)

    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        from http_ece import decrypt as http_ece_decrypt
    except ImportError:
        _fcm_patch_note("cryptography unavailable — unpadded-base64 decrypt fix not applied")
        return None, skip_exceptions

    decrypt_method = getattr(fcm_push_client_cls, "_decrypt_raw_data", None)
    if decrypt_method is None or list(inspect.signature(decrypt_method).parameters) != [
        "credentials",
        "crypto_key_str",
        "salt_str",
        "raw_data",
    ]:
        _fcm_patch_note(
            "upstream _decrypt_raw_data() signature changed — "
            "unpadded-base64 decrypt fix not applied"
        )
        return None, skip_exceptions

    def _decrypt_raw_data(
        credentials: dict[str, dict[str, str]],
        crypto_key_str: str,
        salt_str: str,
        raw_data: bytes,
    ) -> bytes:
        """Decrypt an FCM data message, tolerating unpadded base64 (#37)."""
        crypto_key = _decode_message_header(crypto_key_str)
        salt = _decode_message_header(salt_str)
        der_data = _decode_credential_material(credentials["keys"]["private"])
        secret = _decode_credential_material(credentials["keys"]["secret"])
        # A failure here means OUR stored credentials are corrupt — a
        # client-wide fault, deliberately left unguarded so it propagates.
        privkey = load_der_private_key(der_data, password=None, backend=default_backend())
        # http_ece.decrypt()'s own EC-point parsing of THIS message's crypto-key
        # bytes is not wrapped into ECEException the way its AEAD path is: it
        # raises a bare ValueError("Invalid EC key.") straight out of
        # `cryptography`, which would tear down the whole client over one bad
        # message. Pre-parse the point ourselves and convert ONLY that failure —
        # deliberately not a broad try/except around decrypt(), which would also
        # mask ValueErrors caused by our own stored private key.
        try:
            crypto_key_point = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), crypto_key
            )
        except ValueError as ex:
            raise ECEException(str(ex)) from ex

        decrypted: bytes = http_ece_decrypt(
            raw_data,
            salt=salt,
            private_key=privkey,
            dh=crypto_key_point,
            version="aesgcm",
            auth_secret=secret,
        )
        return decrypted

    return _decrypt_raw_data, skip_exceptions


def _build_fcm_handle_data_message_override(
    fcm_push_client_cls: type,
) -> Optional[Any]:
    """Build the corrected ``_handle_data_message()`` override (#42 + #44).

    The body is identical to the installed library version except the
    ``crypto_key``/``salt`` extraction lines, which use
    :func:`_extract_crypto_header` instead of upstream's blind slice.

    The replicated body calls six *other* private upstream methods that a future
    release could rename independently of ``_handle_data_message`` itself, so the
    guard checks all of them — otherwise an upstream change elsewhere would
    silently attach a body that ``AttributeError``s at runtime, reintroducing the
    very crash class this fixes. An upstream handler that became a coroutine is
    also rejected: this replica is deliberately sync (as every 0.4.x release is).
    """
    import inspect

    handler = getattr(fcm_push_client_cls, "_handle_data_message", None)
    required_helpers = (
        "_app_data_by_key",
        "_log_warn_with_limit",
        "_log_verbose",
        "_reset_error_count",
        "_try_increment_error_count",
        "_decrypt_raw_data",
    )
    if (
        handler is None
        or inspect.iscoroutinefunction(handler)
        or list(inspect.signature(handler).parameters) != ["self", "msg"]
        or not all(callable(getattr(fcm_push_client_cls, name, None)) for name in required_helpers)
    ):
        _fcm_patch_note(
            "upstream _handle_data_message() changed — crypto-key/salt header fix not applied"
        )
        return None

    try:
        from firebase_messaging.fcmpushclient import ErrorType as _ErrorType
    except ImportError:
        _fcm_patch_note(
            "firebase_messaging.ErrorType unavailable — crypto-key/salt header fix not applied"
        )
        return None

    def _handle_data_message(self: Any, msg: Any) -> None:
        if self._app_data_by_key(msg, "message_type", do_not_raise=True) == "deleted_messages":
            # The deleted_messages message does not contain data.
            return
        crypto_key = _extract_crypto_header(self._app_data_by_key(msg, "crypto-key"), "dh=")
        salt = _extract_crypto_header(self._app_data_by_key(msg, "encryption"), "salt=")
        subtype = self._app_data_by_key(msg, "subtype")
        if subtype != self.credentials["gcm"]["app_id"]:
            self._log_warn_with_limit(
                "Subtype %s in data message does not match"
                + "app id client was registered with %s",
                subtype,
                self.credentials["gcm"]["app_id"],
            )
        decrypted = self._decrypt_raw_data(self.credentials, crypto_key, salt, msg.raw_data)
        decrypted_json = None
        try:
            decrypted_json = json.loads(decrypted.decode("utf-8"))
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            decrypted_json = None

        if not decrypted_json:
            self._log_warn_with_limit("Failed to decrypt data for message %s", msg.persistent_id)

        ret_val = decrypted_json if decrypted_json else decrypted
        self._log_verbose("Data for message %s is: %s", msg.persistent_id, ret_val)
        try:
            if not isinstance(ret_val, dict):
                ret_val = {"message": ret_val}
            self.callback(ret_val, msg.persistent_id, self.callback_context)
            self._reset_error_count(_ErrorType.NOTIFY)
        except Exception as ex:
            print(f"  [warn] FCM notification callback raised: {ex}", file=sys.stderr)
            self._try_increment_error_count(_ErrorType.NOTIFY)

    return _handle_data_message


def _patch_fcm_push_client_class() -> Optional[type]:
    """Return a patched ``FcmPushClient`` subclass, or ``None`` if the installed
    library is too new/old for safe subclassing (``_listen`` signature changed).
    """
    try:
        from firebase_messaging import FcmPushClient, FcmPushClientRunState
    except ImportError:
        return None

    import asyncio
    import inspect
    import ssl

    listen_method = getattr(FcmPushClient, "_listen", None)
    if listen_method is None or list(inspect.signature(listen_method).parameters) != ["self"]:
        _fcm_patch_note("upstream _listen() signature changed — noise/crash fixes not applied")
        return None

    decrypt_override, skip_exceptions = _build_fcm_decrypt_override(FcmPushClient)
    handle_data_message_override = _build_fcm_handle_data_message_override(FcmPushClient)

    # run_state / do_listen / persistent_ids live on the (untyped, external)
    # FcmPushClient base class, which neither pylint nor mypy can introspect.
    class _Patched(FcmPushClient):  # type: ignore[misc]  # pylint: disable=too-few-public-methods,access-member-before-definition,attribute-defined-outside-init
        """FcmPushClient with the upstream #33/#37/#42/#44 fixes applied."""

        async def _listen(self) -> None:
            """Upstream ``_listen()`` plus the #33 state fix and per-message
            skip handlers, so one undecryptable push can no longer terminate
            the whole client."""
            if not await self._connect_with_retry():
                return

            try:
                await self._login()

                while self.do_listen:
                    try:
                        if self.run_state == FcmPushClientRunState.RESETTING:  # type: ignore[has-type]  # untyped external base class attr  # pylint: disable=access-member-before-definition
                            await asyncio.sleep(1)
                        elif msg := await self._receive_msg():

                            async def _skip_and_ack(exc: Exception) -> None:
                                persistent_id = getattr(msg, "persistent_id", None)
                                print(
                                    "  [warn] Skipping undecryptable FCM push message "
                                    f"(id={persistent_id}): {exc}",
                                    file=sys.stderr,
                                )
                                # Ack it anyway: upstream only appends to
                                # persistent_ids / sends the selective ack AFTER
                                # _handle_data_message() returns, so without this
                                # Google MCS redelivers the same poisoned message
                                # on every reconnect, forever.
                                if persistent_id:
                                    self.persistent_ids.append(persistent_id)
                                    if self.config.send_selective_acknowledgements:
                                        await self._send_selective_ack(persistent_id)

                            try:
                                await self._handle_message(msg)
                            except skip_exceptions as decode_ex:
                                # binascii.Error / ECEException are single-message
                                # faults (bad padding, truncated body, tag mismatch
                                # on a message meant for another subtype). Kept
                                # narrower than ValueError on purpose: a plain
                                # ValueError means our *stored* credentials are
                                # corrupt, which must stay a client-wide fault.
                                await _skip_and_ack(decode_ex)
                            except RuntimeError as app_data_ex:
                                # Upstream's _handle_data_message() unconditionally
                                # looks up the crypto-key/encryption app_data
                                # entries and raises a bare RuntimeError when
                                # either is absent — e.g. a non-webpush control
                                # message, or (RFC 8291) an aes128gcm-encoded one
                                # that carries no such headers at all. Match only
                                # that specific message shape.
                                if "couldn't find in app_data" not in str(app_data_ex):
                                    raise
                                await _skip_and_ack(app_data_ex)

                    except (OSError, EOFError) as osex:
                        # FIX for upstream #33: advance to RESETTING here, before
                        # the quiet-path check below — the library only sets it
                        # inside _reset(), which runs afterwards, so the first OS
                        # error always took the loud traceback branch.
                        if self.run_state not in (  # type: ignore[has-type]  # untyped external base class attr  # pylint: disable=access-member-before-definition
                            FcmPushClientRunState.RESETTING,
                            FcmPushClientRunState.STOPPING,
                            FcmPushClientRunState.STOPPED,
                        ):
                            self.run_state = (  # pylint: disable=attribute-defined-outside-init
                                FcmPushClientRunState.RESETTING
                            )

                        quiet_reset = (
                            isinstance(
                                osex,
                                (
                                    ConnectionResetError,
                                    TimeoutError,
                                    asyncio.IncompleteReadError,
                                    ssl.SSLError,
                                ),
                            )
                            and self.run_state == FcmPushClientRunState.RESETTING
                        )
                        if quiet_reset:
                            if (
                                isinstance(osex, ssl.SSLError)
                                and osex.reason != "APPLICATION_DATA_AFTER_CLOSE_NOTIFY"
                            ):
                                self._log_warn_with_limit(
                                    "Unexpected SSLError reason during reset of %s",
                                    osex.reason,
                                )
                            else:
                                self._log_verbose(
                                    "Expected read error during reset: %s",
                                    type(osex).__name__,
                                )
                        else:
                            print(
                                f"  [warn] FCM read error: {osex!r}",
                                file=sys.stderr,
                            )

                        # Upstream's own quiet branch never calls _reset() —
                        # harmless there because run_state only becomes RESETTING
                        # inside _reset() itself. Our pre-emptive flag above makes
                        # the quiet branch reachable on the FIRST error of every
                        # blip, so without resetting here _listen() would just spin
                        # on `if run_state == RESETTING: sleep(1)` forever instead
                        # of reconnecting. _reset() is idempotent.
                        try:
                            from firebase_messaging.fcmpushclient import (
                                ErrorType as _ErrorType,
                            )

                            if self._try_increment_error_count(_ErrorType.CONNECTION):
                                await self._reset()
                        except ImportError:
                            await self._reset()
            except Exception as ex:
                print(f"  ❌  FCM client shutting down after unknown error: {ex}", file=sys.stderr)
                self._terminate()
            finally:
                await self._do_writer_close()

    if decrypt_override is not None:
        _Patched._decrypt_raw_data = staticmethod(decrypt_override)
    if handle_data_message_override is not None:
        _Patched._handle_data_message = handle_data_message_override

    return _Patched


# False = not yet computed; None = library present but unpatchable.
_FCM_PATCHED_CLASS: Any = False


def _get_fcm_push_client_class() -> Optional[type]:
    """Return the patched ``FcmPushClient`` subclass, falling back to the vanilla
    class if it cannot be patched, or ``None`` if the library is not installed.

    Cached after the first call — the patch is built at most once per process.
    """
    global _FCM_PATCHED_CLASS
    if _FCM_PATCHED_CLASS is False:
        _FCM_PATCHED_CLASS = _patch_fcm_push_client_class()
    if _FCM_PATCHED_CLASS is None:
        try:
            from firebase_messaging import FcmPushClient

            return cast(type, FcmPushClient)
        except ImportError:
            return None
    return cast(type, _FCM_PATCHED_CLASS)


def _effective_event_type(event: dict[str, Any]) -> str:
    """Return the effective event type for display and routing.

    Gen2 cameras send ``eventType=MOVEMENT`` with ``eventTags=["PERSON"]``
    for human detections.  This helper promotes such events to ``"PERSON"``
    so that icons, Signal messages, and webhook payloads are consistent
    across Gen1 (which sends ``eventType=PERSON`` directly) and Gen2.
    """
    raw: str = event.get("eventType") or ""
    tags: list[str] = event.get("eventTags") or []
    if raw == "MOVEMENT" and "PERSON" in tags:
        return "PERSON"
    return raw


def _send_signal_alert(
    signal_url: str,
    sender: str,
    recipients: list[str],
    cam_name: str,
    event_type: str,
    ts: str,
    image_url: str = "",
    token: str = "",
) -> None:
    """Send an alert message (with optional snapshot) via signal-cli-rest-api.

    API: POST {signal_url}/v2/send
    Body: {"message": "...", "number": sender, "recipients": [...], "base64_attachments": [...]}
    """
    import base64 as _b64

    msg = f"{cam_name}: {event_type} um {ts}"
    body: dict[str, Any] = {
        "message": msg,
        "number": sender,
        "recipients": recipients,
    }

    # Download and attach the event snapshot if available
    if image_url and token:
        try:
            headers = {"Authorization": f"Bearer {token}", "Accept": "*/*"}
            r = requests.get(image_url, headers=headers, timeout=15)
            if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                b64 = _b64.b64encode(r.content).decode()
                body["base64_attachments"] = [b64]
        except Exception as e:
            print(f"             ⚠️  Signal image download failed: {e}")

    try:
        r = requests.post(
            f"{signal_url.rstrip('/')}/v2/send",
            json=body,
            timeout=15,
        )
        if r.status_code in (200, 201):
            print(f"             📨 Signal alert sent to {', '.join(recipients)}")
        else:
            print(f"             ⚠️  Signal send failed: HTTP {r.status_code} {r.text[:100]}")
    except Exception as e:
        print(f"             ⚠️  Signal send error: {e}")


def _post_event_webhook(
    url: str,
    cam_name: str,
    cam_id: str,
    event_type: str,
    timestamp: str,
    event: dict[str, Any],
) -> None:
    """POST a single camera event as JSON to the configured webhook URL.

    Silently swallows all errors (non-critical delivery path) — failure is
    printed to stderr but never interrupts the watch loop.

    Payload shape::

        {
            "camera": "<cam_name>",
            "camera_id": "<cam_id>",
            "event_type": "<MOVEMENT|AUDIO_ALARM|PERSON|INTRUSION>",
            "timestamp": "<ISO-8601>",
            "event_id": "<uuid>",
            "image_url": "<url or ''>",
            "clip_url": "<url or ''>",
        }
    """
    payload: dict[str, Any] = {
        "camera": cam_name,
        "camera_id": cam_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "event_id": event.get("id", ""),
        "image_url": event.get("imageUrl", ""),
        "clip_url": event.get("videoClipUrl", ""),
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code >= 400:
            print(
                f"             ⚠️  Webhook POST returned HTTP {resp.status_code}",
                file=sys.stderr,
            )
        else:
            print(f"             🔗 Webhook → HTTP {resp.status_code}")
    except Exception as err:
        print(f"             ⚠️  Webhook POST error: {err}", file=sys.stderr)


def _watch_fcm_push(
    cfg: dict[str, Any],
    token: str,
    cams: dict[str, Any],
    duration: int,
    auto_snap: bool,
    signal_url: str = "",
    signal_sender: str = "",
    signal_recipients: list[str] | None = None,
    fcm_app_id: str = "",
    fcm_api_key: str = "",
    mode_label: str = "Android",
) -> None:
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
    print("\n  Fetching baseline events...")
    for name, cam_info in cams.items():
        events = api_get_events(session_req, cam_info["id"], limit=1)
        if events:
            last_seen[name] = events[0].get("id", "")
        print(f"  {name}: baseline = {last_seen.get(name, '(none)')[:8]}")

    total_new = [0]
    start_time = [time.time()]

    def on_notification(notification: Any, persistent_id: Any, obj: Any = None) -> None:
        """Called on each FCM push — fetch events for all cameras."""
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        # Re-get token in case it was refreshed. make_session() returns the
        # cached module-level Session with the Authorization header updated, so
        # the connection pool is shared across all FCM-triggered fetches.
        tok = cfg["account"].get("bearer_token", token)
        # Pre-emptive token refresh before making API calls.
        if _is_token_near_expiry(tok):
            tok = get_token(cfg)
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
                etype = _effective_event_type(ev)
                ts = ev.get("timestamp", "")[:19]
                img_url = ev.get("imageUrl", "")
                clip_url = ev.get("videoClipUrl", "")
                icon = "🔊" if "AUDIO" in etype else ("👤" if etype == "PERSON" else "🚨")
                print(f"\n  [{now_str}] {icon} {etype:<15s}  cam={name:<12s}  {ts}  (via FCM push)")
                if img_url:
                    print(f"             📸 {img_url}")
                if clip_url:
                    print(f"             🎬 {clip_url}")
                total_new[0] += 1

                # Signal alert
                if signal_url and signal_sender and signal_recipients:
                    _send_signal_alert(
                        signal_url,
                        signal_sender,
                        signal_recipients,
                        name,
                        etype,
                        ts,
                        img_url,
                        tok,
                    )

                if auto_snap and img_url and _is_safe_bosch_url(img_url):
                    try:
                        r = sess.get(img_url, timeout=15)
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
                # Mark new events as read on the Bosch cloud
                read_ids = [ev.get("id") for ev in new_events if ev.get("id")]
                if read_ids:
                    try:
                        api_mark_events_read(sess, read_ids)
                    except Exception:
                        pass

    def on_creds_updated(creds: Any) -> None:
        cfg["settings"][FCM_CRED_KEY] = creds
        save_config(cfg)

    async def _run() -> None:
        fcm_config = FcmRegisterConfig(
            project_id=FCM_PROJECT_ID,
            app_id=fcm_app_id or FCM_APP_ID,
            api_key=fcm_api_key or _get_fcm_api_key(),
            messaging_sender_id=FCM_SENDER_ID,
        )

        saved_creds = cfg.get("settings", {}).get(FCM_CRED_KEY)

        # Patched subclass fixing three open upstream firebase-messaging bugs
        # (#33 log noise, #37 unpadded base64, #42/#44 header extraction — the
        # last of which crashes the whole client on a single bad message).
        # Falls back to the vanilla class if the installed library diverges.
        client_cls = _get_fcm_push_client_class() or FcmPushClient

        client = client_cls(
            callback=on_notification,
            fcm_config=fcm_config,
            credentials=saved_creds,
            credentials_updated_callback=on_creds_updated,
        )

        print("\n  🔑  Registering with FCM...")
        fcm_token = await client.checkin_or_register()
        print(f"  ✅  FCM Token: {fcm_token[:50]}...")

        # Register with Bosch CBS — always ANDROID (Sebastian-OSS-sanctioned key covers both platforms)
        device_type = "ANDROID"
        print(f"  🔗  Registering with Bosch CBS (deviceType={device_type})...")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        r = requests_post_bosch_cloud(
            f"{CLOUD_API}/v11/devices",
            headers=headers,
            json={"deviceType": device_type, "deviceToken": fcm_token},
            timeout=10,
        )
        if r.status_code in (200, 201, 204):
            print("  ✅  Registered with Bosch CBS!")
        else:
            print(f"  ⚠️   CBS registration: HTTP {r.status_code} — pushes may not arrive")

        n_cams = len(cams)
        print(f"\n  📡  Listening for FCM pushes ({n_cams} camera(s), mode={mode_label})...")
        print("      Near-instant event detection (~2-3s latency)")
        if duration:
            print(f"      Will stop after {duration}s.")
        print("      Press Ctrl+C to stop.\n")

        start_time[0] = time.time()

        await client.start()

        try:
            while not _STOP_REQUESTED.is_set():
                await asyncio.sleep(1)
                if duration and (time.time() - start_time[0]) >= duration:
                    print(f"\n  Duration of {duration}s reached — stopping.")
                    break
        except asyncio.CancelledError:
            pass
        finally:
            # Ensure FCM client is always shut down cleanly, even on SIGTERM.
            try:
                await client.stop()
            except Exception as e:
                print(f"  [warn] FCM client.stop() raised: {e}", file=sys.stderr)

    _install_stop_handlers()

    try:
        import asyncio

        asyncio.run(_run())
    except KeyboardInterrupt:
        elapsed = int(time.time() - start_time[0])
        print(f"\n\n  Stopped after {elapsed}s. Total new events: {total_new[0]}")


class MotionEdgeTracker:
    """
    Track motion state with rising/falling edge detection and hysteresis.

    State machine:
      inactive → active  : rising edge  (first motion event after quiet period)
      active   → inactive: falling edge (no events for quiet_secs seconds)

    Usage::
        tracker = MotionEdgeTracker(quiet_secs=30)
        edge = tracker.update(new_events)  # returns "rising", "falling", or None
    """

    INACTIVE: str = "inactive"
    ACTIVE: str = "active"

    def __init__(self, quiet_secs: int = 30) -> None:
        self.quiet_secs: int = quiet_secs
        self._state: str = self.INACTIVE
        # Timestamp of last seen motion event; float('-inf') = never seen any event
        self._last_event_time: float = float("-inf")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> str:
        return self._state

    def update(self, events: list[dict[str, Any]], now: Optional[float] = None) -> Optional[str]:
        """
        Process a list of new motion-related events and return an edge transition.

        Parameters
        ----------
        events:
            New events since last poll (may be empty). Each dict must have at
            least a ``"timestamp"`` key (ISO-8601 string) or will be ignored for
            timing; the *presence* of any event counts as a motion signal.
        now:
            Wall-clock time (``time.time()``). Defaults to ``time.time()``.
            Supplied explicitly by tests via freezegun-controlled time.

        Returns
        -------
        ``"rising"``
            Transitioned from inactive → active.
        ``"falling"``
            Transitioned from active → inactive (hysteresis expired).
        ``None``
            No state change.
        """
        if now is None:
            now = time.time()

        has_events = bool(events)

        if has_events:
            self._last_event_time = now
            if self._state == self.INACTIVE:
                self._state = self.ACTIVE
                return "rising"
            # Already active — motion continues, reset quiet timer (done above)
            return None

        # No new events — check if quiet period has elapsed
        if self._state == self.ACTIVE:
            quiet_elapsed = now - self._last_event_time
            if self.quiet_secs == 0 or quiet_elapsed >= self.quiet_secs:
                self._state = self.INACTIVE
                return "falling"

        return None

    def active_duration(self, now: Optional[float] = None) -> float:
        """Return how many seconds we have been continuously active (0 if inactive)."""
        if self._state == self.INACTIVE:
            return 0.0
        if now is None:
            now = time.time()
        return max(0.0, now - self._last_event_time)


# ── Motion snapshot helpers ────────────────────────────────────────────────────

_MOTION_SNAPSHOT_KEEP = 100  # max snapshots per camera in captures/<cam>/


def _motion_snapshot_dir(cam_name: str) -> str:
    """Return (and create) the captures/<cam> directory for motion snapshots."""
    d = os.path.join(BASE_DIR, "captures", cam_name)
    os.makedirs(d, exist_ok=True)
    return d


def _motion_snapshot_cleanup(cam_name: str, keep: int = _MOTION_SNAPSHOT_KEEP) -> None:
    """Delete oldest motion_*.jpg files if count exceeds *keep*."""
    d = _motion_snapshot_dir(cam_name)
    snaps = sorted([f for f in os.listdir(d) if f.startswith("motion_") and f.endswith(".jpg")])
    excess = len(snaps) - keep
    if excess > 0:
        for fname in snaps[:excess]:
            try:
                os.remove(os.path.join(d, fname))
            except OSError:
                pass
        print(t("watch.motion.cleanup_purged", count=excess, kept=keep))


# ══════════════════════════ NVR (BETA) ═══════════════════════════════════════
#
# Mini-NVR: motion-triggered local MP4 recording via ffmpeg segment muxer.
#
# Storage layout:  captures/<cam>/nvr/YYYY-MM-DD/HHMMSS.mp4
# FIFO eviction:   oldest clips deleted when count exceeds nvr.max_clips.
# SMB upload:      optional, via smbprotocol library; sequential, own connection
#                  cache per upload to avoid SMB credit starvation (see
#                  knowledge-base/smb-credit-starvation.md).
#
# BETA limitations (see README):
#   - RTSP URL must already be resolved (camera must have been live at least once).
#   - ffmpeg is required (brew install ffmpeg / apt-get install ffmpeg).
#   - smbprotocol is optional; install with: pip install smbprotocol
#   - No H.265 transcoding — clips are remuxed as-is from the RTSP stream.
#   - clip naming is second-precision; rapid consecutive recordings may collide
#     (TODO: add sub-second suffix if needed).
#   - Recording is motion-triggered only (single ffmpeg segment-muxer process per
#     active motion session, started on rising edge / stopped on falling edge) —
#     unlike the HA integration's "continuous" NVR mode there is no always-on
#     background daemon here; the CLI only runs while `watch --auto-record` is
#     attached to a foreground/background process.
#   - TODO(preroll): no pre-trigger buffer yet. A few seconds of video from
#     *before* the motion rising edge (matching the HA Mini-NVR ring-buffer
#     concept) would need a second, continuously-running ffmpeg ring segmenter
#     for the whole `watch --auto-record` session (not just while motion is
#     active) plus a concat-demuxer splice step onto the front of each event.
#     Deliberately not implemented in this iteration — it's a real architectural
#     addition (a second long-lived process per camera, a ring/tmpfs directory,
#     splicing logic) that deserves its own change rather than being bolted onto
#     the segment-muxing fix below.

_NVR_DEFAULT_MAX_CLIPS = 50
_NVR_DEFAULT_SEGMENT_SECONDS = 60  # seconds per segment while motion stays active
# Legacy alias — kept for backward compatibility with existing bosch_config.json
# files that only set nvr.max_duration (pre-segmenting semantics: used to be the
# single clip's *maximum total* length; now it's the *segment* length used while
# motion continues, see cmd_watch's nvr_segment_seconds resolution).
_NVR_DEFAULT_MAX_DURATION = _NVR_DEFAULT_SEGMENT_SECONDS


def _nvr_clip_dir(cam_name: str, base_dir: Optional[str] = None) -> str:
    """Return (and create) captures/<cam>/nvr/YYYY-MM-DD/ for today."""
    root = base_dir or BASE_DIR
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    d = os.path.join(root, "captures", cam_name, "nvr", date_str)
    os.makedirs(d, exist_ok=True)
    return d


def _nvr_clip_path(cam_name: str, base_dir: Optional[str] = None) -> str:
    """Return full path for a new clip: .../nvr/YYYY-MM-DD/HHMMSS.mp4"""
    clip_dir = _nvr_clip_dir(cam_name, base_dir)
    ts = datetime.datetime.now().strftime("%H%M%S")
    return os.path.join(clip_dir, f"{ts}.mp4")


def _nvr_all_clips(cam_name: str, base_dir: Optional[str] = None) -> list[str]:
    """Return sorted list of all MP4 clip paths for a camera (oldest first)."""
    root = base_dir or BASE_DIR
    nvr_root = os.path.join(root, "captures", cam_name, "nvr")
    clips: list[str] = []
    if not os.path.isdir(nvr_root):
        return clips
    for day_dir in sorted(os.listdir(nvr_root)):
        day_path = os.path.join(nvr_root, day_dir)
        if not os.path.isdir(day_path):
            continue
        for fname in sorted(os.listdir(day_path)):
            if fname.endswith(".mp4"):
                clips.append(os.path.join(day_path, fname))
    return clips


def _nvr_prune(
    cam_name: str, keep: int = _NVR_DEFAULT_MAX_CLIPS, base_dir: Optional[str] = None
) -> tuple[int, int]:
    """FIFO: delete oldest clips so at most *keep* remain.

    Returns (removed_count, kept_count).
    """
    clips = _nvr_all_clips(cam_name, base_dir)
    excess = len(clips) - keep
    removed = 0
    if excess > 0:
        for path in clips[:excess]:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
        # Remove empty day-directories
        root = base_dir or BASE_DIR
        nvr_root = os.path.join(root, "captures", cam_name, "nvr")
        if os.path.isdir(nvr_root):
            for day_dir in os.listdir(nvr_root):
                day_path = os.path.join(nvr_root, day_dir)
                try:
                    if os.path.isdir(day_path) and not os.listdir(day_path):
                        os.rmdir(day_path)
                except OSError:
                    pass
    kept = len(_nvr_all_clips(cam_name, base_dir))
    return removed, kept


def _nvr_disk_mb(cam_name: str, base_dir: Optional[str] = None) -> float:
    """Return total disk usage of NVR clips for a camera in MiB."""
    clips = _nvr_all_clips(cam_name, base_dir)
    total = 0
    for p in clips:
        try:
            total += os.path.getsize(p)
        except OSError:
            pass
    return total / (1024 * 1024)


def _nvr_session_clips(clip_dir: str, since: float) -> list[str]:
    """Return segment clip paths in *clip_dir* written at/after *since* (epoch secs).

    With segment muxing a single motion recording session (rising edge to
    falling edge) can produce more than one file if motion stays active longer
    than one segment_seconds interval, so callers that need "all clips this
    session produced" (for prune bookkeeping / SMB upload / total byte count)
    use this instead of a single fixed output path.

    A small (1s) slack is applied to *since* to tolerate filesystem mtime
    granularity — this can very rarely pick up the tail end of an
    immediately-preceding session's last segment, which is harmless (it just
    gets uploaded/counted once, under whichever session's falling edge fires
    first).
    """
    if not clip_dir or not os.path.isdir(clip_dir):
        return []
    matches: list[str] = []
    for fname in os.listdir(clip_dir):
        if not fname.endswith(".mp4"):
            continue
        p = os.path.join(clip_dir, fname)
        try:
            if os.path.getmtime(p) >= since - 1:
                matches.append(p)
        except OSError:
            continue
    return sorted(matches)


def _start_motion_recording(
    cam: dict[str, Any],
    segment_seconds: int = _NVR_DEFAULT_SEGMENT_SECONDS,
    base_dir: Optional[str] = None,
) -> Optional["subprocess.Popen[bytes]"]:
    """Start an ffmpeg process that segments the camera RTSP stream into MP4 clips.

    Uses the RTSP URL stored in cam['last_live'] (set when the camera was last
    opened via the 'live' command).  If no RTSP URL is available, returns None.

    Unlike the previous single-file `-t <max_duration>` behavior, this uses
    ffmpeg's own `-f segment` muxer (`-c copy`, no re-encode) so ONE ffmpeg
    child process keeps rotating output files on its own, every
    *segment_seconds* seconds, for as long as the process keeps running — motion
    that continues past *segment_seconds* simply produces additional
    consecutive segment clips instead of the recording stopping early. The
    caller (`cmd_watch`) starts this process on a motion rising edge and
    terminates it on the matching falling edge; ffmpeg finalizes whatever
    segment is in progress on SIGTERM.

    Returns the subprocess.Popen object so the caller can wait() / terminate()
    it, or None on error. The Popen gets a `_nvr_clip_dir` attribute (the
    directory segments are written into) so callers can discover which files
    a given session produced via `_nvr_session_clips()`.

    TODO: add RTSP URL auto-resolution via PUT /connection when last_live is empty.
    """
    last_live = cam.get("last_live") or {}
    rtsp_url = last_live.get("rtsp_url", "")
    if not rtsp_url:
        # Fallback: build a best-effort RTSP URL from proxy_url if present
        proxy_url = last_live.get("proxy_url", "")
        if proxy_url and proxy_url.startswith("rtsps://"):
            rtsp_url = proxy_url
    if not rtsp_url:
        return None

    cam_name = cam.get("name", "unknown")
    clip_dir = _nvr_clip_dir(cam_name, base_dir)
    out_pattern = os.path.join(clip_dir, "%H%M%S.mp4")

    ffmpeg_cmd = [
        "ffmpeg",
        "-y",
        "-rtsp_transport",
        "tcp",
        "-i",
        rtsp_url,
        "-c",
        "copy",
        "-f",
        "segment",
        "-segment_time",
        str(segment_seconds),
        "-reset_timestamps",
        "1",
        "-strftime",
        "1",
        "-movflags",
        "+faststart",
        out_pattern,
    ]

    try:
        proc = subprocess.Popen(
            ffmpeg_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Attach the clip directory as a custom attribute so callers can find
        # this session's segment files (there is no single "output path"
        # anymore once motion continues past one segment_seconds interval).
        proc._nvr_clip_dir = clip_dir  # type: ignore[attr-defined]
        proc._nvr_out_pattern = out_pattern  # type: ignore[attr-defined]
        return proc
    except FileNotFoundError:
        # ffmpeg not installed
        return None
    except Exception:
        return None


def _nvr_smb_upload(clip_path: str, cfg: dict[str, Any]) -> tuple[bool, str]:
    """Upload *clip_path* to the configured SMB share.

    Best-practice: fresh connection_cache per upload session (avoids SMB credit
    starvation when multiple uploads run — see knowledge-base/smb-credit-starvation.md).

    Returns (success: bool, message: str).
    """
    smb_cfg = cfg.get("nvr", {}).get("smb", {})
    host = smb_cfg.get("host", "").strip()
    share = smb_cfg.get("share", "").strip()
    username = smb_cfg.get("username", "").strip()
    password = smb_cfg.get("password", "").strip()
    remote_path = smb_cfg.get("path", "").strip().lstrip("/\\")

    if not host:
        return False, t("nvr.upload.not_configured")

    try:
        import smbclient
    except ImportError:
        return False, t("err.smb.library_missing")

    fname = os.path.basename(clip_path)
    # Build remote directory path inside the share
    remote_dir_parts = [f"\\\\{host}\\{share}"]
    if remote_path:
        remote_dir_parts.append(remote_path.replace("/", "\\"))
    remote_dir = "\\".join(remote_dir_parts)
    remote_file = remote_dir + "\\" + fname

    # Fresh connection_cache per upload — prevents credit starvation
    conn_cache: dict[str, Any] = {}

    t_start = time.time()
    try:
        # Ensure remote directory exists
        smbclient.makedirs(
            remote_dir,
            username=username,
            password=password,
            connection_cache=conn_cache,
            exist_ok=True,
        )
        file_size = os.path.getsize(clip_path)
        with open(clip_path, "rb") as local_f:
            with smbclient.open_file(
                remote_file,
                mode="wb",
                username=username,
                password=password,
                connection_cache=conn_cache,
            ) as remote_f:
                shutil.copyfileobj(local_f, remote_f)

        duration_secs = round(time.time() - t_start, 1)
        return True, t(
            "nvr.upload.success",
            bytes=file_size,
            duration_secs=duration_secs,
        )
    except Exception as exc:
        return False, t("nvr.upload.failed", reason=str(exc))
    finally:
        # Explicitly close connection to release SMB credits
        try:
            smbclient.reset_connection_cache(connection_cache=conn_cache)
        except Exception:
            pass


# ── NVR state (in-process; resets on restart) ────────────────────────────────
# Maps camera name → active Popen (None if not recording)
_nvr_active: dict[str, Optional["subprocess.Popen[bytes]"]] = {}
_nvr_start_times: dict[str, float] = {}  # camera name → epoch when recording started


def _nvr_is_recording(cam_name: str) -> bool:
    proc = _nvr_active.get(cam_name)
    return proc is not None and proc.poll() is None


def _nvr_recording_duration(cam_name: str) -> int:
    """Seconds since this camera's recording started (0 if not recording)."""
    if not _nvr_is_recording(cam_name):
        return 0
    return int(time.time() - _nvr_start_times.get(cam_name, time.time()))


# ── NVR sub-command handlers ──────────────────────────────────────────────────


def _cmd_nvr_status(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    cam_arg = getattr(args, "cam", None)
    cams = resolve_cam(cfg, cam_arg)
    base_dir = BASE_DIR
    for name in cams:
        clips = _nvr_all_clips(name, base_dir)
        disk_mb = round(_nvr_disk_mb(name, base_dir), 1)
        print(t("nvr.status.summary", camera=name, clip_count=len(clips), disk_mb=disk_mb))
        if _nvr_is_recording(name):
            dur = _nvr_recording_duration(name)
            print(t("nvr.status.recording", camera=name, duration_secs=dur))


def _cmd_nvr_list(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    cam_arg = getattr(args, "cam", None)
    limit = getattr(args, "limit", 20) or 20
    cams = resolve_cam(cfg, cam_arg)
    for name in cams:
        clips = _nvr_all_clips(name)
        clips_to_show = clips[-limit:][::-1]  # newest first
        print(f"\n  {name}: {len(clips)} clip(s) total\n")
        for p in clips_to_show:
            try:
                size_kb = round(os.path.getsize(p) / 1024, 1)
            except OSError:
                size_kb = 0.0
            print(f"    {p}  ({size_kb} KB)")


def _cmd_nvr_prune(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    cam_arg = getattr(args, "cam", None)
    keep = getattr(args, "keep", None)
    if keep is None:
        keep = cfg.get("nvr", {}).get("max_clips", _NVR_DEFAULT_MAX_CLIPS)
    cams = resolve_cam(cfg, cam_arg)
    for name in cams:
        removed, kept = _nvr_prune(name, keep=keep)
        print(t("nvr.prune.done", camera=name, removed=removed, kept=kept))


def _cmd_nvr_upload(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    smb_cfg = cfg.get("nvr", {}).get("smb", {})
    host = smb_cfg.get("host", "").strip()
    if not host:
        print(t("nvr.upload.not_configured"))
        return

    cam_arg = getattr(args, "cam", None)
    clip_arg = getattr(args, "clip", None)
    delete_after = smb_cfg.get("delete_after_upload", False)

    if clip_arg:
        clips_to_upload = [clip_arg]
    else:
        cams = resolve_cam(cfg, cam_arg)
        clips_to_upload = []
        for name in cams:
            clips_to_upload.extend(_nvr_all_clips(name))

    if not clips_to_upload:
        print("  [NVR] No clips to upload.")
        return

    share = smb_cfg.get("share", "")
    for clip_path in clips_to_upload:
        print(t("nvr.upload.started", path=clip_path, host=host, share=share))
        ok, msg = _nvr_smb_upload(clip_path, cfg)
        print(f"  {msg}")
        if ok and delete_after:
            try:
                os.remove(clip_path)
            except OSError:
                pass


def cmd_nvr(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """BETA: Mini-NVR sub-command dispatcher (status / list / prune / upload)."""
    sub = getattr(args, "nvr_sub", None)
    handlers = {
        "status": _cmd_nvr_status,
        "list": _cmd_nvr_list,
        "prune": _cmd_nvr_prune,
        "upload": _cmd_nvr_upload,
    }
    if sub not in handlers:
        print(t("help.nvr.subcommand"))
        print("  Subcommands: status | list | prune | upload")
        return
    handlers[sub](cfg, args)


def cmd_watch(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """
    Watch for new camera events by polling GET /v11/events every N seconds.

    Usage:
      python3 bosch_camera.py watch [<cam-name>] [--interval N] [--duration N]

    Polls every --interval seconds (default 30). Runs until Ctrl+C or --duration
    seconds elapsed. Prints each new event with type, timestamp, image URL and
    clip URL.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))
    interval = getattr(args, "interval", 30) or 30
    duration = getattr(args, "duration", 0) or 0
    auto_snap = getattr(args, "snapshot", False)
    use_push = getattr(args, "push", False)
    signal_url = getattr(args, "signal", "") or ""
    signal_sender = getattr(args, "signal_sender", "") or ""
    signal_recipients_str = getattr(args, "signal_recipients", "") or ""
    signal_recipients = (
        [r.strip() for r in signal_recipients_str.split(",") if r.strip()]
        if signal_recipients_str
        else []
    )
    webhook_url: str = (getattr(args, "webhook", "") or "").strip()

    # Motion edge tracking flags
    quiet_secs: int = getattr(args, "quiet_secs", 30) or 30
    motion_auto_snap: bool = getattr(args, "auto_snapshot", False)
    auto_record: bool = getattr(args, "auto_record", False)
    track_motion: bool = getattr(args, "track_motion", False) or motion_auto_snap or auto_record

    # NVR config (used when auto_record=True)
    nvr_cfg = cfg.get("nvr", {})
    nvr_max_clips = nvr_cfg.get("max_clips", _NVR_DEFAULT_MAX_CLIPS)
    # --nvr-segment-seconds CLI flag > nvr.segment_seconds config (opt-in, never
    # auto-injected into an existing config — see DEFAULT_CONFIG's nvr._note) >
    # nvr.max_duration config (the persisted default key) > built-in default.
    # `is not None` (not truthiness) throughout: an explicit 0 must be honored
    # as "user said 0", not silently treated as "unset" and skipped.
    cli_segment_seconds = getattr(args, "nvr_segment_seconds", None)
    if cli_segment_seconds is not None:
        nvr_segment_seconds = cli_segment_seconds
    else:
        nvr_segment_seconds = nvr_cfg.get("segment_seconds")
        if nvr_segment_seconds is None:
            nvr_segment_seconds = nvr_cfg.get("max_duration")
    # ffmpeg's -segment_time rejects 0/negative — clamp any such explicit or
    # unset value (including a config file with max_duration: 0) to the
    # built-in default rather than handing ffmpeg an invalid argument.
    if not nvr_segment_seconds or nvr_segment_seconds <= 0:
        nvr_segment_seconds = _NVR_DEFAULT_SEGMENT_SECONDS

    # One MotionEdgeTracker per camera (keyed by camera name)
    motion_trackers: dict[str, MotionEdgeTracker] = {}
    # Timestamp of rising edge (per camera) — used to compute duration on falling edge
    motion_rise_time: dict[str, float] = {}
    if track_motion:
        for cam_name in cams:
            motion_trackers[cam_name] = MotionEdgeTracker(quiet_secs=quiet_secs)

    if signal_url:
        print(
            f"  📨  Signal alerts → {signal_url} (sender={signal_sender}, recipients={signal_recipients})"
        )

    push_mode = getattr(args, "push_mode", "auto")
    # Back-compat: --push-mode android/ios accepted but treated as auto (iOS path removed in v10.7.1)
    if push_mode in ("android", "ios"):
        import sys as _sys

        print(f"WARNING: --push-mode {push_mode} is deprecated, treating as auto", file=_sys.stderr)
        push_mode = "auto"

    if use_push:
        push_succeeded = False

        if push_mode == "polling":
            modes_to_try = []  # skip FCM, go straight to polling
        else:  # auto: single Android attempt (Sebastian-OSS-sanctioned key handles all platforms)
            modes_to_try = [("Android", FCM_APP_ID, _get_fcm_api_key)]

        for label, app_id, key_fn in modes_to_try:
            try:
                _watch_fcm_push(
                    cfg,
                    token,
                    cams,
                    duration,
                    auto_snap,
                    signal_url,
                    signal_sender,
                    signal_recipients,
                    fcm_app_id=app_id,
                    fcm_api_key=key_fn(),
                    mode_label=label,
                )
                push_succeeded = True
                break
            except Exception as e:
                print(f"\n  ⚠️  {label} FCM failed: {e}")

        if push_succeeded:
            return

        if push_mode != "polling":
            print("  🔄  FCM failed — falling back to standard API polling...")
        # Fall through to polling code below

    # Build initial baseline of seen event IDs per camera
    last_seen: dict[str, str] = {}
    print("\n  Fetching baseline events...")
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
        print("  --snapshot: will auto-download and open event JPEG on new events.")
    print()

    start_time = time.time()
    total_new = 0

    def _renew_session() -> tuple[str, requests.Session]:
        # With cached module-level session, this only refreshes the Bearer token
        # on the shared Session object — no new connection pool is created.
        t = get_token(cfg)
        s = make_session(t)
        return t, s

    _install_stop_handlers()

    try:
        while not _STOP_REQUESTED.is_set():
            if duration and (time.time() - start_time) >= duration:
                print(f"\n  Duration of {duration}s reached — stopping.")
                break

            # Sleep in short slices so SIGTERM/SIGINT is honored promptly.
            slept = 0.0
            while slept < interval and not _STOP_REQUESTED.is_set():
                time.sleep(min(1.0, interval - slept))
                slept += 1.0
            if _STOP_REQUESTED.is_set():
                break

            now_str = datetime.datetime.now().strftime("%H:%M:%S")

            # Pre-emptive token refresh: renew before the token expires
            # rather than waiting for a 401 response.
            if _is_token_near_expiry(token):
                token, session = _renew_session()

            for name, cam_info in cams.items():
                cam_id = cam_info["id"]

                # Fetch latest events; retry once on 401
                try:
                    events = api_get_events(session, cam_id, limit=20)
                except Exception as e:
                    print(f"  [warn] event fetch failed for {name}: {e}", file=sys.stderr)
                    events = []

                if not events and session.headers.get("Authorization", ""):
                    # Possibly 401 — try renewing
                    try:
                        token, session = _renew_session()
                        events = api_get_events(session, cam_id, limit=20)
                    except Exception as e:
                        print(
                            f"  [warn] event re-fetch after renew failed for {name}: {e}",
                            file=sys.stderr,
                        )
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
                    etype = _effective_event_type(ev)
                    ts = ev.get("timestamp", "")[:19]
                    img_url = ev.get("imageUrl", "")
                    clip_url = ev.get("videoClipUrl", "")
                    type_icon = "🔊" if "AUDIO" in etype else ("👤" if etype == "PERSON" else "🚨")
                    print(f"  [{now_str}] {type_icon} {etype:<15s}  cam={name:<12s}  {ts}")
                    if img_url:
                        print(f"             📸 {img_url}")
                    if clip_url:
                        print(f"             🎬 {clip_url}")
                    total_new += 1
                    # Signal alert
                    if signal_url and signal_sender and signal_recipients:
                        _send_signal_alert(
                            signal_url,
                            signal_sender,
                            signal_recipients,
                            name,
                            etype,
                            ts,
                            img_url,
                            token,
                        )
                    # Webhook delivery
                    if webhook_url:
                        _post_event_webhook(webhook_url, name, cam_id, etype, ts, ev)
                    # Auto-download and open the event snapshot if requested
                    if auto_snap and img_url and _is_safe_bosch_url(img_url):
                        try:
                            r = session.get(img_url, timeout=15)
                            if r.status_code == 200 and "image" in r.headers.get(
                                "Content-Type", ""
                            ):
                                fname = f"event_{name}_{ts.replace(':', '-').replace(' ', '_')}.jpg"
                                fpath = os.path.join(BASE_DIR, fname)
                                with open(fpath, "wb") as f:
                                    f.write(r.content)
                                print(f"             💾 Saved: {fpath}")
                                open_file(fpath)
                            else:
                                print(
                                    f"             ⚠️  Could not download snapshot (HTTP {r.status_code})"
                                )
                        except Exception as snap_err:
                            print(f"             ⚠️  Snapshot download error: {snap_err}")

                if new_events:
                    last_seen[name] = new_events[0].get("id", baseline)
                    # Mark new events as read on the Bosch cloud
                    read_ids = [ev.get("id") for ev in new_events if ev.get("id")]
                    if read_ids:
                        try:
                            api_mark_events_read(session, read_ids)
                        except Exception:
                            pass

                # ── Motion edge tracking ───────────────────────────────────
                # Called every poll iteration (new_events may be []) so that
                # the hysteresis timer fires even when no events arrive.
                if track_motion and name in motion_trackers:
                    tracker = motion_trackers[name]
                    edge = tracker.update(new_events)
                    if edge == "rising":
                        ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        motion_rise_time[name] = time.time()
                        print(t("watch.motion.rising", camera=name, timestamp=ts_now))
                        # Auto-record on rising edge (BETA)
                        if auto_record and not _nvr_is_recording(name):
                            proc = _start_motion_recording(
                                cam_info,
                                segment_seconds=nvr_segment_seconds,
                            )
                            if proc is not None:
                                out_pattern = getattr(proc, "_nvr_out_pattern", "?")
                                _nvr_active[name] = proc
                                _nvr_start_times[name] = time.time()
                                print(t("nvr.recording.started", camera=name, path=out_pattern))
                            else:
                                print(
                                    t(
                                        "nvr.recording.failed",
                                        camera=name,
                                        reason="ffmpeg not found or no RTSP URL",
                                    )
                                )
                        # Auto-snapshot on rising edge
                        if motion_auto_snap:
                            snap_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                            snap_dir = _motion_snapshot_dir(name)
                            snap_path = os.path.join(snap_dir, f"motion_{snap_ts}.jpg")
                            snap_data: Optional[bytes] = None
                            try:
                                snap_data = snap_from_proxy(
                                    cam_info, token, hq=False, cfg=cfg, session=session
                                )
                            except Exception:
                                pass
                            if snap_data is None:
                                try:
                                    snap_data = snap_from_local(cam_info, cfg=cfg)
                                except Exception:
                                    pass
                            if snap_data:
                                try:
                                    with open(snap_path, "wb") as _sf:
                                        _sf.write(snap_data)
                                    print(t("watch.motion.snapshot_saved", path=snap_path))
                                    _motion_snapshot_cleanup(name)
                                except Exception as _se:
                                    print(t("watch.motion.snapshot_failed", reason=str(_se)))
                            else:
                                print(t("watch.motion.snapshot_failed", reason="no image data"))
                    elif edge == "falling":
                        rise_t = motion_rise_time.pop(name, time.time())
                        duration_secs = int(time.time() - rise_t)
                        print(t("watch.motion.falling", camera=name, duration_secs=duration_secs))
                        # Stop NVR recording on falling edge (BETA)
                        if auto_record and _nvr_is_recording(name):
                            proc = _nvr_active.pop(name, None)
                            if proc is not None:
                                proc.terminate()
                                try:
                                    proc.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    proc.kill()
                                clip_dir = getattr(proc, "_nvr_clip_dir", "")
                                session_start = _nvr_start_times.get(name, time.time())
                                session_clips = _nvr_session_clips(clip_dir, session_start)
                                clip_bytes = 0
                                for _cp in session_clips:
                                    try:
                                        clip_bytes += os.path.getsize(_cp)
                                    except OSError:
                                        pass
                                print(
                                    t(
                                        "nvr.recording.stopped",
                                        camera=name,
                                        duration_secs=duration_secs,
                                        bytes=clip_bytes,
                                    )
                                )
                                # Auto-upload if SMB configured — one or more
                                # segment clips may have been produced this
                                # session if motion outlasted one segment.
                                # IMPORTANT: upload BEFORE prune. A single long
                                # motion session can easily emit more segments
                                # than nvr.max_clips (unlike the old
                                # single-file-per-session cap) — pruning first
                                # would delete this session's own clips before
                                # they ever got uploaded.
                                smb_host = cfg.get("nvr", {}).get("smb", {}).get("host", "").strip()
                                if smb_host and session_clips:
                                    smb_share = cfg.get("nvr", {}).get("smb", {}).get("share", "")
                                    delete_after = (
                                        cfg.get("nvr", {})
                                        .get("smb", {})
                                        .get("delete_after_upload", False)
                                    )
                                    for clip_path in session_clips:
                                        print(
                                            t(
                                                "nvr.upload.started",
                                                path=clip_path,
                                                host=smb_host,
                                                share=smb_share,
                                            )
                                        )
                                        ok, msg = _nvr_smb_upload(clip_path, cfg)
                                        print(f"  {msg}")
                                        if ok and delete_after:
                                            try:
                                                os.remove(clip_path)
                                            except OSError:
                                                pass
                                # FIFO prune after upload — see the comment above
                                # the upload block for why this must run last.
                                _nvr_prune(name, keep=nvr_max_clips)

    except KeyboardInterrupt:
        elapsed = int(time.time() - start_time)
        print(f"\n\n  Stopped after {elapsed}s. Total new events seen: {total_new}")


def cmd_intercom(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """
    Open a two-way audio (intercom) session to a camera.

    Usage:
      python3 bosch_camera.py intercom <cam-name> [--duration N] [--speaker-level N]

    Opens a media tunnel to the camera for push-to-talk audio.
    Requires: pip install pyaudio

    API flow:
      1. PUT /v11/video_inputs/{id}/connection -> get proxy URL
      2. Open TCP+TLS socket to proxy for bidirectional audio
      3. Capture microphone -> send to camera speaker
      4. Camera audio -> play on local speakers
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))
    duration = getattr(args, "duration", 60) or 60
    speaker_level = getattr(args, "speaker_level", 50) or 50

    if len(cams) != 1:
        print("  ❌  Intercom requires exactly one camera. Specify the camera name.")
        return

    cam_name, cam_info = next(iter(cams.items()))
    cam_id = cam_info["id"]

    print(f"\n── Intercom: {cam_name} ──────────────────────────────────────")

    # Step 1: Set speaker level — GET current audio state first, then full-body PUT
    # (Bosch /audio is a full-body endpoint; partial PUT can reset omitted fields)
    print(f"  🔊  Setting speaker level to {speaker_level}%...")
    rg = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/audio", timeout=10)
    if rg.status_code == 442:
        print("  ⚠️  Audio settings not supported on this camera model (HTTP 442)")
    elif rg.status_code != 200:
        print(f"  ⚠️  Could not fetch current audio state: HTTP {rg.status_code}")
    else:
        cur_audio = rg.json()
        cur_enabled = cur_audio.get("audioEnabled", cur_audio.get("enabled", True))
        cur_mic = cur_audio.get("microphoneLevel", cur_audio.get("MicrophoneLevel", 50))
        r = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/audio",
            json={
                "audioEnabled": cur_enabled,
                "microphoneLevel": cur_mic,
                "speakerLevel": speaker_level,
            },
            timeout=10,
        )
        if r.status_code in (200, 201, 204):
            print(f"  ✅  Speaker level set to {speaker_level}%")
        elif r.status_code == 442:
            print("  ⚠️  Audio settings not supported on this camera model (HTTP 442)")
        else:
            print(f"  ⚠️  Could not set speaker level: HTTP {r.status_code}")

    # Step 2: Open live connection with audio enabled
    print("  📡  Opening live connection with audio...")
    conn_data = None
    for conn_type in LIVE_TYPE_CANDIDATES:
        try:
            r = session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
                json={"type": conn_type, "highQualityVideo": False},
                timeout=10,
            )
            if r.status_code in (200, 201):
                conn_data = r.json()
                break
        except Exception:
            continue

    if not conn_data or not conn_data.get("urls"):
        print("  ❌  Could not open live connection for intercom.")
        return

    proxy_url = conn_data["urls"][0]
    proxy_host = proxy_url.split("/")[0].replace(":42090", "")
    proxy_hash = proxy_url.split("/", 1)[1] if "/" in proxy_url else ""

    # Build RTSPS URL with audio enabled
    rtsps_url = f"rtsps://{proxy_host}:443/{proxy_hash}/rtsp_tunnel?inst=2&enableaudio=1&fmtp=1&maxSessionDuration={duration}"

    print("  ✅  Connection established!")
    print(f"  🎤  Intercom session ({duration}s)")
    print(f"  🔗  Audio stream: {rtsps_url}")
    print()

    # Step 3: Use ffmpeg for bidirectional audio
    # Listen: RTSPS stream -> local speakers
    # Talk: local microphone -> not yet supported via cloud API (requires media tunnel)
    print("  📻  Starting audio playback from camera...")
    print("      (Two-way talk requires direct media tunnel — listen-only via RTSPS)")
    print("      Press Ctrl+C to stop.\n")

    # Use ffplay for audio playback
    ffplay = shutil.which("ffplay")
    if not ffplay:
        print("  ❌  ffplay not found. Install ffmpeg to use intercom.")
        print("      brew install ffmpeg")
        return

    try:
        proc = subprocess.Popen(
            [
                ffplay,
                "-nodisp",  # no video window
                "-rtsp_transport",
                "tcp",
                "-fflags",
                "nobuffer",
                "-flags",
                "low_delay",
                "-analyzeduration",
                "500000",
                "-probesize",
                "32768",
                rtsps_url,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  🔊  Playing camera audio (PID {proc.pid})...")
        print("      Ctrl+C to stop.")
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
        print(f"\n  ⏱️  Duration of {duration}s reached.")
    except KeyboardInterrupt:
        proc.terminate()
        print("\n  ⏹️  Intercom stopped.")
    except Exception as e:
        print(f"  ❌  Intercom error: {e}")


def cmd_maintenance(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show the current Bosch cloud maintenance / outage status.

    Fetches the community RSS feeds and prints the best-match announcement.
    Use --json to emit a machine-readable JSON blob for scripting.

    Usage:
      python3 bosch_camera.py maintenance
      python3 bosch_camera.py maintenance --json
    """
    import json as _json

    emit_json: bool = getattr(args, "json", False)

    print(t("cmd.maintenance.header"))
    mw: MaintenanceWindow | None = fetch_maintenance(timeout_s=8.0)

    if mw is None:
        if emit_json:
            print(_json.dumps(None))
        else:
            print(t("cmd.maintenance.fetch_failed"))
        return

    if emit_json:
        print(_json.dumps(mw.as_dict(), ensure_ascii=False, indent=2))
        return

    state = mw.state()
    fmt = "%Y-%m-%d %H:%M UTC"
    start_str = mw.scheduled_start.strftime(fmt) if mw.scheduled_start else ""
    end_str = mw.scheduled_end.strftime(fmt) if mw.scheduled_end else ""

    if state == "active":
        print(t("cmd.maintenance.active", start=start_str, end=end_str))
    elif state == "scheduled":
        print(t("cmd.maintenance.scheduled", start=start_str, end=end_str))
    elif state == "past":
        print(t("cmd.maintenance.past", end=end_str))
    elif state == "recent":
        print(t("cmd.maintenance.recent", title=mw.title))
    else:
        print(t("cmd.maintenance.unknown", title=mw.title))

    print(t("cmd.maintenance.title", title=mw.title))
    if mw.summary:
        print(t("cmd.maintenance.summary", summary=mw.summary))
    if mw.camera_relevant:
        print(t("cmd.maintenance.camera_relevant"))
    if mw.link:
        print(t("cmd.maintenance.link", link=mw.link))
    print()


def cmd_motion(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))
    enable = getattr(args, "enable", False)
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
        data = r.json()
        current_enabled = data.get("enabled", False)
        current_sens = data.get("motionAlarmConfiguration", data.get("sensitivity", "UNKNOWN"))

        enabled_str = "ENABLED" if current_enabled else "DISABLED"
        icon = "✅" if current_enabled else "❌"
        print(f"  {icon}  Motion: {enabled_str}  Sensitivity: {current_sens}")

        if not enable and not disable and not sensitivity:
            print("\n  Run with --enable / --disable / --sensitivity to change.")
            print(
                f"  E.g.: python3 bosch_camera.py motion {name.lower()} --enable --sensitivity SUPER_HIGH"
            )
            continue

        # Build PUT body
        new_enabled = current_enabled
        new_sens = current_sens
        if enable:
            new_enabled = True
        if disable:
            new_enabled = False
        if sensitivity:
            new_sens = sensitivity
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
            icon_new = "✅" if new_enabled else "❌"
            print(f"  {icon_new}  Motion {state_str}  Sensitivity: {new_sens}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_recording(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """
    Get or set cloud recording options.

    Usage:
      python3 bosch_camera.py recording [<cam>]                 # show current
      python3 bosch_camera.py recording [<cam>] --sound-on      # include audio
      python3 bosch_camera.py recording [<cam>] --sound-off     # exclude audio

    API: GET/PUT /v11/video_inputs/{id}/recording_options
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))
    sound_on = getattr(args, "sound_on", False)
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
        data = r.json()
        current_sound = data.get("recordSound", False)

        sound_str = "ON" if current_sound else "OFF"
        icon = "🔊" if current_sound else "🔇"
        print(f"  {icon}  Record Sound: {sound_str}")

        if not sound_on and not sound_off:
            print("\n  Run with --sound-on or --sound-off to change.")
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
            icon_new = "🔊" if new_sound else "🔇"
            print(f"  {icon_new}  Record Sound: {state_str}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_audio(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Get or set microphone and speaker levels for a camera.

    Usage:
      python3 bosch_camera.py audio [<cam>]                  # show current levels
      python3 bosch_camera.py audio [<cam>] --mic N          # set mic level 0-100
      python3 bosch_camera.py audio [<cam>] --speaker N      # set speaker level 0-100
      python3 bosch_camera.py audio [<cam>] --json           # machine-readable output

    API: GET/PUT /v11/video_inputs/{id}/audio
         Body: {"audioEnabled": bool, "microphoneLevel": 0-100, "speakerLevel": 0-100}
    Source: captures/api-findings.md §6.2 (verified 2026-04)
    """
    import json as _json_mod

    token = get_token(cfg)
    session = make_session(token)
    _cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    mic = getattr(args, "mic", None)
    speaker = getattr(args, "speaker", None)
    as_json = getattr(args, "json", False)

    cams = resolve_cam(cfg, cam_arg)
    results: list[dict[str, Any]] = []

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/audio", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 442:
            if not as_json:
                print(f"\n── Audio: {name} ────────────────────────────────────────────")
                print("  ⚠️   Audio settings not supported on this camera model (HTTP 442)")
            results.append({"cam": name, "error": "not_supported"})
            continue
        if r.status_code != 200:
            if not as_json:
                print(f"\n── Audio: {name} ────────────────────────────────────────────")
                print(f"  ❌  Could not fetch audio settings: HTTP {r.status_code}")
            results.append({"cam": name, "error": f"http_{r.status_code}"})
            continue

        data = r.json()
        enabled = data.get("audioEnabled", data.get("enabled", False))
        mic_lvl = data.get("microphoneLevel", data.get("MicrophoneLevel", 50))
        spk_lvl = data.get("speakerLevel", data.get("SpeakerLevel", 50))

        entry: dict[str, Any] = {
            "cam": name,
            "audioEnabled": enabled,
            "microphoneLevel": mic_lvl,
            "speakerLevel": spk_lvl,
        }

        if not as_json:
            print(f"\n── Audio: {name} ────────────────────────────────────────────")
            icon = "🔊" if enabled else "🔇"
            print(f"  {icon}  Enabled: {'YES' if enabled else 'NO'}")
            print(f"       Microphone level:  {mic_lvl}")
            print(f"       Speaker level:     {spk_lvl}")

        if mic is None and speaker is None:
            if not as_json:
                print("\n  Run with --mic N / --speaker N (0-100) to change. E.g.:")
                print(f"    python3 bosch_camera.py audio {name.lower()} --mic 60 --speaker 80")
            results.append(entry)
            continue

        # Validate ranges
        if mic is not None and not (0 <= mic <= 100):
            print(f"  ❌  --mic must be 0-100, got {mic}")
            return
        if speaker is not None and not (0 <= speaker <= 100):
            print(f"  ❌  --speaker must be 0-100, got {speaker}")
            return

        new_mic = mic if mic is not None else mic_lvl
        new_spk = speaker if speaker is not None else spk_lvl
        body = {"audioEnabled": enabled, "microphoneLevel": new_mic, "speakerLevel": new_spk}

        if not as_json:
            print(f"  🔄  Setting audio → mic={new_mic}  speaker={new_spk}...")

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/audio",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            if not as_json:
                print(f"  ✅  Microphone level: {new_mic}  Speaker level: {new_spk}")
            entry.update({"microphoneLevel": new_mic, "speakerLevel": new_spk})
        else:
            if not as_json:
                print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")
            entry["error"] = f"put_http_{pr.status_code}"

        results.append(entry)

    if as_json:
        print(_json_mod.dumps(results, indent=2))


def cmd_intrusion(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Get or set intrusion detection configuration.

    Usage:
      python3 bosch_camera.py intrusion [<cam>]                     # show current config
      python3 bosch_camera.py intrusion [<cam>] --mode indoor|outdoor
      python3 bosch_camera.py intrusion [<cam>] --sensitivity 0-7
      python3 bosch_camera.py intrusion [<cam>] --distance 1-8
      python3 bosch_camera.py intrusion [<cam>] --json              # machine-readable output

    API: GET/PUT /v11/video_inputs/{id}/intrusionDetectionConfig
         Body: {"enabled": bool, "detectionMode": str, "sensitivity": 0-7, "distance": 1-8}
    Source: captures/api-findings.md §6.2 (verified 2026-04); sensitivity range extended 0-7 in 2026.
    """
    import json as _json_mod

    token = get_token(cfg)
    session = make_session(token)
    _cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    mode = getattr(args, "mode", None)
    sens = getattr(args, "sensitivity", None)
    dist = getattr(args, "distance", None)
    as_json = getattr(args, "json", False)

    cams = resolve_cam(cfg, cam_arg)
    results: list[dict[str, Any]] = []

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]

        r = session.get(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/intrusionDetectionConfig", timeout=10
        )
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 442:
            if not as_json:
                print(f"\n── Intrusion Detection: {name} ─────────────────────────────────")
                print("  ⚠️   Intrusion detection not supported on this camera model (HTTP 442)")
            results.append({"cam": name, "error": "not_supported"})
            continue
        if r.status_code != 200:
            if not as_json:
                print(f"\n── Intrusion Detection: {name} ─────────────────────────────────")
                print(f"  ❌  Could not fetch intrusion config: HTTP {r.status_code}")
            results.append({"cam": name, "error": f"http_{r.status_code}"})
            continue

        data = r.json()
        enabled = data.get("enabled", False)
        det_mode = data.get("detectionMode", "UNKNOWN")
        cur_sens = data.get("sensitivity", 3)
        cur_dist = data.get("distance", 5)

        entry: dict[str, Any] = {
            "cam": name,
            "enabled": enabled,
            "detectionMode": det_mode,
            "sensitivity": cur_sens,
            "distance": cur_dist,
        }

        if not as_json:
            print(f"\n── Intrusion Detection: {name} ─────────────────────────────────")
            icon = "✅" if enabled else "❌"
            print(f"  {icon}  Enabled: {'YES' if enabled else 'NO'}")
            print(f"       Detection mode:   {det_mode}")
            print(f"       Sensitivity:      {cur_sens}  (0-7)")
            print(f"       Distance:         {cur_dist}  (1-8)")

        if mode is None and sens is None and dist is None:
            if not as_json:
                print("\n  Run with --mode / --sensitivity / --distance to change. E.g.:")
                print(
                    f"    python3 bosch_camera.py intrusion {name.lower()} --mode indoor --sensitivity 4"
                )
            results.append(entry)
            continue

        # Validate
        if mode is not None and mode.lower() not in ("indoor", "outdoor"):
            # also accept raw API values
            if mode not in ("ALL_MOTIONS", "ZONES"):
                print(f"  ❌  --mode must be indoor or outdoor, got '{mode}'")
                return
        if sens is not None and not (0 <= sens <= 7):
            print(f"  ❌  --sensitivity must be 0-7, got {sens}")
            return
        if dist is not None and not (1 <= dist <= 8):
            print(f"  ❌  --distance must be 1-8, got {dist}")
            return

        MODE_MAP = {"indoor": "ALL_MOTIONS", "outdoor": "ZONES"}
        new_mode = MODE_MAP.get((mode or "").lower(), mode) if mode else det_mode
        new_sens = sens if sens is not None else cur_sens
        new_dist = dist if dist is not None else cur_dist
        body = {
            "enabled": enabled,
            "detectionMode": new_mode,
            "sensitivity": new_sens,
            "distance": new_dist,
        }

        if not as_json:
            print(
                f"  🔄  Setting intrusion → mode={new_mode}  sensitivity={new_sens}  distance={new_dist}..."
            )

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/intrusionDetectionConfig",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            if not as_json:
                print(f"  ✅  Mode: {new_mode}  Sensitivity: {new_sens}  Distance: {new_dist}")
            entry.update({"detectionMode": new_mode, "sensitivity": new_sens, "distance": new_dist})
        else:
            if not as_json:
                print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")
            entry["error"] = f"put_http_{pr.status_code}"

        results.append(entry)

    if as_json:
        print(_json_mod.dumps(results, indent=2))


def cmd_wifi(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show WiFi info (RSSI, SSID, signal strength) for cameras.

    Usage:
      python3 bosch_camera.py wifi [<cam>]        # show for all or one camera
      python3 bosch_camera.py wifi [<cam>] --json # machine-readable output

    API: GET /v11/video_inputs/{id}/wifiinfo
    Source: captures/api-findings.md §5 (wifiinfo in top-frequency endpoint list)
    """
    import json as _json_mod

    token = get_token(cfg)
    session = make_session(token)
    _cameras = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    as_json = getattr(args, "json", False)

    cams = resolve_cam(cfg, cam_arg)
    results: list[dict[str, Any]] = []

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/wifiinfo", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 442:
            if not as_json:
                print(f"  {name:<20}  WiFi not available (HTTP 442 — camera may be wired)")
            results.append({"cam": name, "error": "not_supported"})
            continue
        if r.status_code != 200:
            if not as_json:
                print(f"  {name:<20}  ❌  HTTP {r.status_code}")
            results.append({"cam": name, "error": f"http_{r.status_code}"})
            continue

        data = r.json()
        ssid = data.get("ssid", data.get("SSID", "?"))
        rssi = data.get("rssi", data.get("RSSI", data.get("signalLevel", None)))
        signal = data.get("signalStrength", data.get("signal", None))
        ip_w = data.get("ipAddress", data.get("ip", "?"))
        mac_w = data.get("macAddress", data.get("mac", "?"))

        entry: dict[str, Any] = {
            "cam": name,
            "ssid": ssid,
            "rssi_dbm": rssi,
            "signal_pct": signal,
            "ip": ip_w,
            "mac": mac_w,
        }
        results.append(entry)

        if not as_json:
            rssi_str = f"{rssi} dBm" if rssi is not None else "?"
            signal_str = (
                f"{signal}%" if isinstance(signal, int) else (str(signal) if signal else "?")
            )
            icon = "📶" if signal is not None and isinstance(signal, int) and signal >= 50 else "📉"
            print(
                f"  {icon}  {name:<20}  SSID: {ssid:<24}  RSSI: {rssi_str:<12}  Signal: {signal_str}"
            )

    if as_json:
        print(_json_mod.dumps(results, indent=2))


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


def rcp_open_connection(cam_id: str, token: str) -> tuple[str, str]:
    """
    Open a REMOTE proxy connection for the given camera.
    Returns (proxy_base_url, proxy_hash_path) where:
      proxy_base_url = 'https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}'
    Raises RuntimeError on failure.

    NOT migrated to bosch_rcp_client/bosch-shc-camera-client: this is a plain
    "PUT a JSON body, check status, read a field" cloud call with no
    RCP-protocol-specific logic to share, so reimplementing it against the
    library's async cloud_put_json() helper would add an asyncio.run()
    boundary without removing any duplicated protocol code. Left as the
    existing sync `requests_put_bosch_cloud` implementation.
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests_put_bosch_cloud(
        f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
        headers=headers,
        json={"type": "REMOTE", "highQualityVideo": False},
        timeout=15,
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


def rcp_session_cached(proxy_base: str) -> str:
    """Return a cached RCP session ID, performing the RCP handshake if missing or expired.

    Delegates to bosch_rcp_client (bosch-shc-camera-client library) for the
    2-step handshake (0xff0c HELLO + 0xff0d SESSION_INIT) and its 5-minute
    TTL cache -- avoids the handshake overhead when multiple RCP commands are
    called in sequence for the same camera within a session, same as before.

    Raises RuntimeError if the handshake fails. Unlike the CLI's previous
    hand-rolled implementation, the library does not distinguish *why* the
    handshake failed (HTTP error vs. malformed response vs. rejected
    session) in the exception message -- it logs the specific cause at DEBUG
    level internally and this wrapper only sees a final None/success.
    """
    session_id = bosch_rcp_client.get_session_id(proxy_base)
    if not session_id:
        raise RuntimeError(f"RCP session handshake failed for {proxy_base}")
    return session_id


def rcp_read(
    rcp_url: str, command: str, sessionid: str, type_: str = "P_OCTET", num: int = 0
) -> bytes | None:
    """
    Send an RCP READ request and return the raw result bytes.
    Returns None if the response is empty (len=0) or an error occurs.

    Args:
        rcp_url:   full URL to rcp.xml, e.g. https://proxy-NN:42090/{hash}/rcp.xml
        command:   hex command code, e.g. '0x0a0f'
        sessionid: session ID from rcp_session_cached()
        type_:     RCP type string, default 'P_OCTET'
        num:       instance number (0 = default)

    Delegates to bosch_rcp_client (bosch-shc-camera-client library).
    """
    return bosch_rcp_client.rcp_read(rcp_url, command, sessionid, type_=type_, num=num)


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
        word = data[i : i + 2]
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
        year = (data[0] << 8) | data[1]
        month = data[2]
        day = data[3]
        hour = data[4]
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


def _rcp_setup(cam_info: dict[str, Any], token: str) -> tuple[str, str]:
    """
    Open a REMOTE connection and perform RCP session handshake.
    Returns (rcp_url, sessionid).
    Prints status messages. Raises RuntimeError on failure.
    """
    cam_id = cam_info["id"]
    print("  🌐  Opening REMOTE proxy connection...")
    proxy_base, _ = rcp_open_connection(cam_id, token)
    print(f"  🔗  Proxy: {proxy_base}")
    print("  🤝  RCP session handshake (cached)...")
    sessionid = rcp_session_cached(proxy_base)
    print(f"  ✅  Session: {sessionid}")
    rcp_url = f"{proxy_base}/rcp.xml"
    return rcp_url, sessionid


def cmd_rcp(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub = (getattr(args, "sub", None) or "").lower()

    # Allow "rcp info" without a camera name (sub parsed as cam_arg)
    RCP_SUBS = (
        "info",
        "clock",
        "snapshot",
        "alarms",
        "privacy",
        "dimmer",
        "motion",
        "services",
        "frame",
        "script",
        "iva",
        "bitrate",
        "all",
    )
    if cam_arg and cam_arg.lower() in RCP_SUBS and not sub:
        sub, cam_arg = cam_arg.lower(), None

    if not sub:
        print("\n  ℹ️   Usage: python3 bosch_camera.py rcp [camera] <subcommand>")
        print(
            "  Subcommands: info | clock | snapshot | alarms | privacy | dimmer | motion | services | frame | script | iva | bitrate | all"
        )
        return

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        print(f"\n── RCP: {name} ({sub}) ─────────────────────────────────────────")

        try:
            rcp_url, sessionid = _rcp_setup(cam_info, token)
        except RuntimeError as e:
            print(f"  ❌  RCP setup failed: {e}")
            continue

        # ── info ──────────────────────────────────────────────────────────────
        if sub in ("info", "all"):
            print("\n  ── Identity ──────────────────────────────────────────────")
            # 0x0aea — product name (null-terminated ASCII)
            d = rcp_read(rcp_url, "0x0aea", sessionid)
            if d:
                print(f"  Product:    {rcp_parse_string(d)}")
            else:
                print("  Product:    (not available)")
            # 0x0aee — cloud FQDN
            d = rcp_read(rcp_url, "0x0aee", sessionid)
            if d:
                print(f"  Cloud FQDN: {rcp_parse_string(d)}")
            else:
                print("  Cloud FQDN: (not available)")
            # 0x0a36 — LAN IP (4-byte or string)
            d = rcp_read(rcp_url, "0x0a36", sessionid)
            if d:
                ip_str = rcp_parse_ip(d) if len(d) == 4 else rcp_parse_string(d)
                print(f"  LAN IP:     {ip_str}  (via RCP)")
            else:
                print("  LAN IP:     (not available)")
            # 0x0a30 — MAC address (6 bytes)
            d = rcp_read(rcp_url, "0x0a30", sessionid)
            if d and len(d) >= 6:
                mac_str = ":".join(f"{b:02x}" for b in d[:6])
                print(f"  MAC:        {mac_str}  (via RCP)")
            elif d:
                print(f"  MAC:        {rcp_parse_string(d)}")
            else:
                print("  MAC:        (not available)")

        # ── clock ─────────────────────────────────────────────────────────────
        if sub in ("clock", "all"):
            print("\n  ── Camera Clock ──────────────────────────────────────────")
            d = rcp_read(rcp_url, "0x0a0f", sessionid)
            if d:
                print(f"  Clock:      {rcp_parse_clock(d)}  (camera local time)")
                print(f"  Raw:        {d.hex()}")
            else:
                print("  Clock:      (not available)")

        # ── snapshot ──────────────────────────────────────────────────────────
        if sub in ("snapshot", "all"):
            print("\n  ── RCP Thumbnail Snapshot ────────────────────────────────")
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
                print("  Snapshot:   (not available)")

        # ── alarms ────────────────────────────────────────────────────────────
        if sub in ("alarms", "all"):
            print("\n  ── Alarm Catalog (0x0c38) ────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c38", sessionid)
            if d:
                strings = rcp_parse_utf16be_strings(d)
                if strings:
                    for i, s in enumerate(strings):
                        print(f"  [{i:02d}] {s}")
                else:
                    print(f"  (no strings decoded — raw {len(d)} bytes: {d[:32].hex()}...)")
            else:
                print("  Alarms:     (not available)")

        # ── privacy ───────────────────────────────────────────────────────────
        if sub in ("privacy", "all"):
            print("\n  ── Privacy Mask State (0x0d00) ───────────────────────────")
            d = rcp_read(rcp_url, "0x0d00", sessionid)
            if d and len(d) >= 1:
                state_byte = d[1] if len(d) > 1 else d[0]
                state_str = "ON (masked)" if state_byte else "OFF (visible)"
                icon = "🔒" if state_byte else "👁️"
                print(f"  {icon}  Privacy mask: {state_str}  (byte[1]={state_byte:#04x})")
                print(f"  Raw:          {d.hex()}")
            else:
                print("  Privacy:    (not available)")

        # ── dimmer ────────────────────────────────────────────────────────────
        if sub in ("dimmer", "all"):
            print("\n  ── LED Dimmer (0x0c22) ───────────────────────────────────")
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
                print("  Dimmer:     (not available)")

        # ── motion ────────────────────────────────────────────────────────────
        if sub in ("motion", "all"):
            print("\n  ── Motion Zones (0x0c0a) ─────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c0a", sessionid)
            if d:
                # Each zone is typically 8 bytes: x1(2B) y1(2B) x2(2B) y2(2B) in 0-10000 units
                zone_size = 8
                n_zones = len(d) // zone_size
                print(f"  Zones:      {n_zones} zone(s)  ({len(d)} bytes raw)")
                for z in range(n_zones):
                    chunk = d[z * zone_size : (z + 1) * zone_size]
                    if len(chunk) == 8:
                        x1 = (chunk[0] << 8) | chunk[1]
                        y1 = (chunk[2] << 8) | chunk[3]
                        x2 = (chunk[4] << 8) | chunk[5]
                        y2 = (chunk[6] << 8) | chunk[7]
                        print(f"  Zone {z}:     ({x1},{y1}) → ({x2},{y2})  [0-10000 coords]")
                    else:
                        print(f"  Zone {z}:     {chunk.hex()}")
            else:
                print("  Motion:     (not available)")

        # ── services ──────────────────────────────────────────────────────────
        if sub in ("services", "all"):
            print("\n  ── Network Services (0x0c62) ─────────────────────────────")
            d = rcp_read(rcp_url, "0x0c62", sessionid)
            if d:
                # Services list is typically null-terminated ASCII strings
                services = [
                    s for s in d.decode("ascii", errors="replace").split("\x00") if s.strip()
                ]
                if services:
                    for svc in services:
                        print(f"  Service:    {svc}")
                else:
                    print(f"  Services raw: {len(d)} bytes  {d[:48].hex()}")
            else:
                print("  Services:   (not available)")

        # ── frame ─────────────────────────────────────────────────────────────
        if sub in ("frame", "all"):
            print("\n  ── Raw Frame (0x0c98) ────────────────────────────────────")
            d = rcp_read(rcp_url, "0x0c98", sessionid)
            if d and len(d) == 115200:
                safe_name = name.replace(" ", "_")
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
                    print(
                        f"  Frame:      320x180 YUV422 ({len(d):,} bytes) -> saved as JPEG: {path}"
                    )
                    open_file(path)
                except Exception:
                    path = os.path.join(BASE_DIR, f"rcp_frame_{safe_name}.yuv")
                    with open(path, "wb") as f:
                        f.write(d)
                    print(
                        f"  Frame:      320x180 YUV422 ({len(d):,} bytes) -> saved as raw YUV: {path}"
                    )
                    print("  Note:       Install numpy + Pillow for JPEG conversion")
            elif d:
                safe_name = name.replace(" ", "_")
                path = os.path.join(BASE_DIR, f"rcp_frame_{safe_name}.bin")
                with open(path, "wb") as f:
                    f.write(d)
                print(f"  Frame:      {len(d):,} bytes (unexpected size — saved as .bin: {path})")
            else:
                print("  Frame:      (not available)")

        # ── script ────────────────────────────────────────────────────────────
        if sub in ("script", "all"):
            print("\n  ── IVA Automation Script (0x09f3) ────────────────────────")
            d = rcp_read(rcp_url, "0x09f3", sessionid)
            if d and d[:2] == b"\x1f\x8b":  # gzip magic
                import gzip

                try:
                    text = gzip.decompress(d).decode("utf-8", errors="replace")
                    print(
                        f"  Script:     {len(d):,} bytes compressed -> {len(text):,} chars decompressed"
                    )
                    for line in text.splitlines():
                        print(f"  {line}")
                except Exception as exc:
                    print(f"  Decompress error: {exc}")
                    print(f"  Raw header: {d[:16].hex()}")
            elif d:
                print(f"  Data:       {len(d):,} bytes (not gzip)")
                print(f"  Raw header: {d[:16].hex()}")
            else:
                print("  Script:     (not available)")

        # ── iva ───────────────────────────────────────────────────────────────
        if sub in ("iva", "all"):
            print("\n  ── IVA Rules & resiMotion Config ─────────────────────────")
            # 0x0ba9 — IVA rule type names (null-terminated ASCII list)
            d = rcp_read(rcp_url, "0x0ba9", sessionid)
            if d:
                rule_names = [
                    s for s in d.decode("ascii", errors="replace").split("\x00") if s.strip()
                ]
                if rule_names:
                    print(f"  IVA rule types ({len(rule_names)}):")
                    for rn in rule_names:
                        print(f"    • {rn}")
                else:
                    print(f"  IVA rule types: raw {len(d)} bytes  {d[:32].hex()}")
            else:
                print("  IVA rule types: (not available)")
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
                print("  resiMotion config: (not available)")

        # ── bitrate ───────────────────────────────────────────────────────────────
        if sub in ("bitrate", "all"):
            print("\n  ── Bitrate Ladder (0x0c81) ───────────────────────────────")
            d = rcp_read(rcp_url, "0x0c81", sessionid)
            if d and len(d) >= 4:
                import struct as _s

                # Ladder is a series of big-endian uint32 values (kbps)
                n = len(d) // 4
                tiers = [_s.unpack(">I", d[i * 4 : (i + 1) * 4])[0] for i in range(n)]
                labels = ["low", "medium-low", "medium", "medium-high", "high"]
                for i, kbps in enumerate(tiers):
                    label = labels[i] if i < len(labels) else f"tier{i}"
                    marker = " ←" if i == len(tiers) - 1 else ""
                    print(f"  [{label}]  {kbps:,} kbps  ({kbps // 1000:.1f} Mbps){marker}")
                print("\n  Note: highQualityVideo=true selects the highest tier")
            else:
                print("  Bitrate: (not available)")

        print()


def cmd_token(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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

    acct = cfg.get("account", {})
    token = acct.get("bearer_token", "").strip()
    refresh = acct.get("refresh_token", "").strip()

    print("\n── Token Status ─────────────────────────────────────────────")
    if token:
        print(f"  Access token:  {token[:24]}...  ({len(token)} chars)")
        try:
            parts = token.split(".")
            pad = len(parts[1]) % 4
            info = json.loads(_b64.urlsafe_b64decode(parts[1] + "=" * pad))
            exp = info.get("exp", 0)
            exp_dt = datetime.datetime.fromtimestamp(exp)
            diff = exp_dt - datetime.datetime.now()
            mins = int(diff.total_seconds() / 60)
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
        force_browser = action == "browser"
        try:
            from get_token import get_token_auto

            new_token = get_token_auto(cfg, force_browser=force_browser)
            if new_token:
                print("\n  ✅  Token renewed successfully.")
            else:
                print("\n  ❌  Token renewal failed.")
        except ImportError:
            print("  ❌  get_token.py not found in the same folder.")
    elif expired:
        print()
        print("  ➡️   To fix: python3 bosch_camera.py token fix")
    print()


def cmd_rescan(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Re-discover cameras from API and update config."""
    token = get_token(cfg)
    session = make_session(token)
    print("\n  🔍  Re-scanning cameras...")
    cameras = discover_cameras(cfg, session)
    print(f"\n  Found {len(cameras)} camera(s):")
    for name, cam in cameras.items():
        print(f"    • {name}  ({cam['model']})  ID: {cam['id']}")


# ══════════════════════════ INTERACTIVE MENU ══════════════════════════════════


def cmd_menu(cfg: dict[str, Any]) -> None:
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

    live_local_start = offset
    for i, name in enumerate(cam_names, start=offset):
        print(f"  {i})  Live stream LOCAL — {name} (LAN, TLS proxy)")
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
    pan_actions = [
        ("left", "◀◀ Full left"),
        ("center", "■  Center (0°)"),
        ("right", "▶▶ Full right"),
        ("home", "🏠 Home (0°)"),
        ("back-left", "◀◀◀ Back-left (-120°)"),
        ("back-right", "▶▶▶ Back-right (+120°)"),
    ]
    if pan_cams:
        print()
        print("  ── Pan ──────────────────────────────────────────────────────")
        for name in pan_cams:
            for action_key, label in pan_actions:
                lim = cameras[name].get("pan_limit", 120)
                lim_str = (
                    f"-{lim}°"
                    if action_key == "left"
                    else (f"+{lim}°" if action_key == "right" else "0°")
                )
                print(f"  {offset})  Pan {label} ({lim_str}) — {name}")
                offset += 1

    # Auto-follow — only pan_cams
    autofollow_start = offset
    if pan_cams:
        print()
        print("  ── Auto-follow ──────────────────────────────────────────────")
        for name in pan_cams:
            print(f"  {offset})  Auto-follow ON  — {name}")
            offset += 1
            print(f"  {offset})  Auto-follow OFF — {name}")
            offset += 1

    print()
    print("  ── Intercom ─────────────────────────────────────────────────")
    intercom_start = offset
    for name in cam_names:
        print(f"  {offset})  Intercom (listen) — {name}")
        offset += 1

    print()
    print("  ── Siren ────────────────────────────────────────────────────")
    siren_start = offset
    for name in cam_names:
        print(f"  {offset})  Siren (acoustic alarm) — {name}")
        offset += 1

    # WiFi info — all cameras
    print()
    print("  ── WiFi Info ────────────────────────────────────────────────")
    wifi_start = offset
    for name in cam_names:
        print(f"  {offset})  WiFi info — {name}")
        offset += 1

    # Audio levels — Gen2 cams only
    gen2_cams = [n for n in cam_names if cameras.get(n, {}).get("model", "").startswith("HOME_")]
    audio_start = offset
    if gen2_cams:
        print()
        print("  ── Audio ────────────────────────────────────────────────────")
        for name in gen2_cams:
            print(f"  {offset})  Audio levels — {name}")
            offset += 1

    # Intrusion detection — Gen2 cams only
    intrusion_start = offset
    if gen2_cams:
        print()
        print("  ── Intrusion Detection ──────────────────────────────────────")
        for name in gen2_cams:
            print(f"  {offset})  Intrusion config — {name}")
            offset += 1

    print()
    print("  ── Unread Events ────────────────────────────────────────────")
    unread_item = offset
    print(f"  {offset})  Show unread event counts")
    offset += 1

    # Maintenance status — global
    print()
    print("  ── Maintenance ──────────────────────────────────────────────")
    maint_item = offset
    print(f"  {offset})  Bosch cloud maintenance status")
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
    print("  q)  Exit")
    print()

    choice = input("  Enter choice: ").strip()

    a = argparse.Namespace(
        cam=None,
        action=None,
        sub=None,
        limit=None,
        re_download=False,
        live=False,
        vlc=False,
        local=False,
        full=False,
        minutes=None,
        quality=None,
        duration=None,
        speaker_level=None,
    )

    if choice.lower() in ("q", "quit", "exit", "0"):
        sys.exit(0)

    try:
        c = int(choice)
    except ValueError:
        return  # empty Enter or invalid → just redraw menu

    if c == 1:
        cmd_status(cfg, a)
    elif c == 2:
        cmd_info(cfg, a)
    elif 3 <= c < 3 + len(cam_names):
        a.cam = cam_names[c - 3]
        a.live = False
        cmd_snapshot(cfg, a)
    elif c == 3 + len(cam_names):
        a.live = False
        cmd_snapshot(cfg, a)
    elif liveshot_start <= c < liveshot_start + len(cam_names):
        a.cam = cam_names[c - liveshot_start]
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
    elif live_local_start <= c < live_local_start + len(cam_names):
        a.cam = cam_names[c - live_local_start]
        a.local = True
        a.quality = "high"  # LOCAL always best quality
        cmd_live(cfg, a)
    # Privacy
    elif privacy_start <= c < privacy_start + len(cam_names) * 2:
        idx = c - privacy_start
        a.cam = cam_names[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_privacy(cfg, a)
    # Light (only light_cams)
    elif light_cams and light_start <= c < light_start + len(light_cams) * 2:
        idx = c - light_start
        a.cam = light_cams[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_light(cfg, a)
    # Notifications
    elif notif_start <= c < notif_start + len(cam_names) * 2:
        idx = c - notif_start
        a.cam = cam_names[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_notifications(cfg, a)
    # Pan (only pan_cams)
    elif pan_cams and pan_start <= c < pan_start + len(pan_cams) * len(pan_actions):
        idx = c - pan_start
        a.cam = pan_cams[idx // len(pan_actions)]
        a.action = pan_actions[idx % len(pan_actions)][0]
        cmd_pan(cfg, a)
    # Auto-follow (only pan_cams)
    elif pan_cams and autofollow_start <= c < autofollow_start + len(pan_cams) * 2:
        idx = c - autofollow_start
        a.cam = pan_cams[idx // 2]
        a.action = "on" if idx % 2 == 0 else "off"
        cmd_autofollow(cfg, a)
    # Intercom
    elif intercom_start <= c < intercom_start + len(cam_names):
        a.cam = cam_names[c - intercom_start]
        a.duration = 60
        a.speaker_level = 50
        cmd_intercom(cfg, a)
    # Siren
    elif siren_start <= c < siren_start + len(cam_names):
        a.cam = cam_names[c - siren_start]
        cmd_siren(cfg, a)
    # WiFi info
    elif wifi_start <= c < wifi_start + len(cam_names):
        a.cam = cam_names[c - wifi_start]
        cmd_wifi(cfg, a)
    # Audio levels (Gen2 only)
    elif gen2_cams and audio_start <= c < audio_start + len(gen2_cams):
        a.cam = gen2_cams[c - audio_start]
        cmd_audio(cfg, a)
    # Intrusion detection (Gen2 only)
    elif gen2_cams and intrusion_start <= c < intrusion_start + len(gen2_cams):
        a.cam = gen2_cams[c - intrusion_start]
        cmd_intrusion(cfg, a)
    # Unread
    elif c == unread_item:
        cmd_unread(cfg, a)
    # Maintenance status
    elif c == maint_item:
        cmd_maintenance(cfg, a)
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


def cmd_autofollow(cfg: dict[str, Any], args: argparse.Namespace) -> None:
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
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)

    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        pan_limit = cam_info.get("pan_limit", 0)

        print(f"\n── Auto-Follow: {name} ─────────────────────────────────────")
        if not pan_limit:
            print("  ℹ️   This camera does not support auto-follow (panLimit=0).")
            continue

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/autofollow", timeout=10)
        if r.status_code != 200:
            print(f"  ❌  Could not fetch auto-follow state: HTTP {r.status_code}")
            continue
        current = r.json().get("result", False)
        icon = "🎯" if current else "⏸️"
        print(f"  {icon}  Auto-follow:  {'ENABLED' if current else 'DISABLED'}")

        if action is None:
            print("\n  Run with 'on' or 'off' to toggle. E.g.:")
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


def cmd_siren(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Trigger or stop the siren on a camera.

    Usage:
      python3 bosch_camera.py siren <cam-name>                        # trigger
      python3 bosch_camera.py siren <cam-name> --stop                 # stop active alarm
      python3 bosch_camera.py siren <cam-name> --set-duration <secs>  # configure duration then trigger

    Endpoint depends on camera model:
      - Gen2 Indoor II (HOME_Eyes_Indoor): PUT /v11/video_inputs/{id}/panic_alarm
        Body: {"status": "ON"|"OFF"} — 75 dB integrated hardware siren.
      - Gen1 INDOOR/OUTDOOR: the documented /acoustic_alarm endpoint returns
        HTTP 404 in production (verified 2026-05-28). No working Gen1 siren
        endpoint is currently known.

    Duration is camera-side configured via PUT /v11/video_inputs/{id}/alarm_settings
    (field: alarmDelayInSeconds, range 10–300 s). Use --set-duration to update this
    before triggering the alarm.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))

    if len(cams) != 1:
        print("  ❌  Siren requires exactly one camera. Specify the camera name.")
        return

    cam_name, cam_info = next(iter(cams.items()))
    cam_id = cam_info["id"]
    model = cam_info.get("model", "")
    stop = bool(getattr(args, "stop", False))
    set_duration = getattr(args, "set_duration", None)

    print(f"\n── Siren: {cam_name} ──────────────────────────────────────")

    if model != "HOME_Eyes_Indoor":
        print(f"  ⚠️  Siren not supported on model '{model or 'unknown'}'.")
        print("      Only HOME_Eyes_Indoor (Gen2 Indoor II) is currently supported.")
        print("      Gen1 /acoustic_alarm endpoint returns HTTP 404 — needs investigation.")
        return

    # Optional: update alarm duration via alarm_settings before triggering
    if set_duration is not None:
        duration_secs = int(set_duration)
        if not 10 <= duration_secs <= 300:
            print("  ❌  Duration must be between 10 and 300 seconds.")
            return
        # Fetch current alarm_settings to preserve other fields
        rs = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/alarm_settings", timeout=10)
        if rs.status_code == 200:
            alarm_cfg = rs.json()
        else:
            alarm_cfg = {}
        alarm_cfg["alarmDelayInSeconds"] = duration_secs
        rp = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/alarm_settings",
            json=alarm_cfg,
            timeout=10,
        )
        if rp.status_code in (200, 201, 204):
            print(f"  ✅  Siren duration set to {duration_secs}s")
        elif rp.status_code == 443:
            print("  ❌  Camera is in privacy mode — disable privacy first")
            return
        else:
            print(f"  ⚠️  Could not set duration: HTTP {rp.status_code}  {rp.text[:200]}")
            print("      Continuing to trigger alarm with existing duration...")

    action = "Stopping" if stop else "Triggering"
    print(f"  🔔  {action} panic alarm (Gen2 Indoor II)...")

    r = session.put(
        f"{CLOUD_API}/v11/video_inputs/{cam_id}/panic_alarm",
        json={"status": "OFF" if stop else "ON"},
        timeout=10,
    )
    if r.status_code in (200, 201, 204):
        print(f"  ✅  Siren {'stopped' if stop else 'activated'}!")
    elif r.status_code == 443:
        print("  ❌  Camera is in privacy mode — disable privacy first")
    elif r.status_code == 442:
        print("  ⚠️  Siren not supported on this camera model (HTTP 442)")
    else:
        print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")


def cmd_unread(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show unread event count per camera.

    Usage:
      python3 bosch_camera.py unread

    API: GET /v11/video_inputs/{id}  →  field: numberOfUnreadEvents
    Note: /v11/video_inputs/{id}/unread_events_count returns HTTP 404 in
    production (verified 2026-05-28). The field is available in the per-camera
    detail endpoint instead.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))

    print("\n── Unread Events ──────────────────────────────────────")
    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        r = session.get(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}",
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            count = data.get("numberOfUnreadEvents", 0)
            print(f"  📬  {name}: {count} unread event(s)")
        elif r.status_code == 401:
            print("  ❌  Token expired.")
            return
        else:
            print(f"  ❌  {name}: HTTP {r.status_code}")


def cmd_privacy_sound(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Get or set privacy sound override for a camera.

    Usage:
      python3 bosch_camera.py privacy-sound [cam-name]        → show current state
      python3 bosch_camera.py privacy-sound [cam-name] on     → enable privacy sound
      python3 bosch_camera.py privacy-sound [cam-name] off    → disable privacy sound

    API: GET/PUT /v11/video_inputs/{id}/privacy_sound_override
         Body: {"result": true/false}
         Response: {"result": true/false}
    When enabled, the camera plays an audible indicator when privacy mode changes.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)

    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Privacy Sound: {name} ─────────────────────────────────────")

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy_sound_override", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 442:
            print("  ⚠️   Privacy sound not supported on this camera model (HTTP 442)")
            continue
        if r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch privacy sound state: HTTP {r.status_code}")
            continue
        data = r.json()
        current = data.get("result", False)
        icon = "🔊" if current else "🔇"
        print(f"  {icon}  Privacy sound:  {'ENABLED' if current else 'DISABLED'}")

        if action is None:
            print("\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py privacy-sound {name.lower()} on")
            continue

        new_state = action == "on"
        if new_state == current:
            print(f"  ✅  Already {'ENABLED' if current else 'DISABLED'} — no change needed.")
            continue

        print(f"  🔄  Setting privacy sound → {'ENABLED' if new_state else 'DISABLED'}...")
        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy_sound_override",
            json={"result": new_state},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            icon_new = "🔊" if new_state else "🔇"
            print(f"  {icon_new}  Privacy sound {'ENABLED' if new_state else 'DISABLED'}.")
        elif pr.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {pr.json()}")
            except Exception:
                print(f"       {pr.text[:200]}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_audio_detection(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Get or set glass-break + smoke/fire-alarm sound detection (Gen2 Audio-Plus).

    Usage:
      python3 bosch_camera.py audio-detection [<cam>]                      # show current config
      python3 bosch_camera.py audio-detection [<cam>] --glass-break on|off
      python3 bosch_camera.py audio-detection [<cam>] --fire-alarm on|off
      python3 bosch_camera.py audio-detection [<cam>] --glass-break on --fire-alarm off
      python3 bosch_camera.py audio-detection [<cam>] --json               # machine-readable output

    API: GET/PUT /v11/video_inputs/{id}/audioDetectionConfig
         Body: {"detectGlassBreak": bool, "detectFireAlarm": bool} — BOTH fields are
         always sent on every PUT (read-modify-write), otherwise the field not
         addressed by a flag would be reset by the camera.
    Gating: only Gen2 cameras (HOME_Eyes_* / *_GEN2 hardwareVersion) with the Sound
    (Audio-Plus) feature expose this endpoint — non-Gen2 cameras are skipped
    client-side; Gen2-without-sound returns HTTP 442 from the API.
    Note: Returns HTTP 443 when privacy mode is active (write rejected).
    Source: cross-ported from HA v14.2.0 (2026-06-25).
    """
    import json as _json_mod

    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    glass_break = getattr(args, "glass_break", None)
    fire_alarm = getattr(args, "fire_alarm", None)
    as_json = getattr(args, "json", False)

    cams = resolve_cam(cfg, cam_arg)
    results: list[dict[str, Any]] = []

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        # Config-based entries use "model"; live API responses use "hardwareVersion"
        model = cam_info.get("model") or cam_info.get("hardwareVersion", "?")
        is_gen2 = model.startswith("HOME_Eyes_") or model.endswith("_GEN2")
        if not is_gen2:
            if not as_json:
                print(f"\n── Audio Detection: {name} ─────────────────────────────────")
                print(
                    f"  ⚠️   Glass-break/fire-alarm detection requires a Gen2 Audio-Plus "
                    f"camera ({model})"
                )
            results.append({"cam": name, "error": "not_gen2"})
            continue

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/audioDetectionConfig", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 442:
            if not as_json:
                print(f"\n── Audio Detection: {name} ─────────────────────────────────")
                print("  ⚠️   Sound detection not supported on this camera model (HTTP 442)")
            results.append({"cam": name, "error": "not_supported"})
            continue
        if r.status_code == 443:
            if not as_json:
                print(f"\n── Audio Detection: {name} ─────────────────────────────────")
                print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            results.append({"cam": name, "error": "privacy_mode"})
            continue
        if r.status_code != 200:
            if not as_json:
                print(f"\n── Audio Detection: {name} ─────────────────────────────────")
                print(f"  ❌  Could not fetch audio detection config: HTTP {r.status_code}")
            results.append({"cam": name, "error": f"http_{r.status_code}"})
            continue

        data = r.json()
        cur_glass = data.get("detectGlassBreak", False)
        cur_fire = data.get("detectFireAlarm", False)

        entry: dict[str, Any] = {
            "cam": name,
            "detectGlassBreak": cur_glass,
            "detectFireAlarm": cur_fire,
        }

        if not as_json:
            print(f"\n── Audio Detection: {name} ─────────────────────────────────")
            glass_icon = "✅" if cur_glass else "❌"
            fire_icon = "✅" if cur_fire else "❌"
            print(f"  {glass_icon}  Glass-break detection:  {'ON' if cur_glass else 'OFF'}")
            print(f"  {fire_icon}  Fire-alarm detection:   {'ON' if cur_fire else 'OFF'}")

        if glass_break is None and fire_alarm is None:
            if not as_json:
                print("\n  Run with --glass-break / --fire-alarm on|off to change. E.g.:")
                print(
                    f"    python3 bosch_camera.py audio-detection {name.lower()} --glass-break on"
                )
            results.append(entry)
            continue

        new_glass = (glass_break == "on") if glass_break is not None else cur_glass
        new_fire = (fire_alarm == "on") if fire_alarm is not None else cur_fire
        body = {"detectGlassBreak": new_glass, "detectFireAlarm": new_fire}

        if not as_json:
            print(
                f"  🔄  Setting audio detection → glass-break={new_glass}  fire-alarm={new_fire}..."
            )

        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/audioDetectionConfig",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            if not as_json:
                print(
                    f"  ✅  Glass-break: {'ON' if new_glass else 'OFF'}  "
                    f"Fire-alarm: {'ON' if new_fire else 'OFF'}"
                )
            entry.update({"detectGlassBreak": new_glass, "detectFireAlarm": new_fire})
        elif pr.status_code == 443:
            if not as_json:
                print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            entry["error"] = "privacy_mode"
        else:
            if not as_json:
                print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")
            entry["error"] = f"put_http_{pr.status_code}"

        results.append(entry)

    if as_json:
        print(_json_mod.dumps(results, indent=2))


def cmd_rules(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Manage camera automation rules (time-based schedules).

    Usage:
      python3 bosch_camera.py rules [cam]                                            → list all rules
      python3 bosch_camera.py rules [cam] add --name NAME --start HH:MM --end HH:MM --days 0,1,2,3,4,5,6
      python3 bosch_camera.py rules [cam] edit --id RULE_ID [--active|--inactive] [--name NAME] [--start HH:MM] [--end HH:MM] [--days 0,1,2,3,4,5,6]
      python3 bosch_camera.py rules [cam] delete --id RULE_ID

    API: GET/POST/PUT/DELETE /v11/video_inputs/{id}/rules
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub = getattr(args, "sub", None)

    # Allow "rules add" without camera name
    RULES_SUBS = ("add", "edit", "delete")
    if cam_arg and cam_arg.lower() in RULES_SUBS and not sub:
        sub, cam_arg = cam_arg.lower(), None
    if sub:
        sub = sub.lower()

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Rules: {name} ──────────────────────────────────────────────")

        if sub == "add":
            rule_name = getattr(args, "rule_name", None) or "New Rule"
            start = getattr(args, "start", None) or "00:00"
            end = getattr(args, "end", None) or "23:59"
            days_str = getattr(args, "days", None) or "0,1,2,3,4,5,6"
            weekdays = [int(d.strip()) for d in days_str.split(",") if d.strip().isdigit()]

            body = {
                "id": None,
                "name": rule_name,
                "isActive": True,
                "startTime": f"{start}:00",
                "endTime": f"{end}:00",
                "weekdays": weekdays,
            }
            print(f"  ➕  Creating rule: {rule_name}")
            print(f"      Time: {start} → {end}  Days: {weekdays}")
            r = session.post(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/rules",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 201):
                data = r.json()
                rule_id = data.get("id", "(unknown)")
                print(f"  ✅  Rule created: id={rule_id}")
            elif r.status_code == 444:
                print("  ⚠️   Camera offline or unavailable for this operation")
                try:
                    print(f"       {r.json()}")
                except Exception:
                    print(f"       {r.text[:200]}")
            else:
                print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
            continue

        if sub == "edit":
            rule_id = getattr(args, "rule_id", None)
            if not rule_id:
                print(
                    "  ❌  --id is required for edit. Usage: rules [cam] edit --id RULE_ID --active|--inactive"
                )
                continue
            active = getattr(args, "active", False)
            inactive = getattr(args, "inactive", False)

            # Fetch current rule first
            r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/rules", timeout=10)
            if r.status_code != 200:
                print(f"  ❌  Could not fetch rules: HTTP {r.status_code}")
                continue
            rules = r.json()
            target_rule = None
            for rule in rules:
                if rule.get("id") == rule_id:
                    target_rule = rule
                    break
            if not target_rule:
                print(f"  ❌  Rule ID '{rule_id}' not found.")
                continue

            if active:
                target_rule["isActive"] = True
            if inactive:
                target_rule["isActive"] = False
            # Allow changing name, times, and weekdays
            edit_name = getattr(args, "name", None)
            edit_start = getattr(args, "start", None)
            edit_end = getattr(args, "end", None)
            edit_days = getattr(args, "days", None)
            if edit_name:
                target_rule["name"] = edit_name
            if edit_start:
                target_rule["startTime"] = (
                    edit_start if len(edit_start.split(":")) == 3 else f"{edit_start}:00"
                )
            if edit_end:
                target_rule["endTime"] = (
                    edit_end if len(edit_end.split(":")) == 3 else f"{edit_end}:00"
                )
            if edit_days:
                target_rule["weekdays"] = [int(d.strip()) for d in edit_days.split(",")]

            print(f"  ✏️   Updating rule: {rule_id}")
            pr = session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/rules/{rule_id}",
                json=target_rule,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if pr.status_code in (200, 201, 204):
                print(f"  ✅  Rule updated: isActive={target_rule.get('isActive')}")
            elif pr.status_code == 444:
                print("  ⚠️   Camera offline or unavailable for this operation")
                try:
                    print(f"       {pr.json()}")
                except Exception:
                    print(f"       {pr.text[:200]}")
            else:
                print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")
            continue

        if sub == "delete":
            rule_id = getattr(args, "rule_id", None)
            if not rule_id:
                print("  ❌  --id is required for delete. Usage: rules [cam] delete --id RULE_ID")
                continue
            print(f"  🗑️   Deleting rule: {rule_id}")
            r = session.delete(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/rules/{rule_id}",
                timeout=10,
            )
            if r.status_code in (200, 204):
                print("  ✅  Rule deleted.")
            elif r.status_code == 444:
                print("  ⚠️   Camera offline or unavailable for this operation")
                try:
                    print(f"       {r.json()}")
                except Exception:
                    print(f"       {r.text[:200]}")
            else:
                print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
            continue

        # Default: list all rules
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/rules", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch rules: HTTP {r.status_code}")
            continue
        rules = r.json()
        if not rules:
            print("  (no rules configured)")
            print("\n  Create a rule with:")
            print(
                f"    python3 bosch_camera.py rules {name.lower()} add --name 'Night Mode' --start 22:00 --end 06:00 --days 0,1,2,3,4,5,6"
            )
            continue
        print(f"  {len(rules)} rule(s):\n")
        DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        for rule in rules:
            rid = rule.get("id", "?")
            rname = rule.get("name", "?")
            active = rule.get("isActive", False)
            start = rule.get("startTime", "?")
            end = rule.get("endTime", "?")
            days = rule.get("weekdays", [])
            days_str = ", ".join(DAY_NAMES[d] if d < len(DAY_NAMES) else str(d) for d in days)
            icon = "✅" if active else "⏸️"
            print(f"  {icon}  {rname}")
            print(f"      ID:     {rid}")
            print(f"      Active: {active}")
            print(f"      Time:   {start} → {end}")
            print(f"      Days:   {days_str}")
            print()


def cmd_friends(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Manage camera sharing with friends.

    Usage:
      python3 bosch_camera.py friends                              → list all friends
      python3 bosch_camera.py friends invite EMAIL                 → invite a friend
      python3 bosch_camera.py friends share FRIEND_ID CAM [--days N]
      python3 bosch_camera.py friends unshare FRIEND_ID
      python3 bosch_camera.py friends resend FRIEND_ID
      python3 bosch_camera.py friends remove FRIEND_ID

    API: GET/POST/PUT/DELETE /v11/friends/*
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    sub = getattr(args, "sub", None)
    sub_arg = getattr(args, "sub_arg", None)

    print("\n── Friends / Camera Sharing ─────────────────────────────────────")

    if sub == "invite":
        email = sub_arg
        if not email:
            print("  ❌  Email is required. Usage: friends invite EMAIL")
            return
        body = {"invitationEmail": email, "nickName": email}
        print(f"  📨  Inviting {email}...")
        r = session.post(
            f"{CLOUD_API}/v11/friends",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code in (200, 201):
            data = r.json()
            print(f"  ✅  Invitation sent! Friend ID: {data.get('id', '(see response)')}")
            print(f"      {json.dumps(data, indent=2)}")
        elif r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
        else:
            print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
        return

    if sub == "share":
        friend_id = sub_arg
        cam_name = getattr(args, "share_cam", None)
        days = getattr(args, "days", None)
        if not friend_id or not cam_name:
            print("  ❌  Usage: friends share FRIEND_ID CAM [--days N]")
            return
        target_cams = resolve_cam(cfg, cam_name)
        if not target_cams:
            return
        shares = []
        for cname, cinfo in target_cams.items():
            share_entry = {"videoInputId": cinfo["id"]}
            if days:
                now = datetime.datetime.utcnow()
                end = now + datetime.timedelta(days=days)
                share_entry["shareTime"] = {
                    "start": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "end": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                }
            shares.append(share_entry)

        print(f"  🔗  Sharing {len(shares)} camera(s) with friend {friend_id}...")
        r = session.put(
            f"{CLOUD_API}/v11/friends/{friend_id}/share",
            json=shares,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code in (200, 201, 204):
            print("  ✅  Camera(s) shared!")
        elif r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
        else:
            print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
        return

    if sub == "unshare":
        friend_id = sub_arg
        if not friend_id:
            print("  ❌  Usage: friends unshare FRIEND_ID")
            return
        print(f"  🔓  Removing all camera shares from friend {friend_id}...")
        r = session.put(
            f"{CLOUD_API}/v11/friends/{friend_id}/share",
            json=[],
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code in (200, 201, 204):
            print("  ✅  All cameras unshared.")
        elif r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
        else:
            print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
        return

    if sub == "resend":
        friend_id = sub_arg
        if not friend_id:
            print("  ❌  Usage: friends resend FRIEND_ID")
            return
        print(f"  📨  Re-sending invitation to friend {friend_id}...")
        r = session.put(
            f"{CLOUD_API}/v11/friends/{friend_id}/resend_invite",
            json={"email": ""},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code in (200, 201, 204):
            print("  ✅  Invitation re-sent!")
        elif r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
        else:
            print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
        return

    if sub == "remove":
        friend_id = sub_arg
        if not friend_id:
            print("  ❌  Usage: friends remove FRIEND_ID")
            return
        print(f"  🗑️   Removing friend {friend_id}...")
        r = session.delete(f"{CLOUD_API}/v11/friends/{friend_id}", timeout=10)
        if r.status_code in (200, 204):
            print("  ✅  Friend removed.")
        elif r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable for this operation")
            try:
                print(f"       {r.json()}")
            except Exception:
                print(f"       {r.text[:200]}")
        else:
            print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
        return

    # Default: list all friends
    r = session.get(f"{CLOUD_API}/v11/friends", timeout=10)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    if r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
        try:
            print(f"       {r.json()}")
        except Exception:
            print(f"       {r.text[:200]}")
        return
    if r.status_code != 200:
        print(f"  ❌  Could not fetch friends: HTTP {r.status_code}")
        return
    friends = r.json()
    if not friends:
        print("  (no friends / camera shares)")
        print("\n  Invite a friend with:")
        print("    python3 bosch_camera.py friends invite user@example.com")
        return
    print(f"  {len(friends)} friend(s):\n")
    for friend in friends:
        fid = friend.get("id", "?")
        email = friend.get("email", friend.get("invitationEmail", "?"))
        nick = friend.get("nickName", "?")
        status = friend.get("status", friend.get("invitationStatus", "?"))
        shares = friend.get("sharedVideoInputs", friend.get("shares", []))
        icon = "✅" if status in ("ACCEPTED", "ACTIVE") else "⏳"
        print(f"  {icon}  {nick} ({email})")
        print(f"      ID:     {fid}")
        print(f"      Status: {status}")
        if shares:
            print(f"      Shared: {len(shares)} camera(s)")
            for sh in shares:
                vid = sh.get("videoInputId", "?")
                print(f"        • {vid}")
        print()


def cmd_accept_invite(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Accept an incoming friend/camera sharing invitation.

    Usage:
      python3 bosch_camera.py accept-invite TOKEN

    API: POST /v11/friends/accept
    """
    token = get_token(cfg)
    session = make_session(token)
    invite_token = getattr(args, "token", None)

    if not invite_token:
        print("  ❌  Invitation token is required. Usage: accept-invite TOKEN")
        return

    print("\n── Accept Friend Invitation ───────────────────────────────────")
    print("  📨  Accepting invitation...")

    r = session.post(
        f"{CLOUD_API}/v11/friends/accept",
        json={"token": invite_token},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if r.status_code in (200, 201, 204):
        print("  ✅  Invitation accepted!")
        try:
            data = r.json()
            print(f"      {json.dumps(data, indent=2)}")
        except Exception:
            pass
    elif r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
        try:
            print(f"       {r.json()}")
        except Exception:
            print(f"       {r.text[:200]}")
    else:
        print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")


def cmd_shared_with_friends(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show which friends have access to a specific camera.

    Usage:
      python3 bosch_camera.py shared [cam-name]

    API: GET /v11/video_inputs/{id}/shared_with_friends
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cams = resolve_cam(cfg, getattr(args, "cam", None))

    print("\n── Shared With Friends ────────────────────────────────────────")

    for cam_name, cam_info in cams.items():
        cam_id = cam_info["id"]
        # Config-based entries use "model"; live API responses use "hardwareVersion"
        model = cam_info.get("model") or cam_info.get("hardwareVersion", "?")
        model_name = HW_DISPLAY_NAMES.get(model, model)
        print(f"\n  📷  {cam_name} ({model_name})")

        # Gen1 cameras (INDOOR, OUTDOOR, CAMERA_360, CAMERA_EYES) do not expose
        # the /shared_with_friends endpoint — returns HTTP 404 in production.
        # Gen2 cameras use hardwareVersion "HOME_Eyes_*" or "CAMERA_*_GEN2".
        is_gen2 = model.startswith("HOME_Eyes_") or model.endswith("_GEN2")
        if not is_gen2:
            print(f"      ⚠️  Sharing not supported on Gen1 cameras ({model})")
            continue

        r = session.get(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/shared_with_friends",
            timeout=10,
        )
        if r.status_code == 200:
            friends = r.json()
            if not friends:
                print("      (not shared with anyone)")
                continue
            if isinstance(friends, list):
                print(f"      Shared with {len(friends)} friend(s):")
                for friend in friends:
                    fid = friend.get("id", friend.get("friendId", "?"))
                    email = friend.get("email", friend.get("invitationEmail", "?"))
                    nick = friend.get("nickName", "?")
                    status = friend.get("status", friend.get("invitationStatus", "?"))
                    icon = "✅" if status in ("ACCEPTED", "ACTIVE") else "⏳"
                    print(f"      {icon}  {nick} ({email})")
                    print(f"          ID:     {fid}")
                    print(f"          Status: {status}")
                    share_time = friend.get("shareTime", {})
                    if share_time:
                        print(f"          From:   {share_time.get('start', '?')}")
                        print(f"          Until:  {share_time.get('end', 'permanent')}")
            else:
                print(f"      {json.dumps(friends, indent=2)}")
        elif r.status_code == 444:
            print("      ⚠️   Camera offline or unavailable")
        else:
            print(f"      ❌  HTTP {r.status_code}  {r.text[:200]}")

    print()


def cmd_zones(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Manage motion detection zones (cloud API).

    Usage:
      python3 bosch_camera.py zones [cam]                  → list current zones
      python3 bosch_camera.py zones [cam] set --json '[{"x":0.0,"y":0.3,"w":0.67,"h":0.7}]'
      python3 bosch_camera.py zones [cam] clear             → remove all zones

    API: GET/POST /v11/video_inputs/{id}/motion_sensitive_areas
    Coordinates: normalized 0.0–1.0 (x, y = top-left corner, w = width, h = height)
    Note: Returns HTTP 443 when privacy mode is active.
    """
    import json as _json

    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub = getattr(args, "sub", None)

    ZONES_SUBS = ("set", "clear")
    if cam_arg and cam_arg.lower() in ZONES_SUBS and not sub:
        sub, cam_arg = cam_arg.lower(), None
    if sub:
        sub = sub.lower()

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Motion Zones: {name} ──────────────────────────────────────")

        if sub == "set":
            zones_json = getattr(args, "json", None)
            if not zones_json:
                print(
                    '  ❌  --json is required. Example: --json \'[{"x":0.0,"y":0.3,"w":0.67,"h":0.7}]\''
                )
                continue
            try:
                zones = _json.loads(zones_json)
            except _json.JSONDecodeError as e:
                print(f"  ❌  Invalid JSON: {e}")
                continue
            if not isinstance(zones, list):
                print("  ❌  Zones must be a JSON array of objects with x, y, w, h")
                continue
            for i, z in enumerate(zones):
                for key in ("x", "y", "w", "h"):
                    if key not in z:
                        print(f"  ❌  Zone {i} missing '{key}'")
                        continue
            print(f"  ✏️   Setting {len(zones)} zone(s)...")
            r = session.post(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion_sensitive_areas",
                json=zones,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 204):
                print(f"  ✅  {len(zones)} zone(s) set.")
            elif r.status_code == 443:
                print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            else:
                print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
            continue

        if sub == "clear":
            print("  🗑️   Clearing all zones...")
            r = session.post(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion_sensitive_areas",
                json=[],
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 204):
                print("  ✅  All zones cleared.")
            elif r.status_code == 443:
                print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            else:
                print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
            continue

        # Default: list zones
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/motion_sensitive_areas", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 443:
            print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch zones: HTTP {r.status_code}")
            continue
        zones = r.json()
        if not zones:
            print("  (no motion zones configured)")
            continue
        print(f"  {len(zones)} zone(s):\n")
        for i, z in enumerate(zones):
            print(
                f"  Zone {i + 1}: x={z.get('x', 0):.4f}  y={z.get('y', 0):.4f}  w={z.get('w', 0):.4f}  h={z.get('h', 0):.4f}"
            )
        print(f"\n  JSON: {_json.dumps(zones)}")


def cmd_privacy_masks(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Manage privacy mask zones (cloud API).

    Usage:
      python3 bosch_camera.py privacy-masks [cam]                  → list current masks
      python3 bosch_camera.py privacy-masks [cam] set --json '[{"x":0.0,"y":0.0,"w":0.3,"h":0.3}]'
      python3 bosch_camera.py privacy-masks [cam] clear            → remove all masks

    API: GET/POST /v11/video_inputs/{id}/privacy_masks
    Coordinates: normalized 0.0–1.0 (x, y = top-left corner, w = width, h = height)
    Note: Returns HTTP 443 when privacy mode is active.
    """
    import json as _json

    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub = getattr(args, "sub", None)

    MASKS_SUBS = ("set", "clear")
    if cam_arg and cam_arg.lower() in MASKS_SUBS and not sub:
        sub, cam_arg = cam_arg.lower(), None
    if sub:
        sub = sub.lower()

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Privacy Masks: {name} ──────────────────────────────────────")

        if sub == "set":
            masks_json = getattr(args, "json", None)
            if not masks_json:
                print(
                    '  ❌  --json is required. Example: --json \'[{"x":0.0,"y":0.0,"w":0.3,"h":0.3}]\''
                )
                continue
            try:
                masks = _json.loads(masks_json)
            except _json.JSONDecodeError as e:
                print(f"  ❌  Invalid JSON: {e}")
                continue
            if not isinstance(masks, list):
                print("  ❌  Masks must be a JSON array of objects with x, y, w, h")
                continue
            print(f"  ✏️   Setting {len(masks)} mask(s)...")
            r = session.post(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy_masks",
                json=masks,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 204):
                print(f"  ✅  {len(masks)} mask(s) set.")
            elif r.status_code == 443:
                print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            else:
                print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
            continue

        if sub == "clear":
            print("  🗑️   Clearing all masks...")
            r = session.post(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy_masks",
                json=[],
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 204):
                print("  ✅  All masks cleared.")
            elif r.status_code == 443:
                print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            else:
                print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")
            continue

        # Default: list masks
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/privacy_masks", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 443:
            print("  ⚠️   Not available (HTTP 443) — privacy mode may be active.")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch masks: HTTP {r.status_code}")
            continue
        masks = r.json()
        if not masks:
            print("  (no privacy masks configured)")
            continue
        print(f"  {len(masks)} mask(s):\n")
        for i, m in enumerate(masks):
            print(
                f"  Mask {i + 1}: x={m.get('x', 0):.4f}  y={m.get('y', 0):.4f}  w={m.get('w', 0):.4f}  h={m.get('h', 0):.4f}"
            )
        print(f"\n  JSON: {_json.dumps(masks)}")


def cmd_lighting_schedule(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """View or modify the lighting schedule for cameras with LED light.

    Usage:
      python3 bosch_camera.py lighting-schedule [cam]      → show current schedule
      python3 bosch_camera.py lighting-schedule [cam] set --on HH:MM --off HH:MM [--motion] [--threshold 0.0-1.0]

    API: GET/PUT /v11/video_inputs/{id}/lighting_options
    Only available for outdoor cameras (Eyes) with LED light.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub = getattr(args, "sub", None)

    if cam_arg and cam_arg.lower() == "set" and not sub:
        sub, cam_arg = "set", None
    if sub:
        sub = sub.lower()

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Lighting Schedule: {name} ──────────────────────────────────")

        if sub == "set":
            # Fetch current first
            r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_options", timeout=10)
            if r.status_code != 200:
                print(f"  ❌  Could not fetch: HTTP {r.status_code}")
                continue
            data = r.json()
            on_time = getattr(args, "on", None)
            off_time = getattr(args, "off", None)
            motion = getattr(args, "motion", None)
            threshold = getattr(args, "threshold", None)
            if on_time:
                data["generalLightOnTime"] = (
                    on_time if len(on_time.split(":")) == 3 else f"{on_time}:00"
                )
            if off_time:
                data["generalLightOffTime"] = (
                    off_time if len(off_time.split(":")) == 3 else f"{off_time}:00"
                )
            if motion is not None:
                data["lightOnMotion"] = motion
            if threshold is not None:
                data["darknessThreshold"] = float(threshold)
            data["scheduleStatus"] = "FOLLOW_SCHEDULE"
            print("  ✏️   Updating schedule...")
            pr = session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_options",
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if pr.status_code in (200, 204):
                print(
                    f"  ✅  Schedule updated: {data.get('generalLightOnTime')} → {data.get('generalLightOffTime')}"
                )
            elif pr.status_code == 444:
                print("  ⚠️   Camera offline.")
            else:
                print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")
            continue

        # Default: show schedule
        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/lighting_options", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 444:
            print("  ⚠️   Camera offline.")
            continue
        if r.status_code == 442:
            print("  ⚠️   Not supported on this camera model.")
            continue
        if r.status_code != 200:
            print(f"  ❌  HTTP {r.status_code}")
            continue
        d = r.json()
        print(f"  Modus:          {d.get('scheduleStatus', '?')}")
        print(
            f"  Zeitplan:       {d.get('generalLightOnTime', '?')} → {d.get('generalLightOffTime', '?')}"
        )
        print(f"  Dunkelheit:     {d.get('darknessThreshold', '?')}")
        print(
            f"  Bei Bewegung:   {'Ja' if d.get('lightOnMotion') else 'Nein'} ({d.get('lightOnMotionFollowUpTimeSeconds', 0)}s Nachlauf)"
        )
        print(
            f"  Frontlicht:     {'An' if d.get('frontIlluminatorInGeneralLightOn') else 'Aus'} (Intensität: {d.get('frontIlluminatorGeneralLightIntensity', '?')})"
        )
        print(f"  Wallwasher:     {'An' if d.get('wallwasherInGeneralLightOn') else 'Aus'}")


def cmd_firmware_update(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """View firmware update status, or trigger an install.

    Usage:
      python3 bosch_camera.py firmware-update [cam]          → show current/latest/status
      python3 bosch_camera.py firmware-update [cam] install  → install the pending update

    API: GET /v11/video_inputs/{id}/firmware, PUT (install) same endpoint with {"id": <update>}.
    Same endpoint the official Bosch app's "Update now" button uses. Cross-ported from the
    HA integration's BoschCameraCoordinator.async_install_firmware (2026-07-11 family-parity work).
    Installing reboots the camera for 3-7 minutes.
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sub = getattr(args, "sub", None)

    if cam_arg and cam_arg.lower() == "install" and not sub:
        sub, cam_arg = "install", None
    if sub:
        sub = sub.lower()

    cams = resolve_cam(cfg, cam_arg)

    # Guard: "firmware-update install" with no camera targets EVERY camera —
    # each install reboots the physical camera for 3-7 minutes. Bug-hunt
    # finding (2026-07-11): this was silently fleet-wide with zero
    # confirmation, unlike every other multi-cam command in this file (none
    # of which are this destructive/slow). Require an explicit y/N unless
    # --yes was passed (for scripting).
    if sub == "install" and len(cams) > 1 and not getattr(args, "yes", False):
        names = ", ".join(cams.keys())
        print(f"\n⚠️   This will install firmware on ALL {len(cams)} cameras: {names}")
        print("    Each camera reboots for 3-7 minutes. Pass a camera name to target just one.")
        try:
            reply = input("    Continue for all cameras? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            reply = ""
        if reply != "y":
            print("    Aborted.")
            return

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Firmware: {name} ────────────────────────────────────────────")

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/firmware", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 444:
            print("  ⚠️   Camera offline.")
            continue
        if r.status_code == 442:
            print("  ⚠️   Not supported on this camera model.")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch: HTTP {r.status_code}")
            continue
        fw = r.json()
        current = fw.get("current", "?")
        up_to_date = fw.get("upToDate")
        updating = fw.get("updating", False)
        update_target = fw.get("update")

        if sub == "install":
            if updating:
                print("  ⚠️   Install already in progress.")
                continue
            if not update_target:
                print("  ✅  Already up to date — nothing to install.")
                continue
            print(f"  ✏️   Installing firmware {update_target} (camera will reboot)...")
            pr = session.put(
                f"{CLOUD_API}/v11/video_inputs/{cam_id}/firmware",
                json={"id": update_target},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if pr.status_code in (200, 201, 204):
                print(f"  ✅  Install started: {current} → {update_target}")
            elif pr.status_code == 444:
                print("  ⚠️   Camera offline.")
            else:
                print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")
            continue

        print(f"  Installed:      {current}")
        print(f"  Up to date:     {up_to_date}")
        if not up_to_date and update_target:
            print(f"  Update available: {update_target}")
        print(f"  Installing now: {updating}")


def cmd_rename(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Rename a camera via the Bosch cloud API.

    Usage:
      python3 bosch_camera.py rename CAM "New Name"

    API: PUT /v11/video_inputs
         Body: {"videoInputId": "uuid", "title": "New Name", "timeZone": "Europe/Berlin"}
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    new_name = getattr(args, "new_name", None)

    if not cam_arg or not new_name:
        print('  ❌  Usage: rename CAM "New Name"')
        return

    cams = resolve_cam(cfg, cam_arg)
    if len(cams) != 1:
        print("  ❌  Rename requires exactly one camera.")
        return

    name, cam_info = next(iter(cams.items()))
    cam_id = cam_info["id"]

    print("\n── Rename Camera ──────────────────────────────────────────────")
    print(f"  📷  Camera:    {name}")
    print(f"  ✏️   New name:  {new_name}")

    body = {
        "videoInputId": cam_id,
        "title": new_name,
        "timeZone": "Europe/Berlin",
    }
    r = session.put(
        f"{CLOUD_API}/v11/video_inputs",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if r.status_code in (200, 201, 204):
        print(f"  ✅  Camera renamed to '{new_name}'.")
        # Update local config
        old_name = name
        cam_info["name"] = new_name
        cfg["cameras"][new_name] = cam_info
        if old_name != new_name and old_name in cfg["cameras"]:
            del cfg["cameras"][old_name]
        save_config(cfg)
        print("  💾  Config updated.")
    elif r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
        try:
            print(f"       {r.json()}")
        except Exception:
            print(f"       {r.text[:200]}")
    else:
        print(f"  ❌  Failed: HTTP {r.status_code}  {r.text[:200]}")


def cmd_profile(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show or edit user profile.

    Usage:
      python3 bosch_camera.py profile                                → show user info
      python3 bosch_camera.py profile edit --display-name NAME --marketing on|off

    API: GET /v11/registration/check, PUT /v11/registration
    """
    token = get_token(cfg)
    session = make_session(token)
    edit = getattr(args, "sub", None)
    display_name = getattr(args, "display_name", None)
    marketing = getattr(args, "marketing", None)

    # Allow "profile edit" without the sub argument
    if edit and edit.lower() == "edit":
        edit = "edit"
    elif edit:
        edit = None

    print("\n── User Profile ───────────────────────────────────────────────")

    # Fetch current profile
    r = session.get(f"{CLOUD_API}/v11/registration/check", timeout=10)
    if r.status_code == 401:
        print("  ❌  Token expired.")
        return
    if r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
        try:
            print(f"       {r.json()}")
        except Exception:
            print(f"       {r.text[:200]}")
        return
    if r.status_code != 200:
        print(f"  ❌  Could not fetch profile: HTTP {r.status_code}  {r.text[:200]}")
        return
    data = r.json()
    # Response has nested "userInformation" object
    user_info = data.get("userInformation", data)

    # Display profile info
    email = user_info.get("email", "?")
    first = user_info.get("firstName", "")
    last = user_info.get("lastName", "")
    display = user_info.get("displayName", "?")
    name = f"{first} {last}".strip() if first else display
    last_login = data.get("lastLoginTime", "?")
    token_exp = data.get("tokenExpirationTime", "?")
    mkt = user_info.get("marketingContact", "?")
    iot = user_info.get("iotThingsIntegration", "?")
    lang = user_info.get("language", "?")
    tz = user_info.get("timeZone", "?")
    problems = data.get("loginProblems", [])

    print(f"  👤  Name:           {name} (display: {display})")
    print(f"  📧  Email:          {email}")
    print(f"  🌍  Language:       {lang}  /  Timezone: {tz}")
    print(f"  🕐  Last login:     {last_login}")
    print(f"  🔑  Token expires:  {token_exp}")
    print(f"  📢  Marketing:      {'✅ yes' if mkt is True else '❌ no' if mkt is False else mkt}")
    print(f"  🏠  IoT integration: {'✅ yes' if iot is True else '❌ no' if iot is False else iot}")
    if problems:
        print(f"  ⚠️   Login problems: {problems}")

    # Show token age from local config
    print(f"  🔐  Local token:    {check_token_age(cfg)}")

    # Show full response for debugging
    for key, val in data.items():
        if key not in (
            "userInformation",
            "lastLoginTime",
            "tokenExpirationTime",
            "loginProblems",
            "userInformation",
            "lastLoginTime",
            "tokenExpirationTime",
            "loginProblems",
        ):
            print(f"  ℹ️   {key}: {val}")

    if edit != "edit":
        print(
            "\n  Edit with: python3 bosch_camera.py profile edit --display-name 'Name' --marketing on|off"
        )
        return

    # Edit profile — build body from current profile + changes
    body = {
        "firstName": user_info.get("firstName", ""),
        "lastName": user_info.get("lastName", ""),
        "language": user_info.get("language", "de_DE"),
        "locale": user_info.get("locale", "de_DE"),
        "displayName": user_info.get("displayName", ""),
        "marketingContact": user_info.get("marketingContact", False),
        "iotThingsIntegration": user_info.get("iotThingsIntegration", True),
    }
    changed = False
    if display_name:
        body["displayName"] = display_name
        changed = True
    if marketing:
        body["marketingContact"] = marketing.lower() == "on"
        changed = True

    if not changed:
        print("\n  ⚠️   No changes specified. Use --display-name and/or --marketing.")
        return

    print(f"\n  🔄  Updating profile: {body}")
    pr = session.put(
        f"{CLOUD_API}/v11/registration",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if pr.status_code in (200, 201, 204):
        print("  ✅  Profile updated.")
    elif pr.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
        try:
            print(f"       {pr.json()}")
        except Exception:
            print(f"       {pr.text[:200]}")
    else:
        print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_account(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show account info: feature flags, contracts, subscription status.

    Usage:
      python3 bosch_camera.py account

    API: GET /v11/feature_flags, GET /v11/contracts, GET /v11/purchases
    """
    token = get_token(cfg)
    session = make_session(token)

    print("\n── Account Info ───────────────────────────────────────────────")

    # Feature flags
    print("\n  ── Feature Flags ──────────────────────────────────────────────")
    r = session.get(f"{CLOUD_API}/v11/feature_flags", timeout=10)
    if r.status_code == 200:
        flags = r.json()
        if isinstance(flags, dict):
            for key, val in flags.items():
                icon = "✅" if val else "❌"
                print(f"  {icon}  {key}: {val}")
        elif isinstance(flags, list):
            for flag in flags:
                if isinstance(flag, dict):
                    fname = flag.get("name", flag.get("key", "?"))
                    fval = flag.get("value", flag.get("enabled", "?"))
                    icon = "✅" if fval else "❌"
                    print(f"  {icon}  {fname}: {fval}")
                else:
                    print(f"  ✅  {flag}")
        else:
            print(f"  {json.dumps(flags, indent=2)}")
    elif r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
    else:
        print(f"  ⚠️   Feature flags: HTTP {r.status_code}")

    # Contracts (T&C versions)
    print("\n  ── Contracts / Terms ──────────────────────────────────────────")
    r = session.get(f"{CLOUD_API}/v11/contracts", params={"locale": "de_DE"}, timeout=10)
    if r.status_code == 200:
        contracts = r.json()
        if isinstance(contracts, dict):
            tac_ver = contracts.get("tacVersion", "?")
            tac_url = contracts.get("tacURL", "?")
            dpn_ver = contracts.get("dpnVersion", "?")
            dpn_url = contracts.get("dpnURL", "?")
            print(f"  📄  Terms & Conditions: {tac_ver}")
            print(f"     {tac_url}")
            print(f"  🔒  Data Protection:    {dpn_ver}")
            print(f"     {dpn_url}")
        elif isinstance(contracts, list):
            for c in contracts:
                print(f"  📄  {json.dumps(c)}")
        else:
            print(f"  {contracts}")
    elif r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
    else:
        print(f"  ⚠️   Contracts: HTTP {r.status_code}")

    # Purchases / subscription
    print("\n  ── Purchases / Subscriptions ──────────────────────────────────")
    r = session.get(f"{CLOUD_API}/v11/purchases", timeout=10)
    if r.status_code == 200:
        purchases = r.json()
        if isinstance(purchases, list):
            if not purchases:
                print("  (no active purchases/subscriptions)")
            for p in purchases:
                pname = p.get("name", p.get("productId", "?"))
                pstatus = p.get("status", p.get("state", "?"))
                pexpiry = p.get("expiryDate", p.get("validUntil", "?"))
                icon = "✅" if pstatus in ("ACTIVE", "active") else "⏸️"
                print(f"  {icon}  {pname}")
                print(f"      Status: {pstatus}")
                if pexpiry and pexpiry != "?":
                    print(f"      Expires: {pexpiry}")
        elif isinstance(purchases, dict):
            print(f"  {json.dumps(purchases, indent=2)}")
        else:
            print(f"  {purchases}")
    elif r.status_code == 444:
        print("  ⚠️   Camera offline or unavailable for this operation")
    else:
        print(f"  ⚠️   Purchases: HTTP {r.status_code}")

    print()


# ══════════════════════ DIAGNOSTIC & PERFORMANCE HELPERS ═══════════════════════


def fetch_rcp_lan(
    cam_ip: str,
    user: str,
    password: str,
    opcode_hex: str,
    type_: str = "P_OCTET",
    num: int = 0,
) -> bytes | None:
    """Read a single RCP opcode from the camera directly over LAN (HTTPS, Digest auth).

    Uses the cbs-user / local camera credentials that come from PUT /connection LOCAL.
    Returns raw payload bytes on success, or None on any error (network, auth, parse).

    Args:
        cam_ip:     LAN IP of the camera (e.g. "192.0.2.149")
        user:       Digest-auth username (from PUT /connection LOCAL response)
        password:   Digest-auth password (from PUT /connection LOCAL response)
        opcode_hex: RCP command code, e.g. "0x0a98"
        type_:      RCP type string, default "P_OCTET"
        num:        Instance number (default 0)
    """
    import re as _re
    from requests.auth import HTTPDigestAuth

    url = f"https://{cam_ip}/rcp.xml"
    params: dict[str, str | int] = {
        "command": opcode_hex,
        "direction": "READ",
        "type": type_,
        "num": num,
    }
    try:
        r = requests.get(
            url,
            params=params,
            auth=HTTPDigestAuth(user, password),
            verify=False,
            timeout=8,
        )
    except Exception:
        return None

    if r.status_code != 200:
        return None

    # Parse XML — result payload is in <str>HEX</str>
    m = _re.search(r"<str>([0-9a-fA-F]*)</str>", r.text)
    if not m:
        return None
    hex_str = m.group(1)
    if not hex_str:
        return None
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def _get_local_connection_creds(
    session: requests.Session,
    cam_id: str,
) -> tuple[str, str, str] | None:
    """Open PUT /connection LOCAL and return (host_ip, user, password).

    Returns None on failure (HTTP error, no URLs, no creds).
    The returned host_ip has no port (strip ":443" if present).
    """
    try:
        r = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection",
            json={"type": "LOCAL", "highQualityVideo": False},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
    except Exception:
        return None

    if r.status_code != 200:
        return None

    data = r.json()
    urls = data.get("urls", [])
    user = data.get("user") or ""
    pw = data.get("password") or ""

    if not urls or not user or not pw:
        return None

    raw_url = urls[0]  # e.g. "192.0.2.149:443"
    host = raw_url.split(":")[0]
    return host, user, pw


# ══════════════════════ NEW CLI COMMANDS (F1/F4/F6/F13) ══════════════════════


def cmd_snapshot_mjpeg(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """F1 — MJPEG/FFmpeg snapshot for Gen2 cameras (faster than snap.jpg).

    Captures a single JPEG frame via FFmpeg from the local RTSP stream.
    Requires the camera to be reachable on LAN and Gen2 (HOME_Eyes_*).

    FFmpeg command:
      ffmpeg -rtsp_transport tcp -i rtsp://user:pw@ip:443/rtsp_tunnel?inst=3
             -vframes 1 -f image2pipe -

    On Gen1 or FFmpeg error: prints "skipped" and exits with code 0.

    Usage:
      python3 bosch_camera.py snapshot-mjpeg [<cam>] [-o out.jpg]
    """
    token = get_token(cfg)
    session = make_session(token)
    _cams = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    out_path: str | None = getattr(args, "output", None)

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        print(f"\n── MJPEG Snapshot: {name} ──────────────────────────────────────")

        model = cam_info.get("model", cam_info.get("hardwareVersion", ""))
        is_gen2 = model.startswith("HOME_")
        if not is_gen2:
            print(f"  ⚠️   Skipped — snapshot-mjpeg requires Gen2 (HOME_Eyes_*), got '{model}'.")
            continue

        # Get LAN credentials via PUT /connection LOCAL
        print("  🔄  Opening LOCAL connection for LAN credentials...")
        creds = _get_local_connection_creds(session, cam_info["id"])
        if not creds:
            print(
                "  ⚠️   Skipped — could not obtain LOCAL connection creds (camera offline or LAN not reachable)."
            )
            continue

        cam_host, cam_user, cam_pass = creds
        rtsp_url = f"rtsp://{cam_user}:{cam_pass}@{cam_host}:443/rtsp_tunnel?inst=3"
        print(f"  📡  RTSP: rtsp://{cam_user}:***@{cam_host}:443/rtsp_tunnel?inst=3")

        # Determine output path
        if out_path:
            dest = out_path
        else:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = name.replace(" ", "_")
            dest = os.path.join(BASE_DIR, f"mjpeg_snapshot_{safe_name}_{ts}.jpg")

        # FFmpeg subprocess — capture stdout as JPEG bytes
        print("  🎞️   Running FFmpeg...")
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-rtsp_transport",
                    "tcp",
                    "-i",
                    rtsp_url,
                    "-vframes",
                    "1",
                    "-f",
                    "image2pipe",
                    "-",
                ],
                capture_output=True,
                timeout=15,
            )
        except FileNotFoundError:
            print("  ⚠️   Skipped — ffmpeg not found. Install with: brew install ffmpeg")
            continue
        except subprocess.TimeoutExpired:
            print("  ⚠️   Skipped — FFmpeg timed out.")
            continue
        except Exception as e:
            print(f"  ⚠️   Skipped — FFmpeg error: {e}")
            continue

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        if proc.returncode != 0 or not proc.stdout:
            # FFmpeg writes diagnostics to stderr — show tail for debugging
            stderr_tail = (
                (proc.stderr or b"").decode("utf-8", errors="replace").strip().splitlines()
            )
            hint = stderr_tail[-1] if stderr_tail else "(no output)"
            print(f"  ⚠️   Skipped — FFmpeg exited {proc.returncode}: {hint}")
            continue

        jpeg_bytes = proc.stdout
        if not jpeg_bytes[:2] == b"\xff\xd8":
            print(f"  ⚠️   Skipped — FFmpeg output is not a JPEG (got {jpeg_bytes[:4].hex()}).")
            continue

        with open(dest, "wb") as fh:
            fh.write(jpeg_bytes)
        print(f"  ✅  {dest}  ({len(jpeg_bytes):,} bytes, {elapsed_ms} ms)")
        open_file(dest)


def cmd_onvif_scopes(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """F4 — ONVIF Scopes Reader via RCP 0x0a98 (LAN, Digest auth).

    Reads the ONVIF scope string from the camera directly over LAN (HTTPS + Digest).
    Decodes the null-terminated ASCII TLV payload returned by opcode 0x0a98.

    Usage:
      python3 bosch_camera.py onvif-scopes [<cam>] [--json]
    """
    import json as _json_mod

    token = get_token(cfg)
    session = make_session(token)
    _cams = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    as_json = getattr(args, "json", False)

    cams = resolve_cam(cfg, cam_arg)
    results: list[dict[str, Any]] = []

    for name, cam_info in cams.items():
        if not as_json:
            print(f"\n── ONVIF Scopes: {name} ──────────────────────────────────────────")

        # Get LAN credentials
        creds = _get_local_connection_creds(session, cam_info["id"])
        if not creds:
            if not as_json:
                print(
                    "  ⚠️   Could not open LOCAL connection — camera offline or LAN not reachable."
                )
            results.append({"cam": name, "error": "local_connection_failed"})
            continue

        cam_host, cam_user, cam_pass = creds

        if not as_json:
            print(f"  📡  Reading RCP 0x0a98 from {cam_host}...")

        raw = fetch_rcp_lan(cam_host, cam_user, cam_pass, "0x0a98")
        if raw is None:
            if not as_json:
                print("  ⚠️   RCP 0x0a98 returned no data (opcode not supported or LAN error).")
            results.append({"cam": name, "error": "rcp_no_data"})
            continue

        # Parse null-terminated ASCII strings from payload
        scopes: list[str] = []
        for chunk in raw.split(b"\x00"):
            s = chunk.decode("ascii", errors="replace").strip()
            if s:
                scopes.append(s)

        entry: dict[str, Any] = {"cam": name, "scopes": scopes, "raw_hex": raw.hex()}
        results.append(entry)

        if not as_json:
            if scopes:
                print(f"  ✅  {len(scopes)} scope(s):")
                for sc in scopes:
                    print(f"       {sc}")
            else:
                print(f"  ℹ️   No scope strings in payload ({len(raw)} bytes raw).")
                print(f"       Raw: {raw.hex()}")

    if as_json:
        print(_json_mod.dumps(results, indent=2))


def cmd_rcp_version(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """F6 — Print RCP protocol version from camera via cloud proxy.

    Reads opcodes 0xff00 (primary version) and 0xff04 (secondary version).
    Each returns a 4-byte big-endian version word. Formatted as "major.minor.patch.build".

    Usage:
      python3 bosch_camera.py rcp-version [<cam>]
    """

    token = get_token(cfg)
    session = make_session(token)
    _cams = get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        print(f"\n── RCP Version: {name} ────────────────────────────────────────────")

        try:
            rcp_url, sessionid = _rcp_setup(cam_info, token)
        except RuntimeError as e:
            print(f"  ❌  RCP setup failed: {e}")
            continue

        def _read_version(opcode: str) -> str:
            d = rcp_read(rcp_url, opcode, sessionid, type_="T_DWORD")
            if d and len(d) >= 4:
                major, minor, patch, build = d[0], d[1], d[2], d[3]
                return f"{major}.{minor}.{patch}.{build}"
            # Fallback: try P_OCTET
            d2 = rcp_read(rcp_url, opcode, sessionid, type_="P_OCTET")
            if d2 and len(d2) >= 4:
                major, minor, patch, build = d2[0], d2[1], d2[2], d2[3]
                return f"{major}.{minor}.{patch}.{build}"
            return "(not available)"

        fw = cam_info.get("firmware", cam_info.get("firmwareVersion", "?"))
        model = cam_info.get("model", cam_info.get("hardwareVersion", "?"))
        print(f"  Camera:       {model}  FW {fw}")

        ver_primary = _read_version("0xff00")
        ver_secondary = _read_version("0xff04")

        print(f"  RCP Primary:   {ver_primary}")
        print(f"  RCP Secondary: {ver_secondary}")

        if ver_primary != "(not available)":
            print(f"\n  ✅  {model} FW {fw}: RCP v{ver_primary}")
        else:
            print("\n  ⚠️   RCP version opcodes not available on this camera.")


def cmd_feature_flags(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """F13 — Print Bosch Cloud feature flags for this account.

    GET /v11/feature_flags — account-level capabilities bitmask.
    Human-readable list by default; --json for structured output.

    Usage:
      python3 bosch_camera.py feature-flags [--json]
    """
    import json as _json_mod

    token = get_token(cfg)
    session = make_session(token)
    as_json = getattr(args, "json", False)

    if not as_json:
        print("\n── Feature Flags ───────────────────────────────────────────────────")

    r = session.get(f"{CLOUD_API}/v11/feature_flags", timeout=10)

    if r.status_code == 401:
        if not as_json:
            print("  ❌  Token expired. Run `python3 get_token.py` to renew.")
        return

    if r.status_code != 200:
        if not as_json:
            print(f"  ⚠️   HTTP {r.status_code}: could not fetch feature flags.")
        else:
            print(_json_mod.dumps({"error": f"http_{r.status_code}"}))
        return

    flags = r.json()

    # Normalise to dict[str, bool|str]
    flags_dict: dict[str, object]
    if isinstance(flags, dict):
        flags_dict = flags
    elif isinstance(flags, list):
        flags_dict = {}
        for item in flags:
            if isinstance(item, dict):
                key: str = str(item.get("name", item.get("key", "?")))
                val = item.get("value", item.get("enabled", "?"))
                flags_dict[key] = val
            else:
                flags_dict[str(item)] = True
    else:
        flags_dict = {"raw": flags}

    if as_json:
        print(_json_mod.dumps(flags_dict, indent=2))
    else:
        enabled = [k for k, v in flags_dict.items() if v is True or v == "true"]
        disabled = [k for k, v in flags_dict.items() if v is False or v == "false"]
        other = [(k, v) for k, v in flags_dict.items() if k not in enabled and k not in disabled]
        if enabled:
            print(f"\n  Enabled ({len(enabled)}):")
            for k in sorted(enabled):
                print(f"    ✅  {k}")
        if disabled:
            print(f"\n  Disabled ({len(disabled)}):")
            for k in sorted(disabled):
                print(f"    ❌  {k}")
        if other:
            print("\n  Other:")
            for k, v in sorted(other):
                print(f"    ℹ️   {k}: {v}")
        if not flags_dict:
            print("  (empty response)")
        print()


def cmd_timestamp(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Get or set time/date overlay on camera video.

    Usage:
      python3 bosch_camera.py timestamp [cam-name]        → show current state
      python3 bosch_camera.py timestamp [cam-name] on     → enable timestamp overlay
      python3 bosch_camera.py timestamp [cam-name] off    → disable timestamp overlay

    API: GET/PUT /v11/video_inputs/{id}/timestamp
         Body: {"result": true/false}
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    action = getattr(args, "action", None)

    if cam_arg and cam_arg.lower() in ("on", "off") and action is None:
        action = cam_arg.lower()
        cam_arg = None

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Timestamp Overlay: {name} ─────────────────────────────────────")

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/timestamp", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch timestamp state: HTTP {r.status_code}")
            continue
        data = r.json()
        current = data.get("result", False)
        icon = "🕐" if current else "🕐"
        print(f"  {icon}  Timestamp overlay:  {'ENABLED' if current else 'DISABLED'}")

        if action is None:
            print("\n  Run with 'on' or 'off' to toggle. E.g.:")
            print(f"    python3 bosch_camera.py timestamp {name.lower()} on")
            continue

        new_state = action == "on"
        if new_state == current:
            print(f"  ✅  Already {'ENABLED' if current else 'DISABLED'} — no change needed.")
            continue

        print(f"  🔄  Setting timestamp overlay → {'ENABLED' if new_state else 'DISABLED'}...")
        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/timestamp",
            json={"result": new_state},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            print(f"  ✅  Timestamp overlay {'ENABLED' if new_state else 'DISABLED'}.")
        elif pr.status_code == 444:
            print("  ⚠️   Camera offline or unavailable")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def cmd_notification_types(cfg: dict[str, Any], args: argparse.Namespace) -> None:
    """Show or toggle per-type notification settings.

    Usage:
      python3 bosch_camera.py notification-types [cam-name]
      python3 bosch_camera.py notification-types [cam-name] --set movement=on person=off

    API: GET/PUT /v11/video_inputs/{id}/notifications
    """
    token = get_token(cfg)
    session = make_session(token)
    get_cameras(cfg, session)
    cam_arg = getattr(args, "cam", None)
    sets = getattr(args, "set", None)

    cams = resolve_cam(cfg, cam_arg)

    for name, cam_info in cams.items():
        cam_id = cam_info["id"]
        print(f"\n── Notification Types: {name} ─────────────────────────────────────")

        r = session.get(f"{CLOUD_API}/v11/video_inputs/{cam_id}/notifications", timeout=10)
        if r.status_code == 401:
            print("  ❌  Token expired.")
            return
        if r.status_code == 444:
            print("  ⚠️   Camera offline or unavailable")
            continue
        if r.status_code != 200:
            print(f"  ❌  Could not fetch notification types: HTTP {r.status_code}")
            continue
        data = r.json()
        for key, val in sorted(data.items()):
            icon = "✅" if val else "❌"
            print(f"  {icon}  {key}: {'ON' if val else 'OFF'}")

        if not sets:
            print("\n  Toggle with: --set movement=on person=off audio=on")
            continue

        # Parse --set pairs
        for pair in sets:
            key, _, val_str = pair.partition("=")
            if val_str.lower() in ("on", "true", "1"):
                data[key] = True
            elif val_str.lower() in ("off", "false", "0"):
                data[key] = False
            else:
                print(f"  ⚠️   Invalid value for {key}: {val_str} (use on/off)")
                continue

        print("\n  🔄  Updating notification types...")
        pr = session.put(
            f"{CLOUD_API}/v11/video_inputs/{cam_id}/notifications",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if pr.status_code in (200, 201, 204):
            print("  ✅  Notification types updated.")
            for key, val in sorted(data.items()):
                icon = "✅" if val else "❌"
                print(f"  {icon}  {key}: {'ON' if val else 'OFF'}")
        else:
            print(f"  ❌  Failed: HTTP {pr.status_code}  {pr.text[:200]}")


def main() -> None:
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
            "  Examples:\n    python3 bosch_camera.py info\n    python3 bosch_camera.py info --full"
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
            help="Alias for 'snapshot --live'",
            description=f"📸  {_alias} — Alias for: snapshot --live\n\nSee 'snapshot --help' for full details.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        p_alias.add_argument(
            "cam", nargs="?", metavar="<camera>", help="Camera name or partial match"
        )
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
    p_live.add_argument(
        "--local",
        action="store_true",
        help="Force LOCAL connection type (direct LAN stream with credentials)",
    )
    p_live.add_argument(
        "--sub",
        action="store_true",
        help=t("help.live.sub"),
    )
    p_live.add_argument(
        "--webrtc",
        action="store_true",
        dest="webrtc",
        help=t("help.live.webrtc"),
    )
    p_live.add_argument(
        "--go2rtc-binary",
        metavar="PATH",
        dest="go2rtc_binary",
        default="go2rtc",
        help=t("help.live.go2rtc_binary"),
    )
    p_live.add_argument(
        "--webrtc-port",
        type=int,
        metavar="N",
        dest="webrtc_port",
        default=1984,
        help=t("help.live.webrtc_port"),
    )

    # ── test-local ─────────────────────────────────────────────────────────────
    p_testlocal = subparsers.add_parser(
        "test-local",
        help="Test LOCAL vs REMOTE connection — full response dump + snap timing + RTSP URL",
        description=(
            "🔬  test-local — Test LOCAL vs REMOTE connection\n"
            "\n"
            "  Calls PUT /connection with both LOCAL and REMOTE types and prints:\n"
            "    • Full raw JSON response (user, password, urls, imageUrlScheme, ...)\n"
            "    • snap.jpg HTTP status + timing\n"
            "    • RTSPS URL to try manually in VLC or ffplay\n"
            "\n"
            "  Use this to verify LOCAL streaming works and diagnose the 15s startup issue.\n"
            "  Add --play to immediately open the LOCAL stream in ffplay."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_testlocal.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = first camera)",
    )
    p_testlocal.add_argument(
        "--play", action="store_true", help="Open LOCAL RTSPS stream in ffplay after testing"
    )

    # stream alias
    p_stream = subparsers.add_parser(
        "stream",
        help="Alias for 'live'",
        description="📺  stream — Alias for: live\n\nSee 'live --help' for full details.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_stream.add_argument("cam", nargs="?", metavar="<camera>", help="Camera name or partial match")
    p_stream.add_argument(
        "--vlc", action="store_true", help="Open in VLC via ffmpeg pipe instead of ffplay"
    )
    p_stream.add_argument(
        "--hq", action="store_true", help="Request highQualityVideo=true in PUT /connection"
    )
    p_stream.add_argument(
        "--inst",
        type=int,
        default=2,
        metavar="N",
        help="Stream instance number in RTSPS URL (default: 2)",
    )
    p_stream.add_argument(
        "--quality",
        choices=["auto", "high", "low"],
        metavar="Q",
        help="Quality preset: auto | high (30Mbps) | low (1.9Mbps)",
    )
    p_stream.add_argument(
        "--webrtc", action="store_true", dest="webrtc", help=t("help.live.webrtc")
    )
    p_stream.add_argument(
        "--go2rtc-binary",
        metavar="PATH",
        dest="go2rtc_binary",
        default="go2rtc",
        help=t("help.live.go2rtc_binary"),
    )
    p_stream.add_argument(
        "--webrtc-port",
        type=int,
        metavar="N",
        dest="webrtc_port",
        default=1984,
        help=t("help.live.webrtc_port"),
    )

    # "download" and "events" subcommands removed (Bosch request)

    # ── ping ───────────────────────────────────────────────────────────────────
    p_ping = subparsers.add_parser(
        "ping",
        help="TCP-connect probe to camera LAN IP port 443",
        description=(
            "📡  ping — TCP-connect probe to camera LAN IP\n"
            "\n"
            "  Checks whether each camera is reachable on the LAN (port 443).\n"
            "  Uses configured local_ip / lan_ips from bosch_config.json.\n"
            "  Does not require a cloud token.\n"
            "\n"
            "  Output: per-camera OK/FAIL + round-trip time in ms."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py ping\n"
            "    python3 bosch_camera.py ping Garten\n"
            "    python3 bosch_camera.py ping --json"
        ),
    )
    p_ping.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_ping.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON array",
    )

    # ── lan-ips ────────────────────────────────────────────────────────────────
    p_lan = subparsers.add_parser(
        "lan-ips",
        help="List or edit the LAN IP map (used by --local flag)",
        description=(
            "🌐  lan-ips — LAN IP map management\n"
            "\n"
            "  Manages the cam_id → LAN IP mapping used by --local flag commands\n"
            "  (privacy --local, light --local) and by 'bosch ping'.\n"
            "\n"
            "  Subcommands:\n"
            "    (none)              list IPs + ping each\n"
            "    set <cam> <ip>      set or overwrite IP for a camera\n"
            "    unset <cam>         remove IP for a camera\n"
            "    sync                copy local_ip fields → lan_ips map\n"
            "\n"
            "  IPs are stored in bosch_config.json under 'lan_ips'.\n"
            "  You can also set 'local_ip' per camera — lan-ips reads both."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py lan-ips\n"
            "    python3 bosch_camera.py lan-ips set Garten 192.168.1.100\n"
            "    python3 bosch_camera.py lan-ips unset Garten\n"
            "    python3 bosch_camera.py lan-ips sync"
        ),
    )
    p_lan.add_argument(
        "lan_sub",
        nargs="?",
        metavar="set|unset|sync",
        choices=["set", "unset", "sync"],
        help="Subcommand",
    )
    p_lan.add_argument(
        "lan_cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name (for set/unset)",
    )
    p_lan.add_argument(
        "lan_ip",
        nargs="?",
        metavar="<ip>",
        help="LAN IP address (for set)",
    )

    # ── privacy ────────────────────────────────────────────────────────────────
    p_priv = subparsers.add_parser(
        "privacy",
        help="Show or toggle privacy mode (cloud API or LAN RCP with --local)",
        description=(
            "🔒  privacy — Show or toggle privacy mode\n"
            "\n"
            "  Default: uses the Bosch cloud API.\n"
            "  With --local: writes directly via LAN RCP (Gen2 only, no token needed).\n"
            "  API: PUT /v11/video_inputs/{id}/privacy\n"
            "\n"
            "  States:\n"
            "    ON  — camera is blocked, no live images available\n"
            "    OFF — camera is active, live images available\n"
            "\n"
            "  With --minutes: sets a timed privacy period (auto-expires, cloud only)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py privacy                    # show all\n"
            "    python3 bosch_camera.py privacy Garten             # show one\n"
            "    python3 bosch_camera.py privacy on                 # ON (all cameras)\n"
            "    python3 bosch_camera.py privacy Garten on\n"
            "    python3 bosch_camera.py privacy Garten off\n"
            "    python3 bosch_camera.py privacy Garten on --minutes 30\n"
            "    python3 bosch_camera.py privacy Garten on --local  # LAN RCP (Gen2)"
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
    p_priv.add_argument(
        "--local",
        action="store_true",
        help="Force LAN RCP write (Gen2 only) — skip cloud, no token needed",
    )

    # ── light ──────────────────────────────────────────────────────────────────
    p_light = subparsers.add_parser(
        "light",
        help="Show or toggle camera light (cloud API or LAN RCP with --local)",
        description=(
            "💡  light — Show or toggle camera light manual override\n"
            "\n"
            "  Default: uses the Bosch cloud API.\n"
            "  With --local: writes front-light brightness via LAN RCP (Gen2 only).\n"
            "  Wallwasher is cloud-only (--local ignores wallwasher).\n"
            "  Only available for cameras with featureSupport.light = true.\n"
            "  API: PUT /v11/video_inputs/{id}/lighting_override\n"
            "\n"
            "  Shows current schedule mode, intensity, and motion-triggered\n"
            "  light settings when called without on/off."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py light                      # show all\n"
            "    python3 bosch_camera.py light Garten               # show one\n"
            "    python3 bosch_camera.py light on                   # ON (all cameras)\n"
            "    python3 bosch_camera.py light Garten on\n"
            "    python3 bosch_camera.py light Garten off\n"
            "    python3 bosch_camera.py light Garten on --local    # LAN RCP (Gen2)\n"
            "    python3 bosch_camera.py light Garten intensity 50 --local"
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
        metavar="on|off|front|wall|intensity",
        help="Turn light override on or off, or set component",
    )
    p_light.add_argument(
        "--local",
        action="store_true",
        help="Force LAN RCP write for front light (Gen2 only) — skip cloud",
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
            '       Body: {"absolutePosition": <degrees>}\n'
            "\n"
            "  Named presets (--preset):\n"
            "    home       →    0°\n"
            "    left       →  -60°\n"
            "    right      →  +60°\n"
            "    back-left  → -120° (full left)\n"
            "    back-right → +120° (full right)\n"
            "\n"
            "  Or pass any integer in range -panLimit to +panLimit."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py pan                          # show position\n"
            "    python3 bosch_camera.py pan Kamera                   # show position\n"
            "    python3 bosch_camera.py pan Kamera --preset home\n"
            "    python3 bosch_camera.py pan Kamera --preset left\n"
            "    python3 bosch_camera.py pan Kamera --preset back-right\n"
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
        metavar="center|<degrees>",
        help="Legacy: angle in degrees or 'center' (prefer --preset)",
    )
    p_pan.add_argument(
        "--preset",
        metavar="PRESET",
        choices=list(PAN_PRESET_MAP),
        help="Named preset: home (0°) / left (-60°) / right (+60°) / back-left (-120°) / back-right (+120°)",
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
    p_watch.add_argument(
        "--interval",
        type=int,
        default=30,
        metavar="N",
        help="Poll interval in seconds (default: 30)",
    )
    p_watch.add_argument(
        "--duration",
        type=int,
        default=0,
        metavar="N",
        help="Stop after N seconds (default: 0 = infinite)",
    )
    p_watch.add_argument(
        "--snapshot",
        action="store_true",
        help="Auto-download and open the event JPEG when a new event arrives",
    )
    p_watch.add_argument(
        "--push",
        action="store_true",
        help="Use FCM push notifications instead of polling (~2s latency, requires firebase-messaging)",
    )
    p_watch.add_argument(
        "--signal",
        metavar="URL",
        help="Send alerts to Signal via signal-cli-rest-api (e.g. http://localhost:8080)",
    )
    p_watch.add_argument(
        "--signal-recipients",
        metavar="NUMS",
        help="Comma-separated Signal recipients (phone numbers, e.g. +49 170 1234567)",
    )
    p_watch.add_argument(
        "--signal-sender",
        metavar="NUM",
        help="Signal sender number (your registered signal-cli number)",
    )
    p_watch.add_argument(
        "--push-mode",
        choices=["auto", "android", "ios", "polling"],
        default="auto",
        help="Push notification mode: auto (FCM with polling fallback), polling. "
        "android/ios accepted for back-compat but treated as auto (iOS path removed in v10.7.1)",
    )
    p_watch.add_argument(
        "--track-motion",
        action="store_true",
        dest="track_motion",
        help=t("help.watch.track_motion"),
    )
    p_watch.add_argument(
        "--auto-snapshot",
        action="store_true",
        dest="auto_snapshot",
        help=t("help.watch.auto_snapshot"),
    )
    p_watch.add_argument(
        "--quiet-secs",
        type=int,
        default=30,
        metavar="N",
        dest="quiet_secs",
        help=t("help.watch.quiet_secs"),
    )
    p_watch.add_argument(
        "--auto-record", action="store_true", dest="auto_record", help=t("help.watch.auto_record")
    )
    p_watch.add_argument(
        "--nvr-segment-seconds",
        type=int,
        default=None,
        metavar="N",
        dest="nvr_segment_seconds",
        help=t("help.watch.nvr_segment_seconds"),
    )
    p_watch.add_argument(
        "--webhook",
        metavar="URL",
        default="",
        help="POST each new event as JSON to this URL (default: off). "
        "Payload: {camera, camera_id, event_type, timestamp, event_id, image_url, clip_url}.",
    )

    # ── nvr (BETA) ──────────────────────────────────────────────────────────────
    p_nvr = subparsers.add_parser(
        "nvr",
        help=t("help.nvr.subcommand"),
        description=(
            "📹  nvr — BETA: motion-triggered local recording + optional SMB/NAS upload\n"
            "\n"
            "  Subcommands:\n"
            "    status [cam]              — show clip count, disk usage, live recording\n"
            "    list   [cam] [--limit N]  — list clips (newest first)\n"
            "    prune  [cam] [--keep N]   — manually run FIFO eviction\n"
            "    upload [cam] [--clip PATH] — upload to SMB/NAS (requires smbprotocol)\n"
            "\n"
            "  Config (bosch_config.json):\n"
            "    nvr.max_clips        — FIFO limit (default 50)\n"
            "    nvr.max_duration     — segment length in seconds while motion stays "
            "active (default 60; --nvr-segment-seconds on `watch` overrides per-run)\n"
            "    nvr.segment_seconds  — optional newer name for max_duration, wins if "
            "both are set (not written to new configs automatically, so setting "
            "max_duration always works)\n"
            "    nvr.smb.host / .share / .username / .password / .path\n"
            "    nvr.smb.delete_after_upload — remove local file after successful upload\n"
            "\n"
            "  ⚠️  BETA — test before use in production. Requires ffmpeg."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py nvr status\n"
            "    python3 bosch_camera.py nvr status Garten\n"
            "    python3 bosch_camera.py nvr list Garten --limit 10\n"
            "    python3 bosch_camera.py nvr prune Garten --keep 20\n"
            "    python3 bosch_camera.py nvr upload Garten\n"
            "    python3 bosch_camera.py nvr upload --clip captures/Garten/nvr/2026-05-17/120000.mp4"
        ),
    )
    nvr_sub = p_nvr.add_subparsers(dest="nvr_sub", metavar="<subcommand>")

    p_nvr_status = nvr_sub.add_parser("status", help="Show NVR status")
    p_nvr_status.add_argument("cam", nargs="?", help="Camera name (optional)")

    p_nvr_list = nvr_sub.add_parser("list", help="List recorded clips")
    p_nvr_list.add_argument("cam", nargs="?", help="Camera name (optional)")
    p_nvr_list.add_argument(
        "--limit", type=int, default=20, metavar="N", help="Max clips to show (default: 20)"
    )

    p_nvr_prune = nvr_sub.add_parser("prune", help="FIFO prune old clips")
    p_nvr_prune.add_argument("cam", nargs="?", help="Camera name (optional)")
    p_nvr_prune.add_argument(
        "--keep",
        type=int,
        default=None,
        metavar="N",
        help="Keep N most recent clips (default: nvr.max_clips from config)",
    )

    p_nvr_upload = nvr_sub.add_parser("upload", help="Upload clips to SMB/NAS")
    p_nvr_upload.add_argument("cam", nargs="?", help="Camera name (optional)")
    p_nvr_upload.add_argument(
        "--clip", metavar="PATH", help="Upload a specific clip (default: all pending)"
    )

    # ── intercom ────────────────────────────────────────────────────────────────
    p_intercom = subparsers.add_parser(
        "intercom",
        help="Open two-way audio (intercom) to a camera",
        description=(
            "🎤  intercom — Open a two-way audio session to a camera\n"
            "\n"
            "  Opens a live audio connection to the camera via the cloud proxy.\n"
            "  Plays camera audio through local speakers using ffplay.\n"
            "\n"
            "  Requires: ffmpeg (brew install ffmpeg)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py intercom Kamera\n"
            "    python3 bosch_camera.py intercom Garten --duration 120\n"
            "    python3 bosch_camera.py intercom Kamera --speaker-level 80"
        ),
    )
    p_intercom.add_argument("cam", nargs="?", help="Camera name")
    p_intercom.add_argument(
        "--duration", type=int, default=60, help="Session duration in seconds (default 60)"
    )
    p_intercom.add_argument(
        "--speaker-level", type=int, default=50, help="Speaker volume 0-100 (default 50)"
    )

    # ── maintenance ────────────────────────────────────────────────────────────
    p_maint = subparsers.add_parser(
        "maintenance",
        help="Show Bosch cloud maintenance / outage status",
        description=(
            "🔧  maintenance — Check Bosch community RSS for announced maintenance\n"
            "\n"
            "  Fetches the Bosch Smart Home community boards 'Wartungsarbeiten'\n"
            "  and 'Statusmeldungen'. Returns the best-match announcement with its\n"
            "  state (active / scheduled / past / recent / unknown).\n"
            "\n"
            "  Falls back to HTML scraping when the RSS feeds are unavailable.\n"
            "  Returns None (or null in JSON) only when all sources fail."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py maintenance\n"
            "    python3 bosch_camera.py maintenance --json"
        ),
    )
    p_maint.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit raw JSON (MaintenanceWindow dict) for scripting",
    )

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
    p_motion.add_argument("--enable", action="store_true", help="Enable motion detection")
    p_motion.add_argument("--disable", action="store_true", help="Disable motion detection")
    p_motion.add_argument(
        "--sensitivity",
        choices=["OFF", "LOW", "MEDIUM_LOW", "MEDIUM_HIGH", "HIGH", "SUPER_HIGH"],
        metavar="S",
        help="Sensitivity: OFF | LOW | MEDIUM | HIGH | SUPER_HIGH",
    )

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
    p_rec.add_argument(
        "--sound-on", action="store_true", dest="sound_on", help="Enable sound recording"
    )
    p_rec.add_argument(
        "--sound-off", action="store_true", dest="sound_off", help="Disable sound recording"
    )

    # ── audio (mic/speaker levels) ─────────────────────────────────────────────
    p_audio_levels = subparsers.add_parser(
        "audio",
        help="Get/set microphone and speaker levels (0-100)",
        description=(
            "🎙️  audio — Get or set microphone and speaker volume levels\n"
            "\n"
            "  Reads or writes microphoneLevel and speakerLevel (each 0-100).\n"
            "  API: GET/PUT /v11/video_inputs/{id}/audio\n"
            "\n"
            '  Body: {"audioEnabled": bool, "microphoneLevel": 0-100, "speakerLevel": 0-100}'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py audio Garten\n"
            "    python3 bosch_camera.py audio Garten --mic 60\n"
            "    python3 bosch_camera.py audio Garten --speaker 80\n"
            "    python3 bosch_camera.py audio Garten --mic 60 --speaker 80\n"
            "    python3 bosch_camera.py audio --json"
        ),
    )
    p_audio_levels.add_argument(
        "cam", nargs="?", help="Camera name (optional, all cameras if omitted)"
    )
    p_audio_levels.add_argument("--mic", type=int, metavar="N", help="Microphone level 0-100")
    p_audio_levels.add_argument("--speaker", type=int, metavar="N", help="Speaker level 0-100")
    p_audio_levels.add_argument(
        "--json", action="store_true", default=False, help="Machine-readable JSON output"
    )

    # ── intrusion detection config ─────────────────────────────────────────────
    p_intrusion = subparsers.add_parser(
        "intrusion",
        help="Get/set intrusion detection config (mode/sensitivity/distance)",
        description=(
            "🚨  intrusion — Get or set intrusion detection configuration\n"
            "\n"
            "  Reads or writes detectionMode, sensitivity (0-7), and distance (1-8).\n"
            "  API: GET/PUT /v11/video_inputs/{id}/intrusionDetectionConfig\n"
            "\n"
            "  Mode: indoor (ALL_MOTIONS) | outdoor (ZONES)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py intrusion Garten\n"
            "    python3 bosch_camera.py intrusion Garten --mode outdoor\n"
            "    python3 bosch_camera.py intrusion Garten --sensitivity 4\n"
            "    python3 bosch_camera.py intrusion Garten --distance 8\n"
            "    python3 bosch_camera.py intrusion Garten --mode indoor --sensitivity 4 --distance 6\n"
            "    python3 bosch_camera.py intrusion --json"
        ),
    )
    p_intrusion.add_argument(
        "cam", nargs="?", help="Camera name (optional, all cameras if omitted)"
    )
    p_intrusion.add_argument(
        "--mode", metavar="MODE", help="Detection mode: indoor (ALL_MOTIONS) or outdoor (ZONES)"
    )
    p_intrusion.add_argument(
        "--sensitivity", type=int, metavar="N", help="Sensitivity 0-7 (higher = more sensitive)"
    )
    p_intrusion.add_argument(
        "--distance",
        type=int,
        metavar="N",
        help="Detection distance 1-8 (Bosch rejects >8 with HTTP 400)",
    )
    p_intrusion.add_argument(
        "--json", action="store_true", default=False, help="Machine-readable JSON output"
    )

    # ── wifi info ─────────────────────────────────────────────────────────────
    p_wifi = subparsers.add_parser(
        "wifi",
        help="Show WiFi info (RSSI, SSID, signal strength)",
        description=(
            "📶  wifi — Show WiFi connection info for cameras\n"
            "\n"
            "  Fetches RSSI (dBm), SSID, and signal strength percentage.\n"
            "  API: GET /v11/video_inputs/{id}/wifiinfo\n"
            "\n"
            "  Read-only: no set operation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py wifi\n"
            "    python3 bosch_camera.py wifi Garten\n"
            "    python3 bosch_camera.py wifi --json"
        ),
    )
    p_wifi.add_argument("cam", nargs="?", help="Camera name (optional, all cameras if omitted)")
    p_wifi.add_argument(
        "--json", action="store_true", default=False, help="Machine-readable JSON output"
    )

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
    p_af.add_argument(
        "action", nargs="?", choices=["on", "off"], help="on = enable auto-follow, off = disable"
    )

    # ── siren ─────────────────────────────────────────────────────────────────
    p_siren = subparsers.add_parser(
        "siren",
        help="Trigger or stop the panic alarm (siren) on a Gen2 Indoor II camera",
        description=(
            "🔔  siren — Trigger or stop the panic alarm on a camera\n"
            "\n"
            "  Endpoint depends on camera model:\n"
            "    HOME_Eyes_Indoor (Gen2 Indoor II): PUT /panic_alarm — 75 dB siren ✓\n"
            "    INDOOR / OUTDOOR (Gen1):           /acoustic_alarm → HTTP 404 (broken)\n"
            "\n"
            "  Use --stop to cancel an active panic alarm before its configured\n"
            "  duration expires.\n"
            "  Use --set-duration N to update the siren duration (10–300 s) via\n"
            "  PUT /alarm_settings (alarmDelayInSeconds) and then trigger the alarm.\n"
            "  Duration is stored camera-side; subsequent triggers use the saved value."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_siren.add_argument("cam", nargs="?", help="Camera name")
    p_siren.add_argument(
        "--stop",
        action="store_true",
        default=False,
        help="Stop an active panic alarm instead of triggering one",
    )
    p_siren.add_argument(
        "--set-duration",
        type=int,
        metavar="SECS",
        dest="set_duration",
        help="Set siren duration in seconds (10–300) via alarm_settings, then trigger alarm",
    )

    # ── unread ────────────────────────────────────────────────────────────────
    p_unread = subparsers.add_parser(
        "unread",
        help="Show unread event count per camera",
        description=(
            "📬  unread — Show unread event count per camera\n"
            "\n"
            "  Queries each camera for the number of unread events."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_unread.add_argument("cam", nargs="?", help="Camera name (optional, all cameras if omitted)")

    # ── privacy-sound ─────────────────────────────────────────────────────
    p_psound = subparsers.add_parser(
        "privacy-sound",
        help="Show or toggle privacy sound (audible indicator when privacy mode changes)",
        description=(
            "🔊  privacy-sound — Show or toggle privacy sound override\n"
            "\n"
            "  When enabled, the camera plays an audible indicator whenever\n"
            "  privacy mode is toggled on or off.\n"
            "  API: GET/PUT /v11/video_inputs/{id}/privacy_sound_override\n"
            '       Body: {"result": true/false}'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py privacy-sound\n"
            "    python3 bosch_camera.py privacy-sound Garten\n"
            "    python3 bosch_camera.py privacy-sound on\n"
            "    python3 bosch_camera.py privacy-sound Garten on\n"
            "    python3 bosch_camera.py privacy-sound Garten off"
        ),
    )
    p_psound.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_psound.add_argument(
        "action",
        nargs="?",
        metavar="on|off",
        choices=["on", "off"],
        help="Enable or disable privacy sound",
    )

    # ── audio-detection ──────────────────────────────────────────────────
    p_adet = subparsers.add_parser(
        "audio-detection",
        help="Get/set glass-break + smoke/fire-alarm sound detection (Gen2 Audio-Plus)",
        description=(
            "🔔  audio-detection — Get or set glass-break + fire-alarm sound detection\n"
            "\n"
            "  Gen2 Audio-Plus cameras can listen for glass-break and smoke/fire-alarm\n"
            "  sounds. Both flags are read-modify-write: a PUT always sends both\n"
            "  fields, so setting one never resets the other.\n"
            "  API: GET/PUT /v11/video_inputs/{id}/audioDetectionConfig\n"
            '       Body: {"detectGlassBreak": bool, "detectFireAlarm": bool}'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py audio-detection\n"
            "    python3 bosch_camera.py audio-detection Garten\n"
            "    python3 bosch_camera.py audio-detection Garten --glass-break on\n"
            "    python3 bosch_camera.py audio-detection Garten --fire-alarm off\n"
            "    python3 bosch_camera.py audio-detection Garten --glass-break on --fire-alarm on\n"
            "    python3 bosch_camera.py audio-detection --json"
        ),
    )
    p_adet.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_adet.add_argument(
        "--glass-break",
        dest="glass_break",
        metavar="on|off",
        choices=["on", "off"],
        help="Enable or disable glass-break sound detection",
    )
    p_adet.add_argument(
        "--fire-alarm",
        dest="fire_alarm",
        metavar="on|off",
        choices=["on", "off"],
        help="Enable or disable smoke/fire-alarm sound detection",
    )
    p_adet.add_argument(
        "--json", action="store_true", default=False, help="Machine-readable JSON output"
    )

    # ── rules ─────────────────────────────────────────────────────────────
    p_rules = subparsers.add_parser(
        "rules",
        help="Manage camera automation rules (time-based schedules)",
        description=(
            "📋  rules — Manage camera automation rules\n"
            "\n"
            "  Time-based schedules stored on the camera.\n"
            "  API: GET/POST/PUT/DELETE /v11/video_inputs/{id}/rules\n"
            "\n"
            "  Subcommands:\n"
            "    (none)  → list all rules for a camera\n"
            "    add     → create a new rule with name, time, days\n"
            "    edit    → update an existing rule (activate/deactivate)\n"
            "    delete  → remove a rule by ID"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py rules Garten\n"
            "    python3 bosch_camera.py rules Garten add --name 'Night Mode' --start 22:00 --end 06:00 --days 0,1,2,3,4,5,6\n"
            "    python3 bosch_camera.py rules Garten edit --id UUID --active\n"
            "    python3 bosch_camera.py rules Garten edit --id UUID --inactive\n"
            "    python3 bosch_camera.py rules Garten delete --id UUID"
        ),
    )
    p_rules.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_rules.add_argument(
        "sub",
        nargs="?",
        metavar="add|edit|delete",
        help="Subcommand: add, edit, or delete a rule",
    )
    p_rules.add_argument("--name", dest="rule_name", metavar="NAME", help="Rule name (for add)")
    p_rules.add_argument(
        "--start", default="00:00", metavar="HH:MM", help="Start time (for add, default 00:00)"
    )
    p_rules.add_argument(
        "--end", default="23:59", metavar="HH:MM", help="End time (for add, default 23:59)"
    )
    p_rules.add_argument(
        "--days",
        default="0,1,2,3,4,5,6",
        metavar="0,1,2,...",
        help="Weekdays 0=Mon..6=Sun comma-separated (for add, default all)",
    )
    p_rules.add_argument(
        "--id", dest="rule_id", metavar="RULE_ID", help="Rule ID (for edit/delete)"
    )
    p_rules.add_argument("--active", action="store_true", help="Activate the rule (for edit)")
    p_rules.add_argument("--inactive", action="store_true", help="Deactivate the rule (for edit)")

    # ── friends ───────────────────────────────────────────────────────────
    p_friends = subparsers.add_parser(
        "friends",
        help="Manage camera sharing with friends",
        description=(
            "👥  friends — Manage camera sharing with friends\n"
            "\n"
            "  Invite friends, share cameras, manage invitations.\n"
            "  API: GET/POST/PUT/DELETE /v11/friends/*\n"
            "\n"
            "  Subcommands:\n"
            "    (none)  → list all friends\n"
            "    invite  → send invitation to an email address\n"
            "    share   → share a camera with a friend\n"
            "    unshare → remove all camera shares from a friend\n"
            "    resend  → re-send the invitation email\n"
            "    remove  → remove a friend entirely"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py friends\n"
            "    python3 bosch_camera.py friends invite user@example.com\n"
            "    python3 bosch_camera.py friends share FRIEND_ID Garten\n"
            "    python3 bosch_camera.py friends share FRIEND_ID Garten --days 7\n"
            "    python3 bosch_camera.py friends unshare FRIEND_ID\n"
            "    python3 bosch_camera.py friends resend FRIEND_ID\n"
            "    python3 bosch_camera.py friends remove FRIEND_ID"
        ),
    )
    p_friends.add_argument(
        "sub",
        nargs="?",
        metavar="invite|share|unshare|resend|remove",
        help="Subcommand",
    )
    p_friends.add_argument(
        "sub_arg",
        nargs="?",
        metavar="EMAIL|FRIEND_ID",
        help="Email (for invite) or Friend ID (for other subcommands)",
    )
    p_friends.add_argument(
        "share_cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name (for share subcommand)",
    )
    p_friends.add_argument(
        "--days", type=int, metavar="N", help="Share duration in days (for share; omit = permanent)"
    )

    # ── accept-invite ─────────────────────────────────────────────────────
    p_accept = subparsers.add_parser(
        "accept-invite",
        help="Accept an incoming friend/camera sharing invitation",
        description=(
            "📨  accept-invite — Accept a friend invitation\n"
            "\n"
            "  Accepts an incoming camera sharing invitation using the\n"
            "  invitation token received from a friend.\n"
            "\n"
            "  API: POST /v11/friends/accept"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("  Examples:\n    python3 bosch_camera.py accept-invite ABC123TOKEN"),
    )
    p_accept.add_argument(
        "token",
        metavar="TOKEN",
        help="Invitation token from the friend invitation",
    )

    # ── shared ────────────────────────────────────────────────────────────
    p_shared = subparsers.add_parser(
        "shared",
        help="Show which friends have access to a camera",
        description=(
            "🔗  shared — Show friends with access to a camera\n"
            "\n"
            "  Lists all friends who have been granted access to\n"
            "  a specific camera via camera sharing.\n"
            "\n"
            "  API: GET /v11/video_inputs/{id}/shared_with_friends"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py shared\n"
            "    python3 bosch_camera.py shared Garten"
        ),
    )
    p_shared.add_argument(
        "cam", nargs="?", metavar="<camera>", help="Camera name (optional, default: all cameras)"
    )

    # ── zones ─────────────────────────────────────────────────────────────
    p_zones = subparsers.add_parser(
        "zones",
        help="Manage motion detection zones (cloud API)",
        description=(
            "🎯  zones — Manage motion detection zones\n"
            "\n"
            "  Normalized 0.0–1.0 rectangles stored on the camera.\n"
            "  API: GET/POST /v11/video_inputs/{id}/motion_sensitive_areas\n"
            "\n"
            "  Subcommands:\n"
            "    (none)  → list current zones\n"
            "    set     → replace zones from a JSON array (--json)\n"
            "    clear   → remove all zones"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py zones Garten\n"
            '    python3 bosch_camera.py zones Garten set --json \'[{"x":0.0,"y":0.3,"w":0.67,"h":0.7}]\'\n'
            "    python3 bosch_camera.py zones Garten clear"
        ),
    )
    p_zones.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_zones.add_argument(
        "sub", nargs="?", metavar="set|clear", help="Subcommand: set or clear zones"
    )
    p_zones.add_argument(
        "--json", metavar="JSON", help="Zones as a JSON array of {x,y,w,h} (for set)"
    )

    # ── privacy-masks ─────────────────────────────────────────────────────
    p_pmasks = subparsers.add_parser(
        "privacy-masks",
        help="Manage privacy mask zones (cloud API)",
        description=(
            "🛡️  privacy-masks — Manage privacy mask zones\n"
            "\n"
            "  Normalized 0.0–1.0 rectangles blacked out in the video.\n"
            "  API: GET/POST /v11/video_inputs/{id}/privacy_masks\n"
            "\n"
            "  Subcommands:\n"
            "    (none)  → list current masks\n"
            "    set     → replace masks from a JSON array (--json)\n"
            "    clear   → remove all masks"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py privacy-masks Garten\n"
            '    python3 bosch_camera.py privacy-masks Garten set --json \'[{"x":0.0,"y":0.0,"w":0.3,"h":0.3}]\'\n'
            "    python3 bosch_camera.py privacy-masks Garten clear"
        ),
    )
    p_pmasks.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_pmasks.add_argument(
        "sub", nargs="?", metavar="set|clear", help="Subcommand: set or clear masks"
    )
    p_pmasks.add_argument(
        "--json", metavar="JSON", help="Masks as a JSON array of {x,y,w,h} (for set)"
    )

    # ── lighting-schedule ─────────────────────────────────────────────────
    p_lsched = subparsers.add_parser(
        "lighting-schedule",
        help="View or modify the LED lighting schedule (outdoor cameras)",
        description=(
            "💡  lighting-schedule — LED light schedule\n"
            "\n"
            "  Only available for outdoor cameras (Eyes) with an LED light.\n"
            "  API: GET/PUT /v11/video_inputs/{id}/lighting_options\n"
            "\n"
            "  Subcommands:\n"
            "    (none)  → show current schedule\n"
            "    set     → update on/off time, motion, darkness threshold"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py lighting-schedule Garten\n"
            "    python3 bosch_camera.py lighting-schedule Garten set --on 18:00 --off 23:00 --motion --threshold 0.4"
        ),
    )
    p_lsched.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_lsched.add_argument("sub", nargs="?", metavar="set", help="Subcommand: set the schedule")
    p_lsched.add_argument("--on", metavar="HH:MM", help="Light-on time (for set)")
    p_lsched.add_argument("--off", metavar="HH:MM", help="Light-off time (for set)")
    p_lsched.add_argument(
        "--motion",
        action="store_true",
        default=None,
        help="Turn on light when motion is detected (for set)",
    )
    p_lsched.add_argument(
        "--threshold", type=float, metavar="0.0-1.0", help="Darkness threshold 0.0–1.0 (for set)"
    )

    # ── firmware-update ──────────────────────────────────────────────────
    p_fwupdate = subparsers.add_parser(
        "firmware-update",
        help="View firmware update status, or install a pending update",
        description=(
            "🔧  firmware-update — camera firmware status + install\n"
            "\n"
            "  API: GET /v11/video_inputs/{id}/firmware, PUT (install) same endpoint.\n"
            "\n"
            "  Subcommands:\n"
            "    (none)   → show installed/latest version + up-to-date status\n"
            "    install  → install the pending update (camera reboots 3-7 min)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py firmware-update Garten\n"
            "    python3 bosch_camera.py firmware-update Garten install"
        ),
    )
    p_fwupdate.add_argument(
        "cam",
        nargs="?",
        metavar="<camera>",
        help="Camera name or partial match (omit = all cameras)",
    )
    p_fwupdate.add_argument(
        "sub", nargs="?", metavar="install", help="Subcommand: install the update"
    )
    p_fwupdate.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the confirmation prompt when installing on all cameras",
    )

    # ── rename ────────────────────────────────────────────────────────────
    p_rename = subparsers.add_parser(
        "rename",
        help="Rename a camera",
        description=(
            "✏️   rename — Rename a camera via the Bosch cloud API\n"
            "\n"
            "  Changes the camera title stored in the Bosch cloud.\n"
            "  Also updates the local bosch_config.json.\n"
            "  API: PUT /v11/video_inputs"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            '    python3 bosch_camera.py rename Garten "Garden Camera"\n'
            '    python3 bosch_camera.py rename Kamera "Indoor Cam"'
        ),
    )
    p_rename.add_argument(
        "cam",
        metavar="<camera>",
        help="Current camera name or partial match",
    )
    p_rename.add_argument(
        "new_name",
        metavar='"New Name"',
        help="New camera name (use quotes if it contains spaces)",
    )

    # ── profile ───────────────────────────────────────────────────────────
    p_profile = subparsers.add_parser(
        "profile",
        help="Show or edit user profile (name, email, marketing consent)",
        description=(
            "👤  profile — Show or edit user profile\n"
            "\n"
            "  Displays account info from the Bosch cloud:\n"
            "  name, email, last login, marketing consent, IoT integration.\n"
            "\n"
            "  API: GET /v11/registration/check, PUT /v11/registration"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py profile\n"
            "    python3 bosch_camera.py profile edit --display-name 'John'\n"
            "    python3 bosch_camera.py profile edit --marketing off\n"
            "    python3 bosch_camera.py profile edit --display-name 'John' --marketing on"
        ),
    )
    p_profile.add_argument(
        "sub",
        nargs="?",
        metavar="edit",
        help="Subcommand: 'edit' to update profile",
    )
    p_profile.add_argument(
        "--display-name", dest="display_name", metavar="NAME", help="New display name"
    )
    p_profile.add_argument("--marketing", metavar="on|off", help="Marketing consent: on or off")

    # ── account ───────────────────────────────────────────────────────────
    subparsers.add_parser(
        "account",
        help="Show account info: feature flags, contracts, subscriptions",
        description=(
            "📊  account — Show account information\n"
            "\n"
            "  Displays feature flags, terms & conditions versions,\n"
            "  and active purchases/subscriptions.\n"
            "\n"
            "  API: GET /v11/feature_flags, GET /v11/contracts, GET /v11/purchases"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  Example:\n    python3 bosch_camera.py account",
    )

    # ── timestamp ──────────────────────────────────────────────────────────
    p_ts = subparsers.add_parser(
        "timestamp",
        help="Get or set time/date overlay on camera video",
        description=(
            "🕐  timestamp — Control the time/date overlay on camera video\n"
            "\n"
            "  API: GET/PUT /v11/video_inputs/{id}/timestamp\n"
            '       Body: {"result": true/false}'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py timestamp\n"
            "    python3 bosch_camera.py timestamp kamera on\n"
            "    python3 bosch_camera.py timestamp garten off"
        ),
    )
    p_ts.add_argument(
        "cam", nargs="?", metavar="<camera>", help="Camera name (optional, default: all)"
    )
    p_ts.add_argument(
        "action", nargs="?", metavar="on|off", help="on = show overlay, off = hide overlay"
    )

    # ── notification-types ─────────────────────────────────────────────────
    p_nt = subparsers.add_parser(
        "notification-types",
        help="Show or toggle per-type notification settings",
        description=(
            "🔔  notification-types — Per-type notification toggles\n"
            "\n"
            "  Types: movement, person, audio, trouble, cameraAlarm\n"
            "  API: GET/PUT /v11/video_inputs/{id}/notifications"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py notification-types\n"
            "    python3 bosch_camera.py notification-types kamera --set movement=on person=off"
        ),
    )
    p_nt.add_argument(
        "cam", nargs="?", metavar="<camera>", help="Camera name (optional, default: all)"
    )
    p_nt.add_argument(
        "--set",
        nargs="+",
        metavar="key=on|off",
        help="Set notification types (e.g. movement=on person=off)",
    )

    # ── snapshot-mjpeg (F1) ────────────────────────────────────────────────
    p_smj = subparsers.add_parser(
        "snapshot-mjpeg",
        help="Fast JPEG snapshot via FFmpeg/RTSP (Gen2 only)",
        description=(
            "🎞️   snapshot-mjpeg — Fast JPEG snapshot via FFmpeg (Gen2 only)\n"
            "\n"
            "  Captures a single frame directly from the camera's RTSP stream\n"
            "  using FFmpeg. ~150-300 ms faster than the cloud snap.jpg method.\n"
            "\n"
            "  Requires: Gen2 camera (HOME_Eyes_*), LAN reachability, ffmpeg installed.\n"
            "  Credentials are fetched automatically via PUT /connection LOCAL.\n"
            "\n"
            "  On Gen1 or FFmpeg error: prints 'skipped' and exits cleanly."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py snapshot-mjpeg\n"
            "    python3 bosch_camera.py snapshot-mjpeg Terrasse\n"
            "    python3 bosch_camera.py snapshot-mjpeg Terrasse -o /tmp/snap.jpg"
        ),
    )
    p_smj.add_argument(
        "cam", nargs="?", metavar="<camera>", help="Camera name (optional, default: all Gen2)"
    )
    p_smj.add_argument(
        "-o",
        "--output",
        dest="output",
        metavar="PATH",
        help="Output file path (default: mjpeg_snapshot_<cam>_<ts>.jpg in script dir)",
    )

    # ── onvif-scopes (F4) ─────────────────────────────────────────────────
    p_ov = subparsers.add_parser(
        "onvif-scopes",
        help="Read ONVIF scopes from camera via LAN RCP (0x0a98)",
        description=(
            "📡  onvif-scopes — Read ONVIF scope strings from camera (LAN)\n"
            "\n"
            "  Reads RCP opcode 0x0a98 directly from the camera over HTTPS+Digest.\n"
            "  Decodes null-terminated ASCII TLV payload → scope strings.\n"
            "\n"
            "  Credentials are fetched automatically via PUT /connection LOCAL."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py onvif-scopes\n"
            "    python3 bosch_camera.py onvif-scopes Terrasse\n"
            "    python3 bosch_camera.py onvif-scopes Terrasse --json"
        ),
    )
    p_ov.add_argument(
        "cam", nargs="?", metavar="<camera>", help="Camera name (optional, default: all)"
    )
    p_ov.add_argument("--json", dest="json", action="store_true", help="Output as JSON")

    # ── rcp-version (F6) ──────────────────────────────────────────────────
    p_rv = subparsers.add_parser(
        "rcp-version",
        help="Show RCP protocol version (opcodes 0xff00 + 0xff04)",
        description=(
            "🔢  rcp-version — Print RCP protocol version\n"
            "\n"
            "  Reads RCP opcodes 0xff00 (primary) and 0xff04 (secondary)\n"
            "  via the cloud proxy. Returns a 4-part version string.\n"
            "\n"
            "  Example output:\n"
            "    HOME_Eyes_Outdoor FW 9.40.102: RCP v1.2.38.150"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py rcp-version\n"
            "    python3 bosch_camera.py rcp-version Terrasse"
        ),
    )
    p_rv.add_argument(
        "cam", nargs="?", metavar="<camera>", help="Camera name (optional, default: all)"
    )

    # ── feature-flags (F13) ───────────────────────────────────────────────
    p_ff = subparsers.add_parser(
        "feature-flags",
        help="Show Bosch cloud feature flags for this account",
        description=(
            "🏁  feature-flags — Show account-level feature flags\n"
            "\n"
            "  GET /v11/feature_flags — shows which cloud features are enabled\n"
            "  for your account (e.g. APP_RATING, IOT_THINGS_INTEGRATION, ...).\n"
            "\n"
            "  Use --json for machine-readable output."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 bosch_camera.py feature-flags\n"
            "    python3 bosch_camera.py feature-flags --json"
        ),
    )
    p_ff.add_argument("--json", dest="json", action="store_true", help="Output as JSON")

    # ── global --lang ──────────────────────────────────────────────────────────
    from bosch_i18n import AVAILABLE_LANGS as _AVAILABLE_LANGS

    parser.add_argument(
        "--lang",
        choices=list(_AVAILABLE_LANGS),
        metavar="LANG",
        default=None,
        help=t("help.lang"),
    )

    # ── parse ──────────────────────────────────────────────────────────────────
    args = parser.parse_args()

    # Note: cmd_* functions read optional args exclusively via
    # getattr(args, "name", fallback) with per-call fallbacks. We deliberately do
    # NOT pre-populate missing attributes here — the previous `_defaults` dict
    # has been removed so argparse's own Namespace is the single source of truth.

    # Load (or create) config
    cfg = load_config()

    # Initialise i18n — --lang flag overrides config and $LANG
    if getattr(args, "lang", None):
        set_lang(args.lang)
    else:
        set_lang(detect_lang(cfg))

    if not args.command:
        # If no cameras yet, do initial discovery
        if not cfg.get("cameras"):
            print(t("cli.first_run"))
            token = get_token(cfg)
            session = make_session(token)
            cameras = discover_cameras(cfg, session)
            if cameras:
                print(t("cli.found_cameras", count=len(cameras), names=", ".join(cameras.keys())))
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
        "status": cmd_status,
        "info": cmd_info,
        "snapshot": cmd_snapshot,
        "live": cmd_live,
        # "download" and "events" removed (Bosch request)
        "ping": cmd_ping,
        "lan-ips": cmd_lan_ips,
        "privacy": cmd_privacy,
        "light": cmd_light,
        "pan": cmd_pan,
        "notifications": cmd_notifications,
        "watch": cmd_watch,
        "nvr": cmd_nvr,
        "motion": cmd_motion,
        "recording": cmd_recording,
        "audio": cmd_audio,
        "intrusion": cmd_intrusion,
        "wifi": cmd_wifi,
        "autofollow": cmd_autofollow,
        "siren": cmd_siren,
        "unread": cmd_unread,
        "privacy-sound": cmd_privacy_sound,
        "audio-detection": cmd_audio_detection,
        "rules": cmd_rules,
        "friends": cmd_friends,
        "accept-invite": cmd_accept_invite,
        "shared": cmd_shared_with_friends,
        "zones": cmd_zones,
        "privacy-masks": cmd_privacy_masks,
        "lighting-schedule": cmd_lighting_schedule,
        "firmware-update": cmd_firmware_update,
        "rename": cmd_rename,
        "profile": cmd_profile,
        "account": cmd_account,
        "intercom": cmd_intercom,
        "maintenance": cmd_maintenance,
        "rcp": cmd_rcp,
        "token": cmd_token,
        "config": cmd_config,
        "rescan": cmd_rescan,
        "timestamp": cmd_timestamp,
        "notification-types": cmd_notification_types,
        "test-local": cmd_test_local,
        # ── Diagnostic & Performance Commands (F1/F4/F6/F13) ───────────────
        "snapshot-mjpeg": cmd_snapshot_mjpeg,
        "onvif-scopes": cmd_onvif_scopes,
        "rcp-version": cmd_rcp_version,
        "feature-flags": cmd_feature_flags,
    }
    if cmd not in dispatch:
        print(t("err.unknown_command", cmd=cmd))
        sys.exit(1)
    dispatch[cmd](cfg, args)


if __name__ == "__main__":
    main()
