#!/usr/bin/env python3
"""
Bosch Smart Home Camera — Automatic Token Manager
Version: 1.0.0
==================================================
Obtains and manages the Bearer JWT token needed to access the Bosch cloud API.
No mitmproxy needed after the first login.

How it works:
  1. If a refresh_token is saved in bosch_config.json
     → renews access_token silently (no browser, no user interaction)
  2. Otherwise → opens a browser for a one-time login via SingleKey ID
     → starts a local HTTP server on http://localhost:8321/callback
     → Bosch Keycloak redirects back after login — code is captured automatically
     → exchanges it for access_token + refresh_token
     → saves both to bosch_config.json

After the first browser login, all future renewals are fully automatic.
Refresh tokens have the "offline_access" scope and last a very long time.

Usage:
  python3 get_token.py                  # auto: refresh or browser login
  python3 get_token.py --browser        # force new browser login
  python3 get_token.py --refresh        # force refresh_token renewal only
  python3 get_token.py --show           # show current token status
"""

import os
import sys
import json
import hashlib
import base64
import secrets
import webbrowser
import argparse
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode

import requests

urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "bosch_config.json")

KEYCLOAK_BASE = (
    "https://smarthome.authz.bosch.com"
    "/auth/realms/home_auth_provider/protocol/openid-connect"
)
CLIENT_ID     = "oss_residential_app"

CLIENT_SECRET = base64.b64decode("RjFqWnpzRzVOdHc3eDJWVmM4SjZxZ3NuaXNNT2ZhWmc=").decode()
SCOPES        = "email offline_access profile openid"
REDIRECT_URI  = "http://localhost:8321/callback"
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════ CONFIG ════════════════════════════════════════════

def load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        print(f"❌  Config not found: {CONFIG_FILE}")
        print("    Run bosch_camera.py first to create it.")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return json.load(f)


def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)


# ══════════════════════════ PKCE ══════════════════════════════════════════════

def _pkce_pair() -> tuple[str, str]:
    verifier  = secrets.token_urlsafe(64)
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _build_auth_url(code_challenge: str, state: str) -> str:
    params = {
        "client_id":             CLIENT_ID,
        "response_type":         "code",
        "scope":                 SCOPES,
        "redirect_uri":          REDIRECT_URI,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
        "state":                 state,
    }
    return f"{KEYCLOAK_BASE}/auth?" + urlencode(params)


# ══════════════════════════ CALLBACK SERVER ═══════════════════════════════════

def _wait_for_callback(timeout: int = 120) -> str | None:
    """
    Start a local HTTP server on localhost:8321 to capture the OAuth callback.

    After login, Bosch Keycloak redirects to http://localhost:8321/callback?code=...
    The server captures the auth code automatically and shows a success page.
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading

    auth_code = None
    error_msg = None

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal auth_code, error_msg
            qs = parse_qs(urlparse(self.path).query)

            err = qs.get("error", [None])[0]
            if err:
                error_msg = qs.get("error_description", [err])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<html><body><h2>Login Error</h2><p>{error_msg}</p></body></html>".encode())
                return

            auth_code = qs.get("code", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if auth_code:
                self.wfile.write(
                    b"<html><body style='font-family:sans-serif;text-align:center;padding:60px'>"
                    b"<h2 style='color:#2e7d32'>&#10004; Login successful!</h2>"
                    b"<p>You can close this tab and return to the terminal.</p>"
                    b"</body></html>"
                )
            else:
                self.wfile.write(b"<html><body><h2>No auth code received.</h2></body></html>")

        def log_message(self, format, *args):
            pass  # suppress HTTP log noise

    print()
    print("  ┌─ Steps ──────────────────────────────────────────────────┐")
    print("  │  1. Log in with your Bosch SingleKey ID in the browser   │")
    print("  │  2. After login, the browser redirects back here         │")
    print("  │  3. The auth code is captured automatically              │")
    print("  └──────────────────────────────────────────────────────────┘")
    print()

    try:
        server = HTTPServer(("127.0.0.1", 8321), CallbackHandler)
    except OSError as e:
        print(f"  ❌  Cannot start callback server on port 8321: {e}")
        return _wait_for_callback_manual()

    server.timeout = timeout

    def serve():
        server.handle_request()  # handle exactly one request

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    print(f"  ⏳  Waiting for login callback on http://localhost:8321/callback ...")
    t.join(timeout=timeout)
    server.server_close()

    if error_msg:
        print(f"  ❌  Login error: {error_msg}")
        return None
    if not auth_code:
        print(f"  ❌  Timeout — no callback received within {timeout}s.")
        return _wait_for_callback_manual()

    print("  ✅  Auth code received automatically!")
    return auth_code


def _wait_for_callback_manual() -> str | None:
    """Fallback: ask user to paste the redirect URL manually."""
    print()
    print("  ➡️   Paste the full redirect URL from your browser:")
    try:
        raw = input("  URL: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw:
        return None
    if "?" in raw:
        raw = raw.split("?", 1)[1]
    qs = parse_qs(raw)
    error = qs.get("error", [None])[0]
    if error:
        print(f"  ❌  Login error: {qs.get('error_description', [error])[0]}")
        return None
    code = qs.get("code", [None])[0]
    if not code:
        print(f"  ❌  No 'code' found in the URL.")
        return None
    return code


# ══════════════════════════ TOKEN EXCHANGE ════════════════════════════════════

def _exchange_code(auth_code: str, code_verifier: str) -> dict | None:
    r = requests.post(
        f"{KEYCLOAK_BASE}/token",
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          auth_code,
            "redirect_uri":  REDIRECT_URI,
            "code_verifier": code_verifier,
        },
        verify=False, timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    print(f"  ❌  Token exchange failed: HTTP {r.status_code}")
    print(f"      {r.text[:300]}")
    return None


def _do_refresh(refresh: str) -> dict | None:
    r = requests.post(
        f"{KEYCLOAK_BASE}/token",
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type":    "refresh_token",
            "refresh_token": refresh,
        },
        verify=False, timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    print(f"  ⚠️   Refresh failed: HTTP {r.status_code} — {r.text[:80]}")
    return None


# ══════════════════════════ MAIN FLOW ═════════════════════════════════════════

def get_token_auto(cfg: dict, force_browser: bool = False) -> str | None:
    """
    Obtain a valid access token using the best available method.
    Saves access_token + refresh_token to config.
    Returns access_token or None.
    """
    acct = cfg.setdefault("account", {})

    # ── Method 1: Refresh token (silent) ─────────────────────────────────────
    saved_refresh = acct.get("refresh_token", "").strip()
    if saved_refresh and not force_browser:
        print("  🔄  Renewing token via saved refresh_token...")
        tokens = _do_refresh(saved_refresh)
        if tokens:
            access  = tokens.get("access_token", "")
            refresh = tokens.get("refresh_token", saved_refresh)
            acct["bearer_token"]  = access
            acct["refresh_token"] = refresh
            save_config(cfg)
            print(f"  ✅  Token renewed ({len(access)} chars) — saved to bosch_config.json")
            return access
        print("  ℹ️   Refresh token expired — falling back to browser login.")
        acct["refresh_token"] = ""

    # ── Method 2: Browser PKCE login ─────────────────────────────────────────
    username = acct.get("username", "your email")
    print(f"\n  🌐  Opening browser login (SingleKey ID)...")
    print(f"      Account: {username}")
    print()

    verifier, challenge = _pkce_pair()
    state    = secrets.token_urlsafe(16)
    auth_url = _build_auth_url(challenge, state)

    webbrowser.open(auth_url)
    print(f"  If the browser didn't open, go to:\n  {auth_url}\n")

    code = _wait_for_callback(timeout=120)
    if not code:
        print("  ❌  No auth code received.")
        return None

    print("  ✅  Auth code received — exchanging for tokens...")
    tokens = _exchange_code(code, verifier)
    if not tokens:
        return None

    access  = tokens.get("access_token", "")
    refresh = tokens.get("refresh_token", "")

    acct["bearer_token"]  = access
    acct["refresh_token"] = refresh
    save_config(cfg)

    print(f"  ✅  Access token:  {len(access)} chars")
    if refresh:
        print(f"  ✅  Refresh token: {len(refresh)} chars — saved for automatic renewal")
        print("      Next token refresh will be silent (no browser).")
    else:
        print("  ⚠️   No refresh_token — you'll need to log in again when this token expires.")
    return access


def show_token_info(cfg: dict) -> None:
    acct    = cfg.get("account", {})
    token   = acct.get("bearer_token", "")
    refresh = acct.get("refresh_token", "")

    print("\n── Token Status ───────────────────────────────────────────────")
    if token:
        print(f"  Access token:  {token[:30]}...  ({len(token)} chars)")
        try:
            import datetime
            pad  = len(token.split(".")[1]) % 4
            body = base64.urlsafe_b64decode(token.split(".")[1] + "=" * pad)
            info = json.loads(body)
            exp  = info.get("exp", 0)
            exp_dt = datetime.datetime.fromtimestamp(exp)
            diff   = exp_dt - datetime.datetime.now()
            mins   = int(diff.total_seconds() / 60)
            status = f"valid ~{mins}m ✅" if mins > 0 else f"EXPIRED {abs(mins)}m ago ❌"
            print(f"  Email:         {info.get('email', '')}")
            print(f"  Expires:       {exp_dt.strftime('%Y-%m-%d %H:%M')}  ({status})")
        except Exception:
            pass
    else:
        print("  Access token:  (none)")
    if refresh:
        print(f"  Refresh token: {refresh[:20]}...  ({len(refresh)} chars) — auto-renewal ✅")
    else:
        print("  Refresh token: (none) — browser login required when token expires")
    print()


# ══════════════════════════ CLI ═══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Bosch camera token manager")
    parser.add_argument("--browser",  action="store_true", help="Force new browser login")
    parser.add_argument("--refresh",  action="store_true", help="Force refresh_token renewal")
    parser.add_argument("--show",     action="store_true", help="Show current token status")
    args = parser.parse_args()

    cfg = load_config()

    if args.show:
        show_token_info(cfg)
        return

    if args.refresh:
        refresh = cfg.get("account", {}).get("refresh_token", "")
        if not refresh:
            print("  ❌  No refresh_token. Run without --refresh to log in via browser.")
            sys.exit(1)
        tokens = _do_refresh(refresh)
        if tokens:
            cfg["account"]["bearer_token"]  = tokens.get("access_token", "")
            cfg["account"]["refresh_token"] = tokens.get("refresh_token", refresh)
            save_config(cfg)
            print("  ✅  Token refreshed.")
        show_token_info(cfg)
        return

    token = get_token_auto(cfg, force_browser=args.browser)
    if token:
        show_token_info(cfg)
    else:
        print("\n  ❌  Could not obtain a token.")
        sys.exit(1)


if __name__ == "__main__":
    main()
