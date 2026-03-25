#!/usr/bin/env python3
"""
Bosch Smart Camera — mitmproxy Helper
======================================
Starts a mitmproxy instance pre-configured for capturing Bosch Smart Camera
app traffic. Useful for:
  - Discovering new API endpoints
  - Capturing local camera Digest auth credentials
  - Investigating motion detection rule changes
  - Debugging app ↔ cloud communication

Requirements:
  pip3 install mitmproxy

Usage:
  python3 start_proxy.py              # auto-detect IP, port 8890
  python3 start_proxy.py --port 9090  # custom port
  python3 start_proxy.py --dump       # save flows to file for later analysis

Then configure your phone's WiFi proxy to point to this Mac.
See README.md section "Capturing App Traffic with mitmproxy" for full setup.
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from datetime import datetime


def get_local_ip() -> str:
    """Get the Mac's local IP address on the active network interface."""
    try:
        result = subprocess.run(
            ["ipconfig", "getifaddr", "en0"],
            capture_output=True, text=True, timeout=5,
        )
        ip = result.stdout.strip()
        if ip:
            return ip
    except Exception:
        pass

    # Fallback: connect to external host to find local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_mitmproxy() -> bool:
    """Check if mitmproxy is installed."""
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Start mitmproxy for Bosch Smart Camera app traffic capture"
    )
    parser.add_argument(
        "--port", type=int, default=8890,
        help="Proxy listen port (default: 8890)"
    )
    parser.add_argument(
        "--dump", action="store_true",
        help="Save captured flows to a timestamped file for later analysis"
    )
    parser.add_argument(
        "--filter", type=str, default="",
        help="Filter expression (e.g. '~d boschsecurity.com' for Bosch traffic only)"
    )
    args = parser.parse_args()

    if not check_mitmproxy():
        print("  mitmproxy is not installed.")
        print("  Install it with: pip3 install mitmproxy")
        sys.exit(1)

    local_ip = get_local_ip()
    port = args.port

    # Dump file location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dump_dir = os.path.join(script_dir, "captures")
    os.makedirs(dump_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    dump_file = os.path.join(dump_dir, f"bosch_flows_{timestamp}.mitm")

    print()
    print("=" * 64)
    print("  Bosch Smart Camera — mitmproxy Capture")
    print("=" * 64)
    print()
    print(f"  Proxy address:  {local_ip}:{port}")
    if args.dump:
        print(f"  Saving flows:   {dump_file}")
    print()
    print("  Phone Setup (iOS / Android):")
    print("  ─────────────────────────────────────────────────────")
    print(f"  1. WiFi → your network → Proxy → Manual")
    print(f"     Server: {local_ip}   Port: {port}")
    print(f"  2. Open http://mitm.it on the phone browser")
    print(f"     → download + install the CA certificate")
    print(f"  3. iOS: Settings → General → About → Certificate Trust")
    print(f"     → enable mitmproxy cert")
    print(f"  4. Force-close the Bosch Smart Camera app")
    print(f"  5. Reopen the app — traffic appears below")
    print()
    print("  What to look for:")
    print("  ─────────────────────────────────────────────────────")
    print("  • Motion detection changes:")
    print("    PUT /v11/video_inputs/{id}/motion")
    print("    PUT /v11/video_inputs/{id}/rules/{ruleId}")
    print("  • Local camera credentials:")
    print("    Watch for Digest auth headers to camera LAN IPs")
    print("  • Bearer token (in Authorization header):")
    print("    Copy to bosch_config.json if needed")
    print()
    print("  Press Ctrl+C to stop the proxy.")
    print("=" * 64)
    print()

    # Build mitmdump command
    cmd = [
        "mitmdump",
        "--listen-host", local_ip,
        "--listen-port", str(port),
        "--set", "console_eventlog_verbosity=info",
        "--showhost",
    ]

    if args.dump:
        cmd.extend(["--save-stream-file", dump_file])

    if args.filter:
        cmd.extend(["--flow-filter", args.filter])

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print()
        print()
        if args.dump and os.path.exists(dump_file):
            size = os.path.getsize(dump_file) / 1024
            print(f"  Flows saved to: {dump_file} ({size:.0f} KB)")
            print(f"  View later:     mitmproxy --rfile \"{dump_file}\"")
        print()
        print("  Don't forget to remove the proxy from your phone's WiFi settings!")
        print()


if __name__ == "__main__":
    main()
