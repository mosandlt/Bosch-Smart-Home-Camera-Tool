# Bosch Smart Home Camera — Python CLI Tool

> **Reverse-engineered** Bosch Cloud API client for Bosch Smart Home cameras.
> Live snapshots, event downloads, live video stream — all from the command line.
> No official API. No app needed after setup.

---

## Disclaimer

**This project is an independent, community-developed tool. It is not affiliated
with, endorsed by, sponsored by, or in any way officially connected to Robert Bosch
GmbH, Bosch Smart Home GmbH, or any of their subsidiaries or affiliates.
"Bosch", "Bosch Smart Home", and related names and logos are registered trademarks
of Robert Bosch GmbH.**

This tool communicates with a reverse-engineered, undocumented, and unofficial API.
The author(s) provide this software **"as is", without warranty of any kind**,
express or implied, including but not limited to warranties of merchantability,
fitness for a particular purpose, or non-infringement.

**By using this software, you agree that:**

- You use it entirely **at your own risk**.
- The author(s) shall not be held liable for any direct, indirect, incidental,
  special, or consequential damages arising from the use of, or inability to use,
  this software — including but not limited to data loss, service disruption,
  account suspension, or device damage.
- The API may be changed, restricted, or shut down by Bosch at any time without
  notice, which may render this tool non-functional.
- You are solely responsible for ensuring your use complies with Bosch's Terms of
  Service and any applicable laws in your jurisdiction.
- All rights and any legal recourse are expressly disclaimed by the author(s).
  Any use of this software is entirely your own responsibility.

**Reverse engineering notice:** The API was discovered solely for the purpose of
achieving interoperability with the user's own devices and data, which is explicitly
permitted under **§ 69e of the German Copyright Act (UrhG)** and **Article 6 of
EU Directive 2009/24/EC** on the legal protection of computer programs. No copy
of Bosch's software was distributed. Only network protocol observations were used.

---

## Features

| Feature | Command |
|---------|---------|
| Camera status (ONLINE / OFFLINE) | `status` |
| Latest event snapshot (motion-triggered JPEG) | `snapshot` |
| Live snapshot — current image, ~1.5 s | `liveshot` |
| Live video stream in ffplay window | `live` |
| Download all events (JPEG + MP4) | `download` |
| Recent event list | `events` |
| Automatic token via browser login | `get_token.py` |
| Silent token renewal (no browser) | automatic |

---

## Requirements

```bash
pip3 install requests
brew install ffmpeg          # macOS — provides ffplay for live video
```

Python 3.10+ required (uses `str | None` union type syntax).

---

## Quick Start

### 1. First run

```bash
python3 bosch_camera.py
```

On first run the tool:
1. Creates `bosch_config.json` with empty defaults
2. Opens your browser for a one-time Bosch SingleKey ID login
3. Saves the `refresh_token` — all future logins are silent and automatic
4. Discovers all your cameras and saves them to config
5. Asks for the local IP of each camera (optional, press Enter to skip)
6. Opens the interactive menu

### 2. Interactive menu

Run without arguments to get the menu:

```
╔══════════════════════════════════════════════════════════╗
║        Bosch Smart Home Camera — Control Panel           ║
╚══════════════════════════════════════════════════════════╝

  1)  Camera status (ONLINE / OFFLINE)
  2)  Latest event snapshot — Outdoor
  3)  Latest event snapshot — Indoor
  4)  Latest event snapshot — ALL cameras
  5)  Live snapshot — Outdoor  (remote/local)
  6)  Live snapshot — Indoor  (remote/local)
  7)  Live stream — Outdoor (ffplay video window)
  8)  Live stream — Indoor (ffplay video window)
  ...
  0)  Exit
```

Press a number, the command runs, then press Enter to return to the menu.

### 3. CLI usage

```bash
# Status
python3 bosch_camera.py status

# Snapshots
python3 bosch_camera.py snapshot Outdoor          # latest motion-triggered JPEG
python3 bosch_camera.py liveshot Outdoor          # current live image (~1.5s)
python3 bosch_camera.py snapshot --live           # all cameras, live

# Live video (ffplay window, ~1 fps MJPEG)
python3 bosch_camera.py live Outdoor

# Download events
python3 bosch_camera.py download                  # all cameras
python3 bosch_camera.py download Outdoor
python3 bosch_camera.py download Outdoor --limit 50
python3 bosch_camera.py download Outdoor --snaps-only
python3 bosch_camera.py download Outdoor --clips-only

# Events list
python3 bosch_camera.py events Outdoor --limit 20

# Config
python3 bosch_camera.py config                   # show current config
python3 bosch_camera.py rescan                   # re-discover cameras
```

---

## How It Works

### System Overview

```
┌─────────────┐    Bearer JWT     ┌──────────────────────────────┐
│  This tool  │ ────────────────► │  Bosch Cloud API             │
│  (Python)   │                   │  residential.cbs.bosch       │
└─────────────┘                   │  security.com                │
                                  └──────────────┬───────────────┘
                                                 │
                                  ┌──────────────▼───────────────┐
                                  │  Proxy Server (live only)    │
                                  │  proxy-NN.live.cbs.bosch     │
                                  │  security.com:42090          │
                                  └──────────────┬───────────────┘
                                                 │
                                  ┌──────────────▼───────────────┐
                                  │  Camera (via SHC)            │
                                  │  Bosch CAMERA_EYES / 360     │
                                  └──────────────────────────────┘
```

All camera access goes through the Bosch Cloud — there is no supported
direct local API. The Smart Home Controller (SHC) bridges the camera
to the cloud.

---

### Authentication — Bearer JWT Token

The API uses OAuth2 with JWT Bearer tokens issued by Bosch's Keycloak server.

**Token properties:**
- Issuer: `smarthome.authz.bosch.com`
- Audience: `https://residential.cbs.boschsecurity.com/app`
- Client ID: `residential_app`
- Lifetime: ~1 hour
- Refresh token scope: `offline_access` → lasts very long (months)

**Login flow (PKCE + `client_secret`):**

```
1. Script generates code_verifier + code_challenge (SHA256, S256)
2. Browser opens:
   https://smarthome.authz.bosch.com/auth/realms/home_auth_provider/
   protocol/openid-connect/auth?client_id=residential_app&
   response_type=code&scope=email+offline_access+profile+openid&
   redirect_uri=https://www.bosch.com/boschcam&
   code_challenge=...&code_challenge_method=S256
3. User logs in with SingleKey ID
4. Browser redirects to https://www.bosch.com/boschcam?code=...
   (shows a 404 page — that's expected)
5. User pastes the full URL into the terminal
6. Script extracts the code and POSTs to the token endpoint:
   POST /protocol/openid-connect/token
   grant_type=authorization_code&code=...&
   client_secret=...&code_verifier=...
7. Response: {access_token, refresh_token, expires_in}
8. Both tokens saved to bosch_config.json
```

**Silent renewal (subsequent runs):**
```
POST /protocol/openid-connect/token
grant_type=refresh_token&refresh_token={saved_token}&client_secret=...
→ New access_token + rotated refresh_token
```

All of this is handled automatically by `get_token.py`, which is imported
and called by `bosch_camera.py` on startup when the saved token is missing.

---

### Event Snapshots (motion-triggered)

Every time a camera detects motion, the Bosch backend stores:
- A JPEG snapshot
- An MP4 video clip (uploaded asynchronously, status: `"Done"` when ready)

```
GET /v11/events?videoInputId={camera-uuid}&limit=400
Authorization: Bearer {token}
```

Response (array):
```json
[
  {
    "id": "abc123",
    "timestamp": "2026-03-19T12:00:00.000Z",
    "eventType": "MOTION_DETECTED",
    "imageUrl": "https://residential.cbs.boschsecurity.com/v11/events/abc123/snap.jpg",
    "videoClipUrl": "https://residential.cbs.boschsecurity.com/v11/events/abc123/clip.mp4",
    "videoClipUploadStatus": "Done"
  },
  ...
]
```

Both `imageUrl` and `videoClipUrl` are authenticated with the same Bearer
token and downloaded directly. Files are named
`YYYY-MM-DD_HH-MM-SS_{type}_{id}.jpg/mp4`.

---

### Live Snapshot — Current Image

To get the **current** camera image (not the last motion event), the tool
opens a live proxy connection:

```
PUT /v11/video_inputs/{camera-uuid}/connection
Authorization: Bearer {token}
Content-Type: application/json

{"type": "REMOTE"}
```

Response:
```json
{
  "bufferingTime": 1000,
  "user": null,
  "password": null,
  "urls": ["proxy-20.live.cbs.boschsecurity.com:42090/{hash}"],
  "imageUrlScheme":  "https://{url}/snap.jpg",
  "videoUrlScheme":  "rtsp://{url}/rtsp_tunnel?inst=1&enableaudio=1&fmtp=1&maxSessionDuration=60",
  "httpsUrlScheme":  "https://{url}/",
  "rtspUrl": null
}
```

Replace `{url}` with `urls[0]` to get the live snap URL:
```
https://proxy-20.live.cbs.boschsecurity.com:42090/{hash}/snap.jpg
```

This URL requires **no authentication** — the session hash is the credential.
It returns a full **1920×1080 JPEG** of the current camera view.

The proxy session expires after ~60 seconds. A new `PUT /connection` opens
a new session.

**Connection types:**

| Type | URL returns | Auth for snap | Speed |
|------|-------------|---------------|-------|
| `REMOTE` | Cloud proxy host:port/hash | None (hash = credential) | ~1.5 s |
| `LOCAL` | Camera LAN IP:443 | HTTP Digest (user/password in response) | ~15 s |

`REMOTE` is always faster. `LOCAL` is only useful as a fallback if the
cloud is unreachable.

---

### Live Video Stream

Standard RTSP players (VLC, ffplay) **cannot** open the `rtsp://` URL from
the proxy — the camera uses a proprietary RTSP-over-HTTPS tunnel that
requires the Bosch app's custom protocol stack.

The tool works around this by polling `snap.jpg` and serving it as MJPEG:

```
1. PUT /connection REMOTE → get proxy snap URL
2. Start Python HTTP server on localhost:PORT
3. Background thread fetches snap.jpg every 1 second
4. HTTP server serves frames as multipart/x-mixed-replace (MJPEG)
5. ffplay opens http://localhost:PORT → displays live video window
6. Press Q in ffplay to stop
```

This gives ~1 fps live view at full 1920×1080 resolution.

---

### Download

```
GET /v11/events?videoInputId={id}&limit=400
```

The tool iterates all events and downloads:
- `snap.jpg` for each event with `imageUrl`
- `clip.mp4` for each event with `videoClipUploadStatus == "Done"`

Already-downloaded files are skipped (by filename). Rate-limited to
0.5 s between requests to avoid API throttling.

---

## Token Management

### Automatic (recommended)

```bash
python3 get_token.py           # first login → browser → saves refresh_token
python3 get_token.py --refresh # force silent renewal via saved refresh_token
python3 get_token.py --show    # show token info + expiry time
python3 get_token.py --browser # force new browser login (if refresh expired)
```

After the first login, `bosch_camera.py` renews the token automatically
on every run — no browser, no user interaction.

### Manual (mitmproxy fallback)

If the browser login flow fails, you can capture a token directly from
the Bosch Smart Home Camera app using mitmproxy:

1. Install: `pip3 install mitmproxy`
2. Find your Mac's local IP: `ipconfig getifaddr en0`
3. Start the proxy:
   ```bash
   mitmdump --listen-host YOUR_MAC_IP --listen-port 8890
   ```
4. On your iPhone: **Settings → WiFi → your network → Configure Proxy → Manual**
   - Server: `YOUR_MAC_IP`, Port: `8890`
5. Visit `http://mitm.it` on the phone → install CA cert → enable Certificate Trust
6. Force-close and reopen the **Bosch Smart Home Camera** app
7. The terminal shows the Bearer token — copy it
8. Add to `bosch_config.json`:
   ```json
   "bearer_token": "eyJ..."
   ```

> Note: The Bosch Cloud API (`residential.cbs.boschsecurity.com`) uses SSL
> pinning in the app. mitmproxy intercepts at the OS level after installing
> the CA cert, which bypasses the pin.

---

## Cloud API Reference

```
Base URL:  https://residential.cbs.boschsecurity.com
Auth:      Authorization: Bearer {token}
SSL:       Use verify=False — Bosch uses a private root CA not in the system store
```

### All Known Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v11/video_inputs` | List all cameras (id, title, model, firmware, mac) |
| `GET` | `/v11/video_inputs/{id}` | Single camera details |
| `GET` | `/v11/video_inputs/{id}/ping` | Returns `"ONLINE"` or `"OFFLINE"` |
| `GET` | `/v11/video_inputs/{id}/firmware` | Firmware version info |
| `GET` | `/v11/events?videoInputId={id}` | All events for a camera |
| `GET` | `/v11/events?videoInputId={id}&limit=N` | Limited event list |
| `GET` | `{event.imageUrl}` | Download event JPEG snapshot |
| `GET` | `{event.videoClipUrl}` | Download event MP4 clip |
| `PUT` | `/v11/video_inputs/{id}/connection` | Open live proxy connection |
| `GET` | `/v11/feature_flags` | Feature flags for the account |
| `GET` | `/v11/purchases` | Subscription / purchase info |
| `GET` | `/v11/contracts?locale=de_DE` | Contract info |

### Live Proxy Endpoints (after PUT /connection)

```
https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/snap.jpg
  → Current camera image (1920×1080 JPEG, no auth needed)

https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/snap.jpg?JpegSize=1206
  → Smaller image (1206px wide)

rtsp://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/rtsp_tunnel?inst=1&enableaudio=1&fmtp=1&maxSessionDuration=60
  → RTSP stream (proprietary tunnel, not openable with standard players)
```

---

## Config File Reference

`bosch_config.json` (auto-created on first run):

```json
{
  "account": {
    "username":      "your.email@example.com",
    "bearer_token":  "eyJ...",
    "refresh_token": "eyJ..."
  },
  "cameras": {
    "Outdoor": {
      "id":              "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name":            "Outdoor",
      "model":           "CAMERA_EYES",
      "firmware":        "x.xx.xx",
      "mac":             "xx:xx:xx:xx:xx:xx",
      "download_folder": "Outdoor",
      "local_ip":        "",
      "local_username":  "",
      "local_password":  ""
    }
  },
  "settings": {
    "download_base_path":    "",
    "scan_interval_seconds": 30,
    "request_delay_seconds": 0.5
  }
}
```

| Field | Description |
|-------|-------------|
| `bearer_token` | Current JWT access token (auto-renewed on startup) |
| `refresh_token` | Long-lived token for silent renewal, keep this safe |
| `id` | Bosch Cloud camera UUID — discovered automatically |
| `download_folder` | Subfolder name for downloaded events |
| `local_ip` | Optional: LAN IP for direct camera access |
| `local_username` | Optional: Digest auth username (randomly set by SHC) |
| `local_password` | Optional: Digest auth password (randomly set by SHC) |
| `download_base_path` | Where to save events. Empty = same folder as script |

Local credentials (`local_username` / `local_password`) are randomly
generated by the Smart Home Controller during camera pairing. They can
be captured via mitmproxy from the **Bosch Smart Home** (not Camera) app
traffic. These are optional — the cloud API works without them.

> ⚠️ **Warning:** Too many direct HTTPS requests to the camera's local IP
> can break the LAN connection, causing the SHC to regenerate credentials.

---

## Troubleshooting

**Token expired / HTTP 401**
→ Run `python3 get_token.py` to renew. If the refresh_token is also expired
  (after months of inactivity), use `python3 get_token.py --browser` for
  a new browser login.

**Camera OFFLINE**
→ Check the Bosch Smart Home Controller app. The camera may have lost its
  LAN connection to the SHC.

**Live stream shows only one frame**
→ Make sure `ffmpeg` / `ffplay` is installed: `brew install ffmpeg`

**Live snapshot slow (~15 s)**
→ The tool tried LOCAL first and it timed out. This is normal if no local
  credentials are set. REMOTE fallback works in ~1.5 s.

**`get_token.py` browser login fails**
→ Make sure you paste the **full redirect URL** (starting with
  `https://www.bosch.com/boschcam?code=...`), not just the code.
  The page shows a 404 — that is expected.

**Download stops mid-way**
→ Token expired during a large download. Re-run `python3 get_token.py`
  and restart the download. Already-downloaded files are skipped.

---

## File Structure

```
tool/
  bosch_camera.py      — main CLI tool (all commands + interactive menu)
  get_token.py         — OAuth2 PKCE token manager (browser login + renewal)
  bosch_config.json    — auto-created config (credentials + camera list)
  README.md            — this file
  Outdoor/             — downloaded outdoor camera events (JPEG + MP4)
  Indoor/              — downloaded indoor camera events (JPEG + MP4)
```

---

## Known Limitations

- **Live video is ~1 fps** — the `snap.jpg` polling approach is a workaround
  for the proprietary RTSP tunnel. True video streaming would require
  reverse-engineering the Bosch app's RTSP-over-HTTPS protocol.
- **Proxy session = 60 s** — after 60 seconds the proxy hash expires and
  the live stream stops. The `live` command opens a new session each time.
- **No audio** — the snap.jpg approach is video only.
- **Cloud dependency** — everything goes through `residential.cbs.boschsecurity.com`.
  There is no documented local API on the SHC for camera images.

---

## Related

- [Bosch SHC API Issue #63](https://github.com/BoschSmartHome/bosch-shc-api-docs/issues/63) — community discussion on camera API
- [Bosch SHC API Issue #30](https://github.com/BoschSmartHome/bosch-shc-api-docs/issues/30) — camera integration discussion
- [boschshcpy](https://github.com/tschamm/boschshcpy) — Python library for the local SHC API (not camera images)
