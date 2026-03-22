# Bosch Smart Home Camera — Python CLI Tool

> **Reverse-engineered** Bosch Cloud API client for Bosch Smart Home cameras.
> Live snapshots, event downloads, live video stream, privacy mode, light, notifications, pan control, RCP protocol reads, and real-time event watching — all from the command line.
> No official API. No app needed after setup. **v1.8.0**

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
| Full camera info + live stream URLs | `info` |
| Latest event snapshot (motion-triggered JPEG) | `snapshot` |
| Live snapshot — current image, ~1.5 s | `liveshot` |
| **Live stream — 30fps H.264 + AAC audio** | `live` |
| Live stream in VLC | `live --vlc` |
| Live stream — high quality | `live --hq` or `live --quality high` |
| Live stream — low bandwidth | `live --quality low` |
| Live stream — select instance | `live --inst N` |
| Download all events (JPEG + MP4) | `download` |
| Recent event list | `events` |
| **Privacy mode — get/set via cloud API** | `privacy [cam] [on\|off]` |
| **Camera light — on/off via cloud API** | `light [cam] [on\|off]` |
| **Push notifications — on/off** | `notifications [cam] [on\|off]` |
| **Pan 360 camera** | `pan [cam] [left\|center\|right\|<-120..120>]` |
| **RCP reads via cloud proxy** | `rcp [cam] <info\|clock\|snapshot\|alarms\|...>` |
| **Real-time event watching** | `watch [cam] [--interval N] [--duration N] [--snapshot]` |
| **Motion detection — get/set** | `motion [cam] [--enable\|--disable] [--sensitivity S]` |
| **Audio alarm — get/set** | `audio-alarm [cam] [--enable\|--disable] [--threshold N]` |
| **Recording options — sound on/off** | `recording [cam] [--sound-on\|--sound-off]` |
| Automatic token via browser login | `get_token.py` |
| Silent token renewal / token fix | `token [fix\|browser]` |

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
  2)  Camera info (full details + stream URLs)
  3)  Latest event snapshot — Outdoor
  4)  Latest event snapshot — Indoor
  5)  Latest event snapshot — ALL cameras
  6)  Live snapshot — Outdoor  (remote/local)
  7)  Live snapshot — Indoor  (remote/local)
  8)  Live stream — Outdoor (ffplay, audio+video)
  9)  Live stream — Indoor (ffplay, audio+video)
  10) Live stream — Outdoor (VLC, audio+video)
  11) Live stream — Indoor (VLC, audio+video)
  ...
  0)  Exit
```

Press a number, the command runs, then press Enter to return to the menu.

### 3. CLI usage

```bash
# Status & Info
python3 bosch_camera.py status
python3 bosch_camera.py info               # full details + live stream URLs
python3 bosch_camera.py info --full        # also fetch firmware, motion, audio, ambient light, WiFi

# Snapshots
python3 bosch_camera.py snapshot Outdoor          # latest motion-triggered JPEG
python3 bosch_camera.py liveshot Outdoor          # current live image (~1.5s)
python3 bosch_camera.py snapshot --live           # all cameras, live
python3 bosch_camera.py liveshot Outdoor --hq     # high-quality live snapshot

# Live stream — 30fps H.264 + AAC audio
python3 bosch_camera.py live Outdoor              # opens in ffplay
python3 bosch_camera.py live Outdoor --vlc        # opens in VLC
python3 bosch_camera.py live Outdoor --hq         # request high-quality (highest bitrate tier)
python3 bosch_camera.py live Outdoor --inst 1     # use stream instance 1 instead of 2
python3 bosch_camera.py live Garten --quality high    # 30 Mbps stream (inst=1, highQualityVideo=true)
python3 bosch_camera.py live Garten --quality low     # low bandwidth (inst=4, ~1.9 Mbps)
python3 bosch_camera.py live Garten --quality auto    # default balanced (inst=2, ~7.5 Mbps)

# Download events
python3 bosch_camera.py download                  # all cameras
python3 bosch_camera.py download Outdoor
python3 bosch_camera.py download Outdoor --limit 50
python3 bosch_camera.py download Outdoor --snaps-only
python3 bosch_camera.py download Outdoor --clips-only

# Events list
python3 bosch_camera.py events Outdoor --limit 20

# Privacy mode (cloud API — no SHC needed)
python3 bosch_camera.py privacy                  # show all cameras' privacy state
python3 bosch_camera.py privacy Outdoor          # show one camera's privacy state
python3 bosch_camera.py privacy Outdoor on       # enable privacy mode (indefinite)
python3 bosch_camera.py privacy Outdoor on --minutes 30  # enable privacy for 30 minutes
python3 bosch_camera.py privacy Outdoor off      # disable privacy mode

# Camera light (cloud API — no SHC needed)
python3 bosch_camera.py light                    # show light state (all cameras)
python3 bosch_camera.py light Outdoor            # show light state (one camera)
python3 bosch_camera.py light Outdoor on         # turn camera light on
python3 bosch_camera.py light Outdoor off        # turn camera light off

# Push notifications
python3 bosch_camera.py notifications                # show notification state (all)
python3 bosch_camera.py notifications Outdoor on     # enable notifications (FOLLOW_CAMERA_SCHEDULE)
python3 bosch_camera.py notifications Outdoor off    # disable notifications (ALWAYS_OFF)

# Pan (CAMERA_360 only)
python3 bosch_camera.py pan Indoor left          # pan to left limit
python3 bosch_camera.py pan Indoor center        # pan to center (0°)
python3 bosch_camera.py pan Indoor right         # pan to right limit
python3 bosch_camera.py pan Indoor 45            # pan to absolute position (degrees)

# RCP protocol reads via cloud proxy
python3 bosch_camera.py rcp info                 # all cameras: product name, FQDN, LAN IP, MAC
python3 bosch_camera.py rcp Outdoor info         # identity for one camera
python3 bosch_camera.py rcp Outdoor clock        # real-time camera clock
python3 bosch_camera.py rcp Outdoor snapshot     # RCP JPEG thumbnail 160×90 — save + open
python3 bosch_camera.py rcp Outdoor alarms       # alarm catalog (UTF-16-BE strings)
python3 bosch_camera.py rcp Outdoor privacy      # privacy mask state read
python3 bosch_camera.py rcp Outdoor dimmer       # LED dimmer value 0-100
python3 bosch_camera.py rcp Outdoor motion       # motion zone count + coordinates
python3 bosch_camera.py rcp Outdoor services     # network services list
python3 bosch_camera.py rcp Outdoor frame        # raw video frame 320x180 YUV422 -> JPEG
python3 bosch_camera.py rcp Outdoor script       # IVA automation script (gzip -> text)
python3 bosch_camera.py rcp Outdoor iva          # IVA rule types + resiMotion config
python3 bosch_camera.py rcp Outdoor bitrate      # bitrate ladder tiers in kbps
python3 bosch_camera.py rcp Outdoor all          # run all RCP reads

# Watch for new events in real-time
python3 bosch_camera.py watch                    # all cameras, poll every 30s
python3 bosch_camera.py watch Garten             # one camera
python3 bosch_camera.py watch Garten --interval 15  # poll every 15s
python3 bosch_camera.py watch --duration 600     # stop after 10 minutes

# Motion detection
python3 bosch_camera.py motion Garten            # show current settings
python3 bosch_camera.py motion Garten --enable   # enable motion detection
python3 bosch_camera.py motion Garten --disable  # disable motion detection
python3 bosch_camera.py motion Garten --enable --sensitivity SUPER_HIGH
python3 bosch_camera.py motion Garten --sensitivity MEDIUM

# Audio alarm
python3 bosch_camera.py audio-alarm Garten       # show current settings
python3 bosch_camera.py audio-alarm Garten --enable  # enable audio alarm
python3 bosch_camera.py audio-alarm Garten --disable # disable audio alarm
python3 bosch_camera.py audio-alarm Garten --enable --threshold 60

# Recording options
python3 bosch_camera.py recording Garten         # show current settings
python3 bosch_camera.py recording Garten --sound-on   # record with audio
python3 bosch_camera.py recording Garten --sound-off  # record without audio

# Token
python3 bosch_camera.py token                    # show token info + expiry
python3 bosch_camera.py token fix                # silent renewal via refresh_token
python3 bosch_camera.py token browser            # force new browser login

# Config
python3 bosch_camera.py config                   # show current config
python3 bosch_camera.py rescan                   # re-discover cameras
```

---

## What's New in v1.8.0

- **RCP session caching**: The 2-step RCP handshake (0xff0c + 0xff0d) is now cached per proxy connection with a 5-minute TTL. Subsequent `rcp` subcommands on the same camera reuse the existing session, avoiding two redundant round-trips.
- **`watch --snapshot`**: New flag — when a new event arrives, automatically downloads the event JPEG and opens it in the default viewer. Example: `python3 bosch_camera.py watch Garten --snapshot`
- **`rcp snapshot` resolution fix**: Now reads `0x0a88` first to confirm the camera's configured snapshot resolution (320×180), then fetches `0x099e`. The saved filename and output now show the actual resolution instead of the incorrect "160×90".

## What's New in v1.7.0

- **`--quality` flag for `live` and `snapshot`**: convenience preset that sets both `highQualityVideo` and `inst` in one flag.

| `--quality` | `highQualityVideo` | `inst` | Approx. bitrate | Notes |
|-------------|-------------------|--------|----------------|-------|
| `auto` (default) | `false` | `2` | ~7.5 Mbps | iOS app default, balanced |
| `high` | `true` | `1` | ~30 Mbps | Primary encoder, maximum quality |
| `low` | `false` | `4` | ~1.9 Mbps | Low bandwidth / remote access |

---

## What's New in v1.6.0

- **`watch` command**: real-time event polling — polls `GET /v11/events` every N seconds (default 30) and prints new events as they arrive, with type, timestamp, snapshot URL, and clip URL. Supports `--interval N` and `--duration N` (infinite by default). Handles token expiry automatically.
- **`motion` command**: get or set motion detection settings via `GET/PUT /v11/video_inputs/{id}/motion`. Supports `--enable`, `--disable`, and `--sensitivity OFF|LOW|MEDIUM|HIGH|SUPER_HIGH`.
- **`audio-alarm` command**: get or set audio alarm settings via `GET/PUT /v11/video_inputs/{id}/audioAlarm`. Supports `--enable`, `--disable`, and `--threshold N` (0–100).
- **`recording` command**: get or set cloud recording options via `GET/PUT /v11/video_inputs/{id}/recording_options`. Supports `--sound-on` and `--sound-off`.

---

## What's New in v1.5.0

- **Streaming stability fix**: `maxSessionDuration` changed from 60 → 3600 seconds — prevents forced stream reconnection every 60 s
- **`--hq` flag for `live`**: pass `highQualityVideo: true` in `PUT /connection` to request the highest bitrate tier
- **`--hq` flag for `snapshot` / `liveshot`**: same high-quality flag for proxy live snapshots
- **`--inst N` flag for `live`**: select the RTSPS stream instance in the URL (default 2; use 1 for the alternative stream)
- **`rcp bitrate` subcommand**: reads the camera's bitrate ladder (0x0c81) and displays all tiers in kbps/Mbps; included in `rcp all`

---

## What's New in v1.4.0

- New `rcp frame` subcommand: fetches a live 320×180 YUV422 raw video frame (0x0c98, 115,200 bytes) directly via RCP, converts to JPEG using numpy + Pillow (falls back to raw `.yuv` if not installed)
- New `rcp script` subcommand: fetches the gzip-compressed IVA automation script (0x09f3), decompresses it, and prints the Bosch IVA scripting language source
- New `rcp iva` subcommand: reads IVA rule type names (0x0ba9, null-separated ASCII list) and the resiMotion motion detection config (0x0a1b, polygon coordinates + sensitivity params)
- All 3 new subcommands included in `rcp all`

---

## What's New in v1.3.0

- New `rcp` command: read low-level camera data via the RCP (Remote Configuration Protocol) tunnelled through the cloud proxy
- RCP subcommands: `info`, `clock`, `snapshot`, `alarms`, `privacy`, `dimmer`, `motion`, `services`, `all`
- `info --full` now includes an RCP section: product name, cloud FQDN, camera clock, LAN IP
- RCP session handshake (0xff0c / 0xff0d) implemented; no additional auth beyond the proxy hash

---

## What's New in v1.2.0

- `info --full` flag: fetches 8 additional per-camera endpoints (firmware, motion, audio alarm, ambient light, WiFi, recording options, light override, commissioned state)
- `privacy on --minutes N`: timed privacy mode via `privacyTimeSeconds`
- WiFi info now shown in standard `info` output (SSID, signal, IP, MAC)
- All `PUT /connection` calls now include `highQualityVideo: false` (matches app behaviour)
- Live stream URL uses `inst=2` (correct proxy stream index, as used by the app)
- Proxy snap 404 handling: automatic retry with a new connection session
- 3-state notification display: `ALWAYS_OFF`, `FOLLOW_CAMERA_SCHEDULE`, `ON_CAMERA_SCHEDULE`

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
  "videoUrlScheme":  "rtsp://{url}/rtsp_tunnel?inst=1&enableaudio=1&fmtp=1&maxSessionDuration=60",  ← server returns inst=1 but app uses inst=2 for rtsps://
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

### Live Video Stream — 30fps + Audio

**Key discovery:** The proxy exposes two ports:
- Port `42090` — HTTP only (`snap.jpg`, video-only ~1fps fallback)
- Port `443` — **RTSP/1.0 over TLS** (`rtsps://`) — full 30fps H.264 + AAC audio ✅

URL from `PUT /connection REMOTE` → `urls[0]` = `proxy-NN:42090/{hash}`:
replace port `42090` → `443`, use `rtsps://` scheme.

**Default: ffplay** (opened in a window, `live` command):
```bash
ffplay -rtsp_transport tcp -tls_verify 0 \
  "rtsps://proxy-NN.live.cbs.boschsecurity.com:443/{hash}/rtsp_tunnel?inst=2&enableaudio=1&fmtp=1&maxSessionDuration=60"
```

**VLC option** (`live --vlc`): VLC can't skip TLS cert verification, so the tool pipes via ffmpeg:
```
ffmpeg (pulls rtsps:// with -tls_verify 0) → mpegts stdout → VLC stdin (-)
```

Stream specs: **H.264 Main 1920×1080 30fps + AAC-LC 16kHz mono ~48kbps**

No auth needed — the session hash is the credential. Session lasts ~60s.

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

### RCP Protocol — Low-Level Camera Reads

After a REMOTE proxy connection is opened (`PUT /connection`), the same
proxy hash also exposes the camera's **RCP (Remote Configuration Protocol)**
endpoint at:

```
https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/rcp.xml
```

RCP is Bosch's proprietary binary protocol used internally for low-level
camera configuration. All payloads are hex-encoded in the URL query string.
Responses are XML containing a `<str>HEX</str>` field with the result bytes.

**Session handshake:**

```
# Step 1: HELLO (0xff0c WRITE P_OCTET) — initiates session, returns sessionid
GET /rcp.xml?command=0xff0c&direction=WRITE&type=P_OCTET&payload=0102004000...

# Step 2: SESSION_INIT (0xff0d WRITE P_OCTET) — activates the session
GET /rcp.xml?command=0xff0d&direction=WRITE&type=P_OCTET&sessionid=0xXXXXXXXX&payload=...
```

Basic auth `empty:empty` is used (the proxy hash is the real credential).
Auth level via cloud proxy = **3 (viewer)** — read-only. Writes require
auth level 5 (service account), which is not accessible via the cloud proxy.

**Most useful RCP reads:**

| Command | Type | Description |
|---------|------|-------------|
| `0x099e` | P_OCTET | JPEG thumbnail snapshot (160×90) |
| `0x0a0f` | P_OCTET | Camera real-time clock (8 bytes: YYYY MM DD HH MM SS DOW) |
| `0x0aea` | P_OCTET | Product name (null-terminated ASCII) |
| `0x0aee` | P_OCTET | Cloud FQDN (null-terminated ASCII) |
| `0x0a36` | P_OCTET | LAN IP address (4-byte big-endian) |
| `0x0a30` | P_OCTET | MAC address (6 bytes) |
| `0x0d00` | P_OCTET | Privacy mask state (byte[1]: 0=off, 1=on) |
| `0x0c22` | T_WORD  | LED dimmer value (0-100) |
| `0x0c0a` | P_OCTET | Motion zones (8 bytes each: x1 y1 x2 y2 in 0-10000 coords) |
| `0x0c38` | P_OCTET | Alarm catalog (UTF-16-BE encoded string list) |
| `0x0c62` | P_OCTET | Network services list (null-separated ASCII) |
| `0x0c98` | P_OCTET | Live raw video frame 320×180 YUV422 (115,200 bytes) |
| `0x09f3` | P_OCTET | IVA automation script (gzip-compressed Bosch scripting language) |
| `0x0ba9` | P_OCTET | IVA rule type names (null-separated ASCII: "Object in field", etc.) |
| `0x0a1b` | P_OCTET | resiMotion config (polygon coordinates + sensitivity parameters) |

**Note:** The `rcp snapshot` subcommand (0x099e) returns a small 160×90 JPEG
thumbnail directly from the camera's firmware — distinct from the cloud proxy
`snap.jpg` which is a full 1920×1080 image. The thumbnail does not require a
new proxy connection, only an active RCP session.

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

**Account / App**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/protocol_support?protocol=11&client=iphoneV2.11.2` | Protocol version check → `{"supportedProtocol": 11}` |
| `GET` | `/v11/registration/check` | Logged-in user info: firstName, lastName, email, timeZone, tokenExpirationTime |
| `GET` | `/v11/feature_flags` | Feature flags for the account |
| `GET` | `/v11/purchases` | Subscription / purchase info |
| `GET` | `/v11/contracts?locale=de_DE` | T&C + privacy URLs: tacVersion, tacURL, dpnVersion, dpnURL |

**Camera — list & status**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v11/video_inputs` | List all cameras (id, title, model, firmware, mac, privacyMode) |
| `GET` | `/v11/video_inputs/{id}` | Single camera details (same shape as list entry) |
| `GET` | `/v11/video_inputs/{id}/ping` | Returns `"ONLINE"` or `"OFFLINE"` |

**Camera — live connection**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v11/video_inputs/{id}/commissioned` | Current live proxy connection info (same shape as `PUT /connection` response) — read-only, no session opened |
| `PUT` | `/v11/video_inputs/{id}/connection` | Open live proxy connection (body: `{"type": "REMOTE"}` or `{"type": "LOCAL"}`) |

**Camera — events**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v11/events?videoInputId={id}` | All events for a camera |
| `GET` | `/v11/events?videoInputId={id}&limit=N` | Limited event list |
| `GET` | `{event.imageUrl}` | Download event JPEG snapshot |
| `GET` | `{event.videoClipUrl}` | Download event MP4 clip |

**Camera — settings (read)**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v11/video_inputs/{id}/privacy` | Get privacy mode state → `{"privacyMode": "ON"/"OFF"}` |
| `GET` | `/v11/video_inputs/{id}/firmware` | Returns T&C/privacy info (tacVersion, tacURL, dpnVersion, dpnURL) — label appears to be a Bosch API mislabel |
| `GET` | `/v11/video_inputs/{id}/lighting_override` | Current manual light override state → `{"frontLightOn": bool, "wallwasherOn": bool}` |
| `GET` | `/v11/video_inputs/{id}/lighting_options` | Light schedule options |
| `GET` | `/v11/video_inputs/{id}/ambient_light_sensor_level` | Current ambient light sensor reading |
| `GET` | `/v11/video_inputs/{id}/motion` | Motion detection settings |
| `GET` | `/v11/video_inputs/{id}/motion_sensitive_areas` | Configured motion detection zones |
| `GET` | `/v11/video_inputs/{id}/audioAlarm` | Audio alarm settings |
| `GET` | `/v11/video_inputs/{id}/recording_options` | Recording settings |
| `GET` | `/v11/video_inputs/{id}/timestamp` | Camera timestamp / clock info |
| `GET` | `/v11/video_inputs/{id}/rules` | Automation rules (returns `[]` when none configured) |
| `GET` | `/v11/video_inputs/{id}/wifiinfo` | WiFi info — returns **HTTP 401** (requires different/elevated auth) |

**Camera — settings (write)**

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/v11/video_inputs/{id}/privacy` | Set privacy mode → HTTP 204 on success |
| `PUT` | `/v11/video_inputs/{id}/lighting_override` | Set manual light override → HTTP 204 on success |
| `PUT` | `/v11/video_inputs/{id}/enable_notifications` | Set notification schedule → HTTP 204 on success |

### Privacy Mode

```
GET  /v11/video_inputs/{id}/privacy
→ {"privacyMode": "ON"} or {"privacyMode": "OFF"}

PUT  /v11/video_inputs/{id}/privacy
Content-Type: application/json
{"privacyMode": "ON", "durationInSeconds": null}
→ HTTP 204 No Content on success
```

Also available from the `GET /v11/video_inputs` response — each camera object includes
a top-level `"privacyMode"` field, so no extra poll is needed for status.

### Camera Light Override

Manual light override state can be read and set directly via the cloud API:

```
GET  /v11/video_inputs/{id}/lighting_override
→ {"frontLightOn": false, "wallwasherOn": false}

PUT  /v11/video_inputs/{id}/lighting_override
Content-Type: application/json

# Turn on:
{"frontLightOn": true, "wallwasherOn": true, "frontLightIntensity": 1.0}

# Turn off:
{"frontLightOn": false, "wallwasherOn": false}
→ HTTP 204 No Content on success
```

Light schedule options (read-only) are available via `GET /v11/video_inputs/{id}/lighting_options`.

### Camera Light Schedule (read-only via cloud API)

The camera light schedule state is included in `GET /v11/video_inputs` per camera:

```json
"featureStatus": {
  "scheduleStatus": "ALWAYS_OFF",
  "frontIlluminatorInGeneralLightOn": false,
  "frontIlluminatorGeneralLightIntensity": 1.0,
  "generalLightOnTime": "20:15:00",
  "generalLightOffTime": "22:35:00",
  "darknessThreshold": 0.0,
  "lightOnMotion": false,
  "lightOnMotionFollowUpTimeSeconds": 60
}
```

`featureSupport.light` (boolean) indicates whether the camera has a built-in LED indicator.

### Notifications

```
PUT  /v11/video_inputs/{id}/enable_notifications
Content-Type: application/json

# Disable all notifications:
{"enabledNotificationsStatus": "ALWAYS_OFF"}

# Follow the camera schedule:
{"enabledNotificationsStatus": "FOLLOW_CAMERA_SCHEDULE"}
→ HTTP 204 No Content on success
```

Current notification state is available in the `GET /v11/video_inputs` response as
`notificationsEnabledStatus` per camera (e.g. `"ON_CAMERA_SCHEDULE"`, `"ALWAYS_OFF"`).

### Live Proxy Endpoints (after PUT /connection)

```
# Port 42090 — HTTP only
https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/snap.jpg
  → Current camera image (1920×1080 JPEG, no auth needed)

https://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/snap.jpg?JpegSize=1206
  → Smaller image (1206px wide)

# Port 443 — RTSP/1.0 over TLS  ✅ WORKING
rtsps://proxy-NN.live.cbs.boschsecurity.com:443/{hash}/rtsp_tunnel?inst=2&enableaudio=1&fmtp=1&maxSessionDuration=60
  → Full 30fps H.264 1920×1080 + AAC 16kHz audio
  → Open with: ffplay -rtsp_transport tcp -tls_verify 0 -i "rtsps://..."
  → Or: ffmpeg -rtsp_transport tcp -tls_verify 0 -i "rtsps://..." -c copy out.mkv

# Port 42090 — RTSP tunnel (proprietary, NOT openable with standard players)
rtsp://proxy-NN.live.cbs.boschsecurity.com:42090/{hash}/rtsp_tunnel?...
  → Silently drops all connections
```

---

## Discovered API Endpoints (v1.2.0)

The following endpoints were discovered via proxy analysis (mitmproxy capture of the Bosch Smart Home Camera app).

### Account / Protocol

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v11/registration/check` | GET | User info + exact token expiration time |
| `/protocol_support?protocol=11` | GET | Protocol support check |
| `/v11/state/pre-maintenance` | GET | Server maintenance mode check |

### Per-Camera (GET)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v11/video_inputs/{id}` | GET | Fetch single camera by ID (same shape as list entry) |
| `/v11/video_inputs/{id}/commissioned` | GET | Pairing/connection status |
| `/v11/video_inputs/{id}/firmware` | GET | Firmware version + update status |
| `/v11/video_inputs/{id}/lighting_override` | GET | Current light override state |
| `/v11/video_inputs/{id}/lighting_options` | GET | Full light schedule config |
| `/v11/video_inputs/{id}/ambient_light_sensor_level` | GET | Ambient light sensor reading |
| `/v11/video_inputs/{id}/motion` | GET | Motion detection on/off + sensitivity |
| `/v11/video_inputs/{id}/motion_sensitive_areas` | GET | Motion zones (normalized rect coords) |
| `/v11/video_inputs/{id}/audioAlarm` | GET | Audio alarm threshold + config |
| `/v11/video_inputs/{id}/recording_options` | GET | Sound-in-recording setting |
| `/v11/video_inputs/{id}/timestamp` | GET | Timestamp overlay on/off |
| `/v11/video_inputs/{id}/wifiinfo` | GET | WiFi SSID, signal strength, local IP, MAC |
| `/v11/video_inputs/{id}/rules` | GET | Camera automation rules |

All of these are accessible via `info --full` (except `wifiinfo` which is shown by default in `info`).

### RCP via Cloud Proxy

After opening a live connection (`PUT /connection REMOTE`), the proxy hash also exposes the camera's
**RCP (Remote Configuration Protocol)** interface — normally LAN-only, but tunnelled through the proxy:

```
GET https://proxy-XX.live.cbs.boschsecurity.com:42090/{hash}/rcp.xml?command=HEX&direction=READ|WRITE&type=TYPE&sessionid=0xXXXX&payload=HEX
```

This is Bosch's proprietary binary configuration protocol, used internally by the app for low-level
camera settings. The hash from `PUT /connection` acts as the credential.

Use the `rcp` command to access these reads:

```bash
python3 bosch_camera.py rcp Outdoor info       # product, FQDN, LAN IP, MAC
python3 bosch_camera.py rcp Outdoor clock      # camera clock
python3 bosch_camera.py rcp Outdoor snapshot   # 160×90 JPEG thumbnail
python3 bosch_camera.py rcp Outdoor all        # all reads
```

See the [RCP Protocol](#rcp-protocol--low-level-camera-reads) section in "How It Works" for full details
and a table of all known readable commands.

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

- **Proxy session = 60 s** — after 60 seconds the proxy hash expires and
  the live stream stops. The `live` command opens a new session each time.
- **Cloud dependency** — everything goes through `residential.cbs.boschsecurity.com`.
  There is no documented local API on the SHC for camera images.
- **VLC needs ffmpeg** — the `live --vlc` option requires ffmpeg to proxy the stream,
  because VLC cannot skip TLS certificate verification for `rtsps://`.
- **Camera light control** — the `light on/off` command uses `PUT /v11/video_inputs/{id}/lighting_override` (cloud API, no SHC needed). Full light schedule control (time-based scheduling) is only available via the SHC local API with mutual TLS.

---

## Example: Event Monitoring & Automation

### Watch for live events (CLI)

```bash
# Watch all cameras, print new events every 30 seconds
python3 bosch_camera.py watch

# Watch only Garten camera, poll every 15 seconds
python3 bosch_camera.py watch Garten --interval 15

# Watch for 10 minutes then exit
python3 bosch_camera.py watch --duration 600
```

Example output:
```
Watching 2 camera(s)... (Ctrl+C to stop)
  [14:32:07] 🚨 MOVEMENT       cam=Garten        2026-03-22T14:32:05Z
             📸 https://...events/.../snap.jpg
             🎬 https://...events/.../clip.mp4
  [14:35:12] 🔊 AUDIO_ALARM    cam=Kamera        2026-03-22T14:35:10Z
             📸 https://...events/.../snap.jpg
```

### Motion detection control

```bash
# Show current motion settings
python3 bosch_camera.py motion Garten

# Enable motion with max sensitivity
python3 bosch_camera.py motion Garten --enable --sensitivity SUPER_HIGH

# Lower sensitivity (reduce false alarms)
python3 bosch_camera.py motion Garten --sensitivity MEDIUM
```

### Audio alarm control

```bash
# Show audio alarm settings
python3 bosch_camera.py audio-alarm Garten

# Enable audio alarm with threshold 60
python3 bosch_camera.py audio-alarm Garten --enable --threshold 60
```

### Home Assistant Automation Examples

#### Motion alert with camera snapshot

```yaml
automation:
  - alias: "Bosch Garten — Motion Alert"
    description: "Send push notification with snapshot when motion is detected"
    trigger:
      - platform: state
        entity_id: sensor.bosch_garten_last_event
    condition:
      - condition: template
        value_template: >
          {{ trigger.to_state.state not in ['unknown', 'unavailable', '']
             and trigger.to_state.state != trigger.from_state.state }}
      - condition: template
        value_template: >
          {{ state_attr('sensor.bosch_garten_last_event', 'event_type') == 'MOVEMENT' }}
    action:
      - service: notify.mobile_app
        data:
          title: "🚨 Bewegung — Garten"
          message: >
            {{ now().strftime('%H:%M') }} Uhr —
            {{ state_attr('sensor.bosch_garten_last_event', 'event_type') }}
          data:
            image: "{{ state_attr('sensor.bosch_garten_last_event', 'image_url') }}"
            url: "{{ state_attr('sensor.bosch_garten_last_event', 'video_clip_url') }}"
```

#### Audio alarm alert

```yaml
automation:
  - alias: "Bosch Kamera — Audio Alarm"
    description: "Notify when audio alarm triggers"
    trigger:
      - platform: state
        entity_id: sensor.bosch_kamera_last_event_type
        to: "AUDIO_ALARM"
    action:
      - service: notify.mobile_app
        data:
          title: "🔊 Geräusch erkannt — Kamera"
          message: "Audio-Alarm um {{ now().strftime('%H:%M') }} Uhr"
```

#### Privacy mode at night

```yaml
automation:
  - alias: "Bosch Kamera — Privacy Mode at Night"
    trigger:
      - platform: time
        at: "22:00:00"
    action:
      - service: switch.turn_on
        target:
          entity_id: switch.bosch_kamera_privacy_mode

  - alias: "Bosch Kamera — Privacy Mode Off in Morning"
    trigger:
      - platform: time
        at: "07:00:00"
    action:
      - service: switch.turn_off
        target:
          entity_id: switch.bosch_kamera_privacy_mode
```

#### Camera light on motion after sunset

```yaml
automation:
  - alias: "Bosch Garten — Light on Motion After Sunset"
    trigger:
      - platform: state
        entity_id: sensor.bosch_garten_last_event_type
        to: "MOVEMENT"
    condition:
      - condition: sun
        after: sunset
        before: sunrise
    action:
      - service: switch.turn_on
        target:
          entity_id: switch.bosch_garten_camera_light
      - delay:
          minutes: 5
      - service: switch.turn_off
        target:
          entity_id: switch.bosch_garten_camera_light
```

---

## Related

- [Bosch SHC API Issue #63](https://github.com/BoschSmartHome/bosch-shc-api-docs/issues/63) — community discussion on camera API
- [Bosch SHC API Issue #30](https://github.com/BoschSmartHome/bosch-shc-api-docs/issues/30) — camera integration discussion
- [boschshcpy](https://github.com/tschamm/boschshcpy) — Python library for the local SHC API (not camera images)
