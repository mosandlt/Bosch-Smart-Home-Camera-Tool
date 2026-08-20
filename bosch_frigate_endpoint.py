"""Always-on, credential-free RTSP front-door for external recorders (Frigate/BlueIris/go2rtc).

Ported from the HA integration's ``frigate_endpoint.py`` (persistent local
front-door for external NVR software) to this CLI as the ``frigate-endpoint
start`` command.

Problem: a normal LOCAL Bosch session URL carries inline Digest credentials
that rotate roughly hourly (Gen2 firmware) and only exists while something
holds the session open. An external recorder polling on its own schedule gets
"Connection refused" or a stale-credential 401 whenever nothing else happens
to have a session open at that moment.

This module opens one always-listening TCP socket per camera at a *stable*
port. On the first client connection it opens a Bosch LOCAL session (``PUT
/v11/video_inputs/{id}/connection``, the same call ``cmd_test_local`` makes)
and performs the RTSP Digest-auth dance against the camera itself, so
recorder clients get a fully credential-free ``rtsp://127.0.0.1:<port>/...``
URL.

Architecture difference from the HA port: HA's LOCAL sessions go through a
per-camera TLS-terminating proxy (``tls_proxy.py``) because HA always dials
the camera over TLS for LOCAL sessions. This CLI's LOCAL sessions use
**plain ``rtsp://``** instead (see ``cmd_test_local``'s "LOCAL: plain
rtsp://, credentials URL-encoded" branch — no TLS is involved for LOCAL at
all in this tool). There is therefore no inner-proxy hop to reproduce: the
front-door here relays directly to the camera's ``host:port`` obtained from
the Bosch LOCAL session response — one hop instead of HA's two. The
REMOTE-viewing / ``relay_factory`` generality HA's file carries (a second
relay type with no Digest dance at all, used only for its REMOTE front-door)
is dropped entirely — this module is LOCAL-only.

Runs on its own asyncio event loop, started synchronously from
``cmd_frigate_endpoint``/``_cmd_frigate_start`` in ``bosch_camera.py`` via
``asyncio.run()``, the same pattern this CLI's existing FCM push-watch loop
(``_watch_fcm_push``) already uses.

This module deliberately does NOT import ``bosch_camera`` at module level —
``bosch_camera.py`` imports front-door plumbing from here, so a top-level
back-import would be circular. The one place that needs ``bosch_camera``'s
``get_token``/``make_session``/``CLOUD_API`` (``_resolve_camera_target_sync``
below) imports them lazily, inside the function body, at call time.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import logging
import socket
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote as _urlquote

import requests
from bosch_shc_camera_client.auth_utils import (
    _build_digest_header,
    _parse_digest_challenge,
)

_LOGGER = logging.getLogger(__name__)

# Auth modes for the optional front-door gate (IP allowlist is separate/additive).
AUTH_NONE = "none"
AUTH_PATH_TOKEN = "path_token"  # noqa: S105 # auth-mode name, not a credential
AUTH_BASIC = "basic"

# Max time to wait for the direct camera TCP connect before dropping the client.
_CAMERA_CONNECT_TIMEOUT = 10.0
# Max time to wait for resolve_inner (opening a Bosch LOCAL session can take a while).
_RESOLVE_TIMEOUT = 40.0
# Max time to wait for one camera RTSP response during the auth dance.
_AUTH_READ_TIMEOUT = 30.0
# Max bytes for a single RTSP message head (guards against a non-RTSP flood).
_MAX_HEAD_BYTES = 64 * 1024


@dataclass(frozen=True)
class CameraTarget:
    """What ``resolve_inner`` returns: the camera's LOCAL host/port + live creds."""

    host: str
    port: int
    digest_user: str
    digest_password: str


# resolve_inner(cam_id) -> awaitable[CameraTarget | None]; None = camera
# currently unreachable / no LOCAL session available -> the front-door drops
# the client cleanly so the recorder retries later.
ResolveInner = Callable[[str], Coroutine[Any, Any, "CameraTarget | None"]]


@dataclass
class FrontDoorConfig:
    """Per-process front-door settings, mirrors the HA options-flow config shape."""

    bind_host: str = "127.0.0.1"
    # Empty = allow any client IP. Entries may be plain IPs or CIDR networks.
    ip_allowlist: frozenset[str] = field(default_factory=frozenset)
    auth_mode: str = AUTH_NONE
    # Shared secret: the path segment for AUTH_PATH_TOKEN, the password for AUTH_BASIC.
    token: str = ""
    basic_user: str = "frigate"
    # Zero-client linger before signalling idle.
    idle_timeout: float = 60.0
    # Max simultaneous recorder clients per camera (anti-flood guard).
    max_connections: int = 8
    # Passed through to the LOCAL PUT /connection call's highQualityVideo flag.
    high_quality: bool = False

    def __post_init__(self) -> None:
        # Bug-hunt finding: an auth_mode other than "none" with an empty token
        # used to silently disable the gate (every request forwarded
        # unauthenticated) instead of failing loudly. Fail fast here too, as
        # defense in depth for any caller that builds a FrontDoorConfig
        # directly instead of going through the CLI's own validation.
        if self.auth_mode != AUTH_NONE and not self.token:
            raise ValueError(
                f"FrontDoorConfig: auth_mode={self.auth_mode!r} requires a non-empty token"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Pure helpers (exported for unit tests) — ported near-verbatim from the HA
# integration's frigate_endpoint.py (itself ported from ioBroker's rtsp_auth.ts).
# ─────────────────────────────────────────────────────────────────────────────


def find_rtsp_message_end(buf: bytes) -> int:
    """Return the offset right after ``\\r\\n\\r\\n``, or -1 if not present."""
    i = buf.find(b"\r\n\r\n")
    return i + 4 if i >= 0 else -1


def parse_request_start_line(buf: bytes) -> tuple[str, str] | None:
    """Parse ``METHOD uri RTSP/1.x`` from the first line. None on parse error."""
    eol = buf.find(b"\r\n")
    first = (buf[:eol] if eol >= 0 else buf).decode("utf-8", errors="replace")
    parts = first.split()
    if len(parts) >= 3 and parts[2].upper().startswith("RTSP/") and parts[0].isupper():
        return parts[0], parts[1]
    return None


def parse_response_status(buf: bytes) -> int | None:
    """Parse the numeric code from an ``RTSP/1.0 NNN PHRASE`` start line."""
    eol = buf.find(b"\r\n")
    first = (buf[:eol] if eol >= 0 else buf).decode("utf-8", errors="replace")
    parts = first.split()
    if len(parts) >= 2 and parts[0].upper().startswith("RTSP/") and parts[1].isdigit():
        return int(parts[1])
    return None


def extract_header(buf: bytes, name: str) -> str | None:
    """Return the first value of header ``name`` (case-insensitive), or None."""
    lname = name.lower()
    for line in buf.decode("utf-8", errors="replace").split("\r\n"):
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == lname:
            return value.strip()
    return None


def has_authorization_header(buf: bytes) -> bool:
    """True if the request headers contain an ``Authorization:`` line."""
    return extract_header(buf, "Authorization") is not None


def content_length(buf: bytes) -> int:
    """Parse ``Content-Length`` (0 when absent or unparseable)."""
    raw = extract_header(buf, "Content-Length")
    if raw and raw.isdigit():
        return int(raw)
    return 0


def inject_auth_header(request: bytes, auth_value: str) -> bytes:
    """Insert ``Authorization: <value>`` before the blank line ending the head.

    Any existing ``Authorization:`` line is dropped first so a client-supplied
    (gate) credential never reaches the camera alongside our injected Digest.
    Caller has verified the buffer ends with ``\\r\\n\\r\\n``.
    """
    sep = request.find(b"\r\n\r\n")
    if sep < 0:
        return request
    head = request[:sep].decode("utf-8", errors="replace")
    tail = request[sep:]
    kept = [
        ln for ln in head.split("\r\n") if ln.split(":", 1)[0].strip().lower() != "authorization"
    ]
    kept.append(f"Authorization: {auth_value}")
    return ("\r\n".join(kept)).encode("utf-8") + tail


def ip_allowed(peer_ip: str, allowlist: frozenset[str]) -> bool:
    """True if ``peer_ip`` is permitted. Empty allowlist = allow all."""
    if not allowlist:
        return True
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    # A dual-stack (0.0.0.0) bind reports an IPv4 client as an IPv4-mapped IPv6
    # address (``::ffff:192.0.2.5``). Match against the real IPv4 too, so an
    # IPv4 allowlist entry still applies.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for entry in allowlist:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def split_path_token(uri: str, token: str) -> tuple[bool, str]:
    """Validate + strip a leading ``/<token>`` path segment from ``uri``.

    Returns ``(ok, rewritten_uri)``. ``ok`` is False when the token is required
    but missing/wrong. The rewritten URI has the token segment removed so the
    camera sees the canonical path (e.g. ``rtsp://h:p/tok/high`` -> ``…/high``).
    """
    if not token:
        return True, uri
    # Work on the path portion only; preserve scheme://host and ?query.
    scheme_sep = uri.find("://")
    prefix = ""
    rest = uri
    if scheme_sep >= 0:
        slash = uri.find("/", scheme_sep + 3)
        if slash < 0:
            return False, uri
        prefix = uri[:slash]
        rest = uri[slash:]
    query = ""
    qpos = rest.find("?")
    if qpos >= 0:
        query = rest[qpos:]
        rest = rest[:qpos]
    segments = [s for s in rest.split("/") if s != ""]
    if not segments or not hmac.compare_digest(segments[0], token):
        return False, uri
    remaining = segments[1:]
    # Bug-hunt finding: a ".." segment in the path token URI was kept
    # verbatim and forwarded to the camera — reject path-traversal segments
    # outright instead of relaying them.
    if any(seg in (".", "..") for seg in remaining):
        return False, uri
    remainder = "/" + "/".join(remaining)
    return True, f"{prefix}{remainder}{query}"


def check_basic_auth(buf: bytes, user: str, password: str) -> bool:
    """True if the request carries a matching ``Authorization: Basic`` header."""
    value = extract_header(buf, "Authorization")
    if not value:
        return False
    scheme, _, b64 = value.partition(" ")
    if scheme.strip().lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(b64.strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(decoded, f"{user}:{password}")


def build_public_url(
    host: str,
    port: int,
    config: FrontDoorConfig,
    *,
    inst: int = 1,
    max_session_duration: int = 3600,
    enableaudio: int = 1,
    fmtp: int = 1,
) -> str:
    """Build the credential-free RTSP URL a recorder should connect to.

    Matches this CLI's own existing RTSP-URL shape (see ``cmd_test_local``):
    ``rtsp_tunnel?inst=N&enableaudio=1&fmtp=1&maxSessionDuration=N``, forwarded
    verbatim to the camera so SDP/control-URL behaviour matches the direct
    path. ``inst`` selects the stream (1=main/high, 2=sub/low). Auth-mode adds
    an in-URL Basic credential or a leading path-token segment (stripped at
    the gate before the request reaches the camera).
    """
    path = (
        f"rtsp_tunnel?inst={inst}&enableaudio={enableaudio}"
        f"&fmtp={fmtp}&maxSessionDuration={max_session_duration}"
    )
    cred = ""
    prefix = ""
    if config.auth_mode == AUTH_BASIC and config.token:
        cred = f"{_urlquote(config.basic_user, safe='')}:{_urlquote(config.token, safe='')}@"
    elif config.auth_mode == AUTH_PATH_TOKEN and config.token:
        prefix = f"{_urlquote(config.token, safe='')}/"
    return f"rtsp://{cred}{host}:{port}/{prefix}{path}"


def frigate_url_host(bind_host: str) -> str:
    """Host to embed in the published URL.

    - A specific interface IP (e.g. 192.168.1.50) or 127.0.0.1 is routable
      as-is and used verbatim.
    - An all-interfaces bind (0.0.0.0 / :: / empty) isn't routable, so we
      detect this machine's primary outbound IPv4 (no packet is actually
      sent — a UDP "connect" only resolves routing) instead.
    """
    if bind_host not in ("0.0.0.0", "::", ""):  # noqa: S104 # all-interfaces sentinels
        return bind_host
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Close ``writer`` and wait for the close to actually complete.

    A bare ``writer.close()`` only schedules the close — under load the
    underlying TCP socket can stay open past the point the caller has already
    moved on (semaphore release, idle-linger rearm, etc.), so every close site
    here awaits ``wait_closed()`` too. ``wait_closed()`` can itself raise on an
    already-broken connection (reset/broken-pipe/OS-level errors) — that's
    expected on an abrupt client/camera disconnect, not a bug, so it's
    swallowed here rather than propagated.
    """
    writer.close()
    try:
        await writer.wait_closed()
    except Exception as err:  # best-effort close of an already-abrupt connection
        _LOGGER.debug("frigate front-door: wait_closed() error (non-fatal): %s", err)


# ─────────────────────────────────────────────────────────────────────────────
# Per-connection relay (Digest auth dance + steady injection).
# ─────────────────────────────────────────────────────────────────────────────


class _Relay:  # pylint: disable=too-few-public-methods
    """Handles one downstream client <-> camera connection.

    Single public entry point (`run`) by design — this mirrors the HA
    integration's `Relay` protocol shape (an object with just an async
    `run()`), even though this CLI dropped the `RelayFactory`/`Protocol`
    generality since it only ever has one relay implementation.
    """

    def __init__(
        self,
        cam_id: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target: CameraTarget,
        first_request: bytes,
    ) -> None:
        self._cam = cam_id[:8]
        self._cr = client_reader
        self._cw = client_writer
        self._target = target
        self._first = first_request
        self._challenge: dict[str, str] | None = None
        self._ir: asyncio.StreamReader | None = None
        self._iw: asyncio.StreamWriter | None = None

    async def run(self) -> None:
        """Connect directly to the camera, do the auth dance, then pipe both ways."""
        ir, iw = await asyncio.wait_for(
            asyncio.open_connection(self._target.host, self._target.port),
            timeout=_CAMERA_CONNECT_TIMEOUT,
        )
        self._ir, self._iw = ir, iw
        try:
            if has_authorization_header(self._first):
                # Back-compat: client supplies its own creds -> pure passthrough.
                iw.write(self._first)
                await iw.drain()
            else:
                ok = await self._auth_dance()
                if not ok:
                    # _auth_dance already logged why (stale creds / no usable
                    # challenge) and forwarded whatever response it could to
                    # the client. Bug-hunt fix: this used to fall through to
                    # the normal pipe below regardless, silently relaying
                    # every further request unauthenticated despite the log
                    # message claiming the connection was being closed.
                    return
            await asyncio.gather(
                self._pipe_client_to_camera(),
                self._pipe_camera_to_client(),
            )
        finally:
            for w in (iw, self._cw):
                if not w.is_closing():
                    await _close_writer(w)

    async def _read_message(self, reader: asyncio.StreamReader) -> bytes:
        """Read one full RTSP message head (+body if Content-Length present).

        Bounded by ``_AUTH_READ_TIMEOUT`` so a stalled camera during the auth
        dance can't pin the connection. A response head exceeding asyncio's
        64 KB readuntil limit (``LimitOverrunError``) is treated as a protocol
        error -> ConnectionError (caught by ``run``) so both sockets close.
        """
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=_AUTH_READ_TIMEOUT)
            body_len = content_length(head)
            if body_len:
                head += await asyncio.wait_for(
                    reader.readexactly(body_len), timeout=_AUTH_READ_TIMEOUT
                )
        except (TimeoutError, asyncio.LimitOverrunError) as err:
            raise ConnectionError(f"camera read failed: {err}") from err
        return head

    async def _auth_dance(self) -> bool:
        """Probe for the camera's Digest challenge, then resend authenticated.

        Returns True if the relay should proceed to the normal bidirectional
        pipe, False if the connection must be aborted (the caller closes both
        sockets instead of piping) — e.g. stale/rotated creds, or no usable
        Digest challenge was ever learned. Never silently proceed to piping
        in a state where subsequent requests would go out unauthenticated.
        """
        assert self._ir is not None and self._iw is not None
        self._iw.write(self._first)
        await self._iw.drain()
        resp = await self._read_message(self._ir)
        status = parse_response_status(resp)

        if status != 401:
            # Camera accepted this particular request without auth (e.g. an
            # unauthenticated OPTIONS) — forward it, but self._challenge
            # stays None. _drain_requests aborts rather than forwarding a
            # later real request unauthenticated in that state.
            self._cw.write(resp)
            await self._cw.drain()
            return True

        www = extract_header(resp, "WWW-Authenticate")
        if www:
            try:
                self._challenge = _parse_digest_challenge(www)
            except ValueError:
                self._challenge = None
        parsed = parse_request_start_line(self._first)
        if self._challenge and parsed:
            method, uri = parsed
            auth = _build_digest_header(
                method,
                uri,
                self._target.digest_user,
                self._target.digest_password,
                self._challenge,
            )
            self._iw.write(inject_auth_header(self._first, auth))
            await self._iw.drain()
            resp2 = await self._read_message(self._ir)
            # The original 401 is swallowed — never forwarded to the client.
            self._cw.write(resp2)
            await self._cw.drain()
            if parse_response_status(resp2) == 401:
                # Stale creds (Bosch rotated server-side). Forward the honest
                # 401 + actually close so the recorder reconnects with
                # refreshed creds, instead of falling through to piping every
                # further request unauthenticated.
                _LOGGER.debug(
                    "frigate front-door %s: camera rotated Digest creds — closing for reconnect",
                    self._cam,
                )
                self._challenge = None
                return False
            return True
        # Couldn't compute auth — forward the 401 and abort instead of
        # silently proceeding to pipe every further request unauthenticated.
        _LOGGER.warning(
            "frigate front-door %s: cannot compute Digest challenge, aborting",
            self._cam,
        )
        self._cw.write(resp)
        await self._cw.drain()
        return False

    async def _pipe_client_to_camera(self) -> None:
        """Forward client->camera, injecting a fresh Authorization per request."""
        assert self._ir is not None and self._iw is not None
        buf = b""
        try:
            while True:
                chunk = await self._cr.read(65536)
                if not chunk:
                    break
                buf += chunk
                buf = await self._drain_requests(buf)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            if not self._iw.is_closing():
                await _close_writer(self._iw)

    async def _drain_requests(self, buf: bytes) -> bytes:
        """Emit every complete request in ``buf``, return the unparsed tail."""
        assert self._iw is not None
        while buf:
            if buf[:1] == b"$":
                # Interleaved RTP/RTCP binary frame — forward raw, never parse.
                self._iw.write(buf)
                await self._iw.drain()
                return b""
            end = find_rtsp_message_end(buf)
            if end < 0:
                if len(buf) > _MAX_HEAD_BYTES:
                    # Not RTSP and not interleaved — forward raw to avoid a stall.
                    self._iw.write(buf)
                    await self._iw.drain()
                    return b""
                return buf
            req, buf = buf[:end], buf[end:]
            body = content_length(req)
            if body:
                if len(buf) < body:
                    return req + buf  # body incomplete — wait for more
                req, buf = req + buf[:body], buf[body:]
            parsed = parse_request_start_line(req)
            if parsed and self._challenge:
                method, uri = parsed
                try:
                    auth = _build_digest_header(
                        method,
                        uri,
                        self._target.digest_user,
                        self._target.digest_password,
                        self._challenge,
                    )
                    self._iw.write(inject_auth_header(req, auth))
                except (ValueError, KeyError):
                    self._iw.write(req)
            elif parsed and not self._challenge:
                # No Digest challenge was ever learned for this session (the
                # very first request's response wasn't a 401, or the
                # challenge couldn't be parsed). Never silently forward a
                # real RTSP request unauthenticated — abort so the client
                # reconnects and gets a fresh probe instead of looping
                # against a camera that will just keep 401ing it.
                _LOGGER.warning(
                    "frigate front-door %s: no Digest challenge learned — aborting relay "
                    "instead of forwarding %s unauthenticated",
                    self._cam,
                    parsed[0],
                )
                raise ConnectionError("no Digest challenge learned for this session")
            else:
                self._iw.write(req)
            await self._iw.drain()
        return b""

    async def _pipe_camera_to_client(self) -> None:
        """Forward camera->client verbatim (RTP frames, responses)."""
        assert self._ir is not None
        try:
            while True:
                chunk = await self._ir.read(65536)
                if not chunk:
                    break
                self._cw.write(chunk)
                await self._cw.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            if not self._cw.is_closing():
                await _close_writer(self._cw)


def _rewrite_request_uri(request: bytes, new_uri: str) -> bytes:
    """Replace the request-line URI (2nd token) with ``new_uri``."""
    eol = request.find(b"\r\n")
    if eol < 0:
        return request
    first = request[:eol].decode("utf-8", errors="replace")
    rest = request[eol:]
    parts = first.split(" ")
    if len(parts) < 3:
        return request
    parts[1] = new_uri
    return (" ".join(parts)).encode("utf-8") + rest


def _strip_authorization(request: bytes) -> bytes:
    """Remove any ``Authorization:`` line from the request head."""
    sep = request.find(b"\r\n\r\n")
    if sep < 0:
        return request
    head = request[:sep].decode("utf-8", errors="replace")
    tail = request[sep:]
    kept = [
        ln for ln in head.split("\r\n") if ln.split(":", 1)[0].strip().lower() != "authorization"
    ]
    return ("\r\n".join(kept)).encode("utf-8") + tail


# ─────────────────────────────────────────────────────────────────────────────
# Front-door server (one per camera) + shared runner.
# ─────────────────────────────────────────────────────────────────────────────


class _CameraServer:
    """One always-on listener for a single camera."""

    def __init__(
        self,
        cam_id: str,
        config: FrontDoorConfig,
        resolve_inner: ResolveInner,
        on_idle: Callable[[], None] | None,
    ) -> None:
        self.cam_id = cam_id
        self.config = config
        self._resolve = resolve_inner
        self._on_idle = on_idle
        self._server: asyncio.base_events.Server | None = None
        self._sem = asyncio.Semaphore(self.config.max_connections)
        self.port = 0
        self.client_count = 0
        # Pending zero-client idle-linger task. See _idle_linger.
        self._idle_task: asyncio.Task[None] | None = None

    async def start(self, preferred_port: int) -> int:
        """Bind the listener; returns the bound port."""
        self._server = await asyncio.start_server(
            self._handle, self.config.bind_host, preferred_port
        )
        self.port = self._server.sockets[0].getsockname()[1]
        _LOGGER.info(
            "frigate front-door for %s listening on %s:%d (session opens on demand)",
            self.cam_id[:8],
            self.config.bind_host,
            self.port,
        )
        return self.port

    def close(self) -> None:
        """Stop accepting new connections (synchronous, best-effort)."""
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = None
        if self._server is not None:
            self._server.close()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else ""
        cam = self.cam_id[:8]
        if not ip_allowed(peer_ip, self.config.ip_allowlist):
            _LOGGER.warning(
                "frigate front-door %s: rejecting client %s (not allowlisted)", cam, peer_ip
            )
            await _close_writer(writer)
            return

        if self._sem.locked():
            _LOGGER.warning(
                "frigate front-door %s: connection cap (%d) reached, rejecting %s",
                cam,
                self.config.max_connections,
                peer_ip,
            )
            await _close_writer(writer)
            return
        await self._sem.acquire()

        self.client_count += 1
        if self.client_count == 1 and self._idle_task is not None and not self._idle_task.done():
            # New activity cancels any pending idle-linger teardown.
            self._idle_task.cancel()
            self._idle_task = None
        try:
            await self._serve(reader, writer, peer_ip)
        finally:
            self._sem.release()
            self.client_count -= 1
            if self.client_count == 0 and self._on_idle is not None:
                # Linger config.idle_timeout seconds of continuous zero clients
                # before signalling idle, so a recorder that briefly
                # reconnects doesn't thrash. idle_timeout <= 0 -> signal
                # immediately ("0 = close immediately").
                if self._idle_task is not None and not self._idle_task.done():
                    self._idle_task.cancel()
                self._idle_task = asyncio.create_task(self._idle_linger())

    async def _idle_linger(self) -> None:
        """Wait config.idle_timeout of continuous zero-client idle, then fire
        on_idle. Cancelled and replaced the instant a new client connects.
        """
        try:
            if self.config.idle_timeout > 0:
                await asyncio.sleep(self.config.idle_timeout)
        except asyncio.CancelledError:
            return
        self._idle_task = None
        # A client may have arrived (and left) again during the sleep; only
        # signal if we are genuinely still idle.
        if self.client_count == 0 and self._on_idle is not None:
            try:
                self._on_idle()
            except Exception as err:  # caller callback must never kill the listener
                _LOGGER.debug("frigate front-door %s: on_idle raised — %s", self.cam_id[:8], err)

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_ip: str
    ) -> None:
        cam = self.cam_id[:8]
        try:
            first = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        except (
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            TimeoutError,
            OSError,
        ):
            await _close_writer(writer)
            return
        body = content_length(first)
        if body:
            try:
                first += await reader.readexactly(body)
            except (asyncio.IncompleteReadError, OSError):
                await _close_writer(writer)
                return

        parsed = parse_request_start_line(first)
        if parsed is None:
            await _close_writer(writer)
            return
        _method, uri = parsed

        # -- Gate auth --------------------------------------------------------
        cfg = self.config
        if cfg.auth_mode == AUTH_PATH_TOKEN and cfg.token:
            ok, rewritten = split_path_token(uri, cfg.token)
            if not ok:
                _LOGGER.warning(
                    "frigate front-door %s: bad/missing path token from %s", cam, peer_ip
                )
                await _close_writer(writer)
                return
            first = _rewrite_request_uri(first, rewritten)
        elif cfg.auth_mode == AUTH_BASIC and cfg.token:
            if not check_basic_auth(first, cfg.basic_user, cfg.token):
                writer.write(
                    b'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm="bosch-frigate"\r\n\r\n'
                )
                await writer.drain()
                await _close_writer(writer)
                return
            # Strip the gate header so the camera Digest dance starts clean.
            first = _strip_authorization(first)

        # -- Resolve the camera target lazily (opens the Bosch LOCAL session) -
        try:
            target = await asyncio.wait_for(self._resolve(self.cam_id), timeout=_RESOLVE_TIMEOUT)
        except Exception as err:  # broad: any resolve failure -> drop client, recorder retries
            _LOGGER.debug("frigate front-door %s: resolve_inner failed — %s", cam, err)
            target = None
        if target is None:
            writer.write(b"RTSP/1.0 503 Service Unavailable\r\n\r\n")
            try:
                await writer.drain()
            except OSError:
                pass
            await _close_writer(writer)
            return

        relay = _Relay(self.cam_id, reader, writer, target, first)
        try:
            await relay.run()
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as err:
            _LOGGER.debug("frigate front-door %s: relay ended — %s", cam, err)
        finally:
            # `relay.run()` closes both sockets itself once it reaches its own
            # try/finally — but a failure BEFORE that point (e.g. the initial
            # connect to the camera, `ConnectionRefusedError`) raises straight
            # out of `run()` without ever closing the client's writer, leaking
            # the connection open. Always make sure it's closed here too.
            if not writer.is_closing():
                await _close_writer(writer)


class FrontDoorRunner:
    """Hosts every camera's front-door server on the current asyncio event loop."""

    def __init__(self) -> None:
        self._servers: dict[str, _CameraServer] = {}

    async def start_server(
        self,
        cam_id: str,
        config: FrontDoorConfig,
        resolve_inner: ResolveInner,
        preferred_port: int = 0,
        on_idle: Callable[[], None] | None = None,
    ) -> int:
        """Start (or restart) the front-door for ``cam_id``; returns the port."""
        self.stop_server(cam_id)
        server = _CameraServer(cam_id, config, resolve_inner, on_idle)
        port = await server.start(preferred_port)
        self._servers[cam_id] = server
        return port

    def stop_server(self, cam_id: str) -> None:
        """Close the listener for ``cam_id`` (sync — stops accepting at once)."""
        server = self._servers.pop(cam_id, None)
        if server is not None:
            server.close()

    def active_count(self, cam_id: str) -> int:
        server = self._servers.get(cam_id)
        return server.client_count if server is not None else 0

    def has_server(self, cam_id: str) -> bool:
        return cam_id in self._servers

    def has_any_server(self) -> bool:
        return bool(self._servers)

    def port(self, cam_id: str) -> int:
        server = self._servers.get(cam_id)
        return server.port if server is not None else 0

    def stop_all(self) -> None:
        for cam_id in list(self._servers):
            self.stop_server(cam_id)


# ─────────────────────────────────────────────────────────────────────────────
# resolve_inner builder — the one piece that talks to bosch_camera.py.
# ─────────────────────────────────────────────────────────────────────────────


def make_resolve_inner(
    cfg: dict[str, Any], cam_id: str, *, high_quality: bool = False
) -> ResolveInner:
    """Build a ``resolve_inner`` callback that opens a Bosch LOCAL session.

    Called on every new client connection (a ``PUT /connection`` is cheap and
    idempotent on Bosch's side, safe to repeat) — this CLI has no persistent
    session object cached across connections the way HA's coordinator caches
    ``live_connections``, so "releasing the session on idle" (the
    ``on_idle``/idle-linger machinery in ``_CameraServer``) is a no-op beyond
    logging here: the Bosch-side LOCAL session simply expires server-side
    after ``maxSessionDuration`` once nothing renews it.

    requests is synchronous; the PUT is bridged onto a worker thread via
    ``run_in_executor`` so it never blocks the front-door's asyncio event loop
    (other cameras' listeners, in-flight relays) while waiting on the network.
    """

    async def _resolve(_cam_id: str) -> CameraTarget | None:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, _resolve_camera_target_sync, cfg, cam_id, high_quality
        )

    return _resolve


def _resolve_camera_target_sync(
    cfg: dict[str, Any], cam_id: str, high_quality: bool
) -> CameraTarget | None:
    """Synchronous worker for ``make_resolve_inner`` — runs in a thread pool.

    Lazy-imports ``get_token``/``make_session``/``CLOUD_API`` from
    ``bosch_camera`` at call time to avoid the circular import described in
    this module's docstring.
    """
    # pylint: disable-next=cyclic-import,import-outside-toplevel
    from bosch_camera import CLOUD_API, get_token, make_session  # circular-import avoidance

    token = get_token(cfg)
    session = make_session(token)
    url = f"{CLOUD_API}/v11/video_inputs/{cam_id}/connection"
    try:
        resp = session.put(
            url,
            json={"type": "LOCAL", "highQualityVideo": high_quality},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
    except requests.exceptions.RequestException as err:
        _LOGGER.debug("frigate front-door: PUT /connection failed for %s: %s", cam_id[:8], err)
        return None
    if resp.status_code not in (200, 201):
        _LOGGER.debug(
            "frigate front-door: PUT /connection HTTP %d for %s", resp.status_code, cam_id[:8]
        )
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    urls_list = data.get("urls", [])
    user = data.get("user", "")
    password = data.get("password", "")
    if not urls_list or not user or not password:
        return None
    u = urls_list[0]
    if "/" in u:
        # A "host:port/hash" shape is the REMOTE proxy form — a LOCAL PUT
        # should never return this, but guard rather than mis-parse it as a
        # LOCAL host:port pair.
        _LOGGER.warning(
            "frigate front-door: unexpected REMOTE-shaped URL for LOCAL session on %s",
            cam_id[:8],
        )
        return None
    host, _, port_str = u.partition(":")
    port = int(port_str) if port_str.isdigit() else 443
    return CameraTarget(host=host, port=port, digest_user=str(user), digest_password=str(password))
