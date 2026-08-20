"""
Tests for bosch_frigate_endpoint.py — always-on, credential-free RTSP
front-door for external recorders (Frigate/BlueIris/go2rtc), ported from the
HA integration's frigate_endpoint.py.

Covers: every pure helper (parsing/auth/allowlist), build_public_url per auth
mode, the CLI wiring (cmd_frigate_endpoint dispatch), and an end-to-end
asyncio integration test of _CameraServer/FrontDoorRunner against a fake
in-process "camera" TCP server with a mocked resolve_inner.

Fake IDs only — NEVER real device values, IPs, tokens, or secrets.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import bosch_camera
import bosch_frigate_endpoint as fe

CAM_ID = "AABBCCDD-0000-1111-2222-333344445555"
CAM_NAME = "Testcam"


# ─────────────────────────────────────────────────────────────────────────────
# Pure helpers
# ─────────────────────────────────────────────────────────────────────────────


class TestFindRtspMessageEnd:
    def test_found(self) -> None:
        assert fe.find_rtsp_message_end(b"OPTIONS * RTSP/1.0\r\n\r\n") == len(
            b"OPTIONS * RTSP/1.0\r\n\r\n"
        )

    def test_not_found(self) -> None:
        assert fe.find_rtsp_message_end(b"OPTIONS * RTSP/1.0\r\n") == -1

    def test_with_trailing_body(self) -> None:
        buf = b"HEAD\r\n\r\nBODY"
        assert fe.find_rtsp_message_end(buf) == 8


class TestParseRequestStartLine:
    def test_valid(self) -> None:
        assert fe.parse_request_start_line(b"DESCRIBE rtsp://h/p RTSP/1.0\r\n\r\n") == (
            "DESCRIBE",
            "rtsp://h/p",
        )

    def test_lowercase_method_rejected(self) -> None:
        assert fe.parse_request_start_line(b"describe rtsp://h/p RTSP/1.0\r\n\r\n") is None

    def test_not_rtsp_rejected(self) -> None:
        assert fe.parse_request_start_line(b"GET / HTTP/1.1\r\n\r\n") is None

    def test_too_few_parts(self) -> None:
        assert fe.parse_request_start_line(b"GARBAGE\r\n\r\n") is None

    def test_no_crlf(self) -> None:
        assert fe.parse_request_start_line(b"DESCRIBE rtsp://h/p RTSP/1.0") == (
            "DESCRIBE",
            "rtsp://h/p",
        )


class TestParseResponseStatus:
    def test_valid(self) -> None:
        assert fe.parse_response_status(b"RTSP/1.0 401 Unauthorized\r\n\r\n") == 401

    def test_ok(self) -> None:
        assert fe.parse_response_status(b"RTSP/1.0 200 OK\r\n\r\n") == 200

    def test_malformed(self) -> None:
        assert fe.parse_response_status(b"NOT A RESPONSE\r\n\r\n") is None

    def test_non_numeric_code(self) -> None:
        assert fe.parse_response_status(b"RTSP/1.0 ABC Bad\r\n\r\n") is None


class TestExtractHeader:
    def test_found_case_insensitive(self) -> None:
        buf = b"DESCRIBE * RTSP/1.0\r\nContent-Length: 42\r\n\r\n"
        assert fe.extract_header(buf, "content-length") == "42"

    def test_missing(self) -> None:
        buf = b"DESCRIBE * RTSP/1.0\r\n\r\n"
        assert fe.extract_header(buf, "Content-Length") is None

    def test_value_with_colon(self) -> None:
        buf = b'X RTSP/1.0\r\nWWW-Authenticate: Digest realm="x", nonce="a:b"\r\n\r\n'
        assert fe.extract_header(buf, "WWW-Authenticate") == 'Digest realm="x", nonce="a:b"'


class TestHasAuthorizationHeader:
    def test_present(self) -> None:
        buf = b"X RTSP/1.0\r\nAuthorization: Digest x\r\n\r\n"
        assert fe.has_authorization_header(buf) is True

    def test_absent(self) -> None:
        buf = b"X RTSP/1.0\r\n\r\n"
        assert fe.has_authorization_header(buf) is False


class TestContentLength:
    def test_present(self) -> None:
        buf = b"X RTSP/1.0\r\nContent-Length: 7\r\n\r\n"
        assert fe.content_length(buf) == 7

    def test_absent_defaults_zero(self) -> None:
        assert fe.content_length(b"X RTSP/1.0\r\n\r\n") == 0

    def test_non_numeric_defaults_zero(self) -> None:
        buf = b"X RTSP/1.0\r\nContent-Length: abc\r\n\r\n"
        assert fe.content_length(buf) == 0


class TestInjectAuthHeader:
    def test_inserts_header(self) -> None:
        req = b"DESCRIBE * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        out = fe.inject_auth_header(req, "Digest x")
        assert b"Authorization: Digest x" in out
        assert out.endswith(b"\r\n\r\n")

    def test_replaces_existing_authorization(self) -> None:
        req = b"DESCRIBE * RTSP/1.0\r\nAuthorization: Basic old\r\n\r\n"
        out = fe.inject_auth_header(req, "Digest new")
        assert b"Authorization: Basic old" not in out
        assert b"Authorization: Digest new" in out

    def test_no_terminator_returns_unchanged(self) -> None:
        req = b"DESCRIBE * RTSP/1.0\r\nCSeq: 1\r\n"
        assert fe.inject_auth_header(req, "Digest x") == req


class TestIpAllowed:
    def test_empty_allowlist_allows_all(self) -> None:
        assert fe.ip_allowed("203.0.113.5", frozenset()) is True

    def test_exact_match(self) -> None:
        assert fe.ip_allowed("192.0.2.5", frozenset({"192.0.2.5"})) is True

    def test_no_match(self) -> None:
        assert fe.ip_allowed("192.0.2.9", frozenset({"192.0.2.5"})) is False

    def test_cidr_match(self) -> None:
        assert fe.ip_allowed("192.0.2.200", frozenset({"192.0.2.0/24"})) is True

    def test_cidr_no_match(self) -> None:
        assert fe.ip_allowed("192.0.3.1", frozenset({"192.0.2.0/24"})) is False

    def test_invalid_peer_ip_rejected(self) -> None:
        assert fe.ip_allowed("not-an-ip", frozenset({"192.0.2.0/24"})) is False

    def test_invalid_allowlist_entry_ignored(self) -> None:
        assert fe.ip_allowed("192.0.2.5", frozenset({"not-an-entry", "192.0.2.5"})) is True

    def test_only_invalid_entries_rejects(self) -> None:
        # No valid entry anywhere in the set -> guaranteed to hit the ValueError
        # catch (the mixed-entry test above can short-circuit before reaching it,
        # since frozenset iteration order is unspecified).
        assert fe.ip_allowed("192.0.2.5", frozenset({"not-an-entry"})) is False

    def test_invalid_cidr_entry_ignored(self) -> None:
        assert fe.ip_allowed("192.0.2.5", frozenset({"not-a-cidr/xyz"})) is False

    def test_ipv4_mapped_ipv6_matches_ipv4_entry(self) -> None:
        assert fe.ip_allowed("::ffff:192.0.2.5", frozenset({"192.0.2.5"})) is True

    def test_blank_entry_skipped(self) -> None:
        assert fe.ip_allowed("192.0.2.5", frozenset({"", "192.0.2.5"})) is True


class TestSplitPathToken:
    def test_no_token_configured_passthrough(self) -> None:
        assert fe.split_path_token("rtsp://h:p/high", "") == (True, "rtsp://h:p/high")

    def test_valid_token_stripped(self) -> None:
        ok, uri = fe.split_path_token("rtsp://h:p/tok/high", "tok")
        assert ok is True
        assert uri == "rtsp://h:p/high"

    def test_wrong_token_rejected(self) -> None:
        ok, _ = fe.split_path_token("rtsp://h:p/wrong/high", "tok")
        assert ok is False

    def test_missing_token_rejected(self) -> None:
        ok, _ = fe.split_path_token("rtsp://h:p/", "tok")
        assert ok is False

    def test_preserves_query(self) -> None:
        ok, uri = fe.split_path_token("rtsp://h:p/tok/high?inst=1", "tok")
        assert ok is True
        assert uri == "rtsp://h:p/high?inst=1"

    def test_no_scheme_relative_uri(self) -> None:
        ok, uri = fe.split_path_token("*", "tok")
        assert ok is False
        assert uri == "*"

    def test_path_traversal_segment_rejected(self) -> None:
        """Bug-hunt regression: a '..' segment after the token used to be
        kept verbatim and forwarded to the camera unchanged."""
        ok, uri = fe.split_path_token("rtsp://h:p/tok/../high", "tok")
        assert ok is False
        assert uri == "rtsp://h:p/tok/../high"

    def test_current_dir_segment_rejected(self) -> None:
        ok, _ = fe.split_path_token("rtsp://h:p/tok/./high", "tok")
        assert ok is False

    def test_traversal_segment_deep_in_path_rejected(self) -> None:
        ok, _ = fe.split_path_token("rtsp://h:p/tok/high/../../etc", "tok")
        assert ok is False

    def test_scheme_with_no_path_slash(self) -> None:
        # "rtsp://host" (no trailing "/...") can't have a token segment stripped.
        ok, uri = fe.split_path_token("rtsp://host", "tok")
        assert ok is False
        assert uri == "rtsp://host"


class TestCheckBasicAuth:
    def test_valid(self) -> None:
        import base64

        creds = base64.b64encode(b"frigate:secret").decode()
        buf = f"X RTSP/1.0\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
        assert fe.check_basic_auth(buf, "frigate", "secret") is True

    def test_wrong_password(self) -> None:
        import base64

        creds = base64.b64encode(b"frigate:wrong").decode()
        buf = f"X RTSP/1.0\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
        assert fe.check_basic_auth(buf, "frigate", "secret") is False

    def test_missing_header(self) -> None:
        assert fe.check_basic_auth(b"X RTSP/1.0\r\n\r\n", "frigate", "secret") is False

    def test_wrong_scheme(self) -> None:
        buf = b"X RTSP/1.0\r\nAuthorization: Digest x\r\n\r\n"
        assert fe.check_basic_auth(buf, "frigate", "secret") is False

    def test_invalid_base64(self) -> None:
        buf = b"X RTSP/1.0\r\nAuthorization: Basic ###notb64###\r\n\r\n"
        assert fe.check_basic_auth(buf, "frigate", "secret") is False


class TestBuildPublicUrl:
    def test_auth_none(self) -> None:
        config = fe.FrontDoorConfig(auth_mode=fe.AUTH_NONE)
        url = fe.build_public_url("127.0.0.1", 8554, config)
        assert url == (
            "rtsp://127.0.0.1:8554/rtsp_tunnel?inst=1&enableaudio=1&fmtp=1&maxSessionDuration=3600"
        )

    def test_auth_basic_embeds_credentials(self) -> None:
        config = fe.FrontDoorConfig(auth_mode=fe.AUTH_BASIC, token="secret", basic_user="frigate")
        url = fe.build_public_url("127.0.0.1", 8554, config)
        assert url.startswith("rtsp://frigate:secret@127.0.0.1:8554/")

    def test_auth_basic_without_token_rejected(self) -> None:
        """Bug-hunt regression: auth_mode=basic with an empty token used to
        silently build a credential-free (unauthenticated) URL instead of
        failing — FrontDoorConfig now refuses to construct in that state at
        all, so the gate can never be silently disabled this way."""
        with pytest.raises(ValueError, match="requires a non-empty token"):
            fe.FrontDoorConfig(auth_mode=fe.AUTH_BASIC, token="")

    def test_auth_path_token_prefixes_path(self) -> None:
        config = fe.FrontDoorConfig(auth_mode=fe.AUTH_PATH_TOKEN, token="mytok")
        url = fe.build_public_url("127.0.0.1", 8554, config)
        assert url == (
            "rtsp://127.0.0.1:8554/mytok/rtsp_tunnel?inst=1&enableaudio=1&fmtp=1&maxSessionDuration=3600"
        )

    def test_quality_low_selects_inst2(self) -> None:
        config = fe.FrontDoorConfig(auth_mode=fe.AUTH_NONE)
        url = fe.build_public_url("127.0.0.1", 8554, config, inst=2)
        assert "inst=2" in url

    def test_token_url_encoded(self) -> None:
        config = fe.FrontDoorConfig(auth_mode=fe.AUTH_PATH_TOKEN, token="a b/c")
        url = fe.build_public_url("127.0.0.1", 8554, config)
        assert "a%20b%2Fc" in url


class TestFrigateUrlHost:
    def test_specific_host_verbatim(self) -> None:
        assert fe.frigate_url_host("192.168.1.50") == "192.168.1.50"

    def test_localhost_verbatim(self) -> None:
        assert fe.frigate_url_host("127.0.0.1") == "127.0.0.1"

    def test_all_interfaces_resolves_outbound_ip(self) -> None:
        # Real UDP "connect" never actually sends a packet — safe to run for real.
        host = fe.frigate_url_host("0.0.0.0")
        assert host  # non-empty; exact value depends on the test host's routing

    def test_all_interfaces_falls_back_on_oserror(self) -> None:
        import socket as _socket

        class _BoomSocket:
            def connect(self, *_args: Any) -> None:
                raise OSError("no route")

            def close(self) -> None:
                pass

        with patch.object(_socket, "socket", return_value=_BoomSocket()):
            assert fe.frigate_url_host("0.0.0.0") == "127.0.0.1"


class TestCloseWriter:  # pylint: disable=too-few-public-methods
    def test_swallows_wait_closed_error(self) -> None:
        writer = MagicMock()

        async def _raise() -> None:
            raise OSError("already gone")

        writer.wait_closed = _raise

        async def _run() -> None:
            await fe._close_writer(writer)  # must not raise

        asyncio.run(_run())
        writer.close.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# resolve_camera_target_sync
# ─────────────────────────────────────────────────────────────────────────────


def _make_cfg(cam_id: str = CAM_ID, cam_name: str = CAM_NAME) -> dict[str, Any]:
    return {
        "account": {"bearer_token": "tok", "refresh_token": "", "username": ""},
        "cameras": {cam_name: {"id": cam_id, "name": cam_name, "model": "HOME_Eyes_Outdoor"}},
        "settings": {},
        "lan_ips": {},
    }


class TestResolveCameraTargetSync:
    def test_success(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "urls": ["192.0.2.10:443"],
            "user": "u",
            "password": "p",
        }
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            target = fe._resolve_camera_target_sync(cfg, CAM_ID, False)
        assert target == fe.CameraTarget(
            host="192.0.2.10", port=443, digest_user="u", digest_password="p"
        )

    def test_non_200_returns_none(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 442
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            assert fe._resolve_camera_target_sync(cfg, CAM_ID, False) is None

    def test_missing_urls_returns_none(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"urls": [], "user": "u", "password": "p"}
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            assert fe._resolve_camera_target_sync(cfg, CAM_ID, False) is None

    def test_remote_shaped_url_rejected(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "urls": ["proxy-01.live.cbs.boschsecurity.com:42090/somehash"],
            "user": "u",
            "password": "p",
        }
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            assert fe._resolve_camera_target_sync(cfg, CAM_ID, False) is None

    def test_request_exception_returns_none(self) -> None:
        import requests

        cfg = _make_cfg()
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.side_effect = requests.exceptions.ConnectionError(
                "boom"
            )
            assert fe._resolve_camera_target_sync(cfg, CAM_ID, False) is None

    def test_no_port_defaults_443(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"urls": ["192.0.2.10"], "user": "u", "password": "p"}
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            target = fe._resolve_camera_target_sync(cfg, CAM_ID, False)
        assert target is not None
        assert target.port == 443

    def test_non_json_body_returns_none(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("not json")
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            assert fe._resolve_camera_target_sync(cfg, CAM_ID, False) is None


class TestMakeResolveInner:  # pylint: disable=too-few-public-methods
    def test_bridges_to_worker_thread_and_returns_target(self) -> None:
        cfg = _make_cfg()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"urls": ["192.0.2.10:443"], "user": "u", "password": "p"}
        with (
            patch("bosch_camera.get_token", return_value="tok"),
            patch("bosch_camera.make_session") as mock_make_session,
        ):
            mock_make_session.return_value.put.return_value = resp
            resolve = fe.make_resolve_inner(cfg, CAM_ID)
            target = asyncio.run(resolve(CAM_ID))
        assert target == fe.CameraTarget(
            host="192.0.2.10", port=443, digest_user="u", digest_password="p"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CLI dispatch wiring
# ─────────────────────────────────────────────────────────────────────────────


class TestCmdFrigateEndpointDispatch:
    def test_unknown_sub_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(frigate_sub=None)
        bosch_camera.cmd_frigate_endpoint(cfg, args)
        out = capsys.readouterr().out
        assert "Subcommands" in out

    def test_start_dispatches(self) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(frigate_sub="start")
        with patch("bosch_camera._cmd_frigate_start") as mock_start:
            bosch_camera.cmd_frigate_endpoint(cfg, args)
        mock_start.assert_called_once_with(cfg, args)

    def test_no_cameras_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        cfg = _make_cfg()
        cfg["cameras"] = {}
        args = argparse.Namespace(
            cam=None,
            bind_host="127.0.0.1",
            port=8554,
            ip_allowlist="",
            auth_mode="none",
            token="",
            basic_user="frigate",
            idle_timeout=60.0,
        )
        bosch_camera._cmd_frigate_start(cfg, args)
        assert "No cameras found" in capsys.readouterr().out

    def test_unknown_auth_mode_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(
            cam=None,
            bind_host="127.0.0.1",
            port=8554,
            ip_allowlist="",
            auth_mode="bogus",
            token="",
            basic_user="frigate",
            idle_timeout=60.0,
        )
        bosch_camera._cmd_frigate_start(cfg, args)
        assert "Unknown --auth-mode" in capsys.readouterr().out

    def test_auth_mode_basic_without_token_aborts(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Bug-hunt regression: --auth-mode basic/path_token with no --token
        used to only print a warning and then start the listener anyway,
        unauthenticated — the opposite of what was requested. It must now
        abort before the listener ever starts."""
        cfg = _make_cfg()
        args = argparse.Namespace(
            cam=None,
            bind_host="127.0.0.1",
            port=8554,
            ip_allowlist="",
            auth_mode="basic",
            token="",
            basic_user="frigate",
            idle_timeout=60.0,
        )
        with patch("bosch_frigate_endpoint.FrontDoorRunner") as mock_runner_cls:
            bosch_camera._cmd_frigate_start(cfg, args)
        out = capsys.readouterr().out
        assert "requires --token" in out
        mock_runner_cls.assert_not_called()

    def test_auth_mode_path_token_without_token_aborts(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(
            cam=None,
            bind_host="127.0.0.1",
            port=8554,
            ip_allowlist="",
            auth_mode="path_token",
            token="",
            basic_user="frigate",
            idle_timeout=60.0,
        )
        with patch("bosch_frigate_endpoint.FrontDoorRunner") as mock_runner_cls:
            bosch_camera._cmd_frigate_start(cfg, args)
        out = capsys.readouterr().out
        assert "requires --token" in out
        mock_runner_cls.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Async integration: _CameraServer/FrontDoorRunner against a fake camera.
# ─────────────────────────────────────────────────────────────────────────────


async def _fake_camera_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Minimal fake 'camera': challenges the first request with a 401+Digest
    challenge, then answers 200 OK on the authenticated retry — on the SAME
    connection, mirroring the real two-round-trip Digest dance that
    ``_Relay._auth_dance`` performs (a real camera keeps the RTSP TCP
    connection open across the challenge/response exchange).
    """
    try:
        while True:
            data = await reader.readuntil(b"\r\n\r\n")
            if fe.has_authorization_header(data):
                writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                break
            writer.write(
                b'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="cam", '
                b'nonce="abc123", qop="auth"\r\n\r\n'
            )
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - best-effort test-fixture teardown
            pass


async def _run_front_door_roundtrip() -> tuple[int, bytes]:
    """Start a fake camera + a real _CameraServer front-door pointed at it,
    connect a plain client, send one RTSP OPTIONS request, return (status,
    raw response).
    """
    fake_cam_server = await asyncio.start_server(_fake_camera_handler, "127.0.0.1", 0)
    fake_cam_port = fake_cam_server.sockets[0].getsockname()[1]

    async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
        return fe.CameraTarget(
            host="127.0.0.1", port=fake_cam_port, digest_user="u", digest_password="p"
        )

    config = fe.FrontDoorConfig(bind_host="127.0.0.1", idle_timeout=0.1)
    runner = fe.FrontDoorRunner()
    try:
        port = await runner.start_server(CAM_ID, config, resolve_inner)
        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
        client_writer.write(b"OPTIONS rtsp://127.0.0.1/high RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        await client_writer.drain()
        resp = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), timeout=5)
        client_writer.close()
        try:
            await client_writer.wait_closed()
        except Exception:  # noqa: BLE001 - best-effort test-fixture teardown
            pass
        status = fe.parse_response_status(resp)
        assert status is not None
        return status, resp
    finally:
        runner.stop_all()
        fake_cam_server.close()
        await fake_cam_server.wait_closed()


class TestFrontDoorIntegration:
    def test_full_digest_roundtrip_returns_200(self) -> None:
        status, resp = asyncio.run(_run_front_door_roundtrip())
        assert status == 200
        assert b"401" not in resp

    def test_ip_allowlist_rejects_disallowed_client(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(
                bind_host="127.0.0.1", ip_allowlist=frozenset({"203.0.113.1"})
            )
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                # The gate rejects and closes before reading — this is a genuine
                # TCP race: the client's write can land either before or after
                # the server-side close, surfacing as either an empty read
                # (FIN) or a ConnectionResetError (RST). Both mean "rejected".
                try:
                    writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                    await writer.drain()
                    data = await reader.read(100)
                except (ConnectionResetError, BrokenPipeError):
                    data = b""
                assert data == b""
                writer.close()
            finally:
                runner.stop_all()

        asyncio.run(_run())

    def test_resolve_inner_none_returns_503(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(bind_host="127.0.0.1")
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                assert fe.parse_response_status(resp) == 503
            finally:
                runner.stop_all()

        asyncio.run(_run())

    def test_path_token_gate_rejects_bad_token(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(
                bind_host="127.0.0.1", auth_mode=fe.AUTH_PATH_TOKEN, token="secrettok"
            )
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    writer.write(b"OPTIONS rtsp://h/wrongtoken/high RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                    await writer.drain()
                    data = await reader.read(100)
                except (ConnectionResetError, BrokenPipeError):
                    data = b""
                assert data == b""  # rejected, connection closed with no response
                writer.close()
            finally:
                runner.stop_all()

        asyncio.run(_run())

    def test_basic_auth_gate_challenges_without_creds(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(
                bind_host="127.0.0.1", auth_mode=fe.AUTH_BASIC, token="secret"
            )
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                assert fe.parse_response_status(resp) == 401
            finally:
                runner.stop_all()

        asyncio.run(_run())

    def test_runner_start_stop_reports_port_and_active_count(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(bind_host="127.0.0.1")
            runner = fe.FrontDoorRunner()
            assert runner.has_server(CAM_ID) is False
            port = await runner.start_server(CAM_ID, config, resolve_inner)
            assert port != 0
            assert runner.has_server(CAM_ID) is True
            assert runner.port(CAM_ID) == port
            assert runner.active_count(CAM_ID) == 0
            assert runner.has_any_server() is True
            runner.stop_server(CAM_ID)
            assert runner.has_server(CAM_ID) is False
            assert runner.port(CAM_ID) == 0
            assert runner.has_any_server() is False

        asyncio.run(_run())

    def test_queries_for_unknown_camera_return_defaults(self) -> None:
        runner = fe.FrontDoorRunner()
        assert runner.active_count("unknown") == 0
        assert runner.port("unknown") == 0
        assert runner.has_server("unknown") is False
        assert runner.has_any_server() is False
        # stop_server on a camera with no server is a no-op, not an error.
        runner.stop_server("unknown")


# ─────────────────────────────────────────────────────────────────────────────
# Direct unit tests for the private request-rewriting helpers.
# ─────────────────────────────────────────────────────────────────────────────


class TestRewriteRequestUri:
    def test_replaces_uri(self) -> None:
        req = b"OPTIONS rtsp://h/tok/high RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        out = fe._rewrite_request_uri(req, "rtsp://h/high")
        assert out.startswith(b"OPTIONS rtsp://h/high RTSP/1.0")

    def test_no_crlf_returns_unchanged(self) -> None:
        req = b"OPTIONS * RTSP/1.0"
        assert fe._rewrite_request_uri(req, "new") == req

    def test_too_few_parts_returns_unchanged(self) -> None:
        req = b"GARBAGE\r\nCSeq: 1\r\n\r\n"
        assert fe._rewrite_request_uri(req, "new") == req


class TestStripAuthorization:
    def test_removes_header(self) -> None:
        req = b"OPTIONS * RTSP/1.0\r\nAuthorization: Basic xyz\r\nCSeq: 1\r\n\r\n"
        out = fe._strip_authorization(req)
        assert b"Authorization" not in out
        assert b"CSeq: 1" in out

    def test_no_terminator_returns_unchanged(self) -> None:
        req = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
        assert fe._strip_authorization(req) == req


# ─────────────────────────────────────────────────────────────────────────────
# More _CameraServer/_Relay branch coverage against fake cameras/clients.
# ─────────────────────────────────────────────────────────────────────────────


async def _fake_camera_no_challenge(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Fake camera that accepts every request without ever sending a 401."""
    try:
        while True:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def _fake_camera_echo_binary(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, received: list[bytes]
) -> None:
    """Fake camera: 200s the first (real RTSP) request, then records any
    raw bytes it receives afterwards (used to verify interleaved binary
    ``$`` frames and oversized non-RTSP data are forwarded byte-for-byte).
    """
    try:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
        await writer.drain()
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            received.append(chunk)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()


class TestRelayBranches:
    def test_camera_accepts_without_401(self) -> None:
        async def _run() -> tuple[int, bytes]:
            cam_server = await asyncio.start_server(_fake_camera_no_challenge, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status, resp
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        status, resp = asyncio.run(_run())
        assert status == 200
        assert b"401" not in resp

    def test_client_supplied_auth_is_passthrough(self) -> None:
        async def _run() -> int:
            cam_server = await asyncio.start_server(_fake_camera_no_challenge, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nAuthorization: Digest x\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        assert asyncio.run(_run()) == 200

    def test_resolve_inner_raising_returns_503(self) -> None:
        async def _run() -> int:
            async def resolve_inner(_cam_id: str) -> None:
                raise RuntimeError("boom")

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()

        assert asyncio.run(_run()) == 503

    def test_malformed_initial_request_closes_silently(self) -> None:
        async def _run() -> bytes:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    writer.write(b"not rtsp at all\r\n\r\n")
                    await writer.drain()
                    data = await reader.read(100)
                except (ConnectionResetError, BrokenPipeError):
                    data = b""
                writer.close()
                return data
            finally:
                runner.stop_all()

        assert asyncio.run(_run()) == b""

    def test_initial_request_with_content_length_body(self) -> None:
        async def _run() -> int:
            cam_server = await asyncio.start_server(_fake_camera_no_challenge, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                body = b"<sdp/>"
                writer.write(
                    b"ANNOUNCE * RTSP/1.0\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        assert asyncio.run(_run()) == 200

    def test_max_connections_cap_rejects_extra_client(self) -> None:
        async def _run() -> bytes:
            async def resolve_inner(_cam_id: str) -> None:
                await asyncio.sleep(1)  # keep the first connection "in flight"
                return None

            config = fe.FrontDoorConfig(bind_host="127.0.0.1", max_connections=1)
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                r1, w1 = await asyncio.open_connection("127.0.0.1", port)
                w1.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await w1.drain()
                await asyncio.sleep(0.1)  # let the server accept + acquire the semaphore

                r2, w2 = await asyncio.open_connection("127.0.0.1", port)
                try:
                    w2.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                    await w2.drain()
                    data = await r2.read(100)
                except (ConnectionResetError, BrokenPipeError):
                    data = b""
                w2.close()
                w1.close()
                return data
            finally:
                runner.stop_all()

        # Rejected immediately — no response, connection closed.
        assert asyncio.run(_run()) == b""

    def test_idle_linger_fires_on_idle_after_last_client_leaves(self) -> None:
        async def _run() -> bool:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            fired = asyncio.Event()

            def on_idle() -> None:
                fired.set()

            config = fe.FrontDoorConfig(bind_host="127.0.0.1", idle_timeout=0.05)
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner, on_idle=on_idle)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                await asyncio.wait_for(fired.wait(), timeout=5)
                return fired.is_set()
            finally:
                runner.stop_all()

        assert asyncio.run(_run()) is True

    def test_interleaved_binary_frame_and_oversized_data_forwarded_raw(self) -> None:
        async def _run() -> list[bytes]:
            received: list[bytes] = []
            cam_server = await asyncio.start_server(
                lambda r, w: _fake_camera_echo_binary(r, w, received), "127.0.0.1", 0
            )
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)

                # Interleaved RTP/RTCP binary frame: '$' + channel + 2-byte len + payload.
                binary_frame = b"$" + bytes([0]) + b"\x00\x04" + b"data"
                writer.write(binary_frame)
                await writer.drain()
                await asyncio.sleep(0.05)

                # Non-RTSP data exceeding _MAX_HEAD_BYTES with no CRLFCRLF —
                # forwarded raw instead of buffered forever.
                oversized = b"x" * (fe._MAX_HEAD_BYTES + 10)
                writer.write(oversized)
                await writer.drain()
                await asyncio.sleep(0.2)

                writer.close()
                return received
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        received = asyncio.run(_run())
        combined = b"".join(received)
        assert b"$" + bytes([0]) + b"\x00\x04" + b"data" in combined
        assert b"x" * (fe._MAX_HEAD_BYTES + 10) in combined

    def test_valid_path_token_gate_reaches_resolve(self) -> None:
        async def _run() -> int:
            async def resolve_inner(_cam_id: str) -> None:
                return None  # not reached far enough to matter — 503 either way

            config = fe.FrontDoorConfig(
                bind_host="127.0.0.1", auth_mode=fe.AUTH_PATH_TOKEN, token="secrettok"
            )
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS rtsp://h/secrettok/high RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()

        # Token accepted + URI rewritten -> reaches resolve_inner -> 503 (no target).
        assert asyncio.run(_run()) == 503

    def test_valid_basic_auth_gate_strips_header_and_reaches_resolve(self) -> None:
        async def _run() -> int:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(
                bind_host="127.0.0.1", auth_mode=fe.AUTH_BASIC, token="secret", basic_user="frigate"
            )
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                import base64

                creds = base64.b64encode(b"frigate:secret").decode()
                writer.write(
                    b"OPTIONS * RTSP/1.0\r\nAuthorization: Basic " + creds.encode() + b"\r\n\r\n"
                )
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()

        assert asyncio.run(_run()) == 503

    def test_camera_connection_refused_ends_relay_gracefully(self) -> None:
        async def _run() -> bytes:
            # Bind + immediately close to get a port nothing is listening on.
            probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
            dead_port = probe.sockets[0].getsockname()[1]
            probe.close()
            await probe.wait_closed()

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=dead_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(100), timeout=5)
                except (ConnectionResetError, BrokenPipeError):
                    data = b""
                writer.close()
                return data
            finally:
                runner.stop_all()

        # Camera unreachable -> relay.run()'s connect fails -> caught in _serve,
        # client connection just closes (no crash, no response).
        assert asyncio.run(_run()) == b""

    def test_malformed_digest_challenge_forwards_401(self) -> None:
        async def fake_camera(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
                # Syntactically-broken challenge -> _parse_digest_challenge raises.
                writer.write(
                    b"RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: not-a-digest-challenge\r\n\r\n"
                )
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def _run() -> int:
            cam_server = await asyncio.start_server(fake_camera, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        assert asyncio.run(_run()) == 401

    def test_missing_www_authenticate_header_forwards_401(self) -> None:
        async def fake_camera(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
                # 401 with no WWW-Authenticate at all -> nothing to compute from.
                writer.write(b"RTSP/1.0 401 Unauthorized\r\n\r\n")
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def _run() -> int:
            cam_server = await asyncio.start_server(fake_camera, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                status = fe.parse_response_status(resp)
                assert status is not None
                return status
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        assert asyncio.run(_run()) == 401

    def test_steady_state_second_request_gets_injected_auth(self) -> None:
        """After a successful Digest dance, a second request on the same
        connection should also get an Authorization header injected (via
        ``_drain_requests``'s cached-challenge path), without repeating the
        401 round trip.
        """

        seen_requests: list[bytes] = []

        async def fake_camera(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    req = await reader.readuntil(b"\r\n\r\n")
                    seen_requests.append(req)
                    if fe.has_authorization_header(req):
                        writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
                    else:
                        writer.write(
                            b'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="cam", '
                            b'nonce="abc123", qop="auth"\r\n\r\n'
                        )
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def _run() -> list[bytes]:
            cam_server = await asyncio.start_server(fake_camera, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)

                # Second request on the SAME connection — no client-side auth.
                writer.write(b"SETUP rtsp://h/high RTSP/1.0\r\nCSeq: 2\r\n\r\n")
                await writer.drain()
                resp2 = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                assert fe.parse_response_status(resp2) == 200
                writer.close()
                return seen_requests
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        seen = asyncio.run(_run())
        assert len(seen) >= 3  # unauth OPTIONS, auth'd OPTIONS retry, auth'd SETUP
        assert fe.has_authorization_header(seen[-1])

    def test_stale_creds_closes_instead_of_piping_unauthenticated(self) -> None:
        """Bug-hunt regression: a camera that rejects even the authenticated
        retry (rotated/stale Digest creds) used to log 'closing for
        reconnect' but then fall through to the normal pipe anyway, forwarding
        every further request unauthenticated. The connection must actually
        close — the client must not get a second response at all."""

        async def fake_camera_always_401(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while True:
                    await reader.readuntil(b"\r\n\r\n")
                    writer.write(
                        b'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="cam", '
                        b'nonce="abc123", qop="auth"\r\n\r\n'
                    )
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def _run() -> bytes:
            cam_server = await asyncio.start_server(fake_camera_always_401, "127.0.0.1", 0)
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                assert fe.parse_response_status(resp) == 401

                # A second request on the same connection must NOT get a
                # response — the relay must have already closed instead of
                # forwarding it unauthenticated. The relay closes right after
                # the 401 (before this second write is even sent), so the
                # OS-level outcome of writing to an already-peer-closed
                # socket is a genuine race: a clean EOF on the next read, or
                # a ConnectionResetError if the write reaches the kernel
                # before the FIN/RST teardown completes (timing-dependent,
                # not a code bug — same security property either way: zero
                # bytes of an actual RTSP response are ever received).
                writer.write(b"SETUP rtsp://h/high RTSP/1.0\r\nCSeq: 2\r\n\r\n")
                await writer.drain()
                try:
                    remainder = await asyncio.wait_for(reader.read(4096), timeout=5)
                except ConnectionResetError:
                    remainder = b""
                writer.close()
                return remainder
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        # EOF (empty read) or a reset — either way, no response was forwarded.
        assert asyncio.run(_run()) == b""

    def test_no_challenge_learned_aborts_instead_of_forwarding_unauth(self) -> None:
        """Bug-hunt regression: if the camera accepts the very first request
        without a 401 (e.g. an unauthenticated OPTIONS), no Digest challenge
        is ever learned. A later real request used to be forwarded to the
        camera completely unauthenticated forever. It must now abort the
        relay instead."""

        seen_requests: list[bytes] = []

        async def fake_camera_no_challenge_then_setup(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while True:
                    req = await reader.readuntil(b"\r\n\r\n")
                    seen_requests.append(req)
                    writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def _run() -> bytes:
            cam_server = await asyncio.start_server(
                fake_camera_no_challenge_then_setup, "127.0.0.1", 0
            )
            cam_port = cam_server.sockets[0].getsockname()[1]

            async def resolve_inner(_cam_id: str) -> fe.CameraTarget:
                return fe.CameraTarget(
                    host="127.0.0.1", port=cam_port, digest_user="u", digest_password="p"
                )

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                assert fe.parse_response_status(resp) == 200

                writer.write(b"SETUP rtsp://h/high RTSP/1.0\r\nCSeq: 2\r\n\r\n")
                await writer.drain()
                remainder = await asyncio.wait_for(reader.read(4096), timeout=5)
                writer.close()
                return remainder
            finally:
                runner.stop_all()
                cam_server.close()
                await cam_server.wait_closed()

        remainder = asyncio.run(_run())
        # The relay closed instead of forwarding SETUP — camera never saw it.
        assert remainder == b""
        assert len(seen_requests) == 1

    def test_idle_task_cancelled_when_server_closed_while_pending(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            config = fe.FrontDoorConfig(bind_host="127.0.0.1", idle_timeout=30.0)
            runner = fe.FrontDoorRunner()
            port = await runner.start_server(CAM_ID, config, resolve_inner)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            writer.close()
            await asyncio.sleep(0.05)  # let the idle-linger task get scheduled
            # Closing the server while the 30s idle-linger is still pending
            # must cancel it cleanly instead of leaking/crashing.
            runner.stop_all()

        asyncio.run(_run())

    def test_idle_task_cancelled_by_a_reconnect(self) -> None:
        async def _run() -> bool:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            fired = False

            def on_idle() -> None:
                nonlocal fired
                fired = True

            config = fe.FrontDoorConfig(bind_host="127.0.0.1", idle_timeout=0.3)
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner, on_idle=on_idle)

                reader1, writer1 = await asyncio.open_connection("127.0.0.1", port)
                writer1.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer1.drain()
                await asyncio.wait_for(reader1.readuntil(b"\r\n\r\n"), timeout=5)
                writer1.close()

                # Reconnect quickly, well before the 0.3s idle-linger fires.
                await asyncio.sleep(0.05)
                reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
                writer2.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer2.drain()
                await asyncio.wait_for(reader2.readuntil(b"\r\n\r\n"), timeout=5)
                writer2.close()

                # By now the FIRST idle-linger task should have been cancelled.
                await asyncio.sleep(0.1)
                return fired
            finally:
                runner.stop_all()

        # The first idle-linger was cancelled by the reconnect, so it must not
        # have fired for the (irrelevant) 0.3s window that started at disconnect 1.
        assert asyncio.run(_run()) is False

    def test_on_idle_exception_is_swallowed(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            def on_idle() -> None:
                raise RuntimeError("callback bug")

            config = fe.FrontDoorConfig(bind_host="127.0.0.1", idle_timeout=0.05)
            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(CAM_ID, config, resolve_inner, on_idle=on_idle)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.close()
                # Must not propagate/crash the server despite on_idle raising.
                await asyncio.sleep(0.2)
            finally:
                runner.stop_all()

        asyncio.run(_run())  # no exception escapes

    def test_client_disconnects_before_full_head_sent(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n")  # no terminating blank line
                await writer.drain()
                writer.close()
                await asyncio.sleep(0.1)  # let the server observe the abrupt close
            finally:
                runner.stop_all()

        asyncio.run(_run())  # server must not crash on an incomplete head

    def test_client_disconnects_mid_body(self) -> None:
        async def _run() -> None:
            async def resolve_inner(_cam_id: str) -> None:
                return None

            runner = fe.FrontDoorRunner()
            try:
                port = await runner.start_server(
                    CAM_ID, fe.FrontDoorConfig(bind_host="127.0.0.1"), resolve_inner
                )
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"ANNOUNCE * RTSP/1.0\r\nContent-Length: 100\r\n\r\nshort")
                await writer.drain()
                writer.close()  # body never fully arrives
                await asyncio.sleep(0.1)
            finally:
                runner.stop_all()

        asyncio.run(_run())  # server must not crash on an incomplete body
