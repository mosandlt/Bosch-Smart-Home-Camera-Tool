"""
Tests for cmd_reset — camera soft reset (reboot) / hard reset (factory reset).

Cross-ported from the HA integration's device_actions.async_soft_reset_camera /
async_hard_reset_camera (2026-08 family-parity work).

API: PUT /v11/video_inputs/{id}/soft_reset  (bodyless) — reboot
     PUT /v11/video_inputs/{id}/hard_reset  (bodyless) — factory reset (DESTRUCTIVE)

--hard requires --confirm or an interactive 'yes' — pinned both ways, matching
this repo's existing destructive-action confirmation pattern (cmd_firmware_update
install-on-all-cameras).
Fake IDs only — NEVER real device values, IPs, tokens, or secrets.
"""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import MagicMock, patch

import bosch_camera
from bosch_camera import cmd_reset

CAM_ID = "AABBCCDD-0000-1111-2222-333344445555"
CAM_NAME = "Testcam"


def _make_cfg(cam_id: str = CAM_ID, cam_name: str = CAM_NAME) -> dict[str, Any]:
    return {
        "account": {"bearer_token": "tok", "refresh_token": "", "username": ""},
        "cameras": {
            cam_name: {
                "id": cam_id,
                "name": cam_name,
                "model": "HOME_Eyes_Outdoor",
                "firmware": "9.40.25",
            }
        },
        "settings": {},
        "lan_ips": {},
    }


def _make_multi_cfg() -> dict[str, Any]:
    return {
        "account": {"bearer_token": "tok", "refresh_token": "", "username": ""},
        "cameras": {
            "Terrasse": {
                "id": "AABBCCDD-0000-1111-2222-333344440001",
                "name": "Terrasse",
                "model": "HOME_Eyes_Outdoor",
                "firmware": "9.40.25",
            },
            "Garten": {
                "id": "AABBCCDD-0000-1111-2222-333344440002",
                "name": "Garten",
                "model": "HOME_Eyes_Outdoor",
                "firmware": "9.40.25",
            },
        },
        "settings": {},
        "lan_ips": {},
    }


def _args(**kwargs: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "cam": CAM_NAME,
        "soft": False,
        "hard": False,
        "confirm": False,
        "all": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _patched(sess: MagicMock, cfg: dict[str, Any]) -> Any:
    return (
        patch.object(bosch_camera, "get_token", return_value="tok"),
        patch.object(bosch_camera, "make_session", return_value=sess),
        patch.object(bosch_camera, "get_cameras", return_value=cfg["cameras"]),
    )


class TestNoModeSelected:
    def test_neither_soft_nor_hard_prints_hint(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args())
        out = capsys.readouterr().out
        assert "Specify exactly one" in out
        sess.put.assert_not_called()

    def test_both_soft_and_hard_prints_hint(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(soft=True, hard=True))
        out = capsys.readouterr().out
        assert "Specify exactly one" in out
        sess.put.assert_not_called()


class TestSoftReset:
    def test_soft_reset_ok(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(soft=True))
        out = capsys.readouterr().out
        assert "triggered" in out
        url = sess.put.call_args.args[0]
        assert url.endswith(f"/video_inputs/{CAM_ID}/soft_reset")
        assert "json" not in sess.put.call_args.kwargs

    def test_soft_reset_no_confirmation_prompt(self, capsys: Any, monkeypatch: Any) -> None:
        """Soft reset is non-destructive — never prompts, even without --confirm."""
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)

        def _fail_input(_: str) -> str:
            raise AssertionError("soft reset must never prompt for input")

        monkeypatch.setattr("builtins.input", _fail_input)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(soft=True))
        sess.put.assert_called_once()

    def test_soft_reset_camera_not_found_404(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=404, text="sh:entity.notfound")
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(soft=True))
        out = capsys.readouterr().out
        assert "Failed" in out
        assert "404" in out


class TestHardReset:
    def test_hard_reset_with_confirm_flag(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=204)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(hard=True, confirm=True))
        out = capsys.readouterr().out
        assert "FACTORY RESET" in out
        assert "triggered" in out
        url = sess.put.call_args.args[0]
        assert url.endswith(f"/video_inputs/{CAM_ID}/hard_reset")

    def test_hard_reset_interactive_yes(self, capsys: Any, monkeypatch: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=204)
        monkeypatch.setattr("builtins.input", lambda _: "yes")
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(hard=True))
        sess.put.assert_called_once()

    def test_hard_reset_interactive_declined(self, capsys: Any, monkeypatch: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        monkeypatch.setattr("builtins.input", lambda _: "n")
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(hard=True))
        out = capsys.readouterr().out
        assert "Aborted" in out
        sess.put.assert_not_called()

    def test_hard_reset_offline_camera(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=444)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(hard=True, confirm=True))
        out = capsys.readouterr().out
        assert "offline" in out.lower()


class TestNoCameraFanOutGuard:
    """Regression tests for the bug-hunt finding: reset --hard with no camera
    name fanned out to EVERY configured camera (resolve_cam(cfg, None) returns
    the whole cameras dict), even with --confirm — same bug class as the
    firmware-update fleet-wide install incident, but --hard is destructive
    (factory reset) so it must be rejected outright, never just prompted.
    """

    def test_hard_reset_no_camera_rejected_even_with_confirm(self, capsys: Any) -> None:
        cfg = _make_multi_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(cam=None, hard=True, confirm=True))
        out = capsys.readouterr().out
        assert "requires an explicit camera" in out
        sess.put.assert_not_called()

    def test_hard_reset_no_camera_rejected_single_camera_config(self, capsys: Any) -> None:
        """Even with exactly one camera configured, --hard still requires
        an explicit name — resolve_cam(cfg, None) still returns "all
        cameras" mechanically, and the guard must not depend on count."""
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(cam=None, hard=True, confirm=True))
        out = capsys.readouterr().out
        assert "requires an explicit camera" in out
        sess.put.assert_not_called()

    def test_soft_reset_no_camera_no_all_rejected(self, capsys: Any) -> None:
        cfg = _make_multi_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(cam=None, soft=True))
        out = capsys.readouterr().out
        assert "No camera given" in out
        sess.put.assert_not_called()

    def test_soft_reset_no_camera_with_all_prompts_and_confirms(self, capsys: Any) -> None:
        cfg = _make_multi_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(cam=None, soft=True, all=True, confirm=True))
        out = capsys.readouterr().out
        assert sess.put.call_count == 2
        assert "triggered" in out

    def test_soft_reset_no_camera_with_all_declined_prompt(
        self, capsys: Any, monkeypatch: Any
    ) -> None:
        cfg = _make_multi_cfg()
        sess = MagicMock()
        monkeypatch.setattr("builtins.input", lambda _: "n")
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_reset(cfg, _args(cam=None, soft=True, all=True))
        out = capsys.readouterr().out
        assert "Aborted" in out
        sess.put.assert_not_called()
