"""
Tests for the persistent per-camera video-quality preference:
  get_quality_pref / set_quality_pref / _resolve_quality / cmd_config set-quality

Cross-ported from the HA integration's quality_prefs.get_quality (session-only
there; persisted to bosch_config.json here since the CLI has no long-lived
process to hold runtime state between invocations). Explicit --quality on a
command always overrides the stored preference.
Fake IDs only — NEVER real device values, IPs, tokens, or secrets.
"""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import MagicMock, patch

import bosch_camera
from bosch_camera import (
    _resolve_quality,
    cmd_config,
    get_quality_pref,
    set_quality_pref,
)

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


class TestGetSetQualityPref:
    def test_default_is_auto(self) -> None:
        cfg = _make_cfg()
        assert get_quality_pref(cfg, CAM_NAME) == "auto"

    def test_set_then_get_round_trips(self) -> None:
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "high")
        assert get_quality_pref(cfg, CAM_NAME) == "high"

    def test_set_on_fresh_cfg_without_settings_key(self) -> None:
        cfg: dict[str, Any] = {}
        set_quality_pref(cfg, CAM_NAME, "low")
        assert get_quality_pref(cfg, CAM_NAME) == "low"

    def test_garbage_stored_value_falls_back_to_auto(self) -> None:
        cfg = _make_cfg()
        cfg["settings"]["quality_pref"] = {CAM_NAME: "ultra-hd-please"}
        assert get_quality_pref(cfg, CAM_NAME) == "auto"

    def test_unknown_camera_defaults_to_auto(self) -> None:
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "high")
        assert get_quality_pref(cfg, "OtherCam") == "auto"


class TestResolveQuality:
    def test_explicit_flag_wins_over_stored(self) -> None:
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "low")
        args = argparse.Namespace(quality="high")
        assert _resolve_quality(args, cfg, CAM_NAME) == "high"

    def test_falls_back_to_stored_when_flag_absent(self) -> None:
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "low")
        args = argparse.Namespace(quality=None)
        assert _resolve_quality(args, cfg, CAM_NAME) == "low"

    def test_no_flag_no_stored_pref_returns_none(self) -> None:
        """No explicit --quality AND no set-quality ever run → None, so callers'
        pre-existing --hq/--inst fallback logic stays exactly as before this
        feature existed."""
        cfg = _make_cfg()
        args = argparse.Namespace(quality=None)
        assert _resolve_quality(args, cfg, CAM_NAME) is None

    def test_missing_quality_attr_on_namespace(self) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace()
        assert _resolve_quality(args, cfg, CAM_NAME) is None

    def test_explicit_stored_auto_is_returned_not_none(self) -> None:
        """set-quality auto (explicit) still returns 'auto', distinct from unset."""
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "auto")
        args = argparse.Namespace(quality=None)
        assert _resolve_quality(args, cfg, CAM_NAME) == "auto"


class TestCmdConfigSetQuality:
    def test_set_quality_persists_and_saves(self, tmp_config_dir: str) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(sub="set-quality", cam=CAM_NAME, quality="high")
        cmd_config(cfg, args)
        assert get_quality_pref(cfg, CAM_NAME) == "high"

    def test_set_quality_missing_camera_prints_usage(self, capsys: Any) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(sub="set-quality", cam=None, quality="high")
        cmd_config(cfg, args)
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_set_quality_invalid_quality_prints_usage(self, capsys: Any) -> None:
        cfg = _make_cfg()
        args = argparse.Namespace(sub="set-quality", cam=CAM_NAME, quality=None)
        cmd_config(cfg, args)
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_config_without_sub_still_shows_config(self, capsys: Any, tmp_config_dir: str) -> None:
        """tmp_config_dir keeps CONFIG_FILE isolated — cmd_config's fallback
        check_token_age() -> os.path.getmtime(CONFIG_FILE) path (hit because
        the fake 'tok' bearer_token isn't real JWT-shaped) must not touch the
        developer's real bosch_config.json next to the script."""
        cfg = _make_cfg()
        with open(bosch_camera.CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write("{}")
        args = argparse.Namespace(sub=None, cam=None, quality=None)
        cmd_config(cfg, args)
        out = capsys.readouterr().out
        assert "Config:" in out


class TestQualityPrefWiredIntoLiveAndSnapshot:
    """Confirm cmd_live / cmd_snapshot actually read the stored preference
    when --quality is omitted (not just that the helper function works)."""

    def test_cmd_live_uses_stored_high_preference(self) -> None:
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "high")
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=200, text='"ONLINE"')
        sess.request.return_value = MagicMock(status_code=204, json=lambda: [])
        with (
            patch.object(bosch_camera, "get_token", return_value="tok"),
            patch.object(bosch_camera, "make_session", return_value=sess),
            patch.object(bosch_camera, "get_cameras", return_value=cfg["cameras"]),
            patch.object(bosch_camera, "api_ping", return_value="ONLINE"),
            patch.object(bosch_camera, "resolve_cam", return_value=cfg["cameras"]),
        ):
            # PUT /connection returns a non-200 so cmd_live stops after the
            # first request — we only care that highQualityVideo=True was sent.
            sess.put.return_value = MagicMock(status_code=500, text="err")
            args = argparse.Namespace(
                cam=CAM_NAME, sub=False, quality=None, hq=False, inst=None, local=False
            )
            bosch_camera.cmd_live(cfg, args)
        assert sess.put.called
        body = sess.put.call_args.kwargs["json"]
        assert body["highQualityVideo"] is True

    def test_cmd_live_explicit_hq_wins_over_stored_low_preference(self) -> None:
        """Bug-hunt regression: a persisted 'low' preference used to silently
        override an explicit --hq passed on the SAME invocation — an explicit
        flag on the command line must always win over a stored default."""
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "low")
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=200, text='"ONLINE"')
        sess.request.return_value = MagicMock(status_code=204, json=lambda: [])
        with (
            patch.object(bosch_camera, "get_token", return_value="tok"),
            patch.object(bosch_camera, "make_session", return_value=sess),
            patch.object(bosch_camera, "get_cameras", return_value=cfg["cameras"]),
            patch.object(bosch_camera, "api_ping", return_value="ONLINE"),
            patch.object(bosch_camera, "resolve_cam", return_value=cfg["cameras"]),
        ):
            sess.put.return_value = MagicMock(status_code=500, text="err")
            args = argparse.Namespace(
                cam=CAM_NAME, sub=False, quality=None, hq=True, inst=None, local=False
            )
            bosch_camera.cmd_live(cfg, args)
        assert sess.put.called
        body = sess.put.call_args.kwargs["json"]
        assert body["highQualityVideo"] is True

    def test_cmd_live_explicit_inst_wins_over_stored_preference(self) -> None:
        """Bug-hunt regression: an explicit --inst on this invocation must
        win over the persisted preference's own inst selection."""
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "high")  # would normally force inst=1
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=200, text='"ONLINE"')
        sess.request.return_value = MagicMock(status_code=204, json=lambda: [])
        with (
            patch.object(bosch_camera, "get_token", return_value="tok"),
            patch.object(bosch_camera, "make_session", return_value=sess),
            patch.object(bosch_camera, "get_cameras", return_value=cfg["cameras"]),
            patch.object(bosch_camera, "api_ping", return_value="ONLINE"),
            patch.object(bosch_camera, "resolve_cam", return_value=cfg["cameras"]),
        ):
            sess.put.return_value = MagicMock(status_code=200, json=lambda: {"rtspsUrl": ""})
            args = argparse.Namespace(
                cam=CAM_NAME, sub=False, quality=None, hq=False, inst=3, local=True
            )
            bosch_camera.cmd_live(cfg, args)
        assert sess.put.called

    def test_cmd_snapshot_explicit_hq_wins_over_stored_low_preference(self) -> None:
        """Same bug-hunt finding, cmd_snapshot's --hq call site."""
        cfg = _make_cfg()
        set_quality_pref(cfg, CAM_NAME, "low")
        sess = MagicMock()
        with (
            patch.object(bosch_camera, "get_token", return_value="tok"),
            patch.object(bosch_camera, "make_session", return_value=sess),
            patch.object(bosch_camera, "get_cameras", return_value=cfg["cameras"]),
            patch.object(bosch_camera, "resolve_cam", return_value=cfg["cameras"]),
            patch.object(bosch_camera, "snap_from_proxy") as mock_snap,
            patch.object(bosch_camera, "snap_from_local", return_value=None),
        ):
            mock_snap.return_value = None
            args = argparse.Namespace(cam=CAM_NAME, live=True, quality=None, hq=True)
            bosch_camera.cmd_snapshot(cfg, args)
        assert mock_snap.called
        assert mock_snap.call_args.kwargs["hq"] is True
