"""
Tests for cmd_lighting — Gen2 lighting/LED tuning surface (white balance,
lens elevation, darkness threshold, soft light fading, top/bottom LED
brightness, power LED brightness, motion light sensitivity, status LED).

Cross-ported from the HA integration's number.py/switch.py (2026-08
family-parity work). PIN_EVERY_MODE: every flag pinned happy-path + at
least one error path; the "show everything" no-flag path is pinned too.

API shapes (from HA's real GET/PUT request bodies — see number.py/switch.py):
  GET/PUT /v11/video_inputs/{id}/lighting/switch
    {"frontLightSettings": {...}, "topLedLightSettings": {...},
     "bottomLedLightSettings": {...}}
  GET/PUT /v11/video_inputs/{id}/lens_elevation      {"elevation": float}
  GET/PUT /v11/video_inputs/{id}/lighting            {"darknessThreshold": float, "softLightFading": bool}
  GET/PUT /v11/video_inputs/{id}/lighting/motion     {..., "motionLightSensitivity": int}
  GET/PUT /v11/video_inputs/{id}/iconLedBrightness   {"value": int}
  GET/PUT /v11/video_inputs/{id}/ledlights           {"state": "ON"/"OFF"}
Fake IDs only — NEVER real device values, IPs, tokens, or secrets.
"""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import MagicMock, patch

import bosch_camera
from bosch_camera import cmd_lighting

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


def _args(**kwargs: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "cam": CAM_NAME,
        "white_balance": None,
        "lens_elevation": None,
        "darkness_threshold": None,
        "soft_light_fading": None,
        "top_led_brightness": None,
        "bottom_led_brightness": None,
        "power_led_brightness": None,
        "motion_light_sensitivity": None,
        "status_led": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _patched(sess: MagicMock, cfg: dict[str, Any]) -> Any:
    return (
        patch.object(bosch_camera, "get_token", return_value="tok"),
        patch.object(bosch_camera, "make_session", return_value=sess),
        patch.object(bosch_camera, "get_cameras", return_value=cfg["cameras"]),
    )


class TestWhiteBalance:
    def test_set_white_balance_ok(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "frontLightSettings": {"brightness": 0, "color": None, "whiteBalance": 0.0},
                "topLedLightSettings": {"brightness": 0, "color": None, "whiteBalance": 0.0},
                "bottomLedLightSettings": {"brightness": 0, "color": None, "whiteBalance": 0.0},
            },
        )
        sess.put.return_value = MagicMock(status_code=204)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(white_balance=0.5))
        out = capsys.readouterr().out
        assert "White balance set to 0.5" in out
        body = sess.put.call_args.kwargs["json"]
        assert body["frontLightSettings"]["whiteBalance"] == 0.5
        assert "topLedLightSettings" in body and "bottomLedLightSettings" in body

    def test_white_balance_get_fails(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=442, json=lambda: {})
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(white_balance=0.5))
        out = capsys.readouterr().out
        assert "not supported" in out.lower()
        sess.put.assert_not_called()


class TestLedBrightness:
    def test_top_and_bottom_brightness_combined(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "frontLightSettings": {"brightness": 0, "color": None, "whiteBalance": 0.0},
                "topLedLightSettings": {"brightness": 10, "color": None, "whiteBalance": 0.0},
                "bottomLedLightSettings": {"brightness": 20, "color": None, "whiteBalance": 0.0},
            },
        )
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(top_led_brightness=75, bottom_led_brightness=25))
        out = capsys.readouterr().out
        assert "Top LED brightness set to 75%" in out
        assert "Bottom LED brightness set to 25%" in out
        body = sess.put.call_args.kwargs["json"]
        assert body["topLedLightSettings"]["brightness"] == 75
        assert body["bottomLedLightSettings"]["brightness"] == 25

    def test_led_brightness_put_fails(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "frontLightSettings": {},
                "topLedLightSettings": {},
                "bottomLedLightSettings": {},
            },
        )
        sess.put.return_value = MagicMock(status_code=500, text="err")
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(top_led_brightness=50))
        out = capsys.readouterr().out
        assert "PUT failed" in out


class TestLensElevation:
    def test_set_lens_elevation_ok(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(lens_elevation=2.5))
        out = capsys.readouterr().out
        assert "Lens elevation set to 2.5m" in out
        assert sess.put.call_args.kwargs["json"] == {"elevation": 2.5}

    def test_lens_elevation_camera_offline(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=444)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(lens_elevation=2.5))
        out = capsys.readouterr().out
        assert "offline" in out.lower()


class TestDarknessThresholdAndFading:
    def test_set_darkness_threshold_preserves_fading(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200, json=lambda: {"darknessThreshold": 0.2, "softLightFading": True}
        )
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(darkness_threshold=40))
        out = capsys.readouterr().out
        assert "Darkness threshold set to 40%" in out
        body = sess.put.call_args.kwargs["json"]
        assert body["darknessThreshold"] == 0.4
        assert body["softLightFading"] is True

    def test_set_soft_light_fading_off(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200, json=lambda: {"darknessThreshold": 0.5, "softLightFading": True}
        )
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(soft_light_fading="off"))
        out = capsys.readouterr().out
        assert "Soft light fading set to OFF" in out
        body = sess.put.call_args.kwargs["json"]
        assert body["softLightFading"] is False
        assert body["darknessThreshold"] == 0.5

    def test_darkness_threshold_get_fails(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=401, json=lambda: {})
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(darkness_threshold=10))
        out = capsys.readouterr().out
        assert "Token expired" in out
        sess.put.assert_not_called()


class TestMotionLightSensitivity:
    def test_set_motion_sensitivity_ok(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"lightOnMotionEnabled": True, "motionLightSensitivity": 2},
        )
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(motion_light_sensitivity=4))
        out = capsys.readouterr().out
        assert "Motion light sensitivity set to 4" in out
        body = sess.put.call_args.kwargs["json"]
        assert body["motionLightSensitivity"] == 4
        assert body["lightOnMotionEnabled"] is True  # rest of the body preserved

    def test_motion_sensitivity_put_fails(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"lightOnMotionEnabled": True, "motionLightSensitivity": 1},
        )
        sess.put.return_value = MagicMock(status_code=500, text="err")
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(motion_light_sensitivity=3))
        out = capsys.readouterr().out
        assert "PUT failed" in out

    def test_motion_sensitivity_empty_get_aborts_write(self, capsys: Any) -> None:
        """Bug-hunt regression: GET returning an empty dict used to still send
        a PUT with only motionLightSensitivity set, silently clobbering the
        sibling lightOnMotionEnabled field (this is a full-object PUT, not a
        partial patch). Must abort the write instead, mirroring the HA
        integration's number.py `if not cache: return` guard."""
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=200, json=lambda: {})
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(motion_light_sensitivity=3))
        out = capsys.readouterr().out
        assert "refusing to write" in out
        assert "clobber" in out
        sess.put.assert_not_called()

    def test_motion_sensitivity_non_dict_get_aborts_write(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=200, json=lambda: None)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(motion_light_sensitivity=3))
        out = capsys.readouterr().out
        assert "refusing to write" in out
        sess.put.assert_not_called()


class TestPowerLedBrightness:
    def test_set_power_led_brightness_clamped(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(power_led_brightness=9))  # clamp to 4
        out = capsys.readouterr().out
        assert "Power LED brightness set to 4" in out
        assert sess.put.call_args.kwargs["json"] == {"value": 4}

    def test_power_led_brightness_not_supported(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=442)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(power_led_brightness=2))
        out = capsys.readouterr().out
        assert "not supported" in out.lower()


class TestStatusLed:
    def test_status_led_on(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(status_led="on"))
        out = capsys.readouterr().out
        assert "Status LED set to ON" in out
        assert sess.put.call_args.kwargs["json"] == {"state": "ON"}

    def test_status_led_off_generic_error(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=400)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(status_led="off"))
        out = capsys.readouterr().out
        assert "PUT failed" in out
        assert "HTTP 400" in out


class TestShowAll:
    def test_no_flags_shows_all_endpoints(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        sess.get.return_value = MagicMock(status_code=200, json=lambda: {"some": "value"})
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args())
        out = capsys.readouterr().out
        assert "Lighting (front/top/bottom LEDs)" in out
        assert "Lens elevation" in out
        assert "Status LED" in out
        sess.put.assert_not_called()


class TestRangeValidation:
    """Bug-hunt regression: numeric flags had no client-side range
    validation — Bosch's API would reject/confusingly error on an
    out-of-range value instead of a clear local error message. Mirrors HA's
    NumberEntity min/max definitions (see docstring). One test per bound per
    flag (PIN_EVERY_MODE)."""

    def test_white_balance_above_max_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(white_balance=1.5))
        out = capsys.readouterr().out
        assert "--white-balance must be between -1.0 and 1.0" in out
        sess.get.assert_not_called()
        sess.put.assert_not_called()

    def test_white_balance_below_min_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(white_balance=-1.5))
        out = capsys.readouterr().out
        assert "--white-balance must be between -1.0 and 1.0" in out
        sess.put.assert_not_called()

    def test_lens_elevation_below_min_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(lens_elevation=0.1))
        out = capsys.readouterr().out
        assert "--lens-elevation must be between 0.5 and 5.0" in out
        sess.put.assert_not_called()

    def test_lens_elevation_above_max_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(lens_elevation=6.0))
        out = capsys.readouterr().out
        assert "--lens-elevation must be between 0.5 and 5.0" in out
        sess.put.assert_not_called()

    def test_darkness_threshold_above_max_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(darkness_threshold=150))
        out = capsys.readouterr().out
        assert "--darkness-threshold must be between 0 and 100" in out
        sess.put.assert_not_called()

    def test_darkness_threshold_below_min_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(darkness_threshold=-10))
        out = capsys.readouterr().out
        assert "--darkness-threshold must be between 0 and 100" in out
        sess.put.assert_not_called()

    def test_top_led_brightness_above_max_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(top_led_brightness=120))
        out = capsys.readouterr().out
        assert "--top-led-brightness must be between 0 and 100" in out
        sess.put.assert_not_called()

    def test_bottom_led_brightness_below_min_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(bottom_led_brightness=-5))
        out = capsys.readouterr().out
        assert "--bottom-led-brightness must be between 0 and 100" in out
        sess.put.assert_not_called()

    def test_motion_light_sensitivity_above_max_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(motion_light_sensitivity=6))
        out = capsys.readouterr().out
        assert "--motion-light-sensitivity must be between 1 and 5" in out
        sess.put.assert_not_called()

    def test_motion_light_sensitivity_below_min_rejected(self, capsys: Any) -> None:
        cfg = _make_cfg()
        sess = MagicMock()
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(motion_light_sensitivity=0))
        out = capsys.readouterr().out
        assert "--motion-light-sensitivity must be between 1 and 5" in out
        sess.put.assert_not_called()

    def test_boundary_values_accepted(self, capsys: Any) -> None:
        """Exact boundary values (inclusive range) must not be rejected."""
        cfg = _make_cfg()
        sess = MagicMock()
        sess.put.return_value = MagicMock(status_code=200)
        p1, p2, p3 = _patched(sess, cfg)
        with p1, p2, p3:
            cmd_lighting(cfg, _args(lens_elevation=0.5))
        out = capsys.readouterr().out
        assert "must be between" not in out
        assert "Lens elevation set to 0.5m" in out
