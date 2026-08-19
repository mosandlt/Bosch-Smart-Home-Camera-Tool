"""
Regression tests for the patched ``FcmPushClient`` subclass that fixes three
open upstream ``firebase-messaging`` bugs:

  * sdb9696/firebase-messaging#33 — first connectivity error logs a traceback
  * sdb9696/firebase-messaging#37 — unpadded urlsafe-base64 crypto headers
  * sdb9696/firebase-messaging#42 + #44 — blind ``dh=``/``salt=`` header slice

The #42/#44 bug is the severe one: a corrupted crypto-key raises a bare
``ValueError("Invalid EC key.")`` that terminates the whole push client, ending
the watch session silently.

Fake IDs/keys only — NEVER real device values, tokens, or credentials.
PIN_EVERY_MODE: one explicit test per discrete branch.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import json
import ssl
import sys
import types
from enum import Enum
from typing import Any, Iterator
from unittest.mock import MagicMock

import pytest

import bosch_camera


# ─────────────────────────────────────────────────────────────────────────────
# Fake firebase_messaging / http_ece modules
# ─────────────────────────────────────────────────────────────────────────────


class _FakeRunState(Enum):
    STARTED = "STARTED"
    RESETTING = "RESETTING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class _FakeConfig:
    send_selective_acknowledgements = True


class _FakeFcmPushClient:
    """Minimal stand-in mirroring the structural contract _patch_class needs."""

    do_listen = True
    run_state = _FakeRunState.STARTED
    credentials: dict[str, Any] | None = None
    callback: Any = None
    callback_context: Any = None

    def __init__(self) -> None:
        self.persistent_ids: list[str] = []
        self.config = _FakeConfig()
        self.acked: list[str] = []
        self.warns: list[tuple[Any, ...]] = []
        self.verbose: list[tuple[Any, ...]] = []
        self.resets = 0
        self.terminated = False
        self.writer_closed = False
        self.reset_error_counts: list[Any] = []
        self.incremented: list[Any] = []
        self.messages: list[Any] = []
        self.connect_ok = True
        self.increment_returns = True
        self.run_state_at_reset: Any = None

    async def _listen(self) -> None:
        """Required signature: only ``self``."""

    @staticmethod
    def _decrypt_raw_data(
        credentials: Any, crypto_key_str: str, salt_str: str, raw_data: bytes
    ) -> bytes:
        """Required signature: credentials, crypto_key_str, salt_str, raw_data."""
        return b""

    async def _connect_with_retry(self) -> bool:
        return self.connect_ok

    async def _login(self) -> None: ...

    async def _receive_msg(self) -> Any:
        if self.messages:
            return self.messages.pop(0)
        self.do_listen = False
        return None

    async def _handle_message(self, msg: Any) -> None: ...

    async def _do_writer_close(self) -> None:
        self.writer_closed = True

    async def _reset(self) -> None:
        # Mirrors the real _reset(): records the state it was entered with,
        # then hands the loop back to the connected state.
        self.resets += 1
        self.run_state_at_reset = self.run_state
        self.run_state = _FakeRunState.STARTED

    async def _send_selective_ack(self, persistent_id: str) -> None:
        self.acked.append(persistent_id)

    def _terminate(self) -> None:
        self.terminated = True

    def _log_verbose(self, *a: Any, **kw: Any) -> None:
        self.verbose.append(a)

    def _log_warn_with_limit(self, *a: Any, **kw: Any) -> None:
        self.warns.append(a)

    def _try_increment_error_count(self, err_type: Any) -> bool:
        self.incremented.append(err_type)
        return self.increment_returns

    def _reset_error_count(self, err_type: Any) -> None:
        self.reset_error_counts.append(err_type)

    def _app_data_by_key(self, msg: Any, key: str, do_not_raise: bool = False) -> str:
        """Required signature: self, msg, key, do_not_raise=False."""
        for item in msg.app_data:
            if item.key == key:
                return str(item.value)
        if do_not_raise:
            return ""
        raise RuntimeError(f"couldn't find in app_data {key}")

    def _handle_data_message(self, msg: Any) -> None:
        """Required signature: self, msg."""


class _AppDataItem:
    def __init__(self, key: str, value: str) -> None:
        self.key = key
        self.value = value


class _FakeMsg:
    def __init__(self, app_data: list[_AppDataItem], raw_data: bytes = b"raw") -> None:
        self.app_data = app_data
        self.raw_data = raw_data
        self.persistent_id = "fake-persistent-id-0001"
        self.stream_id = 1
        self.last_stream_id_received = 0
        self.status = 0


class _FakeECEException(Exception):
    pass


def _install_firebase(monkeypatch: pytest.MonkeyPatch, cls: type = _FakeFcmPushClient) -> Any:
    """Install a fake ``firebase_messaging`` (+ submodule) in ``sys.modules``."""
    mod = types.ModuleType("firebase_messaging")
    mod.FcmPushClient = cls  # type: ignore[attr-defined]
    mod.FcmPushClientRunState = _FakeRunState  # type: ignore[attr-defined]
    mod.FcmRegisterConfig = MagicMock()  # type: ignore[attr-defined]
    sub = types.ModuleType("firebase_messaging.fcmpushclient")
    sub.ErrorType = types.SimpleNamespace(  # type: ignore[attr-defined]
        CONNECTION="connection", NOTIFY="notify"
    )
    monkeypatch.setitem(sys.modules, "firebase_messaging", mod)
    monkeypatch.setitem(sys.modules, "firebase_messaging.fcmpushclient", sub)
    return mod


def _install_http_ece(monkeypatch: pytest.MonkeyPatch, decrypt: Any = None) -> Any:
    """Install a fake ``http_ece`` module (the real one is an optional dep)."""
    mod = types.ModuleType("http_ece")
    mod.ECEException = _FakeECEException  # type: ignore[attr-defined]
    mod.decrypt = decrypt or (lambda *a, **kw: b'{"ok": true}')  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "http_ece", mod)
    return mod


@pytest.fixture(autouse=True)
def _reset_patch_cache() -> Iterator[None]:
    """Never leak a patched class built against a fake module into other tests."""
    saved = bosch_camera._FCM_PATCHED_CLASS
    bosch_camera._FCM_PATCHED_CLASS = False
    yield
    bosch_camera._FCM_PATCHED_CLASS = saved


# ─────────────────────────────────────────────────────────────────────────────
# _extract_crypto_header — upstream #42 + #44
# ─────────────────────────────────────────────────────────────────────────────


class TestExtractCryptoHeader:
    def test_plain_prefix(self) -> None:
        assert bosch_camera._extract_crypto_header("dh=AAAA", "dh=") == "AAAA"

    def test_salt_prefix(self) -> None:
        assert bosch_camera._extract_crypto_header("salt=BBBB", "salt=") == "BBBB"

    def test_vapid_segment_after_dh(self) -> None:
        """``dh=<key>; p256ecdsa=<vapid>`` — upstream's slice returns both."""
        raw = "dh=AAAA; p256ecdsa=ZZZZ"
        assert bosch_camera._extract_crypto_header(raw, "dh=") == "AAAA"

    def test_vapid_segment_before_dh(self) -> None:
        """``dh=`` need not be the FIRST segment — upstream returns the VAPID key."""
        raw = "p256ecdsa=ZZZZ; dh=AAAA"
        assert bosch_camera._extract_crypto_header(raw, "dh=") == "AAAA"

    def test_comma_separated_element_list(self) -> None:
        """RFC 8188 allows ``,``-separated elements as well as ``;`` params."""
        raw = "keyid=a;rs=4096, dh=AAAA"
        assert bosch_camera._extract_crypto_header(raw, "dh=") == "AAAA"

    def test_case_insensitive_prefix(self) -> None:
        assert bosch_camera._extract_crypto_header("DH=AAAA", "dh=") == "AAAA"
        assert bosch_camera._extract_crypto_header("Salt=BBBB", "salt=") == "BBBB"

    def test_whitespace_around_value_stripped(self) -> None:
        """Leftover whitespace would corrupt the base64 padding math."""
        assert bosch_camera._extract_crypto_header("  dh=  AAAA  ", "dh=") == "AAAA"

    def test_no_match_falls_back_to_stripped_raw(self) -> None:
        """Unexpected shape passes through unmodified rather than being guessed at."""
        assert bosch_camera._extract_crypto_header("  AAAA  ", "dh=") == "AAAA"

    def test_prefix_only_yields_empty(self) -> None:
        assert bosch_camera._extract_crypto_header("dh=", "dh=") == ""


# ─────────────────────────────────────────────────────────────────────────────
# base64 padding helpers — upstream #37
# ─────────────────────────────────────────────────────────────────────────────


class TestPaddingHelpers:
    def test_padded_input_roundtrip(self) -> None:
        raw = b"\x01\x02\x03\x04"
        enc = base64.urlsafe_b64encode(raw).decode()
        assert bosch_camera._urlsafe_b64decode_padded(enc) == raw

    def test_unpadded_input_decodes(self) -> None:
        """Plain ``urlsafe_b64decode`` raises binascii.Error on this input."""
        raw = b"\x01\x02\x03\x04\x05"
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        assert "=" not in enc
        with pytest.raises(binascii.Error):
            base64.urlsafe_b64decode(enc)
        assert bosch_camera._urlsafe_b64decode_padded(enc) == raw

    def test_message_header_non_ascii_becomes_binascii_error(self) -> None:
        """UnicodeEncodeError must normalise to a skippable single-message fault."""
        with pytest.raises(binascii.Error):
            bosch_camera._decode_message_header("AAÿAA")

    def test_credential_material_non_ascii_becomes_value_error(self) -> None:
        """Corrupt STORED credentials must stay a client-wide fault."""
        with pytest.raises(ValueError, match="corrupt stored credential material"):
            bosch_camera._decode_credential_material("AAÿAA")

    def test_credential_material_bad_base64_becomes_value_error(self) -> None:
        with pytest.raises(ValueError, match="corrupt stored credential material"):
            bosch_camera._decode_credential_material("A")

    def test_credential_material_valid_roundtrip(self) -> None:
        raw = b"\x09\x08\x07"
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        assert bosch_camera._decode_credential_material(enc) == raw

    def test_message_header_valid_roundtrip(self) -> None:
        raw = b"\x09\x08\x07"
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        assert bosch_camera._decode_message_header(enc) == raw


# ─────────────────────────────────────────────────────────────────────────────
# _build_fcm_decrypt_override — upstream #37 + the "Invalid EC key." crash
# ─────────────────────────────────────────────────────────────────────────────


_UNCOMPRESSED_POINT_LEN = 65  # 0x04 || X(32) || Y(32) for P-256


class _FakePublicKey:
    def __init__(self, point: bytes) -> None:
        self.point = point


class _FakeEC:
    """Stand-in for ``cryptography...asymmetric.ec`` — the real package is not a
    test dependency of this repo, and the logic under test is our own error
    mapping, not the curve maths."""

    class SECP256R1:
        pass

    class EllipticCurvePublicKey:
        @staticmethod
        def from_encoded_point(curve: Any, data: bytes) -> _FakePublicKey:
            if len(data) != _UNCOMPRESSED_POINT_LEN or data[0] != 0x04:
                raise ValueError("Invalid EC key.")
            return _FakePublicKey(data)


def _install_fake_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the three ``cryptography`` symbols the override imports."""

    def _load_der_private_key(der: bytes, password: Any = None, backend: Any = None) -> str:
        if der == b"corrupt-der":
            raise ValueError("Could not deserialize key data.")
        return "fake-private-key"

    pkgs = {
        "cryptography": {},
        "cryptography.hazmat": {},
        "cryptography.hazmat.backends": {"default_backend": lambda: "fake-backend"},
        "cryptography.hazmat.primitives": {},
        "cryptography.hazmat.primitives.asymmetric": {"ec": _FakeEC},
        "cryptography.hazmat.primitives.serialization": {
            "load_der_private_key": _load_der_private_key
        },
    }
    for name, attrs in pkgs.items():
        mod = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        monkeypatch.setitem(sys.modules, name, mod)


def _b64u(raw: bytes) -> str:
    """Unpadded urlsafe base64, exactly as these fields arrive on the wire."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _fake_credentials(private: bytes = b"fake-der-key") -> dict[str, dict[str, str]]:
    """Fake credential material only — NEVER real stored keys."""
    return {
        "keys": {
            "private": _b64u(private),
            "secret": _b64u(b"0123456789abcdef"),
        }
    }


def _valid_crypto_key_header() -> str:
    """An unpadded urlsafe-base64 uncompressed P-256 point, as sent on the wire."""
    return _b64u(b"\x04" + bytes(range(64)))


class TestBuildDecryptOverride:
    def test_http_ece_missing_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "http_ece", None)
        override, skips = bosch_camera._build_fcm_decrypt_override(_FakeFcmPushClient)
        assert override is None
        assert skips == (binascii.Error,)

    def test_cryptography_missing_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_http_ece(monkeypatch)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.backends", None)
        override, skips = bosch_camera._build_fcm_decrypt_override(_FakeFcmPushClient)
        assert override is None
        assert skips == (binascii.Error, _FakeECEException)

    def test_signature_change_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_http_ece(monkeypatch)
        _install_fake_cryptography(monkeypatch)

        class _Changed(_FakeFcmPushClient):
            @staticmethod
            def _decrypt_raw_data(  # type: ignore[override]
                credentials: Any,
                crypto_key_str: str,
                salt_str: str,
                raw_data: bytes,
                extra: int = 0,
            ) -> bytes:
                return b""

        override, skips = bosch_camera._build_fcm_decrypt_override(_Changed)
        assert override is None
        assert skips == (binascii.Error, _FakeECEException)

    def test_missing_method_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_http_ece(monkeypatch)
        _install_fake_cryptography(monkeypatch)

        class _NoMethod:
            pass

        override, _ = bosch_camera._build_fcm_decrypt_override(_NoMethod)
        assert override is None

    def _override(self, monkeypatch: pytest.MonkeyPatch, decrypt: Any = None) -> Any:
        _install_http_ece(monkeypatch, decrypt=decrypt)
        _install_fake_cryptography(monkeypatch)
        override, skips = bosch_camera._build_fcm_decrypt_override(_FakeFcmPushClient)
        assert override is not None
        return override, skips

    def test_decrypts_unpadded_headers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The #37 regression: these headers arrive WITHOUT base64 padding."""
        seen: dict[str, Any] = {}

        def _decrypt(raw_data: bytes, **kw: Any) -> bytes:
            seen.update(kw)
            seen["raw_data"] = raw_data
            return b'{"ok": true}'

        override, _ = self._override(monkeypatch, decrypt=_decrypt)

        crypto_key = _valid_crypto_key_header()
        assert "=" not in crypto_key
        with pytest.raises(binascii.Error):
            base64.urlsafe_b64decode(crypto_key)  # what upstream does — and fails on

        out = override(_fake_credentials(), crypto_key, _b64u(b"0123456789abcdef"), b"body")
        assert out == b'{"ok": true}'
        assert seen["raw_data"] == b"body"
        assert seen["version"] == "aesgcm"
        assert seen["salt"] == b"0123456789abcdef"
        assert seen["auth_secret"] == b"0123456789abcdef"
        assert seen["private_key"] == "fake-private-key"
        assert seen["dh"].point == b"\x04" + bytes(range(64))

    def test_invalid_ec_point_becomes_eceexception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The #42/#44 crash: a corrupted key must be skippable, not fatal."""
        override, skips = self._override(monkeypatch)

        bad_key = _b64u(b"\x04" + b"\x00" * 8)  # right prefix, wrong length
        with pytest.raises(_FakeECEException, match="Invalid EC key."):
            override(_fake_credentials(), bad_key, _b64u(b"0123456789abcdef"), b"body")
        # …and it is in the skip list, so _listen() skips just this message.
        assert _FakeECEException in skips

    def test_corrupt_stored_key_stays_value_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Corrupt OWN credentials must NOT be masked as a skippable message."""
        override, skips = self._override(monkeypatch)

        creds = _fake_credentials(private=b"corrupt-der")
        with pytest.raises(ValueError) as exc:
            override(creds, _valid_crypto_key_header(), _b64u(b"0123456789abcdef"), b"body")
        assert not isinstance(exc.value, skips)

    def test_undecodable_stored_key_stays_value_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        override, skips = self._override(monkeypatch)

        creds = _fake_credentials()
        creds["keys"]["private"] = "A"  # not a decodable base64 length
        with pytest.raises(ValueError, match="corrupt stored credential material"):
            override(creds, _valid_crypto_key_header(), _b64u(b"0123456789abcdef"), b"body")
        assert binascii.Error in skips  # but a bad *header* still is skippable

    def test_undecodable_header_is_skippable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        override, skips = self._override(monkeypatch)
        with pytest.raises(binascii.Error):
            override(_fake_credentials(), "A", _b64u(b"0123456789abcdef"), b"body")
        assert binascii.Error in skips


# ─────────────────────────────────────────────────────────────────────────────
# _build_fcm_handle_data_message_override — upstream #42 + #44
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildHandleDataMessageOverride:
    def test_missing_handler_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_firebase(monkeypatch)

        class _NoHandler:
            pass

        assert bosch_camera._build_fcm_handle_data_message_override(_NoHandler) is None

    def test_signature_change_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_firebase(monkeypatch)

        class _Changed(_FakeFcmPushClient):
            def _handle_data_message(self, msg: Any, extra: int = 0) -> None:  # type: ignore[override]
                pass

        assert bosch_camera._build_fcm_handle_data_message_override(_Changed) is None

    def test_coroutine_handler_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A sync override under an awaiting caller would TypeError on message 1."""
        _install_firebase(monkeypatch)

        class _Async(_FakeFcmPushClient):
            async def _handle_data_message(self, msg: Any) -> None:  # type: ignore[override]
                pass

        assert bosch_camera._build_fcm_handle_data_message_override(_Async) is None

    def test_missing_helper_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A renamed *helper* must also degrade — the body calls six of them."""
        _install_firebase(monkeypatch)

        class _NoHelper(_FakeFcmPushClient):
            _app_data_by_key = None  # type: ignore[assignment]

        assert bosch_camera._build_fcm_handle_data_message_override(_NoHelper) is None

    def test_errortype_unavailable_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_firebase(monkeypatch)
        monkeypatch.setitem(sys.modules, "firebase_messaging.fcmpushclient", None)
        assert bosch_camera._build_fcm_handle_data_message_override(_FakeFcmPushClient) is None

    def test_handler_defined_when_contract_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_firebase(monkeypatch)
        override = bosch_camera._build_fcm_handle_data_message_override(_FakeFcmPushClient)
        assert override is not None
        assert list(inspect.signature(override).parameters) == ["self", "msg"]


# ─────────────────────────────────────────────────────────────────────────────
# The patched _handle_data_message body
# ─────────────────────────────────────────────────────────────────────────────


class _Client(_FakeFcmPushClient):
    """Fake client wired up so the override's body can run end to end."""

    def __init__(self) -> None:
        super().__init__()
        self.credentials = {"gcm": {"app_id": "fake-app-id"}}
        self.decrypt_args: tuple[Any, ...] = ()
        self.decrypted: bytes = json.dumps({"hello": "world"}).encode()
        self.notified: list[Any] = []
        self.callback = lambda payload, pid, ctx: self.notified.append(payload)

    def _decrypt_raw_data(  # type: ignore[override]
        self, credentials: Any, crypto_key: str, salt: str, raw_data: bytes
    ) -> bytes:
        self.decrypt_args = (credentials, crypto_key, salt, raw_data)
        return self.decrypted


def _msg(crypto_key: str, encryption: str, subtype: str = "fake-app-id") -> _FakeMsg:
    return _FakeMsg(
        [
            _AppDataItem("crypto-key", crypto_key),
            _AppDataItem("encryption", encryption),
            _AppDataItem("subtype", subtype),
        ]
    )


class TestPatchedHandleDataMessage:
    def _override(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        _install_firebase(monkeypatch)
        override = bosch_camera._build_fcm_handle_data_message_override(_FakeFcmPushClient)
        assert override is not None
        return override

    def test_multi_segment_header_extracted_correctly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The regression: upstream's slice would hand ``AAAA; p256ecdsa=ZZZZ`` on."""
        override = self._override(monkeypatch)
        client = _Client()
        override(client, _msg("dh=AAAA; p256ecdsa=ZZZZ", "salt=BBBB; rs=4096"))
        assert client.decrypt_args[1] == "AAAA"
        assert client.decrypt_args[2] == "BBBB"

    def test_simple_header_matches_upstream_behaviour(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        override = self._override(monkeypatch)
        client = _Client()
        override(client, _msg("dh=AAAA", "salt=BBBB"))
        assert client.decrypt_args[1] == "AAAA"
        assert client.decrypt_args[2] == "BBBB"

    def test_callback_receives_decoded_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        override = self._override(monkeypatch)
        client = _Client()
        override(client, _msg("dh=AAAA", "salt=BBBB"))
        assert client.notified == [{"hello": "world"}]
        assert client.reset_error_counts == ["notify"]

    def test_deleted_messages_short_circuit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        override = self._override(monkeypatch)
        client = _Client()
        msg = _FakeMsg([_AppDataItem("message_type", "deleted_messages")])
        override(client, msg)
        assert client.decrypt_args == ()

    def test_subtype_mismatch_warns_but_continues(self, monkeypatch: pytest.MonkeyPatch) -> None:
        override = self._override(monkeypatch)
        client = _Client()
        override(client, _msg("dh=AAAA", "salt=BBBB", subtype="other-app-id"))
        assert client.warns
        assert client.notified

    def test_undecodable_payload_warns_and_wraps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        override = self._override(monkeypatch)
        client = _Client()
        client.decrypted = b"\xff\xfe not json"
        override(client, _msg("dh=AAAA", "salt=BBBB"))
        assert any("Failed to decrypt" in str(w[0]) for w in client.warns)
        assert client.notified == [{"message": b"\xff\xfe not json"}]

    def test_non_dict_json_is_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        override = self._override(monkeypatch)
        client = _Client()
        client.decrypted = b'"a string"'
        override(client, _msg("dh=AAAA", "salt=BBBB"))
        assert client.notified == [{"message": "a string"}]

    def test_callback_exception_counted_not_raised(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        override = self._override(monkeypatch)
        client = _Client()

        def _boom(*a: Any) -> None:
            raise RuntimeError("callback boom")

        client.callback = _boom
        override(client, _msg("dh=AAAA", "salt=BBBB"))
        assert client.incremented == ["notify"]
        assert "callback boom" in capsys.readouterr().err

    def test_missing_crypto_key_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_listen()'s RuntimeError branch depends on this exact message."""
        override = self._override(monkeypatch)
        client = _Client()
        with pytest.raises(RuntimeError, match="couldn't find in app_data"):
            override(client, _FakeMsg([_AppDataItem("subtype", "fake-app-id")]))


# ─────────────────────────────────────────────────────────────────────────────
# _patch_fcm_push_client_class / _get_fcm_push_client_class
# ─────────────────────────────────────────────────────────────────────────────


class TestPatchClassCreation:
    def test_library_missing_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "firebase_messaging", None)
        assert bosch_camera._patch_fcm_push_client_class() is None

    def test_listen_missing_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _NoListen:
            pass

        _install_firebase(monkeypatch, cls=_NoListen)
        assert bosch_camera._patch_fcm_push_client_class() is None

    def test_listen_signature_change_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Changed(_FakeFcmPushClient):
            async def _listen(self, extra: int = 0) -> None:  # type: ignore[override]
                pass

        _install_firebase(monkeypatch, cls=_Changed)
        assert bosch_camera._patch_fcm_push_client_class() is None

    def test_creates_subclass_with_all_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_firebase(monkeypatch)
        _install_http_ece(monkeypatch)
        _install_fake_cryptography(monkeypatch)
        patched = bosch_camera._patch_fcm_push_client_class()
        assert patched is not None
        assert issubclass(patched, _FakeFcmPushClient)
        assert patched._listen is not _FakeFcmPushClient._listen
        assert patched._decrypt_raw_data is not _FakeFcmPushClient._decrypt_raw_data
        assert patched._handle_data_message is not _FakeFcmPushClient._handle_data_message

    def test_decrypt_override_failure_does_not_gate_listen_fix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each fix degrades independently — #37 off must not disable #33."""
        _install_firebase(monkeypatch)
        monkeypatch.setitem(sys.modules, "http_ece", None)
        patched = bosch_camera._patch_fcm_push_client_class()
        assert patched is not None
        assert patched._listen is not _FakeFcmPushClient._listen
        assert patched._decrypt_raw_data is _FakeFcmPushClient._decrypt_raw_data


class TestGetFcmPushClientClass:
    def test_returns_patched_class_and_caches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_firebase(monkeypatch)
        _install_http_ece(monkeypatch)
        _install_fake_cryptography(monkeypatch)
        first = bosch_camera._get_fcm_push_client_class()
        assert first is not None and issubclass(first, _FakeFcmPushClient)
        assert bosch_camera._get_fcm_push_client_class() is first

    def test_falls_back_to_vanilla_when_unpatchable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _NoListen:
            pass

        _install_firebase(monkeypatch, cls=_NoListen)
        assert bosch_camera._get_fcm_push_client_class() is _NoListen

    def test_returns_none_without_library(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "firebase_messaging", None)
        assert bosch_camera._get_fcm_push_client_class() is None


# ─────────────────────────────────────────────────────────────────────────────
# The patched _listen body — upstream #33 + per-message skip handling
# ─────────────────────────────────────────────────────────────────────────────


def _patched_client(monkeypatch: pytest.MonkeyPatch) -> Any:
    _install_firebase(monkeypatch)
    _install_http_ece(monkeypatch)
    _install_fake_cryptography(monkeypatch)
    patched = bosch_camera._patch_fcm_push_client_class()
    assert patched is not None
    return patched()


class TestPatchedListen:
    def test_connect_failure_returns_early(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)
        client.connect_ok = False
        asyncio.run(client._listen())
        assert client.writer_closed is False

    def test_clean_exit_closes_writer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)
        asyncio.run(client._listen())
        assert client.writer_closed is True

    def test_undecryptable_message_skipped_and_acked(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The crash regression: one bad message must not terminate the client."""
        client = _patched_client(monkeypatch)
        client.messages = [_FakeMsg([])]

        async def _boom(msg: Any) -> None:
            raise binascii.Error("bad padding")

        client._handle_message = _boom
        asyncio.run(client._listen())
        assert client.terminated is False
        assert client.acked == ["fake-persistent-id-0001"]
        assert client.persistent_ids == ["fake-persistent-id-0001"]
        assert "Skipping undecryptable" in capsys.readouterr().err

    def test_ece_exception_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)
        client.messages = [_FakeMsg([])]

        async def _boom(msg: Any) -> None:
            raise _FakeECEException("Invalid EC key.")

        client._handle_message = _boom
        asyncio.run(client._listen())
        assert client.terminated is False
        assert client.acked == ["fake-persistent-id-0001"]

    def test_missing_app_data_runtime_error_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)
        client.messages = [_FakeMsg([])]

        async def _boom(msg: Any) -> None:
            raise RuntimeError("couldn't find in app_data crypto-key")

        client._handle_message = _boom
        asyncio.run(client._listen())
        assert client.terminated is False
        assert client.acked == ["fake-persistent-id-0001"]

    def test_unrelated_runtime_error_terminates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only the app_data shape is single-message scoped — others must propagate."""
        client = _patched_client(monkeypatch)
        client.messages = [_FakeMsg([])]

        async def _boom(msg: Any) -> None:
            raise RuntimeError("writer is closed")

        client._handle_message = _boom
        asyncio.run(client._listen())
        assert client.terminated is True

    def test_corrupt_credentials_value_error_terminates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A client-wide fault must NOT be masked as a skippable message."""
        client = _patched_client(monkeypatch)
        client.messages = [_FakeMsg([])]

        async def _boom(msg: Any) -> None:
            raise ValueError("corrupt stored credential material: nope")

        client._handle_message = _boom
        asyncio.run(client._listen())
        assert client.terminated is True

    def test_empty_persistent_id_not_acked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The protobuf field defaults to ``""`` — never ack a meaningless id."""
        client = _patched_client(monkeypatch)
        msg = _FakeMsg([])
        msg.persistent_id = ""
        client.messages = [msg]

        async def _boom(m: Any) -> None:
            raise binascii.Error("bad padding")

        client._handle_message = _boom
        asyncio.run(client._listen())
        assert client.acked == []
        assert client.persistent_ids == []

    def test_first_connection_error_is_quiet_and_resets(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Upstream #33: the FIRST error used to log a full traceback."""
        client = _patched_client(monkeypatch)
        calls = {"n": 0}

        async def _recv() -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionResetError("peer reset")
            client.do_listen = False
            return None

        client._receive_msg = _recv
        asyncio.run(client._listen())
        err = capsys.readouterr().err
        assert "FCM read error" not in err
        assert client.verbose
        # The quiet branch must still reconnect (else _listen spins forever).
        assert client.resets == 1
        assert client.run_state_at_reset is _FakeRunState.RESETTING

    def test_unexpected_ssl_reason_warns_with_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)
        calls = {"n": 0}

        async def _recv() -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                exc = ssl.SSLError("boom")
                exc.reason = "SOME_OTHER_REASON"
                raise exc
            client.do_listen = False
            return None

        client._receive_msg = _recv
        asyncio.run(client._listen())
        assert client.warns

    def test_unexpected_os_error_logged_loudly(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = _patched_client(monkeypatch)
        calls = {"n": 0}

        async def _recv() -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("disk on fire")
            client.do_listen = False
            return None

        client._receive_msg = _recv
        asyncio.run(client._listen())
        assert "FCM read error" in capsys.readouterr().err

    def test_error_count_not_incremented_skips_reset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)

        def _no_increment(err_type: Any) -> bool:
            # Nothing else would end the loop: without a _reset() the run_state
            # stays RESETTING, so stop listening here.
            client.do_listen = False
            return False

        client._try_increment_error_count = _no_increment

        async def _recv() -> Any:
            raise ConnectionResetError("peer reset")

        client._receive_msg = _recv
        asyncio.run(client._listen())
        assert client.resets == 0

    def test_errortype_import_failure_still_resets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _patched_client(monkeypatch)
        monkeypatch.setitem(sys.modules, "firebase_messaging.fcmpushclient", None)
        calls = {"n": 0}

        async def _recv() -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionResetError("peer reset")
            client.do_listen = False
            return None

        client._receive_msg = _recv
        asyncio.run(client._listen())
        assert client.resets == 1

    def test_resetting_state_sleeps_instead_of_receiving(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _patched_client(monkeypatch)
        client.run_state = _FakeRunState.RESETTING
        sleeps = {"n": 0}
        real_sleep = asyncio.sleep

        async def _sleep(secs: float) -> None:
            sleeps["n"] += 1
            client.do_listen = False
            await real_sleep(0)

        monkeypatch.setattr(asyncio, "sleep", _sleep)
        asyncio.run(client._listen())
        assert sleeps["n"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# _watch_fcm_push wiring
# ─────────────────────────────────────────────────────────────────────────────


class TestWatchUsesPatchedClass:
    def test_watch_instantiates_patched_class(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_watch_fcm_push must build the client from the PATCHED class."""
        used: dict[str, Any] = {}

        class _Recording:
            def __init__(self, **kw: Any) -> None:
                used["cls"] = type(self)

            async def checkin_or_register(self) -> str:
                return "fake-fcm-token"

            async def start(self) -> None:
                bosch_camera._STOP_REQUESTED.set()

            async def stop(self) -> None: ...

        mod = types.ModuleType("firebase_messaging")
        mod.FcmPushClient = MagicMock()  # type: ignore[attr-defined]
        mod.FcmRegisterConfig = MagicMock()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "firebase_messaging", mod)
        monkeypatch.setattr(bosch_camera, "_get_fcm_push_client_class", lambda: _Recording)
        monkeypatch.setattr(bosch_camera, "make_session", lambda tok: MagicMock())
        monkeypatch.setattr(bosch_camera, "api_get_events", lambda *a, **kw: [])
        monkeypatch.setattr(
            bosch_camera,
            "requests_post_bosch_cloud",
            lambda *a, **kw: types.SimpleNamespace(status_code=200),
        )
        bosch_camera._STOP_REQUESTED.clear()
        try:
            bosch_camera._watch_fcm_push(
                {"account": {"bearer_token": "fake-token"}, "settings": {}},
                "fake-token",
                {"FakeCam": {"id": "11111111-2222-3333-4444-555555555555"}},
                duration=0,
                auto_snap=False,
            )
        finally:
            bosch_camera._STOP_REQUESTED.clear()
        assert used["cls"] is _Recording
        mod.FcmPushClient.assert_not_called()  # type: ignore[attr-defined]

    def test_watch_falls_back_when_class_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A None from the resolver must still leave the vanilla class usable."""
        constructed: list[Any] = []

        class _Vanilla:
            def __init__(self, **kw: Any) -> None:
                constructed.append(kw)

            async def checkin_or_register(self) -> str:
                return "fake-fcm-token"

            async def start(self) -> None:
                bosch_camera._STOP_REQUESTED.set()

            async def stop(self) -> None: ...

        mod = types.ModuleType("firebase_messaging")
        mod.FcmPushClient = _Vanilla  # type: ignore[attr-defined]
        mod.FcmRegisterConfig = MagicMock()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "firebase_messaging", mod)
        monkeypatch.setattr(bosch_camera, "_get_fcm_push_client_class", lambda: None)
        monkeypatch.setattr(bosch_camera, "make_session", lambda tok: MagicMock())
        monkeypatch.setattr(bosch_camera, "api_get_events", lambda *a, **kw: [])
        monkeypatch.setattr(
            bosch_camera,
            "requests_post_bosch_cloud",
            lambda *a, **kw: types.SimpleNamespace(status_code=500),
        )
        bosch_camera._STOP_REQUESTED.clear()
        try:
            bosch_camera._watch_fcm_push(
                {"account": {"bearer_token": "fake-token"}, "settings": {}},
                "fake-token",
                {"FakeCam": {"id": "11111111-2222-3333-4444-555555555555"}},
                duration=0,
                auto_snap=False,
            )
        finally:
            bosch_camera._STOP_REQUESTED.clear()
        assert len(constructed) == 1


def test_fcm_patch_note_writes_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    bosch_camera._fcm_patch_note("something changed")
    assert "FCM patch: something changed" in capsys.readouterr().err
