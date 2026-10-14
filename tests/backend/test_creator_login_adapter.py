from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_creator_phone_code_does_not_retry_http_406(monkeypatch):
    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    attempts = []

    class FakeCreatorLoginApi:
        def __init__(self):
            self.session_number = len(attempts) + 1
            attempts.append(self.session_number)

        def _prepare_login_session(self):
            return {"a1": f"anonymous-session-{self.session_number}"}, {"active": False}

        def _complete_security(self):
            pass

        @property
        def profile(self):
            class FakeProfile:
                cookie_map = {"a1": "prepared-session"}

            return FakeProfile()

        def send_phone_code(self, phone, cookies):
            assert phone == "redacted-test-value"
            assert cookies == {"a1": "prepared-session"}
            return False, "HTTP 406: request rejected", {}

        def close(self):
            pass

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)

    try:
        XhsCreatorLoginAdapter().create_phone_session("redacted-test-value")
    except RuntimeError as exc:
        assert "HTTP 406" in str(exc)
    else:
        raise AssertionError("HTTP 406 must stop without a fresh-device retry")

    assert attempts == [1]


def test_creator_phone_code_uses_creator_login_preflight_before_sending(monkeypatch):
    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    calls = []

    class FakeCreatorLoginApi:
        def _prepare_login_session(self):
            calls.append("preflight")
            return {"a1": "anonymous-session"}, {"active": False}

        def _complete_security(self):
            calls.append("security")

        @property
        def profile(self):
            class FakeProfile:
                cookie_map = {"a1": "prepared-session"}

            return FakeProfile()

        def send_phone_code(self, phone, cookies):
            calls.append("send")
            assert phone == "redacted-test-value"
            assert cookies == {"a1": "prepared-session"}
            return True, "sent", {}

        def close(self):
            calls.append("close")

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)

    result = XhsCreatorLoginAdapter().create_phone_session("redacted-test-value")

    assert calls == ["preflight", "security", "send"]
    assert result == {"cookies": {"a1": "prepared-session"}, "message": "sent"}


def test_creator_phone_confirmation_reuses_the_client_that_sent_the_code(monkeypatch):
    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    clients = []

    class FakeCreatorLoginApi:
        def __init__(self):
            self.closed = False
            clients.append(self)

        def _prepare_login_session(self):
            return {"a1": "same-device"}, {"active": False}

        def _complete_security(self):
            pass

        @property
        def profile(self):
            class FakeProfile:
                cookie_map = {"a1": "same-device"}

            return FakeProfile()

        def send_phone_code(self, phone, cookies):
            assert phone == "redacted-test-value"
            assert cookies == {"a1": "same-device"}
            assert not self.closed
            return True, "sent", {}

        def login_by_phone(self, phone, code, cookies):
            assert phone == "redacted-test-value"
            assert code == "test-code"
            assert cookies == {"a1": "same-device"}
            assert not self.closed
            return True, "成功", {"cookies": {"a1": "same-device", "web_session": "test-session"}}

        def get_user_info(self, cookies):
            assert not self.closed
            assert cookies["web_session"] == "test-session"
            return True, {"userId": "test-user", "userName": "test"}, cookies

        def close(self):
            self.closed = True

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)
    adapter = XhsCreatorLoginAdapter()

    sent = adapter.create_phone_session("redacted-test-value")
    assert not clients[0].closed
    confirmed = adapter.confirm_phone_login(
        "redacted-test-value", "test-code", sent["cookies"]
    )

    assert len(clients) == 1
    assert clients[0].closed
    assert confirmed["status"] == "confirmed"
    assert confirmed["user_info"]["external_user_id"] == "test-user"


def test_creator_phone_wrong_code_keeps_the_session_for_correction(monkeypatch):
    import pytest

    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    clients = []

    class FakeCreatorLoginApi:
        def __init__(self):
            self.closed = False
            self.attempts = 0
            clients.append(self)

        def _prepare_login_session(self):
            return {"a1": "correction-device"}, {"active": False}

        def _complete_security(self):
            pass

        @property
        def profile(self):
            class FakeProfile:
                cookie_map = {"a1": "correction-device"}

            return FakeProfile()

        def send_phone_code(self, phone, cookies):
            return True, "sent", {}

        def login_by_phone(self, phone, code, cookies):
            assert not self.closed
            self.attempts += 1
            if code == "wrong-code":
                return False, "invalid code", None
            return True, "成功", {"cookies": {"a1": "correction-device", "web_session": "test-session"}}

        def get_user_info(self, cookies):
            return True, {"userId": "test-user"}, cookies

        def close(self):
            self.closed = True

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)
    adapter = XhsCreatorLoginAdapter()
    sent = adapter.create_phone_session("redacted-test-value")

    with pytest.raises(RuntimeError):
        adapter.confirm_phone_login("redacted-test-value", "wrong-code", sent["cookies"])
    assert not clients[0].closed

    result = adapter.confirm_phone_login("redacted-test-value", "right-code", sent["cookies"])
    assert result["status"] == "confirmed"
    assert len(clients) == 1
    assert clients[0].attempts == 2
    assert clients[0].closed


def test_creator_phone_code_does_not_retry_non_406_failures(monkeypatch):
    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    attempts = []

    class FakeCreatorLoginApi:
        def __init__(self):
            attempts.append(1)

        def _prepare_login_session(self):
            return {"a1": "anonymous-session"}, {"active": False}

        def _complete_security(self):
            pass

        @property
        def profile(self):
            class FakeProfile:
                cookie_map = {"a1": "prepared-session"}

            return FakeProfile()

        def send_phone_code(self, phone, cookies):
            return False, "HTTP 429: rate limited", {}

        def close(self):
            pass

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)

    try:
        XhsCreatorLoginAdapter().create_phone_session("redacted-test-value")
    except RuntimeError as exc:
        assert "429" in str(exc)
    else:
        raise AssertionError("non-406 Creator SMS failures must be returned without retry")

    assert attempts == [1]


def test_creator_phone_failure_message_exposes_only_safe_http_category():
    from backend.app.api.login_sessions import _safe_creator_phone_error

    message = _safe_creator_phone_error(
        RuntimeError("HTTP 429: rejected request for private-number-123456")
    )

    assert "429" in message
    assert "private-number-123456" not in message


def test_creator_phone_initialization_error_does_not_echo_exception_text():
    from backend.app.api.login_sessions import _safe_creator_phone_error

    message = _safe_creator_phone_error(RuntimeError("secret cookie leaked in exception"))

    assert message == "Creator 登录初始化失败，请稍后重试。"
    assert "secret cookie" not in message


def test_creator_qr_failure_exposes_http_status_without_upstream_secrets():
    from backend.app.api.login_sessions import _safe_creator_qr_error

    message = _safe_creator_qr_error(
        RuntimeError("获取二维码失败 (HTTP 406, code=-1); secret cookie value")
    )

    assert "HTTP 406" in message
    assert "secret cookie" not in message


def test_creator_qrcode_uses_creator_login_preflight_before_generating_qrcode(monkeypatch):
    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    calls = []

    class FakeCreatorLoginApi:
        def _prepare_login_session(self):
            calls.append("preflight")
            return {"a1": "anonymous-session"}, {"active": False}

        def _complete_security(self):
            calls.append("security")

        @property
        def profile(self):
            class FakeProfile:
                cookie_map = {"a1": "prepared-session"}

            return FakeProfile()

        def generate_qrcode(self, cookies):
            calls.append("qrcode")
            assert cookies == {"a1": "prepared-session"}
            return True, "成功", {
                "cookies": {"a1": "qr-session"},
                "qr_id": "test-qr-id",
                "qr_url": "https://example.invalid/qr",
            }

        def check_qrcode_status(self, qr_id, cookies):
            calls.append("poll")
            assert qr_id == "test-qr-id"
            assert cookies == {"a1": "qr-session"}
            return True, "登录成功", {"a1": "confirmed-session"}

        def get_user_info(self, cookies):
            calls.append("user-info")
            assert cookies == {"a1": "confirmed-session"}
            return True, {"userId": "test-user", "userName": "test"}, cookies

        def close(self):
            calls.append("close")

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)

    result = XhsCreatorLoginAdapter().create_qrcode()

    assert calls == ["preflight", "security", "qrcode"]
    assert result == {
        "cookies": {"a1": "qr-session"},
        "qr_id": "test-qr-id",
        "qr_url": "https://example.invalid/qr",
    }

    adapter = XhsCreatorLoginAdapter()
    status = adapter.check_qrcode_status("test-qr-id", result["cookies"])
    account = adapter.get_user_info(status["cookies"], qr_id="test-qr-id")

    assert status == {"status": "confirmed", "cookies": {"a1": "confirmed-session"}}
    assert account["external_user_id"] == "test-user"
    assert calls == ["preflight", "security", "qrcode", "poll", "user-info", "close"]


def test_creator_sdk_matches_current_spider_login_build():
    from apis.xhs_creator_login_apis import CREATOR_USER_AGENT, CREATOR_WEB_BUILD
    from xhs_utils.xhs_creator.params import CREATOR_SEC_CH_UA

    assert CREATOR_WEB_BUILD == "1.26.0"
    assert "Chrome/152.0.0.0" in CREATOR_USER_AGENT
    assert '"Chromium";v="152"' in CREATOR_SEC_CH_UA


def test_creator_login_preflight_follows_current_browser_order():
    from types import SimpleNamespace

    from apis.xhs_creator_login_apis import XHSCreatorLoginApi

    calls = []
    api = SimpleNamespace(
        generate_init_cookies=lambda **kwargs: calls.append("init") or {"a1": "test"},
        _finish_security_bootstrap=lambda: calls.append("security"),
        _build_zone_request=lambda cookies: calls.append("build-zones") or "zones",
        _build_session_request=lambda cookies: calls.append("build-session") or "session",
        _send_zone_request=lambda request: calls.append("send-zones"),
        _send_session_request=lambda request: calls.append("send-session") or {"active": False},
        profile=SimpleNamespace(cookie_map={"a1": "prepared"}),
    )

    cookies, session = XHSCreatorLoginApi._prepare_login_session(api)

    assert calls == [
        "init",
        "security",
        "build-zones",
        "build-session",
        "send-zones",
        "send-session",
    ]
    assert cookies == {"a1": "prepared"}
    assert session == {"active": False}


def test_creator_406_preflight_response_is_not_retried():
    from types import SimpleNamespace

    from apis.xhs_creator_login_apis import XHSCreatorLoginApi

    attempts = []
    api = SimpleNamespace(
        _send_with_gate_retry=XHSCreatorLoginApi._send_with_gate_retry.__get__(
            SimpleNamespace(), XHSCreatorLoginApi
        )
    )

    response = api._send_with_gate_retry(
        lambda: attempts.append(1) or SimpleNamespace(status_code=406),
        label="test",
    )

    assert response.status_code == 406
    assert attempts == [1]


def test_pc_cookie_bridge_prepares_creator_navigation_and_signing_before_session_probe():
    from apis.xhs_creator_login_apis import XHSCreatorLoginApi

    calls = []

    class Profile:
        cookie_map = {"a1": "test-device"}

        def update_cookies(self, cookies):
            calls.append("import-pc-cookies")

    class Bridge:
        profile = Profile()

        def bootstrap_publish_navigation(self):
            calls.append("publish-navigation")

        def _complete_security(self):
            calls.append("security")

        def query_session(self):
            assert calls == ["import-pc-cookies", "publish-navigation", "security"]
            calls.append("session-probe")
            return {"active": True, "res_json": {}}

        def get_user_info(self):
            calls.append("user-info")
            return True, {"userId": "test-user"}, {"a1": "creator-device"}

    success, _, payload = XHSCreatorLoginApi.exchange_creator_session_from_user_cookies(
        Bridge(), {"a1": "test-device"}
    )

    assert success is True
    assert payload["user_info"]["userId"] == "test-user"
    assert calls == [
        "import-pc-cookies", "publish-navigation", "security", "session-probe", "user-info"
    ]


def test_creator_bridge_returns_verified_profile_and_closes_its_client(monkeypatch):
    import apis.xhs_creator_login_apis as creator_login_apis
    from backend.app.adapters.xhs.creator_login_adapter import XhsCreatorLoginAdapter

    clients = []

    class FakeCreatorLoginApi:
        def __init__(self):
            self.closed = False
            clients.append(self)

        def exchange_creator_session_from_user_cookies(self, cookies):
            assert cookies == {"a1": "test-device"}
            return True, "成功", {
                "cookies": {"a1": "creator-device"},
                "user_info": {"userId": "test-user", "userName": "test-creator"},
            }

        def close(self):
            self.closed = True

    monkeypatch.setattr(creator_login_apis, "XHSCreatorLoginApi", FakeCreatorLoginApi)

    result = XhsCreatorLoginAdapter().exchange_from_user_cookies({"a1": "test-device"})

    assert result["user_info"]["external_user_id"] == "test-user"
    assert result["user_info"]["nickname"] == "test-creator"
    assert clients[0].closed


def test_creator_debug_log_never_includes_login_secrets(monkeypatch):
    from types import SimpleNamespace

    import apis.xhs_creator_login_apis as creator_login_apis

    messages = []
    monkeypatch.setenv("XHS_CREATOR_DEBUG", "1")
    monkeypatch.setattr(
        creator_login_apis,
        "logger",
        SimpleNamespace(debug=messages.append),
    )
    creator_login_apis.XHSCreatorLoginApi._debug_dump(
        SimpleNamespace(),
        "qr-code",
        request_headers={"cookie": "secret-cookie", "x-s": "secret-signature"},
        request_body='{"phone":"secret-phone"}',
        response=SimpleNamespace(
            status_code=406,
            cookies={"session": "secret-response-cookie"},
            text="secret-response-body",
        ),
    )

    log_text = "\n".join(messages)
    assert "406" in log_text
    assert "secret-" not in log_text
