from backend.app.adapters.xhs.pc_login_adapter import XhsPcLoginAdapter
from types import SimpleNamespace


def test_pc_qr_login_prechecks_reports_webprofile_and_reuses_signing_session(monkeypatch):
    from apis import xhs_pc_login_apis

    created_apis = []

    class FakeLoginApi:
        def __init__(self):
            self.calls = []
            created_apis.append(self)

        def generate_init_cookies(self):
            self.calls.append("initialize")
            return {"a1": "anonymous"}

        def generate_qrcode(self, cookies):
            self.calls.append("create_qrcode")
            return True, "成功", {
                "cookies": cookies,
                "qr_id": "qr-test",
                "code": "code-test",
                "qr_url": "https://example.test/qr",
            }

        def check_qrcode_status(self, qr_id, code, cookies):
            self.calls.append(("check", qr_id, code))
            if len([call for call in self.calls if isinstance(call, tuple)]) == 1:
                return False, "请扫描二维码", cookies
            return True, "验证成功", {**cookies, "web_session": "issued"}

        def ensure_webprofile(self, cookies):
            self.calls.append("webprofile")
            cookies["gid"] = "issued-gid"
            self.profile = SimpleNamespace(cookie_map=dict(cookies))
            return cookies["gid"]

        def get_user_info(self, cookies):
            self.calls.append("get_user_info")
            return True, {"user_id": "test-user", "nickname": "test"}, cookies

        def close(self):
            self.calls.append("close")

    monkeypatch.setattr(xhs_pc_login_apis, "XHSLoginApi", FakeLoginApi)
    adapter = XhsPcLoginAdapter()

    created = adapter.create_qrcode()
    assert created["cookies"]["gid"] == "issued-gid"
    assert created_apis[0].calls == [
        "initialize",
        "create_qrcode",
        ("check", "qr-test", "code-test"),
        "webprofile",
    ]

    polled = adapter.check_qrcode_status("qr-test", "code-test", created["cookies"])
    assert polled["status"] == "confirmed"
    assert polled["cookies"]["web_session"] == "issued"
    assert len(created_apis) == 1
    assert created_apis[0].calls[-1] == ("check", "qr-test", "code-test")

    user = adapter.get_user_info(polled["cookies"])
    assert user["external_user_id"] == "test-user"
    assert len(created_apis) == 1
    assert created_apis[0].calls[-2:] == ["get_user_info", "close"]
