from __future__ import annotations

import threading
import time
from typing import Any

from backend.app.adapters.xhs.request_env import direct_xhs_request_env


class XhsPcLoginAdapter:
    _active_qr_sessions: dict[str, tuple[float, Any, Any]] = {}
    _active_qr_sessions_lock = threading.RLock()
    _qr_session_ttl_seconds = 10 * 60
    _max_active_qr_sessions = 32

    @classmethod
    def _close_api(cls, api: Any) -> None:
        try:
            api.close()
        except Exception:
            pass

    @classmethod
    def _prune_qr_sessions(cls) -> None:
        now = time.monotonic()
        expired = []
        with cls._active_qr_sessions_lock:
            for qr_id, (created_at, api, _) in list(cls._active_qr_sessions.items()):
                if now - created_at > cls._qr_session_ttl_seconds:
                    expired.append(api)
                    del cls._active_qr_sessions[qr_id]
            while len(cls._active_qr_sessions) >= cls._max_active_qr_sessions:
                oldest_qr_id = next(iter(cls._active_qr_sessions))
                _, api, _ = cls._active_qr_sessions.pop(oldest_qr_id)
                expired.append(api)
        for api in expired:
            cls._close_api(api)

    @classmethod
    def _remember_qr_session(cls, qr_id: str, api: Any) -> None:
        cls._prune_qr_sessions()
        with cls._active_qr_sessions_lock:
            previous = cls._active_qr_sessions.pop(qr_id, None)
            cls._active_qr_sessions[qr_id] = (time.monotonic(), api, threading.RLock())
        if previous:
            cls._close_api(previous[1])

    @classmethod
    def _get_qr_session(cls, qr_id: str) -> tuple[Any, Any] | None:
        with cls._active_qr_sessions_lock:
            session = cls._active_qr_sessions.get(qr_id)
            if session is None:
                return None
            created_at, api, request_lock = session
            if time.monotonic() - created_at > cls._qr_session_ttl_seconds:
                del cls._active_qr_sessions[qr_id]
            else:
                return api, request_lock
        cls._close_api(session[1])
        return None

    @classmethod
    def _forget_qr_session(cls, qr_id: str) -> None:
        with cls._active_qr_sessions_lock:
            session = cls._active_qr_sessions.pop(qr_id, None)
        if session:
            cls._close_api(session[1])

    def create_qrcode(self) -> dict[str, Any]:
        with direct_xhs_request_env():
            from apis.xhs_pc_login_apis import XHSLoginApi

            api = XHSLoginApi()
            try:
                cookies = api.generate_init_cookies()
                success, message, payload = api.generate_qrcode(cookies)
                if not success or not payload:
                    raise RuntimeError(message)
                cookies = payload["cookies"]

                # Keep the browser's QR login order: validate the initial QR
                # state, report webprofile, and only then expose it for scanning.
                checked, check_message, cookies = api.check_qrcode_status(
                    payload["qr_id"], payload["code"], cookies
                )
                if checked or check_message != "请扫描二维码":
                    raise RuntimeError(f"二维码预检查状态异常: {check_message}")
                api.ensure_webprofile(cookies)
            except Exception:
                self._close_api(api)
                raise

        self._remember_qr_session(payload["qr_id"], api)
        return {
            "cookies": cookies,
            "qr_id": payload["qr_id"],
            "code": payload["code"],
            "qr_url": payload["qr_url"],
        }

    def check_qrcode_status(self, qr_id: str, code: str, cookies: dict[str, Any]) -> dict[str, Any]:
        qr_session = self._get_qr_session(qr_id)
        if qr_session is None:
            # The in-memory signing context is lost after a backend restart;
            # require a fresh QR rather than sending a mismatched signature.
            return {"status": "expired", "cookies": cookies}
        api, request_lock = qr_session
        with direct_xhs_request_env():
            with request_lock:
                success, message, updated_cookies = api.check_qrcode_status(qr_id, code, cookies)
        status = "confirmed" if success else "pending"
        if "过期" in message or "expired" in message.lower():
            status = "expired"
        if "确认" in message or "confirm" in message.lower():
            status = "scanned"
        if status == "expired":
            self._forget_qr_session(qr_id)
        return {"status": status, "cookies": updated_cookies}

    def get_user_info(self, cookies: dict[str, Any]) -> dict[str, Any]:
        with self._active_qr_sessions_lock:
            matching = next(
                (
                    (qr_id, api, request_lock)
                    for qr_id, (_, api, request_lock) in self._active_qr_sessions.items()
                    if getattr(api, "profile", None) is not None
                    and api.profile.cookie_map.get("a1") == str(cookies.get("a1") or "")
                ),
                None,
            )
        if matching is not None:
            qr_id, api, request_lock = matching
            with direct_xhs_request_env():
                with request_lock:
                    success, data, _ = api.get_user_info(cookies)
            if success:
                self._forget_qr_session(qr_id)
        else:
            with direct_xhs_request_env():
                from apis.xhs_pc_login_apis import XHSLoginApi

                api = XHSLoginApi()
                try:
                    success, data, _ = api.get_user_info(cookies)
                finally:
                    self._close_api(api)
        if not success:
            raise RuntimeError("Failed to fetch XHS user info")
        return {
            "external_user_id": data.get("user_id", ""),
            "nickname": data.get("nickname", ""),
            "avatar_url": data.get("images") or data.get("imageb") or "",
            "profile": {
                "red_id": data.get("red_id") or data.get("redId") or "",
                "followers": data.get("fans") or data.get("followers") or data.get("follower_count"),
                "following": data.get("follows") or data.get("following") or data.get("following_count"),
                "likes": data.get("liked_count") or data.get("likes") or data.get("like_count"),
                "raw": data,
            },
        }

    def create_phone_session(self, phone: str) -> dict[str, Any]:
        with direct_xhs_request_env():
            from apis.xhs_pc_login_apis import XHSLoginApi

            api = XHSLoginApi()
            cookies = api.generate_init_cookies()
            success, message, _ = api.send_phone_code(phone, cookies)
        if not success:
            raise RuntimeError(message)
        return {"cookies": cookies, "message": message or "sent"}

    def confirm_phone_login(self, phone: str, code: str, cookies: dict[str, Any]) -> dict[str, Any]:
        with direct_xhs_request_env():
            from apis.xhs_pc_login_apis import XHSLoginApi

            api = XHSLoginApi()
            success, message, payload = api.login_by_phone(phone, code, cookies)
        if not success or not payload:
            raise RuntimeError(message)
        return {"status": "confirmed", "cookies": payload["cookies"]}
