from __future__ import annotations

from threading import RLock
from time import monotonic
from typing import Any

from backend.app.adapters.xhs.request_env import direct_xhs_request_env

_CREATOR_QR_SESSION_TTL_SECONDS = 300
_creator_qr_sessions: dict[str, tuple[float, Any]] = {}
_creator_qr_sessions_lock = RLock()
_CREATOR_PHONE_SESSION_TTL_SECONDS = 600
_creator_phone_sessions: dict[str, tuple[float, Any, Any]] = {}
_creator_phone_sessions_lock = RLock()


def _close_expired_creator_qr_sessions() -> None:
    now = monotonic()
    with _creator_qr_sessions_lock:
        expired = [
            qr_id
            for qr_id, (expires_at, _) in _creator_qr_sessions.items()
            if expires_at <= now
        ]
        apis = [
            _creator_qr_sessions.pop(qr_id)[1]
            for qr_id in expired
        ]
    for api in apis:
        api.close()


def _take_creator_qr_session(qr_id: str) -> Any | None:
    with _creator_qr_sessions_lock:
        entry = _creator_qr_sessions.pop(qr_id, None)
    if entry is None:
        return None
    expires_at, api = entry
    if expires_at <= monotonic():
        api.close()
        return None
    return api


def _close_expired_creator_phone_sessions() -> None:
    now = monotonic()
    with _creator_phone_sessions_lock:
        expired = [
            key for key, (expires_at, _, _) in _creator_phone_sessions.items()
            if expires_at <= now
        ]
        entries = [_creator_phone_sessions.pop(key) for key in expired]
    for _, api, session_lock in entries:
        with session_lock:
            api.close()


class XhsCreatorLoginAdapter:
    def exchange_from_user_cookies(self, user_cookies: dict[str, Any]) -> dict[str, Any]:
        with direct_xhs_request_env():
            from apis.xhs_creator_login_apis import XHSCreatorLoginApi

            api = XHSCreatorLoginApi()
            try:
                success, message, payload = api.exchange_creator_session_from_user_cookies(dict(user_cookies))
            finally:
                api.close()
        if not success or not payload:
            raise RuntimeError(message)
        return {
            "status": "confirmed",
            "cookies": payload["cookies"],
            "user_info": self._map_user_info(payload["user_info"]),
        }

    def create_qrcode(self) -> dict[str, Any]:
        _close_expired_creator_qr_sessions()
        with direct_xhs_request_env():
            from apis.xhs_creator_login_apis import XHSCreatorLoginApi

            api = XHSCreatorLoginApi()
            try:
                cookies, login_state = api._prepare_login_session()
                if login_state.get("active"):
                    raise RuntimeError("Creator session is already active")
                api._complete_security()
                cookies = api.profile.cookie_map
                success, message, payload = api.generate_qrcode(cookies)
                qr_id = str((payload or {}).get("qr_id") or "")
                if success and payload and qr_id:
                    with _creator_qr_sessions_lock:
                        previous = _creator_qr_sessions.pop(qr_id, None)
                        _creator_qr_sessions[qr_id] = (
                            monotonic() + _CREATOR_QR_SESSION_TTL_SECONDS,
                            api,
                        )
                    if previous:
                        previous[1].close()
                    api = None
            finally:
                if api is not None:
                    api.close()
        if not success or not payload:
            raise RuntimeError(message)
        return {
            "cookies": payload["cookies"],
            "qr_id": payload["qr_id"],
            "qr_url": payload["qr_url"],
        }

    def check_qrcode_status(self, qr_id: str, cookies: dict[str, Any]) -> dict[str, Any]:
        _close_expired_creator_qr_sessions()
        api = None
        with _creator_qr_sessions_lock:
            entry = _creator_qr_sessions.get(qr_id)
        if entry:
            api = entry[1]
        if api is None:
            return {"status": "expired", "cookies": cookies}
        with direct_xhs_request_env():
            try:
                success, message, updated_cookies = api.check_qrcode_status(qr_id, cookies)
            except Exception:
                _take_creator_qr_session(qr_id)
                api.close()
                raise
        status = "confirmed" if success else "pending"
        if "过期" in message or "expired" in message.lower():
            status = "expired"
        if "确认" in message or "confirm" in message.lower():
            status = "scanned"
        if status == "expired":
            expired_api = _take_creator_qr_session(qr_id)
            if expired_api:
                expired_api.close()
        return {"status": status, "cookies": updated_cookies}

    def get_user_info(
        self,
        cookies: dict[str, Any],
        qr_id: str | None = None,
        api: Any | None = None,
    ) -> dict[str, Any]:
        with direct_xhs_request_env():
            owns_api = api is None
            if api is None:
                if qr_id:
                    api = _take_creator_qr_session(qr_id)
                    if api is None:
                        raise RuntimeError("Creator login session expired; refresh QR code")
                else:
                    from apis.xhs_creator_login_apis import XHSCreatorLoginApi

                    api = XHSCreatorLoginApi()
            try:
                success, data, _ = api.get_user_info(cookies)
            finally:
                if owns_api:
                    api.close()
        if not success:
            raise RuntimeError("Failed to fetch XHS Creator user info")
        return self._map_user_info(data)

    @staticmethod
    def _map_user_info(data: dict[str, Any]) -> dict[str, Any]:
        return {
            "external_user_id": data.get("userId", ""),
            "nickname": data.get("userName", ""),
            "avatar_url": data.get("userAvatar", ""),
            "profile": {
                "red_id": data.get("redId") or data.get("red_id") or "",
                "role": data.get("role") or "",
                "real_name_verified": data.get("realNameVerified"),
                "followers": data.get("fans") or data.get("followers") or data.get("followerCount"),
                "following": data.get("follows") or data.get("following") or data.get("followingCount"),
                "likes": data.get("likedCount") or data.get("likes") or data.get("likeCount"),
                "raw": data,
            },
        }

    def create_phone_session(self, phone: str) -> dict[str, Any]:
        _close_expired_creator_phone_sessions()
        with direct_xhs_request_env():
            from apis.xhs_creator_login_apis import XHSCreatorLoginApi

            api = XHSCreatorLoginApi()
            try:
                cookies, login_state = api._prepare_login_session()
                if login_state.get("active"):
                    raise RuntimeError("Creator session is already active")
                api._complete_security()
                cookies = api.profile.cookie_map
                success, message, _ = api.send_phone_code(phone, cookies)
                if success:
                    session_key = str(cookies.get("a1") or "")
                    if not session_key:
                        raise RuntimeError("Creator device session missing")
                    with _creator_phone_sessions_lock:
                        previous = _creator_phone_sessions.pop(session_key, None)
                        _creator_phone_sessions[session_key] = (
                            monotonic() + _CREATOR_PHONE_SESSION_TTL_SECONDS,
                            api,
                            RLock(),
                        )
                    if previous:
                        with previous[2]:
                            previous[1].close()
                    api = None
            finally:
                if api is not None:
                    api.close()
        if not success:
            raise RuntimeError(message)
        return {"cookies": cookies, "message": message or "sent"}

    def confirm_phone_login(self, phone: str, code: str, cookies: dict[str, Any]) -> dict[str, Any]:
        _close_expired_creator_phone_sessions()
        session_key = str(cookies.get("a1") or "")
        with _creator_phone_sessions_lock:
            entry = _creator_phone_sessions.get(session_key)
        if entry is None:
            raise RuntimeError("Creator login session expired; send code again")
        _, api, session_lock = entry
        with session_lock:
            with _creator_phone_sessions_lock:
                if _creator_phone_sessions.get(session_key) is not entry:
                    raise RuntimeError("Creator login session expired; send code again")
            with direct_xhs_request_env():
                success, message, payload = api.login_by_phone(phone, code, cookies)
                if not success or not payload:
                    raise RuntimeError(message)
                user_info = self.get_user_info(payload["cookies"], api=api)
            with _creator_phone_sessions_lock:
                _creator_phone_sessions.pop(session_key, None)
            api.close()
        return {"status": "confirmed", "cookies": payload["cookies"], "user_info": user_info}
