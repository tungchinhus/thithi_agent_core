"""Gateway gọi Privacy Vault qua client này. Gateway không có ánh xạ, chỉ có bản đã che."""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from .masking import LeakError
from .ner import NerUnavailable


class PrivacyClient(Protocol):
    def mask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any: ...
    def unmask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any: ...
    def purge(self, trace_id: str) -> None: ...


class PrivacyUnavailable(NerUnavailable):
    """Không gọi được Privacy Vault: coi như không che được, Gateway phải chặn."""


class HttpPrivacyClient:
    def __init__(self, base_url: str, token: str, timeout: float = 60, http: httpx.Client | None = None):
        self._http = http or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._http.headers["X-Service-Token"] = token

    def _post(self, path: str, trace_id: str, payload: Any, actor: str | None) -> Any:
        try:
            resp = self._http.post(path, json={"trace_id": trace_id, "payload": payload, "actor": actor})
        except httpx.HTTPError as exc:
            raise PrivacyUnavailable(f"Không gọi được Privacy Vault: {exc}") from exc
        if resp.status_code >= 400:
            code, detail = _error_of(resp)
            if code == "ner_unavailable":
                raise NerUnavailable(detail)
            if code == "leak":
                raise LeakError(detail)
            raise PrivacyUnavailable(f"Privacy Vault trả lỗi {resp.status_code}")
        try:
            return resp.json()["payload"]
        except (ValueError, KeyError) as exc:
            raise PrivacyUnavailable("Privacy Vault trả về dữ liệu không hợp lệ") from exc

    def mask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any:
        return self._post("/v1/mask", trace_id, payload, actor)

    def unmask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any:
        return self._post("/v1/unmask", trace_id, payload, actor)

    def purge(self, trace_id: str) -> None:
        try:
            resp = self._http.delete(f"/v1/traces/{trace_id}")
        except httpx.HTTPError as exc:
            raise PrivacyUnavailable(f"Không gọi được Privacy Vault: {exc}") from exc
        if resp.status_code >= 400:
            raise PrivacyUnavailable(f"Privacy Vault trả lỗi {resp.status_code}")


def _error_of(resp: httpx.Response) -> tuple[str | None, str]:
    """Đọc lỗi có cấu trúc của Vault. Lỗi từ proxy/tường lửa (HTML, rỗng) thì không có mã."""
    try:
        detail = resp.json().get("detail")
    except ValueError:
        return None, resp.text[:200]
    if isinstance(detail, dict):
        return detail.get("code"), str(detail.get("detail", ""))
    return None, str(detail)
