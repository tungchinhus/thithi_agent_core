"""Gateway gọi Privacy Vault qua client này. Gateway không có ánh xạ, chỉ có bản đã che."""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from .masking import LeakError
from .ner import NerUnavailable


class PrivacyClient(Protocol):
    def mask(self, trace_id: str, payload: Any) -> Any: ...
    def unmask(self, trace_id: str, payload: Any) -> Any: ...
    def purge(self, trace_id: str) -> None: ...


class PrivacyUnavailable(NerUnavailable):
    """Không gọi được Privacy Vault: coi như không che được, Gateway phải chặn."""


class HttpPrivacyClient:
    def __init__(self, base_url: str, token: str, timeout: float = 60, http: httpx.Client | None = None):
        self._http = http or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._http.headers["X-Service-Token"] = token

    def _post(self, path: str, trace_id: str, payload: Any) -> Any:
        try:
            resp = self._http.post(path, json={"trace_id": trace_id, "payload": payload})
        except httpx.HTTPError as exc:
            raise PrivacyUnavailable(f"Không gọi được Privacy Vault: {exc}") from exc
        if resp.status_code == 503:
            raise NerUnavailable(resp.json()["detail"]["detail"])
        if resp.status_code == 422 and isinstance(resp.json().get("detail"), dict):
            raise LeakError(resp.json()["detail"]["detail"])
        if resp.status_code >= 400:
            raise PrivacyUnavailable(f"Privacy Vault trả lỗi {resp.status_code}")
        return resp.json()["payload"]

    def mask(self, trace_id: str, payload: Any) -> Any:
        return self._post("/v1/mask", trace_id, payload)

    def unmask(self, trace_id: str, payload: Any) -> Any:
        return self._post("/v1/unmask", trace_id, payload)

    def purge(self, trace_id: str) -> None:
        self._http.delete(f"/v1/traces/{trace_id}")
