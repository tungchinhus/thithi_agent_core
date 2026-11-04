"""API của dịch vụ Privacy Vault, chạy trên máy AI local, chỉ mở trong mạng nội bộ.

    uvicorn thithi.privacy.api:app --host 0.0.0.0 --port 8090

Chỉ Gateway được gọi (header X-Service-Token). Không có endpoint nào trả về ánh xạ thô.
"""

from __future__ import annotations

import hmac
import os
from functools import lru_cache
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .engine import LeakError, NerUnavailable, PrivacyEngine, build_engine

app = FastAPI(title="THITHI Privacy Vault")


@lru_cache(maxsize=1)
def get_engine() -> PrivacyEngine:
    return build_engine()


def service_auth(x_service_token: str = Header(...)) -> None:
    expected = os.environ.get("PRIVACY_SERVICE_TOKEN", "")
    if not expected or not hmac.compare_digest(x_service_token, expected):
        raise HTTPException(401, "Sai service token")


class Payload(BaseModel):
    trace_id: str
    payload: Any
    actor: str | None = None  # người dùng đứng sau lời gọi, chỉ để ghi nhật ký truy cập


@app.post("/v1/mask", dependencies=[Depends(service_auth)])
def mask(body: Payload, engine: PrivacyEngine = Depends(get_engine)):
    try:
        return {"payload": engine.mask(body.trace_id, body.payload, actor=body.actor)}
    except NerUnavailable as exc:
        raise HTTPException(503, {"code": "ner_unavailable", "detail": str(exc)}) from exc
    except LeakError as exc:
        raise HTTPException(422, {"code": "leak", "detail": str(exc)}) from exc


@app.post("/v1/unmask", dependencies=[Depends(service_auth)])
def unmask(body: Payload, engine: PrivacyEngine = Depends(get_engine)):
    return {"payload": engine.unmask(body.trace_id, body.payload, actor=body.actor)}


@app.delete("/v1/traces/{trace_id}", dependencies=[Depends(service_auth)])
def purge(trace_id: str, engine: PrivacyEngine = Depends(get_engine)):
    engine.purge(trace_id)
    return {"purged": trace_id}


@app.get("/healthz")
def healthz():
    return {"ok": True}
