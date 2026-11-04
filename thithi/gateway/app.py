"""API của Gateway (FastAPI). Chạy: uvicorn thithi.gateway.app:app"""

from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from thithi.mcp_servers.authz import roles_of
from thithi.orchestrator.agents import load_agents
from thithi.orchestrator.registry import default_registry
from thithi.orchestrator.runner import Orchestrator, RequestState

from .labels import LabelPolicy
from .service import AuditLog, Gateway

app = FastAPI(title="THITHI Agentic Core Gateway")


@lru_cache(maxsize=1)
def get_orchestrator() -> Orchestrator:
    from thithi.cloud.brain import ClaudeBrain

    gateway = Gateway(
        LabelPolicy.from_yaml(os.environ.get("THITHI_LABELS", "config/labels.yaml")),
        privacy=_privacy_client(),
        audit=AuditLog(os.environ.get("THITHI_AUDIT_LOG", "data/audit.jsonl")),
    )
    brain = ClaudeBrain() if os.environ.get("ANTHROPIC_API_KEY") else None
    agents = load_agents(os.environ.get("THITHI_AGENTS", "agents"))
    return Orchestrator(gateway, brain, agents, default_registry())


def _privacy_client():
    """Production: bắt buộc gọi Privacy Vault trên máy AI local. Chỉ dev mới chạy engine cùng tiến trình."""
    url = os.environ.get("PRIVACY_URL")
    if url:
        from thithi.privacy.client import HttpPrivacyClient

        return HttpPrivacyClient(url, os.environ.get("PRIVACY_SERVICE_TOKEN", ""))
    if os.environ.get("THITHI_ENV") == "dev":
        from thithi.privacy.engine import build_engine

        return build_engine()
    raise RuntimeError("Thiếu PRIVACY_URL: Gateway phải dùng Privacy Vault chạy trên máy AI local")


def current_user(x_user_id: str = Header(...)) -> str:
    # TODO giai đoạn 1: thay bằng xác thực OIDC (Google Workspace / Microsoft 365).
    if not roles_of(x_user_id):
        raise HTTPException(401, "Người dùng không xác định")
    return x_user_id


class NewRequest(BaseModel):
    agent: str
    text: str


class Approval(BaseModel):
    approved: bool


def _view(state: RequestState, orch: Orchestrator, viewer: str) -> dict:
    gw = orch.gateway
    return {
        "trace_id": state.trace_id,
        "status": state.status,
        "route": state.route,
        "error": state.error,
        "plan": state.plan.model_dump() if state.plan else None,
        "waiting_step": (
            state.plan.steps[state.next_index].id
            if state.status == "waiting_approval" and state.plan
            else None
        ),
        # Chỉ đường lai mới có ánh xạ; đường thuần local không gọi Vault.
        "results": (
            gw.inbound(state.trace_id, [r.model_dump() for r in state.results], actor=viewer)
            if state.route == "hybrid" and state.results
            else [r.model_dump() for r in state.results]
        ),
    }


@app.post("/v1/requests")
def create_request(body: NewRequest, user: str = Depends(current_user), orch: Orchestrator = Depends(get_orchestrator)):
    state = orch.submit(user, roles_of(user), body.agent, body.text)
    return _view(state, orch, user)


@app.get("/v1/requests/{trace_id}")
def get_request(trace_id: str, user: str = Depends(current_user), orch: Orchestrator = Depends(get_orchestrator)):
    state = orch.requests.get(trace_id)
    if state is None or (state.user_id != user and "ban_giam_doc" not in roles_of(user)):
        raise HTTPException(404, "Không tìm thấy")
    return _view(state, orch, user)


@app.post("/v1/approvals/{trace_id}/{step_id}")
def approve(trace_id: str, step_id: int, body: Approval, user: str = Depends(current_user),
            orch: Orchestrator = Depends(get_orchestrator)):
    if trace_id not in orch.requests:
        raise HTTPException(404, "Không tìm thấy")
    try:
        state = orch.approve(trace_id, step_id, user, body.approved)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _view(state, orch, user)


@app.get("/healthz")
def healthz():
    return {"ok": True}
