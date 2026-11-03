"""Orchestrator: định tuyến yêu cầu, lấy Plan, thực thi từng bước ở local, gọi QA, chờ duyệt."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from thithi.cloud.brain import ClaudeBrain
from thithi.gateway.labels import Label
from thithi.gateway.plan_validator import validate_plan
from thithi.gateway.service import Gateway

from .agents import AgentDef
from .models import Plan, PlanStep, Review, StepResult
from .registry import ToolRegistry

Status = Literal["planning", "running", "waiting_approval", "done", "failed", "rejected"]
LOCAL_ONLY_AGENTS = {"knowledge"}
MAX_QA_RETRIES = 1


@dataclass
class RequestState:
    trace_id: str
    user_id: str
    user_roles: set[str]
    agent_id: str
    text: str
    route: Literal["local", "hybrid"] = "hybrid"
    status: Status = "planning"
    plan: Plan | None = None
    next_index: int = 0
    outputs: dict[int, Any] = field(default_factory=dict)
    sources: dict[int, list[str]] = field(default_factory=dict)
    results: list[StepResult] = field(default_factory=list)
    reviews: dict[int, Review] = field(default_factory=dict)
    qa_retries: dict[int, int] = field(default_factory=dict)
    error: str | None = None


def _sources_of(output: Any) -> list[str]:
    if not isinstance(output, dict):
        return []
    if output.get("source"):
        return [output["source"]]
    return list(output.get("sources") or [])


class Orchestrator:
    def __init__(self, gateway: Gateway, brain: ClaudeBrain | None, agents: dict[str, AgentDef], registry: ToolRegistry):
        self.gateway = gateway
        self.brain = brain
        self.agents = agents
        self.registry = registry
        self.requests: dict[str, RequestState] = {}

    # ---------- định tuyến ----------
    def route(self, agent: AgentDef) -> Literal["local", "hybrid"]:
        if agent.id in LOCAL_ONLY_AGENTS or agent.max_label == Label.TOI_MAT:
            return "local"
        return "hybrid"

    def submit(self, user_id: str, user_roles: set[str], agent_id: str, text: str) -> RequestState:
        trace_id = "REQ-" + uuid.uuid4().hex[:12]
        state = RequestState(trace_id, user_id, user_roles, agent_id, text)
        self.requests[trace_id] = state
        agent = self.agents.get(agent_id)
        if agent is None:
            return self._fail(state, f"Không có agent '{agent_id}'")
        if not user_roles & set(agent.allowed_roles):
            return self._fail(state, "Không có quyền dùng agent này")
        state.route = self.route(agent)
        self.gateway.audit.log(trace_id, "submitted", user_id=user_id, agent=agent_id, route=state.route)
        try:
            state.plan = self._local_plan(state) if state.route == "local" else self._cloud_plan(state, agent)
            validate_plan(state.plan, self.agents, self.registry, user_roles)
        except Exception as exc:  # Plan sai hoặc bị chặn: không chạy gì cả
            return self._fail(state, f"Không lập được kế hoạch: {exc}", status="rejected")
        state.status = "running"
        return self._run(state)

    def _local_plan(self, state: RequestState) -> Plan:
        if state.agent_id != "knowledge":
            raise NotImplementedError("Giai đoạn 1 mới hỗ trợ luồng thuần local cho agent 'knowledge' (WF1)")
        return Plan(
            trace_id=state.trace_id,
            goal="Trả lời câu hỏi từ tài liệu nội bộ",
            steps=[
                PlanStep(id=1, agent="knowledge", tool="mcp-docs.search", input={"query": state.text},
                         runs_on="local", done_when="có ít nhất 1 đoạn liên quan"),
                PlanStep(id=2, agent="knowledge", tool="mcp-local-llm.answer_with_sources",
                         input={"question": state.text, "from_step": 1}, runs_on="local",
                         done_when="câu trả lời có trích dẫn"),
            ],
        )

    def _cloud_plan(self, state: RequestState, agent: AgentDef) -> Plan:
        if self.brain is None:
            raise RuntimeError("Chưa cấu hình Claude")
        masked = self.gateway.outbound(state.trace_id, state.text, ["user.request"], purpose="plan")
        catalog = [{"agent": agent.id, "name": agent.name, "tools": self.registry.catalog(agent.tools)}]
        return self.brain.plan(state.trace_id, masked, catalog)

    # ---------- thực thi ----------
    def approve(self, trace_id: str, step_id: int, approver: str, approved: bool) -> RequestState:
        state = self.requests[trace_id]
        if state.status != "waiting_approval" or state.plan is None:
            raise ValueError("Yêu cầu không ở trạng thái chờ duyệt")
        step = state.plan.steps[state.next_index]
        if step.id != step_id:
            raise ValueError(f"Bước đang chờ duyệt là {step.id}, không phải {step_id}")
        agent = self.agents[step.agent]
        if agent.approvers and approver not in agent.approvers:
            raise PermissionError(f"{approver} không phải người duyệt của agent {agent.id}")
        self.gateway.audit.log(trace_id, "approval", step=step_id, approver=approver, approved=approved)
        if not approved:
            state.results.append(StepResult(step_id=step_id, status="rejected"))
            state.status = "rejected"
            return state
        state.status = "running"
        return self._run(state, approved_step=step_id)

    def _run(self, state: RequestState, approved_step: int | None = None) -> RequestState:
        assert state.plan is not None
        steps = state.plan.steps
        while state.next_index < len(steps):
            step = steps[state.next_index]
            if step.approval and step.id != approved_step:
                state.status = "waiting_approval"
                state.results.append(StepResult(step_id=step.id, status="waiting_approval"))
                return state
            try:
                if step.tool == "claude.review":
                    retry_from = self._review(state, step)
                    if retry_from is not None:
                        state.next_index = retry_from
                        continue
                else:
                    self._exec_local(state, step)
            except Exception as exc:
                state.results.append(StepResult(step_id=step.id, status="failed", error=str(exc)))
                return self._fail(state, f"Bước {step.id} lỗi: {exc}")
            state.next_index += 1
        state.status = "done"
        self.gateway.audit.log(state.trace_id, "done")
        return state

    def _resolve_input(self, state: RequestState, step: PlanStep) -> tuple[dict[str, Any], list[str]]:
        args = dict(step.input)
        inherited: list[str] = []
        ref = args.pop("from_step", None)
        if ref is not None:
            prev = state.outputs[ref]
            inherited = state.sources.get(ref, [])
            spec = self.registry.get(step.tool)
            params = spec.fn.__code__.co_varnames[: spec.fn.__code__.co_argcount] if spec else ()
            if "chunks" in params and isinstance(prev, dict) and "chunks" in prev:
                args["chunks"] = prev["chunks"]
            elif "text" in params:
                args["text"] = prev if isinstance(prev, str) else json.dumps(prev, ensure_ascii=False, default=str)
            elif "body" in params:
                args.setdefault("body", prev.get("summary", str(prev)) if isinstance(prev, dict) else str(prev))
        return args, inherited

    def _exec_local(self, state: RequestState, step: PlanStep) -> None:
        spec = self.registry.get(step.tool)
        args, inherited = self._resolve_input(state, step)
        if spec.writes:
            args = self.gateway.inbound(state.trace_id, args)  # bản nháp gửi người thật: đổi token về giá trị thật
        output = spec.fn(user_id=state.user_id, **args)
        state.outputs[step.id] = output
        state.sources[step.id] = sorted(set(inherited + _sources_of(output)))
        state.results.append(StepResult(step_id=step.id, status="done", output=output))
        self.gateway.audit.log(state.trace_id, "step_done", step=step.id, tool=step.tool)

    def _review(self, state: RequestState, step: PlanStep) -> int | None:
        """Gửi đầu ra (đã che) lên Claude QA. Trả về chỉ số bước cần chạy lại, hoặc None."""
        if self.brain is None:
            raise RuntimeError("Chưa cấu hình Claude")
        ref = step.input["from_step"]
        target = next(s for s in state.plan.steps if s.id == ref)
        masked = self.gateway.outbound(state.trace_id, state.outputs[ref], state.sources.get(ref, []), purpose="review")
        review = self.brain.review(target, target.done_when, masked)
        state.reviews[ref] = review
        state.results.append(StepResult(step_id=step.id, status="done", output=review.model_dump()))
        if review.passed:
            return None
        tries = state.qa_retries.get(ref, 0)
        if tries >= MAX_QA_RETRIES:
            raise RuntimeError("QA không đạt: " + "; ".join(review.reasons))
        state.qa_retries[ref] = tries + 1
        return next(i for i, s in enumerate(state.plan.steps) if s.id == ref)

    def _fail(self, state: RequestState, error: str, status: Status = "failed") -> RequestState:
        state.status = status
        state.error = error
        self.gateway.audit.log(state.trace_id, status, error=error)
        return state
