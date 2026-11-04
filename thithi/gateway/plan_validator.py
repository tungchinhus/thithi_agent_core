"""Kiểm tra Plan Claude trả về trước khi cho Orchestrator chạy.

Đây là lớp chống prompt injection chính: dù nội dung đọc vào có xúi gì, chỉ những bước
qua được các luật dưới đây mới được thực thi.
"""

from __future__ import annotations

from thithi.orchestrator.agents import AgentDef
from thithi.orchestrator.models import Plan
from thithi.orchestrator.registry import ToolRegistry

CLOUD_TOOLS = {"claude.review"}


class PlanRejected(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def validate_plan(plan: Plan, agents: dict[str, AgentDef], registry: ToolRegistry, user_roles: set[str]) -> None:
    problems: list[str] = []
    seen: set[int] = set()
    if not plan.steps:
        problems.append("Plan không có bước nào")
    for step in plan.steps:
        where = f"bước {step.id}"
        if step.id in seen:
            problems.append(f"{where}: trùng id")
        agent = agents.get(step.agent)
        if agent is None:
            problems.append(f"{where}: agent '{step.agent}' không tồn tại")
        else:
            if not user_roles & set(agent.allowed_roles):
                problems.append(f"{where}: người yêu cầu không có quyền dùng agent '{agent.id}'")
            if step.tool not in CLOUD_TOOLS and not agent.can_use(step.tool):
                problems.append(f"{where}: agent '{agent.id}' không được dùng '{step.tool}'")
            if step.tool in agent.requires_approval and not step.approval:
                problems.append(f"{where}: '{step.tool}' phải có approval")
        if step.tool in CLOUD_TOOLS:
            if step.runs_on != "cloud":
                problems.append(f"{where}: '{step.tool}' chỉ chạy trên cloud")
        else:
            spec = registry.get(step.tool)
            if spec is None:
                problems.append(f"{where}: công cụ '{step.tool}' không có trong danh mục")
            elif spec.writes and not step.approval:
                problems.append(f"{where}: công cụ ghi '{step.tool}' phải có approval")
            if step.runs_on != "local":
                problems.append(f"{where}: công cụ nội bộ phải chạy local")
        ref = step.input.get("from_step")
        if ref is not None and ref not in seen:
            problems.append(f"{where}: from_step={ref} không phải bước trước đó")
        seen.add(step.id)
    if problems:
        raise PlanRejected(problems)
