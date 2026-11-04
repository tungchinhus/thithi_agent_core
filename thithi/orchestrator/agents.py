"""Định nghĩa agent theo phòng ban, đọc từ agents/*.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from thithi.gateway.labels import Label


class AgentDef(BaseModel):
    id: str
    name: str
    allowed_roles: list[str]
    max_label: Label
    tools: list[str]
    requires_approval: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)
    monthly_token_budget_usd: float = 0
    local_prompt: str = ""

    @field_validator("max_label", mode="before")
    @classmethod
    def _parse_label(cls, v):
        return Label.parse(v) if isinstance(v, str) else v

    def can_use(self, tool: str) -> bool:
        return tool in self.tools


def load_agents(directory: str | Path) -> dict[str, AgentDef]:
    agents = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        agent = AgentDef(**yaml.safe_load(path.read_text(encoding="utf-8")))
        if agent.id in agents:
            raise ValueError(f"Trùng agent id: {agent.id}")
        agents[agent.id] = agent
    return agents
