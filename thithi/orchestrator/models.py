"""Kiểu dữ liệu chung: Plan do Claude lập, kết quả từng bước, đánh giá QA."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class PlanStep(BaseModel):
    id: int
    agent: str
    tool: str
    input: dict[str, Any] = Field(default_factory=dict)
    runs_on: Literal["local", "cloud"]
    done_when: str
    approval: bool = False


class Plan(BaseModel):
    trace_id: str
    goal: str
    steps: list[PlanStep]


class Review(BaseModel):
    score: int = Field(ge=1, le=5)
    passed: bool
    reasons: list[str]


class StepResult(BaseModel):
    step_id: int
    status: Literal["done", "waiting_approval", "rejected", "failed"]
    output: Any = None
    error: str | None = None
