import pytest

from thithi.gateway.plan_validator import PlanRejected, validate_plan
from thithi.orchestrator.models import Plan, PlanStep


def step(**kw):
    base = dict(id=1, agent="finance", tool="mcp-erp.query_ar_aging", input={}, runs_on="local", done_when="x")
    base.update(kw)
    return PlanStep(**base)


def test_valid_plan(agents, registry):
    plan = Plan(trace_id="t", goal="g", steps=[
        step(id=1),
        step(id=2, tool="claude.review", runs_on="cloud", input={"from_step": 1}),
        step(id=3, tool="mcp-notify.draft_email", input={"from_step": 1}, approval=True),
    ])
    validate_plan(plan, agents, registry, {"finance"})


@pytest.mark.parametrize("bad,expect", [
    (step(tool="mcp-hrm.payroll"), "không được dùng"),
    (step(tool="mcp-notify.draft_email"), "phải có approval"),
    (step(runs_on="cloud"), "phải chạy local"),
    (step(agent="ghost"), "không tồn tại"),
    (step(input={"from_step": 9}), "from_step"),
    (step(tool="mcp-docs.search"), "không được dùng"),
])
def test_rejects(bad, expect, agents, registry):
    with pytest.raises(PlanRejected) as e:
        validate_plan(Plan(trace_id="t", goal="g", steps=[bad]), agents, registry, {"finance"})
    assert expect in str(e.value)


def test_rejects_user_without_role(agents, registry):
    with pytest.raises(PlanRejected, match="không có quyền"):
        validate_plan(Plan(trace_id="t", goal="g", steps=[step()]), agents, registry, {"nhan_vien"})
