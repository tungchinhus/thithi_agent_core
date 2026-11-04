"""Chạy WF1 và WF2 đầu cuối với Claude giả và LLM local giả."""

import json

import pytest

from thithi.gateway.service import Gateway
from thithi.mcp_servers import local_llm
from thithi.orchestrator.models import Plan, PlanStep, Review
from thithi.orchestrator.runner import Orchestrator


class FakeBrain:
    def __init__(self, plan_steps, reviews=None):
        self.plan_steps = plan_steps
        self.reviews = list(reviews or [Review(score=5, passed=True, reasons=["ok"])])
        self.seen: list[str] = []

    def plan(self, trace_id, masked_request, catalog):
        self.seen.append(masked_request)
        return Plan(trace_id=trace_id, goal="g", steps=[PlanStep(**s) for s in self.plan_steps])

    def review(self, step, done_when, masked_output):
        self.seen.append(masked_output)
        return self.reviews.pop(0)


@pytest.fixture(autouse=True)
def fake_local_llm(monkeypatch):
    def chat(system, user, json_mode=False):
        return json.dumps({"ok": True}) if json_mode else "TÓM TẮT: " + user[-80:]

    monkeypatch.setattr(local_llm, "_chat", chat)


WF2 = [
    dict(id=1, agent="finance", tool="mcp-erp.query_ar_aging", input={"as_of": "2026-11-02"}, runs_on="local", done_when="có bảng aging"),
    dict(id=2, agent="finance", tool="mcp-local-llm.summarize", input={"from_step": 1}, runs_on="local", done_when="tóm tắt"),
    dict(id=3, agent="finance", tool="claude.review", input={"from_step": 1}, runs_on="cloud", done_when="kiểm duyệt"),
    dict(id=4, agent="finance", tool="mcp-notify.draft_email",
         input={"from_step": 2, "to": ["bgd@thithi.vn"], "subject": "Báo cáo tuần"},
         runs_on="local", done_when="có nháp", approval=True),
]


def make(policy, agents, registry, brain):
    return Orchestrator(Gateway(policy), brain, agents, registry)


def test_wf2_runs_pauses_for_approval_and_never_leaks(policy, agents, registry):
    brain = FakeBrain(WF2)
    orch = make(policy, agents, registry, brain)
    state = orch.submit("ketoan.lan", {"finance"}, "finance", "Báo cáo công nợ, liên hệ kế toán 0912345678")
    assert state.status == "waiting_approval", state.error
    # Không giá trị thật nào lên cloud
    sent = "\n".join(brain.seen)
    assert "0912345678" not in sent and "<SDT_01>" in sent
    assert "Minh An" not in sent and "185000000" not in sent  # cột nhạy cảm của ERP bị che theo tên cột
    assert "<KH_01>" in sent and "<SO_TIEN_01>" in sent
    with pytest.raises(PermissionError):
        orch.approve(state.trace_id, 4, "ketoan.lan", True)
    state = orch.approve(state.trace_id, 4, "truongphong.kt", True)
    assert state.status == "done"
    assert state.outputs[4]["status"] == "draft"


def test_qa_failure_retries_once_then_fails(policy, agents, registry):
    bad = Review(score=2, passed=False, reasons=["thiếu số liệu"])
    brain = FakeBrain(WF2[:3], reviews=[bad, bad])
    state = make(policy, agents, registry, brain).submit("ketoan.lan", {"finance"}, "finance", "Báo cáo")
    assert state.status == "failed"
    assert "QA không đạt" in state.error


def test_plan_with_forbidden_tool_is_rejected_before_running(policy, agents, registry):
    brain = FakeBrain([dict(id=1, agent="finance", tool="mcp-docs.get_document",
                            input={"doc_id": "HD-MAU-01"}, runs_on="local", done_when="x")])
    state = make(policy, agents, registry, brain).submit("ketoan.lan", {"finance"}, "finance", "Lấy hợp đồng")
    assert state.status == "rejected"
    assert state.results == []


def test_wf1_is_local_only(policy, agents, registry):
    brain = FakeBrain([])
    state = make(policy, agents, registry, brain).submit("nhanvien.an", {"nhan_vien"}, "knowledge", "Quy trình nghỉ phép thế nào?")
    assert state.status == "done", state.error
    assert state.route == "local"
    assert brain.seen == []  # không gọi Claude
    assert state.outputs[2]["sources"][0] == "docs.quy_che/nghi_phep.docx"


def test_toi_mat_data_is_blocked_from_review(policy, agents, registry, monkeypatch):
    from thithi.mcp_servers import erp

    monkeypatch.setitem(erp._DEMO, "ar_aging", [])
    orch = make(policy, agents, registry, FakeBrain(WF2[:3]))
    original = orch._exec_local

    def leak_hr(state, step):
        original(state, step)
        state.sources[step.id] = ["hrm.payroll"]

    monkeypatch.setattr(orch, "_exec_local", leak_hr)
    state = orch.submit("ketoan.lan", {"finance"}, "finance", "x")
    assert state.status == "failed" and "không được gửi lên cloud" in state.error
