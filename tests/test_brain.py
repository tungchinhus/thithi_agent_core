import json
from types import SimpleNamespace

import pytest

from thithi.cloud.brain import ClaudeBrain, CloudError
from thithi.orchestrator.models import PlanStep


class FakeMessages:
    def __init__(self, payload, stop_reason="end_turn"):
        self.payload, self.stop_reason, self.calls = payload, stop_reason, []

    def create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(stop_reason=self.stop_reason, content=[SimpleNamespace(type="text", text=json.dumps(self.payload))])


def brain_with(payload, stop_reason="end_turn"):
    msgs = FakeMessages(payload, stop_reason)
    return ClaudeBrain(client=SimpleNamespace(beta=SimpleNamespace(messages=msgs))), msgs


def test_plan_parses_input_json_and_sends_cacheable_system():
    b, msgs = brain_with({"goal": "g", "steps": [{"id": 1, "agent": "finance", "tool": "mcp-erp.query_ar_aging",
                                                  "input_json": "{\"as_of\": \"2026-11-02\"}", "runs_on": "local",
                                                  "done_when": "x", "approval": False}]})
    plan = b.plan("T1", "yêu cầu <SDT_01>", [])
    assert plan.steps[0].input == {"as_of": "2026-11-02"}
    call = msgs.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert call["fallbacks"] == "default"


def test_refusal_raises():
    b, _ = brain_with({}, stop_reason="refusal")
    with pytest.raises(CloudError):
        b.review(PlanStep(id=1, agent="a", tool="t", runs_on="local", done_when="x"), "x", "out")
