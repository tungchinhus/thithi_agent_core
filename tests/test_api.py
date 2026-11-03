import json

from fastapi.testclient import TestClient

from thithi.gateway import app as app_module
from thithi.mcp_servers import local_llm


def test_wf1_over_http(monkeypatch, tmp_path):
    monkeypatch.setenv("THITHI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("PRIVACY_URL", raising=False)
    monkeypatch.setenv("THITHI_ENV", "dev")
    monkeypatch.setenv("THITHI_NER", "off")
    monkeypatch.setattr(local_llm, "_chat", lambda system, user, json_mode=False: "Gửi đơn trước 3 ngày [QC-NP-01]")
    app_module.get_orchestrator.cache_clear()
    client = TestClient(app_module.app)

    assert client.post("/v1/requests", json={"agent": "knowledge", "text": "x"}, headers={"X-User-Id": "la"}).status_code == 401

    r = client.post("/v1/requests", json={"agent": "knowledge", "text": "Quy trình nghỉ phép?"}, headers={"X-User-Id": "nhanvien.an"})
    body = r.json()
    assert r.status_code == 200 and body["status"] == "done" and body["route"] == "local"
    assert "[QC-NP-01]" in body["results"][-1]["output"]["answer"]

    other = client.get(f"/v1/requests/{body['trace_id']}", headers={"X-User-Id": "hanhchinh.mai"})
    assert other.status_code == 404

    log = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {e["event"] for e in log} >= {"submitted", "step_done", "done"}
    assert not any(e["event"] == "outbound" for e in log)  # WF1 không gửi gì lên cloud
    app_module.get_orchestrator.cache_clear()
