"""LLM local tái tạo/soát lại, số đo, giám sát và lệnh quản trị của Privacy Vault."""

import json
import os
import stat

import httpx
import pytest
from fastapi.testclient import TestClient

from thithi.privacy import api as privacy_api
from thithi.privacy import monitor
from thithi.privacy.admin import main as admin
from thithi.privacy.engine import PrivacyEngine
from thithi.privacy.masking import Masker
from thithi.privacy.metrics import Metrics, parse
from thithi.privacy.ner import LocalLlmNer, NerUnavailable
from thithi.privacy.restore import RestorePlan, SmartRestorer
from thithi.privacy.surrogates import PSEUDONYM, SurrogatePolicy
from thithi.privacy.vault import InMemoryVault, SqliteVault

MAPPING = {
    "Hoàng Minh Khôi": "Trần Thị Lan",
    "Công ty TNHH Sao Mai": "Công ty Minh An",
    "0900 000 001": "0912345678",
    "<SO_TIEN_01>": "125.000.000 đ",
    "lienhe01@example.vn": "lan@minhan.vn",
}


def ner(entities):
    return LocalLlmNer(lambda s, u, json_mode=False: json.dumps({"entities": entities}))


# ---------- tái tạo ----------

@pytest.mark.parametrize(
    "reply, expected",
    [
        ("Gọi anh Khôi (0900000001) bên Sao Mai để chốt so_tien_01.", "Gọi anh Lan (0912345678) bên Minh An để chốt 125.000.000 đ."),
        ("Minh Khôi xác nhận [SO_TIEN_01], mail LIENHE01@example.vn", "Lan xác nhận 125.000.000 đ, mail lan@minhan.vn"),
        ("Hoàng Minh Khôi, Công ty TNHH Sao Mai: <SO_TIEN_01>", "Trần Thị Lan, Công ty Minh An: 125.000.000 đ"),
        ("Họp ở Hà Nội, khôi phục số liệu", "Họp ở Hà Nội, khôi phục số liệu"),  # không đụng chữ thường
    ],
)
def test_restores_rewritten_surrogates_without_llm(reply, expected):
    out, stats = SmartRestorer().restore(reply, RestorePlan.build(MAPPING))
    assert out == expected
    assert stats.unresolved == 0


def test_given_name_alone_needs_llm_and_is_counted_when_missing():
    plan = RestorePlan.build(MAPPING)
    out, stats = SmartRestorer().restore("Khôi đã gửi hồ sơ", plan)
    assert out == "Khôi đã gửi hồ sơ" and stats.unresolved == 1


def test_local_llm_restores_only_suspect_lines_and_result_is_checked():
    sent = []

    def chat(system, user, json_mode=False):
        lines = json.loads(user.split("Các dòng cần khôi phục:\n")[1])["lines"]
        sent.append(lines)
        assert "Trần Thị Lan" in user  # bảng ánh xạ chỉ đi tới LLM local
        return json.dumps({"lines": [line.replace("Khôi", "Lan") for line in lines]})

    out, stats = SmartRestorer(chat).restore("Khôi đã gửi hồ sơ\nDòng không liên quan", RestorePlan.build(MAPPING))
    assert out == "Lan đã gửi hồ sơ\nDòng không liên quan"
    assert sent == [["Khôi đã gửi hồ sơ"]] and stats.llm_lines == 1 and stats.unresolved == 0


def test_llm_rewrite_that_changes_meaning_is_rejected():
    def chat(system, user, json_mode=False):
        return json.dumps({"lines": ["Đã chuyển 999 tỷ cho một người hoàn toàn khác ở nơi khác"]})

    out, stats = SmartRestorer(chat).restore("Khôi đã gửi hồ sơ", RestorePlan.build(MAPPING))
    assert out == "Khôi đã gửi hồ sơ" and stats.unresolved == 1


def test_llm_failure_does_not_break_unmask():
    def chat(*a, **k):
        raise ConnectionError("ai-local chết")

    out, stats = SmartRestorer(chat).restore("Khôi, <SO_TIEN_01>", RestorePlan.build(MAPPING))
    assert out == "Khôi, 125.000.000 đ" and stats.llm_error and stats.unresolved == 1


def test_restored_real_value_is_not_rematched():
    # Tên thật chứa chữ giống tên gọi của giá trị giả: không bị nghi, không gọi LLM
    plan = RestorePlan.build({"Hoàng Minh Khôi": "Lê Văn Khôi"})

    def chat(*a, **k):
        raise AssertionError("không được gọi LLM")

    out, stats = SmartRestorer(chat).restore("Gặp Hoàng Minh Khôi", plan)
    assert out == "Gặp Lê Văn Khôi" and stats.unresolved == 0


def test_engine_pseudonym_roundtrip_through_claude_paraphrase():
    e = PrivacyEngine(InMemoryVault(SurrogatePolicy(PSEUDONYM)), Masker(ner=ner([{"text": "Trần Thị Lan", "type": "PERSON"}])))
    masked = e.mask("T1", "Chị Trần Thị Lan gọi 0912345678")
    assert masked == "Chị Hoàng Minh Khôi gọi 0900 000 001"
    reply = {"tom_tat": "Đề nghị chị Khôi gọi lại số 0900000001"}
    assert e.unmask("T1", reply) == {"tom_tat": "Đề nghị chị Lan gọi lại số 0912345678"}
    assert e.metrics.get("thithi_vault_restored_total", method="variant") == 2


# ---------- soát lại bằng LLM local ----------

def test_recheck_masks_what_first_ner_missed():
    first = ner([{"text": "Trần Thị Lan", "type": "PERSON"}])
    second = ner([{"text": "Phạm Quốc Việt", "type": "PERSON"}, {"text": "<NGUOI_01>", "type": "PERSON"}])
    e = PrivacyEngine(InMemoryVault(), Masker(ner=first), recheck=second)
    out = e.mask("T1", "Chị Trần Thị Lan và anh Phạm Quốc Việt")
    assert out == "Chị <NGUOI_01> và anh <NGUOI_02>"
    assert e.metrics.get("thithi_vault_recheck_found_total") == 1
    assert e.unmask("T1", out) == "Chị Trần Thị Lan và anh Phạm Quốc Việt"


def test_recheck_ignores_pseudonyms_it_sees():
    first = ner([{"text": "Trần Thị Lan", "type": "PERSON"}])
    second = ner([{"text": "Hoàng Minh Khôi", "type": "PERSON"}, {"text": "Khôi", "type": "PERSON"}])
    e = PrivacyEngine(InMemoryVault(SurrogatePolicy(PSEUDONYM)), Masker(ner=first), recheck=second)
    assert e.mask("T1", "Chị Trần Thị Lan") == "Chị Hoàng Minh Khôi"
    assert e.metrics.get("thithi_vault_recheck_found_total") == 0


def test_recheck_failure_blocks():
    def down(*a, **k):
        raise ConnectionError("x")

    e = PrivacyEngine(InMemoryVault(), Masker(ner=ner([])), recheck=LocalLlmNer(down))
    with pytest.raises(NerUnavailable):
        e.mask("T1", "Nội dung bất kỳ")
    assert e.metrics.get("thithi_vault_mask_total", result="ner_unavailable") == 1
    assert e.metrics.get("thithi_vault_llm_errors_total", step="recheck") == 1


# ---------- số đo, readyz ----------

@pytest.fixture
def vault_client(monkeypatch):
    monkeypatch.setenv("PRIVACY_SERVICE_TOKEN", "s3cret")
    holder = {}

    def make(ping=None):
        holder["e"] = PrivacyEngine(InMemoryVault(), Masker(), require_ner=False, llm_ping=ping)
        privacy_api.app.dependency_overrides[privacy_api.get_engine] = lambda: holder["e"]
        return TestClient(privacy_api.app), holder["e"]

    yield make
    privacy_api.app.dependency_overrides.clear()


def test_metrics_endpoint_has_counts_but_no_values(vault_client):
    client, _ = vault_client()
    h = {"X-Service-Token": "s3cret"}
    out = client.post("/v1/mask", json={"trace_id": "T", "payload": "Gọi 0912345678"}, headers=h).json()["payload"]
    client.post("/v1/unmask", json={"trace_id": "T", "payload": out}, headers=h)
    text = client.get("/metrics").text
    assert "0912345678" not in text and "<SDT_01>" not in text and '"T"' not in text
    m = parse(text)
    assert m['thithi_vault_mask_total{result="ok"}'] == 1
    assert m['thithi_vault_restored_total{method="exact"}'] == 1
    assert m["thithi_vault_mask_seconds_count"] == 1


def test_readyz_reports_llm_down(vault_client):
    def ping():
        raise httpx.ConnectError("refused")

    client, _ = vault_client(ping)
    resp = client.get("/readyz")
    assert resp.status_code == 503 and resp.json()["checks"]["llm"].startswith("lỗi")
    client, _ = vault_client(lambda: None)
    assert client.get("/readyz").json() == {"ready": True, "checks": {"vault": "ok", "llm": "ok"}}


# ---------- giám sát ----------

def snap(ok=0, ner_=0, leak=0, unresolved=0, found=0, restore_err=0):
    return {
        'thithi_vault_mask_total{result="ok"}': ok,
        'thithi_vault_mask_total{result="ner_unavailable"}': ner_,
        'thithi_vault_mask_total{result="leak"}': leak,
        "thithi_vault_unresolved_total": unresolved,
        "thithi_vault_recheck_found_total": found,
        'thithi_vault_llm_errors_total{step="restore"}': restore_err,
    }


def test_monitor_rules():
    assert monitor.evaluate(snap(ok=100), {}) == []  # lần đầu chỉ ghi mốc
    assert monitor.evaluate(snap(ok=110), snap(ok=100)) == []
    alerts = monitor.evaluate(snap(ok=105, ner_=5, unresolved=2, found=1), snap(ok=100))
    assert any("bị chặn" in a for a in alerts)
    assert any("không tái tạo được" in a for a in alerts)
    assert any("bỏ sót" in a for a in alerts)
    assert monitor.evaluate(snap(ok=3), snap(ok=100, unresolved=5)) == []  # Vault khởi động lại


def test_monitor_run_alerts_via_webhook(tmp_path):
    posted = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/readyz":
            return httpx.Response(503, json={"ready": False, "checks": {"vault": "ok", "llm": "lỗi: ConnectError"}})
        if req.url.path == "/metrics":
            return httpx.Response(200, text=Metrics().render())
        posted.append(json.loads(req.content))
        return httpx.Response(200)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    import thithi.privacy.monitor as mon

    orig = mon.httpx.post
    mon.httpx.post = lambda url, json, timeout: http.post(url, json=json)
    try:
        code = mon.run("http://vault", tmp_path / "s.json", "http://hook/x", "teams", 0.2, http=http)
    finally:
        mon.httpx.post = orig
    assert code == 2
    card = posted[0]["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and "llm=lỗi" in json.dumps(card, ensure_ascii=False)


def test_monitor_alerts_when_vault_unreachable(tmp_path, capsys):
    http = httpx.Client(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))
    assert monitor.run("http://vault", tmp_path / "s.json", None, "text", 0.2, http=http) == 2
    assert "Không gọi được Privacy Vault" in capsys.readouterr().out


# ---------- quản trị ----------

def test_admin_init_writes_private_env_and_refuses_overwrite(tmp_path, capsys):
    env = tmp_path / "vault.env"
    assert admin(["init", "--env", str(env), "--template", "vault.env.example"]) == 0
    assert stat.S_IMODE(os.stat(env).st_mode) == 0o600
    values = dict(line.split("=", 1) for line in env.read_text().splitlines() if "=" in line and not line.startswith("#"))
    assert values["PRIVACY_VAULT_KEY"] and len(values["PRIVACY_SERVICE_TOKEN"]) >= 32
    assert "PRIVACY_ACCESS_LOG" in values  # giữ các dòng của file mẫu
    assert values["PRIVACY_VAULT_KEY"] not in capsys.readouterr().out  # không in khoá
    assert admin(["init", "--env", str(env)]) == 1


def test_rotate_key_reencrypts_and_old_key_stops_working(tmp_path, monkeypatch):
    from cryptography.fernet import InvalidToken

    db, env = tmp_path / "vault" / "v.db", tmp_path / "vault.env"
    old = SqliteVault.generate_key()
    env.write_text(f"PRIVACY_VAULT_KEY={old}\nPRIVACY_VAULT_DB={db}\n")
    v = SqliteVault(db, old)
    s = v.for_trace("T").surrogate_for("SDT", "0912345678")
    monkeypatch.setenv("PRIVACY_VAULT_DB", str(db))
    assert admin(["rotate-key", "--env", str(env)]) == 0
    new = dict(line.split("=", 1) for line in env.read_text().splitlines())["PRIVACY_VAULT_KEY"]
    assert new != old
    rotated = SqliteVault(db, new)
    assert rotated.for_trace("T").mapping() == {s: "0912345678"}
    assert rotated.for_trace("T").surrogate_for("SDT", "0912345678") == s  # chỉ mục HMAC cũng được làm lại
    with pytest.raises(InvalidToken):
        SqliteVault(db, old).for_trace("T").mapping()
    assert list((tmp_path / "vault").glob("v.db.bak-*")) and list((tmp_path / "vault").glob("vault.env.bak-*"))


def test_admin_purge_expired(tmp_path, monkeypatch, capsys):
    db, key = tmp_path / "v.db", SqliteVault.generate_key()
    SqliteVault(db, key, ttl_hours=-1).for_trace("T").surrogate_for("SDT", "0912345678")
    monkeypatch.setenv("PRIVACY_VAULT_DB", str(db))
    monkeypatch.setenv("PRIVACY_VAULT_KEY", key)
    assert admin(["purge-expired"]) == 0
    assert "Đã xoá 1" in capsys.readouterr().out


# ---------- nghiệm thu: câu trả lời viết lại, thời gian, file mẫu ----------

def _oracle_ner(samples):
    """NER 'hoàn hảo' giả lập: biết mọi tên trong bộ mẫu (để thử công cụ đo, không phải đo NER)."""
    from thithi.privacy.pii import PATTERNS

    names = {}
    for s in samples:
        for value in s["pii"]:
            if any(p.search(value) for p in PATTERNS.values()):
                continue
            kind = "ORG" if value.split()[0] in ("Công", "Cửa") else "ADDRESS" if value[0].isdigit() else "PERSON"
            names[value] = kind
    return LocalLlmNer(lambda s, u, json_mode=False: json.dumps(
        {"entities": [{"text": k, "type": t} for k, t in names.items() if k in u]}, ensure_ascii=False))


@pytest.mark.parametrize("mode", ["token", PSEUDONYM])
def test_example_sample_file_passes_with_perfect_ner(mode):
    from thithi.privacy.evaluate import evaluate, load_samples

    samples = load_samples("config/pii_samples.example.jsonl")
    engine = PrivacyEngine(InMemoryVault(SurrogatePolicy(mode)), Masker(ner=_oracle_ner(samples)))
    report = evaluate(engine, samples)
    assert report.passed, report.summary()
    assert report.replies_total == 4 and report.replies_ok == 4
    assert "Thời gian che" in report.summary()


def test_reply_failures_are_reported_by_index_only():
    from thithi.privacy.evaluate import evaluate

    sample = {"id": "x", "text": "Chị Trần Thị Lan gọi 0912345678", "pii": ["Trần Thị Lan", "0912345678"],
              "replies": ["{0:ten} đã gọi"]}  # tên gọi đứng một mình, không có LLM local: không tái tạo được
    engine = PrivacyEngine(InMemoryVault(SurrogatePolicy(PSEUDONYM)), Masker(ner=ner([{"text": "Trần Thị Lan", "type": "PERSON"}])))
    report = evaluate(engine, [sample])
    assert not report.passed and report.replies_ok == 0
    summary = report.summary()
    assert "replies'): 0" in summary and "Lan" not in summary
