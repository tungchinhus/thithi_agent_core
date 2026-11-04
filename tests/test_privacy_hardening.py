"""Các lỗi tìm thấy khi rà PR #1-#3 và phần mở rộng của Privacy Vault."""

import json
import threading
import unicodedata
from pathlib import Path

import httpx
import pytest

from thithi.gateway.service import Gateway
from thithi.orchestrator.models import Plan, PlanStep, Review
from thithi.orchestrator.registry import ToolSpec
from thithi.orchestrator.runner import Orchestrator
from thithi.privacy.client import HttpPrivacyClient, PrivacyUnavailable
from thithi.privacy.engine import AccessLog, PrivacyConfig, PrivacyEngine, build_engine
from thithi.privacy.evaluate import evaluate, load_samples, main
from thithi.privacy.masking import Masker, new_trace_vault
from thithi.privacy.ner import LocalLlmNer
from thithi.privacy.pii import KeywordDetector, PiiScanner
from thithi.privacy.vault import InMemoryVault, SqliteVault

SAMPLES = Path(__file__).parent / "data" / "pii_samples.jsonl"


def fake_ner(entities):
    return LocalLlmNer(lambda s, u, json_mode=False: json.dumps({"entities": entities}))


# ---------- nhận diện ----------

def test_ner_matches_decomposed_vietnamese_text():
    """Văn bản dạng NFD (Word/macOS) vẫn phải che được tên LLM trả về ở dạng NFC."""
    text = unicodedata.normalize("NFD", "Chị Trần Thị Lan gọi lại")
    m, v = Masker(ner=fake_ner([{"text": "Trần Thị Lan", "type": "PERSON"}])), new_trace_vault()
    out = m.mask_payload(text, v)
    assert out == "Chị <NGUOI_01> gọi lại"


def test_known_name_does_not_mask_inside_other_words():
    m = Masker(PiiScanner(extra=[KeywordDetector({"An": "NGUOI"})]))
    out = m.mask("Ban giám đốc duyệt cho An, mang theo bản thanh toán", new_trace_vault())
    assert out == "Ban giám đốc duyệt cho <NGUOI_01>, mang theo bản thanh toán"


@pytest.mark.parametrize(
    "text, leaked",
    [
        ("Văn phòng 028 3822 1234", "028 3822 1234"),  # số cố định 11 chữ số
        ("TK 0071000123456 Vietcombank", "0071000123456"),
        ("STK 1903 4567 8901 23", "1903 4567 8901 23"),
        ("Mã số thuế là 0312345678", "0312345678"),
        ("Thưởng 500k", "500k"),
    ],
)
def test_regex_gaps_found_in_review_are_closed(text, leaked):
    out = Masker().mask(text, new_trace_vault())
    assert leaked not in out


def test_cccd_is_not_split_into_a_phone_number():
    out = Masker().mask("CCCD 001203004567", new_trace_vault())
    assert out == "CCCD <CCCD_01>"


# ---------- kho ánh xạ ----------

def test_expired_entry_is_reissued_not_reused(tmp_path):
    v = SqliteVault(tmp_path / "v.db", SqliteVault.generate_key(), ttl_hours=-1)
    v.for_trace("T").surrogate_for("SDT", "0912345678")
    v.ttl = 3600
    # Trước đây trả lại token đã hết hạn (không tái tạo được) hoặc vướng khoá chính
    s = v.for_trace("T").surrogate_for("SDT", "0912345678")
    assert v.for_trace("T").mapping() == {s: "0912345678"}


def test_sqlite_vault_is_thread_safe(tmp_path):
    v = SqliteVault(tmp_path / "v.db", SqliteVault.generate_key())
    errors = []

    def work(i):
        try:
            for j in range(30):
                v.for_trace("T").surrogate_for("SDT", f"09{i:02d}{j:06d}")
                v.for_trace("T").mapping()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(v.for_trace("T").mapping()) == 240


def test_mask_payload_reads_vault_once():
    class Counting(InMemoryVault):
        reads = 0

        def for_trace(self, trace_id):
            tv = super().for_trace(trace_id)
            outer = self

            class Wrapped:
                def surrogate_for(self, kind, value):
                    return tv.surrogate_for(kind, value)

                def mapping(self):
                    outer.reads += 1
                    return tv.mapping()

            return Wrapped()

    vault = Counting()
    engine = PrivacyEngine(vault, Masker(), require_ner=False)
    engine.mask("T", {"rows": [{"note": f"gọi 09123456{i:02d}"} for i in range(50)]})
    assert vault.reads <= 5  # không tăng theo số chuỗi; trước đây mỗi chuỗi một lần giải mã toàn bộ kho (>50)


# ---------- client HTTP ----------

def test_client_handles_non_json_errors_from_proxy():
    transport = httpx.MockTransport(lambda req: httpx.Response(503, text="<html>Service Unavailable</html>"))
    client = HttpPrivacyClient("http://vault", "t", http=httpx.Client(base_url="http://vault", transport=transport))
    with pytest.raises(PrivacyUnavailable):
        client.mask("T", "x")
    with pytest.raises(PrivacyUnavailable):
        client.purge("T")


# ---------- orchestrator ----------

def test_local_tools_receive_real_values_not_tokens(policy, agents, registry):
    """Claude chỉ thấy <KH_01>; công cụ local phải nhận lại tên thật để tra ERP."""
    seen = {}

    def lookup(user_id: str, customer: str) -> dict:
        seen["customer"] = customer
        return {"label": "mat", "source": "erp.ar_aging", "rows": []}

    registry.register(ToolSpec("mcp-erp.lookup_customer", lookup, description="tra khách hàng"))
    agents["finance"].tools.append("mcp-erp.lookup_customer")

    class Brain:
        def plan(self, trace_id, masked_request, catalog, feedback=None):
            assert "Công ty Minh An" not in masked_request
            token = masked_request.split("khách ")[1].split(" ")[0]
            return Plan(trace_id=trace_id, goal="g", steps=[
                PlanStep(id=1, agent="finance", tool="mcp-erp.lookup_customer", input={"customer": token},
                         runs_on="local", done_when="x"),
            ])

        def review(self, *a):
            return Review(score=5, passed=True, reasons=[])

    engine = PrivacyEngine(InMemoryVault(), Masker(ner=fake_ner([{"text": "Công ty Minh An", "type": "ORG"}])))
    orch = Orchestrator(Gateway(policy, engine), Brain(), agents, registry)
    state = orch.submit("ketoan.lan", {"finance"}, "finance", "Tra công nợ khách Công ty Minh An giúp em")
    assert state.status == "done", state.error
    assert seen["customer"] == "Công ty Minh An"


# ---------- cấu hình, nhật ký, nghiệm thu ----------

def test_config_adds_known_names_and_sensitive_columns(tmp_path):
    names = tmp_path / "danh_ba.csv"
    names.write_text("name,kind\nNguyễn Văn Bình,NGUOI\nCông ty Hải Âu,KH\n", encoding="utf-8")
    cfg_file = tmp_path / "privacy.yaml"
    cfg_file.write_text(f"mode: token\nknown_names: {names}\nsensitive_keys:\n  ma_nv: NV\n", encoding="utf-8")
    masker = PrivacyConfig.from_yaml(cfg_file).masker(ner=None)
    v = new_trace_vault()
    assert masker.mask("Anh Nguyễn Văn Bình bên Công ty Hải Âu", v) == "Anh <NGUOI_01> bên <KH_01>"
    assert masker.mask_obj({"ma_nv": "NV0012", "x": 1}, v) == {"ma_nv": "<NV_01>", "x": 1}


def test_access_log_records_who_restored_but_never_values(tmp_path):
    log = AccessLog(tmp_path / "access.jsonl")
    engine = PrivacyEngine(InMemoryVault(), Masker(), require_ner=False, access_log=log)
    out = engine.mask("T1", "Gọi 0912345678", actor="gateway")
    engine.unmask("T1", out, actor="ketoan.lan")
    engine.purge("T1", actor="ketoan.lan")
    raw = (tmp_path / "access.jsonl").read_text(encoding="utf-8")
    assert "0912345678" not in raw and "<SDT_01>" not in raw
    events = [json.loads(line) for line in raw.splitlines()]
    assert [e["event"] for e in events] == ["mask", "unmask", "purge"]
    assert events[1]["actor"] == "ketoan.lan" and events[1]["restored"] == 1


def test_evaluate_seed_samples_pass():
    engine = PrivacyEngine(InMemoryVault(), Masker(), require_ner=False)
    report = evaluate(engine, load_samples(SAMPLES))
    assert report.passed, report.summary()
    assert report.recall == 1.0 and report.over_masked == 0


def test_evaluate_reports_leaks_without_printing_values(tmp_path, capsys, monkeypatch):
    f = tmp_path / "s.jsonl"
    f.write_text(json.dumps({"id": "x", "text": "Chị Hoa ở Huế", "pii": ["Hoa"]}, ensure_ascii=False) + "\n", encoding="utf-8")
    monkeypatch.setenv("THITHI_ENV", "dev")
    monkeypatch.setenv("THITHI_NER", "off")
    assert main([str(f)]) == 1
    out = capsys.readouterr().out
    assert "RÒ RỈ" in out and "Hoa" not in out


def test_build_engine_in_memory_ignores_real_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVACY_VAULT_DB", str(tmp_path / "real.db"))
    monkeypatch.setenv("THITHI_ENV", "dev")
    monkeypatch.setenv("THITHI_NER", "off")
    build_engine(in_memory=True)
    assert not (tmp_path / "real.db").exists()
