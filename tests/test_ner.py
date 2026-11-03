import json

import pytest

from thithi.gateway.labels import LabelPolicy
from thithi.gateway.service import Blocked, Gateway
from thithi.privacy.engine import PrivacyEngine
from thithi.privacy.masking import Masker, new_trace_vault
from thithi.privacy.ner import LocalLlmNer, NerUnavailable
from thithi.privacy.vault import InMemoryVault


def fake_llm(entities):
    calls = []

    def chat(system, user, json_mode=False):
        calls.append(user)
        return json.dumps({"entities": entities})

    chat.calls = calls
    return chat


TEXT = "Chị Trần Thị Lan bên Công ty Minh An (12 Lê Lợi, Quận 1) xin gia hạn công nợ, gọi 0912345678."


def test_masks_names_found_by_local_llm():
    chat = fake_llm([
        {"text": "Trần Thị Lan", "type": "PERSON"},
        {"text": "Công ty Minh An", "type": "ORG"},
        {"text": "12 Lê Lợi, Quận 1", "type": "ADDRESS"},
    ])
    m, v = Masker(ner=LocalLlmNer(chat)), new_trace_vault()
    out = m.mask_payload(TEXT, v)
    assert out == "Chị <NGUOI_01> bên <CTY_01> (<DIA_CHI_01>) xin gia hạn công nợ, gọi <SDT_01>."
    assert m.unmask(out, v) == TEXT


def test_ner_runs_once_per_payload_and_covers_nested_strings():
    chat = fake_llm([{"text": "Minh An", "type": "ORG"}])
    m, v = Masker(ner=LocalLlmNer(chat)), new_trace_vault()
    out = m.mask_payload({"rows": [{"note": "Khách Minh An hẹn trả"}, {"note": "Minh An gọi lại"}]}, v)
    assert len(chat.calls) == 1
    assert out == {"rows": [{"note": "Khách <CTY_01> hẹn trả"}, {"note": "<CTY_01> gọi lại"}]}


def test_ignores_hallucinated_or_unknown_entities():
    chat = fake_llm([
        {"text": "Nguyễn Văn Bịa", "type": "PERSON"},  # không có trong văn bản
        {"text": "Lan", "type": "PET"},  # loại không hỗ trợ
        {"text": "A", "type": "PERSON"},  # quá ngắn
    ])
    assert LocalLlmNer(chat).extract(TEXT) == {}


@pytest.mark.parametrize("reply", ["không phải json", json.dumps({"wrong": []})])
def test_bad_llm_output_raises(reply):
    with pytest.raises(NerUnavailable):
        LocalLlmNer(lambda s, u, json_mode=False: reply).extract(TEXT)


def test_gateway_fails_closed_when_local_llm_is_down(policy):
    def down(system, user, json_mode=False):
        raise ConnectionError("ai-local không phản hồi")

    gw = Gateway(policy, PrivacyEngine(InMemoryVault(), Masker(ner=LocalLlmNer(down))))
    with pytest.raises(Blocked, match="che được tên riêng"):
        gw.outbound("T1", TEXT, ["user.request"], purpose="plan")
    assert gw.audit.entries[-1]["event"] == "ner_blocked"
    assert not any(e["event"] == "outbound" for e in gw.audit.entries)


def test_raw_public_data_skips_ner(tmp_path):
    p = tmp_path / "labels.yaml"
    p.write_text("sources:\n  docs.public/*: {label: cong_khai, allow_cloud: raw}\n", encoding="utf-8")
    calls = []
    ner = LocalLlmNer(lambda *a, **k: calls.append(1) or "{}")
    gw = Gateway(LabelPolicy.from_yaml(p), PrivacyEngine(InMemoryVault(), Masker(ner=ner)))
    assert gw.outbound("T1", "Giới thiệu công ty", ["docs.public/a.pdf"], purpose="plan") == "Giới thiệu công ty"
    assert calls == []
