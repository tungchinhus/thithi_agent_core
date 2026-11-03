import json

import pytest
from cryptography.fernet import InvalidToken
from fastapi.testclient import TestClient

from thithi.gateway.service import Blocked, Gateway
from thithi.privacy import api as privacy_api
from thithi.privacy.client import HttpPrivacyClient, PrivacyUnavailable
from thithi.privacy.engine import PrivacyEngine
from thithi.privacy.masking import Masker
from thithi.privacy.ner import LocalLlmNer, NerUnavailable
from thithi.privacy.surrogates import PSEUDONYM, SurrogatePolicy
from thithi.privacy.vault import InMemoryVault, SqliteVault

TEXT = "Chị Trần Thị Lan bên Công ty Minh An, SĐT 0912345678, email lan@minhan.vn, còn nợ 125.000.000 đ."
ENTITIES = [{"text": "Trần Thị Lan", "type": "PERSON"}, {"text": "Công ty Minh An", "type": "ORG"}]


def ner(entities=ENTITIES):
    return LocalLlmNer(lambda s, u, json_mode=False: json.dumps({"entities": entities}))


def engine(mode="token", vault=None, entities=ENTITIES):
    return PrivacyEngine(vault or InMemoryVault(SurrogatePolicy(mode)), Masker(ner=ner(entities)))


def test_token_mode_roundtrip():
    e = engine()
    out = e.mask("T1", TEXT)
    assert out == "Chị <NGUOI_01> bên <CTY_01>, SĐT <SDT_01>, email <EMAIL_01>, còn nợ <SO_TIEN_01>."
    assert e.unmask("T1", out) == TEXT


def test_pseudonym_mode_swaps_to_realistic_fakes_and_restores():
    e = engine(PSEUDONYM)
    out = e.mask("T1", TEXT)
    assert out == ("Chị Hoàng Minh Khôi bên Công ty TNHH Sao Mai, SĐT 0900 000 001, "
                   "email lienhe01@example.vn, còn nợ <SO_TIEN_01>.")  # số tiền luôn dùng token
    # Claude viết lại câu khác nhưng giữ nguyên giá trị giả -> tái tạo đúng
    reply = "Đề nghị gọi Hoàng Minh Khôi (0900 000 001) của Công ty TNHH Sao Mai để chốt <SO_TIEN_01>."
    assert e.unmask("T1", reply) == "Đề nghị gọi Trần Thị Lan (0912345678) của Công ty Minh An để chốt 125.000.000 đ."


def test_pseudonyms_are_not_masked_again():
    e = engine(PSEUDONYM, entities=[{"text": "Trần Thị Lan", "type": "PERSON"}])
    first = e.mask("T1", "Gọi Trần Thị Lan 0912345678")
    # Lần sau payload chứa chính giá trị giả (vd. Plan của Claude quay về): không sinh ánh xạ chồng
    again = PrivacyEngine(e.vault, Masker(ner=ner([{"text": "Hoàng Minh Khôi", "type": "PERSON"}]))).mask("T1", first)
    assert again == first
    assert len(e.vault.for_trace("T1").mapping()) == 2


def test_pseudonym_never_collides_with_a_real_value():
    e = engine(PSEUDONYM, entities=[{"text": "Hoàng Minh Khôi", "type": "PERSON"}, {"text": "Trần Thị Lan", "type": "PERSON"}])
    out = e.mask("T1", "Hoàng Minh Khôi và Trần Thị Lan")
    mapping = e.vault.for_trace("T1").mapping()
    assert len(set(mapping)) == 2 and "Hoàng Minh Khôi" not in mapping  # tên thật không bị dùng làm tên giả
    assert e.unmask("T1", out) == "Hoàng Minh Khôi và Trần Thị Lan"


def test_traces_are_isolated():
    e = engine()
    e.mask("A", TEXT)
    assert e.unmask("B", "<NGUOI_01>") == "<NGUOI_01>"


def test_ner_is_mandatory_by_default():
    with pytest.raises(ValueError, match="NER"):
        PrivacyEngine(InMemoryVault(), Masker())


def test_sqlite_vault_is_encrypted_persistent_and_purgeable(tmp_path):
    key = SqliteVault.generate_key()
    db = tmp_path / "vault.db"
    e = engine(PSEUDONYM, vault=SqliteVault(db, key, SurrogatePolicy(PSEUDONYM)))
    out = e.mask("T1", TEXT)
    raw = db.read_bytes()
    for secret in ("Trần Thị Lan", "0912345678", "lan@minhan.vn"):
        assert secret.encode() not in raw
    # Khởi động lại dịch vụ: vẫn tái tạo được bằng đúng khoá
    reopened = engine(PSEUDONYM, vault=SqliteVault(db, key, SurrogatePolicy(PSEUDONYM)))
    assert reopened.unmask("T1", out) == TEXT
    # Sai khoá thì không giải mã được
    with pytest.raises(InvalidToken):
        SqliteVault(db, SqliteVault.generate_key()).for_trace("T1").mapping()
    reopened.purge("T1")
    assert reopened.unmask("T1", out) == out


def test_sqlite_vault_expires(tmp_path):
    v = SqliteVault(tmp_path / "v.db", SqliteVault.generate_key(), ttl_hours=-1)
    v.for_trace("T1").surrogate_for("SDT", "0912345678")
    assert v.for_trace("T1").mapping() == {}
    assert v.purge_expired() == 1


@pytest.fixture
def vault_api(monkeypatch):
    monkeypatch.setenv("PRIVACY_SERVICE_TOKEN", "s3cret")
    shared = engine()
    privacy_api.app.dependency_overrides[privacy_api.get_engine] = lambda: shared
    yield TestClient(privacy_api.app), shared
    privacy_api.app.dependency_overrides.clear()


def test_api_requires_service_token(vault_api):
    client, _ = vault_api
    assert client.post("/v1/mask", json={"trace_id": "T", "payload": "x"}, headers={"X-Service-Token": "sai"}).status_code == 401


def test_gateway_uses_vault_over_http_and_never_holds_mapping(vault_api, policy):
    http, shared = vault_api
    gw = Gateway(policy, HttpPrivacyClient("http://vault", "s3cret", http=http))
    sent = gw.outbound("T1", {"note": TEXT}, ["user.request"], purpose="plan")
    assert "Trần Thị Lan" not in sent and "<NGUOI_01>" in sent
    assert not hasattr(gw, "vaults")  # Gateway không có kho ánh xạ
    assert gw.inbound("T1", "Liên hệ <NGUOI_01>") == "Liên hệ Trần Thị Lan"


def test_gateway_blocks_when_vault_ner_fails(vault_api, policy):
    http, shared = vault_api

    def down(*a, **k):
        raise ConnectionError("ai-local chết")

    privacy_api.app.dependency_overrides[privacy_api.get_engine] = lambda: PrivacyEngine(InMemoryVault(), Masker(ner=LocalLlmNer(down)))
    gw = Gateway(policy, HttpPrivacyClient("http://vault", "s3cret", http=http))
    with pytest.raises(Blocked, match="tên riêng"):
        gw.outbound("T1", TEXT, ["user.request"], purpose="plan")


def test_gateway_blocks_when_vault_unreachable(policy):
    client = HttpPrivacyClient("http://127.0.0.1:9", "x", timeout=0.5)
    with pytest.raises(PrivacyUnavailable):
        client.mask("T1", TEXT)
    gw = Gateway(policy, client)
    with pytest.raises(Blocked):
        gw.outbound("T1", TEXT, ["user.request"], purpose="plan")
    assert issubclass(PrivacyUnavailable, NerUnavailable)


def test_gateway_app_refuses_to_start_without_vault(monkeypatch):
    from thithi.gateway import app as gw_app

    monkeypatch.delenv("PRIVACY_URL", raising=False)
    monkeypatch.delenv("THITHI_ENV", raising=False)
    with pytest.raises(RuntimeError, match="PRIVACY_URL"):
        gw_app._privacy_client()
