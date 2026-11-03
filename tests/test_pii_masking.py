import pytest

from thithi.gateway.masking import LeakError, Masker, TokenVault
from thithi.gateway.pii import KeywordDetector, PiiScanner

SAMPLE = (
    "Anh Nam (nam.tran@abc.vn, 0912 345 678) CCCD 001203004567 còn nợ 125.000.000 đ, "
    "STK: 1903456789012, MST: 0101234567, gọi thêm +84 987654321."
)


def test_masks_structured_pii_and_roundtrips():
    m, v = Masker(), TokenVault()
    masked = m.mask(SAMPLE, v)
    for raw in ["nam.tran@abc.vn", "0912 345 678", "001203004567", "125.000.000 đ", "1903456789012", "0101234567", "+84 987654321"]:
        assert raw not in masked
    for token in ["<EMAIL_01>", "<SDT_01>", "<CCCD_01>", "<SO_TIEN_01>", "<STK_01>", "<MST_01>", "<SDT_02>"]:
        assert token in masked
    m.verify_clean(masked)
    assert m.unmask(masked, v) == SAMPLE


def test_same_value_gets_same_token_within_trace():
    m, v = Masker(), TokenVault()
    out = m.mask("Gọi 0912345678 rồi lại gọi 0912345678", v)
    assert out.count("<SDT_01>") == 2
    assert len(v) == 1


def test_keyword_detector_masks_known_names():
    m = Masker(PiiScanner(extra=[KeywordDetector({"Công ty TNHH Minh An": "CTY"})]))
    v = TokenVault()
    assert m.mask("Khách Công ty TNHH Minh An quá hạn 64 ngày", v) == "Khách <CTY_01> quá hạn 64 ngày"


def test_verify_clean_blocks_leftovers():
    with pytest.raises(LeakError):
        Masker().verify_clean("Liên hệ chị Hoa 0987654321")


def test_mask_obj_masks_strings_and_sensitive_columns():
    m, v = Masker(), TokenVault()
    row = {"customer_name": "Cửa hàng Thanh Hương", "amount": 12000000, "note": "a@b.vn", "days": 64}
    out = m.mask_obj({"rows": [row]}, v)
    assert out == {"rows": [{"customer_name": "<KH_01>", "amount": "<SO_TIEN_01>", "note": "<EMAIL_01>", "days": 64}]}
    back = m.unmask_obj(out, v)["rows"][0]
    assert back["customer_name"] == "Cửa hàng Thanh Hương" and back["amount"] == "12000000"
