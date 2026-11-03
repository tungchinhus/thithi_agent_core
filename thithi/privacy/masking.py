"""Che hoặc đổi thông tin nhạy cảm thành giá trị thay thế, và tái tạo khi kết quả quay về.

Chạy trong dịch vụ Privacy Vault trên máy AI local. Ánh xạ nằm trong `Vault`, không bao giờ rời máy đó.
"""

from __future__ import annotations

import re
from typing import Any

from .pii import KeywordDetector, PiiScanner
from .surrogates import SurrogatePolicy
from .vault import InMemoryVault, TraceVault

TOKEN_RE = re.compile(r"<([A-Z_]+)_(\d{2,})>")


def new_trace_vault(policy: SurrogatePolicy | None = None) -> TraceVault:
    """Kho tạm trong bộ nhớ cho một trace (test, công cụ dòng lệnh)."""
    return InMemoryVault(policy).for_trace("local")


class LeakError(RuntimeError):
    """Bản đã che vẫn còn PII: chặn, không gửi lên cloud."""


# Trường dữ liệu có cấu trúc luôn bị che theo TÊN cột, kể cả khi giá trị không khớp mẫu PII nào
# (vd. tên khách hàng trong bảng ERP, số tiền dạng số). Bổ sung theo schema thật của ERP/CRM.
SENSITIVE_KEYS: dict[str, str] = {
    "customer_name": "KH",
    "ten_khach_hang": "KH",
    "supplier_name": "NCC",
    "employee_name": "NGUOI",
    "ho_ten": "NGUOI",
    "contact_name": "NGUOI",
    "address": "DIA_CHI",
    "dia_chi": "DIA_CHI",
    "amount": "SO_TIEN",
    "so_tien": "SO_TIEN",
}


class Masker:
    def __init__(
        self,
        scanner: PiiScanner | None = None,
        sensitive_keys: dict[str, str] | None = None,
        ner: Any | None = None,
    ):
        self.scanner = scanner or PiiScanner()
        self.sensitive_keys = SENSITIVE_KEYS if sensitive_keys is None else sensitive_keys
        self.ner = ner  # vd. LocalLlmNer; None = chỉ dùng regex, danh bạ và tên cột

    def mask_payload(self, payload: Any, vault: TraceVault) -> Any:
        """Chạy NER một lần trên mọi chuỗi của payload rồi che. Lỗi NER được để nổi lên để chặn."""
        scanner = self.scanner
        if self.ner is not None:
            entities = self.ner.extract("\n".join(_strings(payload)))
            if entities:
                scanner = scanner.with_extra(KeywordDetector(entities))
        return self.mask_obj(payload, vault, scanner)

    def mask(self, text: str, vault: TraceVault, scanner: PiiScanner | None = None) -> str:
        known = vault.mapping()  # giá trị thay thế đã phát hành: không che lại lần nữa
        out, last = [], 0
        for span in (scanner or self.scanner).scan(text):
            if span.text in known:
                continue
            out.append(text[last : span.start])
            out.append(vault.surrogate_for(span.kind, span.text))
            last = span.end
        out.append(text[last:])
        return "".join(out)

    def mask_obj(self, obj: Any, vault: TraceVault, scanner: PiiScanner | None = None) -> Any:
        if isinstance(obj, str):
            return self.mask(obj, vault, scanner)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                kind = self.sensitive_keys.get(k)
                if kind and v is not None and not isinstance(v, (dict, list)):
                    out[k] = vault.surrogate_for(kind, str(v))
                else:
                    out[k] = self.mask_obj(v, vault, scanner)
            return out
        if isinstance(obj, list):
            return [self.mask_obj(v, vault, scanner) for v in obj]
        return obj

    def verify_clean(self, text: str, vault: TraceVault | None = None) -> None:
        """Quét lần hai trên bản đã che (bỏ qua giá trị thay thế đã phát hành); còn sót thì chặn."""
        for surrogate in sorted((vault.mapping() if vault else {}), key=len, reverse=True):
            text = text.replace(surrogate, " ")
        leftovers = self.scanner.scan(TOKEN_RE.sub(" ", text))
        if leftovers:
            kinds = sorted({s.kind for s in leftovers})
            raise LeakError(f"Còn sót PII sau khi che: {', '.join(kinds)}")

    @staticmethod
    def unmask(text: str, vault: TraceVault) -> str:
        mapping = vault.mapping()
        if not mapping:
            return text
        pattern = re.compile("|".join(re.escape(k) for k in sorted(mapping, key=len, reverse=True)))
        return pattern.sub(lambda m: mapping[m.group(0)], text)

    def unmask_obj(self, obj: Any, vault: TraceVault) -> Any:
        if isinstance(obj, str):
            return self.unmask(obj, vault)
        if isinstance(obj, dict):
            return {k: self.unmask_obj(v, vault) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.unmask_obj(v, vault) for v in obj]
        return obj


def _strings(obj: Any) -> list[str]:
    """Mọi chuỗi trong payload (kể cả khoá dict) để NER đọc một lần."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [x for k, v in obj.items() for x in (*_strings(k), *_strings(v))]
    if isinstance(obj, list):
        return [x for v in obj for x in _strings(v)]
    return []
