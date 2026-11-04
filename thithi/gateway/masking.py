"""Thay PII bằng token ổn định trong một trace, và đổi ngược khi kết quả quay về."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .pii import KeywordDetector, PiiScanner

TOKEN_RE = re.compile(r"<([A-Z_]+)_(\d{2,})>")


class TokenVault:
    """Bảng ánh xạ token ↔ giá trị thật của một trace.

    Bản này giữ trong bộ nhớ. Triển khai thật: Redis, mã hoá khi lưu, hết hạn sau 24 giờ.
    Bảng không bao giờ rời mạng nội bộ.
    """

    def __init__(self) -> None:
        self._by_value: dict[str, str] = {}
        self._by_token: dict[str, str] = {}
        self._counters: dict[str, int] = defaultdict(int)

    def token_for(self, kind: str, value: str) -> str:
        if value in self._by_value:
            return self._by_value[value]
        self._counters[kind] += 1
        token = f"<{kind}_{self._counters[kind]:02d}>"
        self._by_value[value] = token
        self._by_token[token] = value
        return token

    def value_for(self, token: str) -> str | None:
        return self._by_token.get(token)

    def __len__(self) -> int:
        return len(self._by_token)


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

    def mask_payload(self, payload: Any, vault: TokenVault) -> Any:
        """Điểm vào của Gateway: chạy NER một lần trên mọi chuỗi của payload rồi che.

        Lỗi NER (`NerUnavailable`) được để nổi lên để Gateway chặn payload.
        """
        scanner = self.scanner
        if self.ner is not None:
            entities = self.ner.extract("\n".join(_strings(payload)))
            if entities:
                scanner = scanner.with_extra(KeywordDetector(entities))
        return self.mask_obj(payload, vault, scanner)

    def mask(self, text: str, vault: TokenVault, scanner: PiiScanner | None = None) -> str:
        out, last = [], 0
        for span in (scanner or self.scanner).scan(text):
            out.append(text[last : span.start])
            out.append(vault.token_for(span.kind, span.text))
            last = span.end
        out.append(text[last:])
        return "".join(out)

    def mask_obj(self, obj: Any, vault: TokenVault, scanner: PiiScanner | None = None) -> Any:
        if isinstance(obj, str):
            return self.mask(obj, vault, scanner)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                kind = self.sensitive_keys.get(k)
                if kind and v is not None and not isinstance(v, (dict, list)):
                    out[k] = vault.token_for(kind, str(v))
                else:
                    out[k] = self.mask_obj(v, vault, scanner)
            return out
        if isinstance(obj, list):
            return [self.mask_obj(v, vault, scanner) for v in obj]
        return obj

    def verify_clean(self, text: str) -> None:
        """Quét lần hai trên bản đã che; còn sót thì chặn."""
        leftovers = self.scanner.scan(TOKEN_RE.sub("", text))
        if leftovers:
            kinds = sorted({s.kind for s in leftovers})
            raise LeakError(f"Còn sót PII sau khi che: {', '.join(kinds)}")

    @staticmethod
    def unmask(text: str, vault: TokenVault) -> str:
        return TOKEN_RE.sub(lambda m: vault.value_for(m.group(0)) or m.group(0), text)

    def unmask_obj(self, obj: Any, vault: TokenVault) -> Any:
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
