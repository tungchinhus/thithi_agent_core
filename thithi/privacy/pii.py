"""Nhận diện thông tin cá nhân (PII) trong văn bản tiếng Việt.

Bộ nhận diện bằng biểu thức chính quy bắt các mẫu có cấu trúc. Tên người, tên công ty và
địa chỉ cần NER: cắm thêm một `Detector` (vd. gọi LLM local) qua `PiiScanner(extra=[...])`.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Protocol


def nfc(text: str) -> str:
    """Chuẩn hoá Unicode NFC. Tiếng Việt từ Word/macOS hay ở dạng tổ hợp (NFD): "Lan" của LLM và "Lan"
    trong văn bản trông giống nhau nhưng khác byte, nên mọi so khớp phải làm trên cùng một dạng."""
    return unicodedata.normalize("NFC", text)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    text: str


class Detector(Protocol):
    def find(self, text: str) -> Iterable[Span]: ...


# Thứ tự không quan trọng: chồng lấn được giải quyết bằng cách giữ đoạn dài hơn.
# Mẫu có nhóm tên `v` thì chỉ che phần giá trị, giữ lại từ khoá ngữ cảnh ("STK: <STK_01>").
PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    # CCCD 12 số
    "CCCD": re.compile(r"(?<!\d)0\d{11}(?!\d)"),
    # Di động (0 + 9 số) và cố định (0 + 10 số, vd. 024 3826 1234) hoặc +84, cho phép dấu cách/chấm/gạch
    "SDT": re.compile(r"(?<![\d+])(?:\+84|0)(?:[\s.-]?\d){9,10}(?!\d)"),
    # Mã số thuế: 10 số hoặc 10-3 số, có chữ "MST"/"mã số thuế" đứng trước
    "MST": re.compile(r"(?i)(?<!\w)(?:MST|mã số thuế|ma so thue)(?:\s+là)?\s*[:.]?\s*(?P<v>\d{10}(?:-\d{3})?)(?!\d)"),
    # Số tài khoản: 8–19 số (cho phép cách/chấm/gạch) sau "STK"/"TK"/"số tài khoản"/"tài khoản số"
    "STK": re.compile(
        r"(?i)(?<!\w)(?:STK|TK|tài khoản|tai khoan)(?:\s+số)?(?:\s+là)?\s*[:.]?\s*(?P<v>\d(?:[\s.-]?\d){7,18})(?!\d)"
    ),
    # Số tiền có đơn vị
    "SO_TIEN": re.compile(
        r"(?i)\d{1,3}(?:[.,]\d{3})+(?:[.,]\d+)?\s?(?:đ|đồng|vnđ|vnd|usd)(?!\w)"
        r"|\d+(?:[.,]\d+)?\s?(?:triệu|tỷ|tỉ|tr|nghìn|ngàn|k)(?:\s?đồng)?(?!\w)"
    ),
}


PRIORITY = {"MST": 0, "STK": 0, "EMAIL": 1, "CCCD": 2, "SO_TIEN": 3, "SDT": 4}


class RegexDetector:
    def __init__(self, patterns: dict[str, re.Pattern[str]] | None = None):
        self.patterns = patterns or PATTERNS

    def find(self, text: str) -> Iterable[Span]:
        for kind, pattern in self.patterns.items():
            group = "v" if "v" in pattern.groupindex else 0
            for m in pattern.finditer(text):
                start, end = m.span(group)
                value = text[start:end]
                lead = len(value) - len(value.lstrip())
                yield Span(start + lead, end, kind, value.strip())


class KeywordDetector:
    """Che các tên đã biết (khách hàng, nhân viên, đối tác) lấy từ danh bạ nội bộ."""

    def __init__(self, names: dict[str, str]):
        # names: {"Công ty ABC": "CTY", "Nguyễn Văn A": "NGUOI"}
        # Khớp nguyên từ, không phân biệt hoa thường: tên "An" không được che chữ "an" trong "Ban giám đốc".
        self.names = [
            (re.compile(r"(?<!\w)" + re.escape(nfc(name)) + r"(?!\w)", re.IGNORECASE), kind)
            for name, kind in sorted(names.items(), key=lambda kv: -len(kv[0]))
            if name.strip()
        ]

    def find(self, text: str) -> Iterable[Span]:
        for pattern, kind in self.names:
            for m in pattern.finditer(text):
                yield Span(m.start(), m.end(), kind, m.group(0))


class PiiScanner:
    def __init__(self, extra: list[Detector] | None = None):
        self.detectors: list[Detector] = [RegexDetector(), *(extra or [])]

    def with_extra(self, *detectors: Detector) -> "PiiScanner":
        """Bản sao có thêm bộ nhận diện, dùng cho một lần che (vd. tên do NER tìm ra)."""
        clone = PiiScanner()
        clone.detectors = [*self.detectors, *detectors]
        return clone

    def scan(self, text: str) -> list[Span]:
        spans = [s for d in self.detectors for s in d.find(text)]
        # Giữ đoạn dài nhất khi chồng lấn
        # Bằng độ dài thì ưu tiên loại có ngữ cảnh rõ (MST, STK) hơn loại đoán theo hình dạng (SDT).
        spans.sort(key=lambda s: (s.start, -(s.end - s.start), PRIORITY.get(s.kind, 5)))
        kept: list[Span] = []
        for s in spans:
            if kept and s.start < kept[-1].end:
                if (s.end - s.start) > (kept[-1].end - kept[-1].start):
                    kept[-1] = s
                continue
            kept.append(s)
        return kept
