"""Nhận diện thông tin cá nhân (PII) trong văn bản tiếng Việt.

Bộ nhận diện bằng biểu thức chính quy bắt các mẫu có cấu trúc. Tên người, tên công ty và
địa chỉ cần NER: cắm thêm một `Detector` (vd. gọi LLM local) qua `PiiScanner(extra=[...])`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Protocol


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    text: str


class Detector(Protocol):
    def find(self, text: str) -> Iterable[Span]: ...


# Thứ tự không quan trọng: chồng lấn được giải quyết bằng cách giữ đoạn dài hơn.
PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    # CCCD 12 số
    "CCCD": re.compile(r"(?<!\d)0\d{11}(?!\d)"),
    # Di động Việt Nam: 0xxxxxxxxx hoặc +84xxxxxxxxx, cho phép dấu cách/chấm/gạch
    "SDT": re.compile(r"(?<![\d+])(?:\+84|0)(?:[\s.-]?\d){9}(?!\d)"),
    # Mã số thuế: 10 số hoặc 10-3 số, phải có chữ "MST"/"mã số thuế" đứng trước
    "MST": re.compile(r"(?i)(?<=MST[:\s])\s*\d{10}(?:-\d{3})?|(?<=mã số thuế[:\s])\s*\d{10}(?:-\d{3})?"),
    # Số tài khoản: 8–16 số đứng sau "STK"/"số tài khoản"/"TK"
    "STK": re.compile(r"(?i)(?<=STK[:\s])\s*\d{8,16}|(?<=tài khoản[:\s])\s*\d{8,16}"),
    # Số tiền có đơn vị
    "SO_TIEN": re.compile(
        r"(?i)\d{1,3}(?:[.,]\d{3})+(?:[.,]\d+)?\s?(?:đ|đồng|vnđ|vnd|usd)\b|\d+(?:[.,]\d+)?\s?(?:triệu|tỷ)(?:\s?đồng)?"
    ),
}


PRIORITY = {"MST": 0, "STK": 0, "EMAIL": 1, "CCCD": 2, "SO_TIEN": 3, "SDT": 4}


class RegexDetector:
    def __init__(self, patterns: dict[str, re.Pattern[str]] | None = None):
        self.patterns = patterns or PATTERNS

    def find(self, text: str) -> Iterable[Span]:
        for kind, pattern in self.patterns.items():
            for m in pattern.finditer(text):
                value = m.group(0)
                lead = len(value) - len(value.lstrip())
                yield Span(m.start() + lead, m.end(), kind, value.strip())


class KeywordDetector:
    """Che các tên đã biết (khách hàng, nhân viên, đối tác) lấy từ danh bạ nội bộ."""

    def __init__(self, names: dict[str, str]):
        # names: {"Công ty ABC": "CTY", "Nguyễn Văn A": "NGUOI"}
        self.names = sorted(names.items(), key=lambda kv: -len(kv[0]))

    def find(self, text: str) -> Iterable[Span]:
        lowered = text.lower()
        for name, kind in self.names:
            start = 0
            needle = name.lower()
            while (i := lowered.find(needle, start)) != -1:
                yield Span(i, i + len(name), kind, text[i : i + len(name)])
                start = i + len(name)


class PiiScanner:
    def __init__(self, extra: list[Detector] | None = None):
        self.detectors: list[Detector] = [RegexDetector(), *(extra or [])]

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
