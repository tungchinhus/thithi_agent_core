"""Tái tạo thông tin thật từ câu trả lời của Claude, kể cả khi Claude viết lại giá trị thay thế.

Claude có thể không giữ nguyên giá trị thay thế: viết "anh Khôi" thay cho "Hoàng Minh Khôi", "kh_01" thay
cho "<KH_01>", "0900000001" thay cho "0900 000 001". Việc đổi ngược chạy hoàn toàn trên máy AI local, theo
ba tầng, tầng sau chỉ chạy khi tầng trước còn sót:

1. **Khớp chính xác** giá trị thay thế (như trước).
2. **Biến thể xác định**: token sai hoa thường/thiếu ngoặc, số điện thoại viết liền, tên gọi tắt
   ("Minh Khôi", hoặc "anh Khôi" khi có danh xưng đứng trước), tên công ty bỏ tiền tố ("Sao Mai").
   Biến thể trùng nhau giữa hai giá trị thay thế thì bỏ qua, không đoán.
3. **LLM local**: dòng nào còn dấu vết giá trị thay thế thì gửi dòng đó cùng bảng ánh xạ cho LLM local
   (không rời mạng nội bộ) để viết lại. Kết quả chỉ được nhận nếu không còn dấu vết và gần như giữ nguyên
   phần còn lại (so độ giống); LLM lỗi hay viết lệch thì giữ kết quả tầng 2 và đếm là "chưa tái tạo".
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from typing import Callable

from .pii import nfc
from .surrogates import _NAMES, _ORGS

ChatFn = Callable[..., str]

TOKEN_RE = re.compile(r"<([A-Z_]+)_(\d{2,})>")
HONORIFIC = r"(?:anh|chị|chi|ông|bà|em|cô|chú|bác|bạn|thầy|mr\.?|ms\.?|mrs\.?)"
ORG_PREFIX = re.compile(r"^(?:công ty|cty|cong ty)\s+(?:tnhh|cp|cổ phần|co phan)?\s*", re.IGNORECASE)
_NAME_BASES = set(_NAMES)
_ORG_BASES = set(_ORGS)
_SENTINEL = "\x00{}\x00"
_SENTINEL_RE = re.compile("\x00(\\d+)\x00")

SYSTEM = """Bạn khôi phục dữ liệu thật cho một văn bản tiếng Việt, chạy trong mạng nội bộ.
Bảng ánh xạ cho biết mỗi giá trị GIẢ tương ứng với giá trị THẬT nào. Văn bản có thể nhắc tới giá trị giả
ở dạng rút gọn hoặc biến thể (chỉ tên gọi, viết thường, thiếu dấu ngoặc, cách viết số khác).
Thay MỌI chỗ nhắc tới giá trị giả bằng giá trị thật tương ứng ở dạng phù hợp (vd. "anh Khôi" -> "anh Lan"
nếu "Hoàng Minh Khôi" là giá trị giả của "Trần Thị Lan"). Không sửa, thêm hay bớt bất kỳ chữ nào khác.
Chỉ trả về JSON: {"lines": ["dòng 1 đã khôi phục", "dòng 2 đã khôi phục", ...]} đúng số dòng, đúng thứ tự."""


@dataclass
class RestoreStats:
    exact: int = 0
    variant: int = 0
    llm_lines: int = 0
    unresolved: int = 0
    llm_error: bool = False

    def add(self, other: "RestoreStats") -> None:
        self.exact += other.exact
        self.variant += other.variant
        self.llm_lines += other.llm_lines
        self.unresolved += other.unresolved
        self.llm_error = self.llm_error or other.llm_error


@dataclass
class _Rule:
    pattern: re.Pattern[str]
    real: Callable[[re.Match[str]], str]


@dataclass
class RestorePlan:
    """Các luật đổi ngược dựng một lần từ bảng ánh xạ của một trace."""

    mapping: dict[str, str]
    exact: re.Pattern[str] | None = None
    variants: list[_Rule] = field(default_factory=list)
    traces: re.Pattern[str] | None = None  # dấu vết giá trị thay thế còn sót

    @classmethod
    def build(cls, mapping: dict[str, str]) -> "RestorePlan":
        plan = cls(mapping)
        if not mapping:
            return plan
        plan.exact = re.compile("|".join(re.escape(k) for k in sorted(mapping, key=len, reverse=True)))
        candidates: dict[str, list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]]] = {}
        trace_parts: set[str] = set()

        def add(key: str, pattern: str, real: Callable[[re.Match[str]], str], flags: int = re.IGNORECASE) -> None:
            candidates.setdefault(key.lower(), []).append((re.compile(pattern, flags), real))

        for fake, real in mapping.items():
            m = TOKEN_RE.fullmatch(fake)
            if m:
                kind, n = m.group(1), int(m.group(2))
                # <KH_01> -> kh_01, KH-1, [KH_01], < KH_01 >
                add(f"tok:{kind}:{n}", rf"(?:[<\[(]\s*)?(?<![\w]){re.escape(kind)}[_-]0*{n}(?!\d)(?:\s*[>\])])?", _const(real))
                trace_parts.add(rf"(?i:(?<![\w]){re.escape(kind)}[_-]\d{{1,3}}(?!\d))")
                continue
            if "@" in fake:  # email giả: Claude có thể đổi hoa thường
                add(f"mail:{fake}", rf"(?<![\w.]){re.escape(fake)}(?!\w)", _const(real))
                continue
            digits = re.sub(r"\D", "", fake)
            if digits and len(digits) >= 9 and not re.search(r"[^\d\s.+-]", fake):  # số điện thoại giả
                add(f"num:{digits}", r"(?<!\d)" + r"[\s.-]?".join(digits) + r"(?!\d)", _const(real))
                continue
            base = re.sub(r"\s+\d+$", "", fake)
            if base in _NAME_BASES:
                words, real_words = fake.split(), real.split()
                if len(words) >= 3:
                    short2 = " ".join(words[-2:]) if not words[-1].isdigit() else None
                    if short2:
                        add(f"name2:{short2}", rf"(?<!\w){re.escape(short2)}(?!\w)", _const(real_words[-1]), 0)
                        given = words[-1]
                        add(
                            f"name1:{given}",
                            rf"(?i:(?<!\w)({HONORIFIC})\s+){re.escape(given)}(?!\w)",
                            lambda mm, r=real_words[-1]: f"{mm.group(1)} {r}",
                            0,
                        )
                        trace_parts.add(rf"(?<!\w){re.escape(given)}(?!\w)")
                continue
            if base in _ORG_BASES:
                core = ORG_PREFIX.sub("", fake)
                if core and core != fake:
                    add(f"org:{core}", rf"(?<!\w){re.escape(core)}(?!\w)", _const(ORG_PREFIX.sub("", real) or real), 0)
                    trace_parts.add(rf"(?<!\w){re.escape(core)}(?!\w)")
        # Biến thể dùng chung cho hai giá trị thay thế: không đoán
        for rules in candidates.values():
            if len(rules) == 1:
                plan.variants.append(_Rule(*rules[0]))
        if trace_parts:
            # Tên gọi phân biệt hoa thường ("Khôi" là tên, "khôi phục" thì không); token thì không phân biệt
            plan.traces = re.compile("|".join(sorted(trace_parts)))
        return plan


def _const(value: str) -> Callable[[re.Match[str]], str]:
    return lambda _m: value


class SmartRestorer:
    def __init__(self, chat: ChatFn | None = None, min_similarity: float = 0.6, max_lines: int = 40):
        self.chat = chat
        self.min_similarity = min_similarity
        self.max_lines = max_lines

    def restore(self, text: str, plan: RestorePlan) -> tuple[str, RestoreStats]:
        stats = RestoreStats()
        if plan.exact is None:
            return text, stats
        text = nfc(text)
        reals: list[str] = []

        def park(value: str) -> str:
            # Giá trị thật được "gửi tạm" sau một dấu canh: luật ở tầng sau không khớp nhầm vào giá trị thật
            reals.append(value)
            return _SENTINEL.format(len(reals) - 1)

        def exact(m: re.Match[str]) -> str:
            stats.exact += 1
            return park(plan.mapping[m.group(0)])

        text = plan.exact.sub(exact, text)
        for rule in plan.variants:
            def variant(m: re.Match[str], rule: _Rule = rule) -> str:
                stats.variant += 1
                return park(rule.real(m))

            text = rule.pattern.sub(variant, text)
        # Tìm dấu vết còn sót khi giá trị thật vẫn đang ở dạng dấu canh: tên thật tình cờ chứa "Khôi" không bị nghi
        resolve = lambda t: _SENTINEL_RE.sub(lambda m: reals[int(m.group(1))], t)  # noqa: E731
        parked = text.split("\n")
        idx = [i for i, line in enumerate(parked) if self._suspect(line, plan)]
        lines = [resolve(line) for line in parked]
        if len(lines) != len(resolve(text).split("\n")):  # giá trị thật có xuống dòng: dò lại trên bản đã đổi
            lines = resolve(text).split("\n")
            idx = [i for i, line in enumerate(lines) if self._suspect(line, plan)]
        if idx:
            lines = self._llm_pass(lines, idx, plan, stats)
        return "\n".join(lines), stats

    def _suspect(self, line: str, plan: RestorePlan) -> bool:
        return plan.traces is not None and plan.traces.search(line) is not None

    def _llm_pass(self, lines: list[str], idx: list[int], plan: RestorePlan, stats: RestoreStats) -> list[str]:
        if self.chat is None or len(idx) > self.max_lines:
            stats.unresolved += len(idx)
            return lines
        sent = [lines[i] for i in idx]
        user = (
            "Bảng ánh xạ (giả -> thật):\n"
            + json.dumps(plan.mapping, ensure_ascii=False, indent=1)
            + "\n\nCác dòng cần khôi phục:\n"
            + json.dumps({"lines": sent}, ensure_ascii=False)
        )
        try:
            out = json.loads(self.chat(SYSTEM, user, json_mode=True))["lines"]
            if not isinstance(out, list) or len(out) != len(sent):
                raise ValueError("sai số dòng")
        except Exception:  # noqa: BLE001 - LLM chết hay trả rác: tái tạo không phải bước bảo mật, không chặn
            stats.llm_error = True
            stats.unresolved += len(idx)
            return lines
        for i, before, after in zip(idx, sent, out, strict=True):
            after = nfc(str(after))
            ok = (
                "\n" not in after
                and not any(k in after for k in plan.mapping)  # không còn giá trị thay thế nguyên vẹn
                and difflib.SequenceMatcher(None, before, after).ratio() >= self.min_similarity
            )
            if ok and after != before:
                lines[i] = after
                stats.llm_lines += 1
            if not ok:
                stats.unresolved += 1
        return lines
