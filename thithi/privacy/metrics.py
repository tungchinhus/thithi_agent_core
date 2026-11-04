"""Số đo của Privacy Vault ở định dạng Prometheus (text exposition), không cần thư viện ngoài.

Chỉ đếm và đo thời gian; không có nhãn nào chứa giá trị thật, giá trị thay thế hay trace_id.
"""

from __future__ import annotations

import threading
from collections import defaultdict

HELP = {
    "thithi_vault_mask_total": ("counter", "Số lần che, theo kết quả (ok, ner_unavailable, leak)"),
    "thithi_vault_masked_values_total": ("counter", "Số giá trị thật mới được thay thế"),
    "thithi_vault_recheck_found_total": ("counter", "Giá trị LLM local tìm thêm ở lượt soát cuối (NER lượt đầu bỏ sót)"),
    "thithi_vault_unmask_total": ("counter", "Số lần tái tạo"),
    "thithi_vault_restored_total": ("counter", "Giá trị đã tái tạo, theo cách (exact, variant, llm_line)"),
    "thithi_vault_unresolved_total": ("counter", "Dòng còn dấu vết giá trị thay thế mà không tái tạo được"),
    "thithi_vault_llm_errors_total": ("counter", "Lỗi gọi LLM local, theo bước (ner, recheck, restore)"),
    "thithi_vault_mask_seconds": ("summary", "Thời gian che một payload"),
    "thithi_vault_unmask_seconds": ("summary", "Thời gian tái tạo một payload"),
}


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._timings: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])  # [tổng giây, số lần]

    def inc(self, name: str, value: float = 1, **labels: str) -> None:
        if value:
            with self._lock:
                self._counters[(name, tuple(sorted(labels.items())))] += value

    def observe(self, name: str, seconds: float) -> None:
        with self._lock:
            t = self._timings[name]
            t[0] += seconds
            t[1] += 1

    def get(self, name: str, **labels: str) -> float:
        return self._counters.get((name, tuple(sorted(labels.items()))), 0.0)

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            counters = dict(self._counters)
            timings = {k: list(v) for k, v in self._timings.items()}
        for name, (kind, text) in HELP.items():
            lines += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
            if kind == "summary":
                total, count = timings.get(name, [0.0, 0.0])
                lines += [f"{name}_sum {total:.6f}", f"{name}_count {int(count)}"]
                continue
            series = [(lbl, v) for (n, lbl), v in counters.items() if n == name]
            for lbl, v in sorted(series) or [((), 0.0)]:
                label = "{" + ",".join(f'{k}="{val}"' for k, val in lbl) + "}" if lbl else ""
                lines.append(f"{name}{label} {v:g}")
        return "\n".join(lines) + "\n"


def parse(text: str) -> dict[str, float]:
    """Đọc lại text Prometheus thành {tên{nhãn}: giá trị} (dùng cho script giám sát)."""
    out: dict[str, float] = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.rpartition(" ")
            try:
                out[key] = float(value)
            except ValueError:
                continue
    return out
