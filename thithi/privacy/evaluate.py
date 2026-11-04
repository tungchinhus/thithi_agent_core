"""Nghiệm thu Privacy Vault trên bộ mẫu PII của công ty.

    python -m thithi.privacy.evaluate data/pii_samples.jsonl            # dùng NER thật (cần LLM local)
    THITHI_ENV=dev THITHI_NER=off python -m thithi.privacy.evaluate tests/data/pii_samples.jsonl

Mỗi dòng của file mẫu là một JSON:
    {"id": "kt-001", "text": "...", "pii": ["Trần Thị Lan", "0912345678"], "keep": ["Ban giám đốc"]}

- `pii`: các chuỗi BẮT BUỘC phải biến mất khỏi bản đã che (đo độ phủ, tức recall).
- `keep`: các chuỗi KHÔNG được che (đo che nhầm, làm Claude mất ngữ cảnh). Không bắt buộc.
- `replies`: câu trả lời Claude có thể viết, dùng chỗ trống trỏ tới phần tử của `pii` (đo tái tạo khi Claude
  viết lại giá trị thay thế). Không bắt buộc. `{0}` = nguyên giá trị thay thế của pii[0]; `{0:ten}` = chỉ tên
  gọi (từ cuối, vd. "anh {0:ten}"); `{0:thuong}` = viết thường; `{0:so}` = chỉ còn chữ số; `{0:tron}` = token
  bỏ ngoặc. Kết quả mong đợi tự suy ra từ giá trị thật. Ví dụ:
      "replies": ["Đề nghị chị {0:ten} chuyển {2} trước thứ Sáu", "Gọi {1:so}"]

Một mẫu cũng phải tái tạo về đúng văn bản gốc. Lệnh trả mã lỗi 1 nếu còn rò rỉ hoặc tái tạo sai,
nên có thể chạy trong CI hoặc trước mỗi lần đổi mô hình LLM local.
File mẫu chứa dữ liệu thật thì chỉ để trên máy AI local (thư mục `data/`, đã nằm trong .gitignore).
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import PrivacyEngine, build_engine
from .masking import LeakError
from .ner import NerUnavailable
from .pii import nfc


@dataclass
class SampleResult:
    id: str
    leaked: list[str] = field(default_factory=list)
    over_masked: list[str] = field(default_factory=list)
    roundtrip_ok: bool = True
    error: str | None = None
    replies_total: int = 0
    replies_failed: list[str] = field(default_factory=list)  # chỉ số trong 'replies'
    mask_seconds: float = 0.0
    unmask_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.leaked and self.roundtrip_ok and self.error is None and not self.replies_failed


_SLOT = re.compile(r"\{(\d+)(?::(ten|thuong|so|tron))?\}")


def _render_reply(template: str, pii: list[str], real_to_fake: dict[str, str]) -> tuple[str, str] | None:
    """Trả về (câu Claude viết, câu mong đợi sau tái tạo); None nếu chỗ trống trỏ tới giá trị không được che."""
    missing = False

    def fake(m: re.Match[str]) -> str:
        nonlocal missing
        idx, form = int(m.group(1)), m.group(2)
        surrogate = real_to_fake.get(pii[idx]) if idx < len(pii) else None
        if surrogate is None:
            missing = True
            return m.group(0)
        is_token = surrogate.startswith("<")
        if form == "ten":
            return surrogate if is_token else surrogate.split()[-1]
        if form == "thuong":
            return surrogate.lower()
        if form == "so":
            return surrogate.strip("<>") if is_token else re.sub(r"\D", "", surrogate)
        if form == "tron":
            return surrogate.strip("<>")
        return surrogate

    def real(m: re.Match[str]) -> str:
        idx, form = int(m.group(1)), m.group(2)
        surrogate = real_to_fake.get(pii[idx], "")
        if form == "ten" and not surrogate.startswith("<"):
            return pii[idx].split()[-1]
        return pii[idx]

    said = _SLOT.sub(fake, template)
    return None if missing else (said, _SLOT.sub(real, template))


@dataclass
class Report:
    results: list[SampleResult]
    pii_total: int
    keep_total: int

    @property
    def leaked(self) -> int:
        return sum(len(r.leaked) for r in self.results)

    @property
    def over_masked(self) -> int:
        return sum(len(r.over_masked) for r in self.results)

    @property
    def recall(self) -> float:
        return 1.0 if not self.pii_total else 1 - self.leaked / self.pii_total

    @property
    def passed(self) -> bool:
        return all(r.ok for r in self.results)

    @property
    def replies_total(self) -> int:
        return sum(r.replies_total for r in self.results)

    @property
    def replies_ok(self) -> int:
        return self.replies_total - sum(len(r.replies_failed) for r in self.results)

    def timing(self, attr: str) -> tuple[float, float]:
        """(trung vị, p95) tính bằng giây."""
        values = sorted(getattr(r, attr) for r in self.results if r.error is None)
        if not values:
            return 0.0, 0.0
        return statistics.median(values), values[min(len(values) - 1, math.ceil(0.95 * len(values)) - 1)]

    def summary(self) -> str:
        lines = [
            f"Mẫu: {len(self.results)}  |  Đạt: {sum(r.ok for r in self.results)}",
            f"Độ phủ (recall): {self.recall:.1%}  ({self.pii_total - self.leaked}/{self.pii_total} giá trị PII đã che)",
            f"Che nhầm: {self.over_masked}/{self.keep_total} chuỗi cần giữ",
        ]
        if self.replies_total:
            lines.append(
                f"Tái tạo khi Claude viết lại: {self.replies_ok}/{self.replies_total} câu đúng "
                f"({self.replies_ok / self.replies_total:.1%})"
            )
        m_med, m_p95 = self.timing("mask_seconds")
        u_med, u_p95 = self.timing("unmask_seconds")
        lines.append(f"Thời gian che: trung vị {m_med:.2f}s, p95 {m_p95:.2f}s | tái tạo: trung vị {u_med:.2f}s, p95 {u_p95:.2f}s")
        for r in self.results:
            if r.error:
                lines.append(f"  [{r.id}] LỖI: {r.error}")
            if r.leaked:
                # Không in giá trị thật ra màn hình/log CI: chỉ in vị trí trong danh sách pii của mẫu
                lines.append(f"  [{r.id}] RÒ RỈ {len(r.leaked)} giá trị (chỉ số trong 'pii': {', '.join(r.leaked)})")
            if not r.roundtrip_ok:
                lines.append(f"  [{r.id}] tái tạo không khớp văn bản gốc")
            if r.over_masked:
                lines.append(f"  [{r.id}] che nhầm: {', '.join(r.over_masked)}")
            if r.replies_failed:
                lines.append(f"  [{r.id}] tái tạo sai câu trả lời (chỉ số trong 'replies'): {', '.join(r.replies_failed)}")
        return "\n".join(lines)


def load_samples(path: str | Path) -> list[dict[str, Any]]:
    samples = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip() and not line.lstrip().startswith("#"):
            sample = json.loads(line)
            sample.setdefault("id", f"dong-{n}")
            samples.append(sample)
    return samples


def evaluate(engine: PrivacyEngine, samples: list[dict[str, Any]]) -> Report:
    results, pii_total, keep_total = [], 0, 0
    for i, sample in enumerate(samples):
        trace = f"EVAL-{i}"
        text, pii, keep = nfc(sample["text"]), [nfc(p) for p in sample.get("pii", [])], sample.get("keep", [])
        pii_total += len(pii)
        keep_total += len(keep)
        res = SampleResult(str(sample["id"]))
        try:
            started = time.perf_counter()
            masked = engine.mask(trace, text)
            res.mask_seconds = time.perf_counter() - started
        except (LeakError, NerUnavailable) as exc:
            # LeakError nghĩa là Vault đã chặn đúng (không gửi lên cloud) nhưng chưa tự che được: vẫn tính là lỗi
            res.error = f"{type(exc).__name__}: {exc}"
            res.leaked = [str(j) for j in range(len(pii))]
            results.append(res)
            continue
        try:
            lowered = masked.lower()
            res.leaked = [str(j) for j, value in enumerate(pii) if value.lower() in lowered]
            res.over_masked = [k for k in keep if nfc(k) not in masked]
            started = time.perf_counter()
            res.roundtrip_ok = engine.unmask(trace, masked) == text
            res.unmask_seconds = time.perf_counter() - started
            real_to_fake = {real: fake for fake, real in engine.vault.for_trace(trace).mapping().items()}
            for j, template in enumerate(sample.get("replies", [])):
                rendered = _render_reply(template, pii, real_to_fake)
                if rendered is None:  # giá trị đó đã rò rỉ, đã tính ở trên
                    continue
                said, expected = rendered
                res.replies_total += 1
                if engine.unmask(trace, said) != nfc(expected):
                    res.replies_failed.append(str(j))
        finally:
            engine.purge(trace)
        results.append(res)
    return Report(results, pii_total, keep_total)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Nghiệm thu Privacy Vault trên bộ mẫu PII")
    parser.add_argument("samples", help="File JSONL mẫu")
    parser.add_argument("--config", help="Đường dẫn privacy.yaml (mặc định: PRIVACY_CONFIG)")
    args = parser.parse_args(argv)
    # Kho tạm trong bộ nhớ: nghiệm thu không ghi gì vào kho ánh xạ thật
    report = evaluate(build_engine(args.config, in_memory=True), load_samples(args.samples))
    print(report.summary())
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
