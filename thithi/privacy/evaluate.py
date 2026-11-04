"""Nghiệm thu Privacy Vault trên bộ mẫu PII của công ty.

    python -m thithi.privacy.evaluate data/pii_samples.jsonl            # dùng NER thật (cần LLM local)
    THITHI_ENV=dev THITHI_NER=off python -m thithi.privacy.evaluate tests/data/pii_samples.jsonl

Mỗi dòng của file mẫu là một JSON:
    {"id": "kt-001", "text": "...", "pii": ["Trần Thị Lan", "0912345678"], "keep": ["Ban giám đốc"]}

- `pii`: các chuỗi BẮT BUỘC phải biến mất khỏi bản đã che (đo độ phủ, tức recall).
- `keep`: các chuỗi KHÔNG được che (đo che nhầm, làm Claude mất ngữ cảnh). Không bắt buộc.

Một mẫu cũng phải tái tạo về đúng văn bản gốc. Lệnh trả mã lỗi 1 nếu còn rò rỉ hoặc tái tạo sai,
nên có thể chạy trong CI hoặc trước mỗi lần đổi mô hình LLM local.
File mẫu chứa dữ liệu thật thì chỉ để trên máy AI local (thư mục `data/`, đã nằm trong .gitignore).
"""

from __future__ import annotations

import argparse
import json
import sys
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

    @property
    def ok(self) -> bool:
        return not self.leaked and self.roundtrip_ok and self.error is None


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

    def summary(self) -> str:
        lines = [
            f"Mẫu: {len(self.results)}  |  Đạt: {sum(r.ok for r in self.results)}",
            f"Độ phủ (recall): {self.recall:.1%}  ({self.pii_total - self.leaked}/{self.pii_total} giá trị PII đã che)",
            f"Che nhầm: {self.over_masked}/{self.keep_total} chuỗi cần giữ",
        ]
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
            masked = engine.mask(trace, text)
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
            res.roundtrip_ok = engine.unmask(trace, masked) == text
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
