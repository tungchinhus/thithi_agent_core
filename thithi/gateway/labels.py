"""Phân loại dữ liệu theo nguồn: quyết định dữ liệu được xử lý ở đâu."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from fnmatch import fnmatch
from pathlib import Path

import yaml


class Label(IntEnum):
    """Nhãn dữ liệu, sắp theo mức nhạy cảm tăng dần."""

    CONG_KHAI = 0
    NOI_BO = 1
    MAT = 2
    TOI_MAT = 3

    @classmethod
    def parse(cls, value: str) -> "Label":
        return cls[value.strip().upper()]


class CloudPolicy:
    RAW = "raw"  # gửi nguyên văn
    MASKED = "masked"  # chỉ gửi bản đã che PII
    NEVER = "never"  # không bao giờ rời mạng nội bộ


@dataclass(frozen=True)
class SourceRule:
    pattern: str
    label: Label
    allow_cloud: str


@dataclass(frozen=True)
class Classification:
    label: Label
    allow_cloud: str

    @property
    def cloud_allowed(self) -> bool:
        return self.allow_cloud != CloudPolicy.NEVER


class LabelPolicy:
    """Ánh xạ nguồn dữ liệu (vd. `erp.ar_aging`, `docs.hop_dong/x.pdf`) sang nhãn.

    Nguồn không khớp quy tắc nào nhận nhãn mặc định (mặc định là MAT): khi không chắc,
    luôn chọn mức cao hơn.
    """

    _STRICTNESS = {CloudPolicy.RAW: 0, CloudPolicy.MASKED: 1, CloudPolicy.NEVER: 2}

    def __init__(self, rules: list[SourceRule], default_label: Label = Label.MAT):
        self.rules = rules
        self.default = Classification(default_label, self._default_policy(default_label))

    @staticmethod
    def _default_policy(label: Label) -> str:
        if label == Label.TOI_MAT:
            return CloudPolicy.NEVER
        if label == Label.CONG_KHAI:
            return CloudPolicy.RAW
        return CloudPolicy.MASKED

    @classmethod
    def from_yaml(cls, path: str | Path) -> "LabelPolicy":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules = []
        for pattern, spec in (data.get("sources") or {}).items():
            label = Label.parse(spec["label"])
            allow = spec.get("allow_cloud", cls._default_policy(label))
            if label == Label.TOI_MAT and allow != CloudPolicy.NEVER:
                raise ValueError(f"Nguồn {pattern} là TOI_MAT nhưng allow_cloud={allow}; phải là 'never'")
            rules.append(SourceRule(pattern, label, allow))
        default = Label.parse(data.get("default_label", "mat"))
        return cls(rules, default)

    def classify_source(self, source: str) -> Classification:
        for rule in self.rules:
            if fnmatch(source, rule.pattern):
                return Classification(rule.label, rule.allow_cloud)
        return self.default

    def classify(self, sources: list[str]) -> Classification:
        """Nhãn của một payload gộp nhiều nguồn = nhãn cao nhất, chính sách chặt nhất."""
        if not sources:
            return self.default
        found = [self.classify_source(s) for s in sources]
        label = max(c.label for c in found)
        allow = max((c.allow_cloud for c in found), key=self._STRICTNESS.__getitem__)
        return Classification(label, allow)
