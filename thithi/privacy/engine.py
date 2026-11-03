"""PrivacyEngine: che/đổi và tái tạo thông tin, chạy trên máy AI local.

Mọi bước đều ở local: nhận diện (regex + danh bạ + tên cột + NER bằng LLM local), sinh giá trị thay
thế, lưu ánh xạ có mã hoá, quét lần hai, và tái tạo. Gateway chỉ gửi payload tới đây và nhận lại bản
đã che; Gateway không giữ ánh xạ nên không tự tái tạo được.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .masking import LeakError, Masker
from .ner import LocalLlmNer, NerUnavailable
from .surrogates import SurrogatePolicy
from .vault import InMemoryVault, SqliteVault, Vault

__all__ = ["PrivacyEngine", "PrivacyConfig", "LeakError", "NerUnavailable", "build_engine"]


@dataclass
class PrivacyConfig:
    mode: str = "token"
    pseudonym_kinds: set[str] | None = None
    ttl_hours: float = 24
    require_ner: bool = True

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PrivacyConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        kinds = data.get("pseudonym_kinds")
        return cls(
            mode=data.get("mode", "token"),
            pseudonym_kinds=set(kinds) if kinds else None,
            ttl_hours=float(data.get("ttl_hours", 24)),
            require_ner=bool(data.get("require_ner", True)),
        )

    def policy(self) -> SurrogatePolicy:
        if self.pseudonym_kinds is None:
            return SurrogatePolicy(self.mode)
        return SurrogatePolicy(self.mode, self.pseudonym_kinds)


class PrivacyEngine:
    def __init__(self, vault: Vault, masker: Masker, require_ner: bool = True):
        if require_ner and masker.ner is None:
            raise ValueError("Privacy Vault bắt buộc có NER bằng LLM local (require_ner=true)")
        self.vault = vault
        self.masker = masker

    def mask(self, trace_id: str, payload: Any) -> Any:
        """Che/đổi payload. Lỗi NER (`NerUnavailable`) hoặc còn sót PII (`LeakError`) thì báo lỗi."""
        tv = self.vault.for_trace(trace_id)
        masked = self.masker.mask_payload(payload, tv)
        text = masked if isinstance(masked, str) else json.dumps(masked, ensure_ascii=False, default=str)
        self.masker.verify_clean(text, tv)
        return masked

    def unmask(self, trace_id: str, payload: Any) -> Any:
        return self.masker.unmask_obj(payload, self.vault.for_trace(trace_id))

    def purge(self, trace_id: str) -> None:
        self.vault.purge(trace_id)


def build_engine(config_path: str | None = None) -> PrivacyEngine:
    """Dựng engine từ biến môi trường, dùng cho dịch vụ Privacy Vault."""
    path = config_path or os.environ.get("PRIVACY_CONFIG", "config/privacy.yaml")
    cfg = PrivacyConfig.from_yaml(path) if Path(path).exists() else PrivacyConfig()
    db = os.environ.get("PRIVACY_VAULT_DB")
    if db:
        vault: Vault = SqliteVault(db, os.environ.get("PRIVACY_VAULT_KEY", ""), cfg.policy(), cfg.ttl_hours)
    elif os.environ.get("THITHI_ENV") == "dev":
        vault = InMemoryVault(cfg.policy())
    else:
        raise RuntimeError("Thiếu PRIVACY_VAULT_DB: ngoài môi trường dev, kho ánh xạ phải lưu bền và mã hoá")
    ner = None if os.environ.get("THITHI_ENV") == "dev" and os.environ.get("THITHI_NER") == "off" else LocalLlmNer()
    return PrivacyEngine(vault, Masker(ner=ner), require_ner=cfg.require_ner and ner is not None)
