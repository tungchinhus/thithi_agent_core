"""PrivacyEngine: che/đổi và tái tạo thông tin, chạy trên máy AI local.

Mọi bước đều ở local: nhận diện (regex + danh bạ + tên cột + NER bằng LLM local), sinh giá trị thay
thế, lưu ánh xạ có mã hoá, quét lần hai, và tái tạo. Gateway chỉ gửi payload tới đây và nhận lại bản
đã che; Gateway không giữ ánh xạ nên không tự tái tạo được.
"""

from __future__ import annotations

import csv
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .masking import SENSITIVE_KEYS, LeakError, Masker
from .ner import LocalLlmNer, NerUnavailable
from .pii import KeywordDetector, PiiScanner
from .surrogates import SurrogatePolicy
from .vault import InMemoryVault, SqliteVault, Vault

__all__ = ["AccessLog", "PrivacyEngine", "PrivacyConfig", "LeakError", "NerUnavailable", "build_engine", "load_known_names"]


@dataclass
class PrivacyConfig:
    mode: str = "token"
    pseudonym_kinds: set[str] | None = None
    ttl_hours: float = 24
    require_ner: bool = True
    sensitive_keys: dict[str, str] = field(default_factory=dict)  # cột nhạy cảm bổ sung: tên cột -> loại
    known_names: list[str] = field(default_factory=list)  # file danh bạ tên đã biết (CSV: name,kind)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PrivacyConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        kinds = data.get("pseudonym_kinds")
        names = data.get("known_names") or []
        return cls(
            mode=data.get("mode", "token"),
            pseudonym_kinds=set(kinds) if kinds else None,
            ttl_hours=float(data.get("ttl_hours", 24)),
            require_ner=bool(data.get("require_ner", True)),
            sensitive_keys={str(k): str(v) for k, v in (data.get("sensitive_keys") or {}).items()},
            known_names=[names] if isinstance(names, str) else list(names),
        )

    def scanner(self) -> PiiScanner:
        """Regex + danh bạ tên đã biết (file thiếu thì bỏ qua: danh bạ chỉ bổ sung cho NER, không thay NER)."""
        names: dict[str, str] = {}
        for path in self.known_names:
            if Path(path).exists():
                names.update(load_known_names(path))
        return PiiScanner(extra=[KeywordDetector(names)] if names else None)

    def masker(self, ner: LocalLlmNer | None) -> Masker:
        return Masker(self.scanner(), {**SENSITIVE_KEYS, **self.sensitive_keys}, ner=ner)

    def policy(self) -> SurrogatePolicy:
        if self.pseudonym_kinds is None:
            return SurrogatePolicy(self.mode)
        return SurrogatePolicy(self.mode, self.pseudonym_kinds)


def load_known_names(path: str | Path) -> dict[str, str]:
    """Danh bạ tên đã biết, xuất từ ERP/CRM/Entra ID: CSV hai cột `name,kind` (kind: NGUOI, KH, NCC, CTY...)."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        return {
            row["name"].strip(): (row.get("kind") or "NGUOI").strip().upper()
            for row in csv.DictReader(f)
            if (row.get("name") or "").strip()
        }


class AccessLog:
    """Nhật ký truy cập Vault: ai che/tái tạo trace nào, bao nhiêu giá trị. KHÔNG ghi giá trị thật hay giả.

    Ghép với nhật ký Gateway qua trace_id để biết người dùng nào đứng sau mỗi lần tái tạo.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def log(self, trace_id: str, event: str, **data: Any) -> None:
        entry = {"ts": time.time(), "trace_id": trace_id, "event": event, **data}
        with self._lock:
            self.entries.append(entry)
            del self.entries[:-1000]  # chỉ giữ gần đây trong bộ nhớ; bản đầy đủ nằm trong file
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class PrivacyEngine:
    def __init__(self, vault: Vault, masker: Masker, require_ner: bool = True, access_log: AccessLog | None = None):
        if require_ner and masker.ner is None:
            raise ValueError("Privacy Vault bắt buộc có NER bằng LLM local (require_ner=true)")
        self.vault = vault
        self.masker = masker
        self.access_log = access_log or AccessLog()

    def mask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any:
        """Che/đổi payload. Lỗi NER (`NerUnavailable`) hoặc còn sót PII (`LeakError`) thì báo lỗi."""
        tv = self.vault.for_trace(trace_id)
        before = len(tv.mapping())
        try:
            masked = self.masker.mask_payload(payload, tv)
            text = masked if isinstance(masked, str) else json.dumps(masked, ensure_ascii=False, default=str)
            self.masker.verify_clean(text, tv)
        except (NerUnavailable, LeakError) as exc:
            self.access_log.log(trace_id, "mask_blocked", actor=actor, reason=type(exc).__name__)
            raise
        self.access_log.log(trace_id, "mask", actor=actor, new_values=len(tv.mapping()) - before)
        return masked

    def unmask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any:
        tv = self.vault.for_trace(trace_id)
        out = self.masker.unmask_obj(payload, tv)
        restored = sum(_count(payload, s) for s in tv.mapping())
        self.access_log.log(trace_id, "unmask", actor=actor, restored=restored)
        return out

    def purge(self, trace_id: str, actor: str | None = None) -> None:
        self.vault.purge(trace_id)
        self.access_log.log(trace_id, "purge", actor=actor)


def _count(obj: Any, needle: str) -> int:
    if isinstance(obj, str):
        return obj.count(needle)
    if isinstance(obj, dict):
        return sum(_count(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return sum(_count(v, needle) for v in obj)
    return 0


def build_engine(config_path: str | None = None, in_memory: bool = False) -> PrivacyEngine:
    """Dựng engine từ biến môi trường, dùng cho dịch vụ Privacy Vault.

    `in_memory=True`: kho tạm trong bộ nhớ (công cụ nghiệm thu), không đụng tới kho ánh xạ thật."""
    path = config_path or os.environ.get("PRIVACY_CONFIG", "config/privacy.yaml")
    cfg = PrivacyConfig.from_yaml(path) if Path(path).exists() else PrivacyConfig()
    if os.environ.get("PRIVACY_KNOWN_NAMES"):  # đường dẫn trong container khác trên máy dev
        cfg.known_names = [x.strip() for x in os.environ["PRIVACY_KNOWN_NAMES"].split(",") if x.strip()]
    db = os.environ.get("PRIVACY_VAULT_DB")
    vault: Vault
    if db and not in_memory:
        sqlite = SqliteVault(db, os.environ.get("PRIVACY_VAULT_KEY", ""), cfg.policy(), cfg.ttl_hours)
        sqlite.purge_expired()  # dọn ánh xạ quá hạn còn sót từ lần chạy trước
        vault = sqlite
    elif in_memory or os.environ.get("THITHI_ENV") == "dev":
        vault = InMemoryVault(cfg.policy())
    else:
        raise RuntimeError("Thiếu PRIVACY_VAULT_DB: ngoài môi trường dev, kho ánh xạ phải lưu bền và mã hoá")
    ner = None if os.environ.get("THITHI_ENV") == "dev" and os.environ.get("THITHI_NER") == "off" else LocalLlmNer()
    return PrivacyEngine(
        vault,
        cfg.masker(ner),
        require_ner=cfg.require_ner and ner is not None,
        access_log=AccessLog(os.environ.get("PRIVACY_ACCESS_LOG")),
    )
