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
from typing import Any, Callable

import yaml

from .masking import SENSITIVE_KEYS, TOKEN_RE, LeakError, Masker, _IssuedCache, _walk, normalize
from .metrics import Metrics
from .ner import LocalLlmNer, NerUnavailable, default_chat, ping_local_llm
from .pii import KeywordDetector, PiiScanner
from .restore import RestorePlan, RestoreStats, SmartRestorer
from .surrogates import SurrogatePolicy
from .vault import InMemoryVault, SqliteVault, Vault

__all__ = ["AccessLog", "PrivacyEngine", "PrivacyConfig", "LeakError", "NerUnavailable", "build_engine", "load_known_names"]


@dataclass
class PrivacyConfig:
    mode: str = "token"
    pseudonym_kinds: set[str] | None = None
    ttl_hours: float = 24
    require_ner: bool = True
    llm_recheck: bool = True  # LLM local soát lại bản đã che trước khi gửi lên cloud
    llm_restore: bool = True  # LLM local tái tạo giá trị thay thế bị Claude viết lại
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
            llm_recheck=bool(data.get("llm_recheck", True)),
            llm_restore=bool(data.get("llm_restore", True)),
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
    """Mọi việc chạm tới giá trị thật, giao cho LLM local và kho ánh xạ trên cùng máy:

    - che: regex + danh bạ + tên cột + NER bằng LLM local, rồi (tuỳ chọn) LLM local soát lại bản đã che;
    - tái tạo: khớp chính xác, biến thể xác định, rồi LLM local cho phần Claude viết lại;
    - đo đếm mọi bước vào `metrics` để giám sát.
    """

    def __init__(
        self,
        vault: Vault,
        masker: Masker,
        require_ner: bool = True,
        access_log: AccessLog | None = None,
        restorer: SmartRestorer | None = None,
        recheck: LocalLlmNer | None = None,
        metrics: Metrics | None = None,
        llm_ping: Callable[[], None] | None = None,
    ):
        if require_ner and masker.ner is None:
            raise ValueError("Privacy Vault bắt buộc có NER bằng LLM local (require_ner=true)")
        self.vault = vault
        self.masker = masker
        self.access_log = access_log or AccessLog()
        self.restorer = restorer or SmartRestorer()
        self.recheck = recheck
        self.metrics = metrics or Metrics()
        self.llm_ping = llm_ping

    def mask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any:
        """Che/đổi payload. Lỗi NER (`NerUnavailable`) hoặc còn sót PII (`LeakError`) thì báo lỗi."""
        started = time.perf_counter()
        tv = self.vault.for_trace(trace_id)
        before = len(tv.mapping())
        try:
            masked = self.masker.mask_payload(payload, tv)
            self.masker.verify_clean(_text(masked), tv)
            if self.recheck is not None:
                masked = self._recheck(trace_id, masked, tv)
        except NerUnavailable as exc:
            self.metrics.inc("thithi_vault_mask_total", result="ner_unavailable")
            self.access_log.log(trace_id, "mask_blocked", actor=actor, reason=type(exc).__name__)
            raise
        except LeakError as exc:
            self.metrics.inc("thithi_vault_mask_total", result="leak")
            self.access_log.log(trace_id, "mask_blocked", actor=actor, reason=type(exc).__name__)
            raise
        finally:
            self.metrics.observe("thithi_vault_mask_seconds", time.perf_counter() - started)
        new_values = len(tv.mapping()) - before
        self.metrics.inc("thithi_vault_mask_total", result="ok")
        self.metrics.inc("thithi_vault_masked_values_total", new_values)
        self.access_log.log(trace_id, "mask", actor=actor, new_values=new_values)
        return masked

    def _recheck(self, trace_id: str, masked: Any, tv: Any) -> Any:
        """Lượt soát cuối: LLM local đọc chính bản sắp gửi lên cloud. Tên nào còn sót thì che nốt."""
        issued = tv.mapping()
        try:
            found = self.recheck.extract(_text(masked))
        except NerUnavailable:
            self.metrics.inc("thithi_vault_llm_errors_total", step="recheck")
            raise
        missed = {
            value: kind
            for value, kind in found.items()
            if value not in issued and not TOKEN_RE.search(value) and not any(value in s for s in issued)
        }
        if not missed:
            return masked
        self.metrics.inc("thithi_vault_recheck_found_total", len(missed))
        scanner = self.masker.scanner.with_extra(KeywordDetector(missed))
        masked = self.masker.mask_obj(normalize(masked), _IssuedCache(tv), scanner)
        self.masker.verify_clean(_text(masked), tv)
        self.access_log.log(trace_id, "recheck_masked", values=len(missed))
        return masked

    def unmask(self, trace_id: str, payload: Any, actor: str | None = None) -> Any:
        started = time.perf_counter()
        plan = RestorePlan.build(self.vault.for_trace(trace_id).mapping())  # giải mã kho một lần
        stats = RestoreStats()

        def restore(text: str) -> str:
            out, st = self.restorer.restore(text, plan)
            stats.add(st)
            return out

        out = _walk(payload, restore) if plan.exact is not None else payload
        self.metrics.observe("thithi_vault_unmask_seconds", time.perf_counter() - started)
        self.metrics.inc("thithi_vault_unmask_total")
        self.metrics.inc("thithi_vault_restored_total", stats.exact, method="exact")
        self.metrics.inc("thithi_vault_restored_total", stats.variant, method="variant")
        self.metrics.inc("thithi_vault_restored_total", stats.llm_lines, method="llm_line")
        self.metrics.inc("thithi_vault_unresolved_total", stats.unresolved)
        if stats.llm_error:
            self.metrics.inc("thithi_vault_llm_errors_total", step="restore")
        self.access_log.log(
            trace_id, "unmask", actor=actor, restored=stats.exact + stats.variant,
            llm_lines=stats.llm_lines, unresolved=stats.unresolved,
        )
        return out

    def purge(self, trace_id: str, actor: str | None = None) -> None:
        self.vault.purge(trace_id)
        self.access_log.log(trace_id, "purge", actor=actor)

    def ready(self) -> dict[str, str]:
        """Kiểm tra sẵn sàng: kho ánh xạ đọc được và LLM local trả lời. Giá trị "ok" hoặc mô tả lỗi."""
        checks: dict[str, str] = {}
        try:
            self.vault.for_trace("__readyz__").mapping()
            checks["vault"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["vault"] = f"lỗi: {type(exc).__name__}"
        if self.llm_ping is None:
            checks["llm"] = "tắt (dev)"
        else:
            try:
                self.llm_ping()
                checks["llm"] = "ok"
            except Exception as exc:  # noqa: BLE001
                checks["llm"] = f"lỗi: {type(exc).__name__}"
        return checks


def _text(obj: Any) -> str:
    return obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)


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
    llm_off = os.environ.get("THITHI_ENV") == "dev" and os.environ.get("THITHI_NER") == "off"
    ner = None if llm_off else LocalLlmNer()
    return PrivacyEngine(
        vault,
        cfg.masker(ner),
        require_ner=cfg.require_ner and ner is not None,
        access_log=AccessLog(os.environ.get("PRIVACY_ACCESS_LOG")),
        restorer=SmartRestorer(None if llm_off or not cfg.llm_restore else default_chat),
        recheck=LocalLlmNer() if ner is not None and cfg.llm_recheck else None,
        llm_ping=None if llm_off else ping_local_llm,
    )
