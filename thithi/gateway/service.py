"""Gateway: cửa duy nhất giữa mạng nội bộ và cloud."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from thithi.privacy.client import PrivacyClient
from thithi.privacy.masking import LeakError
from thithi.privacy.ner import NerUnavailable

from .labels import CloudPolicy, LabelPolicy


class Blocked(RuntimeError):
    """Payload không được phép rời mạng nội bộ."""


class AuditLog:
    """Nhật ký theo trace_id. Chỉ lưu bản ĐÃ CHE. Triển khai thật: PostgreSQL, giữ 12 tháng."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []

    def log(self, trace_id: str, event: str, **data: Any) -> None:
        entry = {"ts": time.time(), "trace_id": trace_id, "event": event, **data}
        self.entries.append(entry)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class Gateway:
    """Cửa duy nhất ra cloud. Việc che/đổi và tái tạo do Privacy Vault trên máy AI local làm;
    Gateway không giữ ánh xạ nên tự nó không tái tạo được thông tin thật."""

    def __init__(self, policy: LabelPolicy, privacy: PrivacyClient, audit: AuditLog | None = None):
        self.policy = policy
        self.privacy = privacy
        self.audit = audit or AuditLog()

    def outbound(self, trace_id: str, payload: Any, sources: list[str], purpose: str) -> str:
        """Chuẩn bị payload để gửi lên Claude: gắn nhãn, nhờ Privacy Vault che và quét lần hai, ghi log."""
        cls = self.policy.classify(sources)
        if not cls.cloud_allowed:
            self.audit.log(trace_id, "blocked", purpose=purpose, label=cls.label.name, sources=sources)
            raise Blocked(f"Dữ liệu nhãn {cls.label.name} không được gửi lên cloud")
        if cls.allow_cloud != CloudPolicy.RAW:
            try:
                payload = self.privacy.mask(trace_id, payload)
            except NerUnavailable as exc:
                self.audit.log(trace_id, "ner_blocked", purpose=purpose, error=str(exc))
                raise Blocked(f"{exc}. Không gửi lên cloud khi chưa che được tên riêng.") from exc
            except LeakError as exc:
                self.audit.log(trace_id, "leak_blocked", purpose=purpose, error=str(exc))
                raise Blocked(str(exc)) from exc
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, default=str)
        self.audit.log(trace_id, "outbound", purpose=purpose, label=cls.label.name, payload=text)
        return text

    def inbound(self, trace_id: str, value: Any) -> Any:
        """Nhờ Privacy Vault tái tạo giá trị thật trước khi trả cho người dùng trong mạng nội bộ."""
        return self.privacy.unmask(trace_id, value)
