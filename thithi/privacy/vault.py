"""Kho ánh xạ giá trị thay thế ↔ giá trị thật, theo từng trace.

Kho này là thứ duy nhất cho phép tái tạo thông tin thật, nên nó CHỈ chạy trên máy AI local
(dịch vụ Privacy Vault). Gateway và Claude không bao giờ đọc được nó.

- `InMemoryVault`: cho test và dev.
- `SqliteVault`: lưu bền; giá trị thật mã hoá bằng Fernet (AES-128-CBC + HMAC), chỉ mục tra cứu
  là HMAC-SHA256 của giá trị nên file CSDL không chứa giá trị thật dạng đọc được. Hết hạn theo TTL.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Protocol

from cryptography.fernet import Fernet

from .surrogates import SurrogatePolicy


class TraceVault(Protocol):
    def surrogate_for(self, kind: str, value: str) -> str: ...
    def mapping(self) -> dict[str, str]: ...  # surrogate -> giá trị thật


class Vault(Protocol):
    def for_trace(self, trace_id: str) -> TraceVault: ...
    def purge(self, trace_id: str) -> None: ...


class _MemoryTrace:
    def __init__(self, policy: SurrogatePolicy):
        self.policy = policy
        self._by_value: dict[str, str] = {}
        self._by_surrogate: dict[str, str] = {}
        self._counters: dict[str, int] = defaultdict(int)

    def surrogate_for(self, kind: str, value: str) -> str:
        if value in self._by_value:
            return self._by_value[value]
        while True:
            self._counters[kind] += 1
            surrogate = self.policy.make(kind, self._counters[kind])
            # Không dùng giá trị giả trùng một giá trị thật hay giá trị giả đã có
            if surrogate != value and surrogate not in self._by_value and surrogate not in self._by_surrogate:
                break
        self._by_value[value] = surrogate
        self._by_surrogate[surrogate] = value
        return surrogate

    def mapping(self) -> dict[str, str]:
        return dict(self._by_surrogate)


class InMemoryVault:
    def __init__(self, policy: SurrogatePolicy | None = None):
        self.policy = policy or SurrogatePolicy()
        self._traces: dict[str, _MemoryTrace] = {}

    def for_trace(self, trace_id: str) -> _MemoryTrace:
        return self._traces.setdefault(trace_id, _MemoryTrace(self.policy))

    def purge(self, trace_id: str) -> None:
        self._traces.pop(trace_id, None)


class _SqliteTrace:
    def __init__(self, vault: "SqliteVault", trace_id: str):
        self.vault, self.trace_id = vault, trace_id

    def surrogate_for(self, kind: str, value: str) -> str:
        return self.vault._surrogate_for(self.trace_id, kind, value)

    def mapping(self) -> dict[str, str]:
        return self.vault._mapping(self.trace_id)


class SqliteVault:
    def __init__(self, path: str | Path, key: str | bytes, policy: SurrogatePolicy | None = None, ttl_hours: float = 24):
        if not key:
            raise ValueError("Thiếu khoá mã hoá PRIVACY_VAULT_KEY")
        self.policy = policy or SurrogatePolicy()
        self.ttl = ttl_hours * 3600
        self._fernet = Fernet(key)
        raw = key.encode() if isinstance(key, str) else key
        self._index_key = hashlib.sha256(b"thithi-vault-index:" + raw).digest()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS entries (
                trace_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                n INTEGER NOT NULL,
                surrogate TEXT NOT NULL,
                value_mac TEXT NOT NULL,
                value_enc BLOB NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY (trace_id, value_mac),
                UNIQUE (trace_id, surrogate)
            );
            CREATE INDEX IF NOT EXISTS entries_expiry ON entries (expires_at);
            """
        )

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode()

    def for_trace(self, trace_id: str) -> _SqliteTrace:
        return _SqliteTrace(self, trace_id)

    def _mac(self, value: str) -> str:
        return hmac.new(self._index_key, value.encode(), hashlib.sha256).hexdigest()

    def _surrogate_for(self, trace_id: str, kind: str, value: str) -> str:
        mac = self._mac(value)
        with self._lock:
            row = self._db.execute(
                "SELECT surrogate FROM entries WHERE trace_id = ? AND value_mac = ?", (trace_id, mac)
            ).fetchone()
            if row:
                return row[0]
            n = self._db.execute(
                "SELECT COALESCE(MAX(n), 0) FROM entries WHERE trace_id = ? AND kind = ?", (trace_id, kind)
            ).fetchone()[0]
            while True:
                n += 1
                surrogate = self.policy.make(kind, n)
                taken = self._db.execute(
                    "SELECT 1 FROM entries WHERE trace_id = ? AND (surrogate = ? OR value_mac = ?)",
                    (trace_id, surrogate, self._mac(surrogate)),
                ).fetchone()
                if not taken and surrogate != value:
                    break
            self._db.execute(
                "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)",
                (trace_id, kind, n, surrogate, mac, self._fernet.encrypt(value.encode()), time.time() + self.ttl),
            )
            return surrogate

    def _mapping(self, trace_id: str) -> dict[str, str]:
        rows = self._db.execute(
            "SELECT surrogate, value_enc FROM entries WHERE trace_id = ? AND expires_at > ?", (trace_id, time.time())
        ).fetchall()
        return {s: self._fernet.decrypt(enc).decode() for s, enc in rows}

    def purge(self, trace_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM entries WHERE trace_id = ?", (trace_id,))

    def purge_expired(self) -> int:
        with self._lock:
            return self._db.execute("DELETE FROM entries WHERE expires_at <= ?", (time.time(),)).rowcount
