"""Phân quyền người dùng cho MCP server: công cụ chạy với quyền của người yêu cầu."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml


class Forbidden(PermissionError):
    pass


@lru_cache(maxsize=1)
def _roles() -> dict[str, set[str]]:
    path = Path(os.environ.get("THITHI_ROLES", "config/roles.yaml"))
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {user: set(roles) for user, roles in (data.get("users") or {}).items()}


def roles_of(user_id: str) -> set[str]:
    return _roles().get(user_id, set())


def require_role(user_id: str, *allowed: str) -> None:
    if not roles_of(user_id) & set(allowed):
        raise Forbidden(f"{user_id} không có vai trò {', '.join(allowed)}")


def writes(fn):
    """Đánh dấu công cụ ghi/gửi: Plan gọi nó bắt buộc phải có approval."""
    fn.writes = True
    return fn
