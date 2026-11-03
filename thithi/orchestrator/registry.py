"""Danh mục công cụ mà Plan được phép gọi.

Bản khung gọi trực tiếp hàm Python của các MCP server trong cùng tiến trình để dễ chạy thử.
Triển khai thật: Orchestrator là MCP client, gọi từng server qua streamable-http trong mạng nội bộ.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ToolSpec:
    name: str  # vd. "mcp-erp.query_ar_aging"
    fn: Callable[..., Any]
    writes: bool = False  # công cụ ghi/gửi bắt buộc phải có approval trong Plan
    description: str = ""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def catalog(self, names: list[str]) -> list[dict[str, Any]]:
        """Mô tả công cụ gửi lên Claude: chỉ tên, mô tả, có ghi hay không. Không có dữ liệu."""
        return [
            {"name": n, "description": self._tools[n].description, "writes": self._tools[n].writes}
            for n in names
            if n in self._tools
        ]


def default_registry() -> ToolRegistry:
    from thithi.mcp_servers import docs, erp, local_llm, notify

    reg = ToolRegistry()
    for server, prefix in ((erp, "mcp-erp"), (docs, "mcp-docs"), (local_llm, "mcp-local-llm"), (notify, "mcp-notify")):
        for fn in server.TOOLS:
            reg.register(
                ToolSpec(
                    name=f"{prefix}.{fn.__name__}",
                    fn=fn,
                    writes=getattr(fn, "writes", False),
                    description=(fn.__doc__ or "").strip().splitlines()[0],
                )
            )
    return reg
