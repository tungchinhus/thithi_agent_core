"""MCP server `mcp-notify`: chỉ tạo BẢN NHÁP. Gửi thật do Gateway làm sau khi có người duyệt."""

from __future__ import annotations

import uuid

from mcp.server.mcpserver import MCPServer

from .authz import writes

mcp = MCPServer("mcp-notify")
DRAFTS: dict[str, dict] = {}


@mcp.tool()
@writes
def draft_email(user_id: str, to: list[str], subject: str, body: str) -> dict:
    """Tạo bản nháp email nội bộ để người duyệt xem trước khi gửi."""
    draft_id = uuid.uuid4().hex[:12]
    DRAFTS[draft_id] = {"to": to, "subject": subject, "body": body, "created_by": user_id, "sent": False}
    return {"label": "noi_bo", "draft_id": draft_id, "status": "draft"}


TOOLS = [draft_email]

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
