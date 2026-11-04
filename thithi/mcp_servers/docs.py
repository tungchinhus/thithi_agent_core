"""MCP server `mcp-docs`: tìm tài liệu nội bộ cho RAG, lọc theo quyền người hỏi.

Bản khung dùng chỉ mục từ khoá trong bộ nhớ. Triển khai thật: embedding đa ngôn ngữ chạy
local + Qdrant/pgvector, mỗi đoạn lưu kèm `allowed_roles` và `source` để lọc và gắn nhãn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcp.server.mcpserver import MCPServer

from .authz import roles_of

mcp = MCPServer("mcp-docs")


@dataclass
class Chunk:
    doc_id: str
    title: str
    text: str
    source: str
    allowed_roles: set[str] = field(default_factory=lambda: {"*"})


INDEX: list[Chunk] = [
    Chunk(
        "QC-NP-01",
        "Quy chế nghỉ phép",
        "Nhân viên gửi đơn nghỉ phép trên cổng nội bộ trước 3 ngày làm việc. "
        "Trưởng phòng duyệt trong 1 ngày. Nghỉ trên 5 ngày cần Giám đốc duyệt.",
        "docs.quy_che/nghi_phep.docx",
    ),
    Chunk(
        "QC-TT-02",
        "Quy trình thanh toán",
        "Đề nghị thanh toán cần chứng từ gốc và chữ ký trưởng bộ phận. Kế toán kiểm tra trong 2 ngày.",
        "docs.quy_che/thanh_toan.docx",
    ),
    Chunk(
        "HD-MAU-01",
        "Mẫu hợp đồng mua bán",
        "Điều 5: Thanh toán trong 30 ngày kể từ ngày xuất hoá đơn.",
        "docs.hop_dong/mau_mua_ban.docx",
        {"finance", "hanh_chinh", "ban_giam_doc"},
    ),
]


def _words(text: str) -> set[str]:
    return set(re.findall(r"\w+", text.lower()))


def _visible(chunk: Chunk, roles: set[str]) -> bool:
    return "*" in chunk.allowed_roles or bool(chunk.allowed_roles & roles)


@mcp.tool()
def search(user_id: str, query: str, top_k: int = 5) -> dict:
    """Tìm các đoạn tài liệu liên quan mà người hỏi được phép xem."""
    roles = roles_of(user_id)
    q = _words(query)
    scored = [(len(q & _words(c.title + " " + c.text)), c) for c in INDEX if _visible(c, roles)]
    hits = [c for score, c in sorted(scored, key=lambda x: -x[0]) if score > 0][:top_k]
    return {
        "label": "noi_bo",
        "sources": [c.source for c in hits],
        "chunks": [{"doc_id": c.doc_id, "title": c.title, "text": c.text, "source": c.source} for c in hits],
    }


@mcp.tool()
def get_document(user_id: str, doc_id: str) -> dict:
    """Lấy toàn văn một tài liệu theo mã, nếu người hỏi được xem."""
    roles = roles_of(user_id)
    for c in INDEX:
        if c.doc_id == doc_id and _visible(c, roles):
            return {"label": "noi_bo", "source": c.source, "doc_id": c.doc_id, "title": c.title, "text": c.text}
    return {"label": "noi_bo", "source": None, "error": "không tìm thấy hoặc không có quyền"}


TOOLS = [search, get_document]

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
