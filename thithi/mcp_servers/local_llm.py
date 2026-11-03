"""MCP server `mcp-local-llm`: gọi LLM chạy on-premise (vLLM/Ollama, API chuẩn OpenAI).

Dữ liệu thô chỉ đi tới máy AI local; không có lời gọi nào ra internet từ đây.
"""

from __future__ import annotations

import json
import os

import httpx
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("mcp-local-llm")

BASE_URL = os.environ.get("LOCAL_LLM_URL", "http://ai-local:8000/v1")
MODEL = os.environ.get("LOCAL_LLM_MODEL", "local-model")
TIMEOUT = float(os.environ.get("LOCAL_LLM_TIMEOUT", "120"))


def _chat(system: str, user: str, json_mode: bool = False) -> str:
    body = {
        "model": MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0.1,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    resp = httpx.post(f"{BASE_URL}/chat/completions", json=body, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


@mcp.tool()
def summarize(user_id: str, text: str, instructions: str = "", max_words: int = 200) -> dict:
    """Tóm tắt văn bản/dữ liệu nội bộ bằng LLM local, giữ nguyên số liệu."""
    system = (
        "Bạn là trợ lý nội bộ. Tóm tắt bằng tiếng Việt, giữ nguyên mọi con số và tên, "
        f"không thêm thông tin ngoài văn bản. Tối đa {max_words} từ."
    )
    return {"label": "inherit", "summary": _chat(system, f"{instructions}\n\n---\n{text}".strip())}


@mcp.tool()
def extract(user_id: str, text: str, json_schema: dict) -> dict:
    """Trích dữ liệu có cấu trúc (JSON theo schema) từ văn bản bằng LLM local."""
    system = "Trích thông tin theo đúng JSON schema sau, chỉ trả về JSON hợp lệ:\n" + json.dumps(
        json_schema, ensure_ascii=False
    )
    return {"label": "inherit", "data": json.loads(_chat(system, text, json_mode=True))}


@mcp.tool()
def answer_with_sources(user_id: str, question: str, chunks: list[dict]) -> dict:
    """Trả lời câu hỏi chỉ dựa trên các đoạn tài liệu cho trước, kèm trích dẫn."""
    if not chunks:
        return {"label": "noi_bo", "answer": "Không tìm thấy tài liệu liên quan.", "sources": []}
    context = "\n\n".join(f"[{c['doc_id']}] {c['title']}: {c['text']}" for c in chunks)
    system = (
        "Trả lời bằng tiếng Việt, CHỈ dựa trên tài liệu được cung cấp. Mỗi ý ghi mã tài liệu "
        "trong ngoặc vuông. Nếu tài liệu không có câu trả lời, nói 'Không tìm thấy trong tài liệu'."
    )
    answer = _chat(system, f"Tài liệu:\n{context}\n\nCâu hỏi: {question}")
    return {"label": "noi_bo", "answer": answer, "sources": [c["source"] for c in chunks]}


TOOLS = [summarize, extract, answer_with_sources]

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
