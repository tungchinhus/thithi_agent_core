"""Nhận diện tên người, tên tổ chức, địa chỉ trong văn bản tự do bằng LLM chạy local.

Regex không bắt được "chị Lan bên công ty Minh An". Module này hỏi LLM local (dữ liệu không
rời mạng nội bộ) để lấy danh sách thực thể, rồi Masker che chúng như mọi PII khác.

Nguyên tắc an toàn: LLM local lỗi hoặc trả về sai định dạng thì báo `NerUnavailable`, và
Gateway CHẶN payload thay vì gửi bản che thiếu lên cloud (fail closed).
"""

from __future__ import annotations

import json
import re
from typing import Callable

from .pii import nfc

ChatFn = Callable[..., str]

KINDS = {"PERSON": "NGUOI", "ORG": "CTY", "ADDRESS": "DIA_CHI"}
TOKEN_RE = re.compile(r"<[A-Z_]+_\d{2,}>")

SYSTEM = """Bạn là bộ nhận diện thực thể cho tiếng Việt. Liệt kê MỌI tên người, tên tổ chức
(công ty, cửa hàng, cơ quan, ngân hàng) và địa chỉ cụ thể xuất hiện trong văn bản.
Chép nguyên văn từng thực thể như trong văn bản, không sửa chính tả, không thêm danh xưng
(anh, chị, ông, bà) nếu nó không nằm liền trong tên. Bỏ qua các token dạng <ABC_01>.
Chỉ trả về JSON: {"entities": [{"text": "...", "type": "PERSON|ORG|ADDRESS"}]}"""


class NerUnavailable(RuntimeError):
    pass


def default_chat(system: str, user: str, json_mode: bool = False) -> str:
    from thithi.mcp_servers.local_llm import _chat

    return _chat(system, user, json_mode=json_mode)


_default_chat = default_chat  # tên cũ


def ping_local_llm(timeout: float = 5) -> None:
    """Gọi /models của LLM local (vLLM/Ollama, API chuẩn OpenAI). Lỗi thì ném ngoại lệ."""
    import httpx

    from thithi.mcp_servers.local_llm import BASE_URL

    httpx.get(f"{BASE_URL}/models", timeout=timeout).raise_for_status()


class LocalLlmNer:
    def __init__(self, chat: ChatFn | None = None, max_chars: int = 6000):
        self.chat = chat or _default_chat
        self.max_chars = max_chars

    def _chunks(self, text: str) -> list[str]:
        lines, chunks, size = text.splitlines(keepends=True), [], 0
        current: list[str] = []
        for line in lines:
            if current and size + len(line) > self.max_chars:
                chunks.append("".join(current))
                current, size = [], 0
            current.append(line)
            size += len(line)
        if current:
            chunks.append("".join(current))
        return chunks

    def extract(self, text: str) -> dict[str, str]:
        """Trả về {thực thể: loại token}. Chỉ giữ thực thể thật sự xuất hiện trong văn bản."""
        if not TOKEN_RE.sub("", text).strip():
            return {}
        found: dict[str, str] = {}
        for chunk in self._chunks(nfc(text)):
            try:
                data = json.loads(self.chat(SYSTEM, chunk, json_mode=True))
                entities = data["entities"]
            except Exception as exc:  # LLM local chết, quá giờ, hoặc trả về rác
                raise NerUnavailable(f"Không nhận diện được tên riêng: {exc}") from exc
            for ent in entities:
                value = nfc(str(ent.get("text", "")).strip())
                kind = KINDS.get(str(ent.get("type", "")).upper())
                # Chống LLM bịa: chỉ che chuỗi có thật trong văn bản, bỏ chuỗi quá ngắn và token sẵn có
                if kind and len(value) >= 2 and value.lower() in chunk.lower() and not TOKEN_RE.fullmatch(value):
                    found[value] = kind
        return found
