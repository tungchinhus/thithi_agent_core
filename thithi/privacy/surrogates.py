"""Sinh giá trị thay thế (surrogate) cho thông tin nhạy cảm.

Hai chế độ:
- `token`: `<KH_01>`, `<SDT_02>`... Rõ ràng là đã che, an toàn nhất, Claude vẫn suy luận được cấu trúc.
- `pseudonym`: đổi sang giá trị giả trông như thật ("Hoàng Minh Khôi", "0900 000 001",
  "lienhe01@example.vn"). Claude viết văn bản tự nhiên hơn, nhưng việc đổi ngược phụ thuộc vào việc
  Claude giữ nguyên chuỗi giả, nên chỉ dùng cho các loại có danh sách giả riêng bên dưới.

Giá trị giả được chọn từ danh sách cố định, duy nhất trong một trace, và không trùng giá trị thật
nào đã gặp trong trace đó.
"""

from __future__ import annotations

from dataclasses import dataclass, field

TOKEN = "token"
PSEUDONYM = "pseudonym"

_NAMES = [
    "Hoàng Minh Khôi", "Lý Thu Hà", "Đinh Quốc Bảo", "Tạ Ngọc Diệp", "Vương Gia Huy", "Mai Thanh Trúc",
    "Kiều Đức Anh", "Lạc Bảo Ngọc", "Quách Hữu Phước", "Từ Mỹ Linh", "Doãn Tuấn Kiệt", "Thái Khánh Vy",
]
_ORGS = [
    "Công ty TNHH Sao Mai", "Công ty CP Hải Đăng", "Công ty TNHH Thiên Phúc", "Công ty CP Hướng Dương",
    "Công ty TNHH Bạch Dương", "Công ty CP Lam Sơn", "Công ty TNHH Phương Nam", "Công ty CP Kim Ngân",
]


def _pseudonym(kind: str, n: int) -> str | None:
    if kind in ("NGUOI",):
        base = _NAMES[(n - 1) % len(_NAMES)]
        return base if n <= len(_NAMES) else f"{base} {n // len(_NAMES) + 1}"
    if kind in ("CTY", "KH", "NCC"):
        base = _ORGS[(n - 1) % len(_ORGS)]
        return base if n <= len(_ORGS) else f"{base} {n // len(_ORGS) + 1}"
    if kind == "DIA_CHI":
        return f"Số {n} đường Hoa Sữa, phường Mẫu Đơn"
    if kind == "EMAIL":
        return f"lienhe{n:02d}@example.vn"
    if kind == "SDT":
        return f"0900 000 {n:03d}"
    return None  # số tiền, CCCD, STK, MST...: luôn dùng token


@dataclass
class SurrogatePolicy:
    mode: str = TOKEN
    pseudonym_kinds: set[str] = field(default_factory=lambda: {"NGUOI", "CTY", "KH", "NCC", "DIA_CHI", "EMAIL", "SDT"})

    def __post_init__(self) -> None:
        if self.mode not in (TOKEN, PSEUDONYM):
            raise ValueError(f"Chế độ không hợp lệ: {self.mode}")

    def make(self, kind: str, n: int) -> str:
        if self.mode == PSEUDONYM and kind in self.pseudonym_kinds:
            fake = _pseudonym(kind, n)
            if fake:
                return fake
        return f"<{kind}_{n:02d}>"
