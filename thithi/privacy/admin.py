"""Lệnh quản trị Privacy Vault, chạy trên máy AI local (tay hoặc theo lịch systemd).

    python -m thithi.privacy.admin init --env vault.env      # tạo khoá mã hoá + service token, file quyền 600
    python -m thithi.privacy.admin purge-expired              # xoá ánh xạ quá hạn (chạy mỗi giờ)
    python -m thithi.privacy.admin rotate-key --env vault.env # xoay khoá: mã hoá lại toàn bộ kho
    python -m thithi.privacy.admin check                      # kho + LLM local; mã lỗi 1 nếu chưa sẵn sàng

Lệnh đọc biến môi trường như dịch vụ Vault (PRIVACY_VAULT_DB, PRIVACY_VAULT_KEY...). Không lệnh nào in giá
trị thật; `init` và `rotate-key` chỉ ghi khoá vào file env, không in ra màn hình.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import sys
import time
from pathlib import Path

from .vault import SqliteVault


def _read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def _write_env(path: Path, updates: dict[str, str], template: Path | None = None) -> None:
    """Ghi/cập nhật các khoá trong file env, giữ nguyên chú thích và thứ tự; quyền 600."""
    source = path if path.exists() else template
    lines = source.read_text(encoding="utf-8").splitlines() if source and source.exists() else []
    seen: set[str] = set()
    for i, line in enumerate(lines):
        key = line.partition("=")[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in updates:
            lines[i] = f"{key}={updates[key]}"
            seen.add(key)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in seen]
    path.parent.mkdir(parents=True, exist_ok=True)
    # Ghi tại chỗ (không đổi tên file): file env thường được bind-mount vào container
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def cmd_init(args: argparse.Namespace) -> int:
    env = Path(args.env)
    current = _read_env(env)
    if current.get("PRIVACY_VAULT_KEY") and not args.force:
        print(f"{env} đã có PRIVACY_VAULT_KEY; không ghi đè (dùng rotate-key, hoặc --force nếu kho đang trống).")
        return 1
    updates = {"PRIVACY_VAULT_KEY": SqliteVault.generate_key()}
    if not current.get("PRIVACY_SERVICE_TOKEN"):
        updates["PRIVACY_SERVICE_TOKEN"] = secrets.token_urlsafe(32)
    _write_env(env, updates, template=Path(args.template))
    print(f"Đã ghi khoá mới vào {env} (quyền 600). Chép PRIVACY_SERVICE_TOKEN sang .env của Gateway.")
    print("Sao lưu khoá ở nơi an toàn: mất khoá thì không tái tạo được dữ liệu đang xử lý.")
    return 0


def _open_vault() -> SqliteVault:
    db, key = os.environ.get("PRIVACY_VAULT_DB"), os.environ.get("PRIVACY_VAULT_KEY", "")
    if not db:
        raise SystemExit("Thiếu PRIVACY_VAULT_DB")
    return SqliteVault(db, key)


def cmd_purge(args: argparse.Namespace) -> int:
    n = _open_vault().purge_expired()
    print(f"Đã xoá {n} ánh xạ quá hạn.")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    env = Path(args.env)
    old_key = _read_env(env).get("PRIVACY_VAULT_KEY") or os.environ.get("PRIVACY_VAULT_KEY", "")
    db = os.environ.get("PRIVACY_VAULT_DB") or _read_env(env).get("PRIVACY_VAULT_DB")
    if not old_key or not db:
        raise SystemExit("Thiếu PRIVACY_VAULT_KEY hoặc PRIVACY_VAULT_DB")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = Path(f"{db}.bak-{stamp}")
    shutil.copy2(db, backup)  # bản sao vẫn mã hoá bằng khoá cũ
    os.chmod(backup, 0o600)
    new_key = SqliteVault.generate_key()
    n = SqliteVault(db, old_key).rotate(new_key)
    env_backup = Path(db).parent / f"{env.name}.bak-{stamp}"  # cạnh kho (thư mục được lưu bền)
    if env.exists():
        shutil.copy2(env, env_backup)
        os.chmod(env_backup, 0o600)
    _write_env(env, {"PRIVACY_VAULT_KEY": new_key})
    print(f"Đã mã hoá lại {n} ánh xạ bằng khoá mới, ghi vào {env}.")
    print(f"Bản sao kho và env cũ: {backup}, {env_backup}. Khởi động lại privacy-vault, rồi xoá bản sao khi ổn.")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from .engine import build_engine

    checks = build_engine().ready()
    for name, status in checks.items():
        print(f"{name}: {status}")
    return 0 if all(v == "ok" or v.startswith("tắt") for v in checks.values()) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="thithi.privacy.admin", description="Quản trị Privacy Vault")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="Tạo khoá mã hoá và service token")
    p.add_argument("--env", default="vault.env")
    p.add_argument("--template", default="vault.env.example")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    sub.add_parser("purge-expired", help="Xoá ánh xạ quá hạn").set_defaults(fn=cmd_purge)
    p = sub.add_parser("rotate-key", help="Xoay khoá mã hoá kho ánh xạ")
    p.add_argument("--env", default="vault.env")
    p.set_defaults(fn=cmd_rotate)
    sub.add_parser("check", help="Kiểm tra kho và LLM local").set_defaults(fn=cmd_check)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
