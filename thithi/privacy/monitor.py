"""Giám sát Privacy Vault: chạy theo lịch (systemd timer 5 phút), cảnh báo qua webhook Microsoft Teams.

    python -m thithi.privacy.monitor --url http://127.0.0.1:8090
    python -m thithi.privacy.monitor --notify "Nghiệm thu PII đêm qua có rò rỉ"   # gửi một cảnh báo bất kỳ

Mỗi lần chạy: gọi /readyz và /metrics, so với lần chạy trước (file trạng thái) rồi cảnh báo khi
- Vault hoặc LLM local không sẵn sàng (hoặc không gọi được Vault);
- tỉ lệ bị chặn vì LLM local lỗi hay còn sót PII vượt ngưỡng;
- có giá trị thay thế không tái tạo được, lỗi LLM khi tái tạo, hoặc lượt soát cuối phải che thêm.

Webhook đặt bằng `THITHI_ALERT_WEBHOOK` (Teams: tạo bằng Workflows "Post to a channel when a webhook request
is received"). Không đặt thì chỉ in ra stdout/journal. Nội dung cảnh báo chỉ có số đếm, không có dữ liệu.
Mã thoát: 0 bình thường, 2 có cảnh báo, để systemd/cron cũng thấy được.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from .metrics import parse

DEFAULT_STATE = "data/vault/monitor-state.json"


def _delta(now: dict[str, float], before: dict[str, float], key: str) -> float:
    return max(0.0, now.get(key, 0.0) - before.get(key, 0.0))


def evaluate(now: dict[str, float], before: dict[str, float], max_block_rate: float = 0.2, min_requests: int = 5) -> list[str]:
    """So số đo hiện tại với lần trước, trả về danh sách cảnh báo (rỗng = ổn)."""
    alerts: list[str] = []
    if not before:
        return alerts  # lần chạy đầu: chỉ ghi mốc
    if any(v < before.get(k, 0.0) for k, v in now.items() if k.endswith("_total") or "_total{" in k):
        return alerts  # Vault vừa khởi động lại, bộ đếm về 0: lấy mốc mới
    ok = _delta(now, before, 'thithi_vault_mask_total{result="ok"}')
    ner = _delta(now, before, 'thithi_vault_mask_total{result="ner_unavailable"}')
    leak = _delta(now, before, 'thithi_vault_mask_total{result="leak"}')
    total = ok + ner + leak
    if total >= min_requests and (ner + leak) / total > max_block_rate:
        alerts.append(
            f"{int(ner + leak)}/{int(total)} lần che bị chặn ({int(ner)} do LLM local lỗi, {int(leak)} do còn sót PII)."
        )
    elif ner and not ok:
        alerts.append(f"Mọi lần che đều bị chặn vì LLM local lỗi ({int(ner)} lần).")
    unresolved = _delta(now, before, "thithi_vault_unresolved_total")
    if unresolved:
        alerts.append(f"{int(unresolved)} dòng còn giá trị thay thế không tái tạo được (người dùng thấy giá trị giả).")
    restore_err = _delta(now, before, 'thithi_vault_llm_errors_total{step="restore"}')
    if restore_err:
        alerts.append(f"LLM local lỗi {int(restore_err)} lần khi tái tạo.")
    found = _delta(now, before, "thithi_vault_recheck_found_total")
    if found:
        alerts.append(
            f"Lượt soát cuối phải che thêm {int(found)} giá trị mà NER lượt đầu bỏ sót: nên xem lại mô hình/prompt NER."
        )
    return alerts


def send(webhook: str | None, title: str, lines: list[str], fmt: str = "teams") -> None:
    print(title)
    for line in lines:
        print(f"- {line}")
    if not webhook:
        return
    if fmt == "teams":
        body = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True}]
                    + [{"type": "TextBlock", "text": f"- {line}", "wrap": True} for line in lines],
                },
            }],
        }
    else:
        body = {"text": title + "\n" + "\n".join(f"- {line}" for line in lines)}
    httpx.post(webhook, json=body, timeout=10).raise_for_status()


def run(url: str, state_path: Path, webhook: str | None, fmt: str, max_block_rate: float, http: httpx.Client | None = None) -> int:
    client = http or httpx.Client(timeout=10)
    host = os.environ.get("THITHI_SITE", "AI local")
    try:
        ready = client.get(f"{url}/readyz")
        metrics = parse(client.get(f"{url}/metrics").text)
    except httpx.HTTPError as exc:
        send(webhook, f"[THITHI] Không gọi được Privacy Vault ({host})", [f"{type(exc).__name__}: {exc}",
             "Gateway sẽ chặn mọi yêu cầu lai cho tới khi Vault chạy lại."], fmt)
        return 2
    alerts: list[str] = []
    if ready.status_code != 200:
        checks = ready.json().get("checks", {}) if ready.headers.get("content-type", "").startswith("application/json") else {}
        alerts.append("Vault chưa sẵn sàng: " + (", ".join(f"{k}={v}" for k, v in checks.items()) or str(ready.status_code)))
    before = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    alerts += evaluate(metrics, before, max_block_rate)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(metrics), encoding="utf-8")
    if alerts:
        send(webhook, f"[THITHI] Cảnh báo Privacy Vault ({host})", alerts, fmt)
        return 2
    print("Privacy Vault ổn.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="thithi.privacy.monitor", description="Giám sát Privacy Vault")
    parser.add_argument("--url", default=os.environ.get("PRIVACY_URL", "http://127.0.0.1:8090"))
    parser.add_argument("--state", default=os.environ.get("THITHI_MONITOR_STATE", DEFAULT_STATE))
    parser.add_argument("--webhook", default=os.environ.get("THITHI_ALERT_WEBHOOK"))
    parser.add_argument("--format", choices=["teams", "text"], default=os.environ.get("THITHI_ALERT_FORMAT", "teams"))
    parser.add_argument("--max-block-rate", type=float, default=0.2)
    parser.add_argument("--notify", help="Gửi một cảnh báo với nội dung này rồi thoát")
    args = parser.parse_args(argv)
    if args.notify:
        send(args.webhook, "[THITHI] " + args.notify, [], args.format)
        return 0
    return run(args.url.rstrip("/"), Path(args.state), args.webhook, args.format, args.max_block_rate)


if __name__ == "__main__":
    sys.exit(main())
