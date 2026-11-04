#!/usr/bin/env bash
# Cài các việc định kỳ của Privacy Vault vào systemd (chạy bằng sudo trên máy AI local).
#   purge   mỗi giờ   | monitor 5 phút | eval 2 giờ sáng
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "Chạy bằng sudo" >&2; exit 1; }
echo "THITHI_HOME=$ROOT" > /etc/default/thithi
install -m 644 "$ROOT"/deploy/systemd/thithi-vault@.service "$ROOT"/deploy/systemd/thithi-vault-*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now thithi-vault-purge.timer thithi-vault-monitor.timer thithi-vault-eval.timer
systemctl list-timers 'thithi-vault-*' --no-pager
echo "Xem log: journalctl -u 'thithi-vault@*' -f"
