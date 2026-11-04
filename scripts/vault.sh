#!/usr/bin/env bash
# Vận hành Privacy Vault trên máy AI local (Ubuntu + Docker Compose). Chạy tay hoặc từ systemd timer.
#
#   scripts/vault.sh setup        # lần đầu: tạo khoá, thư mục, dựng và chạy stack, chờ sẵn sàng
#   scripts/vault.sh check        # kho + LLM local sẵn sàng chưa
#   scripts/vault.sh purge        # xoá ánh xạ quá hạn                       (timer: mỗi giờ)
#   scripts/vault.sh monitor      # đo và cảnh báo Teams nếu bất thường        (timer: 5 phút)
#   scripts/vault.sh eval         # nghiệm thu trên bộ mẫu PII thật, cảnh báo nếu rò rỉ (timer: 2 giờ sáng)
#   scripts/vault.sh rotate-key   # xoay khoá mã hoá kho (dừng Vault vài giây)
#
# Biến: THITHI_HOME (mặc định: thư mục repo), THITHI_PII_SAMPLES (mặc định: data/vault/pii_samples.jsonl).
set -euo pipefail

ROOT="${THITHI_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml" --project-directory "$ROOT/deploy")
SAMPLES="${THITHI_PII_SAMPLES:-$ROOT/data/vault/pii_samples.jsonl}"

vault() { "${COMPOSE[@]}" exec -T privacy-vault "$@"; }
gateway() { "${COMPOSE[@]}" exec -T gateway "$@"; }
# Cảnh báo đi qua gateway: container privacy-vault không có đường ra internet.
notify() { gateway python -m thithi.privacy.monitor --notify "$1" || echo "Không gửi được cảnh báo: $1" >&2; }

wait_ready() {
  for _ in $(seq 1 60); do
    if vault python -m thithi.privacy.admin check >/dev/null 2>&1; then
      echo "Privacy Vault sẵn sàng."; return 0
    fi
    sleep 5
  done
  echo "Privacy Vault chưa sẵn sàng sau 5 phút. Xem: ${COMPOSE[*]} logs privacy-vault ai-local" >&2
  return 1
}

case "${1:-}" in
  setup)
    command -v docker >/dev/null || { echo "Cần cài Docker và Docker Compose" >&2; exit 1; }
    mkdir -p "$ROOT/data/vault" "$ROOT/data/gateway"
    chmod 700 "$ROOT/data/vault"
    [ -f "$ROOT/.env" ] || { cp "$ROOT/.env.example" "$ROOT/.env"; chmod 600 "$ROOT/.env"; }
    [ -f "$ROOT/vault.env" ] || install -m 600 "$ROOT/vault.env.example" "$ROOT/vault.env"
    if ! grep -q '^PRIVACY_VAULT_KEY=.\+' "$ROOT/vault.env"; then
      python3 -m thithi.privacy.admin init --env "$ROOT/vault.env" --template "$ROOT/vault.env.example" 2>/dev/null \
        || "${COMPOSE[@]}" run --rm --no-deps -v "$ROOT:/host" privacy-vault \
             python -m thithi.privacy.admin init --env /host/vault.env --template /host/vault.env.example
      token=$(grep '^PRIVACY_SERVICE_TOKEN=' "$ROOT/vault.env" | cut -d= -f2-)
      sed -i "s|^PRIVACY_SERVICE_TOKEN=.*|PRIVACY_SERVICE_TOKEN=${token}|" "$ROOT/.env"
    fi
    "${COMPOSE[@]}" up -d --build
    wait_ready
    echo "Xong. Điền ANTHROPIC_API_KEY và THITHI_ALERT_WEBHOOK trong .env, rồi cài timer: sudo scripts/install-timers.sh"
    ;;
  check)
    vault python -m thithi.privacy.admin check
    ;;
  purge)
    vault python -m thithi.privacy.admin purge-expired
    ;;
  monitor)
    gateway python -m thithi.privacy.monitor --url http://privacy-vault:8090 --state /app/data/monitor-state.json
    ;;
  eval)
    [ -f "$SAMPLES" ] || { echo "Chưa có bộ mẫu $SAMPLES" >&2; exit 1; }
    # data/vault được mount vào /app/vault; bộ mẫu chứa dữ liệu thật nên chỉ nằm ở đó
    if ! vault python -m thithi.privacy.evaluate "/app/vault/$(basename "$SAMPLES")"; then
      notify "Nghiệm thu PII trên bộ mẫu thất bại (còn rò rỉ hoặc tái tạo sai). Xem journalctl -u thithi-vault-eval."
      exit 1
    fi
    ;;
  rotate-key)
    "${COMPOSE[@]}" stop privacy-vault
    "${COMPOSE[@]}" run --rm --no-deps -v "$ROOT/vault.env:/app/vault.env" privacy-vault \
      python -m thithi.privacy.admin rotate-key --env /app/vault.env \
      || { "${COMPOSE[@]}" up -d privacy-vault; echo "Xoay khoá thất bại, kho giữ nguyên khoá cũ." >&2; exit 1; }
    "${COMPOSE[@]}" up -d privacy-vault
    wait_ready
    ;;
  *)
    sed -n "2,10p" "$0"; exit 1
    ;;
esac
