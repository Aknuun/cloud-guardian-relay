#!/usr/bin/env bash
# ============================================================
# srv-relay installer — رلهٔ واحد SSH برای ربات نگهبان ابری
# نصب/آپدیت:  sudo bash -c "$(curl -sL https://raw.githubusercontent.com/Aknuun/cloud-guardian-relay/main/srv-relay-install.sh)"
# یا با توکن دلخواه:  sudo SRV_RELAY_TOKEN=<token> bash srv-relay-install.sh
# • اگر srv-relay.js کنار اسکریپت باشد از همان استفاده می‌شود؛
#   وگرنه از مخزن گیت‌هاب دانلود می‌شود.
# • در آپدیت، توکنِ سرویسِ قبلی حفظ می‌شود (مگر توکن جدید بدهید).
# ============================================================
set -euo pipefail

APP_NAME="srv-relay"
APP_DIR="/opt/srv-relay"
SERVICE="${APP_NAME}.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE}"
RAW_URLS=(
  "https://raw.githubusercontent.com/Aknuun/cloud-guardian-relay/main/srv-relay.js"
  "https://cdn.jsdelivr.net/gh/Aknuun/cloud-guardian-relay@main/srv-relay.js"
)
TOKEN="${SRV_RELAY_TOKEN:-}"

# --- منبع فایل رله: کنار اسکریپت یا دانلود از مخزن ---
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo ".")"
if [ -f "${SRC_DIR}/srv-relay.js" ]; then
  SRC_FILE="${SRC_DIR}/srv-relay.js"
  echo "[*] استفاده از فایل محلی: ${SRC_FILE}"
else
  SRC_FILE="/tmp/srv-relay.js.$(date +%s)"
  echo "[*] دانلود srv-relay.js از مخزن…"
  ok=0
  for u in "${RAW_URLS[@]}"; do
    # cache-buster: کش CDN را دور می‌زنیم تا همیشه آخرین نسخه نصب شود
    bu="$u?_=$(date +%s)"
    echo "    -> $u"
    if curl -fsSL --max-time 30 "$bu" -o "$SRC_FILE" && grep -q "RELAY_REV" "$SRC_FILE" 2>/dev/null; then
      ok=1; break
    fi
  done
  if [ "$ok" != "1" ]; then
    echo "[✗] دانلود نسخهٔ جدید ناموفق بود (کش CDN ممکن است قدیمی باشد)."
    echo "    چند دقیقه بعد دوباره اجرا کنید، یا فایل srv-relay.js را کنار اسکریپت بگذارید."
    exit 1
  fi
  echo "[✓] فایل جدید تأیید شد (شامل نشانگر rev)."
fi

mkdir -p "$APP_DIR"
cp "$SRC_FILE" "${APP_DIR}/srv-relay.js"
chmod 755 "${APP_DIR}/srv-relay.js"
[ "${SRC_FILE}" != "${APP_DIR}/srv-relay.js" ] && rm -f "$SRC_FILE" || true

# --- توکن: env > سرویس قبلی > تصادفی ---
if [ -z "$TOKEN" ] && [ -f "$SERVICE_FILE" ]; then
  TOKEN=$(grep -oP 'Environment=SRV_RELAY_TOKEN=\K.*' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
  if [ -n "$TOKEN" ]; then
    echo "[*] توکن سرویس قبلی حفظ شد."
  fi
fi
if [ -z "$TOKEN" ]; then
  TOKEN=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  echo "[*] توکن تصادفی ساخته شد: $TOKEN"
fi

echo "[*] نصب پیش‌نیازها (openssh-client، sshpass برای احراز رمزی)…"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true
  apt-get install -y -qq openssh-client sshpass curl >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y openssh-clients sshpass curl >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
  yum install -y openssh-clients sshpass curl >/dev/null 2>&1 || true
fi

echo "[*] ساخت سرویس systemd…"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=srv-relay — unified SSH relay for Cloud Guardian Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
Environment=SRV_RELAY_PORT=8788
Environment=SRV_RELAY_TOKEN=${TOKEN}
ExecStart=$(command -v node || echo /usr/bin/node) ${APP_DIR}/srv-relay.js
Restart=always
RestartSec=5
NoNewPrivileges=no
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"

sleep 1
if systemctl is-active --quiet "$SERVICE"; then
  echo "[✓] srv-relay فعال شد روی پورت 8788"
  echo "    تست:  curl http://127.0.0.1:8788/ping"
  echo "    (توکن در فایل سرویس ذخیره شده: ${SERVICE_FILE})"
else
  echo "[✗] سرویس فعال نشد؛ لاگ:"
  journalctl -u "$SERVICE" -n 20 --no-pager
  exit 1
fi

# --- خودتست: مطمئن شو کد جدید (rev>=2) واقعاً فعال است ---
REV=$(curl -s -m 5 http://127.0.0.1:8788/ping | grep -o '"rev":[0-9]*' | grep -o '[0-9]*' || echo 0)
if [ "${REV:-0}" -ge 2 ] 2>/dev/null; then
  echo "[✓] بازبینی فعال: rev=$REV (کد جدید)"
else
  echo "[✗] هشدار: /ping بازبینی rev=$REV نشان می‌دهد — کد جدید فعال نشده!"
  echo "    دستی اجرا کنید:  systemctl restart srv-relay  و دوباره اسکریپت را بزنید."
  exit 1
fi
TEST=$(curl -s -m 25 -X POST http://127.0.0.1:8788/exec \
  -H "Content-Type: application/json" -H "X-SRV-Token: $TOKEN" \
  -d '{"host":"127.0.0.1","port":22,"user":"root","password":"x","command":"echo ok"}' || true)
if printf '%s' "$TEST" | grep -q 'resolve hostname /tmp/'; then
  echo "[✗] خودتست شکست: هنوز کد قدیمی در حال اجراست! سرویس را دستی ری‌استارت کنید:"
  echo "    systemctl restart srv-relay"
  exit 1
elif printf '%s' "$TEST" | grep -q 'Connection refused\|Connection timed out\|Permission denied\|password'; then
  echo "[✓] خودتست موفق: احراز رمزی درست کار می‌کند (ssh به هاست واقعی وصل شد)."
else
  echo "[i] خودتست (اطلاعاتی): ${TEST:0:200}"
fi
