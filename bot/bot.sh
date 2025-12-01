#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   North Africa Script - Bot Installer  (PRIVATE REPO)
#   Works on: Debian 9–13 / Ubuntu 18–25
#   Author   : Abdul
#   Channel  : https://t.me/northafrica9
#   Group    : https://t.me/groupnorthafrica
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ===== License check (must be installed earlier) =====
if [[ -f /usr/local/lib/na-license.sh ]]; then
  # shellcheck disable=SC1091
  source /usr/local/lib/na-license.sh
  check_license_or_exit
fi

# ===== Repo info (keep here) =====
GH_OWNER="asloma1984"
GH_REPO="NorthAfrica"
GH_REF="main"
GH_TOKEN_FILE="/etc/kyt/.gh_token"

# ===== ghget: fetch any path from PRIVATE repo as raw =====
ghget() {
  local path="$1"
  [[ -z "$path" ]] && { echo "Usage: ghget path/in/repo" >&2; return 1; }

  # Prefer helper if it exists
  if command -v ghget >/dev/null 2>&1 && [[ "$(command -v ghget)" != "$0" ]]; then
    command ghget "$path"
    return
  fi

  # Inline fallback
  local token=""
  if [[ -f "$GH_TOKEN_FILE" ]]; then
    token="$(tr -d '\n' < "$GH_TOKEN_FILE")"
  elif [[ -n "${GH_TOKEN:-}" ]]; then
    token="$GH_TOKEN"
  fi
  [[ -z "$token" ]] && { echo "Missing token: $GH_TOKEN_FILE or GH_TOKEN" >&2; return 1; }

  curl -fsSL \
    -H "Authorization: token $token" \
    -H "Accept: application/vnd.github.raw" \
    "https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${path}?ref=${GH_REF}"
}

# ===== Basic env data =====
domain="$(cat /etc/xray/domain 2>/dev/null || echo "")"
NS="$(cat /etc/xray/dns 2>/dev/null || echo "")"
PUB="$(cat /etc/slowdns/server.pub 2>/dev/null || echo "")"

# ===== Packages =====
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y python3 python3-pip unzip curl git
# PEP 668 على ديبيان 12 – لو فشل pip بسبب النظام المُدار بالحزم
pip3 --version >/dev/null 2>&1 || true

# ===== Download bot.zip & kyt.zip from PRIVATE repo =====
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "[*] Downloading bot.zip & kyt.zip from private repo…"
ghget "bot/bot.zip" > "$tmpdir/bot.zip"
ghget "bot/kyt.zip" > "$tmpdir/kyt.zip"

# ===== Install bot scripts =====
echo "[*] Installing bot scripts to /usr/bin…"
unzip -oq "$tmpdir/bot.zip" -d "$tmpdir/bot"
# الأرشيف يحتوي مجلد bot/ بداخله سكربتات
if [[ -d "$tmpdir/bot/bot" ]]; then
  install -m 0755 "$tmpdir/bot"/bot/* /usr/bin/
else
  install -m 0755 "$tmpdir/bot"/* /usr/bin/
fi

# ===== Install Python package kyt =====
echo "[*] Installing Python package kyt…"
unzip -oq "$tmpdir/kyt.zip" -d /usr/bin
# تثبيت المتطلبات
if [[ -f /usr/bin/kyt/requirements.txt ]]; then
  pip3 install -r /usr/bin/kyt/requirements.txt \
    || pip3 install --break-system-packages -r /usr/bin/kyt/requirements.txt
fi

# ===== Ask for Bot token & admin id =====
echo ""
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[1;97;101m              » ADD BOT PANEL «              \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "Create bot on @BotFather and get your token."
echo -e "Get your Telegram ID from @MissRose_bot or @userinfobot"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""

read -r -p "[»] Input your Bot Token   : " bottoken
read -r -p "[»] Input Your Id Telegram : " admin

mkdir -p /usr/bin/kyt
cat > /usr/bin/kyt/var.txt <<EOF
BOT_TOKEN="$bottoken"
ADMIN="$admin"
DOMAIN="$domain"
PUB="$PUB"
HOST="$NS"
EOF

# ===== systemd service =====
cat > /etc/systemd/system/kyt.service <<'UNIT'
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/python3 -m kyt
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable kyt >/dev/null 2>&1 || true
systemctl restart kyt

clear
echo "Input Data Successfully processed!"
echo "Your Bot Telegram:"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Token Bot  : $bottoken"
echo "Admin      : $admin"
echo "Domain     : ${domain:-N/A}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Installations complete. Type /menu in your bot."
read -r -p "Press Enter to back to menu… " _
command -v menu >/dev/null 2>&1 && menu || true