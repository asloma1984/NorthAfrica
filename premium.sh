#!/bin/bash
set -e

REPO_BASE="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main"
ENC_URL="$REPO_BASE/premium.enc"

# تأكد من وجود curl
if ! command -v curl >/dev/null 2>&1; then
  apt update -y && apt install -y curl
fi

# تأكد من وجود openssl
if ! command -v openssl >/dev/null 2>&1; then
  apt update -y && apt install -y openssl
fi

TMP=$(mktemp)

echo ""
echo "Downloading encrypted installer..."
# تحميل الملف المشفَّر من GitHub
if ! curl -fsSL "$ENC_URL" -o "$TMP"; then
  echo "[ERROR] Failed to download premium.enc"
  rm -f "$TMP"
  exit 1
fi

# طلب نفس الباسورد الذي استعملته في openssl enc
read -s -p "Enter installer password: " PASS
echo ""

echo "Decrypting and running installer..."
if ! openssl enc -d -aes-256-cbc -pbkdf2 \
  -pass pass:"$PASS" \
  -in "$TMP" | bash; then
  echo "[ERROR] Decrypt or run failed (wrong password or corrupted file)"
  rm -f "$TMP"
  exit 1
fi

rm -f "$TMP"
