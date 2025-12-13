#!/bin/bash
set -euo pipefail

REPO_BASE="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main"
ENC_URL="$REPO_BASE/premium.enc"

# Ensure curl is installed
if ! command -v curl >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y curl
fi

# Ensure openssl is installed
if ! command -v openssl >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y openssl
fi

TMP_ENC=$(mktemp)
TMP_DEC=$(mktemp)

echo ""
echo ">>> NorthAfrica encrypted installer"
echo "Downloading encrypted installer payload from GitHub..."

# Download encrypted file
if ! curl -fsSL "$ENC_URL" -o "$TMP_ENC"; then
  echo "[ERROR] Failed to download premium.enc from GitHub"
  rm -f "$TMP_ENC" "$TMP_DEC"
  exit 1
fi

# Ask for the same password used with openssl enc
echo ""
read -s -p "Enter installer password: " PASS
echo ""

echo "Decrypting payload..."
if ! openssl enc -d -aes-256-cbc -pbkdf2 \
  -pass pass:"$PASS" \
  -in "$TMP_ENC" -out "$TMP_DEC"; then
  echo ""
  echo "[ERROR] Decryption failed (wrong password or corrupted premium.enc)"
  rm -f "$TMP_ENC" "$TMP_DEC"
  exit 1
fi

chmod +x "$TMP_DEC"

echo ""
echo "Running installer script..."
bash "$TMP_DEC"

echo ""
echo "Installer finished. You can now use NorthAfrica Script."

rm -f "$TMP_ENC" "$TMP_DEC"
