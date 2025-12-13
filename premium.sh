#!/bin/bash
set -e

REPO_BASE="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main"
ENC_URL="$REPO_BASE/premium.enc"

# Ensure curl is installed
if ! command -v curl >/dev/null 2>&1; then
  apt update -y && apt install -y curl
fi

# Ensure openssl is installed
if ! command -v openssl >/dev/null 2>&1; then
  apt update -y && apt install -y openssl
fi

TMP="$(mktemp -t na_premium.XXXXXX)"

echo ""
echo "Downloading encrypted installer from GitHub..."
# Download encrypted file from GitHub
if ! curl -fsSL "$ENC_URL" -o "$TMP"; then
  echo "[ERROR] Failed to download premium.enc from $ENC_URL"
  rm -f "$TMP"
  exit 1
fi

# Ask for the same password used with openssl enc
echo ""
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
echo "Installer finished successfully."
