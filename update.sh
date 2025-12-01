#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# North Africa Script - Encrypted Update Loader
# System Request : Debian 9+/Ubuntu 18.04+/20+/24+
# Developer   » Abdul (NorthAfrica Script)
# Repo        » https://github.com/asloma1984/NorthAfrica
# Register    » https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/register
# Contact     » Telegram: t.me/Abdulsalam403
# Year        » 2025
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NC='\e[0m'
RED="\033[31m"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'

# --------------------------------------------------------------------
# Encrypted (gzip+base64) payload + Anti-Tamper (sha256)
# --------------------------------------------------------------------
PAYLOAD_B64='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'

EXPECTED_SHA256='aebc812d930f7a228154118f85f38778cfa1a8d4d440e5a446f84ca780f0a09d'

# --------------------------------------------------------------------
# Decode + run encrypted payload
# --------------------------------------------------------------------
if ! command -v base64 >/dev/null 2>&1 || ! command -v gzip >/dev/null 2>&1; then
  echo -e "${RED}ERROR:${NC} Missing required tools (base64, gzip)."
  echo -e "Please install them first, for example:"
  echo -e "  ${GREEN}apt update && apt install -y coreutils gzip${NC}"
  exit 1
fi

CALC_SHA256=$(printf '%s' "$PAYLOAD_B64" | sha256sum | awk '{print $1}')

if [[ "$CALC_SHA256" != "$EXPECTED_SHA256" ]]; then
  echo -e "${RED}ERROR:${NC} Script integrity check failed."
  echo -e "This file has been modified or corrupted."
  echo -e "Please download a fresh copy from the official repository:"
  echo -e "  ${GREEN}https://github.com/asloma1984/NorthAfrica${NC}"
  exit 1
fi

TMP_SCRIPT="$(mktemp /tmp/.upd.XXXXXX)" || {
  echo -e "${RED}ERROR:${NC} Failed to create temporary file."
  exit 1
}

if ! printf '%s' "$PAYLOAD_B64" | base64 -d 2>/dev/null | gzip -d 2>/dev/null > "$TMP_SCRIPT"; then
  echo -e "${RED}ERROR:${NC} Failed to decode internal update script."
  rm -f "$TMP_SCRIPT"
  exit 1
fi

chmod +x "$TMP_SCRIPT"
bash "$TMP_SCRIPT"
RET=$?
rm -f "$TMP_SCRIPT"
exit $RET