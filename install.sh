#!/bin/bash
set -e

REPO_URL="https://github.com/asloma1984/NorthAfrica.git"
INSTALL_DIR="/root/NorthAfrica"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NorthAfrica Auto Script - Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sleep 1

# Ensure git is installed
if ! command -v git >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y git
fi

# Ensure wget is installed
if ! command -v wget >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y wget
fi

cd /root

# Clone or update repository
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing NorthAfrica repository..."
  cd "$INSTALL_DIR"
  git pull --rebase
else
  echo "Cloning NorthAfrica repository..."
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# Make sure premium.sh (shc binary) is executable
if [ -f premium.sh ]; then
  chmod +x premium.sh || true
fi

if [ ! -x premium.sh ]; then
  echo "[ERROR] premium.sh is missing or not executable. Please check repository."
  exit 1
fi

echo "Starting premium installer..."
./premium.sh

echo "Installer finished. You can now use NorthAfrica Script."
