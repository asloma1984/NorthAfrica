#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9 to 13 / Ubuntu 18 to 25
# Developer  » Abdul (NorthAfrica Script)
# Channel    » https://t.me/northafrica9
# Group      » https://t.me/groupnorthafrica
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# North Africa Script

REPO="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/"

# Download systemd services
wget -q -O /etc/systemd/system/limitvmess.service "${REPO}files/limitvmess.service"
wget -q -O /etc/systemd/system/limitvless.service "${REPO}files/limitvless.service"
wget -q -O /etc/systemd/system/limittrojan.service "${REPO}files/limittrojan.service"
wget -q -O /etc/systemd/system/limitshadowsocks.service "${REPO}files/limitshadowsocks.service"

# Download limit scripts
wget -q -O /etc/xray/limit.vmess "${REPO}limit/vmess"
wget -q -O /etc/xray/limit.vless "${REPO}limit/vless"
wget -q -O /etc/xray/limit.trojan "${REPO}limit/trojan"
wget -q -O /etc/xray/limit.shadowsocks "${REPO}limit/shadowsocks"

# Permissions
chmod +x /etc/xray/limit.vmess
chmod +x /etc/xray/limit.vless
chmod +x /etc/xray/limit.trojan
chmod +x /etc/xray/limit.shadowsocks

# Enable services
systemctl daemon-reload
systemctl enable --now limitvmess
systemctl enable --now limitvless
systemctl enable --now limittrojan
systemctl enable --now limitshadowsocks