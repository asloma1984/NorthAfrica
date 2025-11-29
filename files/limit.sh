#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Developer  » Abdul NorthAfrica࿐
# Email      » yourmail@example.com
# Telegram   » https://t.me/YourChannel
# Group      » https://t.me/YourGroup
# Whatsapp   » wa.me/+212600000000
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REPO="https://raw.githubusercontent.com/YourGitHubUser/YourRepo/main/"

# Download and install service files
wget -q -O /etc/systemd/system/limitvmess.service "${REPO}files/limitvmess.service" && chmod +x /etc/systemd/system/limitvmess.service >/dev/null 2>&1
wget -q -O /etc/systemd/system/limitvless.service "${REPO}files/limitvless.service" && chmod +x /etc/systemd/system/limitvless.service >/dev/null 2>&1
wget -q -O /etc/systemd/system/limittrojan.service "${REPO}files/limittrojan.service" && chmod +x /etc/systemd/system/limittrojan.service >/dev/null 2>&1
wget -q -O /etc/systemd/system/limitshadowsocks.service "${REPO}files/limitshadowsocks.service" && chmod +x /etc/systemd/system/limitshadowsocks.service >/dev/null 2>&1

# Download IP limit scripts for each protocol
wget -q -O /etc/xray/limit.vmess "${REPO}limit/vmess" >/dev/null 2>&1
wget -q -O /etc/xray/limit.vless "${REPO}limit/vless" >/dev/null 2>&1
wget -q -O /etc/xray/limit.trojan "${REPO}limit/trojan" >/dev/null 2>&1
wget -q -O /etc/xray/limit.shadowsocks "${REPO}limit/shadowsocks" >/dev/null 2>&1

# Apply permissions
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

echo -e "\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[0;32m      Limit Services Installed     \e[0m"
echo -e "\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[33mTelegram:\e[0m https://t.me/YourChannel"
echo -e "\e[33mGroup:\e[0m https://t.me/YourGroup"
echo -e "\e[33mWhatsApp:\e[0m wa.me/+212600000000"
echo -e "\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"