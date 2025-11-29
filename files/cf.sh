#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Requirement : Debian 9+ / Ubuntu 18.04+ / 20+
# Developer  : Abdul NorthAfrica
# Email      : abdul@northafrica.dev
# Telegram   : https://t.me/AbdulNorthAfrica
# WhatsApp   : wa.me/+0000000000000
# Description: Automatically add and update Cloudflare DNS A record.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Install required packages
apt install jq curl -y >/dev/null 2>&1

# Prepare directories
rm -rf /root/xray/scdomain >/dev/null 2>&1
mkdir -p /root/xray
clear

echo ""
echo ""
echo ""
# You can generate a random subdomain if needed:
# sub=$(</dev/urandom tr -dc a-z0-9 | head -c3)
read -rp "Enter Subdomain Name (Example: vpn01): " -e sub

# Main domain and subdomain
DOMAIN="serverpremium.biz.id"
SUB_DOMAIN="${sub}.serverpremium.biz.id"

# ⚠️ Cloudflare account credentials (replace with your real ones)
CF_ID="vscobangst111@gmail.com"
CF_KEY="4a912a2d56a1b3837d48751da5334b74a4fb8"

set -euo pipefail
IP=$(curl -sS ifconfig.me)

echo ""
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "Updating DNS record for: \e[32m${SUB_DOMAIN}\e[0m"
echo -e "Detected Server IP: \e[33m${IP}\e[0m"
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"

# Fetch the Zone ID for your domain
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" | jq -r .result[0].id)

# Fetch existing DNS record ID (if any)
RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${SUB_DOMAIN}" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" | jq -r .result[0].id)

# If record doesn't exist, create a new one
if [[ "${#RECORD}" -le 10 ]]; then
  echo -e "\e[33mDNS record not found, creating a new one...\e[0m"
  RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
  -H "X-Auth-Email: ${CF_ID}" \
  -H "X-Auth-Key: ${CF_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

# Update the DNS record with current IP
RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" \
--data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}')

# Save the domain to local files for other services
echo "$SUB_DOMAIN" | tee /root/domain /root/scdomain >/dev/null
mkdir -p /etc/xray /etc/v2ray /var/lib/kyt >/dev/null 2>&1
echo "$SUB_DOMAIN" | tee /etc/xray/domain /etc/v2ray/domain /etc/xray/scdomain >/dev/null
echo "IP=$SUB_DOMAIN" > /var/lib/kyt/ipvps.conf

# Clean up
rm -rf cf >/dev/null 2>&1
sleep 1

echo ""
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[0;32mDNS Updated Successfully!\e[0m"
echo -e "Your domain is: \e[33m${SUB_DOMAIN}\e[0m"
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"