#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Developer  : NORTH AFRICA TEAM
# Email      : Aslomaking1984@gmail.com
# Telegram   : https://t.me/northafrica9
# Telegram Group : https://t.me/groupnorthafrica
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# Install required tools
apt install jq curl -y

# Prepare folders
rm -rf /root/xray/scdomain
mkdir -p /root/xray
clear
echo ""
echo ""
echo ""

# Ask user for subdomain
read -rp "Input Subdomain Prefix (Example: vpn01): " -e sub

# Your Cloudflare Domain
DOMAIN=my-north-africa.com
SUB_DOMAIN=${sub}.my-north-africa.com

# Cloudflare API Token (YOU ADD IT HERE)
CF_TOKEN="L1XTye_QX7mg_XLw0yOHOBtFPpMZHUzBrQtFkufE"

set -euo pipefail

# Get server IP
IP=$(curl -sS ifconfig.me);

echo "Updating DNS for ${SUB_DOMAIN}..."

# Get Zone ID from Cloudflare
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
-H "Authorization: Bearer ${CF_TOKEN}" \
-H "Content-Type: application/json" | jq -r .result[0].id)

# Get existing DNS record (if exists)
RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${SUB_DOMAIN}" \
-H "Authorization: Bearer ${CF_TOKEN}" \
-H "Content-Type: application/json" | jq -r .result[0].id)

# Create new DNS record if not found
if [[ "${#RECORD}" -le 10 ]]; then
    RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" \
    --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' \
    | jq -r .result.id)
fi

# Update record
RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
-H "Authorization: Bearer ${CF_TOKEN}" \
-H "Content-Type: application/json" \
--data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}')

# Save domain information
echo "$SUB_DOMAIN" > /root/domain
echo "$SUB_DOMAIN" > /root/scdomain
echo "$SUB_DOMAIN" > /etc/xray/domain
echo "$SUB_DOMAIN" > /etc/v2ray/domain
echo "$SUB_DOMAIN" > /etc/xray/scdomain

# Store domain in config file
echo "IP=$SUB_DOMAIN" > /var/lib/kyt/ipvps.conf

# Clean
rm -rf cf
sleep 1

echo ""
echo "✔ Successfully added subdomain:"
echo "→ $SUB_DOMAIN"
echo ""