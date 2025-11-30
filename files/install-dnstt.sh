#!/bin/bash
# SlowDNS Installer by NorthAfrica Script
# telegram: https://t.me/northafrica9

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

clear
echo -e "${GREEN}SlowDNS Setup Starting...${NC}"
sleep 1

# ===============================
# Variables
# ===============================
DNSTT_URL="https://github.com/ycd/dnstt/releases/latest/download"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/slowdns"
SERVICE="/etc/systemd/system/slowdns.service"

mkdir -p $CONFIG_DIR

# ===============================
# Choose NS Domain
# ===============================
read -p "Enter SlowDNS NS Domain (example: dns.yourdomain.com): " NS
echo "$NS" > $CONFIG_DIR/ns

# ===============================
# Download dnstt-server
# ===============================
echo -e "${GREEN}Downloading dnstt-server...${NC}"
wget -q -O /usr/local/bin/dnstt-server "${DNSTT_URL}/dnstt-server-linux-amd64"

chmod +x /usr/local/bin/dnstt-server

# ===============================
# Generate Public & Private Keys
# ===============================
echo -e "${GREEN}Generating keys...${NC}"

dnstt-server -gen-key \
   -privkey-file $CONFIG_DIR/server.key \
   -pubkey-file $CONFIG_DIR/server.pub

PUBKEY=$(cat $CONFIG_DIR/server.pub)

# ===============================
# Create systemd Service
# ===============================
echo -e "${GREEN}Creating systemd service...${NC}"

cat > $SERVICE <<-EOF
[Unit]
Description=SlowDNS (dnstt) Server
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file $CONFIG_DIR/server.key $NS 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns
systemctl restart slowdns

# ===============================
# Output
# ===============================

clear
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  SlowDNS Installation Done   ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "NS Domain : $NS"
echo -e "Public Key:"
echo -e "${YELLOW}$PUBKEY${NC}"
echo -e "${GREEN}Port: 5300 (redirect from 53)${NC}"
echo -e "${GREEN}Config Dir: /etc/slowdns${NC}"
echo -e "${GREEN}Service: slowdns${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
