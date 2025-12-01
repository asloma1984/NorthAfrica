#!/bin/bash
# ---------------------------------------------------
# SlowDNS Installer by NorthAfrica Script
# Developer  : @NorthAfrica9
# Telegram   : https://t.me/northafrica9
# Group Chat : https://t.me/northafricagroup
# ---------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

clear
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}     SlowDNS Automatic Installer     ${NC}"
echo -e "${GREEN}       NorthAfrica Script 🇩🇿        ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
sleep 1

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/slowdns"
SERVICE_FILE="/etc/systemd/system/slowdns.service"

mkdir -p $CONFIG_DIR

# ---------------------------------------------------
# Detect architecture
# ---------------------------------------------------
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)   BINARY="dnstt-server-linux-amd64" ;;
    aarch64)  BINARY="dnstt-server-linux-arm64" ;;
    armv7l)   BINARY="dnstt-server-linux-arm" ;;
    armv6l)   BINARY="dnstt-server-linux-arm" ;;
    i686|i386) BINARY="dnstt-server-linux-386" ;;
    *) echo -e "${RED}[ERROR] Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${GREEN}[INFO] Architecture detected: $ARCH → using $BINARY${NC}"

# ---------------------------------------------------
# Ask NS Domain
# ---------------------------------------------------
read -p "Enter NS Domain (example: dns.domain.com): " NS_DOMAIN
if [[ -z "$NS_DOMAIN" ]]; then
    echo -e "${RED}[ERROR] NS Domain cannot be empty!${NC}"
    exit 1
fi
echo "$NS_DOMAIN" > $CONFIG_DIR/ns

# ---------------------------------------------------
# Install Dependencies
# ---------------------------------------------------
echo -e "${GREEN}[INFO] Installing dependencies...${NC}"
if command -v apt >/dev/null 2>&1; then
    apt update -y
    apt install -y wget curl iptables iptables-persistent
elif command -v yum >/dev/null 2>&1; then
    yum install -y wget curl iptables iptables-services
fi

# ---------------------------------------------------
# Download dnstt-server (FIXED)
# ---------------------------------------------------
echo -e "${GREEN}[INFO] Downloading dnstt-server binary...${NC}"

wget -q -O $INSTALL_DIR/dnstt-server \
"https://github.com/ycd/dnstt/releases/latest/download/$BINARY"

if [[ ! -s $INSTALL_DIR/dnstt-server ]]; then
    echo -e "${RED}[ERROR] dnstt-server download failed!${NC}"
    exit 1
fi

chmod +x $INSTALL_DIR/dnstt-server

# ---------------------------------------------------
# Generate NEW public/private keys
# ---------------------------------------------------
echo -e "${GREEN}[INFO] Generating keys...${NC}"

rm -f $CONFIG_DIR/server.key
rm -f $CONFIG_DIR/server.pub

$INSTALL_DIR/dnstt-server -gen-key \
    -privkey-file $CONFIG_DIR/server.key \
    -pubkey-file $CONFIG_DIR/server.pub

if [[ ! -f $CONFIG_DIR/server.pub ]]; then
    echo -e "${RED}[ERROR] Failed to generate public key!${NC}"
    exit 1
fi

PUBKEY=$(cat $CONFIG_DIR/server.pub)

# ---------------------------------------------------
# Firewall
# ---------------------------------------------------
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
fi

# ---------------------------------------------------
# Systemd Service
# ---------------------------------------------------
cat > $SERVICE_FILE <<EOF
[Unit]
Description=SlowDNS (dnstt) Server by NorthAfrica
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file $CONFIG_DIR/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns
systemctl restart slowdns

# ---------------------------------------------------
# Output
# ---------------------------------------------------
clear
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}     SlowDNS Installed Successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "NS Domain     : ${YELLOW}$NS_DOMAIN${NC}"
echo -e "Public Key    : ${YELLOW}$PUBKEY${NC}"
echo -e "Port (UDP)    : 5300 → Redirected from 53"
echo -e "Config Path   : /etc/slowdns"
echo -e "Service Name  : slowdns"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Developer     : @NorthAfrica9"
echo -e "Telegram      : https://t.me/northafrica9"
echo -e "Group Chat    : https://t.me/northafricagroup"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"