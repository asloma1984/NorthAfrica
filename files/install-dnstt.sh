#!/bin/bash

# ======================================================================
#   DNSTT SlowDNS Server Installer  (Clean & Stable Version)
#   Developer: NorthAfrica
#   Works on: Debian, Ubuntu, Rocky, AlmaLinux, Fedora, CentOS
#   Language: English
# ======================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/slowdns"
SERVICE_FILE="/etc/systemd/system/slowdns.service"
DNSTT_PORT="5300"

DNSTT_BASE_URL="https://dnstt.network"

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}            NorthAfrica SlowDNS Installer           ${NC}"
echo -e "${GREEN}=====================================================${NC}"
sleep 1

# Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) BINARY="dnstt-server-linux-amd64" ;;
    aarch64) BINARY="dnstt-server-linux-arm64" ;;
    armv7l|armv6l) BINARY="dnstt-server-linux-arm" ;;
    i386|i686) BINARY="dnstt-server-linux-386" ;;
    *) echo -e "${RED}[ERROR] Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${GREEN}[INFO] Detected ARCH: $ARCH → $BINARY${NC}"

# Ask NS Domain
read -p "Enter NS Domain (example: dns.domain.com): " NS_DOMAIN
if [[ -z "$NS_DOMAIN" ]]; then
    echo -e "${RED}[ERROR] NS Domain cannot be empty.${NC}"
    exit 1
fi

mkdir -p $CONFIG_DIR
echo "$NS_DOMAIN" > "$CONFIG_DIR/ns"

# Install Dependencies
if command -v apt >/dev/null 2>&1; then
    apt update -y
    apt install -y wget curl iptables iptables-persistent
else
    yum install -y wget curl iptables iptables-services
fi

# Download DNSTT Binary
echo -e "${GREEN}[INFO] Downloading dnstt-server…${NC}"

wget -q -O "$INSTALL_DIR/dnstt-server" \
"$DNSTT_BASE_URL/$BINARY"

if [[ ! -s "$INSTALL_DIR/dnstt-server" ]]; then
    echo -e "${RED}[ERROR] dnstt-server download failed!${NC}"
    exit 1
fi

chmod +x "$INSTALL_DIR/dnstt-server"

# Generate Keys
echo -e "${GREEN}[INFO] Generating server keys…${NC}"

$INSTALL_DIR/dnstt-server -gen-key \
    -privkey-file "$CONFIG_DIR/server.key" \
    -pubkey-file "$CONFIG_DIR/server.pub"

PUBKEY=$(cat "$CONFIG_DIR/server.pub")

# Firewall Rules
iptables -I INPUT -p udp --dport $DNSTT_PORT -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port $DNSTT_PORT
netfilter-persistent save >/dev/null 2>&1 || true

# Create Systemd Service
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SlowDNS DNSTT Server
After=network.target

[Service]
ExecStart=$INSTALL_DIR/dnstt-server -udp :$DNSTT_PORT -privkey-file $CONFIG_DIR/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns
systemctl restart slowdns

clear

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}         SlowDNS (DNSTT) Installed Successfully       ${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo -e " NS Domain   : ${YELLOW}$NS_DOMAIN${NC}"
echo -e " Public Key  : ${YELLOW}$PUBKEY${NC}"
echo -e " UDP Port    : 5300 (DNS 53 redirected)"
echo -e " Config Path : /etc/slowdns"
echo -e " Service     : slowdns"
echo -e "${GREEN}=====================================================${NC}"
echo ""