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
echo -e "${GREEN}       NorthAfrica Script 🇱🇾        ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
sleep 1

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/slowdns"
SERVICE_FILE="/etc/systemd/system/slowdns.service"

mkdir -p $CONFIG_DIR

# Detect architecture (correct GitHub names)
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)   BINARY="dnstt-server-x86_64-linux-gnu" ;;
    aarch64)  BINARY="dnstt-server-aarch64-linux-gnu" ;;
    armv7l)   BINARY="dnstt-server-arm-linux-gnueabi" ;;
    armv6l)   BINARY="dnstt-server-arm-linux-gnueabi" ;;
    i686|i386) BINARY="dnstt-server-i686-linux-gnu" ;;
    *) echo -e "${RED}[ERROR] Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${GREEN}[INFO] Architecture detected: $ARCH → using $BINARY${NC}"

# Ask domain
read -p "Enter NS Domain (example: dns.domain.com): " NS_DOMAIN
if [[ -z "$NS_DOMAIN" ]]; then
    echo -e "${RED}[ERROR] NS Domain cannot be empty!${NC}"
    exit 1
fi

echo "$NS_DOMAIN" > $CONFIG_DIR/ns

# Dependencies
echo -e "${GREEN}[INFO] Installing dependencies...${NC}"
if command -v apt >/dev/null 2>&1; then
    apt update -y
    apt install -y wget curl iptables iptables-persistent
elif command -v yum >/dev/null 2>&1; then
    yum install -y wget curl iptables iptables-services
fi

# Download dnstt-server
echo -e "${GREEN}[INFO] Downloading dnstt-server binary...${NC}"
wget -q -O $INSTALL_DIR/dnstt-server \
"https://github.com/ycd/dnstt/releases/latest/download/$BINARY"

if [[ ! -s $INSTALL_DIR/dnstt-server ]]; then
    echo -e "${RED}[ERROR] dnstt-server download failed!${NC}"
    exit 1
fi

chmod +x $INSTALL_DIR/dnstt-server

# Generate Keys
$INSTALL_DIR/dnstt-server -gen-key \
    -privkey-file $CONFIG_DIR/server.key \
    -pubkey-file $CONFIG_DIR/server.pub

PUBKEY=$(cat $CONFIG_DIR/server.pub)

# Firewall
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
netfilter-persistent save >/dev/null 2>&1

# Create service
cat > $SERVICE_FILE <<EOF
[Unit]
Description=SlowDNS dnstt Server
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

clear
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   SlowDNS Installed Successfully!   ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "NS Domain   : ${YELLOW}$NS_DOMAIN${NC}"
echo -e "Public Key  : ${YELLOW}$PUBKEY${NC}"
echo -e "Port (UDP)  : 5300"
echo -e "Config Path : /etc/slowdns"
echo -e "Service     : slowdns"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"