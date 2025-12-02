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

# Require root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[ERROR] This script must be run as root.${NC}"
  exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BINARY="dnstt-server-linux-amd64" ;;
    aarch64) BINARY="dnstt-server-linux-arm64" ;;
    armv7l|armv6l) BINARY="dnstt-server-linux-arm" ;;
    i386|i686) BINARY="dnstt-server-linux-386" ;;
    *)
        echo -e "${RED}[ERROR] Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}[INFO] Detected ARCH: $ARCH → binary: $BINARY${NC}"
echo ""

# Ask NS Domain
read -rp "Enter NS Domain (example: dns.domain.com): " NS_DOMAIN
if [[ -z "$NS_DOMAIN" ]]; then
    echo -e "${RED}[ERROR] NS Domain cannot be empty.${NC}"
    exit 1
fi

# Create config dir & save NS
mkdir -p "$CONFIG_DIR"
echo "$NS_DOMAIN" > "$CONFIG_DIR/ns"
# extra copies for compatibility with menus
echo "$NS_DOMAIN" > "$CONFIG_DIR/nsdomain" 2>/dev/null || true
mkdir -p /etc/xray 2>/dev/null || true
echo "$NS_DOMAIN" > /etc/xray/slowdns_ns 2>/dev/null || true

# Install dependencies
echo -e "${GREEN}[INFO] Installing required packages...${NC}"
if command -v apt >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt install -y wget curl iptables iptables-persistent netfilter-persistent socat
else
    yum install -y epel-release >/dev/null 2>&1 || true
    yum install -y wget curl iptables iptables-services
    systemctl enable --now iptables >/dev/null 2>&1 || true
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
"$INSTALL_DIR/dnstt-server" -gen-key \
    -privkey-file "$CONFIG_DIR/server.key" \
    -pubkey-file "$CONFIG_DIR/server.pub"

PUBKEY=$(cat "$CONFIG_DIR/server.pub")

# extra copies for menus (if they read other filenames)
echo "$PUBKEY" > "$CONFIG_DIR/public.key"
echo "$PUBKEY" > /etc/xray/slowdns_pub 2>/dev/null || true

# Firewall rules
echo -e "${GREEN}[INFO] Applying firewall rules…${NC}"
iptables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port "$DNSTT_PORT"

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
    netfilter-persistent reload >/dev/null 2>&1 || true
fi

# Create systemd service
echo -e "${GREEN}[INFO] Creating systemd service…${NC}"
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
echo -e " UDP Port    : ${YELLOW}$DNSTT_PORT${NC} (DNS 53 redirected)"
echo -e " Config Path : ${YELLOW}$CONFIG_DIR${NC}"
echo -e " Service     : ${YELLOW}slowdns${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo ""
echo -e "Now add this NS record in your DNS panel (Cloudflare etc.):"
echo -e "  ${YELLOW}$NS_DOMAIN  NS  <your-main-domain>${NC}"
echo ""