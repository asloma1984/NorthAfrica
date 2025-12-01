#!/bin/bash

# ============================================================
#   DNSTT SlowDNS Server Installer (Clean & Stable Version)
#   Developer: NorthAfrica
#   Works on: Debian, Ubuntu, Rocky, AlmaLinux, Fedora, CentOS
#   Language: English only
# ============================================================

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

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}     SlowDNS Automatic Installer (DNSTT)      ${NC}"
echo -e "${GREEN}==============================================${NC}"
sleep 1

# ------------------------------------------------------------
#   Detect OS Package Manager
# ------------------------------------------------------------
detect_pkg_manager() {
    if command -v apt >/dev/null 2>&1; then
        PKG="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG="yum"
    else
        echo -e "${RED}[ERROR] Unsupported OS.${NC}"
        exit 1
    fi
}

# ------------------------------------------------------------
#   Detect Architecture
# ------------------------------------------------------------
detect_arch() {
    case "$(uname -m)" in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv6l) ARCH="arm" ;;
        i386|i686) ARCH="386" ;;
        *)
            echo -e "${RED}[ERROR] Unsupported architecture: $(uname -m)${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}[INFO] Architecture detected: $ARCH${NC}"
}

# ------------------------------------------------------------
#   Install Dependencies
# ------------------------------------------------------------
install_dependencies() {
    echo -e "${GREEN}[INFO] Installing required packages...${NC}"

    if [[ $PKG == "apt" ]]; then
        apt update -y
        apt install -y wget curl iptables iptables-persistent
    else
        $PKG install -y wget curl iptables
    fi
}

# ------------------------------------------------------------
#   Ask for NS Domain
# ------------------------------------------------------------
read -p "Enter NS Domain (example: dns.example.com): " NS_DOMAIN
if [[ -z "$NS_DOMAIN" ]]; then
    echo -e "${RED}[ERROR] NS Domain cannot be empty.${NC}"
    exit 1
fi

mkdir -p $CONFIG_DIR
echo "$NS_DOMAIN" > "$CONFIG_DIR/ns"

# ------------------------------------------------------------
#   Download DNSTT Binary
# ------------------------------------------------------------
download_dnstt() {
    BINARY_NAME="dnstt-server-linux-${ARCH}"
    DOWNLOAD_URL="$DNSTT_BASE_URL/$BINARY_NAME"

    echo -e "${GREEN}[INFO] Downloading DNSTT from:${NC} $DOWNLOAD_URL"

    wget -q -O "$INSTALL_DIR/dnstt-server" "$DOWNLOAD_URL"
    if [[ ! -s "$INSTALL_DIR/dnstt-server" ]]; then
        echo -e "${RED}[ERROR] Failed to download dnstt-server binary.${NC}"
        exit 1
    fi

    chmod +x "$INSTALL_DIR/dnstt-server"
}

# ------------------------------------------------------------
#   Generate Keys
# ------------------------------------------------------------
generate_keys() {
    PRIVKEY="$CONFIG_DIR/server.key"
    PUBKEY="$CONFIG_DIR/server.pub"

    echo -e "${GREEN}[INFO] Generating server keys...${NC}"

    $INSTALL_DIR/dnstt-server -gen-key \
        -privkey-file "$PRIVKEY" \
        -pubkey-file "$PUBKEY"

    PUBKEY_CONTENT=$(cat $PUBKEY)
}

# ------------------------------------------------------------
#   Configure Firewall
# ------------------------------------------------------------
configure_firewall() {
    echo -e "${GREEN}[INFO] Configuring firewall...${NC}"

    iptables -I INPUT -p udp --dport $DNSTT_PORT -j ACCEPT
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port $DNSTT_PORT

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
}

# ------------------------------------------------------------
#   Create Systemd Service
# ------------------------------------------------------------
create_service() {
cat > $SERVICE_FILE <<EOF
[Unit]
Description=SlowDNS DNSTT Server
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file /etc/slowdns/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slowdns
    systemctl restart slowdns
}

# ------------------------------------------------------------
#   Display Final Information
# ------------------------------------------------------------
display_info() {
clear
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}      SlowDNS Installed Successfully!         ${NC}"
echo -e "${GREEN}==============================================${NC}"

echo -e "NS Domain   : ${YELLOW}$NS_DOMAIN${NC}"
echo -e "Public Key  : ${YELLOW}$PUBKEY_CONTENT${NC}"
echo -e "Port (UDP)  : 5300"
echo -e "Service     : slowdns"
echo -e "Config Dir  : /etc/slowdns"

echo -e "${GREEN}==============================================${NC}"
}

# ------------------------------------------------------------
#   Execute all steps
# ------------------------------------------------------------
detect_pkg_manager
detect_arch
install_dependencies
download_dnstt
generate_keys
configure_firewall
create_service
display_info