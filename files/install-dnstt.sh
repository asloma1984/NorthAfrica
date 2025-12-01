#!/bin/bash

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/slowdns"
SERVICE_FILE="/etc/systemd/system/slowdns.service"

mkdir -p $CONFIG_DIR

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)   BINARY="dnstt-server-linux-amd64" ;;
    aarch64)  BINARY="dnstt-server-linux-arm64" ;;
    armv7l)   BINARY="dnstt-server-linux-arm" ;;
    armv6l)   BINARY="dnstt-server-linux-arm" ;;
    i686|i386) BINARY="dnstt-server-linux-386" ;;
    *) echo "[ERROR] Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "[INFO] Architecture detected: $ARCH → using $BINARY"

read -p "Enter NS Domain (example: dns.domain.com): " NS_DOMAIN
[[ -z "$NS_DOMAIN" ]] && echo "[ERROR] NS Domain cannot be empty!" && exit 1
echo "$NS_DOMAIN" > $CONFIG_DIR/ns

apt update -y
apt install -y wget curl iptables iptables-persistent

echo "[INFO] Downloading dnstt-server..."
wget -q -O $INSTALL_DIR/dnstt-server \
"https://github.com/ycd/dnstt/releases/latest/download/$BINARY"

if [[ ! -s $INSTALL_DIR/dnstt-server ]]; then
    echo "[ERROR] dnstt-server download failed!"
    exit 1
fi

chmod +x $INSTALL_DIR/dnstt-server

$INSTALL_DIR/dnstt-server -gen-key \
    -privkey-file $CONFIG_DIR/server.key \
    -pubkey-file $CONFIG_DIR/server.pub

PUBKEY=$(cat $CONFIG_DIR/server.pub)

iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
netfilter-persistent save >/dev/null 2>&1

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

echo "NS Domain: $NS_DOMAIN"
echo "Public Key: $PUBKEY"
echo "Port (UDP): 5300"