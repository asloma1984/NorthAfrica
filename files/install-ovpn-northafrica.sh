
#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Developer  : NORTH AFRICA TEAM
# Email      : Aslomaking1984@gmail.com
# Telegram   : https://t.me/northafrica9
# Telegram Group : https://t.me/groupnorthafrica
# Script Name : install-ovpn-northafrica.sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipinfo.io/ip);
domain=$(cat /root/domain)
MYIP2="s/xxxxxxxxx/$domain/g";

function ovpn_install() {
    rm -rf /etc/openvpn
    mkdir -p /etc/openvpn
    wget -O /etc/openvpn/vpn.zip "https://raw.githubusercontent.com/jaka1m/project/main/ssh/vpn.zip" >/dev/null 2>&1 
    unzip -d /etc/openvpn/ /etc/openvpn/vpn.zip
    rm -f /etc/openvpn/vpn.zip
    chown -R root:root /etc/openvpn/server/easy-rsa/
}

function config_easy() {
    cd
    mkdir -p /usr/lib/openvpn/
    cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
    sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
    systemctl enable --now openvpn-server@server-tcp
    systemctl enable --now openvpn-server@server-udp
    /etc/init.d/openvpn restart
}

function make_follow() {
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

cat > /etc/openvpn/tcp.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END

    sed -i $MYIP2 /etc/openvpn/tcp.ovpn;

cat > /etc/openvpn/udp.ovpn <<-END
client
dev tun
proto udp
remote xxxxxxxxx 2200
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END

    sed -i $MYIP2 /etc/openvpn/udp.ovpn;

cat > /etc/openvpn/ws-ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END

    sed -i $MYIP2 /etc/openvpn/ws-ssl.ovpn;

cat > /etc/openvpn/ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END

    sed -i $MYIP2 /etc/openvpn/ssl.ovpn;
}

function cert_ovpn() {
    echo '<ca>' >> /etc/openvpn/tcp.ovpn
    cat /etc/openvpn/server/ca.crt >> /etc/openvpn/tcp.ovpn
    echo '</ca>' >> /etc/openvpn/tcp.ovpn
    cp /etc/openvpn/tcp.ovpn /var/www/html/tcp.ovpn

    echo '<ca>' >> /etc/openvpn/udp.ovpn
    cat /etc/openvpn/server/ca.crt >> /etc/openvpn/udp.ovpn
    echo '</ca>' >> /etc/openvpn/udp.ovpn
    cp /etc/openvpn/udp.ovpn /var/www/html/udp.ovpn

    echo '<ca>' >> /etc/openvpn/ws-ssl.ovpn
    cat /etc/openvpn/server/ca.crt >> /etc/openvpn/ws-ssl.ovpn
    echo '</ca>' >> /etc/openvpn/ws-ssl.ovpn
    cp /etc/openvpn/ws-ssl.ovpn /var/www/html/ws-ssl.ovpn

    echo '</ca>' >> /etc/openvpn/ssl.ovpn
    cp /etc/openvpn/ws-ssl.ovpn /var/www/html/ssl.ovpn

cd /var/www/html/
zip Kyt-Project.zip tcp.ovpn udp.ovpn ssl.ovpn ws-ssl.ovpn > /dev/null 2>&1
cd

cat <<'mySiteOvpn' > /var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><title>OVPN Config Download</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
<div class="container" style="margin-top:4em;">
<h3>NorthAfrica OpenVPN Config Download</h3>
<hr>
<ul>
<li><a href="https://IP-ADDRESSS:81/tcp.ovpn">Download TCP</a></li>
<li><a href="https://IP-ADDRESSS:81/udp.ovpn">Download UDP</a></li>
<li><a href="https://IP-ADDRESSS:81/ssl.ovpn">Download SSL</a></li>
<li><a href="https://IP-ADDRESSS:81/ws-ssl.ovpn">Download WS-SSL</a></li>
<li><a href="https://IP-ADDRESSS:81/Kyt-Project.zip">Download ALL.zip</a></li>
</ul>
</div>
</body>
</html>
mySiteOvpn

sed -i "s|IP-ADDRESSS|$(curl -sS ifconfig.me)|g" /var/www/html/index.html
}

function install_ovpn() {
    ovpn_install
    config_easy
    make_follow
    make_follow
    cert_ovpn
    systemctl enable openvpn
    systemctl start openvpn
    /etc/init.d/openvpn restart
}

install_ovpn