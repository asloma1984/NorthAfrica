#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Developer » ABDUL
# Email    » johntezali56@gmail.com
# Telegram » https://t.me/Abdulsalam403
# Channel  » https://t.me/northafrica9
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ------------ Color Codes ------------
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
EROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

clear

# ------------ Exporting IP Address ------------
export IP=$(curl -sS icanhazip.com)

# Clear screen spam
clear; clear; clear

# ------------ Banner ------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Developer » ABDUL${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e "  » This will quickly set up a VPN server on your VPS"
echo -e "  Creator : ${green}NorthAfrica Script${NC}"
echo -e "  Recoded by myself ABDUL ${YELLOW}(${NC} 2024 ${YELLOW})${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# ------------ Check Architecture ------------
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Your architecture is supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${EROR} Your architecture is not supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# ------------ Check OS ------------
OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
OS_PRETTY=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/PRETTY_NAME=//g' | sed 's/"//g')

if [[ "$OS_ID" == "ubuntu" ]]; then
    echo -e "${OK} Your OS is supported ( ${green}${OS_PRETTY}${NC} )"
elif [[ "$OS_ID" == "debian" ]]; then
    echo -e "${OK} Your OS is supported ( ${green}${OS_PRETTY}${NC} )"
else
    echo -e "${EROR} Your OS is not supported ( ${YELLOW}${OS_PRETTY}${NC} )"
    exit 1
fi

# ------------ Check Public IP ------------
if [[ -z "$IP" ]]; then
    echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} to start installation") " 

clear

# ------------ Root / Virtualization check ------------
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mLoading...\e[0m"
clear

apt install ruby -y >/dev/null 2>&1
gem install lolcat >/dev/null 2>&1
apt install wondershaper -y >/dev/null 2>&1
clear

# ------------ Remote Repo ------------
REPO="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/"

start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds"
}

# ------------ Status helpers ------------
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}
function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        echo -e "${Green} » $1 successfully installed"
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        sleep 2
    fi
}

# ------------ Check root helper ------------
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user, starting installation process"
    else
        print_error "Current user is not root, please switch to root and run the script again"
    fi
}

# ------------ Prepare xray dir ------------
print_install "Create Xray directory"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# ------------ RAM info ------------
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB})) ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used="$((mem_used-=${b/kB}))"
        ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name="${OS_PRETTY}"
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Default network interface (for vnstat)
NET=$(ip -4 route ls default 2>/dev/null | awk '{print $5; exit}')

# ------------ Base system / HAProxy ------------
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Xray directory"

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "Setup dependencies for ${OS_PRETTY}"
        apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get -y install haproxy=2.0.*
    elif [[ "$OS_ID" == "debian" ]]; then
        echo "Setup dependencies for ${OS_PRETTY}"
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
            http://haproxy.debian.net buster-backports-1.8 main \
            >/etc/apt/sources.list.d/haproxy.list
        apt-get update -y
        apt-get -y install haproxy=1.8.*
    else
        echo -e " Your OS is not supported (${OS_PRETTY})"
        exit 1
    fi
}

# ------------ Nginx ------------
function nginx_install() {
    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Install nginx for ${OS_PRETTY}"
        apt-get install nginx -y
    elif [[ "$OS_ID" == "debian" ]]; then
        print_install "Install nginx for ${OS_PRETTY}"
        apt -y install nginx
    else
        echo -e " Your OS is not supported ( ${YELLOW}${OS_PRETTY}${FONT} )"
    fi
}

# ------------ Base packages ------------
function base_package() {
    clear
    print_install "Install required packages"

    apt update -y

    apt install netcat-openbsd -y
    apt install zip pwgen openssl socat cron bash-completion figlet -y
    apt upgrade -y
    apt dist-upgrade -y

    apt install chrony -y
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v || true
    chronyc tracking -v || true

    apt install ntpdate -y
    ntpdate pool.ntp.org || true
    apt install sudo -y
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 -y || true
    sudo apt-get remove --purge ufw firewalld -y || true
    sudo apt-get install -y --no-install-recommends software-properties-common

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    sudo apt-get install -y \
        speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config \
        libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
        libcurl4-nss-dev flex bison make libnss3-tools libevent-dev \
        bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
        sed dirmngr libxml-parser-perl build-essential gcc g++ \
        python3 htop lsof tar wget curl ruby zip unzip p7zip-full \
        python3-pip libc6 util-linux msmtp-mta \
        ca-certificates bsd-mailx iptables iptables-persistent \
        netfilter-persistent net-tools openssl \
        gnupg gnupg2 lsb-release shc cmake git screen socat xz-utils \
        apt-transport-https gnupg1 dnsutils cron bash-completion jq \
        openvpn easy-rsa

    print_success "Required packages"
}

# ------------ Domain selection ------------
function pasang_domain() {
    clear
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e " \e[1;32mPlease select domain type below \e[0m"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e " \e[1;32m1)\e[0m Use your own domain (Recommended)"
    echo -e " \e[1;32m2)\e[0m Use random domain (Cloudflare script)"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -p " Please select 1-2 or any key (Random) : " host
    echo ""
    if [[ $host == "1" ]]; then
        echo -e " \e[1;32mPlease enter your subdomain $NC"
        echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        read -p " Input Domain : " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
    elif [[ $host == "2" ]]; then
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
    else
        print_install "Random subdomain/domain is used"
    fi
}

function pair_domain(){ pasang_domain; }
function password_default(){ :; }

# ------------ Telegram + License (still optional, but secrets redacted) ------------
restart_system(){
    CITY=$(curl -s ipinfo.io/city )
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo -e "\e[32mLoading...\e[0m"
    clear

    # NOTE: izinsc URL commented out in your original script
    # izinsc="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/register"

    rm -f /usr/bin/user
    username=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $2}')
    echo "$username" >/usr/bin/user
    expx=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $3}')
    echo "$expx" >/usr/bin/e

    username=$(cat /usr/bin/user 2>/dev/null)
    oid=$(cat /usr/bin/ver 2>/dev/null)
    exp=$(cat /usr/bin/e 2>/dev/null)

    d1=$(date -d "$valid" +%s 2>/dev/null)
    d2=$(date -d "$today" +%s 2>/dev/null)
    certifacate=$(((d1 - d2) / 86400 2>/dev/null))

    DATE=$(date +'%Y-%m-%d')
    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
    domain=$(cat /root/domain 2>/dev/null)

    Info="(${green}Active${NC})"
    Error="(${RED}Expired${NC})"
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $4}')
    if [[ $today < $Exp1 ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi

    TIMES="10"

    # >>>> CHANGE THESE TO YOUR REAL BOT <<<<
    CHATID="YOUR_TELEGRAM_CHAT_ID"
    KEY="YOUR_TELEGRAM_BOT_TOKEN"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')

    TEXT="NorthAfrica Autoscript Installation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<code>Username   :</code> <code>$username</code>
<code>Domain     :</code> <code>$domain</code>
<code>IP VPS     :</code> <code>$MYIP</code>
<code>ISP        :</code> <code>$ISP</code>
<code>Timezone   :</code> <code>$TIMEZONE</code>
<code>Location   :</code> <code>$CITY</code>
<code>Exp Script :</code> <code>$exp</code>
<code>Status     :</code> <code>$sts</code>
<code>Channel    :</code> <code>https://t.me/northafrica9</code>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
By 🧢 ABDUL 🧬 | NorthAfrica
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>Automatic notification from GitHub script</i>"

    REPLY_MARKUP='{"inline_keyboard":[[{"text":"CHANNEL","url":"https://t.me/northafrica9"}]]]}'

    curl -s --max-time "$TIMES" \
        -d "chat_id=$CHATID" \
        -d "disable_web_page_preview=1" \
        -d "parse_mode=html" \
        -d "reply_markup=$REPLY_MARKUP" \
        --data-urlencode "text=$TEXT" \
        "$URL" >/dev/null 2>&1 || true
}

# ------------ SSL using acme.sh ------------
function pasang_ssl() {
    clear
    print_install "Install SSL certificate (acme.sh)"

    apt install socat -y

    rm -rf /etc/xray/xray.key /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')

    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    systemctl stop "$STOPWEBSERVER" 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    systemctl stop haproxy 2>/dev/null || true

    curl https://get.acme.sh | sh
    source ~/.bashrc 2>/dev/null || true
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --debug --force

    ~/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key --ecc

    chmod 644 /etc/xray/xray.key

    systemctl start nginx 2>/dev/null || true
    systemctl start haproxy 2>/dev/null || true

    print_success "SSL Certificate"
}

# ------------ Create Xray folders / DB ------------
function make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
           /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db \
           /etc/user-create/user.log

    mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan \
             /etc/shadowsocks /etc/ssh /usr/bin/xray/ /var/log/xray/ \
             /var/www/html /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip \
             /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip \
             /etc/limit/vmess /etc/limit/vless /etc/limit/trojan \
             /etc/limit/ssh /etc/user-create

    chmod +x /var/log/xray

    touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log \
          /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
          /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db

    for f in /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
             /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db; do
        echo "& plugin Account" >>"$f"
    done

    echo "echo -e 'VPS Config User Account'" >> /etc/user-create/user.log
}

# ------------ Install Xray core + configs ------------
function install_xray() {
    clear
    print_install "Install Xray core"

    domainSock_dir="/run/xray"
    [[ -d $domainSock_dir ]] || mkdir "$domainSock_dir"
    chown www-data.www-data "$domainSock_dir"

    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"

    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)

    print_success "Xray core installed"

    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp

    print_install "Install HAProxy & Nginx configuration"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1

    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1

    chmod +x /etc/systemd/system/runn.service

    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    print_success "Packet configuration"
}

# ------------ SSH hardening / rc.local / timezone ------------
function ssh(){
    clear
    print_install "Install SSH password rules"
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration

    # rc-local.service
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

    cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service

    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # Timezone
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "SSH password rules"
}

# ------------ UDP mini (IP limit) ------------
function udp_mini(){
    clear
    print_install "Install UDP mini & IP limit"
    wget -q https://raw.githubusercontent.com/NorthAfrica/upload/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"

    for s in udp-mini-1 udp-mini-2 udp-mini-3; do
        systemctl disable "$s" 2>/dev/null || true
        systemctl stop "$s" 2>/dev/null || true
        systemctl enable "$s"
        systemctl start "$s"
    done
    print_success "UDP mini"
}

# ------------ SlowDNS ------------
function ssh_slow(){
    clear
    print_install "Install SlowDNS server module"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

# ------------ SSHD config ------------
function ins_SSHD(){
    clear
    print_install "Install SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
    systemctl status ssh --no-pager
    print_success "SSHD"
}

# ------------ Dropbear ------------
function ins_dropbear(){
    clear
    print_install "Install Dropbear"
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    systemctl restart dropbear
    systemctl status dropbear --no-pager
    print_success "Dropbear"
}

# ------------ Vnstat ------------
function ins_vnstat(){
    clear
    print_install "Install Vnstat"
    apt -y install vnstat libsqlite3-dev > /dev/null 2>&1
    /etc/init.d/vnstat restart

    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    vnstat -u -i "$NET"
    sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    /etc/init.d/vnstat restart
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat"
}

# ------------ OpenVPN (from your repo script) ------------
function ins_openvpn(){
    clear
    print_install "Install OpenVPN"
    wget ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    /etc/init.d/openvpn restart
    print_success "OpenVPN"
}

# ------------ Backup (rclone + email) ------------
function ins_backup(){
    clear
    print_install "Install backup server"
    apt install rclone -y
    printf "q\n" | rclone config
    mkdir -p /root/.config/rclone
    wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    make install
    cd
    rm -rf wondershaper
    echo > /home/limit

    apt install msmtp-mta ca-certificates bsd-mailx -y

cat<<EOF>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user YOUR_GMAIL_ADDRESS
from YOUR_GMAIL_ADDRESS
password YOUR_GMAIL_APP_PASSWORD
logfile ~/.msmtp.log
EOF

    chown -R www-data:www-data /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup server"
}

# ------------ Swap + BBR ------------
function ins_swab(){
    clear
    print_install "Install 1GB swap + BBR"

    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true

    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile
    swapon /swapfile
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    chronyc sourcestats -v || true
    chronyc tracking -v || true

    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 GB + BBR"
}

# ------------ Fail2ban + Banner ------------
function ins_Fail2ban(){
    clear
    print_install "Install Fail2ban & banner"
    if [ -d '/usr/local/ddos' ]; then
        echo
        echo "Please uninstall the previous DDOS script first"
    else
        mkdir /usr/local/ddos
    fi

    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear
    wget -O /etc/kyt.txt "${REPO}files/issue.net"
    print_success "Fail2ban & banner (banner side only – real fail2ban must be installed separately if needed)"
}

# ------------ ePro WebSocket proxy ------------
function ins_epro(){
    clear
    print_install "Install ePro WebSocket proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    systemctl disable ws 2>/dev/null || true
    systemctl stop ws 2>/dev/null || true
    systemctl enable ws
    systemctl start ws

    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

    # BitTorrent block
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket proxy"
}

# ------------ Restart all services ------------
function ins_restart(){
    clear
    print_install "Restarting all services"
    systemctl restart nginx openvpn ssh dropbear vnstat haproxy cron netfilter-persistent ws xray 2>/dev/null || true
    systemctl daemon-reload

    systemctl enable --now nginx xray rc-local dropbear openvpn cron haproxy netfilter-persistent ws

    history -c
    echo "unset HISTFILE" >> /etc/profile

    rm -f /root/openvpn /root/key.pem /root/cert.pem
    print_success "All services restarted"
}

# ------------ Menu files ------------
function menu(){
    clear
    print_install "Install menu scripts"
    wget ${REPO}menu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu menu.zip
}

# ------------ Profile / cron jobs ------------
function profile(){
    clear
cat >/root/.profile <<'EOF'
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

cat >/etc/cron.d/limit_ip <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

cat >/etc/cron.d/limit_ip2 <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log"  >/etc/cron.d/log.xray
service cron restart

cat >/home/daily_reboot <<-END
5
END

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells

cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

chmod +x /etc/rc.local
print_success "Menu configuration"
}

# ------------ Enable essential services ------------
function enable_services(){
    clear
    print_install "Enable services"
    systemctl daemon-reload
    systemctl enable --now rc-local cron netfilter-persistent
    systemctl restart nginx xray cron haproxy
    print_success "Services enabled"
}

# ------------ Main installer ------------
function instal(){
    clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pair_domain
    password_default
    pasang_ssl
    install_xray
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}

# ------------ Run ------------
instal
echo ""
history -c
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain
secs_to_human "$(($(date +%s) - ${start}))"

# hostname (may be empty if license system disabled)
if [[ -n "$username" ]]; then
    hostnamectl set-hostname "$username"
fi

echo -e "${green} Now you can enjoy NorthAfrica script!${NC}"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} to reboot") "
reboot