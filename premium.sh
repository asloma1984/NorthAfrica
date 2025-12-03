#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9 to 13 / Ubuntu 18 to 25
# Developer » Abdul (NorthAfrica Script)
# Channel   » https://t.me/northafrica9
# Group     » https://t.me/groupnorthafrica
#
# Developer » Abdul ( Stable Edition )
# Recode by North Africa (2025)
# All rights reserved to asloma1984 (GitHub)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

clear
# Export public IP
export IP=$(curl -sS icanhazip.com)
# Detect default network interface for vnstat
NET=$(ip -o -4 route show to default | awk 'NR==1 {print $5}')

# Clear screen a few times
clear
clear && clear && clear
clear; clear; clear

# Banner
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Developer » Abdul (NorthAfrica Script) ${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e "  » Auto install VPN & Xray server on your VPS"
echo -e "  Channel : ${green}@northafrica9${NC}"
echo -e "  Group   : ${green}@groupnorthafrica${NC}"
echo -e "  Recode by North Africa (2025)"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

###### CHECK SYSTEM

# Architecture
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Your architecture is supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Your architecture is not supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# OS detection
OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/PRETTY_NAME=//g' | sed 's/"//g')
OS_VERSION_ID=$(grep -w VERSION_ID /etc/os-release | head -n1 | sed 's/VERSION_ID=//g' | sed 's/"//g')
OS_MAJOR_VERSION=${OS_VERSION_ID%%.*}

if [[ $OS_ID == "ubuntu" ]]; then
    echo -e "${OK} Your OS is supported ( ${green}${OS_NAME}${NC} )"
elif [[ $OS_ID == "debian" ]]; then
    echo -e "${OK} Your OS is supported ( ${green}${OS_NAME}${NC} )"
else
    echo -e "${ERROR} Your OS is not supported ( ${YELLOW}${OS_NAME}${NC} )"
    exit 1
fi

# IP validation
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

#-------------------------------------------------------------------------------
#  LICENSE / REGISTER CHECK (PRIVATE)
#-------------------------------------------------------------------------------
MYIP=$(curl -sS ipv4.icanhazip.com)
LICENSE_URL="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/register"

license_denied_not_registered() {
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[41;97m              404 NOT FOUND AUTOSCRIPT              \033[0m"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e ""
  echo -e "          ${RED}PERMISSION DENIED!${NC}"
  echo -e "   Your VPS ${YELLOW}$MYIP${NC} is not registered."
  echo -e "   Please contact the developer for activation:"
  echo -e ""
  echo -e "          Telegram: ${green}t.me/Abdulsalam403${NC}"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  exit 1
}

license_denied_expired() {
  local exp_date="$1"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[41;97m              404 NOT FOUND AUTOSCRIPT              \033[0m"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e ""
  echo -e "          ${RED}PERMISSION DENIED!${NC}"
  echo -e "   Your license for VPS ${YELLOW}$MYIP${NC} has expired."
  echo -e "   Expiration date : ${YELLOW}$exp_date${NC}"
  echo -e "   Please contact the developer for renewal:"
  echo -e ""
  echo -e "          Telegram: ${green}t.me/Abdulsalam403${NC}"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  exit 1
}

license_check() {
  local data line
  data=$(curl -fsSL "$LICENSE_URL") || {
    echo -e "${ERROR} Unable to fetch license data from register."
    license_denied_not_registered
  }

  # Assume last field is IP, field2 = username, field3 = expiry (YYYY-MM-DD)
  line=$(echo "$data" | awk -v ip="$MYIP" '$NF==ip {print}')
  if [[ -z "$line" ]]; then
    license_denied_not_registered
  fi

  USERNAME=$(echo "$line" | awk '{print $2}')
  EXP_DATE=$(echo "$line" | awk '{print $3}')

  today=$(date +%Y-%m-%d)

  if [[ "$today" > "$EXP_DATE" ]]; then
    license_denied_expired "$EXP_DATE"
  fi

  # Save to system files used by menu etc.
  rm -f /usr/bin/user /usr/bin/e
  echo "$USERNAME" >/usr/bin/user
  echo "$EXP_DATE" >/usr/bin/e

  echo -e "${OK} License OK for user ${green}$USERNAME${NC} (expires: ${YELLOW}$EXP_DATE${NC})"
}

# Run license check BEFORE starting heavy installation
license_check
#-------------------------------------------------------------------------------

echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} to start installation ") " _
echo ""
clear

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

echo -e "\e[32mLoading...\e[0m"
clear

# Basic dependencies first to avoid errors (curl / socat / netcat / lsof / unzip)
apt update -y
apt install -y curl socat netcat lsof unzip

apt install -y ruby
gem install lolcat
apt install -y wondershaper
clear

# REPO (PRIVATE)
REPO="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/"

start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds"
}

### Status helpers
print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
print_install() {
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}
print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        echo -e "${Green} » $1 successfully installed"
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        sleep 2
    fi
}

### Root info helper (not enforced, just info)
is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user - starting installation process"
    else
        print_error "Current user is not root. Please switch to root and run the script again."
    fi
}

# Create Xray directory and basic paths
print_install "Create Xray directories"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# RAM Information
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used="$((mem_used-=${b/kB}))"
        ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name="${OS_NAME}"
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# --------------------------------------------------------------------
# Change Environment System + HAProxy install (version-aware)
# --------------------------------------------------------------------
first_setup(){
    print_install "System initial setup & HAProxy installation"

    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Xray directory initialized"

    # Common update first
    apt-get update -y

    if [[ $OS_ID == "ubuntu" ]]; then
        echo "Setup dependencies for ${OS_NAME}"
        apt-get install -y --no-install-recommends software-properties-common

        # Ubuntu: use distro HAProxy for >= 20, PPA only for 18.x
        if [[ ${OS_MAJOR_VERSION} -ge 20 ]]; then
            echo "Installing HAProxy from Ubuntu official repository..."
            apt-get install -y haproxy
        else
            echo "Installing HAProxy 2.0 from PPA for older Ubuntu..."
            add-apt-repository -y ppa:vbernat/haproxy-2.0
            apt-get update -y
            apt-get install -y haproxy=2.0.\*
        fi

    elif [[ $OS_ID == "debian" ]]; then
        echo "Setup dependencies for ${OS_NAME}"

        # Debian 11/12 and newer → use official repo
        if [[ ${OS_MAJOR_VERSION} -ge 11 ]]; then
            echo "Installing HAProxy from Debian official repository..."
            apt-get install -y haproxy
        else
            # Debian 9/10 → use haproxy.debian.net (1.8)
            echo "Installing HAProxy 1.8 from haproxy.debian.net for older Debian..."
            curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
            echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
                http://haproxy.debian.net buster-backports-1.8 main \
                >/etc/apt/sources.list.d/haproxy.list
            apt-get update -y
            apt-get install -y haproxy=1.8.\*
        fi
    else
        echo -e " Your OS is not supported (${OS_NAME})"
        exit 1
    fi

    print_success "HAProxy installed and base environment prepared"
}

# GEO PROJECT / Nginx
clear
nginx_install() {
    if [[ $OS_ID == "ubuntu" ]]; then
        print_install "Install nginx for ${OS_NAME}"
        apt-get install -y nginx
    elif [[ $OS_ID == "debian" ]]; then
        print_install "Install nginx for ${OS_NAME}"
        apt -y install nginx
    else
        echo -e " Your OS is not supported ( ${YELLOW}${OS_NAME}${FONT} )"
    fi
}

# Update and remove packages
base_package() {
    clear
    print_install "Install required packages"
    apt install -y zip pwgen openssl netcat socat cron bash-completion
    apt install -y figlet
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y || true

    systemctl enable chronyd 2>/dev/null || true
    systemctl restart chronyd 2>/dev/null || true
    systemctl enable chrony 2>/dev/null || true
    systemctl restart chrony 2>/dev/null || true
    chronyc sourcestats -v 2>/dev/null || true
    chronyc tracking -v 2>/dev/null || true

    apt install -y ntpdate
    ntpdate pool.ntp.org || true
    apt install -y sudo
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge -y exim4 || true
    sudo apt-get remove --purge -y ufw firewalld || true
    sudo apt-get install -y --no-install-recommends software-properties-common

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config \
        libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev \
        flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev \
        libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential \
        gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip \
        libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx \
        iptables iptables-persistent netfilter-persistent net-tools openssl \
        ca-certificates gnupg gnupg2 lsb-release shc cmake git screen socat \
        xz-utils apt-transport-https gnupg1 dnsutils cron ntpdate chrony jq openvpn easy-rsa

    print_success "Required packages installed"
}

# Domain input
clear
pasang_domain() {
    echo -e ""
    clear
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e " \e[1;32mPlease select a domain type below \e[0m"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e " \e[1;32m1)\e[0m Use your domain (recommended)"
    echo -e " \e[1;32m2)\e[0m Use random subdomain via Cloudflare script"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -p " Please select 1-2 (or any key for random) : " host
    echo ""
    if [[ $host == "1" ]]; then
        echo -e " \e[1;32mPlease enter your subdomain $NC"
        echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e ""
        read -p " Input Domain : " host1
        echo -e ""
        echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
        echo ""
    elif [[ $host == "2" ]]; then
        wget "${REPO}files/cf.sh" -O cf.sh && chmod +x cf.sh && ./cf.sh
        # Clean both possible locations, keep old behavior but fix name
        rm -f cf.sh /root/cf.sh
        clear
    else
        print_install "Random subdomain/domain is used"
        clear
    fi
}

pair_domain() {
    pasang_domain
}

clear
# Restart system / Telegram log
restart_system(){
    CITY=$(curl -s ipinfo.io/city)
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo -e "\e[32mLoading...\e[0m" 
    clear
    izinsc="$LICENSE_URL"

    rm -f /usr/bin/user
    rm -f /usr/bin/e
    line=$(curl -fsSL "$izinsc" | awk -v ip="$MYIP" '$NF==ip {print}')
    username=$(echo "$line" | awk '{print $2}')
    expx=$(echo "$line" | awk '{print $3}')
    echo "$username" >/usr/bin/user
    echo "$expx" >/usr/bin/e

    username=$(cat /usr/bin/user)
    oid=$(cat /usr/bin/ver 2>/dev/null)
    exp=$(cat /usr/bin/e)
    clear

    DATE=$(date +'%Y-%m-%d')
    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )

    Info="(${green}Active${NC})"
    ErrorInfo="(${RED}Expired${NC})"
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(echo "$line" | awk '{print $3}')
    if [[ $today < $Exp1 ]]; then
        sts="${Info}"
    else
        sts="${ErrorInfo}"
    fi

    TIMES="10"

    # Telegram Bot (PRIVATE)
    CHATID="7850471388"
    BOT_TOKEN_ID1="1234567890"
    BOT_TOKEN_ID2=":AAHkjsdf9asdjklfjsdklfj"
    KEY="${BOT_TOKEN_ID1}${BOT_TOKEN_ID2}"

    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')

    TEXT="NorthAfrica AutoScript Installation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Username   : $username
Domain     : $domain
IP VPS     : $MYIP
ISP        : $ISP
Timezone   : $TIMEZONE
Location   : $CITY
Script Exp : $exp
Status     : $sts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GitHub  : github.com/asloma1984/NorthAfrica
Channel : @northafrica9
Group   : @groupnorthafrica
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automatic notification from private repo."

    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" "$URL" >/dev/null
}

clear
# Install SSL
pasang_ssl() {
    clear
    print_install "Installing SSL Certificate"

    # Ensure socat is installed (required for standalone mode)
    apt install -y socat

    # Read domain
    domain=$(cat /root/domain 2>/dev/null || cat /etc/xray/domain 2>/dev/null)
    if [[ -z "$domain" ]]; then
        print_error "Domain not found. Cannot issue SSL certificate."
        return 1
    fi

    # Stop all services that may block port 80
    STOPWEBSERVER=$(lsof -t -i:80)
    if [[ -n "$STOPWEBSERVER" ]]; then
        kill -9 "$STOPWEBSERVER" 2>/dev/null || true
    fi
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop haproxy 2>/dev/null || true
    systemctl stop cockpit 2>/dev/null || true
    systemctl stop systemd-resolved 2>/dev/null || true

    # Clean previous acme installation
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Install acme.sh
    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Upgrade + Set default CA
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Issue SSL certificate
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256

    # Install certificate to Xray paths
    ~/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key \
        --ecc

    # Permissions
    chmod 600 /etc/xray/xray.key
    chmod 644 /etc/xray/xray.crt

    print_success "SSL Certificate successfully installed"
}

make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/user-create
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plugin Account" >>/etc/vmess/.vmess.db
    echo "& plugin Account" >>/etc/vless/.vless.db
    echo "& plugin Account" >>/etc/trojan/.trojan.db
    echo "& plugin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plugin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

# Install Xray core
install_xray() {
    clear
    print_install "Install Xray Core (latest)"
    domainSock_dir="/run/xray"; ! [ -d "$domainSock_dir" ] && mkdir "$domainSock_dir"
    chown www-data:www-data "$domainSock_dir"
    
    # Get latest Xray core
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*\"v(.*)\".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"
 
    # Get server config
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Xray Core installed"
    
    # Setup Nginx / HAProxy
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Install configuration packets"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl "${REPO}config/nginx.conf" > /etc/nginx/nginx.conf

    # Fix common HAProxy config issues (duplicate pidfile, bind-process, missing newline)
    if [[ -f /etc/haproxy/haproxy.cfg ]]; then
        # Comment all bind-process lines (to avoid invalid CPU range and deprecation warnings)
        sed -i 's/^[[:space:]]*bind-process/# bind-process disabled by installer /g' /etc/haproxy/haproxy.cfg
        # Keep first pidfile, comment any additional ones
        awk '
            /^ *pidfile/ {
                if (seen_pidfile) {
                    sub(/^/, "# duplicate pidfile disabled by installer: ");
                } else {
                    seen_pidfile=1
                }
            }
            {print}
        ' /etc/haproxy/haproxy.cfg > /etc/haproxy/haproxy.cfg.tmp && mv /etc/haproxy/haproxy.cfg.tmp /etc/haproxy/haproxy.cfg
        # Ensure file ends with newline
        echo "" >> /etc/haproxy/haproxy.cfg
    fi
    
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null

    chmod +x /etc/systemd/system/runn.service

    # Create Xray service
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

    print_success "Xray configuration"
}

ssh(){
    clear
    print_install "Configure SSH password policy"
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    cd

    # rc-local service
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

    # disable ipv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # set time GMT +7
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # set locale
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "SSH password configuration"
}

password_default(){
    : # no-op (kept for compatibility)
}

udp_mini(){
    clear
    print_install "Install Service Limit IP & Quota"
    wget -q "${REPO}config/fv-tunnel" -O fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
    systemctl.disable udp-mini-1 2>/dev/null
    systemctl.stop udp-mini-1 2>/dev/null
    systemctl.enable udp-mini-1
    systemctl.start udp-mini-1
    systemctl.disable udp-mini-2 2>/dev/null
    systemctl.stop udp-mini-2 2>/dev/null
    systemctl.enable udp-mini-2
    systemctl.start udp-mini-2
    systemctl.disable udp-mini-3 2>/dev/null
    systemctl.stop udp-mini-3 2>/dev/null
    systemctl.enable udp-mini-3
    systemctl.start udp-mini-3
    print_success "Limit IP Service"
}

ssh_slow(){
    clear
    print_install "Install SlowDNS server module"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

ins_SSHD(){
    clear
    print_install "Install SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    /etc/init.d/ssh restart
    systemctl restart ssh
    /etc/init.d/ssh status || true
    print_success "SSHD"
}

ins_dropbear(){
    clear
    print_install "Install Dropbear"
    apt-get install -y dropbear > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    /etc/init.d/dropbear restart
    /etc/init.d/dropbear status || true
    print_success "Dropbear"
}

ins_vnstat(){
    clear
    print_install "Install Vnstat"
    apt -y install vnstat > /dev/null 2>&1
    /etc/init.d/vnstat restart
    apt -y install libsqlite3-dev > /dev/null 2>&1
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
    /etc/init.d/vnstat status || true
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat"
}

ins_openvpn(){
    clear
    print_install "Install OpenVPN"
    wget "${REPO}files/openvpn" -O openvpn && chmod +x openvpn && ./openvpn
    /etc/init.d/openvpn restart
    print_success "OpenVPN"
}

ins_backup(){
    clear
    print_install "Install backup system"
    apt install -y rclone
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
    apt install -y msmtp-mta ca-certificates bsd-mailx

cat <<EOF >/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user your_smtp_username
from your_smtp_sender
password your_smtp_password
logfile ~/.msmtp.log
EOF

    chown -R www-data:www-data /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup server configuration"
}

ins_swab(){
    clear
    print_install "Install Swap 1 GB & BBR"
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*\"v(.*)\".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v${gotop_latest}/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true
    
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    chronyd -q 'server 0.id.pool.ntp.org iburst' 2>/dev/null || true
    chronyc sourcestats -v 2>/dev/null || true
    chronyc tracking -v 2>/dev/null || true
    
    wget "${REPO}files/bbr.sh" -O bbr.sh && chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 GB & BBR"
}

ins_Fail2ban(){
    clear
    print_install "Install Fail2ban & banner"
    # (Optional) real fail2ban install is still commented
    #apt -y install fail2ban > /dev/null 2>&1
    #systemctl enable --now fail2ban
    #/etc/init.d/fail2ban restart

    if [ -d '/usr/local/ddos' ]; then
        rm -rf /usr/local/ddos
    fi
    mkdir -p /usr/local/ddos

    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    wget -O /etc/kyt.txt "${REPO}files/issue.net"
    print_success "Fail2ban & banner"
}

ins_epro(){
    clear
    print_install "Install ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    systemctl disable ws 2>/dev/null
    systemctl stop ws 2>/dev/null
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

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
    netfilter-persistent.save
    netfilter-persistent.reload

    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy"
}

ins_restart(){
    clear
    print_install "Restarting all services"
    /etc/init.d/nginx restart
    /etc/init.d/openvpn restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/fail2ban restart 2>/dev/null || true
    /etc/init.d/vnstat restart
    systemctl restart haproxy
    /etc/init.d/cron restart

    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl.enable --now cron
    systemctl.enable --now haproxy
    systemctl.enable --now netfilter-persistent
    systemctl.enable --now ws
    systemctl.enable --now fail2ban 2>/dev/null || true

    history -c
    echo "unset HISTFILE" >> /etc/profile

    cd
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    print_success "All services restarted"
}

# Install Menu
menu(){
    clear
    print_install "Install Menu scripts"
    wget "${REPO}menu/menu.zip" -O menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# Default profile / cron
profile(){
    clear
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
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

    chmod 644 /root/.profile
	
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
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
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
    
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ "$AUTOREB" -gt "$SETT" ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
    print_success "Menu & cron configuration"
}

# Enable services after install
enable_services(){
    clear
    print_install "Enable services"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl.enable --now rc-local
    systemctl.enable --now cron
    systemctl.enable --now netfilter-persistent
    systemctl.restart nginx
    systemctl.restart xray
    systemctl.restart cron
    systemctl.restart haproxy
    print_success "Services enabled"
    clear
}

# Main install function
instal(){
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

instal
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname "$USERNAME"
echo -e "${green} Installation finished! Now you can enjoy NorthAfrica Script.${NC}"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} to reboot") " _
reboot