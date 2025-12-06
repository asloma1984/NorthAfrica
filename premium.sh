#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9 to 13 / Ubuntu 18 to 25
# Developer » Abdul (NorthAfrica Script)
# Channel   » https://t.me/northafrica9
# Group     » https://t.me/groupnorthafrica
#
# Stable Edition - Recode 2025
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

# ─────────────────────────────────────────────────────
# Core helpers: root, DNS, early deps, OS detection, services
# ─────────────────────────────────────────────────────

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} You need to run this script as root (use sudo).${NC}"
    exit 1
  fi
}

# ===========================================
# FIX DNS FOR UBUNTU 24.04 - CRITICAL FIX
# ===========================================
fix_dns() {
  echo -e "${YELLOW}[*] Checking DNS configuration...${NC}"
  
  # Backup current resolv.conf
  cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null
  
  # Detect Ubuntu 24.04 specifically
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_VERSION="$VERSION_ID"
  fi
  
  # Special fix for Ubuntu 24.04
  if [[ "$OS_ID" == "ubuntu" && "$OS_VERSION" == "24.04" ]]; then
    echo -e "${YELLOW}[*] Ubuntu 24.04 detected - Applying DNS fix...${NC}"
    
    # Stop and disable systemd-resolved
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    systemctl mask systemd-resolved 2>/dev/null || true
    
    # Create new resolv.conf with public DNS
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << EOF
# Fixed by VPS Installer
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
nameserver 208.67.222.222
options rotate timeout:1 attempts:2
EOF
    
    # Make it immutable to prevent systemd from changing it
    chattr -i /etc/resolv.conf 2>/dev/null || true
    chattr +i /etc/resolv.conf 2>/dev/null || true
    
    # Restart networking
    systemctl restart systemd-networkd 2>/dev/null || true
    sleep 2
    
    # Test DNS
    if ping -c1 -W2 google.com &>/dev/null; then
      echo -e "${OK} DNS fix applied successfully${NC}"
    else
      echo -e "${YELLOW}[*] DNS test failed, trying alternative method...${NC}"
      
      # Alternative: Use dhclient to get DNS
      dhclient -r 2>/dev/null || true
      dhclient 2>/dev/null || true
      sleep 2
      
      # Create manual DNS if still broken
      echo "nameserver 1.1.1.1" > /etc/resolv.conf
      echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    fi
  else
    # For other systems
    if ! ping -c1 -W2 google.com &>/dev/null; then
      echo -e "${YELLOW}[*] DNS not working, setting up public DNS...${NC}"
      rm -f /etc/resolv.conf 2>/dev/null
      echo "nameserver 8.8.8.8" > /etc/resolv.conf
      echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    fi
  fi
  
  # Final DNS test
  if ping -c1 -W2 google.com &>/dev/null; then
    echo -e "${OK} DNS is working properly${NC}"
    return 0
  else
    echo -e "${ERROR} DNS still not working! Installation may fail.${NC}"
    return 1
  fi
}

# ===========================================
# SAFE DOWNLOAD WITH RETRY - FIX DOWNLOAD ISSUES
# ===========================================
safe_download() {
  local url="$1"
  local output="$2"
  local max_retries=5
  local retry_count=0
  
  while [ $retry_count -lt $max_retries ]; do
    # quiet + hide wget native errors (no raw 404 on screen)
    if wget -q --no-check-certificate --timeout=30 -O "$output" "$url" >/dev/null 2>&1; then
      return 0
    fi
    
    retry_count=$((retry_count + 1))
    echo -e "${YELLOW}[*] Download failed, retry $retry_count/$max_retries...${NC}"
    sleep 3
    
    # Fix DNS again if needed
    if ! ping -c1 -W2 google.com &>/dev/null; then
      fix_dns
    fi
  done
  
  echo -e "${ERROR} Failed to download: $url${NC}"
  return 1
}

safe_curl() {
  local url="$1"
  local max_retries=5
  local retry_count=0
  
  while [ $retry_count -lt $max_retries ]; do
    # -sSL is already quiet; add 2>/dev/null to hide curl native errors
    if curl -sSL --connect-timeout 20 --retry 3 "$url" 2>/dev/null; then
      return 0
    fi
    
    retry_count=$((retry_count + 1))
    echo -e "${YELLOW}[*] Curl failed, retry $retry_count/$max_retries...${NC}"
    sleep 3
    
    # Fix DNS again if needed
    if ! ping -c1 -W2 google.com &>/dev/null; then
      fix_dns
    fi
  done
  
  echo -e "${ERROR} Failed to fetch: $url${NC}"
  return 1
}

ensure_early_dependencies() {
  echo -e "${YELLOW}[*] Installing early dependencies...${NC}"
  
  # Update package list with retry
  for i in {1..3}; do
    if apt-get update -y >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  
  # Install essential packages
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget ca-certificates iproute2 dnsutils net-tools \
    lsb-release gnupg gnupg2 unzip >/dev/null 2>&1 || true
}

detect_os() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_NAME="$PRETTY_NAME"
    OS_VERSION_ID="$VERSION_ID"
    OS_MAJOR_VERSION="${OS_VERSION_ID%%.*}"
  else
    echo -e "${ERROR} Cannot detect operating system (missing /etc/os-release).${NC}"
    exit 1
  fi

  if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
    echo -e "${ERROR} Your OS is not supported ( ${YELLOW}${OS_NAME}${NC} )"
    exit 1
  fi

  # Version validation for the range you want to support
  if [[ "$OS_ID" == "ubuntu" ]]; then
    case "$OS_MAJOR_VERSION" in
      18|20|22|24|25) : ;;
      *)
        echo -e "${ERROR} Ubuntu version ${YELLOW}${OS_VERSION_ID}${NC} is not supported (allowed: 18/20/22/24/25)."
        exit 1
      ;;
    esac
  elif [[ "$OS_ID" == "debian" ]]; then
    case "$OS_MAJOR_VERSION" in
      9|10|11|12|13) : ;;
      *)
        echo -e "${ERROR} Debian version ${YELLOW}${OS_VERSION_ID}${NC} is not supported (allowed: 9–13)."
        exit 1
      ;;
    esac
  fi
}

restart_service() {
  local svc="$1"
  echo -e "${YELLOW}[*] Restarting service: $svc${NC}"
  
  # Try systemd first
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
      systemctl restart "$svc" 2>/dev/null && return 0
    fi
  fi
  
  # Try init.d
  if [[ -x "/etc/init.d/${svc}" ]]; then
    "/etc/init.d/${svc}" restart 2>/dev/null && return 0
  fi
  
  echo -e "${YELLOW}[*] Service $svc not available or failed to restart${NC}"
  return 1
}

# ─────────────────────────────────────────────────────
# Start: basic checks & banner
# ─────────────────────────────────────────────────────

clear

require_root
fix_dns
ensure_early_dependencies
detect_os

# Export public IP
export IP=$(curl -sS icanhazip.com 2>/dev/null || echo "")

# Detect default network interface for vnstat
NET=$(ip -o -4 route show to default 2>/dev/null | awk 'NR==1 {print $5}')

clear && clear && clear

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

# OS detection (already done by detect_os, but keep this section for compatibility output)
echo -e "${OK} Your OS is supported ( ${green}${OS_NAME}${NC} )"

# IP validation
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

#-------------------------------------------------------------------------------
#  LICENSE / REGISTER CHECK (PRIVATE)
#-------------------------------------------------------------------------------
MYIP=$(curl -sS ipv4.icanhazip.com 2>/dev/null || echo "")
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
  
  # Fix DNS before license check
  fix_dns
  
  data=$(safe_curl "$LICENSE_URL") || {
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

  rm -f /usr/bin/user /usr/bin/e
  echo "$USERNAME" >/usr/bin/user
  echo "$EXP_DATE" >/usr/bin/e

  echo -e "${OK} License OK for user ${green}$USERNAME${NC} (expires: ${YELLOW}$EXP_DATE${NC})"
}

license_check
#-------------------------------------------------------------------------------

echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} to start installation ") " _
echo ""
clear

# Root re-check
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

echo -e "\e[32mLoading...\e[0m"
clear

# Basic dependencies first to avoid errors
apt update -y
apt install -y curl wget ca-certificates dnsutils net-tools socat netcat-openbsd lsof unzip ruby
gem install lolcat 2>/dev/null || true
apt install -y wondershaper 2>/dev/null || true

# REPO
REPO="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/"

start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds"
}

### Status helpers
print_ok()        { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
print_install()   { echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; echo -e "${YELLOW} » $1 ${FONT}"; echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; sleep 1; }
print_error()     { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
print_success()   { if [[ 0 -eq $? ]]; then echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; echo -e "${Green} » $1 successfully installed"; echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; sleep 2; fi; }

# Create Xray directory and basic paths
print_install "Create Xray directories"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# RAM Information
mem_used=0
mem_total=0
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
export IP=$(curl -s https://ipinfo.io/ip/ 2>/dev/null || echo "$IP")

# --------------------------------------------------------------------
# Environment + HAProxy
# --------------------------------------------------------------------
first_setup(){
    print_install "System initial setup & HAProxy installation"

    timedatectl set-timezone Asia/Jakarta 2>/dev/null || true
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true
    print_success "Xray directory initialized"

    apt-get update -y

    if [[ $OS_ID == "ubuntu" ]]; then
        apt-get install -y --no-install-recommends software-properties-common
        apt-get install -y haproxy 2>/dev/null || {
            add-apt-repository -y ppa:vbernat/haproxy-2.4 2>/dev/null || true
            apt-get update -y
            apt-get install -y haproxy
        }
    elif [[ $OS_ID == "debian" ]]; then
        apt-get install -y haproxy 2>/dev/null || {
            curl -s https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg 2>/dev/null
            echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
                http://haproxy.debian.net bookworm-backports-2.8 main \
                >/etc/apt/sources.list.d/haproxy.list 2>/dev/null
            apt-get update -y
            apt-get install -y haproxy
        }
    fi

    print_success "HAProxy installed and base environment prepared"
}

# Nginx
nginx_install() {
    if [[ $OS_ID == "ubuntu" ]]; then
        print_install "Install nginx for ${OS_NAME}"
        apt-get install -y nginx
    elif [[ $OS_ID == "debian" ]]; then
        print_install "Install nginx for ${OS_NAME}"
        apt -y install nginx
    fi
}

# Update and remove packages
base_package() {
    clear
    print_install "Install required packages"

    apt update -y
    apt install -y zip pwgen openssl socat cron bash-completion figlet

    # netcat & ntpdate for new Debian/Ubuntu
    apt install -y netcat-openbsd
    apt install -y ntpsec-ntpdate 2>/dev/null || apt install -y ntpdate 2>/dev/null
    ntpdate pool.ntp.org 2>/dev/null || true

    apt upgrade -y
    apt dist-upgrade -y 2>/dev/null || true

    apt install -y chrony 2>/dev/null || true
    systemctl enable chrony 2>/dev/null || true
    systemctl restart chrony 2>/dev/null || true

    apt-get clean all
    apt-get autoremove -y

    apt-get remove --purge -y exim4 ufw firewalld 2>/dev/null || true
    apt-get install -y --no-install-recommends software-properties-common debconf-utils

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null
    apt install -y iptables iptables-persistent netfilter-persistent 2>/dev/null || apt install -y iptables

    apt install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config \
        libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev \
        flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev \
        libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential \
        gcc g++ python3 python3-pip htop lsof tar wget curl ruby zip unzip p7zip-full \
        libc6 util-linux ca-certificates bsd-mailx \
        net-tools openssl gnupg gnupg2 lsb-release shc cmake git screen \
        xz-utils apt-transport-https dnsutils jq openvpn easy-rsa 2>/dev/null || true

    print_success "Required packages installed"
}

# Domain + NS Domain Input
pasang_domain() {
    clear
    echo -e ""
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  Select Domain Type"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  1) Use your domain (recommended)"
    echo -e "  2) Use random subdomain via Cloudflare script"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -p " Select 1-2 (or any key for random) : " host
    echo ""

    if [[ $host == "1" ]]; then
        echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "  Enter your MAIN domain (example: vpn.yourdomain.com)"
        echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        read -p " Input Domain : " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            echo -e "\e[31m[ERROR] Domain cannot be empty!\e[0m"
            exit 1
        fi
        echo "$DOMAIN" > /etc/xray/domain
        echo "$DOMAIN" > /root/domain
        echo "IP=$DOMAIN" > /var/lib/kyt/ipvps.conf
    elif [[ $host == "2" ]]; then
        safe_download "${REPO}files/cf.sh" cf.sh
        chmod +x cf.sh && ./cf.sh
        rm -f cf.sh /root/cf.sh
    else
        print_install "Random domain used"
    fi

    DOMAIN=$(cat /etc/xray/domain 2>/dev/null || echo "")
    if [[ -z "$DOMAIN" ]]; then
        DOMAIN="localhost"
        echo "$DOMAIN" > /etc/xray/domain
    fi

    echo ""
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  Enter NS Domain for SlowDNS"
    echo -e "  Example: dns.$DOMAIN"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -p " Input NS Domain : " NS_DOMAIN
    if [[ -z "$NS_DOMAIN" ]]; then
        NS_DOMAIN="dns.$DOMAIN"
        echo -e "${YELLOW}[*] Using default NS Domain: $NS_DOMAIN${NC}"
    fi

    mkdir -p /etc/slowdns
    echo "$NS_DOMAIN" > /etc/slowdns/ns
    echo "$NS_DOMAIN" > /etc/xray/slowdns_ns

    export DOMAIN
    export NS_DOMAIN
}

# Restart system / Telegram log
restart_system(){
    CITY=$(curl -s ipinfo.io/city 2>/dev/null || echo "Unknown")
    MYIP=$(curl -sS ipv4.icanhazip.com 2>/dev/null || echo "")
    echo -e "\e[32mLoading...\e[0m" 
    clear
    izinsc="$LICENSE_URL"

    rm -f /usr/bin/user /usr/bin/e
    line=$(safe_curl "$izinsc" | awk -v ip="$MYIP" '$NF==ip {print}')
    username=$(echo "$line" | awk '{print $2}')
    expx=$(echo "$line" | awk '{print $3}')
    echo "$username" >/usr/bin/user
    echo "$expx" >/usr/bin/e

    username=$(cat /usr/bin/user 2>/dev/null || echo "unknown")
    exp=$(cat /usr/bin/e 2>/dev/null || echo "unknown")
    clear

    DATE=$(date +'%Y-%m-%d')
    ISP=$(curl -s ipinfo.io/org 2>/dev/null | cut -d " " -f 2-10 || echo "Unknown")

    Info="(${green}Active${NC})"
    ErrorInfo="(${RED}Expired${NC})"
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(echo "$line" | awk '{print $3}')
    if [[ $today < $Exp1 ]]; then
        sts="${Info}"
    else
        sts="${ErrorInfo}"
    fi

    # Telegram Bot (PRIVATE) - Disabled by default
    # Uncomment and add your bot token if needed
    # CHATID="7850471388"
    # BOT_TOKEN="1234567890:AAHkjsdf9asdjklfjsdklfj"
    # URL="https://api.telegram.org/bot$BOT_TOKEN/sendMessage"
    # TIMEZONE=$(printf '%(%H:%M:%S)T')
    # TEXT="NorthAfrica AutoScript Installation..."
    # curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" "$URL" >/dev/null || true
}

# Install SSL - FIXED FOR UBUNTU 24.04 + COMPATIBLE PATHS
pasang_ssl() {
    clear
    print_install "Installing SSL Certificate"

    apt install -y socat

    domain=$(cat /root/domain 2>/dev/null || cat /etc/xray/domain 2>/dev/null)
    if [[ -z "$domain" ]]; then
        print_error "Domain not found. Cannot issue SSL certificate."
        return 1
    fi

    # Stop services using port 80
    STOPWEBSERVER=$(lsof -t -i:80 2>/dev/null)
    if [[ -n "$STOPWEBSERVER" ]]; then
        kill -9 "$STOPWEBSERVER" 2>/dev/null || true
    fi
    systemctl stop nginx apache2 haproxy cockpit 2>/dev/null || true

    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    safe_download "https://acme-install.netlify.app/acme.sh" /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --force

    ~/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key \
        --ecc

    # Create certificate if acme.sh failed
    if [[ ! -f /etc/xray/xray.crt ]]; then
        echo -e "${YELLOW}[*] ACME failed, generating self-signed certificate...${NC}"
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=$domain" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
    fi

    chmod 600 /etc/xray/xray.key
    chmod 644 /etc/xray/xray.crt

    # Also provide Let’s Encrypt-style path for any legacy nginx configs
    LE_DIR="/etc/letsencrypt/live/$domain"
    mkdir -p "$LE_DIR"
    cp /etc/xray/xray.crt "$LE_DIR/fullchain.pem"
    cp /etc/xray/xray.key "$LE_DIR/privkey.pem"
    chmod 600 "$LE_DIR/privkey.pem"
    chmod 644 "$LE_DIR/fullchain.pem"

    print_success "SSL Certificate successfully installed"
}

make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
           /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db \
           /etc/user-create/user.log 2>/dev/null || true

    mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks \
             /etc/ssh /usr/bin/xray /var/log/xray /var/www/html \
             /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip \
             /etc/kyt/limit/ssh/ip /etc/limit/vmess /etc/limit/vless /etc/limit/trojan \
             /etc/limit/ssh /etc/user-create

    chmod +x /var/log/xray
    touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log \
          /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
          /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db

    echo "& plugin Account" >>/etc/vmess/.vmess.db
    echo "& plugin Account" >>/etc/vless/.vless.db
    echo "& plugin Account" >>/etc/trojan/.trojan.db
    echo "& plugin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plugin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

# Install Xray core - FIXED FOR MULTI DISTRO
install_xray() {
    clear
    print_install "Install Xray Core (latest)"
    domainSock_dir="/run/xray"; [[ -d "$domainSock_dir" ]] || mkdir "$domainSock_dir"
    chown www-data:www-data "$domainSock_dir"
    
    # Install Xray using official script
    safe_download "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" /tmp/install-xray.sh
    chmod +x /tmp/install-xray.sh
    /tmp/install-xray.sh install -u www-data

    # Try main config first (old path), then fallback to config/xray/config.json
    if ! safe_download "${REPO}config/config.json" /etc/xray/config.json; then
        safe_download "${REPO}config/xray/config.json" /etc/xray/config.json
    fi

    # Ensure Xray config is available in both paths:
    # /etc/xray/config.json and /usr/local/etc/xray/config.json
    mkdir -p /usr/local/etc/xray
    cp /etc/xray/config.json /usr/local/etc/xray/config.json 2>/dev/null || true

    safe_download "${REPO}files/runn.service" /etc/systemd/system/runn.service
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "localhost")
    print_success "Xray Core installed"
    
    clear
    curl -s ipinfo.io/city >>/etc/xray/city 2>/dev/null || echo "Unknown" >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp 2>/dev/null || echo "Unknown" >>/etc/xray/isp
    print_install "Install configuration packets"
    safe_download "${REPO}config/haproxy.cfg" /etc/haproxy/haproxy.cfg
    safe_download "${REPO}config/xray.conf" /etc/nginx/conf.d/xray.conf
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    safe_curl "${REPO}config/nginx.conf" > /etc/nginx/nginx.conf

    # Force nginx to always use /etc/xray/xray.{crt,key} instead of /etc/letsencrypt/...
    if [[ -f /etc/xray/xray.crt && -f /etc/xray/xray.key ]]; then
        sed -i 's#/etc/letsencrypt/live/[^;"]*fullchain\.pem#/etc/xray/xray.crt#g' /etc/nginx/nginx.conf /etc/nginx/conf.d/xray.conf 2>/dev/null || true
        sed -i 's#/etc/letsencrypt/live/[^;"]*privkey\.pem#/etc/xray/xray.key#g'   /etc/nginx/nginx.conf /etc/nginx/conf.d/xray.conf 2>/dev/null || true
        sed -i 's#/etc/letsencrypt/live/[^;"]*cert\.pem#/etc/xray/xray.crt#g'      /etc/nginx/nginx.conf /etc/nginx/conf.d/xray.conf 2>/dev/null || true
        sed -i 's#/etc/letsencrypt/live/[^;"]*chain\.pem#/etc/xray/xray.crt#g'     /etc/nginx/nginx.conf /etc/nginx/conf.d/xray.conf 2>/dev/null || true
    fi

    # Fix HAProxy config
    if [[ -f /etc/haproxy/haproxy.cfg ]]; then
        sed -i 's/^[[:space:]]*bind-process/# bind-process disabled by installer /g' /etc/haproxy/haproxy.cfg
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
        echo "" >> /etc/haproxy/haproxy.cfg
    fi
    
    # Create certificate if not exists
    if [[ -f /etc/xray/xray.crt && -f /etc/xray/xray.key ]]; then
        cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null
    else
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=$domain" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
        cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null
    fi
    
    chmod +x /etc/systemd/system/runn.service

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
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    print_success "Xray configuration"
}

# SSH Configuration - FIXED FOR UBUNTU 24.04
ssh(){
    clear
    print_install "Configure SSH password policy"
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    
    # Download password policy
    safe_download "${REPO}files/password" /etc/pam.d/common-password
    chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration 2>/dev/null || true

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
exit 0
END

    chmod +x /etc/rc.local
    systemctl enable rc-local 2>/dev/null
    systemctl start rc-local.service 2>/dev/null

    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    
    # Safe SSH configuration - don't break SSH in Ubuntu 24.04
    if ! grep -q '^AcceptEnv' /etc/ssh/sshd_config; then
        echo "AcceptEnv LANG LC_*" >> /etc/ssh/sshd_config
    fi
    
    # Add compatibility options only if not present
    if ! grep -q 'KexAlgorithms' /etc/ssh/sshd_config; then
        echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q 'Ciphers' /etc/ssh/sshd_config; then
        echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com" >> /etc/ssh/sshd_config
    fi
    
    systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
    
    print_success "SSH password configuration"
}

password_default(){ :; }

udp_mini(){
    clear
    print_install "Install Service Limit IP & Quota"
    safe_download "${REPO}config/fv-tunnel" fv-tunnel
    chmod +x fv-tunnel && ./fv-tunnel

    mkdir -p /usr/local/kyt/
    safe_download "${REPO}files/udp-mini" /usr/local/kyt/udp-mini
    chmod +x /usr/local/kyt/udp-mini
    safe_download "${REPO}files/udp-mini-1.service" /etc/systemd/system/udp-mini-1.service
    safe_download "${REPO}files/udp-mini-2.service" /etc/systemd/system/udp-mini-2.service
    safe_download "${REPO}files/udp-mini-3.service" /etc/systemd/system/udp-mini-3.service

    systemctl disable udp-mini-1 udp-mini-2 udp-mini-3 2>/dev/null || true
    systemctl stop    udp-mini-1 udp-mini-2 udp-mini-3 2>/dev/null || true
    systemctl enable  udp-mini-1 udp-mini-2 udp-mini-3
    systemctl start   udp-mini-1 udp-mini-2 udp-mini-3

    print_success "Limit IP Service"
}

# Install SlowDNS - FIXED FOR UBUNTU 24.04
install_slowdns() {
    clear
    print_install "Installing SlowDNS (DNSTT) Server"

    CONFIG_DIR="/etc/slowdns"
    INSTALL_DIR="/usr/local/bin"
    DNSTT_PORT="5300"
    DNSTT_URL="https://dnstt.network"

    mkdir -p "$CONFIG_DIR"

    NS_DOMAIN=$(cat /etc/slowdns/ns 2>/dev/null)
    if [[ -z "$NS_DOMAIN" ]]; then
        NS_DOMAIN="dns.localhost"
        echo "$NS_DOMAIN" > /etc/slowdns/ns
        echo -e "${YELLOW}[*] Using default NS Domain: $NS_DOMAIN${NC}"
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  BIN="dnstt-server-linux-amd64" ;;
        aarch64) BIN="dnstt-server-linux-arm64" ;;
        armv7l|armv6l) BIN="dnstt-server-linux-arm" ;;
        i386|i686) BIN="dnstt-server-linux-386" ;;
        *) echo -e "${YELLOW}[*] Unsupported architecture: $ARCH, using amd64${NC}"; BIN="dnstt-server-linux-amd64" ;;
    esac

    safe_download "$DNSTT_URL/$BIN" "$INSTALL_DIR/dnstt-server"
    chmod +x "$INSTALL_DIR/dnstt-server"

    # Generate keys
    "$INSTALL_DIR/dnstt-server" -gen-key \
        -privkey-file "$CONFIG_DIR/server.key" \
        -pubkey-file "$CONFIG_DIR/server.pub"

    PUBKEY=$(cat "$CONFIG_DIR/server.pub" 2>/dev/null || echo "")
    if [[ -z "$PUBKEY" ]]; then
        echo -e "${YELLOW}[*] Failed to generate keys, creating dummy keys...${NC}"
        echo "dummy-private-key" > "$CONFIG_DIR/server.key"
        echo "dummy-public-key" > "$CONFIG_DIR/server.pub"
        PUBKEY="dummy-public-key"
    fi
    
    echo "$PUBKEY" > "$CONFIG_DIR/public.key"
    echo "$PUBKEY" > /etc/xray/slowdns_pub

    iptables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port "$DNSTT_PORT" 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || true
    netfilter-persistent reload 2>/dev/null || true

cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS (DNSTT) Server
After=network.target

[Service]
ExecStart=$INSTALL_DIR/dnstt-server -udp :$DNSTT_PORT -privkey-file $CONFIG_DIR/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slowdns
    systemctl restart slowdns

    print_success "SlowDNS Installed Successfully"
}

ins_SSHD(){
    clear
    print_install "Install SSHD"
    safe_download "${REPO}files/sshd" /etc/ssh/sshd_config
    chmod 600 /etc/ssh/sshd_config

    # Banner for SSH (idempotent)
    if ! grep -q '^Banner /etc/kyt.txt' /etc/ssh/sshd_config 2>/dev/null; then
        echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    fi

    # HTTP Custom / SlowDNS compatibility (old algorithms)
    if ! grep -q 'diffie-hellman-group1-sha1' /etc/ssh/sshd_config 2>/dev/null; then
        echo "KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config
    fi
    if ! grep -q 'aes128-cbc' /etc/ssh/sshd_config 2>/dev/null; then
        echo "Ciphers +aes128-cbc,aes256-cbc,3des-cbc" >> /etc/ssh/sshd_config
    fi
    if ! grep -q 'hmac-sha1' /etc/ssh/sshd_config 2>/dev/null; then
        echo "MACs +hmac-sha1,hmac-md5" >> /etc/ssh/sshd_config
    fi

    systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
    systemctl enable ssh 2>/dev/null || update-rc.d ssh enable 2>/dev/null
    print_success "SSHD"
}

ins_dropbear(){
    clear
    print_install "Install Dropbear"
    apt-get install -y dropbear 2>/dev/null || {
        echo -e "${YELLOW}[*] Dropbear not available in repos, installing from source...${NC}"
        apt-get install -y build-essential zlib1g-dev libssl-dev
        safe_download "https://matt.ucc.asn.au/dropbear/releases/dropbear-2022.83.tar.bz2" dropbear.tar.bz2
        tar -xjf dropbear.tar.bz2
        cd dropbear-2022.83
        ./configure && make && make install
        cd ..
        rm -rf dropbear-2022.83 dropbear.tar.bz2
    }
    
    safe_download "${REPO}config/dropbear.conf" /etc/default/dropbear
    chmod +x /etc/default/dropbear
    
    # Create systemd service if not exists
    # NOTE: we avoid using port 22/443 here to prevent conflict with SSH/nginx
    if [[ ! -f /etc/systemd/system/dropbear.service ]]; then
        cat > /etc/systemd/system/dropbear.service << EOF
[Unit]
Description=Dropbear SSH server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -E -p 109 -p 143
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    systemctl enable dropbear 2>/dev/null
    systemctl restart dropbear 2>/dev/null || /etc/init.d/dropbear restart 2>/dev/null
    print_success "Dropbear"
}

ins_vnstat(){
    clear
    print_install "Install Vnstat"
    
    # Try to install from repo first
    if apt-get install -y vnstat 2>/dev/null; then
        echo -e "${OK} Vnstat installed from repository${NC}"
    else
        echo -e "${YELLOW}[*] Installing vnstat from source...${NC}"
        apt-get install -y build-essential libsqlite3-dev
        safe_download "https://humdi.net/vnstat/vnstat-2.6.tar.gz" vnstat-2.6.tar.gz
        tar zxvf vnstat-2.6.tar.gz
        cd vnstat-2.6
        ./configure --prefix=/usr --sysconfdir=/etc && make && make install
        cd
    fi
    
    # Initialize vnstat
    if [[ -n "$NET" ]]; then
        vnstat -u -i "$NET" 2>/dev/null || true
        sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf 2>/dev/null || true
    fi
    
    chown vnstat:vnstat /var/lib/vnstat -R 2>/dev/null || true
    systemctl enable vnstat 2>/dev/null || true
    systemctl restart vnstat 2>/dev/null || /etc/init.d/vnstat restart 2>/dev/null
    
    # Cleanup
    rm -f /root/vnstat-2.6.tar.gz 2>/dev/null
    rm -rf /root/vnstat-2.6 2>/dev/null
    print_success "Vnstat"
}

ins_openvpn(){
    clear
    print_install "Install OpenVPN"
    safe_download "${REPO}files/openvpn" openvpn
    chmod +x openvpn && ./openvpn
    restart_service openvpn
    print_success "OpenVPN"
}

ins_backup(){
    clear
    print_install "Install backup system"
    apt install -y rclone 2>/dev/null || true
    
    # Only configure rclone if installed
    if command -v rclone >/dev/null 2>&1; then
        mkdir -p /root/.config/rclone
        safe_download "${REPO}config/rclone.conf" /root/.config/rclone/rclone.conf
    fi

    cd /bin
    git clone https://github.com/magnific0/wondershaper.git 2>/dev/null || true
    cd wondershaper 2>/dev/null && make install 2>/dev/null || true
    cd
    rm -rf wondershaper 2>/dev/null || true
    echo > /home/limit
    
    # Email setup (optional)
    apt install -y msmtp-mta ca-certificates bsd-mailx 2>/dev/null || true

cat <<EOF >/etc/msmtprc 2>/dev/null || true
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

    chown -R www-data:www-data /etc/msmtprc 2>/dev/null || true
    safe_download "${REPO}files/ipserver" /etc/ipserver && bash /etc/ipserver
    print_success "Backup server configuration"
}

ins_swab(){
    clear
    print_install "Install Swap 1 GB & BBR"
    
    # Install gotop if available
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases 2>/dev/null | grep tag_name | sed -E 's/.*\"v(.*)\".*/\1/' | head -n 1 || echo "")"
    if [[ -n "$gotop_latest" ]]; then
        gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v${gotop_latest}/gotop_v${gotop_latest}_linux_amd64.deb"
        safe_download "$gotop_link" /tmp/gotop.deb
        dpkg -i /tmp/gotop.deb 2>/dev/null || true
    fi
    
    # Create swap if not exists
    if [[ ! -f /swapfile ]]; then
        dd if=/dev/zero of=/swapfile bs=1024 count=1048576
        mkswap /swapfile
        chown root:root /swapfile
        chmod 0600 /swapfile
        swapon /swapfile
        echo '/swapfile      swap swap   defaults    0 0' >> /etc/fstab
    fi

    # Install BBR
    safe_download "${REPO}files/bbr.sh" bbr.sh
    chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 GB & BBR"
}

ins_Fail2ban(){
    clear
    print_install "Install Fail2ban & banner"
    
    apt install -y fail2ban 2>/dev/null || true

    # Banner for SSH
    safe_download "${REPO}files/issue.net" /etc/kyt.txt
    
    if ! grep -q '^Banner /etc/kyt.txt' /etc/ssh/sshd_config 2>/dev/null; then
        echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    fi

    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear 2>/dev/null || true
    
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    print_success "Fail2ban & banner"
}

# ePro WebSocket Proxy - FIXED FOR UBUNTU/DEBIAN (NO 404, NO MASKED)
ins_epro(){
    clear
    print_install "Install ePro WebSocket Proxy"
    
    safe_download "${REPO}files/ws" /usr/bin/ws
    safe_download "${REPO}config/tun.conf" /usr/bin/tun.conf
    
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    # Create ws.service locally to avoid 404 and mask issues
cat > /etc/systemd/system/ws.service << EOF
[Unit]
Description=WS-ePro WebSocket Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ws -f /usr/bin/tun.conf
Restart=always
RestartSec=5
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/ws.service

    systemctl daemon-reload
    systemctl unmask ws 2>/dev/null || true
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    # Ensure Xray share dir exists
    mkdir -p /usr/local/share/xray

    safe_download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" /usr/local/share/xray/geosite.dat
    safe_download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" /usr/local/share/xray/geoip.dat
    safe_download "${REPO}files/ftvpn" /usr/sbin/ftvpn
    chmod +x /usr/sbin/ftvpn

    # iptables rules
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP 2>/dev/null || true
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP 2>/dev/null || true
    
    iptables-save > /etc/iptables.up.rules 2>/dev/null || true
    iptables-restore < /etc/iptables.up.rules 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || true
    netfilter-persistent reload 2>/dev/null || true

    apt autoclean -y 2>/dev/null || true
    apt autoremove -y 2>/dev/null || true
    print_success "ePro WebSocket Proxy"
}

ins_restart(){
    clear
    print_install "Restarting all services"

    # Restart services
    restart_service nginx
    restart_service openvpn
    restart_service ssh
    restart_service dropbear
    restart_service fail2ban
    restart_service vnstat
    restart_service haproxy
    restart_service cron
    restart_service ws
    restart_service slowdns
    restart_service xray

    systemctl daemon-reload
    systemctl start netfilter-persistent 2>/dev/null || true
    systemctl enable nginx 2>/dev/null || true
    systemctl enable xray 2>/dev/null || true
    systemctl enable rc-local 2>/dev/null || true
    systemctl enable dropbear 2>/dev/null || true
    systemctl enable openvpn 2>/dev/null || true
    systemctl enable cron 2>/dev/null || true
    systemctl enable haproxy 2>/dev/null || true
    systemctl enable netfilter-persistent 2>/dev/null || true
    systemctl enable ws 2>/dev/null || true
    systemctl enable fail2ban 2>/dev/null || true
    systemctl enable ssh 2>/dev/null || true
    systemctl enable slowdns 2>/dev/null || true

    history -c
    echo "unset HISTFILE" >> /etc/profile

    cd
    rm -f /root/openvpn /root/key.pem /root/cert.pem 2>/dev/null || true
    print_success "All services restarted"
}

# Install Menu
menu(){
    clear
    print_install "Install Menu scripts"
    safe_download "${REPO}menu/menu.zip" menu.zip
    unzip -o menu.zip 2>/dev/null || true
    chmod +x menu/* 2>/dev/null || true
    mv menu/* /usr/local/sbin 2>/dev/null || true
    rm -rf menu menu.zip 2>/dev/null || true
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

    # Cron jobs
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
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >/etc/cron.d/log.xray
    service cron restart 2>/dev/null || systemctl restart cron 2>/dev/null

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
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    
    AUTOREB=$(cat /home/daily_reboot 2>/dev/null || echo "5")
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
    systemctl start netfilter-persistent 2>/dev/null || true
    systemctl enable rc-local 2>/dev/null || true
    systemctl enable cron 2>/dev/null || true
    systemctl enable netfilter-persistent 2>/dev/null || true
    systemctl restart nginx 2>/dev/null || true
    systemctl restart xray 2>/dev/null || true
    systemctl restart cron 2>/dev/null || true
    systemctl restart haproxy 2>/dev/null || true
    systemctl enable ssh 2>/dev/null || true
    systemctl enable ws 2>/dev/null || true
    systemctl enable slowdns 2>/dev/null || true
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
    pasang_domain
    password_default
    pasang_ssl
    install_xray
    ssh
    udp_mini
    install_slowdns
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

# Run installation
instal
echo ""
history -c
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain 2>/dev/null || true
secs_to_human "$(($(date +%s) - ${start}))"
hostnamectl set-hostname "$USERNAME" 2>/dev/null || true
echo -e "${green} Installation finished! Now you can enjoy NorthAfrica Script.${NC}"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} to reboot") " _
reboot