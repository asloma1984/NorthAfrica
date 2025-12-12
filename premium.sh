#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Requirements : Debian 9–13 / Ubuntu 18–25
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
# Cleanup helper: remove installer files and exit
# ─────────────────────────────────────────────────────
clean_and_exit() {
  echo ""
  echo -e "${YELLOW}[*] Installer will exit in 3 seconds...${NC}"
  sleep 3

  echo -e "${YELLOW}[*] Cleaning installer files before exit...${NC}"

  # Remove this script itself
  rm -f "$0" 2>/dev/null

  # Common script names in /root (adjust if needed)
  rm -f /root/premium.sh /root/update.sh 2>/dev/null

  # Temporary / downloaded content
  rm -f /root/menu.zip 2>/dev/null
  rm -rf /root/menu 2>/dev/null
  rm -f /tmp/install-xray.sh /root/openvpn /root/bbr.sh /root/cf.sh 2>/dev/null

  echo -e "${RED}Installer files removed. Exiting now.${NC}"
  exit 1
}

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
    echo -e "${YELLOW}[*] Ubuntu 24.04 detected - applying DNS fix...${NC}"

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
    echo -e "${ERROR} DNS is still not working! Installation may fail.${NC}"
    return 1
  fi
}

# ===========================================
# SAFE DOWNLOAD WITH RETRY - IMPROVED (NO SPAM ON 404)
# ===========================================
safe_download() {
  local url="$1"
  local output="$2"
  local max_retries=5
  local retry_count=0
  local http_code="000"

  while [ $retry_count -lt $max_retries ]; do
    if wget -q --no-check-certificate --timeout=30 -O "$output" "$url"; then
      return 0
    fi

    # Check HTTP code (to detect 404/4xx and stop retrying)
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "$url" || echo "000")

    if [[ "$http_code" == 4* ]]; then
      echo -e "${ERROR} Remote file not found (HTTP $http_code): $url${NC}"
      return 1
    fi

    retry_count=$((retry_count + 1))
    echo -e "${YELLOW}[*] Download failed (HTTP $http_code), retry $retry_count/$max_retries...${NC}"
    sleep 3

    # Fix DNS again if needed
    if ! ping -c1 -W2 google.com &>/dev/null; then
      fix_dns
    fi
  done

  echo -e "${ERROR} Failed to download after $max_retries attempts: $url${NC}"
  return 1
}

safe_curl() {
  local url="$1"
  local max_retries=5
  local retry_count=0
  local http_code="000"

  while [ $retry_count -lt $max_retries ]; do
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "$url" || echo "000")

    if [[ "$http_code" == "200" ]]; then
      curl -sSL "$url"
      return 0
    fi

    if [[ "$http_code" == 4* ]]; then
      echo -e "${ERROR} Remote resource not found (HTTP $http_code): $url${NC}"
      return 1
    fi

    retry_count=$((retry_count + 1))
    echo -e "${YELLOW}[*] Curl failed (HTTP $http_code), retry $retry_count/$max_retries...${NC}"
    sleep 3

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

# Ensure /etc/sysctl.conf exists and has net.ipv4.ip_forward=1
# This fixes "sed: can't read /etc/sysctl.conf" from OpenVPN helper scripts.
ensure_sysctl_conf() {
  if [[ ! -f /etc/sysctl.conf ]]; then
    cat > /etc/sysctl.conf <<EOF
# Sysctl configuration created by NorthAfrica installer
net.ipv4.ip_forward=1
EOF
  else
    if grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf; then
      sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    else
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
  fi

  sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true
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
echo -e "  Developer » ${YELLOW}Abdul (NorthAfrica Script)${NC} ${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e "  » Auto-install VPN & Xray server on your VPS"
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

# Ask client for subscriber name (as in register file)
echo ""
read -rp "Enter subscriber name (as registered) : " SUBSCRIBER_NAME
if [[ -z "$SUBSCRIBER_NAME" ]]; then
  echo -e "${ERROR} Subscriber name cannot be empty.${NC}"
  clean_and_exit
fi

#-------------------------------------------------------------------------------
#  LICENSE / REGISTER CHECK (PRIVATE)  -  IP + NAME COMBINATION
#-------------------------------------------------------------------------------
MYIP=$(curl -sS ipv4.icanhazip.com 2>/dev/null || echo "")
LICENSE_URL="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/register"

license_denied_not_registered() {
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[41;97m              404 NOT FOUND AUTOSCRIPT              \033[0m"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e ""
  echo -e "          ${RED}PERMISSION DENIED!${NC}"
  echo -e "   VPS IP   : ${YELLOW}$MYIP${NC}"
  echo -e "   Name     : ${YELLOW}$SUBSCRIBER_NAME${NC}"
  echo -e ""
  echo -e "   This IP + Name is NOT registered in license."
  echo -e "   Please contact the developer for activation:"
  echo -e ""
  echo -e "          Telegram: ${green}t.me/Abdulsalam403${NC}"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  clean_and_exit
}

license_denied_expired() {
  local exp_date="$1"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[41;97m              404 NOT FOUND AUTOSCRIPT              \033[0m"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e ""
  echo -e "          ${RED}PERMISSION DENIED!${NC}"
  echo -e "   VPS IP   : ${YELLOW}$MYIP${NC}"
  echo -e "   Name     : ${YELLOW}$SUBSCRIBER_NAME${NC}"
  echo -e "   Expired  : ${YELLOW}$exp_date${NC}"
  echo -e ""
  echo -e "   Your license has EXPIRED."
  echo -e "   Please contact the developer for renewal:"
  echo -e ""
  echo -e "          Telegram: ${green}t.me/Abdulsalam403${NC}"
  echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  clean_and_exit
}

license_check() {
  local data line

  # Fix DNS before license check
  fix_dns

  data=$(safe_curl "$LICENSE_URL") || {
    echo -e "${ERROR} Unable to fetch license data from register.${NC}"
    license_denied_not_registered
  }

  # Register line format example:
  # ### Abdul 2027-08-09 31.14.135.141
  # Field2 = name, Field3 = expiry, last field = IP
  line=$(echo "$data" \
    | awk -v ip="$MYIP" -v name="$SUBSCRIBER_NAME" '$NF==ip && $2==name {print}')

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
print_ok()      { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
print_install() { echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; echo -e "${YELLOW} » $1 ${FONT}"; echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; sleep 1; }
print_error()   { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
print_success() { if [[ 0 -eq $? ]]; then echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; echo -e "${Green} » $1 successfully installed"; echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; sleep 2; fi; }

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
    "Shmem")    ((mem_used+=${b/kB})) ;;
    "MemFree" | "Buffers" | "Cached" | "SReclaimable")
      mem_used="$((mem_used-=${b/kB}))"
    ;;
  esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name="${OS_NAME}"
export Kernel
Kernel=$(uname -r)
export Arch
Arch=$(uname -m)
export IP
IP=$(curl -s https://ipinfo.io/ip/ 2>/dev/null || echo "$IP")

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
      curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg 2>/dev/null
      echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
        http://haproxy.debian.net bookworm-backports-2.8 main \
        >/etc/apt/sources.list.d/haproxy.list 2>/dev/null
      apt-get update -y
      apt-get install -y haproxy
    }
  fi

  # Make sure sysctl.conf exists before any script touches it
  ensure_sysctl_conf

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
    gcc g++ python3 python3-pip python-is-python3 htop lsof tar wget curl ruby zip unzip p7zip-full \
    libc6 util-linux ca-certificates bsd-mailx \
    net-tools openssl gnupg gnupg2 lsb-release shc cmake git screen \
    xz-utils apt-transport-https dnsutils jq openvpn easy-rsa 2>/dev/null || true

  # Ensure sysctl.conf is present & correct before OpenVPN helpers touch it
  ensure_sysctl_conf

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
      echo -e "\e[31m[ERROR] Domain cannot be empty!\
