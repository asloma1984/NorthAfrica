#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Developer  » North Africa Team
#
# Personal TG » @Abdulsalam403
# Bot         » @NorthSSHAfrica5_bot
# Channel     » https://t.me/NorthAfrica_Channel
# Group       » https://t.me/NorthAfrica_Group
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Color Codes
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
NC='\e[0m'

clear

# Your Repository - CHANGE THIS TO YOUR REPO
YOUR_REPO="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main"
YOUR_UPLOAD_REPO="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main"

# Progress Bar Function
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} >/dev/null 2>&1
        ${CMD[1]} >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "\033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "\033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}

# Safety Check Function
check_safety() {
    echo -e "\033[0;36mChecking connection and repository...\033[0m"
    
    # Check internet connection
    ping -c1 github.com >/dev/null 2>&1 || {
        echo -e "${ERROR} No internet connection!"
        return 1
    }
    
    # Check if your repository is accessible
    wget -q --spider "${YOUR_UPLOAD_REPO}/menu/menu.zip" || {
        echo -e "${ERROR} Repository not accessible!"
        echo -e "${ERROR} Please check: ${YOUR_UPLOAD_REPO}/menu/menu.zip"
        return 1
    }
    echo -e "${OK} Repository verified successfully."
    return 0
}

# Main Update Function
res1() {
    # Run safety check first
    check_safety || {
        echo -e "${ERROR} Safety check failed!"
        return 1
    }
    
    # Download from your repository
    echo -e "${OK} Downloading from your repository..."
    wget -q "${YOUR_UPLOAD_REPO}/menu/menu.zip" -O menu.zip || {
        echo -e "${ERROR} Failed to download menu.zip!"
        return 1
    }
    
    # Check file size
    SIZE=$(stat -c%s "menu.zip" 2>/dev/null || echo "0")
    if [[ $SIZE -lt 50000 ]]; then
        echo -e "${ERROR} Invalid file size: ${SIZE} bytes"
        rm -f menu.zip
        return 1
    fi
    
    # Extract files
    echo -e "${OK} Extracting files..."
    unzip -oq menu.zip || {
        echo -e "${ERROR} Failed to extract menu.zip!"
        return 1
    }
    
    # Check if menu directory exists
    if [[ ! -d "menu" ]]; then
        echo -e "${ERROR} Menu directory not found!"
        return 1
    fi
    
    # Set permissions and install
    echo -e "${OK} Setting permissions..."
    chmod +x menu/*
    
    echo -e "${OK} Installing files..."
    mkdir -p /usr/local/sbin/
    mv menu/* /usr/local/sbin/
    
    # Cleanup
    echo -e "${OK} Cleaning up..."
    rm -rf menu
    rm -f menu.zip
    
    # Reload systemd
    systemctl daemon-reload 2>/dev/null
    
    echo -e "${OK} Update completed successfully!"
    return 0
}

# Reload netfilter-persistent if available
reload_firewall() {
    if command -v netfilter-persistent &>/dev/null; then
        echo -e "${OK} Reloading firewall rules..."
        netfilter-persistent reload >/dev/null 2>&1
    fi
}

# Check if lolcat is available
check_lolcat() {
    if ! command -v lolcat &>/dev/null; then
        echo -e "${YELLOW}[INFO] Installing lolcat for better display...${NC}"
        apt-get update >/dev/null 2>&1
        apt-get install -y ruby >/dev/null 2>&1
        gem install lolcat >/dev/null 2>&1
    fi
}

# Main Execution
clear

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} This script must be run as root!"
    echo -e "Please run: sudo bash $0"
    exit 1
fi

# Install lolcat if needed
check_lolcat

# Display header
echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\e[1;97;101m            » UPDATE SCRIPT «             \033[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
echo -e "\033[1;91mUpdate North Africa Script Service\033[1;37m"

# Execute update
fun_bar 'res1'

# Reload firewall
reload_firewall

# Display completion
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
echo -e "\033[1;92m✅ Update Completed Successfully!\033[0m"
echo -e ""
echo -e "\033[1;94m📊 Repository Information:\033[0m"
echo -e "   ${OK} Main Repo: ${YOUR_REPO}"
echo -e "   ${OK} Upload Repo: ${YOUR_UPLOAD_REPO}"
echo -e ""
echo -e "\033[1;96m📢 Contact Information:\033[0m"
echo -e "   🌐 Channel: https://t.me/NorthAfrica_Channel"
echo -e "   👥 Group: https://t.me/NorthAfrica_Group"
echo -e "   🤖 Bot: @NorthSSHAfrica5_bot"
echo -e "   👤 Admin: @Abdulsalam403"
echo -e ""

# Restart services if they exist
echo -e "\033[1;93m🔄 Restarting services...\033[0m"
services=("xray" "nginx" "haproxy")
for service in "${services[@]}"; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        systemctl restart "$service" >/dev/null 2>&1 && \
        echo -e "   ${OK} $service restarted" || \
        echo -e "   ${ERROR} Failed to restart $service"
    fi
done

sleep 2

# Return to menu
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] To Back On Menu"
clear
menu