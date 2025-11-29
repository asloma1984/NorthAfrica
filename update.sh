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

# Progress Bar Function
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm "$HOME/fim"
        ${CMD[0]} >/dev/null 2>&1
        ${CMD[1]} >/dev/null 2>&1
        touch "$HOME/fim"
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "\033[0;33mPlease wait, loading \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm "$HOME/fim" && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "\033[0;33mPlease wait, loading \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK!\033[1;37m"
    tput cnorm
}

# Safety Check Function
check_safety() {
    echo -e "\033[0;36mChecking connection and file integrity...\033[0m"
    
    # Check internet connection
    ping -c1 github.com >/dev/null 2>&1 || {
        echo -e "${ERROR} No internet connection!"
        exit 1
    }
    
    # Check if file exists on GitHub
    wget -q --spider https://raw.githubusercontent.com/NorthAfrica/upload/main/menu/menu.zip || {
        echo -e "${ERROR} menu.zip not found on GitHub!"
        exit 1
    }
    
    # Download the file
    echo -e "${OK} Downloading update package..."
    wget -q -O menu.zip https://raw.githubusercontent.com/NorthAfrica/upload/main/menu/menu.zip || {
        echo -e "${ERROR} Failed to download menu.zip!"
        exit 1
    }
    
    # Check file size
    SIZE=$(stat -c%s "menu.zip" 2>/dev/null || echo "0")
    if [[ $SIZE -lt 50000 ]]; then
        echo -e "${ERROR} Invalid or corrupted menu.zip! (Size: ${SIZE} bytes)"
        rm -f menu.zip
        exit 1
    fi
    
    echo -e "${OK} File verified successfully. (Size: ${SIZE} bytes)"
}

# Main Update Function
res1() {
    # Run safety check
    check_safety || {
        echo -e "${ERROR} Safety check failed!"
        return 1
    }
    
    # Create backup
    echo -e "${OK} Creating backup..."
    backup_dir="/root/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup existing menu files
    if [[ -d "/usr/local/sbin" ]]; then
        cp -r /usr/local/sbin/* "$backup_dir/" 2>/dev/null
        echo -e "${OK} Backup created in: $backup_dir"
    fi
    
    # Extract files
    echo -e "${OK} Extracting files..."
    unzip -oq menu.zip || {
        echo -e "${ERROR} Failed to extract menu.zip!"
        return 1
    }
    
    # Check if menu directory exists
    if [[ ! -d "menu" ]]; then
        echo -e "${ERROR} 'menu' directory not found in zip file!"
        return 1
    fi
    
    # Set execution permissions
    echo -e "${OK} Setting permissions..."
    chmod +x menu/* 2>/dev/null
    
    # Ensure target directory exists
    mkdir -p /usr/local/sbin/
    
    # Copy files to destination
    echo -e "${OK} Installing updates..."
    cp -r menu/* /usr/local/sbin/ 2>/dev/null
    
    # Set permissions for all copied files
    chmod +x /usr/local/sbin/* 2>/dev/null
    
    # Clean up temporary files
    echo -e "${OK} Cleaning up temporary files..."
    rm -rf menu menu.zip
    
    # Reload systemd services
    systemctl daemon-reload 2>/dev/null
    
    echo -e "${OK} Update process completed successfully!"
    return 0
}

# Check if netfilter-persistent is available and reload it
reload_netfilter() {
    if command -v netfilter-persistent &>/dev/null; then
        echo -e "${OK} Reloading netfilter-persistent..."
        netfilter-persistent reload >/dev/null 2>&1
    fi
}

# Main Execution
clear

# Display header
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\e[1;97;101m            » UPDATE SCRIPT «             \033[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\033[1;91mUpdating North Africa Script Service\033[1;37m"
echo -e ""

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} This script must be run as root!"
    echo -e "Please run: sudo bash $0"
    exit 1
fi

# Check if lolcat is installed, if not try to install it
if ! command -v lolcat &>/dev/null; then
    echo -e "${OK} Installing lolcat for better display..."
    apt-get update >/dev/null 2>&1
    apt-get install -y ruby >/dev/null 2>&1
    gem install lolcat >/dev/null 2>&1
fi

# Execute update with progress bar
fun_bar 'res1'

# Reload netfilter-persistent after update
reload_netfilter

# Display completion message
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
echo -e "\033[1;92m✅ Update Completed Successfully!\033[0m"
echo -e ""
echo -e "\033[1;94m📊 Update Summary:\033[0m"
echo -e "   ${OK} Files downloaded and verified"
echo -e "   ${OK} Backup created successfully"
echo -e "   ${OK} Permissions set correctly"
echo -e "   ${OK} System services reloaded"
echo -e ""
echo -e "\033[1;93m🔧 Services Status:\033[0m"

# Check and display service status
services=("xray" "nginx" "haproxy")
for service in "${services[@]}"; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        echo -e "   ${OK} $service: ${Green}Active${NC}"
    elif systemctl is-enabled "$service" >/dev/null 2>&1; then
        echo -e "   ${OK} $service: ${YELLOW}Enabled but not running${NC}"
    else
        echo -e "   ${ERROR} $service: ${RED}Not available${NC}"
    fi
done

echo -e ""
echo -e "\033[1;96m📢 Join Our Community:\033[0m"
echo -e "   🌐 Channel: https://t.me/NorthAfrica_Channel"
echo -e "   👥 Group:   https://t.me/NorthAfrica_Group"
echo -e "   🤖 Bot:     @NorthSSHAfrica5_bot"
echo -e ""
echo -e "\033[1;95m💡 Need Help?\033[0m"
echo -e "   Contact: @Abdulsalam403"
echo -e ""

# Restart related services if they exist
echo -e "\033[1;93m🔄 Restarting related services...\033[0m"
for service in "${services[@]}"; do
    if systemctl list-unit-files | grep -q "$service.service"; then
        systemctl restart "$service" >/dev/null 2>&1 && \
        echo -e "   ${OK} $service service restarted" || \
        echo -e "   ${ERROR} Failed to restart $service"
    fi
done

sleep 3

# Return to main menu if available
echo -e ""
if command -v menu &>/dev/null; then
    echo -e "\033[1;92m🎯 Returning to main menu...\033[0m"
    read -p "$(echo -e "Press ${Green}Enter${NC} to continue to main menu or ${RED}Ctrl+C${NC} to exit") "
    clear
    menu
else
    echo -e "\033[1;93m⚠️  Note: Main menu command not found\033[0m"
    echo -e "${OK} You can access scripts manually from /usr/local/sbin/"
    echo -e "${OK} Available commands:"
    ls /usr/local/sbin/ 2>/dev/null | head -10
    echo -e ""
    read -p "$(echo -e "Press ${Green}Enter${NC} to exit") "
    clear
fi