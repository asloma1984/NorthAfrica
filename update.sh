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

# Fixed Progress Bar Function
fun_bar() {
    local command="$1"
    local description="$2"
    
    echo -e "${OK} $description"
    
    # Create temporary file to track progress
    local temp_file=$(mktemp)
    
    # Run the command in background and track progress
    (
        $command >/dev/null 2>&1
        echo "100" > "$temp_file"
    ) &
    
    local pid=$!
    local i=0
    local spin='-\|/'
    
    # Show progress animation
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r[${spin:$i:1}] Processing... Please wait "
        sleep 0.5
    done
    
    # Wait for process to complete
    wait "$pid"
    
    # Clean up
    rm -f "$temp_file"
    printf "\r${OK} Completed successfully!                          \n"
}

# Safety Check Function
check_safety() {
    echo -e "\033[0;36mChecking connection and file integrity...\033[0m"
    
    # Check internet connection
    if ! ping -c1 -W2 github.com >/dev/null 2>&1; then
        echo -e "${ERROR} No internet connection!"
        return 1
    fi
    
    # Check if file exists on GitHub
    echo -e "${OK} Verifying update source..."
    if ! wget -q --spider --timeout=10 "https://raw.githubusercontent.com/NorthAfrica/upload/main/menu/menu.zip"; then
        echo -e "${ERROR} menu.zip not found on GitHub!"
        return 1
    fi
    
    # Download the file
    echo -e "${OK} Downloading update package..."
    if ! wget -q --timeout=30 -O menu.zip "https://raw.githubusercontent.com/NorthAfrica/upload/main/menu/menu.zip"; then
        echo -e "${ERROR} Failed to download menu.zip!"
        return 1
    fi
    
    # Check file size
    local SIZE=0
    if [[ -f "menu.zip" ]]; then
        SIZE=$(stat -c%s "menu.zip" 2>/dev/null || echo "0")
    fi
    
    if [[ $SIZE -lt 50000 ]]; then
        echo -e "${ERROR} Invalid or corrupted menu.zip! (Size: ${SIZE} bytes)"
        rm -f menu.zip
        return 1
    fi
    
    echo -e "${OK} File verified successfully. (Size: ${SIZE} bytes)"
    return 0
}

# Main Update Function
perform_update() {
    echo -e "${OK} Starting update process..."
    
    # Run safety check
    if ! check_safety; then
        echo -e "${ERROR} Safety check failed! Update aborted."
        return 1
    fi
    
    # Create backup
    echo -e "${OK} Creating backup..."
    local backup_dir="/root/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup existing menu files
    if [[ -d "/usr/local/sbin" ]]; then
        cp -r /usr/local/sbin/* "$backup_dir/" 2>/dev/null
        echo -e "${OK} Backup created in: $backup_dir"
    fi
    
    # Extract files
    echo -e "${OK} Extracting files..."
    if ! unzip -oq menu.zip; then
        echo -e "${ERROR} Failed to extract menu.zip!"
        return 1
    fi
    
    # Check if menu directory exists
    if [[ ! -d "menu" ]]; then
        echo -e "${ERROR} 'menu' directory not found in zip file!"
        return 1
    fi
    
    # Check if there are files in menu directory
    if [[ -z "$(ls -A menu/ 2>/dev/null)" ]]; then
        echo -e "${ERROR} No files found in menu directory!"
        return 1
    fi
    
    # Set execution permissions
    echo -e "${OK} Setting permissions..."
    chmod +x menu/* 2>/dev/null
    
    # Ensure target directory exists
    mkdir -p /usr/local/sbin/
    
    # Copy files to destination
    echo -e "${OK} Installing updates..."
    if ! cp -r menu/* /usr/local/sbin/ 2>/dev/null; then
        echo -e "${ERROR} Failed to copy files to /usr/local/sbin/"
        return 1
    fi
    
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

# Check and reload netfilter-persistent
reload_netfilter() {
    if command -v netfilter-persistent &>/dev/null; then
        echo -e "${OK} Reloading netfilter-persistent..."
        netfilter-persistent reload >/dev/null 2>&1
    fi
}

# Check if lolcat is available, if not use fallback
safe_lolcat() {
    if command -v lolcat &>/dev/null; then
        echo "$1" | lolcat
    else
        echo "$1"
    fi
}

# Main Execution
clear

# Display header
safe_lolcat "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "\e[1;97;101m            » UPDATE SCRIPT «             \033[0m"
safe_lolcat "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "\033[1;91mUpdating North Africa Script Service\033[1;37m"
echo -e ""

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} This script must be run as root!"
    echo -e "Please run: sudo bash $0"
    exit 1
fi

# Check if we can install lolcat if missing
if ! command -v lolcat &>/dev/null; then
    echo -e "${YELLOW}[INFO] lolcat not found, using plain text display${NC}"
fi

# Execute update with simple progress
echo -e "${OK} Starting update process..."
if perform_update; then
    echo -e "\033[1;92m✅ Update Completed Successfully!\033[0m"
else
    echo -e "\033[1;91m❌ Update Failed!\033[0m"
    exit 1
fi

# Reload netfilter-persistent after update
reload_netfilter

# Display completion message
safe_lolcat "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
    if systemctl list-unit-files | grep -q "$service.service" && systemctl is-active "$service" >/dev/null 2>&1; then
        if systemctl restart "$service" >/dev/null 2>&1; then
            echo -e "   ${OK} $service service restarted"
        else
            echo -e "   ${ERROR} Failed to restart $service"
        fi
    fi
done

sleep 2

# Return to main menu if available
echo -e ""
if command -v menu &>/dev/null; then
    echo -e "\033[1;92m🎯 Returning to main menu...\033[0m"
    read -p "$(echo -e "Press ${Green}Enter${NC} to continue to main menu or ${RED}Ctrl+C${NC} to exit") "
    clear
    menu
else
    echo -e "\033[1;93m⚠️  Note: Main menu command not found\033[0m"
    echo -e "${OK} Update completed. You can run scripts from /usr/local/sbin/"
    echo -e ""
    read -p "$(echo -e "Press ${Green}Enter${NC} to exit") "
    clear
fi