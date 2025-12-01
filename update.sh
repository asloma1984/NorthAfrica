#!/bin/bash
# =========================================================
# North Africa Script - Update System
# Developer : Abdul
# Contact   : t.me/Abdulsalam403
# Repo      : https://github.com/asloma1984/NorthAfrica
# Year      : 2025
# =========================================================

###============================###
### 1 — Anti-Tamper Protection ###
###============================###

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[91mERROR: You must run this script as root.\e[0m"
    exit 1
fi

# Prevent renaming
SCRIPT_NAME="$(basename "$0")"
if [[ "$SCRIPT_NAME" != "update.sh" ]]; then
    echo -e "\e[91mERROR: Script filename has been modified.\e[0m"
    exit 1
fi

# Script integrity checksum
SCRIPT_HASH_ORIGINAL="__REPLACE_HASH__"
SCRIPT_HASH_CURRENT=$(sha256sum "$0" | awk '{print $1}')

if [[ "$SCRIPT_HASH_CURRENT" != "$SCRIPT_HASH_ORIGINAL" ]]; then
    echo -e "\e[91mERROR: Script content has been modified.\e[0m"
    exit 1
fi

###============================###
### 2 — License / IP Validation ###
###============================###

MYIP=$(curl -sS ipv4.icanhazip.com)
REG_URL="https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/register"

VALID_IP=$(curl -sS $REG_URL | grep $MYIP | awk '{print $1}')

if [[ "$VALID_IP" == "" ]]; then
    clear
    echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[41;97m          404 NOT FOUND AUTOSCRIPT          \033[0m"
    echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e "            \033[31mPERMISSION DENIED!\033[0m"
    echo -e "   Your VPS \033[33m$MYIP\033[0m is not registered."
    echo -e "   Please contact the developer for activation:"
    echo -e ""
    echo -e "          Telegram : \033[32mt.me/Abdulsalam403\033[0m"
    echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    exit 1
fi

###============================###
### 3 — Update Function ###
###============================###

fun_bar() {
    CMD1="$1"
    (
        $CMD1 >/dev/null 2>&1
        touch /tmp/update_done
    ) &
    echo -ne "\033[0;33mUpdating... \033[1;37m["
    while true; do
        for (( i=0; i<20; i++ )); do
            echo -ne "\033[0;32m#"
            sleep 0.1
        done
        [[ -e /tmp/update_done ]] && rm /tmp/update_done && break
        echo -e "\033[0;33m]"
        echo -ne "\033[0;33mUpdating... \033[1;37m["
    done
    echo -e "\033[0;33m]\033[1;32m DONE!\033[0m"
}

update_now() {
    echo ""
    echo -e "\033[1;36mDownloading latest menu update...\033[0m"
    wget -q https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/menu/menu.zip -O menu.zip
    unzip -o menu.zip >/dev/null 2>&1
    chmod +x menu/* >/dev/null 2>&1
    mv -f menu/* /usr/local/sbin >/dev/null 2>&1
    rm -rf menu menu.zip
    echo -e "\033[1;32mMenu updated.\033[0m"

    echo ""
    echo -e "\033[1;36mUpdating premium.sh installer...\033[0m"
    wget -q https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/premium.sh -O /root/premium.sh
    chmod +x /root/premium.sh
    echo -e "\033[1;32mInstaller updated.\033[0m"

    rm -f /root/update.sh
}

###============================###
### 4 — Run Update ###
###============================###

clear
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\e[1;97;101m       » UPDATE NORTH AFRICA SCRIPT «       \033[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo ""
echo -e "\033[1;91mUpdating components... Please wait...\033[1;37m"

fun_bar update_now

echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\033[1;32mAll components updated successfully!\033[0m"
echo ""
read -n 1 -s -r -p "Press [ Enter ] to return to menu"
menu