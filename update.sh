#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers  » Tøxic savage࿐
# Email       » johntezali56@gmail.com
# telegram    » https://t.me/ToxicSavage
# whatsapp    » wa.me/+254716637803
#
# Personal TG » @Abdulsalam403
# Bot         » @NorthSSHAfrica5_bot
# Channel     » https://t.me/northafrica9
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

clear

fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm "$HOME/fim"
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
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

# 🔐 دالة التحقق من الاتصال وسلامة الملف
check_safety() {
    echo -e "\033[0;36mChecking connection and file integrity...\033[0m"
    ping -c1 github.com >/dev/null 2>&1 || {
        echo -e "\033[0;31m[ERROR]\033[0m No internet connection!"
        exit 1
    }

    wget -q --spider https://raw.githubusercontent.com/NorthAfrica/upload/main/menu/menu.zip || {
        echo -e "\033[0;31m[ERROR]\033[0m menu.zip not found on GitHub!"
        exit 1
    }

    wget -q -O menu.zip https://raw.githubusercontent.com/NorthAfrica/upload/main/menu/menu.zip

    # 🔍 تحقق من حجم الملف (أكثر من 50KB يعني ملف حقيقي)
    SIZE=$(stat -c%s "menu.zip")
    if [[ $SIZE -lt 50000 ]]; then
        echo -e "\033[0;31m[ERROR]\033[0m Invalid or corrupted menu.zip!"
        rm -f menu.zip
        exit 1
    fi

    echo -e "\033[1;32mFile verified successfully.\033[0m"
}

res1() {
    check_safety
    unzip -oq menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin/
    rm -rf menu menu.zip update.sh
}

netfilter-persistent
clear

echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\e[1;97;101m            » UPDATE SCRIPT «             \033[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
echo -e "\033[1;91mUpdate North Africa Script Service\033[1;37m"
fun_bar 'res1'
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] To Back On Menu"
menu