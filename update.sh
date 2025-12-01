#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# UPDATE NORTH AFRICA SCRIPT (Simple Version)
# No encryption – No SHA256 check – No modification lock
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

clear

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
    echo -ne "\033[0;33mPlease wait updating \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1
        tput cuu1
        tput dl1
        echo -ne "\033[0;33mPlease wait updating \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m DONE!\033[0m"
    tput cnorm
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Update Function
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

update_now() {
    cd /root || exit
    echo ""
    echo -e "\033[1;36m🔄 Downloading latest menu update...\033[0m"

    wget -q https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/menu/menu.zip -O menu.zip
    unzip -o menu.zip >/dev/null 2>&1
    chmod +x menu/* >/dev/null 2>&1
    mv -f menu/* /usr/local/sbin >/dev/null 2>&1
    rm -rf menu menu.zip
    echo -e "\033[1;32m✔ Menu updated successfully.\033[0m"

    echo ""
    echo -e "\033[1;36m🔄 Updating premium.sh...\033[0m"
    wget -q https://raw.githubusercontent.com/asloma1984/NorthAfrica/main/premium.sh -O /root/premium.sh
    chmod +x /root/premium.sh
    echo -e "\033[1;32m✔ premium.sh updated successfully.\033[0m"

    echo ""
    echo -e "\033[1;32m✓ Update completed.\033[0m"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Run Update
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

clear
echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e "\e[1;97;101m        » UPDATE NORTH AFRICA SCRIPT «       \033[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo ""
echo -e "\033[1;91mUpdating script components... Please wait...\033[0m"

fun_bar update_now

echo -e ""
echo -e "\033[1;32mAll components updated successfully!\033[0m"
echo ""
read -n 1 -s -r -p "Press Enter to return to menu"
menu