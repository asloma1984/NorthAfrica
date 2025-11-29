#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » Tøxic savage࿐
# Email      » johntezali56@gmail.com
# telegram   » https://t.me/ToxicSavage
# whatsapp   » wa.me/+254716637803
#
# Personal TG : @Abdulsalam403
# Bot        : @NorthSSHAfrica5_bot
# Channel    : https://t.me/northafrica9
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NS=$(cat /etc/xray/dns)
PUB=$(cat /etc/slowdns/server.pub)
domain=$(cat /etc/xray/domain)

# colors
grenbo="\e[92;1m"
NC='\e[0m'

# your default bot data
MY_BOT_TOKEN="7850471388:AAHDPIVeDvXPBU_Wu-2p-jVZSMDRkjZWpLk"
MY_ADMIN_ID="1066158218"   # your Telegram ID

# install packages
apt update -y && apt upgrade -y
apt install -y python3 python3-pip git unzip

cd /usr/bin
wget https://raw.githubusercontent.com/NorthAfrica/upload/main/bot/bot.zip
unzip bot.zip
mv bot/* /usr/bin
chmod +x /usr/bin/*
rm -rf bot
rm -rf bot.zip
clear

wget https://raw.githubusercontent.com/NorthAfrica/upload/main/bot/kyt.zip
unzip kyt.zip
pip3 install -r kyt/requirements.txt

clear
echo ""
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[1;97;101m              » ADD BOT PANEL «              \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "${grenbo}Tutorial: Create Telegram Bot and get your ID${NC}"
echo -e "${grenbo}[»] Create Bot & Token  : @BotFather${NC}"
echo -e "${grenbo}[»] Get Telegram ID     : @MissRose_bot or @userinfobot${NC}"
echo -e "${grenbo}[»] Default Bot         : @NorthSSHAfrica5_bot${NC}"
echo -e "${grenbo}[»] Owner Account       : @Abdulsalam403${NC}"
echo -e "${grenbo}[»] Channel             : https://t.me/northafrica9${NC}"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""

read -e -p "[»] Input your Bot Token   (default: ${MY_BOT_TOKEN}) : " bottoken
bottoken=${bottoken:-$MY_BOT_TOKEN}

read -e -p "[»] Input your Telegram ID (default: ${MY_ADMIN_ID})   : " admin
admin=${admin:-$MY_ADMIN_ID}

echo -e BOT_TOKEN='"'"$bottoken"'"' > /usr/bin/kyt/var.txt
echo -e ADMIN='"'"$admin"'"'     >> /usr/bin/kyt/var.txt
echo -e DOMAIN='"'"$domain"'"'   >> /usr/bin/kyt/var.txt
echo -e PUB='"'"$PUB"'"'         >> /usr/bin/kyt/var.txt
echo -e HOST='"'"$NS"'"'         >> /usr/bin/kyt/var.txt
clear

cat > /etc/systemd/system/kyt.service << END
[Unit]
Description=NorthAfrica Bot Panel - @NorthSSHAfrica5_bot
After=network.target

[Service]
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/python3 -m kyt
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl start kyt
systemctl enable kyt
systemctl restart kyt

cd /root
rm -rf kyt.zip
rm -rf kyt.sh

echo "Input data successfully processed!"
echo "Your Telegram Bot Data:"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Token Bot      : $bottoken"
echo "Admin (ID)     : $admin"
echo "Domain         : $domain"
# echo "Pub            : $PUB"
# echo "Host           : $NS"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bot settings completed successfully!"
sleep 2
clear

echo "Installation complete. Open your bot and type /menu"
read -p "Press Enter to go back to menu"
menu