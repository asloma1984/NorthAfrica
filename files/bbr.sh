#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Requirement : Debian 9+ / Ubuntu 18.04+ / 20+
# Developer  : Abdul NorthAfrica
# GitHub     : https://github.com/AbdulNorthAfrica
# Telegram   : https://t.me/AbdulNorthAfrica
# WhatsApp   : wa.me/+0000000000000
# Description: TCP BBR Installation & System Optimization Script
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

red='\e[1;31m'
green='\e[0;32m'
purple='\e[0;35m'
orange='\e[0;33m'
NC='\e[0m'
clear

echo ""
echo -e "${green}Installing TCP BBR and optimizing system parameters...${NC}"
sleep 3
clear

touch /usr/local/sbin/bbr

Add_To_New_Line(){
	if [ "$(tail -n1 $1 | wc -l)" == "0" ]; then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

Check_And_Add_Line(){
	if [ -z "$(grep "$2" "$1")" ]; then
		Add_To_New_Line "$1" "$2"
	fi
}

Install_BBR(){
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[32;1mInstalling TCP BBR...\e[0m"
if [ -n "$(lsmod | grep bbr)" ]; then
	echo -e "\e[0;32mTCP BBR is already installed.\e[0m"
	echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
	return 1
fi
echo -e "\e[0;32mStarting TCP BBR installation...\e[0m"
modprobe tcp_bbr
Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
sysctl -p
if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ]; then
	echo -e "\e[0;32mTCP BBR installation successful!\e[0m"
else
	echo -e "\e[1;31mFailed to install TCP BBR.\e[0m"
fi
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
}

Optimize_Parameters(){
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[32;1mOptimizing system parameters...\e[0m"
modprobe ip_conntrack

# File limits
Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 65535"
Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 65535"
Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"

# IPv4 forwarding
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.route_localnet=1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_forward = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.forwarding = 1"

# IPv6 forwarding
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.forwarding = 1"

# IPv6 settings
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_ra = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_ra = 2"

# Kernel and TCP tuning
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget = 50000"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget_usecs = 5000"
Check_And_Add_Line "/etc/sysctl.conf" "#fs.file-max = 51200"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_default = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_default = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.optmem_max = 65536"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn = 10000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "net.netfilter.nf_conntrack_max = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "net.nf_conntrack_max = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "vm.swappiness = 1"
Check_And_Add_Line "/etc/sysctl.conf" "vm.overcommit_memory = 1"
Check_And_Add_Line "/etc/sysctl.conf" "kernel.pid_max=64000"

# Systemd limits
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultTimeoutStopSec=30s"
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitCORE=infinity"
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitNOFILE=65535"

echo -e "\e[0;32mSystem parameters optimized successfully.\e[0m"
echo -e "\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
}

Install_BBR
Optimize_Parameters

rm -f /root/bbr.sh >/dev/null 2>&1
echo -e '\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m'
echo -e '\e[0;32m       Installation Completed!       \e[0m'
echo -e '\e[32;1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m'
sleep 1