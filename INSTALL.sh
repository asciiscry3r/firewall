#!/usr/bin/env bash

function install_simplestatefulfirewall {
    yes | sudo cp -rf simplestatefulfirewall.service /usr/lib/systemd/system/simplestatefulfirewall.service
    yes | sudo cp -rf simplestatefulfirewall.timer /usr/lib/systemd/system/simplestatefulfirewall.timer
    yes | sudo cp -rf simplestatefulfirewall.sh /usr/bin/simplestatefulfirewall.sh
    chmod 0640 /usr/lib/systemd/system/simplestatefulfirewall.service
    chmod 0640 /usr/lib/systemd/system/simplestatefulfirewall.timer
    chmod 0750 /usr/bin/simplestatefulfirewall.sh
    systemctl daemon-reload
}

function install_settingstosysctl {
    yes | sudo cp -rf sysctl.conf /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf
    interfaces=(`sudo  sysctl -a | grep accept_redirects | awk 'BEGIN{FS="."} {print $4}'`)

    for i in "${interfaces[@]}"; do
	sudo sysctl -w net.ipv4.conf."${i}".forwarding=0
	sudo sysctl -w net.ipv6.conf."${i}".forwarding=0
	sudo sysctl -w net.ipv4.conf."${i}".rp_filter=1
	sudo sysctl -w net.ipv4.conf."${i}".accept_redirects=0
	sudo sysctl -w net.ipv4.conf."${i}".secure_redirects=0
	sudo sysctl -w net.ipv4.conf."${i}".send_redirects=0
	sudo sysctl -w net.ipv4.conf."${i}".accept_source_route=0
	sudo sysctl -w net.ipv6.conf."${i}".accept_redirects=0
	sudo sysctl -w net.ipv6.conf."${i}".accept_source_route=0
	sudo sysctl -w net.ipv4.conf."${i}".bootp_relay=0
	sudo sysctl -w net.ipv4.conf."${i}".proxy_arp=0
	sudo sysctl -w net.ipv4.conf."${i}".arp_ignore=1
        sudo sysctl -w net.ipv4.conf."${i}".arp_announce=2
	sudo sysctl -w net.ipv4.conf."${i}".log_martians=1
	sudo sysctl -w net.ipv6.conf."${i}".autoconf=0
        sudo sysctl -w net.ipv6.conf."${i}".accept_ra=0
	sudo sysctl -w net.ipv6.conf."${i}".use_tempaddr=2
	sudo sysctl -w net.ipv6.conf."${i}".rpl_seg_enabled=0
	sudo sysctl -w net.ipv6.conf."${i}".disable_ipv6=1
    done
}

function install_dispatcher_scripts {
    mkdir -p /etc/systemd/system/NetworkManager-dispatcher.service.d/
    yes | sudo cp -rf remain_after_exit.conf /etc/systemd/system/NetworkManager-dispatcher.service.d/remain_after_exit.conf
    yes | sudo cp -rf 30-restart-firewall.sh /etc/NetworkManager/dispatcher.d/30-restart-firewall.sh 
    chown root:root /etc/systemd/system/NetworkManager-dispatcher.service.d/remain_after_exit.conf
    chown root:root /etc/NetworkManager/dispatcher.d/30-restart-firewall.sh 
    chmod 0750 /etc/NetworkManager/dispatcher.d/30-restart-firewall.sh
    chmod 0640 /etc/systemd/system/NetworkManager-dispatcher.service.d/remain_after_exit.conf
    systemctl daemon-reload
}

install_dispatcher_scripts

install_settingstosysctl

install_simplestatefulfirewall
