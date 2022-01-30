#!/usr/bin/env bash
# Klimenko Maxim Sergievich 2022
# https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html#PROTOCOLSTXT
# https://github.com/ukanth/afwall/wiki/CustomScripts#droidwall-only-examples
# https://wiki.archlinux.org/title/simple_stateful_firewall
# https://ipgeolocation.io/resources/bogon.html

iptables -F
iptables -t nat -F
iptables -t mangle -F
#
# erase all chains that's not default in filter and nat table.
#
iptables -X
iptables -t nat -X
iptables -t mangle -X

ip6tables -F
ip6tables -t nat -F
ip6tables -t mangle -F
#
# erase all chains that's not default in filter and nat table.
#
ip6tables -X
ip6tables -t nat -X
ip6tables -t mangle -X

#
# AAAA
#

iptables -N TCP
iptables -N UDP
# iptables -N IN_SSH # Uncomment if you need ssh connection to machine
iptables -N LOG_AND_DROP
iptables -N LOG_AND_REJECT
iptables -N bad_tcp_packets

iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP

iptables -A LOG_AND_DROP -j LOG --log-prefix "iptables deny: " --log-level 7
iptables -A LOG_AND_DROP -j DROP
iptables -A LOG_AND_REJECT -j LOG --log-prefix "iptables reject: " --log-level 7
iptables -A LOG_AND_REJECT -j REJECT --reject-with icmp-proto-unreachable

# Ip lists
iptables -A INPUT -s 0.0.0.0/8 -j LOG_AND_DROP
iptables -A OUTPUT -s 0.0.0.0/8 -j LOG_AND_DROP
iptables -A INPUT -s 10.0.0.0/8 -j LOG_AND_DROP
iptables -A OUTPUT -s 10.0.0.0/8 -j LOG_AND_DROP
iptables -A INPUT -s 100.64.0.0/10 -j LOG_AND_DROP
iptables -A OUTPUT -s 100.64.0.0/10 -j LOG_AND_DROP
# iptables -A INPUT -s 127.0.0.1/8 -j LOG_AND_DROP
# iptables -A OUTPUT -s 127.0.0.1/8 -j LOG_AND_DROP
iptables -A INPUT -s 127.0.53.53 -j LOG_AND_DROP
iptables -A OUTPUT -s 127.0.53.53 -j LOG_AND_DROP
iptables -A INPUT -s 169.254.0.0/16 -j LOG_AND_DROP
iptables -A OUTPUT -s 169.254.0.0/16 -j LOG_AND_DROP

# iptables -A INPUT -s 172.16.0.0/12 -j LOG_AND_DROP
# iptables -A OUTPUT -s 172.16.0.0/12 -j LOG_AND_DROP
iptables -A INPUT -s 192.0.0.0/24 -j LOG_AND_DROP
iptables -A OUTPUT -s 192.0.0.0/24 -j LOG_AND_DROP
iptables -A INPUT -s 192.0.2.0/24 -j LOG_AND_DROP
iptables -A OUTPUT -s 192.0.2.0/24 -j LOG_AND_DROP
# iptables -A INPUT -s 192.168.0.0/16 -j LOG_AND_DROP
# iptables -A OUTPUT -s 192.168.0.0/16 -j LOG_AND_DROP

iptables -A INPUT -s 198.18.0.0/15 -j LOG_AND_DROP
iptables -A OUTPUT -s 198.18.0.0/15 -j LOG_AND_DROP
iptables -A INPUT -s 198.51.100.0/24 -j LOG_AND_DROP
iptables -A OUTPUT -s 198.51.100.0/24 -j LOG_AND_DROP
iptables -A INPUT -s 203.0.113.0/24 -j LOG_AND_DROP
iptables -A OUTPUT -s 203.0.113.0/24 -j LOG_AND_DROP
iptables -A INPUT -s 224.0.0.0/4 -j LOG_AND_DROP
iptables -A OUTPUT -s 224.0.0.0/4 -j LOG_AND_DROP
iptables -A INPUT -s 240.0.0.0/4 -j LOG_AND_DROP
iptables -A OUTPUT -s 240.0.0.0/4 -j LOG_AND_DROP
iptables -A INPUT -s 255.255.255.255/32 -j LOG_AND_DROP
iptables -A OUTPUT -s 255.255.255.255/32 -j LOG_AND_DROP

# From rc.DMZ.firewall - DMZ IP Firewall script for Linux 2.4.x and iptables
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
# bad_tcp_packets chain
iptables -A bad_tcp_packets -p tcp -m length --length 20 -j LOG \
--log-prefix "Empty packets: "
iptables -A bad_tcp_packets -p tcp -m length --length 20 -j DROP
iptables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG \
--log-prefix "New not syn: "
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type address-mask-request -j LOG_AND_DROP
iptables -A INPUT -p icmp --icmp-type timestamp-request -j LOG_AND_DROP
iptables -A INPUT -p icmp --icmp-type router-solicitation -j LOG_AND_DROP
iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
# SSH  # Uncomment if you need ssh connection to machine 
# iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j IN_SSH
# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 3 --seconds 10 -j LOG_AND_DROP
# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 4 --seconds 1800 -j LOG_AND_DROP 
# iptables -A IN_SSH -m recent --name sshbf --set -j ACCEPT
iptables -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j LOG_AND_DROP
iptables -A INPUT -f -j LOG_AND_DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG_AND_DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG_AND_DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG_AND_DROP
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
iptables -A INPUT -p tcp -j bad_tcp_packets
iptables -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -p dccp -j LOG_AND_DROP
iptables -A INPUT -p sctp -j LOG_AND_DROP
iptables -A OUTPUT -p dccp -j LOG_AND_DROP
iptables -A OUTPUT -p sctp -j LOG_AND_DROP
iptables -A OUTPUT -f -j LOG_AND_DROP
iptables -A OUTPUT -p tcp -j bad_tcp_packets
iptables -A OUTPUT -p udp --dport 67 -j LOG_AND_DROP

# iptables -A OUTPUT -p tcp --dport 80 -j LOG_AND_DROP
iptables -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level DEBUG --log-prefix "IPT OUTPUT packet died: "
# iptables -A INPUT -m set --match-set bogons src -j LOG_AND_DROP
# 224.0.0.1
# iptables -A OUTPUT -m set --match-set bogons src -j LOG_AND_DROP
# iptables -A OUTPUT -j opensnitch-filter-OUTPUT
# iptables -A OUTPUT -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass
# iptables -A opensnitch-filter-OUTPUT -p icmp -j ACCEPT

iptables -t raw -I PREROUTING -m rpfilter --invert -j DROP
iptables -A INPUT -j LOG_AND_REJECT

########## Ipv6

ip6tables -N TCP
ip6tables -N UDP
ip6tables -N LOG_AND_DROP
ip6tables -N LOG_AND_REJECT
ip6tables -N bad_tcp_packets

ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -P INPUT DROP

ip6tables -A LOG_AND_DROP -j LOG --log-prefix "ip6tables deny: " --log-level 7
ip6tables -A LOG_AND_DROP -j DROP
ip6tables -A LOG_AND_REJECT -j LOG --log-prefix "ip6tables reject: " --log-level 7
ip6tables -A LOG_AND_REJECT -j REJECT --reject-with icmp6-adm-prohibited

# Ip lists
ip6tables -A INPUT -s ::/128 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::/128 -j LOG_AND_DROP
ip6tables -A INPUT -s ::1/128 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::1/128 -j LOG_AND_DROP
ip6tables -A INPUT -s ::ffff:0:0/96 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::ffff:0:0/96 -j LOG_AND_DROP
ip6tables -A INPUT -s ::/96 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::/96 -j LOG_AND_DROP
ip6tables -A INPUT -s 100::/64 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 100::/64 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:10::/28 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:10::/28 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:db8::/32 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:db8::/32 -j LOG_AND_DROP
ip6tables -A INPUT -s fc00::/7 -j LOG_AND_DROP
ip6tables -A OUTPUT -s fc00::/7	-j LOG_AND_DROP
ip6tables -A INPUT -s fe80::/10 -j LOG_AND_DROP
ip6tables -A OUTPUT -s fe80::/10 -j LOG_AND_DROP
ip6tables -A INPUT -s fec0::/10	-j LOG_AND_DROP
ip6tables -A OUTPUT -s fec0::/10 -j LOG_AND_DROP
ip6tables -A INPUT -s ff00::/8 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ff00::/8 -j LOG_AND_DROP

ip6tables -A INPUT -s 2002::/24 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002::/24 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:a00::/24 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:a00::/24 -j LOG_AND_DROP
# ip6tables -A INPUT -s 2002:7f00::/24 -j LOG_AND_DROP
# ip6tables -A OUTPUT -s 2002:7f00::/24 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:a9fe::/24 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:a9fe::/24 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:ac10::/28 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:ac10::/28 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:c000::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:c000::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:c000:200::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:c000:200::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:c0a8::/32 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:c0a8::/32 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:c612::/31 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:c612::/31 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:c633:6400::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:c633:6400::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:cb00:7100::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:cb00:7100::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:e000::/20 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:e000::/20 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:f000::/20 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:f000::/20 -j LOG_AND_DROP
ip6tables -A INPUT -s 2002:ffff:ffff::/48 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2002:ffff:ffff::/48 -j LOG_AND_DROP

ip6tables -A INPUT -s 2001::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:a00::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:a00::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:7f00::/40 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:7f00::/40 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:c000::/56 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:c000::/56 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:ac10::/44 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:ac10::/44 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:a9fe::/48 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:a9fe::/48 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:c000:200::/56 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:c000:200::/56 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:c0a8::/48 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:c0a8::/48 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:c612::/47 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:c612::/47 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:c633:6400::/56 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:c633:6400::/56 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:cb00:7100::/56 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:cb00:7100::/56 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:e000::/36 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:e000::/36 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:f000::/36 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:f000::/36 -j LOG_AND_DROP
ip6tables -A INPUT -s 2001:0:ffff:ffff::/64 -j LOG_AND_DROP
ip6tables -A OUTPUT -s 2001:0:ffff:ffff::/64 -j LOG_AND_DROP

# From rc.DMZ.firewall - DMZ IP Firewall script for Linux 2.4.x and iptables
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
# bad_tcp_packets chain
ip6tables -A bad_tcp_packets -p tcp -m length --length 20 -j LOG \
--log-prefix "Empty packets: "
ip6tables -A bad_tcp_packets -p tcp -m length --length 20 -j DROP
ip6tables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
ip6tables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG \
--log-prefix "New not syn: "
ip6tables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j LOG_AND_DROP
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type packet-too-big -j LOG_AND_DROP
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type time-exceeded -j LOG_AND_DROP
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type parameter-problem -j LOG_AND_DROP
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j ACCEPT
# ip6tables -A INPUT -s fe80::/10 -p ipv6-icmp -j ACCEPT
# ip6tables -A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
ip6tables -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j LOG_AND_DROP
ip6tables -A INPUT -m ipv6header --header frag --soft -j LOG_AND_DROP
ip6tables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG_AND_DROP
ip6tables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG_AND_DROP
ip6tables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate INVALID -j LOG_AND_DROP
ip6tables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
ip6tables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
ip6tables -A INPUT -p tcp -j bad_tcp_packets
ip6tables -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
ip6tables -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp6-adm-prohibited
ip6tables -A INPUT -p dccp -j LOG_AND_DROP
ip6tables -A INPUT -p sctp -j LOG_AND_DROP
ip6tables -A OUTPUT -p dccp -j LOG_AND_DROP
ip6tables -A OUTPUT -p sctp -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp -j bad_tcp_packets
ip6tables -A OUTPUT -m ipv6header --header frag --soft -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --dport 547 -j LOG_AND_DROP
# ip6tables -A OUTPUT -p tcp --dport 80 -j LOG_AND_DROP
ip6tables -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level DEBUG --log-prefix "IPT OUTPUT packet died: "

# ip6tables -A INPUT -m set --match-set bogonsv6 src -j LOG_AND_DROP
# ip6tables -A OUTPUT -m set --match-set bogonsv6 src -j LOG_AND_DROP
# 224.0.0.1
# ip6tables -A OUTPUT -j opensnitch-filter-OUTPUT
# ip6tables -A OUTPUT -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass
# ip6tables -A opensnitch-filter-OUTPUT -p icmp -j ACCEPT

ip6tables -t raw -I PREROUTING -m rpfilter --invert -j DROP
ip6tables -A INPUT -j LOG_AND_REJECT


##################
# NAT and Mangle #
##################

# iptables -t nat -P PREROUTING ACCEPT
# iptables -t nat -P POSTROUTING ACCEPT
# iptables -t nat -P OUTPUT ACCEPT

# iptables -t mangle -P PREROUTING ACCEPT
# iptables -t mangle -P POSTROUTING ACCEPT
# iptables -t mangle -P INPUT ACCEPT
# iptables -t mangle -P OUTPUT ACCEPT
# iptables -t mangle -P FORWARD ACCEPT


# ip6tables -t nat -P PREROUTING ACCEPT
# ip6tables -t nat -P POSTROUTING ACCEPT
# ip6tables -t nat -P OUTPUT ACCEPT

# ip6tables -t mangle -P PREROUTING ACCEPT
# ip6tables -t mangle -P POSTROUTING ACCEPT
# ip6tables -t mangle -P INPUT ACCEPT
# ip6tables -t mangle -P OUTPUT ACCEPT
# ip6tables -t mangle -P FORWARD ACCEPT

#################

iptables-save > /etc/iptables/iptables.rules
ip6tables-save > /etc/iptables/ip6tables.rules

systemctl enable iptables
systemctl start iptables
systemctl restart iptables

systemctl enable ip6tables
systemctl start ip6tables
systemctl restart ip6tables
