#!/usr/bin/env bash

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

# https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html#PROTOCOLSTXT
# https://wiki.archlinux.org/title/simple_stateful_firewall

iptables -N TCP
iptables -N UDP
iptables -N LOG
iptables -N LOG_AND_DROP
iptables -N LOG_AND_REJECT
iptables -N bad_tcp_packets
# iptables -N DCCP
# iptables -N SCTP

iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP

iptables -A LOG_AND_DROP -j LOG --log-prefix "iptables deny: " --log-level 7
iptables -A LOG_AND_DROP -j DROP
iptables -A LOG_AND_REJECT -j LOG --log-prefix "iptables reject: " --log-level 7
iptables -A LOG_AND_REJECT -j REJECT --reject-with icmp-proto-unreachable

# From rc.DMZ.firewall - DMZ IP Firewall script for Linux 2.4.x and iptables
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
# bad_tcp_packets chain
iptables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG \
--log-prefix "New not syn:"
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG_AND_DROP
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
iptables -A INPUT -p tcp -j bad_tcp_packets
iptables -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachabl
iptables -A INPUT -p dccp -j LOG_AND_DROP
iptables -A INPUT -p sctp -j LOG_AND_DROP
iptables -A OUTPUT -p dccp -j LOG_AND_DROP
iptables -A OUTPUT -p sctp -j LOG_AND_DROP
iptables -A OUTPUT -p tcp -j bad_tcp_packets
iptables -A OUTPUT -p udp --dport 67 -j LOG_AND_DROP
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
ip6tables -N LOG
ip6tables -N LOG_AND_DROP
ip6tables -N LOG_AND_REJECT
ip6tables -N bad_tcp_packets
# ip6tables -N DCCP
# ip6tables -N SCTP

ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -P INPUT DROP

ip6tables -A LOG_AND_DROP -j LOG --log-prefix "ip6tables deny: " --log-level 7
ip6tables -A LOG_AND_DROP -j DROP
ip6tables -A LOG_AND_REJECT -j LOG --log-prefix "ip6tables reject: " --log-level 7
ip6tables -A LOG_AND_REJECT -j REJECT --reject-with icmp6-adm-prohibited

# From rc.DMZ.firewall - DMZ IP Firewall script for Linux 2.4.x and iptables
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
# bad_tcp_packets chain
ip6tables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
ip6tables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG \
--log-prefix "New not syn:"
ip6tables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j ACCEPT
# ip6tables -A INPUT -s fe80::/10 -p ipv6-icmp -j ACCEPT
# ip6tables -A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
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
ip6tables -A OUTPUT -p udp --dport 547 -j LOG_AND_DROP
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

iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT

iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t mangle -P INPUT ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -t mangle-P FORWARD ACCEPT


ip6tables -t nat -P PREROUTING ACCEPT
ip6tables -t nat -P POSTROUTING ACCEPT
ip6tables -t nat -P OUTPUT ACCEPT

ip6tables -t mangle -P PREROUTING ACCEPT
ip6tables -t mangle -P POSTROUTING ACCEPT
ip6tables -t mangle -P INPUT ACCEPT
ip6tables -t mangle -P OUTPUT ACCEPT
ip6tables -t mangle -P FORWARD ACCEPT
