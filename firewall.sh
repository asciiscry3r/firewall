#!/usr/bin/env bash
# Klimenko Maxim Sergievich 2022
# https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html#PROTOCOLSTXT
# https://github.com/ukanth/afwall/wiki/CustomScripts#droidwall-only-examples
# https://wiki.archlinux.org/title/simple_stateful_firewall
# https://ipgeolocation.io/resources/bogon.html

iptables -F
iptables -t raw -F
iptables -t nat -F
iptables -t mangle -F

#
# erase all chains that's not default in filter and nat table.
#

iptables -X
iptables -t raw -X
iptables -t nat -X
iptables -t mangle -X

ip6tables -F
ip6tables -t raw -F
ip6tables -t nat -F
ip6tables -t mangle -F

#
# erase all chains that's not default in filter and nat table.
#

ip6tables -X
ip6tables -t raw -X
ip6tables -t nat -X
ip6tables -t mangle -X

#
# ARP
#

ip -s neighbour flush all
# arptables --flush
# arptables -A INPUT --source-mac ${yourmac1} -j ACCEPT
# arptables -A INPUT --source-mac ${yourmac2} -j ACCEPT

######################################################################
########## Ipv4 ######################################################

iptables -N TCP
iptables -N UDP
iptables -N LOG_AND_DROP
iptables -N LOG_AND_REJECT
iptables -N bad_tcp_packets
iptables -N icmp_packets

iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP

iptables -A LOG_AND_DROP -j LOG --log-prefix "Iptables: v4Deny: " --log-level 7
iptables -A LOG_AND_DROP -j DROP
iptables -A LOG_AND_REJECT -j LOG --log-prefix "Iptables: v4Reject: " --log-level 7
iptables -A LOG_AND_REJECT -j REJECT --reject-with icmp-proto-unreachable


# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 3 --seconds 10 -j LOG_AND_REJECT
# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 4 --seconds 1800 -j LOG_AND_REJECT
# iptables -A IN_SSH -m recent --name sshbf --set -j ACCEPT


# Comment this and rerun script for get access to most networks provided by vpn services
# 10.0.0.0/8

BLOCKLIST="0.0.0.0/8,100.64.0.0/10,127.0.53.53,169.254.0.0/16,192.0.0.0/24,192.0.2.0/24,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,240.0.0.0/4,255.255.255.255/32,35.190.56.182/32,52.73.169.169"


# From rc.DMZ.firewall - DMZ IP Firewall script for Linux 2.4.x and iptables
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
# bad_tcp_packets chain
iptables -A bad_tcp_packets -p tcp -m limit -m length --length 20 -j LOG \
--log-prefix "Iptables: Empty packets: "
iptables -A bad_tcp_packets -p tcp -m length --length 20 -j DROP
iptables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
iptables -A bad_tcp_packets -p tcp  -m limit ! --syn -m state --state NEW -j LOG \
--log-prefix "Iptables: Drop new not syn: "
iptables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

iptables -A INPUT -m addrtype --dst-type BROADCAST -j LOG_AND_DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -s 127.0.0.1 -j ACCEPT
iptables -A icmp_packets -p icmp -s 0/0 --icmp-type 8 -j ACCEPT
iptables -A icmp_packets -p icmp -s 0/0 --icmp-type 11 -j ACCEPT
iptables -A icmp_packets -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP
# iptables -A INPUT -p icmp -j DROP
# iptables -A INPUT ! -p tcp -j DROP
# iptables -A INPUT ! -p udp -j DROP
# iptables -A INPUT -s ${BLOCKLIST} -j LOG_AND_REJECT
# SSH  # Uncomment if you need ssh connection to machine 
# iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j IN_SSH
# TBD MORE EXPLOITS ##################################################
iptables -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j LOG_AND_REJECT
iptables -A INPUT -m string --algo bm --hex-string '|FF FF FF FF FF FF|' -j LOG_AND_REJECT
iptables -A INPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_REJECT
iptables -A INPUT -m string --algo bm --hex-string '|72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00|' -j LOG_AND_REJECT
iptables -A INPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_REJECT
iptables -A INPUT -m u32 --u32 "8&0xFFF=0x4d5a" -j LOG_AND_REJECT
# FF
iptables -A INPUT -p tcp \
  -m connbytes --connbytes 0:1024 \
    --connbytes-dir both --connbytes-mode bytes \
  -m state --state ESTABLISHED \
  -m u32 --u32 "0>>22&0x3C@ 12>>26&0x3C@ 0=0x52464220" \
  -m string --algo kmp --string "RFB 003." --to 130 \
  -j REJECT --reject-with tcp-reset
# ####################################################################
iptables -A INPUT -f -j LOG_AND_REJECT
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG_AND_REJECT
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG_AND_REJECT
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG_AND_REJECT
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
iptables -A INPUT -p tcp -j bad_tcp_packets
iptables -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -p dccp -j LOG_AND_REJECT
iptables -A INPUT -p sctp -j LOG_AND_REJECT
iptables -A INPUT -p udp --match multiport --sport 1:21 -j LOG_AND_REJECT
iptables -A INPUT -p udp --match multiport --dport 1:50 -j LOG_AND_REJECT
iptables -A INPUT -p tcp --match multiport --sport 1:21 -j LOG_AND_REJECT
iptables -A INPUT -p tcp --match multiport --dport 1:50 -j LOG_AND_REJECT
iptables -A INPUT -p udp --dport 664 -j LOG_AND_REJECT
iptables -A INPUT -p tcp --sport 664 -j LOG_AND_REJECT
iptables -A INPUT -p udp --match multiport --sport 16992:16996 -j LOG_AND_REJECT
iptables -A INPUT -p udp --match multiport --dport 16992:16996 -j LOG_AND_REJECT
iptables -A INPUT -p tcp --match multiport --sport 16992:16996 -j LOG_AND_REJECT
iptables -A INPUT -p tcp --match multiport --dport 16992:16996 -j LOG_AND_REJECT
iptables -A INPUT -s ${BLOCKLIST} -j LOG_AND_REJECT
# Possible ME comm and other strange staf used by piracy and hackers #
iptables -A INPUT -i lo -s 127.0.0.0/8 -p ICMP -m limit -j LOG_AND_DROP
iptables -A INPUT -i lo -s 127.0.0.0/8 -m limit -p UDP --sport 53 -j LOG_AND_DROP
iptables -A INPUT -i lo -s 127.0.0.0/8 -m limit -p TCP --sport 53 -j LOG_AND_DROP
iptables -A INPUT -i lo -s 127.0.0.0/8 -p ICMP -j DROP
iptables -A INPUT -i lo -s 127.0.0.0/8 -p UDP --sport 53 -j DROP
iptables -A INPUT -i lo -s 127.0.0.0/8 -p TCP --sport 53 -j DROP
# TBD MORE EXPLOITS ##################################################
iptables -A OUTPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j LOG_AND_DROP
iptables -A OUTPUT -m string --algo bm --hex-string '|FF FF FF FF FF FF|' -j LOG_AND_DROP
iptables -A OUTPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_DROP
iptables -A OUTPUT -m string --algo bm --hex-string '|72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00|' -j LOG_AND_DROP
iptables -A OUTPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_DROP
iptables -A OUTPUT -m u32 --u32 "8&0xFFF=0x4d5a" -j LOG_AND_DROP
# ####################################################################
iptables -A OUTPUT -s ${BLOCKLIST} -j LOG_AND_DROP
iptables -A OUTPUT -p dccp -j LOG_AND_DROP
iptables -A OUTPUT -p sctp -j LOG_AND_DROP
iptables -A OUTPUT -f -j LOG_AND_DROP
iptables -A OUTPUT -p tcp -j bad_tcp_packets
# iptables -A FORWARD -f -j LOG_AND_DROP
# iptables -A FORWARD -p tcp -j bad_tcp_packets
# iptables -A OUTPUT -p udp --dport 68 -j LOG_AND_DROP
iptables -A OUTPUT -p tcp --match multiport --dport 1:21 -j LOG_AND_DROP
iptables -A OUTPUT -p tcp --match multiport --sport 1:50 -j LOG_AND_DROP
iptables -A OUTPUT -p udp --match multiport --dport 1:21 -j LOG_AND_DROP
iptables -A OUTPUT -p udp --match multiport --sport 1:50 -j LOG_AND_DROP
iptables -A OUTPUT -p udp --dport 664 -j LOG_AND_REJECT
iptables -A OUTPUT -p tcp --sport 664 -j LOG_AND_REJECT
iptables -A OUTPUT -p udp --match multiport --sport 16992:16996 -j LOG_AND_DROP
iptables -A OUTPUT -p udp --match multiport --dport 16992:16996 -j LOG_AND_DROP
iptables -A OUTPUT -p tcp --match multiport --sport 16992:16996 -j LOG_AND_DROP
iptables -A OUTPUT -p tcp --match multiport --dport 16992:16996 -j LOG_AND_DROP
# Torrents ##############################################################
iptables -A OUTPUT -p tcp --dport 6881:6889 -j LOG_AND_DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j LOG_AND_DROP
iptables -A OUTPUT -p udp --dport 1646 -j LOG_AND_DROP
iptables -A OUTPUT -m string --algo bm --string “BitTorrent” -j LOG_AND_DROP
# Possible ME comm and other strange staf used by piracy and hackers #
iptables -A OUTPUT -s 127.0.0.0/8 -p ICMP -m limit -j LOG_AND_DROP
iptables -A OUTPUT -s 127.0.0.0/8 -p UDP -m limit --sport 53 -j LOG_AND_DROP
iptables -A OUTPUT -s 127.0.0.0/8 -p TCP -m limit --sport 53 -j LOG_AND_DROP
iptables -A OUTPUT -s 127.0.0.0/8 -p ICMP -j DROP
iptables -A OUTPUT -s 127.0.0.0/8 -p UDP --sport 53 -j DROP
iptables -A OUTPUT -s 127.0.0.0/8 -p TCP --sport 53 -j DROP
iptables -A OUTPUT -m addrtype --dst-type BROADCAST -j LOG_AND_DROP
# ####################################################################
iptables -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level DEBUG --log-prefix "Iptables: IPT OUTPUT packet died: "
# iptables -A OUTPUT ! -p icmp -j DROP
# iptables -A OUTPUT ! -p tcp -j DROP
# iptables -A OUTPUT ! -p udp -j DROP

iptables -t raw -A PREROUTING -m rpfilter --invert -j DROP
iptables -A INPUT -j LOG_AND_REJECT

######################################################################
########## Ipv6 ######################################################

ip6tables -N TCP
ip6tables -N UDP
ip6tables -N LOG_AND_DROP
ip6tables -N LOG_AND_REJECT
ip6tables -N bad_tcp_packets
ip6tables -N icmp_packets

ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -P INPUT DROP

ip6tables -A LOG_AND_DROP -j LOG --log-prefix "Iptables: v6Deny: " --log-level 7
ip6tables -A LOG_AND_DROP -j DROP
ip6tables -A LOG_AND_REJECT -j LOG --log-prefix "Iptables: v6Reject: " --log-level 7
ip6tables -A LOG_AND_REJECT -j REJECT --reject-with icmp6-adm-prohibited

V6BLOCKLIST="ff00::/8,::/128,::1/128,::ffff:0:0/96,::/96,100::/64,2001:10::/28,2001:10::/28,2001:db8::/32,fc00::/7,fe80::/10,fec0::/10,2600:1901:0:8813::/128,2002::/24,2002:a00::/24,2002:a00::/24,2002:a9fe::/24,2002:ac10::/28,2002:c000::/40,2002:c000:200::/40,2002:c0a8::/32,2002:c612::/31,2002:c633:6400::/40,2002:cb00:7100::/40,2002:e000::/20,2002:f000::/20,2002:ffff:ffff::/48,2001::/40,2001:0:a00::/40,2001:0:7f00::/40,2001:0:c000::/56,2001:0:ac10::/44,2001:0:a9fe::/48,2001:0:c000:200::/56,2001:0:c0a8::/48,2001:0:c612::/47,2001:0:c633:6400::/56,2001:0:cb00:7100::/56,2001:0:e000::/36,2001:0:f000::/36"


# From rc.DMZ.firewall - DMZ IP Firewall script for Linux 2.4.x and iptables
# Copyright (C) 2001  Oskar Andreasson <bluefluxATkoffeinDOTnet>
# bad_tcp_packets chain
ip6tables -A bad_tcp_packets -p tcp  -m limit -m length --length 20 -j LOG \
--log-prefix "Iptables: Empty packets: "
ip6tables -A bad_tcp_packets -p tcp -m length --length 20 -j DROP
ip6tables -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
ip6tables -A bad_tcp_packets -p tcp  -m limit ! --syn -m state --state NEW -j LOG \
--log-prefix "Iptables: Drop new not syn: "
ip6tables -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -i lo -s ::1 -j ACCEPT
ip6tables -A icmp_packets -p ipv6-icmp -s 0/0 --icmpv6-type 8 -j ACCEPT
ip6tables -A icmp_packets -p ipv6-icmp -s 0/0 --icmpv6-type 11 -j ACCEPT
ip6tables -A icmp_packets -p ipv6-icmp --icmpv6-type echo-request -m length --length 86:0xffff -j DROP
# ip6tables -A INPUT -p icmp -j DROP
# ip6tables -A INPUT ! -p tcp -j DROP
# ip6tables -A INPUT ! -p udp -j DROP
# ip6tables -A INPUT -s fe80::/10 -p ipv6-icmp -j ACCEPT
# ip6tables -A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
# TBD MORE EXPLOITS ######################################################
ip6tables -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j LOG_AND_REJECT
ip6tables -A INPUT -m string --algo bm --hex-string '|FF FF FF FF FF FF|' -j LOG_AND_REJECT
ip6tables -A INPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_REJECT
ip6tables -A INPUT -m string --algo bm --hex-string '|72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00|' -j LOG_AND_REJECT
ip6tables -A INPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_REJECT
ip6tables -A INPUT -m u32 --u32 "8&0xFFF=0x4d5a" -j LOG_AND_DROP
# FF
ip6tables -A INPUT -p tcp \
  -m connbytes --connbytes 0:1024 \
    --connbytes-dir both --connbytes-mode bytes \
  -m state --state ESTABLISHED \
  -m u32 --u32 "0>>22&0x3C@ 12>>26&0x3C@ 0=0x52464220" \
  -m string --algo kmp --string "RFB 003." --to 130 \
  -j REJECT --reject-with tcp-reset
# ########################################################################
ip6tables -A INPUT -m ipv6header --header frag --soft -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate INVALID -j LOG_AND_REJECT
ip6tables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
ip6tables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
ip6tables -A INPUT -p tcp -j bad_tcp_packets
ip6tables -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
ip6tables -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp6-adm-prohibited
ip6tables -A INPUT -p dccp -j LOG_AND_REJECT
ip6tables -A INPUT -p sctp -j LOG_AND_REJECT
ip6tables -A INPUT -p udp --match multiport --sport 1:50 -j LOG_AND_REJECT
ip6tables -A INPUT -p udp --match multiport --dport 1:50 -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --match multiport --sport 1:50 -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --match multiport --dport 1:50 -j LOG_AND_REJECT
ip6tables -A INPUT -s ${V6BLOCKLIST} -j LOG_AND_REJECT
# Possible ME comm and other strange staf used by piracy and hackers #####
ip6tables -A INPUT -i lo -s ::1/32 -p ICMP -m limit -j LOG_AND_DROP
ip6tables -A INPUT -i lo -s ::1/32 -p UDP -m limit --sport 53 -j LOG_AND_DROP
ip6tables -A INPUT -i lo -s ::1/32 -p TCP -m limit --sport 53 -j LOG_AND_DROP
ip6tables -A INPUT -i lo -s ::1/32 -p ICMP -j DROP
ip6tables -A INPUT -i lo -s ::1/32 -p UDP --sport 53 -j DROP
ip6tables -A INPUT -i lo -s ::1/32 -p TCP --sport 53 -j DROP
# ########################################################################
ip6tables -A INPUT -p udp --sport 664 -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --sport 664 -j LOG_AND_REJECT
ip6tables -A INPUT -p udp --match multiport --sport 16992:16996 -j LOG_AND_REJECT
ip6tables -A INPUT -p udp --match multiport --dport 16992:16996 -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --match multiport --sport 16992:16996 -j LOG_AND_REJECT
ip6tables -A INPUT -p tcp --match multiport --dport 16992:16996 -j LOG_AND_REJECT
# TBD MORE EXPLOITS ######################################################
ip6tables -A OUTPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j LOG_AND_DROP
ip6tables -A OUTPUT -m string --algo bm --hex-string '|FF FF FF FF FF FF|' -j LOG_AND_DROP
ip6tables -A OUTPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_DROP
ip6tables -A OUTPUT -m string --algo bm --hex-string '|72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00|' -j LOG_AND_DROP
ip6tables -A OUTPUT -m string --algo bm --hex-string '|D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04|' -j LOG_AND_DROP
ip6tables -A OUTPUT -m u32 --u32 "8&0xFFF=0x4d5a" -j LOG_AND_DROP
# ########################################################################
ip6tables -A OUTPUT -s ${V6BLOCKLIST} -j LOG_AND_DROP
ip6tables -A OUTPUT -p dccp -j LOG_AND_DROP
ip6tables -A OUTPUT -p sctp -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp -j bad_tcp_packets
ip6tables -A OUTPUT -m ipv6header --header frag --soft -j LOG_AND_DROP
# ip6tables -A FORWARD -p tcp -j bad_tcp_packets
# ip6tables -A FORWARD -m ipv6header --header frag --soft -j LOG_AND_DROP
# ip6tables -A OUTPUT -p udp --dport 547 -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp --match multiport --dport 1:50 -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp --match multiport --sport 1:50 -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --match multiport --dport 1:50 -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --match multiport --sport 1:50 -j LOG_AND_DROP
# #######################################################################
ip6tables -A OUTPUT -p udp --sport 664 -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp --sport 664 -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --match multiport --sport 16992:16996 -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --match multiport --dport 16992:16996 -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp --match multiport --sport 16992:16996 -j LOG_AND_DROP
ip6tables -A OUTPUT -p tcp --match multiport --dport 16992:16996 -j LOG_AND_DROP
# Torrents ##############################################################
ip6tables -A OUTPUT -p tcp --dport 6881:6889 -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --dport 1024:65534 -j LOG_AND_DROP
ip6tables -A OUTPUT -p udp --dport 1646 -j LOG_AND_DROP
ip6tables -A OUTPUT -m string --algo bm --string “BitTorrent” -j LOG_AND_DROP
# Possible ME comm and other strange staf used by piracy and hackers ####
ip6tables -A OUTPUT -s ::1/32 -p ICMP -m limit -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::1/32 -p UDP -m limit --sport 53 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::1/32 -p TCP -m limit --sport 53 -j LOG_AND_DROP
ip6tables -A OUTPUT -s ::1/32 -p ICMP -j DROP
ip6tables -A OUTPUT -s ::1/32 -p UDP --sport 53 -j DROP
ip6tables -A OUTPUT -s ::1/32 -p TCP --sport 53 -j DROP
# #######################################################################
ip6tables -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG --log-level DEBUG --log-prefix "Iptables: IPT OUTPUT packet died: "

ip6tables -t raw -A PREROUTING -m rpfilter --invert -j DROP
ip6tables -A INPUT -j LOG_AND_REJECT

#########################################################################################
# IPV4 NAT and Mangle ###################################################################
#########################################################################################

# The "nat" table is not intended for filtering, the use of DROP is therefore inhibited.
# iptables -t nat -P PREROUTING ACCEPT
# iptables -t nat -P POSTROUTING ACCEPT
# iptables -t nat -P OUTPUT ACCEPT

# iptables -t mangle -P PREROUTING ACCEPT
# iptables -t mangle -P POSTROUTING ACCEPT
# iptables -t mangle -P INPUT ACCEPT
# iptables -t mangle -P OUTPUT ACCEPT
# iptables -t mangle -P FORWARD ACCEPT

########################################################################################

iptables -t mangle -A PREROUTING -m rpfilter -j ACCEPT
iptables -t mangle -A PREROUTING -j DROP
iptables -t mangle -A FORWARD -m addrtype --dst-type BROADCAST -j DROP
iptables -t mangle -A OUTPUT -s 127.0.0.0/8 -j DROP
iptables -t mangle -A FORWARD -s 127.0.0.0/8 -j DROP
iptables -t mangle -A OUTPUT -f -j DROP
iptables -t mangle -A FORWARD -f -j DROP
iptables -t mangle -A OUTPUT -p tcp --match multiport --dport 1:21 -j DROP
iptables -t mangle -A OUTPUT -p tcp --match multiport --sport 1:50 -j DROP
iptables -t mangle -A OUTPUT -p udp --match multiport --dport 1:21 -j DROP
iptables -t mangle -A OUTPUT -p udp --match multiport --sport 1:50 -j DROP
iptables -t mangle -A OUTPUT -p udp --sport 664 -j DROP
iptables -t mangle -A OUTPUT -p tcp --sport 664 -j DROP
iptables -t mangle -A OUTPUT -p udp --match multiport --sport 16992:16996 -j DROP
iptables -t mangle -A OUTPUT -p udp --match multiport --dport 16992:16996 -j DROP
iptables -t mangle -A OUTPUT -p tcp --match multiport --sport 16992:16996 -j DROP
iptables -t mangle -A OUTPUT -p tcp --match multiport --dport 16992:16996 -j DROP
iptables -t mangle -A FORWARD -p tcp --match multiport --dport 1:50 -j DROP
iptables -t mangle -A FORWARD -p tcp --match multiport --sport 1:50 -j DROP
iptables -t mangle -A FORWARD -p udp --match multiport --dport 1:50 -j DROP
iptables -t mangle -A FORWARD -p udp --match multiport --sport 1:50 -j DROP
iptables -t mangle -A FORWARD -p udp --sport 664 -j DROP
iptables -t mangle -A FORWARD -p tcp --sport 664 -j DROP
iptables -t mangle -A FORWARD -p udp --match multiport --sport 16992:16996 -j DROP
iptables -t mangle -A FORWARD -p udp --match multiport --dport 16992:16996 -j DROP
iptables -t mangle -A FORWARD -p tcp --match multiport --sport 16992:16996 -j DROP
iptables -t mangle -A FORWARD -p tcp --match multiport --dport 16992:16996 -j DROP

#########################################################################################
# IPV6 NAT and Mangle ###################################################################
#########################################################################################

# The "nat" table is not intended for filtering, the use of DROP is therefore inhibited.
# ip6tables -t nat -P PREROUTING ACCEPT
# ip6tables -t nat -P POSTROUTING ACCEPT
# ip6tables -t nat -P OUTPUT ACCEPT

# ip6tables -t mangle -P PREROUTING ACCEPT
# ip6tables -t mangle -P POSTROUTING ACCEPT
# ip6tables -t mangle -P INPUT ACCEPT
# ip6tables -t mangle -P OUTPUT ACCEPT
# ip6tables -t mangle -P FORWARD ACCEPT

########################################################################################

ip6tables -t mangle -A PREROUTING -m rpfilter -j ACCEPT
ip6tables -t mangle -A PREROUTING -j DROP
ip6tables -t mangle -A OUTPUT -s ::1/32 -j DROP
ip6tables -t mangle -A FORWARD -s ::1/32 -j DROP
ip6tables -t mangle -A OUTPUT -m ipv6header --header frag --soft -j DROP
ip6tables -t mangle -A FORWARD -m ipv6header --header frag --soft -j DROP
ip6tables -t mangle -A OUTPUT -p tcp --match multiport --dport 1:50 -j DROP
ip6tables -t mangle -A OUTPUT -p tcp --match multiport --sport 1:50 -j DROP
ip6tables -t mangle -A OUTPUT -p udp --match multiport --dport 1:50 -j DROP
ip6tables -t mangle -A OUTPUT -p udp --match multiport --sport 1:50 -j DROP
ip6tables -t mangle -A OUTPUT -p udp --sport 664 -j DROP
ip6tables -t mangle -A OUTPUT -p tcp --sport 664 -j DROP
ip6tables -t mangle -A OUTPUT -p udp --match multiport --sport 16992:16996 -j DROP
ip6tables -t mangle -A OUTPUT -p udp --match multiport --dport 16992:16996 -j DROP
ip6tables -t mangle -A OUTPUT -p tcp --match multiport --sport 16992:16996 -j DROP
ip6tables -t mangle -A OUTPUT -p tcp --match multiport --dport 16992:16996 -j DROP
ip6tables -t mangle -A FORWARD -p tcp --match multiport --dport 1:50 -j DROP
ip6tables -t mangle -A FORWARD -p tcp --match multiport --sport 1:50 -j DROP
ip6tables -t mangle -A FORWARD -p udp --match multiport --dport 1:50 -j DROP
ip6tables -t mangle -A FORWARD -p udp --match multiport --sport 1:50 -j DROP
ip6tables -t mangle -A FORWARD -p udp --sport 664 -j DROP
ip6tables -t mangle -A FORWARD -p tcp --sport 664 -j DROP
ip6tables -t mangle -A FORWARD -p udp --match multiport --sport 16992:16996 -j DROP
ip6tables -t mangle -A FORWARD -p udp --match multiport --dport 16992:16996 -j DROP
ip6tables -t mangle -A FORWARD -p tcp --match multiport --sport 16992:16996 -j DROP
ip6tables -t mangle -A FORWARD -p tcp --match multiport --dport 16992:16996 -j DROP

####################################################################################

release=`grep -e '^ID=' /etc/os-release |  cut -c 4-`

if [[ $release == 'arch' ]]; then
    iptables-save > /etc/iptables/iptables.rules
    ip6tables-save > /etc/iptables/ip6tables.rules

    systemctl enable iptables
    systemctl start iptables
    systemctl restart iptables

    systemctl enable ip6tables
    systemctl start ip6tables
    systemctl restart ip6tables

    if [ -f /usr/lib/systemd/system/opensnitchd.service ]; then
        systemctl restart opensnitchd
    fi
elif [[ $release == 'manjaro' ]]; then
    iptables-save > /etc/iptables/iptables.rules
    ip6tables-save > /etc/iptables/ip6tables.rules

    systemctl enable iptables
    systemctl start iptables
    systemctl restart iptables

    systemctl enable ip6tables
    systemctl start ip6tables
    systemctl restart ip6tables

    if [ -f /usr/lib/systemd/system/opensnitchd.service ]; then
        systemctl restart opensnitchd
    fi
elif [[ $release == 'raspbian' ]]; then
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v4

    systemctl enable netfilter-persistent
    systemctl start netfilter-persistent
    systemctl restart netfilter-persistent
elif [[ $release == 'ubuntu' ]]; then
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v4

    systemctl enable netfilter-persistent
    systemctl start netfilter-persistent
    systemctl restart netfilter-persistent
    systemctl restart opensnitch
fi
