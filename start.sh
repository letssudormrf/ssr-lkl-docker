#!/bin/sh

if [ $# -gt 0 ];
then
        while getopts "p:k:m:O:o:" arg;
                do
                        case $arg in
                                p)
                                        sed -i "3,12s/^.*\"port\":.*$/        \"port\": ${OPTARG},/" mudb.json
                                ;;
                                k)
                                        sed -i "3,12s/^.*\"passwd\":.*$/        \"passwd\": \"${OPTARG}\",/" mudb.json
                                ;;
                                m)
                                        sed -i "3,12s/^.*\"method\":.*$/        \"method\": \"${OPTARG}\",/" mudb.json
                                ;;
                                O)
                                        sed -i "3,12s/^.*\"protocol\":.*$/        \"protocol\": \"${OPTARG}\",/" mudb.json
                                ;;
                                o)
                                        sed -i "3,12s/^.*\"obfs\":.*$/        \"obfs\": \"${OPTARG}\",/" mudb.json
                                ;;
                        esac
                done
fi
cat mudb.json | awk '$1=="\"port\":" {print $NF+0}' | awk '$NF<=65535' > /root/mudb_port.txt

ip tuntap add tap0 mode tap
ip addr add 10.99.254.1/24 dev tap0
ip addr add fd90:a:b:c::1/64 dev tap0
ip link set tap0 up

iptables -P FORWARD ACCEPT
ip6tables -P FORWARD ACCEPT

iptables -t nat -A POSTROUTING -s 10.99.254.0/24 ! -d 10.99.254.0/24 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s fd90:a:b:c::/64 ! -d fd90:a:b:c::/64 -j MASQUERADE

while read line
do
	iptables -t nat -A PREROUTING -i eth0 -p tcp --dport $line -j DNAT --to-destination 10.99.254.2
	iptables -t nat -A PREROUTING -i eth0 -p udp --dport $line -j DNAT --to-destination 10.99.254.2
	ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport $line -j DNAT --to-destination fd90:a:b:c::2
	ip6tables -t nat -A PREROUTING -i eth0 -p udp --dport $line -j DNAT --to-destination fd90:a:b:c::2
done < /root/mudb_port.txt

export LD_PRELOAD="/root/liblkl-hijack.so"
export LKL_HIJACK_NET_QDISC="root|fq"
export LKL_HIJACK_SYSCTL="net.ipv4.tcp_congestion_control=bbr;net.ipv4.tcp_wmem=4096 16384 100000000"
export LKL_HIJACK_NET_IFTYPE="tap"
export LKL_HIJACK_NET_IFPARAMS="tap0"
export LKL_HIJACK_NET_IP="10.99.254.2"
export LKL_HIJACK_NET_NETMASK_LEN="24"
export LKL_HIJACK_NET_GATEWAY="10.99.254.1"
export LKL_HIJACK_NET_IPV6="fd90:a:b:c::2"
export LKL_HIJACK_NET_NETMASK6_LEN="64"
export LKL_HIJACK_NET_GATEWAY6="fd90:a:b:c::1"
export LKL_HIJACK_OFFLOAD="0x9983"

python /shadowsocksr/server.py m>> ssserver.log 2>&1
