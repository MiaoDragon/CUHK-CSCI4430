server=$1
client=$2

iptables -t filter -F
iptables -A INPUT -p udp -s $client -d $server -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p udp -s $server -d $client -j NFQUEUE --queue-num 0

