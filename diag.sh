#!/bin/bash
# VPN node read-only diagnostic — собирает данные для локализации bottleneck'а.
# Безопасно: ничего не меняет, только читает state.
# Usage: sudo bash <(curl -fsSL <URL>)
#        или: sudo bash diag.sh > /tmp/diag-$(hostname).txt

set +e

H() { echo ""; echo "═══ $1 ═══"; }

H "NODE"
echo "host=$(hostname) ram=$(free -m|awk '/^Mem:/{print $2}')MB cpu=$(nproc) kernel=$(uname -r) uptime=$(uptime -p)"

IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
echo "iface=$IFACE driver=$(ethtool -i $IFACE 2>/dev/null | awk '/^driver:/{print $2}')"

H "NIC QUEUES (N-6: single-queue check)"
ethtool -l $IFACE 2>/dev/null | grep -E "Combined:|RX:|TX:" || echo "ethtool -l не сработал"

H "PER-CPU SOFTIRQ (N-6 confirmation — измерение 6 сек)"
mpstat -P ALL 2 3 2>/dev/null | awk '/^Average/ && $2 ~ /^[0-9]/ {printf "CPU%-3s soft=%5.1f%% sys=%5.1f%% idle=%5.1f%%\n", $2, $(NF-2), $5, $(NF)}' || \
    echo "mpstat не установлен (apt install sysstat для будущего)"

H "UDP BUFFER ERRORS (N-1: Hysteria2)"
awk '/^Udp:/{getline; printf "InDatagrams=%s NoPorts=%s InErrors=%s OutDatagrams=%s RcvbufErrors=%s SndbufErrors=%s InCsumErrors=%s IgnoredMulti=%s\n",$2,$3,$5,$4,$6,$7,$8,$9}' /proc/net/snmp

H "TCP RETRANS / OUT-OF-ORDER"
awk '/^Tcp:/{getline; printf "RetransSegs=%s InSegs=%s OutSegs=%s\n",$13,$11,$12}' /proc/net/snmp
awk '/^TcpExt:/{getline; printf "TCPLostRetransmit=%s TCPSpuriousRtxHostQueues=%s TCPBacklogDrop=%s TCPOFOQueue=%s\n",$70,$95,$87,$57}' /proc/net/netstat 2>/dev/null

H "KERNEL LOG RATE (S-1: log_martians flood)"
echo "kern.log: $(du -h /var/log/kern.log* 2>/dev/null | tr '\n' ' ')"
echo "syslog:   $(du -h /var/log/syslog* 2>/dev/null | tr '\n' ' ')"
echo "journal events last 1h: $(journalctl -k --since '1 hour ago' --no-pager 2>/dev/null | wc -l)"
echo "martian/rpfilter last 1h: $(journalctl -k --since '1 hour ago' --no-pager 2>/dev/null | grep -ciE 'martian|rpfilter')"
echo "shield drops last 1h: $(journalctl -k --since '1 hour ago' --no-pager 2>/dev/null | grep -c '\[shield:')"

H "SYSCTL (что выставлено)"
sysctl -a 2>/dev/null | grep -E '^net\.(core\.(r|w)mem_max|ipv4\.(tcp_(adv_win_scale|congestion_control|fastopen|synack_retries|syn_retries|rmem|wmem|notsent_lowat)|udp_(mem|rmem_min|wmem_min)|conf\.all\.(rp_filter|log_martians)|tcp_syncookies|ip_local_port_range))' | sort
echo "--- conntrack ---"
sysctl -a 2>/dev/null | grep -E '^net\.netfilter\.nf_conntrack_(max|udp_timeout|tcp_timeout_(established|time_wait)|generic_timeout|buckets)' | sort

H "NIC OFFLOADS (N-7 UDP-GRO, N-8 LRO)"
ethtool -k $IFACE 2>/dev/null | grep -E '^(generic-receive-offload|tcp-segmentation-offload|generic-segmentation-offload|large-receive-offload|rx-udp-gro-forwarding|rx-gro-list|rx-vlan-offload):'

H "RING BUFFERS"
ethtool -g $IFACE 2>/dev/null

H "QDISC"
tc -s qdisc show dev $IFACE 2>/dev/null | head -30

H "CONNTRACK"
COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
echo "count=$COUNT max=$MAX ratio=$(awk -v c=$COUNT -v m=$MAX 'BEGIN{if(m>0)print int(c*100/m)"%"; else print "?"}')"
echo "hashsize=$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null)"
awk '{drop+=$4; ifail+=$6; early+=$8} END{print "drop_total="drop" insert_failed="ifail" early_drop="early}' /proc/net/stat/nf_conntrack 2>/dev/null

H "NFT DROP COUNTERS (кого реально дропаем)"
nft list table inet ddos_protect 2>/dev/null | awk '
/^[[:space:]]+counter (scanner_drops|threat_drops|custom_drops|tor_drops|confirmed_drops|syn_confirmed|udp_confirmed|conn_flood|newconn_flood|tcp_invalid|ssh_conn_flood|ssh_newconn_flood|infrastructure_passes)/ {name=$2}
name && /packets/ {gsub(/[^0-9]/,"",$2); if($2+0 > 0) printf "  %-30s %s pkts\n", name, $2; name=""}
'
echo "--- active suspect/banned ---"
echo "suspect_v4: $(nft list set inet ddos_protect suspect_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l) IPs"
echo "confirmed_attack_v4: $(nft list set inet ddos_protect confirmed_attack_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l) IPs"

H "INTERFACE STATS"
ip -s -s link show dev $IFACE 2>/dev/null | tail -10

H "IRQ DISTRIBUTION"
NIC_IRQS=$(grep -E "(^|[[:space:]])${IFACE}(-|$)" /proc/interrupts 2>/dev/null | awk -F: '{gsub(/ /,"",$1); print $1}')
if [ -n "$NIC_IRQS" ]; then
    for irq in $NIC_IRQS; do
        aff=$(cat /proc/irq/$irq/smp_affinity 2>/dev/null)
        echo "  irq=$irq affinity_mask=$aff"
    done | head -10
else
    echo "(нет IRQ для $IFACE — paravirt без MSI-X)"
fi

H "ACTIVE CONNECTIONS"
echo "TCP established (Xray ports 443/8443): $(ss -tan state established '( sport = :443 or sport = :8443 )' 2>/dev/null | tail -n +2 | wc -l)"
echo "TCP established total: $(ss -tan state established 2>/dev/null | tail -n +2 | wc -l)"
echo "UDP sockets: $(ss -uan 2>/dev/null | tail -n +2 | wc -l)"
echo "load: $(cut -d' ' -f1-3 /proc/loadavg)"

H "TOP CPU PROCESSES"
ps -eo pid,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -8

H "RSYSLOG/JOURNALD CPU (S-1 confirmation)"
ps -eo pid,pcpu,comm 2>/dev/null | grep -E 'rsyslog|journal|kworker' | head -10

H "IOWAIT (S-1: disk saturation от log flood)"
vmstat 1 5 2>/dev/null | awk 'NR>2 {sum_wa+=$16; sum_id+=$15; n++} END{if(n)printf "avg_iowait=%.1f%% avg_idle=%.1f%% (%d samples)\n", sum_wa/n, sum_id/n, n}'

H "DOCKER CONTAINER LIMITS"
if command -v docker >/dev/null 2>&1; then
    REMNA_CID=$(docker ps --filter 'name=remnanode' --format '{{.ID}}' 2>/dev/null | head -1)
    [ -z "$REMNA_CID" ] && REMNA_CID=$(docker ps --format '{{.ID}} {{.Image}}' 2>/dev/null | grep -i remna | awk '{print $1}' | head -1)
    if [ -n "$REMNA_CID" ]; then
        PID=$(docker inspect --format '{{.State.Pid}}' $REMNA_CID 2>/dev/null)
        if [ -n "$PID" ] && [ "$PID" != "0" ]; then
            cat /proc/$PID/limits 2>/dev/null | grep -E 'Max open files|Max processes' | head -2
        fi
    else
        echo "(remnanode container не найден)"
    fi
    echo "dockerd: $(cat /proc/$(pgrep -x dockerd 2>/dev/null | head -1)/limits 2>/dev/null | awk '/Max open files/{print "soft="$4" hard="$5}')"
fi

H "DONE"
echo "$(date '+%Y-%m-%d %H:%M:%S %z') host=$(hostname)"
