#!/bin/bash
# VPN node DEEP diagnostic v2 — закрываем оставшиеся вопросы после v1.
# Безопасно: ничего не меняет, только читает state.
# Запуск: sudo bash diag-v2.sh > /tmp/diag2-$(hostname).txt 2>&1
#
# Focus:
#   - TCP retrans источник (BBR, pacing, qdisc drops)
#   - UDP status ПОСЛЕ udp-fix (проверка что 0 ошибок устойчив)
#   - Ring buffer pressure (что virtio упирается в потолок)
#   - Хост-уровень: memory pressure, swap, dirty pages
#   - Xray process detail
#   - DNS resolution latency
#   - Route MTU/PMTU
#   - nft hot-path counters

set +e

H() { echo ""; echo "═══ $1 ═══"; }
SH() { echo ""; echo "  ─── $1 ───"; }

H "META"
echo "diag-v2 host=$(hostname) ts=$(date -Iseconds)"
echo "ram=$(free -m|awk '/^Mem:/{print $2}')MB cpu=$(nproc) kernel=$(uname -r)"
echo "uptime=$(uptime -p) loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
echo "iface=$IFACE driver=$(ethtool -i $IFACE 2>/dev/null | awk '/^driver:/{print $2}')"

# =====================================================================
# 1. UDP STATUS (verification что fix держится)
# =====================================================================

H "UDP STATUS (после udp-fix)"
awk '/^Udp:/{header=$0; getline; print "Headers:", header; print "Values: ", $0}' /proc/net/snmp
SH "Live delta over 30s"
A_IN=$(awk '/^Udp:/{getline; print $2}' /proc/net/snmp)
A_INE=$(awk '/^Udp:/{getline; print $3}' /proc/net/snmp)
A_RCV=$(awk '/^Udp:/{getline; print $5}' /proc/net/snmp)
A_SND=$(awk '/^Udp:/{getline; print $6}' /proc/net/snmp)
A_MEM=$(awk '/^Udp:/{getline; print $9}' /proc/net/snmp)
sleep 30
B_IN=$(awk '/^Udp:/{getline; print $2}' /proc/net/snmp)
B_INE=$(awk '/^Udp:/{getline; print $3}' /proc/net/snmp)
B_RCV=$(awk '/^Udp:/{getline; print $5}' /proc/net/snmp)
B_SND=$(awk '/^Udp:/{getline; print $6}' /proc/net/snmp)
B_MEM=$(awk '/^Udp:/{getline; print $9}' /proc/net/snmp)
echo "InDatagrams Δ=$((B_IN - A_IN)) per 30s"
echo "InErrors    Δ=$((B_INE - A_INE)) per 30s"
echo "RcvbufErr   Δ=$((B_RCV - A_RCV)) per 30s"
echo "SndbufErr   Δ=$((B_SND - A_SND)) per 30s"
echo "MemErrors   Δ=$((B_MEM - A_MEM)) per 30s"

SH "UDP socket buffer usage (top 10 — actual vs limits)"
ss -uan 2>/dev/null | awk 'NR>1 {print $3,$4}' | sort -rn | head -10
echo "(format: RecvQ SendQ)"

# =====================================================================
# 2. TCP DETAILS (источник 3.6% retrans)
# =====================================================================

H "TCP DETAILS (retrans investigation)"

SH "Global counters"
awk '/^Tcp:/{header=$0; getline; print "Headers:", header; print "Values: ", $0}' /proc/net/snmp
SH "TcpExt extended"
awk '/^TcpExt:/{header=$0; getline; for(i=1;i<=NF;i++) {split(header,h," "); printf "%-30s %s\n", h[i], $i}}' /proc/net/netstat | grep -E '(Retrans|Lost|Spurious|FastRetrans|Reordering|TimeoutRehash|Backlog|Renege|Rcv|TCPOFOQueue|TCPPureAcks|DSACK|TCPSackRecovery|TCPSlowStartRetrans|TCPTimeouts|TCPDeferAcceptDrop|TCPReqQFullDrop)'

SH "Retrans rate live (30s window)"
A_OUT=$(awk '/^Tcp:/{getline; print $12}' /proc/net/snmp)
A_RTX=$(awk '/^Tcp:/{getline; print $13}' /proc/net/snmp)
sleep 30
B_OUT=$(awk '/^Tcp:/{getline; print $12}' /proc/net/snmp)
B_RTX=$(awk '/^Tcp:/{getline; print $13}' /proc/net/snmp)
DOUT=$((B_OUT - A_OUT))
DRTX=$((B_RTX - A_RTX))
if [ "$DOUT" -gt 0 ]; then
    echo "OutSegs Δ=$DOUT  RetransSegs Δ=$DRTX  ratio=$(awk -v r=$DRTX -v o=$DOUT 'BEGIN{printf "%.2f%%", r*100/o}')"
else
    echo "OutSegs Δ=$DOUT  RetransSegs Δ=$DRTX (low traffic)"
fi

SH "BBR pacing diagnostic"
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_available_congestion_control 2>/dev/null
SH "Sockets with BBR vs other CC (top 10 by retrans)"
ss -tin state established 2>/dev/null | grep -oE 'bbr|cubic|reno|vegas' | sort | uniq -c | sort -rn | head -5

SH "Active TCP с большим recv-Q / send-Q (потенциально hung)"
ss -tan state established 2>/dev/null | awk 'NR>1 && ($2>10000 || $3>10000) {print $0}' | head -10

# =====================================================================
# 3. NIC / RING BUFFER PRESSURE
# =====================================================================

H "NIC PRESSURE"

SH "Ring buffer status"
ethtool -g $IFACE 2>/dev/null

SH "NIC statistics extended (virtio-net)"
ethtool -S $IFACE 2>/dev/null | grep -E '(drop|err|missed|over|stall|underrun|backlog|queue_full|rx_packets|tx_packets|rx_bytes|tx_bytes|rx_dropped|tx_dropped)' | head -40

SH "/proc/net/dev"
grep "$IFACE:" /proc/net/dev | awk '{print "RX:", "bytes="$2, "pkts="$3, "errs="$4, "drop="$5, "fifo="$6, "frame="$7; print "TX:", "bytes="$10, "pkts="$11, "errs="$12, "drop="$13, "fifo="$14, "colls="$15}'

SH "Interface drops live (30s)"
A_RX_DROP=$(awk -v if="$IFACE" '$1 ~ if":" {print $5; exit}' /proc/net/dev)
A_TX_DROP=$(awk -v if="$IFACE" '$1 ~ if":" {print $13; exit}' /proc/net/dev)
sleep 30
B_RX_DROP=$(awk -v if="$IFACE" '$1 ~ if":" {print $5; exit}' /proc/net/dev)
B_TX_DROP=$(awk -v if="$IFACE" '$1 ~ if":" {print $13; exit}' /proc/net/dev)
echo "rx_drop Δ=$((B_RX_DROP - A_RX_DROP))  tx_drop Δ=$((B_TX_DROP - A_TX_DROP))"

# =====================================================================
# 4. QDISC DEEP
# =====================================================================

H "QDISC DEEP"
tc -s -d qdisc show dev $IFACE 2>/dev/null

SH "fq stats (BBR's beloved qdisc)"
tc -s class show dev $IFACE 2>/dev/null | head -20

SH "qdisc drops live (30s)"
A_DROP=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'dropped [0-9]+' | awk '{print $2}' | head -1)
A_DROP=${A_DROP:-0}
sleep 30
B_DROP=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'dropped [0-9]+' | awk '{print $2}' | head -1)
B_DROP=${B_DROP:-0}
echo "qdisc dropped Δ=$((B_DROP - A_DROP)) per 30s"

# =====================================================================
# 5. PER-CPU SOFTIRQ ПОДРОБНО
# =====================================================================

H "PER-CPU SOFTIRQ DETAIL"
SH "mpstat per-CPU 10s × 3 samples"
mpstat -P ALL 10 3 2>/dev/null | awk '/^[0-9]/ {printf "%s CPU%-3s soft=%6.2f%% sys=%6.2f%% idle=%6.2f%%\n", $1, $3, $(NF-2), $5, $(NF)}' 2>/dev/null

SH "/proc/softirqs (по типам)"
awk 'NR==1 {print; next} /NET_RX|NET_TX|TIMER|TASKLET|SCHED/ {print}' /proc/softirqs | head -10

SH "ksoftirqd процессы (если >0% — softirq не помещается в interrupt context)"
ps -eo pid,pcpu,comm 2>/dev/null | grep -E 'ksoftirqd' | awk '$2 > 0.5 {print}'

# =====================================================================
# 6. MEMORY / PAGE PRESSURE
# =====================================================================

H "MEMORY DETAIL"

SH "Memory snapshot"
free -h
SH "Memory pressure (PSI)"
cat /proc/pressure/memory 2>/dev/null
cat /proc/pressure/io 2>/dev/null
cat /proc/pressure/cpu 2>/dev/null

SH "Swap usage"
swapon --show 2>/dev/null
grep -E '^(SwapTotal|SwapFree|SwapCached|Dirty|Writeback|Slab|SReclaimable|PageTables)' /proc/meminfo

SH "OOM / kill events за 24h"
journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -ciE 'out of memory|oom-killer|killed process|invoked oom-killer'

# =====================================================================
# 7. XRAY / REMNANODE PROCESS DETAIL
# =====================================================================

H "REMNANODE / XRAY DETAIL"

REMNA_CID=$(docker ps --filter 'name=remna' --format '{{.ID}}' 2>/dev/null | head -1)
if [ -n "$REMNA_CID" ]; then
    echo "container=$REMNA_CID"
    REMNA_PID=$(docker inspect --format '{{.State.Pid}}' $REMNA_CID 2>/dev/null)
    echo "main_pid=$REMNA_PID"

    SH "Container resource usage"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" $REMNA_CID 2>/dev/null

    SH "Все процессы внутри контейнера (CPU/MEM)"
    if [ -n "$REMNA_PID" ] && [ "$REMNA_PID" != "0" ]; then
        ps -L -p $REMNA_PID -o pid,tid,pcpu,pmem,comm 2>/dev/null | head -20
        echo "---"
        # threads count
        echo "threads=$(ps -L -p $REMNA_PID 2>/dev/null | wc -l)"
        # fd count
        echo "open_fds=$(ls /proc/$REMNA_PID/fd 2>/dev/null | wc -l)"
        # limits
        cat /proc/$REMNA_PID/limits 2>/dev/null | grep -E 'open files|processes|locked|memory' | head -5
    fi

    SH "Xray socket распределение"
    if [ -n "$REMNA_PID" ]; then
        SOCKS=$(ls -la /proc/$REMNA_PID/fd 2>/dev/null | grep -c socket)
        echo "total_sockets=$SOCKS"
        # listening
        ss -tlnp 2>/dev/null | grep -E "pid=$REMNA_PID|pid=[0-9]+.*xray" | head -10
    fi
else
    echo "(remnanode container not found)"
fi

SH "Xray-related процессы на хосте"
ps -eo pid,pcpu,pmem,rss,comm --sort=-pcpu 2>/dev/null | grep -iE 'xray|hysteria|sing-box|rw-core|remna' | head -10

# =====================================================================
# 8. NFT HOT-PATH COUNTERS
# =====================================================================

H "NFT HOT-PATH"

SH "Counter rates (15s sample)"
nft list table inet ddos_protect 2>/dev/null | awk '
/^[[:space:]]+counter / {name=$2}
name && /packets/ {gsub(/[^0-9]/,"",$2); pkts[name]=$2; name=""}
END {for (n in pkts) print n"|"pkts[n]}
' > /tmp/.nft-a-$$

sleep 15

nft list table inet ddos_protect 2>/dev/null | awk '
/^[[:space:]]+counter / {name=$2}
name && /packets/ {gsub(/[^0-9]/,"",$2); pkts[name]=$2; name=""}
END {for (n in pkts) print n"|"pkts[n]}
' > /tmp/.nft-b-$$

awk -F'|' 'NR==FNR {a[$1]=$2; next} {d=$2-a[$1]; if (d>0) printf "  %-35s +%d pkts/15s\n", $1, d}' /tmp/.nft-a-$$ /tmp/.nft-b-$$ | sort -k2 -rn | head -15
rm -f /tmp/.nft-a-$$ /tmp/.nft-b-$$

SH "Sets sizes"
for s in scanner_blocklist_v4 threat_blocklist_v4 custom_blocklist_v4 tor_exit_blocklist_v4 confirmed_attack_v4 suspect_v4 manual_whitelist_v4 infrastructure_v4 protected_ports_tcp protected_ports_udp; do
    SIZE=$(nft list set inet ddos_protect $s 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    PORTS=$(nft list set inet ddos_protect $s 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+(-[0-9]+)?' | wc -l)
    [ "$SIZE" -gt 0 ] && printf "  %-25s %d entries\n" "$s" "$SIZE" || \
        ([ "$PORTS" -gt 0 ] && [ "$s" = "protected_ports_tcp" -o "$s" = "protected_ports_udp" ] && printf "  %-25s %d entries\n" "$s" "$PORTS")
done

SH "CrowdSec bouncer set size"
if nft list table ip crowdsec >/dev/null 2>&1; then
    nft list table ip crowdsec 2>/dev/null | grep -E 'elements = |elements=' | wc -l
    echo "bouncer chains:"
    nft list table ip crowdsec 2>/dev/null | grep -E '^[[:space:]]+chain' | awk '{print "    "$2}'
fi

# =====================================================================
# 9. CONNTRACK DETAIL
# =====================================================================

H "CONNTRACK DETAIL"

SH "Counters"
echo "count=$(cat /proc/sys/net/netfilter/nf_conntrack_count) max=$(cat /proc/sys/net/netfilter/nf_conntrack_max) hashsize=$(cat /sys/module/nf_conntrack/parameters/hashsize)"

SH "Distribution by state (top types)"
if command -v conntrack >/dev/null 2>&1; then
    conntrack -L 2>/dev/null | awk '{
        for(i=1;i<=NF;i++) {
            if ($i ~ /^(ESTABLISHED|TIME_WAIT|CLOSE_WAIT|FIN_WAIT|SYN_SENT|SYN_RECV|UNREPLIED|ASSURED)$/) states[$i]++
            if ($i == "udp" || $i == "tcp" || $i == "icmp") protos[$i]++
        }
    } END {
        print "Protocols:"; for (p in protos) print "  "p"="protos[p]
        print "States:"; for (s in states) print "  "s"="states[s]
    }'
else
    echo "(conntrack tool не установлен — apt install conntrack)"
fi

SH "Top source IPs (CGNAT detection)"
if command -v conntrack >/dev/null 2>&1; then
    conntrack -L 2>/dev/null | grep -oE 'src=[^ ]+' | sort | uniq -c | sort -rn | head -10
fi

SH "Drop counters"
awk '{drop+=$4; ifail+=$6; early+=$8; search+=$2; found+=$3; new+=$5} END{print "search_total="search" found="found" new="new" drop="drop" insert_failed="ifail" early_drop="early}' /proc/net/stat/nf_conntrack 2>/dev/null

# =====================================================================
# 10. DNS LATENCY (resolver на хосте)
# =====================================================================

H "DNS LATENCY"
SH "Current resolver"
cat /etc/resolv.conf 2>/dev/null | grep -E '^nameserver|^search|^options' | head -10

SH "Resolve test (5 popular domains)"
for d in cloudflare.com google.com youtube.com instagram.com telegram.org; do
    if command -v dig >/dev/null 2>&1; then
        T=$(dig +tries=1 +timeout=2 +stats $d 2>/dev/null | grep -oE 'Query time: [0-9]+' | awk '{print $3}')
        echo "  $d: ${T:-timeout} ms"
    else
        T=$( (time -p getent ahosts $d) 2>&1 | grep real | awk '{print $2}')
        echo "  $d: ${T:-timeout} sec (getent)"
    fi
done

# =====================================================================
# 11. ROUTE / MTU
# =====================================================================

H "ROUTE / MTU"
SH "Default route"
ip -4 route show default
SH "MTU on iface"
ip -4 link show dev $IFACE | grep -oE 'mtu [0-9]+'
SH "MTU on key destinations (PMTU)"
for h in 1.1.1.1 8.8.8.8 connectivitycheck.gstatic.com; do
    R=$(ip route get $h 2>/dev/null | head -1)
    M=$(echo "$R" | grep -oE 'mtu [0-9]+' || echo "default")
    echo "  $h: $R | $M"
done

# =====================================================================
# 12. SYSTEM-WIDE CHECKS
# =====================================================================

H "SYSTEMS"

SH "Top processes by CPU"
ps -eo pid,pcpu,pmem,rss,comm --sort=-pcpu 2>/dev/null | head -10

SH "Top processes by memory"
ps -eo pid,pcpu,pmem,rss,comm --sort=-rss 2>/dev/null | head -10

SH "I/O wait & disk activity"
iostat 5 2 2>/dev/null | tail -20 || echo "(iostat не установлен — apt install sysstat)"

SH "Disk usage"
df -h / /var /var/log 2>/dev/null | grep -v tmpfs

SH "Дата запуска RemnaNode container"
if [ -n "$REMNA_CID" ]; then
    docker inspect --format '{{.State.StartedAt}} (status: {{.State.Status}})' $REMNA_CID 2>/dev/null
fi

# =====================================================================
# 13. SYSCTL VERIFY (после udp-fix)
# =====================================================================

H "SYSCTL FINAL STATE"
sysctl -a 2>/dev/null | grep -E '^net\.(core|ipv4)\.(rmem_|wmem_|udp_|tcp_(adv_win_scale|congestion_control|notsent_lowat|rmem|wmem|fastopen|synack_retries|syn_retries))' | sort
echo "---"
sysctl -a 2>/dev/null | grep -E '^net\.(netfilter\.nf_conntrack_|ipv4\.conf\.all\.(rp_filter|log_martians))' | sort

H "DONE"
echo "$(date -Iseconds) host=$(hostname)"
echo "Total runtime: ~3 minutes (samples + delta windows)"
