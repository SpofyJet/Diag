#!/bin/bash
# retrans-deep — исследование TCP retransmits на VPN forwarder.
# Безопасно: read-only, кроме одного опционального ss-фильтра.
# Запуск: sudo bash retrans-deep.sh > /tmp/retrans-$(hostname).txt 2>&1
#
# Цель: понять источник retrans 4.83%
# Гипотезы которые проверяем:
#   1. Где теряются пакеты — на TX (от ноды клиенту) или RX (от destination к ноде)
#   2. BBR ли это / тип congestion control
#   3. Конкретные сокеты с высоким retrans (хвост распределения)
#   4. Хостовый pacing через fq
#   5. TCP timestamps / SACK / DSACK
#   6. Backlog drops источник

set +e

H() { echo ""; echo "═══ $1 ═══"; }
SH() { echo ""; echo "  ─── $1 ───"; }

# Найти главный интерфейс
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')

H "META"
echo "host=$(hostname) ts=$(date -Iseconds) iface=$IFACE"
echo "ram=$(free -m|awk '/^Mem:/{print $2}')MB cpu=$(nproc)"

# =====================================================================
# 1. RETRANS RATE — несколько окон для исключения burst-эффекта
# =====================================================================

H "RETRANS RATE — multi-window sampling"

for win in 10 30 60; do
    A_OUT=$(awk '/^Tcp:/{getline; print $12}' /proc/net/snmp)
    A_RTX=$(awk '/^Tcp:/{getline; print $13}' /proc/net/snmp)
    sleep $win
    B_OUT=$(awk '/^Tcp:/{getline; print $12}' /proc/net/snmp)
    B_RTX=$(awk '/^Tcp:/{getline; print $13}' /proc/net/snmp)
    DOUT=$((B_OUT - A_OUT))
    DRTX=$((B_RTX - A_RTX))
    if [ "$DOUT" -gt 0 ]; then
        RATE=$(awk -v r=$DRTX -v o=$DOUT 'BEGIN{printf "%.3f", r*100/o}')
        echo "  window=${win}s  OutSegs Δ=$DOUT  Retrans Δ=$DRTX  rate=${RATE}%"
    fi
done

SH "InSegs vs OutSegs (TX-heavy or balanced?)"
A_IN=$(awk '/^Tcp:/{getline; print $11}' /proc/net/snmp)
A_OUT=$(awk '/^Tcp:/{getline; print $12}' /proc/net/snmp)
sleep 30
B_IN=$(awk '/^Tcp:/{getline; print $11}' /proc/net/snmp)
B_OUT=$(awk '/^Tcp:/{getline; print $12}' /proc/net/snmp)
DIN=$((B_IN - A_IN))
DOUT=$((B_OUT - A_OUT))
echo "  InSegs Δ=$DIN  OutSegs Δ=$DOUT  ratio=$(awk -v i=$DIN -v o=$DOUT 'BEGIN{if(i>0)printf "%.2f", o/i; else print "?"}')"
echo "  (если ratio >> 1 — TX-heavy = download-через-ноду; ratio < 1 = upload)"

# =====================================================================
# 2. TCPEXT — детальная разбивка retrans по типам
# =====================================================================

H "TCPEXT BREAKDOWN — какой именно тип retrans"

awk '/^TcpExt:/{header=$0; getline; n=split(header,h," "); for(i=1;i<=NF;i++) printf "%-35s %s\n", h[i], $i}' /proc/net/netstat | \
    grep -E '(Retrans|TCPLost|Spurious|FastRetrans|Reordering|Timeout|Slow|Sack|DSACK|TCPBacklog|TCPDeferAccept|TCPReqQFull|TCPRcvCollapsed|TCPRcvQDrop|TCPMemoryPressures|TCPRetransFail|TCPSynRetrans)'

SH "Live rates per 30s"
declare -A A_VALS B_VALS
for k in TCPSlowStartRetrans TCPLostRetransmit TCPSpuriousRtxHostQueues TCPTimeouts TCPSackRecovery TCPFastRetrans TCPRetransFail TCPSynRetrans TCPBacklogDrop TCPRcvQDrop; do
    v=$(awk -v key=$k '/^TcpExt:/{header=$0; getline; n=split(header,h," "); for(i=1;i<=n;i++) if(h[i]==key) print $i}' /proc/net/netstat)
    A_VALS[$k]=${v:-0}
done

sleep 30

for k in TCPSlowStartRetrans TCPLostRetransmit TCPSpuriousRtxHostQueues TCPTimeouts TCPSackRecovery TCPFastRetrans TCPRetransFail TCPSynRetrans TCPBacklogDrop TCPRcvQDrop; do
    v=$(awk -v key=$k '/^TcpExt:/{header=$0; getline; n=split(header,h," "); for(i=1;i<=n;i++) if(h[i]==key) print $i}' /proc/net/netstat)
    B_VALS[$k]=${v:-0}
    delta=$(( ${B_VALS[$k]} - ${A_VALS[$k]} ))
    if [ "$delta" -gt 0 ]; then
        printf "  %-30s +%d / 30s\n" "$k" "$delta"
    fi
done

echo ""
echo "  Интерпретация:"
echo "    TCPFastRetrans = классические duplicate ACK → real loss"
echo "    TCPLostRetransmit = retrans который сам потерялся → bad path"
echo "    TCPTimeouts = RTO triggered → серьёзный loss или stall"
echo "    TCPSpuriousRtxHostQueues = host-queue буферизация (qdisc/ring)"
echo "    TCPSackRecovery = SACK-based loss detection (BBR любит это)"
echo "    TCPBacklogDrop = listen-socket overflow (app не успевает accept)"
echo "    TCPSlowStartRetrans = retrans в slow-start (новые коннекты)"

# =====================================================================
# 3. PER-SOCKET RETRANS — хвост распределения
# =====================================================================

H "PER-SOCKET RETRANS (top 30 сокетов с retrans)"

SH "Listening sockets summary"
ss -tn state listening 2>/dev/null | head -20

SH "Established TCP sockets с retrans > 0 (top 30)"
ss -tin state established 2>/dev/null | awk '
/^ESTAB/ {
    line=$0
    getline next_line
    if (next_line ~ /retrans:/) {
        # Извлекаем retrans count: "retrans:0/12" → 12
        match(next_line, /retrans:[0-9]+\/[0-9]+/)
        if (RSTART > 0) {
            rtx_str = substr(next_line, RSTART, RLENGTH)
            split(rtx_str, parts, "/")
            rtx = parts[2]
            if (rtx+0 > 0) print rtx, line
        }
    }
}' | sort -rn | head -30

SH "Распределение retrans count по сокетам"
ss -tin state established 2>/dev/null | grep -oE 'retrans:[0-9]+/[0-9]+' | awk -F/ '{print $2}' | awk '
{
    if ($1 == 0) bucket["0"]++
    else if ($1 < 5) bucket["1-4"]++
    else if ($1 < 20) bucket["5-19"]++
    else if ($1 < 100) bucket["20-99"]++
    else if ($1 < 1000) bucket["100-999"]++
    else bucket["1000+"]++
    total++
}
END {
    print "  Total sockets: " total
    for (b in bucket) printf "  retrans=%-10s %d sockets (%.1f%%)\n", b, bucket[b], bucket[b]*100/total
}'

# =====================================================================
# 4. CONGESTION CONTROL — какой реально используется на сокетах
# =====================================================================

H "CONGESTION CONTROL"

SH "Settings"
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_available_congestion_control net.core.default_qdisc 2>/dev/null

SH "Live sockets — CC distribution"
ss -tin state established 2>/dev/null | grep -oE ' (bbr|cubic|reno|vegas|westwood|htcp|hybla|illinois|dctcp|cdg) ' | sort | uniq -c | sort -rn

SH "BBR-specific stats (если BBR — должны быть bw/rtt поля)"
ss -tin state established 2>/dev/null | grep -A1 'ESTAB' | grep -oE 'bbr:\([^)]+\)' | head -5
echo "(если пусто — BBR не активен на сокетах или ss слишком старый)"

# =====================================================================
# 5. QDISC / FQ PACING
# =====================================================================

H "QDISC PACING"

SH "Current qdisc"
tc -s qdisc show dev $IFACE 2>/dev/null

SH "FQ class stats (если fq)"
tc -s class show dev $IFACE 2>/dev/null | head -30

SH "QDISC dropped per minute (60s window)"
A_DROP=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'dropped [0-9]+' | head -1 | awk '{print $2}')
A_DROP=${A_DROP:-0}
A_OVER=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'overlimits [0-9]+' | head -1 | awk '{print $2}')
A_OVER=${A_OVER:-0}
A_REQ=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'requeues [0-9]+' | head -1 | awk '{print $2}')
A_REQ=${A_REQ:-0}
sleep 60
B_DROP=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'dropped [0-9]+' | head -1 | awk '{print $2}')
B_DROP=${B_DROP:-0}
B_OVER=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'overlimits [0-9]+' | head -1 | awk '{print $2}')
B_OVER=${B_OVER:-0}
B_REQ=$(tc -s qdisc show dev $IFACE 2>/dev/null | grep -oE 'requeues [0-9]+' | head -1 | awk '{print $2}')
B_REQ=${B_REQ:-0}
echo "  dropped Δ=$((B_DROP - A_DROP)) / 60s"
echo "  overlimits Δ=$((B_OVER - A_OVER)) / 60s"
echo "  requeues Δ=$((B_REQ - A_REQ)) / 60s"

# =====================================================================
# 6. NIC RING BUFFER PRESSURE
# =====================================================================

H "NIC RING / DRIVER PRESSURE"

SH "Ring buffer config"
ethtool -g $IFACE 2>/dev/null

SH "ethtool -S detailed (60s window)"
ethtool -S $IFACE 2>/dev/null > /tmp/.ethtool-a-$$
sleep 60
ethtool -S $IFACE 2>/dev/null > /tmp/.ethtool-b-$$
awk 'NR==FNR {a[$1]=$2; next} {if ($2+0 > a[$1] && a[$1] != "") printf "  %-40s +%d / 60s\n", $1, $2-a[$1]}' /tmp/.ethtool-a-$$ /tmp/.ethtool-b-$$ | grep -iE 'drop|err|miss|over|stall|underrun|full|backlog' | head -20
rm -f /tmp/.ethtool-a-$$ /tmp/.ethtool-b-$$

# =====================================================================
# 7. CPU SOFTIRQ DETAIL (если NAPI не успевает — drops в drivers)
# =====================================================================

H "SOFTIRQ DEEP"
SH "ksoftirqd активность (если >0 — softirq не помещается)"
ps -eo pid,pcpu,comm 2>/dev/null | grep ksoftirqd

SH "/proc/softirqs delta 60s"
cp /proc/softirqs /tmp/.si-a-$$
sleep 60
cp /proc/softirqs /tmp/.si-b-$$
awk 'NR==FNR {if(NR>1) {key=$1; vals[key]=$0} next}
NR>FNR {if(FNR>1) {
    key=$1
    if (key in vals) {
        split(vals[key], a, " ")
        sum=0; for(i=2;i<=NF;i++) sum += ($i - a[i])
        if (sum > 0) printf "  %-15s Δ_total=%d / 60s\n", key, sum
    }
}}' /tmp/.si-a-$$ /tmp/.si-b-$$ | grep -E 'NET_RX|NET_TX|TIMER|TASKLET'
rm -f /tmp/.si-a-$$ /tmp/.si-b-$$

# =====================================================================
# 8. NETSTAT NUMBERS — TCP listen / sync
# =====================================================================

H "TCP STATE COUNTS"

SH "Live state distribution"
ss -tan 2>/dev/null | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn

SH "Listen queue drops (если есть — accept-queue overflow)"
ss -tlnH 2>/dev/null | awk '{print "  port="$4, "recvq="$2, "sendq="$3}' | head -10

# =====================================================================
# 9. NETWORK PATH ASYMMETRY
# =====================================================================

H "NETWORK PATH — asymmetric routing check"

SH "Route to remote — несколько целей"
for dst in 1.1.1.1 8.8.8.8 9.9.9.9; do
    R=$(ip route get $dst 2>/dev/null | head -1)
    echo "  $dst → $R"
done

SH "MTU on default iface"
ip link show $IFACE | grep -oE 'mtu [0-9]+'

SH "ARP table size (proxy/multipath signal)"
ip neigh 2>/dev/null | wc -l

# =====================================================================
# 10. APP-SIDE — Xray детально
# =====================================================================

H "XRAY APP-SIDE"

REMNA_CID=$(docker ps --filter 'name=remna' --format '{{.ID}}' 2>/dev/null | head -1)
if [ -n "$REMNA_CID" ]; then
    REMNA_PID=$(docker inspect --format '{{.State.Pid}}' $REMNA_CID 2>/dev/null)
    echo "  container=$REMNA_CID pid=$REMNA_PID"
    
    SH "Threads top by CPU (1 sec sample) — есть ли single-thread bottleneck?"
    top -H -p $REMNA_PID -b -n 1 -d 1 2>/dev/null | awk 'NR>7 && $9 != "" {print "  tid="$1, "cpu="$9"%", "cmd="$NF}' | head -15
    
    SH "Аккуратнее — top без warm-up может быть mislead. Делаем второй замер через 5s"
    sleep 5
    top -H -p $REMNA_PID -b -n 1 -d 1 2>/dev/null | awk 'NR>7 && $9 != "" {print "  tid="$1, "cpu="$9"%", "cmd="$NF}' | head -15
    
    SH "Number of listening sockets / per-port"
    ss -tlnp 2>/dev/null | awk -v pid=$REMNA_PID '$0 ~ "pid="pid {print "  "$0}' | head -10
    
    SH "Accept queue depth для Xray listening"
    ss -tlnH 2>/dev/null | awk '{print "  port="$4, "current_backlog="$2, "max_backlog="$3}'
else
    echo "(remna container not found)"
fi

# =====================================================================
# 11. TCP TIMESTAMP / SACK
# =====================================================================

H "TCP FEATURES"
sysctl net.ipv4.tcp_timestamps net.ipv4.tcp_sack net.ipv4.tcp_dsack net.ipv4.tcp_fack net.ipv4.tcp_early_retrans net.ipv4.tcp_frto net.ipv4.tcp_recovery net.ipv4.tcp_mtu_probing net.ipv4.tcp_window_scaling 2>/dev/null

# =====================================================================
# DONE
# =====================================================================

H "DONE"
echo "$(date -Iseconds) host=$(hostname)"
echo "Total runtime ~5 minutes"
echo ""
echo "Главные вопросы которые этот скрипт отвечает:"
echo "  1. Retrans rate стабилен или плавает (3 окна 10/30/60s)"
echo "  2. Это download (server→client) или upload (client→server) трафик"
echo "  3. Какой ТИП retrans доминирует (FastRetrans=loss, Timeouts=stall, SlowStart=new conns)"
echo "  4. Сосредоточены retrans на нескольких сокетах или равномерны"
echo "  5. BBR реально активен или скрытно cubic"
echo "  6. Qdisc/ring buffer overflow — TX side"
echo "  7. Xray single-thread bottleneck (одна tid на 100%)"
echo "  8. Accept queue overflow источник TCPBacklogDrop"
