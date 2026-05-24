#!/bin/bash
# ==============================================================================
# shieldnode-diag.sh — диагностика "лежащего" сервера после инцидента
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode-diag.sh | sudo bash
#   # или скачать и запустить
#   sudo bash shieldnode-diag.sh > /tmp/diag-$(hostname)-$(date +%F-%H%M).txt
#
# Выводит диагностику в stdout, можно перенаправить в файл или отправить хостеру.
# ==============================================================================

set -uo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: запусти с sudo (нужны права на /proc, dmesg, journalctl)" >&2
    exit 1
fi

# Colors (отключаются если не tty)
if [ -t 1 ]; then
    R='\033[31m'; G='\033[32m'; Y='\033[33m'; B='\033[34m'; C='\033[36m'; D='\033[2m'; N='\033[0m'; BOLD='\033[1m'
else
    R=''; G=''; Y=''; B=''; C=''; D=''; N=''; BOLD=''
fi

section() { echo ""; echo -e "${BOLD}${C}═══ $1 ═══${N}"; }
ok()      { echo -e "  ${G}✓${N} $1"; }
warn()    { echo -e "  ${Y}⚠${N} $1"; }
err()     { echo -e "  ${R}✗${N} $1"; }
info()    { echo -e "  ${D}·${N} $1"; }

# Итоговая оценка
VERDICT_DDOS=0
VERDICT_OOM=0
VERDICT_DISK=0
VERDICT_KERNEL=0
VERDICT_NETWORK=0

echo -e "${BOLD}shieldnode incident diagnostics${N}"
echo -e "${D}Node: $(hostname) | Time: $(date -u +%FT%TZ) | Uptime: $(uptime -p)${N}"

# === 1. UPTIME & REBOOT HISTORY ===
section "1. Uptime & Reboot history"
uptime
echo ""
echo "Последние reboot'ы:"
last -x reboot shutdown 2>/dev/null | head -6 || journalctl --list-boots 2>/dev/null | tail -5

BOOT_TIME=$(who -b 2>/dev/null | awk '{print $3, $4}')
[ -n "$BOOT_TIME" ] && info "Текущий boot: $BOOT_TIME"

# Если нода ребутилась меньше часа назад — высокий шанс что был crash
LAST_BOOT_EPOCH=$(date -d "$BOOT_TIME" +%s 2>/dev/null || echo 0)
NOW_EPOCH=$(date +%s)
if [ "$LAST_BOOT_EPOCH" -gt 0 ] && [ $((NOW_EPOCH - LAST_BOOT_EPOCH)) -lt 3600 ]; then
    warn "Boot < 1 часа назад — возможно недавний crash"
fi

# === 2. CONNTRACK OVERFLOW (главный признак DDoS) ===
section "2. Conntrack state"
CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
echo "Conntrack: $CT_COUNT / $CT_MAX"

if [ "$CT_MAX" -gt 0 ]; then
    PCT=$((CT_COUNT * 100 / CT_MAX))
    if [ "$PCT" -gt 80 ]; then
        warn "Conntrack заполнен на ${PCT}% — критичная нагрузка"
    elif [ "$PCT" -gt 50 ]; then
        info "Conntrack ${PCT}% — повышенная нагрузка"
    else
        ok "Conntrack ${PCT}% — норма"
    fi
fi

echo ""
echo "Conntrack overflow в kernel logs:"
CONNTRACK_OVERFLOW=$(dmesg -T 2>/dev/null | grep -iE "nf_conntrack.*table full|conntrack.*full" | tail -5)
if [ -n "$CONNTRACK_OVERFLOW" ]; then
    echo "$CONNTRACK_OVERFLOW"
    err "Conntrack overflow обнаружен — DDoS пробил защиту"
    VERDICT_DDOS=$((VERDICT_DDOS + 3))
else
    ok "Conntrack overflow не зафиксирован"
fi

# === 3. OOM KILLER ===
section "3. OOM killer (Out Of Memory)"
OOM_KILLS=$(dmesg -T 2>/dev/null | grep -iE "killed process|oom-killer|out of memory" | tail -10)
if [ -n "$OOM_KILLS" ]; then
    echo "$OOM_KILLS"
    err "OOM killer срабатывал!"
    VERDICT_OOM=$((VERDICT_OOM + 3))

    # Что было убито?
    KILLED=$(echo "$OOM_KILLS" | grep -oE "Killed process [0-9]+ \([^\)]+\)" | sort -u)
    [ -n "$KILLED" ] && warn "Убитые процессы: $KILLED"
else
    ok "OOM killer не срабатывал"
fi

# Memory pressure
echo ""
echo "RAM сейчас:"
free -h
SWAP_USED=$(free | awk '/Swap:/ {if($2>0) print int($3*100/$2); else print 0}')
[ "$SWAP_USED" -gt 80 ] && warn "Swap >80% — heavy memory pressure"

# === 4. KERNEL PANIC / HARDWARE ===
section "4. Kernel panic / Hardware errors"
KERNEL_ERR=$(dmesg -T 2>/dev/null | grep -iE "panic|hardware error|mce|general protection|soft lockup|hung task" | tail -10)
if [ -n "$KERNEL_ERR" ]; then
    echo "$KERNEL_ERR"
    err "Kernel/hardware ошибки обнаружены"
    VERDICT_KERNEL=$((VERDICT_KERNEL + 3))
else
    ok "Kernel/hardware ошибки не зафиксированы"
fi

# Segfaults
SEGFAULTS=$(dmesg -T 2>/dev/null | grep -iE "segfault" | tail -5)
if [ -n "$SEGFAULTS" ]; then
    warn "Сегфолты в kernel log:"
    echo "$SEGFAULTS"
fi

# === 5. DISK FULL ===
section "5. Disk usage"
df -h | grep -vE "tmpfs|udev|overlay" | head -10
echo ""
DISK_FULL=$(df 2>/dev/null | awk 'NR>1 && $5+0 > 90 && $1 !~ /tmpfs|udev/ {print $1": "$5" used at "$6}')
if [ -n "$DISK_FULL" ]; then
    echo "$DISK_FULL"
    err "Диск переполнен!"
    VERDICT_DISK=$((VERDICT_DISK + 3))
else
    ok "Диск в порядке"
fi

# Inode
INODE_FULL=$(df -i 2>/dev/null | awk 'NR>1 && $5+0 > 90 && $1 !~ /tmpfs|udev/ {print $1": "$5" inodes used at "$6}')
if [ -n "$INODE_FULL" ]; then
    echo "$INODE_FULL"
    err "Inode'ы исчерпаны!"
    VERDICT_DISK=$((VERDICT_DISK + 2))
fi

# Топ потребителей места
echo ""
echo "Топ-5 крупных директорий:"
du -sh /var/log 2>/dev/null
du -sh /var/lib 2>/dev/null
du -sh /tmp 2>/dev/null
du -sh /home 2>/dev/null

# === 6. SHIELDNODE EVENTS ===
section "6. Shieldnode events (последние 12 часов)"

DB=/var/lib/shieldnode/events.db
if [ ! -f "$DB" ]; then
    warn "events.db не найден — shieldnode не установлен или новый"
else
    echo "Сводка по типам атак:"
    sqlite3 "$DB" "
        SELECT 
          type,
          COUNT(*) as unique_ips,
          SUM(count) as total_hits
        FROM events 
        WHERE last_seen > strftime('%s','now') - 43200
        GROUP BY type
        ORDER BY total_hits DESC;
    " 2>/dev/null | column -t -s '|'

    TOTAL_HITS=$(sqlite3 "$DB" "SELECT COALESCE(SUM(count),0) FROM events WHERE last_seen > strftime('%s','now')-43200 AND type IN ('conn_flood','syn_flood','udp_flood');" 2>/dev/null)
    if [ "${TOTAL_HITS:-0}" -gt 100000 ]; then
        err "DDoS events: $TOTAL_HITS hits за 12ч — massive attack"
        VERDICT_DDOS=$((VERDICT_DDOS + 3))
    elif [ "${TOTAL_HITS:-0}" -gt 10000 ]; then
        warn "DDoS events: $TOTAL_HITS hits за 12ч — moderate attack"
        VERDICT_DDOS=$((VERDICT_DDOS + 2))
    elif [ "${TOTAL_HITS:-0}" -gt 1000 ]; then
        info "DDoS events: $TOTAL_HITS hits — фоновый шум сканеров"
    fi

    echo ""
    echo "Топ-10 атакующих за 12ч:"
    sqlite3 "$DB" "
        SELECT datetime(last_seen,'unixepoch'), ip, type, count
        FROM events
        WHERE last_seen > strftime('%s','now') - 43200
          AND count >= 500
        ORDER BY count DESC
        LIMIT 10;
    " 2>/dev/null | column -t -s '|'
fi

# === 7. NFT DROP COUNTERS ===
section "7. nftables drop counters"

if nft list table inet ddos_protect >/dev/null 2>&1; then
    echo "Top drop counters:"
    nft list table inet ddos_protect 2>/dev/null | \
        grep -E "counter packets [0-9]+ bytes" | \
        grep -vE "packets 0 bytes 0" | \
        head -15

    TOTAL_DROPS=$(nft list table inet ddos_protect 2>/dev/null | \
        awk '/counter packets/ {gsub(/[^0-9]/,"",$3); sum+=$3} END {print sum+0}')

    if [ "$TOTAL_DROPS" -gt 100000000 ]; then
        warn "Total nft drops: $TOTAL_DROPS — massive traffic dropped"
        VERDICT_DDOS=$((VERDICT_DDOS + 2))
    elif [ "$TOTAL_DROPS" -gt 1000000 ]; then
        info "Total nft drops: $TOTAL_DROPS"
    fi
else
    err "nft table 'inet ddos_protect' отсутствует!"
    warn "shieldnode-nftables.service может быть упавшим"
fi

# === 8. NETWORK TRAFFIC ===
section "8. Network traffic (текущий)"

DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
if [ -n "$DEFAULT_IFACE" ]; then
    echo "Interface: $DEFAULT_IFACE"
    ip -s link show "$DEFAULT_IFACE" 2>/dev/null | grep -A1 "RX:" | head -2
    echo ""
    ip -s link show "$DEFAULT_IFACE" 2>/dev/null | grep -A1 "TX:" | head -2
fi

if command -v vnstat >/dev/null 2>&1; then
    echo ""
    echo "vnstat (последний час):"
    vnstat -h 2>/dev/null | tail -10
fi

# === 9. SERVICES STATUS ===
section "9. Critical services"

for svc in shieldnode-nftables shieldnode-pcap crowdsec crowdsec-firewall-bouncer xray ssh; do
    if systemctl is-enabled "$svc" >/dev/null 2>&1; then
        status=$(systemctl is-active "$svc" 2>/dev/null)
        case "$status" in
            active) ok "$svc: active" ;;
            failed) err "$svc: FAILED" ;;
            *) warn "$svc: $status" ;;
        esac
    fi
done

# Crashes за 12 часов
echo ""
CRASHED=$(journalctl --since "12 hours ago" --no-pager 2>/dev/null | grep -iE "killed by signal|core-dumped|main process exited" | head -10)
if [ -n "$CRASHED" ]; then
    warn "Crashes за 12ч:"
    echo "$CRASHED"
fi

# === 10. NETWORK CONNECTIVITY ===
section "10. Network connectivity"

# Ping наружу
if ping -c 2 -W 2 1.1.1.1 >/dev/null 2>&1; then
    ok "Внешний интернет (1.1.1.1) доступен"
else
    err "Нет связи с внешним интернетом — хостер мог сделать null-route"
    VERDICT_NETWORK=$((VERDICT_NETWORK + 2))
fi

# DNS
if getent hosts google.com >/dev/null 2>&1; then
    ok "DNS resolve работает"
else
    warn "DNS resolve не работает"
fi

# === 11. VERDICT ===
section "11. Итоговая оценка"

echo "Score:"
echo "  DDoS attack:     $VERDICT_DDOS"
echo "  OOM/memory:      $VERDICT_OOM"
echo "  Disk:            $VERDICT_DISK"
echo "  Kernel:          $VERDICT_KERNEL"
echo "  Network/hoster:  $VERDICT_NETWORK"
echo ""

MAX_SCORE=$(echo -e "$VERDICT_DDOS\n$VERDICT_OOM\n$VERDICT_DISK\n$VERDICT_KERNEL\n$VERDICT_NETWORK" | sort -rn | head -1)

if [ "$MAX_SCORE" -eq 0 ]; then
    ok "Признаков проблем не обнаружено — нода в норме"
elif [ "$VERDICT_DDOS" = "$MAX_SCORE" ]; then
    err "ВЕРДИКТ: DDoS атака (score: $VERDICT_DDOS)"
    info "Рекомендации: upgrade до shieldnode v3.23.4+, проверь ct count лимит = 15000"
elif [ "$VERDICT_OOM" = "$MAX_SCORE" ]; then
    err "ВЕРДИКТ: Out Of Memory (score: $VERDICT_OOM)"
    info "Рекомендации: добавить RAM, проверить утечки Xray/CrowdSec, поднять nf_conntrack_max разумно"
elif [ "$VERDICT_DISK" = "$MAX_SCORE" ]; then
    err "ВЕРДИКТ: Disk full / inode exhaustion (score: $VERDICT_DISK)"
    info "Рекомендации: почистить /var/log, /tmp, проверить logrotate"
elif [ "$VERDICT_KERNEL" = "$MAX_SCORE" ]; then
    err "ВЕРДИКТ: Kernel panic / hardware (score: $VERDICT_KERNEL)"
    info "Рекомендации: контакт с хостером, проверить железо, возможно нужна миграция"
elif [ "$VERDICT_NETWORK" = "$MAX_SCORE" ]; then
    err "ВЕРДИКТ: Network/hoster issue (score: $VERDICT_NETWORK)"
    info "Рекомендации: связь с хостером — возможен null-route или abuse-блокировка"
fi

echo ""
echo -e "${D}Diagnostic completed at $(date -u +%FT%TZ)${N}"
echo -e "${D}Save: sudo bash $(basename $0) > /tmp/diag-\$(hostname)-\$(date +%F-%H%M).txt${N}"
