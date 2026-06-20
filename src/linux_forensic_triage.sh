#!/usr/bin/env bash
set -u

HOURS=24
OUTPUT_DIR=""

usage() {
  echo "Usage: linux_forensic_triage.sh [--hours N] [--output DIR]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours) HOURS="${2:-24}"; shift 2 ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$HOURS" =~ ^[0-9]+$ ]] || { echo "--hours must be numeric" >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOSTNAME_SAFE="$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9_.-' || echo host)"
OUTPUT_DIR="${OUTPUT_DIR:-./triage-${HOSTNAME_SAFE}-${STAMP}}"
mkdir -p "$OUTPUT_DIR"
ERRORS="$OUTPUT_DIR/command-errors.log"
MANIFEST="$OUTPUT_DIR/SHA256SUMS"
SUMMARY="$OUTPUT_DIR/summary.json"
: > "$ERRORS"

run_capture() {
  local file="$1"
  shift
  {
    printf '# Collected UTC: %s\n' "$(date -u -Is)"
    printf '# Command:'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } > "$OUTPUT_DIR/$file" 2>> "$ERRORS" || true
}

run_shell() {
  local file="$1"
  local command="$2"
  {
    printf '# Collected UTC: %s\n' "$(date -u -Is)"
    printf '# Shell command: %s\n\n' "$command"
    bash -c "$command"
  } > "$OUTPUT_DIR/$file" 2>> "$ERRORS" || true
}

have() { command -v "$1" >/dev/null 2>&1; }

run_shell "host-context.txt" 'date -u -Is; date -Is; hostnamectl 2>/dev/null || hostname; cat /etc/os-release 2>/dev/null || true; uname -a; uptime; who -b 2>/dev/null || true; cat /proc/sys/kernel/random/boot_id 2>/dev/null || true'
run_shell "hardware-context.txt" 'lscpu 2>/dev/null || true; free -h; lsblk -o NAME,PATH,TYPE,FSTYPE,SIZE,MODEL,SERIAL,MOUNTPOINTS 2>/dev/null || lsblk; dmidecode -t system -t bios 2>/dev/null || true'
run_shell "logged-on-users.txt" 'who -a; w; loginctl list-sessions --no-legend 2>/dev/null || true'
run_shell "login-history.txt" 'last -Faiwx 2>/dev/null | head -n 500; echo; lastb -Faiwx 2>/dev/null | head -n 500 || true'
run_shell "account-inventory.txt" 'getent passwd; echo; getent group; echo; awk -F: "($3==0){print}" /etc/passwd'
run_shell "processes.txt" 'ps -eo user,pid,ppid,lstart,etimes,state,pcpu,pmem,rss,vsz,nlwp,comm,args --sort=pid'
run_shell "process-tree.txt" 'pstree -ap 2>/dev/null || ps -ef --forest'
run_shell "process-executables.txt" 'for p in /proc/[0-9]*; do pid=${p##*/}; exe=$(readlink -f "$p/exe" 2>/dev/null || true); [[ -n "$exe" ]] && printf "%s\t%s\n" "$pid" "$exe"; done | sort -n'
run_shell "network-sockets.txt" 'ss -H -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true'
run_shell "network-listeners.txt" 'ss -H -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true'
run_shell "network-context.txt" 'ip -br address 2>/dev/null || ifconfig -a; echo; ip route show table all 2>/dev/null || route -n; echo; ip neigh show 2>/dev/null || arp -an; echo; cat /etc/resolv.conf 2>/dev/null || true'
run_shell "mounts.txt" 'findmnt -A 2>/dev/null || mount; echo; df -hT; echo; cat /proc/mounts'
run_shell "loaded-modules.txt" 'lsmod 2>/dev/null || cat /proc/modules'
run_shell "systemd-services.txt" 'systemctl list-unit-files --type=service --no-pager 2>/dev/null || true; echo; systemctl --failed --no-pager 2>/dev/null || true'
run_shell "systemd-timers.txt" 'systemctl list-timers --all --no-pager 2>/dev/null || true'
run_shell "cron-metadata.txt" 'find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs -maxdepth 2 -type f -printf "%M %u:%g %s %TY-%Tm-%TdT%TH:%TM:%TS %p\n" 2>/dev/null | sort || true'
run_shell "startup-persistence-metadata.txt" 'find /etc/systemd/system /usr/local/lib/systemd/system /etc/init.d /etc/rc.local /etc/profile.d /etc/ld.so.preload /etc/modprobe.d -maxdepth 3 -type f -printf "%M %u:%g %s %TY-%Tm-%TdT%TH:%TM:%TS %p\n" 2>/dev/null | sort || true'
run_shell "recent-executables.txt" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f -mtime -$((HOURS / 24 + 2)) -printf '%M %u:%g %s %TY-%Tm-%TdT%TH:%TM:%TS %p\n' 2>/dev/null | sort"
run_shell "recent-high-priority-journal.txt" "journalctl --since '$HOURS hours ago' -p 0..4 --no-pager 2>/dev/null | tail -n 5000 || true"
run_shell "recent-auth-events.txt" "journalctl --since '$HOURS hours ago' --no-pager 2>/dev/null | grep -Ei 'sshd|sudo|su:|authentication failure|failed password|invalid user|session opened|session closed' | tail -n 5000 || true"
run_shell "recent-kernel-events.txt" "journalctl -k --since '$HOURS hours ago' --no-pager 2>/dev/null | tail -n 5000 || dmesg 2>/dev/null | tail -n 5000"

if have ausearch; then
  run_capture "audit-events.txt" ausearch -ts recent -i
fi

if have dpkg; then
  run_shell "package-inventory.txt" 'dpkg-query -W -f="${Package}\t${Version}\t${Architecture}\n" 2>/dev/null | sort'
  run_shell "package-verification.txt" 'debsums -s 2>/dev/null || true'
elif have rpm; then
  run_shell "package-inventory.txt" 'rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort'
  run_shell "package-verification.txt" 'rpm -Va 2>/dev/null || true'
fi

run_shell "process-executable-hashes.txt" 'for p in /proc/[0-9]*; do pid=${p##*/}; exe=$(readlink -f "$p/exe" 2>/dev/null || true); [[ -f "$exe" ]] || continue; printf "%s\t%s\t" "$pid" "$exe"; sha256sum "$exe" 2>/dev/null | awk "{print \$1}"; done | sort -u -k2,2'

PROCESS_COUNT="$(ps -e --no-headers 2>/dev/null | wc -l | tr -d ' ')"
LISTENING_COUNT="$(ss -H -lntup 2>/dev/null | wc -l | tr -d ' ')"
LOGGED_ON_COUNT="$(who 2>/dev/null | wc -l | tr -d ' ')"
FAILED_UNITS="$(systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ')"

cat > "$SUMMARY" <<EOF
{
  "collection_utc": "$(date -u -Is)",
  "hostname": "$(hostname -f 2>/dev/null || hostname)",
  "hours_reviewed": $HOURS,
  "process_count": ${PROCESS_COUNT:-0},
  "logged_on_session_count": ${LOGGED_ON_COUNT:-0},
  "listening_socket_count": ${LISTENING_COUNT:-0},
  "failed_systemd_unit_count": ${FAILED_UNITS:-0},
  "collector_user": "$(id -un)",
  "output_directory": "$OUTPUT_DIR"
}
EOF

(
  cd "$OUTPUT_DIR" || exit 1
  find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > "$(basename "$MANIFEST")"
)

printf 'Forensic triage collection completed: %s\n' "$OUTPUT_DIR"
printf 'Preserve the directory and SHA256SUMS file together.\n'
