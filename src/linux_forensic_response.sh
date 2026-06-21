#!/usr/bin/env bash
set -u

STOP_SERVICE=""
TERMINATE_PID=""
QUARANTINE_FILE=""
DRY_RUN=false
ASSUME_YES=false
OUTPUT_DIR=""
FAILURES=0
ACTIONS=0

usage(){ cat <<'EOF'
Usage: linux_forensic_response.sh [options]

  --stop-service UNIT      Stop one selected systemd service after evidence capture.
  --terminate-pid PID      Send TERM to one selected non-system process.
  --quarantine-file PATH   Copy, hash and move one regular file into quarantine.
  --dry-run                Collect evidence and show actions without changing the host.
  --yes                    Skip confirmation prompts.
  --output DIR             Save evidence, logs and quarantine data in DIR.
EOF
}
while [ "$#" -gt 0 ]; do case "$1" in
  --stop-service) STOP_SERVICE="${2:-}"; shift 2;;
  --terminate-pid) TERMINATE_PID="${2:-}"; shift 2;;
  --quarantine-file) QUARANTINE_FILE="${2:-}"; shift 2;;
  --dry-run) DRY_RUN=true; shift;; --yes) ASSUME_YES=true; shift;;
  --output) OUTPUT_DIR="${2:-}"; shift 2;; -h|--help) usage; exit 0;;
  *) echo "Unknown argument: $1" >&2; usage; exit 2;; esac; done

if [ -z "$STOP_SERVICE" ] && [ -z "$TERMINATE_PID" ] && [ -z "$QUARANTINE_FILE" ]; then echo "Choose at least one response action." >&2; exit 2; fi
if [ -n "$STOP_SERVICE" ]; then systemctl cat "$STOP_SERVICE" >/dev/null 2>&1 || { echo "Unit not found: $STOP_SERVICE" >&2; exit 2; }; fi
if [ -n "$TERMINATE_PID" ]; then case "$TERMINATE_PID" in ''|*[!0-9]*) echo "PID must be numeric." >&2; exit 2;; esac; [ "$TERMINATE_PID" -gt 99 ] || { echo "Refusing low system PID." >&2; exit 2; }; PROC_UID=$(ps -o uid= -p "$TERMINATE_PID" 2>/dev/null | tr -d ' '); [ -n "$PROC_UID" ] || { echo "Process not found." >&2; exit 2; }; [ "$PROC_UID" -ge 1000 ] || { echo "Use --stop-service for system processes." >&2; exit 2; }; fi
if [ -n "$QUARANTINE_FILE" ]; then [ -f "$QUARANTINE_FILE" ] && [ ! -L "$QUARANTINE_FILE" ] || { echo "Quarantine target must be a regular non-symlink file." >&2; exit 2; }; fi

STAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-./forensic-response-$STAMP}"
EVIDENCE="$OUTPUT_DIR/evidence"
QUARANTINE="$OUTPUT_DIR/quarantine"
mkdir -p "$EVIDENCE" "$QUARANTINE"
chmod 700 "$OUTPUT_DIR" "$EVIDENCE" "$QUARANTINE" 2>/dev/null || true
LOG="$OUTPUT_DIR/response.log"; : >"$LOG"
log(){ printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
confirm(){ $ASSUME_YES && return 0; read -r -p "$1 [y/N]: " a; case "$a" in y|Y|yes|YES) return 0;; *) return 1;; esac; }
run(){ local d="$1"; shift; ACTIONS=$((ACTIONS+1)); log "$d"; if $DRY_RUN; then printf 'DRY-RUN:' >>"$LOG"; printf ' %q' "$@" >>"$LOG"; printf '\n' >>"$LOG"; return 0; fi; if "$@" >>"$LOG" 2>&1; then log "SUCCESS: $d"; else FAILURES=$((FAILURES+1)); log "WARNING: $d failed"; return 1; fi; }
root(){ local d="$1"; shift; if [ "$(id -u)" -eq 0 ]; then run "$d" "$@"; else run "$d" sudo "$@"; fi; }
capture(){ ps -efww >"$EVIDENCE/processes.txt" 2>&1 || true; ss -plantue >"$EVIDENCE/network.txt" 2>&1 || true; systemctl --failed --no-pager >"$EVIDENCE/failed-units.txt" 2>&1 || true; journalctl -n 500 --no-pager >"$EVIDENCE/journal.txt" 2>&1 || true; [ -n "$STOP_SERVICE" ] && systemctl status "$STOP_SERVICE" --no-pager -l >"$EVIDENCE/service.txt" 2>&1 || true; [ -n "$TERMINATE_PID" ] && ps -p "$TERMINATE_PID" -o pid,ppid,user,uid,stat,etime,cmd >"$EVIDENCE/process-target.txt" 2>&1 || true; [ -n "$QUARANTINE_FILE" ] && { stat "$QUARANTINE_FILE" >"$EVIDENCE/file-stat.txt" 2>&1 || true; sha256sum "$QUARANTINE_FILE" >"$EVIDENCE/file-sha256.txt" 2>&1 || true; }; find "$EVIDENCE" -type f -exec sha256sum {} + >"$OUTPUT_DIR/evidence-manifest.sha256" 2>/dev/null || true; }

capture
confirm "Apply the selected response actions after evidence capture?" || { log "Response cancelled."; exit 10; }
[ -z "$STOP_SERVICE" ] || root "Stopping $STOP_SERVICE" systemctl stop "$STOP_SERVICE" || true
if [ -n "$TERMINATE_PID" ]; then root "Sending TERM to process $TERMINATE_PID" kill -TERM "$TERMINATE_PID" || true; fi
if [ -n "$QUARANTINE_FILE" ]; then
  HASH=$(sha256sum "$QUARANTINE_FILE" | awk '{print $1}')
  DEST="$QUARANTINE/${HASH}_$(basename "$QUARANTINE_FILE")"
  root "Copying file into quarantine" cp -a "$QUARANTINE_FILE" "$DEST" || true
  [ "$FAILURES" -gt 0 ] || root "Removing original file after verified copy" rm -f -- "$QUARANTINE_FILE" || true
  [ -f "$DEST" ] && chmod 600 "$DEST" 2>/dev/null || true
fi
$DRY_RUN || sleep 2
capture
[ "$FAILURES" -eq 0 ] || exit 20
log "Response completed successfully. Actions performed: $ACTIONS"
