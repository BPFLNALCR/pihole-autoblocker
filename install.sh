#!/usr/bin/env bash
set -euo pipefail

# Pi-hole Autoblocker Installer
# Usage: sudo ./install.sh [--no-fzf]
# Assumes you cloned the repo containing:
#   - pihole-autoblocker (python, executable with shebang)
#   - pihole-autoblocker-review.py
#   - docs (optional)

NO_FZF=0
if [[ ${1:-} == "--no-fzf" ]]; then NO_FZF=1; fi

# --- prereqs ---
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

command -v pihole >/dev/null || {
  echo "Pi-hole not found. Install Pi-hole first." >&2
  exit 1
}

apt-get update
DEBS=(python3 python3-yaml sqlite3 jq)
(( NO_FZF == 1 )) || DEBS+=(fzf)
apt-get install -y "${DEBS[@]}"

# --- paths ---
BIN=/usr/local/bin
ETC=/etc/pihole-autoblocker
VAR=/var/lib/pihole-autoblocker
LOG=/var/log/pihole-autoblocker.log
PH_ETC=/etc/pihole
OUT_FILE=$PH_ETC/pihole-autoblocker.txt
LEGACY_SYMLINK=$PH_ETC/custom_autoblocker.txt
REVIEW_JSON=$VAR/quarantine_review.json
QUAR_JSON=$VAR/quarantine.json
TSV=$VAR/quarantine.tsv
FTL_DB=$PH_ETC/pihole-FTL.db

install -d -m 0755 "$ETC" "$VAR"
# --- install binaries ---
install -m 0755 ./pihole-autoblocker "$BIN/pihole-autoblocker"
install -m 0755 ./pihole-autoblocker-review.py "$BIN/pihole-autoblocker-review"

# --- default config (create if absent) ---
CFG=$ETC/config.yml
if [[ ! -f $CFG ]]; then
  cat > "$CFG" <<YAML
# Pi-hole Autoblocker config
lookback_hours: 24
min_hits: 10
min_unique_clients: 2
min_hours_active: 0
quarantine_hours: 12
promotion_min_score: 0.90

# Heuristics
suspicious_substrings: [adserver, ads, metrics, telemetry, track, analytic, pixel, beacon]
suspicious_tlds: [click, xyz, top, work, support, country, pw, buzz, gq, cf, tk]
auto_learn_keywords: true
learn_refresh_hours: 24
learn_min_support_etlds: 8
learn_max_keywords: 200
learn_stopwords: [www, api, cdn, img, static]

# CNAME checks
cname_max_depth: 2
cname_cache_only: true
cname_cache_ttl_hours: 24
cname_cache_path: $VAR/cname_cache.json

# Reputation by family (eTLD+1 overlaps across adlists)
family_adlist_threshold: 6

# Files/paths
output_file: $OUT_FILE
legacy_output_symlink: $LEGACY_SYMLINK
manual_block_file: $PH_ETC/pihole-autoblocker.manual-block.txt
allowlist_file:     $PH_ETC/pihole-autoblocker.allow.txt
quarantine_file:    $QUAR_JSON
quarantine_review_file: $REVIEW_JSON
quarantine_tsv_file: $TSV
ftl_db: $FTL_DB
log_file: $LOG
metrics_path: /var/lib/node_exporter/textfile_collector/pihole_autoblocker.prom

# Promotion method
sql_promotion: true
promotion_group: Default
promotion_comment: autoblocker

# Limits
top_n_cname: 200
score_hits_k: 20
score_uniq_k: 3
score_hours_k: 6
YAML
fi

# --- systemd unit + timer ---
cat > /etc/systemd/system/pihole-autoblocker.service <<'UNIT'
[Unit]
Description=Pi-hole Autoblocker - generate dynamic blocklist
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/pihole-autoblocker
# Rebuild gravity so Pi-hole ingests the updated list
ExecStartPost=/usr/local/bin/pihole -g
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/pihole-autoblocker.timer <<'TIMER'
[Unit]
Description=Run Pi-hole Autoblocker periodically

[Timer]
OnCalendar=hourly
RandomizedDelaySec=15m
Persistent=true
Unit=pihole-autoblocker.service

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now pihole-autoblocker.timer

# --- register adlist in gravity (idempotent) ---
sqlite3 $PH_ETC/gravity.db "INSERT OR IGNORE INTO adlist (address, enabled, comment) VALUES ('file://$OUT_FILE', 1, 'Autoblocker dynamic');"

# --- first run ---
/usr/local/bin/pihole-autoblocker || true
/usr/local/bin/pihole -g || true

# --- status hints ---
echo "\nInstall complete. Useful checks:"
echo "  systemctl status pihole-autoblocker.timer"
echo "  journalctl -u pihole-autoblocker.service -n 80 --no-pager"
echo "  ls -l $OUT_FILE $LEGACY_SYMLINK || true"
echo "  pihole-autoblocker-review --top 20"
