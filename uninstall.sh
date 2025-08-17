#!/usr/bin/env bash
set -euo pipefail

# Pi-hole Autoblocker Uninstaller
# Usage: sudo ./uninstall.sh

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

PH_ETC=/etc/pihole
ETC=/etc/pihole-autoblocker
VAR=/var/lib/pihole-autoblocker
BIN=/usr/local/bin

# --- stop services ---
systemctl disable --now pihole-autoblocker.timer 2>/dev/null || true
systemctl disable --now pihole-autoblocker.service 2>/dev/null || true

# --- remove systemd units ---
rm -f /etc/systemd/system/pihole-autoblocker.service
rm -f /etc/systemd/system/pihole-autoblocker.timer
systemctl daemon-reload

# --- remove executables ---
rm -f $BIN/pihole-autoblocker $BIN/pihole-autoblocker-review

# --- remove config/state (prompt first) ---
echo "Remove config in $ETC and quarantine state in $VAR? [y/N]"
read -r ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
  rm -rf "$ETC" "$VAR"
fi

# --- remove adlist entry from Pi-hole ---
SQL="DELETE FROM adlist WHERE address LIKE 'file://%autoblocker%.txt';"
sqlite3 $PH_ETC/gravity.db "$SQL" || true

# --- remove output files ---
rm -f $PH_ETC/pihole-autoblocker.txt $PH_ETC/custom_autoblocker.txt \
      $PH_ETC/pihole-autoblocker.manual-block.txt $PH_ETC/pihole-autoblocker.allow.txt

# --- rebuild gravity to purge ---
/usr/local/bin/pihole -g || true

echo "Pi-hole Autoblocker uninstalled."
