#!/usr/bin/env bash
set -euo pipefail

# Pi-hole Autoblocker Upgrader
# Usage:
#   sudo ./upgrade.sh                # pull latest from default remote + reinstall binaries
#   sudo ./upgrade.sh --branch dev   # pull a specific branch
#   sudo ./upgrade.sh --no-pull      # skip git pull (use local working tree)
#   sudo ./upgrade.sh --restart-only # don't reinstall, just restart service
#   sudo ./upgrade.sh --check        # show detected versions/paths and exit

if [[ $EUID -ne 0 ]]; then
	echo "Please run as root (sudo)." >&2
	exit 1
fi

BRANCH=""
NO_PULL=0
RESTART_ONLY=0
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--branch)
		BRANCH="$2"
		shift 2
		;;
	--no-pull)
		NO_PULL=1
		shift
		;;
	--restart-only)
		RESTART_ONLY=1
		shift
		;;
	--check)
		CHECK_ONLY=1
		shift
		;;
	*)
		echo "Unknown arg: $1" >&2
		exit 2
		;;
	esac
done

# --- locate repo root ---
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)
if [[ -z $REPO_ROOT ]]; then
	echo "Not a git repo. Please run from your cloned repository (e.g., https://github.com/BPFLNALCR/pihole-autoblocker)." >&2
	exit 3
fi

BIN=/usr/local/bin
SERVICE=/etc/systemd/system/pihole-autoblocker.service
TIMER=/etc/systemd/system/pihole-autoblocker.timer

APP_SRC_A="$REPO_ROOT/pihole-autoblocker"
APP_SRC_B="$REPO_ROOT/pihole-autoblocker.py"
REVIEW_SRC="$REPO_ROOT/pihole-autoblocker-review.py"

# --- status ----
if ((CHECK_ONLY)); then
	echo "Repo root: $REPO_ROOT"
	echo "Service:   $SERVICE"
	echo "Timer:     $TIMER"
	echo "Binary:    $BIN/pihole-autoblocker (exists: $([[ -x $BIN/pihole-autoblocker ]] && echo yes || echo no))"
	echo "Reviewer:  $BIN/pihole-autoblocker-review (exists: $([[ -x $BIN/pihole-autoblocker-review ]] && echo yes || echo no))"
	systemctl is-enabled pihole-autoblocker.timer >/dev/null 2>&1 && S=en || S=dis
	echo "Timer is $S and $(systemctl is-active pihole-autoblocker.timer || true)"
	exit 0
fi

# --- pull latest ---
if ((!RESTART_ONLY)) && ((!NO_PULL)); then
	git -C "$REPO_ROOT" fetch --all --tags
	if [[ -n $BRANCH ]]; then
		git -C "$REPO_ROOT" checkout "$BRANCH"
	fi
	git -C "$REPO_ROOT" pull --ff-only || {
		echo "git pull failed. Resolve conflicts and rerun." >&2
		exit 4
	}
fi

# --- reinstall binaries unless restart-only ---
if ((!RESTART_ONLY)); then
	# choose main script path
	if [[ -x $APP_SRC_A ]]; then
		APP_SRC="$APP_SRC_A"
	elif [[ -f $APP_SRC_B ]]; then
		APP_SRC="$APP_SRC_B"
	else
		echo "Cannot find pihole-autoblocker in repo. Expected $APP_SRC_A or $APP_SRC_B" >&2
		exit 5
	fi

	# Syntax check if python source
	if head -n1 "$APP_SRC" | grep -qE "python"; then
		python3 -m py_compile "$APP_SRC" || {
			echo "Python syntax check failed for $APP_SRC" >&2
			exit 6
		}
	fi

	install -m 0755 "$APP_SRC" "$BIN/pihole-autoblocker"

	if [[ -f $REVIEW_SRC ]]; then
		python3 -m py_compile "$REVIEW_SRC" || true
		install -m 0755 "$REVIEW_SRC" "$BIN/pihole-autoblocker-review"
	fi
fi

# --- reload units if changed ---
if [[ -f $SERVICE || -f $TIMER ]]; then
	systemctl daemon-reload || true
fi

# --- restart service to pick up new code ---
systemctl start pihole-autoblocker.service || true

# --- optional gravity refresh (best-effort) ---
/usr/local/bin/pihole -g || true

# --- report ---
echo "Upgrade complete. Quick checks:"
echo "  journalctl -u pihole-autoblocker.service -n 80 --no-pager"
echo "  pihole-autoblocker-review --top 20"
