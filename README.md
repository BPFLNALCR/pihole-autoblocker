# Pi-hole Autoblocker

An **adaptive, low-noise** companion to Pi-hole that automatically detects, quarantines, and promotes suspicious domains into Pi-hole’s blocklist. It balances autonomous operation with user control via an interactive reviewer.

---

## Why Autoblocker?
- **Personalized signal**: Blocks only domains that *your* network repeatedly queries.
- **Safety rails**: Quarantine delay, score threshold, allowlist, and activity filters prevent false positives.
- **CNAME cloak detection**: Optionally detects first‑party tracker cloaks with minimal DNS noise.
- **Low noise design**: Thresholds-first + cache-only lookups + persistent caches.
- **Interactive control**: Review quarantined domains and promote/release manually if desired.

---

## Features
- Threshold-first candidate selection (hits, unique clients, and active hours)
- Static + auto-learned keywords (from adlists)
- Family reputation by eTLD+1 overlap across adlists
- Optional CNAME chase with cache-only lookups and TTL cache
- Quarantine → promote flow with dry-run mode
- Auto-promotion after score ≥ **0.90** (default) and quarantine ≥ **12h**
- SQL promotions (direct to gravity.db) or manual blocklist file
- Skips duplicates already blocked via adlists or blacklist
- Prometheus textfile metrics (optional)
- Interactive reviewer (`pihole-autoblocker-review`) with prompt or `fzf`

---

## Quickstart

### 1. Clone Repo
```bash
git clone https://github.com/BPFLNALCR/pihole-autoblocker.git
cd pihole-autoblocker
```

### 2. Install
Use the installer to set up binaries, config, systemd units, and adlist registration:
```bash
sudo ./install.sh
```

### 3. Verify
```bash
systemctl status pihole-autoblocker.timer
journalctl -u pihole-autoblocker.service -n 50 --no-pager
ls -l /etc/pihole/pihole-autoblocker.txt
```

### 4. First Run
```bash
sudo systemctl start pihole-autoblocker.service
sudo pihole -g
```

### 5. Review Quarantine
```bash
pihole-autoblocker-review --top 20
pihole-autoblocker-review --interactive
```

---

## Config (`/etc/pihole-autoblocker/config.yml`)

Key options:
```yaml
lookback_hours: 24
min_hits: 10
min_unique_clients: 2
min_hours_active: 0
quarantine_hours: 12
promotion_min_score: 0.90

suspicious_substrings: [adserver, ads, metrics, telemetry, track, analytic, pixel, beacon]
suspicious_tlds: [click, xyz, top, work, support, country, pw, buzz, gq, cf, tk]

sql_promotion: true
promotion_group: Default
promotion_comment: autoblocker

output_file: /etc/pihole/pihole-autoblocker.txt
legacy_output_symlink: /etc/pihole/custom_autoblocker.txt
manual_block_file: /etc/pihole/pihole-autoblocker.manual-block.txt
allowlist_file: /etc/pihole/pihole-autoblocker.allow.txt
log_file: /var/log/pihole-autoblocker.log
```

---

## Maintenance

### Upgrade
```bash
cd ~/pihole-autoblocker
sudo ./upgrade.sh
```

### Uninstall
```bash
cd ~/pihole-autoblocker
sudo ./uninstall.sh
```

---

## Troubleshooting
- **Empty blocklist file**: Normal until domains are promoted or manually added.
- **No quarantine.json**: Ensure service is running and `quarantine_file` is set.
- **Promotion not working**: Check `promotion_min_score` and `quarantine_hours`.
- **Systemd errors**: Run `journalctl -u pihole-autoblocker.service -n 50`.

---

## License
MIT (or TBD)
