#README.md

## Pi-hole Autoblocker (Adaptive + Low-Noise)

A small Python service that watches your Pi-hole query history, identifies likely trackers with conservative heuristics, and automatically promotes repeat offenders to the blacklist after a quarantine window.

### Why this instead of just more adlists?

- **Local, personalized signal**: Promotes only what *your* network repeatedly hits.
- **CNAME cloak detection**: (optional) catches first-party cloaks with minimal DNS noise.
- **Safety rails**: quarantine delay, allowlist, hours-active filter, and client diversity.
- **Low noise**: thresholds-first + cache-only CNAME + persistent cache keep localhost DNS bursts small.

---

## Features

- Threshold-first candidate selection (hits, unique clients, and active hours)
- Static + auto-learned keywords (mined from your existing adlists)
- Family reputation by eTLD+1 overlap across adlists
- Optional CNAME chase with cache-only lookups and persistent cache
- Quarantine → promote flow with dry-run mode
- SQL promotions (no REST) with CLI fallback
- Skips duplicates: ignores domains already blocked via adlists or blacklist
- Prometheus textfile metrics (optional)
- Concurrency lock (no overlapping runs)

---

## Install

```
Stil working on this
```

### Example config (`/etc/pihole-autoblocker/config.yml`)

```yaml
# How aggressive?
lookback_hours: 24
min_hits: 10
min_unique_clients: 2
min_hours_active: 2   # require presence in ≥2 hours within lookback (optional)

# Quarantine
quarantine_hours: 12

# CNAME detection (set cname_max_depth: 0 to disable)
cname_max_depth: 1
cname_cache_only: true             # do not trigger upstream recursion
cname_cache_path: "/var/lib/pihole-autoblocker/cname_cache.json"
cname_cache_ttl_hours: 24
# Only CNAME-check this many busiest domains per run
top_n_cname: 100

# Learned keywords (auto)
auto_learn_keywords: true
learn_min_support_etlds: 8
learn_max_keywords: 200
learn_refresh_hours: 24
learned_keywords_path: "/var/lib/pihole-autoblocker/learned_keywords.json"
learn_stopwords: ["www","api","cdn","img","static","assets","edge","files","m","s","i","v","gw","ad"]

# Family reputation: treat eTLD+1 as suspicious if present in ≥N adlists
family_adlist_threshold: 3

# Static heuristics
suspicious_substrings: ["doubleclick","adnxs","braze","branch.io","outbrain","taboola","moatads","googlesyndication","analytics","scorecardresearch"]
suspicious_tlds: [".doubleclick.net",".adnxs.com",".scorecardresearch.com"]

# Never auto-block
allowlist: ["google.com","gstatic.com","googleapis.com","microsoft.com","github.com","githubusercontent.com","cloudfront.net","cdn.cloudflare.net","fastly.net","akamai.net","apple.com","icloud.com"]

# Behavior
sql_promotion: true                 # write to gravity.db directly
promotion_group: "Default"
promotion_comment: "autoblocker"
dry_run: false

# Paths
ftl_db: "/etc/pihole/pihole-FTL.db"
quarantine_file: "/var/lib/pihole-autoblocker/quarantine.json"
state_file: "/var/lib/pihole-autoblocker/state.json"
log_file: "/var/log/pihole-autoblocker/run.log"

# Optional Prometheus textfile metrics
metrics_path: "/var/lib/node_exporter/textfile_collector/autoblocker.prom"
```

### systemd service & timer

```bash
sudo tee /etc/systemd/system/pihole-autoblocker.service >/dev/null <<'UNIT'
[Unit]
Description=Pi-hole Autoblocker (quarantine + promote)
After=network-online.target pihole-FTL.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pihole-autoblocker.py
User=root
Group=root
Nice=10

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/pihole-autoblocker.timer >/dev/null <<'UNIT'
[Unit]
Description=Run Pi-hole Autoblocker periodically

[Timer]
OnBootSec=5m
OnUnitActiveSec=3h      # adjust to taste
AccuracySec=5m
Persistent=true

[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now pihole-autoblocker.timer
```

---

## How it decides to block

1. Domain crosses thresholds (hits, unique clients, optional hours-active).
2. Domain looks suspicious by **static/learned keywords**, **TLD**, or **family reputation**.
3. Optionally, CNAME chain (1 hop by default) also looks suspicious.
4. Domain sits in **quarantine**. If still active after `quarantine_hours`, it is promoted.

---

## Tips

- Set `cname_max_depth: 0` for **zero extra DNS** from the script.
- Keep `cname_cache_only: true` to avoid upstream recursion during checks.
- Use `dry_run: true` to audit what would be promoted without touching Pi-hole.
- Use Pi-hole **Groups** to send promotions to an "Aggressive" group for IoT/Guest VLANs only.

---

## Troubleshooting

- Check logs: `journalctl -u pihole-autoblocker.service -n 100 --no-pager`
- Validate YAML: `python3 -c 'import yaml; print(yaml.safe_load(open("/etc/pihole-autoblocker/config.yml")))'`
- Confirm blacklist inserts: `sqlite3 /etc/pihole/gravity.db "SELECT domain,type FROM domainlist WHERE comment='autoblocker';"`

---

## License

None at the moment
