#!/usr/bin/env python3
"""
Pi-hole Autoblocker Script (with Quarantine + Promote)
----------------------------------------------------
This script watches recent queries in Pi-hole and automatically promotes suspicious
trackers to the blacklist after a quarantine period. It is designed to:
- Pull query statistics from FTL's sqlite database (or fallback to the log)
- Apply simple heuristics (substrings / TLD matches)
- Optionally follow CNAMEs to catch cloaked trackers
- Quarantine suspicious domains, then promote to the blacklist after repeated hits
- Keep a state file so actions are reversible
- Avoid hammering Pi-hole's API (uses gravity.db directly)

Tunable settings are provided in /etc/pihole-autoblocker/config.yml
"""

import json, os, time, subprocess, sqlite3, sys
from datetime import datetime
from pathlib import Path

# ---- Dependencies ----
try:
    import yaml  # For parsing YAML config file
except ImportError:
    raise SystemExit("Missing dependency: python3-yaml. Install with: sudo apt-get install -y python3-yaml")

# ---- Utility functions ----
def load_yaml(p):
    """Load YAML config from path."""
    with open(p, 'r') as f:
        return yaml.safe_load(f)

def now_ts():
    """Return current timestamp in seconds."""
    return int(time.time())

def domain_suffix_in_list(domain: str, suffixes: list[str]) -> bool:
    """Check if domain exactly matches or ends with any suffix in list."""
    d = domain.lower().rstrip('.')
    for s in suffixes or []:
        s = (s or "").lower().strip().lstrip('*')
        if not s:
            continue
        if d == s or d.endswith("." + s) or d.endswith(s):
            return True
    return False

def log(path: str, msg: str):
    """Append a log line with timestamp."""
    ts = datetime.now().isoformat(timespec='seconds')
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as f:
        f.write(f"[{ts}] {msg}\n")

def load_json(path: str, default):
    """Load JSON file or return default."""
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except Exception:
        return default

def save_json(path: str, obj):
    """Save dict to JSON file (pretty)."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True))

# ---- Pi-hole database access ----
def get_recent_counts_from_ftl(ftl_db: str, lookback_hours: int):
    """
    Query Pi-hole FTL sqlite database for domain statistics in last lookback_hours.
    Returns { domain: {hits: int, uniq: int} }
    """
    try:
        conn = sqlite3.connect(ftl_db)
        cur = conn.cursor()
        since = int(time.time()) - lookback_hours * 3600
        cur.execute("""
            SELECT domain, COUNT(*) AS hits, COUNT(DISTINCT client) AS uniq
            FROM queries
            WHERE timestamp >= ?
              AND domain NOT NULL
              AND domain != ''
              AND domain NOT LIKE '%.in-addr.arpa'
              AND domain NOT LIKE '%.ip6.arpa'
            GROUP BY domain
        """, (since,))
        rows = cur.fetchall()
        conn.close()
        return {d: {"hits": h, "uniq": u} for d, h, u in rows}
    except Exception:
        return {}

def fallback_counts_from_log(lookback_hours: int):
    """
    If FTL.db is unavailable, parse the raw pihole.log as a fallback.
    """
    path = "/var/log/pihole/pihole.log"
    if not os.path.exists(path):
        return {}
    counts = {}
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                if " query[" not in line or " from " not in line:
                    continue
                parts = line.strip().split()
                try:
                    dom = parts[5]; cli = parts[7]
                except Exception:
                    continue
                d = counts.get(dom, {"hits": 0, "clients": set()})
                d["hits"] += 1
                d["clients"].add(cli)
                counts[dom] = d
        return {k: {"hits": v["hits"], "uniq": len(v["clients"])} for k, v in counts.items()}
    except Exception:
        return {}

def is_already_blocked_anywhere(domain: str) -> bool:
    """
    Return True if the domain is already blocked **either** by:
      - exact/regex blacklist entries (domainlist type 1 or 3), OR
      - any adlist (aggregated in gravity table).
    This prevents duplicate promotions when a domain is already present in your
    subscribed lists.
    """
    try:
        conn = sqlite3.connect("/etc/pihole/gravity.db")
        cur = conn.cursor()
        # 1) Check domainlist (exact/regex blacklist)
        cur.execute(
            "SELECT 1 FROM domainlist WHERE domain = ? AND type IN (1,3) AND enabled = 1 LIMIT 1",
            (domain,)
        )
        if cur.fetchone() is not None:
            conn.close()
            return True
        # 2) Check gravity (domains from adlists)
        cur.execute(
            "SELECT 1 FROM gravity WHERE domain = ? LIMIT 1",
            (domain,)
        )
        hit = cur.fetchone() is not None
        conn.close()
        return hit
    except Exception:
        # Be conservative: assume not blocked if we cannot read DB
        return False

def add_to_blacklist(domain: str) -> bool:
    """Promote a domain to Pi-hole blacklist using CLI (keeps UI consistent)."""
    try:
        r = subprocess.run(["pihole", "-b", domain], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False

# ---- Heuristic checks ----
def substr_or_tld_suspicious(domain: str, cfg) -> bool:
    """Check if domain matches suspicious substrings or TLDs."""
    d = domain.lower()
    if domain_suffix_in_list(d, cfg.get("allowlist", [])):
        return False
    if any(ss in d for ss in (cfg.get("suspicious_substrings") or [])):
        return True
    if domain_suffix_in_list(d, cfg.get("suspicious_tlds", [])):
        return True
    return False

CNAME_CACHE = {}
def resolve_cname_chain(domain: str, max_depth: int = 0) -> list[str]:
    """Resolve up to max_depth CNAMEs using dig against Pi-hole (127.0.0.1)."""
    if max_depth < 1:
        return []
    d = domain.lower().rstrip('.')
    if d in CNAME_CACHE:
        return CNAME_CACHE[d]
    chain = []
    current = d
    for _ in range(max_depth):
        try:
            out = subprocess.run(
                ["dig", "@127.0.0.1", "+short", current, "CNAME"],
                capture_output=True, text=True, timeout=4
            )
            lines = [l.strip().rstrip('.') for l in out.stdout.splitlines() if l.strip()]
            if not lines:
                break
            target = lines[0]
            chain.append(target)
            current = target
        except Exception:
            break
    CNAME_CACHE[d] = chain
    return chain

def cname_suspicious(domain: str, cfg) -> bool:
    """Check if any CNAME target looks suspicious (substrings/TLDs)."""
    max_depth = int(cfg.get("cname_max_depth", 0))
    if max_depth < 1:
        return False
    chain = resolve_cname_chain(domain, max_depth)
    for cname in chain:
        if domain_suffix_in_list(cname, cfg.get("allowlist", [])):
            return False
        if any(ss in cname for ss in (cfg.get("suspicious_substrings") or [])) \
           or domain_suffix_in_list(cname, cfg.get("suspicious_tlds", [])):
            return True
    return False

# ---- Main logic ----
def main():
    # Load config and state
    cfg = load_yaml("/etc/pihole-autoblocker/config.yml")
    quarantine = load_json(cfg.get("quarantine_file"), {})
    state = load_json(cfg.get("state_file"), {"blocked": []})

    # Get counts of queries (FTL or log fallback)
    counts = get_recent_counts_from_ftl(cfg.get("ftl_db"), int(cfg.get("lookback_hours", 24)))
    if not counts:
        counts = fallback_counts_from_log(int(cfg.get("lookback_hours", 24)))

    # Config thresholds
    min_hits = int(cfg.get("min_hits", 10))
    min_unique = int(cfg.get("min_unique_clients", 2))
    q_hours = int(cfg.get("quarantine_hours", 12))
    top_n_cname = int(cfg.get("top_n_cname", 200))  # Only CNAME-check this many top talkers

    # 1) Pre-filter by thresholds
    eligible = [(d, m) for d, m in counts.items() if (m["hits"] >= min_hits and m["uniq"] >= min_unique)]

    # 2) Remove domains already blacklisted
    eligible = [(d, m) for d, m in eligible if not is_already_blocked_anywhere(d)]

    # 3) Apply cheap substring/TLD heuristics
    candidates = []
    for d, _ in eligible:
        if substr_or_tld_suspicious(d, cfg):
            candidates.append(d)

    # 4) For the rest, only CNAME-check the top-N busiest
    remaining = [x for x in eligible if x[0] not in candidates]
    remaining = sorted(remaining, key=lambda x: x[1]["hits"], reverse=True)[:top_n_cname]
    for d, _ in remaining:
        if cname_suspicious(d, cfg):
            candidates.append(d)

    # 5) Quarantine update
    now = now_ts()
    for d in candidates:
        entry = quarantine.get(d)
        if entry:
            entry["last_seen"] = now
        else:
            quarantine[d] = {"first_seen": now, "last_seen": now}

    # 6) Promotion check
    promoted = []
    for d, meta in list(quarantine.items()):
        age_hours = (now - meta.get("first_seen", now)) / 3600.0
        still_candidate = d in candidates
        if age_hours >= q_hours and still_candidate:
            if not is_already_blocked_anywhere(d):
                if add_to_blacklist(d):
                    promoted.append(d)
                    state["blocked"].append({"domain": d, "ts": now})
            quarantine.pop(d, None)
        elif (now - meta.get("last_seen", now)) > (3 * int(cfg.get("lookback_hours", 24)) * 3600):
            # Remove stale quarantined domains
            quarantine.pop(d, None)

    # 7) Save state and log
    save_json(cfg.get("quarantine_file"), quarantine)
    save_json(cfg.get("state_file"), state)
    msg = f"Scan complete. New candidates this run: {len(candidates)}. Promoted to blacklist: {len(promoted)}."
    log(cfg.get("log_file"), msg)
    print(msg)

if __name__ == "__main__":
    main()
