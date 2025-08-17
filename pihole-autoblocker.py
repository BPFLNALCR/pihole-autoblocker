#!/usr/bin/env python3
"""
Pi-hole Autoblocker v1.0 (Adaptive + Low-Noise)
-----------------------------------------------
Update highlights in v1.0:
- **Fix:** reliably writes the Pi-hole adlist output file every run (see `output_file`).
- **Compat:** can also mirror to a legacy path via `legacy_output_symlink` (e.g., `/etc/pihole/custom_autoblocker.txt`).
- **v2.1** improvements retained: numeric `score`, `reason`, review exports (JSON/TSV).

Config: /etc/pihole-autoblocker/config.yml
"""

import json, os, time, subprocess, sqlite3, sys
from datetime import datetime
from pathlib import Path

# ---- Dependencies ----
try:
    import yaml
except ImportError:
    raise SystemExit("Missing dependency: python3-yaml. Install with: sudo apt-get install -y python3-yaml")

# ---- Globals populated at runtime ----
CFG = {}
LEARNED = set()           # auto-learned keywords from adlists
FAMS = set()              # eTLD+1 families with high adlist overlap
CNAME_CACHE = {}          # in-run cache
CNAME_PERSIST = {}        # persistent cache with TTL

# ---- Utils ----
def load_yaml(p):
    with open(p, 'r') as f:
        return yaml.safe_load(f)

def now_ts():
    return int(time.time())

def domain_suffix_in_list(domain: str, suffixes: list[str]) -> bool:
    d = domain.lower().rstrip('.')
    for s in suffixes or []:
        s = (s or "").lower().strip().lstrip('*')
        if not s:
            continue
        if d == s or d.endswith("." + s) or d.endswith(s):
            return True
    return False

def log(path: str, msg: str):
    ts = datetime.now().isoformat(timespec='seconds')
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as f:
        f.write(f"[{ts}] {msg}\n")

def load_json(path: str, default):
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except Exception:
        return default

def save_json(path: str, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True))

# ---- Pi-hole DB access ----
def get_recent_counts_from_ftl(ftl_db: str, lookback_hours: int):
    try:
        conn = sqlite3.connect(ftl_db)
        cur = conn.cursor()
        since = int(time.time()) - lookback_hours * 3600
        cur.execute(
            """
            SELECT domain, COUNT(*) AS hits, COUNT(DISTINCT client) AS uniq
            FROM queries
            WHERE timestamp >= ?
              AND domain NOT NULL
              AND domain != ''
              AND domain NOT LIKE '%.in-addr.arpa'
              AND domain NOT LIKE '%.ip6.arpa'
            GROUP BY domain
            """,
            (since,),
        )
        rows = cur.fetchall()
        conn.close()
        return {d: {"hits": h, "uniq": u} for d, h, u in rows}
    except Exception:
        return {}

def fallback_counts_from_log(lookback_hours: int):
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
        return {k: {"hits": v["hits"], "uniq": len(v["clients"]) } for k, v in counts.items()}
    except Exception:
        return {}

def is_already_blocked_anywhere(domain: str) -> bool:
    """True if blocked by local blacklist (domainlist) or by adlists (gravity)."""
    try:
        conn = sqlite3.connect("/etc/pihole/gravity.db")
        cur = conn.cursor()
        # local blacklist
        cur.execute(
            "SELECT 1 FROM domainlist WHERE domain = ? AND type IN (1,3) AND enabled = 1 LIMIT 1",
            (domain,),
        )
        if cur.fetchone() is not None:
            conn.close(); return True
        # adlists (gravity)
        cur.execute("SELECT 1 FROM gravity WHERE domain = ? LIMIT 1", (domain,))
        hit = cur.fetchone() is not None
        conn.close(); return hit
    except Exception:
        return False

# ---- Heuristics ----
def substr_or_tld_suspicious(domain: str, cfg) -> tuple[bool, list]:
    """Return (is_suspicious, reasons[]) for cheap checks."""
    reasons = []
    d = domain.lower()
    if domain_suffix_in_list(d, cfg.get("allowlist", [])):
        return False, ["allowlist"]
    # static substrings
    for ss in (cfg.get("suspicious_substrings") or []):
        if ss and ss.lower() in d:
            reasons.append(f"substr:{ss}")
            break
    # learned substrings
    if LEARNED:
        for tok in LEARNED:
            if tok in d:
                reasons.append(f"learn:{tok}")
                break
    # suspicious TLDs
    if domain_suffix_in_list(d, cfg.get("suspicious_tlds", [])):
        reasons.append("tld")
    # family reputation by eTLD+1
    parts = d.strip('.').split('.')
    etld1 = ".".join(parts[-2:]) if len(parts) >= 2 else d
    if FAMS and etld1 in FAMS:
        reasons.append(f"fam:{etld1}")
    return (len(reasons) > 0), reasons

def resolve_cname_chain(domain: str, max_depth: int = 0) -> list[str]:
    """Resolve up to max_depth CNAMEs using dig; supports cache-only + persistent cache."""
    if max_depth < 1:
        return []
    d = domain.lower().rstrip('.')
    # persistent cache check
    pc = CNAME_PERSIST.get(d)
    now = now_ts()
    if pc and pc.get('until', 0) > now:
        return pc.get('chain', [])
    if d in CNAME_CACHE:
        return CNAME_CACHE[d]
    chain = []
    current = d
    for _ in range(max_depth):
        try:
            if CFG.get('cname_cache_only', False):
                dig_cmd = ["dig", "@127.0.0.1", "+norecurse", "+time=2", "+tries=0", "+short", current, "CNAME"]
            else:
                dig_cmd = ["dig", "@127.0.0.1", "+short", current, "CNAME"]
            out = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=4)
            lines = [l.strip().rstrip('.') for l in out.stdout.splitlines() if l.strip()]
            if not lines:
                break
            target = lines[0]
            chain.append(target)
            current = target
        except Exception:
            break
    CNAME_CACHE[d] = chain
    # persist with TTL
    ttl = int(CFG.get('cname_cache_ttl_hours', 24)) * 3600
    CNAME_PERSIST[d] = {"chain": chain, "until": now + ttl}
    return chain

def cname_suspicious(domain: str, cfg) -> tuple[bool, list]:
    max_depth = int(cfg.get("cname_max_depth", 0))
    if max_depth < 1:
        return False, []
    reasons = []
    chain = resolve_cname_chain(domain, max_depth)
    for cname in chain:
        if domain_suffix_in_list(cname, cfg.get("allowlist", [])):
            return False, ["cname_allowlist"]
        if any(ss in cname for ss in (cfg.get("suspicious_substrings") or [])):
            reasons.append(f"cname_substr:{cname}")
            break
        if LEARNED and any(tok in cname for tok in LEARNED):
            reasons.append(f"cname_learn:{cname}")
            break
        if domain_suffix_in_list(cname, cfg.get("suspicious_tlds", [])):
            reasons.append(f"cname_tld:{cname}")
            break
        parts = cname.lower().strip('.').split('.')
        etld1 = ".".join(parts[-2:]) if len(parts) >= 2 else cname
        if FAMS and etld1 in FAMS:
            reasons.append(f"cname_fam:{etld1}")
            break
    return (len(reasons) > 0), reasons

# ---- Learned keywords & family reputation ----

def load_persist_cache(cfg):
    path = cfg.get("cname_cache_path")
    if not path:
        return {}
    data = load_json(path, {})
    return data if isinstance(data, dict) else {}

def save_persist_cache(cfg):
    path = cfg.get("cname_cache_path")
    if not path:
        return
    save_json(path, CNAME_PERSIST)

def load_learned_keywords(cfg):
    path = cfg.get("learned_keywords_path")
    if not (cfg.get("auto_learn_keywords") and path):
        return set()
    data = load_json(path, {"keywords": [], "built_at": 0})
    return set(data.get("keywords", []))

def maybe_rebuild_learned_keywords(cfg):
    if not cfg.get("auto_learn_keywords"):
        return
    path = cfg.get("learned_keywords_path")
    ttl = int(cfg.get("learn_refresh_hours", 24)) * 3600
    state = load_json(path, {"keywords": [], "built_at": 0})
    if now_ts() - state.get("built_at", 0) < ttl:
        return
    try:
        conn = sqlite3.connect("/etc/pihole/gravity.db"); cur = conn.cursor()
        cur.execute("SELECT domain FROM gravity")
        rows = [r[0] for r in cur.fetchall()]
        conn.close()
    except Exception:
        return
    from collections import defaultdict
    def etld1(d):
        p = d.lower().strip('.').split('.')
        return ".".join(p[-2:]) if len(p) >= 2 else d
    stop = set((cfg.get("learn_stopwords") or []))
    token_to_etlds = defaultdict(set)
    for dom in rows:
        parts = [x for x in dom.split('.') if x and x not in stop and len(x) >= 3]
        root = etld1(dom)
        for t in parts:
            token_to_etlds[t].add(root)
    min_sup = int(cfg.get("learn_min_support_etlds", 8))
    cand = [t for t, s in token_to_etlds.items() if len(s) >= min_sup]
    cand = sorted(cand, key=lambda t: len(token_to_etlds[t]), reverse=True)
    cand = cand[: int(cfg.get("learn_max_keywords", 200))]
    save_json(path, {"keywords": cand, "built_at": now_ts()})


def build_reputation_families(cfg):
    th = int(cfg.get("family_adlist_threshold", 0))
    if th <= 0:
        return set()
    fams = set()
    try:
        conn = sqlite3.connect("/etc/pihole/gravity.db"); cur = conn.cursor()
        cur.execute("SELECT domain, adlist_id FROM gravity")
        from collections import defaultdict
        counts = defaultdict(set)
        for dom, aid in cur.fetchall():
            parts = dom.lower().strip('.').split('.')
            root = ".".join(parts[-2:]) if len(parts) >= 2 else dom
            counts[root].add(aid)
        conn.close()
        for root, s in counts.items():
            if len(s) >= th:
                fams.add(root)
    except Exception:
        return set()
    return fams

# ---- Extra filters ----

def hours_active_map(ftl_db, lookback_hours):
    try:
        conn = sqlite3.connect(ftl_db); cur = conn.cursor()
        since = int(time.time()) - lookback_hours * 3600
        cur.execute(
            """
            SELECT domain, COUNT(DISTINCT strftime('%Y%m%d%H', datetime(timestamp,'unixepoch'))) AS hrs
            FROM queries
            WHERE timestamp >= ?
            GROUP BY domain
            """,
            (since,),
        )
        out = dict(cur.fetchall()); conn.close(); return out
    except Exception:
        return {}

# ---- Scoring ----

def compute_score(domain: str, metrics: dict, reasons: list[str], cfg) -> float:
    """Combine traffic + heuristic signals into 0..1."""
    hits = float(metrics.get("hits", 0))
    uniq = float(metrics.get("uniq", 0))
    hrs  = float(metrics.get("hours", 0))

    # Normalize with soft saturations
    def norm(x, k):
        # logistic-ish squash around k
        try:
            x = float(x)
        except Exception:
            x = 0.0
        return x / (x + k)

    hN = norm(hits, float(cfg.get("score_hits_k", 20)))
    uN = norm(uniq, float(cfg.get("score_uniq_k", 3)))
    tN = norm(hrs,  float(cfg.get("score_hours_k", 6)))

    # Heuristic boosters
    boost = 0.0
    for r in reasons:
        if r.startswith("substr:"):
            boost += 0.25
        elif r.startswith("learn:"):
            boost += 0.15
        elif r == "tld" or r.startswith("cname_tld"):
            boost += 0.20
        elif r.startswith("fam:") or r.startswith("cname_fam"):
            boost += 0.15
        elif r.startswith("cname_"):
            boost += 0.20
    boost = min(boost, 0.6)

    # Weighted blend
    base = 0.4*hN + 0.3*uN + 0.3*tN
    score = max(0.0, min(1.0, base + boost))
    return float(score)

# ---- Promotions ----

def sql_promote(domain: str, comment: str, group_name: str = "Default") -> bool:
    try:
        conn = sqlite3.connect("/etc/pihole/gravity.db"); cur = conn.cursor()
        row = cur.execute("SELECT id FROM 'group' WHERE name=? AND enabled=1;", (group_name,)).fetchone()
        if not row:
            conn.close(); return False
        gid = row[0]
        cur.execute(
            """
            INSERT INTO domainlist (type,domain,enabled,comment,date_added,date_modified)
            VALUES (1,?,1,?,strftime('%s','now'),strftime('%s','now'))
            """,
            (domain, comment),
        )
        dlid = cur.execute("SELECT id FROM domainlist WHERE domain=? ORDER BY id DESC LIMIT 1;", (domain,)).fetchone()[0]
        cur.execute(
            "INSERT OR IGNORE INTO domainlist_by_group (domainlist_id,group_id) VALUES (?,?)",
            (dlid, gid),
        )
        conn.commit(); conn.close()
        subprocess.run(["pihole", "restartdns", "reload-lists"], capture_output=True, text=True, timeout=20)
        return True
    except Exception:
        return False

def add_to_blacklist(domain: str, cfg) -> bool:
    if cfg.get("sql_promotion", False):
        ok = sql_promote(domain, cfg.get("promotion_comment", "autoblocker"), cfg.get("promotion_group", "Default"))
        if ok:
            return True
    try:
        r = subprocess.run(["pihole", "-b", domain], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False

# ---- Metrics ----
def write_metrics(cfg, cand_count, promo_count):
    path = cfg.get("metrics_path")
    if not path:
        return
    content = (
        f"autoblocker_candidates_total {cand_count}\n"
        f"autoblocker_promoted_total {promo_count}\n"
    )
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)

# ---- Output (adlist file) ----

def gather_promoted_from_db(comment: str) -> set:
    out = set()
    try:
        conn = sqlite3.connect("/etc/pihole/gravity.db"); cur = conn.cursor()
        cur.execute("SELECT domain FROM domainlist WHERE enabled=1 AND type IN (1,3) AND comment=?", (comment,))
        out.update(r[0] for r in cur.fetchall())
        conn.close()
    except Exception:
        pass
    return out

def read_lines(path: str) -> set:
    p = Path(path)
    if not p.exists():
        return set()
    try:
        return set(line.strip() for line in p.read_text().splitlines() if line.strip() and not line.strip().startswith('#'))
    except Exception:
        return set()

def write_output_list(cfg):
    """Compose final blocklist file for Pi-hole adlist ingestion."""
    output_path = cfg.get("output_file", "/etc/pihole/pihole-autoblocker.txt")
    allow_file = cfg.get("allowlist_file", "/etc/pihole/pihole-autoblocker.allow.txt")
    manual_file = cfg.get("manual_block_file", "/etc/pihole/pihole-autoblocker.manual-block.txt")
    promo_comment = cfg.get("promotion_comment", "autoblocker")

    # Sources
    S = set()
    S |= read_lines(manual_file)                     # operator-curated
    S |= gather_promoted_from_db(promo_comment)      # items promoted via SQL path

    # Filter allowlist + sanity
    ALLOW = read_lines(allow_file)
    S = {d for d in S if d and d not in ALLOW}

    # Write sorted unique
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text("".join(sorted(S)) + ("" if S else ""))

    # Optional legacy mirror (symlink)
    legacy = cfg.get("legacy_output_symlink")
    if legacy:
        try:
            lp = Path(legacy)
            if lp.exists() or lp.is_symlink():
                try: lp.unlink()
                except Exception: pass
            lp.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(output_path, legacy)
        except Exception:
            # If symlink fails, best-effort copy
            try:
                Path(legacy).write_text(Path(output_path).read_text())
            except Exception:
                pass

# ---- Main ----

def main():
    global CFG, LEARNED, FAMS, CNAME_PERSIST
    CFG = load_yaml("/etc/pihole-autoblocker/config.yml")

    # Concurrency lock
    try:
        import fcntl
        lockf = open("/var/run/pihole-autoblocker.lock", "w")
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        print("Another instance is running; exiting."); return

    # Paths
    quar_path = CFG.get("quarantine_file")  # dict keyed by domain
    state_path = CFG.get("state_file")
    review_json = CFG.get("quarantine_review_file") or str(Path(quar_path).with_name("quarantine_review.json"))
    review_tsv  = CFG.get("quarantine_tsv_file") or str(Path(quar_path).with_suffix(".tsv"))

    quarantine = load_json(quar_path, {})
    state = load_json(state_path, {"blocked": []})

    # Caches & learned data
    CNAME_PERSIST = load_persist_cache(CFG)
    LEARNED = load_learned_keywords(CFG)
    FAMS = build_reputation_families(CFG)
    maybe_rebuild_learned_keywords(CFG)

    # Domain counts
    lookback = int(CFG.get("lookback_hours", 24))
    counts = get_recent_counts_from_ftl(CFG.get("ftl_db"), lookback)
    if not counts:
        counts = fallback_counts_from_log(lookback)

    # Add hours-active metric
    hrs_map = hours_active_map(CFG.get("ftl_db"), lookback) if counts else {}

    min_hits = int(CFG.get("min_hits", 10))
    min_unique = int(CFG.get("min_unique_clients", 2))
    q_hours = int(CFG.get("quarantine_hours", 12))
    top_n_cname = int(CFG.get("top_n_cname", 200))

    # 1) Thresholds first
    eligible = []
    for d, m in counts.items():
        if m.get("hits",0) >= min_hits and m.get("uniq",0) >= min_unique:
            m["hours"] = hrs_map.get(d, 0)
            eligible.append((d, m))

    # 1b) Temporal diversity
    min_hours = int(CFG.get("min_hours_active", 0))
    if min_hours > 0 and eligible:
        eligible = [(d, m) for d, m in eligible if m.get("hours",0) >= min_hours]

    # 2) Already blocked anywhere?
    eligible = [(d, m) for d, m in eligible if not is_already_blocked_anywhere(d)]

    # 3) Cheap heuristic
    cheap_flags = {}
    candidates = []
    for d, m in eligible:
        sus, reasons = substr_or_tld_suspicious(d, CFG)
        if sus:
            cheap_flags[d] = reasons
            candidates.append((d, m))

    # 4) CNAME only for top-N busiest remaining
    rem = [(d, m) for (d, m) in eligible if d not in cheap_flags]
    rem = sorted(rem, key=lambda x: x[1].get("hits",0), reverse=True)[:top_n_cname]
    for d, m in rem:
        sus, reasons = cname_suspicious(d, CFG)
        if sus:
            cheap_flags[d] = reasons
            candidates.append((d, m))

    # 5) Quarantine update with SCORE & REASON
    now = now_ts()
    for d, m in candidates:
        rlist = cheap_flags.get(d, [])
        score = compute_score(d, m, rlist, CFG)
        entry = quarantine.get(d, {}) if isinstance(quarantine, dict) else {}
        entry.setdefault("first_seen", now)
        entry["last_seen"] = now
        entry["score"] = float(score)
        entry["reason"] = ",".join(sorted(set(rlist))) if rlist else ""
        entry["hits"] = int(m.get("hits",0))
        entry["uniq"] = int(m.get("uniq",0))
        entry["hours"] = int(m.get("hours",0))
        quarantine[d] = entry

    # 6) Promotion
    promoted = []
    dry = CFG.get("dry_run", False)
    promo_min_score = float(CFG.get("promotion_min_score", 0.90))
    for d, meta in list(quarantine.items()):
        # Backward-compat upgrades
        meta["score"] = float(meta.get("score", 0.0))
        meta["reason"] = meta.get("reason", "")

        age_hours = (now - meta.get("first_seen", now)) / 3600.0
        still_candidate = d in dict(candidates)
        if age_hours >= q_hours and still_candidate and meta.get("score",0.0) >= promo_min_score:
            if not is_already_blocked_anywhere(d):
                if dry:
                    log(CFG.get("log_file"), f"[DRYRUN] Would promote: {d} score={meta.get('score'):.3f}")
                else:
                    if add_to_blacklist(d, CFG):
                        promoted.append(d)
                        state.setdefault("blocked", []).append({"domain": d, "ts": now, "score": meta.get("score",0.0)})
            quarantine.pop(d, None)
        elif (now - meta.get("last_seen", now)) > (3 * lookback * 3600):
            quarantine.pop(d, None)  # stale

    # Save main state & caches
    save_json(quar_path, quarantine)
    save_json(state_path, state)
    save_persist_cache(CFG)

    # ---- Review exports (JSON array + TSV) ----
    try:
        items = [
            {
                "domain": d,
                "score": float(v.get("score",0.0)),
                "reason": v.get("reason", ""),
                "first_seen": int(v.get("first_seen", now)),
                "last_seen": int(v.get("last_seen", now)),
                "hits": int(v.get("hits", 0)),
                "uniq": int(v.get("uniq", 0)),
                "hours": int(v.get("hours", 0))
            }
            for d, v in quarantine.items()
        ]
        items.sort(key=lambda x: x.get("score",0.0), reverse=True)
        save_json(review_json, items)
        # TSV
        lines = ["domain	score	reason	first_seen	last_seen	hits	uniq	hours"]
        for it in items:
            lines.append(
                f"{it['domain']}	{it['score']:.3f}	{it['reason']}	{it['first_seen']}	{it['last_seen']}	{it['hits']}	{it['uniq']}	{it['hours']}"
            )
        Path(review_tsv).parent.mkdir(parents=True, exist_ok=True)
        Path(review_tsv).write_text("".join(lines) + "")
        
    except Exception as e:
        log(CFG.get("log_file"), f"Failed to write review exports: {e}")

    # ---- Always (re)write adlist output file ----
    write_output_list(CFG)

    msg = (
        f"Scan complete. Eligible: {len(eligible)}. New/updated quarantined: {len(candidates)}. "
        f"Promoted to blacklist: {len(promoted)}."
    )
    log(CFG.get("log_file"), msg)
    write_metrics(CFG, len(candidates), len(promoted))
    print(msg)

if __name__ == "__main__":
    main()
