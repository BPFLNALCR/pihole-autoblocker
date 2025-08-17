#!/usr/bin/env python3
"""
Interactive reviewer for Pi-hole Autoblocker quarantine.

Features
- Reads /etc/pihole-autoblocker/config.yml
- Loads JSON review (sorted) or falls back to quarantine.json and converts
- Lists candidates with score/reason/hits/uniq/hours
- Selection options: indexes, ranges (e.g., 0 1 5-10), regex filter, or fzf if installed
- Actions: promote to manual blocklist (default) or release to allowlist
- Can auto-promote by minimum score
- Triggers pihole-autoblocker systemd service after changes (so output file regenerates)

Usage examples
  # quick view top 20
  pihole-autoblocker-review.py --top 20

  # interactively select with built-in prompt
  pihole-autoblocker-review.py --interactive

  # use fzf multi-select if installed
  pihole-autoblocker-review.py --fzf

  # promote all with score >= 0.95
  pihole-autoblocker-review.py --promote-score 0.95

  # release (whitelist) specific domains
  pihole-autoblocker-review.py --release domains.txt

Requirements
- Python 3.7+
- jq/fzf NOT required (optional for --fzf mode only)
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from pathlib import Path
from typing import List, Dict, Any

try:
    import yaml
except ImportError:
    print("python3-yaml is required. Install: sudo apt-get install -y python3-yaml", file=sys.stderr)
    sys.exit(1)

CONFIG_PATH = "/etc/pihole-autoblocker/config.yml"

# ---------- helpers ----------

def load_cfg(path: str = CONFIG_PATH) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}

def derive_paths(cfg: dict) -> dict:
    # Main quarantine dict file (legacy structure)
    qfile = cfg.get("quarantine_file") or "/var/lib/pihole-autoblocker/quarantine.json"
    # Preferred sorted review array
    review = cfg.get("quarantine_review_file")
    if not review:
        p = Path(qfile)
        review = str(p.with_name("quarantine_review.json"))
    # Operator files
    out = {
        "review": review,
        "qfile": qfile,
        "manual": cfg.get("manual_block_file", "/etc/pihole/pihole-autoblocker.manual-block.txt"),
        "allow": cfg.get("allowlist_file", "/etc/pihole/pihole-autoblocker.allow.txt"),
        "log": cfg.get("log_file", "/var/log/pihole-autoblocker.log"),
        "service": cfg.get("systemd_unit", "pihole-autoblocker.service"),
        "promo_comment": cfg.get("promotion_comment", "autoblocker"),
        "sql_promotion": bool(cfg.get("sql_promotion", False)),
    }
    return out


def load_review(paths: dict) -> List[Dict[str, Any]]:
    rp = Path(paths["review"])  # array sorted by score
    if rp.exists():
        try:
            data = json.loads(rp.read_text())
            if isinstance(data, list):
                return data
        except Exception:
            pass
    # fall back: convert dict to array
    qp = Path(paths["qfile"])  # dict keyed by domain
    if qp.exists():
        try:
            raw = json.loads(qp.read_text())
            if isinstance(raw, dict):
                items = []
                for d, v in raw.items():
                    items.append({
                        "domain": d,
                        "score": float(v.get("score", 0.0)),
                        "reason": v.get("reason", ""),
                        "first_seen": int(v.get("first_seen", 0)),
                        "last_seen": int(v.get("last_seen", 0)),
                        "hits": int(v.get("hits", 0)),
                        "uniq": int(v.get("uniq", 0)),
                        "hours": int(v.get("hours", 0)),
                    })
                items.sort(key=lambda x: x.get("score", 0.0), reverse=True)
                return items
        except Exception:
            pass
    return []


def print_table(items: List[Dict[str, Any]], limit: int | None = None):
    from math import ceil
    rows = items if limit is None else items[:limit]
    print(f"idx  score   hits uniq hrs   domain                                 reason")
    print("-"*100)
    for i, it in enumerate(rows):
        score = f"{float(it.get('score',0.0)):.3f}"
        hits = str(it.get('hits',0))
        uniq = str(it.get('uniq',0))
        hrs  = str(it.get('hours',0))
        dom = it.get('domain','')[:35]
        rsn = it.get('reason','')[:40]
        print(f"{i:>3}  {score:>6}  {hits:>4} {uniq:>4} {hrs:>3}   {dom:<35}  {rsn}")


def has_fzf() -> bool:
    return shutil.which("fzf") is not None


def choose_indices(items: List[Dict[str, Any]]) -> List[int]:
    """Interactive selection without external deps."""
    print_table(items, limit=50)
    print("\nSelect items by index (e.g., '0 2 5-9 /regex/'). Empty to cancel.")
    s = input("> ").strip()
    if not s:
        return []
    sel: List[int] = []
    tokens = s.split()
    for t in tokens:
        if t.startswith("/") and t.endswith("/"):
            pat = re.compile(t[1:-1])
            for idx, it in enumerate(items):
                if pat.search(it.get("domain","")):
                    sel.append(idx)
        elif "-" in t:
            a,b = t.split("-",1)
            try:
                a=int(a); b=int(b)
                sel.extend(list(range(min(a,b), max(a,b)+1)))
            except ValueError:
                pass
        else:
            try:
                sel.append(int(t))
            except ValueError:
                pass
    sel = [i for i in sorted(set(sel)) if 0 <= i < len(items)]
    return sel


def choose_with_fzf(items: List[Dict[str, Any]]) -> List[int]:
    import shutil, subprocess
    if shutil.which("fzf") is None:
        print("fzf not found; falling back to prompt.")
        return choose_indices(items)
    lines = []
    for i,it in enumerate(items):
        lines.append(f"{i}\t{it.get('score',0.0):.3f}\t{it.get('hits',0)}\t{it.get('uniq',0)}\t{it.get('hours',0)}\t{it.get('domain','')}\t{it.get('reason','')}")
    proc = subprocess.run(["fzf","--multi","--with-nth","2..","--prompt","promote> "], input="\n".join(lines), text=True, capture_output=True)
    if proc.returncode != 0:
        return []
    sel = []
    for line in proc.stdout.splitlines():
        try:
            idx = int(line.split("\t",1)[0])
            sel.append(idx)
        except Exception:
            pass
    return sorted(set(sel))


def write_lines(path: str, domains: List[str]):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        for d in domains:
            f.write(d.strip()+"\n")


def promote_sql(domains: List[str], comment: str) -> int:
    ok = 0
    for d in domains:
        try:
            subprocess.run([
                "sqlite3","/etc/pihole/gravity.db",
                "INSERT INTO domainlist (type,domain,enabled,comment,date_added,date_modified) VALUES (1,?,1,?,strftime('%s','now'),strftime('%s','now'));",
                ], input=f"{d}\n{comment}\n", text=True, check=False, capture_output=True)
            ok += 1
        except Exception:
            pass
    try:
        subprocess.run(["pihole","restartdns","reload-lists"], check=False)
    except Exception:
        pass
    return ok


def trigger_service(unit: str):
    try:
        subprocess.run(["systemctl","start", unit], check=False)
    except Exception:
        pass

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Review and promote quarantined domains.")
    ap.add_argument("--top", type=int, default=0, help="Show top N and exit")
    ap.add_argument("--interactive", action="store_true", help="Prompt to select entries for promotion")
    ap.add_argument("--fzf", action="store_true", help="Use fzf for multi-select if installed")
    ap.add_argument("--promote-score", type=float, default=None, help="Promote all items with score >= threshold")
    ap.add_argument("--release", type=str, default=None, help="Whitelist domains from a file (one per line)")
    args = ap.parse_args()

    cfg = load_cfg()
    paths = derive_paths(cfg)
    items = load_review(paths)

    if args.top:
        print_table(items, limit=args.top)
        return

    if args.release:
        domains = [d.strip() for d in Path(args.release).read_text().splitlines() if d.strip()]
        write_lines(paths["allow"], domains)
        trigger_service(paths["service"])  # regenerates output file
        print(f"Released {len(domains)} domains to allowlist → {paths['allow']}")
        return

    targets: List[str] = []

    if args.promote_score is not None:
        thr = float(args.promote_score)
        targets = [it["domain"] for it in items if float(it.get("score",0.0)) >= thr]
    elif args.fzf:
        idxs = choose_with_fzf(items)
        targets = [items[i]["domain"] for i in idxs]
    elif args.interactive:
        idxs = choose_indices(items)
        targets = [items[i]["domain"] for i in idxs]
    else:
        # default to interactive if no action specified
        idxs = choose_indices(items)
        targets = [items[i]["domain"] for i in idxs]

    if not targets:
        print("No selections. Nothing to do.")
        return

    # dedupe
    targets = sorted(set([d.strip() for d in targets if d.strip()]))

    # Prefer manual block file (operator-curated); optionally also SQL insert
    write_lines(paths["manual"], targets)
    inserted = 0
    if paths["sql_promotion"]:
        inserted = promote_sql(targets, paths["promo_comment"])

    trigger_service(paths["service"])  # will regenerate output list

    print(f"Promoted {len(targets)} domains → {paths['manual']}{' and SQL' if inserted else ''}.")

if __name__ == "__main__":
    main()
