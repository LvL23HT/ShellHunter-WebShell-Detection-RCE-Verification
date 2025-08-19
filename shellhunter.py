#!/usr/bin/env python3
import os, re, sys, math, json, csv, hashlib, logging, time
from pathlib import Path, PurePath
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

# --- deps check ---
try:
    import yaml  # pyyaml
except ImportError:
    print("Install pyyaml: pip install pyyaml"); sys.exit(1)
try:
    from tqdm import tqdm
except ImportError:
    print("Install tqdm: pip install tqdm"); sys.exit(1)
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    print("Install colorama: pip install colorama"); sys.exit(1)

# ======== Colors / progress bar formatting (cosmetic) ========
BAR_LEFT = f"{Style.BRIGHT}{Fore.CYAN}Scanning{Style.RESET_ALL} "
BAR_SEP  = f"{Fore.CYAN}|{Style.RESET_ALL}"
BAR_FORMAT = (
    f"{BAR_LEFT}"
    "{percentage:3.0f}%{bar} "
    f"{BAR_SEP} "
    "{n_fmt}/{total_fmt} • {rate_fmt} • {postfix}"
)

def c_high(x):  return f"{Style.BRIGHT}{Fore.RED}{x}{Style.RESET_ALL}"
def c_med(x):   return f"{Fore.YELLOW}{x}{Style.RESET_ALL}"
def c_ok(x):    return f"{Fore.GREEN}{x}{Style.RESET_ALL}"
def c_err(x):   return f"{Style.DIM}{Fore.RED}{x}{Style.RESET_ALL}"
def c_igno(x):  return f"{Fore.BLUE}{x}{Style.RESET_ALL}"
def c_last(x):  return f"{Style.DIM}{x}{Style.RESET_ALL}"

def color_evt(evt_text: str) -> str:
    t = (evt_text or "").lower()
    if "error" in t:
        return c_err(evt_text)
    if "high" in t:
        return c_high(evt_text)
    if "med" in t:
        return c_med(evt_text)
    if "ignored" in t:
        return c_igno(evt_text)
    if "ok" in t:
        return c_ok(evt_text)
    return evt_text

# =============== Logging =================
class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Style.DIM,
        logging.INFO: Fore.CYAN,
        logging.WARNING: Fore.YELLOW,    # [FOUND]
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }
    def format(self, record):
        base = super().format(record)
        color = self.COLORS.get(record.levelno, "")
        reset = Style.RESET_ALL
        return f"{color}{base}{reset}"

def setup_logging(verbose: bool, log_file: str | None):
    lvl = logging.DEBUG if verbose else logging.INFO
    fmt = "[%(levelname)s] %(asctime)s | %(message)s"
    datefmt = "%H:%M:%S"

    handlers = []
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(lvl)
    sh.setFormatter(ColorFormatter(fmt, datefmt))
    handlers.append(sh)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(lvl)
        fh.setFormatter(logging.Formatter(fmt, datefmt))
        handlers.append(fh)

    root = logging.getLogger()
    root.setLevel(lvl)
    root.handlers = handlers

log = logging.getLogger("shellhunter")

# =============== Utils ===================
def read_text_sample(path: Path, max_bytes: int) -> str:
    try:
        with path.open("rb") as f:
            buf = f.read(max_bytes)
        return buf.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def file_sha256_partial(path: Path, max_mb=5) -> str:
    h = hashlib.sha256()
    max_bytes = max_mb * 1024 * 1024
    total = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk); total += len(chunk)
            if total >= max_bytes: break
    return h.hexdigest()

def shannon_entropy(s: str, limit=4000) -> float:
    if not s: return 0.0
    s = s[:limit]
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def load_list_file(path: Path):
    if not path or not path.exists(): return set()
    lines = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"): continue
        lines.append(ln)
    return set(lines)

def truncate_middle(s: str, width: int = 60) -> str:
    if len(s) <= width: return s
    half = (width - 3) // 2
    return s[:half] + "..." + s[-half:]

# =============== Rule Engine ===============
class Rule:
    def __init__(self, rid, weight=1, when_ext=None, any_regex=None, entropy=None, recent_days=None):
        self.id = rid
        self.weight = weight
        self.when_ext = [e.lower() for e in (when_ext or [])]
        self.regexes = [re.compile(p) for p in (any_regex or [])]
        self.entropy_min = (entropy or {}).get("min")
        self.recent_days = recent_days

    def applies_to(self, path: Path) -> bool:
        if not self.when_ext: return True
        return path.suffix.lower() in self.when_ext

    def eval(self, path: Path, text: str, mtime: float):
        hits = []
        matched = False
        for r in self.regexes:
            if r.search(text):
                hits.append(f"regex:{r.pattern[:40]}…")
                matched = True
                break
        if self.entropy_min is not None:
            ent = shannon_entropy(text)
            if ent >= self.entropy_min:
                hits.append(f"entropy:{ent:.2f}")
                matched = True
        if self.recent_days:
            if datetime.fromtimestamp(mtime) >= datetime.now() - timedelta(days=self.recent_days):
                hits.append(f"recent:{self.recent_days}d")
                matched = True
        return matched, hits

class RuleEngine:
    def __init__(self, rules):
        self.rules = rules

    @classmethod
    def from_yaml(cls, path: Path):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules = []
        for r in data.get("rules", []):
            rules.append(Rule(
                rid=r.get("id","unnamed"),
                weight=int(r.get("weight",1)),
                when_ext=r.get("when_ext"),
                any_regex=r.get("any_regex"),
                entropy=r.get("entropy"),
                recent_days=r.get("recent_days"),
            ))
        return cls(rules)

    def score_file(self, path: Path, text: str, mtime: float):
        total = 0
        all_hits = []
        for rule in self.rules:
            if not rule.applies_to(path): continue
            ok, hits = rule.eval(path, text, mtime)
            if ok:
                total += rule.weight
                all_hits.extend(hits)
        seen = set(); dedup = []
        for h in all_hits:
            if h in seen: continue
            seen.add(h); dedup.append(h)
        return total, dedup

# =============== Scan =====================
def should_skip(path: Path, excludes_regex, whitelist_paths_regex):
    sp = str(path)
    for rx in excludes_regex:
        if rx.search(sp): return True
    for rx in whitelist_paths_regex:
        if rx.search(sp): return True
    return False

def scan_file(task):
    path, engine, args, ignore_hashes, max_read_bytes = task
    try:
        st = path.stat()
        size = st.st_size
        if size > args.max_size_mb * 1024 * 1024:
            return None

        sha = file_sha256_partial(path, max_mb=min(args.max_size_mb, 5))
        if sha in ignore_hashes:
            return {"risk": "IGNORED"}

        text = read_text_sample(path, max_read_bytes)
        score, hits = engine.score_file(path, text, st.st_mtime)

        risk = "HIGH" if score >= args.threshold else ("MEDIUM" if score >= max(1, args.threshold-1) else "LOW")
        row = {
            "path": str(path),
            "size": size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "sha256_partial": sha,
            "score": score,
            "risk": risk,
            "hits": ",".join(hits),
        }
        return row
    except Exception as e:
        return {
            "path": str(path),
            "size": "",
            "mtime": "",
            "sha256_partial": "",
            "score": -1,
            "risk": "ERROR",
            "hits": f"error:{e}",
        }

def main():
    ap = argparse.ArgumentParser(description="ShellHunter — local webshell scanner (no-RCE) with a progress bar and single status line")
    ap.add_argument("-r","--roots", nargs="+", required=True, help="Root directories to scan")
    ap.add_argument("--rules", default="rules.yml", help="YAML rules file")
    ap.add_argument("-o","--out", default="shellhunter.json", help="JSON output")
    ap.add_argument("--csv", default="shellhunter.csv", help="CSV output")
    ap.add_argument("--ext", nargs="+", default=[".php",".phtml",".php5",".inc",".asp",".aspx",".jsp",".jspx",".js"], help="Included extensions")
    ap.add_argument("--exclude", nargs="*", default=[r"/wp-includes/", r"/wp-admin/", r"/vendor/", r"/node_modules/", r"/cache/"], help="Exclusion regexes")
    ap.add_argument("--whitelist-paths", type=str, default="", help="File with regexes (one per line) to ignore paths")
    ap.add_argument("--whitelist-hashes", type=str, default="", help="File with partial SHA256 hashes (one per line) to ignore")
    ap.add_argument("--threshold", type=int, default=3, help="Score threshold for HIGH")
    ap.add_argument("--max-size-mb", type=int, default=8, help="Max file size")
    ap.add_argument("--max-read-kb", type=int, default=512, help="Bytes to read per file (for speed)")
    ap.add_argument("--workers", type=int, default=16, help="Threads (I/O bound)")
    ap.add_argument("--keep-all", action="store_true", help="Keep even score=0")
    ap.add_argument("--verbose", action="store_true", help="DEBUG logging to console")
    ap.add_argument("--log-file", type=str, default="", help="Write log to file")
    ap.add_argument("--stream-findings", action="store_true", help="Print each finding (FOUND/ERROR) on separate lines")
    args = ap.parse_args()

    setup_logging(args.verbose, args.log_file or None)

    # Load rules
    rules_path = Path(args.rules)
    try:
        engine = RuleEngine.from_yaml(rules_path)
    except Exception as e:
        log.error(f"Could not load rules '{rules_path}': {e}")
        sys.exit(1)
    log.info(f"Loaded {len(engine.rules)} rules from {rules_path}")

    # Excludes & whitelists
    excludes_regex = [re.compile(p) for p in args.exclude]
    whitelist_paths = load_list_file(Path(args.whitelist_paths)) if args.whitelist_paths else set()
    whitelist_paths_regex = [re.compile(p) for p in whitelist_paths]
    ignore_hashes = load_list_file(Path(args.whitelist_hashes)) if args.whitelist_hashes else set()

    # Build tasks
    start = time.time()
    tasks = []
    max_read_bytes = args.max_read_kb * 1024
    exts = {e.lower() for e in args.ext}
    for root in args.roots:
        rp = Path(root)
        if not rp.exists():
            log.warning(f"Does not exist: {root}")
            continue
        for p in rp.rglob("*"):
            if not p.is_file(): continue
            if p.suffix.lower() not in exts: continue
            if should_skip(p, excludes_regex, whitelist_paths_regex): continue
            tasks.append((p, engine, args, ignore_hashes, max_read_bytes))

    total = len(tasks)
    if total == 0:
        log.info("No candidate files. Check paths/extensions/exclusions.")
        sys.exit(0)

    log.info(f"Scanning {total} files (workers={args.workers}, threshold={args.threshold}, max_read_kb={args.max_read_kb})")

    results = []
    highs = meds = errs = oks = ignored = 0
    last_seen = ""
    last_event = ""

    with ThreadPoolExecutor(max_workers=max(4, args.workers)) as ex:
        futs = [ex.submit(scan_file, t) for t in tasks]
        with tqdm(
            total=total,
            desc="",              # use colored title in BAR_FORMAT
            unit="file",
            dynamic_ncols=True,
            leave=True,
            bar_format=BAR_FORMAT,
            colour="cyan",
        ) as pbar:
            for fut in as_completed(futs):
                row = fut.result()
                if row:
                    results.append(row)
                    risk = row.get("risk", "LOW")
                    if risk == "HIGH":
                        highs += 1
                        last_event = f"FOUND HIGH score={row['score']} {truncate_middle(row['path'])}"
                        if args.stream_findings:
                            log.warning(f"[FOUND] HIGH score={row['score']} file={row['path']} hits={row['hits']}")
                    elif risk == "MEDIUM":
                        meds += 1
                        last_event = f"FOUND MED score={row['score']} {truncate_middle(row['path'])}"
                        if args.stream_findings:
                            log.warning(f"[FOUND] MEDIUM score={row['score']} file={row['path']} hits={row['hits']}")
                    elif risk == "ERROR":
                        errs += 1
                        last_event = f"ERROR {truncate_middle(row.get('hits',''))}"
                        if args.stream_findings:
                            log.error(f"[ERROR] {row.get('path','')} -> {row.get('hits','')}")
                    elif risk == "IGNORED":
                        ignored += 1
                        last_event = "IGNORED (whitelist hash)"
                    else:
                        oks += 1
                        # no log for OK

                    last_seen = truncate_middle(str(PurePath(row.get("path","")).as_posix()), 60)

                # update progress bar
                pbar.update(1)
                post = (
                    f"last={c_last(last_seen)} "
                    f"{Fore.CYAN}•{Style.RESET_ALL} H:{c_high(highs)} "
                    f"M:{c_med(meds)} O:{c_ok(oks)} E:{c_err(errs)} I:{c_igno(ignored)} "
                    f"{Fore.CYAN}•{Style.RESET_ALL} evt: {color_evt(truncate_middle(last_event, 60))}"
                )
                pbar.set_postfix_str(post, refresh=False)

    # sort by risk/score for outputs
    results.sort(key=lambda r: (0 if r["risk"]=="HIGH" else (1 if r["risk"]=="MEDIUM" else (3 if r["risk"]=="ERROR" else 2)), -int(r.get("score",0))))

    # outputs
    Path(args.out).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["path","size","mtime","sha256_partial","score","risk","hits"])
        w.writeheader()
        for r in results:
            if r.get("risk") == "IGNORED":  # lacks full fields
                continue
            w.writerow(r)

    dur = time.time() - start
    log.info(f"Completed in {dur:.1f}s — HIGH:{highs} MEDIUM:{meds} OK:{oks} ERR:{errs} IGNORED:{ignored} — JSON:{args.out} CSV:{args.csv}")

if __name__ == "__main__":
    main()

