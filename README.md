# ShellHunter — WebShell Detection & RCE Verification (Phase 1 + Phase 2)

> "Find, confirm, and document real RCEs — not just hints."

This project automates two phases:

- **Phase 1 – Static Detection** (`shellhunter.py`): scans the codebase, applies heuristics/signatures and produces a `report.json` with candidates.
- **Phase 2 – Dynamic Verification** (`verify_rce.py`): maps Phase-1 file paths to live URLs, fires payloads (including obfuscated variants), detects visible evidence, blind timing, classifies PHP errors, and generates timestamped reports, logs, and artifacts.

![shellhunter](https://raw.githubusercontent.com/LvL23HT/ShellHunter-WebShell-Detection-RCE-Verification/refs/heads/main/banner.gif)

## Layout

```
C:.
|   config.yml
|   endpoints.txt
|   requeriments.txt
|   rules.yml
|   shellhunter.py
|   verify_rce.py
|
\---whitelists
        ignore_hashes.txt
        ignore_paths.txt
```

## Usage
### shellhunter.py

```
python shellhunter.py -h
usage: shellhunter.py [-h] -r ROOTS [ROOTS ...] [--rules RULES] [-o OUT] [--csv CSV] [--ext EXT [EXT ...]] [--exclude [EXCLUDE ...]]
                      [--whitelist-paths WHITELIST_PATHS] [--whitelist-hashes WHITELIST_HASHES] [--threshold THRESHOLD] [--max-size-mb MAX_SIZE_MB]
                      [--max-read-kb MAX_READ_KB] [--workers WORKERS] [--keep-all] [--verbose] [--log-file LOG_FILE] [--stream-findings]

ShellHunter — local webshell scanner (no-RCE) with a progress bar and single status line

options:
  -h, --help            show this help message and exit
  -r ROOTS [ROOTS ...], --roots ROOTS [ROOTS ...]
                        Root directories to scan
  --rules RULES         YAML rules file
  -o OUT, --out OUT     JSON output
  --csv CSV             CSV output
  --ext EXT [EXT ...]   Included extensions
  --exclude [EXCLUDE ...]
                        Exclusion regexes
  --whitelist-paths WHITELIST_PATHS
                        File with regexes (one per line) to ignore paths
  --whitelist-hashes WHITELIST_HASHES
                        File with partial SHA256 hashes (one per line) to ignore
  --threshold THRESHOLD
                        Score threshold for HIGH
  --max-size-mb MAX_SIZE_MB
                        Max file size
  --max-read-kb MAX_READ_KB
                        Bytes to read per file (for speed)
  --workers WORKERS     Threads (I/O bound)
  --keep-all            Keep even score=0
  --verbose             DEBUG logging to console
  --log-file LOG_FILE   Write log to file
  --stream-findings     Print each finding (FOUND/ERROR) on separate lines
```
### verify_rce.py
```
python verify_rce.py -h
usage: verify_rce.py [-h] [--report REPORT] [--map MAP_PATH] [--urls [URLS ...]] [--params [PARAMS ...]] [--methods [METHODS ...]] [--timeout TIMEOUT]
                     [--workers WORKERS] [--out OUT] [--csv CSV] [--verbose] [--headers HEADERS] [--cookie COOKIE] [--risk-min RISK_MIN]
                     [--no-time-based] [--only-http-200] [--aggressive] [--aggr-budget AGGR_BUDGET] [--aggr-max-auth AGGR_MAX_AUTH]
                     [--aggr-max-pass AGGR_MAX_PASS] [--extra-kv EXTRA_KV] [--alt-evidence ALT_EVIDENCE] [--no-datetime] [--log LOG]
                     [--positives-out POSITIVES_OUT] [--positives-csv POSITIVES_CSV] [--save-bodies SAVE_BODIES] [--save-bodies-all]

Verify possible webshell RCE via HTTP requests

options:
  -h, --help            show this help message and exit
  --report REPORT       Phase-1 JSON (report.json)
  --map MAP_PATH        config.yml with mappings root→url_prefix
  --urls [URLS ...]     Additional URLs to test (optional)
  --params [PARAMS ...]
                        Parameter names to try (override)
  --methods [METHODS ...]
                        HTTP methods to try (default GET and POST). Example: --methods GET
  --timeout TIMEOUT
  --workers WORKERS
  --out OUT
  --csv CSV
  --verbose
  --headers HEADERS     Extra headers as JSON (e.g. '{"X-Token":"abc"}')
  --cookie COOKIE       Literal cookie string (e.g. PHPSESSID=abc; other=1)
  --risk-min RISK_MIN   HIGH or MEDIUM (default MEDIUM)
  --no-time-based       Disable timing-based checks
  --only-http-200       Ignore endpoints whose initial status is not 200 (unless name looks like a known shell)
  --aggressive          Enable extra variants (auth/json/multipart + secondary toggles and obfuscated techniques)
  --aggr-budget AGGR_BUDGET
                        Max requests per endpoint in aggressive mode (default 500)
  --aggr-max-auth AGGR_MAX_AUTH
                        Max auth param names to try (default 6)
  --aggr-max-pass AGGR_MAX_PASS
                        Max passwords per auth name (default 8)
  --extra-kv EXTRA_KV   Extra pairs k=v separated by comma (e.g., func=system,ajax=1)
  --alt-evidence ALT_EVIDENCE
                        Extra strings that count as visible evidence if present (comma-separated)
  --no-datetime         Do not append timestamp to output filenames
  --log LOG             Log file (use {ts} to place the timestamp explicitly)
  --positives-out POSITIVES_OUT
                        JSON with positives only (default generated next to --out)
  --positives-csv POSITIVES_CSV
                        CSV with positives only (default generated next to --csv)
  --save-bodies SAVE_BODIES
                        Directory to save HTTP response bodies (positives by default)
  --save-bodies-all     Also save bodies for NO-RCE/ERR (may grow large)
```

## Requirements

- Python 3.9+

```bash
pip install -r requeriments.txt
# or manually:
pip install requests pyyaml tqdm colorama
```

## Configuration

### config.yml (FS path → URL mapping)

Minimal example:

```yaml
mappings:
  - root: "C:\\xampp\\htdocs\\your_patch"
    url_prefix: "http://localhost:8080/your_patch"
```

- **root**: absolute filesystem path where Phase 1 found the files.
- **url_prefix**: HTTP prefix from which those same files are served.

You can define multiple mappings for multiple docroots/vhosts.

## Phase 1 — Static Detection (shellhunter.py)

Run the static scan to build the report:

```bash
python shellhunter.py --rules rules.yml --out report.json --verbose
```

`report.json` should include entries like:

```json
{
  "findings": [
    {"path": "C:\\xampp\\htdocs\\your_patch\\webshell.php", "risk": "HIGH"},
    {"path": "C:\\...\\testshell.php", "risk": "MEDIUM"}
  ]
}
```

Use `whitelists/ignore_paths.txt` and `whitelists/ignore_hashes.txt` to filter Phase-1 false positives.

## Phase 2 — Dynamic Verification (verify_rce.py)

Confirms real RCE by interacting with endpoints.

### Quick examples

#### With Phase 1 + mapping

```bash
python verify_rce.py \
  --report report.json \
  --map config.yml \
  --verbose
```

#### With explicit URLs (no Phase 1)

```bash
# Windows:
python verify_rce.py --urls $(type endpoints.txt) --verbose
# Linux/Mac:
python verify_rce.py --urls $(cat endpoints.txt) --verbose
```

#### "Epic" verification: aggressive, alt-evidence, save bodies, timestamped outputs

```bash
python verify_rce.py \
  --report report.json --map config.yml \
  --methods GET POST --timeout 10 --workers 16 \
  --aggressive --aggr-budget 500 \
  --alt-evidence "SAFE_TEST_OBF_HOT,SAFE_TEST_INCLUDE_USER" \
  --save-bodies out/bodies --save-bodies-all \
  --out out/rce_verified.json --csv out/rce_verified.csv \
  --log out/verify.log \
  --verbose
```

### What it detects

- **Visible evidence**: appearance of the canary token (e.g., `SHCANARY_abcd1234`) or any alt-evidence you define.
- **Blind timing**: ~5s delay over baseline (Linux: `sleep 5`; Windows: `ping -n 6 127.0.0.1`).
- **Informative PHP errors**: classified and included in evidence (e.g., `php_error:php8_incompat`, `php_error:parse_error`) — great to explain "why it didn't pop."

### Outputs (automatic timestamp)

By default, filenames receive `_{YYYYMMDD_HHMMSS}` (disable with `--no-datetime`).

- **Full JSON**: `rce_verified_{ts}.json`
- **Full CSV**: `rce_verified_{ts}.csv`
- **Positives only**:
  - JSON: `rce_verified_{ts}_positives.json`
  - CSV: `rce_verified_{ts}_positives.csv`
- **Log**: `rce_verified_{ts}.log` (or path from `--log`)
- **Bodies (HTML)**: folder from `--save-bodies`

By default, saves positives only.
With `--save-bodies-all`, it also saves `NO-RCE` and `ERR` (watch disk usage).

## CLI Reference (verify_rce.py)

### Input / discovery

| Option | Description |
|--------|-------------|
| `--report PATH` | Phase-1 JSON with `findings[].path` and `risk`. |
| `--map PATH` | `config.yml` with `mappings[].root` → `url_prefix` (requires pyyaml). |
| `--urls URL ...` | List of URLs to verify manually (skip Phase 1). |
| `--risk-min LEVEL` | Filter Phase-1 candidates: `HIGH` or `MEDIUM` (default `MEDIUM`). |

### Attacks & variants

| Option | Description |
|--------|-------------|
| `--params P ...` | Override params to try. Default: `cmd,c,exec,command,run,shell,q,s,action,do,code,payload,p,x,a,b,u,file,include,f,user,page,path,tpl,template,module,data,tmpl`. |
| `--methods GET POST` | HTTP methods to use (default: both). |
| `--no-time-based` | Disable ~5s timing test. |
| `--aggressive` | Extra variants: auth (pass/password/key... + small wordlist), multipart/json, secondary flags (func=system, ajax=1, etc.), base64, and include php://input. |
| `--aggr-budget N` | Max requests per endpoint in aggressive mode (default: 500). |
| `--aggr-max-auth N` | Number of auth param names to try (default: 6). |
| `--aggr-max-pass N` | Passwords per auth name (default: 8). |
| `--extra-kv "k1=v1,k2=v2"` | Extra k/v pairs added to every request (helpful to "unlock" branches). |
| `--alt-evidence "A,B,C"` | Strings that count as visible evidence if present in the response (including baseline). Useful for test pages with known banners. |

### Network & headers

| Option | Description |
|--------|-------------|
| `--headers JSON` | Extra headers (e.g., `'{"X-Token":"abc"}'`). |
| `--cookie "k=v; a=b"` | Literal cookies. |
| `--timeout N` | Per-request timeout (default: 10s). |
| `--workers N` | Concurrency (default: 16). |
| `--only-http-200` | Ignore endpoints whose initial status is not 200 (except if the name looks like a known shell: r57, c99, wso, …). |

### Outputs, logging & naming

| Option | Description |
|--------|-------------|
| `--out PATH` | Full JSON (timestamp added unless `--no-datetime`). |
| `--csv PATH` | Full CSV (timestamp added unless `--no-datetime`). |
| `--positives-out PATH` | Positives-only JSON (default: `<out>_positives.json`). |
| `--positives-csv PATH` | Positives-only CSV (default: `<csv>_positives.csv`). |
| `--log PATH` | Log path (default: `<out_basename>.log`). Accepts `{ts}`. |
| `--save-bodies DIR` | Folder to save HTML bodies. Accepts `{ts}`. |
| `--save-bodies-all` | Save bodies for `NO-RCE` and `ERR` as well. |
| `--no-datetime` | Don't append timestamp to filenames. |
| `--verbose` | Verbose mode (per-URL summary + hints). |

## Result formats

### CSV

```csv
url,rce,method,param,os,evidence,status_code,elapsed,error
http://.../webshell.php,True,GET,cmd,win,token:SHCANARY_xxxx visible,200,0.08,
...
```

### JSON

Each entry includes everything from the CSV plus `resp_text` (when captured) — handy if you enabled `--save-bodies`.

## Best practices & recipes

- **Nail the mapping** (`config.yml`). If you see a lot of 403/404/301/302, your `url_prefix`/base path likely doesn't match. The verifier prints hints automatically.

- **Cookies/Headers**: use `--cookie` / `--headers` for sessions or tokens.

- **Param-specific shells**: some shells require a specific name (`cmd`, `p`, etc.). Use `--params cmd` to force it.

- **alt-evidence**: if your test pages print a unique banner (e.g., `SAFE_TEST_INCLUDE_USER`), pass it via `--alt-evidence "SAFE_TEST_INCLUDE_USER"`. If it appears in the baseline (no params), it still counts.

- **PHP errors**: `php_error:*` in evidence often explains non-exploitation (PHP 8 incompat, disabled functions, …).

- **Blind timing**: when a WAF strips echo, blind timing may be your only confirmation (delay ~5s over baseline).

## Concrete examples

### 1) Minimal with a single URL

```bash
python verify_rce.py --urls http://localhost:8080/your_patch/webshell.php --verbose
```

### 2) With session + custom header

```bash
python verify_rce.py \
  --report report.json --map config.yml \
  --cookie "PHPSESSID=abc123; role=admin" \
  --headers '{"X-Auth":"mytoken"}' \
  --verbose
```

### 3) Force param and go aggressive

```bash
python verify_rce.py \
  --urls http://localhost:8080/your_patch/shell.php \
  --params cmd \
  --aggressive --aggr-budget 300 \
  --verbose
```

### 4) Save all response bodies

```bash
python verify_rce.py \
  --report report.json --map config.yml \
  --save-bodies out/bodies --save-bodies-all \
  --verbose
```

## Troubleshooting (FAQ)

**"Everything is 403/404/301/302"**
Check `config.yml` (`url_prefix`), use `--cookie`/`--headers` to authenticate, and verify the server actually serves that path.

**"r57/c99 doesn't run on PHP 8"**
You'll see `php_error:php8_incompat`. Try `--aggressive` and `--extra-kv` to "unlock" branches; if the code is broken, there won't be RCE.

**"My sample prints something without params, but no token"**
Add that string with `--alt-evidence "MY_BANNER"`. Baseline matches count too.

**"Blind timing doesn't trigger"**
Ensure timing is enabled (don't pass `--no-time-based`). Very low baseline latency might require repeated attempts.

**"I need to see the exact server reply"**
Use `--save-bodies` (and maybe `--save-bodies-all`). Positives also include `resp_text` in JSON.

## Safety & legal

This tool is for authorized security testing only. Make sure you have explicit written permission. Misuse is the operator's responsibility.

## Roadmap (ideas)

- Proxy support and basic/NTLM auth.
- Tech-specific payloads (ASP/JSP).
- WAF-evasion payload mutation engine.
- Add Rules

## Credits

Inspired by classic signatures (r57, c99, wso…) and static scanning tools.
Thanks to the FOSS projects that made this possible.

-- by dEEpEst _ Hack Tools Dark Community --
