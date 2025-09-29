#!/usr/bin/env python3
"""
A tiny Flask dashboard to run scans and visualize results.
- GET / -> show latest results (from latest_scan.json)
- POST /scan -> trigger a new scan (async) against a configured URL

Usage:
  set START_URL (env var) or edit the DEFAULT_START_URL below
  python dashboard.py
"""
import os, json, threading, asyncio, csv, time, re
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, jsonify
import aiohttp  # Add this near other imports

# Import scanner from app.py
from app import AsyncSQLiScanner

DEFAULT_START_URL = os.environ.get("START_URL", "http://localhost:8000")

app = Flask(__name__)

# Global scan status and a dedicated asyncio loop in a worker thread
scan_in_progress = False
_worker_loop = None
_worker_thread = None

progress_state = {
    'crawled': 0,
    'queue': 0,
    'findings': 0
}

# Aggregate metrics for enhanced summary
scan_metrics = {
  'errors_total': 0,
  'errors_by_type': {},      # e.g., {'http_4xx': 3, 'http_5xx': 1, 'timeout': 2, 'network': 1}
  'status_counts': {},       # e.g., {'404': 2, '500': 1}
  'risk_counts': {},         # e.g., {'Critical': 1, 'High': 4, 'Medium': 2}
  'technique_counts': {},    # e.g., {'error-based': 5, 'boolean-blind': 2}
}

def _ensure_worker_loop():
  global _worker_loop, _worker_thread
  if _worker_loop and _worker_thread and _worker_thread.is_alive():
    return _worker_loop
  _worker_loop = asyncio.new_event_loop()
  def _runner(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()
  _worker_thread = threading.Thread(target=_runner, args=(_worker_loop,), daemon=True)
  _worker_thread.start()
  return _worker_loop

def _suggest_fix(technique: str) -> str:
  tech = (technique or "").lower()
  if "error" in tech:
    return (
      "Use prepared statements/parameterized queries. Do not concatenate input. "
      "Validate inputs. Disable detailed DB errors in production; log server-side."
    )
  if "boolean" in tech:
    return (
      "Use parameterized queries and strict input validation (whitelists). "
      "Apply least-privilege DB accounts and normalize responses for invalid conditions."
    )
  if "union" in tech:
    return (
      "Use bound parameters; cast/validate inputs to expected types. Restrict selectable columns."
    )
  return "Use parameterized queries and input validation; avoid string concatenation."

def _enrich_result(r: dict):
  out = dict(r)
  out["solution"] = _suggest_fix(r.get("technique", ""))
  return out

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SQLi Scanner Dashboard</title>
  <style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1220;color:#d6e1ff;margin:0}
  header{padding:16px 24px;border-bottom:1px solid #1c2545;background:#0d1430}
  h1{margin:0;font-size:20px}
  .container{max-width:1100px;margin:24px auto;padding:0 16px}
  .card{background:#0e1a40;border:1px solid #203063;border-radius:10px;padding:16px;margin-bottom:16px}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px 10px;border-bottom:1px solid #203063;text-align:left}
  .btn{background:#4c6fff;border:0;color:white;padding:8px 12px;border-radius:8px;text-decoration:none;cursor:pointer}
  .btn[disabled]{opacity:.5;cursor:not-allowed}
  input[type=text]{background:#0b1736;border:1px solid #203063;color:#d6e1ff;border-radius:8px;padding:8px 10px;width:360px}
  code{color:#f6d365}
  /* Severity colors (enabled when .colors-on is present on body) */
  .colors-on tr.sev-critical{background:rgba(255,77,77,0.15)}
  .colors-on tr.sev-high{background:rgba(255,165,0,0.12)}
  .colors-on tr.sev-medium{background:rgba(255,255,0,0.08)}
  .codebox{background:#0b1736;border:1px dashed #324b96;border-radius:8px;padding:8px;white-space:pre-wrap;color:#b8c7ff;margin-top:6px}
  .toast{position:fixed;right:16px;bottom:16px;background:#203063;color:#fff;padding:10px 14px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.3);opacity:0;transform:translateY(8px);transition:all .25s}
  .toast.show{opacity:1;transform:translateY(0)}
  .toast.success{background:#1f6f43}
  .toast.warn{background:#8a6d3b}
  .toast.error{background:#8b2f2f}
  .loading{display:flex;align-items:center;gap:8px;margin-top:6px}
  .spinner{width:14px;height:14px;border:2px solid #4c6fff33;border-top-color:#4c6fff;border-radius:50%;animation:spin 1s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;background:#203063;color:#fff;margin-right:6px}
  .badge.crit{background:#a61b1b}
  .badge.high{background:#d97706}
  .badge.med{background:#6b7280}
  .badge.low{background:#2563eb}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}
  </style>
</head>
<body>
  <header><h1>SQLi Scanner Dashboard</h1></header>
  <div class="container">
    <div class="card" id="statusCard">
      <h3>Scan Status</h3>
      <p id="statusText">{{ 'Running' if scan_in_progress else 'Idle' }}</p>
      <div id="loadingIndicator" class="loading" {% if not scan_in_progress %}style="display:none"{% endif %}>
        <div class="spinner" aria-hidden="true"></div>
        <div>Scanning… crawling and testing URLs. This may take a few minutes.</div>
      </div>
    </div>
    <div class="card" id="progressCard">
      <h3>Live Progress</h3>
      <p>Crawled URLs: <span id="crawledCount">0</span></p>
      <p>Queue Length: <span id="queueCount">0</span></p>
      <p>Vulnerabilities Found: <span id="findingsCount">0</span></p>
    </div>
    <div class="card" id="summaryCard">
      <h3>Summary</h3>
      <div class="grid">
        <div>
          <strong>Vulnerabilities</strong>
          <div>
            <span class="badge crit" title="Critical">Critical: <span id="critCount">0</span></span>
            <span class="badge high" title="High">High: <span id="highCount">0</span></span>
            <span class="badge med" title="Medium">Medium: <span id="medCount">0</span></span>
            <span class="badge low" title="Low">Low: <span id="lowCount">0</span></span>
          </div>
        </div>
        <div>
          <strong>Errors</strong>
          <div>
            <span class="badge" title="All errors">Total: <span id="errTotal">0</span></span>
            <span class="badge" title="Client errors">4xx: <span id="err4xx">0</span></span>
            <span class="badge" title="Server errors">5xx: <span id="err5xx">0</span></span>
            <span class="badge" title="Timeouts">Timeout: <span id="errTimeout">0</span></span>
            <span class="badge" title="Network">Network: <span id="errNetwork">0</span></span>
          </div>
        </div>
        <div>
          <strong>Techniques (top)</strong>
          <div id="techList" style="margin-top:4px; font-size:13px; color:#b8c7ff"></div>
        </div>
      </div>
    </div>
    <div class="card">
      <form id="scanForm" method="post" action="/scan">
        <label>Start URL</label>
        <input type="text" name="start_url" value="{{ start_url }}">
        <button class="btn" id="scanBtn" type="submit" {% if scan_in_progress %}style="display:none"{% endif %}>Run Scan</button>
      </form>
      <p>Tip: Start the PHP app first. Default is <code>{{ start_url }}</code>.</p>
      <div style="margin-top:8px; display:flex; gap:16px; align-items:center">
        <label><input type="checkbox" id="colorToggle"> Show severity colors</label>
        <label><input type="checkbox" id="codeToggle"> Show secure query snippet</label>
        <label><input type="checkbox" id="sseToggle"> Use live updates (SSE)</label>
      </div>
      <div class="card" style="margin-top:12px">
        <h4 style="margin:0 0 8px 0">Scan controls</h4>
        <div style="display:grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap:8px; align-items:end">
          <label>Max Depth<br><input type="number" id="ctlDepth" min="0" value="2"></label>
          <label>Concurrency<br><input type="number" id="ctlConc" min="1" value="10"></label>
          <label>Delay (s)<br><input type="number" id="ctlDelay" step="0.1" min="0" value="0.2"></label>
          <label>Boolean Rounds<br><input type="number" id="ctlBoolRounds" min="1" value="3"></label>
          <label><input type="checkbox" id="ctlRobots" checked> Respect robots.txt</label>
          <label><input type="checkbox" id="ctlQuiet"> Quiet</label>
          <label><input type="checkbox" id="ctlTimeBased"> Time-based SQLi</label>
          <label>Time Threshold (s)<br><input type="number" id="ctlTimeThreshold" step="0.5" min="1" value="2"></label>
          <label><input type="checkbox" id="ctlParamFuzz"> Param Fuzzing</label>
          <label>Crawler UA<br><input type="text" id="ctlUA" placeholder="e.g., MyScanner/1.0"></label>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Latest Results</h3>
      <p><span id="count">{{ count }}</span> findings | updated <span id="updated">{{ updated }}</span></p>
      <p>
        <a class="btn" href="/api/results?format=json">Download JSON</a>
        <a class="btn" href="/api/results?format=csv">Download CSV</a>
      </p>
      <table>
  <thead><tr><th>Technique</th><th>Risk</th><th>Score</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th><th>Suggested Fix</th></tr></thead>
        <tbody id="resultsBody">
        {% for r in results %}
          <tr class="sev-{{ (r.risk or 'Medium')|lower }}">
            <td>{{ r.technique }}</td>
            <td>{{ r.risk or 'Medium' }}</td>
      <td>{{ r.score or '' }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.url }}</td>
            <td>{{ r.param }}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">{{ r.payload }}</td>
    <td style="max-width:320px; overflow-wrap:anywhere">{{ r.evidence }}</td>
    <td style="max-width:360px; overflow-wrap:anywhere">{{ r.solution }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

  </div>
  <div id="toast" class="toast" role="status" aria-live="polite" aria-atomic="true" style="display:none"></div>
  <script>
    function showToast(msg, type='warn'){
      const t = document.getElementById('toast');
      if(!t) return;
      t.textContent = msg;
      t.className = `toast ${type}`;
      t.style.display = 'block';
      // force reflow to apply transition
      void t.offsetWidth;
      t.classList.add('show');
      clearTimeout(window.__toastTimer);
      window.__toastTimer = setTimeout(()=>{
        t.classList.remove('show');
        setTimeout(()=>{ t.style.display='none'; }, 250);
      }, 3000);
    }
    async function refreshResults(){
      try{
        const r = await fetch('/api/results');
        const j = await r.json();
        document.getElementById('count').textContent = j.count;
        document.getElementById('updated').textContent = j.updated ? new Date(j.updated).toLocaleString() : 'never';
        const tbody = document.getElementById('resultsBody');
        tbody.innerHTML = '';
        const colorsOn = document.getElementById('colorToggle')?.checked;
        const codeOn = document.getElementById('codeToggle')?.checked;
        document.body.classList.toggle('colors-on', !!colorsOn);
        const suggestionFor = (row) => {
          const p = row.param || 'parameter';
          const base = `Use prepared statements/parameterized queries (bind variables) for '${p}'. Validate and whitelist expected types/lengths.`;
          if ((row.technique||'').toLowerCase().includes('error')){
            return base + ' Do not expose database error details; return generic messages and log server-side.';
          }
          if ((row.technique||'').toLowerCase().includes('boolean')){
            return base + ' Normalize error responses so invalid conditions do not change page structure; add consistent responses.';
          }
          if ((row.technique||'').toLowerCase().includes('union')){
            return base + ' Restrict SELECT columns and cast inputs to expected types (e.g., integers).';
          }
          return base;
        };
        (j.results||[]).forEach(r => {
          const tr = document.createElement('tr');
          const fix = r.solution || suggestionFor(r);
          const risk = (r.risk||'Medium');
          const score = (r.score !== undefined && r.score !== null) ? r.score : '';
          tr.className = `sev-${risk.toLowerCase()}`;
          tr.innerHTML = `<td>${r.technique||''}</td>
            <td>${risk}</td>
            <td>${score}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">${r.url||''}</td>
            <td>${r.param||''}</td>
            <td style="max-width:320px; overflow-wrap:anywhere">${r.payload||''}</td>
            <td style=\"max-width:320px; overflow-wrap:anywhere\">${r.evidence||''}</td>
            <td style=\"max-width:360px; overflow-wrap:anywhere\">${fix}</td>`;
          if (codeOn){
            const code = document.createElement('div');
            code.className='codebox';
            code.textContent = (r.fix_snippet || 'Use parameterized queries.');
            const td = document.createElement('td');
            td.colSpan = 8;
            td.appendChild(code);
            const tr2 = document.createElement('tr');
            tr2.className = `sev-${risk.toLowerCase()}`;
            tr2.appendChild(td);
            tbody.appendChild(tr);
            tbody.appendChild(tr2);
            return;
          }
          tbody.appendChild(tr);
        });
      }catch(e){/* ignore */}
    }
    async function refreshStatus(){
      try{
        const r = await fetch('/api/status');
        const j = await r.json();
        const el = document.getElementById('statusText');
  const running = !!j.running;
  el.textContent = running ? 'Running' : 'Idle';
  const li = document.getElementById('loadingIndicator');
  if (li) li.style.display = running ? 'flex' : 'none';
  const btn = document.getElementById('scanBtn');
  if (btn) btn.style.display = running ? 'none' : 'inline-block';
      }catch(e){}
    }
    setInterval(()=>{refreshResults(); refreshStatus();}, 5000);
    document.getElementById('colorToggle')?.addEventListener('change', refreshResults);
    document.getElementById('codeToggle')?.addEventListener('change', refreshResults);
    // Intercept form submit to call /api/scan and show toast if 429
    document.getElementById('scanForm')?.addEventListener('submit', async (e)=>{
      e.preventDefault();
      try{
        const fd = new FormData(e.target);
        const start_url = fd.get('start_url') || '';
        const ctrl = {
          start_url,
          max_depth: parseInt(document.getElementById('ctlDepth')?.value || '2', 10),
          concurrency: parseInt(document.getElementById('ctlConc')?.value || '10', 10),
          delay: parseFloat(document.getElementById('ctlDelay')?.value || '0.2'),
          boolean_rounds: parseInt(document.getElementById('ctlBoolRounds')?.value || '3', 10),
          respect_robots: !!document.getElementById('ctlRobots')?.checked,
          quiet: !!document.getElementById('ctlQuiet')?.checked,
          time_based: !!document.getElementById('ctlTimeBased')?.checked,
          time_threshold: parseFloat(document.getElementById('ctlTimeThreshold')?.value || '2'),
          param_fuzz: !!document.getElementById('ctlParamFuzz')?.checked,
          crawler_ua: (document.getElementById('ctlUA')?.value || '').trim() || null,
        };
        // Immediately clear previous results in the UI
        try{
          document.getElementById('resultsBody').innerHTML = '';
          document.getElementById('count').textContent = '0';
          document.getElementById('updated').textContent = 'scanning…';
          const statusEl = document.getElementById('statusText');
          if (statusEl) statusEl.textContent = 'Running';
          const li = document.getElementById('loadingIndicator');
          if (li) li.style.display = 'flex';
          const btn = document.getElementById('scanBtn');
          if (btn) btn.style.display = 'none';
        }catch(_){ }
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(ctrl)
        });
        if (resp.status === 429){
          const j = await resp.json().catch(()=>({reason:'Scan already running'}));
          showToast(j.reason || 'Scan already running', 'warn');
          return;
        }
        if (resp.ok){
          showToast('Scan started', 'success');
          refreshStatus();
          return;
        }
        showToast('Failed to start scan', 'error');
      }catch(err){
        showToast('Failed to start scan', 'error');
      }
    });

    // Optional SSE live updates
    let es;
    function configureSSE(){
      try{ es && es.close(); }catch(_){ }
      es = undefined;
      const useSSE = document.getElementById('sseToggle')?.checked;
      if(useSSE){
        es = new EventSource('/events');
        es.onmessage = (_ev)=>{ refreshResults(); refreshStatus(); };
        es.onerror = (_e)=>{ /* silent; fallback remains interval */ };
      }
    }
    document.getElementById('sseToggle')?.addEventListener('change', configureSSE);
    configureSSE();

    // In dashboard JS, poll /api/progress every 2s and update these fields:
    setInterval(async ()=>{
      try{
        const r = await fetch('/api/progress');
        const j = await r.json();
        document.getElementById('crawledCount').textContent = j.crawled;
        document.getElementById('queueCount').textContent = j.queue;
        document.getElementById('findingsCount').textContent = j.findings;
      }catch(e){}
    }, 2000);

    // Summary refresher: risk and error breakdowns
    async function refreshSummary(){
      try{
        const r = await fetch('/api/summary');
        const j = await r.json();
        const rc = j.risk_counts || {};
        const ec = (j.errors && j.errors.by_type) || {};
        document.getElementById('critCount').textContent = rc.Critical || 0;
        document.getElementById('highCount').textContent = rc.High || 0;
        document.getElementById('medCount').textContent = rc.Medium || 0;
        document.getElementById('lowCount').textContent = rc.Low || 0;
        document.getElementById('errTotal').textContent = (j.errors && j.errors.total) || 0;
        document.getElementById('err4xx').textContent = ec.http_4xx || 0;
        document.getElementById('err5xx').textContent = ec.http_5xx || 0;
        document.getElementById('errTimeout').textContent = ec.timeout || 0;
        document.getElementById('errNetwork').textContent = ec.network || 0;
        // Techniques list (top 5)
        const tl = Object.entries(j.technique_counts||{}).sort((a,b)=>b[1]-a[1]).slice(0,5);
        const esc = s=>String(s).replace(/[&<>]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
        document.getElementById('techList').innerHTML = tl.map(([k,v])=>`<div>${esc(k)}: <strong>${v}</strong></div>`).join('');
      }catch(e){}
    }
    setInterval(refreshSummary, 3000);
    refreshSummary();
  </script>
</body>
</html>
"""


def load_latest():
    try:
        with open("latest_scan.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        mtime = datetime.fromtimestamp(os.path.getmtime("latest_scan.json"))
        return data, mtime
    except Exception:
        return [], None


# Root dashboard page
@app.route("/", methods=["GET"])
def index():
  results, mtime = load_latest()
  enriched = [_enrich_result(r) for r in results]
  return render_template_string(
    TEMPLATE,
    results=enriched,
    count=len(enriched),
    updated=(mtime.isoformat() if mtime else None),
    scan_in_progress=bool(scan_in_progress),
    start_url=DEFAULT_START_URL,
  )


# Fallback form POST (non-JS submit) -> start scan then redirect
@app.route("/scan", methods=["POST"]) 
def scan_form_post():
  payload = request.form or {}
  start_url = payload.get('start_url') or DEFAULT_START_URL
  if scan_in_progress:
    return redirect(url_for('index'))
  options = {
    'max_depth': 2,
    'concurrency': 10,
    'delay': 0.2,
    'boolean_rounds': 3,
    'respect_robots': True,
    'quiet': False,
    'time_based': False,
    'time_threshold': 2.0,
    'param_fuzz': False,
    'crawler_ua': None,
  }
  run_scan(start_url, options)
  return redirect(url_for('index'))


def run_scan(start_url: str, options: dict | None = None):
  """Schedule the scan coroutine onto a persistent event loop thread."""
  global scan_in_progress
  loop = _ensure_worker_loop()

  async def _run():
    global scan_in_progress
    try:
      scan_in_progress = True
      # reset metrics
      progress_state.update({'crawled': 0, 'queue': 0, 'findings': 0})
      scan_metrics['errors_total'] = 0
      scan_metrics['errors_by_type'] = {}
      scan_metrics['status_counts'] = {}
      scan_metrics['risk_counts'] = {}
      scan_metrics['technique_counts'] = {}

      opts = options or {}
      scanner = AsyncSQLiScanner(
        start_url=start_url,
        max_depth=int(opts.get('max_depth', 2)),
        concurrency=int(opts.get('concurrency', 10)),
        delay=float(opts.get('delay', 0.2)),
        respect_robots=bool(opts.get('respect_robots', True)),
        boolean_rounds=int(opts.get('boolean_rounds', 3)),
        verbose=not bool(opts.get('quiet', False)),
        quiet=bool(opts.get('quiet', False)),
        time_based=bool(opts.get('time_based', False)),
        time_threshold=float(opts.get('time_threshold', 2.0)),
        param_fuzz=bool(opts.get('param_fuzz', False)),
        robots_user_agent=(opts.get('crawler_ua') or None),
        js_render=bool(opts.get('js_render', False)),
      )

      # incremental callbacks
      def _on_finding(_):
        try:
          progress_state['findings'] = len(scanner.results)
          rc = {}
          tc = {}
          for r in scanner.results:
            rc[r.get('risk', 'Unknown')] = rc.get(r.get('risk', 'Unknown'), 0) + 1
            tc[r.get('technique', 'Unknown')] = tc.get(r.get('technique', 'Unknown'), 0) + 1
          scan_metrics['risk_counts'] = rc
          scan_metrics['technique_counts'] = tc
        except Exception:
          pass
      scanner.on_finding = _on_finding

      def _on_progress(p):
        try:
          progress_state.update({
            'crawled': int(p.get('crawled', progress_state['crawled'])),
            'queue': int(p.get('queue', progress_state['queue'])),
            'findings': int(p.get('findings', progress_state['findings'])),
          })
        except Exception:
          pass
      scanner.on_progress = _on_progress

      await scanner.run()
      scanner.export_results()
    finally:
      scan_in_progress = False

  # Create a task in the worker loop without blocking
  def _create_task():
    asyncio.ensure_future(_run(), loop=loop)
  loop.call_soon_threadsafe(_create_task)
@app.route("/api/results", methods=["GET"])
def api_results():
  global scan_in_progress
  # While a scan is running, suppress previous results so the UI only shows fresh results when ready
  if scan_in_progress:
    fmt = request.args.get('format')
    if fmt == 'csv':
      from io import StringIO
      si = StringIO()
      writer = csv.DictWriter(si, fieldnames=["url","risk","score","param","technique","payload","evidence","solution"])
      writer.writeheader()
      resp = app.response_class(si.getvalue(), mimetype='text/csv')
      resp.headers['Content-Disposition'] = 'attachment; filename="latest_scan.csv"'
      return resp
    return jsonify({"count": 0, "updated": None, "results": []})

  results, mtime = load_latest()
  enriched = [_enrich_result(r) for r in results]
  fmt = request.args.get('format')
  if fmt == 'csv':
    # stream CSV
    from io import StringIO
    si = StringIO()
    # include risk and score columns
    writer = csv.DictWriter(si, fieldnames=["url","risk","score","param","technique","payload","evidence","solution"])
    writer.writeheader()
    for r in enriched:
      writer.writerow({k: r.get(k,"") for k in writer.fieldnames})
    resp = app.response_class(si.getvalue(), mimetype='text/csv')
    resp.headers['Content-Disposition'] = 'attachment; filename="latest_scan.csv"'
    return resp
  # default json
  return jsonify({
    "count": len(enriched),
    "updated": mtime.isoformat() if mtime else None,
    "results": enriched,
  })


@app.route("/api/scan", methods=["POST","OPTIONS"])
def api_scan():
  if request.method == 'OPTIONS':
    return ('', 204)
  payload = request.get_json(silent=True) or {}
  start_url = payload.get('start_url') or request.form.get('start_url') or DEFAULT_START_URL
  global scan_in_progress
  if scan_in_progress:
    return jsonify({"started": False, "reason": "Scan already in progress"}), 429
  options = {
    'max_depth': payload.get('max_depth', 2),
    'concurrency': payload.get('concurrency', 10),
    'delay': payload.get('delay', 0.2),
    'boolean_rounds': payload.get('boolean_rounds', 3),
    'respect_robots': payload.get('respect_robots', True),
    'quiet': payload.get('quiet', False),
  'time_based': payload.get('time_based', False),
  'time_threshold': payload.get('time_threshold', 2.0),
  'param_fuzz': payload.get('param_fuzz', False),
  'crawler_ua': payload.get('crawler_ua') or None,
  }
  run_scan(start_url, options)
  return jsonify({"started": True, "start_url": start_url})


@app.route('/events')
def sse_events():
  def generate():
    last_mtime = None
    last_status = None
    while True:
      try:
        try:
          mtime = os.path.getmtime('latest_scan.json')
        except Exception:
          mtime = None
        changed = (mtime != last_mtime) or (last_status != bool(scan_in_progress))
        last_mtime = mtime
        last_status = bool(scan_in_progress)
        if changed:
          yield 'event: message\n'
          yield 'data: update\n\n'
        else:
          yield ': ping\n\n'
      except GeneratorExit:
        break
      except Exception:
        yield ': ping\n\n'
      time.sleep(5)
  return app.response_class(
    generate(),
    mimetype='text/event-stream',
    headers={
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    }
  )


@app.route("/api/status", methods=["GET"]) 
def api_status():
    return jsonify({"running": bool(scan_in_progress)})


@app.route("/api/progress", methods=["GET"])
def api_progress():
    return jsonify({
        "crawled": progress_state['crawled'],
        "queue": progress_state['queue'],
        "findings": progress_state['findings']
    })


# Patch AsyncSQLiScanner to update progress_state
from app import AsyncSQLiScanner as _OrigScanner
class AsyncSQLiScanner(_OrigScanner):
  async def crawl(self):
    async with aiohttp.ClientSession() as session:
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
        progress_state['crawled'] = len(self.visited)
        progress_state['queue'] = len(self.to_visit)
        # Fetch with error accounting
        try:
          status, text = await self.fetch(session, url)
        except asyncio.TimeoutError:
          scan_metrics['errors_total'] += 1
          scan_metrics['errors_by_type']['timeout'] = scan_metrics['errors_by_type'].get('timeout', 0) + 1
          status, text = None, None
        except Exception:
          scan_metrics['errors_total'] += 1
          scan_metrics['errors_by_type']['network'] = scan_metrics['errors_by_type'].get('network', 0) + 1
          status, text = None, None
        # HTTP error buckets
        try:
          if isinstance(status, int):
            if status >= 500:
              scan_metrics['errors_total'] += 1
              scan_metrics['errors_by_type']['http_5xx'] = scan_metrics['errors_by_type'].get('http_5xx', 0) + 1
            elif status >= 400:
              scan_metrics['errors_total'] += 1
              scan_metrics['errors_by_type']['http_4xx'] = scan_metrics['errors_by_type'].get('http_4xx', 0) + 1
            if status >= 400:
              key = str(status)
              scan_metrics['status_counts'][key] = scan_metrics['status_counts'].get(key, 0) + 1
        except Exception:
          pass
        await asyncio.sleep(self.delay)
        if text:
          await self.extract_links_forms(session, text, url, depth)
        progress_state['queue'] = len(self.to_visit)

    def export_results(self, prefix="scan"):
        super().export_results(prefix)
        progress_state['findings'] = len(self.results)

@app.route("/api/summary", methods=["GET"])
def api_summary():
  # Summarize current metrics and last update time
  results, mtime = load_latest()
  # if a scan is in progress, report live counts; otherwise reflect saved file plus metrics
  return jsonify({
    'running': bool(scan_in_progress),
    'last_updated': (mtime.isoformat() if mtime else None),
    'errors': {
      'total': scan_metrics.get('errors_total', 0),
      'by_type': scan_metrics.get('errors_by_type', {}),
      'status_counts': scan_metrics.get('status_counts', {}),
    },
    'risk_counts': scan_metrics.get('risk_counts', {}),
    'technique_counts': scan_metrics.get('technique_counts', {}),
    'findings': progress_state.get('findings', 0),
  })


if __name__ == "__main__":
  # Disable reloader to avoid spawning multiple worker threads/SSE generators
  app.run(host="127.0.0.1", port=5050, debug=True, use_reloader=False)
