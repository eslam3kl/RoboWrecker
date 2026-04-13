"""
dashboard.py
------------
Live fuzzer dashboard on port 7070.
Uses ONLY Python stdlib — no Flask, no flask-socketio needed.

Push mechanism: Server-Sent Events (SSE).
The browser opens GET /events and holds the connection open.
main.py calls push_entry(entry) which writes to every open SSE connection.

Start:  dashboard.start_in_background()   (called from main.py)
Push:   dashboard.push_entry(entry_dict)  (called after every iteration)
"""

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

DASHBOARD_PORT = 7070
LOG_FILE = "logs.jsonl"

# ── Global state ──────────────────────────────────────────────────────────────
_clients: list = []
_clients_lock = threading.Lock()

_advisor_prompt = "(not set)"
_evaluator_prompt = "(not set)"


def set_prompts(advisor_prompt: str, evaluator_prompt: str):
    global _advisor_prompt, _evaluator_prompt
    _advisor_prompt = advisor_prompt
    _evaluator_prompt = evaluator_prompt


def push_entry(entry: dict):
    """Broadcast a new log entry to all connected SSE clients."""
    data = json.dumps(entry, ensure_ascii=False)
    dead = []
    with _clients_lock:
        for q in _clients:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _clients.remove(q)


def _read_logs(limit: int = 200) -> list:
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
            return [json.loads(l.strip()) for l in lines if l.strip()]
    except Exception:
        return []


# ── HTML ──────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FUZZ//CTRL</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#080c0e;--panel:#0d1417;--border:#1a2e38;
    --accent:#00ffe0;--accent2:#ff3e6c;--accent3:#f0c040;
    --text:#c8dde6;--muted:#4a6575;
    --glow:0 0 12px rgba(0,255,224,0.35);--glow2:0 0 12px rgba(255,62,108,0.5);
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:'Space Mono',monospace;font-size:13px;line-height:1.6;min-height:100vh;overflow-x:hidden;}
  body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px);pointer-events:none;z-index:9999;}
  header{display:flex;align-items:center;justify-content:space-between;padding:18px 32px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,#080c0e 60%,#0d1c22 100%);position:sticky;top:0;z-index:100;}
  .logo{font-family:'Orbitron',sans-serif;font-weight:900;font-size:22px;letter-spacing:4px;color:var(--accent);text-shadow:var(--glow);}
  .logo span{color:var(--accent2);}
  .status-bar{display:flex;align-items:center;gap:20px;font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--muted);}
  .status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent2);display:inline-block;margin-right:6px;transition:background 0.3s;}
  .status-dot.live{background:var(--accent);box-shadow:var(--glow);animation:pulse 2s infinite;}
  @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
  .stat-pill{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:3px 10px;color:var(--text);}
  .stat-pill .val{color:var(--accent);font-weight:700;}
  .stat-pill.leak-pill .val{color:var(--accent2);}
  .layout{display:grid;grid-template-columns:360px 1fr;grid-template-rows:auto 1fr;height:calc(100vh - 65px);}
  .prompts-panel{grid-row:1/3;border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;background:var(--panel);}
  .panel-label{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;color:var(--muted);text-transform:uppercase;padding:12px 16px 8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}
  .panel-label::before{content:'';display:inline-block;width:3px;height:14px;background:var(--accent);box-shadow:var(--glow);}
  .prompt-tabs{display:flex;border-bottom:1px solid var(--border);}
  .tab-btn{flex:1;padding:8px;background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:1px;cursor:pointer;transition:all 0.2s;text-transform:uppercase;}
  .tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);background:rgba(0,255,224,0.04);}
  .tab-btn:hover:not(.active){color:var(--text);background:rgba(255,255,255,0.03);}
  .prompt-content{flex:1;overflow-y:auto;padding:14px 16px;display:none;}
  .prompt-content.active{display:block;}
  .prompt-box{font-family:'Share Tech Mono',monospace;font-size:11px;line-height:1.7;color:#8eb4c4;white-space:pre-wrap;word-break:break-word;}
  .current-turn{border-bottom:1px solid var(--border);padding:16px 24px;background:var(--panel);display:grid;grid-template-columns:1fr 1fr;gap:16px;}
  .turn-label{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:6px;}
  .turn-label.payload-lbl{color:var(--accent3);}
  .turn-label.response-lbl{color:var(--accent);}
  .turn-text{font-family:'Share Tech Mono',monospace;font-size:11.5px;color:var(--text);background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:4px;padding:10px 12px;max-height:120px;overflow-y:auto;white-space:pre-wrap;word-break:break-word;transition:border-color 0.4s,box-shadow 0.4s;}
  .turn-text.flash-payload{border-color:var(--accent3);box-shadow:0 0 8px rgba(240,192,64,0.3);}
  .turn-text.flash-response{border-color:var(--accent);box-shadow:var(--glow);}
  .leak-badge{display:none;align-items:center;gap:6px;background:rgba(255,62,108,0.12);border:1px solid var(--accent2);border-radius:3px;padding:6px 12px;margin-top:8px;color:var(--accent2);font-family:'Share Tech Mono',monospace;font-size:11px;box-shadow:var(--glow2);}
  .leak-badge.visible{display:flex;}
  .log-feed{overflow-y:auto;padding:12px 24px 24px;}
  .feed-header{display:flex;align-items:center;justify-content:space-between;padding:10px 0 12px;position:sticky;top:0;background:var(--bg);z-index:10;}
  .feed-title{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;color:var(--muted);text-transform:uppercase;display:flex;align-items:center;gap:8px;}
  .feed-title::before{content:'';display:inline-block;width:3px;height:14px;background:var(--accent2);}
  .clear-btn{background:none;border:1px solid var(--border);color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:1px;padding:3px 10px;border-radius:3px;cursor:pointer;transition:all 0.2s;text-transform:uppercase;}
  .clear-btn:hover{color:var(--accent2);border-color:var(--accent2);}
  .log-entry{border:1px solid var(--border);border-radius:5px;margin-bottom:10px;overflow:hidden;transition:border-color 0.3s;animation:slideIn 0.35s cubic-bezier(0.16,1,0.3,1);}
  @keyframes slideIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}
  .log-entry:hover{border-color:#2a4555;}
  .log-entry.leaked{border-color:var(--accent2);box-shadow:0 0 8px rgba(255,62,108,0.2);}
  .entry-header{display:flex;align-items:center;gap:12px;padding:7px 14px;background:rgba(0,0,0,0.25);cursor:pointer;user-select:none;}
  .entry-iter{font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;color:var(--accent);min-width:56px;}
  .entry-iter.leaked-iter{color:var(--accent2);}
  .entry-mode{font-size:10px;letter-spacing:1px;color:var(--muted);text-transform:uppercase;}
  .entry-payload-preview{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#7a9aaa;font-size:11px;font-style:italic;}
  .leak-tag{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--accent2);background:rgba(255,62,108,0.12);border:1px solid var(--accent2);border-radius:3px;padding:1px 7px;white-space:nowrap;}
  .expand-icon{color:var(--muted);font-size:10px;transition:transform 0.2s;}
  .entry-body{display:none;padding:12px 14px;border-top:1px solid var(--border);gap:10px;flex-direction:column;}
  .entry-body.open{display:flex;}
  .field-label{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}
  .field-label.payload-lbl{color:var(--accent3);}
  .field-label.response-lbl{color:var(--accent);}
  .field-label.leak-lbl{color:var(--accent2);}
  .field-text{font-family:'Share Tech Mono',monospace;font-size:11px;background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:3px;padding:8px 10px;white-space:pre-wrap;word-break:break-word;color:var(--text);line-height:1.6;max-height:200px;overflow-y:auto;}
  .field-text.leak-text{border-color:rgba(255,62,108,0.4);background:rgba(255,62,108,0.06);color:#ff8fa8;}
  ::-webkit-scrollbar{width:4px;height:4px;}
  ::-webkit-scrollbar-track{background:transparent;}
  ::-webkit-scrollbar-thumb{background:#1e3445;border-radius:2px;}
  ::-webkit-scrollbar-thumb:hover{background:var(--accent);}
  #toast{position:fixed;bottom:24px;right:24px;background:var(--panel);border:1px solid var(--accent);border-radius:4px;padding:10px 18px;font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--accent);box-shadow:var(--glow);opacity:0;transform:translateY(10px);transition:all 0.3s;z-index:1000;}
  #toast.show{opacity:1;transform:translateY(0);}
</style>
</head>
<body>
<header>
  <div class="logo">FUZZ<span>//</span>CTRL</div>
  <div class="status-bar">
    <span><span class="status-dot" id="statusDot"></span><span id="statusText">CONNECTING</span></span>
    <span class="stat-pill">ITER <span class="val" id="iterCount">0</span></span>
    <span class="stat-pill leak-pill">LEAKS <span class="val" id="leakCount">0</span></span>
    <span class="stat-pill" id="modeLabel">MODE —</span>
  </div>
</header>
<div class="layout">
  <aside class="prompts-panel">
    <div class="panel-label">Prompt Inspector</div>
    <div class="prompt-tabs">
      <button class="tab-btn active" id="tab-btn-advisor" onclick="switchTab('advisor')">Advisor</button>
      <button class="tab-btn" id="tab-btn-evaluator" onclick="switchTab('evaluator')">Evaluator</button>
    </div>
    <div class="prompt-content active" id="tab-advisor">
      <pre class="prompt-box" id="advisorPromptText">Loading…</pre>
    </div>
    <div class="prompt-content" id="tab-evaluator">
      <pre class="prompt-box" id="evaluatorPromptText">Loading…</pre>
    </div>
  </aside>
  <section class="current-turn">
    <div>
      <div class="turn-label payload-lbl"><span>→</span> Latest Payload</div>
      <div class="turn-text" id="currentPayload">Waiting for first iteration…</div>
    </div>
    <div>
      <div class="turn-label response-lbl"><span>←</span> Target Response</div>
      <div class="turn-text" id="currentResponse">—</div>
      <div class="leak-badge" id="leakBadge">SENSITIVE DATA DETECTED</div>
    </div>
  </section>
  <section class="log-feed" id="logFeed">
    <div class="feed-header">
      <div class="feed-title">Attack Log Feed</div>
      <button class="clear-btn" onclick="document.getElementById('entries').innerHTML=''">Clear</button>
    </div>
    <div id="entries"></div>
  </section>
</div>
<div id="toast"></div>
<script>
  let totalIter=0,totalLeaks=0;

  function switchTab(name){
    ['advisor','evaluator'].forEach(n=>{
      document.getElementById('tab-btn-'+n).classList.toggle('active',n===name);
      document.getElementById('tab-'+n).classList.toggle('active',n===name);
    });
  }

  fetch('/api/config').then(r=>r.json()).then(d=>{
    document.getElementById('advisorPromptText').textContent=d.advisor_prompt||'(not set)';
    document.getElementById('evaluatorPromptText').textContent=d.evaluator_prompt||'(not set)';
  }).catch(()=>{});

  fetch('/api/logs').then(r=>r.json()).then(logs=>{
    logs.forEach(e=>addEntry(e,false));
    if(logs.length){
      const last=logs[logs.length-1];
      updateCurrentTurn(last);
      totalIter=last.iteration||logs.length;
      totalLeaks=logs.filter(e=>e.leaked).length;
      updateStats(last);
    }
  }).catch(()=>{});

  function connectSSE(){
    const es=new EventSource('/events');
    es.onopen=()=>{
      document.getElementById('statusDot').classList.add('live');
      document.getElementById('statusText').textContent='LIVE';
      showToast('Connected — live updates active');
    };
    es.addEventListener('entry',e=>{
      const entry=JSON.parse(e.data);
      addEntry(entry,true);
      updateCurrentTurn(entry);
      totalIter=entry.iteration||(totalIter+1);
      if(entry.leaked)totalLeaks++;
      updateStats(entry);
      document.getElementById('logFeed').scrollTop=0;
    });
    es.onerror=()=>{
      document.getElementById('statusDot').classList.remove('live');
      document.getElementById('statusText').textContent='RECONNECTING…';
      es.close();
      setTimeout(connectSSE,3000);
    };
  }
  connectSSE();

  function updateStats(entry){
    document.getElementById('iterCount').textContent=totalIter;
    document.getElementById('leakCount').textContent=totalLeaks;
    if(entry.mode)document.getElementById('modeLabel').textContent='MODE '+entry.mode.toUpperCase();
  }

  function updateCurrentTurn(entry){
    const pEl=document.getElementById('currentPayload');
    const rEl=document.getElementById('currentResponse');
    const badge=document.getElementById('leakBadge');
    pEl.textContent=entry.payload||'—';
    rEl.textContent=entry.response||'—';
    pEl.classList.remove('flash-payload');rEl.classList.remove('flash-response');
    void pEl.offsetWidth;
    pEl.classList.add('flash-payload');rEl.classList.add('flash-response');
    setTimeout(()=>{pEl.classList.remove('flash-payload');rEl.classList.remove('flash-response');},1400);
    if(entry.leaked&&entry.leak_info){
      badge.textContent='⚠ '+entry.leak_info.slice(0,200);
      badge.classList.add('visible');
    }else{
      badge.classList.remove('visible');
    }
  }

  function addEntry(entry,prepend){
    const c=document.getElementById('entries');
    const div=document.createElement('div');
    div.className='log-entry'+(entry.leaked?' leaked':'');
    const iterCls=entry.leaked?'entry-iter leaked-iter':'entry-iter';
    const preview=(entry.payload||'').replace(/\n/g,' ').slice(0,80);
    div.innerHTML=`
      <div class="entry-header" onclick="toggleEntry(this)">
        <span class="${iterCls}">#${String(entry.iteration||'?').padStart(4,'0')}</span>
        <span class="entry-mode">${(entry.mode||'http').toUpperCase()}</span>
        <span class="entry-payload-preview">${esc(preview)}</span>
        ${entry.leaked?'<span class="leak-tag">🎯 LEAK</span>':''}
        <span class="expand-icon">▼</span>
      </div>
      <div class="entry-body">
        <div><div class="field-label payload-lbl">→ Payload Sent</div>
          <div class="field-text">${esc(entry.payload||'')}</div></div>
        <div><div class="field-label response-lbl">← Target Response</div>
          <div class="field-text">${esc(entry.response||'')}</div></div>
        ${entry.leaked?`<div><div class="field-label leak-lbl">⚠ Leaked Data</div>
          <div class="field-text leak-text">${esc(entry.leak_info||'')}</div></div>`:''}
      </div>`;
    prepend?c.insertBefore(div,c.firstChild):c.appendChild(div);
  }

  function toggleEntry(h){
    const b=h.nextElementSibling;
    b.classList.toggle('open');
    h.querySelector('.expand-icon').style.transform=b.classList.contains('open')?'rotate(180deg)':'';
  }

  function esc(s){
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  let _t;
  function showToast(msg){
    const t=document.getElementById('toast');
    t.textContent=msg;t.classList.add('show');
    clearTimeout(_t);_t=setTimeout(()=>t.classList.remove('show'),3000);
  }
</script>
</body>
</html>
"""


# ── HTTP Request Handler ──────────────────────────────────────────────────────
class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence access logs in terminal

    def do_GET(self):
        if self.path == "/" or self.path == "":
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/logs":
            body = json.dumps(_read_logs(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/config":
            body = json.dumps(
                {"advisor_prompt": _advisor_prompt, "evaluator_prompt": _evaluator_prompt},
                ensure_ascii=False,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/events":
            self._handle_sse()

        else:
            self.send_error(404)

    def _handle_sse(self):
        """Hold the connection open and stream SSE events."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q: queue.Queue = queue.Queue(maxsize=100)
        with _clients_lock:
            _clients.append(q)

        try:
            while True:
                try:
                    data = q.get(timeout=20)
                    msg = f"event: entry\ndata: {data}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # heartbeat keeps the connection alive through proxies
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _clients_lock:
                try:
                    _clients.remove(q)
                except ValueError:
                    pass


# ── Server lifecycle ──────────────────────────────────────────────────────────
def _run_server():
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), _Handler)
    server.daemon_threads = True  # each SSE connection gets its own thread
    server.serve_forever()


def start_in_background():
    """Spawn the dashboard HTTP server in a daemon thread and return immediately."""
    t = threading.Thread(target=_run_server, daemon=True, name="dashboard-server")
    t.start()
    print(f"🖥️  Dashboard  →  http://localhost:{DASHBOARD_PORT}")
    return t