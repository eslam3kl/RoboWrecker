"""
dashboard.py
------------
Live fuzzer dashboard on port 7070.
Uses ONLY Python stdlib — no Flask, no flask-socketio needed.

Push mechanism: Server-Sent Events (SSE).
The browser opens GET /events and holds the connection open.
main.py calls push_entry(entry) which writes to every open SSE connection.

Agent profiles (attacker / target) persist under ./agent_config/ as JSON:
  attacker_agents.json   target_agents.json
The UI loads GET /api/agents and saves via POST /api/agents/{attacker,target};
localStorage mirrors as a fallback when the server is unreachable.

Start:  dashboard.start_in_background()   (called from main.py)
Push:   dashboard.push_entry(entry_dict)  (called after every iteration)
"""

import json
import logging
import os
import queue
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

log = logging.getLogger("dashboard")

DASHBOARD_PORT = 7070
LOG_FILE = "logs.jsonl"
ASSESSMENT_LOG_FILE = "assessment_session_logs.jsonl"

AGENTS_CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_config")
ATTACKER_AGENTS_JSON = os.path.join(AGENTS_CONFIG_DIR, "attacker_agents.json")
TARGET_AGENTS_JSON = os.path.join(AGENTS_CONFIG_DIR, "target_agents.json")
_agents_file_lock = threading.Lock()


def _read_agent_json_file(path: str) -> list:
    with _agents_file_lock:
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception as e:
            log.warning("Could not read agent config %s: %s", path, e)
            return []


def _write_agent_json_file(path: str, agents: list) -> None:
    if not isinstance(agents, list):
        raise ValueError("agents must be a JSON array")
    os.makedirs(AGENTS_CONFIG_DIR, exist_ok=True)
    tmp_path = path + ".tmp"
    text = json.dumps(agents, indent=2, ensure_ascii=False) + "\n"
    with _agents_file_lock:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp_path, path)

# ── Global state ──────────────────────────────────────────────────────────────
_clients: list = []
_clients_lock = threading.Lock()

_advisor_prompt = "(not set)"
_evaluator_prompt = "(not set)"
_launch_handler = None
_pause_handler = None
_resume_handler = None
_finish_handler = None
_state_handler = None
_inject_handler = None
_inject_cancel_handler = None
_attacker_test_handler = None
_target_test_handler = None


def set_prompts(advisor_prompt: str, evaluator_prompt: str):
    global _advisor_prompt, _evaluator_prompt
    _advisor_prompt = advisor_prompt
    _evaluator_prompt = evaluator_prompt


def set_control_handlers(
    launch_handler,
    pause_handler,
    resume_handler,
    finish_handler,
    state_handler,
    inject_handler=None,
    inject_cancel_handler=None,
    attacker_test_handler=None,
    target_test_handler=None,
):
    global _launch_handler, _pause_handler, _resume_handler, _finish_handler, _state_handler, _inject_handler, _inject_cancel_handler, _attacker_test_handler, _target_test_handler
    _launch_handler = launch_handler
    _pause_handler = pause_handler
    _resume_handler = resume_handler
    _finish_handler = finish_handler
    _state_handler = state_handler
    _inject_handler = inject_handler
    _inject_cancel_handler = inject_cancel_handler
    _attacker_test_handler = attacker_test_handler
    _target_test_handler = target_test_handler


def push_entry(entry: dict):
    """Broadcast a new log entry to all connected SSE clients."""
    _append_assessment_log(entry)
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


def _append_assessment_log(entry: dict):
    """Append each exchange to a reusable project log file."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "assessment_name": entry.get("assessment_name", ""),
        "role": entry.get("role", ""),
        "message": entry.get("message", ""),
        "iteration": entry.get("iteration"),
        "leaked": bool(entry.get("leaked")),
    }
    try:
        with open(ASSESSMENT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _read_logs(limit: int = 200) -> list:
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
            return [json.loads(l.strip()) for l in lines if l.strip()]
    except Exception:
        return []


# ── HTML ──────────────────────────────────────────────────────────────────────
# DASHBOARD_HTML = r"""<!DOCTYPE html>
# <html lang="en">
# <head>
# <meta charset="UTF-8">
# <meta name="viewport" content="width=device-width, initial-scale=1.0">
# <title>FUZZ//CTRL</title>
# <link rel="preconnect" href="https://fonts.googleapis.com">
# <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
# <style>
#   :root {
#     --bg:#080c0e;--panel:#0d1417;--border:#1a2e38;
#     --accent:#00ffe0;--accent2:#ff3e6c;--accent3:#f0c040;
#     --text:#c8dde6;--muted:#4a6575;
#     --glow:0 0 12px rgba(0,255,224,0.35);--glow2:0 0 12px rgba(255,62,108,0.5);
#   }
#   *{box-sizing:border-box;margin:0;padding:0;}
#   body{background:var(--bg);color:var(--text);font-family:'Space Mono',monospace;font-size:13px;line-height:1.6;min-height:100vh;overflow-x:hidden;}
#   body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px);pointer-events:none;z-index:9999;}
#   header{display:flex;align-items:center;justify-content:space-between;padding:18px 32px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,#080c0e 60%,#0d1c22 100%);position:sticky;top:0;z-index:100;}
#   .logo{font-family:'Orbitron',sans-serif;font-weight:900;font-size:22px;letter-spacing:4px;color:var(--accent);text-shadow:var(--glow);}
#   .logo span{color:var(--accent2);}
#   .status-bar{display:flex;align-items:center;gap:20px;font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--muted);}
#   .status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent2);display:inline-block;margin-right:6px;transition:background 0.3s;}
#   .status-dot.live{background:var(--accent);box-shadow:var(--glow);animation:pulse 2s infinite;}
#   @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
#   .stat-pill{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:3px 10px;color:var(--text);}
#   .stat-pill .val{color:var(--accent);font-weight:700;}
#   .stat-pill.leak-pill .val{color:var(--accent2);}
#   .layout{display:grid;grid-template-columns:360px 1fr;grid-template-rows:auto 1fr;height:calc(100vh - 65px);}
#   .prompts-panel{grid-row:1/3;border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;background:var(--panel);}
#   .panel-label{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;color:var(--muted);text-transform:uppercase;padding:12px 16px 8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}
#   .panel-label::before{content:'';display:inline-block;width:3px;height:14px;background:var(--accent);box-shadow:var(--glow);}
#   .prompt-tabs{display:flex;border-bottom:1px solid var(--border);}
#   .tab-btn{flex:1;padding:8px;background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:1px;cursor:pointer;transition:all 0.2s;text-transform:uppercase;}
#   .tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);background:rgba(0,255,224,0.04);}
#   .tab-btn:hover:not(.active){color:var(--text);background:rgba(255,255,255,0.03);}
#   .prompt-content{flex:1;overflow-y:auto;padding:14px 16px;display:none;}
#   .prompt-content.active{display:block;}
#   .prompt-box{font-family:'Share Tech Mono',monospace;font-size:11px;line-height:1.7;color:#8eb4c4;white-space:pre-wrap;word-break:break-word;}
#   .current-turn{border-bottom:1px solid var(--border);padding:16px 24px;background:var(--panel);display:grid;grid-template-columns:1fr 1fr;gap:16px;}
#   .turn-label{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:6px;}
#   .turn-label.payload-lbl{color:var(--accent3);}
#   .turn-label.response-lbl{color:var(--accent);}
#   .turn-text{font-family:'Share Tech Mono',monospace;font-size:11.5px;color:var(--text);background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:4px;padding:10px 12px;max-height:120px;overflow-y:auto;white-space:pre-wrap;word-break:break-word;transition:border-color 0.4s,box-shadow 0.4s;}
#   .turn-text.flash-payload{border-color:var(--accent3);box-shadow:0 0 8px rgba(240,192,64,0.3);}
#   .turn-text.flash-response{border-color:var(--accent);box-shadow:var(--glow);}
#   .leak-badge{display:none;align-items:center;gap:6px;background:rgba(255,62,108,0.12);border:1px solid var(--accent2);border-radius:3px;padding:6px 12px;margin-top:8px;color:var(--accent2);font-family:'Share Tech Mono',monospace;font-size:11px;box-shadow:var(--glow2);}
#   .leak-badge.visible{display:flex;}
#   .log-feed{overflow-y:auto;padding:12px 24px 24px;}
#   .feed-header{display:flex;align-items:center;justify-content:space-between;padding:10px 0 12px;position:sticky;top:0;background:var(--bg);z-index:10;}
#   .feed-title{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;color:var(--muted);text-transform:uppercase;display:flex;align-items:center;gap:8px;}
#   .feed-title::before{content:'';display:inline-block;width:3px;height:14px;background:var(--accent2);}
#   .clear-btn{background:none;border:1px solid var(--border);color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:1px;padding:3px 10px;border-radius:3px;cursor:pointer;transition:all 0.2s;text-transform:uppercase;}
#   .clear-btn:hover{color:var(--accent2);border-color:var(--accent2);}
#   .log-entry{border:1px solid var(--border);border-radius:5px;margin-bottom:10px;overflow:hidden;transition:border-color 0.3s;animation:slideIn 0.35s cubic-bezier(0.16,1,0.3,1);}
#   @keyframes slideIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}
#   .log-entry:hover{border-color:#2a4555;}
#   .log-entry.leaked{border-color:var(--accent2);box-shadow:0 0 8px rgba(255,62,108,0.2);}
#   .entry-header{display:flex;align-items:center;gap:12px;padding:7px 14px;background:rgba(0,0,0,0.25);cursor:pointer;user-select:none;}
#   .entry-iter{font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;color:var(--accent);min-width:56px;}
#   .entry-iter.leaked-iter{color:var(--accent2);}
#   .entry-mode{font-size:10px;letter-spacing:1px;color:var(--muted);text-transform:uppercase;}
#   .entry-payload-preview{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#7a9aaa;font-size:11px;font-style:italic;}
#   .leak-tag{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--accent2);background:rgba(255,62,108,0.12);border:1px solid var(--accent2);border-radius:3px;padding:1px 7px;white-space:nowrap;}
#   .expand-icon{color:var(--muted);font-size:10px;transition:transform 0.2s;}
#   .entry-body{display:none;padding:12px 14px;border-top:1px solid var(--border);gap:10px;flex-direction:column;}
#   .entry-body.open{display:flex;}
#   .field-label{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}
#   .field-label.payload-lbl{color:var(--accent3);}
#   .field-label.response-lbl{color:var(--accent);}
#   .field-label.leak-lbl{color:var(--accent2);}
#   .field-text{font-family:'Share Tech Mono',monospace;font-size:11px;background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:3px;padding:8px 10px;white-space:pre-wrap;word-break:break-word;color:var(--text);line-height:1.6;max-height:200px;overflow-y:auto;}
#   .field-text.leak-text{border-color:rgba(255,62,108,0.4);background:rgba(255,62,108,0.06);color:#ff8fa8;}
#   ::-webkit-scrollbar{width:4px;height:4px;}
#   ::-webkit-scrollbar-track{background:transparent;}
#   ::-webkit-scrollbar-thumb{background:#1e3445;border-radius:2px;}
#   ::-webkit-scrollbar-thumb:hover{background:var(--accent);}
#   #toast{position:fixed;bottom:24px;right:24px;background:var(--panel);border:1px solid var(--accent);border-radius:4px;padding:10px 18px;font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--accent);box-shadow:var(--glow);opacity:0;transform:translateY(10px);transition:all 0.3s;z-index:1000;}
#   #toast.show{opacity:1;transform:translateY(0);}
# </style>
# </head>
# <body>
# <header>
#   <div class="logo">FUZZ<span>//</span>CTRL</div>
#   <div class="status-bar">
#     <span><span class="status-dot" id="statusDot"></span><span id="statusText">CONNECTING</span></span>
#     <span class="stat-pill">ITER <span class="val" id="iterCount">0</span></span>
#     <span class="stat-pill leak-pill">LEAKS <span class="val" id="leakCount">0</span></span>
#     <span class="stat-pill" id="modeLabel">MODE —</span>
#   </div>
# </header>
# <div class="layout">
#   <aside class="prompts-panel">
#     <div class="panel-label">Prompt Inspector</div>
#     <div class="prompt-tabs">
#       <button class="tab-btn active" id="tab-btn-advisor" onclick="switchTab('advisor')">Advisor</button>
#       <button class="tab-btn" id="tab-btn-evaluator" onclick="switchTab('evaluator')">Evaluator</button>
#     </div>
#     <div class="prompt-content active" id="tab-advisor">
#       <pre class="prompt-box" id="advisorPromptText">Loading…</pre>
#     </div>
#     <div class="prompt-content" id="tab-evaluator">
#       <pre class="prompt-box" id="evaluatorPromptText">Loading…</pre>
#     </div>
#   </aside>
#   <section class="current-turn">
#     <div>
#       <div class="turn-label payload-lbl"><span>→</span> Latest Payload</div>
#       <div class="turn-text" id="currentPayload">Waiting for first iteration…</div>
#     </div>
#     <div>
#       <div class="turn-label response-lbl"><span>←</span> Target Response</div>
#       <div class="turn-text" id="currentResponse">—</div>
#       <div class="leak-badge" id="leakBadge">SENSITIVE DATA DETECTED</div>
#     </div>
#   </section>
#   <section class="log-feed" id="logFeed">
#     <div class="feed-header">
#       <div class="feed-title">Attack Log Feed</div>
#       <button class="clear-btn" onclick="document.getElementById('entries').innerHTML=''">Clear</button>
#     </div>
#     <div id="entries"></div>
#   </section>
# </div>
# <div id="toast"></div>
# <script>
#   let totalIter=0,totalLeaks=0;

#   function switchTab(name){
#     ['advisor','evaluator'].forEach(n=>{
#       document.getElementById('tab-btn-'+n).classList.toggle('active',n===name);
#       document.getElementById('tab-'+n).classList.toggle('active',n===name);
#     });
#   }

#   fetch('/api/config').then(r=>r.json()).then(d=>{
#     document.getElementById('advisorPromptText').textContent=d.advisor_prompt||'(not set)';
#     document.getElementById('evaluatorPromptText').textContent=d.evaluator_prompt||'(not set)';
#   }).catch(()=>{});

#   fetch('/api/logs').then(r=>r.json()).then(logs=>{
#     logs.forEach(e=>addEntry(e,false));
#     if(logs.length){
#       const last=logs[logs.length-1];
#       updateCurrentTurn(last);
#       totalIter=last.iteration||logs.length;
#       totalLeaks=logs.filter(e=>e.leaked).length;
#       updateStats(last);
#     }
#   }).catch(()=>{});

#   function connectSSE(){
#     const es=new EventSource('/events');
#     es.onopen=()=>{
#       document.getElementById('statusDot').classList.add('live');
#       document.getElementById('statusText').textContent='LIVE';
#       showToast('Connected — live updates active');
#     };
#     es.addEventListener('entry',e=>{
#       const entry=JSON.parse(e.data);
#       addEntry(entry,true);
#       updateCurrentTurn(entry);
#       totalIter=entry.iteration||(totalIter+1);
#       if(entry.leaked)totalLeaks++;
#       updateStats(entry);
#       document.getElementById('logFeed').scrollTop=0;
#     });
#     es.onerror=()=>{
#       document.getElementById('statusDot').classList.remove('live');
#       document.getElementById('statusText').textContent='RECONNECTING…';
#       es.close();
#       setTimeout(connectSSE,3000);
#     };
#   }
#   connectSSE();

#   function updateStats(entry){
#     document.getElementById('iterCount').textContent=totalIter;
#     document.getElementById('leakCount').textContent=totalLeaks;
#     if(entry.mode)document.getElementById('modeLabel').textContent='MODE '+entry.mode.toUpperCase();
#   }

#   function updateCurrentTurn(entry){
#     const pEl=document.getElementById('currentPayload');
#     const rEl=document.getElementById('currentResponse');
#     const badge=document.getElementById('leakBadge');
#     pEl.textContent=entry.payload||'—';
#     rEl.textContent=entry.response||'—';
#     pEl.classList.remove('flash-payload');rEl.classList.remove('flash-response');
#     void pEl.offsetWidth;
#     pEl.classList.add('flash-payload');rEl.classList.add('flash-response');
#     setTimeout(()=>{pEl.classList.remove('flash-payload');rEl.classList.remove('flash-response');},1400);
#     if(entry.leaked&&entry.leak_info){
#       badge.textContent='⚠ '+entry.leak_info.slice(0,200);
#       badge.classList.add('visible');
#     }else{
#       badge.classList.remove('visible');
#     }
#   }

#   function addEntry(entry,prepend){
#     const c=document.getElementById('entries');
#     const div=document.createElement('div');
#     div.className='log-entry'+(entry.leaked?' leaked':'');
#     const iterCls=entry.leaked?'entry-iter leaked-iter':'entry-iter';
#     const preview=(entry.payload||'').replace(/\n/g,' ').slice(0,80);
#     div.innerHTML=`
#       <div class="entry-header" onclick="toggleEntry(this)">
#         <span class="${iterCls}">#${String(entry.iteration||'?').padStart(4,'0')}</span>
#         <span class="entry-mode">${(entry.mode||'http').toUpperCase()}</span>
#         <span class="entry-payload-preview">${esc(preview)}</span>
#         ${entry.leaked?'<span class="leak-tag">🎯 LEAK</span>':''}
#         <span class="expand-icon">▼</span>
#       </div>
#       <div class="entry-body">
#         <div><div class="field-label payload-lbl">→ Payload Sent</div>
#           <div class="field-text">${esc(entry.payload||'')}</div></div>
#         <div><div class="field-label response-lbl">← Target Response</div>
#           <div class="field-text">${esc(entry.response||'')}</div></div>
#         ${entry.leaked?`<div><div class="field-label leak-lbl">⚠ Leaked Data</div>
#           <div class="field-text leak-text">${esc(entry.leak_info||'')}</div></div>`:''}
#       </div>`;
#     prepend?c.insertBefore(div,c.firstChild):c.appendChild(div);
#   }

#   function toggleEntry(h){
#     const b=h.nextElementSibling;
#     b.classList.toggle('open');
#     h.querySelector('.expand-icon').style.transform=b.classList.contains('open')?'rotate(180deg)':'';
#   }

#   function esc(s){
#     return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
#   }

#   let _t;
#   function showToast(msg){
#     const t=document.getElementById('toast');
#     t.textContent=msg;t.classList.add('show');
#     clearTimeout(_t);_t=setTimeout(()=>t.classList.remove('show'),3000);
#   }
# </script>
# </body>
# </html>
# """

# ── HTML ──────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RoboWrecker Dashboard</title>
<style>
  :root{
    --bg:#f5f5f7;--panel:#ffffff;--panel2:#fafafa;--border:#d2d2d7;--text:#1d1d1f;
    --muted:#86868b;--accent:#0071e3;--accent2:#2997ff;--danger:#d70015;--ok:#248a3d;
    --ok-bg:rgba(36,138,61,.07);--danger-bg:rgba(215,0,21,.06);
  }
  [data-theme="dark"]{
    --bg:#0e0e10;--panel:#1c1c1e;--panel2:#151517;--border:#38383a;--text:#f5f5f7;
    --muted:#98989d;--accent:#4ba3ff;--accent2:#64b5f6;--danger:#ff6b6b;--ok:#3dd68c;
    --ok-bg:rgba(61,214,140,.1);--danger-bg:rgba(255,107,107,.08);
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
  .app{display:grid;grid-template-columns:300px 1fr;min-height:100vh}
  .side{background:var(--panel);border-right:.5px solid var(--border);padding:20px 14px 16px;display:flex;flex-direction:column;gap:0;min-height:100vh}
  .side-scroll{flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden}
  .brand{font-size:15px;font-weight:600;letter-spacing:-.01em;margin-bottom:14px;padding:0 4px;flex-shrink:0}
  .brand span{color:var(--muted);font-weight:400}
  .side-nav-agents{display:none;flex-direction:column;flex:1;min-height:0;gap:10px;padding:0 2px 10px;overflow:hidden}
  .side-nav-agents.active{display:flex}
  .agent-list{font-size:12px;border:.5px solid var(--border);border-radius:8px;padding:6px;flex:1;min-height:72px;max-height:min(42vh,260px);overflow-y:auto}
  .agent-list-item{padding:8px 10px;border-radius:6px;cursor:pointer;margin-bottom:2px;color:var(--muted);display:flex;justify-content:space-between;align-items:center;gap:6px}
  .agent-list-item:hover,.agent-list-item.selected{background:var(--panel2);color:var(--text)}
  .agent-list-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
  .side-row{display:flex;gap:6px;flex-wrap:wrap;flex-shrink:0}
  .side-row .btn{flex:1;min-width:0;font-size:11px;padding:8px 10px}
  .nav-btn{display:flex;align-items:flex-start;gap:10px;width:100%;text-align:left;padding:10px 12px;border:none;background:transparent;color:var(--muted);border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;transition:background .12s ease,color .12s ease;margin-top:8px}
  .nav-btn:hover{background:var(--panel2);color:var(--text)}
  .nav-btn.active{background:var(--panel2);color:var(--text);font-weight:600}
  .nav-btn .nav-ic{flex:0 0 22px;width:22px;height:22px;display:flex;align-items:center;justify-content:center;margin-top:0;opacity:.5;color:var(--muted)}
  .nav-btn:hover .nav-ic,.nav-btn:focus-visible .nav-ic{opacity:.62;color:var(--text)}
  .nav-btn.active .nav-ic{opacity:.68;color:var(--text)}
  .nav-btn .nav-ic svg{width:20px;height:20px;stroke-width:1.3}
  .nav-btn .nav-copy{display:flex;flex-direction:column;align-items:flex-start;gap:3px;min-width:0;text-align:left}
  .nav-btn .nav-desc{font-size:10px;font-weight:400;line-height:1.25;color:var(--muted);opacity:.88;max-width:100%}
  .nav-btn.active .nav-desc{color:var(--muted);opacity:.95}
  .nav-btn .nav-title{font-size:13px;line-height:1.25;font-weight:inherit}
  .content{padding:32px 40px;background:var(--bg);overflow-y:auto;max-height:100vh}
  .view{display:none}
  .view.active{display:block}
  .card{background:var(--panel);border:.5px solid var(--border);padding:28px;border-radius:16px;margin-bottom:20px}
  .section-title{font-size:18px;font-weight:600;margin-bottom:22px;letter-spacing:-.02em}
  .field{margin-bottom:20px}
  .label{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;font-weight:500;margin-bottom:8px;letter-spacing:.02em}
  .row{display:flex;gap:12px;align-items:center}
  .actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap;justify-content:center;margin-top:8px}
  input[type=text],textarea,select{width:100%;background:var(--panel2);border:.5px solid var(--border);color:var(--text);padding:10px 14px;border-radius:10px;font-size:13px;font-family:inherit;transition:border-color .15s,box-shadow .15s}
  select{
    appearance:none;
    -webkit-appearance:none;
    -moz-appearance:none;
    padding-right:36px;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%2386868b' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m3.5 6 4.5 4 4.5-4'/%3E%3C/svg%3E");
    background-repeat:no-repeat;
    background-position:right 12px center;
    background-size:14px 14px;
  }
  [data-theme="dark"] select{
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%2398989d' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m3.5 6 4.5 4 4.5-4'/%3E%3C/svg%3E");
  }
  input[type=text]:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,113,227,.1)}
  [data-theme="dark"] input[type=text]:focus,[data-theme="dark"] textarea:focus{box-shadow:0 0 0 3px rgba(75,163,255,.12)}
  input[type=text]:disabled,textarea:disabled{opacity:.45;cursor:not-allowed}
  textarea{min-height:90px;resize:vertical;line-height:1.5}
  .toggle-wrap{display:flex;align-items:center;gap:8px;margin-bottom:8px}
  .toggle{width:34px;height:20px;border-radius:999px;border:none;background:#c7c7cc;position:relative;cursor:pointer;transition:background .2s}
  .toggle::after{content:'';position:absolute;width:16px;height:16px;top:2px;left:2px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.15);transition:left .2s}
  .toggle.on{background:var(--ok)}
  .toggle.on::after{left:16px}
  .btn{padding:10px 18px;border:.5px solid var(--border);border-radius:10px;background:var(--panel);color:var(--text);cursor:pointer;font-size:13px;font-weight:500;transition:all .12s ease;display:inline-flex;align-items:center;justify-content:center;gap:8px;font-family:inherit}
  .btn:hover{background:var(--panel2)}
  .btn:active{transform:scale(.98)}
  .btn.primary{background:var(--text);border-color:var(--text);color:var(--bg);padding:10px 22px;font-weight:600}
  .btn.primary:hover{opacity:.88}
  .btn.warn{border-color:var(--danger);color:var(--danger);background:var(--danger-bg)}
  .btn.warn:hover{background:var(--danger);color:#fff}
  .btn-pause{padding:5px 10px;font-size:12px;border-color:var(--muted);color:var(--muted);background:transparent;width:82px;gap:4px;border-radius:7px;transition:all .2s ease;box-sizing:border-box}
  .btn-pause:hover{background:var(--panel2);color:var(--text);border-color:var(--text)}
  .btn-pause:active{transform:scale(.95);opacity:.8}
  .btn-pause.is-resume{border-color:var(--ok);color:var(--ok);background:var(--ok-bg)}
  .btn-pause.is-resume:hover{background:var(--ok);color:#fff}
  [data-theme="dark"] .btn-pause.is-resume:hover{color:#000}
  .btn-pause:disabled{opacity:.65;cursor:not-allowed}
  .btn-pause:disabled:hover{background:transparent!important;color:var(--muted)!important;border-color:var(--border)!important}
  .btn-pause.is-resume:disabled,.btn-pause.is-resume:disabled:hover{background:var(--panel2)!important;color:var(--muted)!important;border-color:var(--border)!important}
  .btn-stop{padding:5px 10px;font-size:12px;border-color:var(--danger);color:var(--danger);background:var(--danger-bg);width:72px;gap:4px;border-radius:7px;transition:all .2s ease;box-sizing:border-box}
  .btn-stop:hover:not(:disabled){background:var(--danger);color:#fff}
  .btn-stop:active:not(:disabled){transform:scale(.95);opacity:.8}
  .btn-stop:disabled{opacity:.72;cursor:not-allowed;width:auto;min-width:72px;border-color:var(--border);color:var(--muted);background:var(--panel2)}
  .btn-stop-initiated{font-size:11px;font-weight:500;letter-spacing:.01em;white-space:nowrap}
  .actions-cell{display:flex;gap:8px;align-items:center}
  .leak-count{display:inline-flex;align-items:center;gap:4px;font-weight:600;color:var(--danger)}
  .leak-count.has-leaks{color:var(--danger)}
  .leak-count.no-leaks{color:var(--danger);opacity:.72}
  .leak-count .leak-icon-svg{width:15px;height:15px;flex-shrink:0;color:#c62828}
  [data-theme="dark"] .leak-count .leak-icon-svg{color:#ef5350}
  .results-leak-cell{display:inline-flex;align-items:center;gap:5px;color:#c62828}
  [data-theme="dark"] .results-leak-cell{color:#ef5350}
  .results-leak-cell .leak-icon-svg{width:15px;height:15px;flex-shrink:0}
  .table{width:100%;border-collapse:collapse}
  .table th,.table td{border-bottom:.5px solid var(--border);padding:12px 10px;text-align:left;font-size:13px}
  .table th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
  .agent-table-wrap{margin-bottom:12px;overflow-x:auto;border:.5px solid var(--border);border-radius:12px}
  .agent-form-reveal{margin-top:18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .agent-table-wrap .table{margin:0;table-layout:fixed}
  .agent-table-wrap .table th,.agent-table-wrap .table td{padding:10px 12px}
  .agent-table-wrap .table th:nth-child(1),.agent-table-wrap .table td:nth-child(1){width:23%}
  .agent-table-wrap .table th:nth-child(2),.agent-table-wrap .table td:nth-child(2){width:16%}
  .agent-table-wrap .table th:nth-child(3),.agent-table-wrap .table td:nth-child(3){width:37%}
  .agent-table-wrap .table th:nth-child(4),.agent-table-wrap .table td:nth-child(4){width:24%}
  .status-pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px 4px 8px;border-radius:999px;font-size:11px;font-weight:600;border:.5px solid var(--border);background:var(--panel2);color:var(--text);vertical-align:middle}
  .status-pill.connected{color:var(--ok);background:var(--ok-bg);border-color:rgba(36,138,61,.2)}
  .status-pill.disconnected{color:var(--danger);background:var(--danger-bg);border-color:rgba(215,0,21,.15)}
  .status-pill.unknown{color:var(--muted);background:var(--panel2);font-weight:500}
  .status-pill.status-testing{display:inline-flex;align-items:center;gap:8px;font-weight:600;color:var(--accent);background:rgba(0,113,227,.08);border-color:rgba(0,113,227,.18)}
  .agent-conn-ic{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;flex-shrink:0;opacity:.88}
  .agent-conn-ic svg{width:18px;height:18px;display:block;color:inherit}
  [data-theme="dark"] .status-pill.connected{border-color:rgba(61,214,140,.25)}
  [data-theme="dark"] .status-pill.disconnected{border-color:rgba(255,107,107,.22)}
  [data-theme="dark"] .status-pill.status-testing{background:rgba(75,163,255,.1);border-color:rgba(75,163,255,.22)}
  .status-pill.status-testing .spinner{width:14px;height:14px;margin-right:0;border-top-color:var(--accent)}
  .agent-response-cell{display:block;max-width:min(42ch,38vw);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:1.45;color:var(--ok);font-weight:500}
  .agent-response-cell.thinking{color:var(--muted);font-weight:500}
  .table td.agent-cell-response{max-width:min(44ch,40vw);vertical-align:top}
  .agent-response-empty{color:var(--muted);opacity:.65;font-weight:400}
  tr.agent-row-active td{background:var(--panel2)}
  .table-actions{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
  .table-actions .btn{padding:5px 10px;font-size:11px;display:inline-flex;align-items:center;gap:6px}
  .table-actions .btn svg{width:14px;height:14px;flex-shrink:0}
  .table-actions .btn-delete:hover{color:var(--danger)}
  .protocol-btn,.protocol-btn.primary{padding:5px 10px;font-size:11px;display:inline-flex;align-items:center;gap:6px;border-radius:7px;min-width:84px}
  .protocol-btn svg{width:14px;height:14px;flex-shrink:0}
  .agent-form-shell .actions .btn{padding:7px 12px;font-size:12px;border-radius:8px;gap:6px}
  .agent-form-shell .actions .btn .icon{width:14px;height:14px;flex-basis:14px}
  .agent-name-cell{font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .agent-form-shell{border-radius:14px;padding:22px 24px 8px;margin-top:10px;border:.5px solid var(--border);background:var(--panel2);transition:border-color .2s ease,box-shadow .2s ease}
  .agent-form-shell.mode-new{border-left:3px solid var(--border)}
  .agent-form-shell.mode-edit{border-left:3px solid var(--text);box-shadow:0 1px 0 rgba(0,0,0,.04)}
  [data-theme="dark"] .agent-form-shell.mode-edit{box-shadow:0 1px 0 rgba(255,255,255,.05)}
  .agent-mode-ribbon{display:flex;align-items:flex-start;gap:16px;margin-bottom:20px;flex-wrap:nowrap}
  .agent-mode-icon{position:relative;width:48px;height:48px;border-radius:14px;flex-shrink:0;border:.5px solid var(--border);background:var(--panel);color:var(--muted)}
  .agent-mode-icon svg{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:22px;height:22px}
  .agent-mode-badge{font-size:10px;font-weight:800;letter-spacing:.12em;padding:5px 11px;border-radius:7px;text-transform:uppercase;vertical-align:middle;color:var(--muted);background:var(--panel);border:.5px solid var(--border)}
  .agent-form-shell.mode-edit .agent-mode-badge{color:var(--text)}
  .agent-mode-headline{font-size:18px;font-weight:650;letter-spacing:-.03em;color:var(--text);line-height:1.25;margin:8px 0 6px}
  .agent-mode-sub{font-size:12px;color:var(--muted);line-height:1.5;max-width:54ch}
  .agent-mode-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:2px}
  .agent-mode-id{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px;color:var(--muted);padding:2px 8px;border-radius:6px;background:var(--panel);border:.5px solid var(--border);display:none}
  .agent-form-shell.mode-edit .agent-mode-id:not(:empty){display:inline-block}
  .name-btn{background:transparent;border:none;color:var(--accent);cursor:pointer;padding:0;font-weight:500;display:inline-flex;align-items:center;gap:6px}
  .name-btn:hover{text-decoration:underline}
  .icon{width:16px;height:16px;display:inline-block;flex:0 0 16px}
  .field-compact input[type=text],.field-compact select{width:min(420px,100%)}
  .field-wide input[type=text],.field-wide select{width:min(620px,100%)}
  .add-agent-btn{padding:4px 10px;min-height:40px}
  .add-agent-btn .icon{width:30px;height:30px;flex-basis:30px}
  .field-note{font-size:11px;color:var(--muted);margin-top:6px;line-height:1.4}
  .status-msg{font-size:12px;margin-top:8px;padding:8px 12px;border-radius:8px;font-weight:500;display:none}
  .status-msg.visible{display:block}
  .status-msg.ok{color:var(--ok);background:var(--ok-bg)}
  .status-msg.err{color:var(--danger);background:var(--danger-bg)}
  .status-msg.info{color:var(--accent);background:rgba(0,113,227,.06)}
  [data-theme="dark"] .status-msg.info{background:rgba(75,163,255,.08)}
  #injectMessageStatus.status-msg.visible{transition:opacity .45s ease}
  .mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px;line-height:1.6}
  .split{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .theme-switcher{margin-top:auto;padding-top:16px}
  .theme-switch-label{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border-radius:10px;font-size:12px;color:var(--muted)}
  .theme-switch{width:42px;height:24px;border-radius:999px;border:none;background:#c7c7cc;position:relative;cursor:pointer;transition:background .2s}
  .theme-switch::after{content:'';position:absolute;top:2px;left:2px;width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.15);transition:left .2s}
  .theme-switch.on{background:var(--accent)}
  .theme-switch.on::after{left:20px}
  .json-wrap{position:relative}
  .json-toolbar{position:absolute;top:6px;right:6px;display:flex;gap:4px;z-index:2}
  .json-btn{background:var(--panel);border:.5px solid var(--border);border-radius:6px;padding:5px;cursor:pointer;color:var(--muted);display:flex;align-items:center;justify-content:center;transition:all .12s}
  .json-btn:hover{color:var(--text);background:var(--panel2)}
  .json-btn .icon{width:14px;height:14px;flex-basis:14px}
  .json-editor{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px;line-height:1.6;min-height:140px;padding:10px 14px;padding-right:70px;tab-size:2;white-space:pre;overflow-x:auto;resize:vertical}
  #assessmentLogs{margin-top:10px;border:.5px solid var(--border);border-radius:12px;padding:14px;background:var(--panel2)}
  @media(max-width:980px){.app{grid-template-columns:1fr}.side{border-right:none;border-bottom:.5px solid var(--border)}.split{grid-template-columns:1fr}}
  @media(max-width:680px){.content{padding:16px}.card{padding:18px}.row{flex-direction:column;align-items:stretch}.actions{flex-direction:column}.btn{width:100%}.table-actions .btn{width:auto}}
  @keyframes spin{to{transform:rotate(360deg)}}
  .spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:#d4a017;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;margin-right:6px;will-change:transform}
  .spinner-slot{display:inline-block;width:16px;height:16px;margin-right:6px;vertical-align:middle}
  .assessment-phase{display:inline-flex;align-items:center;gap:6px;font-size:0.85rem;color:var(--muted)}
  .assessment-phase .phase-spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;flex-shrink:0;box-sizing:border-box}
  .assessment-phase.phase-running .phase-spinner{border-color:rgba(22,163,74,.35);border-top-color:#16a34a}
  .assessment-phase.phase-stopping .phase-spinner{border-color:rgba(234,88,12,.35);border-top-color:#ea580c}
  .assessment-phase.phase-summarizing .phase-spinner{border-color:rgba(37,99,235,.35);border-top-color:#2563eb}
  .assessment-phase.phase-running{color:var(--muted)}
  .assessment-phase.phase-stopping{color:var(--muted)}
  .assessment-phase.phase-summarizing{color:var(--muted)}
  [data-theme="dark"] .assessment-phase.phase-running .phase-spinner{border-color:rgba(74,222,128,.25);border-top-color:#4ade80}
  [data-theme="dark"] .assessment-phase.phase-stopping .phase-spinner{border-color:rgba(251,146,60,.3);border-top-color:#fb923c}
  [data-theme="dark"] .assessment-phase.phase-summarizing .phase-spinner{border-color:rgba(96,165,250,.3);border-top-color:#60a5fa}
  .chat-container{display:flex;flex-direction:column;gap:14px;max-height:520px;overflow-y:auto;padding:12px 0}
  .chat-msg{display:flex;gap:10px;max-width:82%;align-items:flex-start}
  .chat-msg.attacker,.chat-msg.attacker_ops{align-self:flex-start}
  .chat-msg.victim,.chat-msg.victim_ops{align-self:flex-end;flex-direction:row-reverse}
  .chat-msg.system,.chat-msg.eval,.chat-msg.operator{align-self:center;max-width:92%}
  .chat-msg.attacker_eval{align-self:flex-start;max-width:88%}
  .chat-msg.attacker_eval .chat-name{color:var(--muted);font-size:12px;font-weight:600}
  .chat-msg.attacker_eval .chat-bubble{border-bottom-left-radius:4px;background:var(--panel2);border:.5px solid var(--border);font-size:13px;color:var(--text)}
  .chat-avatar{width:36px;height:36px;border-radius:50%;background:var(--panel2);border:.5px solid var(--border);flex-shrink:0;display:flex;align-items:center;justify-content:center}
  .chat-avatar svg{width:22px;height:22px;color:var(--muted);opacity:1;stroke-width:1.35}
  .chat-body{min-width:0}
  .chat-name{font-size:11px;font-weight:600;color:var(--muted);margin-bottom:3px}
  .chat-msg.attacker .chat-name,.chat-msg.victim .chat-name,.chat-msg.attacker_ops .chat-name,.chat-msg.victim_ops .chat-name,.chat-msg.system .chat-name,.chat-msg.eval .chat-name,.chat-msg.operator .chat-name,.chat-msg.operator_instruct .chat-name{color:var(--muted);font-weight:600}
  .chat-bubble{background:var(--panel2);border:.5px solid var(--border);border-radius:14px;padding:10px 14px;font-size:13px;line-height:1.55;word-break:break-word;white-space:pre-wrap;max-height:280px;overflow-y:auto}
  .chat-msg.attacker .chat-bubble,.chat-msg.attacker_ops .chat-bubble{border-bottom-left-radius:4px;background:var(--panel2);border:.5px solid var(--border);color:var(--text)}
  .chat-msg.victim .chat-bubble,.chat-msg.victim_ops .chat-bubble{border-bottom-right-radius:4px;background:var(--panel2);border:.5px solid var(--border);color:var(--text)}
  .chat-msg.system .chat-bubble,.chat-msg.eval .chat-bubble{font-size:12px;background:var(--panel2);border:.5px solid var(--border);color:var(--muted)}
  .chat-msg.operator .chat-bubble{font-size:13px;background:var(--panel2);border:.5px solid var(--border);color:var(--text)}
  .chat-msg.attacker .chat-bubble,.chat-msg.attacker_ops .chat-bubble,.chat-msg.attacker_eval .chat-bubble,.chat-msg.attacker_confirm .chat-bubble{background:rgba(215,0,21,.08);border-color:rgba(215,0,21,.24)}
  .chat-msg.victim .chat-bubble,.chat-msg.victim_ops .chat-bubble{background:rgba(36,138,61,.08);border-color:rgba(36,138,61,.22)}
  .chat-msg.operator .chat-bubble,.chat-msg.operator_instruct .chat-bubble{background:rgba(0,113,227,.08);border-color:rgba(0,113,227,.22)}
  .chat-msg.system .chat-bubble{background:rgba(120,120,128,.08);border-color:rgba(120,120,128,.2)}
  .chat-msg.eval .chat-bubble{background:rgba(180,120,0,.1);border-color:rgba(180,120,0,.24)}
  [data-theme="dark"] .chat-msg.attacker .chat-bubble,[data-theme="dark"] .chat-msg.attacker_ops .chat-bubble,[data-theme="dark"] .chat-msg.attacker_eval .chat-bubble,[data-theme="dark"] .chat-msg.attacker_confirm .chat-bubble{background:rgba(255,107,107,.12);border-color:rgba(255,107,107,.28)}
  [data-theme="dark"] .chat-msg.victim .chat-bubble,[data-theme="dark"] .chat-msg.victim_ops .chat-bubble{background:rgba(61,214,140,.1);border-color:rgba(61,214,140,.26)}
  [data-theme="dark"] .chat-msg.operator .chat-bubble,[data-theme="dark"] .chat-msg.operator_instruct .chat-bubble{background:rgba(75,163,255,.12);border-color:rgba(75,163,255,.28)}
  [data-theme="dark"] .chat-msg.system .chat-bubble{background:rgba(138,138,143,.12);border-color:rgba(138,138,143,.24)}
  [data-theme="dark"] .chat-msg.eval .chat-bubble{background:rgba(240,192,64,.12);border-color:rgba(240,192,64,.28)}
  .op-inject-dir{display:inline-block;font-size:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin-bottom:6px;padding:2px 8px;border-radius:999px;background:var(--panel2);border:.5px solid var(--border)}
  .op-inject-who{font-size:11px;color:var(--muted);font-weight:600;margin-bottom:8px}
  .op-inject-body{white-space:pre-wrap;word-break:break-word}
  .chat-time{font-size:10px;color:var(--muted);margin-top:3px}
  .chat-msg.victim .chat-name,.chat-msg.victim .chat-time,.chat-msg.victim_ops .chat-name,.chat-msg.victim_ops .chat-time{text-align:right}
  .typing-indicator{display:flex;align-items:center;gap:10px;padding:8px 0}
  .typing-indicator.ti-left{align-self:flex-start}
  .typing-indicator.ti-right{align-self:flex-end;flex-direction:row-reverse}
  .typing-indicator.ti-center{align-self:center}
  .typing-indicator .chat-avatar{width:36px;height:36px;border-radius:50%;background:var(--panel2);border:.5px solid var(--border);display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .typing-indicator .chat-avatar svg{width:22px;height:22px;color:var(--muted);opacity:1;stroke-width:1.35}
  .chat-msg.attacker .chat-avatar svg,.chat-msg.attacker_ops .chat-avatar svg,.chat-msg.attacker_eval .chat-avatar svg,.chat-msg.attacker_confirm .chat-avatar svg{color:#c81e1e}
  .chat-msg.victim .chat-avatar svg,.chat-msg.victim_ops .chat-avatar svg{color:#1f8f4f}
  .chat-msg.operator .chat-avatar svg,.chat-msg.operator_instruct .chat-avatar svg{color:#0066d6}
  .chat-msg.system .chat-avatar svg{color:#6b7280}
  .chat-msg.eval .chat-avatar svg{color:#b97900}
  [data-theme="dark"] .chat-msg.attacker .chat-avatar svg,[data-theme="dark"] .chat-msg.attacker_ops .chat-avatar svg,[data-theme="dark"] .chat-msg.attacker_eval .chat-avatar svg,[data-theme="dark"] .chat-msg.attacker_confirm .chat-avatar svg{color:#ff7b7b}
  [data-theme="dark"] .chat-msg.victim .chat-avatar svg,[data-theme="dark"] .chat-msg.victim_ops .chat-avatar svg{color:#59d68f}
  [data-theme="dark"] .chat-msg.operator .chat-avatar svg,[data-theme="dark"] .chat-msg.operator_instruct .chat-avatar svg{color:#7ab6ff}
  [data-theme="dark"] .chat-msg.system .chat-avatar svg{color:#b0b3b8}
  [data-theme="dark"] .chat-msg.eval .chat-avatar svg{color:#f0c46a}
  .typing-meta{display:flex;flex-direction:column;gap:3px}
  .typing-label{font-size:11px;color:var(--muted);font-weight:500}
  .typing-indicator.ti-right .typing-label{text-align:right}
  .typing-dots{display:inline-flex;gap:4px}
  .typing-dots span{width:5px;height:5px;border-radius:50%;background:var(--muted);animation:typingBounce 1.4s infinite ease-in-out}
  .typing-dots span:nth-child(2){animation-delay:.15s}
  .typing-dots span:nth-child(3){animation-delay:.3s}
  @keyframes typingBounce{0%,60%,100%{opacity:.25;transform:scale(1)}30%{opacity:1;transform:scale(1.3)}}
  .conversation-inject{margin-bottom:18px;padding:16px;border:.5px solid var(--border);border-radius:12px;background:var(--panel2)}
  .conversation-inject .inject-row{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin-top:8px}
  .conversation-inject .inject-row .field{margin-bottom:0;flex:1;min-width:200px}
  .conversation-inject textarea{min-height:88px}
  .inject-queue-wrap{margin-top:14px;padding-top:14px;border-top:.5px solid var(--border)}
  .inject-queue-wrap .inject-queue-hint{font-size:11px;color:var(--muted);margin-bottom:8px}
  .inject-queue-list{display:flex;flex-direction:column;gap:8px}
  .inject-queue-row{display:inline-flex;align-self:flex-start;max-width:100%;gap:10px;align-items:flex-start;padding:10px 12px;border:.5px solid rgba(0,113,227,.25);border-radius:10px;background:linear-gradient(180deg,rgba(0,113,227,.08),rgba(0,113,227,.04));box-shadow:0 2px 10px rgba(0,0,0,.04)}
  .inject-queue-meta{display:flex;align-items:center;gap:8px;margin-bottom:6px}
  .inject-queue-badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;background:rgba(0,113,227,.14);color:#0059b5}
  .inject-queue-row .inject-queue-text{flex:0 1 auto;max-width:min(72ch,70vw);font-size:12px;line-height:1.45;color:var(--text);white-space:pre-wrap;word-break:break-word}
  .inject-queue-remove{flex-shrink:0;width:28px;height:28px;padding:0;border-radius:7px;border:.5px solid rgba(0,113,227,.25);background:rgba(255,255,255,.35);cursor:pointer;line-height:1;font-size:18px;color:#0059b5;display:flex;align-items:center;justify-content:center}
  .inject-queue-remove:hover{color:var(--danger);border-color:rgba(215,0,21,.35)}
  [data-theme="dark"] .inject-queue-row{border-color:rgba(75,163,255,.35);background:linear-gradient(180deg,rgba(75,163,255,.14),rgba(75,163,255,.08));box-shadow:none}
  [data-theme="dark"] .inject-queue-badge{background:rgba(75,163,255,.2);color:#9ecbff}
  [data-theme="dark"] .inject-queue-remove{border-color:rgba(75,163,255,.35);background:rgba(11,16,28,.45);color:#9ecbff}
  .chat-msg.operator-instruct{align-self:flex-start;max-width:88%;border-left:2px solid var(--border);padding-left:10px;margin-left:4px}
  .chat-msg.operator-instruct .chat-name{color:var(--muted);font-size:12px;font-weight:600}
  .chat-msg.operator-instruct .chat-bubble{background:var(--panel2);border:.5px solid var(--border);border-bottom-left-radius:4px}
  .chat-msg.attacker_confirm{align-self:flex-start;max-width:88%;border-left:2px solid rgba(139,0,0,.24);padding-left:10px;margin-left:4px}
  .chat-msg.attacker_confirm .chat-name{color:var(--muted);font-size:12px;font-weight:600}
  .chat-msg.attacker_confirm .chat-bubble{background:linear-gradient(180deg,rgba(215,0,21,.12),rgba(215,0,21,.07));border:.5px solid rgba(215,0,21,.26);border-bottom-left-radius:4px;font-size:13px}
  .attacker-confirm-dir{display:inline-flex;align-items:center;margin-bottom:7px;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;background:rgba(215,0,21,.14);color:#a40018}
  [data-theme="dark"] .chat-msg.attacker_confirm{border-left-color:rgba(255,123,123,.35)}
  [data-theme="dark"] .chat-msg.attacker_confirm .chat-bubble{background:linear-gradient(180deg,rgba(255,107,107,.2),rgba(255,107,107,.11));border-color:rgba(255,123,123,.38)}
  [data-theme="dark"] .attacker-confirm-dir{background:rgba(255,123,123,.24);color:#ffd2d2}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">RoboWrecker</div>
    <button type="button" id="nav-agents-attacker" class="nav-btn" title="Attacker advisor profiles" onclick="switchSideAgentTab('attacker')"><span class="nav-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1v3"/><circle cx="12" cy="1" r=".8"/><rect x="4" y="4" width="16" height="12" rx="2.5"/><path d="M7 7l3 2M17 7l-3 2"/><path d="M8 10.5l1.5-1.2 1.5 1.2M13 10.5l1.5-1.2 1.5 1.2"/><rect x="8" y="12.5" width="8" height="2" rx=".4"/><path d="M10.7 12.5v2M13.3 12.5v2"/><path d="M4 9H2.5M20 9h1.5"/><path d="M7.5 16v3.5a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5V16"/></svg></span><span class="nav-copy"><span class="nav-title">Attacker agents</span><span class="nav-desc">Advisor endpoints &amp; prompts</span></span></button>
    <button type="button" id="nav-agents-target" class="nav-btn" title="Target agent profiles" onclick="switchSideAgentTab('target')"><span class="nav-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1v3"/><circle cx="12" cy="1" r=".8"/><rect x="4.5" y="4" width="15" height="11" rx="2.5"/><circle cx="9" cy="9" r="1.2"/><circle cx="15" cy="9" r="1.2"/><path d="M9 12.5q3 2 6 0"/><path d="M4.5 8.5H3M19.5 8.5H21"/><path d="M7.5 15v4a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5v-4"/><path d="M12 15v1.5"/><path d="M10.5 16.5l1.5 4 1.5-4"/></svg></span><span class="nav-copy"><span class="nav-title">Target agents</span><span class="nav-desc">Victim apps under test</span></span></button>
    <button type="button" id="nav-initiate" class="nav-btn active" title="Configure a new assessment" onclick="showView('initiate')"><span class="nav-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5.5"/><circle cx="12" cy="12" r="1.8"/><path d="M12 2v3.5M12 18.5V22M2 12h3.5M18.5 12H22"/></svg></span><span class="nav-copy"><span class="nav-title">New Assessment</span><span class="nav-desc">Targets, objectives, launch</span></span></button>
    <button type="button" id="nav-running" class="nav-btn" title="In-flight assessments" onclick="showView('running')"><span class="nav-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 7-4-14-3 7H2"/></svg></span><span class="nav-copy"><span class="nav-title">Running Assessments</span><span class="nav-desc">Status, controls, live log</span></span></button>
    <button type="button" id="nav-results" class="nav-btn" title="Finished assessment outputs" onclick="showView('results')"><span class="nav-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z"/><path d="M14 2v6h6"/><path d="M8 18v-4M12 18v-7M16 18v-3"/></svg></span><span class="nav-copy"><span class="nav-title">Reports</span><span class="nav-desc">Summaries &amp; transcripts</span></span></button>
    <div class="side-spacer" style="flex:1;min-height:0"></div>
    <div class="theme-switcher">
      <div class="theme-switch-label">
        <span id="themeLabel">Light Mode</span>
        <div id="themeToggle" class="theme-switch" onclick="toggleTheme()"></div>
      </div>
    </div>
  </aside>
  <main class="content">
    <section id="view-agents-attacker" class="view">
      <div class="card">
        <div class="section-title">Attacker agents</div>
        <p class="field-note" style="margin-top:-12px;margin-bottom:14px">The add form starts hidden. <strong>Add attacker agent</strong> opens it; <strong>Cancel</strong> closes it. <strong>Test</strong> (row or form while editing) updates <strong>Status</strong> and <strong>Agent response</strong> in the table.</p>
        <div class="agent-table-wrap">
          <table class="table">
            <thead><tr><th>Name</th><th>Status</th><th>Agent response</th><th style="min-width:200px">Actions</th></tr></thead>
            <tbody id="attackerAgentsTableBody"></tbody>
          </table>
        </div>
        <div id="attackerFormRevealBar" class="agent-form-reveal">
          <button type="button" class="btn primary add-agent-btn" onclick="openAttackerAgentRegistrationForm()"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="13" height="10" rx="2"/><path d="M6 6.5l2.2 1.5M13 6.5l-2.2 1.5"/><path d="M7 9.5l1-1 1 1M11 9.5l1-1 1 1"/><rect x="7" y="11" width="6" height="1.5" rx=".3"/><path d="M9.2 11v1.5M11.8 11v1.5"/><path d="M19.5 4.5v4M21.5 6.5h-4"/></svg>Add attacker agent</button>
        </div>
        <div id="attackerAgentStatus" class="status-msg"></div>
        <div id="attackerFormShell" class="agent-form-shell mode-new" style="display:none">
          <div class="agent-mode-ribbon">
            <div class="agent-mode-icon" aria-hidden="true">
              <svg id="attackerModeIconNew" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="14" height="10.5" rx="2.2"/><path d="M6 6.5l2.5 1.5M14 6.5l-2.5 1.5"/><path d="M7 9.5l1.2-1 1.2 1M11.5 9.5l1.2-1 1.2 1"/><rect x="7" y="11" width="7" height="1.8" rx=".3"/><path d="M9.3 11v1.8M11.7 11v1.8"/><path d="M3 8.5H1.8M17 8.5h1.2"/><path d="M19.5 4v4M21.5 6h-4"/></svg>
              <svg id="attackerModeIconEdit" style="display:none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="13" height="10" rx="2.2"/><path d="M5 7.5l2.2 1.3M12 7.5l-2.2 1.3"/><path d="M6 10l1.1-.9 1.1.9M10 10l1.1-.9 1.1.9"/><rect x="6" y="11.5" width="6" height="1.5" rx=".3"/><path d="M8.2 11.5v1.5M10.8 11.5v1.5"/><path d="M16 3.5l4 4-8 8-3.5 1 1-3.5 8-8z"/></svg>
            </div>
            <div style="flex:1;min-width:0">
              <div class="agent-mode-meta">
                <span class="agent-mode-id" id="attackerModeIdChip"></span>
              </div>
              <div class="agent-mode-headline" id="attackerModeHeadline">Create a new attacker agent</div>
            </div>
          </div>
        <div class="field field-compact">
          <label class="label">Name</label>
          <input id="attackerAgentName" type="text" placeholder="Ollama local advisor">
        </div>
        <div class="field field-wide">
          <label class="label">URI</label>
          <input id="attackerUri" type="text" placeholder="http://localhost:11434/api/chat">
        </div>
        <div class="field">
          <label class="label">Protocol</label>
          <div class="row">
            <button id="attackerProtocolHttp" class="btn protocol-btn primary" type="button" onclick="setAttackerProtocol('http')"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M2 12h20"/><path d="M12 3a15 15 0 0 0 0 18"/></svg>HTTP</button>
            <button id="attackerProtocolSocket" class="btn protocol-btn" type="button" onclick="setAttackerProtocol('socket')"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"><g transform="rotate(-32 12 12)"><line x1="0.5" y1="12" x2="3" y2="12"/><ellipse cx="7.3" cy="12" rx="2.8" ry="3.8"/><ellipse cx="16.7" cy="12" rx="2.8" ry="3.8"/><line x1="21" y1="12" x2="23.5" y2="12"/><line x1="10.2" y1="12" x2="13.8" y2="12" stroke-dasharray="2 2" opacity=".85"/></g></svg>Socket</button>
          </div>
        </div>
        <div class="field">
          <label class="label">Default initiation prompt</label>
          <textarea id="attackerInitialPrompt" placeholder="You are an expert AI red-teamer and prompt injection specialist."></textarea>
        </div>
        <div class="field">
          <label class="label">Test message</label>
          <input id="attackerTestMessage" type="text" placeholder="Hello from Agent Killer connection test">
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleAttackerHeaders" class="toggle" onclick="toggleField('attackerHeaders')"></div>
            <label class="label">Custom headers</label>
          </div>
          <div class="json-wrap">
            <div class="json-toolbar">
              <button class="json-btn" type="button" onclick="copyField('attackerHeaders','attackerAgentStatus')" title="Copy"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="10" y="10" width="11" height="11" rx="1.5"/><path d="M6 14V5a2 2 0 0 1 2-2h7"/></svg></button>
              <button class="json-btn" type="button" onclick="pasteField('attackerHeaders','attackerAgentStatus')" title="Paste"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3h9a2 2 0 0 1 2 2v14H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M10 2v4h7a2 2 0 0 1 2 2v11"/><path d="M10 11h6M10 15h4"/></svg></button>
            </div>
            <textarea id="attackerHeaders" class="json-editor" spellcheck="false" disabled placeholder="Authorization: Bearer sk-xxx"></textarea>
          </div>
        </div>
        <div class="field">
          <label class="label">Request body (JSON)</label>
          <div class="json-wrap">
            <div class="json-toolbar">
              <button class="json-btn" type="button" onclick="copyJsonBody()" title="Copy"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="10" y="10" width="11" height="11" rx="1.5"/><path d="M6 14V5a2 2 0 0 1 2-2h7"/></svg></button>
              <button class="json-btn" type="button" onclick="pasteJsonBody()" title="Paste"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3h9a2 2 0 0 1 2 2v14H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M10 2v4h7a2 2 0 0 1 2 2v11"/><path d="M10 11h6M10 15h4"/></svg></button>
            </div>
            <textarea id="attackerTestRequest" class="json-editor" spellcheck="false"></textarea>
          </div>
          <div class="field-note"><code>{{message}}</code> in body is replaced during attacks.</div>
        </div>
        <div class="actions" style="justify-content:flex-start">
          <button type="button" class="btn primary" onclick="saveAttackerAgent()" id="btnAttackerFormSave"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M6 4h10l4 4v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="M9 4v5h6V4"/><rect x="8" y="13" width="8" height="6" rx="1"/></svg>Save</button>
          <button type="button" class="btn" onclick="testAttackerAgent()"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-14h-7l1-8z"/></svg>Test</button>
          <button type="button" class="btn" onclick="clearAttackerFormForNew()" id="btnAttackerFormClear"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/></svg>Clear form</button>
          <button type="button" class="btn" onclick="cancelAttackerAgentForm()" id="btnAttackerFormCancel"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/></svg>Cancel</button>
        </div>
        </div>
      </div>
    </section>
    <section id="view-agents-target" class="view">
      <div class="card">
        <div class="section-title">Target agents</div>
        <p class="field-note" style="margin-top:-12px;margin-bottom:14px">The add form starts hidden. <strong>Add target agent</strong> opens it; <strong>Cancel</strong> closes it. <strong>Test</strong> (row or form while editing) updates <strong>Status</strong> and <strong>Agent response</strong> in the table.</p>
        <div class="agent-table-wrap">
          <table class="table">
            <thead><tr><th>Name</th><th>Status</th><th>Agent response</th><th style="min-width:200px">Actions</th></tr></thead>
            <tbody id="targetAgentsTableBody"></tbody>
          </table>
        </div>
        <div id="targetFormRevealBar" class="agent-form-reveal">
          <button type="button" class="btn primary add-agent-btn" onclick="openTargetAgentRegistrationForm()"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="13" height="9" rx="2"/><circle cx="7.5" cy="8.5" r="1"/><circle cx="12" cy="8.5" r="1"/><path d="M7.5 11.5q2.3 1.3 4.5 0"/><path d="M9.5 13v1"/><path d="M8.3 14l1.2 3 1.2-3"/><path d="M19.5 4.5v4M21.5 6.5h-4"/></svg>Add target agent</button>
        </div>
        <div id="targetAgentStatus" class="status-msg"></div>
        <div id="targetFormShell" class="agent-form-shell mode-new" style="display:none">
          <div class="agent-mode-ribbon">
            <div class="agent-mode-icon" aria-hidden="true">
              <svg id="targetModeIconNew" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="4" width="13" height="9.5" rx="2.2"/><circle cx="8" cy="8.5" r="1.1"/><circle cx="13" cy="8.5" r="1.1"/><path d="M8 11.5q2.5 1.5 5 0"/><path d="M3.5 8H2.3M16.5 8h1.2"/><path d="M10 13.5v1.2"/><path d="M8.8 14.7l1.2 3.5 1.2-3.5"/><path d="M19.5 4v4M21.5 6h-4"/></svg>
              <svg id="targetModeIconEdit" style="display:none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="12" height="9" rx="2.2"/><circle cx="6.5" cy="9" r="1"/><circle cx="11.5" cy="9" r="1"/><path d="M6.5 12q2 1.3 5 0"/><path d="M8 14v1"/><path d="M6.8 15l1.2 3 1.2-3"/><path d="M16 3.5l4 4-8 8-3.5 1 1-3.5 8-8z"/></svg>
            </div>
            <div style="flex:1;min-width:0">
              <div class="agent-mode-headline" id="targetModeHeadline">Create a new target agent</div>
            </div>
          </div>
        <div class="field field-compact">
          <label class="label">Name</label>
          <input id="targetAgentName" type="text" placeholder="Victim API">
        </div>
        <div class="field">
          <label class="label">Protocol</label>
          <div class="row">
            <button id="targetProtocolHttp" class="btn protocol-btn primary" type="button" onclick="setTargetProtocol('http')"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M2 12h20"/><path d="M12 3a15 15 0 0 0 0 18"/></svg>HTTP</button>
            <button id="targetProtocolSocket" class="btn protocol-btn" type="button" onclick="setTargetProtocol('socket')"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"><g transform="rotate(-32 12 12)"><line x1="0.5" y1="12" x2="3" y2="12"/><ellipse cx="7.3" cy="12" rx="2.8" ry="3.8"/><ellipse cx="16.7" cy="12" rx="2.8" ry="3.8"/><line x1="21" y1="12" x2="23.5" y2="12"/><line x1="10.2" y1="12" x2="13.8" y2="12" stroke-dasharray="2 2" opacity=".85"/></g></svg>Socket</button>
          </div>
        </div>
        <div class="field field-wide">
          <label class="label">Target URI</label>
          <input id="targetUri" type="text" placeholder="https://… or ws://…">
        </div>
        <div class="field">
          <label class="label">Test message</label>
          <input id="targetTestMessage" type="text" placeholder="Hello from Agent Killer connection test">
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleProxy" class="toggle" onclick="toggleField('proxy')"></div>
            <label class="label">Proxy</label>
          </div>
          <input id="proxyInput" type="text" placeholder="http://127.0.0.1:8080" disabled>
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleTargetHeaders" class="toggle" onclick="toggleField('targetHeaders')"></div>
            <label class="label">Custom headers</label>
          </div>
          <div class="json-wrap">
            <div class="json-toolbar">
              <button class="json-btn" type="button" onclick="copyField('targetHeaders','targetAgentStatus')" title="Copy"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="10" y="10" width="11" height="11" rx="1.5"/><path d="M6 14V5a2 2 0 0 1 2-2h7"/></svg></button>
              <button class="json-btn" type="button" onclick="pasteField('targetHeaders','targetAgentStatus')" title="Paste"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3h9a2 2 0 0 1 2 2v14H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M10 2v4h7a2 2 0 0 1 2 2v11"/><path d="M10 11h6M10 15h4"/></svg></button>
            </div>
            <textarea id="targetHeaders" class="json-editor" spellcheck="false" disabled placeholder="Authorization: Bearer …"></textarea>
          </div>
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleTargetRequest" class="toggle on" onclick="toggleField('targetRequest')"></div>
            <label class="label">Request body template</label>
          </div>
          <div class="json-wrap">
            <div class="json-toolbar">
              <button class="json-btn" type="button" onclick="copyField('targetRequestBody','targetAgentStatus')" title="Copy"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="10" y="10" width="11" height="11" rx="1.5"/><path d="M6 14V5a2 2 0 0 1 2-2h7"/></svg></button>
              <button class="json-btn" type="button" onclick="pasteField('targetRequestBody','targetAgentStatus')" title="Paste"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3h9a2 2 0 0 1 2 2v14H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M10 2v4h7a2 2 0 0 1 2 2v11"/><path d="M10 11h6M10 15h4"/></svg></button>
            </div>
            <textarea id="targetRequestBody" class="json-editor" spellcheck="false"></textarea>
          </div>
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleExtractPrompt" class="toggle" onclick="toggleField('extractPrompt')"></div>
            <label class="label">Response extraction prompt</label>
          </div>
          <textarea id="extractPromptInput" disabled placeholder="Extract only the AI reply from HTML…"></textarea>
        </div>
        <div class="actions" style="justify-content:flex-start">
          <button type="button" class="btn primary" onclick="saveTargetAgent()" id="btnTargetFormSave"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M6 4h10l4 4v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="M9 4v5h6V4"/><rect x="8" y="13" width="8" height="6" rx="1"/></svg>Save</button>
          <button type="button" class="btn" onclick="testTargetMessage()"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-14h-7l1-8z"/></svg>Test</button>
          <button type="button" class="btn" onclick="clearTargetFormForNew()" id="btnTargetFormClear"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/></svg>Clear form</button>
          <button type="button" class="btn" onclick="cancelTargetAgentForm()" id="btnTargetFormCancel"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/></svg>Cancel</button>
        </div>
        </div>
      </div>
    </section>
    <section id="view-initiate" class="view active">
      <div class="card">
        <div class="section-title">New Assessment</div>
        <div class="field field-compact">
          <label class="label"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="5" width="14" height="14" rx="2"/><path d="M8 9h8M8 12h6M8 15h4"/><circle cx="17" cy="8" r="3.5"/><path d="M17 6.8v2.4"/></svg>Assessment name</label>
          <input id="assessmentName" type="text" placeholder="Quarterly HR Agent Abuse Simulation">
        </div>
        <div class="field field-compact">
          <label class="label">Attacker agent</label>
          <select id="selectAttackerAgent"></select>
          <div class="field-note">Add or edit profiles from <strong>Attacker agents</strong> in the left nav (opens in the main panel).</div>
        </div>
        <div class="field field-compact">
          <label class="label">Target (victim) agent</label>
          <select id="selectTargetAgent"></select>
          <div class="field-note">Add or edit profiles from <strong>Target agents</strong> in the left nav (opens in the main panel).</div>
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleContext" class="toggle on" onclick="toggleField('context')"></div>
            <label class="label"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7z"/><path d="M13 5v4h4"/><path d="M8 13h6M8 16h4"/></svg>Add context</label>
          </div>
          <textarea id="contextInput" placeholder="Business context for this run only…"></textarea>
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="toggleObjective" class="toggle on" onclick="toggleField('objective')"></div>
            <label class="label"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1.2"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2"/></svg>Add objective</label>
          </div>
          <textarea id="objectiveInput" placeholder="What counts as a successful attack…"></textarea>
        </div>
        <div class="field">
          <div class="toggle-wrap">
            <div id="togglePrompt" class="toggle on" onclick="toggleField('prompt')"></div>
            <label class="label"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3h11a2 2 0 0 1 2 2v11l-6 6H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M14 3v6h6"/><path d="M9 13h5M9 16h3"/></svg>Custom initiation prompt</label>
          </div>
          <textarea id="promptInput" placeholder="Overrides default for this assessment only."></textarea>
        </div>
        <div id="assessmentLaunchStatus" class="status-msg"></div>
        <div class="actions">
          <button class="btn primary" onclick="launchAssessment()"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5l2 6H10l2-6z"/><path d="M10 8.5h4L13.5 21 12 16l-1.5 5L10 8.5z"/><circle cx="12" cy="5.5" r="1.6"/><path d="M5 15h3M16 15h3"/><path d="M4 18c2 2 5 3.5 8 3.5s6-1.5 8-3.5"/></svg>Launch assessment</button>
        </div>
      </div>
    </section>

    <section id="view-running" class="view">
      <div class="card">
        <div class="section-title">Running Assessments</div>
        <table class="table" id="runningTable">
          <thead><tr><th>Assessment Name</th><th>Attacker</th><th>Target</th><th>Started</th><th>Duration</th><th>Assessment status</th><th>Leaks</th><th>Actions</th></tr></thead>
          <tbody id="runningRows"><tr><td colspan="8" class="mono">No running assessments.</td></tr></tbody>
        </table>
      </div>
      <div class="card">
        <div class="section-title">Conversation Log</div>
        <div id="assessmentDetailTitle" class="label">Select an assessment to view the conversation.</div>
        <div id="conversationInjectPanel" class="conversation-inject" style="display:none">
          <div class="label">Operator instruction to attacker</div>
          <p class="field-note" style="margin-top:4px">Sends only to the <strong>attacker AI</strong> (advisor). The attacker replies in the log to confirm it understood. Nothing here is sent to the target agent.</p>
          <div class="inject-row">
            <div class="field" style="flex:2;min-width:220px">
              <label class="label">Instruction</label>
              <textarea id="injectMessageInput" placeholder="e.g. Pivot to credential extraction; pause until I say go; clarify objective…"></textarea>
            </div>
            <button type="button" class="btn primary" onclick="sendInjectMessage()"><svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>Send to attacker</button>
          </div>
          <div id="injectMessageStatus" class="status-msg"></div>
          <div id="injectQueueWrap" class="inject-queue-wrap" style="display:none">
            <div class="label">Queued for attacker</div>
            <p class="inject-queue-hint">Removed from queue if you cancel before the advisor consumes them.</p>
            <div id="injectQueueList" class="inject-queue-list"></div>
          </div>
        </div>
        <div id="assessmentLogs" class="chat-container"></div>
      </div>
    </section>

    <section id="view-results" class="view">
      <div class="card">
        <div class="section-title">Reports</div>
        <table class="table" id="completedTable">
          <thead><tr><th>Assessment Name</th><th>Duration</th><th>Iterations</th><th>Leaks</th></tr></thead>
          <tbody id="completedRows"><tr><td colspan="4" class="mono">No reports yet.</td></tr></tbody>
        </table>
      </div>
      <div class="card" id="resultDetailCard" style="display:none">
        <div class="section-title" id="resultDetailTitle">Assessment Summary</div>
        <div id="resultSummary" class="mono" style="margin-bottom:20px;padding:14px;background:var(--panel2);border:.5px solid var(--border);border-radius:12px;white-space:pre-wrap;line-height:1.7"></div>
        <div style="font-size:15px;font-weight:600;margin-bottom:12px">Conversation Log</div>
        <div id="resultLogs" class="chat-container"></div>
      </div>
    </section>
  </main>
</div>
<script>
  let targetProtocol='http', attackerProtocol='http', selectedAssessmentId=null, selectedResultId=null;
  const STORAGE_ATTACKERS='agentKiller_attackerAgents_v1';
  const STORAGE_TARGETS='agentKiller_targetAgents_v1';
  const DEFAULT_ATT_REQUEST=JSON.stringify({"model":"llama3.2","messages":[{"role":"user","content":"{{message}}"}],"stream":false},null,2);
  const defaultTargetBody='{{message}}';
  const ASSESSMENT_DRAFT_KEY='assessmentFormDraft';
  let attackerAgents=[];
  let targetAgents=[];
  let editingAttackerFormId=null;
  let editingTargetFormId=null;
  let attackerTestingIds=new Set();
  let targetTestingIds=new Set();
  let assessments=[];
  let completed=[];

  function genId(){return 'id-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,9);}

  function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

  const AGENT_TABLE_ICON_TEST='<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 9-14h-7l1-8z"/></svg>';
  const LEAK_ICON_SVG='<svg class="icon leak-icon-svg" viewBox="0 0 24 24" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M5.25 11h13.5a1.75 1.75 0 0 1 1.75 1.75v8.5A1.75 1.75 0 0 1 18.75 23H5.25A1.75 1.75 0 0 1 3.5 21.25v-8.5A1.75 1.75 0 0 1 5.25 11zm6.75 3a1.35 1.35 0 1 0 0 2.7 1.35 1.35 0 0 0 0-2.7zm-.55 2.55h1.1l.38 2.35h-1.86l.38-2.35z"/><path fill="currentColor" d="M9.25 11V7.4c0-1.55 1.25-2.8 2.8-2.8.75 0 1.42.3 1.92.78l-1.06 1.06a1.35 1.35 0 0 0-.86-.32c-.75 0-1.35.6-1.35 1.35V11h-1.45z"/><path fill="currentColor" d="M8.35 6.45 7.2 5.3l.65-1.1 1.25.75-.55.95-.65-.65-.55.2z"/><path fill="currentColor" d="M14.85 4.9c1.35.35 2.35 1.55 2.35 2.95V11h-1.45V7.85c0-.85-.55-1.55-1.35-1.85l.85-1.55.6.45z"/></svg>';
  const AGENT_TABLE_ICON_EDIT='<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h8.5"/><path d="M16.5 3.5l4 4-9.5 9.5-4 1.5-1.5-4 9.5-9.5z"/></svg>';
  const AGENT_TABLE_ICON_DELETE='<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6M14 11v6"/></svg>';

  function showStatus(elId,type,msg){
    const el=document.getElementById(elId);
    if(!el)return;
    el.className='status-msg visible '+type;
    el.textContent=msg;
    if(elId==='injectMessageStatus'){
      el.style.opacity='';
      el.style.transition='';
      if(el._injectFadeTimer){clearTimeout(el._injectFadeTimer);el._injectFadeTimer=null;}
      if(el._injectFadeTimer2){clearTimeout(el._injectFadeTimer2);el._injectFadeTimer2=null;}
    }
  }

  function showInjectMessageStatusOkFade(msg,holdMs,fadeMs){
    const el=document.getElementById('injectMessageStatus');
    if(!el)return;
    if(el._injectFadeTimer){clearTimeout(el._injectFadeTimer);el._injectFadeTimer=null;}
    if(el._injectFadeTimer2){clearTimeout(el._injectFadeTimer2);el._injectFadeTimer2=null;}
    const hold=typeof holdMs==='number'?holdMs:2400;
    const fd=typeof fadeMs==='number'?fadeMs:450;
    el.className='status-msg visible ok';
    el.textContent=msg;
    el.style.opacity='1';
    el.style.transition='opacity '+fd+'ms ease';
    el._injectFadeTimer=setTimeout(function(){
      el._injectFadeTimer=null;
      el.style.opacity='0';
      el._injectFadeTimer2=setTimeout(function(){
        el._injectFadeTimer2=null;
        el.className='status-msg';
        el.textContent='';
        el.style.opacity='';
        el.style.transition='';
      },fd);
    },hold);
  }

  function showStatusTemporary(elId,type,msg,holdMs,fadeMs){
    const el=document.getElementById(elId);
    if(!el)return;
    if(el._fadeTimer){clearTimeout(el._fadeTimer);el._fadeTimer=null;}
    if(el._fadeTimer2){clearTimeout(el._fadeTimer2);el._fadeTimer2=null;}
    const hold=typeof holdMs==='number'?holdMs:2200;
    const fd=typeof fadeMs==='number'?fadeMs:450;
    el.className='status-msg visible '+type;
    el.textContent=msg;
    el.style.opacity='1';
    el.style.transition='opacity '+fd+'ms ease';
    el._fadeTimer=setTimeout(function(){
      el._fadeTimer=null;
      el.style.opacity='0';
      el._fadeTimer2=setTimeout(function(){
        el._fadeTimer2=null;
        el.className='status-msg';
        el.textContent='';
        el.style.opacity='';
        el.style.transition='';
      },fd+40);
    },hold);
  }

  function prettyJson(str){
    try{return JSON.stringify(JSON.parse(str),null,2);}catch(_){return str;}
  }

  function copyField(id,statusId){
    const sid=statusId||'attackerAgentStatus';
    const el=document.getElementById(id);
    if(!el)return;
    navigator.clipboard.writeText(el.value).then(()=>{showStatus(sid,'ok','Copied.');});
  }

  function pasteField(id,statusId){
    const sid=statusId||'attackerAgentStatus';
    navigator.clipboard.readText().then(text=>{
      const el=document.getElementById(id);
      if(!el)return;
      el.value=text;
      scheduleDashboardPersist();
      showStatus(sid,'ok','Pasted.');
    }).catch(()=>{showStatus(sid,'err','Clipboard denied.');});
  }

  function copyJsonBody(){copyField('attackerTestRequest','attackerAgentStatus');}
  function pasteJsonBody(){pasteField('attackerTestRequest','attackerAgentStatus');}

  function getTargetRequestBodyTemplate(){
    const el=document.getElementById('targetRequestBody');
    const v=(el&&typeof el.value==='string')?el.value.trim():'';
    return v||defaultTargetBody;
  }

  function switchSideAgentTab(which){
    syncAttackerFormToModel();syncTargetFormToModel();
    saveAttackerAgentsToStorage();saveTargetAgentsToStorage();
    showView(which==='attacker'?'agents-attacker':'agents-target');
  }

  function migrateLegacyAgents(){
    try{
      if(!localStorage.getItem(STORAGE_ATTACKERS)){
        const legacy=JSON.parse(localStorage.getItem('attackerConfig')||'{}');
        if(legacy&&typeof legacy==='object'&&(legacy.uri||legacy.testRequest)){
          attackerAgents=[{
            id:genId(),
            name:legacy.uri?'Imported attacker':'Default attacker',
            uri:(legacy.uri||'').trim(),
            initialPrompt:(legacy.initialPrompt||'You are an expert AI red-teamer and prompt injection specialist.').trim(),
            testMessage:(legacy.testMessage||'Hello from Agent Killer connection test').trim(),
            testRequest:(legacy.testRequest||DEFAULT_ATT_REQUEST).trim(),
            protocol:(legacy.protocol==='socket'?'socket':'http'),
            headers:(legacy.headers||'').trim(),
            headersEnabled:!!legacy.attackerHeadersEnabled,
            status:'unknown',
            lastAgentResponse:''
          }];
          localStorage.setItem(STORAGE_ATTACKERS,JSON.stringify(attackerAgents));
        }
      }
      if(!localStorage.getItem(STORAGE_TARGETS)){
        const d=JSON.parse(localStorage.getItem('assessmentFormDraft')||'{}');
        if(d&&typeof d==='object'&&(d.targetUri||d.targetRequestBody)){
          targetAgents=[{
            id:genId(),
            name:d.targetUri?'Imported target':'Default target',
            uri:(d.targetUri||'').trim(),
            protocol:(d.protocol==='socket'?'socket':'http'),
            testMessage:(d.targetTestMessage||'Hello from Agent Killer connection test').trim(),
            requestBody:((d.targetRequestBody||'').trim())||defaultTargetBody,
            headers:(d.targetHeaders||'').trim(),
            headersEnabled:!!(d.toggles&&d.toggles.targetHeaders),
            proxy:(d.proxyUrl||'').trim(),
            proxyEnabled:!!(d.toggles&&d.toggles.proxy),
            extractPrompt:(d.extractPrompt||'').trim(),
            extractEnabled:!!(d.toggles&&d.toggles.extractPrompt),
            targetRequestEnabled:d.toggles&&typeof d.toggles.targetRequest==='boolean'?d.toggles.targetRequest:true,
            status:'unknown',
            lastAgentResponse:''
          }];
          localStorage.setItem(STORAGE_TARGETS,JSON.stringify(targetAgents));
        }
      }
    }catch(_){}
  }

  function loadAgentsFromLocalStorageOnly(){
    try{attackerAgents=JSON.parse(localStorage.getItem(STORAGE_ATTACKERS)||'[]');}catch(_){attackerAgents=[];}
    try{targetAgents=JSON.parse(localStorage.getItem(STORAGE_TARGETS)||'[]');}catch(_){targetAgents=[];}
    if(!Array.isArray(attackerAgents)) attackerAgents=[];
    if(!Array.isArray(targetAgents)) targetAgents=[];
  }

  function applyAgentDefaultsAndMetadata(){
    if(!attackerAgents.length){
      attackerAgents=[{id:genId(),name:'Default attacker',uri:'',initialPrompt:'You are an expert AI red-teamer and prompt injection specialist.',testMessage:'Hello from Agent Killer connection test',testRequest:DEFAULT_ATT_REQUEST,protocol:'http',headers:'',headersEnabled:false,status:'unknown',lastAgentResponse:''}];
    }
    attackerAgents.forEach(function(a){
      a.protocol=a.protocol==='socket'?'socket':'http';
      if(!a.status||['unknown','connected','disconnected'].indexOf(a.status)<0)a.status='unknown';
      if(typeof a.lastAgentResponse!=='string')a.lastAgentResponse='';
    });
    if(!targetAgents.length){
      targetAgents=[{id:genId(),name:'Default target',uri:'',protocol:'http',testMessage:'Hello from Agent Killer connection test',requestBody:defaultTargetBody,headers:'',headersEnabled:false,proxy:'',proxyEnabled:false,extractPrompt:'',extractEnabled:false,targetRequestEnabled:true,status:'unknown',lastAgentResponse:''}];
    }
    targetAgents.forEach(function(t){
      if(!t.status||['unknown','connected','disconnected'].indexOf(t.status)<0)t.status='unknown';
      if(typeof t.lastAgentResponse!=='string')t.lastAgentResponse='';
    });
    editingAttackerFormId=null;
    editingTargetFormId=null;
  }

  function mirrorAgentsToLocalStorage(){
    try{localStorage.setItem(STORAGE_ATTACKERS,JSON.stringify(attackerAgents));}catch(_){}
    try{localStorage.setItem(STORAGE_TARGETS,JSON.stringify(targetAgents));}catch(_){}
  }

  function persistAgentsToServer(done){
    const hdr={'Content-Type':'application/json'};
    const post=function(url,body){
      return fetch(url,{method:'POST',headers:hdr,body:JSON.stringify(body)}).then(function(r){
        if(!r.ok)throw new Error('HTTP '+r.status);
        return r.json();
      });
    };
    Promise.all([
      post('/api/agents/attacker',attackerAgents),
      post('/api/agents/target',targetAgents)
    ]).then(function(rows){
      if(rows[0]&&rows[0].ok&&rows[1]&&rows[1].ok)mirrorAgentsToLocalStorage();
      if(typeof done==='function')done();
    }).catch(function(){
      mirrorAgentsToLocalStorage();
      if(typeof done==='function')done();
    });
  }

  function hydrateAgentsFromServer(done){
    fetch('/api/agents').then(function(r){return r.json();}).then(function(d){
      const atkOk=d.ok&&Array.isArray(d.attackers)&&d.attackers.length;
      const tgtOk=d.ok&&Array.isArray(d.targets)&&d.targets.length;
      if(atkOk){
        attackerAgents=d.attackers;
      }else{
        try{attackerAgents=JSON.parse(localStorage.getItem(STORAGE_ATTACKERS)||'[]');}catch(_){attackerAgents=[];}
        if(!Array.isArray(attackerAgents)) attackerAgents=[];
      }
      if(tgtOk){
        targetAgents=d.targets;
      }else{
        try{targetAgents=JSON.parse(localStorage.getItem(STORAGE_TARGETS)||'[]');}catch(_){targetAgents=[];}
        if(!Array.isArray(targetAgents)) targetAgents=[];
      }
      applyAgentDefaultsAndMetadata();
      mirrorAgentsToLocalStorage();
      persistAgentsToServer(done);
    }).catch(function(){
      loadAgentsFromLocalStorageOnly();
      applyAgentDefaultsAndMetadata();
      mirrorAgentsToLocalStorage();
      if(typeof done==='function')done();
    });
  }

  function saveAttackerAgentsToStorage(){
    fetch('/api/agents/attacker',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(attackerAgents)})
      .then(function(r){if(!r.ok)throw new Error();return r.json();})
      .then(function(d){if(!d.ok)throw new Error();mirrorAgentsToLocalStorage();})
      .catch(function(){mirrorAgentsToLocalStorage();});
  }
  function saveTargetAgentsToStorage(){
    fetch('/api/agents/target',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(targetAgents)})
      .then(function(r){if(!r.ok)throw new Error();return r.json();})
      .then(function(d){if(!d.ok)throw new Error();mirrorAgentsToLocalStorage();})
      .catch(function(){mirrorAgentsToLocalStorage();});
  }

  function syncAttackerFormToModel(){
    if(!editingAttackerFormId)return;
    const a=attackerAgents.find(x=>x.id===editingAttackerFormId);
    if(!a)return;
    a.name=document.getElementById('attackerAgentName').value.trim();
    a.uri=document.getElementById('attackerUri').value.trim();
    a.initialPrompt=document.getElementById('attackerInitialPrompt').value.trim()||'You are an expert AI red-teamer and prompt injection specialist.';
    a.testMessage=document.getElementById('attackerTestMessage').value.trim()||'Hello from Agent Killer connection test';
    a.testRequest=document.getElementById('attackerTestRequest').value.trim()||DEFAULT_ATT_REQUEST;
    a.protocol=attackerProtocol;
    a.headersEnabled=document.getElementById('toggleAttackerHeaders').classList.contains('on');
    a.headers=a.headersEnabled?document.getElementById('attackerHeaders').value.trim():'';
  }

  function syncTargetFormToModel(){
    if(!editingTargetFormId)return;
    const t=targetAgents.find(x=>x.id===editingTargetFormId);
    if(!t)return;
    t.name=document.getElementById('targetAgentName').value.trim();
    t.uri=document.getElementById('targetUri').value.trim();
    t.protocol=targetProtocol;
    t.testMessage=document.getElementById('targetTestMessage').value.trim()||'Hello from Agent Killer connection test';
    t.requestBody=getTargetRequestBodyTemplate();
    t.proxyEnabled=document.getElementById('toggleProxy').classList.contains('on');
    t.proxy=t.proxyEnabled?document.getElementById('proxyInput').value.trim():'';
    t.headersEnabled=document.getElementById('toggleTargetHeaders').classList.contains('on');
    t.headers=t.headersEnabled?document.getElementById('targetHeaders').value.trim():'';
    t.targetRequestEnabled=document.getElementById('toggleTargetRequest').classList.contains('on');
    t.extractEnabled=document.getElementById('toggleExtractPrompt').classList.contains('on');
    t.extractPrompt=t.extractEnabled?document.getElementById('extractPromptInput').value.trim():'';
  }

  function fillAttackerFormFromModel(){
    if(!editingAttackerFormId)return;
    const a=attackerAgents.find(x=>x.id===editingAttackerFormId);
    if(!a)return;
    document.getElementById('attackerAgentName').value=a.name||'';
    document.getElementById('attackerUri').value=a.uri||'';
    document.getElementById('attackerInitialPrompt').value=a.initialPrompt||'';
    document.getElementById('attackerTestMessage').value=a.testMessage||'';
    document.getElementById('attackerTestRequest').value=prettyJson(a.testRequest||DEFAULT_ATT_REQUEST);
    applyAttackerProtocolUi(a.protocol==='socket'?'socket':'http');
    const h=!!a.headersEnabled;
    document.getElementById('toggleAttackerHeaders').classList.toggle('on',h);
    document.getElementById('attackerHeaders').disabled=!h;
    document.getElementById('attackerHeaders').value=a.headers||'';
  }

  function fillTargetFormFromModel(){
    if(!editingTargetFormId)return;
    const t=targetAgents.find(x=>x.id===editingTargetFormId);
    if(!t)return;
    document.getElementById('targetAgentName').value=t.name||'';
    document.getElementById('targetUri').value=t.uri||'';
    applyTargetProtocolUi(t.protocol==='socket'?'socket':'http');
    document.getElementById('targetTestMessage').value=t.testMessage||'';
    const px=!!t.proxyEnabled;
    document.getElementById('toggleProxy').classList.toggle('on',px);
    document.getElementById('proxyInput').disabled=!px;
    document.getElementById('proxyInput').value=t.proxy||'';
    const th=!!t.headersEnabled;
    document.getElementById('toggleTargetHeaders').classList.toggle('on',th);
    document.getElementById('targetHeaders').disabled=!th;
    document.getElementById('targetHeaders').value=t.headers||'';
    const tr=t.targetRequestEnabled!==false;
    document.getElementById('toggleTargetRequest').classList.toggle('on',tr);
    const tb=document.getElementById('targetRequestBody');
    tb.readOnly=!tr;tb.disabled=false;
    tb.value=t.requestBody||defaultTargetBody;
    const ex=!!t.extractEnabled;
    document.getElementById('toggleExtractPrompt').classList.toggle('on',ex);
    document.getElementById('extractPromptInput').disabled=!ex;
    document.getElementById('extractPromptInput').value=t.extractPrompt||'';
  }

  function connectionStatusLabel(s){
    if(s==='connected')return 'Connected';
    if(s==='disconnected')return 'Disconnected';
    return 'Not tested';
  }
  function agentConnectionIconSvg(state){
    const sw='1.35';
    const rot='<g class="agent-conn-plug-g" fill="none" stroke="currentColor" stroke-width="'+sw+'" stroke-linecap="round" stroke-linejoin="round" transform="rotate(-32 12 12)">';
    const end='</g>';
    if(state==='connected'){
      return'<svg class="agent-conn-plug" viewBox="0 0 24 24" aria-hidden="true">'+rot+'<line x1="0.5" y1="12" x2="3.5" y2="12"/><ellipse cx="8.2" cy="12" rx="3" ry="4"/><ellipse cx="15.8" cy="12" rx="3" ry="4"/><line x1="20.5" y1="12" x2="23.5" y2="12"/>'+end+'</svg>';
    }
    if(state==='disconnected'){
      return'<svg class="agent-conn-plug" viewBox="0 0 24 24" aria-hidden="true">'+rot+'<line x1="0.5" y1="12" x2="3" y2="12"/><ellipse cx="7.3" cy="12" rx="2.8" ry="3.8"/><ellipse cx="16.7" cy="12" rx="2.8" ry="3.8"/><line x1="21" y1="12" x2="23.5" y2="12"/><line x1="10.2" y1="12" x2="13.8" y2="12" stroke-dasharray="2 2" opacity=".85"/>'+end+'</svg>';
    }
    return'<svg class="agent-conn-plug" viewBox="0 0 24 24" aria-hidden="true">'+rot+'<line x1="0.5" y1="12" x2="3" y2="12" stroke-dasharray="2 2"/><ellipse cx="7.5" cy="12" rx="2.6" ry="3.6"/><ellipse cx="16.5" cy="12" rx="2.6" ry="3.6"/><line x1="21" y1="12" x2="23.5" y2="12" stroke-dasharray="2 2"/><line x1="10.2" y1="12" x2="13.8" y2="12" stroke-dasharray="1.5 2.5" opacity=".75"/>'+end+'</svg>';
  }
  function agentStatusPillInnerHtml(sid){
    const ic='<span class="agent-conn-ic agent-conn-ic-plug">'+agentConnectionIconSvg(sid)+'</span><span class="status-pill-txt">'+esc(connectionStatusLabel(sid))+'</span>';
    return ic;
  }
  function agentResponseCellHtml(raw){
    const t=String(raw??'').trim().replace(/[ \t\n\r]+/g,' ');
    if(!t)return '<span class="agent-response-empty">—</span>';
    const maxShow=360;
    const shown=t.length>maxShow?t.slice(0,maxShow)+'…':t;
    const ti=t.length>800?t.slice(0,800)+'…':t;
    const thinking=t==='Thinking ...';
    return '<span class="mono agent-response-cell'+(thinking?' thinking':'')+'" title="'+esc(ti)+'">'+esc(shown)+'</span>';
  }
  function extractModelNameFromPayload(raw){
    const txt=String(raw??'').trim();
    if(!txt)return'';
    try{
      const parsed=JSON.parse(txt);
      if(parsed&&typeof parsed==='object'){
        if(typeof parsed.model==='string'&&parsed.model.trim())return parsed.model.trim();
        if(typeof parsed.model_name==='string'&&parsed.model_name.trim())return parsed.model_name.trim();
        if(parsed.options&&typeof parsed.options.model==='string'&&parsed.options.model.trim())return parsed.options.model.trim();
      }
    }catch(_){}
    return'';
  }
  function attackerThinkingLabel(a){
    return 'Thinking ...';
  }
  function targetThinkingLabel(t){
    return 'Thinking ...';
  }
  function attackerStatusPillHtml(a){
    if(attackerTestingIds.has(a.id))return '<span class="status-pill status-testing"><span class="spinner" role="status" aria-label="Loading"></span>Testing…</span>';
    const sid=(a.status&&['unknown','connected','disconnected'].indexOf(a.status)>=0)?a.status:'unknown';
    return '<span class="status-pill '+sid+'">'+agentStatusPillInnerHtml(sid)+'</span>';
  }
  function targetStatusPillHtml(t){
    if(targetTestingIds.has(t.id))return '<span class="status-pill status-testing"><span class="spinner" role="status" aria-label="Loading"></span>Testing…</span>';
    const sid=(t.status&&['unknown','connected','disconnected'].indexOf(t.status)>=0)?t.status:'unknown';
    return '<span class="status-pill '+sid+'">'+agentStatusPillInnerHtml(sid)+'</span>';
  }
  function clearAgentStatus(kind){
    const id=kind==='attacker'?'attackerAgentStatus':'targetAgentStatus';
    const el=document.getElementById(id);
    if(el){el.className='status-msg';el.textContent='';}
  }
  function setAgentFormPanelVisible(kind,visible){
    const shell=document.getElementById(kind==='attacker'?'attackerFormShell':'targetFormShell');
    const bar=document.getElementById(kind==='attacker'?'attackerFormRevealBar':'targetFormRevealBar');
    if(shell) shell.style.display=visible?'':'none';
    if(bar) bar.style.display=visible?'none':'flex';
  }
  function cancelAttackerAgentForm(){
    editingAttackerFormId=null;
    resetAttackerFormFieldsAndTitle();
    renderAttackerAgentsTable();
    setAgentFormPanelVisible('attacker',false);
    clearAgentStatus('attacker');
    scheduleDashboardPersist();
  }
  function cancelTargetAgentForm(){
    editingTargetFormId=null;
    resetTargetFormFieldsAndTitle();
    renderTargetAgentsTable();
    setAgentFormPanelVisible('target',false);
    clearAgentStatus('target');
    scheduleDashboardPersist();
  }
  function openAttackerAgentRegistrationForm(){
    editingAttackerFormId=null;
    resetAttackerFormFieldsAndTitle();
    renderAttackerAgentsTable();
    setAgentFormPanelVisible('attacker',true);
    clearAgentStatus('attacker');
    scheduleDashboardPersist();
  }
  function openTargetAgentRegistrationForm(){
    editingTargetFormId=null;
    resetTargetFormFieldsAndTitle();
    renderTargetAgentsTable();
    setAgentFormPanelVisible('target',true);
    clearAgentStatus('target');
    scheduleDashboardPersist();
  }
  function setAgentFormUiMode(prefix, mode, displayName, agentId){
    const shell=document.getElementById(prefix+'FormShell');
    const badge=document.getElementById(prefix+'ModeBadge');
    const headline=document.getElementById(prefix+'ModeHeadline');
    const sub=document.getElementById(prefix+'ModeSub');
    const chip=document.getElementById(prefix+'ModeIdChip');
    const icNew=document.getElementById(prefix+'ModeIconNew');
    const icEd=document.getElementById(prefix+'ModeIconEdit');
    const btnSave=document.getElementById(prefix==='attacker'?'btnAttackerFormSave':'btnTargetFormSave');
    const btnClear=document.getElementById(prefix==='attacker'?'btnAttackerFormClear':'btnTargetFormClear');
    const btnCancel=document.getElementById(prefix==='attacker'?'btnAttackerFormCancel':'btnTargetFormCancel');
    if(!shell||!headline)return;
    const isAtk=prefix==='attacker';
    const noun=isAtk?'attacker':'target';
    shell.classList.remove('mode-new','mode-edit');
    if(mode==='edit'){
      shell.classList.add('mode-edit');
      if(badge)badge.textContent='Edit';
      const dn=(displayName&&String(displayName).trim())||'Unnamed';
      headline.textContent='Editing: '+dn;
      if(chip)chip.textContent=agentId?('id '+agentId):'';
      if(icNew)icNew.style.display='none';
      if(icEd)icEd.style.display='block';
      if(btnSave)btnSave.textContent='Save changes';
      if(btnClear){btnClear.style.display='none';}
    }else{
      shell.classList.add('mode-new');
      if(badge)badge.textContent='New';
      headline.textContent='Create a new '+noun+' agent';
      if(chip)chip.textContent='';
      if(icNew)icNew.style.display='block';
      if(icEd)icEd.style.display='none';
      if(btnSave)btnSave.textContent='Save';
      if(btnClear){btnClear.style.display='';btnClear.textContent='Clear form';}
    }
    if(btnCancel)btnCancel.style.display='';
  }

  function renderAttackerAgentsTable(){
    const tbody=document.getElementById('attackerAgentsTableBody');
    if(!tbody)return;
    if(!attackerAgents.length){
      tbody.innerHTML='<tr><td colspan="4" class="mono">No attacker agents yet.</td></tr>';
      return;
    }
    tbody.innerHTML=attackerAgents.map(function(a){
      const qid=a.id.replace(/'/g,"\\'");
      const active=a.id===editingAttackerFormId?'agent-row-active':'';
      return '<tr'+(active?' class="'+active+'"':'')+'><td class="agent-name-cell">'+esc(a.name||a.uri||'(unnamed)')+'</td><td>'+attackerStatusPillHtml(a)+'</td><td class="agent-cell-response">'+agentResponseCellHtml(a.lastAgentResponse)+'</td><td><div class="table-actions">'+
        '<button type="button" class="btn" onclick="testAttackerConnectionById(\''+qid+'\')" title="Test connection">'+AGENT_TABLE_ICON_TEST+'Test</button>'+
        '<button type="button" class="btn" onclick="beginEditAttackerAgent(\''+qid+'\')" title="Edit agent">'+AGENT_TABLE_ICON_EDIT+'Edit</button>'+
        '<button type="button" class="btn btn-delete" onclick="deleteAttackerAgent(\''+qid+'\')" title="Remove agent">'+AGENT_TABLE_ICON_DELETE+'Delete</button></div></td></tr>';
    }).join('');
  }

  function resetAttackerFormFieldsAndTitle(){
    document.getElementById('attackerAgentName').value='';
    document.getElementById('attackerUri').value='';
    document.getElementById('attackerInitialPrompt').value='';
    document.getElementById('attackerTestMessage').value='';
    document.getElementById('attackerTestRequest').value=DEFAULT_ATT_REQUEST;
    applyAttackerProtocolUi('http');
    document.getElementById('toggleAttackerHeaders').classList.remove('on');
    document.getElementById('attackerHeaders').disabled=true;
    document.getElementById('attackerHeaders').value='';
    setAgentFormUiMode('attacker','new');
  }

  function clearAttackerFormForNew(){
    editingAttackerFormId=null;
    resetAttackerFormFieldsAndTitle();
    renderAttackerAgentsTable();
    scheduleDashboardPersist();
  }

  function beginEditAttackerAgent(id){
    setAgentFormPanelVisible('attacker',true);
    syncAttackerFormToModel();
    saveAttackerAgentsToStorage();
    editingAttackerFormId=id;
    fillAttackerFormFromModel();
    const a=attackerAgents.find(x=>x.id===id);
    setAgentFormUiMode('attacker','edit',a?(a.name||a.uri):'',id);
    renderAttackerAgentsTable();
    showView('agents-attacker');
  }

  function testAttackerConnectionById(id){
    const a=attackerAgents.find(x=>x.id===id);
    if(!a)return;
    if(!a.uri.trim()){
      a.status='disconnected';
      a.lastAgentResponse='URI required.';
      saveAttackerAgentsToStorage();
      renderAttackerAgentsTable();
      return;
    }
    a.lastAgentResponse=attackerThinkingLabel(a);
    attackerTestingIds.add(id);
    renderAttackerAgentsTable();
    const hdr=a.headersEnabled?a.headers:'';
    const mode=a.protocol==='socket'?'ws':'http';
    fetch('/api/attacker/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uri:a.uri,request_body:a.testRequest,test_message:a.testMessage,custom_headers:hdr,mode:mode})})
      .then(r=>r.json()).then(data=>{
        if(!data.ok)throw new Error(data.error||'Failed');
        a.status='connected';
        a.lastAgentResponse=String(data.response_preview||'').slice(0,800);
        saveAttackerAgentsToStorage();
      }).catch(e=>{
        a.status='disconnected';
        a.lastAgentResponse=String(e.message||'Failed').slice(0,800);
        saveAttackerAgentsToStorage();
      }).finally(function(){
        attackerTestingIds.delete(id);
        renderAttackerAgentsTable();
      });
  }

  function renderTargetAgentsTable(){
    const tbody=document.getElementById('targetAgentsTableBody');
    if(!tbody)return;
    if(!targetAgents.length){
      tbody.innerHTML='<tr><td colspan="4" class="mono">No target agents yet.</td></tr>';
      return;
    }
    tbody.innerHTML=targetAgents.map(function(t){
      const qid=t.id.replace(/'/g,"\\'");
      const active=t.id===editingTargetFormId?'agent-row-active':'';
      return '<tr'+(active?' class="'+active+'"':'')+'><td class="agent-name-cell">'+esc(t.name||t.uri||'(unnamed)')+'</td><td>'+targetStatusPillHtml(t)+'</td><td class="agent-cell-response">'+agentResponseCellHtml(t.lastAgentResponse)+'</td><td><div class="table-actions">'+
        '<button type="button" class="btn" onclick="testTargetConnectionById(\''+qid+'\')" title="Test connection">'+AGENT_TABLE_ICON_TEST+'Test</button>'+
        '<button type="button" class="btn" onclick="beginEditTargetAgent(\''+qid+'\')" title="Edit agent">'+AGENT_TABLE_ICON_EDIT+'Edit</button>'+
        '<button type="button" class="btn btn-delete" onclick="deleteTargetAgent(\''+qid+'\')" title="Remove agent">'+AGENT_TABLE_ICON_DELETE+'Delete</button></div></td></tr>';
    }).join('');
  }

  function resetTargetFormFieldsAndTitle(){
    document.getElementById('targetAgentName').value='';
    document.getElementById('targetUri').value='';
    document.getElementById('targetTestMessage').value='';
    document.getElementById('targetRequestBody').value=defaultTargetBody;
    document.getElementById('toggleProxy').classList.remove('on');
    document.getElementById('proxyInput').disabled=true;
    document.getElementById('proxyInput').value='';
    document.getElementById('toggleTargetHeaders').classList.remove('on');
    document.getElementById('targetHeaders').disabled=true;
    document.getElementById('targetHeaders').value='';
    document.getElementById('toggleTargetRequest').classList.add('on');
    const tb=document.getElementById('targetRequestBody');
    tb.readOnly=false;tb.disabled=false;
    document.getElementById('toggleExtractPrompt').classList.remove('on');
    document.getElementById('extractPromptInput').disabled=true;
    document.getElementById('extractPromptInput').value='';
    applyTargetProtocolUi('http');
    setAgentFormUiMode('target','new');
  }

  function clearTargetFormForNew(){
    editingTargetFormId=null;
    resetTargetFormFieldsAndTitle();
    renderTargetAgentsTable();
    scheduleDashboardPersist();
  }

  function beginEditTargetAgent(id){
    setAgentFormPanelVisible('target',true);
    syncTargetFormToModel();
    saveTargetAgentsToStorage();
    editingTargetFormId=id;
    fillTargetFormFromModel();
    const t=targetAgents.find(x=>x.id===id);
    setAgentFormUiMode('target','edit',t?(t.name||t.uri):'',id);
    renderTargetAgentsTable();
    showView('agents-target');
  }

  function testTargetConnectionById(id){
    const t=targetAgents.find(x=>x.id===id);
    if(!t)return;
    if(!t.uri.trim()){
      t.status='disconnected';
      t.lastAgentResponse='URI required.';
      saveTargetAgentsToStorage();
      renderTargetAgentsTable();
      return;
    }
    t.lastAgentResponse=targetThinkingLabel(t);
    targetTestingIds.add(id);
    renderTargetAgentsTable();
    const mode=t.protocol==='socket'?'ws':'http';
    const body=t.targetRequestEnabled?(((t.requestBody||'').trim())||defaultTargetBody):defaultTargetBody;
    fetch('/api/target/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      uri:t.uri.trim(),request_body:body,test_message:(t.testMessage||'').trim()||'Hello from Agent Killer connection test',
      custom_headers:t.headersEnabled?t.headers.trim():'',proxy_url:t.proxyEnabled?t.proxy.trim():'',mode:mode
    })}).then(r=>r.json()).then(data=>{
      if(!data.ok)throw new Error(data.error||'Failed');
      t.status='connected';
      t.lastAgentResponse=String(data.response_preview||'').slice(0,800);
      saveTargetAgentsToStorage();
    }).catch(e=>{
      t.status='disconnected';
      t.lastAgentResponse=String(e.message||'Failed').slice(0,800);
      saveTargetAgentsToStorage();
    }).finally(function(){
      targetTestingIds.delete(id);
      renderTargetAgentsTable();
    });
  }

  function readTargetFormIntoObject(){
    return{
      name:document.getElementById('targetAgentName').value.trim(),
      uri:document.getElementById('targetUri').value.trim(),
      protocol:targetProtocol,
      testMessage:document.getElementById('targetTestMessage').value.trim()||'Hello from Agent Killer connection test',
      requestBody:getTargetRequestBodyTemplate(),
      proxyEnabled:document.getElementById('toggleProxy').classList.contains('on'),
      proxy:document.getElementById('toggleProxy').classList.contains('on')?document.getElementById('proxyInput').value.trim():'',
      headersEnabled:document.getElementById('toggleTargetHeaders').classList.contains('on'),
      headers:document.getElementById('toggleTargetHeaders').classList.contains('on')?document.getElementById('targetHeaders').value.trim():'',
      targetRequestEnabled:document.getElementById('toggleTargetRequest').classList.contains('on'),
      extractEnabled:document.getElementById('toggleExtractPrompt').classList.contains('on'),
      extractPrompt:document.getElementById('toggleExtractPrompt').classList.contains('on')?document.getElementById('extractPromptInput').value.trim():''
    };
  }

  function readAttackerFormIntoObject(){
    const hdrOn=document.getElementById('toggleAttackerHeaders').classList.contains('on');
    return{
      name:document.getElementById('attackerAgentName').value.trim(),
      uri:document.getElementById('attackerUri').value.trim(),
      initialPrompt:document.getElementById('attackerInitialPrompt').value.trim()||'You are an expert AI red-teamer and prompt injection specialist.',
      testMessage:document.getElementById('attackerTestMessage').value.trim()||'Hello from Agent Killer connection test',
      testRequest:document.getElementById('attackerTestRequest').value.trim()||DEFAULT_ATT_REQUEST,
      protocol:attackerProtocol,
      headersEnabled:hdrOn,
      headers:hdrOn?document.getElementById('attackerHeaders').value.trim():''
    };
  }

  function deleteAttackerAgent(id){
    if(!id)return;
    if(editingAttackerFormId===id)editingAttackerFormId=null;
    else syncAttackerFormToModel();
    attackerAgents=attackerAgents.filter(x=>x.id!==id);
    saveAttackerAgentsToStorage();
    if(!editingAttackerFormId)resetAttackerFormFieldsAndTitle();
    populateAgentSelects();
    renderAttackerAgentsTable();
    const sa=document.getElementById('selectAttackerAgent');
    if(sa&&!attackerAgents.some(x=>x.id===sa.value)&&attackerAgents.length){sa.value=attackerAgents[0].id;}
    applyAttackerPromptDefault();
    showStatus('attackerAgentStatus','ok','Agent removed.');
  }

  function saveAttackerAgent(){
    if(editingAttackerFormId){
      syncAttackerFormToModel();
      saveAttackerAgentsToStorage();
      renderAttackerAgentsTable();
      populateAgentSelects();
      const aUp=attackerAgents.find(x=>x.id===editingAttackerFormId);
      if(aUp)setAgentFormUiMode('attacker','edit',aUp.name||aUp.uri,editingAttackerFormId);
      showStatus('attackerAgentStatus','ok','Attacker agent updated.');
      return;
    }
    const f=readAttackerFormIntoObject();
    if(!f.uri){showStatus('attackerAgentStatus','err','URI is required.');return;}
    const n={
      id:genId(),
      name:f.name||'Attacker',
      uri:f.uri,
      initialPrompt:f.initialPrompt,
      testMessage:f.testMessage,
      testRequest:f.testRequest,
      protocol:f.protocol==='socket'?'socket':'http',
      headers:f.headers,
      headersEnabled:f.headersEnabled,
      status:'unknown',
      lastAgentResponse:''
    };
    attackerAgents.push(n);
    saveAttackerAgentsToStorage();
    populateAgentSelects();
    renderAttackerAgentsTable();
    clearAttackerFormForNew();
    showStatus('attackerAgentStatus','ok','Attacker agent added to the list.');
  }

  function testAttackerAgent(){
    const f=readAttackerFormIntoObject();
    if(!f.uri){showStatus('attackerAgentStatus','err','URI required.');return;}
    const hdr=f.headersEnabled?f.headers:'';
    const rowId=editingAttackerFormId;
    if(rowId){
      const a=attackerAgents.find(x=>x.id===rowId);
      if(a)a.lastAgentResponse=attackerThinkingLabel(a);
      attackerTestingIds.add(rowId);
    }
    else showStatus('attackerAgentStatus','info','Testing…');
    renderAttackerAgentsTable();
    const mode=f.protocol==='socket'?'ws':'http';
    fetch('/api/attacker/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uri:f.uri,request_body:f.testRequest,test_message:f.testMessage,custom_headers:hdr,mode:mode})})
      .then(r=>r.json()).then(data=>{
        if(!data.ok)throw new Error(data.error||'Failed');
        if(rowId){
          const a=attackerAgents.find(x=>x.id===rowId);
          if(a){
            syncAttackerFormToModel();
            a.status='connected';
            a.lastAgentResponse=String(data.response_preview||'').slice(0,800);
            saveAttackerAgentsToStorage();
          }
        }else{
          showStatus('attackerAgentStatus','ok','OK: '+(data.response_preview||'').slice(0,180));
        }
      }).catch(e=>{
        if(rowId){
          const a=attackerAgents.find(x=>x.id===rowId);
          if(a){
            a.status='disconnected';
            a.lastAgentResponse=String(e.message||'Failed').slice(0,800);
            saveAttackerAgentsToStorage();
          }
        }else{
          showStatus('attackerAgentStatus','err',e.message);
        }
      }).finally(function(){
        if(rowId) attackerTestingIds.delete(rowId);
        renderAttackerAgentsTable();
      });
  }

  function deleteTargetAgent(id){
    if(!id)return;
    if(editingTargetFormId===id)editingTargetFormId=null;
    else syncTargetFormToModel();
    targetAgents=targetAgents.filter(x=>x.id!==id);
    saveTargetAgentsToStorage();
    if(!editingTargetFormId)resetTargetFormFieldsAndTitle();
    populateAgentSelects();
    renderTargetAgentsTable();
    const st=document.getElementById('selectTargetAgent');
    if(st&&!targetAgents.some(x=>x.id===st.value)&&targetAgents.length){st.value=targetAgents[0].id;}
    showStatus('targetAgentStatus','ok','Agent removed.');
  }

  function saveTargetAgent(){
    if(editingTargetFormId){
      syncTargetFormToModel();
      saveTargetAgentsToStorage();
      renderTargetAgentsTable();
      populateAgentSelects();
      const tUp=targetAgents.find(x=>x.id===editingTargetFormId);
      if(tUp)setAgentFormUiMode('target','edit',tUp.name||tUp.uri,editingTargetFormId);
      showStatus('targetAgentStatus','ok','Target agent updated.');
      return;
    }
    const f=readTargetFormIntoObject();
    if(!f.uri){showStatus('targetAgentStatus','err','URI is required.');return;}
    const n={
      id:genId(),
      name:f.name||'Target',
      uri:f.uri,
      protocol:f.protocol==='socket'?'socket':'http',
      testMessage:f.testMessage,
      requestBody:f.requestBody,
      headers:f.headers,
      headersEnabled:f.headersEnabled,
      proxy:f.proxy,
      proxyEnabled:f.proxyEnabled,
      extractPrompt:f.extractPrompt,
      extractEnabled:f.extractEnabled,
      targetRequestEnabled:f.targetRequestEnabled,
      status:'unknown',
      lastAgentResponse:''
    };
    targetAgents.push(n);
    saveTargetAgentsToStorage();
    populateAgentSelects();
    renderTargetAgentsTable();
    clearTargetFormForNew();
    showStatus('targetAgentStatus','ok','Target agent added to the list.');
  }

  function populateAgentSelects(){
    const sa=document.getElementById('selectAttackerAgent');
    const st=document.getElementById('selectTargetAgent');
    const ca=sa.value, ct=st.value;
    sa.innerHTML=attackerAgents.map(a=>'<option value="'+a.id+'">'+esc(a.name||a.uri||a.id)+'</option>').join('');
    st.innerHTML=targetAgents.map(t=>'<option value="'+t.id+'">'+esc(t.name||t.uri||t.id)+'</option>').join('');
    if(attackerAgents.some(x=>x.id===ca)) sa.value=ca;
    if(targetAgents.some(x=>x.id===ct)) st.value=ct;
    applyAttackerPromptDefault();
  }

  function initJsonEditors(){
    const attacker=document.getElementById('attackerTestRequest');
    if(!attacker.value.trim()) attacker.value=DEFAULT_ATT_REQUEST;
    else attacker.value=prettyJson(attacker.value);
    attacker.addEventListener('blur',function(){this.value=prettyJson(this.value);scheduleDashboardPersist();});
    const target=document.getElementById('targetRequestBody');
    if(!target.value.trim()) target.value=defaultTargetBody;
  }

  function applyTheme(theme){
    const target=(theme==='dark')?'dark':'light';
    document.documentElement.setAttribute('data-theme',target);
    document.getElementById('themeToggle').classList.toggle('on',target==='dark');
    document.getElementById('themeLabel').textContent=target==='dark'?'Dark Mode':'Light Mode';
    localStorage.setItem('dashboardTheme',target);
  }

  function toggleTheme(){
    const current=document.documentElement.getAttribute('data-theme')||'light';
    applyTheme(current==='dark'?'light':'dark');
  }

  function loadTheme(){
    const saved=localStorage.getItem('dashboardTheme')||'light';
    applyTheme(saved);
  }

  function showView(name){
    const views=['initiate','running','results','agents-attacker','agents-target'];
    views.forEach(v=>{
      const el=document.getElementById('view-'+v);
      if(el) el.classList.toggle('active',v===name);
    });
    [['initiate','nav-initiate'],['running','nav-running'],['results','nav-results'],['agents-attacker','nav-agents-attacker'],['agents-target','nav-agents-target']].forEach(([v,nid])=>{
      const nav=document.getElementById(nid);
      if(nav) nav.classList.toggle('active',v===name);
    });
    if(name==='agents-attacker')renderAttackerAgentsTable();
    if(name==='agents-target')renderTargetAgentsTable();
    try{localStorage.setItem('dashboardLastView',name);}catch(_){}
    if(name==='agents-attacker'||name==='agents-target'){
      try{localStorage.setItem('agentKiller_sideTab',name==='agents-target'?'target':'attacker');}catch(_){}
    }
    if(name==='running')syncConversationInjectUi();
  }

  function applyTargetProtocolUi(mode){
    targetProtocol=mode;
    document.getElementById('targetProtocolHttp').classList.toggle('primary',mode==='http');
    document.getElementById('targetProtocolSocket').classList.toggle('primary',mode==='socket');
  }
  function setTargetProtocol(mode){
    applyTargetProtocolUi(mode);
    scheduleDashboardPersist();
  }
  function applyAttackerProtocolUi(mode){
    attackerProtocol=mode;
    document.getElementById('attackerProtocolHttp').classList.toggle('primary',mode==='http');
    document.getElementById('attackerProtocolSocket').classList.toggle('primary',mode==='socket');
  }
  function setAttackerProtocol(mode){
    applyAttackerProtocolUi(mode);
    scheduleDashboardPersist();
  }

  const TOGGLE_FIELD_MAP={context:'contextInput',objective:'objectiveInput',prompt:'promptInput',proxy:'proxyInput',targetRequest:'targetRequestBody',attackerHeaders:'attackerHeaders',targetHeaders:'targetHeaders',extractPrompt:'extractPromptInput'};

  function toggleField(name){
    const map=TOGGLE_FIELD_MAP;
    const t=document.getElementById('toggle'+name.charAt(0).toUpperCase()+name.slice(1));
    const on=t.classList.toggle('on');
    const field=document.getElementById(map[name]);
    if(name==='targetRequest'){
      field.readOnly=!on;
      field.disabled=false;
    }else{
      field.disabled=!on;
    }
    scheduleDashboardPersist();
  }

  function applyToggleState(name, on){
    const map=TOGGLE_FIELD_MAP;
    const t=document.getElementById('toggle'+name.charAt(0).toUpperCase()+name.slice(1));
    const field=document.getElementById(map[name]);
    if(!t||!field)return;
    t.classList.toggle('on',!!on);
    if(name==='targetRequest'){
      field.readOnly=!on;
      field.disabled=false;
    }else{
      field.disabled=!on;
    }
  }

  function saveAssessmentDraft(){
    const s={
      v:2,
      assessmentName:document.getElementById('assessmentName').value,
      selectAttackerId:document.getElementById('selectAttackerAgent').value,
      selectTargetId:document.getElementById('selectTargetAgent').value,
      toggles:{
        context:document.getElementById('toggleContext').classList.contains('on'),
        objective:document.getElementById('toggleObjective').classList.contains('on'),
        prompt:document.getElementById('togglePrompt').classList.contains('on')
      },
      contextText:document.getElementById('contextInput').value,
      objectiveText:document.getElementById('objectiveInput').value,
      promptText:document.getElementById('promptInput').value
    };
    try{localStorage.setItem(ASSESSMENT_DRAFT_KEY, JSON.stringify(s));}catch(_){}
  }

  function loadAssessmentDraft(){
    try{
      const raw=localStorage.getItem(ASSESSMENT_DRAFT_KEY);
      if(!raw)return;
      const s=JSON.parse(raw);
      if(!s||typeof s!=='object')return;
      if(s.assessmentName!=null) document.getElementById('assessmentName').value=s.assessmentName;
      const tg=s.toggles||{};
      if(typeof tg.context==='boolean') applyToggleState('context',tg.context);
      if(typeof tg.objective==='boolean') applyToggleState('objective',tg.objective);
      if(typeof tg.prompt==='boolean') applyToggleState('prompt',tg.prompt);
      if(s.contextText!=null) document.getElementById('contextInput').value=s.contextText;
      if(s.objectiveText!=null) document.getElementById('objectiveInput').value=s.objectiveText;
      if(s.promptText!=null) document.getElementById('promptInput').value=s.promptText;
      const sa=document.getElementById('selectAttackerAgent');
      const st=document.getElementById('selectTargetAgent');
      if(s.selectAttackerId && attackerAgents.some(x=>x.id===s.selectAttackerId)) sa.value=s.selectAttackerId;
      if(s.selectTargetId && targetAgents.some(x=>x.id===s.selectTargetId)) st.value=s.selectTargetId;
      else if(s.v!==2 && typeof s.targetUri==='string'){
        const u=s.targetUri.trim();
        const m=targetAgents.find(t=>(t.uri||'').trim()===u);
        if(m) st.value=m.id;
      }
      renderAttackerAgentsTable();renderTargetAgentsTable();
      applyAttackerPromptDefault();
      scheduleDashboardPersist();
    }catch(_){}
  }

  let _persistTimer=null;
  function scheduleDashboardPersist(){
    if(_persistTimer) clearTimeout(_persistTimer);
    _persistTimer=setTimeout(function(){
      _persistTimer=null;
      syncAttackerFormToModel();syncTargetFormToModel();
      saveAttackerAgentsToStorage();saveTargetAgentsToStorage();
      saveAssessmentDraft();
    },300);
  }

  function flushDashboardPersist(){
    if(_persistTimer){clearTimeout(_persistTimer);_persistTimer=null;}
    syncAttackerFormToModel();syncTargetFormToModel();
    saveAttackerAgentsToStorage();saveTargetAgentsToStorage();
    saveAssessmentDraft();
  }

  function bindFormPersistence(){
    const ids=['attackerAgentName','attackerUri','attackerInitialPrompt','attackerTestMessage','attackerTestRequest','attackerHeaders','targetAgentName','targetUri','targetTestMessage','proxyInput','targetHeaders','targetRequestBody','extractPromptInput','assessmentName','contextInput','objectiveInput','promptInput'];
    ids.forEach(function(id){
      const el=document.getElementById(id);
      if(!el)return;
      el.addEventListener('input',scheduleDashboardPersist);
      el.addEventListener('change',scheduleDashboardPersist);
    });
    ['selectAttackerAgent','selectTargetAgent'].forEach(function(id){
      const el=document.getElementById(id);
      if(!el)return;
      el.addEventListener('change',function(){
        if(id==='selectAttackerAgent'){applyAttackerPromptDefault();}
        scheduleDashboardPersist();
      });
    });
    const targetUriEl=document.getElementById('targetUri');
    if(targetUriEl){
      targetUriEl.addEventListener('input',function(){
        const v=this.value.trim().toLowerCase();
        if(v.startsWith('ws://')||v.startsWith('wss://')) applyTargetProtocolUi('socket');
      });
    }
    const attackerUriEl=document.getElementById('attackerUri');
    if(attackerUriEl){
      attackerUriEl.addEventListener('input',function(){
        const v=this.value.trim().toLowerCase();
        if(v.startsWith('ws://')||v.startsWith('wss://')) applyAttackerProtocolUi('socket');
      });
    }
    document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')flushDashboardPersist();});
    window.addEventListener('pagehide',flushDashboardPersist);
  }

  function testTargetMessage(){
    const f=readTargetFormIntoObject();
    if(!f.uri){showStatus('targetAgentStatus','err','URI required.');return;}
    const mode=f.protocol==='socket'?'ws':'http';
    const body=f.targetRequestEnabled?(((f.requestBody||'').trim())||defaultTargetBody):defaultTargetBody;
    const rowId=editingTargetFormId;
    if(rowId){
      const t=targetAgents.find(x=>x.id===rowId);
      if(t)t.lastAgentResponse=targetThinkingLabel(t);
      targetTestingIds.add(rowId);
    }
    else showStatus('targetAgentStatus','info','Testing…');
    renderTargetAgentsTable();
    fetch('/api/target/test',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        uri:f.uri.trim(),
        request_body:body,
        test_message:f.testMessage,
        custom_headers:f.headersEnabled?f.headers:'',
        proxy_url:f.proxyEnabled?f.proxy:'',
        mode:mode
      })
    })
      .then(r=>r.json())
      .then(data=>{
        if(!data.ok)throw new Error(data.error||'Test failed');
        if(rowId){
          const t=targetAgents.find(x=>x.id===rowId);
          if(t){
            syncTargetFormToModel();
            t.status='connected';
            t.lastAgentResponse=String(data.response_preview||'').slice(0,800);
            saveTargetAgentsToStorage();
          }
        }else{
          showStatus('targetAgentStatus','ok','OK: '+(data.response_preview||'').slice(0,180));
        }
      })
      .catch(err=>{
        if(rowId){
          const t=targetAgents.find(x=>x.id===rowId);
          if(t){
            t.status='disconnected';
            t.lastAgentResponse=String(err.message||'Failed').slice(0,800);
            saveTargetAgentsToStorage();
          }
        }else{
          showStatus('targetAgentStatus','err',err.message);
        }
      })
      .finally(function(){
        if(rowId) targetTestingIds.delete(rowId);
        renderTargetAgentsTable();
      });
  }

  function applyAttackerPromptDefault(){
    const sa=document.getElementById('selectAttackerAgent');
    const promptEl=document.getElementById('promptInput');
    if(!sa||!promptEl||!attackerAgents.length)return;
    const atk=attackerAgents.find(x=>x.id===sa.value)||attackerAgents[0];
    const ph=(atk.initialPrompt||'').trim();
    promptEl.placeholder=ph||'Overrides default for this assessment only.';
  }

  function launchAssessment(){
    flushDashboardPersist();
    const aid=document.getElementById('selectAttackerAgent').value;
    const tid=document.getElementById('selectTargetAgent').value;
    const atk=attackerAgents.find(x=>x.id===aid);
    const tgt=targetAgents.find(x=>x.id===tid);
    if(!atk||!tgt){showStatus('assessmentLaunchStatus','err','Select attacker and target agents.');return;}
    const atkUri=atk.uri.trim();
    const tgtUri=tgt.uri.trim();
    if(!atkUri){showStatus('assessmentLaunchStatus','err','Attacker agent URI is missing (configure under Attacker agents).');return;}
    if(!tgtUri){showStatus('assessmentLaunchStatus','err','Target agent URI is missing (configure under Target agents).');return;}
    const mode=tgt.protocol==='socket'?'ws':'http';
    const reqBody=tgt.targetRequestEnabled?(((tgt.requestBody||'').trim())||defaultTargetBody):defaultTargetBody;
    const promptEl=document.getElementById('promptInput');
    const initiation=(promptEl.value.trim()||(atk.initialPrompt||'').trim());
    const payload={
      assessment_name:(document.getElementById('assessmentName').value||'Untitled Assessment').trim(),
      attacker_agent_name:(atk.name||atk.uri||'Attacker').trim(),
      target_agent_name:(tgt.name||tgt.uri||'Target').trim(),
      advisor_url:atkUri,
      mode:mode,
      target_uri:tgtUri,
      context_enabled:document.getElementById('toggleContext').classList.contains('on'),
      context_text:document.getElementById('contextInput').value,
      objective_enabled:document.getElementById('toggleObjective').classList.contains('on'),
      objective_text:document.getElementById('objectiveInput').value,
      prompt_enabled:document.getElementById('togglePrompt').classList.contains('on'),
      initiation_prompt:initiation,
      proxy_enabled:!!tgt.proxyEnabled,
      proxy_url:(tgt.proxy||'').trim(),
      target_request_enabled:!!tgt.targetRequestEnabled,
      target_request_body:reqBody,
      attacker_request_body:(atk.testRequest||'').trim(),
      attacker_headers_enabled:!!atk.headersEnabled,
      attacker_headers:(atk.headers||'').trim(),
      target_headers_enabled:!!tgt.headersEnabled,
      target_headers:(tgt.headers||'').trim(),
      extract_prompt_enabled:!!tgt.extractEnabled,
      extract_prompt:(tgt.extractPrompt||'').trim()
    };
    showStatus('assessmentLaunchStatus','info','Launching…');
    fetch('/api/assessment/launch',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    }).then(r=>r.json()).then(d=>{
      if(!d.ok)throw new Error(d.error||'Launch failed');
      showStatusTemporary('assessmentLaunchStatus','ok','Assessment started.',2200,500);
      selectedAssessmentId=d.assessment_id || null;
      refreshAssessmentState();
      showView('running');
    }).catch(err=>{
      showStatus('assessmentLaunchStatus','err','Launch error: '+err.message);
    });
  }

  function currentDurationMs(a){
    if(a.assessmentPhase==='summarizing') return (a.durationSeconds||0)*1000;
    if(a.paused) return (a.durationSeconds||0)*1000;
    const base=(a.durationSeconds||0)*1000;
    const elapsed=Date.now()-(a._refreshedAt||Date.now());
    return base+elapsed;
  }
  function assessmentPhaseLabel(p){
    if(p==='stopping')return'Stopping';
    if(p==='summarizing')return'Evaluating';
    return'Running';
  }
  let _stopInitiatedIds=new Set();
  function fmtDuration(ms){
    const sec=Math.floor(ms/1000);const h=Math.floor(sec/3600);const m=Math.floor((sec%3600)/60);const s=sec%60;
    return [h,m,s].map(n=>String(n).padStart(2,'0')).join(':');
  }
  function fmtTs(ms){return new Date(ms).toLocaleTimeString();}

  let _prevRunIds='';
  function renderRunning(){
    const tbody=document.getElementById('runningRows');
    if(!assessments.length){tbody.innerHTML='<tr><td colspan="8" class="mono">No running assessments.</td></tr>';_prevRunIds='';return;}
    const phase=a=>a.assessmentPhase||'running';
    const curIds=assessments.map(a=>a.id+a.paused+a.worked+phase(a)+(_stopInitiatedIds.has(a.id)?'1':'0')+(a.attackerName||'')+(a.targetName||'')).join(',');
    if(curIds===_prevRunIds){tickDurations();return;}
    _prevRunIds=curIds;
    tbody.innerHTML=assessments.map(a=>{
      const ph=phase(a);
      const sum=ph==='summarizing';
      const userStopFlow=_stopInitiatedIds.has(a.id)||ph==='stopping';
      const pauseDis=(sum||userStopFlow)?' disabled':'';
      const phaseClass=ph==='stopping'?'phase-stopping':ph==='summarizing'?'phase-summarizing':'phase-running';
      const stopSvg='<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>';
      let stopBtn;
      if(userStopFlow){
        stopBtn='<button type="button" class="btn btn-stop" disabled><span class="btn-stop-initiated">Stop initiated</span></button>';
      } else if(sum){
        stopBtn='<button type="button" class="btn btn-stop" disabled>'+stopSvg+'Stop</button>';
      } else {
        stopBtn='<button type="button" class="btn btn-stop" onclick="finishAssessment(\''+a.id+'\')">'+stopSvg+'Stop</button>';
      }
      return`
      <tr>
        <td><button class="name-btn" onclick="selectAssessment('${a.id}')">${esc(a.name)}</button></td>
        <td class="agent-name-cell">${esc(a.attackerName||'—')}</td>
        <td class="agent-name-cell">${esc(a.targetName||'—')}</td>
        <td class="mono">${fmtTs(a.startedAt)}</td>
        <td class="mono"><span id="dur-${a.id}">${fmtDuration(currentDurationMs(a))}</span></td>
        <td><span class="assessment-phase ${phaseClass}"><span class="phase-spinner"></span>${esc(assessmentPhaseLabel(ph))}</span></td>
        <td><span class="leak-count ${a.worked>0?'has-leaks':'no-leaks'}">${LEAK_ICON_SVG}${a.worked||0}</span></td>
        <td><div class="actions-cell">
          <button class="btn btn-pause${a.paused?' is-resume':''}"${pauseDis} onclick="togglePause('${a.id}')">${a.paused?'<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><path d="M8 5.5v13L19 12 8 5.5z"/></svg>Resume':'<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg>Pause'}</button>
          ${stopBtn}
        </div></td>
      </tr>
    `}).join('');
    renderAssessmentLogs();
    syncConversationInjectUi();
  }
  function tickDurations(){
    assessments.forEach(a=>{
      const el=document.getElementById('dur-'+a.id);
      if(el) el.textContent=fmtDuration(currentDurationMs(a));
    });
  }

  function selectAssessment(id){selectedAssessmentId=id;renderAssessmentLogs();syncConversationInjectUi();}
  function syncConversationInjectUi(){
    const panel=document.getElementById('conversationInjectPanel');
    if(!panel)return;
    const a=assessments.find(x=>x.id===selectedAssessmentId);
    const sum=a&&(a.assessmentPhase==='summarizing');
    panel.style.display=a&&!sum?'block':'none';
    renderInjectQueue();
  }
  function renderInjectQueue(){
    const wrap=document.getElementById('injectQueueWrap');
    const list=document.getElementById('injectQueueList');
    if(!wrap||!list)return;
    const a=assessments.find(x=>x.id===selectedAssessmentId);
    const sum=a&&a.assessmentPhase==='summarizing';
    if(!a||sum){
      wrap.style.display='none';
      list.innerHTML='';
      return;
    }
    const raw=a.injectQueue;
    const items=Array.isArray(raw)?raw:[];
    if(!items.length){
      wrap.style.display='none';
      list.innerHTML='';
      return;
    }
    wrap.style.display='block';
    list.innerHTML=items.map(function(row,idx){
      const iid=String(row.id||'');
      return'<div class="inject-queue-row"><div class="inject-queue-text"><div class="inject-queue-meta"><span class="inject-queue-badge">Queued instruction #'+String(idx+1)+'</span></div>'+esc(row.text||'')+'</div><button type="button" class="inject-queue-remove" title="Remove from queue" data-inject-id="'+esc(iid)+'" onclick="cancelQueuedInjectFromBtn(this)">×</button></div>';
    }).join('');
  }
  function cancelQueuedInjectFromBtn(btn){
    const id=btn&&btn.getAttribute('data-inject-id');
    if(id)cancelQueuedInject(id);
  }
  function cancelQueuedInject(injectId){
    const sid=selectedAssessmentId;
    if(!sid||!injectId)return;
    fetch('/api/assessment/inject/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assessment_id:sid,inject_id:injectId})})
      .then(r=>r.json()).then(d=>{
        if(!d.ok)throw new Error(d.error||'Cancel failed');
        refreshAssessmentState();
      }).catch(e=>showStatus('injectMessageStatus','err',e.message));
  }
  function sendInjectMessage(){
    const sid=selectedAssessmentId;
    const msg=(document.getElementById('injectMessageInput').value||'').trim();
    if(!sid){showStatus('injectMessageStatus','err','Select a running assessment in the table above.');return;}
    if(!msg){showStatus('injectMessageStatus','err','Enter an instruction.');return;}
    fetch('/api/assessment/inject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assessment_id:sid,channel:'attacker',message:msg})})
      .then(r=>r.json()).then(d=>{
        if(!d.ok)throw new Error(d.error||'Send failed');
        document.getElementById('injectMessageInput').value='';
        showInjectMessageStatusOkFade('Instruction queued for the attacker AI.');
        refreshAssessmentState();
      }).catch(e=>showStatus('injectMessageStatus','err',e.message));
  }
  const chatAvatars={
    attacker:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1v3"/><circle cx="12" cy="1" r=".8"/><rect x="4" y="4" width="16" height="12" rx="2.5"/><path d="M7 7l3 2M17 7l-3 2"/><path d="M8 10.5l1.5-1.2 1.5 1.2M13 10.5l1.5-1.2 1.5 1.2"/><rect x="8" y="12.5" width="8" height="2" rx=".4"/><path d="M10.7 12.5v2M13.3 12.5v2"/><path d="M4 9H2.5M20 9h1.5"/><path d="M7.5 16v3.5a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5V16"/></svg>',
    victim:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1v3"/><circle cx="12" cy="1" r=".8"/><rect x="4.5" y="4" width="15" height="11" rx="2.5"/><circle cx="9" cy="9" r="1.2"/><circle cx="15" cy="9" r="1.2"/><path d="M9 12.5q3 2 6 0"/><path d="M4.5 8.5H3M19.5 8.5H21"/><path d="M7.5 15v4a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5v-4"/><path d="M12 15v1.5"/><path d="M10.5 16.5l1.5 4 1.5-4"/></svg>',
    system:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M7 9l3 2-3 2M13 13h4"/><path d="M8 21h8M12 17v4"/></svg>',
    eval:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M9 2v2h6V2"/><path d="M8 10l2 2 4-4"/><path d="M8 16h8"/></svg>',
    operator:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 9.5c.7-2.2 2.2-4 4-4s3.3 1.8 4 4"/><path d="M7.5 10c-2 1-3.4 3.2-3.8 6.2-.1.8.5 1.5 1.3 1.7 2.4.5 4.8.7 7 .7s4.6-.2 7-.7c.8-.2 1.4-.9 1.3-1.7-.4-3-1.8-5.2-3.8-6.2"/><path d="M8.6 9.2c.5-2.8 1.9-5.2 3.4-5.2s2.9 2.4 3.4 5.2"/><path d="M10.3 8.2h1.2M12.5 8.2h1.2"/><rect x="6.8" y="12" width="10.4" height="6.2" rx="1.1"/><circle cx="12" cy="15.1" r=".8"/><path d="M1.8 18.8h20.4"/></svg>'
  };
  const chatNames={attacker:'Attacker AI',victim:'Target Agent',system:'System',eval:'Evaluator',operator:'Operator',operator_instruct:'Operator',attacker_confirm:'Attacker AI',attacker_eval:'Attacker AI',attacker_ops:'Attacker AI (operator)',victim_ops:'Target Agent (operator)'};
  function chatDisplayName(a,role){
    const r=role||'system';
    if(a&&(r==='attacker'||r==='attacker_ops'||r==='attacker_confirm'||r==='attacker_eval')){
      if(r==='attacker_ops'){
        const n=a.attackerName!=null?String(a.attackerName).trim():'';
        return n?n+' (operator)':'Attacker AI (operator)';
      }
      if(r==='attacker_confirm'){
        const n=a.attackerName!=null?String(a.attackerName).trim():'';
        return n?n+' (reply to operator)':'Attacker AI (reply to operator)';
      }
      if(r==='attacker_eval'){
        const n=a.attackerName!=null?String(a.attackerName).trim():'';
        return n?n+' (objective)':'Attacker AI (objective)';
      }
      const n=a.attackerName!=null?String(a.attackerName).trim():'';
      if(n)return n;
    }
    if(a&&(r==='victim'||r==='victim_ops')){
      if(r==='victim_ops'){
        const n=a.targetName!=null?String(a.targetName).trim():'';
        return n?n+' (operator)':'Target Agent (operator)';
      }
      const n=a.targetName!=null?String(a.targetName).trim():'';
      if(n)return n;
    }
    return chatNames[r]||r;
  }
  function fmtChatTime(iso){
    if(!iso)return '';
    const d=new Date(iso);
    if(isNaN(d))return iso;
    const mm=String(d.getMonth()+1).padStart(2,'0');
    const dd=String(d.getDate()).padStart(2,'0');
    const hh=String(d.getHours()).padStart(2,'0');
    const mi=String(d.getMinutes()).padStart(2,'0');
    return d.getFullYear()+'-'+mm+'-'+dd+' '+hh+':'+mi;
  }
  const _OP_HDR_V='[→ VICTIM]\n';
  const _OP_HDR_A='[→ ATTACKER]\n';
  function operatorLogTitle(raw){
    const s=raw||'';
    if(s.startsWith(_OP_HDR_V))return'Operator · → Victim';
    if(s.startsWith(_OP_HDR_A))return'Operator · → Attacker';
    return'Operator';
  }
  function operatorInstructTitle(){
    return'Operator → Attacker (instruction)';
  }
  function formatOperatorBubbleHtml(raw){
    const s=raw||'';
    function splitHdr(hdr,label){
      if(!s.startsWith(hdr))return null;
      const rest=s.slice(hdr.length);
      const sep='\n\n';
      const i=rest.indexOf(sep);
      if(i<0)return'<div class="op-inject-body">'+esc(rest)+'</div>';
      const who=rest.slice(0,i);
      const body=rest.slice(i+sep.length);
      return'<div class="op-inject-dir">'+esc(label)+'</div><div class="op-inject-who">'+esc(who)+'</div><div class="op-inject-body">'+esc(body)+'</div>';
    }
    return splitHdr(_OP_HDR_V,'Operator → victim')||splitHdr(_OP_HDR_A,'Operator → attacker')||('<div class="op-inject-body">'+esc(s)+'</div>');
  }
  function formatAttackerConfirmBubbleHtml(raw){
    const body=esc(raw||'');
    return '<div class="attacker-confirm-dir">Attacker → operator reply</div><div class="op-inject-body">'+body+'</div>';
  }
  function typingBubble(role, assessment, typingPhase){
    const r=role||'system';
    const name=chatDisplayName(assessment||null,r);
    const avKey=r==='attacker_ops'||r==='attacker_confirm'||r==='attacker_eval'?'attacker':r==='victim_ops'?'victim':r==='operator_instruct'?'operator':r;
    const avatar=chatAvatars[avKey]||chatAvatars.system;
    const pos=r==='attacker'||r==='attacker_ops'||r==='attacker_confirm'||r==='attacker_eval'?'ti-left':r==='victim'||r==='victim_ops'?'ti-right':'ti-center';
    let label=name;
    if(r==='attacker' && typingPhase==='eval_plan')label=name+' — evaluating objective & planning next attack';
    else if(r==='attacker' && typingPhase==='thinking')label=name+' — thinking';
    else label=name+' is thinking';
    return '<div class="typing-indicator '+pos+'" id="typingIndicator"><div class="chat-avatar">'+avatar+'</div><div class="typing-meta"><span class="typing-label">'+esc(label)+'...</span><span class="typing-dots"><span></span><span></span><span></span></span></div></div>';
  }
  function renderAssessmentLogs(){
    const el=document.getElementById('assessmentLogs');
    const title=document.getElementById('assessmentDetailTitle');
    const a=assessments.find(x=>x.id===selectedAssessmentId);
    if(!a){title.textContent='Select an assessment to view the conversation.';el.innerHTML='';syncConversationInjectUi();return;}
    title.textContent='Conversation: '+a.name;
    const isRunning=assessments.some(x=>x.id===a.id);
    let html=a.logs.map(l=>{
      const r=l.role||'system';
      const name=r==='operator'?operatorLogTitle(l.message):r==='operator_instruct'?operatorInstructTitle():chatDisplayName(a,r);
      const bubble=r==='operator'?formatOperatorBubbleHtml(l.message):r==='attacker_confirm'?formatAttackerConfirmBubbleHtml(l.message):esc(l.message||'');
      const av=(r==='operator_instruct'?chatAvatars.operator:r==='attacker_eval'?chatAvatars.attacker:chatAvatars[r])||chatAvatars.system;
      return '<div class="chat-msg '+r+'"><div class="chat-avatar">'+av+'</div><div class="chat-body"><div class="chat-name">'+esc(name)+'</div><div class="chat-bubble">'+bubble+'</div><div class="chat-time">'+fmtChatTime(l.at)+'</div></div></div>';
    }).join('');
    if(isRunning && a.logs.length>0 && !a.paused && a.assessmentPhase!=='summarizing'){
      const last=a.logs[a.logs.length-1];
      const msg=(last.message||'').toUpperCase();
      const isDone=(last.role==='eval'||last.role==='attacker_eval') && msg.includes('OBJECTIVE ACHIEVED')
        || last.role==='system' && (msg.includes('COMPLETE') || msg.includes('SUMMARY') || msg.includes('STOPPED'));
      if(!isDone){
        let typingPhase=null;
        const nextRole=last.role==='operator_instruct'?'attacker_confirm'
          :last.role==='attacker_confirm'?(typingPhase='thinking','attacker')
          :last.role==='operator'
          ?((last.message||'').startsWith(_OP_HDR_V)?'victim_ops':'attacker_ops')
          :last.role==='attacker_ops'?'victim'
          :last.role==='victim_ops'?'attacker'
          :last.role==='attacker'?'victim'
          :last.role==='victim'?(typingPhase='eval_plan','attacker')
          :'attacker';
        html+=typingBubble(nextRole,a,typingPhase);
      }
    }
    const wasNearBottom=el.scrollHeight-el.scrollTop-el.clientHeight<60;
    el.innerHTML=html;
    if(wasNearBottom) el.scrollTop=el.scrollHeight;
    syncConversationInjectUi();
  }

  function togglePause(id){
    const a=assessments.find(x=>x.id===id);if(!a)return;
    if(a.assessmentPhase==='summarizing')return;
    if(_stopInitiatedIds.has(id)||(a.assessmentPhase||'')==='stopping')return;
    const endpoint=a.paused?'/api/assessment/resume':'/api/assessment/pause';
    fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assessment_id:id})})
      .then(()=>refreshAssessmentState());
  }

  function finishAssessment(id){
    _stopInitiatedIds.add(id);
    _prevRunIds='';
    renderRunning();
    fetch('/api/assessment/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assessment_id:id})})
      .then(()=>{
        if(selectedAssessmentId===id) selectedAssessmentId=null;
        refreshAssessmentState();
      })
      .catch(()=>{
        _stopInitiatedIds.delete(id);
        _prevRunIds='';
        renderRunning();
      });
  }

  function renderResults(){
    const tbody=document.getElementById('completedRows');
    if(!completed.length){tbody.innerHTML='<tr><td colspan="4" class="mono">No reports yet.</td></tr>';document.getElementById('resultDetailCard').style.display='none';return;}
    tbody.innerHTML=completed.map(a=>`
      <tr>
        <td><button class="name-btn" onclick="selectResult('${a.id}')">${esc(a.name)}</button></td>
        <td class="mono">${fmtDuration((a.durationSeconds||0)*1000)}</td>
        <td class="mono">${(a.worked||0)+(a.failed||0)}</td>
        <td class="mono"><span class="results-leak-cell" style="opacity:${a.worked>0?1:.72}">${LEAK_ICON_SVG}${a.worked||0}</span></td>
      </tr>
    `).join('');
    if(selectedResultId){renderResultDetail();}
  }

  function selectResult(id){selectedResultId=id;renderResultDetail();}
  function renderResultDetail(){
    const a=completed.find(x=>x.id===selectedResultId);
    const card=document.getElementById('resultDetailCard');
    if(!a){card.style.display='none';return;}
    card.style.display='block';
    document.getElementById('resultDetailTitle').textContent='Summary: '+a.name;
    const summaryEl=document.getElementById('resultSummary');
    const hasDetailed=a.logs.some(l=>l.message && l.message.startsWith('Detailed Summary:'));
    if(hasDetailed){
      summaryEl.innerHTML=esc(a.summary||'');
    } else {
      summaryEl.innerHTML='<div class="typing-indicator ti-center" style="justify-content:center"><div class="chat-avatar">'+(chatAvatars.eval)+'</div><div class="typing-meta"><span class="typing-label">Evaluator is generating summary...</span><span class="typing-dots"><span></span><span></span><span></span></span></div></div>';
    }
    const el=document.getElementById('resultLogs');
    let logsHtml=a.logs.map(l=>{
      const r=l.role||'system';
      const name=r==='operator'?operatorLogTitle(l.message):r==='operator_instruct'?operatorInstructTitle():chatDisplayName(a,r);
      const bubble=r==='operator'?formatOperatorBubbleHtml(l.message):r==='attacker_confirm'?formatAttackerConfirmBubbleHtml(l.message):esc(l.message||'');
      const av=(r==='operator_instruct'?chatAvatars.operator:r==='attacker_eval'?chatAvatars.attacker:chatAvatars[r])||chatAvatars.system;
      return '<div class="chat-msg '+r+'"><div class="chat-avatar">'+av+'</div><div class="chat-body"><div class="chat-name">'+esc(name)+'</div><div class="chat-bubble">'+bubble+'</div><div class="chat-time">'+fmtChatTime(l.at)+'</div></div></div>';
    }).join('');
    if(!hasDetailed) logsHtml+=typingBubble('eval',a,undefined);
    const wasNearBottom=el.scrollHeight-el.scrollTop-el.clientHeight<60;
    el.innerHTML=logsHtml;
    if(wasNearBottom) el.scrollTop=el.scrollHeight;
  }

  function appendEntryToAssessment(entry){
    const log={at:entry.timestamp||new Date().toISOString(),role:entry.role||'system',message:entry.message||''};
    const running=assessments.find(x=>x.id===entry.assessment_id);
    if(running){running.logs.push(log);if(selectedAssessmentId===running.id)renderAssessmentLogs();return;}
    const done=completed.find(x=>x.id===entry.assessment_id);
    if(done){done.logs.push(log);if(selectedResultId===done.id)renderResultDetail();}
  }

  function connectSSE(){
    const es=new EventSource('/events');
    es.addEventListener('entry',e=>{
      const entry=JSON.parse(e.data);
      appendEntryToAssessment(entry);
      refreshAssessmentState();
      if(selectedResultId)renderResultDetail();
    });
    es.onerror=()=>{es.close();setTimeout(connectSSE,3000);};
  }

  let _prevRunningIds=new Set();
  function refreshAssessmentState(){
    const now=Date.now();
    fetch('/api/assessment/state').then(r=>r.json()).then(state=>{
      const prevIds=_prevRunningIds;
      assessments=state.running || [];
      assessments.forEach(a=>{a._refreshedAt=now;});
      completed=state.completed || [];
      const curRunIds=new Set(assessments.map(a=>a.id));
      for(const sid of [..._stopInitiatedIds]){
        if(!curRunIds.has(sid)) _stopInitiatedIds.delete(sid);
      }
      _prevRunningIds=curRunIds;
      if(selectedAssessmentId&&!curRunIds.has(selectedAssessmentId)) selectedAssessmentId=null;
      if(!selectedAssessmentId && assessments.length){selectedAssessmentId=assessments[0].id;}
      let switched=false;
      if(prevIds.size>0){
        for(const pid of prevIds){
          if(!curRunIds.has(pid) && completed.some(c=>c.id===pid)){
            selectedResultId=pid;
            switched=true;
            break;
          }
        }
      }
      _prevRunIds='';
      renderRunning();
      renderResults();
      renderInjectQueue();
      if(switched) showView('results');
    }).catch(()=>{});
  }

  setInterval(tickDurations,200);
  setInterval(refreshAssessmentState,2000);
  loadTheme();
  migrateLegacyAgents();
  function finishAgentBootstrap(){
    resetAttackerFormFieldsAndTitle();
    resetTargetFormFieldsAndTitle();
    setAgentFormPanelVisible('attacker',false);
    setAgentFormPanelVisible('target',false);
    renderAttackerAgentsTable();
    renderTargetAgentsTable();
    populateAgentSelects();
    initJsonEditors();
    bindFormPersistence();
    loadAssessmentDraft();
    const _lv=localStorage.getItem('dashboardLastView');
    const _okViews=['initiate','running','results','agents-attacker','agents-target'];
    if(_lv&&_okViews.indexOf(_lv)>=0){showView(_lv);}
    else{showView('initiate');}
    refreshAssessmentState();
    connectSSE();
  }
  hydrateAgentsFromServer(finishAgentBootstrap);
</script>
</body>
</html>
"""

# ── HTTP Request Handler ──────────────────────────────────────────────────────
class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        log.info("GET %s from %s", self.path, self.address_string())
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

        elif self.path == "/api/assessment/state":
            data = {"running": [], "completed": []}
            if _state_handler:
                try:
                    data = _state_handler() or data
                except Exception as e:
                    data = {"error": str(e), "running": [], "completed": []}
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/agents":
            attackers = _read_agent_json_file(ATTACKER_AGENTS_JSON)
            targets = _read_agent_json_file(TARGET_AGENTS_JSON)
            body = json.dumps(
                {"ok": True, "attackers": attackers, "targets": targets},
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

    def do_POST(self):
        log.info("POST %s from %s", self.path, self.address_string())
        if self.path == "/api/attacker/test":
            payload = self._read_json_body()
            if not _attacker_test_handler:
                return self._send_json(500, {"ok": False, "error": "Attacker test handler not configured"})
            try:
                result = _attacker_test_handler(payload or {})
                log.info("Attacker test OK")
                return self._send_json(200, {"ok": True, **(result or {})})
            except Exception as e:
                log.error("Attacker test FAILED: %s", e)
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/target/test":
            payload = self._read_json_body()
            if not _target_test_handler:
                return self._send_json(500, {"ok": False, "error": "Target test handler not configured"})
            try:
                result = _target_test_handler(payload or {})
                log.info("Target test OK")
                return self._send_json(200, {"ok": True, **(result or {})})
            except Exception as e:
                log.error("Target test FAILED: %s", e)
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/assessment/launch":
            payload = self._read_json_body()
            if not _launch_handler:
                return self._send_json(500, {"ok": False, "error": "Launch handler not configured"})
            try:
                result = _launch_handler(payload or {})
                return self._send_json(200, {"ok": True, **(result or {})})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/assessment/pause":
            payload = self._read_json_body()
            assessment_id = (payload or {}).get("assessment_id")
            if not _pause_handler:
                return self._send_json(500, {"ok": False, "error": "Pause handler not configured"})
            try:
                _pause_handler(assessment_id)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/assessment/resume":
            payload = self._read_json_body()
            assessment_id = (payload or {}).get("assessment_id")
            if not _resume_handler:
                return self._send_json(500, {"ok": False, "error": "Resume handler not configured"})
            try:
                _resume_handler(assessment_id)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/assessment/finish":
            payload = self._read_json_body()
            assessment_id = (payload or {}).get("assessment_id")
            if not _finish_handler:
                return self._send_json(500, {"ok": False, "error": "Finish handler not configured"})
            try:
                _finish_handler(assessment_id)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/assessment/inject":
            payload = self._read_json_body()
            if not _inject_handler:
                return self._send_json(500, {"ok": False, "error": "Inject handler not configured"})
            p = payload or {}
            assessment_id = p.get("assessment_id")
            channel = p.get("channel")
            message = p.get("message")
            try:
                _inject_handler(assessment_id, channel, message)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/assessment/inject/cancel":
            payload = self._read_json_body()
            if not _inject_cancel_handler:
                return self._send_json(500, {"ok": False, "error": "Inject cancel handler not configured"})
            p = payload or {}
            assessment_id = p.get("assessment_id")
            inject_id = p.get("inject_id")
            try:
                _inject_cancel_handler(assessment_id, inject_id)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path == "/api/agents/attacker":
            payload = self._read_json_body()
            agents = payload if isinstance(payload, list) else []
            try:
                _write_agent_json_file(ATTACKER_AGENTS_JSON, agents)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                log.error("Save attacker agents failed: %s", e)
                return self._send_json(500, {"ok": False, "error": str(e)})

        if self.path == "/api/agents/target":
            payload = self._read_json_body()
            agents = payload if isinstance(payload, list) else []
            try:
                _write_agent_json_file(TARGET_AGENTS_JSON, agents)
                return self._send_json(200, {"ok": True})
            except Exception as e:
                log.error("Save target agents failed: %s", e)
                return self._send_json(500, {"ok": False, "error": str(e)})

        self.send_error(404)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
    try:
        server = ThreadingHTTPServer(("0.0.0.0", DASHBOARD_PORT), _Handler)
        server.daemon_threads = True
        log.info("Server bound to 0.0.0.0:%d", DASHBOARD_PORT)
        server.serve_forever()
    except Exception as e:
        log.critical("SERVER FAILED TO START: %s", e, exc_info=True)


def start_in_background():
    """Spawn the dashboard HTTP server in a daemon thread and return immediately."""
    t = threading.Thread(target=_run_server, daemon=True, name="dashboard-server")
    t.start()
    time.sleep(0.3)
    log.info("Dashboard live at http://localhost:%d", DASHBOARD_PORT)
    return t
