# """
# ws_transport.py
# ---------------
# WebSocket transport for the fuzzer.

# Two bugs fixed vs previous version:
# 1. "Duplicate header names" — websocket-client must receive headers as a plain
#    dict, not a list of "Key: Value" strings. Reserved WS headers are stripped
#    before passing so the library doesn't send them twice.
# 2. Proxy (Burp) support — pass socks/http proxy via the http_proxy_* kwargs
#    that websocket-client exposes, NOT via the environment or requests proxies.
# """

# import json
# import re
# import time
# import websocket   # pip install websocket-client


# # Headers that websocket-client sets automatically — never pass these yourself
# # or the server will see them twice and return 400.
# _RESERVED_WS_HEADERS = {
#     "upgrade", "connection", "sec-websocket-key",
#     "sec-websocket-version", "sec-websocket-extensions",
#     "host",   # also set automatically from the URL
# }


# def load_ws_config(path: str) -> dict:
#     with open(path, "r", encoding="utf-8") as f:
#         cfg = json.load(f)

#     required = ["url", "message_template"]
#     for key in required:
#         if key not in cfg:
#             raise ValueError(f"ws_config.json missing required key: '{key}'")

#     cfg.setdefault("headers",          {})
#     cfg.setdefault("init_messages",    [])
#     cfg.setdefault("placeholder",      "{{payload}}")
#     cfg.setdefault("response_timeout", 20)
#     cfg.setdefault("response_count",   1)
#     cfg.setdefault("extract",          {})
#     cfg.setdefault("proxy",            None)   # e.g. "http://127.0.0.1:8080"

#     return cfg


# # ──────────────────────────────────────────────────────────────────────────────
# # RESPONSE EXTRACTION
# # ──────────────────────────────────────────────────────────────────────────────

# def extract_readable_ws(frame: str, extract_cfg: dict) -> str:
#     if not extract_cfg:
#         return frame[:3000]

#     paths = extract_cfg.get("json_paths") or (
#         [extract_cfg["json_path"]] if "json_path" in extract_cfg else []
#     )

#     if paths:
#         try:
#             obj = json.loads(frame)
#             for path in paths:
#                 value = obj
#                 try:
#                     for key in path.split("."):
#                         value = value[int(key)] if isinstance(value, list) else value[key]
#                     if value and isinstance(value, str):
#                         return value
#                 except (KeyError, IndexError, TypeError, ValueError):
#                     continue
#         except json.JSONDecodeError:
#             pass

#     pattern = extract_cfg.get("regex")
#     if pattern:
#         m = re.search(pattern, frame, re.DOTALL)
#         if m:
#             try:
#                 return m.group(1)
#             except IndexError:
#                 return m.group(0)

#     # Generic key scan
#     try:
#         obj = json.loads(frame)
#         for key in ("text", "message", "content", "response", "reply", "data"):
#             val = obj.get(key)
#             if val and isinstance(val, str):
#                 return val
#             if val and isinstance(val, dict):
#                 for inner in ("text", "content", "message"):
#                     inner_val = val.get(inner)
#                     if inner_val and isinstance(inner_val, str):
#                         return inner_val
#     except (json.JSONDecodeError, AttributeError):
#         pass

#     return frame[:3000]


# # ──────────────────────────────────────────────────────────────────────────────
# # SEND PAYLOAD OVER WEBSOCKET
# # ──────────────────────────────────────────────────────────────────────────────

# def send_ws_payload(cfg: dict, payload: str) -> str:
#     url              = cfg["url"]
#     init_messages    = cfg.get("init_messages", [])
#     placeholder      = cfg.get("placeholder", "{{payload}}")
#     message_template = cfg["message_template"]
#     timeout          = cfg.get("response_timeout", 20)
#     response_count   = cfg.get("response_count", 1)
#     extract_cfg      = cfg.get("extract", {})
#     proxy            = cfg.get("proxy")   # e.g. "http://127.0.0.1:8080"

#     # ── Sanitise headers ────────────────────────────────────────────────────
#     # Pass as a plain dict — websocket-client handles this correctly.
#     # Strip any reserved headers to prevent the "Duplicate header names" 400.
#     raw_headers = cfg.get("headers", {})
#     safe_headers = {
#         k: v for k, v in raw_headers.items()
#         if k.lower() not in _RESERVED_WS_HEADERS
#     }

#     # ── Parse proxy for websocket-client kwargs ──────────────────────────────
#     # websocket-client does NOT accept a proxy URL string — it needs host/port.
#     proxy_kwargs = {}
#     if proxy:
#         proxy_host_port = re.sub(r"^https?://", "", proxy)
#         if ":" in proxy_host_port:
#             proxy_host, proxy_port_str = proxy_host_port.rsplit(":", 1)
#             proxy_kwargs = {
#                 "http_proxy_host": proxy_host,
#                 "http_proxy_port": int(proxy_port_str),
#                 "proxy_type": "http",   # ← this was missing, causes the error
#             }
#         else:
#             proxy_kwargs = {"http_proxy_host": proxy_host_port, "http_proxy_port": 8080}

#     collected_frames = []
#     error_holder     = [None]

#     ws_app = websocket.WebSocketApp(
#         url,
#         header=safe_headers,          # ← dict, not list of strings
#         on_error=lambda ws, err: error_holder.__setitem__(0, err),
#     )

#     def on_open(ws):
#         try:
#             for msg in init_messages:
#                 ws.send(msg if isinstance(msg, str) else json.dumps(msg))
#                 time.sleep(0.3)
#             payload_msg = message_template.replace(placeholder, payload)
#             ws.send(payload_msg)
#         except Exception as e:
#             error_holder[0] = e
#             ws.close()

#     def on_message(ws, message):
#         collected_frames.append(message)
#         if len(collected_frames) >= response_count:
#             ws.close()
#     def on_close(ws, close_status_code, close_msg):
#         print(f"[WS] Closed - status: {close_status_code}, msg: {close_msg}")

    
#     ws_app.on_open    = on_open
#     ws_app.on_message = on_message
#     ws_app.on_close = on_close
    
#     try:
#         ws_app.run_forever(
#             ping_interval=20,
#             ping_timeout=10,
#             sslopt={"cert_reqs": 0},   # equivalent to verify=False
#             **proxy_kwargs             # injects http_proxy_host/port if set
#         )
#     except Exception as e:
#         return f"[WS connection error] {e}"

#     if error_holder[0]:
#         return f"[WS error] {error_holder[0]}"

#     if not collected_frames:
#         return "[WS] No response received within timeout"

#     readable_parts = [extract_readable_ws(f, extract_cfg) for f in collected_frames]
#     return "\n".join(readable_parts)

"""
ws_transport.py
---------------
FINAL WORKING VERSION using websocat + timeout (compatible with apt version)
"""

import json
import subprocess


def load_ws_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    required = ["url", "message_template"]
    for key in required:
        if key not in cfg:
            raise ValueError(f"ws_config.json missing required key: '{key}'")

    cfg.setdefault("headers", {})
    cfg.setdefault("placeholder", "{{payload}}")
    cfg.setdefault("response_timeout", 15)
    cfg.setdefault("extract", {})

    return cfg


def extract_readable_ws(frame: str, extract_cfg: dict) -> str:
    if not extract_cfg:
        return frame

    paths = extract_cfg.get("json_paths") or []
    if not paths:
        return frame

    try:
        obj = json.loads(frame)
    except json.JSONDecodeError:
        return frame

    for path in paths:
        try:
            value = obj
            for key in path.split("."):
                value = value[int(key)] if isinstance(value, list) else value[key]

            if isinstance(value, str) and value.strip():
                return value
        except Exception:
            continue

    return frame


def send_ws_payload(cfg: dict, payload: str) -> str:
    url = cfg.get("url", "").strip()
    if not url:
        return "ERROR: Missing WebSocket URL"

    placeholder = cfg.get("placeholder", "{{payload}}")
    message_template = cfg["message_template"]
    timeout_sec = int(cfg.get("response_timeout", 15))
    extract_cfg = cfg.get("extract", {})
    headers = cfg.get("headers", {})

    payload_msg = message_template.replace(placeholder, payload)

    header_args = []
    for k, v in headers.items():
        header_args += ["-H", f"{k}: {v}"]

    cmd = [
        "timeout", f"{timeout_sec}s",
        "websocat",
        *header_args,
        "-1",
        url
    ]

    process = subprocess.run(
        cmd,
        input=(payload_msg + "\n").encode(),
        capture_output=True,
        timeout=timeout_sec + 5
    )

    stdout = process.stdout.decode("utf-8", errors="ignore")

    if not stdout.strip():
        return "NO RESPONSE"

    frames = [line.strip() for line in stdout.splitlines() if line.strip()]
    parsed = [extract_readable_ws(f, extract_cfg) for f in frames]

    result = "\n".join(parsed)

    # print(payload_msg)
    # print(result)

    return result