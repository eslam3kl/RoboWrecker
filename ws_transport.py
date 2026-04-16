"""
ws_transport.py
---------------
WebSocket transport for assessments and connection tests (Windows-friendly).

Uses the ``websocket-client`` library.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any
from urllib.parse import unquote, urlparse

log = logging.getLogger("ws_transport")

try:
    import websocket
except ImportError as e:  # pragma: no cover
    websocket = None
    _IMPORT_ERROR = e
else:
    _IMPORT_ERROR = None

_RESERVED_WS_HEADERS = {
    "upgrade",
    "connection",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "host",
}

_WS_META_KEYS = frozenset(
    {
        "url",
        "message_template",
        "placeholder",
        "init_messages",
        "response_timeout",
        "response_count",
        "extract",
        "headers",
        "proxy",
    }
)


def load_ws_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    required = ["url", "message_template"]
    for key in required:
        if key not in cfg:
            raise ValueError(f"{path} missing required key: '{key}'")
    cfg.setdefault("headers", {})
    cfg.setdefault("placeholder", "{{payload}}")
    cfg.setdefault("response_timeout", 20)
    cfg.setdefault("response_count", 1)
    cfg.setdefault("extract", {})
    cfg.setdefault("init_messages", [])
    cfg.setdefault("proxy", None)
    return cfg


def is_websocket_url(uri: str | None) -> bool:
    """True if the URI should use WebSocket transport (not HTTP requests)."""
    if not uri or not isinstance(uri, str):
        return False
    u = uri.strip().lstrip("\ufeff").lower()
    return u.startswith("ws://") or u.startswith("wss://")


def extract_readable_ws(frame: str, extract_cfg: dict) -> str:
    if not extract_cfg:
        return frame

    paths = extract_cfg.get("json_paths") or (
        [extract_cfg["json_path"]] if extract_cfg.get("json_path") else []
    )
    if paths:
        try:
            obj = json.loads(frame)
            for path in paths:
                try:
                    value = obj
                    for key in path.split("."):
                        value = value[int(key)] if isinstance(value, list) else value[key]
                    if isinstance(value, str) and value.strip():
                        return value
                except Exception:
                    continue
        except json.JSONDecodeError:
            pass

    pattern = extract_cfg.get("regex")
    if pattern:
        m = re.search(pattern, frame, re.DOTALL)
        if m:
            try:
                return m.group(1)
            except IndexError:
                return m.group(0)

    try:
        obj = json.loads(frame)
        for key in ("text", "message", "content", "response", "reply", "data"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val
            if isinstance(val, dict):
                for inner in ("text", "content", "message"):
                    inner_val = val.get(inner)
                    if isinstance(inner_val, str) and inner_val.strip():
                        return inner_val
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass

    return frame


def _ensure_client():
    if websocket is None or _IMPORT_ERROR is not None:
        raise RuntimeError(
            "websocket-client is required for WebSocket mode. "
            "Install with: pip install websocket-client"
        ) from _IMPORT_ERROR


def _sanitize_headers(raw: dict | None) -> list:
    if not raw:
        return []
    out = []
    for k, v in raw.items():
        kl = str(k).strip()
        if kl.lower() in _RESERVED_WS_HEADERS:
            continue
        out.append(f"{kl}: {v}")
    return out


def proxy_kwargs_from_url(proxy_url: str | None) -> dict:
    """Map proxy URL to websocket-client connect() kwargs (HTTP / SOCKS / auth)."""
    if not proxy_url or not str(proxy_url).strip():
        return {}
    raw = str(proxy_url).strip()
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    scheme = (p.scheme or "http").lower()
    host = p.hostname
    if not host:
        return {}

    port = p.port
    auth = None
    if p.username is not None or p.password is not None:
        auth = (unquote(p.username or ""), unquote(p.password or ""))

    if scheme in ("http", "https"):
        proxy_type = "http"
        port = port or 8080
    elif scheme in ("socks5", "socks5h"):
        proxy_type = scheme
        port = port or 1080
    elif scheme in ("socks4", "socks4a"):
        proxy_type = scheme
        port = port or 1080
    else:
        proxy_type = "http"
        port = port or 8080

    out: dict[str, Any] = {
        "http_proxy_host": host,
        "http_proxy_port": int(port),
        "proxy_type": proxy_type,
    }
    if auth:
        out["http_proxy_auth"] = auth
    return out


def merge_target_ws_config(
    target_uri: str,
    target_request_body: str = "",
    extra_headers: dict | None = None,
    proxy_url: str | None = None,
) -> dict:
    """
    Connection options for WebSocket. Strips transport-only keys from JSON into cfg and
    stores the remainder in ``_payload_template`` for the same HTTP-style body builder
    (placeholders, messages merge) in main.py.
    """
    cfg: dict[str, Any] = {
        "url": (target_uri or "").strip(),
        "headers": dict(extra_headers or {}),
        "placeholder": "{{payload}}",
        "message_template": "{{message}}",
        "response_timeout": 20,
        "response_count": 1,
        "extract": {},
        "init_messages": [],
        "proxy": (proxy_url or "").strip() or None,
        "_payload_template": "",
    }

    body = (target_request_body or "").strip()
    if not body:
        return cfg

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        cfg["_payload_template"] = body
        return cfg

    if isinstance(parsed, dict):
        meta = {k: v for k, v in parsed.items() if k in _WS_META_KEYS}
        meta_headers = meta.pop("headers", None)
        cfg.update(meta)
        if isinstance(meta_headers, dict) and meta_headers:
            cfg["headers"] = {**cfg.get("headers", {}), **meta_headers}
        body_only = {k: v for k, v in parsed.items() if k not in _WS_META_KEYS}
        cfg["_payload_template"] = (
            json.dumps(body_only, ensure_ascii=False) if body_only else ""
        )
        if cfg.get("url") in ("", None):
            cfg["url"] = (target_uri or "").strip()
    else:
        cfg["_payload_template"] = (
            parsed if isinstance(parsed, str) else json.dumps(parsed, ensure_ascii=False)
        )

    return cfg


def send_ws_payload(cfg: dict, outbound_message: str) -> str:
    """Send ``outbound_message`` as the main WebSocket text frame (after optional init_messages)."""
    _ensure_client()

    url = (cfg.get("url") or "").strip()
    if not url:
        return "[WS Error] Missing WebSocket URL"

    timeout_sec = float(cfg.get("response_timeout", 20))
    response_count = max(1, int(cfg.get("response_count", 1)))
    extract_cfg = cfg.get("extract") or {}
    init_messages = cfg.get("init_messages") or []

    raw_headers = cfg.get("headers") or {}
    safe_header_list = _sanitize_headers(raw_headers if isinstance(raw_headers, dict) else {})

    proxy = cfg.get("proxy")
    proxy_kwargs = proxy_kwargs_from_url(proxy)

    msg_out = outbound_message

    sslopt = {"cert_reqs": 0}

    log.debug("WS connect -> %s  proxy=%s", url, proxy or "none")

    try:
        ws = websocket.create_connection(
            url,
            header=safe_header_list or None,
            sslopt=sslopt,
            timeout=timeout_sec,
            **proxy_kwargs,
        )
    except Exception as e:
        log.warning("WS connect failed: %s", e)
        return f"[WS connection error] {e}"

    frames: list[str] = []
    try:
        for raw in init_messages:
            if isinstance(raw, dict):
                ws.send(json.dumps(raw))
            else:
                ws.send(str(raw))
            time.sleep(0.05)

        ws.send(msg_out)

        deadline = time.time() + timeout_sec
        while len(frames) < response_count and time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ws.settimeout(min(remaining, max(0.5, timeout_sec / 4)))
            try:
                incoming = ws.recv()
            except Exception as e:
                log.debug("WS recv end: %s", e)
                break
            if incoming is None:
                continue
            if isinstance(incoming, bytes):
                try:
                    incoming = incoming.decode("utf-8", errors="replace")
                except Exception:
                    incoming = str(incoming)
            frames.append(str(incoming))
    except Exception as e:
        log.warning("WS exchange failed: %s", e)
        return f"[WS error] {e}"
    finally:
        try:
            ws.close()
        except Exception:
            pass

    if not frames:
        return "[WS] No response received within timeout"

    readable = [extract_readable_ws(f, extract_cfg) for f in frames]
    return "\n".join(readable)
