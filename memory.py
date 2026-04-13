import json

LOG_FILE = "logs.jsonl"


def log(entry: dict):
    """Append one interaction record to disk."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_logs(limit: int = 60) -> list:
    """Read the last N log entries from disk."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
            return [json.loads(l.strip()) for l in lines if l.strip()]
    except Exception:
        return []


def build_history(limit: int = 5) -> list:
    """
    Return a list of (payload, response) tuples from recent logs.
    Passed to the advisor so it has conversational context.
    """
    logs = read_logs(limit=limit)
    return [(e.get("payload", ""), e.get("response", "")) for e in logs]