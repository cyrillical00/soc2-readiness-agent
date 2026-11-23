import ipaddress
import json
import os
import threading
from datetime import date

LIMIT_FILE = "rate_limits.json"
DAILY_LIMIT = 5

# How many reverse proxies in front of the app append to X-Forwarded-For.
# The default assumes Streamlit Community Cloud: one platform proxy, whose
# entry is the right-most one. Behind an extra proxy or CDN, set
# RATE_LIMIT_TRUSTED_PROXY_HOPS to the number of proxies you operate.
try:
    TRUSTED_PROXY_HOPS = max(1, int(os.environ.get("RATE_LIMIT_TRUSTED_PROXY_HOPS", "1")))
except ValueError:
    TRUSTED_PROXY_HOPS = 1

_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(LIMIT_FILE):
        return {}
    with open(LIMIT_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save(data: dict):
    with open(LIMIT_FILE, "w") as f:
        json.dump(data, f)


def get_client_ip(headers: dict) -> str:
    """Address our own proxy saw the request come from, or "unknown".

    Every proxy appends the address it received the request from, so the
    left-hand entries of X-Forwarded-For are whatever the client chose to
    send. Only the entry our own proxy added is trusted: the right-most one,
    or the Nth from the right with N trusted proxies. X-Real-IP and
    CF-Connecting-IP are not consulted, because a client can set those too.
    Visitors without a usable address share the "unknown" allowance.
    """
    forwarded = ""
    for key, val in headers.items():
        if str(key).lower() == "x-forwarded-for" and val:
            forwarded = str(val)
            break
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    if len(hops) < TRUSTED_PROXY_HOPS:
        return "unknown"
    try:
        return str(ipaddress.ip_address(hops[-TRUSTED_PROXY_HOPS]))
    except ValueError:
        return "unknown"


def check_limit(ip: str) -> tuple[bool, int]:
    """Returns (allowed, runs_remaining)."""
    today = str(date.today())
    with _lock:
        data = _load()
    entry = data.get(ip, {})

    if entry.get("date") != today:
        entry = {"date": today, "count": 0}

    remaining = DAILY_LIMIT - entry["count"]
    return remaining > 0, remaining


def record_run(ip: str):
    today = str(date.today())
    with _lock:
        # Yesterday's counters are dead weight; dropping them keeps the file small.
        data = {k: v for k, v in _load().items() if isinstance(v, dict) and v.get("date") == today}
        entry = data.get(ip, {"date": today, "count": 0})
        entry["count"] += 1
        data[ip] = entry
        _save(data)
