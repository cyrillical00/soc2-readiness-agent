import json
import os
from datetime import date

LIMIT_FILE = "rate_limits.json"
DAILY_LIMIT = 5


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
    for key in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
        val = headers.get(key)
        if val:
            return val.split(",")[0].strip()
    return "unknown"


def check_limit(ip: str) -> tuple[bool, int]:
    """Returns (allowed, runs_remaining)."""
    today = str(date.today())
    data = _load()
    entry = data.get(ip, {})

    if entry.get("date") != today:
        entry = {"date": today, "count": 0}

    remaining = DAILY_LIMIT - entry["count"]
    return remaining > 0, remaining


def record_run(ip: str):
    today = str(date.today())
    data = _load()
    entry = data.get(ip, {})

    if entry.get("date") != today:
        entry = {"date": today, "count": 0}

    entry["count"] += 1
    data[ip] = entry
    _save(data)
