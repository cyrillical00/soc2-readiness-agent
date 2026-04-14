"""
Okta connector — pulls MFA enrollment, inactive users, admin roles, app integrations.
Covers: CC6 (Logical Access), CC5 (Risk Mitigation)
"""

import os
import requests
import streamlit as st
from datetime import datetime, timedelta, timezone


def _get_creds():
    domain = st.secrets.get("OKTA_DOMAIN", os.getenv("OKTA_DOMAIN", ""))
    token  = st.secrets.get("OKTA_API_TOKEN", os.getenv("OKTA_API_TOKEN", ""))
    return domain.rstrip("/"), token


def is_configured() -> bool:
    domain, token = _get_creds()
    return bool(domain and token)


def test_connection() -> tuple[bool, str]:
    domain, token = _get_creds()
    if not domain or not token:
        return False, "OKTA_DOMAIN or OKTA_API_TOKEN not set."
    try:
        r = requests.get(
            f"https://{domain}/api/v1/org",
            headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            org = r.json()
            return True, f"Connected to {org.get('companyName', domain)}"
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def _paginate(url: str, headers: dict) -> list:
    results = []
    while url:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        results.extend(r.json())
        url = r.links.get("next", {}).get("url")
    return results


def collect(demo: bool = False) -> dict:
    """Return structured findings dict. Uses demo data if demo=True or not configured."""
    if demo or not is_configured():
        return _demo_data()

    domain, token = _get_creds()
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    base = f"https://{domain}/api/v1"
    findings = {}

    try:
        # --- Active users ---
        users = _paginate(f"{base}/users?filter=status+eq+%22ACTIVE%22&limit=200", headers)
        total_users = len(users)
        findings["total_active_users"] = total_users

        # --- MFA enrollment ---
        mfa_enrolled = 0
        for u in users:
            uid = u["id"]
            factors_r = requests.get(f"{base}/users/{uid}/factors", headers=headers, timeout=10)
            if factors_r.ok and factors_r.json():
                mfa_enrolled += 1
        findings["mfa_enrolled_count"] = mfa_enrolled
        findings["mfa_enrollment_rate"] = round(mfa_enrolled / total_users * 100, 1) if total_users else 0

        # --- Inactive users (no login in 90+ days) ---
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        inactive = _paginate(
            f"{base}/users?filter=status+eq+%22ACTIVE%22+and+lastLogin+lt+%22{cutoff}%22&limit=200",
            headers,
        )
        findings["inactive_users_90d"] = len(inactive)
        findings["inactive_user_rate"] = round(len(inactive) / total_users * 100, 1) if total_users else 0

        # --- Admin roles ---
        admins = []
        for u in users:
            roles_r = requests.get(f"{base}/users/{u['id']}/roles", headers=headers, timeout=10)
            if roles_r.ok and roles_r.json():
                admins.append({
                    "id": u["id"],
                    "login": u["profile"].get("login"),
                    "roles": [r["type"] for r in roles_r.json()],
                })
        findings["admin_count"]  = len(admins)
        findings["admin_logins"] = [a["login"] for a in admins]

        # --- Password policy ---
        policies_r = requests.get(f"{base}/policies?type=PASSWORD&limit=50", headers=headers, timeout=10)
        findings["password_policies_count"] = len(policies_r.json()) if policies_r.ok else 0

        # --- App integrations ---
        apps_r = requests.get(f"{base}/apps?filter=status+eq+%22ACTIVE%22&limit=200", headers=headers, timeout=15)
        findings["active_app_count"] = len(apps_r.json()) if apps_r.ok else 0

        findings["_source"] = "okta_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "total_active_users": 142,
        "mfa_enrolled_count": 138,
        "mfa_enrollment_rate": 97.2,
        "inactive_users_90d": 4,
        "inactive_user_rate": 2.8,
        "admin_count": 5,
        "admin_logins": ["alice@acme.com", "bob@acme.com", "carol@acme.com", "dave@acme.com", "eve@acme.com"],
        "password_policies_count": 2,
        "active_app_count": 38,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
