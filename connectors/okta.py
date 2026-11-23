"""
Okta connector — pulls MFA enrollment, inactive users, admin roles, app integrations.
Covers: CC6 (Logical Access), CC5 (Risk Mitigation)
"""

import os
import re
import requests
import streamlit as st

from auth import secret
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

# Hosts Okta itself operates. The API token is sent to this host, so anything
# else (an internal host, an IP address, a look-alike) is refused. A custom
# domain such as login.example.com cannot be told apart from an arbitrary
# host and is not accepted; use the org's own *.okta.com name.
_OKTA_HOST_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"\.(?:okta\.com|oktapreview\.com|okta-emea\.com|okta-gov\.com|okta\.mil)"
)


def normalize_okta_domain(domain: str) -> str:
    """Return the bare Okta hostname for `domain`, or raise ValueError."""
    host = (domain or "").strip().lower()
    for scheme in ("https://", "http://"):
        if host.startswith(scheme):
            host = host[len(scheme):]
    host = host.rstrip("/")
    if not _OKTA_HOST_RE.fullmatch(host):
        raise ValueError(
            "OKTA_DOMAIN must be the org's Okta domain, for example yourorg.okta.com "
            "(okta.com, oktapreview.com, okta-emea.com, okta-gov.com or okta.mil)."
        )
    return host


def _get_creds():
    domain = secret("OKTA_DOMAIN")
    token  = secret("OKTA_API_TOKEN")
    return domain.rstrip("/"), token


def _same_host(url: str, domain: str) -> bool:
    target = urlsplit(url)
    return target.scheme == "https" and target.netloc.lower() == domain


def _get(url: str, domain: str, headers: dict, timeout: int = 10):
    """GET a URL on the validated Okta host. Redirects are not followed, so the
    token is never replayed to wherever a response points."""
    if not _same_host(url, domain):
        raise ValueError("Refusing to send the Okta token to a host other than the configured org.")
    return requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)


def is_configured() -> bool:
    domain, token = _get_creds()
    return bool(domain and token)


def test_connection() -> tuple[bool, str]:
    domain, token = _get_creds()
    if not domain or not token:
        return False, "OKTA_DOMAIN or OKTA_API_TOKEN not set."
    try:
        domain = normalize_okta_domain(domain)
        r = _get(
            f"https://{domain}/api/v1/org",
            domain,
            {"Authorization": f"SSWS {token}", "Accept": "application/json"},
        )
        if r.status_code == 200:
            org = r.json()
            return True, f"Connected to {org.get('companyName', domain)}"
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def _paginate(url: str, domain: str, headers: dict) -> list:
    """Collect every page. A next link is followed only on the same Okta host."""
    results = []
    while url:
        r = _get(url, domain, headers, timeout=15)
        r.raise_for_status()
        if r.status_code != 200:
            raise ValueError(f"Unexpected HTTP {r.status_code} from Okta")
        results.extend(r.json())
        url = r.links.get("next", {}).get("url")
        if url and not _same_host(url, domain):
            raise ValueError("Okta returned a next-page link to another host; not following it.")
    return results


def collect(demo: bool = False) -> dict:
    """Return structured findings dict. Uses demo data if demo=True or not configured."""
    if demo or not is_configured():
        return _demo_data()

    domain, token = _get_creds()
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    findings = {}

    try:
        domain = normalize_okta_domain(domain)
        base = f"https://{domain}/api/v1"

        # --- Active users ---
        users = _paginate(f"{base}/users?filter=status+eq+%22ACTIVE%22&limit=200", domain, headers)
        total_users = len(users)
        findings["total_active_users"] = total_users

        # --- MFA enrollment ---
        mfa_enrolled = 0
        for u in users:
            uid = u["id"]
            factors_r = _get(f"{base}/users/{uid}/factors", domain, headers)
            if factors_r.ok and factors_r.json():
                mfa_enrolled += 1
        findings["mfa_enrolled_count"] = mfa_enrolled
        findings["mfa_enrollment_rate"] = round(mfa_enrolled / total_users * 100, 1) if total_users else 0

        # --- Inactive users (no login in 90+ days) ---
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        inactive = _paginate(
            f"{base}/users?filter=status+eq+%22ACTIVE%22+and+lastLogin+lt+%22{cutoff}%22&limit=200",
            domain,
            headers,
        )
        findings["inactive_users_90d"] = len(inactive)
        findings["inactive_user_rate"] = round(len(inactive) / total_users * 100, 1) if total_users else 0

        # --- Admin roles ---
        admins = []
        for u in users:
            roles_r = _get(f"{base}/users/{u['id']}/roles", domain, headers)
            if roles_r.ok and roles_r.json():
                admins.append({
                    "id": u["id"],
                    "login": u["profile"].get("login"),
                    "roles": [r["type"] for r in roles_r.json()],
                })
        findings["admin_count"]  = len(admins)
        findings["admin_logins"] = [a["login"] for a in admins]

        # --- Password policy ---
        policies_r = _get(f"{base}/policies?type=PASSWORD&limit=50", domain, headers)
        findings["password_policies_count"] = len(policies_r.json()) if policies_r.ok else 0

        # --- App integrations ---
        apps_r = _get(f"{base}/apps?filter=status+eq+%22ACTIVE%22&limit=200", domain, headers, timeout=15)
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
