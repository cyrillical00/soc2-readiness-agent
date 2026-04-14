"""
Jamf Pro connector — FileVault encryption, OS patch compliance, MDM enrollment.
Covers: CC6, PI1
"""

import os
from datetime import datetime

import requests
import streamlit as st


def _get_creds():
    return {
        "base_url":      st.secrets.get("JAMF_BASE_URL",      os.getenv("JAMF_BASE_URL",      "")),
        "client_id":     st.secrets.get("JAMF_CLIENT_ID",     os.getenv("JAMF_CLIENT_ID",     "")),
        "client_secret": st.secrets.get("JAMF_CLIENT_SECRET", os.getenv("JAMF_CLIENT_SECRET", "")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return all(c.values())


def _get_token(c: dict) -> str | None:
    """OAuth2 client credentials for Jamf Pro API."""
    try:
        r = requests.post(
            f"{c['base_url'].rstrip('/')}/api/oauth/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     c["client_id"],
                "client_secret": c["client_secret"],
            },
            timeout=15,
        )
        return r.json().get("access_token") if r.ok else None
    except Exception:
        return None


def test_connection() -> tuple[bool, str]:
    c = _get_creds()
    if not all(c.values()):
        return False, "JAMF_BASE_URL, JAMF_CLIENT_ID, or JAMF_CLIENT_SECRET not set."
    token = _get_token(c)
    if not token:
        return False, "Failed to obtain Jamf access token — check credentials."
    try:
        r = requests.get(
            f"{c['base_url'].rstrip('/')}/api/v1/jamf-pro-information",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=10,
        )
        if r.ok:
            info = r.json()
            return True, f"Connected to Jamf Pro {info.get('version', '')}"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    c = _get_creds()
    base = c["base_url"].rstrip("/")
    token = _get_token(c)
    if not token:
        return {"_error": "Could not authenticate to Jamf", "_source": "jamf_api"}

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    findings = {}

    try:
        # --- Computers summary ---
        computers_resp = requests.get(f"{base}/api/v1/computers-preview", headers=headers, timeout=20)
        computers = computers_resp.json().get("results", []) if computers_resp.ok else []
        total = len(computers)
        findings["total_managed_devices"] = total

        # --- FileVault encryption ---
        encrypted = sum(1 for c2 in computers if c2.get("diskEncryptionEnabled"))
        findings["filevault_enabled_count"] = encrypted
        findings["filevault_rate"] = round(encrypted / total * 100, 1) if total else 0

        # --- OS patch compliance ---
        # Jamf reports managementId; fetch each for OS detail — limited to 100
        outdated = 0
        for comp in computers[:100]:
            detail_r = requests.get(
                f"{base}/api/v1/computers-preview/{comp['id']}",
                headers=headers, timeout=10,
            )
            if detail_r.ok:
                detail = detail_r.json()
                os_ver = detail.get("operatingSystemVersion", "")
                # Simplified: flag anything not on macOS 14+ as potentially outdated
                if os_ver and not os_ver.startswith("14") and not os_ver.startswith("15"):
                    outdated += 1

        findings["os_outdated_estimate"] = outdated
        findings["patch_compliance_rate"] = round((min(100, total) - outdated) / min(100, total) * 100, 1) if total else 0

        findings["_source"] = "jamf_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "total_managed_devices": 87,
        "filevault_enabled_count": 85,
        "filevault_rate": 97.7,
        "os_outdated_estimate": 6,
        "patch_compliance_rate": 93.1,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
