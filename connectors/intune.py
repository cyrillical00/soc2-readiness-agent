"""
Intune connector — BitLocker status, compliance policy assignment, patch ring coverage.
Covers: CC6, PI1
"""

import os
from datetime import datetime

import requests
import streamlit as st


def _get_creds():
    return {
        "tenant_id":     st.secrets.get("INTUNE_TENANT_ID",     os.getenv("INTUNE_TENANT_ID",     "")),
        "client_id":     st.secrets.get("INTUNE_CLIENT_ID",     os.getenv("INTUNE_CLIENT_ID",     "")),
        "client_secret": st.secrets.get("INTUNE_CLIENT_SECRET", os.getenv("INTUNE_CLIENT_SECRET", "")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return all(c.values())


def _get_token(c: dict) -> str | None:
    try:
        r = requests.post(
            f"https://login.microsoftonline.com/{c['tenant_id']}/oauth2/v2.0/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     c["client_id"],
                "client_secret": c["client_secret"],
                "scope":         "https://graph.microsoft.com/.default",
            },
            timeout=15,
        )
        return r.json().get("access_token") if r.ok else None
    except Exception:
        return None


def test_connection() -> tuple[bool, str]:
    c = _get_creds()
    if not all(c.values()):
        return False, "INTUNE_TENANT_ID, INTUNE_CLIENT_ID, or INTUNE_CLIENT_SECRET not set."
    token = _get_token(c)
    if not token:
        return False, "Failed to obtain Microsoft Graph token."
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/deviceManagement",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        return (True, "Connected to Intune (Microsoft Graph).") if r.ok else (False, f"HTTP {r.status_code}")
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    c = _get_creds()
    token = _get_token(c)
    if not token:
        return {"_error": "Authentication failed", "_source": "intune_api"}

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    base = "https://graph.microsoft.com/v1.0/deviceManagement"
    findings = {}

    try:
        # --- Managed devices ---
        devices_r = requests.get(f"{base}/managedDevices?$top=999", headers=headers, timeout=20)
        devices = devices_r.json().get("value", []) if devices_r.ok else []
        total = len(devices)
        findings["total_managed_devices"] = total

        # --- BitLocker ---
        bitlocker_on = sum(1 for d in devices if d.get("isEncrypted"))
        findings["bitlocker_enabled_count"] = bitlocker_on
        findings["bitlocker_rate"] = round(bitlocker_on / total * 100, 1) if total else 0

        # --- Compliance ---
        compliant = sum(1 for d in devices if d.get("complianceState") == "compliant")
        findings["compliant_device_count"] = compliant
        findings["compliance_rate"] = round(compliant / total * 100, 1) if total else 0

        # --- Compliance policies assigned ---
        cp_r = requests.get(f"{base}/deviceCompliancePolicies", headers=headers, timeout=15)
        findings["compliance_policies_count"] = len(cp_r.json().get("value", [])) if cp_r.ok else 0

        # --- Update rings ---
        rings_r = requests.get(f"{base}/windowsUpdateForBusinessConfigurations", headers=headers, timeout=15)
        findings["patch_rings_count"] = len(rings_r.json().get("value", [])) if rings_r.ok else 0

        findings["_source"] = "intune_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "total_managed_devices": 114,
        "bitlocker_enabled_count": 111,
        "bitlocker_rate": 97.4,
        "compliant_device_count": 108,
        "compliance_rate": 94.7,
        "compliance_policies_count": 3,
        "patch_rings_count": 2,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
