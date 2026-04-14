"""
Kandji connector — blueprint compliance rate, encryption status, activation lock.
Covers: CC6, PI1
"""

import os
from datetime import datetime

import requests
import streamlit as st


def _get_creds():
    return {
        "base_url":  st.secrets.get("KANDJI_BASE_URL",  os.getenv("KANDJI_BASE_URL",  "")),
        "api_token": st.secrets.get("KANDJI_API_TOKEN", os.getenv("KANDJI_API_TOKEN", "")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return all(c.values())


def test_connection() -> tuple[bool, str]:
    c = _get_creds()
    if not all(c.values()):
        return False, "KANDJI_BASE_URL or KANDJI_API_TOKEN not set."
    try:
        r = requests.get(
            f"{c['base_url'].rstrip('/')}/api/v1/devices?limit=1",
            headers={"Authorization": f"Bearer {c['api_token']}", "Accept": "application/json"},
            timeout=10,
        )
        return (True, "Connected to Kandji.") if r.ok else (False, f"HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    c = _get_creds()
    base = c["base_url"].rstrip("/")
    headers = {"Authorization": f"Bearer {c['api_token']}", "Accept": "application/json"}
    findings = {}

    try:
        # --- Devices ---
        devices_r = requests.get(f"{base}/api/v1/devices?limit=300", headers=headers, timeout=20)
        devices = devices_r.json() if devices_r.ok else []
        if isinstance(devices, dict):
            devices = devices.get("results", devices.get("devices", []))
        total = len(devices)
        findings["total_managed_devices"] = total

        # --- Encryption ---
        encrypted = sum(
            1 for d in devices
            if d.get("filevault_enabled") or d.get("disk_encryption_enabled") or d.get("encrypted")
        )
        findings["encryption_enabled_count"] = encrypted
        findings["encryption_rate"] = round(encrypted / total * 100, 1) if total else 0

        # --- Activation lock ---
        act_locked = sum(1 for d in devices if d.get("activation_lock_enabled"))
        findings["activation_lock_count"] = act_locked

        # --- Blueprint compliance ---
        blueprints_r = requests.get(f"{base}/api/v1/blueprints", headers=headers, timeout=15)
        blueprints = blueprints_r.json() if blueprints_r.ok else []
        if isinstance(blueprints, dict):
            blueprints = blueprints.get("results", [])
        findings["blueprint_count"] = len(blueprints)

        # Compliance via device status
        compliant = sum(
            1 for d in devices
            if d.get("compliance_status", "").lower() in ("compliant", "pass")
        )
        findings["compliant_device_count"] = compliant
        findings["compliance_rate"] = round(compliant / total * 100, 1) if total else 0

        findings["_source"] = "kandji_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "total_managed_devices": 63,
        "encryption_enabled_count": 62,
        "encryption_rate": 98.4,
        "activation_lock_count": 5,
        "blueprint_count": 4,
        "compliant_device_count": 60,
        "compliance_rate": 95.2,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
