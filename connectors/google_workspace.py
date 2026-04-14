"""
Google Workspace connector — 2SV enforcement, sharing settings, DLP, audit logs.
Covers: CC6, C1, P6
"""

import base64
import json
import os
from datetime import datetime

import streamlit as st


def _get_credentials():
    raw = st.secrets.get("GOOGLE_SERVICE_ACCOUNT_JSON", os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", ""))
    if not raw:
        return None
    try:
        decoded = base64.b64decode(raw).decode()
        return json.loads(decoded)
    except Exception:
        return None


def is_configured() -> bool:
    return _get_credentials() is not None


def test_connection() -> tuple[bool, str]:
    creds_dict = _get_credentials()
    if not creds_dict:
        return False, "GOOGLE_SERVICE_ACCOUNT_JSON not set or invalid."
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        creds = service_account.Credentials.from_service_account_info(
            creds_dict,
            scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
        )
        svc = build("admin", "directory_v1", credentials=creds)
        svc.users().list(customer="my_customer", maxResults=1).execute()
        return True, "Connected to Google Workspace."
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    creds_dict = _get_credentials()
    findings = {}
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        scopes = [
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.domain.readonly",
            "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        ]
        creds = service_account.Credentials.from_service_account_info(creds_dict, scopes=scopes)

        admin_svc = build("admin", "directory_v1", credentials=creds)

        # --- Active users ---
        resp = admin_svc.users().list(customer="my_customer", maxResults=500).execute()
        users = resp.get("users", [])
        total = len(users)
        findings["total_users"] = total

        enrolled_2sv  = sum(1 for u in users if u.get("isEnrolledIn2Sv"))
        enforced_2sv  = sum(1 for u in users if u.get("isEnforcedIn2Sv"))
        suspended     = sum(1 for u in users if u.get("suspended"))

        findings["2sv_enrolled_count"]  = enrolled_2sv
        findings["2sv_enforced_count"]  = enforced_2sv
        findings["2sv_enrollment_rate"] = round(enrolled_2sv / total * 100, 1) if total else 0
        findings["suspended_users"]     = suspended
        findings["admin_users"]         = sum(1 for u in users if u.get("isAdmin"))

        # --- Shared drives / external sharing (requires Admin SDK Reports) ---
        reports_svc = build("admin", "reports_v1", credentials=creds)
        try:
            activity = reports_svc.activities().list(
                userKey="all",
                applicationName="drive",
                maxResults=10,
                eventName="change_user_access",
            ).execute()
            findings["recent_external_share_events"] = len(activity.get("items", []))
        except Exception:
            findings["recent_external_share_events"] = None

        findings["_source"] = "google_workspace_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "total_users": 95,
        "2sv_enrolled_count": 91,
        "2sv_enforced_count": 88,
        "2sv_enrollment_rate": 95.8,
        "suspended_users": 2,
        "admin_users": 3,
        "recent_external_share_events": 7,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
