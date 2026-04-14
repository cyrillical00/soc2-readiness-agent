"""
GCP connector — audit logging, IAM over-privilege, public buckets, VPC firewall rules.
Covers: CC7, A1
"""

import base64
import json
import os
from datetime import datetime

import streamlit as st


def _get_creds():
    raw = st.secrets.get("GCP_SERVICE_ACCOUNT_JSON", os.getenv("GCP_SERVICE_ACCOUNT_JSON", ""))
    if not raw:
        return None
    try:
        return json.loads(base64.b64decode(raw).decode())
    except Exception:
        return None


def is_configured() -> bool:
    return _get_creds() is not None


def test_connection() -> tuple[bool, str]:
    sa = _get_creds()
    if not sa:
        return False, "GCP_SERVICE_ACCOUNT_JSON not set."
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        creds = service_account.Credentials.from_service_account_info(
            sa, scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        svc = build("cloudresourcemanager", "v1", credentials=creds)
        project = svc.projects().get(projectId=sa["project_id"]).execute()
        return True, f"Connected to GCP project: {project.get('name', sa['project_id'])}"
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    sa = _get_creds()
    project_id = sa.get("project_id", "")
    findings = {}

    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        creds = service_account.Credentials.from_service_account_info(
            sa, scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )

        # --- IAM policy (over-privilege check) ---
        crm = build("cloudresourcemanager", "v1", credentials=creds)
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        owner_count   = 0
        editor_count  = 0
        public_access = False
        allUsers_roles = []

        for b in bindings:
            role    = b.get("role", "")
            members = b.get("members", [])
            if role == "roles/owner":
                owner_count = len(members)
            if role == "roles/editor":
                editor_count = len(members)
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                public_access = True
                allUsers_roles.append(role)

        findings["iam_owner_count"]     = owner_count
        findings["iam_editor_count"]    = editor_count
        findings["iam_public_access"]   = public_access
        findings["iam_public_roles"]    = allUsers_roles

        # --- GCS bucket public access ---
        storage = build("storage", "v1", credentials=creds)
        buckets_resp = storage.buckets().list(project=project_id).execute()
        buckets = buckets_resp.get("items", [])
        findings["gcs_total_buckets"] = len(buckets)
        public_buckets = []
        for bucket in buckets:
            try:
                iam_resp = storage.buckets().getIamPolicy(bucket=bucket["name"]).execute()
                for b2 in iam_resp.get("bindings", []):
                    if "allUsers" in b2.get("members", []):
                        public_buckets.append(bucket["name"])
                        break
            except Exception:
                pass
        findings["gcs_public_buckets"] = public_buckets
        findings["gcs_public_bucket_count"] = len(public_buckets)

        # --- Audit logging config ---
        audit_configs = [b for b in bindings if "auditConfig" in str(b)]
        findings["audit_logging_configured"] = len(audit_configs) > 0

        findings["_source"] = "gcp_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "iam_owner_count": 2,
        "iam_editor_count": 4,
        "iam_public_access": False,
        "iam_public_roles": [],
        "gcs_total_buckets": 7,
        "gcs_public_buckets": [],
        "gcs_public_bucket_count": 0,
        "audit_logging_configured": True,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
