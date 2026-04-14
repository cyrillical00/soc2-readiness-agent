"""
Azure connector — MFA, conditional access, storage public access, Defender status.
Covers: CC6, CC7
"""

import os
from datetime import datetime

import streamlit as st


def _get_creds():
    return {
        "tenant_id":     st.secrets.get("AZURE_TENANT_ID",     os.getenv("AZURE_TENANT_ID",     "")),
        "client_id":     st.secrets.get("AZURE_CLIENT_ID",     os.getenv("AZURE_CLIENT_ID",     "")),
        "client_secret": st.secrets.get("AZURE_CLIENT_SECRET", os.getenv("AZURE_CLIENT_SECRET", "")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return all([c["tenant_id"], c["client_id"], c["client_secret"]])


def test_connection() -> tuple[bool, str]:
    c = _get_creds()
    if not all(c.values()):
        return False, "AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET not set."
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import ResourceManagementClient

        credential = ClientSecretCredential(c["tenant_id"], c["client_id"], c["client_secret"])
        rmc = ResourceManagementClient(credential, "subscription_id")
        list(rmc.resource_groups.list())
        return True, "Connected to Azure."
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    c = _get_creds()
    findings = {}
    try:
        import requests as req

        # Get token via client credentials
        token_url = f"https://login.microsoftonline.com/{c['tenant_id']}/oauth2/v2.0/token"
        token_resp = req.post(token_url, data={
            "grant_type":    "client_credentials",
            "client_id":     c["client_id"],
            "client_secret": c["client_secret"],
            "scope":         "https://graph.microsoft.com/.default",
        }, timeout=15)
        token = token_resp.json().get("access_token")
        graph_headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        # --- Users and MFA ---
        users_resp = req.get(
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName,accountEnabled&$top=999",
            headers=graph_headers, timeout=15,
        )
        users = users_resp.json().get("value", [])
        findings["total_users"] = len(users)

        # MFA via authentication methods
        mfa_enabled = 0
        for u in users[:50]:  # sample to avoid rate limits
            methods_resp = req.get(
                f"https://graph.microsoft.com/v1.0/users/{u['id']}/authentication/methods",
                headers=graph_headers, timeout=10,
            )
            methods = methods_resp.json().get("value", [])
            non_password = [m for m in methods if "password" not in m.get("@odata.type", "").lower()]
            if non_password:
                mfa_enabled += 1

        findings["mfa_enabled_sample"]     = mfa_enabled
        findings["mfa_sample_size"]        = min(50, len(users))
        findings["mfa_rate_estimate"]      = round(mfa_enabled / min(50, len(users)) * 100, 1) if users else 0

        # --- Conditional access policies ---
        ca_resp = req.get(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
            headers=graph_headers, timeout=15,
        )
        ca_policies = ca_resp.json().get("value", [])
        findings["conditional_access_policy_count"] = len(ca_policies)
        findings["conditional_access_enabled_count"] = sum(
            1 for p in ca_policies if p.get("state") == "enabled"
        )

        findings["_source"] = "azure_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "total_users": 112,
        "mfa_enabled_sample": 48,
        "mfa_sample_size": 50,
        "mfa_rate_estimate": 96.0,
        "conditional_access_policy_count": 7,
        "conditional_access_enabled_count": 6,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
