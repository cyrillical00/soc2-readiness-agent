"""
Confluence connector — policy doc existence check by title pattern matching.
Covers: CC2 (Communication)
"""

import os
from datetime import datetime

import requests
import streamlit as st

# Patterns to match against page titles — order matters (most specific first)
POLICY_PATTERNS = [
    ("information_security_policy",    ["information security policy", "infosec policy"]),
    ("access_control_policy",          ["access control policy", "logical access policy"]),
    ("change_management_policy",       ["change management policy", "change control policy"]),
    ("incident_response_plan",         ["incident response plan", "incident response policy"]),
    ("business_continuity_plan",       ["business continuity", "bcp", "disaster recovery plan", "drp"]),
    ("vulnerability_management_policy",["vulnerability management", "patch management policy"]),
    ("data_classification_policy",     ["data classification", "data handling policy"]),
    ("vendor_management_policy",       ["vendor management", "third party management", "supplier policy"]),
    ("acceptable_use_policy",          ["acceptable use policy", "aup"]),
    ("privacy_policy",                 ["privacy policy", "data protection policy"]),
    ("password_policy",                ["password policy", "credential policy"]),
    ("risk_assessment_procedure",      ["risk assessment", "risk management policy"]),
    ("code_of_conduct",                ["code of conduct", "code of ethics"]),
    ("physical_security_policy",       ["physical security policy", "facility access policy"]),
    ("backup_policy",                  ["backup policy", "data backup"]),
]


def _get_creds():
    return {
        "base_url":  st.secrets.get("CONFLUENCE_BASE_URL",  os.getenv("CONFLUENCE_BASE_URL",  "")),
        "email":     st.secrets.get("CONFLUENCE_EMAIL",      os.getenv("CONFLUENCE_EMAIL",      "")),
        "api_token": st.secrets.get("CONFLUENCE_API_TOKEN",  os.getenv("CONFLUENCE_API_TOKEN",  "")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return all(c.values())


def test_connection() -> tuple[bool, str]:
    c = _get_creds()
    if not all(c.values()):
        return False, "CONFLUENCE_BASE_URL, CONFLUENCE_EMAIL, or CONFLUENCE_API_TOKEN not set."
    try:
        r = requests.get(
            f"{c['base_url'].rstrip('/')}/rest/api/space",
            auth=(c["email"], c["api_token"]),
            headers={"Accept": "application/json"},
            timeout=10,
        )
        if r.ok:
            spaces = r.json().get("results", [])
            return True, f"Connected to Confluence — {len(spaces)} spaces visible."
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    c = _get_creds()
    base = c["base_url"].rstrip("/")
    auth = (c["email"], c["api_token"])
    headers = {"Accept": "application/json"}
    findings = {"policy_docs": {}}

    try:
        # Fetch all pages (limited to 500 — adjust if needed)
        pages_resp = requests.get(
            f"{base}/rest/api/content?type=page&limit=500&expand=title",
            auth=auth, headers=headers, timeout=20,
        )
        all_pages = []
        if pages_resp.ok:
            all_pages = pages_resp.json().get("results", [])

        page_titles_lower = {p["id"]: p["title"].lower() for p in all_pages}

        for policy_key, patterns in POLICY_PATTERNS:
            found = None
            for pid, title in page_titles_lower.items():
                if any(pattern in title for pattern in patterns):
                    found = {"page_id": pid, "title": title}
                    break
            findings["policy_docs"][policy_key] = found

        findings["total_pages_indexed"] = len(all_pages)
        findings["policies_found"]      = sum(1 for v in findings["policy_docs"].values() if v)
        findings["policies_missing"]    = sum(1 for v in findings["policy_docs"].values() if not v)
        findings["_source"]             = "confluence_api"
        findings["_collected_at"]       = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    found_policies = {
        "information_security_policy":     {"page_id": "1001", "title": "Information Security Policy"},
        "access_control_policy":           {"page_id": "1002", "title": "Access Control Policy"},
        "change_management_policy":        {"page_id": "1003", "title": "Change Management Policy"},
        "incident_response_plan":          {"page_id": "1004", "title": "Incident Response Plan"},
        "business_continuity_plan":        None,
        "vulnerability_management_policy": {"page_id": "1006", "title": "Vulnerability Management Policy"},
        "data_classification_policy":      {"page_id": "1007", "title": "Data Classification Policy"},
        "vendor_management_policy":        None,
        "acceptable_use_policy":           {"page_id": "1009", "title": "Acceptable Use Policy"},
        "privacy_policy":                  {"page_id": "1010", "title": "Privacy Policy"},
        "password_policy":                 {"page_id": "1011", "title": "Password Policy"},
        "risk_assessment_procedure":       {"page_id": "1012", "title": "Risk Assessment Procedure"},
        "code_of_conduct":                 {"page_id": "1013", "title": "Code of Conduct"},
        "physical_security_policy":        None,
        "backup_policy":                   {"page_id": "1015", "title": "Backup and Recovery Policy"},
    }
    return {
        "policy_docs": found_policies,
        "total_pages_indexed": 214,
        "policies_found": sum(1 for v in found_policies.values() if v),
        "policies_missing": sum(1 for v in found_policies.values() if not v),
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
