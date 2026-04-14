"""
Jira connector — open security tickets, SLA breach rate, change request workflow.
Covers: CC4 (Monitoring), CC8 (Change Management)
"""

import os
from datetime import datetime

import streamlit as st


def _get_creds():
    return {
        "base_url":  st.secrets.get("JIRA_BASE_URL",  os.getenv("JIRA_BASE_URL",  "")),
        "email":     st.secrets.get("JIRA_EMAIL",      os.getenv("JIRA_EMAIL",      "")),
        "api_token": st.secrets.get("JIRA_API_TOKEN",  os.getenv("JIRA_API_TOKEN",  "")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return all(c.values())


def test_connection() -> tuple[bool, str]:
    c = _get_creds()
    if not all(c.values()):
        return False, "JIRA_BASE_URL, JIRA_EMAIL, or JIRA_API_TOKEN not set."
    try:
        from jira import JIRA
        j = JIRA(server=c["base_url"], basic_auth=(c["email"], c["api_token"]))
        me = j.myself()
        return True, f"Connected to Jira as {me['displayName']}"
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    c = _get_creds()
    findings = {}
    try:
        from jira import JIRA

        j = JIRA(server=c["base_url"], basic_auth=(c["email"], c["api_token"]))

        # --- Open security issues ---
        security_issues = j.search_issues(
            'labels = "security" AND statusCategory != Done ORDER BY created DESC',
            maxResults=500,
        )
        findings["open_security_issues"] = len(security_issues)

        # --- Overdue / SLA-breached issues ---
        overdue = j.search_issues(
            'labels = "security" AND due < now() AND statusCategory != Done',
            maxResults=500,
        )
        findings["overdue_security_issues"] = len(overdue)
        findings["sla_breach_rate"] = (
            round(len(overdue) / len(security_issues) * 100, 1)
            if security_issues else 0
        )

        # --- Change management workflow check ---
        # Look for issue types or workflow names that suggest a change process
        issue_types = [it.name.lower() for it in j.issue_types()]
        findings["change_request_workflow_exists"] = any(
            "change" in it for it in issue_types
        )
        findings["issue_types"] = issue_types[:20]

        # --- Vulnerability-labelled issues by priority ---
        vuln_issues = j.search_issues(
            'labels = "vulnerability" AND statusCategory != Done',
            maxResults=500,
        )
        findings["open_vulnerability_issues"] = len(vuln_issues)

        high_priority = [
            i for i in vuln_issues
            if i.fields.priority and i.fields.priority.name.lower() in ("high", "critical", "highest")
        ]
        findings["high_priority_vulns"] = len(high_priority)

        findings["_source"] = "jira_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "open_security_issues": 12,
        "overdue_security_issues": 2,
        "sla_breach_rate": 16.7,
        "change_request_workflow_exists": True,
        "issue_types": ["Bug", "Story", "Task", "Change Request", "Incident", "Vulnerability"],
        "open_vulnerability_issues": 5,
        "high_priority_vulns": 1,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
