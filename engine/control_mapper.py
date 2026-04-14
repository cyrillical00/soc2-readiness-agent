"""
control_mapper.py — maps raw connector findings to SOC2 TSC control evidence.

Each map_* function takes a findings dict from a connector and returns a dict of
{ control_id: { evidence_key: value, ... } }  entries.

All mappers are aggregated by aggregate() into a single evidence_by_control dict
that scorer.py consumes.
"""

from typing import Any


# ── Per-connector mappers ────────────────────────────────────────────────────

def map_okta(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC6.1": {
            "mfa_enrollment_rate":  findings.get("mfa_enrollment_rate"),
            "inactive_user_rate":   findings.get("inactive_user_rate"),
            "inactive_users_90d":   findings.get("inactive_users_90d"),
        },
        "CC6.2": {
            "total_active_users": findings.get("total_active_users"),
        },
        "CC6.3": {
            "admin_count":  findings.get("admin_count"),
            "admin_logins": findings.get("admin_logins"),
        },
        "CC6.5": {
            "inactive_users_90d": findings.get("inactive_users_90d"),
        },
    }


def map_google_workspace(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC6.1": {
            "2sv_enrollment_rate": findings.get("2sv_enrollment_rate"),
            "2sv_enforced_count":  findings.get("2sv_enforced_count"),
            "total_users":         findings.get("total_users"),
        },
        "C1.1": {
            "2sv_enrollment_rate": findings.get("2sv_enrollment_rate"),
        },
        "P6.1": {
            "recent_external_share_events": findings.get("recent_external_share_events"),
        },
    }


def map_github(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC8.1": {
            "branch_protection_rate":   findings.get("branch_protection_rate"),
            "pr_review_required_rate":  findings.get("pr_review_required_rate"),
            "org_2fa_required":         findings.get("org_2fa_required"),
            "secret_scanning_rate":     findings.get("secret_scanning_rate"),
            "outside_collaborators":    findings.get("outside_collaborators"),
            "public_repo_count":        findings.get("public_repo_count"),
        },
    }


def map_aws(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC7.2": {
            "cloudtrail_enabled":      findings.get("cloudtrail_enabled"),
            "cloudtrail_multi_region": findings.get("cloudtrail_multi_region"),
            "guardduty_enabled":       findings.get("guardduty_enabled"),
            "aws_config_enabled":      findings.get("aws_config_enabled"),
        },
        "CC7.1": {
            "aws_config_enabled": findings.get("aws_config_enabled"),
        },
        "CC6.1": {
            "root_mfa_enabled": findings.get("root_mfa_enabled"),
        },
        "CC6.3": {
            "iam_users_count":    findings.get("iam_users_count"),
            "iam_users_with_mfa": findings.get("iam_users_with_mfa"),
        },
        "C1.3": {
            "s3_public_bucket_count": findings.get("s3_public_bucket_count"),
            "s3_total_buckets":       findings.get("s3_total_buckets"),
        },
        "A1.1": {
            "guardduty_enabled":  findings.get("guardduty_enabled"),
            "cloudtrail_enabled": findings.get("cloudtrail_enabled"),
        },
    }


def map_gcp(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC7.2": {
            "audit_logging_configured": findings.get("audit_logging_configured"),
        },
        "C1.3": {
            "gcs_public_bucket_count": findings.get("gcs_public_bucket_count"),
            "gcs_total_buckets":       findings.get("gcs_total_buckets"),
        },
        "CC6.3": {
            "iam_owner_count":   findings.get("iam_owner_count"),
            "iam_public_access": findings.get("iam_public_access"),
        },
    }


def map_azure(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC6.1": {
            "mfa_rate_estimate": findings.get("mfa_rate_estimate"),
        },
        "CC7.2": {
            "conditional_access_enabled_count": findings.get("conditional_access_enabled_count"),
        },
    }


def map_jira(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC4.2": {
            "open_security_issues":    findings.get("open_security_issues"),
            "overdue_security_issues": findings.get("overdue_security_issues"),
            "sla_breach_rate":         findings.get("sla_breach_rate"),
        },
        "CC8.1": {
            "change_request_workflow_exists": findings.get("change_request_workflow_exists"),
        },
        "CC7.4": {
            "open_vulnerability_issues": findings.get("open_vulnerability_issues"),
            "high_priority_vulns":       findings.get("high_priority_vulns"),
        },
    }


def map_confluence(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    policy_docs = findings.get("policy_docs", {})

    def _policy_present(key: str) -> bool | None:
        val = policy_docs.get(key)
        if val is None and key not in policy_docs:
            return None  # connector didn't check
        return val is not None

    return {
        "CC2.1": {"information_security_policy":     _policy_present("information_security_policy")},
        "CC2.2": {"acceptable_use_policy":            _policy_present("acceptable_use_policy")},
        "CC1.1": {"code_of_conduct":                  _policy_present("code_of_conduct")},
        "CC3.1": {"risk_assessment_procedure":        _policy_present("risk_assessment_procedure")},
        "CC5.2": {"vulnerability_management_policy":  _policy_present("vulnerability_management_policy"),
                  "patch_management_policy":           _policy_present("vulnerability_management_policy")},
        "CC5.3": {"security_policy_coverage":         findings.get("policies_found"),
                  "policies_missing":                 findings.get("policies_missing")},
        "CC6.2": {"access_control_policy":            _policy_present("access_control_policy")},
        "CC7.3": {"incident_response_plan":           _policy_present("incident_response_plan")},
        "CC7.4": {"incident_response_plan":           _policy_present("incident_response_plan")},
        "CC8.1": {"change_management_policy":         _policy_present("change_management_policy")},
        "CC9.1": {"vendor_management_policy":         _policy_present("vendor_management_policy"),
                  "business_continuity_plan":          _policy_present("business_continuity_plan")},
        "A1.2":  {"backup_policy":                    _policy_present("backup_policy")},
        "C1.1":  {"data_classification_policy":       _policy_present("data_classification_policy")},
        "P1.1":  {"privacy_policy":                   _policy_present("privacy_policy")},
    }


def map_jamf(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC6.7": {
            "filevault_rate":            findings.get("filevault_rate"),
            "filevault_enabled_count":   findings.get("filevault_enabled_count"),
            "total_managed_devices":     findings.get("total_managed_devices"),
        },
        "CC6.8": {
            "patch_compliance_rate": findings.get("patch_compliance_rate"),
        },
        "CC7.1": {
            "patch_compliance_rate": findings.get("patch_compliance_rate"),
        },
    }


def map_intune(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC6.7": {
            "bitlocker_rate":          findings.get("bitlocker_rate"),
            "compliance_rate":         findings.get("compliance_rate"),
            "total_managed_devices":   findings.get("total_managed_devices"),
        },
        "CC6.8": {
            "patch_rings_count":  findings.get("patch_rings_count"),
            "compliance_rate":    findings.get("compliance_rate"),
        },
    }


def map_kandji(findings: dict) -> dict[str, dict]:
    if not findings or "_error" in findings:
        return {}
    return {
        "CC6.7": {
            "encryption_rate":         findings.get("encryption_rate"),
            "compliance_rate":         findings.get("compliance_rate"),
            "total_managed_devices":   findings.get("total_managed_devices"),
        },
    }


def map_manual(findings: dict) -> dict[str, dict]:
    """Fold manual CSV/JSON uploads into the evidence dict."""
    if not findings or "_error" in findings:
        return {}
    result: dict[str, dict] = {}
    for entry in findings.get("manual_entries", []):
        cid = entry.get("control_id", "").upper()
        if cid:
            if cid not in result:
                result[cid] = {}
            result[cid]["manual_status"]   = entry.get("status")
            result[cid]["manual_value"]    = entry.get("evidence_value")
            result[cid]["manual_notes"]    = entry.get("notes")
    return result


# ── Aggregator ───────────────────────────────────────────────────────────────

MAPPER_REGISTRY = {
    "okta":             map_okta,
    "google_workspace": map_google_workspace,
    "github":           map_github,
    "aws":              map_aws,
    "gcp":              map_gcp,
    "azure":            map_azure,
    "jira":             map_jira,
    "confluence":       map_confluence,
    "jamf":             map_jamf,
    "intune":           map_intune,
    "kandji":           map_kandji,
    "manual_upload":    map_manual,
}


def aggregate(all_findings: dict[str, dict]) -> dict[str, dict[str, Any]]:
    """
    all_findings: { connector_name: raw_findings_dict }
    Returns: { control_id: { evidence_key: value, ... } }
    """
    evidence: dict[str, dict] = {}

    for connector, findings in all_findings.items():
        mapper = MAPPER_REGISTRY.get(connector)
        if mapper is None:
            continue
        mapped = mapper(findings)
        for control_id, ev in mapped.items():
            if control_id not in evidence:
                evidence[control_id] = {}
            # Merge: connector-specific keys are prefixed to avoid collisions
            for k, v in ev.items():
                composite_key = f"{connector}__{k}" if k in evidence[control_id] else k
                evidence[control_id][composite_key] = v

    return evidence
