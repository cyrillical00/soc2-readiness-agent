"""
AWS connector — CloudTrail, S3 ACLs, IAM root MFA, GuardDuty, public exposure.
Covers: CC7 (Threat Detection), A1 (Availability)
"""

import os
from datetime import datetime

import streamlit as st


def _get_creds():
    return {
        "aws_access_key_id":     st.secrets.get("AWS_ACCESS_KEY_ID",     os.getenv("AWS_ACCESS_KEY_ID",     "")),
        "aws_secret_access_key": st.secrets.get("AWS_SECRET_ACCESS_KEY", os.getenv("AWS_SECRET_ACCESS_KEY", "")),
        "region_name":           st.secrets.get("AWS_REGION",            os.getenv("AWS_REGION",            "us-east-1")),
    }


def is_configured() -> bool:
    c = _get_creds()
    return bool(c["aws_access_key_id"] and c["aws_secret_access_key"])


def test_connection() -> tuple[bool, str]:
    if not is_configured():
        return False, "AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set."
    try:
        import boto3
        creds = _get_creds()
        sts = boto3.client("sts", **creds)
        identity = sts.get_caller_identity()
        return True, f"Connected as {identity['Arn']}"
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    creds = _get_creds()
    findings = {}
    try:
        import boto3

        # --- CloudTrail ---
        ct = boto3.client("cloudtrail", **creds)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        findings["cloudtrail_trails_count"] = len(trails)
        findings["cloudtrail_enabled"]      = len(trails) > 0
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        findings["cloudtrail_multi_region"] = len(multi_region) > 0

        # --- IAM root account MFA ---
        iam = boto3.client("iam", **creds)
        summary = iam.get_account_summary().get("SummaryMap", {})
        findings["root_mfa_enabled"]       = summary.get("AccountMFAEnabled", 0) == 1
        findings["iam_users_count"]        = summary.get("Users", 0)
        findings["iam_users_with_mfa"]     = summary.get("MFADevices", 0)
        findings["iam_access_keys_count"]  = summary.get("AccessKeysPerUserQuota", 0)

        # --- S3 bucket public exposure ---
        s3 = boto3.client("s3", **creds)
        buckets = s3.list_buckets().get("Buckets", [])
        findings["s3_total_buckets"] = len(buckets)
        public_buckets = []
        for b in buckets:
            name = b["Name"]
            try:
                acl_resp = s3.get_bucket_acl(Bucket=name)
                for grant in acl_resp.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if "AllUsers" in grantee.get("URI", "") or "AuthenticatedUsers" in grantee.get("URI", ""):
                        public_buckets.append(name)
                        break
            except Exception:
                pass
        findings["s3_public_buckets"]      = public_buckets
        findings["s3_public_bucket_count"] = len(public_buckets)

        # --- GuardDuty ---
        gd = boto3.client("guardduty", **creds)
        detectors = gd.list_detectors().get("DetectorIds", [])
        findings["guardduty_enabled"]         = len(detectors) > 0
        findings["guardduty_detector_count"]  = len(detectors)

        # --- Config service ---
        try:
            config_svc = boto3.client("config", **creds)
            recorders  = config_svc.describe_configuration_recorders().get("ConfigurationRecorders", [])
            findings["aws_config_enabled"] = len(recorders) > 0
        except Exception:
            findings["aws_config_enabled"] = None

        findings["_source"] = "aws_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "cloudtrail_trails_count": 2,
        "cloudtrail_enabled": True,
        "cloudtrail_multi_region": True,
        "root_mfa_enabled": True,
        "iam_users_count": 28,
        "iam_users_with_mfa": 26,
        "iam_access_keys_count": 15,
        "s3_total_buckets": 14,
        "s3_public_buckets": ["acme-marketing-assets"],
        "s3_public_bucket_count": 1,
        "guardduty_enabled": True,
        "guardduty_detector_count": 1,
        "aws_config_enabled": True,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
