"""
scorer.py — evaluates evidence against TSC control thresholds.

Status values:
  compliant     — evidence present, all thresholds met
  partial       — some evidence, at least one threshold partially met
  non_compliant — evidence present but threshold not met, or critical gap
  not_assessed  — no evidence from any connected source
  accepted_risk — manually overridden

Type II adds an observation_days count to each result.
"""

import json
import os
from datetime import date
from typing import Any, Optional


def _load_controls() -> list[dict]:
    path = os.path.join(os.path.dirname(__file__), "..", "data", "controls.json")
    with open(path) as f:
        return json.load(f)["controls"]


# ── Threshold evaluation helpers ─────────────────────────────────────────────

def _meets_threshold(value: Any, threshold_def: dict, direction: str = "gte") -> Optional[str]:
    """
    Returns 'compliant', 'partial', or 'non_compliant'.
    direction='gte' means higher is better (rates, counts).
    direction='lte' means lower is better (e.g. breach SLA hours).
    """
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None

    compliant_val = threshold_def.get("compliant")
    partial_val   = threshold_def.get("partial")

    if compliant_val is None:
        return None

    if direction == "gte":
        if v >= compliant_val:
            return "compliant"
        if partial_val is not None and v >= partial_val:
            return "partial"
        return "non_compliant"
    else:  # lte — lower is better (e.g. SLA days)
        if v <= compliant_val:
            return "compliant"
        if partial_val is not None and v <= partial_val:
            return "partial"
        return "non_compliant"


def _bool_status(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return "compliant" if value else "non_compliant"
    if isinstance(value, str):
        return "compliant" if value.lower() in ("true", "yes", "1") else "non_compliant"
    return None


def _policy_status(value: Any) -> Optional[str]:
    """Handles boolean policy-existence checks."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "compliant" if value else "non_compliant"
    return None


# ── Per-control scoring logic ─────────────────────────────────────────────────

def _score_control(control: dict, evidence: dict, overrides: dict) -> dict:
    cid = control["control_id"]

    # Manual override takes priority
    if cid in overrides:
        ov = overrides[cid]
        return {
            "control_id":    cid,
            "status":        ov.get("status_override", "accepted_risk"),
            "override":      True,
            "justification": ov.get("justification"),
            "evidence":      evidence,
            "gaps":          [],
        }

    # Manual upload can directly set status
    manual_status = evidence.get("manual_status", "").lower()
    if manual_status in ("compliant", "partial", "non_compliant"):
        return {
            "control_id": cid,
            "status":     manual_status,
            "override":   False,
            "evidence":   evidence,
            "gaps":       [],
        }

    thresholds = control.get("thresholds", {})
    threshold_results: list[str] = []
    gaps: list[str] = []

    # ── Control-specific scoring rules ──────────────────────────────────────
    if cid == "CC6.1":
        # MFA enrollment rate — primary signal
        rate = evidence.get("mfa_enrollment_rate") or evidence.get("2sv_enrollment_rate") or evidence.get("mfa_rate_estimate")
        root_mfa = evidence.get("root_mfa_enabled")
        r = _meets_threshold(rate, {"compliant": 95, "partial": 80})
        if r:
            threshold_results.append(r)
        if root_mfa is False:
            gaps.append("AWS root account MFA not enabled")
        if rate is not None and float(rate) < 95:
            gaps.append(f"MFA enrollment at {rate}% — target is 95%")

    elif cid == "CC6.3":
        admin = evidence.get("admin_count", 0)
        if admin is not None:
            threshold_results.append("compliant" if int(admin) <= 10 else "partial" if int(admin) <= 20 else "non_compliant")
        iam_mfa = evidence.get("iam_users_with_mfa")
        iam_total = evidence.get("iam_users_count")
        if iam_mfa is not None and iam_total:
            rate = iam_mfa / iam_total * 100
            threshold_results.append("compliant" if rate >= 95 else "partial" if rate >= 80 else "non_compliant")
        if evidence.get("iam_public_access") is True:
            gaps.append("GCP IAM has publicly-accessible roles")

    elif cid == "CC6.5":
        inactive = evidence.get("inactive_users_90d", 0)
        if inactive is not None:
            threshold_results.append("compliant" if int(inactive) == 0 else "partial" if int(inactive) <= 5 else "non_compliant")
            if int(inactive) > 0:
                gaps.append(f"{inactive} active users with no login in 90+ days")

    elif cid == "CC6.7":
        for rate_key in ("filevault_rate", "bitlocker_rate", "encryption_rate"):
            rate = evidence.get(rate_key)
            r = _meets_threshold(rate, {"compliant": 95, "partial": 85})
            if r:
                threshold_results.append(r)
                if float(rate) < 95:
                    gaps.append(f"Endpoint encryption at {rate}% (key: {rate_key})")

    elif cid == "CC7.2":
        for check in ("cloudtrail_enabled", "guardduty_enabled", "aws_config_enabled", "audit_logging_configured"):
            val = evidence.get(check)
            r = _bool_status(val)
            if r:
                threshold_results.append(r)
                if r == "non_compliant":
                    gaps.append(f"{check} is disabled or not configured")

    elif cid == "CC8.1":
        for rate_key in ("branch_protection_rate", "pr_review_required_rate"):
            rate = evidence.get(rate_key)
            r = _meets_threshold(rate, {"compliant": 100, "partial": 80})
            if r:
                threshold_results.append(r)
                if float(rate) < 100:
                    gaps.append(f"{rate_key} at {rate}% (target: 100%)")
        wf = evidence.get("change_request_workflow_exists")
        r = _bool_status(wf)
        if r:
            threshold_results.append(r)

    elif cid in ("CC5.3", "CC2.1"):
        # Policy doc presence checks
        for key in evidence:
            if isinstance(evidence[key], bool):
                r = _policy_status(evidence[key])
                if r:
                    threshold_results.append(r)
                    if r == "non_compliant":
                        gaps.append(f"Policy missing: {key.replace('_', ' ')}")

    elif cid == "C1.3":
        public_s3  = evidence.get("s3_public_bucket_count", 0)
        public_gcs = evidence.get("gcs_public_bucket_count", 0)
        if public_s3 is not None:
            threshold_results.append("compliant" if int(public_s3) == 0 else "non_compliant")
            if int(public_s3) > 0:
                gaps.append(f"{public_s3} S3 buckets with public ACL")
        if public_gcs is not None:
            threshold_results.append("compliant" if int(public_gcs) == 0 else "non_compliant")
            if int(public_gcs) > 0:
                gaps.append(f"{public_gcs} GCS buckets with public access")

    elif cid == "CC4.2":
        sla_breach = evidence.get("sla_breach_rate")
        r = _meets_threshold(sla_breach, {"compliant": 0, "partial": 15}, direction="lte")
        if r:
            threshold_results.append(r)
            if sla_breach and float(sla_breach) > 0:
                gaps.append(f"SLA breach rate: {sla_breach}%")

    else:
        # Generic: boolean fields are positive signals; any present = partial at minimum
        for k, v in evidence.items():
            if isinstance(v, bool):
                r = _bool_status(v)
                if r:
                    threshold_results.append(r)

    # ── Aggregate threshold results ──────────────────────────────────────────
    if not threshold_results:
        if evidence:
            status = "partial"  # evidence exists but no numeric threshold — needs review
        else:
            status = "not_assessed"
    elif all(r == "compliant" for r in threshold_results):
        status = "compliant"
    elif "non_compliant" in threshold_results:
        status = "partial" if any(r == "compliant" for r in threshold_results) else "non_compliant"
    else:
        status = "partial"

    return {
        "control_id": cid,
        "status":     status,
        "override":   False,
        "evidence":   evidence,
        "gaps":       gaps,
    }


# ── Main entry point ─────────────────────────────────────────────────────────

def score_all(
    evidence_by_control: dict[str, dict],
    tsc_scope: list[str],
    overrides: dict[str, dict],
    audit_type: str = "Type I",
    observation_start: Optional[date] = None,
    observation_end: Optional[date] = None,
) -> dict[str, dict]:
    """
    Returns { control_id: scoring_result } for all controls in scope.
    """
    controls = _load_controls()
    results: dict[str, dict] = {}

    for control in controls:
        if control["tsc"] not in tsc_scope:
            continue

        cid = control["control_id"]
        evidence = evidence_by_control.get(cid, {})
        result = _score_control(control, evidence, overrides)

        # Type II: add observation window metadata
        if audit_type == "Type II" and observation_start and observation_end:
            days = (observation_end - observation_start).days
            result["observation_days"]  = days
            result["observation_start"] = str(observation_start)
            result["observation_end"]   = str(observation_end)
            # Partial credit if window < 90 days
            if result["status"] == "compliant" and days < 90:
                result["status"] = "partial"
                result["gaps"].append(f"Observation window is only {days} days (minimum 90 for Type II)")

        results[cid] = result

    return results


def compute_category_scores(results: dict[str, dict]) -> dict[str, float]:
    """Returns { tsc_code: readiness_percent } for each category present in results."""
    from collections import defaultdict

    controls = _load_controls()
    tsc_map: dict[str, str] = {c["control_id"]: c["tsc"] for c in controls}

    by_cat: dict[str, list[str]] = defaultdict(list)
    for cid, r in results.items():
        cat = tsc_map.get(cid, "CC")
        by_cat[cat].append(r["status"])

    scores = {}
    for cat, statuses in by_cat.items():
        total = len(statuses)
        compliant = sum(1 for s in statuses if s == "compliant")
        partial   = sum(1 for s in statuses if s == "partial")
        scores[cat] = round((compliant + partial * 0.5) / total * 100, 1) if total else 0.0

    return scores


def compute_overall_score(results: dict[str, dict]) -> float:
    assessed = [r for r in results.values() if r["status"] != "not_assessed"]
    if not assessed:
        return 0.0
    compliant = sum(1 for r in assessed if r["status"] == "compliant")
    partial   = sum(1 for r in assessed if r["status"] == "partial")
    return round((compliant + partial * 0.5) / len(assessed) * 100, 1)
