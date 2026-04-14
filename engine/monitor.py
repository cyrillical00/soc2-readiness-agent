"""
monitor.py — drift detection by comparing current results to the last Supabase snapshot.
"""

from datetime import datetime
from typing import Optional


STATUS_SEVERITY = {
    "compliant":     0,
    "accepted_risk": 1,
    "partial":       2,
    "non_compliant": 3,
    "not_assessed":  4,
}


def detect_drift(
    current_results: dict,
    previous_findings: dict,
) -> list[dict]:
    """
    Compare current scoring results against a previous snapshot's findings dict.
    Returns a list of drift events: controls whose status worsened.
    """
    drift_events = []

    for cid, current in current_results.items():
        prev = previous_findings.get(cid, {})
        if not prev:
            continue

        prev_status    = prev.get("status", "not_assessed")
        current_status = current.get("status", "not_assessed")

        prev_severity    = STATUS_SEVERITY.get(prev_status,    4)
        current_severity = STATUS_SEVERITY.get(current_status, 4)

        if current_severity > prev_severity:
            drift_events.append({
                "control_id":      cid,
                "prev_status":     prev_status,
                "current_status":  current_status,
                "severity_change": current_severity - prev_severity,
                "gaps":            current.get("gaps", []),
                "detected_at":     datetime.utcnow().isoformat(),
            })

    # Sort by severity change descending
    drift_events.sort(key=lambda x: x["severity_change"], reverse=True)
    return drift_events


def summarize_trend(snapshots: list[dict]) -> dict:
    """
    Given a list of snapshots (newest first), return trend data for charting.
    Returns: { dates: [...], overall_scores: [...], category_scores: {cat: [...]} }
    """
    if not snapshots:
        return {"dates": [], "overall_scores": [], "category_scores": {}}

    dates          = []
    overall_scores = []
    category_data: dict[str, list] = {}

    for snap in reversed(snapshots):  # oldest first for charting
        dates.append(snap.get("run_date", "")[:10])
        overall_scores.append(snap.get("overall_score", 0))

        cat_scores = snap.get("scores_by_category", {})
        for cat, score in cat_scores.items():
            if cat not in category_data:
                category_data[cat] = []
            category_data[cat].append(score)

    return {
        "dates":           dates,
        "overall_scores":  overall_scores,
        "category_scores": category_data,
    }
