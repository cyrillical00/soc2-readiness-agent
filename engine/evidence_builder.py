"""
evidence_builder.py — assembles per-control evidence packages for audit export.
"""

import csv
import io
import json
import zipfile
from datetime import datetime
from typing import Optional


def build_control_matrix(
    results: dict,
    controls: list[dict],
    org_name: str,
    audit_type: str,
) -> str:
    """Returns a CSV string of the full control matrix."""
    ctrl_map = {c["control_id"]: c for c in controls}
    output = io.StringIO()
    fieldnames = [
        "control_id", "category", "title", "status",
        "gaps", "evidence_sources", "last_assessed", "override", "justification",
    ]
    if audit_type == "Type II":
        fieldnames += ["observation_days", "observation_start", "observation_end"]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for cid, result in results.items():
        ctrl = ctrl_map.get(cid, {})
        evidence = result.get("evidence", {})
        sources = list({k.split("__")[0] for k in evidence.keys() if "__" not in k or evidence[k] is not None})
        row = {
            "control_id":       cid,
            "category":         ctrl.get("category", ""),
            "title":            ctrl.get("title", ""),
            "status":           result["status"],
            "gaps":             "; ".join(result.get("gaps", [])),
            "evidence_sources": ", ".join(sources),
            "last_assessed":    datetime.utcnow().date().isoformat(),
            "override":         result.get("override", False),
            "justification":    result.get("justification", ""),
        }
        if audit_type == "Type II":
            row["observation_days"]  = result.get("observation_days", "")
            row["observation_start"] = result.get("observation_start", "")
            row["observation_end"]   = result.get("observation_end", "")
        writer.writerow(row)

    return output.getvalue()


def build_evidence_json(control_id: str, result: dict, ctrl_meta: dict) -> dict:
    """Returns a JSON-serialisable evidence record for one control."""
    return {
        "control_id":   control_id,
        "title":        ctrl_meta.get("title", ""),
        "category":     ctrl_meta.get("category", ""),
        "description":  ctrl_meta.get("description", ""),
        "status":       result["status"],
        "override":     result.get("override", False),
        "justification":result.get("justification"),
        "gaps":         result.get("gaps", []),
        "evidence":     result.get("evidence", {}),
        "observation_days":  result.get("observation_days"),
        "observation_start": result.get("observation_start"),
        "observation_end":   result.get("observation_end"),
        "collected_at": datetime.utcnow().isoformat(),
    }


def build_zip(
    results: dict,
    controls: list[dict],
    org_name: str,
    audit_type: str,
    tsc_scope: list[str],
) -> bytes:
    """
    Returns a ZIP archive as bytes containing:
      - control_matrix.csv
      - evidence/<control_id>.json (one per control)
      - metadata.json
    """
    ctrl_map = {c["control_id"]: c for c in controls}
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # metadata
        meta = {
            "org_name":      org_name,
            "audit_type":    audit_type,
            "tsc_scope":     tsc_scope,
            "controls_count": len(results),
            "exported_at":   datetime.utcnow().isoformat(),
            "status_summary": {
                status: sum(1 for r in results.values() if r["status"] == status)
                for status in ("compliant", "partial", "non_compliant", "not_assessed", "accepted_risk")
            },
        }
        zf.writestr("metadata.json", json.dumps(meta, indent=2))

        # control matrix CSV
        csv_content = build_control_matrix(results, controls, org_name, audit_type)
        zf.writestr("control_matrix.csv", csv_content)

        # per-control evidence JSONs
        for cid, result in results.items():
            ctrl = ctrl_map.get(cid, {})
            ev_json = build_evidence_json(cid, result, ctrl)
            zf.writestr(f"evidence/{cid}.json", json.dumps(ev_json, indent=2))

    buf.seek(0)
    return buf.read()
