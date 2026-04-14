"""
Manual upload connector — accepts CSV or JSON with a control_id column.
This is the universal fallback when no API integration is configured.
"""

import io
import json
from datetime import datetime
from typing import Optional

import pandas as pd
import streamlit as st

REQUIRED_COLUMNS = {"control_id"}
OPTIONAL_COLUMNS = {"status", "evidence_value", "notes", "timestamp", "source"}


def parse_upload(uploaded_file) -> tuple[Optional[pd.DataFrame], Optional[str]]:
    """
    Parse a Streamlit UploadedFile (CSV or JSON) into a DataFrame.
    Returns (df, error_message). One will always be None.
    """
    if uploaded_file is None:
        return None, "No file provided."

    name = uploaded_file.name.lower()
    try:
        content = uploaded_file.read()
        if name.endswith(".csv"):
            df = pd.read_csv(io.StringIO(content.decode("utf-8")))
        elif name.endswith(".json"):
            data = json.loads(content.decode("utf-8"))
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict) and "controls" in data:
                df = pd.DataFrame(data["controls"])
            else:
                df = pd.DataFrame([data])
        else:
            return None, "Unsupported file type. Upload CSV or JSON."
    except Exception as e:
        return None, f"Parse error: {e}"

    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        return None, f"Missing required column(s): {', '.join(missing)}. Expected: {REQUIRED_COLUMNS | OPTIONAL_COLUMNS}"

    return df, None


def collect_from_dataframe(df: pd.DataFrame) -> dict:
    """
    Convert a parsed DataFrame into the standard findings dict format.
    Expected columns: control_id, status (optional), evidence_value (optional), notes (optional).
    """
    findings: dict = {"manual_entries": [], "_source": "manual_upload", "_collected_at": datetime.utcnow().isoformat()}

    for _, row in df.iterrows():
        entry = {
            "control_id":     str(row.get("control_id", "")).strip().upper(),
            "status":         str(row.get("status", "")).strip().lower() or None,
            "evidence_value": row.get("evidence_value"),
            "notes":          row.get("notes"),
            "timestamp":      row.get("timestamp"),
        }
        if entry["control_id"]:
            findings["manual_entries"].append(entry)

    findings["total_entries"] = len(findings["manual_entries"])
    return findings


def render_upload_ui(label: str = "Upload evidence file (CSV or JSON)") -> Optional[dict]:
    """
    Renders Streamlit upload widget + preview. Returns parsed findings or None.
    """
    uploaded = st.file_uploader(label, type=["csv", "json"], key=f"manual_upload_{label[:20]}")
    if not uploaded:
        return None

    df, error = parse_upload(uploaded)
    if error:
        st.error(error)
        return None

    st.success(f"Parsed {len(df)} rows successfully.")
    with st.expander("Preview uploaded data"):
        st.dataframe(df.head(20), use_container_width=True)

    return collect_from_dataframe(df)


def get_csv_template() -> str:
    """Returns a CSV template string for users who don't know the format."""
    return (
        "control_id,status,evidence_value,notes,timestamp\n"
        "CC6.1,compliant,98.5,MFA enforced via Okta,2025-01-15\n"
        "CC6.3,partial,85.0,Access review 85% complete,2025-01-15\n"
        "CC8.1,non_compliant,,Branch protection not enabled on 4 repos,2025-01-15\n"
    )
