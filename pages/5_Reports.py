import json
import os

import pandas as pd
import streamlit as st

if not st.session_state.get("setup_complete"):
    st.warning("Complete session setup on the Home page first.")
    st.stop()

from engine import evidence_builder
from utils import pdf_exporter

st.set_page_config(page_title="Reports · SOC2", page_icon="📊", layout="wide")
st.title("📊 Reports & Exports")

org_name   = st.session_state.get("org_name", "")
audit_type = st.session_state.get("audit_type", "Type I")
tsc_scope  = st.session_state.get("tsc_scope", ["CC"])
results    = st.session_state.get("assessment_results", {})
cat_scores = st.session_state.get("cat_scores", {})
overall    = st.session_state.get("overall_score", 0)
demo       = st.session_state.get("demo_mode", False)


@st.cache_data
def _load_controls():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "controls.json")
    with open(path) as f:
        return json.load(f)["controls"]

controls = _load_controls()

if not results:
    st.warning("Run a Gap Assessment (page 2) before exporting reports.")
    st.stop()

# ── Summary banner ────────────────────────────────────────────────────────────
statuses = [r["status"] for r in results.values()]
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Org",             org_name[:20])
col2.metric("Audit Type",      audit_type)
col3.metric("Overall Score",   f"{overall:.1f}%")
col4.metric("Controls Assessed", len(results))
col5.metric("Compliant",       statuses.count("compliant"))

st.divider()

# ── Report type tabs ──────────────────────────────────────────────────────────
tab_exec, tab_matrix, tab_zip = st.tabs([
    "📄 Executive Summary (PDF)",
    "📋 Full Control Matrix (CSV/XLSX)",
    "📦 Evidence Package (ZIP)",
])

# ════════════════════════════════════════════════════════════════
# Executive Summary PDF
# ════════════════════════════════════════════════════════════════
with tab_exec:
    st.subheader("Executive Summary Report")
    st.markdown("""
    **Contents:**
    - Organization details, audit type, TSC scope
    - Overall readiness score
    - Score per TSC category
    - Top 5 gaps
    - Recommended remediation roadmap
    """)

    try:
        from reportlab.lib.pagesizes import letter
        reportlab_ok = True
    except ImportError:
        reportlab_ok = False

    if not reportlab_ok:
        st.warning("`reportlab` is not installed. Run `pip install reportlab` to enable PDF export.")
    else:
        if st.button("Generate PDF", type="primary"):
            with st.spinner("Building PDF..."):
                pdf_bytes = pdf_exporter.generate_executive_summary(
                    org_name=org_name,
                    audit_type=audit_type,
                    tsc_scope=tsc_scope,
                    results=results,
                    cat_scores=cat_scores,
                    overall_score=overall,
                    controls=controls,
                )
            if pdf_bytes:
                st.download_button(
                    "⬇ Download Executive Summary PDF",
                    data=pdf_bytes,
                    file_name=f"{org_name.replace(' ', '_')}_SOC2_Executive_Summary.pdf",
                    mime="application/pdf",
                )
            else:
                st.error("PDF generation failed.")


# ════════════════════════════════════════════════════════════════
# Full Control Matrix
# ════════════════════════════════════════════════════════════════
with tab_matrix:
    st.subheader("Full Control Matrix")
    st.markdown("Every control in scope with status, evidence sources, gaps, and notes.")

    ctrl_map = {c["control_id"]: c for c in controls}
    rows = []
    tsc_labels = {"CC": "Security", "A": "Availability", "PI": "Processing Integrity", "C": "Confidentiality", "P": "Privacy"}

    for cid, result in results.items():
        ctrl = ctrl_map.get(cid, {})
        evidence = result.get("evidence", {})
        sources = list({k.split("__")[0] for k in evidence.keys()})
        row = {
            "Control ID":       cid,
            "Category":         tsc_labels.get(ctrl.get("tsc", ""), ctrl.get("tsc", "")),
            "Title":            ctrl.get("title", ""),
            "Status":           result["status"],
            "Gaps":             "; ".join(result.get("gaps", [])),
            "Evidence Sources": ", ".join(sources),
            "Override":         result.get("override", False),
            "Justification":    result.get("justification", ""),
        }
        if audit_type == "Type II":
            row["Observation Days"]  = result.get("observation_days", "")
            row["Observation Start"] = result.get("observation_start", "")
            row["Observation End"]   = result.get("observation_end", "")
        rows.append(row)

    df = pd.DataFrame(rows)

    # Preview
    st.dataframe(df, use_container_width=True, hide_index=True, height=350)

    col_csv, col_xlsx = st.columns([1, 1])
    with col_csv:
        csv_str = evidence_builder.build_control_matrix(results, controls, org_name, audit_type)
        st.download_button(
            "⬇ Download CSV",
            data=csv_str,
            file_name=f"{org_name.replace(' ', '_')}_control_matrix.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with col_xlsx:
        try:
            import io as _io
            buf = _io.BytesIO()
            df.to_excel(buf, index=False, engine="openpyxl")
            buf.seek(0)
            st.download_button(
                "⬇ Download XLSX",
                data=buf.read(),
                file_name=f"{org_name.replace(' ', '_')}_control_matrix.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )
        except Exception as e:
            st.warning(f"XLSX export unavailable: {e}")


# ════════════════════════════════════════════════════════════════
# Evidence Package ZIP
# ════════════════════════════════════════════════════════════════
with tab_zip:
    st.subheader("Evidence Package ZIP")
    st.markdown("""
    **ZIP contents:**
    - `metadata.json` — assessment metadata and status summary
    - `control_matrix.csv` — full control matrix
    - `evidence/<control_id>.json` — per-control evidence record
    """)

    if st.button("📦 Build Evidence Package", type="primary"):
        with st.spinner("Building ZIP archive..."):
            zip_bytes = evidence_builder.build_zip(
                results=results,
                controls=controls,
                org_name=org_name,
                audit_type=audit_type,
                tsc_scope=tsc_scope,
            )
        st.download_button(
            "⬇ Download Evidence Package ZIP",
            data=zip_bytes,
            file_name=f"{org_name.replace(' ', '_')}_evidence_package.zip",
            mime="application/zip",
            use_container_width=True,
        )
        st.success(f"Package built — {len(results)} controls included.")
