import streamlit as st
from datetime import datetime

# Guard — require setup
if not st.session_state.get("setup_complete"):
    st.warning("Complete session setup on the Home page first.")
    st.stop()

from connectors import (
    okta, google_workspace, github, aws, gcp, azure,
    jira, confluence, jamf, intune, kandji, manual_upload,
)

st.set_page_config(page_title="Integrations · SOC2", page_icon="🔌", layout="wide")
st.title("🔌 Integrations")
st.caption("Connect data sources. Missing credentials auto-degrade to manual CSV upload.")

demo = st.session_state.get("demo_mode", False)

CONNECTORS = [
    ("okta",             "Okta",              okta,             "CC6, CC5",          "🔐"),
    ("google_workspace", "Google Workspace",  google_workspace, "CC6, C1, P6",       "📧"),
    ("github",           "GitHub",            github,           "CC8",               "🐙"),
    ("aws",              "AWS",               aws,              "CC7, A1, C1.3",     "☁️"),
    ("gcp",              "GCP",               gcp,              "CC7, A1",           "🌐"),
    ("azure",            "Azure",             azure,            "CC6, CC7",          "💙"),
    ("jira",             "Jira",              jira,             "CC4, CC8",          "📋"),
    ("confluence",       "Confluence",        confluence,       "CC2, CC5, CC7",     "📚"),
    ("jamf",             "Jamf Pro",          jamf,             "CC6, PI1",          "💻"),
    ("intune",           "Intune",            intune,           "CC6, PI1",          "🖥️"),
    ("kandji",           "Kandji",            kandji,           "CC6, PI1",          "🍎"),
]

if "connector_status" not in st.session_state:
    st.session_state.connector_status = {}
if "connector_findings" not in st.session_state:
    st.session_state.connector_findings = {}

# ── Run all / individual pull ────────────────────────────────────────────────
col_run, col_clear, _ = st.columns([1, 1, 4])
with col_run:
    if st.button("🔄 Pull All Data", type="primary", use_container_width=True):
        with st.spinner("Collecting data from all integrations..."):
            for key, _, mod, _, _ in CONNECTORS:
                try:
                    findings = mod.collect(demo=demo)
                    st.session_state.connector_findings[key] = findings
                    st.session_state.connector_status[key] = {
                        "ok": "_error" not in findings,
                        "source": findings.get("_source", "api"),
                        "collected_at": findings.get("_collected_at"),
                    }
                except Exception as e:
                    st.session_state.connector_status[key] = {"ok": False, "error": str(e)}
        st.success("Data collection complete.")
        st.rerun()

with col_clear:
    if st.button("🗑 Clear All", use_container_width=True):
        st.session_state.connector_findings = {}
        st.session_state.connector_status = {}
        st.rerun()

st.divider()

# ── Per-connector expanders ──────────────────────────────────────────────────
for key, label, mod, tsc_covers, icon in CONNECTORS:
    configured = demo or mod.is_configured()
    status = st.session_state.connector_status.get(key)
    findings = st.session_state.connector_findings.get(key)

    if status and status.get("ok"):
        badge = "✅ Connected"
        badge_color = "#22c55e"
    elif status and not status.get("ok"):
        badge = "❌ Error"
        badge_color = "#ef4444"
    elif configured:
        badge = "🟡 Configured"
        badge_color = "#f59e0b"
    else:
        badge = "⬜ Not configured"
        badge_color = "#64748b"

    with st.expander(f"{icon} **{label}** · `{tsc_covers}` · {badge}", expanded=False):
        col1, col2 = st.columns([2, 1])

        with col1:
            if not configured and not demo:
                st.info(f"Set credentials in `.streamlit/secrets.toml` to enable the {label} integration.")
                st.markdown("**Manual upload fallback:**")
                manual_findings = manual_upload.render_upload_ui(
                    label=f"Upload {label} export (CSV/JSON)"
                )
                if manual_findings:
                    st.session_state.connector_findings[f"{key}_manual"] = manual_findings
                    st.session_state.connector_status[key] = {"ok": True, "source": "manual_upload"}
            else:
                if st.button(f"Test Connection", key=f"test_{key}"):
                    if demo:
                        st.success("Demo mode — connection simulated.")
                    else:
                        ok, msg = mod.test_connection()
                        if ok:
                            st.success(msg)
                        else:
                            st.error(msg)

                if st.button(f"Pull Data", key=f"pull_{key}", type="primary"):
                    with st.spinner(f"Fetching from {label}..."):
                        try:
                            f = mod.collect(demo=demo)
                            st.session_state.connector_findings[key] = f
                            st.session_state.connector_status[key] = {
                                "ok": "_error" not in f,
                                "source": f.get("_source", "api"),
                                "collected_at": f.get("_collected_at"),
                            }
                            st.rerun()
                        except Exception as e:
                            st.error(str(e))

        with col2:
            if findings:
                st.markdown("**Last pull:**")
                ts = findings.get("_collected_at", "unknown")
                src = findings.get("_source", "unknown")
                st.caption(f"Source: `{src}`")
                st.caption(f"At: `{ts[:19] if ts else 'unknown'}`")

                if "_error" in findings:
                    st.error(f"Error: {findings['_error']}")
                else:
                    # Show a few key metrics
                    show_keys = [k for k in findings if not k.startswith("_") and not isinstance(findings[k], (list, dict))]
                    for k in show_keys[:6]:
                        v = findings[k]
                        if isinstance(v, float):
                            st.metric(k.replace("_", " ").title(), f"{v:.1f}%")
                        elif isinstance(v, bool):
                            st.metric(k.replace("_", " ").title(), "✅" if v else "❌")
                        elif v is not None:
                            st.metric(k.replace("_", " ").title(), str(v))

# ── Manual upload section ────────────────────────────────────────────────────
st.divider()
st.subheader("📎 Manual Upload — Any Integration")
st.markdown(
    "Upload a CSV or JSON with a `control_id` column to directly feed evidence into the assessment engine. "
    "[Download template]"
)

col_dl, _ = st.columns([1, 4])
with col_dl:
    template = manual_upload.get_csv_template()
    st.download_button(
        "⬇ Download CSV Template",
        data=template,
        file_name="soc2_evidence_template.csv",
        mime="text/csv",
    )

manual_bulk = manual_upload.render_upload_ui("Bulk manual evidence upload")
if manual_bulk:
    st.session_state.connector_findings["manual_upload"] = manual_bulk
    st.session_state.connector_status["manual_upload"] = {"ok": True, "source": "manual_upload"}
    st.success(f"Loaded {manual_bulk['total_entries']} manual evidence entries.")
