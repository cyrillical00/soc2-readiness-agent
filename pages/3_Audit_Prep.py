import json
import os

import streamlit as st

if not st.session_state.get("setup_complete"):
    st.warning("Complete session setup on the Home page first.")
    st.stop()

from engine import evidence_builder, policy_generator
from connectors import confluence as confluence_connector

st.set_page_config(page_title="Audit Prep · SOC2", page_icon="📋", layout="wide")
st.title("📋 Audit Prep")

org_name   = st.session_state.get("org_name", "")
audit_type = st.session_state.get("audit_type", "Type I")
tsc_scope  = st.session_state.get("tsc_scope", ["CC"])
results    = st.session_state.get("assessment_results", {})
demo       = st.session_state.get("demo_mode", False)


@st.cache_data
def _load_controls():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "controls.json")
    with open(path) as f:
        return json.load(f)["controls"]

controls = _load_controls()

if not results:
    st.warning("Run a Gap Assessment first (page 2) to populate evidence data.")
    st.stop()

tab1, tab2, tab3 = st.tabs(["📦 Evidence Package", "📝 Policy Generator", "📖 Control Narratives"])


# ════════════════════════════════════════════════════════════════
# TAB 1 — Evidence Package
# ════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Evidence Package")
    st.markdown(
        "Export a complete evidence package for your auditor. "
        "Includes a control matrix CSV and per-control JSON evidence files."
    )

    # Status summary
    statuses = [r["status"] for r in results.values()]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("✅ Compliant",     statuses.count("compliant"))
    c2.metric("⚠️ Partial",       statuses.count("partial"))
    c3.metric("❌ Non-compliant",  statuses.count("non_compliant"))
    c4.metric("Total Controls",   len(results))

    st.divider()
    col_csv, col_zip = st.columns([1, 1])

    with col_csv:
        st.markdown("**Control Matrix (CSV)**")
        csv_data = evidence_builder.build_control_matrix(results, controls, org_name, audit_type)
        st.download_button(
            label="⬇ Download control_matrix.csv",
            data=csv_data,
            file_name=f"{org_name.replace(' ', '_')}_control_matrix.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with col_zip:
        st.markdown("**Full Evidence Package (ZIP)**")
        if st.button("📦 Build & Download ZIP", use_container_width=True):
            with st.spinner("Building evidence package..."):
                zip_bytes = evidence_builder.build_zip(
                    results=results,
                    controls=controls,
                    org_name=org_name,
                    audit_type=audit_type,
                    tsc_scope=tsc_scope,
                )
            st.download_button(
                label="⬇ Download evidence_package.zip",
                data=zip_bytes,
                file_name=f"{org_name.replace(' ', '_')}_evidence_package.zip",
                mime="application/zip",
                use_container_width=True,
            )

    st.divider()
    st.subheader("Control Evidence Preview")
    ctrl_map = {c["control_id"]: c for c in controls}
    selected = st.selectbox(
        "Select control to preview evidence",
        options=sorted(results.keys()),
        format_func=lambda cid: f"{cid} — {ctrl_map.get(cid, {}).get('title', '')}",
    )
    if selected:
        ev_rec = evidence_builder.build_evidence_json(selected, results[selected], ctrl_map.get(selected, {}))
        st.json(ev_rec)


# ════════════════════════════════════════════════════════════════
# TAB 2 — Policy Generator
# ════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("Policy Generator")
    st.markdown(
        "Generate audit-ready policy document drafts using Claude AI. "
        "Missing policies are identified automatically from your Confluence findings."
    )

    # Which policies are missing?
    cf_findings = st.session_state.get("connector_findings", {}).get("confluence", {})
    if not cf_findings and demo:
        cf_findings = confluence_connector.collect(demo=True)

    policy_docs = cf_findings.get("policy_docs", {})
    missing_keys = [k for k, v in policy_docs.items() if v is None]
    present_keys = [k for k, v in policy_docs.items() if v is not None]

    if policy_docs:
        col_miss, col_pres = st.columns([1, 1])
        with col_miss:
            st.markdown(f"**Missing policies ({len(missing_keys)})**")
            for k in missing_keys:
                tmpl = policy_generator.POLICY_TEMPLATES.get(k, {})
                name = tmpl.get("name", k.replace("_", " ").title())
                st.markdown(f"- ❌ {name}")
        with col_pres:
            st.markdown(f"**Found in Confluence ({len(present_keys)})**")
            for k in present_keys:
                tmpl = policy_generator.POLICY_TEMPLATES.get(k, {})
                name = tmpl.get("name", k.replace("_", " ").title())
                st.markdown(f"- ✅ {name}")
    else:
        st.info("Connect Confluence (page 1) to auto-detect missing policies, or select one below.")

    st.divider()

    # All available policies for generation
    all_policy_keys = list(policy_generator.POLICY_TEMPLATES.keys())
    selected_policy = st.selectbox(
        "Select policy to generate",
        options=all_policy_keys,
        format_func=lambda k: policy_generator.POLICY_TEMPLATES[k]["name"],
    )

    additional_ctx = st.text_area(
        "Additional context (optional)",
        placeholder="e.g. We use Okta for SSO, GitHub for code hosting, AWS us-east-1 for production...",
        height=80,
    )

    api_key_set = bool(
        st.secrets.get("ANTHROPIC_API_KEY", os.getenv("ANTHROPIC_API_KEY", ""))
    )
    if not api_key_set:
        st.warning("ANTHROPIC_API_KEY not set — will generate a template placeholder instead of AI-generated content.")

    if st.button("✨ Generate Policy Draft", type="primary"):
        with st.spinner(f"Generating {policy_generator.POLICY_TEMPLATES[selected_policy]['name']}..."):
            draft = policy_generator.generate_policy(
                policy_key=selected_policy,
                org_name=org_name,
                tsc_scope=tsc_scope,
                audit_type=audit_type,
                additional_context=additional_ctx,
            )
        st.session_state[f"policy_draft_{selected_policy}"] = draft

    draft_key = f"policy_draft_{selected_policy}"
    if draft_key in st.session_state:
        st.divider()
        policy_name = policy_generator.POLICY_TEMPLATES[selected_policy]["name"]
        st.markdown(f"#### Draft: {policy_name}")

        edited_draft = st.text_area(
            "Edit draft below",
            value=st.session_state[draft_key],
            height=500,
            key=f"edit_{draft_key}",
        )
        st.session_state[draft_key] = edited_draft

        st.download_button(
            "⬇ Download as .txt",
            data=edited_draft,
            file_name=f"{selected_policy}_{org_name.replace(' ', '_')}.txt",
            mime="text/plain",
        )


# ════════════════════════════════════════════════════════════════
# TAB 3 — Control Narratives
# ════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("Control Narratives")
    st.markdown(
        "Auto-generate auditor-facing narratives per TSC category. "
        "Copy these into auditor questionnaires or RFP responses."
    )

    tsc_labels = {
        "CC": "Security (Common Criteria)",
        "A":  "Availability",
        "PI": "Processing Integrity",
        "C":  "Confidentiality",
        "P":  "Privacy",
    }

    selected_cat = st.selectbox(
        "Select TSC category",
        options=tsc_scope,
        format_func=lambda x: f"{x} — {tsc_labels.get(x, x)}",
    )

    api_key_set = bool(
        st.secrets.get("ANTHROPIC_API_KEY", os.getenv("ANTHROPIC_API_KEY", ""))
    )
    if not api_key_set:
        st.warning("ANTHROPIC_API_KEY not set — narrative will use template format.")

    if st.button("✨ Generate Narrative", type="primary", key="gen_narrative"):
        with st.spinner(f"Generating {tsc_labels.get(selected_cat, selected_cat)} narrative..."):
            narrative = policy_generator.generate_control_narrative(
                category=selected_cat,
                category_label=tsc_labels.get(selected_cat, selected_cat),
                results=results,
                controls=controls,
                org_name=org_name,
                audit_type=audit_type,
            )
        st.session_state[f"narrative_{selected_cat}"] = narrative

    narrative_key = f"narrative_{selected_cat}"
    if narrative_key in st.session_state:
        st.divider()
        narrative_text = st.text_area(
            "Narrative (editable)",
            value=st.session_state[narrative_key],
            height=400,
            key=f"edit_narrative_{selected_cat}",
        )
        st.session_state[narrative_key] = narrative_text

        st.download_button(
            "⬇ Download narrative",
            data=narrative_text,
            file_name=f"narrative_{selected_cat}_{org_name.replace(' ', '_')}.txt",
            mime="text/plain",
        )
