import json
import os
from datetime import date

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

if not st.session_state.get("setup_complete"):
    st.warning("Complete session setup on the Home page first.")
    st.stop()

from engine import control_mapper, scorer
from db import supabase_client
from rate_limiter import get_client_ip, check_limit, record_run

st.set_page_config(page_title="Gap Assessment · SOC2", page_icon="🔍", layout="wide")
st.title("🔍 Gap Assessment")

demo = st.session_state.get("demo_mode", False)
tsc_scope = st.session_state.get("tsc_scope", ["CC", "A", "PI", "C", "P"])
audit_type = st.session_state.get("audit_type", "Type I")
org_name = st.session_state.get("org_name", "")


@st.cache_data
def _load_controls():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "controls.json")
    with open(path) as f:
        return json.load(f)["controls"]

controls = _load_controls()
controls_in_scope = [c for c in controls if c["tsc"] in tsc_scope]


# ── Rate limiting ─────────────────────────────────────────────────────────────
client_ip = get_client_ip(dict(st.context.headers))
allowed, remaining = check_limit(client_ip)

# ── Run assessment ────────────────────────────────────────────────────────────
col_run, col_info, col_save = st.columns([1, 2, 1])
with col_run:
    run_btn = st.button(
        "▶ Run Assessment",
        type="primary",
        use_container_width=True,
        disabled=not allowed,
    )
with col_info:
    if not allowed:
        st.error("Daily limit reached (5 assessments/day per IP). Come back tomorrow.")
    else:
        st.caption(f"{remaining} assessment{'s' if remaining != 1 else ''} remaining today")
with col_save:
    save_btn = st.button("💾 Save Snapshot", use_container_width=True, help="Save results to Supabase")


if run_btn or (demo and "assessment_results" not in st.session_state):
    findings_all = st.session_state.get("connector_findings", {})

    if not findings_all and not demo:
        st.warning("No connector data found. Go to Integrations and pull data first, or enable Demo Mode.")
    else:
        with st.spinner("Running assessment..."):
            if demo and not findings_all:
                # Load demo data from all connectors
                from connectors import (
                    okta as _okta, google_workspace as _gw,
                    github as _gh, aws as _aws, gcp as _gcp,
                    azure as _az, jira as _jira, confluence as _cf,
                    jamf as _jamf, intune as _int, kandji as _kan,
                )
                findings_all = {
                    "okta":             _okta.collect(demo=True),
                    "google_workspace": _gw.collect(demo=True),
                    "github":           _gh.collect(demo=True),
                    "aws":              _aws.collect(demo=True),
                    "gcp":              _gcp.collect(demo=True),
                    "azure":            _az.collect(demo=True),
                    "jira":             _jira.collect(demo=True),
                    "confluence":       _cf.collect(demo=True),
                    "jamf":             _jamf.collect(demo=True),
                    "intune":           _int.collect(demo=True),
                    "kandji":           _kan.collect(demo=True),
                }
                st.session_state.connector_findings = findings_all

            evidence = control_mapper.aggregate(findings_all)

            # Load overrides from Supabase
            overrides_raw = supabase_client.list_overrides(org_name) if supabase_client.is_connected() else []
            overrides = {o["control_id"]: o for o in overrides_raw}

            # Also check local session overrides
            for ctrl_id, ov_data in st.session_state.get("local_overrides", {}).items():
                overrides[ctrl_id] = ov_data

            t2_start = st.session_state.get("type2_start")
            t2_end   = st.session_state.get("type2_end")

            results = scorer.score_all(
                evidence_by_control=evidence,
                tsc_scope=tsc_scope,
                overrides=overrides,
                audit_type=audit_type,
                observation_start=t2_start if audit_type == "Type II" else None,
                observation_end=t2_end   if audit_type == "Type II" else None,
            )

            cat_scores   = scorer.compute_category_scores(results)
            overall      = scorer.compute_overall_score(results)

            st.session_state.assessment_results = results
            st.session_state.cat_scores         = cat_scores
            st.session_state.overall_score      = overall
            st.session_state.scores             = {cid: r["status"] for cid, r in results.items()}
            st.session_state.last_assessment    = date.today().isoformat()

        if run_btn:
            record_run(client_ip)
        st.success(f"Assessment complete — {len(results)} controls evaluated.")

if save_btn and "assessment_results" in st.session_state:
    if not supabase_client.is_connected():
        st.warning("Supabase not connected — set SUPABASE_URL and SUPABASE_KEY in secrets.toml.")
    else:
        snap = supabase_client.save_snapshot(
            org_name=org_name,
            audit_type=audit_type,
            tsc_scope=tsc_scope,
            overall_score=st.session_state.overall_score,
            scores_by_category=st.session_state.cat_scores,
            findings=st.session_state.assessment_results,
        )
        if snap:
            st.success("Snapshot saved to Supabase.")


# ── Display results ───────────────────────────────────────────────────────────
results = st.session_state.get("assessment_results")
if not results:
    st.info("Run the assessment above to see results.")
    st.stop()

overall = st.session_state.get("overall_score", 0)
cat_scores = st.session_state.get("cat_scores", {})

# ── Overall gauge ─────────────────────────────────────────────────────────────
col_gauge, col_counts = st.columns([1, 2])
with col_gauge:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=overall,
        title={"text": "Overall Readiness", "font": {"color": "#f1f5f9"}},
        number={"suffix": "%", "font": {"color": "#f1f5f9", "size": 40}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#64748b"},
            "bar": {"color": "#6366f1"},
            "bgcolor": "#1e293b",
            "steps": [
                {"range": [0, 50],  "color": "#1e293b"},
                {"range": [50, 75], "color": "#1e293b"},
                {"range": [75, 100],"color": "#1e293b"},
            ],
            "threshold": {"line": {"color": "#22c55e", "width": 4}, "thickness": 0.75, "value": 80},
        },
    ))
    fig.update_layout(
        paper_bgcolor="#0f172a", font_color="#f1f5f9",
        height=250, margin=dict(t=30, b=10, l=10, r=10)
    )
    st.plotly_chart(fig, use_container_width=True)

with col_counts:
    statuses = [r["status"] for r in results.values()]
    compliant     = statuses.count("compliant")
    partial       = statuses.count("partial")
    non_compliant = statuses.count("non_compliant")
    not_assessed  = statuses.count("not_assessed")
    accepted      = statuses.count("accepted_risk")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("✅ Compliant",     compliant)
    c2.metric("⚠️ Partial",       partial)
    c3.metric("❌ Non-compliant",  non_compliant)
    c4.metric("⬜ Not assessed",   not_assessed)

    if accepted:
        st.caption(f"🔵 {accepted} controls marked as accepted risk")

# ── Per-category bars ─────────────────────────────────────────────────────────
st.divider()
st.subheader("Readiness by Category")
tsc_labels = {"CC": "Security", "A": "Availability", "PI": "Processing Integrity", "C": "Confidentiality", "P": "Privacy"}
cat_cols = st.columns(len(cat_scores))
for i, (cat, pct) in enumerate(cat_scores.items()):
    with cat_cols[i]:
        color = "#22c55e" if pct >= 80 else "#f59e0b" if pct >= 50 else "#ef4444"
        st.markdown(f"""
        <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1rem;text-align:center;">
            <div style="color:#94a3b8;font-size:0.75rem">{tsc_labels.get(cat, cat)}</div>
            <div style="font-size:1.8rem;font-weight:700;color:{color}">{pct:.0f}%</div>
            <div style="background:#334155;border-radius:4px;height:6px;margin-top:8px">
                <div style="background:{color};width:{pct}%;height:6px;border-radius:4px"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Filterable control table ──────────────────────────────────────────────────
st.divider()
st.subheader("Control Detail")

filt_col1, filt_col2, filt_col3 = st.columns([2, 2, 3])
with filt_col1:
    cat_filter = st.multiselect("Filter by category", options=tsc_scope, default=tsc_scope,
                                format_func=lambda x: f"{x} — {tsc_labels.get(x, x)}")
with filt_col2:
    status_filter = st.multiselect(
        "Filter by status",
        options=["compliant", "partial", "non_compliant", "not_assessed", "accepted_risk"],
        default=["compliant", "partial", "non_compliant", "not_assessed", "accepted_risk"],
    )
with filt_col3:
    search_term = st.text_input("Search control ID or title", placeholder="CC6.1")

# Build display rows
ctrl_map = {c["control_id"]: c for c in controls}
rows = []
for cid, result in results.items():
    ctrl = ctrl_map.get(cid, {})
    tsc = ctrl.get("tsc", "")
    if tsc not in cat_filter:
        continue
    if result["status"] not in status_filter:
        continue
    if search_term and search_term.lower() not in cid.lower() and search_term.lower() not in ctrl.get("title", "").lower():
        continue
    rows.append({
        "ID":       cid,
        "Category": tsc_labels.get(tsc, tsc),
        "Title":    ctrl.get("title", ""),
        "Status":   result["status"],
        "Gaps":     len(result.get("gaps", [])),
    })

if rows:
    df = pd.DataFrame(rows)

    def _style_status(val):
        colors = {
            "compliant":     "color:#22c55e;font-weight:600",
            "partial":       "color:#f59e0b;font-weight:600",
            "non_compliant": "color:#ef4444;font-weight:600",
            "not_assessed":  "color:#64748b",
            "accepted_risk": "color:#6366f1;font-weight:600",
        }
        return colors.get(val, "")

    st.dataframe(
        df.style.map(_style_status, subset=["Status"]),
        use_container_width=True,
        hide_index=True,
        height=400,
    )

    # ── Control drill-down ────────────────────────────────────────────────────
    st.divider()
    st.subheader("Control Detail — Drill Down")

    selected_id = st.selectbox(
        "Select a control to inspect",
        options=[r["ID"] for r in rows],
        format_func=lambda cid: f"{cid} — {ctrl_map.get(cid, {}).get('title', '')}",
    )

    if selected_id:
        result   = results[selected_id]
        ctrl     = ctrl_map[selected_id]

        d_col1, d_col2 = st.columns([1, 1])
        with d_col1:
            status = result["status"]
            status_icons = {
                "compliant": "✅", "partial": "⚠️", "non_compliant": "❌",
                "not_assessed": "⬜", "accepted_risk": "🔵"
            }
            st.markdown(f"**Status:** {status_icons.get(status, '')} `{status}`")
            if result.get("override"):
                st.info(f"Override justification: {result.get('justification', '')}")
            st.markdown(f"**Description:** {ctrl.get('description', '')}")
            if result.get("observation_days"):
                st.caption(f"Type II observation: {result['observation_days']} days ({result['observation_start']} → {result['observation_end']})")

        with d_col2:
            gaps = result.get("gaps", [])
            if gaps:
                st.markdown("**Gaps identified:**")
                for g in gaps:
                    st.markdown(f"- 🔴 {g}")
            else:
                st.markdown("**No gaps identified** for this control.")

            evidence = result.get("evidence", {})
            if evidence:
                with st.expander("Evidence detail"):
                    for k, v in evidence.items():
                        if v is not None:
                            st.text(f"{k}: {v}")

        # ── Accept risk / override ────────────────────────────────────────────
        st.markdown("---")
        with st.expander("⚙️ Mark as Accepted Risk or Override Status"):
            override_status = st.selectbox(
                "Override status",
                ["accepted_risk", "compliant", "not_applicable"],
                key=f"ov_status_{selected_id}",
            )
            justification = st.text_area(
                "Justification (required)",
                key=f"ov_just_{selected_id}",
                placeholder="Describe why this control is being overridden and what compensating controls exist.",
            )
            if st.button("Save Override", key=f"ov_save_{selected_id}"):
                if not justification.strip():
                    st.error("Justification is required.")
                else:
                    if "local_overrides" not in st.session_state:
                        st.session_state.local_overrides = {}
                    st.session_state.local_overrides[selected_id] = {
                        "control_id":      selected_id,
                        "status_override": override_status,
                        "justification":   justification,
                    }
                    if supabase_client.is_connected():
                        supabase_client.upsert_override(
                            org_name=org_name,
                            control_id=selected_id,
                            status_override=override_status,
                            justification=justification,
                        )
                    st.success(f"Override saved for {selected_id}. Re-run assessment to apply.")
else:
    st.info("No controls match the current filter.")
