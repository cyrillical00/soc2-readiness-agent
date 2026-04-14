import streamlit as st
import plotly.graph_objects as go

if not st.session_state.get("setup_complete"):
    st.warning("Complete session setup on the Home page first.")
    st.stop()

from engine import monitor, control_mapper, scorer
from db import supabase_client
from utils import slack_notifier

st.set_page_config(page_title="Monitoring · SOC2", page_icon="📡", layout="wide")
st.title("📡 Continuous Monitoring")

org_name   = st.session_state.get("org_name", "")
audit_type = st.session_state.get("audit_type", "Type I")
tsc_scope  = st.session_state.get("tsc_scope", ["CC"])
demo       = st.session_state.get("demo_mode", False)
results    = st.session_state.get("assessment_results", {})
overall    = st.session_state.get("overall_score", 0)
cat_scores = st.session_state.get("cat_scores", {})

tsc_labels = {
    "CC": "Security",
    "A":  "Availability",
    "PI": "Processing Integrity",
    "C":  "Confidentiality",
    "P":  "Privacy",
}

# ── Header controls ───────────────────────────────────────────────────────────
col_refresh, col_slack, col_save, _ = st.columns([1, 1, 1, 3])

with col_refresh:
    if st.button("🔄 Refresh Assessment", type="primary", use_container_width=True):
        findings_all = st.session_state.get("connector_findings", {})
        if findings_all:
            with st.spinner("Re-running assessment..."):
                evidence  = control_mapper.aggregate(findings_all)
                overrides = {o["control_id"]: o for o in supabase_client.list_overrides(org_name)} if supabase_client.is_connected() else {}
                overrides.update(st.session_state.get("local_overrides", {}))

                t2_start = st.session_state.get("type2_start")
                t2_end   = st.session_state.get("type2_end")
                new_results = scorer.score_all(
                    evidence_by_control=evidence,
                    tsc_scope=tsc_scope,
                    overrides=overrides,
                    audit_type=audit_type,
                    observation_start=t2_start if audit_type == "Type II" else None,
                    observation_end=t2_end   if audit_type == "Type II" else None,
                )
                new_cat = scorer.compute_category_scores(new_results)
                new_overall = scorer.compute_overall_score(new_results)

                st.session_state.assessment_results = new_results
                st.session_state.cat_scores         = new_cat
                st.session_state.overall_score      = new_overall
                st.session_state.scores             = {cid: r["status"] for cid, r in new_results.items()}
                st.rerun()
        else:
            st.warning("No connector data available. Pull data from Integrations first.")

with col_slack:
    if st.button("🔔 Test Slack Alert", use_container_width=True):
        ok, msg = slack_notifier.send_test_message(org_name)
        if ok:
            st.success(msg)
        else:
            st.error(msg)

with col_save:
    if st.button("💾 Save Snapshot", use_container_width=True):
        if supabase_client.is_connected() and results:
            snap = supabase_client.save_snapshot(
                org_name=org_name,
                audit_type=audit_type,
                tsc_scope=tsc_scope,
                overall_score=overall,
                scores_by_category=cat_scores,
                findings=results,
            )
            st.success("Snapshot saved.") if snap else st.error("Save failed.")
        else:
            st.warning("Supabase not connected or no assessment results available.")

# ── TSC health gauges ─────────────────────────────────────────────────────────
st.divider()
st.subheader("TSC Health Gauges")

if cat_scores:
    gauge_cols = st.columns(len(cat_scores))
    for i, (cat, pct) in enumerate(cat_scores.items()):
        with gauge_cols[i]:
            color = "#22c55e" if pct >= 80 else "#f59e0b" if pct >= 50 else "#ef4444"
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=pct,
                title={"text": tsc_labels.get(cat, cat), "font": {"color": "#f1f5f9", "size": 12}},
                number={"suffix": "%", "font": {"color": "#f1f5f9", "size": 24}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#334155", "tickfont": {"size": 8}},
                    "bar": {"color": color},
                    "bgcolor": "#1e293b",
                    "threshold": {"line": {"color": "#22c55e", "width": 2}, "thickness": 0.75, "value": 80},
                },
            ))
            fig.update_layout(
                paper_bgcolor="#0f172a", font_color="#f1f5f9",
                height=180, margin=dict(t=40, b=5, l=10, r=10)
            )
            st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Run a Gap Assessment to populate monitoring data.")

# ── Trend chart (Supabase snapshots) ─────────────────────────────────────────
st.divider()
st.subheader("Readiness Trend")

if supabase_client.is_connected():
    snapshots = supabase_client.list_snapshots(org_name, limit=20)
    if snapshots:
        trend = monitor.summarize_trend(snapshots)
        if trend["dates"]:
            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(
                x=trend["dates"],
                y=trend["overall_scores"],
                name="Overall",
                line=dict(color="#6366f1", width=3),
                mode="lines+markers",
            ))
            for cat, scores_list in trend["category_scores"].items():
                if len(scores_list) == len(trend["dates"]):
                    fig2.add_trace(go.Scatter(
                        x=trend["dates"],
                        y=scores_list,
                        name=tsc_labels.get(cat, cat),
                        line=dict(width=1.5, dash="dot"),
                        mode="lines",
                    ))
            fig2.update_layout(
                paper_bgcolor="#0f172a",
                plot_bgcolor="#1e293b",
                font_color="#f1f5f9",
                xaxis=dict(gridcolor="#334155"),
                yaxis=dict(gridcolor="#334155", range=[0, 100]),
                legend=dict(bgcolor="#1e293b", bordercolor="#334155"),
                height=350,
                margin=dict(t=20, b=20, l=10, r=10),
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No trend data yet — save more snapshots over time.")
    else:
        st.info("No snapshots found for this organisation. Save a snapshot above.")
else:
    st.info("Connect Supabase (SUPABASE_URL + SUPABASE_KEY) to enable trend tracking.")

# ── Drift detection ────────────────────────────────────────────────────────────
st.divider()
st.subheader("Drift Detection")

if supabase_client.is_connected() and results:
    last_snap = supabase_client.get_last_snapshot(org_name)
    if last_snap:
        prev_findings = last_snap.get("findings", {})
        drift_events  = monitor.detect_drift(results, prev_findings)

        if drift_events:
            st.error(f"⚠️ {len(drift_events)} control(s) degraded since last snapshot ({last_snap['run_date'][:10]})")
            import pandas as pd
            rows = []
            for ev in drift_events:
                rows.append({
                    "Control":         ev["control_id"],
                    "Was":             ev["prev_status"],
                    "Now":             ev["current_status"],
                    "Severity Change": ev["severity_change"],
                    "Gaps":            "; ".join(ev["gaps"][:2]) if ev.get("gaps") else "",
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

            if slack_notifier.is_configured():
                if st.button("📣 Send Drift Alert to Slack"):
                    ok, msg = slack_notifier.send_drift_alert(org_name, drift_events, overall)
                    st.success(msg) if ok else st.error(msg)
            else:
                st.caption("Set SLACK_WEBHOOK_URL in secrets.toml to enable Slack alerts.")
        else:
            st.success("✅ No drift detected — all controls stable since last snapshot.")
    else:
        st.info("No previous snapshot found — save one to enable drift detection.")
elif not supabase_client.is_connected():
    st.info("Supabase connection required for drift detection.")
else:
    st.info("Run a Gap Assessment first.")

# ── Last-assessed per integration ─────────────────────────────────────────────
st.divider()
st.subheader("Integration Last Pull Times")

connector_status = st.session_state.get("connector_status", {})
connector_findings = st.session_state.get("connector_findings", {})

if connector_findings:
    import pandas as pd
    rows = []
    for key, findings in connector_findings.items():
        if isinstance(findings, dict):
            rows.append({
                "Integration":   key.replace("_", " ").title(),
                "Source":        findings.get("_source", "unknown"),
                "Last Pull":     findings.get("_collected_at", "")[:19] if findings.get("_collected_at") else "unknown",
                "Status":        "✅ OK" if "_error" not in findings else "❌ Error",
            })
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("No integration data pulled yet.")
