import streamlit as st
from datetime import date, timedelta
import json
import os

st.set_page_config(
    page_title="SOC2 Readiness Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Style overrides ──────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0f172a; }
    .main-header {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 2rem 2.5rem;
        margin-bottom: 2rem;
    }
    .main-header h1 { color: #f1f5f9; margin: 0; font-size: 2rem; }
    .main-header p  { color: #94a3b8; margin: 0.5rem 0 0; font-size: 1rem; }
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 1.25rem;
        text-align: center;
    }
    .badge-type1 {
        background: #1d4ed8; color: #bfdbfe;
        padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600;
    }
    .badge-type2 {
        background: #7c3aed; color: #ddd6fe;
        padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600;
    }
    div[data-testid="stSidebarNav"] li div p { font-size: 0.95rem; }
    .stButton > button {
        background: #6366f1; color: #fff; border: none;
        border-radius: 6px; font-weight: 600;
    }
    .stButton > button:hover { background: #4f46e5; }
</style>
""", unsafe_allow_html=True)


# ── Session state defaults ───────────────────────────────────────────────────
def _init_session():
    defaults = {
        "audit_type": None,
        "tsc_scope": ["CC", "A", "PI", "C", "P"],
        "org_name": "",
        "type2_start": date.today() - timedelta(days=365),
        "type2_end": date.today(),
        "setup_complete": False,
        "connector_status": {},
        "last_assessment": None,
        "findings": {},
        "scores": {},
        "demo_mode": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_session()


# ── Load controls metadata ───────────────────────────────────────────────────
@st.cache_data
def load_controls():
    controls_path = os.path.join(os.path.dirname(__file__), "data", "controls.json")
    with open(controls_path) as f:
        return json.load(f)

controls_data = load_controls()
tsc_meta = controls_data["metadata"]["categories"]


# ── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ SOC2 Readiness Suite</h1>
    <p>Gap assessment · Audit preparation · Continuous monitoring for all 5 Trust Services Criteria</p>
</div>
""", unsafe_allow_html=True)


# ── Setup wizard (shown until complete) ─────────────────────────────────────
if not st.session_state.setup_complete:
    st.subheader("Session Setup")
    st.markdown("Configure your assessment before navigating to any module.")

    col1, col2 = st.columns([1, 1])

    with col1:
        org_name = st.text_input(
            "Organization Name",
            value=st.session_state.org_name,
            placeholder="Acme Corp",
            help="Used in all report headers and evidence packages.",
        )

        audit_type = st.radio(
            "Audit Type",
            options=["Type I", "Type II"],
            captions=[
                "Point-in-time snapshot — are controls designed and in place?",
                "12-month observation — are controls operating effectively over time?",
            ],
            horizontal=False,
        )

    with col2:
        st.markdown("**TSC Scope** — select criteria to include")
        tsc_selected = []
        tsc_display = {
            "CC": "🔐 Security (Common Criteria)",
            "A":  "📡 Availability",
            "PI": "⚙️ Processing Integrity",
            "C":  "🔒 Confidentiality",
            "P":  "🕵️ Privacy",
        }
        for code, label in tsc_display.items():
            default_val = code in st.session_state.tsc_scope
            if st.checkbox(label, value=default_val, key=f"tsc_{code}"):
                tsc_selected.append(code)

        if audit_type == "Type II":
            st.markdown("**Observation Period**")
            t2_col1, t2_col2 = st.columns(2)
            with t2_col1:
                type2_start = st.date_input(
                    "Start Date",
                    value=st.session_state.type2_start,
                    max_value=date.today(),
                )
            with t2_col2:
                type2_end = st.date_input(
                    "End Date",
                    value=st.session_state.type2_end,
                    min_value=type2_start,
                    max_value=date.today(),
                )

    st.divider()
    col_btn1, col_btn2, _ = st.columns([1, 1, 4])

    with col_btn1:
        if st.button("Start Assessment →", type="primary", use_container_width=True):
            if not org_name.strip():
                st.error("Organization name is required.")
            elif not tsc_selected:
                st.error("Select at least one TSC category.")
            else:
                st.session_state.org_name = org_name.strip()
                st.session_state.audit_type = audit_type
                st.session_state.tsc_scope = tsc_selected
                if audit_type == "Type II":
                    st.session_state.type2_start = type2_start
                    st.session_state.type2_end = type2_end
                st.session_state.setup_complete = True
                st.rerun()

    with col_btn2:
        if st.button("🎭 Demo Mode", use_container_width=True, help="Load fake org data — no API keys needed"):
            st.session_state.org_name = "Acme Corp (Demo)"
            st.session_state.audit_type = "Type II"
            st.session_state.tsc_scope = ["CC", "A", "PI", "C", "P"]
            st.session_state.type2_start = date.today() - timedelta(days=365)
            st.session_state.type2_end = date.today()
            st.session_state.demo_mode = True
            st.session_state.setup_complete = True
            st.rerun()

else:
    # ── Dashboard (post-setup) ────────────────────────────────────────────────
    badge_class = "badge-type1" if st.session_state.audit_type == "Type I" else "badge-type2"
    badge_label = st.session_state.audit_type

    demo_banner = ""
    if st.session_state.demo_mode:
        demo_banner = '<span style="background:#d97706;color:#fef3c7;padding:3px 10px;border-radius:12px;font-size:0.8rem;font-weight:600;margin-left:8px;">DEMO</span>'

    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1.5rem;">
        <h3 style="margin:0;color:#f1f5f9;">{st.session_state.org_name}</h3>
        <span class="{badge_class}">{badge_label}</span>
        {demo_banner}
    </div>
    """, unsafe_allow_html=True)

    # Quick-stat row
    total_controls = sum(
        1 for c in controls_data["controls"]
        if c["tsc"] in st.session_state.tsc_scope
    )
    scores = st.session_state.scores or {}
    compliant_count   = sum(1 for v in scores.values() if v == "compliant")
    partial_count     = sum(1 for v in scores.values() if v == "partial")
    noncompliant_count = sum(1 for v in scores.values() if v == "non_compliant")
    assessed = compliant_count + partial_count + noncompliant_count
    readiness_pct = round((compliant_count / assessed * 100) if assessed else 0)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Controls in Scope", total_controls)
    with c2:
        st.metric("Assessed", assessed)
    with c3:
        st.metric("✅ Compliant", compliant_count)
    with c4:
        st.metric("⚠️ Partial / ❌ Gaps", partial_count + noncompliant_count)
    with c5:
        st.metric("Readiness Score", f"{readiness_pct}%")

    st.divider()

    # TSC scope summary
    st.markdown("**Active TSC Scope**")
    cols = st.columns(len(st.session_state.tsc_scope))
    for i, code in enumerate(st.session_state.tsc_scope):
        with cols[i]:
            cat_controls = [c for c in controls_data["controls"] if c["tsc"] == code]
            cat_scored = [v for k, v in scores.items() if k.startswith(code)]
            cat_compliant = sum(1 for v in cat_scored if v == "compliant")
            cat_pct = round(cat_compliant / len(cat_scored) * 100) if cat_scored else 0
            color = "#22c55e" if cat_pct >= 80 else "#f59e0b" if cat_pct >= 50 else "#ef4444"
            st.markdown(f"""
            <div class="metric-card">
                <div style="font-size:1.5rem">{["🔐","📡","⚙️","🔒","🕵️"][["CC","A","PI","C","P"].index(code)]}</div>
                <div style="color:#94a3b8;font-size:0.75rem;margin-top:4px">{tsc_meta[code].split("(")[0].strip()}</div>
                <div style="font-size:1.25rem;font-weight:700;color:{color};margin-top:6px">
                    {cat_pct}%
                </div>
                <div style="color:#64748b;font-size:0.7rem">{len(cat_controls)} controls</div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()
    st.markdown("**Get started:** Use the sidebar to navigate to **Integrations** → connect your data sources, then run a **Gap Assessment**.")

    if st.button("↩ Reset Session"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()


# ── Sidebar context ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("---")
    if st.session_state.setup_complete:
        st.caption(f"**Org:** {st.session_state.org_name}")
        st.caption(f"**Type:** {st.session_state.audit_type}")
        st.caption(f"**Scope:** {', '.join(st.session_state.tsc_scope)}")
        if st.session_state.audit_type == "Type II":
            st.caption(f"**Period:** {st.session_state.type2_start} → {st.session_state.type2_end}")
        if st.session_state.demo_mode:
            st.warning("Demo mode active")
    else:
        st.info("Complete setup on the home page to unlock all modules.")
