"""
Supabase client — state persistence for SOC2 Readiness Suite.

Tables:
  soc2_snapshots          — per-run assessment results
  soc2_controls_override  — accepted-risk overrides per control
"""

import json
import os
from datetime import datetime
from typing import Optional

import streamlit as st


def _get_client():
    """Return an initialised Supabase client, cached on session state."""
    if "supabase_client" not in st.session_state:
        try:
            from supabase import create_client
            url = st.secrets.get("SUPABASE_URL", os.getenv("SUPABASE_URL", ""))
            key = st.secrets.get("SUPABASE_KEY", os.getenv("SUPABASE_KEY", ""))
            if not url or not key:
                st.session_state["supabase_client"] = None
            else:
                st.session_state["supabase_client"] = create_client(url, key)
        except Exception:
            st.session_state["supabase_client"] = None
    return st.session_state["supabase_client"]


def is_connected() -> bool:
    return _get_client() is not None


# ── Snapshots ────────────────────────────────────────────────────────────────

def save_snapshot(
    org_name: str,
    audit_type: str,
    tsc_scope: list[str],
    overall_score: float,
    scores_by_category: dict,
    findings: dict,
) -> Optional[dict]:
    """Insert a new assessment snapshot. Returns the created row or None."""
    client = _get_client()
    if client is None:
        return None
    row = {
        "org_name": org_name,
        "audit_type": audit_type,
        "tsc_scope": tsc_scope,
        "overall_score": overall_score,
        "scores_by_category": scores_by_category,
        "findings": findings,
        "run_date": datetime.utcnow().isoformat(),
    }
    try:
        result = client.table("soc2_snapshots").insert(row).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        st.warning(f"Supabase save failed: {e}")
        return None


def list_snapshots(org_name: str, limit: int = 20) -> list[dict]:
    """Return recent snapshots for an org, newest first."""
    client = _get_client()
    if client is None:
        return []
    try:
        result = (
            client.table("soc2_snapshots")
            .select("*")
            .eq("org_name", org_name)
            .order("run_date", desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []
    except Exception as e:
        st.warning(f"Supabase fetch failed: {e}")
        return []


def get_last_snapshot(org_name: str) -> Optional[dict]:
    rows = list_snapshots(org_name, limit=1)
    return rows[0] if rows else None


# ── Control overrides ────────────────────────────────────────────────────────

def upsert_override(
    org_name: str,
    control_id: str,
    status_override: str,
    justification: str,
    overridden_by: str = "user",
) -> Optional[dict]:
    """Accept a risk / override a control status. Upserts on (org_name, control_id)."""
    client = _get_client()
    if client is None:
        return None
    row = {
        "org_name": org_name,
        "control_id": control_id,
        "status_override": status_override,
        "justification": justification,
        "overridden_by": overridden_by,
        "overridden_at": datetime.utcnow().isoformat(),
    }
    try:
        result = (
            client.table("soc2_controls_override")
            .upsert(row, on_conflict="org_name,control_id")
            .execute()
        )
        return result.data[0] if result.data else None
    except Exception as e:
        st.warning(f"Override save failed: {e}")
        return None


def list_overrides(org_name: str) -> list[dict]:
    client = _get_client()
    if client is None:
        return []
    try:
        result = (
            client.table("soc2_controls_override")
            .select("*")
            .eq("org_name", org_name)
            .execute()
        )
        return result.data or []
    except Exception as e:
        st.warning(f"Override fetch failed: {e}")
        return []


def delete_override(org_name: str, control_id: str) -> bool:
    client = _get_client()
    if client is None:
        return False
    try:
        client.table("soc2_controls_override").delete().eq("org_name", org_name).eq("control_id", control_id).execute()
        return True
    except Exception as e:
        st.warning(f"Override delete failed: {e}")
        return False
