"""
pdf_exporter.py — generates an executive summary PDF using ReportLab.
"""

import io
from datetime import datetime
from typing import Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False


STATUS_LABEL = {
    "compliant":     "Compliant",
    "partial":       "Partial",
    "non_compliant": "Non-Compliant",
    "not_assessed":  "Not Assessed",
    "accepted_risk": "Accepted Risk",
}

TSC_LABELS = {
    "CC": "Security (Common Criteria)",
    "A":  "Availability",
    "PI": "Processing Integrity",
    "C":  "Confidentiality",
    "P":  "Privacy",
}


def generate_executive_summary(
    org_name: str,
    audit_type: str,
    tsc_scope: list[str],
    results: dict,
    cat_scores: dict,
    overall_score: float,
    controls: list[dict],
) -> Optional[bytes]:
    """
    Returns PDF bytes or None if ReportLab is not installed.
    """
    if not _REPORTLAB_AVAILABLE:
        return None

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=inch,
        rightMargin=inch,
    )

    DARK    = colors.HexColor("#0f172a")
    ACCENT  = colors.HexColor("#6366f1")
    LIGHT   = colors.HexColor("#f1f5f9")
    GREEN   = colors.HexColor("#22c55e")
    YELLOW  = colors.HexColor("#f59e0b")
    RED     = colors.HexColor("#ef4444")
    MUTED   = colors.HexColor("#64748b")
    SURFACE = colors.HexColor("#1e293b")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=24, textColor=LIGHT, spaceAfter=4, alignment=TA_LEFT,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontSize=11, textColor=MUTED, spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=14, textColor=ACCENT, spaceAfter=6, spaceBefore=16,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=10, textColor=LIGHT, spaceAfter=4,
    )
    body_muted = ParagraphStyle(
        "BodyMuted", parent=styles["Normal"],
        fontSize=9, textColor=MUTED, spaceAfter=3,
    )

    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Paragraph(f"{org_name}", title_style))
    story.append(Paragraph("SOC 2 Readiness Assessment — Executive Summary", subtitle_style))
    story.append(Paragraph(
        f"Audit Type: <b>{audit_type}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"TSC Scope: <b>{', '.join(tsc_scope)}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Date: <b>{datetime.utcnow().date().isoformat()}</b>",
        body_muted,
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=16))

    # ── Overall score ─────────────────────────────────────────────────────────
    story.append(Paragraph("Overall Readiness", h2_style))
    score_color = GREEN if overall_score >= 80 else YELLOW if overall_score >= 50 else RED
    score_style = ParagraphStyle(
        "Score", parent=styles["Normal"],
        fontSize=42, textColor=score_color, spaceAfter=4,
    )
    story.append(Paragraph(f"{overall_score:.1f}%", score_style))

    statuses = [r["status"] for r in results.values()]
    summary_data = [
        ["Status", "Count"],
        ["✓ Compliant",     str(statuses.count("compliant"))],
        ["⚠ Partial",       str(statuses.count("partial"))],
        ["✗ Non-compliant", str(statuses.count("non_compliant"))],
        ["― Not assessed",  str(statuses.count("not_assessed"))],
        ["○ Accepted risk", str(statuses.count("accepted_risk"))],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 1 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR",  (0, 1), (-1, -1), LIGHT),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK, SURFACE]),
        ("GRID", (0, 0), (-1, -1), 0.5, MUTED),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)

    # ── Per-category scores ───────────────────────────────────────────────────
    story.append(Paragraph("Scores by TSC Category", h2_style))
    cat_data = [["Category", "Readiness %", "Status"]]
    for cat in tsc_scope:
        pct  = cat_scores.get(cat, 0)
        sts  = "Strong" if pct >= 80 else "Developing" if pct >= 50 else "Needs Attention"
        cat_data.append([TSC_LABELS.get(cat, cat), f"{pct:.1f}%", sts])
    cat_table = Table(cat_data, colWidths=[3 * inch, 1.2 * inch, 1.5 * inch])
    cat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR",  (0, 1), (-1, -1), LIGHT),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK, SURFACE]),
        ("GRID", (0, 0), (-1, -1), 0.5, MUTED),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(cat_table)

    # ── Top 5 gaps ────────────────────────────────────────────────────────────
    story.append(Paragraph("Top Gaps", h2_style))
    ctrl_map = {c["control_id"]: c for c in controls}
    gap_controls = [
        (cid, r) for cid, r in results.items()
        if r["status"] == "non_compliant" and r.get("gaps")
    ]
    gap_controls.sort(key=lambda x: len(x[1].get("gaps", [])), reverse=True)

    if gap_controls:
        gap_data = [["Control", "Title", "Primary Gap"]]
        for cid, r in gap_controls[:5]:
            ctrl = ctrl_map.get(cid, {})
            gap_data.append([cid, ctrl.get("title", "")[:45], r["gaps"][0][:50]])
        gap_table = Table(gap_data, colWidths=[0.8 * inch, 2.5 * inch, 2.5 * inch])
        gap_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR",  (0, 1), (-1, -1), LIGHT),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [DARK, SURFACE]),
            ("GRID", (0, 0), (-1, -1), 0.5, MUTED),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("WORDWRAP", (0, 0), (-1, -1), True),
        ]))
        story.append(gap_table)
    else:
        story.append(Paragraph("No non-compliant controls identified.", body_style))

    # ── Remediation roadmap ───────────────────────────────────────────────────
    story.append(Paragraph("Recommended Remediation Priorities", h2_style))
    partial_controls = [(cid, r) for cid, r in results.items() if r["status"] == "partial"]
    all_gaps = gap_controls + partial_controls
    if all_gaps:
        for i, (cid, r) in enumerate(all_gaps[:8]):
            ctrl = ctrl_map.get(cid, {})
            story.append(Paragraph(
                f"{i+1}. <b>{cid}</b> — {ctrl.get('title', '')}",
                body_style,
            ))
            for g in r.get("gaps", [])[:2]:
                story.append(Paragraph(f"   • {g}", body_muted))
    else:
        story.append(Paragraph("All assessed controls are compliant or accepted.", body_style))

    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MUTED))
    story.append(Paragraph(
        f"Generated by SOC2 Readiness Suite · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        body_muted,
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()
