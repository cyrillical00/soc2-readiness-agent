"""
policy_generator.py — Claude API integration for policy doc drafts and control narratives.
"""

import os
import streamlit as st

try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False


POLICY_TEMPLATES = {
    "information_security_policy": {
        "name": "Information Security Policy",
        "controls": ["CC2.1", "CC5.3"],
        "prompt_context": "an overarching information security policy covering risk management, asset protection, access controls, and incident response",
    },
    "access_control_policy": {
        "name": "Access Control Policy",
        "controls": ["CC6.1", "CC6.2", "CC6.3", "CC6.5"],
        "prompt_context": "a logical access control policy covering user provisioning, MFA requirements, role-based access, least privilege, and access reviews",
    },
    "change_management_policy": {
        "name": "Change Management Policy",
        "controls": ["CC8.1"],
        "prompt_context": "a change management policy covering change request processes, testing, approvals, and deployment controls",
    },
    "incident_response_plan": {
        "name": "Incident Response Plan",
        "controls": ["CC7.3", "CC7.4", "CC7.5"],
        "prompt_context": "an incident response plan covering detection, classification, containment, eradication, recovery, and lessons learned",
    },
    "business_continuity_plan": {
        "name": "Business Continuity Plan",
        "controls": ["A1.1", "A1.2", "A1.3"],
        "prompt_context": "a business continuity and disaster recovery plan covering RTO/RPO objectives, backup procedures, and recovery testing",
    },
    "vulnerability_management_policy": {
        "name": "Vulnerability Management Policy",
        "controls": ["CC5.2", "CC7.1"],
        "prompt_context": "a vulnerability management policy covering scanning cadence, CVSS scoring, patching SLAs, and remediation tracking",
    },
    "data_classification_policy": {
        "name": "Data Classification Policy",
        "controls": ["C1.1", "P3.1"],
        "prompt_context": "a data classification policy covering classification tiers (public, internal, confidential, restricted), handling requirements, and labeling procedures",
    },
    "vendor_management_policy": {
        "name": "Vendor Management Policy",
        "controls": ["CC9.1", "CC9.2"],
        "prompt_context": "a third-party vendor management policy covering due diligence, security assessments, contract requirements, and ongoing monitoring",
    },
    "privacy_policy": {
        "name": "Privacy Policy",
        "controls": ["P1.1", "P2.1", "P4.1"],
        "prompt_context": "a privacy policy covering data collection, use, retention, individual rights, and breach notification",
    },
    "acceptable_use_policy": {
        "name": "Acceptable Use Policy",
        "controls": ["CC2.2"],
        "prompt_context": "an acceptable use policy covering employee responsibilities for company systems, data handling, and prohibited activities",
    },
    "backup_policy": {
        "name": "Backup and Recovery Policy",
        "controls": ["A1.2", "A1.3"],
        "prompt_context": "a backup and recovery policy covering backup frequency, storage locations, encryption, retention periods, and recovery testing",
    },
    "physical_security_policy": {
        "name": "Physical Security Policy",
        "controls": ["CC6.4"],
        "prompt_context": "a physical security policy covering facility access, visitor management, clean desk, and equipment disposal",
    },
    "risk_assessment_procedure": {
        "name": "Risk Assessment Procedure",
        "controls": ["CC3.1", "CC3.2", "CC3.3"],
        "prompt_context": "a risk assessment procedure covering risk identification, likelihood/impact scoring, risk register maintenance, and treatment plans",
    },
    "code_of_conduct": {
        "name": "Code of Conduct",
        "controls": ["CC1.1"],
        "prompt_context": "a code of conduct and ethics policy covering integrity, conflicts of interest, confidentiality, and reporting obligations",
    },
}


def _get_client():
    if not _ANTHROPIC_AVAILABLE:
        return None
    api_key = st.secrets.get("ANTHROPIC_API_KEY", os.getenv("ANTHROPIC_API_KEY", ""))
    if not api_key:
        return None
    return anthropic.Anthropic(api_key=api_key)


def generate_policy(
    policy_key: str,
    org_name: str,
    tsc_scope: list[str],
    audit_type: str,
    additional_context: str = "",
) -> str:
    """
    Calls Claude to generate a structured policy document draft.
    Returns the policy text as a string.
    """
    client = _get_client()
    if client is None:
        return _fallback_policy(policy_key, org_name)

    template = POLICY_TEMPLATES.get(policy_key, {})
    policy_name = template.get("name", policy_key.replace("_", " ").title())
    prompt_context = template.get("prompt_context", f"a {policy_name.lower()}")
    controls_str = ", ".join(template.get("controls", []))

    system_prompt = f"""You are an experienced information security officer and SOC2 compliance specialist.
Your task is to draft clear, practical, implementation-ready policy documents for organizations preparing for SOC2 {audit_type} audits.

Write in professional but accessible language. Documents should be complete enough to satisfy auditors while being practical for employees to follow.

Format each document with these sections:
1. **Purpose**
2. **Scope**
3. **Policy Statement**
4. **Procedures** (numbered steps)
5. **Roles and Responsibilities**
6. **Review Cycle**
7. **Exceptions Process**
8. **Related Policies and Controls**

Map each policy to its relevant SOC2 TSC controls."""

    user_prompt = f"""Draft {prompt_context} for {org_name}.

SOC2 controls this policy supports: {controls_str}
TSC scope for this engagement: {', '.join(tsc_scope)}
Audit type: {audit_type}
{f'Additional context: {additional_context}' if additional_context else ''}

Produce a complete, audit-ready policy document. Include specific, actionable requirements rather than generic statements.
Where applicable, include measurable thresholds (e.g., "MFA must be enrolled within 24 hours of account creation")."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": user_prompt}],
            system=system_prompt,
        )
        return response.content[0].text
    except Exception as e:
        return f"Error generating policy: {e}\n\n{_fallback_policy(policy_key, org_name)}"


def generate_control_narrative(
    category: str,
    category_label: str,
    results: dict,
    controls: list[dict],
    org_name: str,
    audit_type: str,
) -> str:
    """
    Generates an auditor-facing control narrative for a TSC category.
    """
    client = _get_client()

    # Assemble evidence summary for this category
    cat_controls = [c for c in controls if c["tsc"] == category]
    cat_results  = {cid: r for cid, r in results.items() if any(c["control_id"] == cid for c in cat_controls)}

    evidence_summary = []
    ctrl_map = {c["control_id"]: c for c in cat_controls}
    for cid, result in cat_results.items():
        ctrl = ctrl_map.get(cid, {})
        evidence_summary.append(
            f"- {cid} ({ctrl.get('title', '')}): {result['status'].upper()}"
            + (f" — gaps: {'; '.join(result.get('gaps', []))}" if result.get("gaps") else "")
        )

    summary_text = "\n".join(evidence_summary) if evidence_summary else "No evidence available."

    if client is None:
        return _fallback_narrative(category, category_label, org_name, summary_text)

    system_prompt = """You are a SOC2 auditor-facing writer. Write control narratives that:
- Describe what controls exist and how they are implemented
- Reference specific systems and tools where mentioned in evidence
- Are factual and evidence-based — do not claim compliance without evidence
- Use present tense, professional tone
- Are 300-500 words per category
- Are suitable for inclusion in a SOC2 readiness report or auditor questionnaire"""

    user_prompt = f"""Write a control narrative for {org_name}'s {category_label} ({category}) controls.

Current control assessment results:
{summary_text}

Audit type: {audit_type}

Describe:
1. What controls {org_name} has implemented for {category_label}
2. Which systems and tools enforce these controls
3. Any identified gaps and their significance
4. The overall maturity of this control domain

Do not fabricate specifics not present in the evidence. For gaps, acknowledge them factually."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=800,
            messages=[{"role": "user", "content": user_prompt}],
            system=system_prompt,
        )
        return response.content[0].text
    except Exception as e:
        return f"Error generating narrative: {e}\n\n{_fallback_narrative(category, category_label, org_name, summary_text)}"


def _fallback_policy(policy_key: str, org_name: str) -> str:
    template = POLICY_TEMPLATES.get(policy_key, {})
    name = template.get("name", policy_key.replace("_", " ").title())
    return f"""# {name}

**Organization:** {org_name}
**Version:** 1.0 (Draft)
**Last Updated:** [DATE]
**Owner:** [POLICY OWNER]
**Approved By:** [APPROVER]

---

## 1. Purpose
[Describe the purpose of this policy and why it exists.]

## 2. Scope
This policy applies to all employees, contractors, and third parties who access {org_name}'s systems and data.

## 3. Policy Statement
[Describe the core policy requirements.]

## 4. Procedures
1. [Step one]
2. [Step two]
3. [Step three]

## 5. Roles and Responsibilities
- **Security Team:** [Responsibilities]
- **All Employees:** [Responsibilities]
- **IT/Engineering:** [Responsibilities]

## 6. Review Cycle
This policy shall be reviewed annually or after any significant change.

## 7. Exceptions Process
Exceptions must be approved in writing by the [CISO/Security Lead] and documented in the risk register.

## 8. Related Policies and Controls
SOC2 controls: {', '.join(template.get('controls', []))}

---
*This is a template. ANTHROPIC_API_KEY must be set in secrets.toml for AI-generated content.*
"""


def _fallback_narrative(category: str, label: str, org_name: str, summary: str) -> str:
    return f"""## {label} ({category}) Control Narrative — {org_name}

*Note: Set ANTHROPIC_API_KEY in secrets.toml for AI-generated narratives.*

### Control Summary
{summary}

### Narrative
[This section will be auto-generated once ANTHROPIC_API_KEY is configured. It will describe:
- What controls are implemented and how they operate
- Which systems enforce these controls
- Identified gaps and compensating controls
- Overall control maturity assessment]
"""
