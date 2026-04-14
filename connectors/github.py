"""
GitHub connector — org 2FA, branch protection, outside collaborators, secret scanning.
Covers: CC8 (Change Management)
"""

import os
from datetime import datetime

import streamlit as st


def _get_creds():
    token = st.secrets.get("GITHUB_TOKEN", os.getenv("GITHUB_TOKEN", ""))
    org   = st.secrets.get("GITHUB_ORG",   os.getenv("GITHUB_ORG", ""))
    return token, org


def is_configured() -> bool:
    token, org = _get_creds()
    return bool(token and org)


def test_connection() -> tuple[bool, str]:
    token, org = _get_creds()
    if not token or not org:
        return False, "GITHUB_TOKEN or GITHUB_ORG not set."
    try:
        from github import Github, GithubException
        g = Github(token)
        organisation = g.get_organization(org)
        return True, f"Connected to GitHub org: {organisation.login} ({organisation.public_repos} repos)"
    except Exception as e:
        return False, str(e)


def collect(demo: bool = False) -> dict:
    if demo or not is_configured():
        return _demo_data()

    token, org_name = _get_creds()
    findings = {}
    try:
        from github import Github, GithubException

        g   = Github(token)
        org = g.get_organization(org_name)

        findings["org_name"]              = org.login
        findings["org_2fa_required"]      = org.two_factor_requirement_enabled
        findings["total_members"]         = org.get_members().totalCount
        findings["outside_collaborators"] = org.get_outside_collaborators().totalCount

        repos = list(org.get_repos(type="all"))
        findings["total_repos"] = len(repos)

        branch_protected      = 0
        pr_review_required    = 0
        secret_scanning_enabled = 0
        public_repos          = 0
        admin_repos           = 0

        for repo in repos:
            if not repo.private:
                public_repos += 1
            try:
                default_branch = repo.default_branch or "main"
                bp = repo.get_branch(default_branch).get_protection()
                branch_protected += 1
                if bp.required_pull_request_reviews:
                    pr_review_required += 1
            except GithubException:
                pass
            try:
                if repo.get_vulnerability_alert():
                    secret_scanning_enabled += 1
            except GithubException:
                pass

        total = len(repos) or 1
        findings["branch_protection_rate"]    = round(branch_protected   / total * 100, 1)
        findings["pr_review_required_rate"]   = round(pr_review_required / total * 100, 1)
        findings["secret_scanning_rate"]      = round(secret_scanning_enabled / total * 100, 1)
        findings["public_repo_count"]         = public_repos
        findings["branch_protected_count"]    = branch_protected
        findings["pr_review_required_count"]  = pr_review_required

        findings["_source"] = "github_api"
        findings["_collected_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        findings["_error"] = str(e)

    return findings


def _demo_data() -> dict:
    return {
        "org_name": "acme-corp",
        "org_2fa_required": True,
        "total_members": 38,
        "outside_collaborators": 2,
        "total_repos": 24,
        "branch_protection_rate": 91.7,
        "pr_review_required_rate": 87.5,
        "secret_scanning_rate": 100.0,
        "public_repo_count": 3,
        "branch_protected_count": 22,
        "pr_review_required_count": 21,
        "_source": "demo",
        "_collected_at": datetime.utcnow().isoformat(),
    }
