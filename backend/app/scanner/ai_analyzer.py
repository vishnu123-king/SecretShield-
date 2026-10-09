import re
from typing import Dict, Any, List

class AISecurityAnalyzer:
    """
    AI-Assisted Security Explanation & Exposure Intelligence Layer.
    Provides explainable rationale, blast radius analysis, and containment advice.
    Maintains strict zero-trust safety: never exposes plaintext secrets or executes payloads.
    """

    @staticmethod
    def generate_explanation(finding: Dict[str, Any]) -> Dict[str, Any]:
        rule_name = finding.get("rule_name", "Credential")
        rule_type = finding.get("secret_type", "credential")
        severity = finding.get("severity", "MEDIUM")
        score = finding.get("score", 50)
        primary_file = finding.get("primary_file", "")
        is_currently_present = finding.get("is_currently_present", True)
        total_occurrences = finding.get("total_occurrences", 1)
        commits = finding.get("commits", [])
        context = finding.get("context", {})
        is_placeholder = context.get("is_placeholder", False)
        is_sensitive_file = context.get("file_classification", {}).get("is_sensitive", False)
        is_test_file = context.get("file_classification", {}).get("is_test_or_example", False)

        # 1. Structural Checklist: "Why SecretShield Detected This"
        evidence_points: List[str] = []
        evidence_points.append(f"Format conforms to verifiable signature pattern for {rule_name}")

        if finding.get("confidence", 0) >= 0.9:
            evidence_points.append("High mathematical confidence match (>= 90%)")
        
        if is_sensitive_file:
            evidence_points.append(f"Committed inside critical environment/config path: '{primary_file}'")
        elif is_test_file:
            evidence_points.append(f"Located in test or sample directory ('{primary_file}')")
        else:
            evidence_points.append(f"Committed in codebase source file ('{primary_file}')")

        if is_currently_present:
            evidence_points.append("Active exposure: Secret is present in current HEAD working files")
        else:
            evidence_points.append("Historical exposure: Deleted from latest working tree, but persists in Git commit history")

        if len(commits) > 0:
            evidence_points.append(f"Traceable commit provenance across {len(commits)} historical commit(s)")

        if is_placeholder:
            evidence_points.append("Surrounding code contains mock / placeholder indicators (lowered risk score)")

        # 2. AI Synthesis Text
        if is_placeholder or is_test_file:
            ai_synthesis = (
                f"While this candidate matches the signature of a {rule_name}, surrounding context analysis "
                f"strongly indicates it is deployed within a test fixture or mock environment in '{primary_file}'. "
                "Although operational risk is mitigated, credentials in test files can sometimes mirror staging/production keys "
                "or leak valid credential syntaxes to external auditors."
            )
            operational_risk = "LOW_PROBABILITY_FIXTURE"
        elif severity == "CRITICAL":
            ai_synthesis = (
                f"CRITICAL THREAT: This token matches a high-privilege {rule_name} signature with elevated entropy "
                f"in a non-test file ('{primary_file}'). "
                f"{'It is currently live in HEAD and vulnerable to immediate unauthorized extraction.' if is_currently_present else 'Although purged from the latest commit, Git history retains full plaintext recoverable copies.'} "
                "Immediate credential revocation in the upstream cloud/SaaS provider is strongly advised."
            )
            operational_risk = "HIGH_LIVE_CREDENTIAL_PROBABILITY"
        elif severity == "HIGH":
            ai_synthesis = (
                f"ELEVATED RISK: Validated {rule_name} exposure discovered in '{primary_file}'. "
                "The payload structure indicates an operational secret with sufficient randomness to evade simple string searches. "
                "Exposure could grant unauthorized API access or database traversal."
            )
            operational_risk = "MODERATE_TO_HIGH_PROBABILITY"
        else:
            ai_synthesis = (
                f"Candidate {rule_name} detected. Risk index is scored at {score}/100. "
                "Review the masked line context to determine if this credential is operational or an internal identifier."
            )
            operational_risk = "INFORMATIONAL_OR_LOW"

        # 3. Blast Radius Assessment
        blast_radius = {
            "scope": "Cloud Infrastructure" if "aws" in rule_type or "cloud" in rule_type else (
                "Database Cluster" if "database" in rule_type or "db" in rule_type else (
                    "Source Code & Version Control" if "github" in rule_type or "gitlab" in rule_type else (
                        "Payment Gateway" if "stripe" in rule_type else "Application Services"
                    )
                )
            ),
            "containment_priority": "P0_IMMEDIATE_REVOCATION" if severity == "CRITICAL" and is_currently_present else (
                "P1_HISTORY_PURGE" if severity in ("CRITICAL", "HIGH") else "P2_AUDIT_REVIEW"
            ),
            "recommended_actions": [
                "1. Immediately rotate or revoke key via upstream provider management portal.",
                "2. Check upstream access/audit logs for anomalous queries originating during the exposure window.",
                "3. Invalidate active session tokens and reissue fresh credentials stored in a Secrets Manager (Vault, AWS Secrets Manager, Doppler).",
                "4. If historical, purge git commit references using 'git filter-repo' to prevent clone-level extraction."
            ]
        }

        return {
            "evidence_points": evidence_points,
            "ai_synthesis": ai_synthesis,
            "operational_risk": operational_risk,
            "blast_radius": blast_radius
        }
