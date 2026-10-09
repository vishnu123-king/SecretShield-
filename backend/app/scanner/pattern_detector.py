import os
import re
import json
from typing import List, Dict, Any, Optional

DEFAULT_BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "id": "aws-access-key-id",
        "name": "AWS Access Key ID",
        "type": "cloud_credential",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "keywords": ["AKIA", "ASIA", "aws_access_key_id", "AWS_ACCESS_KEY"],
        "patterns": [
            r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"
        ],
        "remediation": "1. Revoke the exposed AWS Access Key in IAM console immediately.\n2. Invalidate any active sessions.\n3. Audit CloudTrail for unauthorized API calls.\n4. Rotate to IAM Roles or AWS Secrets Manager."
    },
    {
        "id": "aws-secret-access-key",
        "name": "AWS Secret Access Key",
        "type": "cloud_credential",
        "severity": "CRITICAL",
        "confidence": 0.90,
        "keywords": ["aws_secret_access_key", "secret_key", "aws_secret"],
        "patterns": [
            r"(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]"
        ],
        "remediation": "1. Rotate AWS Secret Key immediately via AWS IAM.\n2. Check CloudTrail audit logs.\n3. Remove from code and store in AWS Secrets Manager or Parameter Store."
    },
    {
        "id": "github-pat",
        "name": "GitHub Personal Access Token",
        "type": "github_token",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "keywords": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        "patterns": [
            r"\b(ghp_[a-zA-Z0-9]{36})\b",
            r"\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b",
            r"\b(gho_[a-zA-Z0-9]{36})\b"
        ],
        "remediation": "1. Revoke token in GitHub Settings > Developer Settings > Personal Access Tokens.\n2. Audit GitHub audit logs for recent repository or org actions.\n3. Regenerate and store in GitHub Actions Secrets."
    },
    {
        "id": "gitlab-pat",
        "name": "GitLab Personal Access Token",
        "type": "gitlab_token",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "keywords": ["glpat-", "gitlab"],
        "patterns": [
            r"\b(glpat-[a-zA-Z0-9_\-]{20,25})\b"
        ],
        "remediation": "1. Revoke the token immediately in GitLab Profile > Access Tokens.\n2. Inspect GitLab security events for suspicious activity."
    },
    {
        "id": "private-key",
        "name": "Asymmetric Private Key",
        "type": "private_key",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "keywords": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN PGP PRIVATE KEY"],
        "patterns": [
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----"
        ],
        "remediation": "1. Treat the key pair as compromised.\n2. Generate a new key pair.\n3. Replace public keys on all servers/authorities.\n4. Remove private key file from repository and commit history."
    },
    {
        "id": "database-connection-string",
        "name": "Database Connection String with Credentials",
        "type": "database_credential",
        "severity": "HIGH",
        "confidence": 0.90,
        "keywords": ["postgres://", "postgresql://", "mysql://", "mongodb://", "redis://"],
        "patterns": [
            r"\b(postgres(?:ql)?://[a-zA-Z0-9_.\-]+:([^@\s/\"']+)@[a-zA-Z0-9_.\-]+(?::\d+)?/[a-zA-Z0-9_\-]+)",
            r"\b(mysql://[a-zA-Z0-9_.\-]+:([^@\s/\"']+)@[a-zA-Z0-9_.\-]+(?::\d+)?/[a-zA-Z0-9_\-]+)",
            r"\b(mongodb(?:\+srv)?://[a-zA-Z0-9_.\-]+:([^@\s/\"']+)@[a-zA-Z0-9_.\-]+)",
            r"\b(redis://:[^@\s/\"']+@[a-zA-Z0-9_.\-]+(?::\d+)?)"
        ],
        "remediation": "1. Change the database user's password immediately.\n2. Update connection configurations across running services.\n3. Move connection strings to environment variables or secret vaults."
    },
    {
        "id": "slack-token",
        "name": "Slack API / Bot Token",
        "type": "cloud_credential",
        "severity": "HIGH",
        "confidence": 0.95,
        "keywords": ["xoxb-", "xoxp-", "xoxa-", "xoxr-"],
        "patterns": [
            r"\b(xox[bpar]-[0-9a-zA-Z]{10,48})\b"
        ],
        "remediation": "1. Revoke the token via Slack API portal.\n2. Reissue a new OAuth/Bot token."
    },
    {
        "id": "stripe-api-key",
        "name": "Stripe Live/Secret Key",
        "type": "payment_credential",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "keywords": ["sk_live_", "rk_live_", "sk_test_"],
        "patterns": [
            r"\b(sk_live_[0-9a-zA-Z]{24,34})\b",
            r"\b(rk_live_[0-9a-zA-Z]{24,34})\b"
        ],
        "remediation": "1. Roll the restricted or secret key in Stripe Dashboard > Developers > API Keys.\n2. Review Stripe audit events."
    },
    {
        "id": "jwt-token",
        "name": "JSON Web Token (JWT)",
        "type": "auth_token",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "keywords": ["eyJhbGci", "Bearer eyJ"],
        "patterns": [
            r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
        ],
        "remediation": "1. Invalidate signing key or revoke active user token.\n2. Verify expiration and claims."
    },
    {
        "id": "generic-secret-assignment",
        "name": "Generic Secret or Password Assignment",
        "type": "generic_secret",
        "severity": "HIGH",
        "confidence": 0.70,
        "keywords": ["password", "secret", "api_key", "token", "access_token", "client_secret", "auth_token", "sess="],
        "patterns": [
            r"(?i)\b(?:password|passwd|pwd|api_key|apikey|secret|client_secret|access_token|auth_token|secret_key)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ],
        "remediation": "1. Evaluate whether the assigned value is an active production secret.\n2. If sensitive, rotate and extract to environment variable or vault."
    },
    {
        "id": "google-gemini-api-key",
        "name": "Google AI / Gemini API Key",
        "type": "ai_credential",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "keywords": ["AIzaSy", "AIza", "GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "patterns": [
            r"\b(AIzaSy[0-9A-Za-z-_]{33})\b",
            r"\b(AIza[0-9A-Za-z-_]{35})\b"
        ],
        "remediation": "1. Revoke the compromised Google AI key in Google Cloud Console or AI Studio.\n2. Audit Cloud Billing for anomalous model consumption.\n3. Regenerate and restrict key by HTTP referrers or IP address."
    },
    {
        "id": "openai-api-key",
        "name": "OpenAI API Key",
        "type": "ai_credential",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "keywords": ["sk-", "sk-proj-", "OPENAI_API_KEY"],
        "patterns": [
            r"\b(sk-proj-[a-zA-Z0-9_\-]{60,})\b",
            r"\b(sk-[a-zA-Z0-9]{48})\b"
        ],
        "remediation": "1. Delete the exposed OpenAI API key immediately in OpenAI Platform Dashboard.\n2. Check organization usage for unauthorized completions.\n3. Store replacement keys in environment variables."
    },
    {
        "id": "anthropic-api-key",
        "name": "Anthropic Claude API Key",
        "type": "ai_credential",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "keywords": ["sk-ant-", "ANTHROPIC_API_KEY"],
        "patterns": [
            r"\b(sk-ant-[a-zA-Z0-9_\-]{80,})\b"
        ],
        "remediation": "1. Revoke key in Anthropic Console > Settings > API Keys.\n2. Reissue a workspace key and store in secrets manager."
    },
    {
        "id": "huggingface-token",
        "name": "Hugging Face User Access Token",
        "type": "ai_credential",
        "severity": "HIGH",
        "confidence": 0.95,
        "keywords": ["hf_", "HUGGINGFACE_TOKEN", "HF_TOKEN"],
        "patterns": [
            r"\b(hf_[a-zA-Z0-9]{34})\b"
        ],
        "remediation": "1. Invalidate token in Hugging Face Account Settings > Access Tokens.\n2. Ensure model repos and inference endpoints are secured."
    },
    {
        "id": "sendgrid-api-key",
        "name": "SendGrid API Key",
        "type": "cloud_credential",
        "severity": "CRITICAL",
        "confidence": 0.97,
        "keywords": ["SG.", "sendgrid"],
        "patterns": [
            r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b"
        ],
        "remediation": "1. Revoke the API key in SendGrid Settings > API Keys.\n2. Verify email activity logs for spam/phishing abuses."
    },
    {
        "id": "twilio-api-key",
        "name": "Twilio API Key / Auth Token",
        "type": "cloud_credential",
        "severity": "HIGH",
        "confidence": 0.94,
        "keywords": ["SK", "twilio", "TWILIO_AUTH_TOKEN"],
        "patterns": [
            r"\b(SK[0-9a-fA-F]{32})\b"
        ],
        "remediation": "1. Delete the API key in Twilio Console > API Keys.\n2. Review SMS/Call logs for unauthorized charges."
    },
    {
        "id": "npm-access-token",
        "name": "NPM Registry Access Token",
        "type": "package_credential",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "keywords": ["npm_", "NPM_TOKEN"],
        "patterns": [
            r"\b(npm_[a-zA-Z0-9]{36})\b"
        ],
        "remediation": "1. Invalidate token in npmjs.com > Profile > Access Tokens.\n2. Check published package versions for malicious injections."
    },
    {
        "id": "pypi-api-token",
        "name": "PyPI Package Upload Token",
        "type": "package_credential",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "keywords": ["pypi-", "PYPI_TOKEN"],
        "patterns": [
            r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,})\b"
        ],
        "remediation": "1. Revoke the PyPI upload token in pypi.org/manage/account/token/.\n2. Audit releases on Python Package Index."
    },
    {
        "id": "discord-webhook-or-bot",
        "name": "Discord Webhook / Bot Token",
        "type": "cloud_credential",
        "severity": "HIGH",
        "confidence": 0.95,
        "keywords": ["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
        "patterns": [
            r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"
        ],
        "remediation": "1. Delete webhook in Discord Server Settings > Integrations.\n2. Recreate webhook with restricted permissions."
    }
]

class PatternDetector:
    def __init__(self, custom_rules: Optional[List[Dict[str, Any]]] = None):
        self.rules: List[Dict[str, Any]] = []
        self._compiled_rules: List[Dict[str, Any]] = []
        self.load_rules(custom_rules)

    def load_rules(self, custom_rules: Optional[List[Dict[str, Any]]] = None):
        rules_list = list(DEFAULT_BUILTIN_RULES)
        if custom_rules:
            # Override or append
            custom_ids = {r.get("id") for r in custom_rules}
            rules_list = [r for r in rules_list if r.get("id") not in custom_ids]
            rules_list.extend(custom_rules)
            
        self.rules = rules_list
        self._compiled_rules = []
        for r in self.rules:
            compiled_patterns = []
            for pat in r.get("patterns", []):
                try:
                    compiled_patterns.append(re.compile(pat))
                except re.error:
                    pass
            self._compiled_rules.append({
                **r,
                "_patterns": compiled_patterns
            })

    def match_line(self, line: str) -> List[Dict[str, Any]]:
        matches = []
        for rule in self._compiled_rules:
            keywords = rule.get("keywords", [])
            # Quick keyword pre-filter if defined
            if keywords:
                line_lower = line.lower()
                if not any(kw.lower() in line_lower for kw in keywords):
                    continue

            for pattern in rule.get("_patterns", []):
                for match in pattern.finditer(line):
                    # Pick capturing group 1 if present, otherwise group 0
                    if match.groups():
                        candidate = match.group(1) or match.group(0)
                    else:
                        candidate = match.group(0)

                    if candidate:
                        matches.append({
                            "rule_id": rule.get("id"),
                            "rule_name": rule.get("name"),
                            "rule_type": rule.get("type"),
                            "base_severity": rule.get("severity"),
                            "base_confidence": rule.get("confidence", 0.8),
                            "remediation": rule.get("remediation", ""),
                            "matched_candidate": candidate,
                            "match_span": match.span()
                        })
        return matches
