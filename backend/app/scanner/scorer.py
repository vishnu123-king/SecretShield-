from typing import Dict, Any, List, Tuple

def calculate_risk_score(
    rule_type: str,
    base_confidence: float,
    entropy_high: bool,
    entropy_value: float,
    is_sensitive_file: bool,
    is_test_or_example: bool,
    is_placeholder: bool,
    is_commented: bool,
    is_production_signal: bool,
    is_in_git_history: bool,
    is_currently_present: bool = True
) -> Dict[str, Any]:
    """
    Calculate an explainable risk score (0-100) and severity rating.
    Returns score, severity, and an itemized breakdown of reasons.
    """
    score = 0
    reasons: List[Dict[str, Any]] = []

    # 1. Base rule type and confidence scoring
    cloud_or_key_types = {
        'cloud_credential', 'private_key', 'aws_credential',
        'github_token', 'database_credential', 'payment_credential'
    }
    
    if rule_type in cloud_or_key_types:
        pts = int(base_confidence * 45)
        score += pts
        reasons.append({
            "delta": f"+{pts}",
            "factor": "High-impact credential pattern (Cloud/Database/Auth/Key)",
            "impact": "positive"
        })
    else:
        pts = int(base_confidence * 30)
        score += pts
        reasons.append({
            "delta": f"+{pts}",
            "factor": f"Pattern match ({rule_type}) with confidence {int(base_confidence * 100)}%",
            "impact": "positive"
        })

    # 2. Shannon Entropy signal
    if entropy_high:
        pts = 20 if entropy_value >= 4.5 else 12
        score += pts
        reasons.append({
            "delta": f"+{pts}",
            "factor": f"Elevated Shannon entropy ({entropy_value:.2f}) indicates high randomness payload",
            "impact": "positive"
        })
    elif entropy_value < 2.5:
        score -= 10
        reasons.append({
            "delta": "-10",
            "factor": f"Low Shannon entropy ({entropy_value:.2f}) indicates repetitive or structured string",
            "impact": "negative"
        })

    # 3. File sensitivity
    if is_sensitive_file:
        score += 15
        reasons.append({
            "delta": "+15",
            "factor": "Sensitive configuration or secrets file location (.env, credentials, tfvars)",
            "impact": "positive"
        })

    # 4. Production keyword signal
    if is_production_signal:
        score += 10
        reasons.append({
            "delta": "+10",
            "factor": "Context references production / live environment",
            "impact": "positive"
        })

    # 5. Git history exposure
    if is_in_git_history:
        pts = 15 if not is_currently_present else 10
        score += pts
        desc = "Exposed in Git commit history (lingering exposure even if removed from HEAD)" if not is_currently_present else "Present in Git commit history"
        reasons.append({
            "delta": f"+{pts}",
            "factor": desc,
            "impact": "positive"
        })

    # 6. Test, sample, or documentation mitigation
    if is_test_or_example:
        score -= 20
        reasons.append({
            "delta": "-20",
            "factor": "Located in test, mock, or documentation directory",
            "impact": "negative"
        })

    # 7. Placeholder or dummy indicator mitigation
    if is_placeholder:
        score -= 35
        reasons.append({
            "delta": "-35",
            "factor": "Appears to be a placeholder or dummy example value",
            "impact": "negative"
        })

    # 8. Commented out code mitigation
    if is_commented:
        score -= 10
        reasons.append({
            "delta": "-10",
            "factor": "Line is commented out in source code",
            "impact": "negative"
        })

    # Bound score between 0 and 100
    final_score = max(0, min(100, score))

    # Map to severity
    if final_score >= 80:
        severity = "CRITICAL"
    elif final_score >= 60:
        severity = "HIGH"
    elif final_score >= 40:
        severity = "MEDIUM"
    elif final_score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "score": final_score,
        "severity": severity,
        "reasons": reasons
    }
