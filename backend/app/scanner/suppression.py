import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

class SuppressionManager:
    def __init__(self, suppressions: Optional[List[Dict[str, Any]]] = None):
        self.suppressions = suppressions or []

    def is_suppressed(
        self,
        finding_id: str,
        fingerprint: str,
        file_path: str,
        rule_id: str,
        repository_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Check if a finding matches any active suppression rule.
        Returns (is_suppressed, matching_suppression_object_or_reason).
        """
        now = datetime.utcnow()
        normalized_path = file_path.replace('\\', '/')

        for sup in self.suppressions:
            # Check expiration date if specified
            expires_at = sup.get("expires_at")
            if expires_at:
                try:
                    if isinstance(expires_at, str):
                        # ISO format
                        exp_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00')).replace(tzinfo=None)
                    else:
                        exp_dt = expires_at
                    if now > exp_dt:
                        continue  # Expired suppression
                except Exception:
                    pass

            # Check repository scope
            sup_repo = sup.get("repository_id")
            if sup_repo and repository_id and sup_repo != repository_id:
                continue

            # 1. Exact finding ID match
            if sup.get("finding_id") and sup.get("finding_id") == finding_id:
                return True, sup.get("reason", f"Suppressed by finding ID {finding_id}")

            # 2. Fingerprint match
            if sup.get("fingerprint") and sup.get("fingerprint") == fingerprint:
                return True, sup.get("reason", f"Suppressed by secret fingerprint {fingerprint}")

            # 3. Rule ID + Path pattern match
            sup_rule = sup.get("rule_id")
            sup_path = sup.get("path_pattern")

            if sup_rule and sup_path:
                if sup_rule == rule_id and (sup_path in normalized_path or re.search(sup_path, normalized_path)):
                    return True, sup.get("reason", f"Suppressed by rule '{rule_id}' on path '{sup_path}'")
            elif sup_rule and not sup_path:
                if sup_rule == rule_id:
                    return True, sup.get("reason", f"Suppressed by rule '{rule_id}' globally")
            elif sup_path and not sup_rule:
                if sup_path in normalized_path or re.search(sup_path, normalized_path):
                    return True, sup.get("reason", f"Suppressed by path pattern '{sup_path}'")

        return False, ""

# Type helper
Tuple_IsSuppressed = tuple[bool, str]
