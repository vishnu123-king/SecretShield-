from typing import List, Dict, Any, Optional

class FindingDeduplicator:
    """
    Groups related occurrences of the same secret fingerprint across multiple
    files, commits, branches, and repositories without creating redundant alert noise.
    """
    def __init__(self):
        self.fingerprint_map: Dict[str, Dict[str, Any]] = {}
        self.finding_counter = 0

    def add_occurrence(
        self,
        fingerprint: str,
        occurrence_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Record an occurrence of a secret. If this fingerprint has been seen before,
        aggregate metadata (commits, files, occurrences, timestamps).
        """
        file_path = occurrence_data.get("file_path", "")
        commit_hash = occurrence_data.get("commit_hash")
        commit_date = occurrence_data.get("commit_date")
        branch = occurrence_data.get("branch")
        is_in_head = occurrence_data.get("is_in_head", True)

        if fingerprint not in self.fingerprint_map:
            self.finding_counter += 1
            finding_id = f"SS-{self.finding_counter:05d}"
            
            self.fingerprint_map[fingerprint] = {
                "id": finding_id,
                "fingerprint": fingerprint,
                "secret_type": occurrence_data.get("rule_type", "secret"),
                "rule_id": occurrence_data.get("rule_id"),
                "rule_name": occurrence_data.get("rule_name"),
                "title": f"Exposed {occurrence_data.get('rule_name', 'Secret')}",
                "severity": occurrence_data.get("severity", "MEDIUM"),
                "confidence": occurrence_data.get("confidence", 0.8),
                "score": occurrence_data.get("score", 50),
                "risk_reasons": occurrence_data.get("risk_reasons", []),
                "masked_secret": occurrence_data.get("masked_secret", "****"),
                "remediation": occurrence_data.get("remediation", ""),
                "status": "Open",
                "is_currently_present": is_in_head,
                "first_seen": commit_date or occurrence_data.get("detected_at"),
                "last_seen": commit_date or occurrence_data.get("detected_at"),
                "primary_file": file_path,
                "primary_line": occurrence_data.get("line_number", 1),
                "files": [file_path] if file_path else [],
                "commits": [commit_hash] if commit_hash else [],
                "branches": [branch] if branch else [],
                "total_occurrences": 1,
                "context": occurrence_data.get("context", {}),
                "occurrences": [occurrence_data]
            }
        else:
            finding = self.fingerprint_map[fingerprint]
            finding["total_occurrences"] += 1
            
            # If any occurrence is in HEAD, then it is currently present
            if is_in_head:
                finding["is_currently_present"] = True

            # Track unique files
            if file_path and file_path not in finding["files"]:
                finding["files"].append(file_path)

            # Track unique commits
            if commit_hash and commit_hash not in finding["commits"]:
                finding["commits"].append(commit_hash)

            # Track unique branches
            if branch and branch not in finding["branches"]:
                finding["branches"].append(branch)

            # Update dates
            if commit_date:
                if not finding.get("first_seen") or commit_date < finding["first_seen"]:
                    finding["first_seen"] = commit_date
                if not finding.get("last_seen") or commit_date > finding["last_seen"]:
                    finding["last_seen"] = commit_date

            # If this occurrence has higher severity/score, elevate finding
            new_score = occurrence_data.get("score", 0)
            if new_score > finding.get("score", 0):
                finding["score"] = new_score
                finding["severity"] = occurrence_data.get("severity", finding["severity"])
                finding["risk_reasons"] = occurrence_data.get("risk_reasons", finding["risk_reasons"])

            finding["occurrences"].append(occurrence_data)

        return self.fingerprint_map[fingerprint]

    def get_findings(self) -> List[Dict[str, Any]]:
        # Sort by score descending (most severe first)
        return sorted(
            list(self.fingerprint_map.values()),
            key=lambda x: x.get("score", 0),
            reverse=True
        )
