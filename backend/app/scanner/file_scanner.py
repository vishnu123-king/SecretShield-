import os
from typing import List, Dict, Any, Optional

from .pattern_detector import PatternDetector
from .entropy_detector import analyze_entropy
from .context_analyzer import analyze_context, classify_file
from .secret_fingerprint import compute_fingerprint, mask_secret
from .scorer import calculate_risk_score
from .suppression import SuppressionManager
from .binary_detector import is_binary_file

class FileScanner:
    def __init__(
        self,
        pattern_detector: Optional[PatternDetector] = None,
        suppression_manager: Optional[SuppressionManager] = None,
        max_file_size_bytes: int = 5 * 1024 * 1024
    ):
        self.pattern_detector = pattern_detector or PatternDetector()
        self.suppression_manager = suppression_manager or SuppressionManager()
        self.max_file_size_bytes = max_file_size_bytes

    def scan_content(
        self,
        content: str,
        file_path: str,
        commit_hash: Optional[str] = None,
        commit_date: Optional[str] = None,
        branch: Optional[str] = None,
        is_in_head: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Scan in-memory string content line-by-line.
        """
        lines = content.splitlines()
        occurrences = []

        file_info = classify_file(file_path)

        for line_idx, line in enumerate(lines):
            # Optimization: Skip extremely long minified lines (> 2000 chars)
            if len(line) > 2000:
                continue

            matches = self.pattern_detector.match_line(line)
            for match in matches:
                candidate = match["matched_candidate"]
                fingerprint = compute_fingerprint(candidate)

                # Check if suppressed
                rule_id = match["rule_id"]
                is_sup, sup_reason = self.suppression_manager.is_suppressed(
                    finding_id="",
                    fingerprint=fingerprint,
                    file_path=file_path,
                    rule_id=rule_id
                )
                if is_sup:
                    continue

                # Entropy analysis
                entropy_high, entropy_val, entropy_reason = analyze_entropy(candidate)

                # Context analysis (+/- 10 lines)
                ctx = analyze_context(lines, line_idx, file_path)

                # Risk scoring
                score_data = calculate_risk_score(
                    rule_type=match["rule_type"],
                    base_confidence=match["base_confidence"],
                    entropy_high=entropy_high,
                    entropy_value=entropy_val,
                    is_sensitive_file=file_info["is_sensitive"],
                    is_test_or_example=file_info["is_test_or_example"],
                    is_placeholder=ctx["is_placeholder"],
                    is_commented=ctx["is_commented"],
                    is_production_signal=ctx["is_production_signal"],
                    is_in_git_history=(commit_hash is not None and not is_in_head),
                    is_currently_present=is_in_head
                )

                masked = mask_secret(candidate)

                occurrences.append({
                    "fingerprint": fingerprint,
                    "masked_secret": masked,
                    "rule_id": rule_id,
                    "rule_name": match["rule_name"],
                    "rule_type": match["rule_type"],
                    "file_path": file_path,
                    "line_number": line_idx + 1,
                    "line_content": line.strip(),
                    "score": score_data["score"],
                    "severity": score_data["severity"],
                    "confidence": match["base_confidence"],
                    "risk_reasons": score_data["reasons"],
                    "remediation": match["remediation"],
                    "context": ctx,
                    "commit_hash": commit_hash,
                    "commit_date": commit_date,
                    "branch": branch,
                    "is_in_head": is_in_head,
                    "entropy": entropy_val
                })

        return occurrences

    def scan_file(
        self,
        absolute_file_path: str,
        relative_file_path: str,
        commit_hash: Optional[str] = None,
        commit_date: Optional[str] = None,
        branch: Optional[str] = None,
        is_in_head: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Scan a physical file on disk.
        """
        if not os.path.exists(absolute_file_path) or not os.path.isfile(absolute_file_path):
            return []

        # Size check
        try:
            if os.path.getsize(absolute_file_path) > self.max_file_size_bytes:
                return []
        except Exception:
            return []

        # Binary check
        if is_binary_file(absolute_file_path):
            return []

        try:
            with open(absolute_file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return self.scan_content(
                content=content,
                file_path=relative_file_path,
                commit_hash=commit_hash,
                commit_date=commit_date,
                branch=branch,
                is_in_head=is_in_head
            )
        except Exception:
            return []
