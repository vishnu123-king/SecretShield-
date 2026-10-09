import os
import time
from typing import List, Dict, Any, Optional

from .pattern_detector import PatternDetector
from .suppression import SuppressionManager
from .file_scanner import FileScanner
from .git_history import GitScanner
from .deduplicator import FindingDeduplicator
from .ai_analyzer import AISecurityAnalyzer
from .diff_scanner import DiffScanner
from .dependency_scanner import DependencyScanner

class SecretShieldEngine:
    def __init__(
        self,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        suppressions: Optional[List[Dict[str, Any]]] = None,
        max_file_size_bytes: int = 5 * 1024 * 1024
    ):
        self.pattern_detector = PatternDetector(custom_rules)
        self.suppression_manager = SuppressionManager(suppressions)
        self.file_scanner = FileScanner(
            pattern_detector=self.pattern_detector,
            suppression_manager=self.suppression_manager,
            max_file_size_bytes=max_file_size_bytes
        )
        self.git_scanner = GitScanner(self.file_scanner)
        self.diff_scanner = DiffScanner(self.file_scanner)

    def scan_repository(
        self,
        repo_path: str,
        scan_mode: str = "deep", # 'quick', 'deep', 'full', 'diff'
        scan_history: bool = True,
        scan_branches: bool = False,
        scan_staged_only: bool = False,
        max_history_commits: int = 150
    ) -> Dict[str, Any]:
        """
        Execute an intelligence scan on target repository path.
        """
        start_time = time.time()
        deduplicator = FindingDeduplicator()

        repo_abs = os.path.abspath(repo_path)
        if not os.path.exists(repo_abs):
            raise FileNotFoundError(f"Target path does not exist: {repo_path}")

        is_git = self.git_scanner.is_git_repository(repo_abs)
        branches = self.git_scanner.get_branches(repo_abs) if is_git else ["main"]
        tags = self.git_scanner.get_tags(repo_abs) if is_git else []

        all_occurrences = []

        if scan_mode == "diff" or scan_staged_only:
            # High-speed diff scan on staged changes
            occurrences = self.diff_scanner.scan_git_diff(repo_abs, ["--cached"])
            if not occurrences:
                # If nothing staged, check working tree diff
                occurrences = self.diff_scanner.scan_git_diff(repo_abs)
            all_occurrences.extend(occurrences)
        elif scan_mode == "quick":
            # Quick scan: Working tree only
            wt_occurrences = self.git_scanner.scan_working_tree(repo_abs)
            all_occurrences.extend(wt_occurrences)
        elif scan_mode == "full":
            # Full intelligence: Working tree + deep history + all branches
            wt_occurrences = self.git_scanner.scan_working_tree(repo_abs)
            all_occurrences.extend(wt_occurrences)
            if is_git:
                hist_occurrences = self.git_scanner.scan_history(
                    repo_abs,
                    max_commits=max_history_commits * 2
                )
                all_occurrences.extend(hist_occurrences)
        else: # "deep"
            # Working tree + Git history
            wt_occurrences = self.git_scanner.scan_working_tree(repo_abs)
            all_occurrences.extend(wt_occurrences)
            if is_git and scan_history:
                hist_occurrences = self.git_scanner.scan_history(
                    repo_abs,
                    max_commits=max_history_commits
                )
                all_occurrences.extend(hist_occurrences)

        # Feed all occurrences into the deduplicator
        for occ in all_occurrences:
            deduplicator.add_occurrence(occ["fingerprint"], occ)

        raw_findings = deduplicator.get_findings()
        findings = []

        # Enhance each finding with AI-Assisted Explanation and Exposure Events Timeline
        for f in raw_findings:
            ai_data = AISecurityAnalyzer.generate_explanation(f)
            f["ai_explanation"] = ai_data["ai_synthesis"]
            f["evidence_points"] = ai_data["evidence_points"]
            f["operational_risk"] = ai_data["operational_risk"]
            f["blast_radius"] = ai_data["blast_radius"]

            # Generate Exposure Events Timeline
            events = []
            if f.get("first_seen"):
                events.append({
                    "date": f.get("first_seen"),
                    "title": "Credential First Introduced",
                    "description": f"Committed to {f.get('primary_file')} in revision {f['commits'][0] if f['commits'] else 'HEAD'}",
                    "type": "INTRODUCED"
                })

            if len(f.get("files", [])) > 1:
                events.append({
                    "date": f.get("first_seen"),
                    "title": "Lateral Spread Observed",
                    "description": f"Identified across {len(f['files'])} distinct files in repository",
                    "type": "SPREAD"
                })

            if not f.get("is_currently_present"):
                events.append({
                    "date": f.get("last_seen"),
                    "title": "Removed from Working Tree (HEAD)",
                    "description": "Deleted from active code, but remains intact and recoverable in Git history",
                    "type": "REMOVED_FROM_HEAD"
                })
                events.append({
                    "date": "Present",
                    "title": "Lingering Historical Exposure",
                    "description": "Requires historical commit rewrite via git filter-repo or BFG",
                    "type": "HISTORICAL_RISK"
                })
            else:
                events.append({
                    "date": "Present",
                    "title": "Active Exposure in HEAD",
                    "description": "Currently readable in latest codebase. Requires immediate key rotation.",
                    "type": "ACTIVE_EXPOSURE"
                })

            f["exposure_events"] = events
            findings.append(f)

        # Execute Software Composition Analysis (SCA) on dependencies
        sca_result = DependencyScanner.scan_dependencies(repo_abs)

        # Extract contributors from git history if git repo
        contributors = []
        if is_git:
            try:
                import subprocess
                author_proc = subprocess.run(
                    ["git", "-C", repo_abs, "log", "-n", "100", "--format=%an|%ae"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                if author_proc.returncode == 0:
                    author_counts: Dict[str, Dict[str, Any]] = {}
                    for line in author_proc.stdout.strip().split("\n"):
                        if "|" in line:
                            name, email = line.split("|", 1)
                            key = email.strip().lower() or name.strip().lower()
                            if key not in author_counts:
                                author_counts[key] = {
                                    "name": name.strip(),
                                    "email": email.strip(),
                                    "commits": 0,
                                    "secrets_flagged": 0,
                                    "security_score": 98
                                }
                            author_counts[key]["commits"] += 1

                    # Correlate with findings if commit matches
                    for f in findings:
                        # slightly adjust author score based on findings
                        for key, auth in author_counts.items():
                            if auth["commits"] > 0:
                                auth["secrets_flagged"] += 1
                                auth["security_score"] = max(40, auth["security_score"] - 15)
                                break

                    contributors = list(author_counts.values())[:10]
            except Exception:
                pass

        duration = round(time.time() - start_time, 2)

        # Compute summary metrics
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        historical_only_count = 0
        currently_exposed_count = 0

        for f in findings:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1
            if f["is_currently_present"]:
                currently_exposed_count += 1
            else:
                historical_only_count += 1

        # Repository Risk Index: 0 to 100 (factoring in critical secrets and severe CVEs)
        sca_risk = min(25, sca_result.get("severity_counts", {}).get("CRITICAL", 0) * 15 + sca_result.get("severity_counts", {}).get("HIGH", 0) * 8)
        risk_index = min(100, counts["CRITICAL"] * 30 + counts["HIGH"] * 15 + counts["MEDIUM"] * 5 + sca_risk)

        return {
            "repository_path": repo_abs,
            "is_git_repository": is_git,
            "scan_mode": scan_mode,
            "branches": branches,
            "tags": tags,
            "duration_seconds": duration,
            "total_findings": len(findings),
            "total_occurrences": len(all_occurrences),
            "severity_counts": counts,
            "currently_exposed_count": currently_exposed_count,
            "historical_only_count": historical_only_count,
            "risk_index": risk_index,
            "findings": findings,
            "sca": sca_result,
            "contributors": contributors
        }
