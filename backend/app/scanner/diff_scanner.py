import re
import subprocess
from typing import List, Dict, Any, Optional

DIFF_FILE_HEADER = re.compile(r'^diff --git a/(.*?) b/(.*?)$')
HUNK_HEADER = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')

class DiffScanner:
    """
    High-speed diff scanner for pre-commit, pull requests, and CI/CD gates.
    Inspects ONLY added lines in unified diffs without reading the entire repository.
    """

    def __init__(self, file_scanner):
        self.file_scanner = file_scanner

    def scan_git_diff(self, repo_path: str, diff_args: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        args = ["git", "diff", "--unified=0"]
        if diff_args:
            args.extend(diff_args)

        try:
            res = subprocess.run(
                args,
                cwd=repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            if res.returncode != 0:
                return []
            return self.parse_and_scan_diff(res.stdout, repo_path)
        except Exception:
            return []

    def parse_and_scan_diff(self, diff_text: str, repo_path: str = "") -> List[Dict[str, Any]]:
        occurrences = []
        current_file = None
        current_line_num = 1

        lines = diff_text.splitlines()
        for line in lines:
            file_match = DIFF_FILE_HEADER.match(line)
            if file_match:
                current_file = file_match.group(2)
                continue

            hunk_match = HUNK_HEADER.match(line)
            if hunk_match:
                current_line_num = int(hunk_match.group(1))
                continue

            # Only analyze added lines
            if line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                if current_file:
                    file_class = self.file_scanner.classify_file(current_file)
                    hits = self.file_scanner.scan_content(
                        content=added_content,
                        file_path=current_file,
                        file_classification=file_class,
                        commit_hash="WORKING_DIFF",
                        commit_date="Pending",
                        branch="staged_diff",
                        is_in_head=True
                    )
                    for hit in hits:
                        hit["line_number"] = current_line_num
                        hit["is_diff_match"] = True
                        occurrences.append(hit)
                current_line_num += 1
            elif not line.startswith("-"):
                current_line_num += 1

        return occurrences
