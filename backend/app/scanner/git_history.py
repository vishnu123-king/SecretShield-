import os
import subprocess
import re
from typing import List, Dict, Any, Optional, Tuple
from .file_scanner import FileScanner

class GitScanner:
    def __init__(self, file_scanner: FileScanner, timeout_seconds: int = 45):
        self.file_scanner = file_scanner
        self.timeout_seconds = timeout_seconds

    def _run_git(self, repo_path: str, args: List[str]) -> Tuple[int, str, str]:
        """
        Execute git commands safely using argument lists and timeouts.
        Never invokes shell=True or executes repository scripts.
        """
        try:
            cmd = ["git"] + args
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=self.timeout_seconds,
                shell=False
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Git command timed out"
        except Exception as e:
            return -1, "", str(e)

    def is_git_repository(self, path: str) -> bool:
        if not os.path.exists(path) or not os.path.isdir(path):
            return False
        git_dir = os.path.join(path, ".git")
        if os.path.exists(git_dir):
            return True
        code, out, _ = self._run_git(path, ["rev-parse", "--is-inside-work-tree"])
        return code == 0 and out.strip() == "true"

    def get_branches(self, repo_path: str) -> List[str]:
        code, out, _ = self._run_git(repo_path, ["branch", "-a"])
        if code != 0:
            return ["main"]
        branches = []
        for line in out.splitlines():
            clean = line.strip().lstrip('* ').strip()
            if clean and "->" not in clean:
                branches.append(clean)
        return branches or ["main"]

    def get_tags(self, repo_path: str) -> List[str]:
        code, out, _ = self._run_git(repo_path, ["tag", "-l"])
        if code != 0:
            return []
        return [t.strip() for t in out.splitlines() if t.strip()]

    def scan_working_tree(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan files currently present on the filesystem in the working tree.
        """
        occurrences = []
        # Get list of tracked files if git, otherwise walk directory
        tracked_files = set()
        if self.is_git_repository(repo_path):
            code, out, _ = self._run_git(repo_path, ["ls-files"])
            if code == 0:
                tracked_files = {line.strip() for line in out.splitlines() if line.strip()}

        # Walk directory respecting common ignores (.git, node_modules, dist, .venv)
        ignored_dirs = {'.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__', '.tox'}

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file_name in files:
                abs_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(abs_path, repo_path).replace('\\', '/')

                file_occs = self.file_scanner.scan_file(
                    absolute_file_path=abs_path,
                    relative_file_path=rel_path,
                    commit_hash=None,
                    commit_date=None,
                    branch="working_tree",
                    is_in_head=True
                )
                occurrences.extend(file_occs)

        return occurrences

    def scan_history(
        self,
        repo_path: str,
        max_commits: int = 150,
        branch: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan Git commit history using `git log -p` to detect historical secrets
        even if they were removed in subsequent commits!
        """
        if not self.is_git_repository(repo_path):
            return []

        args = ["log", "-p", f"-n{max_commits}", "--date=iso-strict"]
        if branch:
            args.append(branch)
        else:
            args.append("--all")

        code, out, err = self._run_git(repo_path, args)
        if code != 0 or not out:
            return []

        occurrences = []
        current_commit = None
        current_author = None
        current_date = None
        current_file = None

        diff_buffer: List[str] = []
        diff_lines_meta: List[Tuple[int, str]] = [] # (line_number_in_diff, line_str)

        commit_re = re.compile(r'^commit ([0-9a-fA-F]{7,40})')
        author_re = re.compile(r'^Author:\s+(.+)')
        date_re = re.compile(r'^Date:\s+(.+)')
        diff_file_re = re.compile(r'^\+\+\+ b/(.+)')

        def flush_file_diff():
            nonlocal diff_buffer, diff_lines_meta, current_file, current_commit, current_date
            if not current_file or not diff_lines_meta:
                diff_buffer = []
                diff_lines_meta = []
                return

            full_text = "\n".join(diff_buffer)
            # Scan the added diff content
            occs = self.file_scanner.scan_content(
                content=full_text,
                file_path=current_file,
                commit_hash=current_commit,
                commit_date=current_date,
                branch=branch or "all_branches",
                is_in_head=False # Marked as historical
            )
            occurrences.extend(occs)
            diff_buffer = []
            diff_lines_meta = []

        for raw_line in out.splitlines():
            c_match = commit_re.match(raw_line)
            if c_match:
                flush_file_diff()
                current_commit = c_match.group(1)[:10]
                current_file = None
                continue

            a_match = author_re.match(raw_line)
            if a_match:
                current_author = a_match.group(1).strip()
                continue

            d_match = date_re.match(raw_line)
            if d_match:
                current_date = d_match.group(1).strip()
                continue

            f_match = diff_file_re.match(raw_line)
            if f_match:
                flush_file_diff()
                current_file = f_match.group(1).strip()
                continue

            # In unified diff, added lines start with '+', excluding '+++'
            if raw_line.startswith('+') and not raw_line.startswith('+++'):
                added_content = raw_line[1:]
                diff_buffer.append(added_content)
                diff_lines_meta.append((len(diff_buffer), added_content))

        flush_file_diff()
        return occurrences

    def scan_staged_changes(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan git staged changes (index vs HEAD). Used for pre-commit hook scanning.
        """
        if not self.is_git_repository(repo_path):
            return []

        code, out, _ = self._run_git(repo_path, ["diff", "--cached", "-U3"])
        if code != 0 or not out:
            return []

        occurrences = []
        current_file = None
        buffer_lines = []

        diff_file_re = re.compile(r'^\+\+\+ b/(.+)')

        def flush():
            nonlocal buffer_lines, current_file
            if current_file and buffer_lines:
                occs = self.file_scanner.scan_content(
                    content="\n".join(buffer_lines),
                    file_path=current_file,
                    commit_hash="STAGED",
                    commit_date="Pending Commit",
                    branch="staged",
                    is_in_head=True
                )
                occurrences.extend(occs)
            buffer_lines = []

        for raw_line in out.splitlines():
            f_match = diff_file_re.match(raw_line)
            if f_match:
                flush()
                current_file = f_match.group(1).strip()
                continue
            if raw_line.startswith('+') and not raw_line.startswith('+++'):
                buffer_lines.append(raw_line[1:])

        flush()
        return occurrences
