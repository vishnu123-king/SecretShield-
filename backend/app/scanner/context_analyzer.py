import os
import re
from typing import List, Dict, Any, Tuple

# Sensitive file patterns that raise risk
SENSITIVE_FILE_PATTERNS = [
    re.compile(r'(^|/)(\.env(\.[a-zA-Z0-9_\-]+)?)$', re.IGNORECASE),
    re.compile(r'(^|/)(credentials|secrets|keys)(\.json|\.yaml|\.yml)$', re.IGNORECASE),
    re.compile(r'(^|/)(terraform\.tfvars|\.tfvars|\.tfvars\.json)$', re.IGNORECASE),
    re.compile(r'(^|/)(docker-compose(\.[a-zA-Z0-9_\-]+)?\.ya?ml)$', re.IGNORECASE),
    re.compile(r'(^|/)(id_rsa|id_dsa|id_ed25519|\.pem|\.key|\.p12|\.pfx)$', re.IGNORECASE),
    re.compile(r'(^|/)(settings|config|database|auth)(\.py|\.ts|\.js|\.json|\.ya?ml)$', re.IGNORECASE),
]

# Test and example paths that typically reduce risk
TEST_OR_EXAMPLE_PATTERNS = [
    re.compile(r'(^|/)(tests?|spec|testing|fixtures?|mocks?|examples?|samples?|docs?|demo)/', re.IGNORECASE),
    re.compile(r'(\.test\.|\.spec\.|_test\.|_spec\.)', re.IGNORECASE),
]

# Dummy or placeholder markers
PLACEHOLDER_MARKERS = [
    re.compile(r'(\b(dummy|fake|mock|example|sample|placeholder|test_key|your[-_]api[-_]key|<YOUR_.*?>|\*{4,})\b)', re.IGNORECASE),
    re.compile(r'(\b(TODO|FIXME|CHANGEME|REPLACE_ME|INSERT_HERE)\b)', re.IGNORECASE),
]

def classify_file(file_path: str) -> Dict[str, Any]:
    """
    Classify a file based on its path and name.
    """
    normalized_path = file_path.replace('\\', '/')
    base_name = os.path.basename(normalized_path)
    extension = os.path.splitext(base_name)[1].lower()

    is_sensitive = any(pattern.search(normalized_path) for pattern in SENSITIVE_FILE_PATTERNS)
    is_test_or_example = any(pattern.search(normalized_path) for pattern in TEST_OR_EXAMPLE_PATTERNS)

    category = "source_code"
    if is_sensitive:
        category = "sensitive_config"
    elif is_test_or_example:
        category = "test_or_sample"
    elif extension in ('.md', '.txt', '.rst', '.adoc'):
        category = "documentation"
    elif extension in ('.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf'):
        category = "configuration"
    elif extension in ('.tf', '.hcl'):
        category = "infrastructure"
    elif base_name in ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Pipfile.lock', 'bun.lock'):
        category = "lockfile"

    return {
        "file_path": file_path,
        "base_name": base_name,
        "extension": extension,
        "category": category,
        "is_sensitive": is_sensitive,
        "is_test_or_example": is_test_or_example
    }

def analyze_context(lines: List[str], target_line_idx: int, file_path: str) -> Dict[str, Any]:
    """
    Inspect +/- 10 lines of surrounding code and determine context signals.
    """
    total_lines = len(lines)
    start_idx = max(0, target_line_idx - 10)
    end_idx = min(total_lines, target_line_idx + 11)

    snippet_lines = lines[start_idx:end_idx]
    surrounding_text = "\n".join(snippet_lines)

    file_meta = classify_file(file_path)

    # Check for placeholder indicators in surrounding text or target line
    is_placeholder = False
    placeholder_reason = ""
    for marker in PLACEHOLDER_MARKERS:
        match = marker.search(surrounding_text)
        if match:
            is_placeholder = True
            placeholder_reason = f"Contains dummy/placeholder marker: '{match.group(1)}'"
            break

    # Check if target line is commented out
    target_line = lines[target_line_idx] if 0 <= target_line_idx < total_lines else ""
    stripped = target_line.strip()
    is_commented = stripped.startswith(('#', '//', '/*', '*', '--', '<!--', ';'))

    # Check for production signals in surrounding context
    is_production_signal = bool(re.search(r'\b(production|prod|live|release|prod_key|master)\b', surrounding_text, re.IGNORECASE))

    return {
        "context_start_line": start_idx + 1,
        "context_end_line": end_idx,
        "target_line_number": target_line_idx + 1,
        "target_line": target_line,
        "snippet": [
            {
                "line_number": start_idx + i + 1,
                "content": line,
                "is_target": (start_idx + i) == target_line_idx
            }
            for i, line in enumerate(snippet_lines)
        ],
        "file_classification": file_meta,
        "is_placeholder": is_placeholder,
        "placeholder_reason": placeholder_reason,
        "is_commented": is_commented,
        "is_production_signal": is_production_signal
    }
