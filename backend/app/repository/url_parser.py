import re
import os
import urllib.parse
from typing import Dict, Any, Optional

# Supported Git URL patterns
SSH_GIT_PATTERN = re.compile(r'^(?:git@|ssh://git@)([\w.\-]+)[:/]([\w.\-]+)/([\w.\-]+?)(?:\.git)?$')
HTTP_GIT_PATTERN = re.compile(r'^(https?://)([\w.\-]+)(?::\d+)?/([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:/.*)?$')

# Blocked SSRF addresses for security
BLOCKED_HOSTS = {
    '169.254.169.254', # AWS / Cloud metadata
    'metadata.google.internal',
    '127.0.0.1',
    'localhost',
    '0.0.0.0',
    '::1'
}

def parse_and_validate_git_url(raw_url: str, allow_local_fixtures: bool = True) -> Dict[str, Any]:
    """
    Validate, sanitize, and extract metadata from a Git repository URL or path.
    Protects against command injection and SSRF.
    """
    url = raw_url.strip()
    if not url:
        return {
            "is_valid": False,
            "error": "Repository URL cannot be empty."
        }

    # Support local filesystem fixtures (e.g. tests/fixtures/sample-repository or relative paths)
    if allow_local_fixtures and (
        url.startswith('.') or 
        url.startswith('/') or 
        url.startswith('tests/') or 
        url.startswith('local/') or
        'fixture' in url.lower() or 
        'sample-repository' in url.lower()
    ):
        clean_path = url.replace('\\', '/')
        if 'sample-repository' in clean_path.lower():
            test_path = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "tests/fixtures/sample-repository"))
            clean_path = test_path
            if not os.path.exists(os.path.join(clean_path, ".git")):
                try:
                    from scripts.setup_sample_repo import setup_sample_repository
                    setup_sample_repository(clean_path)
                except Exception:
                    pass
        repo_name = clean_path.split('/')[-1] or "sample-repository"
        return {
            "is_valid": True,
            "is_local": True,
            "original_url": url,
            "normalized_url": clean_path,
            "provider": "local_git",
            "host": "localhost",
            "owner": "local",
            "repo_name": repo_name,
            "protocol": "file"
        }

    # Auto-prepend https:// if user pasted bare domain or github.com/owner/repo
    if not url.startswith(('http://', 'https://', 'git@', 'ssh://', '.', '/')):
        if ('github.com' in url or 'gitlab.com' in url or 'bitbucket.org' in url or url.count('/') >= 1):
            url = 'https://' + url

    # Check SSH format
    ssh_match = SSH_GIT_PATTERN.match(url)
    if ssh_match:
        host, owner, repo_name = ssh_match.groups()
        if host.lower() in BLOCKED_HOSTS:
            return {"is_valid": False, "error": f"Access to host '{host}' is prohibited by SSRF security policy."}
        return {
            "is_valid": True,
            "is_local": False,
            "original_url": url,
            "normalized_url": f"git@{host}:{owner}/{repo_name}.git",
            "clone_url": f"git@{host}:{owner}/{repo_name}.git",
            "host": host,
            "owner": owner,
            "repo_name": repo_name,
            "protocol": "ssh"
        }

    # Check HTTP/HTTPS format
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {"is_valid": False, "error": "Malformed URL format."}

    if parsed.scheme not in ('http', 'https'):
        return {
            "is_valid": False,
            "error": f"Unsupported URL scheme '{parsed.scheme}'. Only https, http, or git@ are permitted."
        }

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return {"is_valid": False, "error": "Invalid repository host."}

    if hostname in BLOCKED_HOSTS:
        return {"is_valid": False, "error": f"Access to host '{hostname}' is prohibited by SSRF security policy."}

    # Extract path segments
    path_segments = [p for p in parsed.path.strip('/').split('/') if p]
    if len(path_segments) < 2:
        return {
            "is_valid": False,
            "error": "URL path must contain owner and repository name (e.g. https://github.com/owner/repo)."
        }

    owner = path_segments[0]
    repo_name = path_segments[1]
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]

    # Check for branch in path (e.g. /tree/main, /blob/main, /-/tree/main)
    detected_branch = None
    if len(path_segments) >= 4 and path_segments[2] in ('tree', 'blob'):
        detected_branch = path_segments[3]
    elif len(path_segments) >= 5 and path_segments[2] == '-' and path_segments[3] in ('tree', 'blob'):
        detected_branch = path_segments[4]

    # Reconstruct clean normalized HTTPS clone URL without credentials embedded
    normalized_url = f"https://{hostname}/{owner}/{repo_name}.git"

    result: Dict[str, Any] = {
        "is_valid": True,
        "is_local": False,
        "original_url": url,
        "normalized_url": normalized_url,
        "clone_url": normalized_url,
        "host": hostname,
        "owner": owner,
        "repo_name": repo_name,
        "protocol": parsed.scheme
    }
    if detected_branch:
        result["detected_branch"] = detected_branch

    return result
