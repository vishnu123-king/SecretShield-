from typing import Dict, Any

class GitProviderDetector:
    """
    Detects and classifies Git hosting providers from repository URLs and hostnames.
    """
    
    @staticmethod
    def detect_provider(host: str, url: str = "") -> Dict[str, Any]:
        h = host.lower()
        u = url.lower()

        if "github.com" in h:
            return {
                "id": "github",
                "name": "GitHub",
                "badge_color": "cyan",
                "icon": "github",
                "is_public_api_available": True,
                "api_endpoint": "https://api.github.com",
                "docs_url": "https://docs.github.com"
            }
        elif "gitlab" in h:
            return {
                "id": "gitlab",
                "name": "GitLab",
                "badge_color": "amber",
                "icon": "gitlab",
                "is_public_api_available": True,
                "api_endpoint": f"https://{h}/api/v4",
                "docs_url": "https://docs.gitlab.com"
            }
        elif "codeberg.org" in h or "forgejo" in h or "forgejo" in u:
            return {
                "id": "forgejo",
                "name": "Forgejo",
                "badge_color": "emerald",
                "icon": "git-pull-request",
                "is_public_api_available": True,
                "api_endpoint": f"https://{h}/api/v1",
                "docs_url": "https://forgejo.org"
            }
        elif "gitea" in h or "gitea" in u:
            return {
                "id": "gitea",
                "name": "Gitea",
                "badge_color": "teal",
                "icon": "git-merge",
                "is_public_api_available": True,
                "api_endpoint": f"https://{h}/api/v1",
                "docs_url": "https://gitea.io"
            }
        elif "bitbucket.org" in h or "bitbucket" in h:
            return {
                "id": "bitbucket",
                "name": "Bitbucket",
                "badge_color": "blue",
                "icon": "git-branch",
                "is_public_api_available": True,
                "api_endpoint": "https://api.bitbucket.org/2.0",
                "docs_url": "https://bitbucket.org"
            }
        elif h == "localhost" or "local" in h or u.startswith('.') or u.startswith('/'):
            return {
                "id": "local_git",
                "name": "Local Filesystem Git",
                "badge_color": "purple",
                "icon": "folder-git",
                "is_public_api_available": False,
                "api_endpoint": None,
                "docs_url": None
            }
        else:
            return {
                "id": "generic_git",
                "name": "Self-Hosted / Generic Git",
                "badge_color": "slate",
                "icon": "git-commit",
                "is_public_api_available": False,
                "api_endpoint": None,
                "docs_url": None
            }
