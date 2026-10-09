#!/usr/bin/env python3
import sys
import os
import json

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.app.repository.url_parser import parse_and_validate_git_url
from backend.app.repository.provider_detector import GitProviderDetector

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"is_valid": False, "error": "No URL provided."}))
        sys.exit(1)

    raw_url = sys.argv[1]
    parsed = parse_and_validate_git_url(raw_url, allow_local_fixtures=True)
    if not parsed.get("is_valid"):
        print(json.dumps(parsed))
        sys.exit(0)

    provider_info = GitProviderDetector.detect_provider(
        parsed.get("host", ""),
        parsed.get("clone_url", parsed.get("normalized_url", ""))
    )
    parsed["provider_info"] = provider_info
    print(json.dumps(parsed))

if __name__ == "__main__":
    main()
