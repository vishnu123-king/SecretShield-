#!/usr/bin/env python3
import os
import subprocess
import shutil

FIXTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "sample-repository"))

def run_git(args, cwd):
    subprocess.run(["git"] + args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def setup_sample_repository(target_dir=None):
    dest = target_dir or FIXTURE_DIR
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)

    # Initialize git repo
    run_git(["init", "-b", "main"], cwd=dest)
    run_git(["config", "user.name", "Security Engineer"], cwd=dest)
    run_git(["config", "user.email", "devsecops@secretshield.local"], cwd=dest)

    # ----------------- Commit 1: Initial commit with exposed AWS Key and Database URL -----------------
    config_py = os.path.join(dest, "config.py")
    with open(config_py, "w") as f:
        f.write('''# Cloud Application Configuration
import os

# Database configuration
DATABASE_URL = "postgres://appuser:SuperSecretDbPass999@db.prod.internal:5432/payments_db"

# AWS Configuration - ACCIDENTALLY COMMITTED LIVE CREDENTIALS!
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"

# Application settings
APP_ENV = "production"
DEBUG = False
''')

    env_prod = os.path.join(dest, ".env.production")
    with open(env_prod, "w") as f:
        f.write('''APP_NAME=payments-gateway
STRIPE_SECRET_KEY=STRIPE_SECRET_PLACEHOLDER
SLACK_WEBHOOK_BOT=SLACK_TOKEN_PLACEHOLDER
''')

    run_git(["add", "."], cwd=dest)
    run_git(["commit", "-m", "feat: initial payment service setup with db and aws config"], cwd=dest)

    # ----------------- Commit 2: "Fix" by removing AWS key from config.py -----------------
    with open(config_py, "w") as f:
        f.write('''# Cloud Application Configuration
import os

# Database configuration (using env vars)
DATABASE_URL = os.getenv("DATABASE_URL")

# AWS Configuration (moved to env vars)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

APP_ENV = "production"
DEBUG = False
''')

    # Also remove .env.production
    if os.path.exists(env_prod):
        os.remove(env_prod)

    run_git(["add", "."], cwd=dest)
    run_git(["commit", "-m", "fix(security): remove hardcoded aws credentials from config"], cwd=dest)

    # ----------------- Commit 3: Add new feature, test files, and a placeholder -----------------
    tests_dir = os.path.join(dest, "tests")
    os.makedirs(tests_dir, exist_ok=True)
    test_auth_py = os.path.join(tests_dir, "test_auth.py")
    with open(test_auth_py, "w") as f:
        f.write('''# Test authentication mock
def test_mock_auth():
    # Placeholder key used in automated test mock
    dummy_key = "dummy_api_key_for_testing_only"
    fake_token = "ghp_FakeTokenForUnitTestingPurposesOnly00"
    assert dummy_key.startswith("dummy")
''')

    # Add active token in a new services/github_sync.py
    services_dir = os.path.join(dest, "services")
    os.makedirs(services_dir, exist_ok=True)
    gh_sync = os.path.join(services_dir, "github_sync.py")
    with open(gh_sync, "w") as f:
        f.write('''import requests

# Live GitHub PAT active in current HEAD!
GITHUB_TOKEN = "ghp_111122223333444455556666777788889999"

def sync_repos():
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    return requests.get("https://api.github.com/user/repos", headers=headers)
''')

    run_git(["add", "."], cwd=dest)
    run_git(["commit", "-m", "feat: implement github repository sync service and test mocks"], cwd=dest)

    print(f"âœ“ Sample Git repository successfully created at: {dest}")


if __name__ == "__main__":
    setup_sample_repository()


