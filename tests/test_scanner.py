import unittest
import os
import sys

# Ensure backend and cli are in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.scanner.entropy_detector import calculate_shannon_entropy, analyze_entropy
from backend.app.scanner.secret_fingerprint import compute_fingerprint, mask_secret
from backend.app.scanner.context_analyzer import analyze_context, classify_file
from backend.app.scanner.scorer import calculate_risk_score
from backend.app.scanner.pattern_detector import PatternDetector
from backend.app.scanner.suppression import SuppressionManager
from backend.app.scanner.deduplicator import FindingDeduplicator
from backend.app.scanner.engine import SecretShieldEngine

class TestEntropyDetector(unittest.TestCase):
    def test_shannon_entropy_calculation(self):
        # Monotonous string has zero entropy
        self.assertEqual(calculate_shannon_entropy("aaaaaa"), 0.0)
        # Random alphanumeric string has high entropy (> 3.5)
        high_rand = "x9K7mP2qL5vR8wT1zN4b"
        entropy = calculate_shannon_entropy(high_rand)
        self.assertGreater(entropy, 3.8)

    def test_analyze_entropy_uuid_filtered(self):
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        is_high, score, msg = analyze_entropy(uuid_str)
        self.assertFalse(is_high)
        self.assertIn("UUID", msg)

    def test_analyze_entropy_high_token(self):
        token = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
        is_high, score, msg = analyze_entropy(token)
        self.assertTrue(is_high)
        self.assertGreaterEqual(score, 4.0)

class TestSecretFingerprint(unittest.TestCase):
    def test_fingerprint_deterministic(self):
        secret1 = "AKIAIOSFODNN7EXAMPLE"
        secret2 = "  'AKIAIOSFODNN7EXAMPLE'  "
        self.assertEqual(compute_fingerprint(secret1), compute_fingerprint(secret2))
        self.assertTrue(compute_fingerprint(secret1).startswith("sha256:"))

    def test_mask_secret(self):
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_secret(aws_key)
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith("MPLE"))
        self.assertIn("****", masked)
        self.assertNotIn("FODNN7", masked)

class TestPatternDetector(unittest.TestCase):
    def setUp(self):
        self.detector = PatternDetector()

    def test_detect_aws_access_key(self):
        line = 'export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"'
        matches = self.detector.match_line(line)
        self.assertGreaterEqual(len(matches), 1)
        match = next(m for m in matches if m["rule_id"] == "aws-access-key-id")
        self.assertEqual(match["matched_candidate"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(match["base_severity"], "CRITICAL")

    def test_detect_github_token(self):
        line = 'git_token = "ghp_111122223333444455556666777788889999"'
        matches = self.detector.match_line(line)
        self.assertTrue(any(m["rule_id"] == "github-pat" for m in matches))

    def test_detect_database_url(self):
        line = 'DB="postgres://postgres:SuperSecretPw@10.0.0.5:5432/mydb"'
        matches = self.detector.match_line(line)
        self.assertTrue(any(m["rule_id"] == "database-connection-string" for m in matches))

class TestContextAndScorer(unittest.TestCase):
    def test_placeholder_reduces_score(self):
        lines = [
            "# sample configuration",
            "API_KEY = 'dummy_api_key_placeholder_val'",
            "# end of file"
        ]
        ctx = analyze_context(lines, 1, "config.py")
        self.assertTrue(ctx["is_placeholder"])

        score_res = calculate_risk_score(
            rule_type="generic_secret",
            base_confidence=0.8,
            entropy_high=False,
            entropy_value=2.0,
            is_sensitive_file=True,
            is_test_or_example=False,
            is_placeholder=True,
            is_commented=False,
            is_production_signal=False,
            is_in_git_history=False,
            is_currently_present=True
        )
        self.assertLess(score_res["score"], 40)

class TestSuppression(unittest.TestCase):
    def test_suppress_by_fingerprint(self):
        suppressions = [{
            "fingerprint": "sha256:test12345678",
            "reason": "Test fixture key verified non-sensitive"
        }]
        sm = SuppressionManager(suppressions)
        is_sup, reason = sm.is_suppressed("", "sha256:test12345678", "src/auth.py", "aws-key")
        self.assertTrue(is_sup)

    def test_suppress_by_path(self):
        suppressions = [{
            "rule_id": "generic-secret-assignment",
            "path_pattern": "tests/",
            "reason": "Allow tests to have mock secrets"
        }]
        sm = SuppressionManager(suppressions)
        is_sup, reason = sm.is_suppressed("", "sha256:other", "tests/unit/test_mock.py", "generic-secret-assignment")
        self.assertTrue(is_sup)
        # Should not suppress if outside tests/
        is_sup2, _ = sm.is_suppressed("", "sha256:other", "src/production.py", "generic-secret-assignment")
        self.assertFalse(is_sup2)

import tempfile
from scripts.setup_sample_repo import setup_sample_repository

class TestEngineOnSampleRepo(unittest.TestCase):
    def test_scan_sample_fixture_repo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            setup_sample_repository(temp_dir)
            engine = SecretShieldEngine()
            result = engine.scan_repository(temp_dir, scan_history=True)
            self.assertGreater(result["total_findings"], 0)
            self.assertTrue(result["is_git_repository"])
            self.assertGreater(result["historical_only_count"], 0)
            # Verify no raw secrets in finding outputs
            for f in result["findings"]:
                self.assertIn("****", f["masked_secret"])

if __name__ == "__main__":
    unittest.main()
