#!/usr/bin/env python3
"""
Unit and Integration Tests for OSINTALL Zero-False-Alarm Validation Engine
Verifies that all false positive vectors are successfully suppressed.
"""

import unittest
from unittest.mock import MagicMock
import requests
from modules.validation_engine import (
    calculate_shannon_entropy,
    is_authentic_secret_token,
    is_waf_or_anti_bot_response,
    verify_username_finding,
    TAKEOVER_FINGERPRINTS,
    verify_subdomain_takeover,
    validate_cloud_provider_response,
    check_shared_infrastructure_risk
)


class TestValidationEngine(unittest.TestCase):

    # ------------------------------------------------------------------------
    # 1. SHANNON ENTROPY & SECRET TOKEN MITIGATION
    # ------------------------------------------------------------------------

    def test_shannon_entropy_calculation(self):
        """Test entropy mathematics on uniform vs random strings."""
        # Repetitive single character has 0 entropy
        self.assertEqual(calculate_shannon_entropy("AAAAAAAAAA"), 0.0)
        # Low entropy pattern
        low_ent = calculate_shannon_entropy("ABABABABAB")
        self.assertLess(low_ent, 1.5)
        # Real high-entropy cryptographic token
        high_ent = calculate_shannon_entropy("4f8a3b2c1e9d0fa7b6c5d4e3f2a10b9c")
        self.assertGreater(high_ent, 3.2)

    def test_aws_example_key_rejection(self):
        """Standard AWS documentation example keys must be rejected as false alarms."""
        is_auth, reason = is_authentic_secret_token("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE")
        self.assertFalse(is_auth)
        self.assertIn("example", reason.lower())

    def test_dummy_and_mock_token_rejection(self):
        """Tokens containing dummy placeholders must be suppressed."""
        dummies = [
            ("Generic High-Entropy", "YOUR_API_KEY_HERE_1234567"),
            ("Stripe Live Secret Key", "sk_test_51MzXYZ1234567890"),
            ("GitHub Personal Access Token", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            ("Generic High-Entropy", "abcdef1234567890abcdef1234"),
            ("Generic High-Entropy", "11111111111111111111111111")
        ]
        for rule, token in dummies:
            is_auth, reason = is_authentic_secret_token(rule, token)
            self.assertFalse(is_auth, f"Failed to suppress false alarm for token: {token} ({reason})")

    def test_authentic_secret_token_acceptance(self):
        """Real-world high-entropy token candidates must be accepted as authentic."""
        authentic_keys = [
            ("AWS Access Key ID", "AKIAZ9X8P3L2Q4M7R5T1"),
            ("Google Cloud API Key", "AIzaSyDa9f8e7d6c5b4a3_210zyxwvutsrqpoNM"),
            ("Generic High-Entropy Secret Assignment", "c8f1e2d3b4a5960718293a4b5c6d7e8f")
        ]
        for rule, token in authentic_keys:
            is_auth, reason = is_authentic_secret_token(rule, token)
            self.assertTrue(is_auth, f"Unexpectedly rejected valid token: {token} ({reason})")

    # ------------------------------------------------------------------------
    # 2. ANTI-BOT & WAF CHALLENGE SUPPRESSION
    # ------------------------------------------------------------------------

    def test_waf_challenge_detection(self):
        """Cloudflare / Turnstile / Datadome challenge pages must be detected as WAF blocks."""
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 403
        mock_resp.headers = {"Server": "cloudflare", "cf-ray": "123456789abcdef"}
        mock_resp.text = "<html><head><title>Just a moment...</title></head><body><div class='cf-browser-verification'></div></body></html>"

        is_waf, waf_name = is_waf_or_anti_bot_response(mock_resp)
        self.assertTrue(is_waf)
        self.assertIn("Cloudflare", waf_name)

    # ------------------------------------------------------------------------
    # 3. SOCMINT USERNAME SOFT-404 CANARY MITIGATION
    # ------------------------------------------------------------------------

    def test_soft_404_suppression(self):
        """When platform returns 200 on soft-404, matching canary template must be suppressed."""
        platform = {"name": "TestPlatform", "url": "https://example.com/{}", "check": "status_code", "valid": 200}
        username = "johndoe"

        # Target response returns 200 with soft-404 page
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com/johndoe"
        mock_resp.text = "<html><body>Generic Not Found Page</body></html>"

        # Canary profile recorded soft-404 with identical length
        canary_profile = {
            "platform": "TestPlatform",
            "is_soft_404": True,
            "canary_content_len": len(mock_resp.text),
            "reliable": False
        }

        exists, reason = verify_username_finding(platform, username, mock_resp, canary_profile)
        self.assertFalse(exists)
        self.assertIn("Soft-404", reason)

    def test_login_redirect_suppression(self):
        """Redirecting to home or login page must be suppressed as false positive."""
        platform = {"name": "TestPlatform", "url": "https://example.com/{}", "check": "status_code", "valid": 200}
        username = "targetuser"

        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com/login?redirect=/targetuser"
        mock_resp.text = "<html><body>Please Sign In to View Profile</body></html>"

        canary_profile = {"is_soft_404": False, "reliable": True}
        exists, reason = verify_username_finding(platform, username, mock_resp, canary_profile)
        self.assertFalse(exists)
        self.assertIn("Redirected to auth", reason)

    # ------------------------------------------------------------------------
    # 4. SUBDOMAIN TAKEOVER FINGERPRINT PROOF
    # ------------------------------------------------------------------------

    def test_takeover_fingerprint_verification(self):
        """Takeover alerts must only trigger if provider claim signature is returned."""
        session = MagicMock(spec=requests.Session)
        
        # Test 1: Active claimable GitHub Pages
        mock_resp_vulnerable = MagicMock(spec=requests.Response)
        mock_resp_vulnerable.text = "There isn't a GitHub Pages site here."
        mock_resp_vulnerable.status_code = 404
        session.get.return_value = mock_resp_vulnerable

        is_takeable, reason = verify_subdomain_takeover("GitHub Pages", "test.example.com", session)
        self.assertTrue(is_takeable)
        self.assertIn("CONFIRMED TAKEOVER", reason)

        # Test 2: Benign existing website or custom 404 without provider signature
        mock_resp_safe = MagicMock(spec=requests.Response)
        mock_resp_safe.text = "<html><body>Welcome to My Corporate Blog</body></html>"
        mock_resp_safe.status_code = 200
        session.get.return_value = mock_resp_safe

        is_takeable, reason = verify_subdomain_takeover("GitHub Pages", "blog.example.com", session)
        self.assertFalse(is_takeable)
        self.assertIn("signature was not returned", reason)

    # ------------------------------------------------------------------------
    # 5. CLOUD STORAGE PROVIDER HEADER VALIDATION
    # ------------------------------------------------------------------------

    def test_aws_s3_genuine_header_validation(self):
        """Genuine AWS S3 responses must pass, while fake proxies are rejected."""
        # Genuine S3 response
        genuine_s3 = MagicMock(spec=requests.Response)
        genuine_s3.headers = {"x-amz-request-id": "ABC123XYZ", "Server": "AmazonS3"}
        genuine_s3.text = "<ListBucketResult></ListBucketResult>"

        is_genuine, reason = validate_cloud_provider_response("AWS S3", genuine_s3)
        self.assertTrue(is_genuine)

        # Interception proxy / captive portal returning 200 without S3 headers
        proxy_resp = MagicMock(spec=requests.Response)
        proxy_resp.headers = {"Server": "nginx", "Content-Type": "text/html"}
        proxy_resp.text = "<html><body>Company Wi-Fi Login Portal</body></html>"

        is_genuine, reason = validate_cloud_provider_response("AWS S3", proxy_resp)
        self.assertFalse(is_genuine)
        self.assertIn("Filtered out", reason)

    def test_gcp_and_azure_provider_validation(self):
        """Validate GCP and Azure genuine signatures and reject fake portals."""
        genuine_gcp = MagicMock(spec=requests.Response)
        genuine_gcp.headers = {"x-goog-generation": "123456", "Server": "UploadServer"}
        genuine_gcp.text = ""
        is_genuine, _ = validate_cloud_provider_response("Google Cloud Storage", genuine_gcp)
        self.assertTrue(is_genuine)

        genuine_azure = MagicMock(spec=requests.Response)
        genuine_azure.headers = {"x-ms-request-id": "azure-req-123", "Server": "Windows-Azure-Blob/1.0"}
        genuine_azure.text = ""
        is_genuine, _ = validate_cloud_provider_response("Azure Blob", genuine_azure)
        self.assertTrue(is_genuine)

    def test_wildcard_dns_detection_simulation(self):
        """Wildcard DNS detector must identify intersecting canary IPs."""
        from modules.validation_engine import detect_wildcard_dns
        resolver = MagicMock()
        # Mock answers for two random canaries resolving to the same wildcard parking IP
        rdata = MagicMock()
        rdata.__str__.return_value = "192.0.2.1"
        resolver.resolve.return_value = [rdata]

        wildcards = detect_wildcard_dns("wildcard-example.com", resolver)
        self.assertIn("192.0.2.1", wildcards)

    # ------------------------------------------------------------------------
    # 6. SHARED CDN INFRASTRUCTURE DEMARCATION
    # ------------------------------------------------------------------------

    def test_shared_cdn_demarcation(self):
        """Shared Cloudflare or CloudFront IPs must be demarcated from dedicated hosts."""
        is_shared, reason = check_shared_infrastructure_risk("104.21.45.10", "Cloudflare, Inc.")
        self.assertTrue(is_shared)
        self.assertIn("Cloudflare", reason)

        is_shared_direct, reason_direct = check_shared_infrastructure_risk("198.51.100.5", "Internal Dedicated Corp")
        self.assertFalse(is_shared_direct)


if __name__ == "__main__":
    unittest.main()
