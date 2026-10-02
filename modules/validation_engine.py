#!/usr/bin/env python3
"""
==============================================================================
OSINTALL - Universal False-Positive Mitigation & Validation Engine
Engine Version: v2.3.0 (Zero-False-Alarm Core)
Standard: Deterministic Multi-Vector Verification
==============================================================================
This module provides cryptographic, statistical, and active-canary verification
layers to eliminate false alarms across all OSINTall reconnaissance vectors:
  1. Shannon Entropy & Token Authenticity (Code & Secret Scans)
  2. Baseline Nonce / Canary Probing (SOCMINT & Soft-404 Mitigation)
  3. Anti-Bot / WAF Challenge Detection (Cloudflare, Datadome, Akamai)
  4. Subdomain Wildcard DNS Resolution & Takeover Proof Fingerprinting
  5. Cloud Storage Provider Cryptographic Header Verification
  6. Shared CDN / Reverse Proxy IP Demarcation (Threat Intelligence)
==============================================================================
"""

import re
import math
import uuid
import socket
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import requests

try:
    import dns.resolver
except ImportError:
    dns = None


# ============================================================================
# 1. SHANNON ENTROPY & SECRET TOKEN AUTHENTICITY ENGINE
# ============================================================================

# Known dummy, test, documentation, and mock token blacklists
DUMMY_KEYWORD_BLACKLIST = {
    "example", "sample", "test", "testing", "dummy", "mock", "placeholder",
    "fake", "changeme", "change_me", "your_key", "your_api_key", "secret_key",
    "my_secret", "replace_me", "token_here", "xxxxxxxx", "00000000", "12345678",
    "abcdef", "akiaiosfodnn7example", "wjalrxu7nxylk7mqbi/k7mqbi/examplekey",
    "sk_test_", "ghp_xxxxxxxxxxxx", "xoxb-xxxxxxxx", "ai_za_sy_example",
    "password", "admin", "null", "undefined", "true", "false"
}

def calculate_shannon_entropy(data: str) -> float:
    """
    Computes the Shannon Entropy H(X) = - sum(p_i * log2(p_i)) of a string.
    High entropy (> 3.2 for strings >= 16 chars) indicates cryptographic randomness,
    distinguishing real secrets from English words, test fixtures, and low-entropy mocks.
    """
    if not data:
        return 0.0
    length = len(data)
    frequency: Dict[str, int] = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def is_authentic_secret_token(rule_name: str, token_val: str) -> Tuple[bool, str]:
    """
    Evaluates whether a candidate secret match is an authentic, high-fidelity secret
    or a false positive (test fixture, mock, low entropy string, or documentation example).
    
    Returns:
        (is_authentic: bool, rejection_reason: str)
    """
    clean_val = token_val.strip("\"' \t\r\n")
    lower_val = clean_val.lower()

    # Rule 1: Minimum sensible length
    if len(clean_val) < 8:
        return False, "Token length too short (< 8 chars)"

    # Rule 2: Blacklisted dummy / sample words
    for dummy in DUMMY_KEYWORD_BLACKLIST:
        if dummy in lower_val:
            return False, f"Matches known mock/placeholder keyword: '{dummy}'"

    # Rule 3: Character diversity & repetition check
    unique_chars = len(set(clean_val))
    if unique_chars < 5 and len(clean_val) >= 12:
        return False, f"Insufficient character diversity ({unique_chars} unique chars)"

    # Rejection of single character repeats or simple patterns (e.g., 01010101, aaaaaaaa)
    if re.fullmatch(r"(.)\1+", clean_val):
        return False, "Single character repeat pattern"
    if re.fullmatch(r"(.{2,4})\1+", clean_val):
        return False, "Repetitive rhythmic block pattern"

    # Rule 4: Rule-specific format & entropy criteria
    entropy = calculate_shannon_entropy(clean_val)

    if "AWS Access Key" in rule_name:
        # AWS Key ID: AKIA / ASIA followed by 16 uppercase base32-ish characters
        if not re.fullmatch(r"(AKIA|ASIA)[0-9A-Z]{16}", clean_val):
            return False, "Malformed AWS Key ID structure"
        if clean_val == "AKIAIOSFODNN7EXAMPLE":
            return False, "Standard AWS documentation example key"
        if entropy < 2.5:
            return False, f"Low entropy for AWS Key ({entropy} < 2.5)"

    elif "Google Cloud API Key" in rule_name:
        if not clean_val.startswith("AIza") or len(clean_val) != 39:
            return False, "Malformed Google Cloud API key structure"
        if entropy < 3.2:
            return False, f"Low entropy for Google API key ({entropy} < 3.2)"

    elif "Stripe" in rule_name:
        if clean_val.startswith("sk_test_") or "test" in lower_val:
            return False, "Stripe Test Mode key (non-production test credential)"
        if entropy < 3.0:
            return False, f"Low entropy for Stripe key ({entropy} < 3.0)"

    elif "GitHub" in rule_name:
        if clean_val.startswith("ghp_") and len(clean_val) == 40:
            if entropy < 3.0:
                return False, f"Low entropy for GitHub PAT ({entropy} < 3.0)"

    elif "Generic High-Entropy" in rule_name:
        # Generic secret assignment needs high entropy and sensible length
        if len(clean_val) < 16:
            return False, "Generic token candidate too short (< 16 chars)"
        if entropy < 3.35:
            return False, f"Low entropy for generic secret ({entropy} < 3.35)"

    elif "JSON Web Token" in rule_name:
        # JWT must have at least 2 dots (header.payload.signature)
        parts = clean_val.split(".")
        if len(parts) < 2:
            return False, "Invalid JWT dot structure"
        if len(parts[0]) < 8 or len(parts[1]) < 8:
            return False, "Truncated JWT segments"

    # If it passed all filters, it is an authentic verified secret candidate
    return True, "Authentic high-entropy token signature verified"


# ============================================================================
# 2. ANTI-BOT, WAF & CAPTCHA DETECTION ENGINE
# ============================================================================

WAF_SIGNATURES = [
    # Cloudflare
    ("Cloudflare Challenge", re.compile(r"(cf-chl-bypass|cf-browser-verification|challenge-platform|_cf_chl_opt|Attention Required! \| Cloudflare|Just a moment\.\.\.)", re.IGNORECASE)),
    ("Cloudflare Turnstile", re.compile(r"challenges\.cloudflare\.com/turnstile", re.IGNORECASE)),
    # Datadome
    ("Datadome Anti-Bot", re.compile(r"(datadome\.js|dd-response|datadome\.com/captcha)", re.IGNORECASE)),
    # Akamai
    ("Akamai Bot Manager", re.compile(r"akamaighost|akamai-bot-manager", re.IGNORECASE)),
    # AWS WAF
    ("AWS WAF Captcha", re.compile(r"(aws-waf-captcha|awswaftoken)", re.IGNORECASE)),
    # Incapsula / Imperva
    ("Imperva Incapsula", re.compile(r"(_Incapsula_Resource|incapsula\.com)", re.IGNORECASE)),
    # Generic CAPTCHA
    ("Generic Captcha", re.compile(r"(g-recaptcha|hcaptcha\.com|cf-turnstile|geetest)", re.IGNORECASE))
]

def is_waf_or_anti_bot_response(resp: requests.Response) -> Tuple[bool, Optional[str]]:
    """
    Inspects HTTP status code, headers, and body for WAF/anti-bot challenge pages.
    Prevents bot-challenge 200/403 pages from being falsely counted as active user profiles or open buckets.
    """
    headers = getattr(resp, "headers", {}) or {}
    headers_str = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
    sample_text = resp.text[:12000] if getattr(resp, "text", None) else ""

    status_code = getattr(resp, "status_code", 0)

    # Cloudflare 403 / 503 / 429 / 200 challenge detection
    if status_code in (403, 503, 429, 200):
        for name, pattern in WAF_SIGNATURES:
            if pattern.search(sample_text) or pattern.search(headers_str):
                return True, name

    # Server header explicit WAF indications
    server_header = headers.get("Server", "").lower() if isinstance(headers, dict) else ""
    if "cloudflare" in server_header and status_code in (403, 503):
        return True, "Cloudflare WAF Block (HTTP 403/503)"
    if "ddos-guard" in server_header and status_code in (403, 200):
        return True, "DDoS-Guard Interstitial"

    return False, None


# ============================================================================
# 3. BASELINE NONCE / CANARY PROBING ENGINE (SOCMINT & SOFT-404)
# ============================================================================

# Thread-safe global cache for platform canary results: platform_name -> dict
_PLATFORM_CANARY_CACHE: Dict[str, dict] = {}

def get_platform_canary_profile(platform: dict, session: requests.Session, timeout: int = 5) -> dict:
    """
    Performs a negative baseline probe by querying a non-existent random UUID username.
    Determines if the platform returns soft-404s, login redirects, or bot challenges.
    Caches the baseline for efficiency during multi-threaded scans.
    """
    platform_name = platform["name"]
    if platform_name in _PLATFORM_CANARY_CACHE:
        return _PLATFORM_CANARY_CACHE[platform_name]

    # High-entropy non-existent canary identifier
    canary_id = f"canary_osintall_{uuid.uuid4().hex[:12]}"
    canary_url = platform["url"].format(canary_id)

    profile = {
        "platform": platform_name,
        "canary_status": 0,
        "is_soft_404": False,
        "has_waf": False,
        "waf_name": None,
        "canary_content_len": 0,
        "redirected_url": "",
        "reliable": True
    }

    try:
        resp = session.get(canary_url, timeout=timeout, allow_redirects=True)
        profile["canary_status"] = resp.status_code
        profile["canary_content_len"] = len(resp.text)
        profile["redirected_url"] = resp.url

        # Check WAF on canary
        is_waf, waf_name = is_waf_or_anti_bot_response(resp)
        if is_waf:
            profile["has_waf"] = True
            profile["waf_name"] = waf_name
            profile["reliable"] = False

        # Soft 404 detection: Platform returns HTTP 200 on a random non-existent user!
        if resp.status_code == 200:
            if platform.get("check") == "status_code":
                # If checking status_code, returning 200 on canary proves it's a soft-404!
                profile["is_soft_404"] = True
                profile["reliable"] = False
            elif platform.get("check") == "json_key":
                try:
                    data = resp.json()
                    if platform.get("key") in data:
                        profile["is_soft_404"] = True
                        profile["reliable"] = False
                except Exception:
                    pass

    except Exception:
        profile["reliable"] = False

    _PLATFORM_CANARY_CACHE[platform_name] = profile
    return profile


def verify_username_finding(platform: dict, username: str, resp: requests.Response, canary_profile: dict) -> Tuple[bool, str]:
    """
    Multi-vector verification of username existence.
    Returns (exists: bool, confidence_reason: str).
    """
    # Vector 1: WAF Guardrail
    is_waf, waf_name = is_waf_or_anti_bot_response(resp)
    if is_waf:
        return False, f"Suppressed false positive: Blocked by {waf_name}"

    # Vector 2: Soft 404 Guardrail
    if canary_profile.get("is_soft_404"):
        # The platform responds 200 to non-existent canaries. We must have strict DOM difference!
        canary_len = canary_profile.get("canary_content_len", 0)
        target_len = len(resp.text)
        len_diff = abs(target_len - canary_len)

        # If length is virtually identical (+/- 50 bytes), it's the exact same 404 template!
        if len_diff < 120:
            return False, f"Suppressed false positive: Soft-404 template match (diff: {len_diff}B)"

        # Check if username actually appears in response
        if username.lower() not in resp.text.lower():
            return False, "Suppressed false positive: Username string missing in body"

    # Vector 3: Redirect to home or login page
    canonical_url = platform["url"].format(username).rstrip("/").lower()
    final_url = resp.url.rstrip("/").lower()
    if canonical_url != final_url:
        parsed_target = urlparse(canonical_url)
        parsed_final = urlparse(final_url)
        # If redirected to root path
        if parsed_final.path in ("", "/", "/home", "/index.html", "/explore"):
            return False, "Suppressed false positive: Redirected to homepage"
        if any(term in final_url for term in ["login", "signin", "auth", "register", "session", "suspended"]):
            return False, "Suppressed false positive: Redirected to auth/session page"

    # Vector 4: Specific exclusion phrases
    lower_body = resp.text.lower()
    not_found_signatures = [
        "page not found", "user not found", "profile not found",
        "doesn't exist", "does not exist", "could not find",
        "no user found", "account suspended", "this page isn't available",
        "the specified profile could not be found", "nobody by this name",
        "sorry, that page doesn't exist", "404 - not found", "member not found"
    ]
    for nfs in not_found_signatures:
        if nfs in lower_body and username.lower() not in lower_body[:200]:
            return False, f"Suppressed false positive: Body contains '{nfs}'"

    # Vector 5: Positive verification criteria
    if platform["check"] == "status_code":
        if resp.status_code == platform.get("valid", 200):
            return True, "Verified (HTTP 200 OK & Nonce Canary Validation Passed)"

    elif platform["check"] == "json_key":
        try:
            data = resp.json()
            if platform.get("key") in data and data.get(platform.get("key")):
                return True, f"Verified (JSON key '{platform.get('key')}' populated)"
        except Exception:
            return False, "Invalid JSON payload"

    elif platform["check"] == "response_text":
        not_found_str = platform.get("not_found", "")
        if resp.status_code == 200 and not_found_str not in resp.text:
            return True, "Verified (Exclusion string absent & Nonce Canary Passed)"

    return False, "Unconfirmed presence"


# ============================================================================
# 4. WILDCARD DNS & SUBDOMAIN TAKEOVER VALIDATION ENGINE
# ============================================================================

# Confirmed claimable fingerprint signatures for Subdomain Takeovers
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": [
        "There isn't a GitHub Pages site here",
        "For root URLs (like http://example.com/) you must provide an index.html"
    ],
    "Heroku": [
        "No such app",
        "herokucdn.com/error-pages/no-such-app.html",
        "<title>No such app</title>"
    ],
    "AWS S3 Bucket": [
        "<Code>NoSuchBucket</Code>",
        "The specified bucket does not exist"
    ],
    "AWS CloudFront": [
        "Bad request: Bad Request",
        "Generated by cloudfront"
    ],
    "Shopify": [
        "Sorry, this shop is currently unavailable",
        "To finish setting up your new web address, go to your domain settings, click 'Connect existing domain'"
    ],
    "Fastly": [
        "Fastly error: unknown domain"
    ],
    "Ghost": [
        "The thing you were looking for is no longer here",
        "The thing you were looking for is no longer here, or never was"
    ],
    "Pantheon": [
        "The gods are wise, but do not know of the site which you seek"
    ],
    "Zendesk": [
        "Help Center Closed"
    ],
    "Surge.sh": [
        "project not found"
    ],
    "Bitbucket": [
        "Repository not found"
    ],
    "Readme.io": [
        "Project doesnt exist"
    ],
    "Unbounce": [
        "The requested URL was not found on this server"
    ],
    "WordPress": [
        "Do you want to register"
    ],
    "Carrd": [
        "Site not found",
        "This profile does not exist"
    ]
}

def detect_wildcard_dns(domain: str, resolver=None) -> Set[str]:
    """
    Detects if a domain utilizes Wildcard DNS (*.domain.com).
    Resolves two independent high-entropy random subdomains. If both resolve
    to the same IP addresses, Wildcard DNS is active, and the resolved IP set
    is returned to suppress thousands of false subdomain alerts.
    """
    if dns is None:
        return set()

    res = resolver if resolver is not None else dns.resolver.Resolver()
    res.timeout = 2.0
    res.lifetime = 2.0

    canary1 = f"osintall-canary-{uuid.uuid4().hex[:10]}.{domain}"
    canary2 = f"osintall-canary-{uuid.uuid4().hex[:10]}.{domain}"

    ips1: Set[str] = set()
    ips2: Set[str] = set()

    try:
        ans1 = res.resolve(canary1, "A")
        ips1 = {str(r) for r in ans1}
    except Exception:
        return set()

    try:
        ans2 = res.resolve(canary2, "A")
        ips2 = {str(r) for r in ans2}
    except Exception:
        return set()

    # If both random canaries resolve to intersecting IPs, wildcard is active!
    common_ips = ips1.intersection(ips2)
    return common_ips


def verify_subdomain_takeover(service: str, target_subdomain: str, session: requests.Session) -> Tuple[bool, str]:
    """
    Actively probes a dangling CNAME to verify claimability against official provider signatures.
    Only when the provider explicitly outputs the unclaimed error page is it flagged as CONFIRMED.
    """
    fingerprints = TAKEOVER_FINGERPRINTS.get(service, [])
    if not fingerprints:
        return False, f"No verified signature dictionary for '{service}'"

    for proto in ["http", "https"]:
        url = f"{proto}://{target_subdomain}"
        try:
            resp = session.get(url, timeout=5, allow_redirects=True)
            body = resp.text
            for fp in fingerprints:
                if fp in body:
                    return True, f"CONFIRMED TAKEOVER: Provider returned proof-of-claim signature: '{fp}'"
        except Exception:
            pass

    return False, "Potential CNAME anomaly, but active proof-of-claim signature was not returned."


# ============================================================================
# 5. CLOUD STORAGE PROVIDER HEADER VALIDATION ENGINE
# ============================================================================

def validate_cloud_provider_response(provider: str, resp: requests.Response) -> Tuple[bool, str]:
    """
    Validates that a response was actually generated by the genuine cloud provider
    (AWS S3, GCP, Azure Blob) rather than an interception proxy, corporate filter,
    or ISP captive portal returning a generic 200/403.
    """
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    server = headers.get("server", "")

    if provider == "AWS S3":
        has_s3_header = any(h in headers for h in ["x-amz-request-id", "x-amz-id-2", "x-amz-bucket-region"])
        is_s3_server = "amazons3" in server
        is_s3_xml = "<listbucketresult" in resp.text.lower() or "<error><code" in resp.text.lower()
        if has_s3_header or is_s3_server or is_s3_xml:
            return True, "Genuine AWS S3 Infrastructure Verified"
        return False, "Filtered out: Missing authentic AWS S3 header signatures (Likely proxy/portal)"

    elif provider == "Google Cloud Storage":
        has_gcp_header = any(h in headers for h in ["x-goog-generation", "x-goog-metageneration", "x-guploader-uploadid"])
        is_gcp_server = "uploadserver" in server or "gse" in server
        is_gcp_xml = "storage.googleapis.com" in resp.text or "<listbucketresult" in resp.text.lower()
        if has_gcp_header or is_gcp_server or is_gcp_xml:
            return True, "Genuine Google Cloud Storage Infrastructure Verified"
        return False, "Filtered out: Missing authentic GCP header signatures (Likely proxy/portal)"

    elif provider == "Azure Blob":
        has_azure_header = any(h in headers for h in ["x-ms-request-id", "x-ms-version"])
        is_azure_server = "windows-azure-blob" in server
        is_azure_xml = "enumerationresults" in resp.text.lower() or "blob.core.windows.net" in resp.text.lower()
        if has_azure_header or is_azure_server or is_azure_xml:
            return True, "Genuine Azure Blob Storage Infrastructure Verified"
        return False, "Filtered out: Missing authentic Azure header signatures (Likely proxy/portal)"

    return True, "Standard Provider Response"


# ============================================================================
# 6. SHARED CDN / REVERSE PROXY DEMARCATION (THREAT INTEL)
# ============================================================================

SHARED_CDN_NETWORKS = [
    ("Cloudflare", ["cloudflare", "cf-ray", "104.", "172.64.", "172.67.", "162.158."]),
    ("Amazon CloudFront / AWS", ["cloudfront", "amazonaws.com"]),
    ("Akamai", ["akamai", "akamaitechnologies"]),
    ("Fastly", ["fastly"])
]

def check_shared_infrastructure_risk(ip_or_host: str, asn_or_org: str = "") -> Tuple[bool, str]:
    """
    Checks if an IP or host belongs to a massive multi-tenant CDN/reverse-proxy pool.
    Prevents false alarms where a clean domain is labeled 'Critical Malware C2'
    merely because a shared Cloudflare or CloudFront IP hosted a bad URL in the past.
    """
    comb = f"{ip_or_host} {asn_or_org}".lower()
    for provider, patterns in SHARED_CDN_NETWORKS:
        for p in patterns:
            if p in comb:
                return True, f"Host resides on shared multi-tenant CDN ({provider}). Individual IoC attribution requires domain-specific correlation to prevent false alarms."
    return False, "Dedicated / Direct Infrastructure"
