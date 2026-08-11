"""
Configuration constants for the OSINT Investigation Engine.
"""

import random

# ─── Concurrency & Timing ───
MAX_CONCURRENT_REQUESTS = 4       # Legacy default (per-tier when parallel is off)
# Per-tier concurrency for parallel execution
TIER1_CONCURRENCY = 6             # Higher-value sites, more careful
TIER2_CONCURRENCY = 8             # Mainstream sites, moderate speed
TIER3_CONCURRENCY = 10            # Niche sites, fastest
PARALLEL_TIERS = True             # Run all tiers simultaneously
TIER1_DELAY_RANGE = (3.0, 6.0)   # Tier 1 sites: 3-6s randomised delay
TIER2_DELAY_RANGE = (1.5, 3.0)   # Tier 2 sites: 1.5-3s delay
TIER3_DELAY_RANGE = (1.0, 2.5)   # Tier 3 sites: 1-2.5s delay
SAME_DOMAIN_DELAY = (2.0, 4.0)   # Minimum between requests to same domain
SECONDARY_CONFIRM_DELAY = (5.0, 10.0)  # Delay before secondary confirmation

# ─── Retry Configuration ───
MAX_RETRIES = 3
RETRY_BACKOFF = [2, 8, 30]       # Exponential backoff in seconds
RATE_LIMIT_COOLDOWN = (60, 180)  # 429 cooldown range in seconds

# ─── Request Configuration ───
REQUEST_TIMEOUT = 20             # Per-request timeout in seconds
MAX_RESPONSE_BODY = 500_000      # Max response body to read (500KB)

# ─── Confidence Thresholds ───
CONFIDENCE_CONFIRMED = (95, 100)
CONFIDENCE_HIGH = (75, 94)
CONFIDENCE_MEDIUM = (50, 74)
CONFIDENCE_UNVERIFIED = (1, 49)
CONFIDENCE_NOT_FOUND = 0

# ─── Calibration ───
CALIBRATION_TTL = 600            # 10 minutes
SITE_VALIDATION_TTL = 6 * 3600  # 6 hours
SITE_DATA_CACHE_TTL = 3600      # 1 hour

# ─── Permutation Limits ───
MAX_NAME_LENGTH_FOR_LEET = 12   # Only apply l33t speak if name <= 12 chars
MAX_PERMUTATIONS_PER_MODE = 500 # Safety cap

# ─── Indian Number Suffixes ───
INDIAN_NUMBER_SUFFIXES = [
    "1", "2", "99", "98", "07", "007", "786", "123", "0101", "2024", "2025"
]

INDIAN_TEXT_SUFFIXES = [
    "_india", "_official", "_real", ".india", ".official"
]

# ─── Common Indian Separators for Name Permutations ───
NAME_SEPARATORS = ["", ".", "_", "-"]

# ─── Leet Speak Substitutions (1 level deep) ───
LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}

# ─── User-Agent Rotation Pool ───
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]


# ─── Dynamic Chrome major-version range (Snoop technique) ───
# Generate Chrome version per-request rather than picking from a fixed pool —
# defeats simple UA-blacklist fingerprinting that targets known string values.
CHROME_MAJOR_RANGE = (118, 131)
FIREFOX_MAJOR_RANGE = (120, 132)


def _generate_dynamic_chrome_ua() -> str:
    """Generate a fresh Chrome UA with a randomised major version."""
    major = random.randint(*CHROME_MAJOR_RANGE)
    platforms = [
        ("Windows NT 10.0; Win64; x64", "Windows"),
        ("Macintosh; Intel Mac OS X 10_15_7", "macOS"),
        ("X11; Linux x86_64", "Linux"),
    ]
    plat, _ = random.choice(platforms)
    return (
        f"Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


def _generate_dynamic_firefox_ua() -> str:
    major = random.randint(*FIREFOX_MAJOR_RANGE)
    platforms = [
        ("Windows NT 10.0; Win64; x64", "rv"),
        ("Macintosh; Intel Mac OS X 10.15", "rv"),
        ("X11; Linux x86_64", "rv"),
    ]
    plat, _ = random.choice(platforms)
    return (
        f"Mozilla/5.0 ({plat}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"
    )


def get_random_headers(heavy: bool = False):
    """Generate browser-mimicking request headers with rotated User-Agent.

    heavy=True returns a fuller header set including Sec-Ch-Ua client-hints —
    used on retry attempts after a first attempt was blocked. (Snoop pattern.)
    """
    # 70% chance dynamic Chrome, 20% dynamic Firefox, 10% static pool variety
    r = random.random()
    if r < 0.70:
        ua = _generate_dynamic_chrome_ua()
    elif r < 0.90:
        ua = _generate_dynamic_firefox_ua()
    else:
        ua = random.choice(USER_AGENTS)
    is_chrome = "Chrome" in ua and "Edg" not in ua
    is_firefox = "Firefox" in ua

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    if is_chrome:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"
        headers["Sec-Ch-Ua-Platform"] = '"Windows"'
        if heavy:
            # Full client-hints set — more believable browser realism
            # Extract major version from UA for matching client-hints
            import re as _re
            m = _re.search(r"Chrome/(\d+)", ua)
            major = m.group(1) if m else "120"
            headers["Sec-Ch-Ua"] = (
                f'"Not_A Brand";v="8", "Chromium";v="{major}", '
                f'"Google Chrome";v="{major}"'
            )
            headers["Sec-Ch-Ua-Mobile"] = "?0"
    elif is_firefox:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"

    return headers


# ─── WAF / Anti-Bot Detection Signatures ───
# Sources: Sherlock WAFHitMsgs, Maigret COMMON_ERRORS, DataDome CDN docs,
# Cloudflare Turnstile/Managed Challenge HTML, AWS WAF JS challenge,
# Imperva Incapsula, Akamai Bot Manager, PerimeterX/HUMAN, hCaptcha,
# reCAPTCHA, DDoS-Guard, Kasada.
WAF_SIGNATURES = [
    # Cloudflare
    "attention required! | cloudflare",
    "please wait... | cloudflare",
    "cf-browser-verification",
    "checking your browser",
    "checking if the site connection is secure",
    "enable javascript and cookies to continue",
    "just a moment...",
    "ray id:",
    "performance & security by cloudflare",
    "cf-challenge",
    "managed-challenge",
    "challenge-platform",
    "cdn-cgi/challenge-platform",
    "challenge-error-text",                              # Cloudflare Turnstile
    'data-translate="checking_browser"',
    "/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page",
    # Cloudfront
    "generated by cloudfront (cloudfront)",
    # AWS WAF (Sherlock pattern)
    "awswafintegration.forcerefreshtoken",
    "aws-waf-token",
    # PerimeterX / HUMAN
    "perimeterx",
    "_pxaction",
    "perimeterxidentifiers",
    "px-captcha",
    # DataDome
    "datadome",
    "dd_cookie_test",
    "geo.captcha-delivery.com",
    "datadome captcha",
    # Imperva / Incapsula
    "incapsula incident",
    "_incapsula_resource",
    "incident id:",
    # Akamai
    "akamai bot manager",
    "akamai reference",
    "reference&#32;&#35;",
    # DDoS-Guard
    "ddos protection by",
    "<title>ddos-guard</title>",
    "blazingfast.io",
    # Kasada
    "kasada",
    "x-kpsdk-cd",
    # Sucuri
    "sucuri website firewall",
    # Generic
    "access denied",
    "sorry, you have been blocked",
    "please turn javascript on",
    "one more step",
    "why do i have to complete a captcha",
    "bot verification",
    "human verification",
    "pardon our interruption",
    "we need to verify that you are not a robot",
    "captcha",
    "recaptcha",
    "hcaptcha",
    "g-recaptcha",
    "recaptcha/api.js",
    "hcaptcha.com/captcha",
    "browser integrity check",
    "are you a robot",
    "verify you are human",
    "security check",
    "automated access",
    "unusual traffic",
    "too many requests",
    "rate limited",
    "blocked by",
    "shape security",
    "distil networks",
    "<title>client challenge</title>",
    "<title>just a moment</title>",
]

# ─── Permanent (non-retryable) error classifications ───
# Maigret pattern: don't burn retries on captcha/WAF/access-denied/banned.
# These categories indicate the site has decisively decided NOT to serve us;
# retrying with the same identifying network signal won't help.
PERMANENT_ERROR_CATEGORIES = {
    "waf",                # WAF challenge page
    "captcha",            # captcha required
    "access_denied",      # 403 with no body indicators of useful content
    "banned",             # IP/account banned messages
    "geo_blocked",        # geographic restriction
    "consent_required",   # cookie/consent wall
    "censored",           # site-level censorship
}

RETRYABLE_ERROR_CATEGORIES = {
    "timeout",
    "connection_lost",
    "connection_reset",
    "dns_failure",
    "http_5xx",
    "rate_limited",       # cooldown then retry
    "transient_unknown",
}


def is_permanent_error(category: str) -> bool:
    """Classify whether an error category should short-circuit the retry loop."""
    return (category or "").lower() in PERMANENT_ERROR_CATEGORIES

# ─── Rate Limit Detection Patterns ───
RATE_LIMIT_PATTERNS = [
    "rate limit",
    "too many requests",
    "throttled",
    "slow down",
    "try again later",
    "request limit exceeded",
    "api rate limit",
]

# ─── Phone Number Formats (Indian) ───
INDIAN_PHONE_PREFIXES = ["+91", "91", "0"]
INDIAN_PHONE_LENGTH = 10  # 10 digits without country code

# ─── Input Type Detection Patterns ───
import re
EMAIL_RE = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
PHONE_RE = re.compile(r'^[\+]?[\d\s\-\(\)]{10,15}$')

# ─── Sherlock & WhatsMyName Data URLs ───
SHERLOCK_DATA_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "master/sherlock_project/resources/data.json"
)
WMN_DATA_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/"
    "main/wmn-data.json"
)
