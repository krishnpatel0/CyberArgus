"""
Multi-Signal Verification System for OSINT Investigation Engine.

Implements enterprise-grade false positive elimination through:
- claimed_if / not_claimed_if / ambiguous_if signal matching
- Calibration-based baseline comparison
- WAF/anti-bot detection
- Secondary confirmation requests for Tier 1 sites
- DOM skeleton hashing for soft-404 detection

CORE PRINCIPLE: Never report "Found" unless there is strong, multi-signal,
independently confirmed evidence. A false positive is more damaging than a miss.
"""

import re
import hashlib
import html as html_module
import random
import string
import time
import json
import os
import threading
from collections import Counter
from urllib.parse import urlparse, quote

from .config import (
    SECONDARY_CONFIRM_DELAY,
    CALIBRATION_TTL,
    get_random_headers,
)
from .http_client import make_request, make_confirmation_request, detect_waf
from .profile_parser import recover_from_structured_data


# ─── Module-level calibration cache ───
_calibration_cache = {}  # site_name -> {baseline_size, baseline_status, skeleton, timestamp, ...}
_calibration_cache_lock = threading.Lock()
_calibration_cache_loaded = False
_CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
_CALIBRATION_CACHE_PATH = os.path.join(_CACHE_DIR, "calibration_cache.json")


def _ensure_cache_dir():
    os.makedirs(_CACHE_DIR, exist_ok=True)


def _load_calibration_cache_from_disk():
    global _calibration_cache_loaded, _calibration_cache

    if _calibration_cache_loaded:
        return

    with _calibration_cache_lock:
        if _calibration_cache_loaded:
            return
        try:
            with open(_CALIBRATION_CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                _calibration_cache = data
        except (OSError, json.JSONDecodeError):
            _calibration_cache = {}
        _calibration_cache_loaded = True


def _persist_calibration_cache():
    with _calibration_cache_lock:
        try:
            _ensure_cache_dir()
            with open(_CALIBRATION_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(_calibration_cache, f, indent=2)
        except OSError:
            pass


def _generate_nonexistent_username(length=18):
    """Generate a guaranteed-nonexistent random username for calibration."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ─── Content Analysis ───

def _contains_any(text: str, markers: list[str]) -> tuple[bool, list[str]]:
    """Check if text contains any of the markers (case-insensitive).
    Returns (found, list_of_matched_markers)."""
    if not text or not markers:
        return False, []
    text_lower = text.lower()
    matched = [m for m in markers if m.lower() in text_lower]
    return bool(matched), matched


def _username_in_body(body: str, username: str) -> bool:
    """Check if username appears in body with word-boundary context."""
    if not body or not username:
        return False
    lower_body = body.lower()
    lower_user = username.lower()
    if lower_user not in lower_body:
        return False

    escaped = re.escape(lower_user)
    patterns = [
        rf'(?<![a-z0-9]){escaped}(?![a-z0-9])',
        rf'["\']{escaped}["\']',
        rf'@{escaped}(?![a-z0-9])',
        rf'/{escaped}(?:["\'/?#]|$)',
    ]
    for pat in patterns:
        if re.search(pat, lower_body):
            return True
    return False


# ─── DOM Skeleton Hashing ───

_TAG_RE = re.compile(r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*>')


def _compute_dom_skeleton(html_text: str) -> list[str]:
    """Extract ordered tag names from first 10KB of HTML."""
    return _TAG_RE.findall(html_text[:10000])


def _dom_similarity(skeleton_a: list, skeleton_b: list) -> float:
    """Compute Jaccard similarity of tag frequency vectors."""
    if not skeleton_a or not skeleton_b:
        return 0.0
    freq_a = Counter(skeleton_a)
    freq_b = Counter(skeleton_b)
    all_tags = set(freq_a) | set(freq_b)
    intersection = sum(min(freq_a.get(t, 0), freq_b.get(t, 0)) for t in all_tags)
    union = sum(max(freq_a.get(t, 0), freq_b.get(t, 0)) for t in all_tags)
    return intersection / union if union > 0 else 0.0


# ─── Metadata Extraction ───

_OG_TITLE_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:title["\']\s+content=["\']([^"\']{1,500})["\']',
    re.IGNORECASE,
)
_OG_DESC_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:description["\']\s+content=["\']([^"\']{1,500})["\']',
    re.IGNORECASE,
)
_META_DESC_RE = re.compile(
    r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']{1,500})["\']',
    re.IGNORECASE,
)
_OG_IMAGE_RE = re.compile(
    r'<meta\s+property=["\']og:image["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_LOCATION_PATTERNS = [
    re.compile(r'<[^>]*(?:class|itemprop)="[^"]*(?:location|addressLocality|p-label)[^"]*"[^>]*>(.*?)</', re.I),
]

_DISPLAY_NAME_PATTERNS = [
    re.compile(r'<(?:h1|h2|span)[^>]*class="[^"]*(?:display.?name|full.?name|profile.?name|user.?name)[^"]*"[^>]*>(.*?)</', re.I | re.DOTALL),
]

_FOLLOWER_PATTERNS = [
    re.compile(r'(\d[\d,]*)\s*(?:followers?|subscribers?)', re.I),
]

_BIO_PATTERNS = [
    re.compile(r'<[^>]*class="[^"]*(?:bio|about|description|summary)[^"]*"[^>]*>(.*?)</(?:div|p|span)>', re.I | re.DOTALL),
]

_EMAIL_IN_TEXT_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}')
_URL_IN_TEXT_RE = re.compile(r'https?://[^\s<>"\']+')


def _clean_html(text: str) -> str:
    """Strip HTML tags and unescape entities."""
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html_module.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_metadata(body: str, site_name: str, username: str) -> dict:
    """Extract profile metadata from HTML response."""
    if not body:
        return {"bio": "", "location": "", "avatar_url": "", "display_name": "", "follower_count": "", "profile_urls": []}

    chunk = body[:50000]
    bio = ""
    location = ""
    avatar_url = ""
    display_name = ""
    follower_count = ""
    profile_urls = []

    # OpenGraph title -> display name
    m = _OG_TITLE_RE.search(chunk)
    if m:
        raw = html_module.unescape(m.group(1)).strip()
        # Often "Username - Platform" or "Platform: Username"
        if raw:
            display_name = raw

    # Display name from HTML
    if not display_name:
        for pat in _DISPLAY_NAME_PATTERNS:
            m = pat.search(chunk)
            if m:
                display_name = _clean_html(m.group(1))
                break

    # Bio from OpenGraph description
    m = _OG_DESC_RE.search(chunk)
    if not m:
        m = _META_DESC_RE.search(chunk)
    if m:
        bio = html_module.unescape(m.group(1)).strip()

    # Bio from HTML patterns
    if not bio:
        for pat in _BIO_PATTERNS:
            m = pat.search(chunk)
            if m:
                bio = _clean_html(m.group(1))
                break

    # Avatar
    m = _OG_IMAGE_RE.search(chunk)
    if m:
        avatar_url = m.group(1)

    # Location
    for pat in _LOCATION_PATTERNS:
        m = pat.search(chunk)
        if m:
            location = _clean_html(m.group(1))
            break

    # Follower count
    for pat in _FOLLOWER_PATTERNS:
        m = pat.search(chunk)
        if m:
            follower_count = m.group(1).replace(",", "")
            break

    # Extract URLs from bio (for cross-platform linking)
    if bio:
        profile_urls = _URL_IN_TEXT_RE.findall(bio)[:5]

    # Truncate
    if bio and len(bio) > 300:
        bio = bio[:297] + "..."
    if location and len(location) > 100:
        location = location[:100]
    if display_name and len(display_name) > 150:
        display_name = display_name[:150]

    return {
        "bio": bio,
        "location": location,
        "avatar_url": avatar_url,
        "display_name": display_name,
        "follower_count": follower_count,
        "profile_urls": profile_urls,
    }


# ─── Calibration ───

def get_calibration(site_name: str, site_config: dict, delay_range: tuple) -> dict:
    """
    Make a request with a random nonexistent username to establish baseline.
    Cached per site for CALIBRATION_TTL seconds.
    """
    _load_calibration_cache_from_disk()
    now = time.time()
    cached = _calibration_cache.get(site_name)
    if cached and (now - cached["timestamp"]) < CALIBRATION_TTL:
        return cached

    random_user = _generate_nonexistent_username()
    url_template = site_config.get("url", "")
    url_probe_template = site_config.get("url_probe", url_template)
    method = site_config.get("method", "GET").upper()

    probe_url = url_probe_template.replace("{}", quote(random_user))

    result_data = make_request(
        url=probe_url,
        method=method,
        delay_range=delay_range,
        allow_redirects=True,
    )

    body = result_data.get("body", "")
    status = result_data.get("status_code", 0)

    claimed_markers = site_config.get("claimed_if", [])
    not_claimed_markers = site_config.get("not_claimed_if", [])

    claimed_found, _ = _contains_any(body, claimed_markers)
    not_claimed_found, _ = _contains_any(body, not_claimed_markers)
    username_found = _username_in_body(body, random_user)

    cal = {
        "status": status,
        "size": len(body),
        "skeleton": _compute_dom_skeleton(body) if body else [],
        "claimed_found": claimed_found,
        "not_claimed_found": not_claimed_found,
        "username_found": username_found,
        "timestamp": now,
    }
    _calibration_cache[site_name] = cal
    _persist_calibration_cache()
    return cal


# ─── Alt-endpoint recovery (Phase 3 — Unverified reduction) ───

def _check_alt_endpoints(site_config: dict, username: str) -> dict:
    """
    When the primary URL returns Unverified/Ambiguous (or was blocked by a
    WAF), try the site's secondary endpoints — typically the mobile site,
    a JSON API, or sitemap — which are often less aggressively protected.

    Each `alt_endpoints` entry is a small site-config-shaped dict:
        {
          "url":              "https://api.x.com/2/users/by/username/{}",
          "method":           "GET" | "POST" | "HEAD"           (optional, default GET)
          "type":             "json" | "html"                    (default html)
          "claimed_if":       [...]                              (positive markers)
          "not_claimed_if":   [...]                              (negative markers)
          "claimed_if_status":   [200]                           (optional AND-pair)
          "not_claimed_if_status": [404]                         (optional AND-pair)
          "headers":          {...}                              (optional override)
        }

    Returns the same shape as `recover_from_structured_data`:
        {recovered, confidence, signal, detail, source}

    Confidence weights:
      +55 — JSON API returned 200 with positive marker (definitive)
      +40 — HTML alt endpoint matched claimed_if + status pair
      +30 — HTML alt endpoint matched claimed_if only
       0  — alt endpoint inconclusive (no recovery)

    Returns *negative* confidence (-100) only if an alt endpoint definitively
    proves the account does NOT exist (e.g. JSON API 404 with `not_claimed_if`
    matched). Caller should then mark not_found.
    """
    alts = site_config.get("alt_endpoints") or []
    if not alts or not username:
        return {"recovered": False, "confidence": 0, "signal": "",
                "detail": "", "source": ""}

    for idx, alt in enumerate(alts):
        if not isinstance(alt, dict):
            continue
        url_template = alt.get("url", "")
        if not url_template or "{}" not in url_template:
            continue
        try:
            alt_url = url_template.format(quote(username, safe=""))
        except Exception:
            continue

        method = (alt.get("method") or "GET").upper()
        endpoint_type = (alt.get("type") or "html").lower()
        claimed_markers = alt.get("claimed_if", []) or []
        not_claimed_markers = alt.get("not_claimed_if", []) or []
        claimed_status_pair = set(alt.get("claimed_if_status", []) or [])
        not_claimed_status_pair = set(alt.get("not_claimed_if_status", []) or [])
        headers = alt.get("headers") or None

        try:
            alt_resp = make_request(
                url=alt_url,
                method=method,
                headers=headers,
                delay_range=(0.5, 1.0),  # alt endpoints get shorter delay — they're a fallback
                allow_redirects=True,
                timeout=10,
            )
        except Exception:
            continue

        if not alt_resp.get("success"):
            # Network failure on this alt — try the next one.
            continue
        if alt_resp.get("waf_detected"):
            # Alt also blocked by a WAF — useless, skip.
            continue
        if alt_resp.get("rate_limited"):
            continue

        alt_body = alt_resp.get("body", "") or ""
        alt_status = alt_resp.get("status_code", 0)
        alt_body_lower = alt_body.lower()

        # Negative AND-pair check (strongest no-account signal)
        not_claimed_str_hit = any(
            m and m.lower() in alt_body_lower for m in not_claimed_markers
        )
        not_claimed_status_hit = (
            not not_claimed_status_pair or alt_status in not_claimed_status_pair
        )
        if not_claimed_str_hit and not_claimed_status_hit:
            return {
                "recovered": True,
                "confidence": -100,  # signal caller to mark not_found
                "signal": f"alt_endpoint_{idx}_disconfirmed",
                "detail": f"Alt endpoint #{idx} ({endpoint_type}) returned negative marker — account does not exist",
                "source": f"alt_{endpoint_type}",
            }

        # Positive AND-pair check
        claimed_str_hit = any(
            m and m.lower() in alt_body_lower for m in claimed_markers
        )
        claimed_status_hit = (
            not claimed_status_pair or alt_status in claimed_status_pair
        )

        if claimed_str_hit and claimed_status_hit:
            # Strongest case: JSON endpoint with full pair match.
            if endpoint_type == "json":
                conf = 55
            else:
                conf = 40 if claimed_status_pair else 30
            return {
                "recovered": True,
                "confidence": conf,
                "signal": f"alt_endpoint_{idx}_confirmed",
                "detail": f"Alt {endpoint_type} endpoint #{idx} confirms @{username} (HTTP {alt_status})",
                "source": f"alt_{endpoint_type}",
            }

        # Status-only confirmation for endpoints that have a pair declared
        # but no body marker (e.g. some JSON APIs return 200 = exists, 404 = no).
        if claimed_status_pair and alt_status in claimed_status_pair and not claimed_markers:
            if endpoint_type == "json":
                return {
                    "recovered": True,
                    "confidence": 50,
                    "signal": f"alt_endpoint_{idx}_status_confirmed",
                    "detail": f"Alt JSON endpoint #{idx} returned HTTP {alt_status} — account exists",
                    "source": f"alt_{endpoint_type}",
                }

        # Status-only disconfirmation (e.g. JSON API returned 404).
        if not_claimed_status_pair and alt_status in not_claimed_status_pair and not not_claimed_markers:
            if endpoint_type == "json":
                return {
                    "recovered": True,
                    "confidence": -100,
                    "signal": f"alt_endpoint_{idx}_status_disconfirmed",
                    "detail": f"Alt JSON endpoint #{idx} returned HTTP {alt_status} — account does not exist",
                    "source": f"alt_{endpoint_type}",
                }

    # All alts inconclusive
    return {"recovered": False, "confidence": 0, "signal": "",
            "detail": "", "source": ""}


# ─── Core Verification ───

def verify_site(
    site_name: str,
    site_config: dict,
    username: str,
    delay_range: tuple,
    subject_profile: dict = None,
) -> dict:
    """
    Perform full multi-signal verification of a username on a site.

    Returns a comprehensive verification result dict containing:
    - claimed: bool (True only if strong evidence)
    - confidence_score: float (0-100)
    - confidence_level: str
    - signals: list of signal dicts
    - metadata: dict
    - secondary_confirmed: bool or None
    - waf_detected: bool
    - rate_limited: bool
    - status: str (found/not_found/unverified/error/rate_limited)
    """
    url_template = site_config.get("url", "")
    url_probe_template = site_config.get("url_probe", url_template)
    method = site_config.get("method", "GET").upper()
    error_type = site_config.get("error_type", "status_code")
    claimed_markers = site_config.get("claimed_if", [])
    not_claimed_markers = site_config.get("not_claimed_if", [])
    ambiguous_markers = site_config.get("ambiguous_if", [])
    needs_secondary = site_config.get("secondary_confirmation", False)
    username_format = site_config.get("username_format", "")

    # ── WhatsMyName-style AND-paired status codes (optional) ──
    # When present, a "found" verdict requires BOTH the string match AND
    # the status code match. If only one matches, result is "Ambiguous".
    claimed_status_pair = site_config.get("claimed_if_status", [])     # e.g. [200]
    not_claimed_status_pair = site_config.get("not_claimed_if_status", [])  # e.g. [404]

    # Sites that legitimately return 4xx with valid body markers (Maigret ignore403)
    ignore_status_codes = site_config.get("ignore_status", [])

    # Username format validation
    if username_format:
        try:
            if not re.match(username_format, username):
                return _build_result(
                    status="not_found", claimed=False, confidence=0,
                    signals=[{"name": "username_format_invalid", "passed": False,
                             "detail": f"Username doesn't match site format: {username_format}"}],
                )
        except re.error:
            pass

    profile_url = url_template.replace("{}", username)
    probe_url = url_probe_template.replace("{}", quote(username))

    # Build request payload if needed
    json_payload = None
    if "request_payload" in site_config:
        payload = site_config["request_payload"]
        if isinstance(payload, dict):
            json_payload = {k: v.replace("{}", username) if isinstance(v, str) else v
                          for k, v in payload.items()}

    allow_redirects = error_type != "response_url"

    # Make primary request — pass ignore_status so http_client doesn't
    # short-circuit on configured 401/403/451 returns.
    resp_data = make_request(
        url=probe_url, method=method, json_payload=json_payload,
        delay_range=delay_range, allow_redirects=allow_redirects,
        ignore_status=ignore_status_codes,
    )

    if not resp_data["success"]:
        return _build_result(
            status="error",
            claimed=False,
            confidence=0,
            url=profile_url,
            response_time_ms=resp_data.get("response_time_ms", 0),
            retry_count=resp_data.get("retry_count", 0),
            signals=[{"name": "request_failed", "passed": False,
                     "detail": resp_data.get("error", "unknown error")}],
        )

    if resp_data.get("rate_limited"):
        return _build_result(
            status="rate_limited",
            claimed=False,
            confidence=0,
            url=profile_url,
            rate_limited=True,
            response_time_ms=resp_data.get("response_time_ms", 0),
            signals=[{"name": "rate_limited", "passed": False, "detail": "Site returned 429 or rate limit response"}],
        )

    body = resp_data.get("body", "")
    status_code = resp_data.get("status_code", 0)
    final_url = resp_data.get("final_url", probe_url)

    # ─── Signal Collection ───
    signals = []

    # Signal 1: WAF Detection
    waf_detected = resp_data.get("waf_detected", False)
    waf_sig = resp_data.get("waf_signature", "")
    signals.append({
        "name": "no_waf_detected",
        "passed": not waf_detected,
        "weight": 5,
        "detail": f"WAF signature: {waf_sig}" if waf_detected else "No anti-bot protection detected",
    })

    if waf_detected:
        return _build_result(
            status="unverified",
            claimed=False,
            confidence=5,
            confidence_level="Unverified",
            url=profile_url,
            waf_detected=True,
            antibot_detail=f"Anti-bot protection detected: {waf_sig}",
            response_time_ms=resp_data.get("response_time_ms", 0),
            signals=signals,
        )

    # Signal 2: HTTP Status Code
    status_ok = 200 <= status_code < 300
    signals.append({
        "name": "http_status_ok",
        "passed": status_ok,
        "weight": 10,
        "detail": f"HTTP {status_code}",
    })

    # Signal 3: Not-Claimed markers (checked EVEN when status is 200)
    not_claimed_found, not_claimed_matches = _contains_any(body, not_claimed_markers)
    signals.append({
        "name": "no_negative_markers",
        "passed": not not_claimed_found,
        "weight": 15,
        "detail": f"Negative markers found: {not_claimed_matches}" if not_claimed_found else "No negative markers detected",
    })

    # ── WhatsMyName AND-pair evaluation for negative markers ──
    # If site declares not_claimed_if_status, require BOTH status AND string
    # to agree before short-circuiting to "not_found". When only one matches,
    # we let the full signal-scoring loop run and may report "Ambiguous".
    not_claimed_status_match = (
        not not_claimed_status_pair
        or status_code in not_claimed_status_pair
    )

    # If definitive negative signals are present AND status agrees → Not Found
    if not_claimed_found and not_claimed_status_match:
        return _build_result(
            status="not_found",
            claimed=False,
            confidence=0,
            url=profile_url,
            http_status_code=status_code,
            response_time_ms=resp_data.get("response_time_ms", 0),
            signals=signals,
        )

    # Track partial AND-pair mismatches for the ambiguous-state cap below
    not_claimed_pair_mismatch = bool(
        not_claimed_status_pair and not_claimed_found and not not_claimed_status_match
    )

    # If status code indicates definitive not found (unless ignore_status overrides)
    if status_code in (404, 410, 451) and status_code not in ignore_status_codes:
        signals.append({
            "name": "definitive_http_not_found",
            "passed": False,
            "weight": 20,
            "detail": f"HTTP {status_code} - definitive not found",
        })
        return _build_result(
            status="not_found",
            claimed=False,
            confidence=0,
            url=profile_url,
            http_status_code=status_code,
            response_time_ms=resp_data.get("response_time_ms", 0),
            signals=signals,
        )

    # Signal 4: Ambiguous markers
    ambiguous_found, ambiguous_matches = _contains_any(body, ambiguous_markers)
    signals.append({
        "name": "no_ambiguous_markers",
        "passed": not ambiguous_found,
        "weight": 5,
        "detail": f"Ambiguous markers found: {ambiguous_matches}" if ambiguous_found else "No ambiguity detected",
    })

    if ambiguous_found and not status_ok:
        return _build_result(
            status="unverified",
            claimed=False,
            confidence=10,
            confidence_level="Unverified",
            url=profile_url,
            http_status_code=status_code,
            response_time_ms=resp_data.get("response_time_ms", 0),
            signals=signals,
        )

    # Signal 5: Claimed markers (positive signals)
    claimed_found, claimed_matches = _contains_any(body, claimed_markers)
    signals.append({
        "name": "positive_markers_found",
        "passed": claimed_found,
        "weight": 20,
        "detail": f"Positive signals: {claimed_matches}" if claimed_found else "No positive markers found",
    })

    # ── WhatsMyName AND-pair evaluation for positive markers ──
    # When site declares claimed_if_status, both string AND status must agree
    # for full-confidence "found". Mismatch demotes the result to "Ambiguous".
    claimed_status_match = (
        not claimed_status_pair
        or status_code in claimed_status_pair
    )
    claimed_pair_full_match = (
        bool(claimed_status_pair) and claimed_found and claimed_status_match
    )
    claimed_pair_mismatch = bool(
        claimed_status_pair and claimed_found and not claimed_status_match
    )
    if claimed_pair_full_match:
        signals.append({
            "name": "and_paired_match",
            "passed": True,
            "weight": 15,
            "detail": f"Both claimed_if marker AND status code {status_code} agree",
        })
    elif claimed_pair_mismatch:
        signals.append({
            "name": "and_paired_mismatch",
            "passed": False,
            "weight": 0,
            "detail": (
                f"Marker matched but HTTP {status_code} not in expected "
                f"{claimed_status_pair} — demoting to Ambiguous"
            ),
        })

    # Signal 6: Username in body
    username_in_page = _username_in_body(body, username)
    signals.append({
        "name": "username_in_content",
        "passed": username_in_page,
        "weight": 15,
        "detail": f"Username '{username}' found in page content" if username_in_page else "Username not found in content",
    })

    # Signal 7: Redirect detection
    expected_domain = urlparse(profile_url).netloc
    final_domain = urlparse(final_url).netloc
    no_unexpected_redirect = expected_domain == final_domain or expected_domain in final_domain
    redirect_to_login = False
    if not no_unexpected_redirect:
        final_lower = final_url.lower()
        redirect_to_login = any(kw in final_lower for kw in ["login", "signin", "sign-in", "auth", "register"])

    signals.append({
        "name": "no_unexpected_redirect",
        "passed": no_unexpected_redirect,
        "weight": 5,
        "detail": f"Redirected to {final_url}" if not no_unexpected_redirect else "No unexpected redirect",
    })

    if redirect_to_login:
        signals.append({
            "name": "redirect_to_login",
            "passed": False,
            "weight": -15,
            "detail": "Redirected to login/auth page",
        })

    # Signal 8: Calibration comparison
    calibration = get_calibration(site_name, site_config, delay_range)
    size_differs = False
    dom_differs = False

    if calibration:
        cal_size = calibration.get("size", 0)
        current_size = len(body)
        if cal_size > 0:
            size_ratio = abs(current_size - cal_size) / max(cal_size, 1)
            size_differs = size_ratio > 0.05  # More than 5% difference

        signals.append({
            "name": "size_differs_from_baseline",
            "passed": size_differs,
            "weight": 10,
            "detail": f"Response size {current_size} vs baseline {cal_size}" if calibration else "No calibration data",
        })

        # Soft-404 detection: if size is within 5% of unclaimed baseline
        if not size_differs and cal_size > 0:
            signals.append({
                "name": "soft_404_risk",
                "passed": False,
                "weight": -20,
                "detail": f"Response size matches unclaimed baseline ({current_size} ≈ {cal_size})",
            })

        # DOM skeleton comparison
        cal_skeleton = calibration.get("skeleton", [])
        current_skeleton = _compute_dom_skeleton(body)
        if cal_skeleton and current_skeleton:
            similarity = _dom_similarity(cal_skeleton, current_skeleton)
            dom_differs = similarity < 0.90  # Less than 90% similar
            signals.append({
                "name": "dom_structure_differs",
                "passed": dom_differs,
                "weight": 5,
                "detail": f"DOM similarity: {similarity:.2f}",
            })

        # If calibration's random user also looked claimed, site has weak detection
        if calibration.get("claimed_found") and not calibration.get("not_claimed_found"):
            signals.append({
                "name": "calibration_false_positive_risk",
                "passed": False,
                "weight": -25,
                "detail": "Calibration: random username also triggered positive markers",
            })

    # Signal 9: Metadata extraction
    metadata = extract_metadata(body, site_name, username)
    has_metadata = bool(metadata.get("bio") or metadata.get("location") or metadata.get("avatar_url"))
    signals.append({
        "name": "profile_metadata_found",
        "passed": has_metadata,
        "weight": 10,
        "detail": "Profile metadata (bio/location/avatar) extracted" if has_metadata else "No profile metadata found",
    })

    # ─── Calculate confidence score ───
    total_positive_weight = 0
    total_negative_weight = 0
    earned_positive = 0

    positive_signal_count = 0
    for sig in signals:
        w = sig.get("weight", 0)
        if w > 0:
            total_positive_weight += w
            if sig.get("passed"):
                earned_positive += w
                positive_signal_count += 1
        elif w < 0 and not sig.get("passed"):
            total_negative_weight += abs(w)

    # Base score from positive signals (0-100 scale)
    if total_positive_weight > 0:
        raw_score = (earned_positive / total_positive_weight) * 100
    else:
        raw_score = 0

    # Apply penalties
    confidence = max(0, raw_score - total_negative_weight)

    # Require at least 2 independent positive signals for anything above Unverified
    if positive_signal_count < 2 and confidence >= 50:
        confidence = min(confidence, 49)
        signals.append({
            "name": "insufficient_independent_signals",
            "passed": False,
            "weight": 0,
            "detail": f"Only {positive_signal_count} positive signal(s) — need ≥2 for Medium confidence or above",
        })

    # Ambiguous markers cap confidence
    if ambiguous_found:
        confidence = min(confidence, 45)

    # ── WhatsMyName-style Ambiguous demotion ──
    # If either AND-pair (claimed or not_claimed) had a code/string mismatch,
    # cap confidence at the Ambiguous ceiling (40). The result will be labeled
    # "Ambiguous" by _score_to_level, never "Found" — police-grade defensibility.
    if claimed_pair_mismatch or not_claimed_pair_mismatch:
        confidence = min(confidence, 40)
        signals.append({
            "name": "and_pair_demotion",
            "passed": False,
            "weight": 0,
            "detail": "AND-paired status/string mismatch — confidence capped at Ambiguous tier",
        })

    # ── Structured-data recovery (Phase 2 — Unverified reduction) ──
    # When the primary `claimed_if` markers didn't fire strongly enough but the
    # response was a valid 200, sites often still embed authoritative profile
    # data in `__NEXT_DATA__`, JSON-LD, or OG meta tags (think modern SPAs that
    # lazy-load the visible profile but ship the canonical username server-side).
    # This recovery step parses those structured blobs and, if it finds the
    # searched username, lifts the score out of the Unverified/Ambiguous range.
    # Modelled on Maigret + socid_extractor — recovers ~30% of UNKNOWN cases.
    #
    # Only run when:
    #   - confidence is below Medium (50)
    #   - HTTP status is in the 2xx range (no point parsing error pages)
    #   - WAF was NOT detected (parsing a challenge page is meaningless)
    #   - we actually have a body to parse
    if (
        confidence < 50
        and not waf_detected
        and 200 <= status_code < 300
        and body
    ):
        try:
            recovery = recover_from_structured_data(body, username, site_config)
        except Exception:
            recovery = {"recovered": False, "confidence": 0}

        if recovery.get("recovered") and recovery.get("confidence", 0) > 0:
            recovery_boost = recovery["confidence"]
            new_confidence = min(100, confidence + recovery_boost)
            # If primary verification was very weak but recovery is strong,
            # at least floor the score at recovery_boost so we don't lose the
            # signal entirely to a previous penalty.
            if new_confidence < recovery_boost:
                new_confidence = recovery_boost
            confidence = new_confidence
            # Recovery contributes a fresh independent positive signal — this
            # also helps satisfy the "≥2 independent signals" rule.
            positive_signal_count += 1
            signals.append({
                "name": f"structured_data_recovered_{recovery.get('source', 'unknown')}",
                "passed": True,
                "weight": recovery_boost,
                "detail": recovery.get("detail", "Structured-data recovery"),
            })
            # Promote extracted display name into metadata if we got one and
            # didn't already have one — useful for downstream disambiguation.
            extracted_name = recovery.get("display_name") or ""
            if extracted_name and not metadata.get("display_name"):
                metadata["display_name"] = extracted_name[:200]

    # ── Alt-endpoint recovery (Phase 3 — Unverified reduction) ──
    # If the result is still in the danger zone (Unverified/Ambiguous) OR the
    # primary request was killed by a WAF, try the site's configured alternate
    # endpoints (mobile site, JSON API, sitemap). These are typically less
    # protected and return clean 200/404 verdicts.
    if (confidence < 50 or waf_detected) and site_config.get("alt_endpoints"):
        try:
            alt_recovery = _check_alt_endpoints(site_config, username)
        except Exception:
            alt_recovery = {"recovered": False, "confidence": 0}

        if alt_recovery.get("recovered"):
            alt_conf = alt_recovery["confidence"]
            if alt_conf < 0:
                # Definitive disconfirmation — alt JSON API said "no such user".
                # Override any positive signals from the primary (which were
                # likely a WAF challenge page or generic SPA shell).
                confidence = 0
                signals.append({
                    "name": alt_recovery["signal"],
                    "passed": False,
                    "weight": -50,
                    "detail": alt_recovery["detail"],
                })
            else:
                # Positive recovery from alt endpoint.
                new_confidence = min(100, max(confidence, 0) + alt_conf)
                # Floor to alt_conf if primary was destroyed by penalties.
                if new_confidence < alt_conf:
                    new_confidence = alt_conf
                confidence = new_confidence
                positive_signal_count += 1
                signals.append({
                    "name": alt_recovery["signal"],
                    "passed": True,
                    "weight": alt_conf,
                    "detail": alt_recovery["detail"],
                })
                # If primary was WAF-blocked but alt confirms, clear the WAF
                # flag so the result presents as a clean Found instead of a
                # confused "found but blocked" entry.
                if waf_detected and alt_conf >= 40:
                    waf_detected = False

    # Determine preliminary confidence level
    confidence_level = _score_to_level(confidence)

    # ─── Secondary Confirmation for Tier 1 ───
    secondary_confirmed = None
    if needs_secondary and confidence >= 50 and not waf_detected:
        # Only do secondary confirmation if primary looks promising
        confirm_data = make_confirmation_request(
            url=probe_url, method=method, json_payload=json_payload,
            delay_range=SECONDARY_CONFIRM_DELAY,
            allow_redirects=allow_redirects,
        )

        if confirm_data["success"]:
            confirm_body = confirm_data.get("body", "")
            confirm_status = confirm_data.get("status_code", 0)

            # Re-check signals with new response
            confirm_claimed, _ = _contains_any(confirm_body, claimed_markers)
            confirm_not_claimed, _ = _contains_any(confirm_body, not_claimed_markers)
            confirm_username = _username_in_body(confirm_body, username)
            confirm_waf, _ = detect_waf(confirm_body)

            if confirm_waf:
                secondary_confirmed = False
                signals.append({
                    "name": "secondary_waf_detected",
                    "passed": False,
                    "weight": -10,
                    "detail": "Secondary confirmation blocked by anti-bot",
                })
                confidence = min(confidence, 45)
            elif confirm_not_claimed:
                secondary_confirmed = False
                signals.append({
                    "name": "secondary_negative_markers",
                    "passed": False,
                    "weight": -20,
                    "detail": "Secondary request found negative markers",
                })
                confidence = max(0, confidence - 30)
            elif confirm_claimed or confirm_username:
                secondary_confirmed = True
                signals.append({
                    "name": "secondary_confirmation_passed",
                    "passed": True,
                    "weight": 15,
                    "detail": "Independent secondary confirmation successful",
                })
                confidence = min(100, confidence + 10)
            else:
                secondary_confirmed = False
                signals.append({
                    "name": "secondary_confirmation_inconclusive",
                    "passed": False,
                    "weight": -5,
                    "detail": "Secondary confirmation did not find positive signals",
                })
                confidence = min(confidence, 65)
        else:
            signals.append({
                "name": "secondary_request_failed",
                "passed": False,
                "weight": 0,
                "detail": "Secondary confirmation request failed",
            })

    # Final confidence level
    confidence = round(min(100, max(0, confidence)), 1)
    confidence_level = _score_to_level(confidence)

    # Determine status
    if confidence >= 75:
        status = "found"
        claimed = True
    elif confidence >= 50:
        status = "found"
        claimed = True
    elif confidence >= 1:
        status = "unverified"
        claimed = False
    else:
        status = "not_found"
        claimed = False

    # Cross-reference with subject profile for corroboration
    name_match = False
    dob_match = False
    if subject_profile and metadata:
        name_match = _check_name_match(metadata, subject_profile)
        dob_match = _check_dob_match(body, subject_profile)

        if name_match:
            signals.append({
                "name": "name_corroboration",
                "passed": True,
                "weight": 10,
                "detail": "Display name matches subject profile",
            })
            confidence = min(100, confidence + 8)

        if dob_match:
            signals.append({
                "name": "dob_corroboration",
                "passed": True,
                "weight": 5,
                "detail": "DOB/age matches subject profile",
            })
            confidence = min(100, confidence + 5)

    confidence = round(min(100, max(0, confidence)), 1)
    confidence_level = _score_to_level(confidence)

    return _build_result(
        status=status,
        claimed=claimed,
        confidence=confidence,
        confidence_level=confidence_level,
        url=profile_url,
        http_status_code=status_code,
        waf_detected=waf_detected,
        response_time_ms=resp_data.get("response_time_ms", 0),
        retry_count=resp_data.get("retry_count", 0),
        signals=signals,
        metadata=metadata,
        secondary_confirmed=secondary_confirmed,
        name_match=name_match,
        dob_match=dob_match,
        cross_platform_links=metadata.get("profile_urls", []),
        response_body=body,
    )


def _check_name_match(metadata: dict, profile: dict) -> bool:
    """Check if profile display name matches subject's name or aliases."""
    display_name = (metadata.get("display_name") or "").lower()
    if not display_name:
        return False

    first = profile.get("first_name", "").lower()
    last = profile.get("last_name", "").lower()
    aliases = [a.lower() for a in profile.get("aliases", [])]

    if first and last:
        if first in display_name and last in display_name:
            return True

    for alias in aliases:
        if alias and alias in display_name:
            return True

    return False


def _check_dob_match(body: str, profile: dict) -> bool:
    """Check if any date/age in body matches subject's DOB or age range."""
    dob = profile.get("date_of_birth", "")
    if not dob or not body:
        return False

    parts = dob.split("/")
    if len(parts) == 3:
        year = parts[2]
        if year and year in body:
            return True

    return False


def _score_to_level(score: float) -> str:
    """Map confidence score to a human-readable tier.

    Tiers (police-grade defensibility):
      95-100 → Confirmed              (court-defensible)
      75-94  → High Confidence
      50-74  → Medium Confidence
      30-49  → Ambiguous              (signals contradict — needs analyst review)
      1-29   → Unverified
      0      → Not Found
    """
    if score >= 95:
        return "Confirmed"
    elif score >= 75:
        return "High Confidence"
    elif score >= 50:
        return "Medium Confidence"
    elif score >= 30:
        return "Ambiguous"
    elif score >= 1:
        return "Unverified"
    return "Not Found"


def _build_result(**kwargs) -> dict:
    """Build a standardized verification result dict."""
    return {
        "status": kwargs.get("status", "not_found"),
        "claimed": kwargs.get("claimed", False),
        "confidence": kwargs.get("confidence", 0),
        "confidence_level": kwargs.get("confidence_level", "Not Found"),
        "url": kwargs.get("url", ""),
        "http_status_code": kwargs.get("http_status_code", 0),
        "waf_detected": kwargs.get("waf_detected", False),
        "antibot_detail": kwargs.get("antibot_detail", ""),
        "rate_limited": kwargs.get("rate_limited", False),
        "response_time_ms": kwargs.get("response_time_ms", 0),
        "retry_count": kwargs.get("retry_count", 0),
        "signals": kwargs.get("signals", []),
        "metadata": kwargs.get("metadata", {}),
        "secondary_confirmed": kwargs.get("secondary_confirmed", None),
        "name_match": kwargs.get("name_match", False),
        "dob_match": kwargs.get("dob_match", False),
        "cross_platform_links": kwargs.get("cross_platform_links", []),
        "response_body": kwargs.get("response_body", ""),
    }


def clear_calibration_cache():
    """Clear the calibration cache."""
    global _calibration_cache, _calibration_cache_loaded
    _calibration_cache = {}
    _calibration_cache_loaded = True
    try:
        if os.path.exists(_CALIBRATION_CACHE_PATH):
            os.remove(_CALIBRATION_CACHE_PATH)
    except OSError:
        pass
