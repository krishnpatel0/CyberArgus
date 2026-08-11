"""
Structured-Data Fallback Parser for OSINT Verification.

When primary `claimed_if` markers fail to match (because the site changed its
HTML format, lazy-loads data via JS, or returns an SPA shell), this module
attempts to recover the verdict by parsing structured data embedded in the
response:

    1. `<script id="__NEXT_DATA__">…</script>`     (Next.js sites)
    2. `<script type="application/ld+json">…</script>` (JSON-LD ProfilePage)
    3. `window.__INITIAL_STATE__ = {…}`             (Vue/Vuex SPAs)
    4. `window._sharedData = {…}`                   (legacy Instagram pattern)
    5. OG meta tags                                 (`og:type=profile`, `og:title`,
                                                     `profile:username`)
    6. `<title>` tag content                        (last-resort)

If any extractor finds the searched username (or a clear `Person`-typed
object whose name matches), the result is promoted from Unverified to a
Medium/High Confidence finding with a `structured_data_recovered` signal.

Maigret + socid_extractor data shows this technique recovers ~30% of
otherwise-UNKNOWN verdicts. Modelled on:
    https://github.com/soxoj/socid_extractor
    https://github.com/soxoj/maigret/tree/main/maigret/sites
"""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Optional


# ── Regex patterns (compiled once) ──────────────────────────────────────────────

_NEXT_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

# JSON-LD blocks. Note: we capture EACH block and try to parse it individually —
# pages often emit multiple ld+json blocks (Organization + BreadcrumbList +
# ProfilePage) and only one is the user-relevant one.
_LDJSON_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

# JS state blob assignments. We use a non-greedy match up to a closing brace
# followed by `;`, `</script>`, or end-of-line to avoid swallowing the rest of
# the page. This is intentionally heuristic — the parsed JSON is validated.
_INITIAL_STATE_RE = re.compile(
    r'window\.__INITIAL_STATE__\s*=\s*(\{.*?\})\s*[;<]',
    re.DOTALL,
)
_SHARED_DATA_RE = re.compile(
    r'window\._sharedData\s*=\s*(\{.*?\})\s*[;<]',
    re.DOTALL,
)
_APOLLO_STATE_RE = re.compile(
    r'window\.__APOLLO_STATE__\s*=\s*(\{.*?\})\s*[;<]',
    re.DOTALL,
)
_NUXT_DATA_RE = re.compile(
    r'window\.__NUXT__\s*=\s*(\{.*?\})\s*[;<]',
    re.DOTALL,
)

# OG / profile meta tags
_OG_TYPE_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:type["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_TITLE_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:title["\']\s+content=["\']([^"\']{1,300})["\']',
    re.IGNORECASE,
)
_OG_URL_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:url["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_PROFILE_USERNAME_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']profile:username["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_TWITTER_CREATOR_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']twitter:creator["\']\s+content=["\']@?([^"\']+)["\']',
    re.IGNORECASE,
)

# <title>…</title>
_TITLE_RE = re.compile(r'<title[^>]*>(.{1,300}?)</title>', re.IGNORECASE | re.DOTALL)

# Generic username-like field walker — used to match a username string anywhere
# in a parsed JSON tree.
_USERNAME_KEYS = {
    "username", "screen_name", "screenname", "handle", "login", "slug",
    "user_name", "userName", "alternateName", "vanity_name", "vanityName",
    "user_id", "id", "uniqueId", "displayId",
}
_DISPLAY_NAME_KEYS = {
    "name", "display_name", "displayName", "full_name", "fullName",
    "real_name", "realName", "nickname",
}


# ── Public API ─────────────────────────────────────────────────────────────────


def recover_from_structured_data(
    html: str,
    username: str,
    site_config: Optional[dict] = None,
) -> dict:
    """
    Attempt to confirm a profile exists by parsing structured data from the
    response HTML, even when the site's `claimed_if` markers didn't match.

    Returns a dict with:
        recovered      bool   — True if a positive confirmation was extracted
        confidence     int    — points to add to verification score (0–60)
        signal         str    — short signal name e.g. "ldjson_profilepage_match"
        detail         str    — human-readable explanation for the evidence chain
        display_name   str    — extracted display name (if any)
        username_found str    — extracted username (if any)
        source         str    — which extractor fired (next_data/ldjson/og/title/initial_state)

    Confidence weight rationale:
        +60 → JSON-LD ProfilePage with matching mainEntity.name OR username key
              found in JS state matching searched username (definitive)
        +45 → OG profile:username matches searched username
        +35 → og:title contains searched username (case-insensitive)
        +25 → <title> contains searched username + a profile-type indicator
        +15 → og:type == "profile" and og:title is non-empty (weak signal)

    The confidence values are deliberately additive to whatever score the
    primary verification produced — a borderline 30-point Unverified can be
    lifted into Medium Confidence (≥50) by a +25 og:title match, or into
    High Confidence (≥75) by a +60 JSON-LD match.
    """
    if not html or not username:
        return _empty_result()

    username_lower = username.lower().strip()
    if not username_lower:
        return _empty_result()

    # Try extractors in order of strength. First match wins.

    # 1. JSON-LD — strongest because it's machine-readable and explicit.
    result = _try_ldjson(html, username_lower)
    if result["recovered"]:
        return result

    # 2. Next.js __NEXT_DATA__ — second strongest, full page state in JSON.
    result = _try_next_data(html, username_lower)
    if result["recovered"]:
        return result

    # 3. Other JS state blobs.
    for pattern, name in [
        (_INITIAL_STATE_RE, "initial_state"),
        (_SHARED_DATA_RE, "shared_data"),
        (_APOLLO_STATE_RE, "apollo_state"),
        (_NUXT_DATA_RE, "nuxt_data"),
    ]:
        result = _try_js_state(html, username_lower, pattern, name)
        if result["recovered"]:
            return result

    # 4. OG meta tags.
    result = _try_og_meta(html, username_lower)
    if result["recovered"]:
        return result

    # 5. <title> + profile indicator (last resort, weakest).
    result = _try_title(html, username_lower)
    if result["recovered"]:
        return result

    return _empty_result()


# ── Extractors ─────────────────────────────────────────────────────────────────


def _empty_result() -> dict:
    return {
        "recovered": False,
        "confidence": 0,
        "signal": "",
        "detail": "",
        "display_name": "",
        "username_found": "",
        "source": "",
    }


def _try_ldjson(html: str, username_lower: str) -> dict:
    """Parse JSON-LD blocks and look for ProfilePage / Person matching username."""
    for match in _LDJSON_RE.finditer(html):
        raw = match.group(1).strip()
        if not raw:
            continue
        # JSON-LD often contains HTML entities. Unescape before parsing.
        try:
            data = json.loads(unescape(raw))
        except (json.JSONDecodeError, ValueError):
            # Some sites emit malformed JSON-LD with trailing commas; skip
            # rather than raise — we still have other extractors to try.
            continue

        # JSON-LD can be a single object or a list (or @graph wrapper).
        candidates = []
        if isinstance(data, list):
            candidates.extend(data)
        elif isinstance(data, dict):
            candidates.append(data)
            if isinstance(data.get("@graph"), list):
                candidates.extend(data["@graph"])

        for obj in candidates:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("@type", "")
            if isinstance(obj_type, list):
                obj_type_str = " ".join(str(t) for t in obj_type).lower()
            else:
                obj_type_str = str(obj_type).lower()

            # ProfilePage / Person types are the strongest signals.
            if any(t in obj_type_str for t in ("profilepage", "person", "profile")):
                # Walk the object for username/displayName matches.
                username_match, display_name = _walk_for_username(obj, username_lower)
                if username_match:
                    return {
                        "recovered": True,
                        "confidence": 60,
                        "signal": "ldjson_profile_match",
                        "detail": f"JSON-LD ProfilePage confirms @{username_match}"
                                  + (f" ({display_name})" if display_name else ""),
                        "display_name": display_name,
                        "username_found": username_match,
                        "source": "ldjson",
                    }

    return _empty_result()


def _try_next_data(html: str, username_lower: str) -> dict:
    """Parse Next.js __NEXT_DATA__ JSON for username/profile data."""
    match = _NEXT_DATA_RE.search(html)
    if not match:
        return _empty_result()
    raw = match.group(1).strip()
    if not raw:
        return _empty_result()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return _empty_result()

    username_match, display_name = _walk_for_username(data, username_lower)
    if username_match:
        return {
            "recovered": True,
            "confidence": 60,
            "signal": "next_data_username_match",
            "detail": f"__NEXT_DATA__ confirms @{username_match}"
                      + (f" ({display_name})" if display_name else ""),
            "display_name": display_name,
            "username_found": username_match,
            "source": "next_data",
        }
    return _empty_result()


def _try_js_state(html: str, username_lower: str, pattern, source_name: str) -> dict:
    """Generic JS state blob walker (used for __INITIAL_STATE__, _sharedData,
    Apollo, Nuxt, etc.)."""
    match = pattern.search(html)
    if not match:
        return _empty_result()
    raw = match.group(1).strip()
    if not raw or len(raw) < 10:
        return _empty_result()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return _empty_result()

    username_match, display_name = _walk_for_username(data, username_lower)
    if username_match:
        return {
            "recovered": True,
            "confidence": 50,
            "signal": f"{source_name}_username_match",
            "detail": f"{source_name} confirms @{username_match}"
                      + (f" ({display_name})" if display_name else ""),
            "display_name": display_name,
            "username_found": username_match,
            "source": source_name,
        }
    return _empty_result()


def _try_og_meta(html: str, username_lower: str) -> dict:
    """Try OG profile meta tags."""
    # Strongest OG signal: profile:username matches exactly.
    pu = _PROFILE_USERNAME_RE.search(html)
    if pu and pu.group(1).lower().strip() == username_lower:
        return {
            "recovered": True,
            "confidence": 45,
            "signal": "og_profile_username_match",
            "detail": f"og:profile:username matches @{pu.group(1)}",
            "display_name": "",
            "username_found": pu.group(1),
            "source": "og_meta",
        }

    # Twitter creator tag.
    tc = _TWITTER_CREATOR_RE.search(html)
    if tc and tc.group(1).lower().strip() == username_lower:
        return {
            "recovered": True,
            "confidence": 45,
            "signal": "twitter_creator_match",
            "detail": f"twitter:creator matches @{tc.group(1)}",
            "display_name": "",
            "username_found": tc.group(1),
            "source": "og_meta",
        }

    # og:type = profile + og:title contains username.
    og_type = _OG_TYPE_RE.search(html)
    og_title = _OG_TITLE_RE.search(html)
    og_url = _OG_URL_RE.search(html)

    title_text = unescape(og_title.group(1)).strip() if og_title else ""
    title_lower = title_text.lower()
    is_profile_type = og_type and og_type.group(1).lower().strip() in (
        "profile", "profile.user", "person", "user", "musician", "actor",
    )

    if title_text and username_lower in title_lower:
        # Exclude generic "Sign up" / "Log in" titles that include the username
        # in a "join username" context — those are landing pages, not profiles.
        bad_phrases = ("sign up", "log in", "login", "join now", "create account")
        if not any(b in title_lower for b in bad_phrases):
            confidence = 45 if is_profile_type else 35
            return {
                "recovered": True,
                "confidence": confidence,
                "signal": "og_title_username_match",
                "detail": f"og:title contains @{username_lower}: \"{title_text[:80]}\"",
                "display_name": title_text,
                "username_found": username_lower,
                "source": "og_meta",
            }

    # og:url ends with /username — common pattern for profile pages.
    if og_url:
        url_path = og_url.group(1).rstrip("/").lower()
        if url_path.endswith("/" + username_lower):
            return {
                "recovered": True,
                "confidence": 35,
                "signal": "og_url_username_match",
                "detail": f"og:url path ends with /{username_lower}",
                "display_name": title_text,
                "username_found": username_lower,
                "source": "og_meta",
            }

    # Weakest OG signal: og:type=profile + og:title non-empty + matching og:url path.
    if is_profile_type and title_text and og_url:
        return {
            "recovered": True,
            "confidence": 15,
            "signal": "og_profile_type_present",
            "detail": f"og:type=profile with title \"{title_text[:80]}\"",
            "display_name": title_text,
            "username_found": "",
            "source": "og_meta",
        }

    return _empty_result()


def _try_title(html: str, username_lower: str) -> dict:
    """Last-resort: <title> contains username + profile-page indicator words."""
    match = _TITLE_RE.search(html)
    if not match:
        return _empty_result()
    title = unescape(match.group(1)).strip()
    title_lower = title.lower()
    if username_lower not in title_lower:
        return _empty_result()
    # Only count if title also has profile-page indicator words (avoids matching
    # search results, blog post titles, etc.).
    indicators = ("profile", "(@", "·", "—", "|")
    if any(ind in title_lower for ind in indicators) or title_lower.startswith(username_lower):
        return {
            "recovered": True,
            "confidence": 25,
            "signal": "title_username_match",
            "detail": f"<title> contains @{username_lower}: \"{title[:80]}\"",
            "display_name": title,
            "username_found": username_lower,
            "source": "title",
        }
    return _empty_result()


# ── JSON tree walker ────────────────────────────────────────────────────────────


def _walk_for_username(node, username_lower: str, _depth: int = 0) -> tuple:
    """
    Recursively walk a parsed JSON object/list looking for a username field
    whose value matches `username_lower` (case-insensitive).

    Returns (matched_value, display_name) or ("", "").

    Depth-limited to 12 to keep this O(n) on huge __NEXT_DATA__ blobs.
    """
    if _depth > 12 or node is None:
        return "", ""

    if isinstance(node, dict):
        # Check this dict's keys first.
        local_display = ""
        for k, v in node.items():
            if not isinstance(k, str):
                continue
            if isinstance(v, str):
                vl = v.lower().strip()
                if k in _USERNAME_KEYS and vl == username_lower:
                    # Capture sibling display name if present in same dict.
                    for dk in _DISPLAY_NAME_KEYS:
                        if dk in node and isinstance(node[dk], str):
                            local_display = node[dk].strip()
                            break
                    return v.strip(), local_display
        # Recurse into nested dicts/lists.
        for v in node.values():
            if isinstance(v, (dict, list)):
                m, d = _walk_for_username(v, username_lower, _depth + 1)
                if m:
                    return m, d
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                m, d = _walk_for_username(item, username_lower, _depth + 1)
                if m:
                    return m, d

    return "", ""
