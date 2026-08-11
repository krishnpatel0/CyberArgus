"""
Profile Disambiguation Module — Post-fetch subject match scoring and identity clustering.

After an account is found, extracts visible profile attributes from the already-fetched
HTML and scores them against the investigator-provided SubjectProfile. Groups found
accounts into identity clusters (accounts likely belonging to the same real person).
"""

import hashlib
import re
from collections import defaultdict
from html import unescape
from typing import Optional
from urllib.parse import urlparse

# ── Evidence tier constants ───────────────────────────────────────────────────
TIER_DEFINITIVE = "DEFINITIVE"   # email / phone exact match — near-certain
TIER_HIGH       = "HIGH"         # 3+ corroborating bio signals
TIER_POSSIBLE   = "POSSIBLE"     # 1–2 bio signals
TIER_UNLIKELY   = "UNLIKELY"     # zero bio signals, name-only match


# ── Signal Extraction ────────────────────────────────────────────────────────


# OG / meta tag patterns
_OG_TITLE_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:title["\']\s+content=["\']([^"\']{2,200})["\']',
    re.IGNORECASE,
)
_OG_DESC_RE = re.compile(
    r'<meta\s+(?:property|name)=["\'](?:og:description|description)["\']\s+content=["\']([^"\']{2,500})["\']',
    re.IGNORECASE,
)
_OG_IMAGE_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:image["\']\s+content=["\']([^"\']{5,500})["\']',
    re.IGNORECASE,
)

# Location patterns common in social profiles
_LOCATION_RE = re.compile(
    r'(?:location|city|place|lives?\s+in|based\s+in|from)\s*[:\-]?\s*([A-Z][a-zA-Z\s,]{2,60})',
    re.IGNORECASE,
)

# Bio / about patterns
_BIO_RE = re.compile(
    r'(?:bio|about|description|summary)\s*[:\-]?\s*["\']?(.{10,300}?)["\']?\s*[<\n]',
    re.IGNORECASE,
)

# Links in bio — detect cross-platform profile links
_HREF_RE = re.compile(r'href=["\']?(https?://[^"\'\s>]{5,200})', re.IGNORECASE)

# Common social domains for cross-link detection
_SOCIAL_DOMAINS = {
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "github.com", "youtube.com", "t.me", "telegram.me", "reddit.com",
    "tiktok.com", "snapchat.com", "pinterest.com", "medium.com", "dev.to",
    "behance.net", "dribbble.com", "flickr.com", "tumblr.com", "twitch.tv",
    "soundcloud.com", "spotify.com", "linktr.ee", "threads.net",
}


def extract_profile_signals(html: str, url: str) -> dict:
    """
    Extract visible profile attributes from already-fetched HTML content.
    No extra HTTP requests are made — this operates on the cached response.

    Returns dict with keys:
        display_name, bio, location, avatar_url, cross_links, raw_text
    """
    if not html:
        return {}

    signals = {}

    # Display name from og:title
    m = _OG_TITLE_RE.search(html)
    if m:
        signals["display_name"] = unescape(m.group(1)).strip()

    # Bio from og:description or meta description
    m = _OG_DESC_RE.search(html)
    if m:
        signals["bio"] = unescape(m.group(1)).strip()

    # If no bio from meta, try body patterns
    if "bio" not in signals:
        m = _BIO_RE.search(html)
        if m:
            signals["bio"] = unescape(m.group(1)).strip()

    # Avatar URL from og:image
    m = _OG_IMAGE_RE.search(html)
    if m:
        signals["avatar_url"] = m.group(1).strip()

    # Location
    m = _LOCATION_RE.search(html)
    if m:
        loc = m.group(1).strip().rstrip(",.")
        if len(loc) > 2 and not loc.lower().startswith(("http", "www", "script")):
            signals["location"] = loc

    # Cross-platform links in the page
    cross_links = []
    for href_match in _HREF_RE.finditer(html):
        href = href_match.group(1)
        try:
            domain = urlparse(href).netloc.lower().lstrip("www.")
            if domain in _SOCIAL_DOMAINS:
                # Don't include self-links (same domain as the profile being checked)
                profile_domain = urlparse(url).netloc.lower().lstrip("www.")
                if domain != profile_domain:
                    cross_links.append(href)
        except Exception:
            pass
    if cross_links:
        signals["cross_links"] = list(set(cross_links))[:10]

    # Raw text for keyword matching (strip HTML tags, limit size)
    raw_text = re.sub(r'<[^>]+>', ' ', html)
    raw_text = re.sub(r'\s+', ' ', raw_text)[:3000].lower()
    signals["raw_text"] = raw_text

    return signals


# ── Subject Match Scoring ────────────────────────────────────────────────────

# Indian state names and major cities for fuzzy location matching
_INDIAN_STATES = {
    "andhra pradesh", "arunachal pradesh", "assam", "bihar", "chhattisgarh",
    "goa", "gujarat", "haryana", "himachal pradesh", "jharkhand", "karnataka",
    "kerala", "madhya pradesh", "maharashtra", "manipur", "meghalaya", "mizoram",
    "nagaland", "odisha", "punjab", "rajasthan", "sikkim", "tamil nadu",
    "telangana", "tripura", "uttar pradesh", "uttarakhand", "west bengal",
    "delhi", "chandigarh", "puducherry", "jammu", "kashmir", "ladakh",
}

_INDIAN_MAJOR_CITIES = {
    "mumbai", "delhi", "bangalore", "bengaluru", "hyderabad", "ahmedabad",
    "chennai", "kolkata", "pune", "jaipur", "lucknow", "kanpur", "nagpur",
    "indore", "thane", "bhopal", "visakhapatnam", "patna", "vadodara",
    "ghaziabad", "ludhiana", "agra", "nashik", "faridabad", "meerut",
    "rajkot", "varanasi", "srinagar", "aurangabad", "dhanbad", "amritsar",
    "navi mumbai", "allahabad", "prayagraj", "ranchi", "howrah", "coimbatore",
    "jabalpur", "gwalior", "vijayawada", "jodhpur", "madurai", "raipur",
    "kochi", "chandigarh", "mysore", "mysuru", "noida", "gurgaon", "gurugram",
}


def _text_contains(haystack: str, needle: str) -> bool:
    """Case-insensitive word-boundary check."""
    if not needle or not haystack:
        return False
    needle_lower = needle.lower().strip()
    if len(needle_lower) < 2:
        return False
    return needle_lower in haystack.lower()


def score_subject_match(
    signals: dict,
    profile_dict: dict,
) -> tuple[int, list[str]]:
    """
    Compare extracted profile signals against the SubjectProfile fields.

    Returns:
        (score: int 0-100, matched_attributes: list[str])
    """
    if not signals or not profile_dict:
        return 0, []

    score = 0
    matched = []

    # Combine all searchable text from signals
    searchable = " ".join([
        signals.get("display_name", ""),
        signals.get("bio", ""),
        signals.get("location", ""),
        signals.get("raw_text", ""),
    ]).lower()

    if not searchable.strip():
        return 0, []

    # ── City match (+20) ──
    city = profile_dict.get("city", "").strip()
    if city and _text_contains(searchable, city):
        score += 20
        matched.append(f"city:{city}")

    # ── State match (+10) ──
    state = profile_dict.get("state", "").strip()
    if state and _text_contains(searchable, state):
        score += 10
        matched.append(f"state:{state}")

    # ── Country match (+5, only if non-obvious) ──
    country = profile_dict.get("country", "").strip()
    if country and country.lower() not in ("india", "in", "us", "usa"):
        if _text_contains(searchable, country):
            score += 5
            matched.append(f"country:{country}")

    # ── Workplace/company match (+25) ──
    workplace = profile_dict.get("workplace", "").strip()
    if workplace and _text_contains(searchable, workplace):
        score += 25
        matched.append(f"workplace:{workplace}")
    for company in profile_dict.get("companies", []):
        if company and _text_contains(searchable, company):
            score += 20
            matched.append(f"company:{company}")
            break  # Only count once

    # ── Educational institution (+20) ──
    edu = profile_dict.get("educational_institution", "").strip()
    if edu and _text_contains(searchable, edu):
        score += 20
        matched.append(f"education:{edu}")

    # ── Email match (+30) ──
    for email in profile_dict.get("emails", []):
        if email and email.lower() in searchable:
            score += 30
            matched.append(f"email:{email}")
            break

    # ── Phone match (+30) ──
    for phone in profile_dict.get("phones", []):
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 7 and digits[-10:] in searchable.replace(" ", "").replace("-", ""):
            score += 30
            matched.append(f"phone:{phone}")
            break

    # ── Occupation/industry keywords (+15) ──
    occupation = profile_dict.get("occupation", "").strip()
    if occupation and _text_contains(searchable, occupation):
        score += 15
        matched.append(f"occupation:{occupation}")
    industry = profile_dict.get("industry", "").strip()
    if industry and _text_contains(searchable, industry):
        score += 10
        matched.append(f"industry:{industry}")

    # ── Display name closely matches input name (+10) ──
    display_name = signals.get("display_name", "").lower()
    first = profile_dict.get("first_name", "").lower().strip()
    last = profile_dict.get("last_name", "").lower().strip()
    if first and last and display_name:
        if first in display_name and last in display_name:
            score += 10
            matched.append("display_name_match")

    # ── Bio cross-links to another known URL (+20) ──
    known_urls = profile_dict.get("known_profile_urls", [])
    cross_links = signals.get("cross_links", [])
    if known_urls and cross_links:
        for known in known_urls:
            for found in cross_links:
                if _urls_match(known, found):
                    score += 20
                    matched.append(f"cross_link:{found}")
                    break

    return min(score, 100), matched


def _urls_match(a: str, b: str) -> bool:
    """Fuzzy URL matching — same domain and path prefix."""
    try:
        pa, pb = urlparse(a.lower().rstrip("/")), urlparse(b.lower().rstrip("/"))
        da = pa.netloc.lstrip("www.")
        db = pb.netloc.lstrip("www.")
        return da == db and pa.path.rstrip("/") == pb.path.rstrip("/")
    except Exception:
        return False


# ── Identity Clustering ──────────────────────────────────────────────────────


def cluster_identities(
    results: list[dict],
    profile_dict: dict,
) -> list[dict]:
    """
    Group found accounts into identity clusters — accounts likely belonging
    to the same real person based on shared attributes.

    Clustering signals:
    - Same display_name across platforms
    - Same avatar_url domain+path
    - Cross-platform links in bios
    - Same location string
    - High subject_match_score overlap

    Returns list of IdentityCluster dicts sorted by cluster_confidence descending.
    """
    # Only cluster found/unverified results with some signals
    found = [r for r in results if r.get("status") in ("found", "unverified")]
    if len(found) < 2:
        return []

    # Build adjacency: two results are "connected" if they share signals
    n = len(found)
    adjacency = defaultdict(set)

    for i in range(n):
        for j in range(i + 1, n):
            if _should_cluster(found[i], found[j]):
                adjacency[i].add(j)
                adjacency[j].add(i)

    # BFS to find connected components
    visited = set()
    clusters = []
    for start in range(n):
        if start in visited:
            continue
        # BFS
        component = []
        queue = [start]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            component.append(node)
            queue.extend(adjacency[node] - visited)

        if len(component) >= 2:
            cluster_results = [found[i] for i in component]
            clusters.append(_build_cluster(cluster_results, profile_dict))

    # Sort by cluster_confidence descending
    clusters.sort(key=lambda c: c.get("cluster_confidence", 0), reverse=True)
    return clusters


def _should_cluster(a: dict, b: dict) -> bool:
    """Determine if two results should be in the same identity cluster."""
    # Same display name (non-empty, at least 3 chars)
    dn_a = (a.get("display_name") or "").strip().lower()
    dn_b = (b.get("display_name") or "").strip().lower()
    if dn_a and dn_b and len(dn_a) > 2 and dn_a == dn_b:
        return True

    # Same avatar URL (compare domain + path, ignore query params)
    av_a = a.get("avatar_url", "")
    av_b = b.get("avatar_url", "")
    if av_a and av_b and _urls_match(av_a, av_b):
        return True

    # Same location string
    loc_a = (a.get("location") or "").strip().lower()
    loc_b = (b.get("location") or "").strip().lower()
    if loc_a and loc_b and len(loc_a) > 3 and loc_a == loc_b:
        return True

    # Cross-links: one profile links to the other
    links_a = set(a.get("cross_platform_links", []))
    links_b = set(b.get("cross_platform_links", []))
    url_a = a.get("url", "")
    url_b = b.get("url", "")
    if url_a and any(_urls_match(url_a, l) for l in links_b):
        return True
    if url_b and any(_urls_match(url_b, l) for l in links_a):
        return True

    # Both have high subject match scores (>= 40)
    sms_a = a.get("subject_match_score", 0)
    sms_b = b.get("subject_match_score", 0)
    if sms_a >= 40 and sms_b >= 40:
        # Only cluster if they share at least one matched attribute
        attrs_a = set(a.get("matched_attributes", []))
        attrs_b = set(b.get("matched_attributes", []))
        if attrs_a & attrs_b:
            return True

    return False


def _build_cluster(results: list[dict], profile_dict: dict) -> dict:
    """Build an IdentityCluster dict from a list of related results."""
    # Find most common display name
    names = [r.get("display_name", "") for r in results if r.get("display_name")]
    display_name = max(set(names), key=names.count) if names else ""

    # Unique locations
    locations = list(set(
        r.get("location", "") for r in results
        if r.get("location")
    ))

    # Bio snippets (first 100 chars each)
    bios = [
        r.get("bio", "")[:100]
        for r in results
        if r.get("bio")
    ]

    # All cross-links
    cross_links = []
    for r in results:
        cross_links.extend(r.get("cross_platform_links", []))
    cross_links = list(set(cross_links))[:20]

    # Average subject match score
    scores = [r.get("subject_match_score", 0) for r in results]
    avg_score = int(sum(scores) / len(scores)) if scores else 0

    # Cluster ID from first two site names
    sites = sorted(r.get("site_name", "") for r in results)
    cluster_hash = hashlib.md5("|".join(sites).encode()).hexdigest()[:8]

    return {
        "cluster_id": f"cluster_{cluster_hash}",
        "accounts": [
            {
                "site_name": r.get("site_name"),
                "url": r.get("url"),
                "username_searched": r.get("username_searched"),
                "confidence_score": r.get("confidence_score", 0),
                "confidence_level": r.get("confidence_level", ""),
                "subject_match_score": r.get("subject_match_score", 0),
                "display_name": r.get("display_name", ""),
                "location": r.get("location", ""),
            }
            for r in results
        ],
        "cluster_confidence": avg_score,
        "display_name": display_name,
        "locations": locations,
        "bio_snippets": bios[:5],
        "cross_links": cross_links,
        "account_count": len(results),
    }


# ── Evidence Chain ────────────────────────────────────────────────────────────


# Regex to extract emails from raw text
_EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# Regex to extract phone numbers (Indian + international)
_PHONE_RE = re.compile(
    r'(?:\+91[\s\-]?|0)?[6-9]\d{9}|'           # Indian mobile
    r'\+?\d{1,3}[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}'  # international
)


def build_evidence_chain(
    signals: dict,
    result: dict,
    profile_dict: dict,
) -> list[dict]:
    """
    Build a human-readable evidence chain explaining WHY an account matches
    (or doesn't match) the subject profile.

    Each item: {type, label, detail, weight, tier}
      type   — machine key e.g. "EMAIL_MATCH"
      label  — short human label e.g. "Email match"
      detail — specific value e.g. "rahul@tcs.com found in bio"
      weight — contribution to score (int)
      tier   — "definitive" | "strong" | "moderate" | "weak"
    """
    chain = []
    if not signals or not profile_dict:
        return chain

    searchable = " ".join([
        signals.get("display_name", ""),
        signals.get("bio", ""),
        signals.get("location", ""),
        signals.get("raw_text", ""),
    ]).lower()

    # ── DEFINITIVE signals ────────────────────────────────────────────────────

    # Email exact match
    for email in profile_dict.get("emails", []):
        if email and email.lower() in searchable:
            chain.append({
                "type": "EMAIL_MATCH",
                "label": "Email found in profile",
                "detail": email,
                "weight": 30,
                "tier": "definitive",
            })
            break

    # Phone match
    for phone in profile_dict.get("phones", []):
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 7 and digits[-10:] in searchable.replace(" ", "").replace("-", ""):
            chain.append({
                "type": "PHONE_MATCH",
                "label": "Phone number found in profile",
                "detail": phone,
                "weight": 30,
                "tier": "definitive",
            })
            break

    # Known URL cross-link
    known_urls = profile_dict.get("known_profile_urls", [])
    cross_links = signals.get("cross_links", [])
    for known in known_urls:
        for found in cross_links:
            if _urls_match(known, found):
                chain.append({
                    "type": "CROSS_LINK",
                    "label": "Bio links to known profile",
                    "detail": found,
                    "weight": 20,
                    "tier": "definitive",
                })
                break

    # ── STRONG signals ────────────────────────────────────────────────────────

    # Display name contains first+last name
    display_name = signals.get("display_name", "").lower()
    first = profile_dict.get("first_name", "").lower().strip()
    last = profile_dict.get("last_name", "").lower().strip()
    if first and last and display_name and first in display_name and last in display_name:
        chain.append({
            "type": "DISPLAY_NAME_MATCH",
            "label": "Display name matches subject name",
            "detail": signals.get("display_name", ""),
            "weight": 10,
            "tier": "strong",
        })

    # Workplace match
    workplace = profile_dict.get("workplace", "").strip()
    if workplace and _text_contains(searchable, workplace):
        chain.append({
            "type": "WORKPLACE_MATCH",
            "label": "Workplace mentioned in profile",
            "detail": workplace,
            "weight": 25,
            "tier": "strong",
        })

    # Company names
    for company in profile_dict.get("companies", []):
        if company and _text_contains(searchable, company):
            chain.append({
                "type": "COMPANY_MATCH",
                "label": "Company name found in profile",
                "detail": company,
                "weight": 20,
                "tier": "strong",
            })
            break

    # ── MODERATE signals ──────────────────────────────────────────────────────

    # City match
    city = profile_dict.get("city", "").strip()
    if city and _text_contains(searchable, city):
        chain.append({
            "type": "CITY_MATCH",
            "label": "City matches",
            "detail": city,
            "weight": 20,
            "tier": "moderate",
        })

    # State match
    state = profile_dict.get("state", "").strip()
    if state and _text_contains(searchable, state):
        chain.append({
            "type": "STATE_MATCH",
            "label": "State/region matches",
            "detail": state,
            "weight": 10,
            "tier": "moderate",
        })

    # Educational institution
    edu = profile_dict.get("educational_institution", "").strip()
    if edu and _text_contains(searchable, edu):
        chain.append({
            "type": "EDUCATION_MATCH",
            "label": "Educational institution found",
            "detail": edu,
            "weight": 20,
            "tier": "moderate",
        })

    # Occupation keyword
    occupation = profile_dict.get("occupation", "").strip()
    if occupation and _text_contains(searchable, occupation):
        chain.append({
            "type": "OCCUPATION_MATCH",
            "label": "Occupation keyword found",
            "detail": occupation,
            "weight": 15,
            "tier": "moderate",
        })

    # Industry keyword
    industry = profile_dict.get("industry", "").strip()
    if industry and _text_contains(searchable, industry):
        chain.append({
            "type": "INDUSTRY_MATCH",
            "label": "Industry keyword found",
            "detail": industry,
            "weight": 10,
            "tier": "moderate",
        })

    # ── WEAK signals ──────────────────────────────────────────────────────────

    # Username searched is a known username
    username_searched = result.get("username_searched", "").lower().strip()
    known_usernames = [u.lower().strip() for u in profile_dict.get("usernames", []) if u]
    if username_searched and username_searched in known_usernames:
        chain.append({
            "type": "USERNAME_EXACT",
            "label": "Exact username match",
            "detail": f"@{username_searched}",
            "weight": 15,
            "tier": "strong",
        })
    elif username_searched and known_usernames:
        # Check if it's a permutation of a known username
        for ku in known_usernames:
            base = re.sub(r'[._\-\s\d]', '', ku)
            variant = re.sub(r'[._\-\s\d]', '', username_searched)
            if base and variant and base == variant and ku != username_searched:
                chain.append({
                    "type": "USERNAME_VARIANT",
                    "label": "Username variant of known username",
                    "detail": f"@{username_searched} ≈ @{ku}",
                    "weight": 8,
                    "tier": "weak",
                })
                break

    # Name in first/last name fields only (no bio corroboration)
    if first and last and not any(e["type"] == "DISPLAY_NAME_MATCH" for e in chain):
        full_name = f"{first} {last}"
        if _text_contains(searchable, full_name):
            chain.append({
                "type": "NAME_IN_BIO",
                "label": "Subject name found in bio text",
                "detail": full_name.title(),
                "weight": 5,
                "tier": "weak",
            })

    return chain


def calculate_disambiguation_tier(evidence_chain: list[dict]) -> str:
    """
    Assign a disambiguation tier based on the evidence chain.

    DEFINITIVE — has at least one definitive signal (email/phone/known URL)
    HIGH       — 3+ strong/moderate signals
    POSSIBLE   — 1–2 signals of any type
    UNLIKELY   — no signals
    """
    if not evidence_chain:
        return TIER_UNLIKELY

    has_definitive = any(e["tier"] == "definitive" for e in evidence_chain)
    if has_definitive:
        return TIER_DEFINITIVE

    strong_or_higher = [e for e in evidence_chain if e["tier"] in ("definitive", "strong", "moderate")]
    if len(strong_or_higher) >= 3:
        return TIER_HIGH
    if len(evidence_chain) >= 1:
        return TIER_POSSIBLE

    return TIER_UNLIKELY


def extract_new_anchors(signals: dict, profile_dict: dict) -> dict:
    """
    Extract identifiers found in a profile's bio/raw_text that were NOT
    in the original subject profile — these are pivot candidates.

    Returns:
        {
          "emails": [...],
          "phones": [...],
          "profile_urls": [...]   # social links found in bio
        }
    """
    raw = signals.get("raw_text", "") + " " + signals.get("bio", "")
    if not raw.strip():
        return {}

    known_emails = {e.lower() for e in profile_dict.get("emails", []) if e}
    known_phones_digits = set()
    for p in profile_dict.get("phones", []):
        d = re.sub(r'\D', '', p)
        if d:
            known_phones_digits.add(d[-10:])

    new_emails = []
    for m in _EMAIL_RE.finditer(raw):
        email = m.group(0).lower()
        if email not in known_emails and not email.endswith((".png", ".jpg", ".gif", ".webp")):
            new_emails.append(email)

    new_phones = []
    for m in _PHONE_RE.finditer(raw):
        phone = m.group(0).strip()
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 10 and digits[-10:] not in known_phones_digits:
            new_phones.append(phone)

    # Social profile URLs from cross_links that aren't in known_profile_urls
    known_urls = set(profile_dict.get("known_profile_urls", []))
    new_profile_urls = [
        url for url in signals.get("cross_links", [])
        if url not in known_urls
    ]

    result = {}
    if new_emails:
        result["emails"] = list(dict.fromkeys(new_emails))[:5]
    if new_phones:
        result["phones"] = list(dict.fromkeys(new_phones))[:5]
    if new_profile_urls:
        result["profile_urls"] = new_profile_urls[:5]
    return result


def calculate_profile_strength(profile_dict: dict) -> dict:
    """
    Calculate how well the investigator's profile will disambiguate results.

    Returns a dict with:
      score     — 0-100 overall strength
      level     — "STRONG" | "MODERATE" | "WEAK"
      anchors   — list of {name, present, power} for each identifier type
      advice    — human-readable suggestion to improve
    """
    anchors = []
    score = 0

    def _has(field):
        v = profile_dict.get(field)
        if isinstance(v, list):
            return any(bool(x) for x in v)
        return bool(v and str(v).strip())

    # Definitive anchors
    has_email = _has("emails")
    has_phone = _has("phones")
    has_photo = _has("profile_picture_url")
    # Strong anchors
    has_username = _has("usernames")
    has_workplace = _has("workplace") or _has("companies")
    has_education = _has("educational_institution")
    # Moderate anchors
    has_city = _has("city")
    has_state = _has("state")
    has_full_name = _has("first_name") and _has("last_name")
    # Weak
    has_first_only = _has("first_name") and not _has("last_name")

    if has_email:
        score += 35
        anchors.append({"name": "Email", "present": True, "power": "definitive", "icon": "📧"})
    else:
        anchors.append({"name": "Email", "present": False, "power": "definitive", "icon": "📧"})

    if has_phone:
        score += 30
        anchors.append({"name": "Phone", "present": True, "power": "definitive", "icon": "📱"})
    else:
        anchors.append({"name": "Phone", "present": False, "power": "definitive", "icon": "📱"})

    if has_photo:
        score += 15
        anchors.append({"name": "Profile Photo", "present": True, "power": "strong", "icon": "🖼️"})
    else:
        anchors.append({"name": "Profile Photo", "present": False, "power": "strong", "icon": "🖼️"})

    if has_username:
        score += 20
        anchors.append({"name": "Username", "present": True, "power": "strong", "icon": "👤"})
    else:
        anchors.append({"name": "Username", "present": False, "power": "strong", "icon": "👤"})

    if has_workplace:
        score += 15
        anchors.append({"name": "Workplace", "present": True, "power": "strong", "icon": "🏢"})
    else:
        anchors.append({"name": "Workplace", "present": False, "power": "strong", "icon": "🏢"})

    if has_education:
        score += 10
        anchors.append({"name": "Education", "present": True, "power": "moderate", "icon": "🎓"})
    else:
        anchors.append({"name": "Education", "present": False, "power": "moderate", "icon": "🎓"})

    if has_city:
        score += 10
        anchors.append({"name": "City", "present": True, "power": "moderate", "icon": "📍"})
    else:
        anchors.append({"name": "City", "present": False, "power": "moderate", "icon": "📍"})

    if has_full_name:
        score += 5
        anchors.append({"name": "Full Name", "present": True, "power": "weak", "icon": "🏷️"})
    else:
        anchors.append({"name": "Full Name", "present": False, "power": "weak", "icon": "🏷️"})

    score = min(score, 100)

    if score >= 60:
        level = "STRONG"
    elif score >= 25:
        level = "MODERATE"
    else:
        level = "WEAK"

    # Build advice
    advice = ""
    if not has_email and not has_phone:
        advice = "Add email or phone number for definitive identification — these are the strongest disambiguation anchors."
    elif not has_email:
        advice = "Adding a known email address would greatly improve accuracy."
    elif not has_phone:
        advice = "Adding a phone number would strengthen confirmation."
    elif not has_username and not has_workplace:
        advice = "Add a known username or workplace to help filter out same-name accounts."
    elif not has_city:
        advice = "Adding the subject's city will help filter results from different regions."

    return {
        "score": score,
        "level": level,
        "anchors": anchors,
        "advice": advice,
    }
