"""
SERP-based Account Discovery — pre-pass that queries search engines to find
profile URLs the username-permutation engine would never guess (vanity
handles, name + context dorks, mentions in forums/PDFs/leaks).

Backends (priority order, first available wins per query):
  1. SearXNG instance      — set OSINT_SEARXNG_URL=https://your.searx.host
  2. DuckDuckGo HTML       — keyless default, always available
  3. Bing Web Search v7    — set BING_SEARCH_API_KEY
  4. Google CSE            — set GOOGLE_CSE_API_KEY + GOOGLE_CSE_ID

Pipeline:
  build_dorks(profile, sites)  →  query backend  →  parse SERP urls
    →  reverse-map url to (site_name, candidate_username)
    →  score candidate (rank, snippet match, domain trust)
    →  return top discoveries, deduped, capped per site
"""

from __future__ import annotations

import os
import re
import time
import json
import html
from urllib.parse import urlparse, quote_plus, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

from .http_client import make_request


# ── Config ───────────────────────────────────────────────────────────────────

SEARXNG_URL = os.environ.get("OSINT_SEARXNG_URL", "").rstrip("/")
BING_KEY = os.environ.get("BING_SEARCH_API_KEY", "")
GOOGLE_CSE_KEY = os.environ.get("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_ID = os.environ.get("GOOGLE_CSE_ID", "")

MAX_DORKS_PER_INVESTIGATION = int(os.environ.get("OSINT_SERP_MAX_DORKS", "30"))
MAX_RESULTS_PER_DORK = int(os.environ.get("OSINT_SERP_MAX_RESULTS", "10"))
MAX_DISCOVERIES_PER_SITE = int(os.environ.get("OSINT_SERP_MAX_PER_SITE", "5"))
MAX_OPEN_DORKS = int(os.environ.get("OSINT_SERP_MAX_OPEN_DORKS", "6"))
MAX_EXTERNAL_DISCOVERIES = int(os.environ.get("OSINT_SERP_MAX_EXTERNAL", "20"))
MIN_EXTERNAL_SCORE = int(os.environ.get("OSINT_SERP_MIN_EXTERNAL_SCORE", "30"))
SERP_CONCURRENCY = int(os.environ.get("OSINT_SERP_CONCURRENCY", "3"))
SERP_DELAY_RANGE = (1.5, 3.5)
SERP_VERIFY_EXTERNAL = os.environ.get("OSINT_SERP_VERIFY_EXTERNAL", "1") not in ("0", "false", "False")

# Domains we never surface as external discoveries (noise, aggregators, generic).
OFF_LIST_BLOCKLIST = {
    "wikipedia.org", "wikimedia.org", "wiktionary.org", "google.com",
    "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com", "yandex.com",
    "archive.org", "web.archive.org", "translate.google.com", "cache.google.com",
    "pastebin.com",  # too noisy; keep out of off-list (leaks get handled elsewhere)
}

# URL path patterns that look like a user/profile page.
PROFILE_PATH_RES = [
    re.compile(r"^/@([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/u/([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/user/([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/users/([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/profile/([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/member/([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/people/([A-Za-z0-9._\-]{2,50})/?$"),
    re.compile(r"^/in/([A-Za-z0-9._\-]{2,50})/?$"),        # linkedin-style
    re.compile(r"^/([A-Za-z0-9._\-]{3,40})/?$"),           # single-segment slug
]

# Path fragments that mean "this is NOT a profile page" — news, search, article.
NON_PROFILE_PATH_MARKERS = (
    "/search", "/articles/", "/article/", "/news/", "/blog/", "/posts/",
    "/category/", "/tag/", "/topics/", "/help/", "/support/", "/login",
    "/signup", "/register", "/about", "/privacy", "/terms", "/contact",
    "/download", "/page/", "/archive/", "/wiki/",
)

# Indian-priority sites — dorks against these get built first
INDIA_PRIORITY_DOMAINS = {
    "linkedin.com", "naukri.com", "shine.com", "internshala.com", "apna.co",
    "sharechat.com", "koo.app", "instagram.com", "facebook.com", "x.com",
    "twitter.com", "youtube.com", "shaadi.com", "bharatmatrimony.com",
    "jeevansathi.com", "justdial.com", "sulekha.com", "indiamart.com",
    "tradeindia.com", "olx.in", "quikr.com", "practo.com", "zomato.com",
    "flipkart.com", "amazon.in", "github.com", "medium.com",
}


# ── Site URL pattern reversal ────────────────────────────────────────────────

# Compiled per call from sites_config. For e.g. "https://github.com/{}"
# we build a regex that captures the username segment.
def _compile_site_matchers(sites_config: dict) -> list[dict]:
    """
    Build {domain, regex, site_name, tier} list from sites_config so we can
    reverse-match SERP URLs back to (site, username).
    """
    matchers = []
    for site_name, cfg in sites_config.items():
        if site_name.startswith("_"):
            continue
        url_tpl = cfg.get("url", "")
        if "{}" not in url_tpl:
            continue
        try:
            parsed = urlparse(url_tpl.replace("{}", "USERNAME_PLACEHOLDER"))
            domain = parsed.netloc.lower().lstrip("www.")
            path_tpl = parsed.path
            # Build regex: escape path, then replace placeholder with capture
            path_escaped = re.escape(path_tpl).replace(
                "USERNAME_PLACEHOLDER", r"([A-Za-z0-9._\-]{2,50})"
            )
            full_re = re.compile(
                rf"^https?://(?:www\.|m\.)?{re.escape(domain)}{path_escaped}/?$",
                re.IGNORECASE,
            )
            matchers.append({
                "site_name": site_name,
                "domain": domain,
                "regex": full_re,
                "tier": cfg.get("tier", 3),
                "url_format": cfg.get("username_format", ""),
            })
        except Exception:
            continue
    # Tier 1 / India-priority first so dork generation prefers them
    matchers.sort(key=lambda m: (
        m["tier"],
        0 if m["domain"] in INDIA_PRIORITY_DOMAINS else 1,
    ))
    return matchers


# ── Dork generation ──────────────────────────────────────────────────────────

def build_dorks(profile_dict: dict, matchers: list[dict]) -> list[dict]:
    """
    Build a prioritized list of search dorks. Each dork: {query, target_domain,
    candidate_sites: [site_name,...], reason}.
    """
    first = (profile_dict.get("first_name") or "").strip()
    last = (profile_dict.get("last_name") or "").strip()
    full_name = f"{first} {last}".strip()
    usernames = [u for u in (profile_dict.get("usernames") or []) if u]
    city = (profile_dict.get("city") or "").strip()
    workplace = (profile_dict.get("workplace") or "").strip()
    edu = (profile_dict.get("educational_institution") or "").strip()
    emails = [e for e in (profile_dict.get("emails") or []) if e]
    phones = [p for p in (profile_dict.get("phones") or []) if p]

    dorks: list[dict] = []
    seen_queries = set()

    def _add(q: str, domain: str, site_name: str, reason: str):
        key = q.lower()
        if key in seen_queries:
            return
        seen_queries.add(key)
        dorks.append({
            "query": q,
            "target_domain": domain,
            "site_name": site_name,
            "reason": reason,
        })

    # ── Identifier dorks (highest precision) ─────────────────────────────────
    # Email and phone in quotes; no site filter — let any match surface
    for em in emails[:2]:
        _add(f'"{em}"', "", "", "email_global")
    for ph in phones[:2]:
        digits = re.sub(r'\D', '', ph)
        if len(digits) >= 10:
            _add(f'"{digits[-10:]}"', "", "", "phone_global")

    # ── Open dorks (no site: filter) — catches off-list platforms ──
    open_count = 0
    for u in usernames[:2]:
        if open_count >= MAX_OPEN_DORKS: break
        _add(f'"{u}"', "", "", "open_username"); open_count += 1
    for u in usernames[:2]:
        if open_count >= MAX_OPEN_DORKS: break
        _add(f'"{u}" profile', "", "", "open_username_profile"); open_count += 1
    if full_name and len(full_name) > 3 and city:
        if open_count < MAX_OPEN_DORKS:
            _add(f'"{full_name}" "{city}"', "", "", "open_name_city"); open_count += 1
    if full_name and len(full_name) > 3 and workplace:
        if open_count < MAX_OPEN_DORKS:
            _add(f'"{full_name}" "{workplace}"', "", "", "open_name_workplace"); open_count += 1
    if full_name and len(full_name) > 3 and edu:
        if open_count < MAX_OPEN_DORKS:
            _add(f'"{full_name}" "{edu}"', "", "", "open_name_edu"); open_count += 1

    # ── Per-site name + context dorks (Tier 1 first) ─────────────────────────
    contexts = [c for c in [city, workplace, edu] if c]
    for m in matchers:
        if len(dorks) >= MAX_DORKS_PER_INVESTIGATION:
            break
        domain = m["domain"]
        site = m["site_name"]

        # Username + site (most precise when we have a username hint)
        for u in usernames[:2]:
            _add(f'"{u}" site:{domain}', domain, site, "username_site")

        # Full name + site
        if full_name and len(full_name) > 3:
            _add(f'"{full_name}" site:{domain}', domain, site, "name_site")

        # Full name + context + site
        if full_name and contexts:
            ctx = contexts[0]
            _add(f'"{full_name}" "{ctx}" site:{domain}', domain, site, "name_context_site")

    return dorks[:MAX_DORKS_PER_INVESTIGATION]


# ── Backends ─────────────────────────────────────────────────────────────────

def _backend_searxng(query: str) -> list[dict]:
    if not SEARXNG_URL:
        return []
    url = f"{SEARXNG_URL}/search?q={quote_plus(query)}&format=json&safesearch=0"
    res = make_request(url, delay_range=SERP_DELAY_RANGE, timeout=12)
    if not res.get("success") or not res.get("body"):
        return []
    try:
        data = json.loads(res["body"])
    except Exception:
        return []
    out = []
    for r in (data.get("results") or [])[:MAX_RESULTS_PER_DORK]:
        out.append({
            "url": r.get("url", ""),
            "title": r.get("title", ""),
            "snippet": r.get("content", ""),
        })
    return out


_DDG_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>'
    r'.*?<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)


def _backend_duckduckgo(query: str) -> list[dict]:
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    res = make_request(url, delay_range=SERP_DELAY_RANGE, timeout=12)
    if not res.get("success") or not res.get("body"):
        return []
    body = res["body"]
    out = []
    for m in _DDG_RESULT_RE.finditer(body):
        raw_href = m.group(1)
        # DDG wraps urls: //duckduckgo.com/l/?uddg=https%3A%2F%2F...
        actual = _unwrap_ddg_url(raw_href)
        if not actual:
            continue
        title = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        snippet = re.sub(r'<[^>]+>', '', m.group(3)).strip()
        out.append({
            "url": html.unescape(actual),
            "title": html.unescape(title),
            "snippet": html.unescape(snippet),
        })
        if len(out) >= MAX_RESULTS_PER_DORK:
            break
    return out


def _unwrap_ddg_url(href: str) -> str:
    if href.startswith("//"):
        href = "https:" + href
    try:
        parsed = urlparse(href)
        if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
            qs = parse_qs(parsed.query)
            return unquote(qs.get("uddg", [""])[0])
    except Exception:
        pass
    return href if href.startswith("http") else ""


def _backend_bing(query: str) -> list[dict]:
    if not BING_KEY:
        return []
    url = f"https://api.bing.microsoft.com/v7.0/search?q={quote_plus(query)}&count={MAX_RESULTS_PER_DORK}&mkt=en-IN"
    res = make_request(
        url, delay_range=SERP_DELAY_RANGE, timeout=12,
        headers={"Ocp-Apim-Subscription-Key": BING_KEY},
    )
    if not res.get("success") or not res.get("body"):
        return []
    try:
        data = json.loads(res["body"])
    except Exception:
        return []
    out = []
    for r in (data.get("webPages", {}).get("value") or [])[:MAX_RESULTS_PER_DORK]:
        out.append({
            "url": r.get("url", ""),
            "title": r.get("name", ""),
            "snippet": r.get("snippet", ""),
        })
    return out


def _backend_google_cse(query: str) -> list[dict]:
    if not (GOOGLE_CSE_KEY and GOOGLE_CSE_ID):
        return []
    url = (
        f"https://www.googleapis.com/customsearch/v1?key={GOOGLE_CSE_KEY}"
        f"&cx={GOOGLE_CSE_ID}&q={quote_plus(query)}&num={min(MAX_RESULTS_PER_DORK, 10)}&gl=in"
    )
    res = make_request(url, delay_range=SERP_DELAY_RANGE, timeout=12)
    if not res.get("success") or not res.get("body"):
        return []
    try:
        data = json.loads(res["body"])
    except Exception:
        return []
    out = []
    for r in (data.get("items") or [])[:MAX_RESULTS_PER_DORK]:
        out.append({
            "url": r.get("link", ""),
            "title": r.get("title", ""),
            "snippet": r.get("snippet", ""),
        })
    return out


def _query_backends(query: str) -> list[dict]:
    """Try backends in priority order; return first non-empty result set."""
    for backend in (_backend_searxng, _backend_bing, _backend_google_cse, _backend_duckduckgo):
        try:
            results = backend(query)
            if results:
                return results
        except Exception:
            continue
    return []


def active_backends() -> list[str]:
    """Return list of backend names currently configured/active."""
    backends = []
    if SEARXNG_URL:
        backends.append("searxng")
    if BING_KEY:
        backends.append("bing")
    if GOOGLE_CSE_KEY and GOOGLE_CSE_ID:
        backends.append("google_cse")
    backends.append("duckduckgo")  # always available fallback
    return backends


# ── Result scoring & site reverse-mapping ────────────────────────────────────

def _score_result(
    result: dict,
    rank: int,
    profile_dict: dict,
    matched_site: dict,
    target_domain: str,
) -> int:
    """0-100 score for how likely this SERP hit is the subject's profile."""
    score = 0

    # Rank decay: 1st result gets 35, 10th gets ~5
    score += max(0, int(35 * (1 - (rank / 12.0))))

    # URL matches the site we were dorking
    url_domain = urlparse(result.get("url", "")).netloc.lower().lstrip("www.")
    if target_domain and url_domain.endswith(target_domain):
        score += 15

    # Domain trust — Indian-priority domain
    if matched_site["domain"] in INDIA_PRIORITY_DOMAINS:
        score += 10

    # Snippet contains subject attributes
    blob = " ".join([result.get("title", ""), result.get("snippet", "")]).lower()
    for field in ("city", "state", "workplace", "educational_institution", "occupation"):
        v = (profile_dict.get(field) or "").strip().lower()
        if v and len(v) > 2 and v in blob:
            score += 8
    for company in (profile_dict.get("companies") or [])[:3]:
        if company and company.lower() in blob:
            score += 6
    for em in (profile_dict.get("emails") or [])[:2]:
        if em and em.lower() in blob:
            score += 25
    for ph in (profile_dict.get("phones") or [])[:2]:
        digits = re.sub(r'\D', '', ph)
        if len(digits) >= 10 and digits[-10:] in blob.replace(" ", "").replace("-", ""):
            score += 25

    # Display-name match: first+last in title
    first = (profile_dict.get("first_name") or "").lower()
    last = (profile_dict.get("last_name") or "").lower()
    if first and last and first in blob and last in blob:
        score += 12

    return min(score, 100)


def _map_url_to_site(url: str, matchers: list[dict]) -> tuple[str, str] | tuple[None, None]:
    """Reverse-map a SERP url to (site_name, captured_username), or (None, None)."""
    for m in matchers:
        match = m["regex"].match(url.rstrip("/") + "/")
        if not match:
            match = m["regex"].match(url)
        if match:
            try:
                username = match.group(1)
                if username and username.lower() not in (
                    "search", "explore", "login", "signup", "about", "help",
                    "tos", "privacy", "settings", "home", "feed",
                ):
                    return m["site_name"], username
            except IndexError:
                continue
    return None, None


# ── Off-list classifier ──────────────────────────────────────────────────────

def _classify_off_list(url: str) -> tuple[bool, str | None, str | None]:
    """
    Decide whether a SERP URL (that did NOT match any on-list site) is worth
    surfacing as an external discovery.

    Returns: (is_profile_like, domain, extracted_username_or_None)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, None, None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, None, None

    domain = (parsed.netloc or "").lower().lstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    if domain.startswith("m."):
        domain = domain[2:]
    if not domain or "." not in domain:
        return False, None, None

    # Blocklist — exact or suffix match
    for bad in OFF_LIST_BLOCKLIST:
        if domain == bad or domain.endswith("." + bad):
            return False, domain, None

    path = parsed.path or "/"
    low_path = path.lower()

    # Kill obvious non-profile paths
    for marker in NON_PROFILE_PATH_MARKERS:
        if marker in low_path:
            return False, domain, None

    # Path depth: profile pages are usually shallow (1-2 segments).
    segments = [s for s in path.split("/") if s]
    if len(segments) > 3:
        return False, domain, None

    # Match against profile-looking path patterns
    for pat in PROFILE_PATH_RES:
        m = pat.match(path.rstrip("/") + "/") or pat.match(path)
        if m:
            try:
                handle = m.group(1)
            except IndexError:
                handle = None
            if handle and handle.lower() not in (
                "search", "explore", "login", "signup", "about", "help",
                "tos", "privacy", "settings", "home", "feed", "new",
                "trending", "popular", "terms", "contact", "support",
            ):
                return True, domain, handle

    return False, domain, None


def _score_external(
    result: dict,
    rank: int,
    profile_dict: dict,
    domain: str,
) -> int:
    """0-100 score for an off-list SERP hit."""
    score = 0

    # Rank decay (slightly flatter than on-list since this is already lower prior)
    score += max(0, int(25 * (1 - (rank / 12.0))))

    # Indian-priority bonus if we happen to hit one
    if domain in INDIA_PRIORITY_DOMAINS:
        score += 10

    blob = " ".join([result.get("title", ""), result.get("snippet", "")]).lower()
    for field in ("city", "state", "workplace", "educational_institution", "occupation"):
        v = (profile_dict.get(field) or "").strip().lower()
        if v and len(v) > 2 and v in blob:
            score += 8
    for company in (profile_dict.get("companies") or [])[:3]:
        if company and company.lower() in blob:
            score += 6
    for em in (profile_dict.get("emails") or [])[:2]:
        if em and em.lower() in blob:
            score += 25
    for ph in (profile_dict.get("phones") or [])[:2]:
        digits = re.sub(r'\D', '', ph)
        if len(digits) >= 10 and digits[-10:] in blob.replace(" ", "").replace("-", ""):
            score += 25

    first = (profile_dict.get("first_name") or "").lower()
    last = (profile_dict.get("last_name") or "").lower()
    if first and last and first in blob and last in blob:
        score += 15
    elif first and first in blob and len(first) > 2:
        score += 5

    # Small bump if the extracted handle matches any known username
    for u in (profile_dict.get("usernames") or [])[:3]:
        if u and u.lower() in blob:
            score += 10
            break

    return min(score, 100)


def _verify_external_url(url: str) -> bool:
    """Light liveness check. Returns True if URL looks reachable (2xx/3xx)."""
    try:
        res = make_request(url, delay_range=(0.2, 0.6), timeout=6, method="HEAD")
        if res.get("success"):
            return True
        # Some servers reject HEAD — try GET as fallback (still cheap)
        res = make_request(url, delay_range=(0.2, 0.6), timeout=6)
        return bool(res.get("success"))
    except Exception:
        return False


# ── Main entry point ─────────────────────────────────────────────────────────

def discover_via_serp(
    profile_dict: dict,
    sites_config: dict,
    progress_cb=None,
) -> dict:
    """
    Run SERP discovery pre-pass. Returns:
      {
        "discoveries": [
            {site_name, username, url, score, snippet, dork, backend_count}
        ],
        "dorks_executed": int,
        "raw_hits": int,
        "backends": [str],
        "elapsed_ms": int,
        "candidate_usernames_by_site": {site_name: [usernames...]},
      }
    """
    start = time.time()
    backends = active_backends()
    matchers = _compile_site_matchers(sites_config)
    if not matchers:
        return {"discoveries": [], "dorks_executed": 0, "raw_hits": 0,
                "backends": backends, "elapsed_ms": 0,
                "candidate_usernames_by_site": {},
                "external_discoveries": []}

    dorks = build_dorks(profile_dict, matchers)
    if progress_cb:
        progress_cb({"type": "serp_discovery_started", "dorks": len(dorks),
                     "backends": backends})

    raw_hits = 0
    discoveries: dict[tuple[str, str], dict] = {}
    external: dict[tuple[str, str], dict] = {}  # (domain, handle) → payload

    def _run(dork):
        results = _query_backends(dork["query"])
        return dork, results

    with ThreadPoolExecutor(max_workers=SERP_CONCURRENCY) as pool:
        futures = [pool.submit(_run, d) for d in dorks]
        for fut in as_completed(futures):
            try:
                dork, results = fut.result()
            except Exception:
                continue
            raw_hits += len(results)
            for rank, r in enumerate(results):
                url = r.get("url", "")
                if not url:
                    continue
                site_name, username = _map_url_to_site(url, matchers)
                if site_name and username:
                    # ── On-list hit (existing behavior) ──
                    site_match = next((m for m in matchers if m["site_name"] == site_name), None)
                    if not site_match:
                        continue
                    score = _score_result(
                        r, rank, profile_dict, site_match,
                        dork["target_domain"] or site_match["domain"],
                    )
                    key = (site_name, username.lower())
                    if key not in discoveries or discoveries[key]["score"] < score:
                        discoveries[key] = {
                            "site_name": site_name,
                            "username": username,
                            "url": url,
                            "score": score,
                            "title": r.get("title", "")[:160],
                            "snippet": r.get("snippet", "")[:300],
                            "dork": dork["query"],
                            "reason": dork["reason"],
                        }
                else:
                    # ── Off-list candidate ──
                    is_profile, domain, handle = _classify_off_list(url)
                    if not is_profile or not domain or not handle:
                        continue
                    ext_score = _score_external(r, rank, profile_dict, domain)
                    if ext_score < MIN_EXTERNAL_SCORE:
                        continue
                    ekey = (domain, handle.lower())
                    if ekey not in external or external[ekey]["score"] < ext_score:
                        external[ekey] = {
                            "domain": domain,
                            "extracted_username": handle,
                            "url": url,
                            "score": ext_score,
                            "title": r.get("title", "")[:160],
                            "snippet": r.get("snippet", "")[:300],
                            "dork": dork["query"],
                            "reason": dork["reason"],
                            "verified": None,  # filled in later if enabled
                        }
            if progress_cb:
                progress_cb({"type": "serp_dork_done", "query": dork["query"],
                             "hits": len(results)})

    # Cap per-site, sort by score
    by_site: dict[str, list] = {}
    for d in discoveries.values():
        by_site.setdefault(d["site_name"], []).append(d)
    final = []
    candidate_usernames_by_site: dict[str, list[str]] = {}
    for site, items in by_site.items():
        items.sort(key=lambda x: x["score"], reverse=True)
        kept = items[:MAX_DISCOVERIES_PER_SITE]
        final.extend(kept)
        candidate_usernames_by_site[site] = [k["username"] for k in kept]

    final.sort(key=lambda x: x["score"], reverse=True)

    # ── External (off-list) discoveries: sort, cap, optionally verify ──
    external_list = sorted(external.values(), key=lambda x: x["score"], reverse=True)
    external_list = external_list[:MAX_EXTERNAL_DISCOVERIES]

    if SERP_VERIFY_EXTERNAL and external_list:
        with ThreadPoolExecutor(max_workers=SERP_CONCURRENCY) as pool:
            fut_map = {pool.submit(_verify_external_url, e["url"]): e
                       for e in external_list}
            for fut in as_completed(fut_map):
                try:
                    fut_map[fut]["verified"] = bool(fut.result())
                except Exception:
                    fut_map[fut]["verified"] = False

    elapsed_ms = int((time.time() - start) * 1000)

    if progress_cb:
        progress_cb({"type": "serp_discovery_completed",
                     "discoveries": len(final),
                     "external_discoveries": len(external_list),
                     "raw_hits": raw_hits,
                     "elapsed_ms": elapsed_ms})

    return {
        "discoveries": final,
        "external_discoveries": external_list,
        "dorks_executed": len(dorks),
        "raw_hits": raw_hits,
        "backends": backends,
        "elapsed_ms": elapsed_ms,
        "candidate_usernames_by_site": candidate_usernames_by_site,
    }
