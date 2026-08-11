"""
Entity Correlation & Intelligence Enrichment Engine.

Performs cross-reference analysis after searches complete:
- Corroborated Identity Clusters (same username across platforms)
- Name Match Corroboration
- DOB Corroboration
- Cross-Platform Link detection
- Digital Footprint Summary generation
"""

import uuid
from collections import defaultdict


def build_correlation_clusters(results: list[dict], profile: dict) -> list[dict]:
    """
    Analyze results to find corroborated identity clusters.

    Returns list of CorrelationCluster dicts.
    """
    clusters = []

    # ─── 1. Username clusters: same username found on multiple platforms ───
    username_platforms = defaultdict(list)
    for r in results:
        if r.get("status") in ("found",) and r.get("confidence_score", 0) >= 50:
            uname = r.get("username_searched", "").lower()
            if uname:
                username_platforms[uname].append(r.get("site_name", ""))

    for uname, platforms in username_platforms.items():
        if len(platforms) >= 2:
            clusters.append({
                "cluster_id": str(uuid.uuid4())[:8],
                "username": uname,
                "platforms": platforms,
                "corroboration_type": "username_match",
                "confidence_boost": min(15, len(platforms) * 5),
                "detail": f"Username '{uname}' found on {len(platforms)} platforms: {', '.join(platforms[:10])}",
            })

    # ─── 2. Name match corroboration ───
    name_matches = [r for r in results if r.get("name_match") and r.get("status") == "found"]
    if name_matches:
        platforms = [r.get("site_name", "") for r in name_matches]
        clusters.append({
            "cluster_id": str(uuid.uuid4())[:8],
            "username": f"{profile.get('first_name', '')} {profile.get('last_name', '')}",
            "platforms": platforms,
            "corroboration_type": "name_match",
            "confidence_boost": min(10, len(platforms) * 3),
            "detail": f"Display name matches subject's real name on {len(platforms)} platform(s)",
        })

    # ─── 3. DOB corroboration ───
    dob_matches = [r for r in results if r.get("dob_match") and r.get("status") == "found"]
    if dob_matches:
        platforms = [r.get("site_name", "") for r in dob_matches]
        clusters.append({
            "cluster_id": str(uuid.uuid4())[:8],
            "username": profile.get("date_of_birth", ""),
            "platforms": platforms,
            "corroboration_type": "dob_match",
            "confidence_boost": 5,
            "detail": f"DOB/age matches subject profile on {len(platforms)} platform(s)",
        })

    # ─── 4. Cross-platform links ───
    all_urls = {}
    for r in results:
        if r.get("status") == "found":
            url = r.get("url", "")
            if url:
                all_urls[url.lower().rstrip("/")] = r.get("site_name", "")

            for link in r.get("cross_platform_links", []):
                link_lower = link.lower().rstrip("/")
                if link_lower in all_urls:
                    source_site = r.get("site_name", "")
                    target_site = all_urls[link_lower]
                    if source_site != target_site:
                        clusters.append({
                            "cluster_id": str(uuid.uuid4())[:8],
                            "username": "",
                            "platforms": [source_site, target_site],
                            "corroboration_type": "cross_platform_link",
                            "confidence_boost": 10,
                            "detail": f"{source_site} profile links to {target_site} profile",
                        })

    return clusters


def build_digital_footprint(results: list[dict], csv_matches: list[dict], clusters: list[dict]) -> dict:
    """
    Build a consolidated digital footprint summary.
    """
    confirmed = [r for r in results if r.get("confidence_level") in ("Confirmed", "High Confidence") and r.get("status") == "found"]
    medium = [r for r in results if r.get("confidence_level") == "Medium Confidence" and r.get("status") == "found"]
    unverified = [r for r in results if r.get("confidence_level") == "Unverified"]

    # Most active platforms (by metadata richness)
    platform_scores = []
    for r in confirmed:
        score = 0
        if r.get("bio"): score += 2
        if r.get("follower_count"): score += 1
        if r.get("avatar_url"): score += 1
        if r.get("location"): score += 1
        platform_scores.append((r.get("site_name", ""), score))
    platform_scores.sort(key=lambda x: x[1], reverse=True)

    # Category breakdown
    categories = defaultdict(int)
    for r in confirmed:
        cat = _infer_category(r.get("site_name", ""))
        categories[cat] += 1

    # Breach data summary
    breach_sources = set()
    for m in csv_matches:
        breach_sources.add(m.get("_source_csv", "unknown"))

    # Usernames used
    usernames_used = set()
    for r in confirmed:
        u = r.get("username_searched", "")
        if u:
            usernames_used.add(u)

    return {
        "total_confirmed_accounts": len(confirmed),
        "total_medium_confidence": len(medium),
        "total_unverified": len(unverified),
        "total_breach_matches": len(csv_matches),
        "breach_sources": sorted(breach_sources),
        "most_active_platforms": [{"platform": p, "richness_score": s} for p, s in platform_scores[:10]],
        "category_breakdown": dict(categories),
        "usernames_used": sorted(usernames_used),
        "correlation_clusters_count": len(clusters),
        "cross_platform_links_found": sum(1 for c in clusters if c.get("corroboration_type") == "cross_platform_link"),
        "name_corroboration_found": any(c.get("corroboration_type") == "name_match" for c in clusters),
        "dob_corroboration_found": any(c.get("corroboration_type") == "dob_match" for c in clusters),
    }


def _infer_category(site_name: str) -> str:
    """Infer category from site name (fallback if not in config)."""
    site_lower = site_name.lower()
    if any(kw in site_lower for kw in ["github", "gitlab", "stack", "hacker", "leet", "code"]):
        return "dev"
    if any(kw in site_lower for kw in ["facebook", "instagram", "twitter", "reddit", "telegram", "snap"]):
        return "social"
    if any(kw in site_lower for kw in ["youtube", "twitch", "spotify", "sound", "vimeo"]):
        return "media"
    if any(kw in site_lower for kw in ["behance", "dribbble", "deviant", "art"]):
        return "creative"
    if any(kw in site_lower for kw in ["medium", "substack", "wordpress", "blog", "wattpad"]):
        return "blog"
    if any(kw in site_lower for kw in ["steam", "chess", "roblox", "anime"]):
        return "gaming"
    if any(kw in site_lower for kw in ["linkedin", "fiverr", "upwork", "naukri", "freelancer"]):
        return "business"
    if any(kw in site_lower for kw in ["sharechat", "koo", "josh", "moj", "zomato", "swiggy", "paytm", "olx", "meesho"]):
        return "india"
    return "other"
