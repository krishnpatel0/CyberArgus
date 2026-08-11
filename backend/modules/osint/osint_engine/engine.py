"""
Main Investigation Engine — Orchestrator for the OSINT Investigation Platform.

Coordinates:
- Subject profile validation
- Search mode selection and execution
- Tiered site execution (Tier 1 -> Tier 2 -> Tier 3)
- Progress tracking and streaming
- Entity correlation
- Report generation
"""

import json
import os
import re
import time
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import (
    MAX_CONCURRENT_REQUESTS,
    TIER1_CONCURRENCY,
    TIER2_CONCURRENCY,
    TIER3_CONCURRENCY,
    PARALLEL_TIERS,
    TIER1_DELAY_RANGE,
    TIER2_DELAY_RANGE,
    TIER3_DELAY_RANGE,
    EMAIL_RE,
    PHONE_RE,
    SHERLOCK_DATA_URL,
    WMN_DATA_URL,
    SITE_DATA_CACHE_TTL,
)
from .models import (
    SubjectProfile,
    SiteResult,
    InvestigationResult,
    TierProgress,
)
from .permutations import (
    generate_username_permutations,
    generate_name_permutations,
    generate_email_permutations,
    generate_phone_permutations,
)
from .verification import verify_site, clear_calibration_cache
from .csv_search import search_csv_sources
from .correlation import build_correlation_clusters, build_digital_footprint
from .intelbase import IntelbaseLookupError, intelbase_enabled, lookup_email, mask_email
from .profiler import (
    extract_profile_signals, score_subject_match, cluster_identities,
    build_evidence_chain, calculate_disambiguation_tier,
    extract_new_anchors, calculate_profile_strength,
)
from .serp_discovery import discover_via_serp, active_backends as serp_active_backends


# ─── Site Data Loading ───

_sites_cache = {"data": None, "fetched_at": 0}
_external_sites_cache = {"sherlock": None, "wmn": None, "fetched_at": 0}
_CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
_CERTIFIED_SITES_PATH = os.path.join(_CACHE_DIR, "validated_sites.json")
_CERTIFIED_MANIFEST_VERSION = 1


class InvestigationCancelled(Exception):
    """Raised when an investigation is cancelled mid-run."""


def _load_sites_config() -> dict:
    """Load site definitions from sites_config.json."""
    config_path = os.path.join(os.path.dirname(__file__), "sites_config.json")
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Remove metadata key
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except (OSError, json.JSONDecodeError) as e:
        print(f"[OSINT Engine] Failed to load sites_config.json: {e}")
        return {}


def _load_external_sites() -> dict:
    """Load and merge external site definitions from Sherlock + WhatsMyName."""
    import requests

    now = time.time()
    if _external_sites_cache["sherlock"] and (now - _external_sites_cache["fetched_at"]) < SITE_DATA_CACHE_TTL:
        return _merge_external_sites()

    # Load Sherlock data
    sherlock = {}
    try:
        resp = requests.get(SHERLOCK_DATA_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        for name, info in data.items():
            if not name.startswith("$") and isinstance(info, dict) and "url" in info:
                sherlock[name] = info
        print(f"[OSINT Engine] Loaded {len(sherlock)} Sherlock sites")
    except Exception as e:
        print(f"[OSINT Engine] Sherlock fetch failed: {e}")

    # Load WhatsMyName data
    wmn = {}
    try:
        resp = requests.get(WMN_DATA_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        for site in data.get("sites", []):
            name = site.get("name", "")
            uri = site.get("uri_check", "")
            if name and uri:
                wmn_entry = {"url": uri.replace("{account}", "{}")}
                if site.get("e_string"):
                    wmn_entry["not_claimed_if"] = [site["e_string"]]
                if site.get("m_string"):
                    wmn_entry["claimed_if"] = [site["m_string"]]
                if site.get("known", []):
                    wmn_entry["known_username"] = site["known"][0]
                wmn[name] = wmn_entry
        print(f"[OSINT Engine] Loaded {len(wmn)} WhatsMyName sites")
    except Exception as e:
        print(f"[OSINT Engine] WhatsMyName fetch failed: {e}")

    _external_sites_cache["sherlock"] = sherlock
    _external_sites_cache["wmn"] = wmn
    _external_sites_cache["fetched_at"] = now

    return _merge_external_sites()


def _merge_external_sites() -> dict:
    """Merge external sites, converting to our config format."""
    merged = {}
    sherlock = _external_sites_cache.get("sherlock") or {}
    wmn = _external_sites_cache.get("wmn") or {}

    for name, info in sherlock.items():
        if "url" not in info:
            continue
        entry = {
            "url": info["url"],
            "tier": 3,
            "category": "other",
            "error_type": info.get("errorType", "status_code"),
            "claimed_if": [],
            "not_claimed_if": [],
            "ambiguous_if": [],
            "secondary_confirmation": False,
            "delay_multiplier": 1.0,
            "antibot_risk": "low",
        }
        # Convert Sherlock format
        if info.get("presenceStrs"):
            strs = info["presenceStrs"]
            entry["claimed_if"] = strs if isinstance(strs, list) else [strs]
        if info.get("errorMsg"):
            msgs = info["errorMsg"]
            entry["not_claimed_if"] = msgs if isinstance(msgs, list) else [msgs]
        if info.get("urlProbe"):
            entry["url_probe"] = info["urlProbe"]
        if info.get("username_claimed"):
            entry["known_username"] = info["username_claimed"]
        if info.get("regexCheck"):
            entry["username_format"] = info["regexCheck"]

        merged[name] = entry

    # WMN supplements
    for name, info in wmn.items():
        if name not in merged:
            merged[name] = {
                "url": info.get("url", ""),
                "tier": 3,
                "category": "other",
                "error_type": "status_code",
                "claimed_if": info.get("claimed_if", []),
                "not_claimed_if": info.get("not_claimed_if", []),
                "ambiguous_if": [],
                "secondary_confirmation": False,
                "delay_multiplier": 1.0,
                "antibot_risk": "low",
            }
            if info.get("known_username"):
                merged[name]["known_username"] = info["known_username"]
        else:
            # Supplement existing entries
            if not merged[name].get("claimed_if") and info.get("claimed_if"):
                merged[name]["claimed_if"] = info["claimed_if"]
            if not merged[name].get("not_claimed_if") and info.get("not_claimed_if"):
                merged[name]["not_claimed_if"] = info["not_claimed_if"]
            if not merged[name].get("known_username") and info.get("known_username"):
                merged[name]["known_username"] = info["known_username"]

    return merged


def _ensure_cache_dir():
    os.makedirs(_CACHE_DIR, exist_ok=True)


def _load_certified_site_manifest() -> dict | None:
    try:
        with open(_CERTIFIED_SITES_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        if manifest.get("version") != _CERTIFIED_MANIFEST_VERSION:
            return None
        return manifest
    except (OSError, json.JSONDecodeError):
        return None


def _score_site_certification(name: str, config: dict) -> dict:
    claimed_markers = config.get("claimed_if", []) or []
    not_claimed_markers = config.get("not_claimed_if", []) or []
    ambiguous_markers = config.get("ambiguous_if", []) or []
    has_probe = bool(config.get("url_probe"))
    has_known = bool(config.get("known_username"))
    has_url = bool(config.get("url"))
    error_type = config.get("error_type", "status_code")

    strength = 0
    if claimed_markers:
        strength += 3
    if not_claimed_markers:
        strength += 3
    if has_probe:
        strength += 2
    if has_known:
        strength += 1
    if error_type == "response_url":
        strength += 1
    if ambiguous_markers and not claimed_markers and not not_claimed_markers:
        strength -= 1

    enabled = has_url and strength >= 2
    if not has_url:
        reason = "missing_url"
    elif strength < 2:
        reason = "weak_detection_rules"
    else:
        reason = ""

    return {
        "enabled": enabled,
        "strength": strength,
        "reason": reason,
        "claimed_marker_count": len(claimed_markers),
        "not_claimed_marker_count": len(not_claimed_markers),
        "ambiguous_marker_count": len(ambiguous_markers),
        "has_probe": has_probe,
        "has_known_username": has_known,
    }


def build_certified_site_manifest(force: bool = False) -> dict:
    now = time.time()
    if not force:
        cached = _load_certified_site_manifest()
        if cached and (now - cached.get("generated_at_epoch", 0)) < SITE_DATA_CACHE_TTL:
            return cached

    raw_sites = load_all_sites()
    manifest_sites = {}
    enabled_count = 0

    for name, config in raw_sites.items():
        assessment = _score_site_certification(name, config)
        if assessment["enabled"]:
            enabled_count += 1
        manifest_sites[name] = {
            "enabled": assessment["enabled"],
            "suppression_reason": assessment["reason"],
            "rule_strength": assessment["strength"],
            "claimed_marker_count": assessment["claimed_marker_count"],
            "not_claimed_marker_count": assessment["not_claimed_marker_count"],
            "ambiguous_marker_count": assessment["ambiguous_marker_count"],
            "has_probe": assessment["has_probe"],
            "has_known_username": assessment["has_known_username"],
            "config": config,
        }

    manifest = {
        "version": _CERTIFIED_MANIFEST_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_at_epoch": now,
        "path": _CERTIFIED_SITES_PATH,
        "total_sites": len(manifest_sites),
        "enabled_sites": enabled_count,
        "suppressed_sites": len(manifest_sites) - enabled_count,
        "sites": manifest_sites,
    }

    try:
        _ensure_cache_dir()
        with open(_CERTIFIED_SITES_PATH, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
    except OSError as e:
        print(f"[OSINT Engine] Failed to persist certified manifest: {e}")

    return manifest


def load_runtime_sites(force_manifest_refresh: bool = False) -> tuple[dict, dict]:
    manifest = build_certified_site_manifest(force=force_manifest_refresh)
    enabled_sites = {}
    for name, site_info in manifest.get("sites", {}).items():
        if site_info.get("enabled"):
            enabled_sites[name] = site_info.get("config", {})
    return manifest, enabled_sites


def load_all_sites() -> dict:
    """Load all site definitions: config file + external sources."""
    now = time.time()
    if _sites_cache["data"] and (now - _sites_cache["fetched_at"]) < SITE_DATA_CACHE_TTL:
        return _sites_cache["data"]

    # Start with our curated config
    sites = _load_sites_config()

    # Merge external sites (only add sites NOT already in config)
    try:
        external = _load_external_sites()
        for name, info in external.items():
            if name not in sites:
                sites[name] = info
    except Exception as e:
        print(f"[OSINT Engine] External sites loading failed: {e}")

    _sites_cache["data"] = sites
    _sites_cache["fetched_at"] = now
    print(f"[OSINT Engine] Total sites loaded: {len(sites)}")
    return sites


def _get_sites_by_tier(sites: dict, tier: int) -> dict:
    """Filter sites by tier."""
    return {name: config for name, config in sites.items()
            if config.get("tier", 3) == tier}


def _get_delay_for_tier(tier: int) -> tuple:
    """Get delay range for a tier."""
    if tier == 1:
        return TIER1_DELAY_RANGE
    elif tier == 2:
        return TIER2_DELAY_RANGE
    return TIER3_DELAY_RANGE


def _get_concurrency_for_tier(tier: int) -> int:
    """Get max concurrent workers per tier."""
    if tier == 1:
        return TIER1_CONCURRENCY
    elif tier == 2:
        return TIER2_CONCURRENCY
    return TIER3_CONCURRENCY


# ─── Input Detection ───

def detect_input_type(input_str: str) -> str:
    """Auto-detect input type: EMAIL, PHONE, NAME, or USERNAME."""
    s = input_str.strip()
    if EMAIL_RE.match(s):
        return "EMAIL"
    digits = re.sub(r'\D', '', s)
    if 10 <= len(digits) <= 15 and PHONE_RE.match(s):
        return "PHONE"
    if ' ' in s and all(part.isalpha() for part in s.split() if part):
        return "NAME"
    return "USERNAME"


# ─── Investigation Engine ───

class InvestigationEngine:
    """
    Main orchestrator for OSINT investigations.

    Usage:
        engine = InvestigationEngine()
        result = engine.run_investigation(profile, modes=["username", "email"])
    """

    def __init__(self):
        self.sites = {}
        self._progress_lock = threading.Lock()
        self._progress_callback = None
        self._stop_callback = None
        self._pause_callback = None
        self._results = []
        self._tier_progress = {}

    def set_progress_callback(self, callback):
        """Set a callback function for progress updates: callback(progress_dict)."""
        self._progress_callback = callback

    def set_stop_callback(self, callback):
        """Set a callback that returns True when investigation should stop."""
        self._stop_callback = callback

    def set_pause_callback(self, callback):
        """Set a callback that returns True when investigation should pause."""
        self._pause_callback = callback

    def _check_paused(self):
        """Block while investigation is paused, checking for cancellation."""
        if not self._pause_callback:
            return
        import time as _time
        while True:
            try:
                if not self._pause_callback():
                    break
            except Exception:
                break
            self._check_cancelled()
            _time.sleep(0.5)

    def _emit_progress(self, data: dict):
        """Emit a progress update."""
        if self._progress_callback:
            try:
                self._progress_callback(data)
            except Exception:
                pass

    def _should_stop(self) -> bool:
        if not self._stop_callback:
            return False
        try:
            return bool(self._stop_callback())
        except Exception:
            return False

    def _check_cancelled(self):
        if self._should_stop():
            raise InvestigationCancelled("Investigation cancelled by user")

    def run_investigation(
        self,
        profile: SubjectProfile,
        modes: list[str] = None,
        tiers: list[int] = None,
        force_manifest_refresh: bool = False,
        enable_serp_discovery: bool = True,
    ) -> dict:
        """
        Run a full investigation against the subject profile.

        Args:
            profile: SubjectProfile with investigation subject data
            modes: List of search modes to execute ("username", "name", "email", "phone")
                   If None, auto-detects based on available profile fields
            tiers: List of tiers to search (default [1, 2, 3])

        Returns:
            InvestigationResult as dict
        """
        start_time = time.time()
        started_at = datetime.now(timezone.utc).isoformat()

        # Validate
        if not profile.has_searchable_fields():
            return {
                "error": "No searchable fields provided. At least one of: username, first+last name, email, or phone is required.",
                "success": False,
            }

        self._check_cancelled()

        # Load sites through the certified manifest so weak-rule entries
        # are suppressed before runtime probing.
        manifest, runtime_sites = load_runtime_sites(force_manifest_refresh=force_manifest_refresh)
        self.sites = runtime_sites

        if tiers is None:
            tiers = [1, 2, 3]

        # Auto-detect modes if not specified
        if modes is None:
            modes = []
            targets = profile.get_all_search_targets()
            if targets["usernames"]:
                modes.append("username")
            if targets["names"]:
                modes.append("name")
            if targets["emails"]:
                modes.append("email")
            if targets["phones"]:
                modes.append("phone")

        self._results = []
        all_csv_matches = []

        # Initialize tier progress
        for tier in tiers:
            tier_sites = _get_sites_by_tier(self.sites, tier)
            self._tier_progress[tier] = TierProgress(
                tier=tier,
                total_sites=len(tier_sites),
                status="pending",
            )

        # Calculate profile strength before search starts
        profile_strength = calculate_profile_strength(profile.to_dict())

        self._emit_progress({
            "type": "investigation_started",
            "modes": modes,
            "tiers": [tp.to_dict() for tp in self._tier_progress.values()],
            "total_sites": len(self.sites),
            "profile_strength": profile_strength,
        })
        self._emit_progress({
            "type": "manifest_loaded",
            "manifest_path": manifest.get("path"),
            "total_sites": manifest.get("total_sites", 0),
            "enabled_sites": manifest.get("enabled_sites", 0),
            "suppressed_sites": manifest.get("suppressed_sites", 0),
        })

        # ─── SERP pre-pass (optional) ───
        # Adds candidate usernames discovered via Google/DuckDuckGo dorks
        # before the per-site probe loop. Catches vanity handles and name +
        # context profiles that pure permutation cannot guess.
        self._serp_discovery = {"discoveries": [], "external_discoveries": [],
                                 "candidate_usernames_by_site": {},
                                 "dorks_executed": 0, "raw_hits": 0,
                                 "backends": serp_active_backends(), "enabled": False}
        if enable_serp_discovery:
            try:
                self._check_cancelled()
                serp_result = discover_via_serp(
                    profile.to_dict(), self.sites, progress_cb=self._emit_progress,
                )
                serp_result["enabled"] = True
                self._serp_discovery = serp_result
                if "serp" not in modes:
                    modes = list(modes) + ["serp"]
            except InvestigationCancelled:
                raise
            except Exception as e:
                self._emit_progress({"type": "serp_discovery_failed", "error": str(e)})

        # ─── Execute searches ───
        if "email" in modes and targets["emails"]:
            self._run_intelbase_email_lookups(targets["emails"])

        if PARALLEL_TIERS and len(tiers) > 1:
            # Run all tiers in parallel using separate thread pools
            self._execute_tiers_parallel(tiers, modes, profile)
        else:
            # Sequential fallback
            for tier in tiers:
                self._execute_single_tier(tier, modes, profile)

        # ─── CSV Breach Cross-Reference ───
        targets = profile.get_all_search_targets()
        for uname in targets["usernames"][:5]:
            self._check_cancelled()
            csv_matches = search_csv_sources(uname, "USERNAME")
            all_csv_matches.extend(csv_matches)
        for email in targets["emails"][:3]:
            self._check_cancelled()
            csv_matches = search_csv_sources(email, "EMAIL")
            all_csv_matches.extend(csv_matches)
        for phone in targets["phones"][:3]:
            self._check_cancelled()
            csv_matches = search_csv_sources(phone, "PHONE")
            all_csv_matches.extend(csv_matches)
        if targets["names"]:
            self._check_cancelled()
            name_info = targets["names"][0]
            name_str = f"{name_info['first']} {name_info['last']}"
            csv_matches = search_csv_sources(name_str, "NAME")
            all_csv_matches.extend(csv_matches)

        # Deduplicate CSV matches
        seen_csv = set()
        unique_csv = []
        for m in all_csv_matches:
            key = f"{m.get('_source_csv')}_{m.get('email', '')}_{m.get('phone', '')}_{m.get('name', '')}"
            if key not in seen_csv:
                seen_csv.add(key)
                unique_csv.append(m)

        # ─── Entity Correlation ───
        result_dicts = self._results
        clusters = build_correlation_clusters(result_dicts, profile.to_dict())

        # Apply correlation confidence boosts
        for cluster in clusters:
            boost = cluster.get("confidence_boost", 0)
            platforms = cluster.get("platforms", [])
            for r in result_dicts:
                if r.get("site_name") in platforms and r.get("status") == "found":
                    old_score = r.get("confidence_score", 0)
                    new_score = min(100, old_score + boost)
                    r["confidence_score"] = new_score
                    r["confidence_level"] = self._score_to_level(new_score)

        # ─── Identity Clustering (disambiguation) ───
        id_clusters = cluster_identities(result_dicts, profile.to_dict())

        # ─── Digital Footprint ───
        footprint = build_digital_footprint(result_dicts, unique_csv, clusters)

        # ─── Triage pass: reclassify noise before counting ───
        # Rules:
        #  (a) WAF-blocked hits → status="blocked" (not review, not not_found).
        #  (b) Unverified with score < 15 and no profile metadata and no
        #      claimed markers → demote to Not Found. These are noise.
        #  (c) "found" results with subject_match_score < 20 AND no evidence
        #      chain → demote one tier (keeps them visible but out of review).
        _triage_stats = {"auto_dismissed": 0, "blocked": 0, "demoted_low_match": 0}
        for r in result_dicts:
            status = r.get("status")
            cl = r.get("confidence_level")
            score = r.get("confidence_score", 0) or 0

            # (a) WAF → Blocked
            if r.get("waf_detected") and status != "found":
                r["status"] = "blocked"
                r["confidence_level"] = "Blocked"
                _triage_stats["blocked"] += 1
                continue

            # (b) Noise auto-dismiss
            if cl == "Unverified" and score < 15:
                has_metadata = bool(r.get("display_name") or r.get("bio") or r.get("avatar_url"))
                claimed_markers = any(
                    s.get("name") == "positive_markers_found" and s.get("passed")
                    for s in (r.get("signals") or [])
                )
                if not has_metadata and not claimed_markers:
                    r["status"] = "not_found"
                    r["confidence_level"] = "Not Found"
                    r["confidence_score"] = 0
                    r["auto_dismissed"] = True
                    r["auto_dismissed_reason"] = "Low score, no metadata, no positive markers"
                    _triage_stats["auto_dismissed"] += 1
                    continue

            # (c) Found but nothing confirms it's the subject → demote
            if status == "found":
                sms = r.get("subject_match_score", 0) or 0
                ec = r.get("evidence_chain") or []
                if sms < 20 and not ec and cl in ("Medium Confidence", "Ambiguous"):
                    r["confidence_level"] = "Unverified"
                    r["confidence_score"] = min(score, 29)
                    r["triage_demoted"] = True
                    _triage_stats["demoted_low_match"] += 1

        # ─── Build Final Result ───
        elapsed_ms = int((time.time() - start_time) * 1000)

        # Count by confidence level (post-triage)
        confirmed = sum(1 for r in result_dicts if r.get("confidence_level") == "Confirmed")
        high = sum(1 for r in result_dicts if r.get("confidence_level") == "High Confidence")
        medium = sum(1 for r in result_dicts if r.get("confidence_level") == "Medium Confidence")
        ambiguous = sum(1 for r in result_dicts if r.get("confidence_level") == "Ambiguous")
        unverified = sum(1 for r in result_dicts if r.get("confidence_level") == "Unverified")
        blocked = sum(1 for r in result_dicts if r.get("status") == "blocked")
        not_found = sum(1 for r in result_dicts if r.get("status") == "not_found")
        errors = sum(1 for r in result_dicts if r.get("status") in ("error", "rate_limited"))

        # Collect pivot suggestions from all found accounts
        all_pivot_anchors = {}
        for r in result_dicts:
            new_anchors = r.get("new_anchors_found", {})
            for k, vals in new_anchors.items():
                if k not in all_pivot_anchors:
                    all_pivot_anchors[k] = []
                for v in vals:
                    if v not in all_pivot_anchors[k]:
                        all_pivot_anchors[k].append(v)

        investigation = InvestigationResult(
            started_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            elapsed_ms=elapsed_ms,
            subject_profile=profile.to_dict(),
            modes_executed=modes,
            results=result_dicts,
            csv_matches=unique_csv,
            correlation_clusters=[c for c in clusters],
            identity_clusters=id_clusters,
            tier_progress=[tp.to_dict() for tp in self._tier_progress.values()],
            total_sites_checked=len(set(r.get("site_name") for r in result_dicts)),
            total_permutations_checked=len(result_dicts),
            confirmed_count=confirmed,
            high_confidence_count=high,
            medium_confidence_count=medium,
            ambiguous_count=ambiguous,
            unverified_count=unverified,
            blocked_count=blocked,
            not_found_count=not_found,
            error_count=errors,
            actionable_findings=confirmed + high,
            manual_review_count=medium + ambiguous,
            low_signal_count=unverified,
            triage_stats=_triage_stats,
            digital_footprint=footprint,
            profile_strength=profile_strength,
            pivot_suggestions=all_pivot_anchors,
            serp_discovery=getattr(self, "_serp_discovery", {}),
        )

        self._emit_progress({
            "type": "investigation_completed",
            "elapsed_ms": elapsed_ms,
            "actionable_findings": confirmed + high,
        })

        return {"success": True, "data": investigation.to_dict()}

    def _run_intelbase_email_lookups(self, emails: list[str]) -> None:
        """Enrich email investigations with Intelbase results when configured."""
        if not intelbase_enabled():
            self._emit_progress({
                "type": "intelbase_skipped",
                "reason": "INTELBASE_API_KEY is not configured",
            })
            return

        for email in emails[:3]:
            self._check_cancelled()
            masked = mask_email(email)
            self._emit_progress({"type": "intelbase_started", "email": masked})
            try:
                lookup = lookup_email(email)
            except IntelbaseLookupError as exc:
                self._emit_progress({
                    "type": "intelbase_failed",
                    "email": masked,
                    "error": str(exc),
                })
                continue
            except Exception as exc:
                self._emit_progress({
                    "type": "intelbase_failed",
                    "email": masked,
                    "error": f"Unexpected Intelbase error: {exc}",
                })
                continue

            results = self._intelbase_lookup_to_results(lookup, masked)
            with self._progress_lock:
                self._results.extend(results)
            self._emit_progress({
                "type": "intelbase_completed",
                "email": masked,
                "found": lookup.found,
                "platforms": len(lookup.platforms),
                "breaches": len(lookup.breaches),
                "elapsed_ms": lookup.elapsed_ms,
            })

    def _intelbase_lookup_to_results(self, lookup, masked_email: str) -> list[dict]:
        results: list[dict] = []
        checked_at = datetime.now(timezone.utc).isoformat()

        for platform in lookup.platforms:
            score = platform.confidence
            result = SiteResult(
                site_name=f"Intelbase: {platform.name}",
                url=platform.url or f"intelbase://email/{masked_email}/{platform.name}",
                username_searched=lookup.email,
                search_mode="email",
                permutation_pattern="intelbase_email_lookup",
                tier=1,
                status="found",
                confidence_score=score,
                confidence_level=self._score_to_level(score),
                signals=[{
                    "name": "intelbase_platform_registration",
                    "passed": True,
                    "weight": 1.0,
                    "detail": f"Intelbase reported a registration or profile signal for {platform.name}",
                }],
                secondary_confirmation=True,
                secondary_confirmation_passed=True,
                extra_metadata={
                    "provider": "Intelbase",
                    "email": masked_email,
                    "source": "email_lookup",
                    "raw_keys": lookup.raw_keys,
                    "platform_metadata": platform.metadata,
                },
                matched_attributes=[f"email:{masked_email}"],
                subject_match_score=95,
                checked_at=checked_at,
                response_time_ms=lookup.elapsed_ms,
            ).to_dict()
            result["category"] = "email_intelligence"
            result["site"] = result["site_name"]
            result["metadata"] = result["extra_metadata"]
            result["disambiguation_tier"] = "DEFINITIVE"
            result["evidence_chain"] = [{
                "type": "email_lookup",
                "label": "Email matched by Intelbase",
                "detail": f"{masked_email} was returned by Intelbase for {platform.name}",
                "tier": "definitive",
            }]
            results.append(result)

        if lookup.breaches:
            breach_names = [
                str(b.get("name") or b.get("title") or b.get("source") or "Unknown breach")
                for b in lookup.breaches[:10]
            ]
            result = SiteResult(
                site_name="Intelbase: Breach Exposure",
                url=f"intelbase://email/{masked_email}/breaches",
                username_searched=lookup.email,
                search_mode="email",
                permutation_pattern="intelbase_email_lookup",
                tier=1,
                status="found",
                confidence_score=95,
                confidence_level="Confirmed",
                signals=[{
                    "name": "intelbase_breach_records",
                    "passed": True,
                    "weight": 1.0,
                    "detail": f"Intelbase returned {len(lookup.breaches)} breach or leak records",
                }],
                secondary_confirmation=True,
                secondary_confirmation_passed=True,
                bio=", ".join(breach_names),
                extra_metadata={
                    "provider": "Intelbase",
                    "email": masked_email,
                    "source": "breach_lookup",
                    "breaches": lookup.breaches[:25],
                    "raw_keys": lookup.raw_keys,
                },
                matched_attributes=[f"email:{masked_email}"],
                subject_match_score=100,
                checked_at=checked_at,
                response_time_ms=lookup.elapsed_ms,
            ).to_dict()
            result["category"] = "breach"
            result["site"] = result["site_name"]
            result["metadata"] = result["extra_metadata"]
            result["disambiguation_tier"] = "DEFINITIVE"
            result["evidence_chain"] = [{
                "type": "email_breach",
                "label": "Email breach exposure",
                "detail": f"{masked_email} appeared in Intelbase breach intelligence",
                "tier": "definitive",
            }]
            results.append(result)

        if not results:
            result = SiteResult(
                site_name="Intelbase Email Lookup",
                url=f"intelbase://email/{masked_email}",
                username_searched=lookup.email,
                search_mode="email",
                permutation_pattern="intelbase_email_lookup",
                tier=1,
                status="not_found",
                confidence_score=0,
                confidence_level="Not Found",
                extra_metadata={
                    "provider": "Intelbase",
                    "email": masked_email,
                    "source": "email_lookup",
                    "exists": lookup.exists,
                    "valid_format": lookup.valid_format,
                    "deliverable": lookup.deliverable,
                    "disposable": lookup.disposable,
                    "raw_keys": lookup.raw_keys,
                },
                checked_at=checked_at,
                response_time_ms=lookup.elapsed_ms,
            ).to_dict()
            result["category"] = "email_intelligence"
            result["site"] = result["site_name"]
            result["metadata"] = result["extra_metadata"]
            results.append(result)

        return results

    def _execute_single_tier(self, tier: int, modes: list[str], profile: SubjectProfile):
        """Execute all work items for a single tier."""
        self._check_cancelled()
        tier_sites = _get_sites_by_tier(self.sites, tier)
        if not tier_sites:
            return

        self._tier_progress[tier].status = "in_progress"
        self._emit_progress({
            "type": "tier_started",
            "tier": tier,
            "site_count": len(tier_sites),
        })

        delay_range = _get_delay_for_tier(tier)

        work_items = []
        for mode in modes:
            items = self._generate_work_items(profile, mode, tier_sites, tier, delay_range)
            work_items.extend(items)

        concurrency = _get_concurrency_for_tier(tier)
        self._execute_work_items(work_items, profile, max_workers=concurrency)
        self._check_cancelled()

        self._tier_progress[tier].status = "completed"
        self._tier_progress[tier].completed = len(tier_sites)
        self._tier_progress[tier].found = sum(
            1 for r in self._results
            if r.get("tier") == tier and r.get("status") == "found"
        )

        self._emit_progress({
            "type": "tier_completed",
            "tier": tier,
            "progress": self._tier_progress[tier].to_dict(),
        })

    def _execute_tiers_parallel(self, tiers: list[int], modes: list[str], profile: SubjectProfile):
        """Execute all tiers simultaneously using separate threads."""
        tier_threads = []
        tier_errors = {}

        def _run_tier(tier):
            try:
                self._execute_single_tier(tier, modes, profile)
            except InvestigationCancelled:
                raise
            except Exception as e:
                tier_errors[tier] = str(e)

        for tier in tiers:
            t = threading.Thread(target=_run_tier, args=(tier,), daemon=True)
            tier_threads.append(t)
            t.start()

        # Wait for all tier threads to complete
        for t in tier_threads:
            while t.is_alive():
                self._check_cancelled()
                t.join(timeout=1.0)

    @staticmethod
    def _username_matches_format(username: str, site_config: dict) -> bool:
        """Check if username matches the site's username_format regex. Skip invalid ones."""
        fmt = site_config.get("username_format")
        if not fmt:
            return True  # No format restriction
        try:
            return bool(re.match(fmt, username))
        except re.error:
            return True  # Invalid regex, don't filter

    def _generate_work_items(
        self,
        profile: SubjectProfile,
        mode: str,
        tier_sites: dict,
        tier: int,
        delay_range: tuple,
    ) -> list[dict]:
        """Generate work items (site + username pairs) for a given mode and tier."""
        items = []
        targets = profile.get_all_search_targets()

        if mode == "username":
            for username in targets["usernames"]:
                perms = generate_username_permutations(
                    username,
                    birth_year=profile.get_birth_year(),
                    aliases=profile.aliases,
                )
                for perm in perms:
                    for site_name, site_config in tier_sites.items():
                        if not self._username_matches_format(perm["username"], site_config):
                            continue
                        items.append({
                            "site_name": site_name,
                            "site_config": site_config,
                            "username": perm["username"],
                            "pattern": perm["pattern"],
                            "mode": "username",
                            "tier": tier,
                            "delay_range": delay_range,
                        })

        elif mode == "name":
            for name_info in targets["names"]:
                perms = generate_name_permutations(
                    first_name=name_info["first"],
                    last_name=name_info["last"],
                    middle_name=name_info.get("middle", ""),
                    birth_year=profile.get_birth_year(),
                    aliases=profile.aliases,
                )
                for perm in perms:
                    for site_name, site_config in tier_sites.items():
                        if not self._username_matches_format(perm["username"], site_config):
                            continue
                        items.append({
                            "site_name": site_name,
                            "site_config": site_config,
                            "username": perm["username"],
                            "pattern": perm["pattern"],
                            "mode": "name_permutation",
                            "tier": tier,
                            "delay_range": delay_range,
                        })

        elif mode == "email":
            for email in targets["emails"]:
                perms = generate_email_permutations(email)
                for perm in perms:
                    if perm.get("type") == "email":
                        # Email-specific checks (Gravatar, HaveIBeenPwned, etc.)
                        # Only check sites that support email lookup
                        for site_name, site_config in tier_sites.items():
                            if site_name.lower() in ("gravatar",):
                                items.append({
                                    "site_name": site_name,
                                    "site_config": site_config,
                                    "username": perm["username"],
                                    "pattern": perm["pattern"],
                                    "mode": "email",
                                    "tier": tier,
                                    "delay_range": delay_range,
                                })
                    else:
                        # Username derived from email
                        for site_name, site_config in tier_sites.items():
                            items.append({
                                "site_name": site_name,
                                "site_config": site_config,
                                "username": perm["username"],
                                "pattern": perm["pattern"],
                                "mode": "email_derived",
                                "tier": tier,
                                "delay_range": delay_range,
                            })

        elif mode == "serp":
            # SERP-discovered (site, username) pairs. Only check the exact
            # site that surfaced in the search result — no permutation explosion.
            serp_map = getattr(self, "_serp_discovery", {}).get(
                "candidate_usernames_by_site", {}
            )
            for site_name, usernames in serp_map.items():
                site_config = tier_sites.get(site_name)
                if not site_config:
                    continue  # Wrong tier
                for username in usernames:
                    if not self._username_matches_format(username, site_config):
                        continue
                    items.append({
                        "site_name": site_name,
                        "site_config": site_config,
                        "username": username,
                        "pattern": "serp_discovered",
                        "mode": "serp",
                        "tier": tier,
                        "delay_range": delay_range,
                    })

        elif mode == "phone":
            for phone in targets["phones"]:
                phone_perms = generate_phone_permutations(phone)
                # Phone searches are limited to sites that support phone lookup
                # For now, just search username-compatible formats
                for perm in phone_perms:
                    if perm["pattern"] == "raw_10_digit":
                        for site_name, site_config in tier_sites.items():
                            items.append({
                                "site_name": site_name,
                                "site_config": site_config,
                                "username": perm["phone"],
                                "pattern": perm["pattern"],
                                "mode": "phone",
                                "tier": tier,
                                "delay_range": delay_range,
                            })

        return items

    def _execute_work_items(self, work_items: list[dict], profile: SubjectProfile, max_workers: int = None):
        """Execute work items with limited concurrency."""
        if not work_items:
            return

        # Deduplicate: same site + same username = skip
        seen = set()
        unique_items = []
        for item in work_items:
            key = f"{item['site_name']}::{item['username']}"
            if key not in seen:
                seen.add(key)
                unique_items.append(item)

        total = len(unique_items)
        completed = 0
        found_count = 0
        actionable_count = 0
        manual_review_count = 0
        error_count = 0

        self._emit_progress({
            "type": "tier_work_items",
            "tier": unique_items[0]["tier"] if unique_items else 0,
            "total_checks": total,
        })

        with ThreadPoolExecutor(max_workers=max_workers or MAX_CONCURRENT_REQUESTS) as executor:
            futures = {}
            for item in unique_items:
                self._check_cancelled()
                self._emit_progress({
                    "type": "site_check_started",
                    "site_name": item["site_name"],
                    "username": item["username"],
                    "mode": item["mode"],
                    "tier": item["tier"],
                })
                future = executor.submit(
                    self._check_single_site,
                    item, profile,
                )
                futures[future] = item

            for future in as_completed(futures):
                self._check_cancelled()
                self._check_paused()
                item = futures[future]
                completed += 1

                try:
                    result = future.result()
                    if result:
                        with self._progress_lock:
                            self._results.append(result)

                        status = result.get("status")
                        confidence_level = result.get("confidence_level")
                        if status == "found":
                            found_count += 1
                            if confidence_level in ("Confirmed", "High Confidence"):
                                actionable_count += 1
                            else:
                                manual_review_count += 1
                        elif status == "unverified":
                            manual_review_count += 1
                        elif status in ("error", "rate_limited"):
                            error_count += 1

                        self._emit_progress({
                            "type": "site_check_completed",
                            "site_name": result.get("site_name"),
                            "username": result.get("username_searched"),
                            "status": status,
                            "confidence_level": confidence_level,
                            "confidence_score": result.get("confidence_score"),
                            "url": result.get("url"),
                            "tier": result.get("tier"),
                            "response_time_ms": result.get("response_time_ms", 0),
                            "completed": completed,
                            "total": total,
                            "found_count": found_count,
                            "actionable_findings": actionable_count,
                            "manual_review_count": manual_review_count,
                            "error_count": error_count,
                            "subject_match_score": result.get("subject_match_score", 0),
                            "matched_attributes": result.get("matched_attributes", []),
                            "display_name": result.get("display_name", ""),
                            "location": result.get("location", ""),
                            "cross_links": result.get("cross_platform_links", []),
                            "category": result.get("category", ""),
                            "search_mode": result.get("search_mode", ""),
                        })

                        # Emit progress for found results
                        if result.get("status") == "found":
                            self._emit_progress({
                                "type": "site_found",
                                "site_name": result.get("site_name"),
                                "confidence_level": result.get("confidence_level"),
                                "confidence_score": result.get("confidence_score"),
                                "url": result.get("url"),
                                "tier": result.get("tier"),
                                "actionable_findings": actionable_count,
                                "manual_review_count": manual_review_count,
                            })

                except Exception as e:
                    print(f"[OSINT Engine] Error checking {item.get('site_name')}: {e}")
                    error_count += 1
                    self._emit_progress({
                        "type": "site_check_completed",
                        "site_name": item.get("site_name"),
                        "username": item.get("username"),
                        "status": "error",
                        "confidence_level": "Not Found",
                        "confidence_score": 0,
                        "tier": item.get("tier"),
                        "completed": completed,
                        "total": total,
                        "found_count": found_count,
                        "actionable_findings": actionable_count,
                        "manual_review_count": manual_review_count,
                        "error_count": error_count,
                        "error": str(e),
                    })

                # Progress update every 10 items
                if completed % 10 == 0 or completed == total:
                    self._emit_progress({
                        "type": "progress_update",
                        "completed": completed,
                        "total": total,
                        "tier": item.get("tier", 0),
                        "current_site": item.get("site_name", ""),
                        "found_count": found_count,
                        "actionable_findings": actionable_count,
                        "manual_review_count": manual_review_count,
                        "error_count": error_count,
                    })

    def _check_single_site(self, item: dict, profile: SubjectProfile) -> dict:
        """Check a single site for a single username. Returns SiteResult dict or None."""
        site_name = item["site_name"]
        site_config = item["site_config"]
        username = item["username"]
        pattern = item["pattern"]
        mode = item["mode"]
        tier = item["tier"]
        delay_range = item["delay_range"]

        # Apply delay multiplier
        multiplier = site_config.get("delay_multiplier", 1.0)
        adjusted_delay = (delay_range[0] * multiplier, delay_range[1] * multiplier)

        checked_at = datetime.now(timezone.utc).isoformat()

        try:
            vresult = verify_site(
                site_name=site_name,
                site_config=site_config,
                username=username,
                delay_range=adjusted_delay,
                subject_profile=profile.to_dict(),
            )
        except Exception as e:
            return {
                "site_name": site_name,
                "url": site_config.get("url", "").replace("{}", username),
                "username_searched": username,
                "search_mode": mode,
                "permutation_pattern": pattern,
                "tier": tier,
                "status": "error",
                "confidence_score": 0,
                "confidence_level": "Not Found",
                "signals": [{"name": "exception", "passed": False, "detail": str(e)[:200]}],
                "checked_at": checked_at,
            }

        # Only return results that are interesting (not definitive "not found")
        status = vresult.get("status", "not_found")

        metadata = vresult.get("metadata", {})

        result = {
            "site_name": site_name,
            "url": vresult.get("url", ""),
            "username_searched": username,
            "search_mode": mode,
            "permutation_pattern": pattern,
            "tier": tier,
            "status": status,
            "http_status_code": vresult.get("http_status_code", 0),
            "confidence_score": vresult.get("confidence", 0),
            "confidence_level": vresult.get("confidence_level", "Not Found"),
            "signals": vresult.get("signals", []),
            "secondary_confirmation": vresult.get("secondary_confirmed") is not None,
            "secondary_confirmation_passed": vresult.get("secondary_confirmed"),
            "waf_detected": vresult.get("waf_detected", False),
            "rate_limited": vresult.get("rate_limited", False),
            "antibot_detail": vresult.get("antibot_detail", ""),
            "display_name": metadata.get("display_name", ""),
            "bio": metadata.get("bio", ""),
            "location": metadata.get("location", ""),
            "avatar_url": metadata.get("avatar_url", ""),
            "follower_count": metadata.get("follower_count", ""),
            "name_match": vresult.get("name_match", False),
            "dob_match": vresult.get("dob_match", False),
            "cross_platform_links": vresult.get("cross_platform_links", []),
            "checked_at": checked_at,
            "response_time_ms": vresult.get("response_time_ms", 0),
            "retry_count": vresult.get("retry_count", 0),
            "category": site_config.get("category", "other"),
        }

        # ─── Disambiguation: profile signal extraction + subject match scoring ───
        if status in ("found", "unverified"):
            try:
                response_html = vresult.get("response_body", "")
                profile_url = result["url"]
                signals = extract_profile_signals(response_html, profile_url)

                # Enrich result with extracted signals if verification didn't already get them
                if signals.get("display_name") and not result["display_name"]:
                    result["display_name"] = signals["display_name"]
                if signals.get("bio") and not result["bio"]:
                    result["bio"] = signals["bio"]
                if signals.get("location") and not result["location"]:
                    result["location"] = signals["location"]
                if signals.get("avatar_url") and not result["avatar_url"]:
                    result["avatar_url"] = signals["avatar_url"]
                if signals.get("cross_links"):
                    result["cross_platform_links"] = signals["cross_links"]

                # Score against subject profile
                profile_data = profile.to_dict()
                sms, matched_attrs = score_subject_match(signals, profile_data)
                result["subject_match_score"] = sms
                result["matched_attributes"] = matched_attrs

                # Evidence chain — explains WHY this account matches
                evidence = build_evidence_chain(signals, result, profile_data)
                result["evidence_chain"] = evidence
                result["disambiguation_tier"] = calculate_disambiguation_tier(evidence)

                # Pivot candidates — new identifiers found in this bio
                new_anchors = extract_new_anchors(signals, profile_data)
                if new_anchors:
                    result["new_anchors_found"] = new_anchors
            except Exception:
                pass  # Don't let profiler errors break the check

        return result

    def _score_to_level(self, score: float) -> str:
        # Kept in lockstep with verification._score_to_level.
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

    def run_calibration(self, site_names: list[str] = None) -> dict:
        """
        Run calibration/self-test mode.

        Tests each site's detection logic using a known-existing account
        and a known-nonexistent account.
        """
        self.sites = load_all_sites()
        sites_to_test = {}

        if site_names:
            sites_to_test = {n: c for n, c in self.sites.items() if n in site_names}
        else:
            # Only test sites that have known_username
            sites_to_test = {n: c for n, c in self.sites.items() if c.get("known_username")}

        results = []

        for site_name, config in sites_to_test.items():
            known_user = config.get("known_username", "")
            if not known_user:
                continue

            tier = config.get("tier", 3)
            delay_range = _get_delay_for_tier(tier)

            # Test 1: Known existing user should be found
            positive_result = verify_site(
                site_name=site_name,
                site_config=config,
                username=known_user,
                delay_range=delay_range,
            )

            # Test 2: Random user should NOT be found
            import random, string
            fake_user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=18))
            negative_result = verify_site(
                site_name=site_name,
                site_config=config,
                username=fake_user,
                delay_range=delay_range,
            )

            positive_ok = positive_result.get("status") == "found"
            negative_ok = negative_result.get("status") in ("not_found", "unverified")

            passed = positive_ok and negative_ok

            results.append({
                "site_name": site_name,
                "known_username": known_user,
                "passed": passed,
                "positive_test": {
                    "status": positive_result.get("status"),
                    "confidence": positive_result.get("confidence", 0),
                    "expected": "found",
                    "ok": positive_ok,
                },
                "negative_test": {
                    "status": negative_result.get("status"),
                    "confidence": negative_result.get("confidence", 0),
                    "expected": "not_found",
                    "ok": negative_ok,
                },
            })

        passed_count = sum(1 for r in results if r["passed"])
        total = len(results)

        return {
            "success": True,
            "total_tested": total,
            "passed": passed_count,
            "failed": total - passed_count,
            "pass_rate": f"{(passed_count / total * 100):.1f}%" if total > 0 else "N/A",
            "results": results,
        }


# ─── Convenience functions for backward compatibility ───

def quick_search(target: str, modes: list[str] = None) -> dict:
    """
    Quick search with auto-detected input type.
    Maintains backward compatibility with the old osint_checker API.
    """
    input_type = detect_input_type(target)

    profile = SubjectProfile()
    if input_type == "USERNAME":
        profile.usernames = [target]
    elif input_type == "EMAIL":
        profile.emails = [target]
    elif input_type == "PHONE":
        profile.phones = [target]
    elif input_type == "NAME":
        parts = target.strip().split()
        if len(parts) >= 2:
            profile.first_name = parts[0]
            profile.last_name = parts[-1]
            if len(parts) > 2:
                profile.middle_name = " ".join(parts[1:-1])

    if modes is None:
        modes = [input_type.lower()]
        if input_type == "NAME":
            modes = ["name"]

    engine = InvestigationEngine()
    return engine.run_investigation(profile, modes=modes)
