"""
Data models for the OSINT Investigation Engine.
Uses dataclasses for clean, typed data structures.
"""

from dataclasses import dataclass, field
from typing import Optional, TypedDict
from datetime import datetime
import uuid


class NameSearchTarget(TypedDict):
    first: str
    middle: str
    last: str


class SearchTargets(TypedDict):
    usernames: list[str]
    names: list[NameSearchTarget]
    emails: list[str]
    phones: list[str]


@dataclass
class SubjectProfile:
    """Investigation subject profile — rich input for cross-referencing."""

    # Identity Fields
    first_name: str = ""
    middle_name: str = ""
    last_name: str = ""
    aliases: list[str] = field(default_factory=list)       # Known aliases/nicknames
    usernames: list[str] = field(default_factory=list)      # Known usernames
    gender: str = ""                                         # male/female/other
    date_of_birth: str = ""                                  # DD/MM/YYYY
    age_range: str = ""                                      # e.g. "25-35"
    nationality: str = ""
    languages: list[str] = field(default_factory=list)

    # Contact Fields
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    whatsapp_number: str = ""

    # Location Fields
    city: str = ""
    state: str = ""
    country: str = ""
    workplace: str = ""
    educational_institution: str = ""

    # Professional Fields
    occupation: str = ""
    industry: str = ""
    companies: list[str] = field(default_factory=list)
    registration_numbers: list[str] = field(default_factory=list)

    # Digital Footprint Fields
    known_profile_urls: list[str] = field(default_factory=list)
    profile_picture_url: str = ""
    domains: list[str] = field(default_factory=list)
    known_ip: str = ""

    # Case Metadata
    case_id: str = ""
    investigator_name: str = ""
    investigation_purpose: str = ""
    classification_level: str = "Internal"  # Internal/Confidential/Restricted

    def has_searchable_fields(self) -> bool:
        """Check if at least one active search field is provided."""
        return bool(
            self.usernames
            or (self.first_name and self.last_name)
            or self.emails
            or self.phones
        )

    def get_birth_year(self) -> Optional[str]:
        """Extract birth year from DOB if provided."""
        if self.date_of_birth:
            parts = self.date_of_birth.split("/")
            if len(parts) == 3 and len(parts[2]) == 4:
                return parts[2]
        return None

    def get_all_search_targets(self) -> SearchTargets:
        """Get all searchable targets organized by type."""
        targets: SearchTargets = {"usernames": [], "names": [], "emails": [], "phones": []}

        targets["usernames"] = list(self.usernames)
        if self.aliases:
            targets["usernames"].extend(self.aliases)

        if self.first_name and self.last_name:
            targets["names"].append({
                "first": self.first_name.lower().strip(),
                "middle": self.middle_name.lower().strip() if self.middle_name else "",
                "last": self.last_name.lower().strip(),
            })
            # Also generate name entries for each alias
            for alias in self.aliases:
                alias = alias.strip()
                if alias:
                    targets["names"].append({
                        "first": alias.lower(),
                        "middle": "",
                        "last": self.last_name.lower().strip(),
                    })

        targets["emails"] = [e.lower().strip() for e in self.emails if e.strip()]
        targets["phones"] = [p.strip() for p in self.phones if p.strip()]

        return targets

    def to_dict(self) -> dict:
        return {
            "first_name": self.first_name,
            "middle_name": self.middle_name,
            "last_name": self.last_name,
            "aliases": self.aliases,
            "usernames": self.usernames,
            "gender": self.gender,
            "date_of_birth": self.date_of_birth,
            "age_range": self.age_range,
            "nationality": self.nationality,
            "languages": self.languages,
            "emails": self.emails,
            "phones": self.phones,
            "whatsapp_number": self.whatsapp_number,
            "city": self.city,
            "state": self.state,
            "country": self.country,
            "workplace": self.workplace,
            "educational_institution": self.educational_institution,
            "occupation": self.occupation,
            "industry": self.industry,
            "companies": self.companies,
            "registration_numbers": self.registration_numbers,
            "known_profile_urls": self.known_profile_urls,
            "profile_picture_url": self.profile_picture_url,
            "domains": self.domains,
            "known_ip": self.known_ip,
            "case_id": self.case_id,
            "investigator_name": self.investigator_name,
            "investigation_purpose": self.investigation_purpose,
            "classification_level": self.classification_level,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SubjectProfile":
        """Create profile from dictionary, handling comma-separated strings."""
        def to_list(val):
            if isinstance(val, list):
                return [v.strip() for v in val if v and v.strip()]
            if isinstance(val, str) and val.strip():
                return [v.strip() for v in val.split(",") if v.strip()]
            return []

        return cls(
            first_name=str(data.get("first_name", "")).strip(),
            middle_name=str(data.get("middle_name", "")).strip(),
            last_name=str(data.get("last_name", "")).strip(),
            aliases=to_list(data.get("aliases")),
            usernames=to_list(data.get("usernames")),
            gender=str(data.get("gender", "")).strip(),
            date_of_birth=str(data.get("date_of_birth", "")).strip(),
            age_range=str(data.get("age_range", "")).strip(),
            nationality=str(data.get("nationality", "")).strip(),
            languages=to_list(data.get("languages")),
            emails=to_list(data.get("emails")),
            phones=to_list(data.get("phones")),
            whatsapp_number=str(data.get("whatsapp_number", "")).strip(),
            city=str(data.get("city", "")).strip(),
            state=str(data.get("state", "")).strip(),
            country=str(data.get("country", "")).strip(),
            workplace=str(data.get("workplace", "")).strip(),
            educational_institution=str(data.get("educational_institution", "")).strip(),
            occupation=str(data.get("occupation", "")).strip(),
            industry=str(data.get("industry", "")).strip(),
            companies=to_list(data.get("companies")),
            registration_numbers=to_list(data.get("registration_numbers")),
            known_profile_urls=to_list(data.get("known_profile_urls")),
            profile_picture_url=str(data.get("profile_picture_url", "")).strip(),
            domains=to_list(data.get("domains")),
            known_ip=str(data.get("known_ip", "")).strip(),
            case_id=str(data.get("case_id", "")).strip(),
            investigator_name=str(data.get("investigator_name", "")).strip(),
            investigation_purpose=str(data.get("investigation_purpose", "")).strip(),
            classification_level=str(data.get("classification_level", "Internal")).strip(),
        )


@dataclass
class VerificationSignal:
    """A single verification signal contributing to the confidence score."""
    name: str               # e.g. "og_title_matched", "follower_count_present"
    passed: bool
    weight: float
    detail: str = ""        # Human-readable explanation


@dataclass
class SiteResult:
    """Result of checking a single site for a single username/query."""
    site_name: str
    url: str
    username_searched: str
    search_mode: str                    # "username", "name_permutation", "email", "phone"
    permutation_pattern: str = ""       # e.g. "firstname.lastname", "exact_username"
    tier: int = 1

    # Verification
    status: str = "not_found"           # found, not_found, unverified, error, rate_limited
    http_status_code: int = 0
    confidence_score: float = 0.0
    confidence_level: str = "Not Found" # Confirmed, High Confidence, Medium Confidence, Unverified, Not Found
    signals: list = field(default_factory=list)  # List of VerificationSignal dicts
    secondary_confirmation: bool = False
    secondary_confirmation_passed: Optional[bool] = None

    # Anti-bot
    waf_detected: bool = False
    rate_limited: bool = False
    antibot_detail: str = ""

    # Metadata
    display_name: str = ""
    bio: str = ""
    location: str = ""
    avatar_url: str = ""
    profile_created: str = ""
    follower_count: str = ""
    extra_metadata: dict = field(default_factory=dict)

    # Correlation flags
    name_match: bool = False
    dob_match: bool = False
    cross_platform_links: list = field(default_factory=list)

    # Disambiguation (subject match)
    subject_match_score: int = 0              # 0-100: how likely this account belongs to the subject
    matched_attributes: list = field(default_factory=list)  # e.g. ["city:Mumbai", "workplace:TCS"]

    # Timing
    checked_at: str = ""
    response_time_ms: int = 0
    retry_count: int = 0

    # Investigator annotation
    investigator_note: str = ""
    discarded: bool = False

    def to_dict(self) -> dict:
        return {
            "site_name": self.site_name,
            "url": self.url,
            "username_searched": self.username_searched,
            "search_mode": self.search_mode,
            "permutation_pattern": self.permutation_pattern,
            "tier": self.tier,
            "status": self.status,
            "http_status_code": self.http_status_code,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level,
            "signals": self.signals,
            "secondary_confirmation": self.secondary_confirmation,
            "secondary_confirmation_passed": self.secondary_confirmation_passed,
            "waf_detected": self.waf_detected,
            "rate_limited": self.rate_limited,
            "antibot_detail": self.antibot_detail,
            "display_name": self.display_name,
            "bio": self.bio,
            "location": self.location,
            "avatar_url": self.avatar_url,
            "profile_created": self.profile_created,
            "follower_count": self.follower_count,
            "extra_metadata": self.extra_metadata,
            "name_match": self.name_match,
            "dob_match": self.dob_match,
            "cross_platform_links": self.cross_platform_links,
            "subject_match_score": self.subject_match_score,
            "matched_attributes": self.matched_attributes,
            "checked_at": self.checked_at,
            "response_time_ms": self.response_time_ms,
            "retry_count": self.retry_count,
            "investigator_note": self.investigator_note,
            "discarded": self.discarded,
        }


@dataclass
class TierProgress:
    """Progress tracking for a single tier."""
    tier: int
    total_sites: int = 0
    completed: int = 0
    found: int = 0
    status: str = "pending"  # pending, in_progress, completed

    @property
    def percentage(self) -> float:
        if self.total_sites == 0:
            return 0.0
        return round((self.completed / self.total_sites) * 100, 1)

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "total_sites": self.total_sites,
            "completed": self.completed,
            "found": self.found,
            "status": self.status,
            "percentage": self.percentage,
        }


@dataclass
class CorrelationCluster:
    """A cluster of corroborated findings across platforms."""
    cluster_id: str = ""
    username: str = ""
    platforms: list = field(default_factory=list)
    corroboration_type: str = ""  # username_match, name_match, dob_match, cross_link
    confidence_boost: float = 0.0
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "username": self.username,
            "platforms": self.platforms,
            "corroboration_type": self.corroboration_type,
            "confidence_boost": self.confidence_boost,
            "detail": self.detail,
        }


@dataclass
class InvestigationResult:
    """Complete investigation result."""
    investigation_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    started_at: str = ""
    completed_at: str = ""
    elapsed_ms: int = 0

    # Subject
    subject_profile: dict = field(default_factory=dict)

    # Search modes executed
    modes_executed: list = field(default_factory=list)  # ["username", "name", "email", "phone"]

    # Results
    results: list = field(default_factory=list)          # List of SiteResult dicts
    csv_matches: list = field(default_factory=list)      # Breach CSV matches
    correlation_clusters: list = field(default_factory=list)
    identity_clusters: list = field(default_factory=list)  # Disambiguation clusters

    # Tier progress
    tier_progress: list = field(default_factory=list)

    # Summary
    total_sites_checked: int = 0
    total_permutations_checked: int = 0
    confirmed_count: int = 0
    high_confidence_count: int = 0
    medium_confidence_count: int = 0
    ambiguous_count: int = 0
    unverified_count: int = 0
    blocked_count: int = 0
    not_found_count: int = 0
    error_count: int = 0
    actionable_findings: int = 0     # Confirmed + High Confidence
    manual_review_count: int = 0     # Medium + Ambiguous (real leads only)
    low_signal_count: int = 0        # Unverified — not recommended to review
    triage_stats: dict = field(default_factory=dict)

    # Digital footprint summary
    digital_footprint: dict = field(default_factory=dict)

    # Calibration
    calibration_failures: list = field(default_factory=list)

    # Profile strength / disambiguation metadata
    profile_strength: dict = field(default_factory=dict)
    # Pivot suggestions: new identifiers discovered in found account bios
    pivot_suggestions: dict = field(default_factory=dict)

    # SERP pre-pass results (Google/DDG dork discoveries)
    serp_discovery: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "elapsed_ms": self.elapsed_ms,
            "subject_profile": self.subject_profile,
            "modes_executed": self.modes_executed,
            "results": self.results,
            "csv_matches": self.csv_matches,
            "correlation_clusters": self.correlation_clusters,
            "identity_clusters": self.identity_clusters,
            "tier_progress": self.tier_progress,
            "total_sites_checked": self.total_sites_checked,
            "total_permutations_checked": self.total_permutations_checked,
            "confirmed_count": self.confirmed_count,
            "high_confidence_count": self.high_confidence_count,
            "medium_confidence_count": self.medium_confidence_count,
            "ambiguous_count": self.ambiguous_count,
            "unverified_count": self.unverified_count,
            "blocked_count": self.blocked_count,
            "not_found_count": self.not_found_count,
            "error_count": self.error_count,
            "actionable_findings": self.actionable_findings,
            "manual_review_count": self.manual_review_count,
            "low_signal_count": self.low_signal_count,
            "triage_stats": self.triage_stats,
            "digital_footprint": self.digital_footprint,
            "calibration_failures": self.calibration_failures,
            "profile_strength": self.profile_strength,
            "pivot_suggestions": self.pivot_suggestions,
            "serp_discovery": self.serp_discovery,
        }
