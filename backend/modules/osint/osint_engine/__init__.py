"""
OSINT Intelligence Engine — Enterprise-Grade Investigation Platform.

Designed for professional investigative use: law enforcement support,
corporate due diligence, fraud investigation, and security research.

Architecture:
    - Multi-signal verification with claimed_if/not_claimed_if/ambiguous_if
    - Enterprise confidence scoring (Confirmed/High/Medium/Unverified/NotFound)
    - 4 independent search modes: Username, Full Name, Email, Phone
    - India-centric tiered site ordering (Tier 1/2/3)
    - Entity correlation and intelligence enrichment
    - Professional report generation (JSON/CSV/PDF)
"""

__version__ = "2.0.0"

from .engine import InvestigationEngine
from .models import SubjectProfile, InvestigationResult, SiteResult

__all__ = ["InvestigationEngine", "SubjectProfile", "InvestigationResult", "SiteResult"]
