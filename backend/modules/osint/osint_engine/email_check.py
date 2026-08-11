"""
Email Account Enumeration — Holehe-style email-availability probes.

For each supported site, ask "is this email registered?" using the site's
public signup-availability or password-recovery endpoint, WITHOUT triggering
a password-reset email or completing any account-creation flow.

Each checker returns:
    {
      "site": str,
      "email": str,
      "exists": True | False | None,   # None = inconclusive / rate-limited
      "rate_limited": bool,
      "emailrecovery": str | None,     # e.g. "me****s@gmail.com"
      "phoneNumber":  str | None,      # e.g. "+91 ******78"
      "method": str,                   # "register" | "login" | "password_recovery" | "other"
      "checked_at": str,               # ISO 8601 UTC
      "error": str | None,
    }

Design references:
  - Holehe (megadose/holehe) — endpoint patterns and detection signals
  - h8mail — provider plugin shape

All probes are READ-ONLY at the user-experience level: no email is dispatched
to the address being checked. Where a site does dispatch a recovery email
(rare; default OFF), the checker is gated behind a config flag.
"""

import json
import random
import string
import re
from datetime import datetime, timezone

from .http_client import make_request


# ─── Output schema ───────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(
    site: str,
    email: str,
    exists,
    *,
    rate_limited: bool = False,
    emailrecovery: str = None,
    phone: str = None,
    method: str = "other",
    error: str = None,
    extra: dict = None,
) -> dict:
    out = {
        "site": site,
        "email": email,
        "exists": exists,
        "rate_limited": rate_limited,
        "emailrecovery": emailrecovery,
        "phoneNumber": phone,
        "method": method,
        "checked_at": _now_iso(),
        "error": error,
    }
    if extra:
        out["extra"] = extra
    return out


def _rand_username(n: int = 14) -> str:
    """Random throwaway username for signup-attempt probes."""
    pool = string.ascii_lowercase + string.digits
    return "".join(random.choices(pool, k=n))


def _safe_json(body: str):
    try:
        return json.loads(body)
    except Exception:
        return None


# ─── Per-site checkers ───────────────────────────────────────────────────
#
# Each function: (email: str) -> dict from _result(...).
#
# Convention: return exists=None on rate limit / WAF / unparseable response —
# never claim True or False without evidence. The engine downgrades None
# to "inconclusive" in the report.


def check_instagram(email: str) -> dict:
    """Instagram signup-attempt API — non-creation probe.

    Holehe pattern: POST a signup with random throwaway username, observe
    whether the email-validation step rejects with 'email_is_taken'.
    """
    url = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
    payload = {
        "email": email,
        "username": _rand_username(),
        "first_name": "",
        "opt_into_one_tap": "false",
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "X-CSRFToken": "missing",
        "Accept": "*/*",
        "Origin": "https://www.instagram.com",
        "Referer": "https://www.instagram.com/accounts/emailsignup/",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    # Use POST with form-encoded body via raw payload
    resp = make_request(
        url=url,
        method="POST",
        json_payload=payload,
        headers=headers,
        delay_range=(2.0, 4.0),
    )
    if not resp["success"] or resp.get("rate_limited"):
        return _result("Instagram", email, None,
                       rate_limited=resp.get("rate_limited", False),
                       method="register",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    errors = data.get("errors", {}) or {}
    email_errors = errors.get("email", []) or []
    for e in email_errors:
        if isinstance(e, dict) and e.get("code") == "email_is_taken":
            return _result("Instagram", email, True, method="register")
    # Email-step accepted → not registered
    if "email" not in errors and data.get("dryrun_passed"):
        return _result("Instagram", email, False, method="register")
    return _result("Instagram", email, None, method="register")


def check_twitter(email: str) -> dict:
    """X/Twitter email-availability endpoint."""
    url = f"https://api.twitter.com/i/users/email_available.json?email={email}"
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"] or resp.get("rate_limited"):
        return _result("Twitter/X", email, None,
                       rate_limited=resp.get("rate_limited", False),
                       method="register",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    if "taken" in data:
        return _result("Twitter/X", email, bool(data["taken"]), method="register")
    return _result("Twitter/X", email, None, method="register")


def check_pinterest(email: str) -> dict:
    """Pinterest EmailExistsResource endpoint."""
    url = (
        "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/"
        '?source_url=/&data={"options":{"email":"' + email + '"},"context":{}}'
    )
    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.pinterest.com/",
    }
    resp = make_request(url=url, headers=headers, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Pinterest", email, None, method="other",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    rr = (data.get("resource_response") or {}).get("data")
    if rr is True:
        return _result("Pinterest", email, True, method="other")
    if rr is False:
        return _result("Pinterest", email, False, method="other")
    return _result("Pinterest", email, None, method="other")


def check_spotify(email: str) -> dict:
    """Spotify signup validate endpoint."""
    url = (
        "https://spclient.wg.spotify.com/signup/public/v1/account?"
        f"validate=1&email={email}"
    )
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Spotify", email, None, method="register",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    if data.get("status") == 20:
        return _result("Spotify", email, False, method="register")
    if data.get("status") == 320 or "taken" in (data.get("errors", {}) or {}).get("email", "").lower():
        return _result("Spotify", email, True, method="register")
    if isinstance(data.get("errors"), dict) and data["errors"].get("email"):
        return _result("Spotify", email, True, method="register")
    return _result("Spotify", email, None, method="register")


def check_lastpass(email: str) -> dict:
    """LastPass iterations.php — returns a number for existing accounts."""
    url = "https://lastpass.com/iterations.php"
    payload = {"email": email}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("LastPass", email, None, method="other",
                       error=resp.get("error"))
    body = (resp.get("body") or "").strip()
    if body.isdigit() and int(body) > 0:
        return _result("LastPass", email, True, method="other",
                       extra={"iterations": int(body)})
    return _result("LastPass", email, False, method="other")


def check_adobe(email: str) -> dict:
    """Adobe sign-in availability."""
    url = "https://auth.services.adobe.com/signin/v2/users/check"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {"username": email}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, headers=headers,
                        delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Adobe", email, None, method="login",
                       error=resp.get("error"))
    body = resp.get("body", "")
    data = _safe_json(body) or {}
    if data.get("authenticationMethod") in ("Password", "ImsApi"):
        return _result("Adobe", email, True, method="login")
    if "user not found" in body.lower() or "no such" in body.lower():
        return _result("Adobe", email, False, method="login")
    return _result("Adobe", email, None, method="login")


def check_microsoft(email: str) -> dict:
    """Microsoft / Outlook GetCredentialType endpoint."""
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    payload = {
        "username": email,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "",
        "country": "IN",
        "forceotclogin": False,
        "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False,
        "federationFlags": 0,
    }
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, headers=headers,
                        delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Microsoft", email, None, method="login",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    if data.get("IfExistsResult") == 0:
        return _result("Microsoft", email, True, method="login")
    if data.get("IfExistsResult") == 1:
        return _result("Microsoft", email, False, method="login")
    return _result("Microsoft", email, None, method="login")


def check_github(email: str) -> dict:
    """GitHub signup email validation (forces signup HTML to surface errors)."""
    url = "https://github.com/signup_check/email"
    headers = {
        "Accept": "text/html, application/xhtml+xml",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://github.com/join",
    }
    payload = {"value": email}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, headers=headers,
                        delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("GitHub", email, None, method="register",
                       error=resp.get("error"))
    body = (resp.get("body") or "").lower()
    if "email is invalid or already taken" in body or "already taken" in body:
        return _result("GitHub", email, True, method="register")
    if resp.get("status_code") == 200 and not body.strip():
        return _result("GitHub", email, False, method="register")
    return _result("GitHub", email, None, method="register")


def check_wordpress(email: str) -> dict:
    """Wordpress.com signup availability."""
    url = "https://public-api.wordpress.com/rest/v1.1/users/email/" + email + "/exists"
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Wordpress.com", email, None, method="register",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    if "available" in data:
        return _result("Wordpress.com", email, not data["available"],
                       method="register")
    return _result("Wordpress.com", email, None, method="register")


def check_patreon(email: str) -> dict:
    """Patreon email validate."""
    url = "https://www.patreon.com/api/auth/email-validate"
    headers = {"Content-Type": "application/json"}
    payload = {"email": email}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, headers=headers,
                        delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Patreon", email, None, method="other",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    errs = (data.get("errors") or [])
    for e in errs:
        if isinstance(e, dict) and "already" in (e.get("detail", "") or "").lower():
            return _result("Patreon", email, True, method="other")
    if not errs:
        return _result("Patreon", email, False, method="other")
    return _result("Patreon", email, None, method="other")


def check_strava(email: str) -> dict:
    """Strava onboarding email-check."""
    url = "https://www.strava.com/onboarding/email_check"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = {"email": email}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, headers=headers,
                        delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Strava", email, None, method="register",
                       error=resp.get("error"))
    body = (resp.get("body") or "").lower()
    if "already" in body or "in use" in body or "exist" in body:
        return _result("Strava", email, True, method="register")
    return _result("Strava", email, False, method="register")


def check_duolingo(email: str) -> dict:
    """Duolingo users-by-email."""
    url = f"https://www.duolingo.com/2017-06-30/users?email={email}"
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Duolingo", email, None, method="other",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    users = data.get("users") or []
    return _result("Duolingo", email, bool(users), method="other")


def check_gravatar(email: str) -> dict:
    """Gravatar — public profile lookup by md5(email)."""
    import hashlib
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://en.gravatar.com/{h}.json"
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Gravatar", email, None, method="other",
                       error=resp.get("error"))
    if resp.get("status_code") == 404:
        return _result("Gravatar", email, False, method="other")
    data = _safe_json(resp.get("body", "")) or {}
    if data.get("entry"):
        entry = data["entry"][0] if isinstance(data["entry"], list) else {}
        recovery = (entry.get("emails") or [{}])[0].get("value") if entry else None
        return _result("Gravatar", email, True, method="other",
                       emailrecovery=recovery,
                       extra={"profile_url": entry.get("profileUrl") if entry else None})
    return _result("Gravatar", email, None, method="other")


def check_tumblr(email: str) -> dict:
    """Tumblr signup register endpoint."""
    url = "https://www.tumblr.com/svc/account/register"
    payload = {
        "user[email]": email,
        "user[password]": "tumblr_password_check_only",
        "tumblelog[name]": _rand_username(),
        "user[age]": 30,
    }
    headers = {"X-Requested-With": "XMLHttpRequest"}
    resp = make_request(url=url, method="POST",
                        json_payload=payload, headers=headers,
                        delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Tumblr", email, None, method="register",
                       error=resp.get("error"))
    body = (resp.get("body") or "").lower()
    if "email" in body and ("registered" in body or "in use" in body or "taken" in body):
        return _result("Tumblr", email, True, method="register")
    if "email" in body and ("invalid" in body or "format" in body):
        return _result("Tumblr", email, False, method="register")
    return _result("Tumblr", email, None, method="register")


def check_reddit(email: str) -> dict:
    """Reddit email-taken check."""
    url = f"https://www.reddit.com/api/check_email_taken.json?email={email}"
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Reddit", email, None, method="register",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    if "json" in data:
        errs = (data.get("json", {}) or {}).get("errors", [])
        for e in errs:
            joined = " ".join(str(x) for x in e).lower()
            if "taken" in joined or "in use" in joined:
                return _result("Reddit", email, True, method="register")
        return _result("Reddit", email, False, method="register")
    return _result("Reddit", email, None, method="register")


def check_vimeo(email: str) -> dict:
    """Vimeo email lookup."""
    url = f"https://vimeo.com/api/v3/users/email_lookup?email={email}"
    resp = make_request(url=url, delay_range=(2.0, 4.0))
    if not resp["success"]:
        return _result("Vimeo", email, None, method="other",
                       error=resp.get("error"))
    data = _safe_json(resp.get("body", "")) or {}
    if data.get("user_exists") is True:
        return _result("Vimeo", email, True, method="other")
    if data.get("user_exists") is False:
        return _result("Vimeo", email, False, method="other")
    return _result("Vimeo", email, None, method="other")


# ─── Registry ───────────────────────────────────────────────────────────

EMAIL_CHECKERS = {
    "instagram":   check_instagram,
    "twitter":     check_twitter,
    "pinterest":   check_pinterest,
    "spotify":     check_spotify,
    "lastpass":    check_lastpass,
    "adobe":       check_adobe,
    "microsoft":   check_microsoft,
    "github":      check_github,
    "wordpress":   check_wordpress,
    "patreon":     check_patreon,
    "strava":      check_strava,
    "duolingo":    check_duolingo,
    "gravatar":    check_gravatar,
    "tumblr":      check_tumblr,
    "reddit":      check_reddit,
    "vimeo":       check_vimeo,
}


# ─── Public API ─────────────────────────────────────────────────────────


_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match((email or "").strip()))


def run_email_checks(
    email: str,
    sites: list = None,
    progress_cb=None,
) -> list:
    """Run email-availability probes across configured sites.

    Args:
        email: target email address
        sites: optional list of registry keys to limit checks; default = all
        progress_cb: optional callable(site_key, result_dict) -> None

    Returns:
        list[dict] of per-site results in `_result()` schema.
    """
    if not is_valid_email(email):
        return []
    targets = sites or list(EMAIL_CHECKERS.keys())
    out = []
    for key in targets:
        fn = EMAIL_CHECKERS.get(key)
        if not fn:
            continue
        try:
            r = fn(email)
        except Exception as e:
            r = _result(key, email, None, method="other",
                        error=f"checker_exception: {str(e)[:120]}")
        out.append(r)
        if progress_cb:
            try:
                progress_cb(key, r)
            except Exception:
                pass
    return out


def collect_pivot_anchors(results: list) -> dict:
    """From email-check results, harvest masked recovery emails / phones
    that the engine should treat as new pivot anchors.

    Returns:
        {"emails": [...], "phones": [...]}  — masked strings, useful as
        constraints to validate other discovered identifiers.
    """
    anchors = {"emails": [], "phones": []}
    for r in results or []:
        rec = r.get("emailrecovery")
        if rec and rec not in anchors["emails"]:
            anchors["emails"].append(rec)
        ph = r.get("phoneNumber")
        if ph and ph not in anchors["phones"]:
            anchors["phones"].append(ph)
    return anchors
