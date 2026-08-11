"""
Username Permutation Generator for OSINT Investigation Engine.

Generates comprehensive username permutations for each search mode:
- Mode 1 (Username): variations, suffixes, separator swaps
- Mode 2 (Full Name): firstname/lastname combinations, initials, leet speak
- Mode 3 (Email): local-part derived username
- Mode 4 (Phone): format normalisation

All permutations are tagged with their pattern for grouping in results.
"""

from .config import (
    INDIAN_NUMBER_SUFFIXES,
    INDIAN_TEXT_SUFFIXES,
    NAME_SEPARATORS,
    LEET_MAP,
    MAX_NAME_LENGTH_FOR_LEET,
    MAX_PERMUTATIONS_PER_MODE,
)


def _deduplicate(permutations: list[dict]) -> list[dict]:
    """Remove duplicate usernames while preserving first occurrence and pattern."""
    seen = set()
    result = []
    for perm in permutations:
        u = perm["username"].lower()
        if u and u not in seen and len(u) >= 2:
            seen.add(u)
            result.append(perm)
    return result[:MAX_PERMUTATIONS_PER_MODE]


# ─── Mode 1: Username Permutations ───

def generate_username_permutations(username: str, birth_year: str = None, aliases: list[str] = None) -> list[dict]:
    """
    Generate username permutations from a known username.

    Returns list of dicts: [{"username": str, "pattern": str}, ...]
    """
    perms = []

    # Exact username
    perms.append({"username": username, "pattern": "exact_username"})

    # Separator swaps
    if "_" in username:
        perms.append({"username": username.replace("_", "."), "pattern": "underscore_to_dot"})
        perms.append({"username": username.replace("_", ""), "pattern": "remove_underscores"})
        perms.append({"username": username.replace("_", "-"), "pattern": "underscore_to_dash"})
    if "." in username:
        perms.append({"username": username.replace(".", "_"), "pattern": "dot_to_underscore"})
        perms.append({"username": username.replace(".", ""), "pattern": "remove_dots"})
        perms.append({"username": username.replace(".", "-"), "pattern": "dot_to_dash"})
    if "-" in username:
        perms.append({"username": username.replace("-", "_"), "pattern": "dash_to_underscore"})
        perms.append({"username": username.replace("-", "."), "pattern": "dash_to_dot"})
        perms.append({"username": username.replace("-", ""), "pattern": "remove_dashes"})

    # Indian number suffixes
    for suffix in INDIAN_NUMBER_SUFFIXES:
        perms.append({"username": f"{username}{suffix}", "pattern": f"suffix_{suffix}"})

    # Birth year suffix
    if birth_year:
        perms.append({"username": f"{username}{birth_year}", "pattern": "suffix_birthyear"})
        short_year = birth_year[-2:]
        perms.append({"username": f"{username}{short_year}", "pattern": "suffix_birthyear_short"})

    # Indian text suffixes
    for suffix in INDIAN_TEXT_SUFFIXES:
        perms.append({"username": f"{username}{suffix}", "pattern": f"suffix_{suffix.strip('_.')}"})

    # Process aliases as separate full search entries
    if aliases:
        for alias in aliases:
            alias = alias.strip().lower()
            if alias and alias != username.lower():
                perms.append({"username": alias, "pattern": "alias"})
                for suffix in INDIAN_NUMBER_SUFFIXES:
                    perms.append({"username": f"{alias}{suffix}", "pattern": f"alias_suffix_{suffix}"})
                if birth_year:
                    perms.append({"username": f"{alias}{birth_year}", "pattern": "alias_suffix_birthyear"})
                for suffix in INDIAN_TEXT_SUFFIXES:
                    perms.append({"username": f"{alias}{suffix}", "pattern": f"alias_suffix_{suffix.strip('_.')}"})

    return _deduplicate(perms)


# ─── Mode 2: Full Name Permutations ───

def generate_name_permutations(
    first_name: str,
    last_name: str,
    middle_name: str = "",
    birth_year: str = None,
    aliases: list[str] = None,
) -> list[dict]:
    """
    Generate comprehensive username permutations from a full name.

    Returns list of dicts: [{"username": str, "pattern": str}, ...]
    """
    first = first_name.lower().strip()
    last = last_name.lower().strip()
    middle = middle_name.lower().strip() if middle_name else ""

    if not first or not last:
        return []

    fi = first[0]  # first initial
    li = last[0]   # last initial
    mi = middle[0] if middle else ""  # middle initial

    perms = []

    # ─── Base permutations ───
    base_patterns = {
        f"{first}{last}": "firstname_lastname",
        f"{last}{first}": "lastname_firstname",
    }

    for sep in [".", "_", "-"]:
        base_patterns[f"{first}{sep}{last}"] = f"first{sep}last"
        base_patterns[f"{last}{sep}{first}"] = f"last{sep}first"

    # Initial-based
    base_patterns[f"{fi}{last}"] = "initial_lastname"
    base_patterns[f"{last}{fi}"] = "lastname_initial"
    base_patterns[f"{fi}.{last}"] = "initial.lastname"
    base_patterns[f"{fi}_{last}"] = "initial_lastname_underscore"
    base_patterns[f"{first}{li}"] = "firstname_lastinitial"

    # Middle name permutations
    if middle:
        base_patterns[f"{fi}{mi}{last}"] = "fi_mi_lastname"
        base_patterns[f"{first}{middle}{last}"] = "first_middle_last"
        base_patterns[f"{first}.{middle}.{last}"] = "first.middle.last"
        base_patterns[f"{first}_{middle}_{last}"] = "first_middle_last_underscore"
        base_patterns[f"{fi}{mi}.{last}"] = "fi_mi.lastname"

    # Add all base patterns
    for username, pattern in base_patterns.items():
        perms.append({"username": username, "pattern": pattern})

    # ─── Add suffixes to all base patterns ───
    base_usernames = list(base_patterns.items())

    # Birth year suffixes
    if birth_year:
        for uname, pat in base_usernames:
            perms.append({"username": f"{uname}{birth_year}", "pattern": f"{pat}_birthyear"})
            short_year = birth_year[-2:]
            perms.append({"username": f"{uname}{short_year}", "pattern": f"{pat}_birthyear_short"})

    # Indian number suffixes
    for suffix in INDIAN_NUMBER_SUFFIXES:
        for uname, pat in base_usernames:
            perms.append({"username": f"{uname}{suffix}", "pattern": f"{pat}_{suffix}"})

    # Indian text suffixes
    for suffix in INDIAN_TEXT_SUFFIXES:
        for uname, pat in base_usernames:
            perms.append({"username": f"{uname}{suffix}", "pattern": f"{pat}_{suffix.strip('_.')}"})

    # ─── Leet speak (only for short names) ───
    combined_len = len(first) + len(last)
    if combined_len <= MAX_NAME_LENGTH_FOR_LEET:
        leet_bases = [f"{first}{last}", f"{first}.{last}", f"{first}_{last}"]
        for base in leet_bases:
            leet = _apply_leet(base)
            if leet != base:
                perms.append({"username": leet, "pattern": "leet_speak"})

    # ─── Alias-based permutations ───
    if aliases:
        for alias in aliases:
            alias = alias.strip().lower()
            if not alias or alias == first:
                continue
            # Treat alias as first name, regenerate core combos
            alias_patterns = {
                f"{alias}{last}": "alias_lastname",
                f"{last}{alias}": "lastname_alias",
                f"{alias}.{last}": "alias.lastname",
                f"{alias}_{last}": "alias_lastname_underscore",
                f"{alias}-{last}": "alias-lastname",
                f"{alias[0]}{last}": "alias_initial_lastname",
            }
            for uname, pat in alias_patterns.items():
                perms.append({"username": uname, "pattern": pat})
                if birth_year:
                    perms.append({"username": f"{uname}{birth_year}", "pattern": f"{pat}_birthyear"})
                for suffix in INDIAN_NUMBER_SUFFIXES:
                    perms.append({"username": f"{uname}{suffix}", "pattern": f"{pat}_{suffix}"})

    return _deduplicate(perms)


def _apply_leet(text: str) -> str:
    """Apply single-level leet speak substitutions."""
    result = []
    for ch in text:
        if ch.lower() in LEET_MAP:
            result.append(LEET_MAP[ch.lower()])
        else:
            result.append(ch)
    return "".join(result)


# ─── Mode 3: Email Permutations ───

def generate_email_permutations(email: str) -> list[dict]:
    """
    Generate search targets from an email address.

    Returns list of dicts: [{"username": str, "pattern": str, "type": str}, ...]
    """
    email = email.lower().strip()
    if "@" not in email:
        return [{"username": email, "pattern": "raw_input", "type": "username"}]

    local_part, domain = email.split("@", 1)

    perms = []

    # The email itself (for email-specific checks)
    perms.append({"username": email, "pattern": "full_email", "type": "email"})

    # Clean local part as username
    clean_local = local_part.replace(".", "").replace("_", "").replace("-", "").replace("+", "")
    perms.append({"username": clean_local, "pattern": "email_local_clean", "type": "username"})

    # Local part with original formatting
    if local_part != clean_local:
        perms.append({"username": local_part, "pattern": "email_local_raw", "type": "username"})

    # Handle plus addressing (user+tag@domain)
    if "+" in local_part:
        base = local_part.split("+")[0]
        perms.append({"username": base, "pattern": "email_plus_stripped", "type": "username"})

    # Handle dot separation (f.last -> flast, f_last)
    if "." in local_part:
        parts = local_part.split(".")
        perms.append({"username": "_".join(parts), "pattern": "email_dot_to_underscore", "type": "username"})
        perms.append({"username": "".join(parts), "pattern": "email_dots_removed", "type": "username"})

    return _deduplicate(perms)


# ─── Mode 4: Phone Permutations ───

def generate_phone_permutations(phone: str) -> list[dict]:
    """
    Generate normalised phone number formats for searching.

    Returns list of dicts: [{"phone": str, "pattern": str}, ...]
    """
    import re
    digits = re.sub(r'\D', '', phone)

    # Remove country code if present
    raw_10 = digits
    if digits.startswith("91") and len(digits) > 10:
        raw_10 = digits[2:]
    elif digits.startswith("1") and len(digits) == 11:
        raw_10 = digits[1:]
    if len(raw_10) > 10:
        raw_10 = raw_10[-10:]

    perms = []

    # All Indian formats
    perms.append({"phone": raw_10, "pattern": "raw_10_digit"})
    perms.append({"phone": f"+91{raw_10}", "pattern": "plus91"})
    perms.append({"phone": f"91{raw_10}", "pattern": "91_prefix"})
    perms.append({"phone": f"0{raw_10}", "pattern": "zero_prefix"})

    # Formatted versions
    if len(raw_10) == 10:
        perms.append({"phone": f"+91-{raw_10[:5]}-{raw_10[5:]}", "pattern": "formatted_dash"})
        perms.append({"phone": f"+91 {raw_10[:5]} {raw_10[5:]}", "pattern": "formatted_space"})

    return perms
