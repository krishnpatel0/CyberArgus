"""
Breach CSV Cross-Reference Search for OSINT Investigation Engine.

Searches operator-mounted CSV files for matches against investigation targets.
No breach-style records are bundled with the public repository or image.
"""

import csv
import os
import re


# Fields to search by input type
SEARCH_FIELDS = {
    "USERNAME": [
        "fb_username", "ig_username", "linkedin_username", "twitter_handle",
        "base_username", "email", "username", "user", "screen_name",
        "first_name", "last_name", "full_name", "name", "contact_person",
    ],
    "EMAIL": [
        "email", "primary_email", "secondary_email", "email2",
        "email_address", "e_mail", "contact_email",
    ],
    "PHONE": [
        "phone", "primary_phone", "secondary_phone", "phone2",
        "mobile", "phone_number", "contact_number", "mobile_number",
        "whatsapp", "telephone",
    ],
    "NAME": [
        "first_name", "last_name", "full_name", "contact_person",
        "name", "display_name", "user_name",
    ],
}

EXCLUDED_FILES = {"connected_users.csv"}

# Resolve the operator-controlled breach-data directory.
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUM_DATA_DIR = os.getenv(
    "ARGUS_BREACH_DATA_DIR",
    os.path.join(_BASE_DIR, "..", "data", "breach"),
)


def _normalize_phone(phone_str: str) -> str:
    """Normalize phone to last 10 digits."""
    digits = re.sub(r'\D', '', str(phone_str))
    if digits.startswith('91') and len(digits) > 10:
        digits = digits[2:]
    if digits.startswith('1') and len(digits) == 11:
        digits = digits[1:]
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


def search_csv_sources(target: str, input_type: str = "USERNAME") -> list[dict]:
    """
    Search CSV breach data files for matches.

    Returns list of matched records with metadata.
    """
    data_dir = DUM_DATA_DIR
    if not os.path.isdir(data_dir):
        return []

    target_lower = target.strip().lower()
    search_fields = SEARCH_FIELDS.get(input_type, SEARCH_FIELDS["USERNAME"])

    # Normalize phone for comparison
    target_phone = ""
    if input_type == "PHONE":
        target_phone = _normalize_phone(target)

    # For NAME searches, extract first and last
    first_name = ""
    last_name = ""
    if input_type == "NAME":
        parts = target.strip().split()
        if len(parts) >= 2:
            first_name = parts[0].lower()
            last_name = parts[-1].lower()

    matches = []

    try:
        csv_files = [f for f in os.listdir(data_dir)
                     if f.endswith('.csv') and f not in EXCLUDED_FILES]
    except OSError:
        return []

    for csv_file in csv_files:
        filepath = os.path.join(data_dir, csv_file)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames is None:
                    continue

                # Find which search fields exist in this CSV
                available_fields = [
                    field for field in search_fields
                    if field in reader.fieldnames
                ]
                if not available_fields:
                    continue

                for row in reader:
                    matched_field = None

                    for field in available_fields:
                        value = (row.get(field) or "").strip()
                        if not value:
                            continue

                        if input_type == "PHONE":
                            if _normalize_phone(value) == target_phone:
                                matched_field = field
                                break
                        elif input_type == "NAME":
                            value_lower = value.lower()
                            if first_name and last_name:
                                if first_name in value_lower and last_name in value_lower:
                                    matched_field = field
                                    break
                            elif target_lower in value_lower:
                                matched_field = field
                                break
                        else:
                            if value.lower() == target_lower:
                                matched_field = field
                                break

                    if matched_field:
                        record = dict(row)
                        record["_matched_field"] = matched_field
                        record["_source_csv"] = csv_file
                        record["_match_type"] = input_type
                        matches.append(record)

        except (OSError, csv.Error):
            continue

    return matches
