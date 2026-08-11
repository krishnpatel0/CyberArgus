from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any


class PIIType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    IP = "ip"
    AADHAAR = "aadhaar"
    USERNAME = "username"
    NAME = "name"
    UNKNOWN = "unknown"


_EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_AADHAAR_PATTERN = re.compile(r"^\d{4}\s?\d{4}\s?\d{4}$")


def normalize_column_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name).strip().lower())


def normalize_email(value: Any) -> str | None:
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if not normalized or normalized == "nan" or "@" not in normalized:
        return None

    return normalized


def hash_email(email: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{email}".encode("utf-8"))
    return digest.hexdigest()


def detect_type(input_str: str) -> PIIType:
    if not input_str or not isinstance(input_str, str):
        return PIIType.UNKNOWN

    input_clean = input_str.strip()
    if not input_clean:
        return PIIType.UNKNOWN

    if "@" in input_clean and _EMAIL_PATTERN.match(input_clean):
        return PIIType.EMAIL

    digits_only = re.sub(r"\D", "", input_clean)
    if digits_only.isdigit() and 10 <= len(digits_only) <= 15:
        return PIIType.PHONE

    if _IP_PATTERN.match(input_clean):
        octets = input_clean.split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            return PIIType.IP

    if _AADHAAR_PATTERN.match(input_clean):
        return PIIType.AADHAAR

    cleaned = input_clean.replace(" ", "").replace(".", "").replace("-", "")
    if cleaned.isalpha() and len(cleaned) >= 3:
        return PIIType.NAME

    if len(input_clean) >= 3:
        return PIIType.USERNAME

    return PIIType.UNKNOWN


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if digits.startswith("91") and len(digits) > 10:
        digits = digits[2:]
    if digits.startswith("1") and len(digits) == 11:
        digits = digits[1:]
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


def normalize_input(input_str: str, pii_type: PIIType | None = None) -> str:
    if not input_str:
        return ""

    pii_type = pii_type or detect_type(input_str)
    input_clean = input_str.strip()

    if pii_type == PIIType.PHONE:
        return normalize_phone(input_clean)
    if pii_type == PIIType.EMAIL:
        return input_clean.lower()
    if pii_type == PIIType.AADHAAR:
        return re.sub(r"\s", "", input_clean)
    if pii_type == PIIType.NAME:
        return " ".join(input_clean.lower().split())

    return input_clean.lower()


def json_dumps_sorted(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
