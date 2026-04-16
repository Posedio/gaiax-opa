#!/usr/bin/env python3
"""validate_vat.py — Gaia-X VatID credential-subject validator.

Called by the OPA python_script plugin via runPythonScript:

    runPythonScript("validate_vat", credentialSubject, expectedCountry)

Arguments (positional, JSON-encoded):
    1. credentialSubject  – the gx:VatID credential subject object
    2. expectedCountry    – ISO 3166-1 alpha-2 country code string (optional)

Stdout: JSON object  {"valid": bool, "reason": str}
Stderr: diagnostic messages (forwarded to OPA logs at warn/error level)
"""

import json
import re
import sys


# ---------------------------------------------------------------------------
# EU VAT number patterns per country code.
# Each value is a compiled regex that matches the national number *without*
# the 2-letter country prefix (the prefix is validated separately).
# ---------------------------------------------------------------------------
_VAT_PATTERNS: dict[str, re.Pattern] = {
    "AT": re.compile(r"^U\d{8}$"),
    "BE": re.compile(r"^\d{10}$"),
    "BG": re.compile(r"^\d{9,10}$"),
    "CY": re.compile(r"^\d{8}[A-Z]$"),
    "CZ": re.compile(r"^\d{8,10}$"),
    "DE": re.compile(r"^\d{9}$"),
    "DK": re.compile(r"^\d{8}$"),
    "EE": re.compile(r"^\d{9}$"),
    "ES": re.compile(r"^[A-Z0-9]\d{7}[A-Z0-9]$"),
    "FI": re.compile(r"^\d{8}$"),
    "FR": re.compile(r"^[A-Z0-9]{2}\d{9}$"),
    "GR": re.compile(r"^\d{9}$"),
    "HR": re.compile(r"^\d{11}$"),
    "HU": re.compile(r"^\d{8}$"),
    "IE": re.compile(r"^\d[A-Z0-9+*]\d{5}[A-Z]{1,2}$"),
    "IT": re.compile(r"^\d{11}$"),
    "LT": re.compile(r"^(\d{9}|\d{12})$"),
    "LU": re.compile(r"^\d{8}$"),
    "LV": re.compile(r"^\d{11}$"),
    "MT": re.compile(r"^\d{8}$"),
    "NL": re.compile(r"^\d{9}B\d{2}$"),
    "PL": re.compile(r"^\d{10}$"),
    "PT": re.compile(r"^\d{9}$"),
    "RO": re.compile(r"^\d{2,10}$"),
    "SE": re.compile(r"^\d{12}$"),
    "SI": re.compile(r"^\d{8}$"),
    "SK": re.compile(r"^\d{10}$"),
}


def validate(credential_subject: dict, expected_country: str | None) -> dict:
    vat_id: str = credential_subject.get("gx:vatID", "")
    if not vat_id:
        return {"valid": False, "reason": "gx:vatID field is missing or empty"}

    if len(vat_id) < 3:
        return {"valid": False, "reason": f"VAT ID {vat_id!r} is too short"}

    country_prefix = vat_id[:2].upper()
    national_part = vat_id[2:]

    # Validate country prefix against expectedCountry when provided
    if expected_country:
        if country_prefix != expected_country.upper():
            return {
                "valid": False,
                "reason": (
                    f"VAT ID country prefix {country_prefix!r} does not match "
                    f"expected country {expected_country!r}"
                ),
            }

    # Cross-check with gx:countryCode in the credential subject
    cs_country: str = credential_subject.get("gx:countryCode", "")
    if cs_country and cs_country.upper() != country_prefix:
        return {
            "valid": False,
            "reason": (
                f"VAT ID country prefix {country_prefix!r} does not match "
                f"credentialSubject gx:countryCode {cs_country!r}"
            ),
        }

    pattern = _VAT_PATTERNS.get(country_prefix)
    if pattern is None:
        # Unknown country — accept the prefix but warn
        print(
            f"warning: no VAT pattern for country {country_prefix!r}, skipping format check",
            file=sys.stderr,
        )
        return {"valid": True, "reason": "format check skipped for unknown country"}

    if not pattern.match(national_part):
        return {
            "valid": False,
            "reason": (
                f"VAT ID {vat_id!r} does not match expected format for country {country_prefix!r}"
            ),
        }

    return {"valid": True, "reason": ""}


def main() -> None:
    if len(sys.argv) < 2:
        print(json.dumps({"valid": False, "reason": "missing credentialSubject argument"}))
        sys.exit(0)

    try:
        credential_subject = json.loads(sys.argv[1])
    except json.JSONDecodeError as exc:
        print(json.dumps({"valid": False, "reason": f"invalid credentialSubject JSON: {exc}"}))
        sys.exit(0)

    expected_country: str | None = None
    if len(sys.argv) >= 3:
        try:
            expected_country = json.loads(sys.argv[2])
        except json.JSONDecodeError as exc:
            print(json.dumps({"valid": False, "reason": f"invalid expectedCountry JSON: {exc}"}))
            sys.exit(0)

    result = validate(credential_subject, expected_country)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
