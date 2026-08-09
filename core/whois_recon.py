#!/usr/bin/env python3
"""WHOIS lookup — retrieve domain/IP registration information."""

try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


def whois_lookup(target):
    """Perform a WHOIS lookup on a domain or IP.

    Requires the ``python-whois`` library.

    Args:
        target: A domain name or IP address string.

    Returns:
        A dict with registration details, or None on failure.
    """
    if not HAS_WHOIS:
        return {"error": "python-whois not installed. Run: pip install python-whois"}

    try:
        w = python_whois.whois(target)

        # Normalise into a clean dict
        info = {
            "domain_name": _normalise(w.domain_name),
            "registrar": w.registrar,
            "creation_date": str(_normalise(w.creation_date)),
            "expiration_date": str(_normalise(w.expiration_date)),
            "updated_date": str(_normalise(w.updated_date)),
            "name_servers": _normalise(w.name_servers),
            "org": w.org,
            "country": w.country,
            "state": w.state,
            "city": w.city,
            "emails": _normalise(w.emails),
        }

        # Remove None / empty entries
        return {k: v for k, v in info.items() if v is not None and v != "None" and v != ""}
    except Exception as e:
        return {"error": str(e)}


def _normalise(value):
    """If *value* is a list, return the first element for single-item lists."""
    if isinstance(value, list):
        return value[0] if len(value) == 1 else value
    return value
