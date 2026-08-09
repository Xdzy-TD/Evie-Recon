#!/usr/bin/env python3
"""
CVE / Vulnerability lookup — query the NIST NVD API for known
vulnerabilities matching detected services and versions.
"""

import re
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Rate limiter: NVD allows 5 requests per 30 seconds without an API key
_last_request_time = 0
_REQUEST_INTERVAL = 6.5  # seconds between requests


def vuln_lookup(service, version=None, max_results=10, timeout=10):
    """Search NVD for CVEs matching *service* and optional *version*.

    Args:
        service: Service name (e.g. ``"apache"``, ``"nginx"``).
        version: Optional version string (e.g. ``"2.4.49"``).
        max_results: Maximum number of CVEs to return.
        timeout: Request timeout in seconds.

    Returns:
        A list of dicts, each with ``cve_id``, ``severity``, ``score``,
        ``description``, and ``url``.
    """
    if not HAS_REQUESTS:
        return [{"error": "requests not installed. Run: pip install requests"}]

    keyword = service
    if version:
        keyword = f"{service} {version}"

    # Respect NVD rate limits
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _REQUEST_INTERVAL:
        time.sleep(_REQUEST_INTERVAL - elapsed)

    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
            },
            headers={"User-Agent": "EVIE-Scanner/4.0"},
            timeout=timeout,
        )
        _last_request_time = time.time()

        if resp.status_code != 200:
            return [{"error": f"NVD API returned {resp.status_code}"}]

        data = resp.json()
        return _parse_nvd_response(data)
    except Exception as e:
        return [{"error": str(e)}]


def _parse_nvd_response(data):
    """Extract clean CVE records from the NVD API v2 response."""
    results = []

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Description
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )
        # Truncate long descriptions
        if len(desc) > 200:
            desc = desc[:197] + "…"

        # CVSS score — try v3.1 first, then v3.0, then v2
        score = None
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})

        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        results.append({
            "cve_id": cve_id,
            "severity": severity,
            "score": score,
            "description": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return results


def extract_service_version(banner):
    """Try to extract a service name and version from a raw banner string.

    Args:
        banner: Raw banner text grabbed from a port.

    Returns:
        A tuple ``(service, version)`` or ``(service, None)``.
    """
    if not banner:
        return None, None

    # Common patterns: "Server: Apache/2.4.49"  "SSH-2.0-OpenSSH_8.2p1"
    patterns = [
        r'(Apache)[/\s](\d+\.\d+[\.\d]*)',
        r'(nginx)[/\s](\d+\.\d+[\.\d]*)',
        r'(OpenSSH)[_\s](\d+\.\d+[\w]*)',
        r'(Microsoft-IIS)[/\s](\d+\.\d+)',
        r'(MySQL)[/\s](\d+\.\d+[\.\d]*)',
        r'(PostgreSQL)[/\s](\d+\.\d+[\.\d]*)',
        r'(ProFTPD)[/\s](\d+\.\d+[\.\d]*)',
        r'(vsftpd)[/\s](\d+\.\d+[\.\d]*)',
        r'(Exim)[/\s](\d+\.\d+[\.\d]*)',
        r'(Postfix)',
        r'(Dovecot)',
        r'(lighttpd)[/\s](\d+\.\d+[\.\d]*)',
        r'(LiteSpeed)[/\s](\d+\.\d+[\.\d]*)',
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            groups = match.groups()
            service = groups[0]
            version = groups[1] if len(groups) > 1 else None
            return service, version

    # Fallback: grab first word
    words = banner.split()
    if words:
        return words[0].rstrip("/:"), None
    return None, None
