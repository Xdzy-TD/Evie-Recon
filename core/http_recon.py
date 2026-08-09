#!/usr/bin/env python3
"""HTTP header analysis — extract server info and security headers."""

import http.client
import ssl


# Security headers to check for
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def fetch_headers(host, port=None, use_https=False, timeout=5):
    """Send a HEAD request and return all response headers.

    Args:
        host: Target hostname or IP.
        port: Target port (defaults to 443 for HTTPS, 80 for HTTP).
        use_https: Whether to use HTTPS.
        timeout: Connection timeout in seconds.

    Returns:
        A dict of header-name → value pairs, or an empty dict on failure.
    """
    try:
        if use_https:
            port = port or 443
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            port = port or 80
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        headers["_status"] = f"{resp.status} {resp.reason}"
        conn.close()
        return headers
    except Exception:
        return {}


def analyze_headers(headers):
    """Analyze HTTP headers for server info and security posture.

    Args:
        headers: A dict returned by ``fetch_headers``.

    Returns:
        A dict with keys ``server_info`` and ``security``.
    """
    analysis = {
        "server_info": {},
        "security": {"present": [], "missing": []},
    }

    # Server information (case-insensitive lookup)
    headers_ci = {k.lower(): v for k, v in headers.items()}
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-runtime"):
        value = headers_ci.get(key)
        if value:
            # Use original-cased key for display
            display_key = key.replace("-", " ").title().replace(" ", "-")
            analysis["server_info"][display_key] = value

    status = headers.get("_status")
    if status:
        analysis["server_info"]["Status"] = status

    # Security header check (case-insensitive)
    headers_lower = {k.lower(): k for k in headers}
    for hdr in SECURITY_HEADERS:
        if hdr.lower() in headers_lower:
            analysis["security"]["present"].append(hdr)
        else:
            analysis["security"]["missing"].append(hdr)

    return analysis
