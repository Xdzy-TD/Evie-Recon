#!/usr/bin/env python3
"""
Technology stack detection — identify web servers, frameworks, CDNs, and
other technologies from HTTP response headers and body content.
"""

import re

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.config import TECH_SIGNATURES


def detect_technologies(host, port=80, use_https=False, timeout=5):
    """Detect technologies running on *host*.

    Sends a GET request and examines both headers and body for known
    technology fingerprints.

    Args:
        host: Target hostname or IP.
        port: Target port.
        use_https: Whether to use HTTPS.
        timeout: Request timeout in seconds.

    Returns:
        A dict with ``technologies``, ``cookies``, ``meta``, and ``scripts``.
    """
    if not HAS_REQUESTS:
        return {"error": "requests not installed. Run: pip install requests"}

    result = {
        "technologies": [],
        "cookies": [],
        "meta_info": [],
        "scripts": [],
        "headers_raw": {},
    }

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"

    try:
        resp = _requests.get(
            url, timeout=timeout, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (EVIE Scanner/4.0)"},
            allow_redirects=True,
        )
    except Exception:
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:50000]  # limit body scan size

    # ── Header-based detection ────────────────────────────────────
    for tech_name, sig in TECH_SIGNATURES.items():
        hdr_name = sig["header"].lower()
        pattern = sig["pattern"].lower()
        hdr_val = headers.get(hdr_name, "").lower()
        if pattern and pattern in hdr_val:
            result["technologies"].append(tech_name)
        elif not pattern and hdr_name in headers:
            result["technologies"].append(tech_name)

    # ── Cookie-based detection ────────────────────────────────────
    cookie_sigs = {
        "PHPSESSID":      "PHP",
        "JSESSIONID":     "Java/Tomcat",
        "ASP.NET":        "ASP.NET",
        "csrftoken":      "Django",
        "_rails":         "Ruby on Rails",
        "laravel_session": "Laravel",
        "wordpress_":     "WordPress",
        "wp-settings":    "WordPress",
    }
    for cookie in resp.cookies:
        for sig, tech in cookie_sigs.items():
            if sig.lower() in cookie.name.lower():
                if tech not in result["technologies"]:
                    result["technologies"].append(tech)
                result["cookies"].append(f"{cookie.name} → {tech}")

    # ── Body-based detection ──────────────────────────────────────
    body_sigs = [
        (r'wp-content|wp-includes',           "WordPress"),
        (r'Joomla',                           "Joomla"),
        (r'Drupal\.settings',                 "Drupal"),
        (r'shopify\.com',                     "Shopify"),
        (r'cdn\.shopify',                     "Shopify"),
        (r'react(?:\.min)?\.js|react-dom',    "React"),
        (r'vue(?:\.min)?\.js|__vue__',        "Vue.js"),
        (r'angular(?:\.min)?\.js|ng-app',     "Angular"),
        (r'jquery(?:\.min)?\.js',             "jQuery"),
        (r'bootstrap(?:\.min)?\.(?:js|css)',  "Bootstrap"),
        (r'tailwindcss|tailwind\.min\.css',   "Tailwind CSS"),
        (r'next(?:/static|Data)',             "Next.js"),
        (r'nuxt',                             "Nuxt.js"),
        (r'gatsby',                           "Gatsby"),
        (r'google-analytics\.com|gtag',       "Google Analytics"),
        (r'googletagmanager\.com',            "Google Tag Manager"),
        (r'recaptcha',                        "reCAPTCHA"),
        (r'cloudflare',                       "Cloudflare"),
        (r'font-awesome|fontawesome',         "Font Awesome"),
    ]
    for pattern, tech in body_sigs:
        if re.search(pattern, body, re.IGNORECASE):
            if tech not in result["technologies"]:
                result["technologies"].append(tech)

    # ── Meta tags ─────────────────────────────────────────────────
    meta_gen = re.findall(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        body, re.IGNORECASE,
    )
    for gen in meta_gen:
        result["meta_info"].append(gen.strip())
        if gen.strip() not in result["technologies"]:
            result["technologies"].append(gen.strip())

    # ── Script sources ────────────────────────────────────────────
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', body, re.IGNORECASE)
    result["scripts"] = scripts[:20]  # top 20 external scripts

    # ── Interesting headers ───────────────────────────────────────
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                "x-drupal-cache", "x-varnish", "x-cache", "via"):
        if key in headers:
            result["headers_raw"][key] = headers[key]

    return result
