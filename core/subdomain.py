#!/usr/bin/env python3
"""
Subdomain enumeration — discover subdomains via Certificate Transparency
logs (crt.sh) and DNS brute-force.
"""

import socket
import concurrent.futures

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.config import SUBDOMAIN_WORDLIST


def enumerate_subdomains(domain, use_bruteforce=True, threads=10, timeout=5):
    """Discover subdomains for *domain*.

    Combines Certificate Transparency (crt.sh) with optional DNS brute-force.

    Args:
        domain: The base domain to enumerate (e.g. ``example.com``).
        use_bruteforce: Whether to also try the built-in wordlist.
        threads: Concurrent threads for brute-force.
        timeout: DNS resolution timeout.

    Returns:
        A list of dicts with ``subdomain`` and ``ip`` keys.
    """
    found = {}

    # ── Certificate Transparency via crt.sh ───────────────────────
    if HAS_REQUESTS:
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=timeout,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "").strip().lower()
                    # crt.sh sometimes returns wildcard or multi-line names
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(domain) and sub not in found:
                            ip = _resolve(sub, timeout)
                            if ip:
                                found[sub] = ip
        except Exception:
            pass

    # ── DNS Brute-force ───────────────────────────────────────────
    if use_bruteforce:
        candidates = [f"{word}.{domain}" for word in SUBDOMAIN_WORDLIST
                      if f"{word}.{domain}" not in found]

        def _probe(subdomain):
            ip = _resolve(subdomain, timeout)
            return (subdomain, ip) if ip else None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for result in pool.map(_probe, candidates):
                if result:
                    sub, ip = result
                    found[sub] = ip

    return [{"subdomain": s, "ip": ip} for s, ip in sorted(found.items())]


def _resolve(hostname, timeout=3):
    """Resolve *hostname* to an IP, or return None."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout, OSError):
        return None
