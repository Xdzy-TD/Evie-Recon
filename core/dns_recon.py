#!/usr/bin/env python3
"""DNS reconnaissance — forward/reverse lookups and record enumeration."""

import socket

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def forward_lookup(hostname):
    """Resolve a hostname to its IP address(es).

    Returns:
        A list of IP address strings, or an empty list on failure.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = sorted({r[4][0] for r in results})
        return ips
    except socket.gaierror:
        return []


def reverse_lookup(ip):
    """Resolve an IP address to its hostname.

    Returns:
        The hostname string, or None on failure.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def dns_records(hostname):
    """Fetch common DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA).

    Requires the ``dnspython`` library. Falls back to a basic A lookup
    via the standard library when unavailable.

    Returns:
        A dict mapping record type names to lists of record strings.
    """
    records = {}

    if not HAS_DNSPYTHON:
        # Fallback: basic resolution only
        ips = forward_lookup(hostname)
        if ips:
            records["A"] = ips
        return records

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            continue

    return records
