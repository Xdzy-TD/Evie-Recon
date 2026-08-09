#!/usr/bin/env python3
"""
GeoIP lookup — retrieve geographic and network information for an IP.
Uses the free ip-api.com service (no API key required).
"""

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def geoip_lookup(ip, timeout=5):
    """Look up geographic and ISP information for *ip*.

    Args:
        ip: Target IP address or hostname.
        timeout: Request timeout in seconds.

    Returns:
        A dict with geographic and network details, or an error dict.
    """
    if not HAS_REQUESTS:
        return {"error": "requests not installed. Run: pip install requests"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,"
            f"countryCode,region,regionName,city,zip,lat,lon,timezone,"
            f"isp,org,as,asname,reverse,mobile,proxy,hosting,query",
            timeout=timeout,
        )

        # Handle rate limiting (45 requests/minute on free tier)
        if resp.status_code == 429:
            import time
            retry_after = int(resp.headers.get("X-Ttl", 15))
            time.sleep(retry_after)
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,"
                f"countryCode,region,regionName,city,zip,lat,lon,timezone,"
                f"isp,org,as,asname,reverse,mobile,proxy,hosting,query",
                timeout=timeout,
            )

        data = resp.json()

        if data.get("status") == "fail":
            return {"error": data.get("message", "Unknown error")}

        return {
            "ip":           data.get("query", ip),
            "country":      data.get("country", "N/A"),
            "country_code": data.get("countryCode", "N/A"),
            "region":       data.get("regionName", "N/A"),
            "city":         data.get("city", "N/A"),
            "zip":          data.get("zip", "N/A"),
            "latitude":     data.get("lat"),
            "longitude":    data.get("lon"),
            "timezone":     data.get("timezone", "N/A"),
            "isp":          data.get("isp", "N/A"),
            "org":          data.get("org", "N/A"),
            "as_number":    data.get("as", "N/A"),
            "as_name":      data.get("asname", "N/A"),
            "reverse_dns":  data.get("reverse", "N/A"),
            "is_proxy":     data.get("proxy", False),
            "is_hosting":   data.get("hosting", False),
            "is_mobile":    data.get("mobile", False),
        }
    except Exception as e:
        return {"error": str(e)}
