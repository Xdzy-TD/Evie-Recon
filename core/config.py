#!/usr/bin/env python3
"""
EVIE — Network Reconnaissance Tool Framework
Centralized configuration and constants.
"""

import os

# ── Framework Identity ─────────────────────────────────────────────

FRAMEWORK_NAME    = "EVIE"
FRAMEWORK_VERSION = "4.0.0"
FRAMEWORK_TAGLINE = "Network Reconnaissance Tool Framework"
FRAMEWORK_AUTHOR  = "Xdzy-TD"
FRAMEWORK_GITHUB  = "https://github.com/Xdzy-TD"

# ── Paths ─────────────────────────────────────────────────────────
# _PROJECT_ROOT is derived from this file's own location (core/config.py ->
# up two levels), NOT from the current working directory. 

EVIE_HOME     = os.path.join(os.path.expanduser("~"), ".evie")
HISTORY_DB    = os.path.join(EVIE_HOME, "scans.db")
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
REPORT_DIR    = os.path.join(_PROJECT_ROOT, "reports")

os.makedirs(EVIE_HOME, exist_ok=True)

# ── Default Scan Parameters ───────────────────────────────────────

DEFAULT_PORTS     = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]
DEFAULT_THREADS   = 10
DEFAULT_TIMEOUT   = 2
DEFAULT_INTERFACE = "eth0"
DEFAULT_DURATION  = 60

# ── Top-N Port Presets ────────────────────────────────────────────

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
]

TOP_1000_PORTS = list(range(1, 1025)) + [
    1080, 1099, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2222,
    2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4040, 4443,
    4444, 4567, 4711, 4848, 4899, 5000, 5001, 5003, 5004, 5005, 5050,
    5060, 5222, 5269, 5280, 5357, 5432, 5555, 5601, 5631, 5666, 5672,
    5800, 5900, 5901, 5984, 5985, 5986, 6000, 6001, 6379, 6443, 6660,
    6661, 6666, 6667, 6697, 7000, 7001, 7002, 7070, 7077, 7443, 7474,
    7547, 7777, 7778, 8000, 8001, 8008, 8009, 8010, 8020, 8042, 8060,
    8069, 8080, 8081, 8082, 8083, 8088, 8090, 8091, 8111, 8139, 8140,
    8181, 8443, 8444, 8480, 8500, 8834, 8880, 8888, 8983, 9000, 9001,
    9002, 9042, 9043, 9060, 9080, 9090, 9091, 9100, 9200, 9300, 9418,
    9443, 9999, 10000, 10250, 10443, 11211, 11443, 12345, 15672, 17000,
    18080, 20000, 25565, 27017, 27018, 28017, 32768, 49152, 49153,
    49154, 49155, 49156, 50000, 50030, 50070, 50075, 50090, 54321,
    55553, 61616,
]

# ── UDP Ports ─────────────────────────────────────────────────────

UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353]

# ── Mathematical Parameters ───────────────────────────────────────

MATH_PARAMS = {
    "epsilon": 1e-10,
    "sigma":   0.5,
    "lambda":  0.1,
    "theta":   0.01,
}

# ── Extended Service Map ──────────────────────────────────────────
# Fallback when socket.getservbyport() doesn't know the port.

SERVICE_MAP = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    67:    "dhcp",
    68:    "dhcp",
    69:    "tftp",
    80:    "http",
    88:    "kerberos",
    110:   "pop3",
    111:   "rpcbind",
    123:   "ntp",
    135:   "msrpc",
    137:   "netbios-ns",
    138:   "netbios-dgm",
    139:   "netbios",
    143:   "imap",
    161:   "snmp",
    162:   "snmptrap",
    389:   "ldap",
    443:   "https",
    445:   "smb",
    465:   "smtps",
    500:   "isakmp",
    514:   "syslog",
    520:   "rip",
    587:   "submission",
    631:   "ipp",
    636:   "ldaps",
    993:   "imaps",
    995:   "pop3s",
    1080:  "socks",
    1433:  "mssql",
    1521:  "oracle",
    1723:  "pptp",
    1883:  "mqtt",
    1900:  "ssdp",
    2049:  "nfs",
    2181:  "zookeeper",
    2375:  "docker",
    3000:  "grafana",
    3128:  "squid",
    3306:  "mysql",
    3389:  "rdp",
    4443:  "https-alt",
    5000:  "upnp",
    5060:  "sip",
    5222:  "xmpp",
    5353:  "mdns",
    5432:  "postgresql",
    5672:  "amqp",
    5900:  "vnc",
    5984:  "couchdb",
    6379:  "redis",
    6443:  "kubernetes",
    6667:  "irc",
    7001:  "weblogic",
    8000:  "http-alt",
    8008:  "http-alt",
    8080:  "http-proxy",
    8443:  "https-alt",
    8834:  "nessus",
    8888:  "http-alt",
    9000:  "sonarqube",
    9090:  "prometheus",
    9200:  "elasticsearch",
    9300:  "elasticsearch",
    9418:  "git",
    10000: "webmin",
    11211: "memcached",
    27017: "mongodb",
    50000: "sap",
}

# ── Severity Levels ───────────────────────────────────────────────

SEVERITY = {
    "CRITICAL": {"score": (9.0, 10.0), "color": "bred"},
    "HIGH":     {"score": (7.0, 8.9),  "color": "bred"},
    "MEDIUM":   {"score": (4.0, 6.9),  "color": "byellow"},
    "LOW":      {"score": (0.1, 3.9),  "color": "bgreen"},
    "INFO":     {"score": (0.0, 0.0),  "color": "bcyan"},
}

# ── Subdomain Brute-force Wordlist ────────────────────────────────

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging",
    "test", "portal", "admin", "blog", "shop", "store", "m", "mobile",
    "app", "vpn", "remote", "secure", "cloud", "cdn", "assets", "static",
    "media", "images", "img", "video", "download", "downloads", "upload",
    "beta", "alpha", "demo", "sandbox", "git", "svn", "hg", "ci", "cd",
    "jenkins", "jira", "confluence", "wiki", "docs", "support", "help",
    "status", "monitor", "grafana", "prometheus", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo", "backup",
    "bak", "old", "new", "web", "web1", "web2", "server", "server1",
    "cpanel", "plesk", "webdisk", "autodiscover", "autoconfig", "mx",
    "relay", "gateway", "proxy", "sso", "auth", "login", "oauth", "ldap",
    "intranet", "internal", "owa", "exchange", "office", "crm", "erp",
]

# ── Technology Detection Signatures ───────────────────────────────

TECH_SIGNATURES = {
    # Server headers
    "nginx":        {"header": "server", "pattern": "nginx"},
    "Apache":       {"header": "server", "pattern": "apache"},
    "IIS":          {"header": "server", "pattern": "microsoft-iis"},
    "LiteSpeed":    {"header": "server", "pattern": "litespeed"},
    "Cloudflare":   {"header": "server", "pattern": "cloudflare"},
    "Caddy":        {"header": "server", "pattern": "caddy"},

    # Frameworks / Platforms
    "PHP":          {"header": "x-powered-by", "pattern": "php"},
    "ASP.NET":      {"header": "x-powered-by", "pattern": "asp.net"},
    "Express.js":   {"header": "x-powered-by", "pattern": "express"},
    "Django":       {"header": "x-framework",  "pattern": "django"},
    "Rails":        {"header": "x-powered-by", "pattern": "phusion"},

    # CDN / Proxy
    "Akamai":       {"header": "x-akamai-transformed", "pattern": ""},
    "Fastly":       {"header": "x-served-by", "pattern": "cache"},
    "Varnish":      {"header": "via",         "pattern": "varnish"},
    "AWS ELB":      {"header": "server",      "pattern": "awselb"},

    # Security
    "ModSecurity":  {"header": "server",      "pattern": "mod_security"},
}