#!/usr/bin/env python3
"""
EVIE — Core Scanner Engine v4.0
Orchestrates port scanning (TCP/UDP), recon module execution,
progress reporting, and result aggregation.
"""

import socket
import time
import ipaddress
import math
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import sniff, IP, TCP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    sniff = IP = TCP = None

from core.config import (
    FRAMEWORK_VERSION,
    DEFAULT_PORTS,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    MATH_PARAMS,
    SERVICE_MAP,
    TOP_100_PORTS,
    TOP_1000_PORTS,
    UDP_PORTS,
)
from core.crypto import (
    generate_salt,
    generate_pepper,
    generate_watermark,
    mathematical_fingerprint,
)
from core.banner import grab_banner
from core.dns_recon import forward_lookup, reverse_lookup, dns_records
from core.http_recon import fetch_headers, analyze_headers
from core.whois_recon import whois_lookup
from core.ssl_recon import get_cert_info
from core.os_detect import detect_os
from core.subdomain import enumerate_subdomains
from core.geoip import geoip_lookup
from core.techdetect import detect_technologies
from core.traceroute import traceroute
from core.vuln_lookup import vuln_lookup, extract_service_version
from core.ui import info, success, warning, error


class EvieScanner:
    """Main scanner engine for the EVIE framework v4.0."""

    VERSION = FRAMEWORK_VERSION

    def __init__(self, salt=None, pepper=None):
        self.results = {}
        self.salt = salt or generate_salt()
        self.pepper = pepper or generate_pepper()
        self.watermark_hash = generate_watermark(self.salt, "EVIE-NRT")
        self.math_params = dict(MATH_PARAMS)
        self._results_lock = threading.Lock()

        # Recon flags — set by the caller before scanning
        self.do_banner     = False
        self.do_dns        = False
        self.do_headers    = False
        self.do_whois      = False
        self.do_ssl        = False
        self.do_os_detect  = False
        self.do_subdomain  = False
        self.do_geoip      = False
        self.do_techdetect = False
        self.do_traceroute = False
        self.do_vuln       = False

        # Scan modes
        self.do_udp = False

        # Tunables
        self.threads = DEFAULT_THREADS
        self.timeout = DEFAULT_TIMEOUT

        # Progress tracking
        self._progress_callback = None
        self._total_work = 0
        self._done_work = 0
        self.scan_start_time = None
        self.scan_end_time = None

    @property
    def scan_duration(self):
        """Return scan duration in seconds, or 0 if not started."""
        if self.scan_start_time is None:
            return 0
        end = self.scan_end_time or time.time()
        return end - self.scan_start_time

    def set_progress_callback(self, callback):
        """Set a callback ``fn(done, total, message)`` for progress updates."""
        self._progress_callback = callback

    def _progress(self, msg=""):
        """Notify the progress callback."""
        self._done_work += 1
        if self._progress_callback:
            self._progress_callback(self._done_work, self._total_work, msg)

    # ═══════════════════════════════════════════════════════════════
    #  TARGET EXPANSION
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def expand_targets(raw_targets):
        """Expand a list of target strings, supporting CIDR notation.

        ``["192.168.1.0/24", "10.0.0.1"]`` → full list of IPs.
        """
        expanded = []
        for t in raw_targets:
            t = t.strip()
            if not t:
                continue
            if "/" in t:
                try:
                    network = ipaddress.ip_network(t, strict=False)
                    expanded.extend(str(ip) for ip in network.hosts())
                except ValueError:
                    expanded.append(t)
            else:
                expanded.append(t)
        return expanded

    @staticmethod
    def load_targets_from_file(filepath):
        """Read targets from a text file (one per line).

        Blank lines and lines starting with ``#`` are skipped.
        """
        targets = []
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        return targets

    # ═══════════════════════════════════════════════════════════════
    #  PORT PRESET RESOLVER
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def resolve_ports(ports_str=None, top_ports=None):
        """Resolve a port specification into a list of port integers.

        Args:
            ports_str: Comma-separated port string, or None for defaults.
            top_ports: If set, use the ``top-N`` preset (16, 100, 1000).
        """
        if top_ports:
            if top_ports >= 1000:
                return TOP_1000_PORTS
            elif top_ports >= 100:
                return TOP_100_PORTS
            else:
                return DEFAULT_PORTS

        if ports_str:
            result = []
            for part in ports_str.split(","):
                part = part.strip()
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    result.extend(range(int(lo), int(hi) + 1))
                elif part.isdigit():
                    result.append(int(part))
            return sorted(set(result))

        return DEFAULT_PORTS

    # ═══════════════════════════════════════════════════════════════
    #  ACTIVE SCANNING
    # ═══════════════════════════════════════════════════════════════

    def active_scan(self, targets, ports=None):
        """Scan a list of targets for open ports, then run enabled recon."""
        ports = ports or DEFAULT_PORTS
        self.scan_start_time = time.time()

        # Calculate total work units for progress
        self._total_work = len(targets) * len(ports)
        self._done_work = 0

        info(f"Scanning {len(targets)} target(s) on {len(ports)} port(s) "
             f"[threads={self.threads}, timeout={self.timeout}s]")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {
                pool.submit(self._scan_target, t, ports): t for t in targets
            }
            for future in as_completed(future_map):
                target = future_map[future]
                try:
                    future.result(timeout=len(ports) * self.timeout + 30)
                except Exception as exc:
                    error(f"Scan failed for {target}: {exc}")

        # UDP scan if enabled
        if self.do_udp:
            self._udp_scan(targets)

        self.scan_end_time = time.time()
        dur = self.scan_end_time - self.scan_start_time
        success(f"Scan completed in {dur:.1f}s")

    def _scan_target(self, target, ports):
        """Probe a single target and store results."""
        open_ports = []

        for port in ports:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self._resolve_service(port)
                    validation = self._validate_service(port, service)
                    if validation > self.math_params["epsilon"]:
                        open_ports.append({"port": port, "service": service})
            except (socket.timeout, socket.error, OSError):
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                self._progress(f"{target}:{port}")

        if open_ports:
            port_strs = [f"{p['port']}/{p['service']}" for p in open_ports]
            with self._results_lock:
                self.results[target] = {"open_ports": port_strs}
            success(f"{target} — open: {', '.join(port_strs)}")
            self._run_recon(target, open_ports)
        else:
            with self._results_lock:
                self.results[target] = {"open_ports": []}
            info(f"{target} — no open ports found")
            # Still run non-port recon modules
            self._run_non_port_recon(target)

    # ═══════════════════════════════════════════════════════════════
    #  UDP SCANNING
    # ═══════════════════════════════════════════════════════════════

    def _udp_scan(self, targets):
        """Probe common UDP ports on each target."""
        info(f"UDP scanning {len(targets)} target(s) on {len(UDP_PORTS)} port(s) …")

        for target in targets:
            udp_open = []
            for port in UDP_PORTS:
                if self._probe_udp(target, port):
                    service = self._resolve_service(port)
                    udp_open.append(f"{port}/{service} (UDP)")

            if udp_open:
                if target not in self.results:
                    self.results[target] = {"open_ports": []}
                elif not isinstance(self.results[target], dict):
                    continue
                self.results[target].setdefault("open_ports", [])
                self.results[target]["open_ports"].extend(udp_open)
                success(f"{target} — UDP open: {', '.join(udp_open)}")

    def _probe_udp(self, target, port):
        """Send a UDP probe and check for a response (open) or ICMP
        port-unreachable (closed).  No response = open|filtered."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"\x00", (target, port))
            try:
                sock.recvfrom(1024)
                sock.close()
                return True   # Got a response → open
            except socket.timeout:
                sock.close()
                return True   # No response → open|filtered (count as open)
        except (socket.error, OSError):
            return False

    # ═══════════════════════════════════════════════════════════════
    #  PASSIVE SCANNING
    # ═══════════════════════════════════════════════════════════════

    def passive_scan(self, interface="eth0", duration=60):
        """Sniff the network and fingerprint observed hosts."""
        if not HAS_SCAPY:
            error("scapy is not installed — passive scanning unavailable.")
            return

        self.scan_start_time = time.time()
        info(f"Passive scan on {interface} for {duration}s …")

        def _callback(packet):
            if IP in packet:
                ip_layer = packet[IP]
                src = ip_layer.src
                fp = mathematical_fingerprint(src, self.pepper, self.math_params)
                proto = "TCP" if TCP in packet else "UDP"
                self.results[src] = {
                    "fingerprint": fp,
                    "timestamp":   time.time(),
                    "protocol":    proto,
                }

        try:
            sniff(iface=interface, prn=_callback, store=False, timeout=duration)
        except KeyboardInterrupt:
            warning("Passive scan interrupted by user.")
        except PermissionError:
            error("Permission denied — passive scanning requires root / sudo.")
        except Exception as e:
            error(f"Passive scan error: {e}")

        self.scan_end_time = time.time()

    # ═══════════════════════════════════════════════════════════════
    #  RECON MODULES
    # ═══════════════════════════════════════════════════════════════

    def _run_recon(self, target, open_ports):
        """Run every enabled recon module against *target*."""
        data = self.results[target]
        port_nums = [p["port"] for p in open_ports]

        # Run recon modules in parallel where possible
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = []

            if self.do_banner:
                futures.append(pool.submit(self._recon_banner, target, open_ports, data))
            if self.do_dns:
                futures.append(pool.submit(self._recon_dns, target, data))
            if self.do_headers:
                futures.append(pool.submit(self._recon_headers, target, port_nums, data))
            if self.do_whois:
                futures.append(pool.submit(self._recon_whois, target, data))
            if self.do_ssl:
                futures.append(pool.submit(self._recon_ssl, target, port_nums, data))
            if self.do_os_detect:
                futures.append(pool.submit(self._recon_os, target, port_nums, data))
            if self.do_geoip:
                futures.append(pool.submit(self._recon_geoip, target, data))
            if self.do_subdomain:
                futures.append(pool.submit(self._recon_subdomain, target, data))
            if self.do_techdetect:
                futures.append(pool.submit(self._recon_techdetect, target, port_nums, data))
            if self.do_traceroute:
                futures.append(pool.submit(self._recon_traceroute, target, data))

            for f in as_completed(futures):
                try:
                    f.result(timeout=60)
                except Exception as exc:
                    warning(f"Recon module error on {target}: {exc}")

        # Vuln lookup depends on banners, so run after
        if self.do_vuln:
            self._recon_vuln(target, data)

    def _run_non_port_recon(self, target):
        """Run recon modules that don't require open ports."""
        data = self.results[target]

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = []
            if self.do_dns:
                futures.append(pool.submit(self._recon_dns, target, data))
            if self.do_geoip:
                futures.append(pool.submit(self._recon_geoip, target, data))
            if self.do_whois:
                futures.append(pool.submit(self._recon_whois, target, data))
            if self.do_traceroute:
                futures.append(pool.submit(self._recon_traceroute, target, data))

            for f in as_completed(futures):
                try:
                    f.result(timeout=60)
                except Exception:
                    pass

    # ── Individual recon methods ──────────────────────────────────

    def _recon_banner(self, target, open_ports, data):
        info(f"Grabbing banners on {target} …")
        banners = {}
        for p in open_ports:
            banner = grab_banner(target, p["port"], timeout=self.timeout)
            if banner:
                banners[p["port"]] = banner
        if banners:
            data["banners"] = banners

    def _recon_dns(self, target, data):
        info(f"DNS lookup for {target} …")
        hostname = reverse_lookup(target)
        dns_info = {"reverse": hostname}
        if hostname:
            dns_info["records"] = dns_records(hostname)
        data["dns"] = dns_info

    def _recon_headers(self, target, port_nums, data):
        if 443 in port_nums:
            info(f"Fetching HTTPS headers from {target} …")
            hdrs = fetch_headers(target, 443, use_https=True)
            data["https_headers"] = analyze_headers(hdrs)
        if 80 in port_nums:
            info(f"Fetching HTTP headers from {target} …")
            hdrs = fetch_headers(target, 80, use_https=False)
            data["http_headers"] = analyze_headers(hdrs)

    def _recon_whois(self, target, data):
        info(f"WHOIS lookup for {target} …")
        data["whois"] = whois_lookup(target)

    def _recon_ssl(self, target, port_nums, data):
        if 443 in port_nums:
            info(f"SSL/TLS inspection on {target}:443 …")
            data["ssl"] = get_cert_info(target, 443)

    def _recon_os(self, target, port_nums, data):
        info(f"OS detection on {target} …")
        probe_port = port_nums[0] if port_nums else 80
        data["os"] = detect_os(target, probe_port)

    def _recon_geoip(self, target, data):
        info(f"GeoIP lookup for {target} …")
        data["geoip"] = geoip_lookup(target)

    def _recon_subdomain(self, target, data):
        info(f"Subdomain enumeration for {target} …")
        # Only run subdomain enum on domain names, not raw IPs
        try:
            ipaddress.ip_address(target)
            # It's a bare IP — skip subdomain enum
            return
        except ValueError:
            pass
        subs = enumerate_subdomains(target, threads=self.threads)
        if subs:
            data["subdomains"] = subs
            success(f"{target} — {len(subs)} subdomain(s) found")

    def _recon_techdetect(self, target, port_nums, data):
        use_https = 443 in port_nums
        port = 443 if use_https else (80 if 80 in port_nums else (port_nums[0] if port_nums else 80))
        info(f"Tech detection on {target}:{port} …")
        data["technologies"] = detect_technologies(target, port, use_https=use_https)

    def _recon_traceroute(self, target, data):
        info(f"Traceroute to {target} …")
        data["traceroute"] = traceroute(target)

    def _recon_vuln(self, target, data):
        """Look up CVEs based on detected banners."""
        banners = data.get("banners", {})
        if not banners:
            return

        info(f"CVE lookup for {target} …")
        all_vulns = []
        seen_services = set()

        for port, banner_text in banners.items():
            svc, ver = extract_service_version(banner_text)
            if svc and svc.lower() not in seen_services:
                seen_services.add(svc.lower())
                vulns = vuln_lookup(svc, ver, max_results=5)
                all_vulns.extend(vulns)

        if all_vulns:
            data["vulnerabilities"] = all_vulns
            valid = [v for v in all_vulns if "error" not in v]
            if valid:
                warning(f"{target} — {len(valid)} CVE(s) found!")

    # ═══════════════════════════════════════════════════════════════
    #  HELPERS
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _resolve_service(port):
        """Resolve a port number to a service name."""
        try:
            return socket.getservbyport(port)
        except OSError:
            return SERVICE_MAP.get(port, "unknown")

    def _validate_service(self, port, service):
        """Mathematical validation score for a detected service."""
        probs = self._service_probabilities(service)
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        return entropy / (1 + math.exp(-self.math_params["sigma"] * port))

    @staticmethod
    def _service_probabilities(service):
        """Return probability distribution for *service*."""
        base = {
            "ssh": [0.3, 0.7], "http": [0.5, 0.5], "https": [0.5, 0.5],
            "smtp": [0.2, 0.8], "ftp": [0.15, 0.85], "dns": [0.25, 0.75],
            "mysql": [0.1, 0.9], "rdp": [0.2, 0.8],
        }
        return base.get(service.lower(), [0.1, 0.9])

    # ═══════════════════════════════════════════════════════════════
    #  EXPORT
    # ═══════════════════════════════════════════════════════════════

    def export_json(self, filepath):
        """Save results to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(self.results, fh, indent=2, default=str)
        success(f"Results saved to {filepath}")
