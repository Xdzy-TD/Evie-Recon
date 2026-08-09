#!/usr/bin/env python3
"""
EVIE — Network Reconnaissance Tool Framework v4.0
Entry point: interactive menu or CLI mode.

Author : Xdzy-TD
GitHub : https://github.com/Xdzy-TD
"""

import sys
import os
import argparse

from core import EvieScanner, FRAMEWORK_NAME, FRAMEWORK_VERSION
from core.config import DEFAULT_PORTS
from core.ui import (
    print_banner, print_help, print_results, print_scan_summary,
    spinner, ProgressBar,
    info, success, warning, error, section,
    interactive_menu, show_scan_history, C,
)


# ═══════════════════════════════════════════════════════════════════
#  SCAN RUNNER
# ═══════════════════════════════════════════════════════════════════

def run_scan(scanner, opts):
    """Configure *scanner* from *opts* and execute the scan."""
    scanner.do_banner     = opts.get("banner", False)
    scanner.do_dns        = opts.get("dns", False)
    scanner.do_headers    = opts.get("headers", False)
    scanner.do_whois      = opts.get("whois", False)
    scanner.do_ssl        = opts.get("ssl", False)
    scanner.do_os_detect  = opts.get("os_detect", False)
    scanner.do_subdomain  = opts.get("subdomain", False)
    scanner.do_geoip      = opts.get("geoip", False)
    scanner.do_techdetect = opts.get("techdetect", False)
    scanner.do_traceroute = opts.get("traceroute", False)
    scanner.do_vuln       = opts.get("vuln", False)
    scanner.do_udp        = opts.get("udp", False)
    scanner.threads       = opts.get("threads", 10)
    scanner.timeout       = opts.get("timeout", 2)

    if opts.get("passive"):
        scanner.passive_scan(
            opts.get("interface", "eth0"),
            opts.get("duration", 60),
        )
    else:
        targets_raw = [t.strip() for t in opts["targets"].split(",") if t.strip()]
        targets = scanner.expand_targets(targets_raw)

        # Resolve ports
        top_ports = opts.get("top_ports")
        raw_ports = opts.get("ports", "")
        ports = scanner.resolve_ports(raw_ports, top_ports)

        # Set up progress bar
        pbar = ProgressBar(len(targets) * len(ports))
        scanner.set_progress_callback(
            lambda done, total, msg: pbar.update(done, total, msg)
        )

        scanner.active_scan(targets, ports)
        pbar.finish()

    # Export to JSON if requested
    output = opts.get("output")
    if output:
        scanner.export_json(output)

    # Generate HTML report if requested
    if opts.get("report"):
        from core.report import generate_report
        targets_str = opts.get("targets", "")
        path = generate_report(
            scanner.results,
            targets_str=targets_str,
            duration_s=scanner.scan_duration,
        )
        success(f"HTML report saved: {path}")

    # Save to history
    try:
        from core.history import save_scan
        scan_id = save_scan(
            opts.get("targets", ""),
            opts,
            scanner.results,
            duration_s=scanner.scan_duration,
        )
        info(f"Scan saved to history (ID: #{scan_id})")
    except Exception:
        pass  # history is best-effort


# ═══════════════════════════════════════════════════════════════════
#  CLI MODE
# ═══════════════════════════════════════════════════════════════════

def cli_mode():
    """Parse CLI args and run the scan."""
    parser = argparse.ArgumentParser(
        prog="evie",
        description=f"{FRAMEWORK_NAME} v{FRAMEWORK_VERSION} — Network Reconnaissance Tool Framework",
        add_help=False,  # we have our own --help
    )

    # Core
    core = parser.add_argument_group("Core Options")
    core.add_argument("--targets",      default=None,       help="Target IP(s) or hostname(s), comma-separated")
    core.add_argument("--target-file",  default=None,       help="Load targets from a file (one per line)")
    core.add_argument("--ports",        default=None,       help="Ports to scan, comma-separated (default: common 16)")
    core.add_argument("--top-ports",    type=int, default=None, help="Use top-N port preset (16, 100, 1000)")
    core.add_argument("--threads",      type=int, default=10, help="Concurrent scan threads")
    core.add_argument("--timeout",      type=int, default=2, help="Socket timeout in seconds")
    core.add_argument("--passive",      action="store_true", help="Passive sniffing mode (requires scapy + root)")
    core.add_argument("--interface",    default="eth0",     help="Network interface for passive mode")
    core.add_argument("--duration",     type=int, default=60, help="Passive scan duration in seconds")

    # Recon
    recon = parser.add_argument_group("Recon Modules")
    recon.add_argument("--banner",      action="store_true", help="Grab service banners")
    recon.add_argument("--dns",         action="store_true", help="Reverse DNS + record enumeration")
    recon.add_argument("--headers",     action="store_true", help="HTTP/S header analysis")
    recon.add_argument("--whois",       action="store_true", help="WHOIS registration lookup")
    recon.add_argument("--ssl",         action="store_true", help="SSL/TLS certificate inspection")
    recon.add_argument("--os-detect",   action="store_true", help="OS fingerprinting via TTL")
    recon.add_argument("--subdomain",   action="store_true", help="Subdomain enumeration")
    recon.add_argument("--geoip",       action="store_true", help="GeoIP / ISP lookup")
    recon.add_argument("--techdetect",  action="store_true", help="Technology stack detection")
    recon.add_argument("--traceroute",  action="store_true", help="Network path tracing")
    recon.add_argument("--vuln",        action="store_true", help="CVE / vulnerability lookup")
    recon.add_argument("--udp",         action="store_true", help="UDP port scan")
    recon.add_argument("--full",        action="store_true", help="Enable ALL recon modules")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--output",    default=None,       help="Save results to a JSON file")
    out.add_argument("--report",    action="store_true", help="Generate HTML report")
    out.add_argument("--quiet",     action="store_true", help="Suppress banner and status output")

    # History
    hist = parser.add_argument_group("History")
    hist.add_argument("--history",  action="store_true", help="Show scan history")

    # Info
    inf = parser.add_argument_group("Info")
    inf.add_argument("-h", "--help",    action="store_true", help="Show detailed help")
    inf.add_argument("-v", "--version", action="store_true", help="Print version")

    args = parser.parse_args()

    if args.help:
        print_help()
        return

    if args.version:
        print(f"  {C.BCYAN}{FRAMEWORK_NAME}{C.RESET} v{FRAMEWORK_VERSION}")
        return

    if args.history:
        show_scan_history()
        return

    # Determine targets
    if args.target_file:
        targets_list = EvieScanner.load_targets_from_file(args.target_file)
        targets_str = ",".join(targets_list)
    elif args.targets:
        targets_str = args.targets
    elif not args.passive:
        error("--targets or --target-file is required (use -h for help)")
        return
    else:
        targets_str = "any"

    scanner = EvieScanner()

    all_on = args.full
    opts = {
        "passive":    args.passive,
        "targets":    targets_str,
        "ports":      args.ports or ",".join(str(p) for p in DEFAULT_PORTS),
        "top_ports":  args.top_ports,
        "threads":    args.threads,
        "timeout":    args.timeout,
        "interface":  args.interface,
        "duration":   args.duration,
        "banner":     all_on or args.banner,
        "dns":        all_on or args.dns,
        "headers":    all_on or args.headers,
        "whois":      all_on or args.whois,
        "ssl":        all_on or args.ssl,
        "os_detect":  all_on or args.os_detect,
        "subdomain":  all_on or args.subdomain,
        "geoip":      all_on or args.geoip,
        "techdetect": all_on or args.techdetect,
        "traceroute": all_on or args.traceroute,
        "vuln":       all_on or args.vuln,
        "udp":        all_on or args.udp,
        "output":     args.output,
        "report":     args.report or all_on,
        "quiet":      args.quiet,
    }

    try:
        run_scan(scanner, opts)
        print_results(scanner.results)
        print_scan_summary(scanner.results, scanner.scan_duration)
    except Exception as e:
        print()
        error(f"Scan failed: {e}")


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    """Entry point — interactive if no args, CLI otherwise."""
    print_banner()

    if len(sys.argv) > 1:
        cli_mode()
        return

    info("No arguments detected — launching interactive mode …")
    spinner("Initialising EVIE v4.0")
    print()

    last_results = None

    while True:
        result = interactive_menu(last_results)

        if result is None:
            continue

        action, data = result

        if action == "exit":
            return

        if action == "history":
            show_scan_history()
            continue

        if action == "report":
            from core.report import generate_report
            path = generate_report(data, duration_s=0)
            success(f"HTML report saved: {path}")
            continue

        if action == "file_scan":
            # Load targets from file and run scan
            try:
                targets_list = EvieScanner.load_targets_from_file(data)
                targets_str = ",".join(targets_list)
                info(f"Loaded {len(targets_list)} target(s) from file")
            except Exception as e:
                error(f"Failed to load file: {e}")
                continue

            # Collect scan options for file-loaded targets
            from core.ui import _ask_yn, _ask
            section("FILE SCAN OPTIONS")
            print()
            opts = {
                "targets": targets_str,
                "ports": "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,8080,8443",
                "top_ports": None,
                "threads": 10,
                "timeout": 2,
                "passive": False,
                "banner": True,
                "dns": True,
                "headers": True,
                "whois": True,
                "ssl": True,
                "os_detect": True,
                "subdomain": False,
                "geoip": _ask_yn("GeoIP lookup"),
                "techdetect": _ask_yn("Technology detection"),
                "traceroute": False,
                "vuln": _ask_yn("CVE lookup", default=False),
                "udp": False,
                "output": None,
                "report": _ask_yn("Generate HTML report", default=True),
                "quiet": False,
            }
            data = opts
            action = "scan"  # fall through to scan

        if action == "scan":
            scanner = EvieScanner()
            print()
            spinner("Starting scan")

            try:
                run_scan(scanner, data)
                print_results(scanner.results)
                print_scan_summary(scanner.results, scanner.scan_duration)
                last_results = scanner.results
                success("Scan complete — returning to main menu …\n")
            except Exception as e:
                print()
                error(f"Scan failed: {e}")
                info("Returning to main menu …\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.BYELLOW}[!]{C.RESET} Interrupted — exiting EVIE.\n")
        sys.exit(0)