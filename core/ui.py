#!/usr/bin/env python3
"""
EVIE — Terminal UI v4.0
Banner, colors, interactive menu, styled output, progress bars,
input validation, and help system.
"""

import os
import re
import sys
import time
import shutil
import textwrap

from core.config import (
    FRAMEWORK_NAME,
    FRAMEWORK_VERSION,
    FRAMEWORK_TAGLINE,
    FRAMEWORK_AUTHOR,
    FRAMEWORK_GITHUB,
)


# ═══════════════════════════════════════════════════════════════════
#  ANSI COLOUR PALETTE
# ═══════════════════════════════════════════════════════════════════

class C:
    """ANSI escape-code shortcuts."""
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    ITALIC   = "\033[3m"
    ULINE    = "\033[4m"

    BLACK    = "\033[30m"
    RED      = "\033[31m"
    GREEN    = "\033[32m"
    YELLOW   = "\033[33m"
    BLUE     = "\033[34m"
    MAGENTA  = "\033[35m"
    CYAN     = "\033[36m"
    WHITE    = "\033[37m"

    BRED     = "\033[91m"
    BGREEN   = "\033[92m"
    BYELLOW  = "\033[93m"
    BBLUE    = "\033[94m"
    BMAGENTA = "\033[95m"
    BCYAN    = "\033[96m"
    BWHITE   = "\033[97m"

    BG_BLACK = "\033[40m"
    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_CYAN  = "\033[46m"


def _w():
    """Terminal width."""
    return shutil.get_terminal_size((80, 24)).columns


# ═══════════════════════════════════════════════════════════════════
#  ASCII BANNER
# ═══════════════════════════════════════════════════════════════════

BANNER = r"""
{c1} ███████╗{c2}██╗   ██╗{c3}██╗{c4}███████╗
{c1} ██╔════╝{c2}██║   ██║{c3}██║{c4}██╔════╝
{c1} █████╗  {c2}██║   ██║{c3}██║{c4}█████╗
{c1} ██╔══╝  {c2}╚██╗ ██╔╝{c3}██║{c4}██╔══╝
{c1} ███████╗{c2} ╚████╔╝ {c3}██║{c4}███████╗
{c1} ╚══════╝{c2}  ╚═══╝  {c3}╚═╝{c4}╚══════╝{r}
"""

TAG_LINE = " {dm}── {bc}{tag}{dm} ──{r}"

INFO_BOX = (
    " {bd}╔════════════════════════════════════════════════════╗{r}\n"
    " {bd}║{r}  {lb}Author  :{r} {bm}{author:<39}{bd} ║{r}\n"
    " {bd}║{r}  {lb}GitHub  :{r} {cy}{github:<39}{bd} ║{r}\n"
    " {bd}║{r}  {lb}Version :{r} {bg}{ver:<39}{bd} ║{r}\n"
    " {bd}╚════════════════════════════════════════════════════╝{r}"
)


def print_banner():
    """Render the full EVIE banner."""
    os.system("")  # enable ANSI on Windows
    art = BANNER.format(
        c1=C.BCYAN, c2=C.BMAGENTA, c3=C.BBLUE, c4=C.BCYAN, r=C.RESET,
    )
    tag = TAG_LINE.format(
        dm=C.DIM + C.CYAN, bc=C.BOLD + C.BWHITE, r=C.RESET,
        tag=FRAMEWORK_TAGLINE,
    )
    box = INFO_BOX.format(
        bd=C.DIM + C.CYAN, lb=C.BOLD + C.WHITE, bm=C.BOLD + C.BMAGENTA,
        cy=C.BCYAN, bg=C.BGREEN, r=C.RESET,
        author=FRAMEWORK_AUTHOR, github=FRAMEWORK_GITHUB,
        ver=FRAMEWORK_VERSION,
    )
    print(art)
    print(tag)
    print()
    print(box)
    print()


# ═══════════════════════════════════════════════════════════════════
#  STATUS HELPERS
# ═══════════════════════════════════════════════════════════════════

def info(msg):
    print(f"  {C.BCYAN}[*]{C.RESET} {msg}")

def success(msg):
    print(f"  {C.BGREEN}[✓]{C.RESET} {msg}")

def warning(msg):
    print(f"  {C.BYELLOW}[!]{C.RESET} {msg}")

def error(msg):
    print(f"  {C.BRED}[✗]{C.RESET} {msg}")

def section(title):
    w = _w()
    pad = max(0, (w - len(title) - 8) // 2)
    line = C.DIM + C.CYAN + "─" * pad + C.RESET
    print(f"\n  {line} {C.BOLD}{C.BWHITE}{title}{C.RESET} {line}")


# ═══════════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ═══════════════════════════════════════════════════════════════════

class ProgressBar:
    """Terminal progress bar with ETA and rate."""

    def __init__(self, total, width=35, prefix="  "):
        self.total = max(total, 1)
        self.width = width
        self.prefix = prefix
        self.start_time = time.time()
        self._last_line_len = 0

    def update(self, done, total=None, msg=""):
        """Redraw the progress bar."""
        if total:
            self.total = max(total, 1)
        done = min(done, self.total)
        pct = done / self.total
        filled = int(self.width * pct)
        bar = "█" * filled + "░" * (self.width - filled)

        elapsed = time.time() - self.start_time
        if done > 0 and pct < 1.0:
            eta = (elapsed / done) * (self.total - done)
            eta_str = f"ETA {eta:.0f}s"
        elif pct >= 1.0:
            eta_str = f"done in {elapsed:.1f}s"
        else:
            eta_str = "..."

        # Truncate message to fit
        msg_short = msg[:20] if msg else ""

        line = (f"{self.prefix}{C.BCYAN}[{bar}]{C.RESET} "
                f"{C.BWHITE}{pct:>6.1%}{C.RESET} "
                f"{C.DIM}{eta_str}{C.RESET} "
                f"{C.DIM}{msg_short}{C.RESET}")

        # Clear previous line
        clear = " " * max(self._last_line_len - len(line), 0)
        sys.stdout.write(f"\r{line}{clear}")
        sys.stdout.flush()
        self._last_line_len = len(line) + len(clear)

    def finish(self, msg="Complete"):
        """Finalise the progress bar."""
        self.update(self.total, msg=msg)
        elapsed = time.time() - self.start_time
        sys.stdout.write(
            f"\r{self.prefix}{C.BGREEN}[{'█' * self.width}]{C.RESET} "
            f"{C.BGREEN}100.0%{C.RESET} "
            f"{C.DIM}done in {elapsed:.1f}s{C.RESET}  \n"
        )
        sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════
#  INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════

def validate_target(target):
    """Check if *target* looks like a valid IP, hostname, or CIDR.

    Returns:
        True if valid, False otherwise.
    """
    target = target.strip()
    if not target:
        return False

    # CIDR notation
    if "/" in target:
        try:
            import ipaddress
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    # IPv4
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True

    # Hostname — basic check
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', target):
        return True

    return False


def validate_ports(ports_str):
    """Check if *ports_str* is a valid port specification.

    Supports comma-separated ports and ranges (e.g., ``80,443,8000-8100``).

    Returns:
        True if valid, False otherwise.
    """
    if not ports_str or not ports_str.strip():
        return True  # empty → use defaults

    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            pieces = part.split("-", 1)
            if len(pieces) != 2:
                return False
            lo, hi = pieces
            if not lo.isdigit() or not hi.isdigit():
                return False
            if not (1 <= int(lo) <= 65535) or not (1 <= int(hi) <= 65535):
                return False
            if int(lo) > int(hi):
                return False
        else:
            if not part.isdigit():
                return False
            if not (1 <= int(part) <= 65535):
                return False
    return True


# ═══════════════════════════════════════════════════════════════════
#  HELP SYSTEM
# ═══════════════════════════════════════════════════════════════════

HELP_TEXT = f"""
  {C.BOLD}{C.BCYAN}EVIE{C.RESET} — {C.DIM}Network Reconnaissance Tool Framework v4.0{C.RESET}

  {C.BOLD}{C.BWHITE}USAGE{C.RESET}
    python3 run.py                              Interactive mode (menu-driven)
    python3 run.py [OPTIONS]                    CLI mode

  {C.BOLD}{C.BWHITE}CORE OPTIONS{C.RESET}
    {C.BCYAN}--targets{C.RESET}  TARGET[,TARGET,...]     {C.DIM}Target IP(s) or hostname(s) — required{C.RESET}
    {C.BCYAN}--target-file{C.RESET}  FILE               {C.DIM}Load targets from a file (one per line){C.RESET}
    {C.BCYAN}--ports{C.RESET}    PORT[,PORT,...]         {C.DIM}Ports to scan (default: common 16){C.RESET}
    {C.BCYAN}--top-ports{C.RESET}  N                     {C.DIM}Use top-N port preset (16, 100, 1000){C.RESET}
    {C.BCYAN}--threads{C.RESET}  N                       {C.DIM}Concurrent threads (default: 10){C.RESET}
    {C.BCYAN}--timeout{C.RESET}  SECS                    {C.DIM}Socket timeout in seconds (default: 2){C.RESET}
    {C.BCYAN}--passive{C.RESET}                          {C.DIM}Passive sniffing mode (requires scapy){C.RESET}
    {C.BCYAN}--interface{C.RESET} IFACE                  {C.DIM}Network interface for passive mode{C.RESET}
    {C.BCYAN}--duration{C.RESET}  SECS                   {C.DIM}Passive scan duration in seconds{C.RESET}

  {C.BOLD}{C.BWHITE}RECON MODULES{C.RESET}
    {C.BGREEN}--banner{C.RESET}                          {C.DIM}Grab service banners from open ports{C.RESET}
    {C.BGREEN}--dns{C.RESET}                             {C.DIM}Reverse DNS + record enumeration{C.RESET}
    {C.BGREEN}--headers{C.RESET}                         {C.DIM}HTTP/S response header analysis{C.RESET}
    {C.BGREEN}--whois{C.RESET}                           {C.DIM}WHOIS domain/IP registration info{C.RESET}
    {C.BGREEN}--ssl{C.RESET}                             {C.DIM}SSL/TLS certificate inspection{C.RESET}
    {C.BGREEN}--os-detect{C.RESET}                       {C.DIM}OS fingerprinting via TTL analysis{C.RESET}
    {C.BGREEN}--subdomain{C.RESET}                       {C.DIM}Subdomain enumeration (crt.sh + brute){C.RESET}
    {C.BGREEN}--geoip{C.RESET}                           {C.DIM}GeoIP / ISP / ASN lookup{C.RESET}
    {C.BGREEN}--techdetect{C.RESET}                      {C.DIM}Web technology stack detection{C.RESET}
    {C.BGREEN}--traceroute{C.RESET}                      {C.DIM}Network path tracing{C.RESET}
    {C.BGREEN}--vuln{C.RESET}                            {C.DIM}CVE / vulnerability lookup (NVD){C.RESET}
    {C.BGREEN}--udp{C.RESET}                             {C.DIM}Scan common UDP ports{C.RESET}
    {C.BGREEN}--full{C.RESET}                            {C.DIM}Enable ALL recon modules at once{C.RESET}

  {C.BOLD}{C.BWHITE}OUTPUT{C.RESET}
    {C.BYELLOW}--output{C.RESET}   FILE                  {C.DIM}Save results to JSON file{C.RESET}
    {C.BYELLOW}--report{C.RESET}                         {C.DIM}Generate HTML report{C.RESET}
    {C.BYELLOW}--quiet{C.RESET}                          {C.DIM}Suppress banner & status messages{C.RESET}

  {C.BOLD}{C.BWHITE}HISTORY{C.RESET}
    {C.BMAGENTA}--history{C.RESET}                        {C.DIM}Show scan history{C.RESET}

  {C.BOLD}{C.BWHITE}INFO{C.RESET}
    {C.BMAGENTA}--help{C.RESET}  , {C.BMAGENTA}-h{C.RESET}                     {C.DIM}Show this help message{C.RESET}
    {C.BMAGENTA}--version{C.RESET}, {C.BMAGENTA}-v{C.RESET}                    {C.DIM}Print EVIE version{C.RESET}

  {C.BOLD}{C.BWHITE}EXAMPLES{C.RESET}
    {C.DIM}# Quick port scan{C.RESET}
    python3 run.py --targets 1.1.1.1

    {C.DIM}# Full recon on multiple targets{C.RESET}
    python3 run.py --targets 1.1.1.1,8.8.8.8 --full

    {C.DIM}# Top 100 ports + GeoIP + vuln scan{C.RESET}
    python3 run.py --targets example.com --top-ports 100 --geoip --vuln

    {C.DIM}# Scan from file with HTML report{C.RESET}
    python3 run.py --target-file hosts.txt --full --report

    {C.DIM}# Banner + SSL only, save to file{C.RESET}
    python3 run.py --targets example.com --banner --ssl --output results.json

    {C.DIM}# Passive sniffing for 120 seconds{C.RESET}
    python3 run.py --targets any --passive --duration 120

  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.DIM}Coded by {C.BMAGENTA}Xdzy-TD{C.RESET}  {C.DIM}│  {C.BCYAN}github.com/Xdzy-TD{C.RESET}
"""


def print_help():
    """Print the full help reference."""
    print(HELP_TEXT)


# ═══════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ═══════════════════════════════════════════════════════════════════

MENU_OPTIONS = [
    ("1", "Active Scan",       "Port scan with service detection"),
    ("2", "Passive Scan",      "Packet sniffing on an interface (requires scapy & root)"),
    ("3", "Full Recon",        "Active scan + every recon module enabled"),
    ("4", "Custom Recon",      "Pick individual recon modules to run"),
    ("5", "Scan History",      "View, compare, or delete past scans"),
    ("6", "Generate Report",   "Create HTML report from last scan"),
    ("7", "Load from File",    "Import targets from a text file"),
    ("8", "Help",              "Show all commands and usage examples"),
    ("0", "Exit",              "Quit EVIE"),
]


def _prompt():
    return input(f"  {C.BMAGENTA}{FRAMEWORK_AUTHOR}{C.RESET}{C.DIM}@evie{C.RESET} ▸ ").strip()


def _ask(prompt, default=""):
    suffix = f" {C.DIM}[{default}]{C.RESET}" if default else ""
    val = input(f"  {C.BCYAN}?{C.RESET} {prompt}{suffix}: ").strip()
    return val if val else default


def _ask_yn(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    val = input(f"  {C.BCYAN}?{C.RESET} {prompt} {C.DIM}[{hint}]{C.RESET}: ").strip().lower()
    if not val:
        return default
    return val.startswith("y")


def _draw_menu():
    section("MAIN MENU")
    print()
    for key, title, desc in MENU_OPTIONS:
        if key == "0":
            clr = C.BRED
        elif key == "8":
            clr = C.BYELLOW
        elif key in ("5", "6", "7"):
            clr = C.BMAGENTA
        else:
            clr = C.BCYAN
        print(f"    {clr}[{key}]{C.RESET}  {C.BOLD}{title}{C.RESET}")
        print(f"         {C.DIM}{desc}{C.RESET}")
    print()
    return _prompt()


def interactive_menu(last_results=None):
    """Interactive menu loop.

    Args:
        last_results: Results from the last scan (for report generation).

    Returns:
        A tuple ``(action, data)`` where *action* is one of:
        ``"scan"``, ``"history"``, ``"report"``, ``"exit"``, or ``None``.
    """
    while True:
        choice = _draw_menu()

        if choice == "0":
            print(f"\n  {C.BMAGENTA}Goodbye! — {FRAMEWORK_AUTHOR}{C.RESET}\n")
            return ("exit", None)

        if choice == "8":
            print_help()
            continue

        if choice == "5":
            return ("history", None)

        if choice == "6":
            if last_results:
                return ("report", last_results)
            else:
                warning("No scan results available yet — run a scan first.")
                continue

        if choice == "7":
            filepath = _ask("Path to targets file")
            if filepath and os.path.isfile(filepath):
                return ("file_scan", filepath)
            else:
                error("File not found.")
                continue

        if choice in ("1", "2", "3", "4"):
            opts = _collect_options(choice)
            if opts:
                return ("scan", opts)
        else:
            warning("Invalid option — try again.")


def _collect_options(choice):
    """Gather scan parameters for the chosen mode."""
    opts = {
        "passive":    False,
        "targets":    "",
        "ports":      "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,8080,8443",
        "top_ports":  None,
        "threads":    10,
        "timeout":    2,
        "interface":  "eth0",
        "duration":   60,
        "banner":     False,
        "dns":        False,
        "headers":    False,
        "whois":      False,
        "ssl":        False,
        "os_detect":  False,
        "subdomain":  False,
        "geoip":      False,
        "techdetect": False,
        "traceroute": False,
        "vuln":       False,
        "udp":        False,
        "output":     None,
        "report":     False,
        "quiet":      False,
    }

    if choice == "2":
        opts["passive"] = True
        opts["interface"] = _ask("Interface", "eth0")
        dur = _ask("Duration (seconds)", "60")
        opts["duration"] = int(dur)
        opts["targets"] = _ask("Targets (for logging)", "any")
        return opts

    # Active modes — collect targets with validation
    while True:
        raw = _ask("Target(s) — comma-separated (supports CIDR, e.g. 192.168.1.0/24)")
        if not raw:
            error("Targets are required.")
            continue

        targets = [t.strip() for t in raw.split(",") if t.strip()]
        all_valid = True
        for t in targets:
            if not validate_target(t):
                error(f"Invalid target: {t}")
                all_valid = False
        if all_valid:
            opts["targets"] = raw
            break

    # Port selection
    port_choice = _ask("Ports — comma-separated, range (1-1024), or preset (top100/top1000)",
                       opts["ports"])
    if port_choice.lower() == "top100":
        opts["top_ports"] = 100
    elif port_choice.lower() == "top1000":
        opts["top_ports"] = 1000
    else:
        if validate_ports(port_choice):
            opts["ports"] = port_choice
        else:
            warning("Invalid port format, using defaults.")

    # Thread / timeout tuning
    t = _ask("Threads", "10")
    opts["threads"] = int(t) if t.isdigit() else 10
    to = _ask("Timeout (seconds)", "2")
    opts["timeout"] = int(to) if to.isdigit() else 2

    if choice == "3":
        # Full recon — enable everything
        for key in ("banner", "dns", "headers", "whois", "ssl", "os_detect",
                     "subdomain", "geoip", "techdetect", "traceroute", "vuln", "udp"):
            opts[key] = True
        opts["report"] = _ask_yn("Generate HTML report", default=True)
        return opts

    if choice == "4":
        section("SELECT MODULES")
        print()
        opts["banner"]    = _ask_yn("Banner grabbing")
        opts["dns"]       = _ask_yn("DNS lookup")
        opts["headers"]   = _ask_yn("HTTP header analysis")
        opts["whois"]     = _ask_yn("WHOIS lookup")
        opts["ssl"]       = _ask_yn("SSL/TLS inspection")
        opts["os_detect"] = _ask_yn("OS detection")
        opts["geoip"]     = _ask_yn("GeoIP lookup")
        opts["subdomain"] = _ask_yn("Subdomain enumeration", default=False)
        opts["techdetect"] = _ask_yn("Technology detection")
        opts["traceroute"] = _ask_yn("Traceroute", default=False)
        opts["vuln"]      = _ask_yn("CVE / vulnerability lookup", default=False)
        opts["udp"]       = _ask_yn("UDP port scan", default=False)
        opts["report"]    = _ask_yn("Generate HTML report", default=False)
        return opts

    # choice == "1" — basic active scan
    return opts


# ═══════════════════════════════════════════════════════════════════
#  SCAN HISTORY UI
# ═══════════════════════════════════════════════════════════════════

def show_scan_history():
    """Display scan history and handle user actions."""
    from core.history import list_scans, get_scan, delete_scan, compare_scans

    section("SCAN HISTORY")
    print()

    scans = list_scans(20)
    if not scans:
        info("No scan history found.")
        return

    # Display table
    print(f"  {C.DIM}{'ID':<5} {'Timestamp':<22} {'Targets':<30} {'Summary':<25} {'Duration':<10}{C.RESET}")
    print(f"  {C.DIM}{'─'*5} {'─'*22} {'─'*30} {'─'*25} {'─'*10}{C.RESET}")

    for s in scans:
        targets_short = s["targets"][:28]
        print(f"  {C.BCYAN}{s['id']:<5}{C.RESET} "
              f"{s['timestamp']:<22} "
              f"{targets_short:<30} "
              f"{C.BGREEN}{s['summary']:<25}{C.RESET} "
              f"{(s['duration_s'] or 0):<10.1f}s")
    print()

    action = _ask("Action — [v]iew ID, [d]elete ID, [c]ompare ID1 ID2, or [b]ack", "b")

    if action.lower().startswith("v"):
        parts = action.split()
        scan_id = int(parts[1]) if len(parts) > 1 else int(_ask("Scan ID"))
        scan = get_scan(scan_id)
        if scan:
            info(f"Scan #{scan_id} — {scan['timestamp']} — {scan['targets']}")
            from core.ui import print_results
            print_results(scan["results"])
        else:
            error(f"Scan #{scan_id} not found.")

    elif action.lower().startswith("d"):
        parts = action.split()
        scan_id = int(parts[1]) if len(parts) > 1 else int(_ask("Scan ID to delete"))
        if delete_scan(scan_id):
            success(f"Scan #{scan_id} deleted.")
        else:
            error(f"Scan #{scan_id} not found.")

    elif action.lower().startswith("c"):
        parts = action.split()
        if len(parts) >= 3:
            id1, id2 = int(parts[1]), int(parts[2])
        else:
            id1 = int(_ask("First scan ID"))
            id2 = int(_ask("Second scan ID"))
        diff = compare_scans(id1, id2)
        if "error" in diff:
            error(diff["error"])
        else:
            section("SCAN COMPARISON")
            print()
            info(f"Scan #{id1} ({diff['scan_1']['timestamp']}) vs "
                 f"Scan #{id2} ({diff['scan_2']['timestamp']})")
            print()
            for target, changes in diff["targets"].items():
                status = changes["status"]
                if status == "new":
                    print(f"  {C.BGREEN}[+]{C.RESET} {target} — {C.BGREEN}NEW{C.RESET}")
                elif status == "removed":
                    print(f"  {C.BRED}[-]{C.RESET} {target} — {C.BRED}REMOVED{C.RESET}")
                elif status == "changed":
                    print(f"  {C.BYELLOW}[~]{C.RESET} {target} — {C.BYELLOW}CHANGED{C.RESET}")
                    for p in changes.get("new_ports", []):
                        print(f"      {C.BGREEN}+ {p}{C.RESET}")
                    for p in changes.get("closed_ports", []):
                        print(f"      {C.BRED}- {p}{C.RESET}")
                else:
                    print(f"  {C.DIM}[=]{C.RESET} {target} — unchanged")
            print()


# ═══════════════════════════════════════════════════════════════════
#  STYLED RESULT RENDERER
# ═══════════════════════════════════════════════════════════════════

_PIPE = f"  {C.DIM}│{C.RESET}"
_LABEL_W = 20  # label column width for alignment

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _pretty_key(key):
    """Convert snake_case dict keys to readable Title Case labels."""
    return key.replace("_", " ").title()


def _kv(label, value, clr=C.WHITE):
    """Print a key : value line aligned under the pipe."""
    # Pad using visible length (strip ANSI for width calculation)
    visible_label = _ANSI_RE.sub('', str(label))
    pad = max(_LABEL_W - len(visible_label), 0)
    print(f"{_PIPE}    {clr}{label}{' ' * pad}{C.RESET} {value}")


def print_results(results):
    """Pretty-print all scan results."""
    if not results:
        warning("No results collected.")
        return

    section("SCAN RESULTS")

    for target, data in results.items():
        print(f"\n  {C.BOLD}{C.BWHITE}┌─ TARGET: {C.BGREEN}{target}{C.RESET}")
        print(_PIPE)

        if isinstance(data, dict):
            _render_target(data)
        elif isinstance(data, (list, tuple)):
            print(f"{_PIPE}  {', '.join(str(d) for d in data)}")
        else:
            print(f"{_PIPE}  {data}")

        print(f"  {C.DIM}└{'─' * 54}{C.RESET}")

    print()


def _render_target(data):
    """Render all sections for one target."""
    # ── Ports ──────────────────────────────────────────────────
    ports = data.get("open_ports")
    if ports:
        print(f"{_PIPE}  {C.BCYAN}⬡ OPEN PORTS{C.RESET}")
        for p in ports:
            print(f"{_PIPE}    {C.BGREEN}●{C.RESET} {p}")

    # ── Fingerprint (passive) ─────────────────────────────────
    fp = data.get("fingerprint")
    if fp is not None:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BCYAN}⬡ FINGERPRINT{C.RESET}")
        _kv("Score",    f"{fp:.4f}",           C.CYAN)
        _kv("Protocol", data.get("protocol", "?"), C.CYAN)

    # ── Banners ───────────────────────────────────────────────
    banners = data.get("banners")
    if banners:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BYELLOW}⬡ SERVICE BANNERS{C.RESET}")
        for port, banner in banners.items():
            # Sanitise control chars so multi-line banners don't break alignment
            clean = banner.replace("\r\n", " ┃ ").replace("\r", "").replace("\n", " ┃ ")
            _kv(f"Port {port}", clean[:120], C.YELLOW)

    # ── DNS ───────────────────────────────────────────────────
    dns_info = data.get("dns")
    if dns_info:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BMAGENTA}⬡ DNS{C.RESET}")
        _kv("Reverse", dns_info.get("reverse") or "N/A", C.MAGENTA)
        for rtype, vals in dns_info.get("records", {}).items():
            _kv(rtype, ", ".join(vals), C.MAGENTA)

    # ── HTTP / HTTPS Headers ─────────────────────────────────
    for key in ("http_headers", "https_headers"):
        hdr = data.get(key)
        if not hdr:
            continue
        proto = "HTTPS" if "https" in key else "HTTP"
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BBLUE}⬡ {proto} HEADERS{C.RESET}")
        for k, v in hdr.get("server_info", {}).items():
            _kv(k, v, C.BLUE)
        sec = hdr.get("security", {})
        present = sec.get("present", [])
        missing = sec.get("missing", [])
        if present:
            _kv("✓ Present", ", ".join(present), C.BGREEN)
        if missing:
            _kv("✗ Missing", ", ".join(missing), C.BRED)

    # ── WHOIS ─────────────────────────────────────────────────
    whois_data = data.get("whois")
    if whois_data and "error" not in whois_data:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BCYAN}⬡ WHOIS{C.RESET}")
        for k, v in whois_data.items():
            val = ", ".join(v) if isinstance(v, list) else str(v)
            _kv(_pretty_key(k), val[:120], C.CYAN)

    # ── SSL / TLS ─────────────────────────────────────────────
    ssl_data = data.get("ssl")
    if ssl_data and "error" not in ssl_data:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BGREEN}⬡ SSL / TLS{C.RESET}")
        for k, v in ssl_data.items():
            if k == "san":
                val = ", ".join(v[:5]) + (" …" if len(v) > 5 else "")
                _kv("SANs", val, C.GREEN)
            else:
                _kv(_pretty_key(k), str(v), C.GREEN)

    # ── OS Detection ──────────────────────────────────────────
    os_data = data.get("os")
    if os_data:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BRED}⬡ OS DETECTION{C.RESET}")
        guess = os_data.get("os_guess", "Unknown")
        conf  = os_data.get("confidence", "N/A")
        conf_clr = C.BGREEN if conf == "high" else C.BYELLOW if conf == "medium" else C.BRED
        _kv("OS Guess",       f"{C.BOLD}{guess}{C.RESET}")
        _kv("Confidence",     f"{conf_clr}{conf}{C.RESET}")
        _kv("TTL",            f"{os_data.get('ttl', '?')} → initial {os_data.get('initial_ttl', '?')}")
        _kv("Window",         str(os_data.get("window", "?")))

    # ── GeoIP ─────────────────────────────────────────────────
    geo = data.get("geoip")
    if geo and "error" not in geo:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BBLUE}⬡ GEO IP{C.RESET}")
        flag = _country_flag(geo.get("country_code", ""))
        _kv("Location",   f"{flag} {geo.get('city', '?')}, {geo.get('region', '?')}, {geo.get('country', '?')}", C.BLUE)
        _kv("ISP",        geo.get("isp", "N/A"), C.BLUE)
        _kv("Org",        geo.get("org", "N/A"), C.BLUE)
        _kv("ASN",        geo.get("as_number", "N/A"), C.BLUE)
        _kv("Timezone",   geo.get("timezone", "N/A"), C.BLUE)
        coords = f"{geo.get('latitude', '?')}, {geo.get('longitude', '?')}"
        _kv("Coordinates", coords, C.BLUE)
        if geo.get("is_proxy"):
            _kv("⚠ Proxy",  f"{C.BYELLOW}Yes{C.RESET}", C.YELLOW)
        if geo.get("is_hosting"):
            _kv("☁ Hosting", f"{C.BCYAN}Yes{C.RESET}", C.CYAN)

    # ── Subdomains ────────────────────────────────────────────
    subs = data.get("subdomains", [])
    if subs:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BMAGENTA}⬡ SUBDOMAINS ({len(subs)} found){C.RESET}")
        # Dynamic column width based on longest subdomain name (capped)
        max_sub_w = min(max((len(s["subdomain"]) for s in subs[:15]), default=_LABEL_W), 40)
        sub_w = max(max_sub_w + 2, _LABEL_W)
        for s in subs[:15]:  # show top 15
            name = s["subdomain"]
            pad = sub_w - len(name)
            print(f"{_PIPE}    {C.MAGENTA}{name}{' ' * pad}{C.RESET} {s['ip']}")
        if len(subs) > 15:
            print(f"{_PIPE}    {C.DIM}… and {len(subs) - 15} more{C.RESET}")

    # ── Technologies ──────────────────────────────────────────
    tech = data.get("technologies")
    if tech and tech.get("technologies"):
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BYELLOW}⬡ TECHNOLOGIES{C.RESET}")
        techs = tech["technologies"]
        # Print tech tags in rows of 4 to avoid line overflow
        row = []
        for i, t in enumerate(techs):
            row.append(f"{C.BG_BLACK}{C.BCYAN} {t} {C.RESET}")
            if len(row) == 4 or i == len(techs) - 1:
                print(f"{_PIPE}    {'  '.join(row)}")
                row = []
        for hdr, val in tech.get("headers_raw", {}).items():
            _kv(_pretty_key(hdr), val, C.YELLOW)

    # ── Traceroute ────────────────────────────────────────────
    trace = data.get("traceroute", [])
    if trace and not (len(trace) == 1 and "error" in trace[0]):
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BWHITE}⬡ TRACEROUTE{C.RESET}")
        for hop in trace:
            hop_num = str(hop.get("hop", "?")).rjust(2)
            ip = hop.get("ip", "*")
            host = hop.get("host", "")
            rtt = hop.get("rtt", "")
            host_part = f" ({host})" if host != ip and host else ""
            print(f"{_PIPE}    {C.DIM}{hop_num}.{C.RESET} {C.BWHITE}{ip}{C.RESET}{C.DIM}{host_part}{C.RESET}  {C.BCYAN}{rtt}{C.RESET}")

    # ── Vulnerabilities ───────────────────────────────────────
    vulns = data.get("vulnerabilities", [])
    valid_vulns = [v for v in vulns if "error" not in v]
    if valid_vulns:
        print(f"{_PIPE}")
        print(f"{_PIPE}  {C.BRED}⬡ VULNERABILITIES ({len(valid_vulns)} CVEs){C.RESET}")
        for v in valid_vulns:
            sev = v.get("severity", "UNKNOWN").upper()
            score = v.get("score", "?")
            if sev in ("CRITICAL", "HIGH"):
                sev_clr = C.BRED
            elif sev == "MEDIUM":
                sev_clr = C.BYELLOW
            else:
                sev_clr = C.BGREEN
            cve_id = v.get("cve_id", "N/A")
            desc = v.get("description", "")[:80]
            print(f"{_PIPE}    {sev_clr}[{sev}]{C.RESET} {C.BOLD}{cve_id}{C.RESET} "
                  f"{C.DIM}(CVSS: {score}){C.RESET}")
            print(f"{_PIPE}      {C.DIM}{desc}{C.RESET}")


def _country_flag(code):
    """Convert a 2-letter country code to a flag emoji (best-effort)."""
    if not code or len(code) != 2:
        return "🌐"
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())
    except Exception:
        return "🌐"


# ═══════════════════════════════════════════════════════════════════
#  SCAN SUMMARY DASHBOARD
# ═══════════════════════════════════════════════════════════════════

def print_scan_summary(results, duration_s=0):
    """Print a quick summary dashboard after scan results."""
    total_targets = len(results)
    total_ports = 0
    total_vulns = 0

    for data in results.values():
        if isinstance(data, dict):
            total_ports += len(data.get("open_ports", []))
            vulns = data.get("vulnerabilities", [])
            total_vulns += len([v for v in vulns if "error" not in v])

    section("SCAN SUMMARY")
    print()
    print(f"  {C.BOLD}{C.BWHITE}Targets:{C.RESET}  {C.BCYAN}{total_targets}{C.RESET}    "
          f"{C.BOLD}{C.BWHITE}Open Ports:{C.RESET}  {C.BGREEN}{total_ports}{C.RESET}    "
          f"{C.BOLD}{C.BWHITE}CVEs:{C.RESET}  "
          f"{C.BRED if total_vulns > 0 else C.BGREEN}{total_vulns}{C.RESET}    "
          f"{C.BOLD}{C.BWHITE}Duration:{C.RESET}  {C.BCYAN}{duration_s:.1f}s{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════════
#  SPINNER
# ═══════════════════════════════════════════════════════════════════

def spinner(msg, duration=1.5):
    """Braille spinner animation."""
    chars = "⣾⣽⣻⢿⡿⣟⣯⣷"
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r  {C.BCYAN}{chars[i % len(chars)]}{C.RESET} {msg}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r  {C.BGREEN}✓{C.RESET} {msg}\n")
    sys.stdout.flush()
